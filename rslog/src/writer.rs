//! 写入器模块
//!
//! 提供 StreamWriter 和 BlockWriter 两种写入器

use lz4_flex::compress_prepend_size;
use std::io;
use std::path::Path;

use crate::constants::{CHANNEL_SHIFT, FLAG_BINARY, FLAG_BLOCK, FLAG_COMPRESSED};
use crate::entry::StreamEntry;
use crate::stream_log::{StreamLog, StreamStats};

/// 块内子记录头大小: len(2B) - v2 格式移除了时间戳
const BLOCK_SUBRECORD_HEADER_SIZE: usize = 2;

/// 简化的写入器
pub struct StreamWriter {
    log: StreamLog,
}

impl StreamWriter {
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64) -> io::Result<Self> {
        let log = StreamLog::open(path, Some(max_size))?;
        Ok(Self { log })
    }

    pub fn write_text(&mut self, text: &str) -> io::Result<u64> {
        self.log.write_text(text)
    }

    /// 写入文本（指定通道）
    pub fn write_text_ch(&mut self, channel: u8, text: &str) -> io::Result<u64> {
        self.log.write_text_ch(channel, text)
    }

    /// 写入二进制数据（默认通道0）
    pub fn write_binary(&mut self, data: &[u8]) -> io::Result<u64> {
        self.log.write_binary(data)
    }

    /// 写入二进制数据（指定通道）
    pub fn write_binary_ch(&mut self, channel: u8, data: &[u8]) -> io::Result<u64> {
        self.log.write_binary_ch(channel, data)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.log.flush()
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.log.sync()
    }

    pub fn stats(&self) -> StreamStats {
        self.log.stats()
    }

    pub fn log_mut(&mut self) -> &mut StreamLog {
        &mut self.log
    }
}

/// 块内缓冲的子记录
struct BlockRecord {
    data: Vec<u8>, // 原始数据
}

/// 块写入器 - 缓冲多条记录后批量压缩写入
///
/// 相比 StreamWriter，BlockWriter 会在内存中缓冲多条记录，
/// 达到阈值后一次性压缩整块写入，能显著提高重复数据的压缩率。
///
/// 块格式（压缩前）:
/// ```text
/// [base_ts:8B][子记录1][子记录2]...
/// 子记录: [rel_ts:2B][len:2B][data:NB]
/// ```
pub struct BlockWriter {
    log: StreamLog,
    /// 每个通道的缓冲区: (base_ts, records, total_bytes, is_binary)
    channel_buffers: [(Option<u64>, Vec<BlockRecord>, usize, bool); 16],
    /// 缓冲区大小阈值（字节）
    block_size_threshold: usize,
    /// 最大记录数阈值
    max_records: usize,
}

impl BlockWriter {
    /// 创建块写入器
    ///
    /// - `block_size_threshold`: 缓冲区达到此大小后自动刷新（默认 4KB）
    /// - `max_records`: 缓冲区达到此记录数后自动刷新（默认 500）
    ///
    /// 注意：单条数据加上 flag 和 LZ4 header 后不能超过 65535 字节（length 字段是 u16）
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64) -> io::Result<Self> {
        Self::with_threshold(path, max_size, 4 * 1024, 500)
    }

    pub fn with_threshold<P: AsRef<Path>>(
        path: P,
        max_size: u64,
        block_size_threshold: usize,
        max_records: usize,
    ) -> io::Result<Self> {
        let log = StreamLog::open(path, Some(max_size))?;
        Ok(Self {
            log,
            channel_buffers: Default::default(),
            block_size_threshold,
            max_records,
        })
    }

    /// StreamEntry 的最大数据长度（length 字段是 u16）
    const MAX_ENTRY_DATA_LEN: usize = 65535;

    /// 写入二进制数据到缓冲区
    ///
    /// 注意：单条数据的长度不能超过 65535 字节（sub-record 的 len 字段是 u16）
    pub fn write_binary_ch(&mut self, channel: u8, data: &[u8]) -> io::Result<u64> {
        // 检查单条数据大小是否超过 u16 限制
        if data.len() > 65535 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Single record too large: {} bytes (max 65535). \
                    Consider splitting the data into smaller chunks.",
                    data.len()
                ),
            ));
        }

        let ch = (channel & 0x0F) as usize;
        let buf = &mut self.channel_buffers[ch];

        // 如果缓冲区为空，初始化
        if buf.0.is_none() {
            buf.0 = Some(0); // 不再使用时间戳
            buf.3 = true; // is_binary
        }

        buf.1.push(BlockRecord {
            data: data.to_vec(),
        });
        buf.2 += BLOCK_SUBRECORD_HEADER_SIZE + data.len();

        // 检查是否需要刷新
        if buf.2 >= self.block_size_threshold || buf.1.len() >= self.max_records {
            self.flush_channel(channel)?;
        }

        Ok(0) // 块模式下序列号在刷新时分配
    }

    /// 写入文本数据到缓冲区
    pub fn write_text_ch(&mut self, channel: u8, text: &str) -> io::Result<u64> {
        let ch = (channel & 0x0F) as usize;
        let buf = &mut self.channel_buffers[ch];

        // 如果缓冲区为空，初始化
        if buf.0.is_none() {
            buf.0 = Some(0); // 不再使用时间戳
            buf.3 = false; // is_binary = false (text)
        }

        buf.1.push(BlockRecord {
            data: text.as_bytes().to_vec(),
        });
        buf.2 += BLOCK_SUBRECORD_HEADER_SIZE + text.len();

        // 检查是否需要刷新
        if buf.2 >= self.block_size_threshold || buf.1.len() >= self.max_records {
            self.flush_channel(channel)?;
        }

        Ok(0)
    }

    /// 刷新指定通道的缓冲区
    fn flush_channel(&mut self, channel: u8) -> io::Result<()> {
        let ch = (channel & 0x0F) as usize;
        let buf = &mut self.channel_buffers[ch];

        if buf.1.is_empty() {
            return Ok(());
        }

        let is_binary = buf.3;

        // 构建块数据
        // 格式: [子记录1][子记录2]...
        // 子记录: [len:2B][data:NB] (移除了 rel_ts)
        let mut block_data = Vec::with_capacity(buf.2);

        for record in buf.1.drain(..) {
            block_data.extend_from_slice(&(record.data.len() as u16).to_le_bytes());
            block_data.extend_from_slice(&record.data);
        }

        // 重置缓冲区状态
        buf.0 = None;
        buf.2 = 0;

        // 压缩并写入
        let compressed = compress_prepend_size(&block_data);
        let use_compressed = compressed.len() < block_data.len();

        let mut flag = (channel << CHANNEL_SHIFT) | FLAG_BLOCK;
        if is_binary {
            flag |= FLAG_BINARY;
        }
        if use_compressed {
            flag |= FLAG_COMPRESSED;
        }

        let final_data = if use_compressed {
            let mut marked = vec![flag];
            marked.extend_from_slice(&compressed);
            marked
        } else {
            let mut marked = vec![flag];
            marked.extend_from_slice(&block_data);
            marked
        };

        // 检查数据大小是否超过 StreamEntry 的 length 字段限制 (u16)
        if final_data.len() > Self::MAX_ENTRY_DATA_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Block data too large: {} bytes (max {}). \
                    Consider reducing batch size or flush interval.",
                    final_data.len(),
                    Self::MAX_ENTRY_DATA_LEN
                ),
            ));
        }

        let seq = self.log.header.global_seq;
        self.log.header.global_seq += 1;

        let entry = StreamEntry {
            sequence: seq,
            data: final_data,
        };

        self.log.write_entry(&entry)?;
        Ok(())
    }

    /// 刷新所有通道的缓冲区
    pub fn flush(&mut self) -> io::Result<()> {
        for ch in 0..16u8 {
            self.flush_channel(ch)?;
        }
        self.log.flush()
    }

    /// 只刷新指定通道的缓冲区（不刷新其他通道）
    ///
    /// 适用于多通道独立刷新策略，避免一个通道的刷新影响其他通道
    pub fn flush_channel_only(&mut self, channel: u8) -> io::Result<()> {
        self.flush_channel(channel)?;
        self.log.flush()
    }

    /// 同步到磁盘
    pub fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        self.log.sync()
    }

    pub fn stats(&self) -> StreamStats {
        self.log.stats()
    }

    pub fn log_mut(&mut self) -> &mut StreamLog {
        &mut self.log
    }

    /// 检查本次会话是否发生了回绕
    pub fn has_wrapped(&self) -> bool {
        self.log.has_wrapped()
    }

    /// 获取本次会话的写入统计
    pub fn session_stats(&self) -> &crate::stream_log::SessionStats {
        self.log.session_stats()
    }

    /// 获取缓冲区状态（用于调试）
    pub fn buffer_stats(&self) -> Vec<(u8, usize, usize)> {
        let mut stats = Vec::new();
        for (ch, buf) in self.channel_buffers.iter().enumerate() {
            if !buf.1.is_empty() {
                stats.push((ch as u8, buf.1.len(), buf.2));
            }
        }
        stats
    }
}

impl Drop for BlockWriter {
    fn drop(&mut self) {
        let _ = self.sync();
    }
}
