//! 核心日志存储
//!
//! 流式循环日志存储的核心实现

use crc32fast::Hasher;
use lz4_flex::compress_prepend_size;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::constants::{
    CHANNEL_MASK, CHANNEL_SHIFT, END_MAGIC, ENTRY_OVERHEAD, FLAG_BINARY, FLAG_COMPRESSED,
    HEADER_SIZE, SYNC_MAGIC,
};
use crate::entry::StreamEntry;
use crate::header::StreamHeader;

/// 统计信息
#[derive(Debug, Clone)]
pub struct StreamStats {
    pub max_size: u64,
    pub used_size: u64,
    pub write_pos: u64,
    pub global_seq: u64,
    pub boot_count: u32,
}

impl std::fmt::Display for StreamStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Stream Log Statistics:")?;
        writeln!(
            f,
            "  Max size: {} bytes ({:.1} KB)",
            self.max_size,
            self.max_size as f64 / 1024.0
        )?;
        writeln!(
            f,
            "  Used: {} bytes ({:.1}%)",
            self.used_size,
            self.used_size as f64 / self.max_size as f64 * 100.0
        )?;
        writeln!(f, "  Write pos: {}", self.write_pos)?;
        writeln!(f, "  Total entries: {}", self.global_seq)?;
        writeln!(f, "  Boot count: {}", self.boot_count)?;
        Ok(())
    }
}

/// 流式循环日志
pub struct StreamLog {
    pub(crate) file: File,
    pub(crate) header: StreamHeader,
    pub(crate) dirty: bool,
}

impl StreamLog {
    /// 打开或创建日志文件
    pub fn open<P: AsRef<Path>>(path: P, max_size: Option<u64>) -> io::Result<Self> {
        let path = path.as_ref();
        let max_size = max_size.unwrap_or(3 * 1024 * 1024); // 默认 3MB

        if path.exists() {
            Self::open_existing(path)
        } else {
            Self::create_new(path, max_size)
        }
    }

    fn create_new<P: AsRef<Path>>(path: P, max_size: u64) -> io::Result<Self> {
        let header = StreamHeader::new(max_size);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        // 写入头部
        header.write_to(&mut file)?;

        // 预分配空间
        file.set_len(HEADER_SIZE + max_size)?;
        file.sync_all()?;

        Ok(Self {
            file,
            header,
            dirty: false,
        })
    }

    fn open_existing<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        let header = StreamHeader::read_from(&mut file)?;

        if !header.is_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid stream log file",
            ));
        }

        let mut log = Self {
            file,
            header,
            dirty: false,
        };

        // 扫描恢复：找到真正的最后写入位置（防止断电导致header未更新）
        log.recover_write_pos()?;

        // 恢复：增加启动计数
        log.header.boot_count += 1;
        log.save_header()?;

        Ok(log)
    }

    /// 扫描文件恢复正确的写入位置
    /// 从 header.write_pos 开始向后扫描，找到最后一条有效记录
    /// 支持回绕：如果扫描到文件末尾会继续从头扫描
    fn recover_write_pos(&mut self) -> io::Result<()> {
        let data_area_size = self.header.max_size;
        let start_pos = self.header.write_pos;
        let mut scan_pos = start_pos;
        let mut found_new_data = false;
        let mut wrapped = false;

        // 从 write_pos 开始扫描，最多扫描整个数据区一遍
        loop {
            // 防止无限循环：如果回绕后又回到起点，停止
            if wrapped && scan_pos >= start_pos {
                break;
            }

            self.file.seek(SeekFrom::Start(HEADER_SIZE + scan_pos))?;

            // 读取 SYNC 标记
            let mut sync_buf = [0u8; 2];
            if self.file.read_exact(&mut sync_buf).is_err() {
                break;
            }

            let sync = u16::from_le_bytes(sync_buf);
            if sync != SYNC_MAGIC {
                // 没有更多有效数据
                break;
            }

            // 读取长度
            let mut len_buf = [0u8; 2];
            if self.file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let data_len = u16::from_le_bytes(len_buf) as u64;

            // 合理性检查
            if data_len > data_area_size / 2 {
                // 长度不合理，可能是残留数据
                break;
            }

            // 计算完整条目大小
            // SYNC(2) + Len(2) + Seq(8) + TS_ms(6) + Data(N) + CRC(4) + END(2) = 24 + N
            let entry_size = ENTRY_OVERHEAD as u64 + data_len;

            // 检查是否会越界
            if scan_pos + entry_size > data_area_size {
                // 条目会越界，这是旧数据残留，不是有效条目
                break;
            }

            // 跳到 CRC 位置验证
            // CRC 位置 = HEADER_SIZE + scan_pos + SYNC(2) + Len(2) + Seq(8) + Data(N)
            //          = HEADER_SIZE + scan_pos + 12 + data_len
            self.file.seek(SeekFrom::Start(
                HEADER_SIZE + scan_pos + crate::constants::ENTRY_HEADER_SIZE as u64 + data_len,
            ))?;
            let mut crc_buf = [0u8; 4];
            if self.file.read_exact(&mut crc_buf).is_err() {
                break;
            }
            let stored_crc = u32::from_le_bytes(crc_buf);

            // 读取完整数据计算 CRC
            // CRC 覆盖从 Len 开始到 Data 结束: Len(2) + Seq(8) + Data(N)
            self.file
                .seek(SeekFrom::Start(HEADER_SIZE + scan_pos + 2))?; // 跳过 SYNC
            let mut entry_data = vec![0u8; (2 + 8 + data_len) as usize];
            if self.file.read_exact(&mut entry_data).is_err() {
                break;
            }

            let mut hasher = Hasher::new();
            hasher.update(&entry_data);
            let calc_crc = hasher.finalize();

            if calc_crc != stored_crc {
                // CRC 不匹配，数据无效
                break;
            }

            // 读取序列号 (entry_data 格式: Len(2) + Seq(8) + Data(N))
            let seq = u64::from_le_bytes([
                entry_data[2],
                entry_data[3],
                entry_data[4],
                entry_data[5],
                entry_data[6],
                entry_data[7],
                entry_data[8],
                entry_data[9],
            ]);

            // 有效条目，更新位置
            found_new_data = true;
            scan_pos += entry_size;

            // 更新全局序列号
            if seq >= self.header.global_seq {
                self.header.global_seq = seq + 1;
            }

            // 处理回绕：如果到达文件末尾，从头开始
            if scan_pos >= data_area_size {
                scan_pos = 0;
                wrapped = true;
            }
        }

        if found_new_data {
            self.header.write_pos = scan_pos;
            self.dirty = true;
        }

        Ok(())
    }

    /// 写入文本日志（默认通道0）
    pub fn write_text(&mut self, text: &str) -> io::Result<u64> {
        self.write_text_ch(0, text)
    }

    /// 写入文本日志（指定通道）
    pub fn write_text_ch(&mut self, channel: u8, text: &str) -> io::Result<u64> {
        let flag = (channel << CHANNEL_SHIFT) & CHANNEL_MASK;
        self.write_data_internal(text.as_bytes(), flag, false)
    }

    /// 写入压缩文本（适合大文本）
    pub fn write_text_compressed(&mut self, text: &str) -> io::Result<u64> {
        self.write_text_compressed_ch(0, text)
    }

    /// 写入压缩文本（指定通道）
    pub fn write_text_compressed_ch(&mut self, channel: u8, text: &str) -> io::Result<u64> {
        let flag = (channel << CHANNEL_SHIFT) & CHANNEL_MASK;
        self.write_data_internal(text.as_bytes(), flag, true)
    }

    /// 写入二进制数据（默认通道0）
    pub fn write_binary(&mut self, data: &[u8]) -> io::Result<u64> {
        self.write_binary_ch(0, data)
    }

    /// 写入二进制数据（指定通道）
    pub fn write_binary_ch(&mut self, channel: u8, data: &[u8]) -> io::Result<u64> {
        let flag = ((channel << CHANNEL_SHIFT) & CHANNEL_MASK) | FLAG_BINARY;
        self.write_data_internal(data, flag, false)
    }

    /// 写入压缩二进制数据
    pub fn write_binary_compressed(&mut self, data: &[u8]) -> io::Result<u64> {
        self.write_binary_compressed_ch(0, data)
    }

    /// 写入压缩二进制数据（指定通道）
    pub fn write_binary_compressed_ch(&mut self, channel: u8, data: &[u8]) -> io::Result<u64> {
        let flag = ((channel << CHANNEL_SHIFT) & CHANNEL_MASK) | FLAG_BINARY;
        self.write_data_internal(data, flag, true)
    }

    /// 内部写入方法
    fn write_data_internal(
        &mut self,
        data: &[u8],
        base_flag: u8,
        compress: bool,
    ) -> io::Result<u64> {
        let seq = self.header.global_seq;
        self.header.global_seq += 1;

        // 可选压缩
        let final_data = if compress && data.len() > 64 {
            let compressed = compress_prepend_size(data);
            if compressed.len() < data.len() {
                // 添加标记+压缩
                let mut marked = vec![base_flag | FLAG_COMPRESSED];
                marked.extend_from_slice(&compressed);
                marked
            } else {
                let mut marked = vec![base_flag]; // 未压缩
                marked.extend_from_slice(data);
                marked
            }
        } else {
            let mut marked = vec![base_flag]; // 未压缩
            marked.extend_from_slice(data);
            marked
        };

        let entry = StreamEntry {
            sequence: seq,
            data: final_data,
        };

        self.write_entry(&entry)?;
        Ok(seq)
    }

    /// 写入条目
    pub(crate) fn write_entry(&mut self, entry: &StreamEntry) -> io::Result<()> {
        let serialized = entry.serialize();
        let entry_size = serialized.len() as u64;

        // 验证序列化数据的完整性
        {
            // 检查 END marker 是否正确
            let end_marker = u16::from_le_bytes([
                serialized[serialized.len() - 2],
                serialized[serialized.len() - 1],
            ]);
            if end_marker != END_MAGIC {
                eprintln!(
                    "rslog ERROR: serialize produced invalid END marker: 0x{:04x}",
                    end_marker
                );
            }
        }

        // 检查是否需要循环
        let data_area_size = self.header.max_size;
        let mut write_pos = self.header.write_pos;

        // 如果写入会超出边界，需要回绕
        if write_pos + entry_size > data_area_size {
            // 检查是否单条数据就超过整个空间
            if entry_size > data_area_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Entry too large for storage",
                ));
            }

            eprintln!(
                "rslog: Wrapping around: write_pos=0x{:x}, entry_size={}, max_size=0x{:x}",
                write_pos, entry_size, data_area_size
            );
            // 从头开始写
            write_pos = 0;
        }

        // 写入数据
        let file_pos = HEADER_SIZE + write_pos;
        self.file.seek(SeekFrom::Start(file_pos))?;
        self.file.write_all(&serialized)?;

        // 立即读回并验证
        {
            self.file.seek(SeekFrom::Start(file_pos))?;
            let mut verify_buf = vec![0u8; serialized.len()];
            if let Err(e) = self.file.read_exact(&mut verify_buf) {
                eprintln!(
                    "rslog ERROR: failed to read back entry for verification: {}",
                    e
                );
            } else if verify_buf != serialized {
                eprintln!(
                    "rslog ERROR: data mismatch after write! seq={}, pos=0x{:x}, size={}",
                    entry.sequence, write_pos, entry_size
                );
                // 打印差异位置
                for (i, (a, b)) in verify_buf.iter().zip(serialized.iter()).enumerate() {
                    if a != b {
                        eprintln!(
                            "  First diff at offset {}: expected 0x{:02x}, got 0x{:02x}",
                            i, b, a
                        );
                        break;
                    }
                }
            }
        }

        // 更新写入位置
        self.header.write_pos = write_pos + entry_size;
        self.dirty = true;

        Ok(())
    }

    /// 查看指定位置的条目大小
    #[allow(dead_code)]
    fn peek_entry_size(&mut self, pos: u64) -> io::Result<Option<usize>> {
        self.file.seek(SeekFrom::Start(HEADER_SIZE + pos))?;

        let mut header = [0u8; 4];
        if self.file.read_exact(&mut header).is_err() {
            return Ok(None);
        }

        let sync = u16::from_le_bytes([header[0], header[1]]);
        if sync != SYNC_MAGIC {
            return Ok(None);
        }

        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
        Ok(Some(ENTRY_OVERHEAD + len))
    }

    /// 读取所有有效条目
    pub fn read_all(&mut self) -> io::Result<Vec<StreamEntry>> {
        // 使用容错读取，然后返回结果
        let (entries, _errors) = self.read_all_tolerant();
        Ok(entries)
    }

    /// 查找下一个 SYNC 标记
    #[allow(dead_code)]
    fn find_next_sync(&self, data: &[u8], start: usize) -> Option<usize> {
        for i in start..data.len() - 1 {
            if data[i] == 0x55 && data[i + 1] == 0xAA {
                return Some(i);
            }
        }
        None
    }

    /// 容错读取 - 跳过损坏数据
    pub fn read_all_tolerant(&mut self) -> (Vec<StreamEntry>, usize) {
        let mut entries = Vec::new();
        let mut errors = 0;

        // 获取文件实际大小
        let file_size = match self.file.seek(SeekFrom::End(0)) {
            Ok(size) => size,
            Err(e) => {
                eprintln!("rslog: Failed to get file size: {}", e);
                return (entries, 1);
            }
        };

        // 使用文件实际大小和 max_size 中较小的那个
        // 这样可以处理 max_size 被错误设置的情况
        let data_area_size = file_size.saturating_sub(HEADER_SIZE);
        let data_size = std::cmp::min(self.header.max_size, data_area_size) as usize;

        // 合理性检查：避免分配过大的内存（限制在 1GB）
        if data_size > 1024 * 1024 * 1024 {
            eprintln!(
                "rslog: Data size too large: {} bytes (max_size={}, file_size={})",
                data_size, self.header.max_size, file_size
            );
            return (entries, 1);
        }

        let mut data = vec![0u8; data_size];

        if self.file.seek(SeekFrom::Start(HEADER_SIZE)).is_err() {
            eprintln!("rslog: Failed to seek to data area");
            return (entries, 1);
        }
        if self.file.read_exact(&mut data).is_err() {
            eprintln!("rslog: Failed to read data area ({} bytes)", data_size);
            return (entries, 1);
        }

        let mut pos = 0;
        while pos < data_size - ENTRY_OVERHEAD {
            // 找 SYNC
            if data[pos] != 0x55 || data[pos + 1] != 0xAA {
                pos += 1;
                continue;
            }

            // 尝试解析
            if let Some((entry, size)) = StreamEntry::deserialize(&data[pos..]) {
                entries.push(entry);
                pos += size;
            } else {
                errors += 1;
                pos += 1;
            }
        }

        // 按序列号排序
        entries.sort_by_key(|e| e.sequence);

        (entries, errors)
    }

    /// 获取统计信息
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            max_size: self.header.max_size,
            used_size: self.header.write_pos, // 简化：write_pos 就是已用大小
            write_pos: self.header.write_pos,
            global_seq: self.header.global_seq,
            boot_count: self.header.boot_count,
        }
    }

    /// 保存头部
    pub(crate) fn save_header(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.header.write_to(&mut self.file)?;
        self.file.sync_data()
    }

    /// 同步到磁盘
    pub fn sync(&mut self) -> io::Result<()> {
        // 先刷新 File 的内部缓冲到操作系统
        self.file.flush()?;
        if self.dirty {
            self.save_header()?;
            self.dirty = false;
        }
        self.file.sync_all()
    }

    /// 强制刷新
    pub fn flush(&mut self) -> io::Result<()> {
        self.sync()
    }
}

impl Drop for StreamLog {
    fn drop(&mut self) {
        let _ = self.sync();
    }
}
