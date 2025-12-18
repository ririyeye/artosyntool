//! 流式循环日志存储
//!
//! 设计要点：
//! 1. 紧凑存储 - 数据一条接一条，无固定块浪费
//! 2. 循环覆盖 - 写满后从头覆盖旧数据
//! 3. 断电安全 - 每条数据带 CRC，损坏可跳过
//! 4. 协议格式 - 类似二进制通讯流，靠协议解析
//!
//! 文件格式：
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ FileHeader (64 bytes)                                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Entry1 │ Entry2 │ Entry3 │ ... │ EntryN │ [空闲] │ Entry1'  │
//! │        │        │        │     │        │        │ (覆盖)   │
//! └─────────────────────────────────────────────────────────────┘
//!          ↑                              ↑
//!       read_pos                      write_pos
//! ```
//!
//! Entry 格式：
//! ```text
//! ┌──────┬──────┬────────┬──────────┬──────────┬──────┬──────┐
//! │ SYNC │ Len  │ SeqNum │ TS_ms    │ Data ... │ CRC  │ END  │
//! │ 2B   │ 2B   │ 8B     │ 6B       │ N bytes  │ 4B   │ 2B   │
//! └──────┴──────┴────────┴──────────┴──────────┴──────┴──────┘
//! ```

use crc32fast::Hasher;
use lz4_flex::compress_prepend_size;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// 同步字节 - 用于定位数据边界
const SYNC_MAGIC: u16 = 0xAA55;
/// 结束标记
const END_MAGIC: u16 = 0x55AA;
/// 文件头魔数
const FILE_MAGIC: u32 = 0x534C4F47; // "SLOG"
/// 版本号
const VERSION: u32 = 1;
/// 文件头大小
const HEADER_SIZE: u64 = 64;
/// 条目头大小 (SYNC + Len + Seq + Timestamp_ms)
const ENTRY_HEADER_SIZE: usize = 2 + 2 + 8 + 6;
/// 条目尾大小 (CRC + END)
const ENTRY_FOOTER_SIZE: usize = 4 + 2;
/// 条目开销
const ENTRY_OVERHEAD: usize = ENTRY_HEADER_SIZE + ENTRY_FOOTER_SIZE;

/// 数据标记字节格式 (存储在 data 首字节):
/// ```text
///   高4位 = 通道号 (0-15)
///   低4位 = 类型+压缩标记
///     bit 3: 0=单条, 1=块(多条打包)
///     bit 2: 0=文本, 1=二进制
///     bit 0: 0=未压缩, 1=已压缩
/// ```
/// 示例:
/// - 0x00: 通道0, 文本, 未压缩
/// - 0x01: 通道0, 文本, 压缩
/// - 0x04: 通道0, 二进制, 未压缩
/// - 0x14: 通道1, 二进制, 未压缩
/// - 0x25: 通道2, 二进制, 压缩
/// - 0x09: 通道0, 文本块, 压缩
/// - 0x0D: 通道0, 二进制块, 压缩
const FLAG_BINARY: u8 = 0x04; // bit 2: 二进制类型
const FLAG_COMPRESSED: u8 = 0x01; // bit 0: 已压缩
const FLAG_BLOCK: u8 = 0x08; // bit 3: 块模式（多条打包）
const CHANNEL_SHIFT: u8 = 4; // 通道号在高4位
const CHANNEL_MASK: u8 = 0xF0; // 通道号掩码

/// 块内子记录头大小: 相对时间戳(2B) + 数据长度(2B)
const BLOCK_RECORD_HEADER_SIZE: usize = 4;

/// 文件头
#[derive(Debug, Clone)]
struct StreamHeader {
    magic: u32,
    version: u32,
    max_size: u64,      // 数据区最大大小
    write_pos: u64,     // 当前写入位置（相对于数据区）
    read_pos: u64,      // 最旧有效数据位置
    global_seq: u64,    // 全局序列号
    boot_count: u32,    // 启动次数
    flags: u32,         // 标志位
    reserved: [u8; 16], // 保留
}

impl StreamHeader {
    fn new(max_size: u64) -> Self {
        Self {
            magic: FILE_MAGIC,
            version: VERSION,
            max_size,
            write_pos: 0,
            read_pos: 0,
            global_seq: 0,
            boot_count: 0,
            flags: 0,
            reserved: [0; 16],
        }
    }

    fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 64];
        reader.read_exact(&mut buf)?;

        Ok(Self {
            magic: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            version: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            max_size: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            write_pos: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            read_pos: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            global_seq: u64::from_le_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]),
            boot_count: u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
            flags: u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
            reserved: buf[48..64].try_into().unwrap(),
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.max_size.to_le_bytes());
        buf[16..24].copy_from_slice(&self.write_pos.to_le_bytes());
        buf[24..32].copy_from_slice(&self.read_pos.to_le_bytes());
        buf[32..40].copy_from_slice(&self.global_seq.to_le_bytes());
        buf[40..44].copy_from_slice(&self.boot_count.to_le_bytes());
        buf[44..48].copy_from_slice(&self.flags.to_le_bytes());
        buf[48..64].copy_from_slice(&self.reserved);
        writer.write_all(&buf)
    }

    fn is_valid(&self) -> bool {
        self.magic == FILE_MAGIC && self.version == VERSION
    }
}

/// 单条日志条目
#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub sequence: u64,
    /// 毫秒时间戳 (6字节，范围约8925年)
    pub timestamp_ms: u64,
    pub data: Vec<u8>,
}

impl StreamEntry {
    /// 获取通道号 (0-15)
    pub fn channel(&self) -> u8 {
        if self.data.is_empty() {
            0
        } else {
            (self.data[0] & CHANNEL_MASK) >> CHANNEL_SHIFT
        }
    }

    /// 是否为文本数据
    pub fn is_text(&self) -> bool {
        if self.data.is_empty() {
            true
        } else {
            self.data[0] & FLAG_BINARY == 0
        }
    }

    /// 是否为二进制数据
    pub fn is_binary(&self) -> bool {
        if self.data.is_empty() {
            false
        } else {
            self.data[0] & FLAG_BINARY != 0
        }
    }

    /// 是否已压缩
    pub fn is_compressed(&self) -> bool {
        if self.data.is_empty() {
            false
        } else {
            self.data[0] & FLAG_COMPRESSED != 0
        }
    }

    /// 是否为块模式（多条记录打包）
    pub fn is_block(&self) -> bool {
        if self.data.is_empty() {
            false
        } else {
            self.data[0] & FLAG_BLOCK != 0
        }
    }

    /// 获取原始数据（自动解压）
    pub fn get_data(&self) -> Vec<u8> {
        if self.data.len() <= 1 {
            return Vec::new();
        }

        if self.is_compressed() {
            // 尝试解压
            if let Ok(decompressed) = lz4_flex::decompress_size_prepended(&self.data[1..]) {
                return decompressed;
            }
        }

        // 未压缩或解压失败，返回原始数据
        self.data[1..].to_vec()
    }

    /// 获取文本内容
    pub fn as_text(&self) -> Option<String> {
        if !self.is_text() {
            return None;
        }
        String::from_utf8(self.get_data()).ok()
    }

    /// 获取二进制内容
    pub fn as_binary(&self) -> Option<Vec<u8>> {
        if !self.is_binary() {
            return None;
        }
        Some(self.get_data())
    }

    /// 解析块内的子记录
    /// 块格式: [base_ts:8B][子记录1][子记录2]...
    /// 子记录格式: [相对时间戳:2B][数据长度:2B][数据:NB]
    /// 返回: Vec<(绝对时间戳, 数据)>
    pub fn unpack_block(&self) -> Option<Vec<(u64, Vec<u8>)>> {
        if !self.is_block() {
            return None;
        }

        let raw = self.get_data();
        if raw.len() < 8 {
            return None;
        }

        // 读取基准时间戳
        let base_ts = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);

        let mut records = Vec::new();
        let mut offset = 8;

        while offset + BLOCK_RECORD_HEADER_SIZE <= raw.len() {
            // 读取相对时间戳 (ms, 2B)
            let rel_ts = u16::from_le_bytes([raw[offset], raw[offset + 1]]) as u64;
            // 读取数据长度 (2B)
            let data_len = u16::from_le_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
            offset += BLOCK_RECORD_HEADER_SIZE;

            if offset + data_len > raw.len() {
                break;
            }

            let data = raw[offset..offset + data_len].to_vec();
            let abs_ts = base_ts + rel_ts;
            records.push((abs_ts, data));
            offset += data_len;
        }

        Some(records)
    }

    /// 计算总大小（包括头尾）
    fn total_size(&self) -> usize {
        ENTRY_OVERHEAD + self.data.len()
    }

    /// 序列化到字节
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_size());

        // SYNC
        buf.extend_from_slice(&SYNC_MAGIC.to_le_bytes());
        // Len (数据长度)
        buf.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        // SeqNum
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        // Timestamp_ms (6 bytes, little-endian)
        let ts_bytes = self.timestamp_ms.to_le_bytes();
        buf.extend_from_slice(&ts_bytes[0..6]);
        // Data
        buf.extend_from_slice(&self.data);

        // CRC (计算从 Len 开始到 Data 结束)
        let mut hasher = Hasher::new();
        hasher.update(&buf[2..]); // 跳过 SYNC
        let crc = hasher.finalize();
        buf.extend_from_slice(&crc.to_le_bytes());

        // END
        buf.extend_from_slice(&END_MAGIC.to_le_bytes());

        buf
    }

    /// 从字节反序列化
    fn deserialize(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < ENTRY_OVERHEAD {
            return None;
        }

        // 检查 SYNC
        let sync = u16::from_le_bytes([data[0], data[1]]);
        if sync != SYNC_MAGIC {
            return None;
        }

        // 读取长度
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let total_size = ENTRY_OVERHEAD + len;

        if data.len() < total_size {
            return None;
        }

        // 检查 END
        let end_pos = total_size - 2;
        let end = u16::from_le_bytes([data[end_pos], data[end_pos + 1]]);
        if end != END_MAGIC {
            return None;
        }

        // 验证 CRC
        let crc_pos = end_pos - 4;
        let stored_crc = u32::from_le_bytes([
            data[crc_pos],
            data[crc_pos + 1],
            data[crc_pos + 2],
            data[crc_pos + 3],
        ]);

        let mut hasher = Hasher::new();
        hasher.update(&data[2..crc_pos]); // 从 Len 到 Data
        let calc_crc = hasher.finalize();

        if stored_crc != calc_crc {
            return None;
        }

        // 解析字段
        let sequence = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        // Timestamp_ms (6 bytes, little-endian)
        let timestamp_ms = u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], 0, 0,
        ]);
        let entry_data = data[18..18 + len].to_vec();

        Some((
            StreamEntry {
                sequence,
                timestamp_ms,
                data: entry_data,
            },
            total_size,
        ))
    }
}

/// 流式循环日志
pub struct StreamLog {
    file: File,
    header: StreamHeader,
    dirty: bool,
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
            // SYNC(2) + Len(2) + Seq(8) + TS_sec(4) + TS_ms(2) + Data(N) + CRC(4) + END(2) = 24 + N
            let entry_size = ENTRY_OVERHEAD as u64 + data_len;

            // 检查是否会越界
            if scan_pos + entry_size > data_area_size {
                // 条目会越界，这是旧数据残留，不是有效条目
                break;
            }

            // 跳到 CRC 位置验证
            self.file.seek(SeekFrom::Start(
                HEADER_SIZE + scan_pos + 4 + 8 + 4 + data_len,
            ))?;
            let mut crc_buf = [0u8; 4];
            if self.file.read_exact(&mut crc_buf).is_err() {
                break;
            }
            let stored_crc = u32::from_le_bytes(crc_buf);

            // 读取完整数据计算 CRC
            self.file
                .seek(SeekFrom::Start(HEADER_SIZE + scan_pos + 4))?;
            let mut entry_data = vec![0u8; (8 + 4 + data_len) as usize];
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

            // 读取序列号
            let seq = u64::from_le_bytes([
                entry_data[0],
                entry_data[1],
                entry_data[2],
                entry_data[3],
                entry_data[4],
                entry_data[5],
                entry_data[6],
                entry_data[7],
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
    /// timestamp_ms: 毫秒时间戳（如 System::now() 的毫秒数）
    pub fn write_text(&mut self, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        self.write_text_ch(0, timestamp_ms, text)
    }

    /// 写入文本日志（指定通道）
    pub fn write_text_ch(&mut self, channel: u8, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        let flag = (channel << CHANNEL_SHIFT) & CHANNEL_MASK;
        self.write_data_internal(timestamp_ms, text.as_bytes(), flag, false)
    }

    /// 写入压缩文本（适合大文本）
    pub fn write_text_compressed(&mut self, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        self.write_text_compressed_ch(0, timestamp_ms, text)
    }

    /// 写入压缩文本（指定通道）
    pub fn write_text_compressed_ch(
        &mut self,
        channel: u8,
        timestamp_ms: u64,
        text: &str,
    ) -> io::Result<u64> {
        let flag = (channel << CHANNEL_SHIFT) & CHANNEL_MASK;
        self.write_data_internal(timestamp_ms, text.as_bytes(), flag, true)
    }

    /// 写入二进制数据（默认通道0）
    pub fn write_binary(&mut self, timestamp_ms: u64, data: &[u8]) -> io::Result<u64> {
        self.write_binary_ch(0, timestamp_ms, data)
    }

    /// 写入二进制数据（指定通道）
    pub fn write_binary_ch(
        &mut self,
        channel: u8,
        timestamp_ms: u64,
        data: &[u8],
    ) -> io::Result<u64> {
        let flag = ((channel << CHANNEL_SHIFT) & CHANNEL_MASK) | FLAG_BINARY;
        self.write_data_internal(timestamp_ms, data, flag, false)
    }

    /// 写入压缩二进制数据
    pub fn write_binary_compressed(&mut self, timestamp_ms: u64, data: &[u8]) -> io::Result<u64> {
        self.write_binary_compressed_ch(0, timestamp_ms, data)
    }

    /// 写入压缩二进制数据（指定通道）
    pub fn write_binary_compressed_ch(
        &mut self,
        channel: u8,
        timestamp_ms: u64,
        data: &[u8],
    ) -> io::Result<u64> {
        let flag = ((channel << CHANNEL_SHIFT) & CHANNEL_MASK) | FLAG_BINARY;
        self.write_data_internal(timestamp_ms, data, flag, true)
    }

    /// 内部写入方法
    /// timestamp_ms: 毫秒时间戳
    fn write_data_internal(
        &mut self,
        timestamp_ms: u64,
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
            timestamp_ms,
            data: final_data,
        };

        self.write_entry(&entry)?;
        Ok(seq)
    }

    /// 写入条目
    fn write_entry(&mut self, entry: &StreamEntry) -> io::Result<()> {
        let serialized = entry.serialize();
        let entry_size = serialized.len() as u64;

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

            // 从头开始写
            write_pos = 0;
        }

        // 写入数据
        self.file.seek(SeekFrom::Start(HEADER_SIZE + write_pos))?;
        self.file.write_all(&serialized)?;

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

        // 扫描整个数据区寻找有效条目
        let data_size = self.header.max_size as usize;
        let mut data = vec![0u8; data_size];

        if self.file.seek(SeekFrom::Start(HEADER_SIZE)).is_err() {
            return (entries, 1);
        }
        if self.file.read_exact(&mut data).is_err() {
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
    fn save_header(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.header.write_to(&mut self.file)?;
        self.file.sync_data()
    }

    /// 同步到磁盘
    pub fn sync(&mut self) -> io::Result<()> {
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

/// 简化的写入器
pub struct StreamWriter {
    log: StreamLog,
}

impl StreamWriter {
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64) -> io::Result<Self> {
        let log = StreamLog::open(path, Some(max_size))?;
        Ok(Self { log })
    }

    pub fn write_text(&mut self, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        self.log.write_text(timestamp_ms, text)
    }

    /// 写入文本（指定通道）
    pub fn write_text_ch(&mut self, channel: u8, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        self.log.write_text_ch(channel, timestamp_ms, text)
    }

    /// 写入二进制数据（默认通道0）
    pub fn write_binary(&mut self, timestamp_ms: u64, data: &[u8]) -> io::Result<u64> {
        self.log.write_binary(timestamp_ms, data)
    }

    /// 写入二进制数据（指定通道）
    pub fn write_binary_ch(
        &mut self,
        channel: u8,
        timestamp_ms: u64,
        data: &[u8],
    ) -> io::Result<u64> {
        self.log.write_binary_ch(channel, timestamp_ms, data)
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
    rel_ts: u16,   // 相对时间戳 (ms)
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

    /// 写入二进制数据到缓冲区
    pub fn write_binary_ch(
        &mut self,
        channel: u8,
        timestamp_ms: u64,
        data: &[u8],
    ) -> io::Result<u64> {
        let ch = (channel & 0x0F) as usize;
        let buf = &mut self.channel_buffers[ch];

        // 如果缓冲区为空，记录基准时间戳
        if buf.0.is_none() {
            buf.0 = Some(timestamp_ms);
            buf.3 = true; // is_binary
        }

        let base_ts = buf.0.unwrap();
        // 计算相对时间戳，限制在 u16 范围内（最大 65535ms ≈ 65秒）
        let rel_ts = timestamp_ms.saturating_sub(base_ts).min(65535) as u16;

        buf.1.push(BlockRecord {
            rel_ts,
            data: data.to_vec(),
        });
        buf.2 += BLOCK_RECORD_HEADER_SIZE + data.len();

        // 检查是否需要刷新
        if buf.2 >= self.block_size_threshold || buf.1.len() >= self.max_records {
            self.flush_channel(channel)?;
        }

        Ok(0) // 块模式下序列号在刷新时分配
    }

    /// 写入文本数据到缓冲区
    pub fn write_text_ch(&mut self, channel: u8, timestamp_ms: u64, text: &str) -> io::Result<u64> {
        let ch = (channel & 0x0F) as usize;
        let buf = &mut self.channel_buffers[ch];

        // 如果缓冲区为空，记录基准时间戳
        if buf.0.is_none() {
            buf.0 = Some(timestamp_ms);
            buf.3 = false; // is_binary = false (text)
        }

        let base_ts = buf.0.unwrap();
        let rel_ts = timestamp_ms.saturating_sub(base_ts).min(65535) as u16;

        buf.1.push(BlockRecord {
            rel_ts,
            data: text.as_bytes().to_vec(),
        });
        buf.2 += BLOCK_RECORD_HEADER_SIZE + text.len();

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

        let base_ts = buf.0.unwrap();
        let is_binary = buf.3;

        // 构建块数据
        // 格式: [base_ts:8B][子记录1][子记录2]...
        let mut block_data = Vec::with_capacity(8 + buf.2);
        block_data.extend_from_slice(&base_ts.to_le_bytes());

        for record in buf.1.drain(..) {
            block_data.extend_from_slice(&record.rel_ts.to_le_bytes());
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

        let seq = self.log.header.global_seq;
        self.log.header.global_seq += 1;

        let entry = StreamEntry {
            sequence: seq,
            timestamp_ms: base_ts,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_stream_basic() {
        let path = "/tmp/test_stream_basic.dat";
        let _ = fs::remove_file(path);

        {
            let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

            for i in 0..100 {
                log.write_text(i * 100, &format!("Log message {}", i))
                    .unwrap();
            }

            log.sync().unwrap();

            let stats = log.stats();
            println!("{}", stats);
            assert!(stats.used_size > 0);
            assert_eq!(stats.global_seq, 100);
        }

        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();
            println!("Read {} entries", entries.len());
            assert_eq!(entries.len(), 100);
        }

        let _ = fs::remove_file(path);
    }

    /// 测试文本和二进制混合写入
    #[test]
    fn test_mixed_text_binary() {
        let path = "/tmp/test_mixed.dat";
        let _ = fs::remove_file(path);

        println!("\n=== 混合数据测试 ===");

        {
            let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

            // 模拟 ar_logcat 和 ar_logbin 交替写入
            for i in 0..10 {
                // 文本日志 (ar_logcat)
                let text = format!("[{}][INFO] Device status check #{}", i * 1000, i);
                log.write_text(i * 1000, &text).unwrap();

                // 二进制数据 (ar_logbin)
                let binary_data: Vec<u8> = vec![
                    0x12,
                    0x34,
                    0x56,
                    0x78,             // header
                    (i & 0xFF) as u8, // counter
                    0xAB,
                    0xCD,
                    0xEF, // data
                ];
                log.write_binary(i * 1000 + 500, &binary_data).unwrap();
            }

            log.sync().unwrap();
            println!("写入 10 条文本 + 10 条二进制");
        }

        // 重新打开读取
        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();

            println!("读取 {} 条记录", entries.len());
            assert_eq!(entries.len(), 20);

            let mut text_count = 0;
            let mut binary_count = 0;

            for entry in &entries {
                if entry.is_text() {
                    text_count += 1;
                    let text = entry.as_text().unwrap();
                    println!(
                        "  [TEXT  seq={:>2} ts={:>8}] {}",
                        entry.sequence, entry.timestamp_ms, text
                    );
                } else if entry.is_binary() {
                    binary_count += 1;
                    let data = entry.as_binary().unwrap();
                    println!(
                        "  [BINARY seq={:>2} ts={:>8}] {:02X?}",
                        entry.sequence, entry.timestamp_ms, data
                    );
                }
            }

            println!("\n文本: {} 条, 二进制: {} 条", text_count, binary_count);
            assert_eq!(text_count, 10);
            assert_eq!(binary_count, 10);

            // 验证按序列号排序后顺序正确（交替出现）
            for (i, entry) in entries.iter().enumerate() {
                assert_eq!(entry.sequence, i as u64);
                if i % 2 == 0 {
                    assert!(entry.is_text(), "偶数序列号应该是文本");
                } else {
                    assert!(entry.is_binary(), "奇数序列号应该是二进制");
                }
            }
            println!("✓ 顺序验证通过：文本和二进制交替出现");
        }

        println!("=== 混合数据测试通过 ===\n");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_stream_small_frequent() {
        let path = "/tmp/test_stream_small.dat";
        let _ = fs::remove_file(path);

        {
            let mut log = StreamLog::open(path, Some(4 * 1024)).unwrap(); // 只有 4KB

            // 模拟每 30 分钟写一条 100 字节
            for i in 0..50 {
                let msg = format!("Status OK at interval {}", i);
                log.write_text(i * 1800, &msg).unwrap();
                log.sync().unwrap(); // 每条都刷新
            }

            let stats = log.stats();
            println!("{}", stats);
        }

        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();
            println!("Stored {} entries in 4KB", entries.len());

            // 验证数据连续性
            for entry in &entries {
                let text = String::from_utf8_lossy(&entry.data[1..]); // 跳过压缩标记
                println!("  [{}] {}", entry.timestamp_ms, text);
            }
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_stream_wraparound() {
        let path = "/tmp/test_stream_wrap.dat";
        let _ = fs::remove_file(path);

        {
            let mut log = StreamLog::open(path, Some(1024)).unwrap(); // 只有 1KB

            // 写入超过 1KB 的数据，触发回绕
            for i in 0..100 {
                log.write_text(i * 100, &format!("Message number {}", i))
                    .unwrap();
            }

            log.sync().unwrap();
            let stats = log.stats();
            println!("After wraparound: {}", stats);
        }

        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();
            println!("After wraparound: {} entries readable", entries.len());

            // 只能读到最新的一部分
            assert!(entries.len() < 100);
            assert!(entries.len() > 0);
        }

        let _ = fs::remove_file(path);
    }

    /// 测试场景：80KB 空间写满 10 个 ~8KB 的块，然后写入一个 20KB 的块
    /// 验证回绕后的数据完整性和顺序
    #[test]
    fn test_stream_large_overwrite() {
        let path = "/tmp/test_stream_large_overwrite.dat";
        let _ = fs::remove_file(path);

        // 使用 80KB 数据区
        let data_size: u64 = 80 * 1024;

        {
            let mut log = StreamLog::open(path, Some(data_size)).unwrap();

            // 写入 10 个约 8KB 的条目 (实际数据 ~8KB - 24 字节开销)
            // 每个 entry: SYNC(2) + Len(2) + Seq(8) + TS_sec(4) + TS_ms(2) + Data(N) + CRC(4) + END(2) = 24 + N
            let block_data_size = 8 * 1024 - 24; // 约 8KB 每条

            println!("\n=== 写入 10 个 ~8KB 的条目 ===");
            for i in 0..10 {
                let data = format!("Block {} data: {}", i, "X".repeat(block_data_size - 20));
                log.write_text(i as u64 * 1000, &data).unwrap();
                println!("写入 Entry seq={}, 数据大小={} 字节", i, data.len());
            }
            log.sync().unwrap();

            let stats = log.stats();
            println!(
                "\n写满后状态: write_pos={}, global_seq={}",
                stats.write_pos, stats.global_seq
            );
            println!("预期: write_pos ≈ 80KB ({}), 已写满", 10 * 8 * 1024);

            // 验证写满了
            let entries_before = log.read_all().unwrap();
            println!("写满后可读条目: {} 条", entries_before.len());
            assert_eq!(entries_before.len(), 10);

            // 现在写入一个 20KB 的大块
            println!("\n=== 写入 1 个 ~20KB 的大条目 ===");
            let large_data_size = 20 * 1024 - 24;
            let large_data = format!("LARGE Block: {}", "Y".repeat(large_data_size - 15));
            log.write_text(99999u64, &large_data).unwrap();
            println!("写入 Entry seq=10, 数据大小={} 字节", large_data.len());
            log.sync().unwrap();

            let stats_after = log.stats();
            println!(
                "\n写入大块后状态: write_pos={}, global_seq={}",
                stats_after.write_pos, stats_after.global_seq
            );
        }

        // 重新打开读取
        {
            let mut log = StreamLog::open(path, None).unwrap();

            println!("\n=== 读取数据 ===");
            let (entries, skipped) = log.read_all_tolerant();

            println!(
                "可读取的条目数: {}, 跳过损坏: {} 次",
                entries.len(),
                skipped
            );
            println!("\n条目详情 (按文件位置顺序):");
            for (i, entry) in entries.iter().enumerate() {
                let preview: String = entry
                    .data
                    .iter()
                    .skip(1) // 跳过压缩标记
                    .take(50)
                    .map(|&b| b as char)
                    .collect();
                println!(
                    "  [{}] seq={:>2}, timestamp={:>8}, size={:>5} bytes, preview: {}...",
                    i,
                    entry.sequence,
                    entry.timestamp_ms,
                    entry.data.len(),
                    preview
                );
            }

            // 按序号排序
            let mut sorted = entries.clone();
            sorted.sort_by_key(|e| e.sequence);

            println!("\n按序号排序后:");
            for entry in &sorted {
                println!(
                    "  seq={:>2}, timestamp={:>8}",
                    entry.sequence, entry.timestamp_ms
                );
            }

            // 验证
            println!("\n=== 验证 ===");

            // 1. 新写入的大块应该存在 (seq=10)
            let has_new = entries.iter().any(|e| e.sequence == 10);
            println!("✓ 新写入的大块 (seq=10) 存在: {}", has_new);
            assert!(has_new, "新写入的大块应该存在");

            // 2. 最老的数据 (seq=0, seq=1) 应该被覆盖
            let has_old_0 = entries.iter().any(|e| e.sequence == 0);
            let has_old_1 = entries.iter().any(|e| e.sequence == 1);
            println!("✓ 最老数据 seq=0 被覆盖: {}", !has_old_0);
            println!("✓ 最老数据 seq=1 被覆盖: {}", !has_old_1);

            // 3. 部分被覆盖的数据不可读
            let has_partial = entries.iter().any(|e| e.sequence == 2);
            println!(
                "✓ 部分覆盖的 seq=2 状态: {}",
                if has_partial {
                    "仍可读"
                } else {
                    "已损坏"
                }
            );

            // 4. 后面的数据应该完整保留
            let preserved: Vec<u64> = (3..10)
                .filter(|&s| entries.iter().any(|e| e.sequence == s))
                .collect();
            println!("✓ 保留的旧数据: {:?}", preserved);

            // 5. 总结
            println!("\n=== 总结 ===");
            println!("原始 10 条 (seq 0-9) + 新增 1 条 (seq 10) = 11 条");
            println!("被覆盖: seq 0, 1 (可能还有 seq 2 部分损坏)");
            println!("实际可读: {} 条", entries.len());
            println!("丢失: {} 条", 11 - entries.len() - 1); // -1 是因为 seq=10 是新的
        }

        let _ = fs::remove_file(path);
    }

    /// 测试断电恢复：模拟写入数据后 header 未更新的情况
    #[test]
    fn test_power_loss_recovery() {
        use std::io::{Seek, Write};

        let path = "/tmp/test_power_loss.dat";
        let _ = fs::remove_file(path);

        println!("\n=== 断电恢复测试 ===");

        // 第一次写入：正常写入 5 条
        let write_pos_after_5;
        {
            let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

            for i in 0..5 {
                log.write_text(i * 100, &format!("Message {}", i)).unwrap();
            }
            log.sync().unwrap();

            write_pos_after_5 = log.stats().write_pos;
            println!("写入 5 条后 write_pos = {}", write_pos_after_5);
        }

        // 第二次写入：再写 3 条，但模拟断电（不调用 sync，手动破坏 header）
        {
            let mut log = StreamLog::open(path, None).unwrap();

            for i in 5..8 {
                log.write_text(i * 100, &format!("Message {}", i)).unwrap();
            }
            // 数据已经写入文件，但故意不 sync header
            // 模拟断电：手动把 header 的 write_pos 恢复到旧值

            let write_pos_after_8 = log.stats().write_pos;
            println!("写入 8 条后 write_pos = {}", write_pos_after_8);

            // 强制同步数据（但不更新 header）
            log.file.flush().unwrap();

            // 破坏 header：把 write_pos 改回 5 条时的值
            log.file.seek(SeekFrom::Start(0)).unwrap();
            let mut header_buf = [0u8; 64];
            log.file.read_exact(&mut header_buf).unwrap();

            // 修改 write_pos (offset 16-24)
            header_buf[16..24].copy_from_slice(&write_pos_after_5.to_le_bytes());
            // 修改 global_seq (offset 32-40) 回到 5
            header_buf[32..40].copy_from_slice(&5u64.to_le_bytes());

            log.file.seek(SeekFrom::Start(0)).unwrap();
            log.file.write_all(&header_buf).unwrap();
            log.file.flush().unwrap();

            println!("模拟断电：header.write_pos 被重置为 {}", write_pos_after_5);
        }

        // 第三次打开：应该扫描恢复到正确位置
        {
            let mut log = StreamLog::open(path, None).unwrap();

            let recovered_pos = log.stats().write_pos;
            let recovered_seq = log.stats().global_seq;
            println!(
                "恢复后 write_pos = {}, global_seq = {}",
                recovered_pos, recovered_seq
            );

            // 验证：应该能读到全部 8 条
            let entries = log.read_all().unwrap();
            println!("可读取条目: {} 条", entries.len());

            for entry in &entries {
                println!("  seq={}, ts={}", entry.sequence, entry.timestamp_ms);
            }

            assert_eq!(entries.len(), 8, "应该恢复全部 8 条日志");

            // 继续写入第 9 条，验证追加正确
            log.write_text(8000, "Message 8 after recovery").unwrap();
            log.sync().unwrap();

            let entries_after = log.read_all().unwrap();
            assert_eq!(entries_after.len(), 9, "应该有 9 条日志");
            println!("追加后共 {} 条", entries_after.len());
        }

        println!("=== 断电恢复测试通过 ===\n");
        let _ = fs::remove_file(path);
    }

    /// 测试回绕后断电恢复
    #[test]
    fn test_power_loss_after_wraparound() {
        use std::io::{Seek, Write};

        let path = "/tmp/test_power_loss_wrap.dat";
        let _ = fs::remove_file(path);

        println!("\n=== 回绕后断电恢复测试 ===");

        // 使用小文件触发回绕：1KB 数据区
        let data_size: u64 = 1024;

        // 第一阶段：写入直到回绕
        let write_pos_before_wrap;
        {
            let mut log = StreamLog::open(path, Some(data_size)).unwrap();

            // 每条约 50 字节，写入约 30 条会触发回绕
            for i in 0..30 {
                log.write_text(i * 100, &format!("Msg{:02}", i)).unwrap();
            }
            log.sync().unwrap();

            write_pos_before_wrap = log.stats().write_pos;
            println!(
                "写入 30 条后 write_pos = {} (已回绕)",
                write_pos_before_wrap
            );
        }

        // 第二阶段：继续写入，但模拟断电
        {
            let mut log = StreamLog::open(path, None).unwrap();

            let pos_on_open = log.stats().write_pos;
            println!("重新打开后 write_pos = {}", pos_on_open);

            // 再写 5 条
            for i in 30..35 {
                log.write_text(i * 100, &format!("Msg{:02}", i)).unwrap();
            }

            let write_pos_after_35 = log.stats().write_pos;
            println!("写入 35 条后 write_pos = {}", write_pos_after_35);

            // 模拟断电：数据写入但 header 未更新
            log.file.flush().unwrap();

            // 破坏 header：把 write_pos 改回之前的值
            log.file.seek(SeekFrom::Start(0)).unwrap();
            let mut header_buf = [0u8; 64];
            log.file.read_exact(&mut header_buf).unwrap();

            // 修改 write_pos 和 global_seq 回到 30 条时的值
            header_buf[16..24].copy_from_slice(&pos_on_open.to_le_bytes());
            header_buf[32..40].copy_from_slice(&31u64.to_le_bytes()); // boot 时 +1 变成 31

            log.file.seek(SeekFrom::Start(0)).unwrap();
            log.file.write_all(&header_buf).unwrap();
            log.file.flush().unwrap();

            println!("模拟断电：header.write_pos 被重置为 {}", pos_on_open);
        }

        // 第三阶段：恢复验证
        {
            let mut log = StreamLog::open(path, None).unwrap();

            let recovered_pos = log.stats().write_pos;
            let recovered_seq = log.stats().global_seq;
            println!(
                "恢复后 write_pos = {}, global_seq = {}",
                recovered_pos, recovered_seq
            );

            // 读取所有数据
            let entries = log.read_all().unwrap();
            println!("可读取条目: {} 条", entries.len());

            // 检查最大序列号
            let max_seq = entries.iter().map(|e| e.sequence).max().unwrap_or(0);
            println!("最大序列号: {}", max_seq);

            // 应该恢复到 35 条的序列号（34，因为从 0 开始）
            assert!(max_seq >= 34, "应该恢复到 seq=34，实际 max_seq={}", max_seq);

            // 继续写入验证追加正确
            log.write_text(99999, "After wrap recovery").unwrap();
            log.sync().unwrap();

            let seq_after = log.stats().global_seq;
            println!("追加后 global_seq = {}", seq_after);
            assert!(seq_after > max_seq, "追加后序列号应该增加");
        }

        println!("=== 回绕后断电恢复测试通过 ===\n");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_multi_channel() {
        let path = "/tmp/test_multi_channel.dat";
        let _ = fs::remove_file(path);

        println!("\n=== 多通道测试 ===");

        // 写入多通道数据
        {
            let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

            // 模拟多个数据源:
            // 通道 0: 主日志 (文本)
            // 通道 1: 调试日志 (文本)
            // 通道 2: 传感器数据 (二进制)
            // 通道 3: 网络包 (二进制)

            for i in 0..5 {
                let ts = i as u64 * 1000;

                // 通道 0: 主日志
                log.write_text_ch(0, ts, &format!("[主日志] 事件 {}", i))
                    .unwrap();

                // 通道 1: 调试日志
                log.write_text_ch(1, ts + 100, &format!("[调试] 详细信息 {}", i))
                    .unwrap();

                // 通道 2: 传感器二进制数据
                let sensor_data = vec![0x01, 0x02, i as u8, 0x04];
                log.write_binary_ch(2, ts + 200, &sensor_data).unwrap();

                // 通道 3: 网络包
                let packet = vec![0xAA, 0xBB, 0xCC, i as u8, 0xDD, 0xEE];
                log.write_binary_ch(3, ts + 300, &packet).unwrap();
            }

            log.sync().unwrap();
            println!("写入 5 轮 x 4 通道 = 20 条记录");
        }

        // 读取并验证
        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();

            assert_eq!(entries.len(), 20);
            println!("读取 {} 条记录", entries.len());

            // 按通道统计
            let mut channel_count = [0u32; 16];
            let mut text_channels = vec![];
            let mut binary_channels = vec![];

            for entry in &entries {
                let ch = entry.channel();
                channel_count[ch as usize] += 1;

                if entry.is_text() {
                    if !text_channels.contains(&ch) {
                        text_channels.push(ch);
                    }
                    let text = entry.as_text().unwrap();
                    println!(
                        "  [CH{} TEXT  seq={:>2} ts={:>8}] {}",
                        ch, entry.sequence, entry.timestamp_ms, text
                    );
                } else if entry.is_binary() {
                    if !binary_channels.contains(&ch) {
                        binary_channels.push(ch);
                    }
                    let data = entry.as_binary().unwrap();
                    println!(
                        "  [CH{} BIN   seq={:>2} ts={:>8}] {:02X?}",
                        ch, entry.sequence, entry.timestamp_ms, data
                    );
                }
            }

            println!("\n通道统计:");
            for ch in 0..4 {
                println!("  通道 {}: {} 条", ch, channel_count[ch]);
            }

            // 验证每个通道都有 5 条
            assert_eq!(channel_count[0], 5);
            assert_eq!(channel_count[1], 5);
            assert_eq!(channel_count[2], 5);
            assert_eq!(channel_count[3], 5);

            // 验证文本/二进制通道分类正确
            text_channels.sort();
            binary_channels.sort();
            println!("文本通道: {:?}", text_channels);
            println!("二进制通道: {:?}", binary_channels);

            assert_eq!(text_channels, vec![0, 1]);
            assert_eq!(binary_channels, vec![2, 3]);

            // 验证记录顺序
            for (i, entry) in entries.iter().enumerate() {
                assert_eq!(entry.sequence, i as u64);
                let expected_ch = (i % 4) as u8;
                assert_eq!(
                    entry.channel(),
                    expected_ch,
                    "序列 {} 应该是通道 {}",
                    i,
                    expected_ch
                );
            }
            println!("✓ 通道顺序验证通过");
        }

        println!("=== 多通道测试通过 ===\n");
        let _ = fs::remove_file(path);
    }

    /// 测试块压缩写入和读取
    #[test]
    fn test_block_writer() {
        let path = "/tmp/test_block_writer.dat";
        let _ = fs::remove_file(path);

        println!("\n=== 块压缩测试 ===");

        // 写入重复日志
        let original_lines: Vec<String> = (0..100)
            .map(|i| format!("[INFO] This is a repeated log message #{}", i))
            .collect();

        {
            // 使用较小的阈值便于测试
            let mut writer = BlockWriter::with_threshold(path, 64 * 1024, 1024, 50).unwrap();

            for (i, line) in original_lines.iter().enumerate() {
                let ts = 1000000 + i as u64 * 10; // 每 10ms 一条
                writer.write_binary_ch(0, ts, line.as_bytes()).unwrap();
            }

            writer.sync().unwrap();

            let stats = writer.stats();
            println!("块写入统计: {:?}", stats);
            println!("  写入位置: {} bytes", stats.write_pos);
        }

        // 读取并验证
        {
            let mut log = StreamLog::open(path, None).unwrap();
            let entries = log.read_all().unwrap();

            println!("读取到 {} 个条目", entries.len());

            let mut recovered_lines: Vec<(u64, String)> = Vec::new();

            for entry in &entries {
                if entry.is_block() {
                    println!(
                        "  块条目: seq={}, ts={}, 压缩={}",
                        entry.sequence,
                        entry.timestamp_ms,
                        entry.is_compressed()
                    );

                    if let Some(records) = entry.unpack_block() {
                        println!("    解包出 {} 条子记录", records.len());
                        for (ts, data) in records {
                            let text = String::from_utf8_lossy(&data).to_string();
                            recovered_lines.push((ts, text));
                        }
                    }
                } else {
                    println!(
                        "  普通条目: seq={}, ts={}",
                        entry.sequence, entry.timestamp_ms
                    );
                    if let Some(data) = entry.as_binary() {
                        let text = String::from_utf8_lossy(&data).to_string();
                        recovered_lines.push((entry.timestamp_ms, text));
                    }
                }
            }

            println!("恢复出 {} 行日志", recovered_lines.len());
            assert_eq!(recovered_lines.len(), original_lines.len());

            // 验证内容
            for (i, (ts, text)) in recovered_lines.iter().enumerate() {
                assert_eq!(text, &original_lines[i], "第 {} 行内容不匹配", i);
                let expected_ts = 1000000 + i as u64 * 10;
                assert_eq!(*ts, expected_ts, "第 {} 行时间戳不匹配", i);
            }
            println!("✓ 内容验证通过");
        }

        // 对比压缩效果
        {
            let path_no_block = "/tmp/test_no_block.dat";
            let _ = fs::remove_file(path_no_block);

            let mut writer = StreamWriter::new(path_no_block, 64 * 1024).unwrap();
            for (i, line) in original_lines.iter().enumerate() {
                let ts = 1000000 + i as u64 * 10;
                writer.write_binary_ch(0, ts, line.as_bytes()).unwrap();
            }
            writer.sync().unwrap();

            let stats_no_block = writer.stats();
            let stats_block = StreamLog::open(path, None).unwrap().stats();

            println!("\n压缩效果对比:");
            println!("  无块压缩: {} bytes", stats_no_block.write_pos);
            println!("  有块压缩: {} bytes", stats_block.write_pos);
            println!(
                "  压缩比: {:.1}%",
                stats_block.write_pos as f64 / stats_no_block.write_pos as f64 * 100.0
            );

            // 块压缩应该更小
            assert!(
                stats_block.write_pos < stats_no_block.write_pos,
                "块压缩应该比无压缩更小"
            );

            let _ = fs::remove_file(path_no_block);
        }

        println!("=== 块压缩测试通过 ===\n");
        let _ = fs::remove_file(path);
    }
}
