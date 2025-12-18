//! 文件头结构
//!
//! 流式循环日志存储的文件头定义

use std::io::{self, Read, Write};

use crate::constants::{FILE_MAGIC, VERSION};

/// 文件头
#[derive(Debug, Clone)]
pub struct StreamHeader {
    pub magic: u32,
    pub version: u32,
    pub max_size: u64,      // 数据区最大大小
    pub write_pos: u64,     // 当前写入位置（相对于数据区）
    pub read_pos: u64,      // 最旧有效数据位置
    pub global_seq: u64,    // 全局序列号
    pub boot_count: u32,    // 启动次数
    pub flags: u32,         // 标志位
    pub reserved: [u8; 16], // 保留
}

impl StreamHeader {
    pub fn new(max_size: u64) -> Self {
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

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
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

    pub fn is_valid(&self) -> bool {
        self.magic == FILE_MAGIC && self.version == VERSION
    }
}
