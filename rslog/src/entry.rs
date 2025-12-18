//! 日志条目结构
//!
//! 流式循环日志存储的条目定义和序列化/反序列化

use crc32fast::Hasher;

use crate::constants::{
    BLOCK_RECORD_HEADER_SIZE, CHANNEL_MASK, CHANNEL_SHIFT, END_MAGIC, ENTRY_HEADER_SIZE,
    ENTRY_OVERHEAD, FLAG_BINARY, FLAG_BLOCK, FLAG_COMPRESSED, SYNC_MAGIC,
};

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
    pub fn total_size(&self) -> usize {
        ENTRY_OVERHEAD + self.data.len()
    }

    /// 序列化到字节
    pub fn serialize(&self) -> Vec<u8> {
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
    pub fn deserialize(data: &[u8]) -> Option<(Self, usize)> {
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
        let entry_data = data[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + len].to_vec();

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
