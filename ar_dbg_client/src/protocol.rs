//! 寄存器跟踪协议 (reg_trace protocol)
//!
//! 协议结构：
//! ```text
//! struct reg_trace_msg {
//!     magic[2]: [u8; 2],    // 0xBB 0xAC
//!     version: u8,          // 协议版本
//!     cmd_id: u8,           // 命令ID
//!     seq_num: u16,         // 序列号 (小端)
//!     payload_len: u16,     // 负载长度 (小端)
//!     payload: [u8],        // 负载数据
//! }
//! ```

use bytes::{Buf, BytesMut};
use std::io;
use thiserror::Error;

/// 协议魔数
pub const HEADER_MAGIC_0: u8 = 0xBB;
pub const HEADER_MAGIC_1: u8 = 0xAC;

/// 协议版本
pub const PROTOCOL_VERSION: u8 = 0x01;

/// 协议头长度 (8字节)
pub const HEADER_SIZE: usize = 8;

/// 默认端口
pub const DEFAULT_PORT: u16 = 12345;

/// 最大配置项数量
/// 最大配置项数量 (与服务端 REG_TRACE_MAX_ITEMS 保持一致)
pub const MAX_ITEMS: usize = 64;

/// 单个配置项最大宽度 (共享内存端限制)
pub const MAX_ITEM_WIDTH: usize = 32;

/// 单条记录最大数据长度
pub const MAX_RECORD_DATA: usize = MAX_ITEMS * MAX_ITEM_WIDTH;

/// 最大批量记录数 - 需要能一次发完整个buffer
pub const MAX_BATCH_RECORDS: usize = 500;

/// 默认缓冲深度
pub const DEFAULT_BUFFER_DEPTH: u16 = 100;

/// 记录头大小 (不含data): timestamp_us(8) + seq_id(4) + irq_type(2) + data_len(2) + valid_mask(8)
pub const RECORD_HEADER_SIZE: usize = 24;

/// TCP 命令 ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmdId {
    Config = 0xB0,   // 配置抓取项（配置后自动推送）
    Stop = 0xB2,     // 停止采集
    Status = 0xB3,   // 查询状态
    ShmInfo = 0xB6,  // 获取共享内存信息
    Version = 0xB8,  // 获取版本信息
    Ping = 0xB9,     // 心跳检测
    DataPush = 0xBA, // 服务端主动推送数据
}

impl From<u8> for CmdId {
    fn from(v: u8) -> Self {
        match v {
            0xB0 => CmdId::Config,
            0xB2 => CmdId::Stop,
            0xB3 => CmdId::Status,
            0xB6 => CmdId::ShmInfo,
            0xB8 => CmdId::Version,
            0xB9 => CmdId::Ping,
            0xBA => CmdId::DataPush,
            _ => CmdId::Ping, // 默认
        }
    }
}

/// 错误码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum ErrorCode {
    Ok = 0,
    InvalidCmd = -1,
    InvalidParam = -2,
    Busy = -3,
    NotStarted = -4,
    BufferEmpty = -5,
    NoConfig = -6,
    CommFail = -7,
    TooManyItems = -8, // 合并后配置项超过 RPC 限制(62个)
}

impl From<i8> for ErrorCode {
    fn from(v: i8) -> Self {
        match v {
            0 => ErrorCode::Ok,
            -1 => ErrorCode::InvalidCmd,
            -2 => ErrorCode::InvalidParam,
            -3 => ErrorCode::Busy,
            -4 => ErrorCode::NotStarted,
            -5 => ErrorCode::BufferEmpty,
            -6 => ErrorCode::NoConfig,
            -7 => ErrorCode::CommFail,
            -8 => ErrorCode::TooManyItems,
            _ => ErrorCode::InvalidCmd,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Ok => write!(f, "OK"),
            ErrorCode::InvalidCmd => write!(f, "INVALID_CMD"),
            ErrorCode::InvalidParam => write!(f, "INVALID_PARAM"),
            ErrorCode::Busy => write!(f, "BUSY"),
            ErrorCode::NotStarted => write!(f, "NOT_STARTED"),
            ErrorCode::BufferEmpty => write!(f, "BUFFER_EMPTY"),
            ErrorCode::NoConfig => write!(f, "NO_CONFIG"),
            ErrorCode::CommFail => write!(f, "COMM_FAIL"),
            ErrorCode::TooManyItems => write!(f, "TOO_MANY_ITEMS"),
        }
    }
}

/// 寄存器宽度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegWidth {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
}

impl From<u8> for RegWidth {
    fn from(v: u8) -> Self {
        match v {
            1 => RegWidth::Bit8,
            2 => RegWidth::Bit16,
            4 => RegWidth::Bit32,
            _ => RegWidth::Bit8,
        }
    }
}

/// 协议错误
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("incomplete message: need {need} bytes, got {got}")]
    IncompleteMessage { need: usize, got: usize },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("server error: {0}")]
    ServerError(ErrorCode),
}

/// 消息头
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub version: u8,
    pub cmd_id: CmdId,
    pub seq_num: u16,
    pub payload_len: u16,
}

/// 完整消息
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

impl Message {
    /// 创建新消息
    pub fn new(cmd_id: CmdId, seq_num: u16, payload: Vec<u8>) -> Self {
        Message {
            header: MessageHeader {
                version: PROTOCOL_VERSION,
                cmd_id,
                seq_num,
                payload_len: payload.len() as u16,
            },
            payload,
        }
    }

    /// 编码消息为字节
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        buf.push(HEADER_MAGIC_0);
        buf.push(HEADER_MAGIC_1);
        buf.push(self.header.version);
        buf.push(self.header.cmd_id as u8);
        buf.extend_from_slice(&self.header.seq_num.to_le_bytes());
        buf.extend_from_slice(&self.header.payload_len.to_le_bytes());

        buf.extend_from_slice(&self.payload);

        buf
    }

    /// 从字节解码消息
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Message>, ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        // 检查魔数
        if buf[0] != HEADER_MAGIC_0 || buf[1] != HEADER_MAGIC_1 {
            return Err(ProtocolError::InvalidMagic);
        }

        // 解析 payload_len
        let payload_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;

        // 检查是否有足够的数据
        let total_len = HEADER_SIZE + payload_len;
        if buf.len() < total_len {
            return Ok(None);
        }

        // 解析头部
        let header = MessageHeader {
            version: buf[2],
            cmd_id: CmdId::from(buf[3]),
            seq_num: u16::from_le_bytes([buf[4], buf[5]]),
            payload_len: payload_len as u16,
        };

        // 提取 payload
        let payload = buf[HEADER_SIZE..total_len].to_vec();

        // 消费已解析的数据
        buf.advance(total_len);

        Ok(Some(Message { header, payload }))
    }
}

/// 单个寄存器抓取项配置
#[derive(Debug, Clone, Copy, Default)]
pub struct RegTraceItem {
    /// 寄存器页号 (0-5)
    pub page: u8,
    /// 页内偏移地址
    pub offset: u8,
    /// 读取宽度: 1/2/4 字节
    pub width: u8,
    /// 中断触发掩码 (见 IrqType)
    pub irq_mask: u16,
}

impl RegTraceItem {
    pub fn new(page: u8, offset: u8, width: u8) -> Self {
        Self {
            page,
            offset,
            width,
            irq_mask: 0xFFFF, // 默认所有中断
        }
    }

    /// 创建带中断掩码的配置项
    pub fn with_irq_mask(page: u8, offset: u8, width: u8, irq_mask: u16) -> Self {
        Self {
            page,
            offset,
            width,
            irq_mask,
        }
    }

    /// 编码为字节 (8字节: page, offset, width, reserved, irq_mask[2], reserved2[2])
    pub fn encode(&self) -> [u8; 8] {
        let irq_bytes = self.irq_mask.to_le_bytes();
        [
            self.page,
            self.offset,
            self.width,
            0, // reserved
            irq_bytes[0],
            irq_bytes[1],
            0, // reserved2[0]
            0, // reserved2[1]
        ]
    }
}

/// 中断类型掩码常量
pub mod irq_type {
    pub const RX_BR_END: u16 = 0x0001;
    pub const TX_BR_END: u16 = 0x0002;
    pub const CSMA_START_ENC: u16 = 0x0004;
    pub const FSM_STATE_CHG: u16 = 0x0008;
    pub const FSM_TRX: u16 = 0x0010;
    pub const SLOT_SOP: u16 = 0x0020;
    pub const TX_PRE_ENC: u16 = 0x0040;
    pub const RX_RDOUT: u16 = 0x0080;
    pub const FCH_DEC: u16 = 0x0100;
    pub const FREQ_SWEEP: u16 = 0x0200;
    pub const ALL: u16 = 0xFFFF;

    /// 将中断类型掩码值转换为名称（原有函数，基于掩码值）
    pub fn irq_name(irq_type: u16) -> &'static str {
        match irq_type {
            0x0001 => "RX_BR_END",
            0x0002 => "TX_BR_END",
            0x0004 => "CSMA_START_ENC",
            0x0008 => "FSM_STATE_CHG",
            0x0010 => "FSM_TRX",
            0x0020 => "SLOT_SOP",
            0x0040 => "TX_PRE_ENC",
            0x0080 => "RX_RDOUT",
            0x0100 => "FCH_DEC",
            0x0200 => "FREQ_SWEEP",
            _ => "UNKNOWN",
        }
    }

    /// 将中断类型索引转换为名称（与 Python IRQ_TYPE_NAMES 对应）
    /// irq_type 值为服务端返回的中断类型索引
    pub fn irq_index_name(irq_type: u16) -> &'static str {
        match irq_type {
            0 => "UNKNOWN",
            1 => "RX_BR_END",
            2 => "TX_BR_END",
            3 => "CSMA_START_ENC",
            4 => "FSM_STATE_CHG",
            5 => "FSM_TRX",
            6 => "SLOT_SOP",
            7 => "TX_PRE_ENC",
            8 => "RX_RDOUT",
            9 => "FCH_DEC",
            10 => "FREQ_SWEEP",
            0xFF => "MANUAL",
            _ => "UNKNOWN",
        }
    }
}

/// 配置命令
#[derive(Debug, Clone)]
pub struct ConfigRequest {
    pub items: Vec<RegTraceItem>,
    pub sample_div: u8,
    pub buffer_depth: u16,
}

impl Default for ConfigRequest {
    fn default() -> Self {
        // 默认配置：第一页的前几个寄存器
        Self {
            items: vec![
                RegTraceItem::new(0, 0x00, 4), // 页0，偏移0，4字节
                RegTraceItem::new(0, 0x04, 4), // 页0，偏移4，4字节
                RegTraceItem::new(0, 0x08, 4), // 页0，偏移8，4字节
                RegTraceItem::new(0, 0x0C, 4), // 页0，偏移12，4字节
            ],
            sample_div: 1,
            buffer_depth: DEFAULT_BUFFER_DEPTH,
        }
    }
}

impl ConfigRequest {
    /// 创建新的配置请求
    pub fn new(items: Vec<RegTraceItem>, sample_div: u8, buffer_depth: u16) -> Self {
        Self {
            items,
            sample_div,
            buffer_depth,
        }
    }

    /// 创建配置请求并自动拆分超过 MAX_ITEM_WIDTH 的配置项
    /// 与 Python 的 config() 方法逻辑一致
    pub fn with_auto_split(
        items: Vec<RegTraceItem>,
        sample_div: u8,
        buffer_depth: u16,
    ) -> Result<Self, ProtocolError> {
        let mut split_items = Vec::new();

        for item in items {
            let mut offset = item.offset;
            let mut remaining_width = item.width as usize;

            // 自动拆分超过 MAX_ITEM_WIDTH 的配置
            while remaining_width > MAX_ITEM_WIDTH {
                split_items.push(RegTraceItem::with_irq_mask(
                    item.page,
                    offset,
                    MAX_ITEM_WIDTH as u8,
                    item.irq_mask,
                ));
                offset = offset.wrapping_add(MAX_ITEM_WIDTH as u8);
                remaining_width -= MAX_ITEM_WIDTH;
            }
            if remaining_width > 0 {
                split_items.push(RegTraceItem::with_irq_mask(
                    item.page,
                    offset,
                    remaining_width as u8,
                    item.irq_mask,
                ));
            }
        }

        if split_items.len() > MAX_ITEMS {
            return Err(ProtocolError::ServerError(ErrorCode::TooManyItems));
        }

        Ok(Self {
            items: split_items,
            sample_div,
            buffer_depth,
        })
    }

    /// 编码为消息 payload
    /// 格式: item_count(1) + sample_div(1) + buffer_depth(2) + reserved(4) + items(64*8)
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(8 + MAX_ITEMS * 8);

        payload.push(self.items.len() as u8);
        payload.push(self.sample_div);
        payload.extend_from_slice(&self.buffer_depth.to_le_bytes());
        payload.extend_from_slice(&[0u8; 4]); // reserved

        // 填充到16项 (每项8字节)
        for i in 0..MAX_ITEMS {
            if i < self.items.len() {
                payload.extend_from_slice(&self.items[i].encode());
            } else {
                payload.extend_from_slice(&[0u8; 8]);
            }
        }

        payload
    }
}

/// 配置响应
#[derive(Debug, Clone)]
pub struct ConfigResponse {
    pub result: ErrorCode,
    pub actual_items: u8,
    pub actual_sample_div: u8,
    pub actual_buffer_depth: u16,
}

impl ConfigResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            actual_items: data[4],
            actual_sample_div: data[5],
            actual_buffer_depth: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

/// 通用响应 (用于 stop)
#[derive(Debug, Clone)]
pub struct GenericResponse {
    pub result: ErrorCode,
}

impl GenericResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
        })
    }
}

/// 状态响应
#[derive(Debug, Clone)]
pub struct StatusResponse {
    pub result: ErrorCode,
    pub is_running: bool,
    pub item_count: u8,
    pub buffer_depth: u16,
    /// 中断触发掩码 (新增)
    pub irq_trigger_mask: u16,
    pub record_count: u16,
    pub overflow_count: u16,
    pub total_samples: u32,
}

impl StatusResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            // data[1..4] reserved
            is_running: data[4] != 0,
            item_count: data[5],
            buffer_depth: u16::from_le_bytes([data[6], data[7]]),
            irq_trigger_mask: u16::from_le_bytes([data[8], data[9]]),
            record_count: u16::from_le_bytes([data[10], data[11]]),
            overflow_count: u16::from_le_bytes([data[12], data[13]]),
            // data[14..16] reserved
            total_samples: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }
}

/// 单条采集记录 (新格式：变长、稀疏)
#[derive(Debug, Clone)]
pub struct TraceRecord {
    /// 时间戳(微秒) - 64位不回绕
    pub timestamp_us: u64,
    /// 记录序列号
    pub seq_id: u32,
    /// 触发该记录的中断类型 (irq_type_e)
    pub irq_type: u16,
    /// 有效配置项位图: bit[i]=1 表示 item[i] 数据有效 (64位支持64个配置项)
    pub valid_mask: u64,
    /// 原始数据 (紧凑排列，按 valid_mask 中置位的配置项顺序)
    pub raw_data: Vec<u8>,
    /// 解析后的值 (兼容旧接口，按 u32 解析)
    pub values: Vec<u32>,
}

impl std::fmt::Display for TraceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let values_str: Vec<String> = self.values.iter().map(|v| format!("0x{:08X}", v)).collect();
        write!(
            f,
            "[{:5}] ts={:12}us irq={:<14} mask=0x{:016X}: {}",
            self.seq_id,
            self.timestamp_us,
            irq_type::irq_index_name(self.irq_type),
            self.valid_mask,
            values_str.join(", ")
        )
    }
}

/// 数据推送响应 (服务端主动推送，格式：变长记录)
#[derive(Debug, Clone)]
pub struct DataPushResponse {
    pub result: ErrorCode,
    pub record_count: u8,
    pub item_count: u8,
    pub remaining_count: u16,
    pub records: Vec<TraceRecord>,
}

impl DataPushResponse {
    /// 从 payload 解析响应 (变长格式)
    ///
    /// 响应头格式 (8字节):
    ///   result(1) + reserved(3) + record_count(1) + item_count(1) + remaining_count(2)
    ///
    /// 每条记录格式 (变长):
    ///   timestamp_us(8) + seq_id(4) + irq_type(2) + data_len(2) + valid_mask(8) + data[data_len]
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let result = ErrorCode::from(data[0] as i8);
        // data[1..4] reserved
        let record_count = data[4];
        let item_count = data[5];
        let remaining_count = u16::from_le_bytes([data[6], data[7]]);

        let mut records = Vec::new();
        let mut offset = 8; // 响应头大小

        for _ in 0..record_count {
            // 检查记录头是否完整 (18字节)
            if offset + RECORD_HEADER_SIZE > data.len() {
                break;
            }

            // 解析记录头
            let timestamp_us = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let seq_id = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            let irq_type = u16::from_le_bytes([data[offset + 12], data[offset + 13]]);
            let data_len = u16::from_le_bytes([data[offset + 14], data[offset + 15]]) as usize;
            let valid_mask = u64::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
                data[offset + 20],
                data[offset + 21],
                data[offset + 22],
                data[offset + 23],
            ]);

            offset += RECORD_HEADER_SIZE;

            // 检查数据区是否完整
            if offset + data_len > data.len() {
                break;
            }

            // 提取原始数据
            let raw_data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            // 按 u32 解析值 (兼容旧接口，每4字节一个值)
            let mut values = Vec::new();
            let mut v_offset = 0;
            while v_offset + 4 <= raw_data.len() {
                values.push(u32::from_le_bytes([
                    raw_data[v_offset],
                    raw_data[v_offset + 1],
                    raw_data[v_offset + 2],
                    raw_data[v_offset + 3],
                ]));
                v_offset += 4;
            }

            records.push(TraceRecord {
                timestamp_us,
                seq_id,
                irq_type,
                valid_mask,
                raw_data,
                values,
            });
        }

        Some(Self {
            result,
            record_count,
            item_count,
            remaining_count,
            records,
        })
    }
}

/// 版本响应
#[derive(Debug, Clone)]
pub struct VersionResponse {
    pub result: ErrorCode,
    pub protocol_version: u8,
    pub fw_version_major: u8,
    pub fw_version_minor: u8,
    pub fw_version_patch: u8,
    pub build_timestamp: u32,
}

impl VersionResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            protocol_version: data[4],
            fw_version_major: data[5],
            fw_version_minor: data[6],
            fw_version_patch: data[7],
            build_timestamp: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// 心跳响应
#[derive(Debug, Clone)]
pub struct PingResponse {
    pub result: ErrorCode,
    pub uptime_sec: u32,
    pub fw_timestamp_us: u32,
}

impl PingResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            uptime_sec: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            fw_timestamp_us: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// 共享内存信息响应
#[derive(Debug, Clone)]
pub struct ShmInfoResponse {
    pub result: ErrorCode,
    /// 共享内存物理地址
    pub shm_pa: u32,
    /// 共享内存总大小
    pub shm_size: u32,
    /// 控制块偏移
    pub ctrl_offset: u32,
    /// 数据区偏移
    pub data_offset: u32,
}

impl ShmInfoResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            // data[1..4] reserved
            shm_pa: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            shm_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            ctrl_offset: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            data_offset: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }
}

/// 创建 Ping 消息
pub fn create_ping_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Ping, seq_num, vec![])
}

/// 创建获取版本消息
pub fn create_version_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Version, seq_num, vec![])
}

/// 创建获取共享内存信息消息
pub fn create_shm_info_msg(seq_num: u16) -> Message {
    Message::new(CmdId::ShmInfo, seq_num, vec![])
}

/// 创建配置消息
pub fn create_config_msg(seq_num: u16, config: &ConfigRequest) -> Message {
    Message::new(CmdId::Config, seq_num, config.encode())
}

/// 创建停止消息
pub fn create_stop_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Stop, seq_num, vec![])
}

/// 创建状态查询消息
pub fn create_status_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Status, seq_num, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let msg = create_ping_msg(1);
        let encoded = msg.encode();

        assert_eq!(encoded[0], HEADER_MAGIC_0);
        assert_eq!(encoded[1], HEADER_MAGIC_1);
        assert_eq!(encoded[2], PROTOCOL_VERSION);
        assert_eq!(encoded[3], CmdId::Ping as u8);

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = Message::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.header.cmd_id, CmdId::Ping);
        assert_eq!(decoded.header.seq_num, 1);
    }

    #[test]
    fn test_config_encode() {
        let config = ConfigRequest::default();
        let payload = config.encode();

        // item_count(1) + sample_div(1) + buffer_depth(2) + reserved(4) + items(16*8)
        assert_eq!(payload.len(), 8 + MAX_ITEMS * 8);
        assert_eq!(payload[0], 4); // 4 items by default
        assert_eq!(payload[1], 1); // sample_div = 1
    }
}
