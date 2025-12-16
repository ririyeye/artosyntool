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
pub const MAX_ITEMS: usize = 16;

/// 最大批量记录数
pub const MAX_BATCH_RECORDS: usize = 50;

/// 默认缓冲深度
pub const DEFAULT_BUFFER_DEPTH: u16 = 100;

/// TCP 命令 ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmdId {
    Config = 0xB0,      // 配置抓取项
    Start = 0xB1,       // 启动抓取
    Stop = 0xB2,        // 停止抓取
    QueryStatus = 0xB3, // 查询缓冲区状态
    FetchData = 0xB4,   // 拉取数据
    ClearBuffer = 0xB5, // 清空缓冲区
    GetVersion = 0xB8,  // 获取版本信息
    Ping = 0xB9,        // 心跳检测
}

impl From<u8> for CmdId {
    fn from(v: u8) -> Self {
        match v {
            0xB0 => CmdId::Config,
            0xB1 => CmdId::Start,
            0xB2 => CmdId::Stop,
            0xB3 => CmdId::QueryStatus,
            0xB4 => CmdId::FetchData,
            0xB5 => CmdId::ClearBuffer,
            0xB8 => CmdId::GetVersion,
            0xB9 => CmdId::Ping,
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

    /// 编码为字节 (5字节: page, offset, width, irq_mask_lo, irq_mask_hi)
    pub fn encode(&self) -> [u8; 5] {
        let irq_bytes = self.irq_mask.to_le_bytes();
        [
            self.page,
            self.offset,
            self.width,
            irq_bytes[0],
            irq_bytes[1],
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

    /// 将中断类型值转换为名称
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
    /// 编码为消息 payload
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(4 + MAX_ITEMS * 5);

        payload.push(self.items.len() as u8);
        payload.push(self.sample_div);
        payload.extend_from_slice(&self.buffer_depth.to_le_bytes());

        // 填充到16项 (每项5字节)
        for i in 0..MAX_ITEMS {
            if i < self.items.len() {
                payload.extend_from_slice(&self.items[i].encode());
            } else {
                payload.extend_from_slice(&[0u8; 5]);
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

/// 启动请求
#[derive(Debug, Clone)]
pub struct StartRequest {
    /// bit0: 清空已有数据
    pub clear_buffer: bool,
}

impl Default for StartRequest {
    fn default() -> Self {
        Self { clear_buffer: true }
    }
}

impl StartRequest {
    pub fn encode(&self) -> Vec<u8> {
        vec![if self.clear_buffer { 0x01 } else { 0x00 }, 0, 0, 0]
    }
}

/// 通用响应 (用于 start/stop/clear)
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
    pub record_count: u16,
    pub overflow_count: u16,
    pub total_samples: u32,
}

impl StatusResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self {
            result: ErrorCode::from(data[0] as i8),
            is_running: data[4] != 0,
            item_count: data[5],
            buffer_depth: u16::from_le_bytes([data[6], data[7]]),
            record_count: u16::from_le_bytes([data[8], data[9]]),
            overflow_count: u16::from_le_bytes([data[10], data[11]]),
            total_samples: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

/// 拉取数据请求
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub max_records: u8,
    /// bit0: 拉取后清除
    pub clear_after_read: bool,
}

impl Default for FetchRequest {
    fn default() -> Self {
        Self {
            max_records: 10,
            clear_after_read: true,
        }
    }
}

impl FetchRequest {
    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.max_records,
            if self.clear_after_read { 0x01 } else { 0x00 },
            0,
            0,
        ]
    }
}

/// 单条采集记录
#[derive(Debug, Clone)]
pub struct TraceRecord {
    pub timestamp_us: u32,
    pub seq_id: u32,
    /// 触发该记录的中断类型
    pub irq_type: u32,
    pub values: Vec<u32>,
}

impl std::fmt::Display for TraceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let values_str: Vec<String> = self.values.iter().map(|v| format!("0x{:08X}", v)).collect();
        write!(
            f,
            "[{:5}] ts={:10}us irq={}: {}",
            self.seq_id,
            self.timestamp_us,
            irq_type::irq_name(self.irq_type as u16),
            values_str.join(", ")
        )
    }
}

/// 拉取数据响应
#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub result: ErrorCode,
    pub record_count: u8,
    pub item_count: u8,
    pub remaining_count: u16,
    pub records: Vec<TraceRecord>,
}

impl FetchResponse {
    pub fn from_payload(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let result = ErrorCode::from(data[0] as i8);
        let record_count = data[1];
        let item_count = data[2];
        let remaining_count = u16::from_le_bytes([data[3], data[4]]);

        let mut records = Vec::new();
        // 每条记录: ts(4) + seq_id(4) + irq_type(4) + values(item_count * 4)
        let record_size = 12 + 4 * item_count as usize;
        let mut offset = 5;

        for _ in 0..record_count {
            if offset + record_size > data.len() {
                break;
            }

            let timestamp_us = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let seq_id = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let irq_type = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);

            let mut values = Vec::new();
            for i in 0..item_count as usize {
                let v_offset = offset + 12 + i * 4;
                if v_offset + 4 <= data.len() {
                    values.push(u32::from_le_bytes([
                        data[v_offset],
                        data[v_offset + 1],
                        data[v_offset + 2],
                        data[v_offset + 3],
                    ]));
                }
            }

            records.push(TraceRecord {
                timestamp_us,
                seq_id,
                irq_type,
                values,
            });
            offset += record_size;
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

/// 创建 Ping 消息
pub fn create_ping_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Ping, seq_num, vec![])
}

/// 创建获取版本消息
pub fn create_version_msg(seq_num: u16) -> Message {
    Message::new(CmdId::GetVersion, seq_num, vec![])
}

/// 创建配置消息
pub fn create_config_msg(seq_num: u16, config: &ConfigRequest) -> Message {
    Message::new(CmdId::Config, seq_num, config.encode())
}

/// 创建启动消息
pub fn create_start_msg(seq_num: u16, clear_buffer: bool) -> Message {
    let req = StartRequest { clear_buffer };
    Message::new(CmdId::Start, seq_num, req.encode())
}

/// 创建停止消息
pub fn create_stop_msg(seq_num: u16) -> Message {
    Message::new(CmdId::Stop, seq_num, vec![])
}

/// 创建状态查询消息
pub fn create_status_msg(seq_num: u16) -> Message {
    Message::new(CmdId::QueryStatus, seq_num, vec![])
}

/// 创建拉取数据消息
pub fn create_fetch_msg(seq_num: u16, max_records: u8, clear_after_read: bool) -> Message {
    let req = FetchRequest {
        max_records,
        clear_after_read,
    };
    Message::new(CmdId::FetchData, seq_num, req.encode())
}

/// 创建清空缓冲消息
pub fn create_clear_msg(seq_num: u16) -> Message {
    Message::new(CmdId::ClearBuffer, seq_num, vec![])
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

        // item_count(1) + sample_div(1) + buffer_depth(2) + items(16*5)
        assert_eq!(payload.len(), 4 + MAX_ITEMS * 5);
        assert_eq!(payload[0], 4); // 4 items by default
        assert_eq!(payload[1], 1); // sample_div = 1
    }
}
