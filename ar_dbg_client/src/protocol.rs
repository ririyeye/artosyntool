//! Artosyn Debug Service Protocol
//!
//! 协议结构：
//! ```text
//! struct ar_dbg_msg {
//!     header1: u8,      // 0xff
//!     header2: u8,      // 0x5a  
//!     version: u8,
//!     msg_id: u8,
//!     seq_num: u16,
//!     msg_len: u32,
//!     header_sum: u8,
//!     checksum: u16,
//!     payload: [u8],
//! }
//! ```

use bytes::{Buf, BytesMut};
use std::io;
use thiserror::Error;

/// 协议魔数
pub const HEADER_MAGIC1: u8 = 0xff;
pub const HEADER_MAGIC2: u8 = 0x5a;

/// 消息 ID 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgId {
    System = 0x0,
    Register = 0x1,
    Baseband = 0x2,
    Camera = 0x3,
}

impl From<u8> for MsgId {
    fn from(v: u8) -> Self {
        match v {
            0x0 => MsgId::System,
            0x1 => MsgId::Register,
            0x2 => MsgId::Baseband,
            0x3 => MsgId::Camera,
            _ => MsgId::System,
        }
    }
}

/// BB 命令基础偏移
pub const AR_BB_CMD_ID_TOOL_INFO_BASE: u32 = 0x04000000;

/// BB 消息命令（工具信息命令）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BbCmd {
    GetVersionInfo = 0x00,
    GetOsdInfo = 0x01,
    GetDeviceInfo = 0x02,
    GetBbMacAddr = 0x03,
    GetBbChnList = 0x04,
    GetCurChnQi = 0x05,
    GetBbDistance = 0x06,
    GetSingleOsd = 0x07,
    SetDbgMode = 0x20,
    ResetBb = 0x21,
    SetSleepMode = 0x22,
    SetBandSwh = 0x23,
    SetSlotHopMode = 0x24,
    SetBrHopMode = 0x25,
    SetMcsMode = 0x26,
    SetSlotQam = 0x27,
    SetSlotLdpc = 0x28,
    SetBrQam = 0x29,
    SetBrLdpc = 0x2a,
    SetAocMode = 0x2b,
    SetPowerMode = 0x2c,
    SetPowerClosed = 0x2d,
    WrBbRegSig = 0x2e,
    WrRfRegSig = 0x2f,
    GetBbRegPage = 0x30,
    SetSlotOnly = 0x33,
    SetBbSlaveMode = 0x34,
    SetSingleTone = 0x35,
    SndUsrData = 0x36,
    GetUsrData = 0x37,
    SetVideoCr = 0x38,
    SetLnaMode = 0x39,
    SetTxRxMode = 0x3a,
    SetChanManual = 0x3b,
    BbSpecialCtl = 0x3c,
    RfStatCtl = 0x3d,
    BroadcastTxCtl = 0x3e,
    StartBbMachine = 0x3f,
    StopBbMachine = 0x40,
    SetPwrValue = 0x41,
    ReloadChnInfoEnd = 0x42,
    GetFacSetting = 0x80,
    SetFacSetting = 0x81,
    ResetFacSetting = 0x82,
    SetBbMacAddr = 0x83,
    SetBbMacAddrTmp = 0x85,
    GetCurrentSn = 0x86,
    ImgUpgrade = 0xd0,
    UpgradeState = 0xd1,
    BbFileWrite = 0xf0,
    BbFileRead = 0xf1,
    BbFlowStatusGet = 0xf2,
    BbFlowModCfg = 0xf3,
    UpdateOsd = 0x100,
}

impl BbCmd {
    /// 获取低8位作为消息 ID
    pub fn to_local_u8(self) -> u8 {
        (self as u32 & 0xff) as u8
    }
}

/// 协议头长度
pub const HEADER_SIZE: usize = 13;

/// 协议错误
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("checksum mismatch: expected {expected}, got {got}")]
    ChecksumMismatch { expected: u16, got: u16 },
    #[error("incomplete message: need {need} bytes, got {got}")]
    IncompleteMessage { need: usize, got: usize },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// 消息头
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub version: u8,
    pub msg_id: MsgId,
    pub seq_num: u16,
    pub msg_len: u32,
    pub header_sum: u8,
    pub checksum: u16,
}

/// 完整消息
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

/// 计算校验和
pub fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    sum as u16
}

impl Message {
    /// 编码消息为字节
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        buf.push(HEADER_MAGIC1);
        buf.push(HEADER_MAGIC2);
        buf.push(self.header.version);
        buf.push(self.header.msg_id as u8);
        buf.extend_from_slice(&self.header.seq_num.to_le_bytes());
        buf.extend_from_slice(&self.header.msg_len.to_le_bytes());

        // 计算 header_sum (前10字节的校验和的低8位)
        let header_sum = calc_checksum(&buf) as u8;
        buf.push(header_sum);

        // checksum
        let checksum = calc_checksum(&self.payload);
        buf.extend_from_slice(&checksum.to_le_bytes());

        // payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// 从字节解码消息
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Message>, ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        // 检查魔数
        if buf[0] != HEADER_MAGIC1 || buf[1] != HEADER_MAGIC2 {
            return Err(ProtocolError::InvalidMagic);
        }

        // 解析 msg_len
        let msg_len = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;

        // 检查是否有足够的数据
        let total_len = HEADER_SIZE + msg_len;
        if buf.len() < total_len {
            return Ok(None);
        }

        // 解析头部
        let header = MessageHeader {
            version: buf[2],
            msg_id: MsgId::from(buf[3]),
            seq_num: u16::from_le_bytes([buf[4], buf[5]]),
            msg_len: msg_len as u32,
            header_sum: buf[10],
            checksum: u16::from_le_bytes([buf[11], buf[12]]),
        };

        // 提取 payload
        let payload = buf[HEADER_SIZE..total_len].to_vec();

        // 校验 checksum
        let calculated_cs = calc_checksum(&payload);
        if calculated_cs != header.checksum && header.checksum != 0 {
            return Err(ProtocolError::ChecksumMismatch {
                expected: header.checksum,
                got: calculated_cs,
            });
        }

        // 消费已解析的数据
        buf.advance(total_len);

        Ok(Some(Message { header, payload }))
    }

    /// 创建 BB 消息
    pub fn new_bb_msg(seq_num: u16, payload: Vec<u8>) -> Self {
        Message {
            header: MessageHeader {
                version: 0,
                msg_id: MsgId::Baseband,
                seq_num,
                msg_len: payload.len() as u32,
                header_sum: 0,
                checksum: 0,
            },
            payload,
        }
    }
}

/// BB 消息头
#[derive(Debug, Clone)]
pub struct BbMsgHeader {
    pub bb_msg_id: u8,
}

/// BB 接收消息头
#[derive(Debug, Clone)]
pub struct BbRcvMsgHeader {
    pub bb_msg_id: u8,
    pub ret_type: u8,
}

impl BbRcvMsgHeader {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(Self {
            bb_msg_id: data[0],
            ret_type: data[1],
        })
    }
}

/// OSD 配置参数
#[derive(Debug, Clone, Copy)]
pub struct OsdConfig {
    /// 是否启用 OSD (1=启用, 0=禁用)
    pub enable: u8,
    /// 周期计数 (0=每周期多包, 1=每周期一包/实时模式)
    pub cycle_cnt: u8,
    /// 用户 ID (0-3)
    pub user_id: u8,
}

impl Default for OsdConfig {
    fn default() -> Self {
        Self {
            enable: 1,
            cycle_cnt: 1, // 实时模式
            user_id: 0,
        }
    }
}

/// 创建启动 OSD 的消息
///
/// 协议格式 (4字节):
/// - bb_msg_id: GET_OSD_INFO (0x01)
/// - osd_plot_en: 1=启用, 0=禁用
/// - cycle_cnt: 0=每周期多包, 1=每周期一包(实时)
/// - osd_user_id: 用户ID (0-3)
pub fn create_start_osd_msg(seq_num: u16) -> Message {
    create_start_osd_msg_with_config(seq_num, OsdConfig::default())
}

/// 创建启动 OSD 的消息（带配置）
pub fn create_start_osd_msg_with_config(seq_num: u16, config: OsdConfig) -> Message {
    let payload = vec![
        BbCmd::GetOsdInfo.to_local_u8(), // bb_msg_id
        config.enable,                   // osd_plot_en: 1=启用
        config.cycle_cnt,                // cycle_cnt: 1=实时模式
        config.user_id,                  // osd_user_id: 用户0
    ];
    Message::new_bb_msg(seq_num, payload)
}

/// 创建停止 OSD 的消息
pub fn create_stop_osd_msg(seq_num: u16) -> Message {
    let payload = vec![
        BbCmd::GetOsdInfo.to_local_u8(), // bb_msg_id
        0x00,                            // osd_plot_en: 0=禁用
        0x00,                            // cycle_cnt
        0x00,                            // osd_user_id
    ];
    Message::new_bb_msg(seq_num, payload)
}

/// 创建获取设备信息的消息
///
/// 用于获取设备角色:
/// - 返回 0: DEV 角色
/// - 返回 1: AP 角色
pub fn create_get_device_info_msg(seq_num: u16) -> Message {
    let payload = vec![
        BbCmd::GetDeviceInfo.to_local_u8(), // bb_msg_id = 0x02
    ];
    Message::new_bb_msg(seq_num, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(calc_checksum(&data), 10);
    }

    #[test]
    fn test_encode_decode() {
        let msg = create_start_osd_msg(1);
        let encoded = msg.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = Message::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.header.msg_id, MsgId::Baseband);
        assert_eq!(decoded.payload.len(), 4); // bb_msg_id + 3个参数
        assert_eq!(decoded.payload[0], BbCmd::GetOsdInfo.to_local_u8());
        assert_eq!(decoded.payload[1], 0x01); // enable
        assert_eq!(decoded.payload[2], 0x01); // cycle_cnt (实时)
        assert_eq!(decoded.payload[3], 0x00); // user_id
    }
}
