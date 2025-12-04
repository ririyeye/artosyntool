//! OSD 数据结构定义
//!
//! 根据设备角色有不同的内存布局:
//!
//! DEV (设备端) 布局:
//! BR_LOCK:4, BR_LDPC_ERR:5, BR_SNR:7,6, BR_AGC0-3:8-b
//! BR_CHN:18, SLOT_TX_CHN:19, SLOT_RX_CHN:1a, SLOT_RX_OPT_CHN:1b
//! MAIN_AVR_PWR:25,24, OPT_AVR_PWR:27,26, MCS_VALUE:28
//!
//! AP (接入点) 布局:
//! FCH_LOCK:c, SLOT_LOCK:d, SLOT_LDPC_ERR:f,e, SLOT_SNR:11,10
//! SLOT_LDPC_AFTER_ERR:13,12, SLOT_AGC0:14, SLOT_AGC1:16, SLOT_AGC2:15, SLOT_AGC3:17
//! SLOT_RX_OPT_CHN:27, MAIN_AVR_PWR:31,30, OPT_AVR_PWR:33,32, MCS_VALUE:34

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// 全局调试模式标志
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

/// 设备角色: 0=DEV, 1=AP
static DEVICE_ROLE: AtomicU8 = AtomicU8::new(0);

/// 设备角色枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceRole {
    #[default]
    Dev = 0, // 设备端
    Ap = 1, // 接入点
}

impl From<u8> for DeviceRole {
    /// 从 skyGround 字段转换: 0=AP, 1=DEV
    fn from(sky_ground: u8) -> Self {
        match sky_ground {
            0 => DeviceRole::Ap,
            1 => DeviceRole::Dev,
            _ => DeviceRole::Dev,
        }
    }
}

impl fmt::Display for DeviceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceRole::Dev => write!(f, "DEV"),
            DeviceRole::Ap => write!(f, "AP"),
        }
    }
}

/// 设置调试模式
pub fn set_debug_mode(enabled: bool) {
    DEBUG_MODE.store(enabled, Ordering::SeqCst);
}

/// 获取调试模式状态
pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

/// 设置设备角色
pub fn set_device_role(role: DeviceRole) {
    DEVICE_ROLE.store(role as u8, Ordering::SeqCst);
}

/// 获取设备角色
pub fn get_device_role() -> DeviceRole {
    // 直接从存储的枚举值转换，不经过 skyGround 的映射
    match DEVICE_ROLE.load(Ordering::SeqCst) {
        0 => DeviceRole::Dev,
        1 => DeviceRole::Ap,
        _ => DeviceRole::Dev,
    }
}

/// OSD 数据每包个数
pub const OSD_NUM_ONE_PKT: usize = 2;

/// OSD 绘图数据 - 统一结构，根据角色解析不同字段
#[derive(Debug, Clone, Default)]
pub struct OsdPlot {
    /// 设备角色
    pub role: DeviceRole,

    // === DEV 专用字段 ===
    /// BR_LOCK (DEV: 0x04)
    pub br_lock: u8,
    /// BR_LDPC_ERR (DEV: 0x05)
    pub br_ldpc_error: u8,
    /// BR_SNR (DEV: 0x06-0x07)
    pub br_snr_value: u16,
    /// BR_AGC0-3 (DEV: 0x08-0x0b)
    pub br_agc_value: [u8; 4],
    /// BR_CHN (DEV: 0x18)
    pub br_channel: u8,
    /// SLOT_TX_CHN (DEV: 0x19)
    pub slot_tx_channel: u8,
    /// SLOT_RX_CHN (DEV: 0x1a)
    pub slot_rx_channel: u8,

    // === AP 专用字段 ===
    /// FCH_LOCK (AP: 0x0c)
    pub fch_lock: u8,
    /// SLOT_LOCK (AP: 0x0d)
    pub slot_lock: u8,
    /// SLOT_LDPC_ERR (AP: 0x0e-0x0f)
    pub slot_ldpc_error: u16,
    /// SLOT_SNR (AP: 0x10-0x11)
    pub slot_snr_value: u16,
    /// SLOT_LDPC_AFTER_ERR (AP: 0x12-0x13)
    pub slot_ldpc_after_error: u16,
    /// SLOT_AGC0-3 (AP: 0x14, 0x16, 0x15, 0x17 - 注意顺序!)
    pub slot_agc_value: [u8; 4],

    // === 共用字段 ===
    /// SLOT_RX_OPT_CHN (DEV: 0x1b, AP: 0x27)
    pub slot_rx_opt_channel: u8,
    /// MAIN_AVR_PWR (DEV: 0x24-0x25, AP: 0x30-0x31)
    pub main_avr_pwr: u16,
    /// OPT_AVR_PWR (DEV: 0x26-0x27, AP: 0x32-0x33)
    pub opt_avr_pwr: u16,
    /// MCS_VALUE (DEV: 0x28, AP: 0x34)
    pub mcs_value: u8,

    /// 原始数据（用于调试）
    pub raw_data: Vec<u8>,
}

impl OsdPlot {
    /// DEV 模式最小大小
    pub const DEV_MIN_SIZE: usize = 0x29; // 41 bytes
    /// AP 模式最小大小
    pub const AP_MIN_SIZE: usize = 0x35; // 53 bytes

    /// 从字节解析 OSD 数据（带可选调试输出）
    pub fn from_bytes_debug(data: &[u8]) -> Option<Self> {
        let role = get_device_role();

        if is_debug_mode() {
            // 打印原始数据 hex dump
            println!(
                "\n=== RAW OSD DATA ({} bytes, Role: {}) ===",
                data.len(),
                role
            );
            for (i, chunk) in data.chunks(16).enumerate() {
                let offset = i * 16;
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("{:04x}: {:48} |{}|", offset, hex.join(" "), ascii);
            }
            println!();

            // 根据角色打印不同的字段
            match role {
                DeviceRole::Dev => Self::print_dev_debug(data),
                DeviceRole::Ap => Self::print_ap_debug(data),
            }
        }

        Self::from_bytes(data)
    }

    /// 打印 DEV 模式调试信息
    fn print_dev_debug(data: &[u8]) {
        if data.len() >= Self::DEV_MIN_SIZE {
            let br_snr_raw = u16::from_le_bytes([data[0x06], data[0x07]]);
            let br_snr_db = if br_snr_raw > 0 {
                10.0 * ((br_snr_raw as f32) / 64.0).log10()
            } else {
                0.0
            };

            println!("=== DEV FIELD DEBUG ===");
            println!(
                "[0x04] BR_LOCK:        0x{:02x} ({})",
                data[0x04], data[0x04]
            );
            println!(
                "[0x05] BR_LDPC_ERR:    0x{:02x} ({})",
                data[0x05], data[0x05]
            );
            println!(
                "[0x06-07] BR_SNR:      0x{:02x}{:02x} raw={} -> {:.1} dB",
                data[0x07], data[0x06], br_snr_raw, br_snr_db
            );
            println!(
                "[0x08] BR_AGC0:        0x{:02x} ({})",
                data[0x08], data[0x08]
            );
            println!(
                "[0x09] BR_AGC1:        0x{:02x} ({})",
                data[0x09], data[0x09]
            );
            println!(
                "[0x0a] BR_AGC2:        0x{:02x} ({})",
                data[0x0a], data[0x0a]
            );
            println!(
                "[0x0b] BR_AGC3:        0x{:02x} ({})",
                data[0x0b], data[0x0b]
            );
            println!(
                "[0x18] BR_CHN:         0x{:02x} ({})",
                data[0x18], data[0x18]
            );
            println!(
                "[0x19] SLOT_TX_CHN:    0x{:02x} ({})",
                data[0x19], data[0x19]
            );
            println!(
                "[0x1a] SLOT_RX_CHN:    0x{:02x} ({})",
                data[0x1a], data[0x1a]
            );
            println!(
                "[0x1b] SLOT_RX_OPT:    0x{:02x} ({})",
                data[0x1b], data[0x1b]
            );
            println!(
                "[0x24-25] MAIN_PWR:    0x{:02x}{:02x} ({})",
                data[0x25],
                data[0x24],
                u16::from_le_bytes([data[0x24], data[0x25]])
            );
            println!(
                "[0x26-27] OPT_PWR:     0x{:02x}{:02x} ({})",
                data[0x27],
                data[0x26],
                u16::from_le_bytes([data[0x26], data[0x27]])
            );
            println!(
                "[0x28] MCS_VALUE:      0x{:02x} ({})",
                data[0x28], data[0x28]
            );
            println!();
        }
    }

    /// 打印 AP 模式调试信息
    fn print_ap_debug(data: &[u8]) {
        if data.len() >= Self::AP_MIN_SIZE {
            let slot_snr_raw = u16::from_le_bytes([data[0x10], data[0x11]]);
            let slot_snr_db = if slot_snr_raw > 0 {
                10.0 * ((slot_snr_raw as f32) / 64.0).log10()
            } else {
                0.0
            };

            println!("=== AP FIELD DEBUG ===");
            println!(
                "[0x0c] FCH_LOCK:       0x{:02x} ({}) *20={}",
                data[0x0c],
                data[0x0c],
                data[0x0c] as u16 * 20
            );
            println!(
                "[0x0d] SLOT_LOCK:      0x{:02x} ({}) *22={}",
                data[0x0d],
                data[0x0d],
                data[0x0d] as u16 * 22
            );
            println!(
                "[0x0e-0f] SLOT_LDPC_ERR: 0x{:02x}{:02x} ({})",
                data[0x0f],
                data[0x0e],
                u16::from_le_bytes([data[0x0e], data[0x0f]])
            );
            println!(
                "[0x10-11] SLOT_SNR:    0x{:02x}{:02x} raw={} -> {:.1} dB",
                data[0x11], data[0x10], slot_snr_raw, slot_snr_db
            );
            println!(
                "[0x12-13] SLOT_LDPC_AFTER: 0x{:02x}{:02x} ({})",
                data[0x13],
                data[0x12],
                u16::from_le_bytes([data[0x12], data[0x13]])
            );
            println!(
                "[0x14] SLOT_AGC0:      0x{:02x} ({})",
                data[0x14], data[0x14]
            );
            println!(
                "[0x15] SLOT_AGC2:      0x{:02x} ({})",
                data[0x15], data[0x15]
            );
            println!(
                "[0x16] SLOT_AGC1:      0x{:02x} ({})",
                data[0x16], data[0x16]
            );
            println!(
                "[0x17] SLOT_AGC3:      0x{:02x} ({})",
                data[0x17], data[0x17]
            );
            println!(
                "[0x27] SLOT_RX_OPT:    0x{:02x} ({}) *10={}",
                data[0x27],
                data[0x27],
                data[0x27] as u16 * 10
            );
            println!(
                "[0x30-31] MAIN_PWR:    0x{:02x}{:02x} ({})",
                data[0x31],
                data[0x30],
                u16::from_le_bytes([data[0x30], data[0x31]])
            );
            println!(
                "[0x32-33] OPT_PWR:     0x{:02x}{:02x} ({})",
                data[0x33],
                data[0x32],
                u16::from_le_bytes([data[0x32], data[0x33]])
            );
            println!(
                "[0x34] MCS_VALUE:      0x{:02x} ({}) *10={}",
                data[0x34],
                data[0x34],
                data[0x34] as u16 * 10
            );
            println!();
        }
    }

    /// 从字节解析 OSD 数据
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let role = get_device_role();

        match role {
            DeviceRole::Dev => Self::from_bytes_dev(data),
            DeviceRole::Ap => Self::from_bytes_ap(data),
        }
    }

    /// DEV 模式解析
    fn from_bytes_dev(data: &[u8]) -> Option<Self> {
        if data.len() < Self::DEV_MIN_SIZE {
            if is_debug_mode() {
                println!(
                    "DEV OSD data too short: {} bytes (need {})",
                    data.len(),
                    Self::DEV_MIN_SIZE
                );
            }
            return None;
        }

        Some(Self {
            role: DeviceRole::Dev,
            raw_data: data.to_vec(),

            // DEV 字段
            br_lock: data[0x04],
            br_ldpc_error: data[0x05],
            br_snr_value: u16::from_le_bytes([data[0x06], data[0x07]]),
            br_agc_value: [data[0x08], data[0x09], data[0x0a], data[0x0b]],
            br_channel: data[0x18],
            slot_tx_channel: data[0x19],
            slot_rx_channel: data[0x1a],
            slot_rx_opt_channel: data[0x1b],
            main_avr_pwr: u16::from_le_bytes([data[0x24], data[0x25]]),
            opt_avr_pwr: u16::from_le_bytes([data[0x26], data[0x27]]),
            mcs_value: data[0x28],

            // AP 字段设为默认
            fch_lock: 0,
            slot_lock: 0,
            slot_ldpc_error: 0,
            slot_snr_value: 0,
            slot_ldpc_after_error: 0,
            slot_agc_value: [0; 4],
        })
    }

    /// AP 模式解析
    fn from_bytes_ap(data: &[u8]) -> Option<Self> {
        if data.len() < Self::AP_MIN_SIZE {
            if is_debug_mode() {
                println!(
                    "AP OSD data too short: {} bytes (need {})",
                    data.len(),
                    Self::AP_MIN_SIZE
                );
            }
            return None;
        }

        Some(Self {
            role: DeviceRole::Ap,
            raw_data: data.to_vec(),

            // AP 字段
            fch_lock: data[0x0c],
            slot_lock: data[0x0d],
            slot_ldpc_error: u16::from_le_bytes([data[0x0e], data[0x0f]]),
            slot_snr_value: u16::from_le_bytes([data[0x10], data[0x11]]),
            slot_ldpc_after_error: u16::from_le_bytes([data[0x12], data[0x13]]),
            // 注意 AGC 顺序: 0x14=AGC0, 0x16=AGC1, 0x15=AGC2, 0x17=AGC3
            slot_agc_value: [data[0x14], data[0x16], data[0x15], data[0x17]],
            slot_rx_opt_channel: data[0x27],
            main_avr_pwr: u16::from_le_bytes([data[0x30], data[0x31]]),
            opt_avr_pwr: u16::from_le_bytes([data[0x32], data[0x33]]),
            mcs_value: data[0x34],

            // DEV 字段设为默认
            br_lock: 0,
            br_ldpc_error: 0,
            br_snr_value: 0,
            br_agc_value: [0; 4],
            br_channel: 0,
            slot_tx_channel: 0,
            slot_rx_channel: 0,
        })
    }

    /// 获取 SNR (dB) - 公式: 10 * log10(value / 64)
    pub fn snr_db(&self) -> f32 {
        let raw = match self.role {
            DeviceRole::Dev => self.br_snr_value,
            DeviceRole::Ap => self.slot_snr_value,
        };
        if raw == 0 {
            return 0.0;
        }
        10.0 * ((raw as f32) / 64.0).log10()
    }

    /// 获取 LDPC 错误
    pub fn ldpc_error(&self) -> u16 {
        match self.role {
            DeviceRole::Dev => self.br_ldpc_error as u16,
            DeviceRole::Ap => self.slot_ldpc_error,
        }
    }

    /// 获取锁定状态
    pub fn is_locked(&self) -> bool {
        match self.role {
            DeviceRole::Dev => self.br_lock != 0,
            DeviceRole::Ap => self.slot_lock != 0,
        }
    }

    /// 获取 AGC 值
    pub fn agc_values(&self) -> &[u8; 4] {
        match self.role {
            DeviceRole::Dev => &self.br_agc_value,
            DeviceRole::Ap => &self.slot_agc_value,
        }
    }

    /// BR 是否锁定 (DEV 模式)
    pub fn is_br_locked(&self) -> bool {
        self.br_lock != 0
    }

    /// 获取 BR SNR (dB) - 公式: 10 * log10(value / 64) (DEV 模式)
    pub fn br_snr_db(&self) -> f32 {
        if self.br_snr_value == 0 {
            return 0.0;
        }
        10.0 * ((self.br_snr_value as f32) / 64.0).log10()
    }
}

impl fmt::Display for OsdPlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== OSD Data ({}) ===", self.role)?;

        match self.role {
            DeviceRole::Dev => {
                writeln!(
                    f,
                    "BR_LOCK: {} ({}) | MCS: {}",
                    self.br_lock,
                    if self.br_lock != 0 {
                        "Locked"
                    } else {
                        "Unlocked"
                    },
                    self.mcs_value
                )?;
                writeln!(
                    f,
                    "BR_SNR: {} ({:.1} dB) | BR_LDPC_ERR: {}",
                    self.br_snr_value,
                    self.snr_db(),
                    self.br_ldpc_error
                )?;
                writeln!(
                    f,
                    "BR_AGC: [{}, {}, {}, {}]",
                    self.br_agc_value[0],
                    self.br_agc_value[1],
                    self.br_agc_value[2],
                    self.br_agc_value[3]
                )?;
                writeln!(
                    f,
                    "Channels: BR={} SLOT_TX={} SLOT_RX={} SLOT_OPT={}",
                    self.br_channel,
                    self.slot_tx_channel,
                    self.slot_rx_channel,
                    self.slot_rx_opt_channel
                )?;
            }
            DeviceRole::Ap => {
                writeln!(
                    f,
                    "FCH_LOCK: {} | SLOT_LOCK: {} ({}) | MCS: {}",
                    self.fch_lock,
                    self.slot_lock,
                    if self.slot_lock != 0 {
                        "Locked"
                    } else {
                        "Unlocked"
                    },
                    self.mcs_value
                )?;
                writeln!(
                    f,
                    "SLOT_SNR: {} ({:.1} dB) | SLOT_LDPC_ERR: {} | AFTER_ERR: {}",
                    self.slot_snr_value,
                    self.snr_db(),
                    self.slot_ldpc_error,
                    self.slot_ldpc_after_error
                )?;
                writeln!(
                    f,
                    "SLOT_AGC: [{}, {}, {}, {}]",
                    self.slot_agc_value[0],
                    self.slot_agc_value[1],
                    self.slot_agc_value[2],
                    self.slot_agc_value[3]
                )?;
                writeln!(f, "SLOT_RX_OPT_CHN: {}", self.slot_rx_opt_channel)?;
            }
        }

        writeln!(
            f,
            "Power: MAIN_AVR={} OPT_AVR={}",
            self.main_avr_pwr, self.opt_avr_pwr
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_min_size() {
        assert_eq!(OsdPlot::DEV_MIN_SIZE, 0x29);
    }

    #[test]
    fn test_ap_min_size() {
        assert_eq!(OsdPlot::AP_MIN_SIZE, 0x35);
    }

    #[test]
    fn test_snr_db() {
        set_device_role(DeviceRole::Dev);
        let mut data = vec![0u8; 0x29];
        data[0x06] = 0x00;
        data[0x07] = 0x19; // 0x1900 = 6400
        let osd = OsdPlot::from_bytes(&data).unwrap();
        let snr = osd.snr_db();
        assert!((snr - 20.0).abs() < 0.1);
    }
}
