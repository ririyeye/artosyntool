//! 寄存器跟踪配置和元数据
//!
//! 支持从 JSON 配置文件读取要采集的寄存器列表

use ar_dbg_client::{ConfigRequest, RegTraceItem, DEFAULT_PORT};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ============================================================================
// Chunk 魔数定义 (用于区分不同类型的二进制块)
// ============================================================================

/// Chunk0 配置描述块魔数: 0x52 0x54 0x43 0x30 ("RTC0")
pub const CHUNK_MAGIC_CONFIG: [u8; 4] = [0x52, 0x54, 0x43, 0x30];

/// ChunkN 数据块魔数: 0x52 0x54 0x44 0x4E ("RTDN")
pub const CHUNK_MAGIC_DATA: [u8; 4] = [0x52, 0x54, 0x44, 0x4E];

/// 单个寄存器配置项（JSON 格式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegItemConfig {
    /// 寄存器页号 (0-5)
    pub page: u8,
    /// 页内偏移地址（支持十六进制字符串如 "0x10"）
    #[serde(deserialize_with = "deserialize_hex_or_int")]
    pub offset: u8,
    /// 读取宽度: 1/2/4 字节
    #[serde(default = "default_width")]
    pub width: u8,
    /// 中断触发掩码 (0xFFFF 表示所有中断)
    #[serde(
        default = "default_irq_mask",
        deserialize_with = "deserialize_hex_or_int_u16"
    )]
    pub irq_mask: u16,
    /// 字段名称（用于 CSV 表头和描述）
    #[serde(default)]
    pub name: String,
    /// 字段描述
    #[serde(default)]
    pub description: String,
    /// 单位
    #[serde(default)]
    pub unit: String,
}

fn default_width() -> u8 {
    4
}

fn default_irq_mask() -> u16 {
    0xFFFF
}

/// 自定义反序列化：支持整数或十六进制字符串
fn deserialize_hex_or_int<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HexOrInt {
        Int(u8),
        Str(String),
    }

    match HexOrInt::deserialize(deserializer)? {
        HexOrInt::Int(v) => Ok(v),
        HexOrInt::Str(s) => {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") {
                u8::from_str_radix(&s[2..], 16).map_err(D::Error::custom)
            } else {
                s.parse::<u8>().map_err(D::Error::custom)
            }
        }
    }
}

/// 自定义反序列化 u16：支持整数或十六进制字符串
fn deserialize_hex_or_int_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HexOrInt {
        Int(u16),
        Str(String),
    }

    match HexOrInt::deserialize(deserializer)? {
        HexOrInt::Int(v) => Ok(v),
        HexOrInt::Str(s) => {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") {
                u16::from_str_radix(&s[2..], 16).map_err(D::Error::custom)
            } else {
                s.parse::<u16>().map_err(D::Error::custom)
            }
        }
    }
}

/// 寄存器跟踪配置（JSON 格式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegTraceConfig {
    /// 配置名称
    #[serde(default)]
    pub name: String,

    /// 配置描述
    #[serde(default)]
    pub description: String,

    /// 目标主机 IP
    #[serde(default = "default_host")]
    pub host: String,

    /// 目标端口
    #[serde(default = "default_port")]
    pub port: u16,

    /// 采样分频: 1=每帧采集, N=每N帧采集一次
    #[serde(default = "default_sample_div")]
    pub sample_div: u8,

    /// 环形缓冲区深度（记录数）
    #[serde(default = "default_buffer_depth")]
    pub buffer_depth: u16,

    /// 要采集的寄存器列表
    pub items: Vec<RegItemConfig>,
}

fn default_host() -> String {
    "192.168.1.100".to_string()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_sample_div() -> u8 {
    1
}

fn default_buffer_depth() -> u16 {
    100
}

/// 编译时嵌入的默认配置 JSON
const DEFAULT_CONFIG_JSON: &str = include_str!("../../example_reg_config.json");

impl Default for RegTraceConfig {
    fn default() -> Self {
        // 编译时解析 JSON（如果解析失败会 panic）
        serde_json::from_str(DEFAULT_CONFIG_JSON)
            .expect("Failed to parse embedded example_reg_config.json")
    }
}

impl RegTraceConfig {
    /// 从 JSON 文件加载配置
    ///
    /// 注意：不再检查配置项数量限制，因为服务器会自动合并相邻寄存器。
    /// 如果合并后仍超出限制，服务器会返回 TooManyItems 错误。
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path.as_ref())?;
        let config: RegTraceConfig = serde_json::from_str(&content)?;

        // 验证配置：只检查是否为空
        if config.items.is_empty() {
            anyhow::bail!("配置文件中 items 不能为空");
        }
        // 不再检查 items.len() > MAX_ITEMS，服务器会合并相邻寄存器，
        // 最终限制由服务器判断并返回错误码

        Ok(config)
    }

    /// 保存配置到 JSON 文件
    #[allow(dead_code)]
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// 转换为 ar_dbg_client 的 ConfigRequest
    pub fn to_config_request(&self) -> ConfigRequest {
        ConfigRequest {
            items: self
                .items
                .iter()
                .map(|item| {
                    RegTraceItem::with_irq_mask(item.page, item.offset, item.width, item.irq_mask)
                })
                .collect(),
            sample_div: self.sample_div,
            buffer_depth: self.buffer_depth,
        }
    }
}

/// 字段描述信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub page: u8,
    pub offset: u8,
    pub width: u8,
    /// 中断触发掩码
    pub irq_mask: u16,
    pub description: String,
    pub unit: String,
}

/// 寄存器跟踪描述符（存储在 rslog 通道1 的文本记录，导出为 JSON）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegTraceDescriptor {
    /// 配置名称
    pub name: String,
    /// 配置描述
    pub description: String,
    /// 采样分频
    pub sample_div: u8,
    /// 缓冲区深度
    pub buffer_depth: u16,
    /// 字段列表
    pub fields: Vec<FieldInfo>,
    /// 时间戳单位
    pub timestamp_unit: String,
    /// PlotJuggler 使用说明
    pub plotjuggler_notes: String,
}

impl RegTraceDescriptor {
    /// 从配置构建描述符
    pub fn from_config(config: &RegTraceConfig) -> Self {
        let fields: Vec<FieldInfo> = config
            .items
            .iter()
            .enumerate()
            .map(|(_i, item)| {
                let name = if item.name.is_empty() {
                    format!("reg_p{}_0x{:02X}", item.page, item.offset)
                } else {
                    item.name.clone()
                };
                FieldInfo {
                    name,
                    page: item.page,
                    offset: item.offset,
                    width: item.width,
                    irq_mask: item.irq_mask,
                    description: item.description.clone(),
                    unit: item.unit.clone(),
                }
            })
            .collect();

        Self {
            name: config.name.clone(),
            description: config.description.clone(),
            sample_div: config.sample_div,
            buffer_depth: config.buffer_depth,
            fields,
            timestamp_unit: "seconds (Unix epoch)".to_string(),
            plotjuggler_notes: "CSV第一列timestamp为时间轴(秒)，可直接在PlotJuggler中选择作为X轴"
                .to_string(),
        }
    }
}

/// 生成示例配置文件内容
#[allow(dead_code)]
pub fn generate_example_config() -> String {
    let config = RegTraceConfig {
        name: "example".to_string(),
        description: "示例配置：采集指定寄存器".to_string(),
        host: "192.168.1.100".to_string(),
        port: DEFAULT_PORT,
        sample_div: 1,
        buffer_depth: 100,
        items: vec![
            RegItemConfig {
                page: 0,
                offset: 0x00,
                width: 4,
                irq_mask: 0xFFFF,
                name: "status_reg".to_string(),
                description: "状态寄存器".to_string(),
                unit: "".to_string(),
            },
            RegItemConfig {
                page: 0,
                offset: 0x04,
                width: 4,
                irq_mask: 0x0006, // TX_BR_END | CSMA_START_ENC
                name: "ctrl_reg".to_string(),
                description: "控制寄存器".to_string(),
                unit: "".to_string(),
            },
            RegItemConfig {
                page: 1,
                offset: 0x10,
                width: 4,
                irq_mask: 0x0001, // RX_BR_END
                name: "snr_raw".to_string(),
                description: "SNR原始值 (dB = 10*log10(value/64))".to_string(),
                unit: "raw".to_string(),
            },
            RegItemConfig {
                page: 4,
                offset: 0xDC,
                width: 4,
                irq_mask: 0xFFFF,
                name: "agc_value".to_string(),
                description: "AGC增益值".to_string(),
                unit: "dB".to_string(),
            },
        ],
    };
    serde_json::to_string_pretty(&config).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RegTraceConfig::default();
        // 验证从 example_reg_config.json 加载
        assert_eq!(config.name, "example_regs");
        assert_eq!(config.items.len(), 23); // 23个默认寄存器
        assert_eq!(config.items[0].page, 4);
        assert_eq!(config.items[0].offset, 0x5C);
        assert_eq!(config.items[0].name, "FSM_CUR_STATE");
    }

    #[test]
    fn test_to_config_request() {
        let config = RegTraceConfig::default();
        let req = config.to_config_request();
        assert_eq!(req.items.len(), 23);
        assert_eq!(req.sample_div, 1);
    }

    #[test]
    fn test_json_parse() {
        let json = r#"{
            "name": "test",
            "items": [
                {"page": 0, "offset": "0x10", "width": 4, "irq_mask": "0x0006", "name": "test_reg"}
            ]
        }"#;
        let config: RegTraceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.items[0].offset, 0x10);
        assert_eq!(config.items[0].irq_mask, 0x0006);
    }

    #[test]
    fn test_descriptor() {
        let config = RegTraceConfig::default();
        let desc = RegTraceDescriptor::from_config(&config);
        assert_eq!(desc.fields.len(), 23);
    }
}
