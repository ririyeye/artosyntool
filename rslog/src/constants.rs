//! 常量定义
//!
//! 流式循环日志存储的各种常量和标记定义

/// 同步字节 - 用于定位数据边界
pub const SYNC_MAGIC: u16 = 0xAA55;
/// 结束标记
pub const END_MAGIC: u16 = 0x55AA;
/// 文件头魔数
pub const FILE_MAGIC: u32 = 0x534C4F47; // "SLOG"
/// 版本号
pub const VERSION: u32 = 1;
/// 文件头大小
pub const HEADER_SIZE: u64 = 64;
/// 条目头大小 (SYNC + Len + Seq + Timestamp_ms)
pub const ENTRY_HEADER_SIZE: usize = 2 + 2 + 8 + 6;
/// 条目尾大小 (CRC + END)
pub const ENTRY_FOOTER_SIZE: usize = 4 + 2;
/// 条目开销
pub const ENTRY_OVERHEAD: usize = ENTRY_HEADER_SIZE + ENTRY_FOOTER_SIZE;

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
pub const FLAG_BINARY: u8 = 0x04; // bit 2: 二进制类型
pub const FLAG_COMPRESSED: u8 = 0x01; // bit 0: 已压缩
pub const FLAG_BLOCK: u8 = 0x08; // bit 3: 块模式（多条打包）
pub const CHANNEL_SHIFT: u8 = 4; // 通道号在高4位
pub const CHANNEL_MASK: u8 = 0xF0; // 通道号掩码

/// 块内子记录头大小: 相对时间戳(2B) + 数据长度(2B)
pub const BLOCK_RECORD_HEADER_SIZE: usize = 4;
