//! rslog - 嵌入式循环日志存储系统
//!
//! 特性：
//! - 循环存储：自动覆盖旧日志
//! - 紧凑存储：流式格式，无固定块浪费
//! - 断电安全：CRC 校验
//! - 可选压缩：大文本自动 LZ4 压缩

pub mod stream_storage;

pub use stream_storage::{StreamEntry, StreamLog, StreamStats, StreamWriter};
