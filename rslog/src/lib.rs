//! rslog - 嵌入式循环日志存储系统
//!
//! 特性：
//! - 循环存储：自动覆盖旧日志
//! - 紧凑存储：流式格式，无固定块浪费
//! - 断电安全：CRC 校验
//! - 可选压缩：大文本自动 LZ4 压缩
//! - 块压缩：批量缓冲后整体压缩，提高重复数据压缩率

pub mod stream_storage;

pub use stream_storage::{BlockWriter, StreamEntry, StreamLog, StreamStats, StreamWriter};
