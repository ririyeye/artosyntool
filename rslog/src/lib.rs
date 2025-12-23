//! rslog - 嵌入式循环日志存储系统
//!
//! 特性：
//! - 循环存储：自动覆盖旧日志
//! - 紧凑存储：流式格式，无固定块浪费
//! - 断电安全：CRC 校验
//! - 可选压缩：大文本自动 LZ4 压缩
//! - 块压缩：批量缓冲后整体压缩，提高重复数据压缩率
//!
//! 文件格式：
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ FileHeader (64 bytes)                                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Entry1 │ Entry2 │ Entry3 │ ... │ EntryN │ [空闲] │ Entry1'  │
//! │        │        │        │     │        │        │ (覆盖)   │
//! └─────────────────────────────────────────────────────────────┘
//!          ↑                              ↑
//!       read_pos                      write_pos
//! ```
//!
//! Entry 格式：
//! ```text
//! ┌──────┬──────┬────────┬──────────┬──────────┬──────┬──────┐
//! │ SYNC │ Len  │ SeqNum │ TS_ms    │ Data ... │ CRC  │ END  │
//! │ 2B   │ 2B   │ 8B     │ 6B       │ N bytes  │ 4B   │ 2B   │
//! └──────┴──────┴────────┴──────────┴──────────┴──────┴──────┘
//! ```

pub mod constants;
pub mod entry;
pub mod header;
pub mod stream_log;
pub mod writer;

#[cfg(test)]
mod tests;

// 兼容性：保留旧的 stream_storage 模块名
pub mod stream_storage {
    //! 兼容性模块 - 重新导出所有类型
    pub use crate::constants::*;
    pub use crate::entry::*;
    pub use crate::header::*;
    pub use crate::stream_log::*;
    pub use crate::writer::*;
}

pub use entry::StreamEntry;
pub use stream_log::{OpenResult, SessionStats, StreamLog, StreamStats};
pub use writer::{BlockWriter, StreamWriter};
