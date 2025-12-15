//! Artosyn Debug Service Client Library
//!
//! 用于连接 Artosyn 调试服务并接收 OSD 数据的 Rust 客户端库。
//!
//! # 示例
//!
//! ```rust,no_run
//! use ar_dbg_client::{ArDbgClient, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = ClientConfig {
//!         host: "192.168.1.100".to_string(),
//!         port: 1234,
//!     };
//!     
//!     let client = ArDbgClient::new(config);
//!     client.start_osd_stream(|osd| {
//!         println!("{}", osd);
//!     }).await.unwrap();
//! }
//! ```

pub mod client;
pub mod osd;
pub mod protocol;

pub use client::{ArDbgClient, ClientConfig, ClientError, DEFAULT_PORT};
pub use osd::{DeviceRole, OsdPlot};
pub use protocol::{BbCmd, Message, MsgId, OsdConfig};
