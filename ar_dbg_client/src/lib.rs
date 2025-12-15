//! 寄存器跟踪服务客户端库
//!
//! 用于连接 Artosyn 寄存器跟踪服务并采集寄存器数据的 Rust 客户端库。
//!
//! # 示例
//!
//! ```rust,no_run
//! use ar_dbg_client::{RegTraceClient, ClientConfig, ConfigRequest};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = ClientConfig {
//!         host: "192.168.1.100".to_string(),
//!         port: 12345,
//!         timeout_secs: 5,
//!     };
//!     
//!     let client = RegTraceClient::new(config);
//!     let mut stream = client.connect().await.unwrap();
//!     
//!     // Ping 测试
//!     let resp = client.ping(&mut stream).await.unwrap();
//!     println!("Uptime: {} seconds", resp.uptime_sec);
//!     
//!     // 配置并启动（默认第一页寄存器）
//!     client.start_trace_default(&mut stream).await.unwrap();
//!     
//!     // 拉取数据
//!     let data = client.fetch(&mut stream, 10, true).await.unwrap();
//!     for record in &data.records {
//!         println!("{}", record);
//!     }
//! }
//! ```

pub mod client;
pub mod protocol;

pub use client::{ClientConfig, ClientError, RegTraceClient};
pub use protocol::{
    CmdId, ConfigRequest, ConfigResponse, ErrorCode, FetchRequest, FetchResponse, GenericResponse,
    Message, PingResponse, RegTraceItem, StatusResponse, TraceRecord, VersionResponse,
    DEFAULT_PORT, MAX_ITEMS, PROTOCOL_VERSION,
};
