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
//!     // 配置（配置后服务端自动推送数据）
//!     client.config_default(&mut stream).await.unwrap();
//!     
//!     // 流式接收推送数据
//!     client.run_streaming(&mut stream, |records| {
//!         for record in records {
//!             println!("{}", record);
//!         }
//!     }).await.unwrap();
//! }
//! ```

pub mod client;
pub mod protocol;

pub use client::{ClientConfig, ClientError, RegTraceClient};
pub use protocol::{
    irq_type, CmdId, ConfigRequest, ConfigResponse, DataPushResponse, ErrorCode, GenericResponse,
    Message, PingResponse, RegTraceItem, ShmInfoResponse, StatusResponse, TraceRecord,
    VersionResponse, DEFAULT_PORT, MAX_BATCH_RECORDS, MAX_ITEMS, MAX_ITEM_WIDTH, MAX_RECORD_DATA,
    PROTOCOL_VERSION, RECORD_HEADER_SIZE,
};
