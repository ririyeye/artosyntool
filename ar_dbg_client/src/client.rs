//! 寄存器跟踪服务客户端

use bytes::BytesMut;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info};

use crate::protocol::{self, *};

/// 客户端错误
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("connection failed: {0}")]
    ConnectionFailed(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("send failed")]
    SendFailed,
    #[error("timeout")]
    Timeout,
    #[error("server error: {0}")]
    ServerError(ErrorCode),
}

/// 客户端配置
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            host: "192.168.1.100".to_string(),
            port: DEFAULT_PORT,
            timeout_secs: 5,
        }
    }
}

/// 寄存器跟踪服务客户端
pub struct RegTraceClient {
    config: ClientConfig,
    seq_num: Arc<AtomicU16>,
}

impl RegTraceClient {
    /// 创建新客户端
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            seq_num: Arc::new(AtomicU16::new(0)),
        }
    }

    /// 获取下一个序列号
    fn next_seq(&self) -> u16 {
        self.seq_num.fetch_add(1, Ordering::SeqCst)
    }

    /// 连接到服务器
    pub async fn connect(&self) -> Result<TcpStream, ClientError> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        info!("Connecting to {}", addr);
        let stream = TcpStream::connect(&addr).await?;
        info!("Connected to {}", addr);
        Ok(stream)
    }

    /// 发送消息
    async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), ClientError> {
        let data = msg.encode();
        debug!("Sending {} bytes: {:02x?}", data.len(), &data);
        stream.write_all(&data).await?;
        Ok(())
    }

    /// 接收消息
    async fn recv_message(
        stream: &mut TcpStream,
        timeout_secs: u64,
    ) -> Result<Message, ClientError> {
        let mut buf = BytesMut::with_capacity(4096);
        let mut read_buf = [0u8; 1024];

        let result = timeout(Duration::from_secs(timeout_secs), async {
            loop {
                let n = stream.read(&mut read_buf).await?;
                if n == 0 {
                    return Err(ClientError::ConnectionClosed);
                }

                buf.extend_from_slice(&read_buf[..n]);
                debug!("Received {} bytes, buffer size: {}", n, buf.len());

                if let Some(msg) = Message::decode(&mut buf)? {
                    return Ok(msg);
                }
            }
        })
        .await;

        match result {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// 发送请求并等待响应
    async fn request(&self, stream: &mut TcpStream, msg: Message) -> Result<Message, ClientError> {
        Self::send_message(stream, &msg).await?;
        Self::recv_message(stream, self.config.timeout_secs).await
    }

    /// 心跳检测
    pub async fn ping(&self, stream: &mut TcpStream) -> Result<PingResponse, ClientError> {
        let msg = create_ping_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        PingResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 获取版本信息
    pub async fn get_version(
        &self,
        stream: &mut TcpStream,
    ) -> Result<VersionResponse, ClientError> {
        let msg = create_version_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        VersionResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 配置抓取项
    pub async fn config(
        &self,
        stream: &mut TcpStream,
        config: &ConfigRequest,
    ) -> Result<ConfigResponse, ClientError> {
        let msg = create_config_msg(self.next_seq(), config);
        let resp = self.request(stream, msg).await?;

        ConfigResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 启动采集
    pub async fn start(
        &self,
        stream: &mut TcpStream,
        clear_buffer: bool,
    ) -> Result<GenericResponse, ClientError> {
        let msg = create_start_msg(self.next_seq(), clear_buffer);
        let resp = self.request(stream, msg).await?;

        GenericResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 停止采集
    pub async fn stop(&self, stream: &mut TcpStream) -> Result<GenericResponse, ClientError> {
        let msg = create_stop_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        GenericResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 查询状态
    pub async fn status(&self, stream: &mut TcpStream) -> Result<StatusResponse, ClientError> {
        let msg = create_status_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        StatusResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 拉取数据
    pub async fn fetch(
        &self,
        stream: &mut TcpStream,
        max_records: u8,
        clear_after_read: bool,
    ) -> Result<FetchResponse, ClientError> {
        let msg = create_fetch_msg(self.next_seq(), max_records, clear_after_read);
        let resp = self.request(stream, msg).await?;

        FetchResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 清空缓冲区
    pub async fn clear(&self, stream: &mut TcpStream) -> Result<GenericResponse, ClientError> {
        let msg = create_clear_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        GenericResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 配置并启动采集（默认配置：第一页寄存器）
    pub async fn start_trace_default(&self, stream: &mut TcpStream) -> Result<(), ClientError> {
        // 使用默认配置（第一页的寄存器）
        let config = ConfigRequest::default();

        info!(
            "Configuring trace with {} items on page 0",
            config.items.len()
        );
        let config_resp = self.config(stream, &config).await?;
        if config_resp.result != ErrorCode::Ok {
            error!("Config failed: {}", config_resp.result);
            return Err(ClientError::ServerError(config_resp.result));
        }
        info!(
            "Config OK: items={}, sample_div={}, buffer_depth={}",
            config_resp.actual_items,
            config_resp.actual_sample_div,
            config_resp.actual_buffer_depth
        );

        // 启动采集
        let start_resp = self.start(stream, true).await?;
        if start_resp.result != ErrorCode::Ok {
            error!("Start failed: {}", start_resp.result);
            return Err(ClientError::ServerError(start_resp.result));
        }
        info!("Trace started");

        Ok(())
    }

    /// 持续监控模式
    pub async fn monitor(
        &self,
        stream: &mut TcpStream,
        interval_ms: u64,
        max_records: u8,
        mut on_record: impl FnMut(&TraceRecord),
    ) -> Result<(), ClientError> {
        info!("Starting monitor mode (interval={}ms)", interval_ms);

        loop {
            // 查询状态
            let status = self.status(stream).await?;
            if status.record_count > 0 {
                // 拉取数据
                let fetch_resp = self.fetch(stream, max_records, true).await?;
                if fetch_resp.result == ErrorCode::Ok {
                    for record in &fetch_resp.records {
                        on_record(record);
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
}
