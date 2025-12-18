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

    /// 配置并开始流式接收（默认配置：第一页寄存器）
    ///
    /// 配置成功后服务端会自动推送数据，无需手动启动
    pub async fn config_default(&self, stream: &mut TcpStream) -> Result<(), ClientError> {
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
            "Config OK: items={}, sample_div={}, buffer_depth={} - auto push started",
            config_resp.actual_items,
            config_resp.actual_sample_div,
            config_resp.actual_buffer_depth
        );

        Ok(())
    }
    /// 获取共享内存信息
    pub async fn get_shm_info(
        &self,
        stream: &mut TcpStream,
    ) -> Result<ShmInfoResponse, ClientError> {
        let msg = create_shm_info_msg(self.next_seq());
        let resp = self.request(stream, msg).await?;

        ShmInfoResponse::from_payload(&resp.payload)
            .ok_or(ClientError::Protocol(ProtocolError::InvalidMagic))
    }

    /// 流式接收模式 - 配置后自动接收服务端推送的数据
    ///
    /// 配置成功后，服务端会通过 DATA_PUSH (0xBA) 命令主动推送数据。
    /// 此方法会持续接收推送的数据并调用回调函数处理。
    ///
    /// # Arguments
    /// * `stream` - TCP 连接流
    /// * `on_records` - 数据回调函数，接收一批 TraceRecord
    ///
    /// # Returns
    /// * `Ok(total_records)` - 总共接收的记录数（当连接关闭时）
    /// * `Err(ClientError)` - 发生错误时
    pub async fn run_streaming<F>(
        &self,
        stream: &mut TcpStream,
        mut on_records: F,
    ) -> Result<u64, ClientError>
    where
        F: FnMut(&[TraceRecord]),
    {
        info!("Streaming mode started");

        let mut total_records: u64 = 0;
        let mut buf = BytesMut::with_capacity(8192);
        let mut read_buf = [0u8; 4096];

        loop {
            // 等待数据，使用较长的超时时间（或无限等待）
            let result = timeout(Duration::from_millis(500), stream.read(&mut read_buf)).await;

            match result {
                Ok(Ok(0)) => {
                    // 连接关闭
                    info!(
                        "Connection closed by server. Total records: {}",
                        total_records
                    );
                    break;
                }
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&read_buf[..n]);
                    debug!("Received {} bytes, buffer size: {}", n, buf.len());

                    // 尝试解析消息
                    while let Some(msg) = Message::decode(&mut buf)? {
                        if msg.header.cmd_id == CmdId::DataPush {
                            // 解析推送数据（格式与 FetchResponse 相同）
                            if let Some(data_resp) = DataPushResponse::from_payload(&msg.payload) {
                                if data_resp.result == ErrorCode::Ok
                                    && !data_resp.records.is_empty()
                                {
                                    total_records += data_resp.records.len() as u64;
                                    on_records(&data_resp.records);
                                }
                            }
                        } else {
                            debug!(
                                "Received non-push message: {:?} (seq={})",
                                msg.header.cmd_id, msg.header.seq_num
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Read error: {}", e);
                    return Err(ClientError::ConnectionFailed(e));
                }
                Err(_) => {
                    // 超时，继续等待
                    continue;
                }
            }
        }

        Ok(total_records)
    }

    /// 流式接收模式（带取消信号）
    ///
    /// 与 `run_streaming` 类似，但支持通过 `cancel_token` 取消。
    ///
    /// # Arguments
    /// * `stream` - TCP 连接流
    /// * `cancel_token` - 取消信号
    /// * `on_records` - 数据回调函数
    pub async fn run_streaming_with_cancel<F>(
        &self,
        stream: &mut TcpStream,
        cancel_token: tokio_util::sync::CancellationToken,
        mut on_records: F,
    ) -> Result<u64, ClientError>
    where
        F: FnMut(&[TraceRecord]),
    {
        info!("Streaming mode started (with cancel token)");

        let mut total_records: u64 = 0;
        let mut buf = BytesMut::with_capacity(8192);
        let mut read_buf = [0u8; 4096];

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("Streaming cancelled. Total records: {}", total_records);
                    // 发送停止命令
                    let _ = self.stop(stream).await;
                    break;
                }
                result = stream.read(&mut read_buf) => {
                    match result {
                        Ok(0) => {
                            info!("Connection closed by server. Total records: {}", total_records);
                            break;
                        }
                        Ok(n) => {
                            buf.extend_from_slice(&read_buf[..n]);

                            while let Some(msg) = Message::decode(&mut buf)? {
                                if msg.header.cmd_id == CmdId::DataPush {
                                    if let Some(data_resp) = DataPushResponse::from_payload(&msg.payload) {
                                        if data_resp.result == ErrorCode::Ok && !data_resp.records.is_empty() {
                                            total_records += data_resp.records.len() as u64;
                                            on_records(&data_resp.records);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Read error: {}", e);
                            return Err(ClientError::ConnectionFailed(e));
                        }
                    }
                }
            }
        }

        Ok(total_records)
    }
}
