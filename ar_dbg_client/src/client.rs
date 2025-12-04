//! Artosyn Debug Service 客户端

use bytes::BytesMut;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

use crate::osd::{set_device_role, DeviceRole, OsdPlot};
use crate::protocol::{self, BbCmd, BbRcvMsgHeader, Message, MsgId};

/// 默认端口
pub const DEFAULT_PORT: u16 = 1234;

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
}

/// OSD 数据回调
pub type OsdCallback = Box<dyn Fn(&OsdPlot) + Send + Sync>;

/// 客户端配置
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            host: "192.168.1.100".to_string(),
            port: DEFAULT_PORT,
        }
    }
}

/// Artosyn Debug Service 客户端
pub struct ArDbgClient {
    config: ClientConfig,
    seq_num: Arc<AtomicU16>,
}

impl ArDbgClient {
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
    pub async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), ClientError> {
        let data = msg.encode();
        debug!("Sending {} bytes: {:02x?}", data.len(), &data);
        stream.write_all(&data).await?;
        Ok(())
    }

    /// 读取超时时间（秒）
    const READ_TIMEOUT_SECS: u64 = 5;

    /// 启动 OSD 并接收数据
    pub async fn start_osd_stream(
        &self,
        mut on_osd: impl FnMut(&OsdPlot) + Send + 'static,
    ) -> Result<(), ClientError> {
        let mut stream = self.connect().await?;

        // 发送启动 OSD 命令
        let start_msg = protocol::create_start_osd_msg(self.next_seq());
        Self::send_message(&mut stream, &start_msg).await?;
        info!("Sent start OSD command");

        // 接收数据
        let mut buf = BytesMut::with_capacity(8192);
        let mut read_buf = [0u8; 4096];

        loop {
            // 读取数据（带超时）
            let read_result = timeout(
                Duration::from_secs(Self::READ_TIMEOUT_SECS),
                stream.read(&mut read_buf),
            )
            .await;

            let n = match read_result {
                Ok(Ok(0)) => {
                    warn!("Connection closed by peer");
                    return Err(ClientError::ConnectionClosed);
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("Read error: {}", e);
                    return Err(ClientError::ConnectionFailed(e));
                }
                Err(_) => {
                    warn!(
                        "Read timeout ({}s), connection may be lost",
                        Self::READ_TIMEOUT_SECS
                    );
                    return Err(ClientError::ConnectionClosed);
                }
            };

            buf.extend_from_slice(&read_buf[..n]);
            debug!("Received {} bytes, buffer size: {}", n, buf.len());

            // 尝试解析消息
            while let Some(msg) = Message::decode(&mut buf)? {
                debug!(
                    "Decoded message: msg_id={:?}, payload_len={}",
                    msg.header.msg_id,
                    msg.payload.len()
                );

                if msg.header.msg_id == MsgId::Baseband {
                    self.handle_bb_message(&msg, &mut on_osd);
                }
            }
        }
    }

    /// 处理 BB 消息
    fn handle_bb_message(&self, msg: &Message, on_osd: &mut impl FnMut(&OsdPlot)) {
        if msg.payload.len() < 2 {
            warn!("BB message too short: {} bytes", msg.payload.len());
            return;
        }

        let rcv_header = match BbRcvMsgHeader::from_bytes(&msg.payload) {
            Some(h) => h,
            None => {
                warn!("Failed to parse BB rcv header");
                return;
            }
        };

        debug!(
            "BB msg: id=0x{:02x}, ret_type=0x{:02x}",
            rcv_header.bb_msg_id, rcv_header.ret_type
        );

        // 检查是否是 OSD 消息
        if rcv_header.bb_msg_id == BbCmd::GetOsdInfo.to_local_u8() {
            let osd_data = &msg.payload[2..];

            if let Some(osd) = OsdPlot::from_bytes_debug(osd_data) {
                on_osd(&osd);
            }
        }
    }

    /// 发送停止 OSD 命令
    pub async fn stop_osd(&self, stream: &mut TcpStream) -> Result<(), ClientError> {
        let stop_msg = protocol::create_stop_osd_msg(self.next_seq());
        Self::send_message(stream, &stop_msg).await?;
        info!("Sent stop OSD command");
        Ok(())
    }

    /// 发送自定义 BB 命令
    pub async fn send_bb_cmd(
        &self,
        stream: &mut TcpStream,
        cmd: BbCmd,
        data: &[u8],
    ) -> Result<(), ClientError> {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(cmd.to_local_u8());
        payload.extend_from_slice(data);

        let msg = Message::new_bb_msg(self.next_seq(), payload);
        Self::send_message(stream, &msg).await?;
        Ok(())
    }

    /// 获取设备信息（角色）
    /// 返回设备角色: 0=DEV, 1=AP
    pub async fn get_device_role(&self, stream: &mut TcpStream) -> Result<DeviceRole, ClientError> {
        // 发送 GET_DEVICE_INFO 命令 (0x02)
        let msg = protocol::create_get_device_info_msg(self.next_seq());
        Self::send_message(stream, &msg).await?;
        info!("Sent GET_DEVICE_INFO command");

        // 接收响应，带超时
        let mut buf = BytesMut::with_capacity(256);
        let mut read_buf = [0u8; 256];

        let result = timeout(Duration::from_secs(3), async {
            loop {
                let n = stream.read(&mut read_buf).await?;
                if n == 0 {
                    return Err(ClientError::ConnectionClosed);
                }

                buf.extend_from_slice(&read_buf[..n]);
                debug!("Received {} bytes for device info", n);

                // 尝试解析消息
                while let Some(msg) = Message::decode(&mut buf)? {
                    if msg.header.msg_id == MsgId::Baseband {
                        if let Some(rcv_header) = BbRcvMsgHeader::from_bytes(&msg.payload) {
                            if rcv_header.bb_msg_id == BbCmd::GetDeviceInfo.to_local_u8() {
                                // device_info_t 结构:
                                // payload[0] = bb_msg_id
                                // payload[1] = ret_type
                                // payload[2..6] = magic_header[4]
                                // payload[6] = skyGround (0x00=AP, 0x01=DEV)
                                if msg.payload.len() >= 7 {
                                    let sky_ground = msg.payload[6];
                                    // skyGround: 0x00=AP, 0x01=DEV
                                    let role = if sky_ground == 0 {
                                        DeviceRole::Ap
                                    } else {
                                        DeviceRole::Dev
                                    };
                                    info!(
                                        "Device role: {:?} (skyGround=0x{:02x})",
                                        role, sky_ground
                                    );
                                    return Ok(role);
                                }
                            }
                        }
                    }
                }
            }
        })
        .await;

        match result {
            Ok(Ok(role)) => Ok(role),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                warn!("Timeout waiting for device info, defaulting to DEV");
                Ok(DeviceRole::Dev)
            }
        }
    }

    /// 启动 OSD 并接收数据（自动检测设备角色）
    pub async fn start_osd_stream_auto_role(
        &self,
        mut on_osd: impl FnMut(&OsdPlot) + Send + 'static,
    ) -> Result<(), ClientError> {
        let mut stream = self.connect().await?;

        // 首先获取设备角色
        let role = self.get_device_role(&mut stream).await?;
        set_device_role(role);
        info!("Device role set to: {:?}", role);

        // 发送启动 OSD 命令
        let start_msg = protocol::create_start_osd_msg(self.next_seq());
        Self::send_message(&mut stream, &start_msg).await?;
        info!("Sent start OSD command");

        // 接收数据
        let mut buf = BytesMut::with_capacity(8192);
        let mut read_buf = [0u8; 4096];

        loop {
            // 读取数据（带超时）
            let read_result = timeout(
                Duration::from_secs(Self::READ_TIMEOUT_SECS),
                stream.read(&mut read_buf),
            )
            .await;

            let n = match read_result {
                Ok(Ok(0)) => {
                    warn!("Connection closed by peer");
                    return Err(ClientError::ConnectionClosed);
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("Read error: {}", e);
                    return Err(ClientError::ConnectionFailed(e));
                }
                Err(_) => {
                    warn!(
                        "Read timeout ({}s), connection may be lost",
                        Self::READ_TIMEOUT_SECS
                    );
                    return Err(ClientError::ConnectionClosed);
                }
            };

            buf.extend_from_slice(&read_buf[..n]);
            debug!("Received {} bytes, buffer size: {}", n, buf.len());

            // 尝试解析消息
            while let Some(msg) = Message::decode(&mut buf)? {
                debug!(
                    "Decoded message: msg_id={:?}, payload_len={}",
                    msg.header.msg_id,
                    msg.payload.len()
                );

                if msg.header.msg_id == MsgId::Baseband {
                    self.handle_bb_message(&msg, &mut on_osd);
                }
            }
        }
    }
}

/// 创建一个带 channel 的 OSD 接收器
pub fn create_osd_receiver() -> (impl FnMut(&OsdPlot), mpsc::UnboundedReceiver<OsdPlot>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let callback = move |osd: &OsdPlot| {
        let _ = tx.send(osd.clone());
    };
    (callback, rx)
}
