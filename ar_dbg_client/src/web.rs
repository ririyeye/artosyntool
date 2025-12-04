//! Web 服务器模块 - 提供实时 OSD 数据展示
//!
//! 通过 WebSocket 推送 OSD 数据到前端网页，使用图表展示变化曲线

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info};

use crate::osd::{DeviceRole, OsdPlot};

/// 内嵌的 HTML 页面
const INDEX_HTML: &str = include_str!("../static/index.html");

/// WebSocket 推送的 OSD 数据结构
#[derive(Debug, Clone, Serialize)]
pub struct OsdWebData {
    /// 时间戳 (毫秒)
    pub timestamp: u64,
    /// 设备角色
    pub role: String,
    /// SNR (dB)
    pub snr_db: f32,
    /// 原始 SNR 值
    pub snr_raw: u16,
    /// LDPC 错误
    pub ldpc_error: u16,
    /// 锁定状态
    pub locked: bool,
    /// AGC 值 (4个)
    pub agc: [u8; 4],
    /// 主功率
    pub main_pwr: u16,
    /// 备选功率
    pub opt_pwr: u16,
    /// MCS 值
    pub mcs: u8,
    /// 通道信息
    pub channel: ChannelInfo,
    /// AP 特有字段
    pub ap_fields: Option<ApFields>,
    /// DEV 特有字段
    pub dev_fields: Option<DevFields>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelInfo {
    pub br_channel: u8,
    pub slot_tx: u8,
    pub slot_rx: u8,
    pub slot_rx_opt: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApFields {
    pub fch_lock: u8,
    pub slot_lock: u8,
    pub ldpc_after_error: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevFields {
    pub br_lock: u8,
    pub br_ldpc_error: u8,
}

impl From<&OsdPlot> for OsdWebData {
    fn from(osd: &OsdPlot) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let (snr_raw, agc) = match osd.role {
            DeviceRole::Dev => (osd.br_snr_value, osd.br_agc_value),
            DeviceRole::Ap => (osd.slot_snr_value, osd.slot_agc_value),
        };

        Self {
            timestamp,
            role: osd.role.to_string(),
            snr_db: osd.snr_db(),
            snr_raw,
            ldpc_error: osd.ldpc_error(),
            locked: osd.is_locked(),
            agc,
            main_pwr: osd.main_avr_pwr,
            opt_pwr: osd.opt_avr_pwr,
            mcs: osd.mcs_value,
            channel: ChannelInfo {
                br_channel: osd.br_channel,
                slot_tx: osd.slot_tx_channel,
                slot_rx: osd.slot_rx_channel,
                slot_rx_opt: osd.slot_rx_opt_channel,
            },
            ap_fields: if osd.role == DeviceRole::Ap {
                Some(ApFields {
                    fch_lock: osd.fch_lock,
                    slot_lock: osd.slot_lock,
                    ldpc_after_error: osd.slot_ldpc_after_error,
                })
            } else {
                None
            },
            dev_fields: if osd.role == DeviceRole::Dev {
                Some(DevFields {
                    br_lock: osd.br_lock,
                    br_ldpc_error: osd.br_ldpc_error,
                })
            } else {
                None
            },
        }
    }
}

/// Web 服务器共享状态
pub struct WebState {
    /// OSD 数据广播通道
    pub tx: broadcast::Sender<OsdWebData>,
}

impl WebState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }

    /// 广播 OSD 数据
    pub fn broadcast(&self, osd: &OsdPlot) {
        let data = OsdWebData::from(osd);
        let _ = self.tx.send(data);
    }
}

/// 创建 Web 服务器路由
pub fn create_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// 首页处理
async fn index_handler() -> impl IntoResponse {
    Html(INDEX_HTML)
}

/// WebSocket 处理
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<WebState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// 处理 WebSocket 连接
async fn handle_socket(socket: WebSocket, state: Arc<WebState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    info!("New WebSocket connection");

    // 发送任务
    let send_task = tokio::spawn(async move {
        while let Ok(data) = rx.recv().await {
            match serde_json::to_string(&data) {
                Ok(json) => {
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize OSD data: {}", e);
                }
            }
        }
    });

    // 接收任务（主要用于检测断开连接）
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => break,
                Ok(Message::Ping(_)) => {
                    debug!("Received ping");
                    // Pong 会自动处理
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    // 等待任一任务完成
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    info!("WebSocket connection closed");
}

/// 启动 Web 服务器
pub async fn start_web_server(state: Arc<WebState>, port: u16) -> Result<(), std::io::Error> {
    let app = create_router(state);
    let addr = format!("0.0.0.0:{}", port);

    info!("Starting web server on http://{}", addr);
    info!("Open http://localhost:{} in your browser", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
