//! 远程模式: 通过 SSH 远程执行 ar_logcat，同时采集 ar_dbg_client OSD 数据

use anyhow::{anyhow, Result};
use ar_dbg_client::{ArDbgClient, ClientConfig, OsdPlot};
use rslog::StreamWriter;
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// OSD 数据通道号
const OSD_CHANNEL: u8 = 1;

/// OSD 重连间隔（秒）
const OSD_RECONNECT_INTERVAL: u64 = 5;

/// 获取当前时间戳（毫秒）
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// SSH 客户端处理器
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

/// 将 OsdPlot 序列化为二进制
fn osd_to_bytes(osd: &OsdPlot) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);

    // role (1B)
    data.push(osd.role as u8);

    // DEV 字段
    data.push(osd.br_lock);
    data.push(osd.br_ldpc_error);
    data.extend_from_slice(&osd.br_snr_value.to_le_bytes());
    data.extend_from_slice(&osd.br_agc_value);
    data.push(osd.br_channel);
    data.push(osd.slot_tx_channel);
    data.push(osd.slot_rx_channel);
    data.push(osd.slot_rx_opt_channel);

    // AP 字段
    data.push(osd.fch_lock);
    data.push(osd.slot_lock);
    data.extend_from_slice(&osd.slot_ldpc_error.to_le_bytes());
    data.extend_from_slice(&osd.slot_snr_value.to_le_bytes());
    data.extend_from_slice(&osd.slot_ldpc_after_error.to_le_bytes());
    data.extend_from_slice(&osd.slot_agc_value);

    // 公共字段
    data.extend_from_slice(&osd.main_avr_pwr.to_le_bytes());
    data.extend_from_slice(&osd.opt_avr_pwr.to_le_bytes());
    data.push(osd.mcs_value);

    data
}

/// 运行远程模式
pub async fn run_remote(
    output: &str,
    max_size: u64,
    host: &str,
    port: u16,
    user: &str,
    password: Option<String>,
    key_path: Option<String>,
    cmd: &str,
    dbg_port: u16,
) -> Result<()> {
    let writer = Arc::new(Mutex::new(StreamWriter::new(output, max_size)?));
    let running = Arc::new(AtomicBool::new(true));

    info!(
        "logcat: Recording from remote '{}@{}:{}' to {} (max {} bytes)",
        user, host, port, output, max_size
    );
    info!("logcat: SSH command: {}", cmd);
    info!("logcat: DBG port: {}", dbg_port);
    info!("logcat: Flush: every 1000 lines or 10s idle");
    info!("logcat: Press Ctrl+C to stop");

    // 设置 Ctrl+C 处理
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        info!("logcat: Ctrl+C received, stopping...");
        running_clone.store(false, Ordering::SeqCst);
    })?;

    // 启动 OSD 采集任务
    let osd_writer = writer.clone();
    let osd_running = running.clone();
    let osd_host = host.to_string();
    let osd_count = Arc::new(AtomicU64::new(0));
    let osd_count_clone = osd_count.clone();

    let osd_task = tokio::spawn(async move {
        run_osd_collector(
            &osd_host,
            dbg_port,
            osd_writer,
            osd_running,
            osd_count_clone,
        )
        .await
    });

    // 运行 SSH logcat
    let ssh_result = run_ssh_logcat(
        writer.clone(),
        running.clone(),
        host,
        port,
        user,
        password,
        key_path,
        cmd,
    )
    .await;

    // 停止 OSD 采集
    running.store(false, Ordering::SeqCst);
    let _ = osd_task.await;

    // 最终同步
    {
        let mut w = writer.lock().await;
        w.sync()?;
    }

    info!(
        "logcat: OSD total: {} records",
        osd_count.load(Ordering::SeqCst)
    );

    ssh_result
}

/// OSD 数据采集（带自动重连）
async fn run_osd_collector(
    host: &str,
    port: u16,
    writer: Arc<Mutex<StreamWriter>>,
    running: Arc<AtomicBool>,
    osd_count: Arc<AtomicU64>,
) {
    info!(
        "osd: Starting OSD collector, connecting to {}:{}",
        host, port
    );

    let mut reconnect_count = 0u64;

    while running.load(Ordering::SeqCst) {
        let config = ClientConfig {
            host: host.to_string(),
            port,
        };
        let client = ArDbgClient::new(config);

        // 使用 channel 来接收 OSD 数据
        let (tx, mut rx) = tokio::sync::mpsc::channel::<OsdPlot>(1000);

        // 启动接收任务
        let recv_running = running.clone();
        let recv_task = tokio::spawn(async move {
            let result = client
                .start_osd_stream(move |osd: &OsdPlot| {
                    // 使用 try_send 避免阻塞
                    if let Err(e) = tx.try_send(osd.clone()) {
                        // 缓冲区满时忽略，不阻塞
                        if !matches!(e, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                            // Channel closed
                        }
                    }
                })
                .await;
            if recv_running.load(Ordering::SeqCst) {
                if let Err(e) = result {
                    warn!("osd: Connection error: {}", e);
                }
            }
        });

        info!("osd: Connected, receiving data...");

        // 处理接收到的数据
        loop {
            tokio::select! {
                osd = rx.recv() => {
                    match osd {
                        Some(osd_data) => {
                            let data = osd_to_bytes(&osd_data);
                            let ts = current_timestamp();
                            {
                                let mut w = writer.lock().await;
                                if let Err(e) = w.write_binary_ch(OSD_CHANNEL, ts, &data) {
                                    error!("osd: Write error: {}", e);
                                }
                            }
                            let count = osd_count.fetch_add(1, Ordering::SeqCst) + 1;
                            if count % 100 == 0 {
                                eprint!("\rosd: {} records", count);
                            }
                        }
                        None => {
                            // Channel closed, connection lost
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !running.load(Ordering::SeqCst) {
                        recv_task.abort();
                        return;
                    }
                }
            }
        }

        recv_task.abort();

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // 重连
        reconnect_count += 1;
        warn!(
            "osd: Connection lost, reconnecting in {}s (attempt #{})",
            OSD_RECONNECT_INTERVAL, reconnect_count
        );
        tokio::time::sleep(Duration::from_secs(OSD_RECONNECT_INTERVAL)).await;
    }

    info!("osd: Collector stopped, {} reconnects", reconnect_count);
}

/// SSH logcat 采集
async fn run_ssh_logcat(
    writer: Arc<Mutex<StreamWriter>>,
    running: Arc<AtomicBool>,
    host: &str,
    port: u16,
    user: &str,
    password: Option<String>,
    key_path: Option<String>,
    cmd: &str,
) -> Result<()> {
    // SSH 配置
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    // 连接 SSH
    info!("logcat: Connecting to {}:{}...", host, port);
    let mut session = client::connect(config, (host, port), SshHandler).await?;

    // 认证
    let auth_result = if let Some(ref key_path) = key_path {
        // 使用密钥认证
        info!("logcat: Authenticating with key: {}", key_path);
        let key_data = tokio::fs::read_to_string(key_path).await?;
        let key_pair = russh::keys::decode_secret_key(&key_data, None)?;
        let hash_alg = session.best_supported_rsa_hash().await?.flatten();
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);
        session.authenticate_publickey(user, key_with_hash).await?
    } else if let Some(ref password) = password {
        // 使用密码认证
        info!("logcat: Authenticating with password");
        session.authenticate_password(user, password).await?
    } else {
        // 尝试无密码认证
        warn!("logcat: No password or key provided, trying none auth");
        session.authenticate_none(user).await?
    };

    if !auth_result.success() {
        return Err(anyhow!("SSH authentication failed"));
    }
    info!("logcat: SSH authentication successful");

    // 打开通道并执行命令
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, cmd).await?;
    info!("logcat: Command started: {}", cmd);

    // 接收数据
    let mut line_count = 0u64;
    let mut flush_count = 0u64;
    let mut pending_lines = 0u64;
    let mut last_activity = Instant::now();
    let idle_timeout = Duration::from_secs(10);

    let mut line_buffer = Vec::new();

    loop {
        if !running.load(Ordering::SeqCst) {
            info!("logcat: Stopping due to signal");
            break;
        }

        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        last_activity = Instant::now();

                        // 按行处理数据
                        for &byte in data.as_ref() {
                            if byte == b'\n' {
                                if !line_buffer.is_empty() {
                                    // 存储到第一个二进制通道 (通道 0)
                                    {
                                        let mut w = writer.lock().await;
                                        w.write_binary_ch(0, current_timestamp(), &line_buffer)?;
                                    }
                                    line_count += 1;
                                    pending_lines += 1;
                                    line_buffer.clear();
                                }
                            } else if byte != b'\r' {
                                line_buffer.push(byte);
                            }
                        }

                        // 每 1000 行刷新一次
                        if pending_lines >= 1000 {
                            {
                                let mut w = writer.lock().await;
                                w.flush()?;
                            }
                            flush_count += 1;
                            pending_lines = 0;
                            eprint!(
                                "\rlogcat: {} lines, {} flushes",
                                line_count, flush_count
                            );
                        }
                    }
                    Some(russh::ChannelMsg::Eof) => {
                        info!("logcat: Remote command ended (EOF)");
                        break;
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        info!("logcat: Remote command exited with status: {}", exit_status);
                        break;
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                        // stderr
                        if ext == 1 {
                            let stderr = String::from_utf8_lossy(data.as_ref());
                            warn!("logcat: stderr: {}", stderr.trim());
                        }
                    }
                    None => {
                        info!("logcat: Channel closed");
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // 检查是否有未刷新的数据且超时
                if pending_lines > 0 && last_activity.elapsed() >= idle_timeout {
                    {
                        let mut w = writer.lock().await;
                        w.flush()?;
                    }
                    flush_count += 1;
                    eprint!(
                        "\rlogcat: {} lines, {} flushes (idle)",
                        line_count, flush_count
                    );
                    pending_lines = 0;
                    last_activity = Instant::now();
                }
            }
        }
    }

    // 处理剩余的数据
    if !line_buffer.is_empty() {
        let mut w = writer.lock().await;
        w.write_binary_ch(0, current_timestamp(), &line_buffer)?;
        line_count += 1;
        pending_lines += 1;
    }

    // 最后刷新
    if pending_lines > 0 {
        let mut w = writer.lock().await;
        w.flush()?;
        flush_count += 1;
    }

    info!(
        "\nlogcat: Done. Total {} lines, {} flushes",
        line_count, flush_count
    );

    Ok(())
}
