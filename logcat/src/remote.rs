//! 远程模式: 通过 SSH 远程执行 ar_logcat，同时采集 ar_dbg_client OSD 数据

use crate::osd_meta::{apply_role_from_payload, build_osd_descriptor};
use anyhow::{anyhow, Result};
use ar_dbg_client::OsdPlot;
use bytes::BytesMut;
use rslog::StreamWriter;
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// OSD 数据通道号
const OSD_CHANNEL: u8 = 1;

/// OSD 重连间隔（秒）
const OSD_RECONNECT_INTERVAL: u64 = 5;

/// OSD 批量写入间隔（秒）
const OSD_FLUSH_INTERVAL: u64 = 10;

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

/// 将单条 OSD 记录打包: 8字节时间戳(ms) + 1字节角色 + 2字节长度 + 原始OSD数据
fn osd_record_to_bytes(ts: u64, osd: &OsdPlot) -> Vec<u8> {
    let len = osd.raw_data.len() as u16;
    let mut data = Vec::with_capacity(8 + 1 + 2 + osd.raw_data.len());
    data.extend_from_slice(&ts.to_le_bytes());
    data.push(osd.role as u8);
    data.extend_from_slice(&len.to_le_bytes());
    data.extend_from_slice(&osd.raw_data);
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

/// OSD 数据采集（带自动重连）- 可中断版本
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
    let mut descriptor_written = false;

    while running.load(Ordering::SeqCst) {
        // 尝试连接
        let addr = format!("{}:{}", host, port);
        let stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    warn!("osd: Connection failed: {}", e);
                    // 可中断的等待
                    for _ in 0..OSD_RECONNECT_INTERVAL * 10 {
                        if !running.load(Ordering::SeqCst) {
                            info!("osd: Collector stopped during reconnect wait");
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                continue;
            }
        };

        info!("osd: Connected to {}", addr);

        // 运行 OSD 流接收
        if let Err(e) = run_osd_stream(
            stream,
            &writer,
            &running,
            &osd_count,
            &mut descriptor_written,
        )
        .await
        {
            if running.load(Ordering::SeqCst) {
                warn!("osd: Stream error: {}", e);
            }
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // 重连
        reconnect_count += 1;
        warn!(
            "osd: Connection lost, reconnecting in {}s (attempt #{})",
            OSD_RECONNECT_INTERVAL, reconnect_count
        );

        // 可中断的等待
        for _ in 0..OSD_RECONNECT_INTERVAL * 10 {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    info!("osd: Collector stopped, {} reconnects", reconnect_count);
}

/// 运行 OSD 数据流接收（可中断，批量写入）
async fn run_osd_stream(
    mut stream: TcpStream,
    writer: &Arc<Mutex<StreamWriter>>,
    running: &Arc<AtomicBool>,
    osd_count: &Arc<AtomicU64>,
    descriptor_written: &mut bool,
) -> Result<()> {
    use ar_dbg_client::protocol::{self, Message, MsgId};

    // 发送启动 OSD 命令
    let start_msg = protocol::create_start_osd_msg(0);
    let data = start_msg.encode();
    stream.write_all(&data).await?;
    info!("osd: Sent start OSD command");

    let mut buf = BytesMut::with_capacity(8192);
    let mut read_buf = [0u8; 4096];

    // OSD 批量缓冲区: 每条记录格式 [ts:8B][role:1B][raw_data]
    let mut osd_batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut batch_count: u64 = 0;
    let mut last_flush = Instant::now();
    let flush_interval = Duration::from_secs(OSD_FLUSH_INTERVAL);

    loop {
        // 每次循环检查停止信号
        if !running.load(Ordering::SeqCst) {
            info!("osd: Stopping stream due to signal");
            // 写入剩余批量数据
            if !osd_batch.is_empty() {
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(OSD_CHANNEL, current_timestamp(), &osd_batch) {
                    error!("osd: Final batch write error: {}", e);
                }
            }
            // 发送停止 OSD 命令
            let stop_msg = protocol::create_stop_osd_msg(1);
            let stop_data = stop_msg.encode();
            let _ = stream.write_all(&stop_data).await;
            return Ok(());
        }

        // 检查是否需要定时刷新批量数据
        if !osd_batch.is_empty() && last_flush.elapsed() >= flush_interval {
            let ts = current_timestamp();
            {
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(OSD_CHANNEL, ts, &osd_batch) {
                    error!("osd: Batch write error: {}", e);
                }
            }
            debug!(
                "osd: Flushed {} records ({} bytes)",
                batch_count,
                osd_batch.len()
            );
            osd_batch.clear();
            batch_count = 0;
            last_flush = Instant::now();
        }

        // 使用带超时的读取，这样可以定期检查停止信号
        let read_result =
            tokio::time::timeout(Duration::from_millis(100), stream.read(&mut read_buf)).await;

        match read_result {
            Ok(Ok(0)) => {
                warn!("osd: Connection closed by peer");
                // 写入剩余批量数据
                if !osd_batch.is_empty() {
                    let mut w = writer.lock().await;
                    if let Err(e) = w.write_binary_ch(OSD_CHANNEL, current_timestamp(), &osd_batch)
                    {
                        error!("osd: Final batch write error: {}", e);
                    }
                }
                return Err(anyhow!("Connection closed"));
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&read_buf[..n]);
                debug!("osd: Received {} bytes, buffer size: {}", n, buf.len());

                // 解析消息
                while let Some(msg) = Message::decode(&mut buf)? {
                    if msg.header.msg_id == MsgId::Baseband {
                        if let Some(osd) = parse_osd_from_bb_message(&msg) {
                            let ts = current_timestamp();

                            // 首次写入 descriptor
                            if !*descriptor_written {
                                let mut w = writer.lock().await;
                                match serde_json::to_string(&build_osd_descriptor(osd.role)) {
                                    Ok(json) => {
                                        if let Err(e) = w.write_text_ch(OSD_CHANNEL, ts, &json) {
                                            error!("osd: Write descriptor error: {}", e);
                                        } else {
                                            *descriptor_written = true;
                                        }
                                    }
                                    Err(e) => error!("osd: Serialize descriptor error: {}", e),
                                }
                            }

                            // 追加到批量缓冲区
                            let record = osd_record_to_bytes(ts, &osd);
                            osd_batch.extend_from_slice(&record);
                            batch_count += 1;

                            let count = osd_count.fetch_add(1, Ordering::SeqCst) + 1;
                            if count % 100 == 0 {
                                eprint!("\rosd: {} records", count);
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                // 写入剩余批量数据
                if !osd_batch.is_empty() {
                    let mut w = writer.lock().await;
                    if let Err(e) = w.write_binary_ch(OSD_CHANNEL, current_timestamp(), &osd_batch)
                    {
                        error!("osd: Final batch write error: {}", e);
                    }
                }
                return Err(anyhow!("Read error: {}", e));
            }
            Err(_) => {
                // 超时，继续循环检查停止信号和定时刷新
            }
        }
    }
}

/// 从 BB 消息中解析 OSD 数据
fn parse_osd_from_bb_message(msg: &ar_dbg_client::protocol::Message) -> Option<OsdPlot> {
    use ar_dbg_client::protocol::{BbCmd, BbRcvMsgHeader};

    if msg.payload.len() < 2 {
        return None;
    }

    let rcv_header = BbRcvMsgHeader::from_bytes(&msg.payload)?;

    if rcv_header.bb_msg_id == BbCmd::GetOsdInfo.to_local_u8() {
        let osd_data = &msg.payload[2..];
        apply_role_from_payload(osd_data);
        OsdPlot::from_bytes_debug(osd_data)
    } else {
        None
    }
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
