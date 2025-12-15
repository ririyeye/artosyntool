//! 远程模式: 通过 SSH 远程执行 ar_logcat，同时采集寄存器跟踪数据

use crate::reg_meta::{RegTraceConfig, RegTraceDescriptor};
use anyhow::{anyhow, Result};
use ar_dbg_client::{ClientConfig, RegTraceClient, TraceRecord};
use rslog::StreamWriter;
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// 寄存器数据通道号
const REG_CHANNEL: u8 = 1;

/// 重连间隔（秒）
const RECONNECT_INTERVAL: u64 = 5;

/// 批量写入间隔（秒）
const FLUSH_INTERVAL: u64 = 10;

/// 远程模式选项
pub struct RemoteOptions<'a> {
    pub output: &'a str,
    pub max_size: u64,
    pub host: &'a str,
    pub ssh_port: u16,
    pub user: &'a str,
    pub password: Option<&'a str>,
    pub key: Option<&'a str>,
    pub cmd: &'a str,
    pub reg_port: u16,
    pub reg_config: Option<RegTraceConfig>,
}

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

/// 将单条寄存器记录打包: 8字节时间戳(ms) + 4字节seq_id + N*4字节values
fn record_to_bytes(ts: u64, record: &TraceRecord) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 4 + record.values.len() * 4);
    data.extend_from_slice(&ts.to_le_bytes());
    data.extend_from_slice(&record.seq_id.to_le_bytes());
    for v in &record.values {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data
}

/// 运行远程模式
pub async fn run_remote(opts: RemoteOptions<'_>) -> Result<()> {
    let writer = Arc::new(Mutex::new(StreamWriter::new(opts.output, opts.max_size)?));
    let running = Arc::new(AtomicBool::new(true));

    info!(
        "logcat: Recording from remote '{}@{}:{}' to {} (max {} bytes)",
        opts.user, opts.host, opts.ssh_port, opts.output, opts.max_size
    );
    info!("logcat: SSH command: {}", opts.cmd);

    if let Some(ref reg_config) = opts.reg_config {
        info!(
            "logcat: Reg trace: {}:{} ({} items)",
            opts.host,
            opts.reg_port,
            reg_config.items.len()
        );
    } else {
        info!("logcat: Reg trace: disabled (no config provided)");
    }
    info!("logcat: Flush: every 1000 lines or 10s idle");
    info!("logcat: Press Ctrl+C to stop");

    // 设置 Ctrl+C 处理
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        info!("logcat: Ctrl+C received, stopping...");
        running_clone.store(false, Ordering::SeqCst);
    })?;

    // 启动寄存器采集任务（如果有配置）
    let reg_count = Arc::new(AtomicU64::new(0));
    let reg_handle = if let Some(reg_config) = opts.reg_config.clone() {
        let reg_writer = writer.clone();
        let reg_running = running.clone();
        let reg_count_clone = reg_count.clone();
        let host = opts.host.to_string();
        let port = opts.reg_port;

        Some(tokio::spawn(async move {
            run_reg_collector(
                &host,
                port,
                reg_config,
                reg_writer,
                reg_running,
                reg_count_clone,
            )
            .await;
        }))
    } else {
        None
    };

    // 启动 SSH logcat 任务
    let ssh_writer = writer.clone();
    let ssh_running = running.clone();
    let host = opts.host.to_string();
    let ssh_port = opts.ssh_port;
    let user = opts.user.to_string();
    let password = opts.password.map(|s| s.to_string());
    let key = opts.key.map(|s| s.to_string());
    let cmd = opts.cmd.to_string();

    let ssh_handle = tokio::spawn(async move {
        let logcat_count = AtomicU64::new(0);
        run_ssh_logcat(
            &host,
            ssh_port,
            &user,
            password,
            key,
            &cmd,
            ssh_writer,
            ssh_running,
            &logcat_count,
        )
        .await;
    });

    // 等待 SSH 任务完成
    let _ = ssh_handle.await;

    // 等待寄存器任务完成
    if let Some(handle) = reg_handle {
        let _ = handle.await;
    }

    // 最终刷新
    if let Ok(mut w) = writer.try_lock() {
        let _ = w.flush();
    }

    let total_reg = reg_count.load(Ordering::Relaxed);
    info!(
        "logcat: Recording finished. Total register records: {}",
        total_reg
    );

    Ok(())
}

/// 寄存器数据采集（带自动重连）
async fn run_reg_collector(
    host: &str,
    port: u16,
    config: RegTraceConfig,
    writer: Arc<Mutex<StreamWriter>>,
    running: Arc<AtomicBool>,
    reg_count: Arc<AtomicU64>,
) {
    info!("reg: Starting collector, connecting to {}:{}", host, port);

    let mut reconnect_count = 0u64;
    let mut descriptor_written = false;

    let client_config = ClientConfig {
        host: host.to_string(),
        port,
        timeout_secs: 5,
    };
    let client = RegTraceClient::new(client_config);

    while running.load(Ordering::SeqCst) {
        // 尝试连接
        let stream = match client.connect().await {
            Ok(s) => s,
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    warn!("reg: Connection failed: {}", e);
                    // 可中断的等待
                    for _ in 0..RECONNECT_INTERVAL * 10 {
                        if !running.load(Ordering::SeqCst) {
                            info!("reg: Collector stopped during reconnect wait");
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                continue;
            }
        };

        info!("reg: Connected to {}:{}", config.host, config.port);

        // 运行寄存器采集流
        if let Err(e) = run_reg_stream(
            stream,
            &config,
            &client,
            &writer,
            &running,
            &reg_count,
            &mut descriptor_written,
        )
        .await
        {
            if running.load(Ordering::SeqCst) {
                warn!("reg: Stream error: {}", e);
            }
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // 重连
        reconnect_count += 1;
        warn!(
            "reg: Connection lost, reconnecting in {}s (attempt #{})",
            RECONNECT_INTERVAL, reconnect_count
        );

        // 可中断的等待
        for _ in 0..RECONNECT_INTERVAL * 10 {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    info!("reg: Collector stopped, {} reconnects", reconnect_count);
}

/// 运行寄存器数据流接收（可中断，批量写入）
async fn run_reg_stream(
    mut stream: TcpStream,
    config: &RegTraceConfig,
    client: &RegTraceClient,
    writer: &Arc<Mutex<StreamWriter>>,
    running: &Arc<AtomicBool>,
    reg_count: &Arc<AtomicU64>,
    descriptor_written: &mut bool,
) -> Result<()> {
    // 配置采集项
    let config_req = config.to_config_request();
    info!("reg: Configuring {} items", config_req.items.len());

    let config_resp = client.config(&mut stream, &config_req).await?;
    if config_resp.result != ar_dbg_client::ErrorCode::Ok {
        return Err(anyhow!("Config failed: {}", config_resp.result));
    }
    info!(
        "reg: Config OK: items={}, sample_div={}, buffer={}",
        config_resp.actual_items, config_resp.actual_sample_div, config_resp.actual_buffer_depth
    );

    // 启动采集
    let start_resp = client.start(&mut stream, true).await?;
    if start_resp.result != ar_dbg_client::ErrorCode::Ok {
        return Err(anyhow!("Start failed: {}", start_resp.result));
    }
    info!("reg: Trace started");

    // 首次写入 descriptor
    if !*descriptor_written {
        let descriptor = RegTraceDescriptor::from_config(config);
        let json = serde_json::to_string(&descriptor)?;
        let ts = current_timestamp();
        {
            let mut w = writer.lock().await;
            w.write_text_ch(REG_CHANNEL, ts, &json)?;
        }
        *descriptor_written = true;
        info!("reg: Descriptor written");
    }

    // 批量缓冲区
    let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut batch_count: u64 = 0;
    let mut last_flush = Instant::now();
    let flush_interval = Duration::from_secs(FLUSH_INTERVAL);
    let poll_interval = Duration::from_millis(500);

    loop {
        // 检查停止信号
        if !running.load(Ordering::SeqCst) {
            info!("reg: Stopping stream due to signal");
            // 写入剩余批量数据
            if !batch.is_empty() {
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(REG_CHANNEL, current_timestamp(), &batch) {
                    error!("reg: Final batch write error: {}", e);
                }
            }
            // 发送停止命令
            let _ = client.stop(&mut stream).await;
            return Ok(());
        }

        // 检查是否需要定时刷新批量数据
        if !batch.is_empty() && last_flush.elapsed() >= flush_interval {
            let ts = current_timestamp();
            {
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(REG_CHANNEL, ts, &batch) {
                    error!("reg: Batch write error: {}", e);
                }
            }
            debug!(
                "reg: Flushed {} records ({} bytes)",
                batch_count,
                batch.len()
            );
            batch.clear();
            batch_count = 0;
            last_flush = Instant::now();
        }

        // 查询状态并拉取数据
        let status = match client.status(&mut stream).await {
            Ok(s) => s,
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    warn!("reg: Status query failed: {}", e);
                }
                // 写入剩余批量数据
                if !batch.is_empty() {
                    let mut w = writer.lock().await;
                    let _ = w.write_binary_ch(REG_CHANNEL, current_timestamp(), &batch);
                }
                return Err(anyhow!("Status query failed: {}", e));
            }
        };

        if status.record_count > 0 {
            // 拉取数据
            match client.fetch(&mut stream, 50, true).await {
                Ok(fetch_resp) => {
                    if fetch_resp.result == ar_dbg_client::ErrorCode::Ok {
                        let ts = current_timestamp();
                        for record in &fetch_resp.records {
                            let record_bytes = record_to_bytes(ts, record);
                            batch.extend_from_slice(&record_bytes);
                            batch_count += 1;

                            let count = reg_count.fetch_add(1, Ordering::SeqCst) + 1;
                            if count % 100 == 0 {
                                eprint!("\rreg: {} records", count);
                            }
                        }
                    }
                }
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        warn!("reg: Fetch failed: {}", e);
                    }
                }
            }
        }

        // 等待下次轮询
        tokio::time::sleep(poll_interval).await;
    }
}

/// SSH logcat 采集
async fn run_ssh_logcat(
    host: &str,
    port: u16,
    user: &str,
    password: Option<String>,
    key_path: Option<String>,
    cmd: &str,
    writer: Arc<Mutex<StreamWriter>>,
    running: Arc<AtomicBool>,
    _logcat_count: &AtomicU64,
) {
    // SSH 配置
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    // 连接 SSH
    info!("logcat: Connecting to {}:{}...", host, port);
    let session = match client::connect(config, (host, port), SshHandler).await {
        Ok(s) => s,
        Err(e) => {
            error!("logcat: SSH connection failed: {}", e);
            return;
        }
    };

    let mut session = session;

    // 认证
    let auth_result = if let Some(ref key_path) = key_path {
        // 使用密钥认证
        info!("logcat: Authenticating with key: {}", key_path);
        let key_data = match tokio::fs::read_to_string(key_path).await {
            Ok(k) => k,
            Err(e) => {
                error!("logcat: Failed to read key file: {}", e);
                return;
            }
        };
        let key_pair = match russh::keys::decode_secret_key(&key_data, None) {
            Ok(k) => k,
            Err(e) => {
                error!("logcat: Failed to decode key: {}", e);
                return;
            }
        };
        let hash_alg = match session.best_supported_rsa_hash().await {
            Ok(h) => h.flatten(),
            Err(e) => {
                error!("logcat: Failed to get RSA hash: {}", e);
                return;
            }
        };
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);
        match session.authenticate_publickey(user, key_with_hash).await {
            Ok(r) => r,
            Err(e) => {
                error!("logcat: Publickey auth failed: {}", e);
                return;
            }
        }
    } else if let Some(ref password) = password {
        // 使用密码认证
        info!("logcat: Authenticating with password");
        match session.authenticate_password(user, password).await {
            Ok(r) => r,
            Err(e) => {
                error!("logcat: Password auth failed: {}", e);
                return;
            }
        }
    } else {
        // 尝试无密码认证
        warn!("logcat: No password or key provided, trying none auth");
        match session.authenticate_none(user).await {
            Ok(r) => r,
            Err(e) => {
                error!("logcat: None auth failed: {}", e);
                return;
            }
        }
    };

    if !auth_result.success() {
        error!("logcat: SSH authentication failed");
        return;
    }
    info!("logcat: SSH authentication successful");

    // 打开通道并执行命令
    let mut channel = match session.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            error!("logcat: Failed to open channel: {}", e);
            return;
        }
    };
    if let Err(e) = channel.exec(true, cmd).await {
        error!("logcat: Failed to exec command: {}", e);
        return;
    }
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
                                        if let Err(e) = w.write_binary_ch(0, current_timestamp(), &line_buffer) {
                                            error!("logcat: Write error: {}", e);
                                        }
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
                                if let Err(e) = w.flush() {
                                    error!("logcat: Flush error: {}", e);
                                }
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
                        if let Err(e) = w.flush() {
                            error!("logcat: Idle flush error: {}", e);
                        }
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
        if let Err(e) = w.write_binary_ch(0, current_timestamp(), &line_buffer) {
            error!("logcat: Final write error: {}", e);
        }
        line_count += 1;
        pending_lines += 1;
    }

    // 最后刷新
    if pending_lines > 0 {
        let mut w = writer.lock().await;
        if let Err(e) = w.flush() {
            error!("logcat: Final flush error: {}", e);
        }
        flush_count += 1;
    }

    info!(
        "\nlogcat: Done. Total {} lines, {} flushes",
        line_count, flush_count
    );
}
