//! 远程模式: 通过 SSH 远程执行 ar_logcat，同时采集寄存器跟踪数据

use crate::reg_meta::{RegTraceConfig, RegTraceDescriptor, CHUNK_MAGIC_CONFIG, CHUNK_MAGIC_DATA};
use anyhow::{anyhow, Result};
use ar_dbg_client::{ClientConfig, RegTraceClient, TraceRecord};
use rslog::BlockWriter;
use russh::client;
use russh::keys::{Algorithm, PrivateKeyWithHashAlg};
use russh::Preferred;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Logcat 文本通道号
const LOGCAT_CHANNEL: u8 = 0;

/// 寄存器数据通道号
const REG_CHANNEL: u8 = 1;

/// 重连间隔（秒）
const RECONNECT_INTERVAL: u64 = 5;

/// 批量写入间隔（秒）
const FLUSH_INTERVAL: u64 = 10;

/// 批量数据最大字节数
/// ChunkN 格式: MAGIC(4) + count(2) + records_data
/// BlockWriter 的 sub-record len 字段是 u16（最大 65535）
/// 所以 records_data 最大为 65535 - 6 = 65529 字节
/// 每条 record 48 字节，最多 1365 条
/// 这里设置为 60KB 以留出一些余量
const MAX_BATCH_BYTES: usize = 60 * 1024;

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

/// SSH 客户端处理器
struct SshHandler {
    /// 是否已经检查过服务器密钥
    checked: std::sync::atomic::AtomicBool,
}

impl SshHandler {
    fn new() -> Self {
        Self {
            checked: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        // 总是接受服务器密钥（跳过 known_hosts 检查）
        self.checked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        async { Ok(true) }
    }
}

/// 将单条寄存器记录打包:
/// 8字节时间戳(us) + 4字节seq_id + 2字节irq_type + 2字节data_len + 8字节valid_mask + raw_data
fn record_to_bytes(record: &TraceRecord) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 4 + 2 + 2 + 8 + record.raw_data.len());
    // 时间戳 (us) - 使用记录的原始时间戳
    let ts = record.timestamp_us;
    data.extend_from_slice(&ts.to_le_bytes());
    // seq_id
    data.extend_from_slice(&record.seq_id.to_le_bytes());
    // irq_type (u16)
    data.extend_from_slice(&record.irq_type.to_le_bytes());
    // data_len (u16) - raw_data 的长度
    data.extend_from_slice(&(record.raw_data.len() as u16).to_le_bytes());
    // valid_mask (u64)
    data.extend_from_slice(&record.valid_mask.to_le_bytes());
    // raw_data
    data.extend_from_slice(&record.raw_data);
    data
}

/// 打包配置描述块 (Chunk0)
/// 格式: [MAGIC:4B][item_count:1B][sample_div:1B][reserved:2B][items:N*8B]
/// 每个 item: [page:1B][offset:1B][width:1B][reserved:1B][irq_mask:2B][reserved:2B]
fn pack_config_chunk(config: &RegTraceConfig) -> Vec<u8> {
    let item_count = config.items.len() as u8;
    // 4(magic) + 1(count) + 1(div) + 2(reserved) + N*8(items)
    let mut data = Vec::with_capacity(8 + config.items.len() * 8);

    // Magic
    data.extend_from_slice(&CHUNK_MAGIC_CONFIG);
    // item_count
    data.push(item_count);
    // sample_div
    data.push(config.sample_div);
    // reserved
    data.extend_from_slice(&[0u8; 2]);

    // Items
    for item in &config.items {
        data.push(item.page);
        data.push(item.offset);
        data.push(item.width);
        data.push(0); // reserved
        data.extend_from_slice(&item.irq_mask.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]); // reserved
    }

    data
}

/// 打包数据块 (ChunkN)
/// 格式: [MAGIC:4B][record_count:2B][records:...]
fn pack_data_chunk(records_data: &[u8], record_count: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(6 + records_data.len());

    // Magic
    data.extend_from_slice(&CHUNK_MAGIC_DATA);
    // record_count
    data.extend_from_slice(&record_count.to_le_bytes());
    // records
    data.extend_from_slice(records_data);

    data
}

/// 写入配置描述块到 writer
/// 包含二进制配置块和 JSON descriptor
async fn write_reg_descriptor(
    writer: &Arc<Mutex<BlockWriter>>,
    config: &RegTraceConfig,
) -> Result<()> {
    // 写入二进制配置块
    let config_chunk = pack_config_chunk(config);
    {
        let mut w = writer.lock().await;
        w.write_binary_ch(REG_CHANNEL, &config_chunk)?;
    }

    // 同时写入 JSON descriptor (便于人工查看)
    let descriptor = RegTraceDescriptor::from_config(config);
    let json = serde_json::to_string(&descriptor)?;
    {
        let mut w = writer.lock().await;
        w.write_text_ch(REG_CHANNEL, &json)?;
    }
    Ok(())
}

/// 检查是否需要重新写入 descriptor（回绕发生时）
/// 返回当前的 wrap_count
async fn check_and_rewrite_descriptor(
    writer: &Arc<Mutex<BlockWriter>>,
    config: &RegTraceConfig,
    last_wrap_count: &mut u32,
) -> Result<()> {
    let current_wrap_count = {
        let w = writer.lock().await;
        w.session_stats().wrap_count
    };

    // 如果发生了新的回绕，需要重新写入 descriptor
    if current_wrap_count > *last_wrap_count {
        info!(
            "reg: Storage wrapped (count: {} -> {}), rewriting descriptor",
            *last_wrap_count, current_wrap_count
        );
        write_reg_descriptor(writer, config).await?;
        *last_wrap_count = current_wrap_count;
    }

    Ok(())
}

/// 运行远程模式
pub async fn run_remote(opts: RemoteOptions<'_>) -> Result<()> {
    // 使用 BlockWriter 进行块压缩写入
    // 阈值: 32KB 或 4000 条记录 (针对 Flash 优化压缩率，与 local 模式一致)
    let writer = Arc::new(Mutex::new(BlockWriter::with_threshold(
        opts.output,
        opts.max_size,
        32 * 1024,
        4000,
    )?));
    let running = Arc::new(AtomicBool::new(true));

    info!(
        "logcat: Recording from remote '{}@{}:{}' to {} (max {} bytes)",
        opts.user, opts.host, opts.ssh_port, opts.output, opts.max_size
    );
    info!("logcat: Block compression enabled (32KB/4000 records threshold)");
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

    // SSH 任务完成后，确保停止 reg 任务
    running.store(false, Ordering::SeqCst);

    // 等待寄存器任务完成（最多等待 3 秒）
    if let Some(handle) = reg_handle {
        let timeout = tokio::time::timeout(Duration::from_secs(3), handle).await;
        if timeout.is_err() {
            warn!("logcat: Reg task did not stop in time, forcing shutdown");
        }
    }

    // 最终刷新
    if let Ok(mut w) = writer.try_lock() {
        let _ = w.flush();
    }

    // 打印本次会话的写入统计
    if let Ok(w) = writer.try_lock() {
        let session = w.session_stats();
        let stats = w.stats();
        info!("logcat: Recording finished. {}", session);
        info!(
            "logcat: Storage: {:.1}KB/{:.1}KB used ({:.1}%)",
            stats.used_size as f64 / 1024.0,
            stats.max_size as f64 / 1024.0,
            stats.used_size as f64 / stats.max_size as f64 * 100.0
        );
    }

    let total_reg = reg_count.load(Ordering::Relaxed);
    info!("logcat: Total register records: {}", total_reg);

    Ok(())
}

/// 寄存器数据采集（带自动重连）
async fn run_reg_collector(
    host: &str,
    port: u16,
    config: RegTraceConfig,
    writer: Arc<Mutex<BlockWriter>>,
    running: Arc<AtomicBool>,
    reg_count: Arc<AtomicU64>,
) {
    info!("reg: Starting collector, connecting to {}:{}", host, port);

    let mut reconnect_count = 0u64;
    // 跟踪本次会话是否已写入 descriptor
    // 每次开机只在第一次写数据时写入 descriptor
    // 后续如果发生回绕覆盖了 descriptor，需要重新写入
    let mut descriptor_written = false;
    // 上次写入 descriptor 后是否发生过回绕
    let mut last_wrap_count = 0u32;

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
            &mut last_wrap_count,
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

/// 运行寄存器数据流接收（流式推送模式）
async fn run_reg_stream(
    mut stream: TcpStream,
    config: &RegTraceConfig,
    client: &RegTraceClient,
    writer: &Arc<Mutex<BlockWriter>>,
    running: &Arc<AtomicBool>,
    reg_count: &Arc<AtomicU64>,
    descriptor_written: &mut bool,
    last_wrap_count: &mut u32,
) -> Result<()> {
    use ar_dbg_client::protocol::{DataPushResponse, Message};
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;

    // 配置采集项
    let config_req = config.to_config_request();
    info!("reg: Configuring {} items", config_req.items.len());

    let config_resp = client.config(&mut stream, &config_req).await?;
    if config_resp.result != ar_dbg_client::ErrorCode::Ok {
        // 根据不同错误码提供更详细的错误信息
        let err_msg = match config_resp.result {
            ar_dbg_client::ErrorCode::TooManyItems => {
                format!(
                    "服务器拒绝配置: 合并后配置项数量仍超过 RPC 限制(62个)，请减少配置项数量 (当前: {} 项)",
                    config_req.items.len()
                )
            }
            other => format!("配置失败: {}", other),
        };
        return Err(anyhow!("{}", err_msg));
    }
    info!(
        "reg: Config OK: items={}, sample_div={}, buffer={}",
        config_resp.actual_items, config_resp.actual_sample_div, config_resp.actual_buffer_depth
    );

    // 配置成功后服务端会自动推送数据
    info!("reg: Streaming mode started (waiting for DATA_PUSH)");

    // 首次写入配置描述块 (Chunk0)
    if !*descriptor_written {
        write_reg_descriptor(writer, config).await?;
        *descriptor_written = true;
        // 记录当前的回绕次数
        {
            let w = writer.lock().await;
            *last_wrap_count = w.session_stats().wrap_count;
        }
        info!("reg: Config chunk (Chunk0) and descriptor written");
    }

    // 批量缓冲区
    let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut batch_count: u64 = 0;
    let mut last_flush = Instant::now();
    let flush_interval = Duration::from_secs(FLUSH_INTERVAL);

    // 流式接收缓冲区
    let mut buf = BytesMut::with_capacity(8192);
    let mut read_buf = [0u8; 4096];

    loop {
        // 检查停止信号
        if !running.load(Ordering::SeqCst) {
            info!("reg: Stopping stream due to signal");
            // 写入剩余批量数据 (打包为 ChunkN)
            if !batch.is_empty() {
                info!("reg: Writing final batch: {} records", batch_count);
                let data_chunk = pack_data_chunk(&batch, batch_count as u16);
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(REG_CHANNEL, &data_chunk) {
                    error!("reg: Final batch write error: {}", e);
                }
                // 确保数据被刷新到文件
                if let Err(e) = w.flush() {
                    error!("reg: Final flush error: {}", e);
                }
            } else {
                // 即使 batch 为空，也要 flush BlockWriter 的内部缓冲
                info!("reg: Flushing BlockWriter (batch empty)");
                let mut w = writer.lock().await;
                if let Err(e) = w.flush() {
                    error!("reg: Final flush error: {}", e);
                }
            }
            // 发送停止命令
            let _ = client.stop(&mut stream).await;
            return Ok(());
        }

        // 检查是否需要定时刷新批量数据 (打包为 ChunkN)
        if !batch.is_empty() && last_flush.elapsed() >= flush_interval {
            let data_chunk = pack_data_chunk(&batch, batch_count as u16);
            {
                let mut w = writer.lock().await;
                if let Err(e) = w.write_binary_ch(REG_CHANNEL, &data_chunk) {
                    error!("reg: Batch write error: {}", e);
                }
                // 刷新 BlockWriter 确保数据写入文件（只刷新寄存器通道）
                if let Err(e) = w.flush_channel_only(REG_CHANNEL) {
                    error!("reg: Flush error: {}", e);
                }
            }
            debug!(
                "reg: Periodic flush: {} records ({} bytes)",
                batch_count,
                batch.len()
            );
            batch.clear();
            batch_count = 0;
            last_flush = Instant::now();

            // 检查是否发生回绕，需要重新写入 descriptor
            if let Err(e) = check_and_rewrite_descriptor(writer, config, last_wrap_count).await {
                error!("reg: Failed to rewrite descriptor after wrap: {}", e);
            }
        }

        // 使用 select 同时检查停止信号和接收数据
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)), if !running.load(Ordering::SeqCst) => {
                continue;
            }
            result = stream.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        // 连接关闭
                        info!("reg: Connection closed by server");
                        if !batch.is_empty() {
                            let data_chunk = pack_data_chunk(&batch, batch_count as u16);
                            let mut w = writer.lock().await;
                            let _ = w.write_binary_ch(REG_CHANNEL, &data_chunk);
                            let _ = w.flush();
                        }
                        return Err(anyhow!("Connection closed by server"));
                    }
                    Ok(n) => {
                        buf.extend_from_slice(&read_buf[..n]);

                        // 尝试解析消息
                        while let Some(msg) = Message::decode(&mut buf)? {
                            if msg.header.cmd_id == ar_dbg_client::CmdId::DataPush {
                                // 解析推送数据
                                if let Some(data_resp) = DataPushResponse::from_payload(&msg.payload) {
                                    if data_resp.result == ar_dbg_client::ErrorCode::Ok {
                                        for record in &data_resp.records {
                                            let record_bytes = record_to_bytes(record);
                                            batch.extend_from_slice(&record_bytes);
                                            batch_count += 1;

                                            let count = reg_count.fetch_add(1, Ordering::SeqCst) + 1;
                                            if count % 100 == 0 {
                                                eprint!("\rreg: {} records", count);
                                            }
                                        }

                                        // 检查批量大小是否超过限制，如果超过则提前刷新
                                        if batch.len() >= MAX_BATCH_BYTES {
                                            let data_chunk = pack_data_chunk(&batch, batch_count as u16);
                                            {
                                                let mut w = writer.lock().await;
                                                if let Err(e) = w.write_binary_ch(REG_CHANNEL, &data_chunk) {
                                                    error!("reg: Batch write error (size limit): {}", e);
                                                }
                                                // 只刷新寄存器通道
                                                if let Err(e) = w.flush_channel_only(REG_CHANNEL) {
                                                    error!("reg: Flush error (size limit): {}", e);
                                                }
                                            }
                                            debug!(
                                                "reg: Size-triggered flush: {} records ({} bytes)",
                                                batch_count,
                                                batch.len()
                                            );
                                            batch.clear();
                                            batch_count = 0;
                                            last_flush = Instant::now();

                                            // 检查是否发生回绕，需要重新写入 descriptor
                                            if let Err(e) = check_and_rewrite_descriptor(writer, config, last_wrap_count).await {
                                                error!("reg: Failed to rewrite descriptor after wrap: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if running.load(Ordering::SeqCst) {
                            warn!("reg: Read error: {}", e);
                        }
                        if !batch.is_empty() {
                            let data_chunk = pack_data_chunk(&batch, batch_count as u16);
                            let mut w = writer.lock().await;
                            let _ = w.write_binary_ch(REG_CHANNEL, &data_chunk);
                            let _ = w.flush();
                        }
                        return Err(anyhow!("Read error: {}", e));
                    }
                }
            }
        }
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
    writer: Arc<Mutex<BlockWriter>>,
    running: Arc<AtomicBool>,
    _logcat_count: &AtomicU64,
) {
    // SSH 配置 - 添加 DSA 支持（dropbear 设备常用）
    // 默认的 Preferred 不包含 DSA，需要手动添加
    let mut preferred = Preferred::DEFAULT;
    // 在 key 算法列表前面添加 DSA，以支持老旧设备
    let mut key_algos: Vec<Algorithm> = vec![Algorithm::Dsa];
    key_algos.extend(preferred.key.iter().cloned());
    preferred.key = Cow::Owned(key_algos);

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        preferred,
        ..Default::default()
    });

    // 连接 SSH
    info!("logcat: Connecting to {}:{}...", host, port);
    let handler = SshHandler::new();
    let session = match client::connect(config, (host, port), handler).await {
        Ok(s) => s,
        Err(e) => {
            error!("logcat: SSH connection failed: {}", e);
            // 设置 running 为 false，通知其他任务停止
            running.store(false, Ordering::SeqCst);
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
                                        if let Err(e) = w.write_binary_ch(0, &line_buffer) {
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

                        // 每 1000 行刷新一次（只刷新 logcat 通道）
                        if pending_lines >= 1000 {
                            {
                                let mut w = writer.lock().await;
                                if let Err(e) = w.flush_channel_only(LOGCAT_CHANNEL) {
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
                // 检查是否有未刷新的数据且超时（只刷新 logcat 通道）
                if pending_lines > 0 && last_activity.elapsed() >= idle_timeout {
                    {
                        let mut w = writer.lock().await;
                        if let Err(e) = w.flush_channel_only(LOGCAT_CHANNEL) {
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
        if let Err(e) = w.write_binary_ch(0, &line_buffer) {
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
