//! 本地模式: 本地执行 ar_logcat 命令

use anyhow::Result;
use rslog::StreamWriter;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::info;

/// 获取当前时间戳（毫秒）
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 运行本地模式
pub async fn run_local(output: &str, cmd: &str, max_size: u64) -> Result<()> {
    let mut writer = StreamWriter::new(output, max_size)?;

    info!(
        "logcat: Recording from '{}' to {} (max {} bytes)",
        cmd, output, max_size
    );
    info!("logcat: Flush: every 1000 lines or 10s idle");
    info!("logcat: Press Ctrl+C to stop");

    // 启动 ar_logcat 进程
    let child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.unwrap();

    // 使用通道在读取线程和主线程之间传递数据
    let (tx, rx) = mpsc::channel::<String>();

    // 读取线程
    let reader_thread = thread::spawn(move || {
        let input = BufReader::new(stdout);
        for line in input.lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break; // 接收端已关闭
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut line_count = 0u64;
    let mut flush_count = 0u64;
    let mut pending_lines = 0u64;
    let mut last_activity = Instant::now();
    let idle_timeout = Duration::from_secs(10);
    let check_interval = Duration::from_millis(100);

    loop {
        match rx.recv_timeout(check_interval) {
            Ok(line) => {
                last_activity = Instant::now();

                if !line.is_empty() {
                    // 存储到第一个二进制通道 (通道 0)
                    writer.write_binary_ch(0, current_timestamp(), line.as_bytes())?;
                }

                line_count += 1;
                pending_lines += 1;

                // 每 1000 行刷新一次
                if pending_lines >= 1000 {
                    writer.flush()?;
                    flush_count += 1;
                    pending_lines = 0;
                    eprint!(
                        "\rlogcat: {} lines, {} flushes (line)",
                        line_count, flush_count
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // 检查是否有未刷新的数据且超时
                if pending_lines > 0 && last_activity.elapsed() >= idle_timeout {
                    writer.flush()?;
                    flush_count += 1;
                    eprint!(
                        "\rlogcat: {} lines, {} flushes (idle)",
                        line_count, flush_count
                    );
                    pending_lines = 0;
                    last_activity = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // 读取线程结束
                break;
            }
        }
    }

    // 最后刷新
    if pending_lines > 0 {
        writer.flush()?;
        flush_count += 1;
    }
    writer.sync()?;

    let _ = reader_thread.join();
    info!(
        "logcat: Done. Total {} lines, {} flushes",
        line_count, flush_count
    );

    Ok(())
}
