//! rslog 命令行工具
//!
//! 用法：
//!   rslog                                                   # 默认记录（ar_logcat -> /factory/rslog.dat）
//!   rslog record                                            # 记录（ar_logcat -> /factory/rslog.dat）
//!   rslog dump [input]                                      # 导出日志（按通道输出到 input.log/ 目录）
//!   rslog stats [input]                                     # 显示统计

use clap::{Parser, Subcommand};
use rslog::{StreamLog, StreamWriter};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "rslog")]
#[command(about = "Embedded ring log storage system", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 记录日志（紧凑流模式）
    Record {
        /// 输出文件路径
        #[arg(short, long, default_value = "/factory/rslog.dat")]
        output: String,

        /// logcat 命令（默认 ar_logcat）
        #[arg(short, long, default_value = "ar_logcat")]
        cmd: String,

        /// 最大存储大小（字节）
        #[arg(short, long, default_value = "3145728")]
        max_size: u64,
    },

    /// 导出日志（按通道输出到 input.log/ 目录）
    Dump {
        /// 输入文件路径
        #[arg(default_value = "/factory/rslog.dat")]
        input: String,
    },

    /// 显示统计信息
    Stats {
        /// 输入文件路径
        #[arg(default_value = "/factory/rslog.dat")]
        input: String,
    },
}

// 默认参数
const DEFAULT_OUTPUT: &str = "/factory/rslog.dat";
const DEFAULT_CMD: &str = "ar_logcat";
const DEFAULT_MAX_SIZE: u64 = 3145728; // 3MB

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // 无子命令时，默认执行 record
        None => cmd_record(DEFAULT_OUTPUT, DEFAULT_CMD, DEFAULT_MAX_SIZE),
        Some(Commands::Record {
            output,
            cmd,
            max_size,
        }) => cmd_record(&output, &cmd, max_size),
        Some(Commands::Dump { input }) => cmd_dump(&input),
        Some(Commands::Stats { input }) => cmd_stats(&input),
    }
}

/// 获取当前时间戳（毫秒）
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 记录日志
fn cmd_record(output: &str, cmd: &str, max_size: u64) -> io::Result<()> {
    let mut writer = StreamWriter::new(output, max_size)?;

    eprintln!(
        "rslog: Recording from '{}' to {} (max {} bytes)",
        cmd, output, max_size
    );
    eprintln!("rslog: Flush: every 1000 lines or 10s idle");
    eprintln!("rslog: Press Ctrl+C to stop");

    // 从命令输出读取
    let child = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(std::process::Stdio::piped())
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
                    // 直接存储原始行，使用当前时间戳
                    writer.write_text(current_timestamp(), &line)?;
                }

                line_count += 1;
                pending_lines += 1;

                // 每 1000 行刷新一次
                if pending_lines >= 1000 {
                    writer.flush()?;
                    flush_count += 1;
                    pending_lines = 0;
                    eprint!(
                        "\rrslog: {} lines, {} flushes (line)",
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
                        "\rrslog: {} lines, {} flushes (idle)",
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
    eprintln!(
        "\nrslog: Done. Total {} lines, {} flushes",
        line_count, flush_count
    );

    Ok(())
}

/// 导出日志（按通道输出到 input.log/ 目录）
fn cmd_dump(input: &str) -> io::Result<()> {
    use std::collections::HashMap;
    use std::io::BufWriter;

    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB 缓冲

    // 输出目录: input.log/
    let output_dir = format!("{}.log", input);

    println!("导出 {} -> {}/", input, output_dir);

    // 创建输出目录
    std::fs::create_dir_all(&output_dir)?;

    let mut log = StreamLog::open(input, None)?;
    let (entries, errors) = log.read_all_tolerant();

    if errors > 0 {
        eprintln!("发现 {} 处损坏数据", errors);
    }

    // 按通道分组，使用 BufWriter 缓冲
    let mut channel_files: HashMap<u8, (bool, BufWriter<File>)> = HashMap::new();
    let mut channel_counts: HashMap<u8, u64> = HashMap::new();

    for entry in &entries {
        let ch = entry.channel();
        let is_binary = entry.is_binary();

        // 获取或创建文件（带缓冲）
        let file = channel_files.entry(ch).or_insert_with(|| {
            let ext = if is_binary { "bin" } else { "txt" };
            let path = format!("{}/{}.{}", output_dir, ch, ext);
            let f = File::create(&path).expect(&format!("无法创建 {}", path));
            println!("  创建 {}", path);
            (is_binary, BufWriter::with_capacity(BUFFER_SIZE, f))
        });

        *channel_counts.entry(ch).or_insert(0) += 1;

        if is_binary {
            // 二进制：每条记录格式 ts_ms(8B) + len(4B) + data
            if let Some(data) = entry.as_binary() {
                let ts_ms = entry.timestamp_ms;
                let len = data.len() as u32;
                file.1.write_all(&ts_ms.to_le_bytes())?;
                file.1.write_all(&len.to_le_bytes())?;
                file.1.write_all(&data)?;
            }
        } else {
            // 文本：每行一条，显示毫秒时间戳
            if let Some(text) = entry.as_text() {
                let ts_ms = entry.timestamp_ms;
                writeln!(file.1, "[{:>13}] {}", ts_ms, text)?;
            }
        }
    }

    // 刷新所有缓冲
    for (_, (_, writer)) in channel_files.iter_mut() {
        writer.flush()?;
    }

    // 汇总
    println!("\n导出完成：");
    let mut channels: Vec<_> = channel_counts.iter().collect();
    channels.sort_by_key(|(ch, _)| *ch);

    for (ch, count) in channels {
        let (is_bin, _) = channel_files.get(ch).unwrap();
        let ext = if *is_bin { "bin" } else { "txt" };
        println!("  通道 {}: {} 条 -> {}.{}", ch, count, ch, ext);
    }

    println!("共导出 {} 条日志", entries.len());

    Ok(())
}

/// 显示统计信息
fn cmd_stats(input: &str) -> io::Result<()> {
    use std::collections::HashMap;

    let mut log = StreamLog::open(input, None)?;
    let stats = log.stats();

    // 基本统计
    println!("Stream Log Statistics:");
    println!(
        "  Max size: {} bytes ({:.1} KB)",
        stats.max_size,
        stats.max_size as f64 / 1024.0
    );
    println!(
        "  Used: {} bytes ({:.1}%)",
        stats.used_size,
        stats.used_size as f64 / stats.max_size as f64 * 100.0
    );
    println!("  Write pos: {}", stats.write_pos);
    println!("  Total entries: {}", stats.global_seq);
    println!("  Boot count: {}", stats.boot_count);

    // 读取数据统计通道
    let (entries, errors) = log.read_all_tolerant();

    if errors > 0 {
        println!("  Corrupted: {} entries", errors);
    }

    if !entries.is_empty() {
        // 按通道统计
        let mut channel_stats: HashMap<u8, (u64, u64, bool)> = HashMap::new(); // (count, bytes, is_binary)

        for entry in &entries {
            let ch = entry.channel();
            let is_binary = entry.is_binary();
            let size = entry.data.len() as u64;

            let stat = channel_stats.entry(ch).or_insert((0, 0, is_binary));
            stat.0 += 1;
            stat.1 += size;
        }

        println!("\nChannel Statistics:");
        let mut channels: Vec<_> = channel_stats.iter().collect();
        channels.sort_by_key(|(ch, _)| *ch);

        for (ch, (count, bytes, is_bin)) in channels {
            let type_str = if *is_bin { "binary" } else { "text" };
            println!(
                "  CH{}: {} entries, {} bytes ({})",
                ch, count, bytes, type_str
            );
        }

        println!("\nReadable entries: {}", entries.len());
    }

    Ok(())
}
