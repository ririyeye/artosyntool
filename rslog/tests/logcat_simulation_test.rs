//! logcat 日志写入模拟测试
//!
//! 测试流程：
//! 1. 解压 test_log/sky.txt.gz 到临时文件
//! 2. 逐行读取日志，解析时间戳
//! 3. 按时间阈值（10s 空闲）和行数阈值（1000 行）批量写入 rslog
//! 4. 检查压缩率
//! 5. 还原日志并与原始对比，验证无数据丢失

use flate2::read::GzDecoder;
use rslog::{BlockWriter, StreamLog};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

/// 解析日志行的时间戳（毫秒）
/// 格式: [283342615][8454573c][ALWAYS] ...
/// 返回 (时间戳ms, 原始行)
fn parse_log_line(line: &str) -> Option<(u64, &str)> {
    if !line.starts_with('[') {
        return None;
    }

    // 找第一个 ] 的位置
    let end_bracket = line.find(']')?;
    let ts_str = &line[1..end_bracket];

    // 解析时间戳
    let ts: u64 = ts_str.parse().ok()?;
    Some((ts, line))
}

/// 解压 gzip 文件到字符串
fn decompress_gzip(gz_path: &Path) -> std::io::Result<String> {
    let file = File::open(gz_path)?;
    let mut decoder = GzDecoder::new(file);
    let mut content = String::new();
    decoder.read_to_string(&mut content)?;
    Ok(content)
}

/// 模拟 logcat 写入行为
/// 按照 1000 行或 10s 空闲刷新的策略
struct LogcatSimulator {
    writer: BlockWriter,
    buffer: Vec<(u64, String)>, // (timestamp_ms, line)
    last_flush_line_count: usize,
    last_timestamp: u64,
    flush_line_threshold: usize,
    flush_time_threshold_ms: u64,
}

impl LogcatSimulator {
    fn new(log_path: &Path, max_size: u64) -> std::io::Result<Self> {
        // 使用较大的块阈值以获得更好的压缩率
        let writer = BlockWriter::with_threshold(log_path, max_size, 8 * 1024, 1000)?;
        Ok(Self {
            writer,
            buffer: Vec::with_capacity(1000),
            last_flush_line_count: 0,
            last_timestamp: 0,
            flush_line_threshold: 1000,      // 1000 行刷新
            flush_time_threshold_ms: 10_000, // 10s 空闲刷新
        })
    }

    /// 写入一行日志
    fn write_line(&mut self, timestamp_ms: u64, line: &str) -> std::io::Result<()> {
        // 检查是否需要基于时间刷新（10s 空闲）
        if self.last_timestamp > 0 && timestamp_ms > self.last_timestamp {
            let elapsed = timestamp_ms - self.last_timestamp;
            if elapsed >= self.flush_time_threshold_ms && !self.buffer.is_empty() {
                self.flush_buffer()?;
            }
        }

        // 添加到缓冲
        self.buffer.push((timestamp_ms, line.to_string()));
        self.last_timestamp = timestamp_ms;

        // 检查是否需要基于行数刷新
        if self.buffer.len() >= self.flush_line_threshold {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// 刷新缓冲区到 rslog
    fn flush_buffer(&mut self) -> std::io::Result<()> {
        for (_ts, line) in self.buffer.drain(..) {
            self.writer.write_text_ch(0, &line)?;
        }
        self.writer.flush()?;
        self.last_flush_line_count = 0;
        Ok(())
    }

    /// 完成写入
    fn finish(&mut self) -> std::io::Result<()> {
        self.flush_buffer()?;
        self.writer.sync()
    }

    fn stats(&self) -> rslog::StreamStats {
        self.writer.stats()
    }
}

/// 从 rslog 还原日志内容
fn restore_logs(log_path: &Path) -> std::io::Result<Vec<String>> {
    let mut log = StreamLog::open(log_path, None)?;
    let (entries, errors) = log.read_all_tolerant();

    if errors > 0 {
        eprintln!("警告：读取时发现 {} 条损坏记录", errors);
    }

    let mut restored_lines = Vec::new();

    for entry in entries {
        if entry.is_block() {
            // 解包块记录
            if let Some(records) = entry.unpack_block() {
                for data in records {
                    if let Ok(text) = String::from_utf8(data) {
                        restored_lines.push(text);
                    }
                }
            }
        } else if entry.is_text() {
            if let Some(text) = entry.as_text() {
                restored_lines.push(text);
            }
        }
    }

    Ok(restored_lines)
}

#[test]
fn test_logcat_simulation() {
    let test_log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_log");
    let gz_path = test_log_dir.join("sky.txt.gz");

    if !gz_path.exists() {
        eprintln!("测试文件不存在: {:?}，跳过测试", gz_path);
        return;
    }

    println!("\n========== logcat 日志写入模拟测试 ==========\n");

    // 1. 解压日志文件
    println!("1. 解压日志文件...");
    let start = Instant::now();
    let original_content = decompress_gzip(&gz_path).expect("解压失败");
    let original_bytes = original_content.len();
    let original_lines: Vec<&str> = original_content.lines().collect();
    println!(
        "   解压完成: {} 行, {} 字节 ({:.1} KB), 耗时 {:?}",
        original_lines.len(),
        original_bytes,
        original_bytes as f64 / 1024.0,
        start.elapsed()
    );

    // 2. 解析日志行，提取时间戳
    println!("\n2. 解析日志行...");
    let mut parsed_lines: Vec<(u64, &str)> = Vec::new();
    let mut no_ts_lines = 0;
    let mut last_ts: u64 = 0;

    for line in &original_lines {
        if let Some((ts, full_line)) = parse_log_line(line) {
            last_ts = ts;
            parsed_lines.push((ts, full_line));
        } else {
            // 没有时间戳的行使用上一行的时间戳
            parsed_lines.push((last_ts, *line));
            no_ts_lines += 1;
        }
    }
    println!(
        "   解析完成: {} 行有时间戳, {} 行无时间戳（使用前一行时间戳）",
        parsed_lines.len() - no_ts_lines,
        no_ts_lines
    );

    // 3. 写入 rslog
    let rslog_path = test_log_dir.join("test_rslog.dat");
    let _ = fs::remove_file(&rslog_path); // 清理旧文件

    println!("\n3. 模拟 logcat 写入 rslog（1000 行或 10s 空闲刷新）...");
    let start = Instant::now();
    let max_rslog_size: u64 = 5 * 1024 * 1024; // 5MB 足够存储测试日志

    {
        let mut simulator =
            LogcatSimulator::new(&rslog_path, max_rslog_size).expect("创建写入器失败");

        for (_ts, line) in &parsed_lines {
            simulator.write_line(0, line).expect("写入失败");
        }

        simulator.finish().expect("完成写入失败");

        let stats = simulator.stats();
        println!("   写入完成: 耗时 {:?}", start.elapsed());
        println!("   rslog 统计:");
        println!(
            "     - 最大容量: {} 字节 ({:.1} KB)",
            stats.max_size,
            stats.max_size as f64 / 1024.0
        );
        println!(
            "     - 已用空间: {} 字节 ({:.1} KB)",
            stats.used_size,
            stats.used_size as f64 / 1024.0
        );
        println!("     - 总条目数: {}", stats.global_seq);
    }

    // 4. 计算压缩率（使用实际写入的数据量，而非预分配的文件大小）
    println!("\n4. 计算压缩率...");
    let rslog_used_size = {
        let log = StreamLog::open(&rslog_path, None).expect("打开日志失败");
        log.stats().used_size
    };
    let gz_file_size = fs::metadata(&gz_path).expect("获取 gz 文件大小失败").len();

    println!(
        "   原始文本大小: {} 字节 ({:.1} KB)",
        original_bytes,
        original_bytes as f64 / 1024.0
    );
    println!(
        "   gzip 压缩后: {} 字节 ({:.1} KB)",
        gz_file_size,
        gz_file_size as f64 / 1024.0
    );
    println!(
        "   rslog 实际使用: {} 字节 ({:.1} KB)",
        rslog_used_size,
        rslog_used_size as f64 / 1024.0
    );
    println!();

    let rslog_ratio = original_bytes as f64 / rslog_used_size as f64;
    let gzip_ratio = original_bytes as f64 / gz_file_size as f64;
    let rslog_vs_gzip = rslog_used_size as f64 / gz_file_size as f64;

    println!("   压缩比:");
    println!("     - rslog 压缩比: {:.2}x (原始/rslog)", rslog_ratio);
    println!("     - gzip 压缩比: {:.2}x (原始/gzip)", gzip_ratio);
    println!(
        "     - rslog vs gzip: {:.2}x (rslog 是 gzip 的 {:.1}%)",
        rslog_vs_gzip,
        rslog_vs_gzip * 100.0
    );

    // 5. 还原日志并对比
    println!("\n5. 还原日志并对比...");
    let start = Instant::now();
    let restored_lines = restore_logs(&rslog_path).expect("还原失败");
    println!(
        "   还原完成: {} 行, 耗时 {:?}",
        restored_lines.len(),
        start.elapsed()
    );

    // 对比行数
    if restored_lines.len() != parsed_lines.len() {
        println!(
            "   ❌ 行数不匹配! 原始: {}, 还原: {}",
            parsed_lines.len(),
            restored_lines.len()
        );
    } else {
        println!("   ✓ 行数匹配: {}", restored_lines.len());
    }

    // 对比内容
    let mut mismatch_count = 0;
    let mut first_mismatch: Option<(usize, String, String)> = None;
    let mut total_original_bytes = 0usize;
    let mut total_restored_bytes = 0usize;

    for (i, ((_orig_ts, orig_line), rest_line)) in
        parsed_lines.iter().zip(restored_lines.iter()).enumerate()
    {
        total_original_bytes += orig_line.len();
        total_restored_bytes += rest_line.len();

        if *orig_line != rest_line {
            mismatch_count += 1;
            if first_mismatch.is_none() {
                first_mismatch = Some((i, orig_line.to_string(), rest_line.clone()));
            }
        }
    }

    if mismatch_count > 0 {
        println!("   ❌ 内容不匹配! {} 行不一致", mismatch_count);
        if let Some((idx, orig, rest)) = first_mismatch {
            println!("   第一个不匹配（行 {}）:", idx);
            println!("     原始: {:?}", &orig[..orig.len().min(100)]);
            println!("     还原: {:?}", &rest[..rest.len().min(100)]);
        }
    } else {
        println!("   ✓ 内容完全匹配!");
    }

    // 字节对比
    if total_original_bytes != total_restored_bytes {
        println!(
            "   ❌ 总字节数不匹配! 原始: {}, 还原: {}, 差异: {}",
            total_original_bytes,
            total_restored_bytes,
            (total_original_bytes as i64 - total_restored_bytes as i64).abs()
        );
    } else {
        println!("   ✓ 总字节数匹配: {}", total_original_bytes);
    }

    // 6. 导出还原的日志到文件进行人工对比
    println!("\n6. 导出还原日志到文件...");
    let restored_path = test_log_dir.join("restored_sky.txt");
    {
        let mut file = File::create(&restored_path).expect("创建还原文件失败");
        for line in &restored_lines {
            writeln!(file, "{}", line).expect("写入还原文件失败");
        }
    }
    println!("   已导出到: {:?}", restored_path);

    // 7. 清理测试文件（可选，注释掉以便调试）
    // let _ = fs::remove_file(&rslog_path);
    // let _ = fs::remove_file(&restored_path);

    println!("\n========== 测试完成 ==========\n");

    // 断言
    assert_eq!(restored_lines.len(), parsed_lines.len(), "行数不匹配");
    assert_eq!(mismatch_count, 0, "内容不匹配");
    assert_eq!(total_original_bytes, total_restored_bytes, "字节数不匹配");
}

/// 测试不同压缩配置的效果
#[test]
fn test_compression_comparison() {
    let test_log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_log");
    let gz_path = test_log_dir.join("sky.txt.gz");

    if !gz_path.exists() {
        eprintln!("测试文件不存在: {:?}，跳过测试", gz_path);
        return;
    }

    println!("\n========== 压缩配置对比测试 ==========\n");

    // 解压日志
    let original_content = decompress_gzip(&gz_path).expect("解压失败");
    let original_bytes = original_content.len();
    let mut parsed_lines: Vec<(u64, &str)> = Vec::new();
    let mut last_ts: u64 = 0;

    for line in original_content.lines() {
        if let Some((ts, full_line)) = parse_log_line(line) {
            last_ts = ts;
            parsed_lines.push((ts, full_line));
        } else {
            parsed_lines.push((last_ts, line));
        }
    }

    let configs = [
        ("无压缩 StreamWriter", false, 0, 0),
        ("BlockWriter 1KB/100行", true, 1024, 100),
        ("BlockWriter 4KB/500行", true, 4096, 500),
        ("BlockWriter 8KB/1000行", true, 8192, 1000),
        ("BlockWriter 16KB/2000行", true, 16384, 2000),
    ];

    println!(
        "原始数据: {} 行, {} 字节 ({:.1} KB)\n",
        parsed_lines.len(),
        original_bytes,
        original_bytes as f64 / 1024.0
    );

    println!(
        "{:<30} {:>12} {:>12} {:>10}",
        "配置", "使用空间", "压缩比", "耗时"
    );
    println!("{:-<66}", "");

    for (name, use_block, block_size, max_records) in configs {
        let rslog_path = test_log_dir.join(format!(
            "test_config_{}.dat",
            name.replace(" ", "_").replace("/", "_")
        ));
        let _ = fs::remove_file(&rslog_path);

        let start = Instant::now();
        let max_size: u64 = 5 * 1024 * 1024;

        let used_size = if use_block {
            let mut writer =
                BlockWriter::with_threshold(&rslog_path, max_size, block_size, max_records)
                    .expect("创建 BlockWriter 失败");
            for (_ts, line) in &parsed_lines {
                writer.write_text_ch(0, line).expect("写入失败");
            }
            writer.sync().expect("同步失败");
            writer.stats().used_size
        } else {
            let mut writer =
                rslog::StreamWriter::new(&rslog_path, max_size).expect("创建 StreamWriter 失败");
            for (_ts, line) in &parsed_lines {
                writer.write_text_ch(0, line).expect("写入失败");
            }
            writer.sync().expect("同步失败");
            writer.stats().used_size
        };

        let elapsed = start.elapsed();
        let ratio = original_bytes as f64 / used_size as f64;

        println!(
            "{:<30} {:>10} B {:>10.2}x {:>10.1}ms",
            name,
            used_size,
            ratio,
            elapsed.as_secs_f64() * 1000.0
        );

        // 清理
        let _ = fs::remove_file(&rslog_path);
    }

    println!("\n========== 对比测试完成 ==========\n");
}
