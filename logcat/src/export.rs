//! 导出 rslog 数据到 CSV 和 JSON

use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use rslog::StreamLog;
use tracing::{info, warn};

use crate::reg_meta::RegTraceDescriptor;

pub struct ExportOptions<'a> {
    pub input: &'a str,
    pub output_dir: &'a str,
}

pub fn run_export(opts: ExportOptions<'_>) -> Result<()> {
    create_dir_all(opts.output_dir)
        .with_context(|| format!("create export dir {}", opts.output_dir))?;

    let mut log =
        StreamLog::open(opts.input, None).with_context(|| format!("open {}", opts.input))?;
    let (entries, errors) = log.read_all_tolerant();
    if errors > 0 {
        warn!("logcat export: skipped {} corrupted entries", errors);
    }

    let logcat_path = format!("{}/ar_logcat.txt", opts.output_dir);
    let reg_csv_path = format!("{}/reg_trace.csv", opts.output_dir);
    let reg_desc_path = format!("{}/reg_descriptor.json", opts.output_dir);

    let mut logcat_writer = BufWriter::new(
        File::create(&logcat_path).with_context(|| format!("create {}", logcat_path))?,
    );
    let mut reg_writer = BufWriter::new(
        File::create(&reg_csv_path).with_context(|| format!("create {}", reg_csv_path))?,
    );
    let mut reg_desc_writer = BufWriter::new(
        File::create(&reg_desc_path).with_context(|| format!("create {}", reg_desc_path))?,
    );

    let mut reg_descriptor: Option<RegTraceDescriptor> = None;
    let mut reg_header_written = false;
    let mut reg_rows: u64 = 0;
    let mut logcat_rows: u64 = 0;

    for entry in entries {
        match entry.channel() {
            0 => {
                // 通道0: logcat 文本
                if let Some(text) = entry.as_text() {
                    writeln!(logcat_writer, "[{}] {}", entry.timestamp_ms, text)?;
                    logcat_rows += 1;
                } else if let Some(data) = entry.as_binary() {
                    let line = String::from_utf8_lossy(&data);
                    writeln!(
                        logcat_writer,
                        "[{}] {}",
                        entry.timestamp_ms,
                        line.trim_end()
                    )?;
                    logcat_rows += 1;
                }
            }
            1 => {
                // 通道1: 寄存器数据
                if entry.is_text() {
                    // 文本记录是 descriptor JSON
                    if reg_descriptor.is_none() {
                        if let Some(text) = entry.as_text() {
                            if let Ok(desc) = serde_json::from_str::<RegTraceDescriptor>(&text) {
                                reg_descriptor = Some(desc);
                            }
                        }
                    }
                    continue;
                }

                let Some(data) = entry.as_binary() else {
                    continue;
                };

                // 解析批量记录
                let records = decode_reg_batch(&data, reg_descriptor.as_ref());

                if records.is_empty() {
                    warn!(
                        "logcat export: failed to parse reg payload len={}",
                        data.len()
                    );
                    continue;
                }

                for (ts, seq_id, values) in records {
                    // 写入 CSV 表头
                    if !reg_header_written {
                        let mut header = vec!["timestamp".to_string(), "seq_id".to_string()];
                        if let Some(ref desc) = reg_descriptor {
                            header.extend(desc.field_names());
                        } else {
                            // 没有 descriptor，使用默认字段名
                            for i in 0..values.len() {
                                header.push(format!("reg_{}", i));
                            }
                        }
                        writeln!(reg_writer, "{}", header.join(","))?;
                        reg_header_written = true;
                    }

                    // 写入 CSV 行
                    let row = format_reg_row(ts, seq_id, &values);
                    writeln!(reg_writer, "{}", row)?;
                    reg_rows += 1;
                }
            }
            _ => {}
        }
    }

    // 写入 descriptor JSON
    if let Some(desc) = reg_descriptor {
        let json = serde_json::to_string_pretty(&desc)?;
        reg_desc_writer.write_all(json.as_bytes())?;
    }

    logcat_writer.flush()?;
    reg_writer.flush()?;
    reg_desc_writer.flush()?;

    info!(
        "logcat export: saved {} logcat lines to {}, {} reg rows to {}",
        logcat_rows, logcat_path, reg_rows, reg_csv_path
    );

    Ok(())
}

/// 解析批量寄存器数据: 多条 [ts:8B][seq_id:4B][values:N*4B] 连续存储
fn decode_reg_batch(data: &[u8], desc: Option<&RegTraceDescriptor>) -> Vec<(u64, u32, Vec<u32>)> {
    let mut results = Vec::new();

    // 确定每条记录的 values 数量
    let item_count = desc.map(|d| d.fields.len()).unwrap_or(4);

    // 每条记录大小: ts(8) + seq_id(4) + values(item_count * 4)
    let record_size = 8 + 4 + item_count * 4;

    if data.len() < record_size {
        // 数据太短，尝试检测 item_count
        return decode_reg_batch_auto_detect(data);
    }

    let mut offset = 0;
    while offset + record_size <= data.len() {
        // 读取时间戳
        let ts = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        // 合理性检查时间戳 (2020年以后的毫秒时间戳)
        const MIN_REASONABLE_TS: u64 = 1577836800000;
        const MAX_REASONABLE_TS: u64 = 4102444800000;
        if ts < MIN_REASONABLE_TS || ts > MAX_REASONABLE_TS {
            break;
        }

        // 读取 seq_id
        let seq_id = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);

        // 读取 values
        let mut values = Vec::with_capacity(item_count);
        for i in 0..item_count {
            let v_offset = offset + 12 + i * 4;
            if v_offset + 4 <= data.len() {
                values.push(u32::from_le_bytes([
                    data[v_offset],
                    data[v_offset + 1],
                    data[v_offset + 2],
                    data[v_offset + 3],
                ]));
            }
        }

        results.push((ts, seq_id, values));
        offset += record_size;
    }

    results
}

/// 自动检测 item_count 并解析
fn decode_reg_batch_auto_detect(data: &[u8]) -> Vec<(u64, u32, Vec<u32>)> {
    let mut results = Vec::new();

    const MIN_REASONABLE_TS: u64 = 1577836800000;
    const MAX_REASONABLE_TS: u64 = 4102444800000;

    // 最小记录: ts(8) + seq_id(4) + 至少1个value(4) = 16
    if data.len() < 16 {
        return results;
    }

    // 检查第一个时间戳
    let first_ts = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    if first_ts < MIN_REASONABLE_TS || first_ts > MAX_REASONABLE_TS {
        return results;
    }

    // 尝试检测 item_count (1-16)
    for item_count in 1..=16 {
        let record_size = 8 + 4 + item_count * 4;

        // 检查是否能整除
        if data.len() % record_size != 0 {
            continue;
        }

        // 检查第二条记录的时间戳
        if data.len() >= record_size * 2 {
            let second_ts = u64::from_le_bytes([
                data[record_size],
                data[record_size + 1],
                data[record_size + 2],
                data[record_size + 3],
                data[record_size + 4],
                data[record_size + 5],
                data[record_size + 6],
                data[record_size + 7],
            ]);
            if second_ts < MIN_REASONABLE_TS || second_ts > MAX_REASONABLE_TS {
                continue;
            }
        }

        // 找到匹配的 item_count，解析所有记录
        let mut offset = 0;
        while offset + record_size <= data.len() {
            let ts = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);

            if ts < MIN_REASONABLE_TS || ts > MAX_REASONABLE_TS {
                break;
            }

            let seq_id = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);

            let mut values = Vec::with_capacity(item_count);
            for i in 0..item_count {
                let v_offset = offset + 12 + i * 4;
                values.push(u32::from_le_bytes([
                    data[v_offset],
                    data[v_offset + 1],
                    data[v_offset + 2],
                    data[v_offset + 3],
                ]));
            }

            results.push((ts, seq_id, values));
            offset += record_size;
        }

        if !results.is_empty() {
            return results;
        }
    }

    results
}

/// 格式化 CSV 行
fn format_reg_row(ts: u64, seq_id: u32, values: &[u32]) -> String {
    let mut fields = Vec::with_capacity(2 + values.len());

    // 将毫秒时间戳转换为秒（浮点数），PlotJuggler 更好识别
    let ts_sec = ts as f64 / 1000.0;
    fields.push(format!("{:.3}", ts_sec));
    fields.push(seq_id.to_string());

    for v in values {
        fields.push(v.to_string());
    }

    fields.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_reg_batch() {
        // 构造测试数据: 2条记录，每条4个values
        let mut data = Vec::new();

        // 记录1
        let ts1: u64 = 1700000000000; // 2023年
        let seq1: u32 = 0;
        let values1: [u32; 4] = [0x1234, 0x5678, 0x9ABC, 0xDEF0];

        data.extend_from_slice(&ts1.to_le_bytes());
        data.extend_from_slice(&seq1.to_le_bytes());
        for v in &values1 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        // 记录2
        let ts2: u64 = 1700000001000;
        let seq2: u32 = 1;
        let values2: [u32; 4] = [0x1111, 0x2222, 0x3333, 0x4444];

        data.extend_from_slice(&ts2.to_le_bytes());
        data.extend_from_slice(&seq2.to_le_bytes());
        for v in &values2 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let records = decode_reg_batch_auto_detect(&data);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, ts1);
        assert_eq!(records[0].1, seq1);
        assert_eq!(records[0].2, values1.to_vec());
        assert_eq!(records[1].0, ts2);
        assert_eq!(records[1].1, seq2);
        assert_eq!(records[1].2, values2.to_vec());
    }
}
