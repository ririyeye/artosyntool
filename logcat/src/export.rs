//! 导出 rslog 数据到 CSV 和 JSON

use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use rslog::StreamLog;
use tracing::{debug, info, warn};

use crate::reg_meta::{RegTraceDescriptor, CHUNK_MAGIC_CONFIG, CHUNK_MAGIC_DATA};

/// 从 Chunk0 解析的配置信息
#[derive(Debug, Clone)]
struct ChunkConfig {
    item_count: u8,
    sample_div: u8,
    items: Vec<ChunkItemConfig>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ChunkItemConfig {
    page: u8,
    offset: u8,
    width: u8,
    irq_mask: u16,
}

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
    let mut chunk_config: Option<ChunkConfig> = None;
    let mut reg_header_written = false;
    let mut reg_rows: u64 = 0;
    let mut logcat_rows: u64 = 0;
    let mut reg_skipped: u64 = 0;

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
                    // 文本记录是 descriptor JSON (人类可读备份)
                    if let Some(text) = entry.as_text() {
                        match serde_json::from_str::<RegTraceDescriptor>(&text) {
                            Ok(desc) => {
                                // 新的 descriptor 出现，重置状态
                                if reg_descriptor.is_some() {
                                    info!(
                                        "logcat export: new descriptor found, resetting CSV header"
                                    );
                                    reg_header_written = false;
                                }
                                reg_descriptor = Some(desc);
                            }
                            Err(e) => {
                                warn!("logcat export: failed to parse descriptor JSON: {}", e);
                            }
                        }
                    }
                    continue;
                }

                let Some(data) = entry.as_binary() else {
                    continue;
                };

                // 检查 Magic 判断 Chunk 类型
                if data.len() >= 4 {
                    if data[0..4] == CHUNK_MAGIC_CONFIG {
                        // Chunk0: 配置描述块
                        if let Some(cfg) = parse_config_chunk(&data) {
                            debug!(
                                "logcat export: parsed Chunk0, {} items, sample_div={}",
                                cfg.item_count, cfg.sample_div
                            );
                            chunk_config = Some(cfg);
                        } else {
                            warn!("logcat export: failed to parse Chunk0");
                        }
                        continue;
                    } else if data[0..4] == CHUNK_MAGIC_DATA {
                        // ChunkN: 数据块
                        // 优先使用 chunk_config，fallback 到 reg_descriptor
                        let item_count = chunk_config
                            .as_ref()
                            .map(|c| c.item_count as usize)
                            .or_else(|| reg_descriptor.as_ref().map(|d| d.fields.len()));

                        if item_count.is_none() {
                            reg_skipped += 1;
                            continue;
                        }

                        let records = parse_data_chunk(&data, item_count.unwrap());
                        if records.is_empty() {
                            warn!("logcat export: failed to parse ChunkN, len={}", data.len());
                            continue;
                        }

                        for (ts, seq_id, irq_type, values) in records {
                            // 写入 CSV 表头
                            if !reg_header_written {
                                let mut header = vec![
                                    "timestamp".to_string(),
                                    "seq_id".to_string(),
                                    "irq_type".to_string(),
                                ];
                                if let Some(ref desc) = reg_descriptor {
                                    header.extend(desc.field_names());
                                } else if let Some(ref cfg) = chunk_config {
                                    // 从 chunk_config 生成默认字段名
                                    for item in cfg.items.iter() {
                                        header.push(format!(
                                            "reg_p{}_0x{:02X}",
                                            item.page, item.offset
                                        ));
                                    }
                                } else {
                                    for i in 0..values.len() {
                                        header.push(format!("reg_{}", i));
                                    }
                                }
                                writeln!(reg_writer, "{}", header.join(","))?;
                                reg_header_written = true;
                            }

                            // 写入 CSV 行
                            let row = format_reg_row(ts, seq_id, irq_type, &values);
                            writeln!(reg_writer, "{}", row)?;
                            reg_rows += 1;
                        }
                        continue;
                    }
                }

                // 未知格式，跳过
                warn!(
                    "logcat export: unknown binary format, len={}, skipping",
                    data.len()
                );
                reg_skipped += 1;
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

    if reg_skipped > 0 {
        warn!(
            "logcat export: skipped {} reg entries (unknown format or before config)",
            reg_skipped
        );
    }

    info!(
        "logcat export: saved {} logcat lines to {}, {} reg rows to {}",
        logcat_rows, logcat_path, reg_rows, reg_csv_path
    );

    Ok(())
}

/// 解析 Chunk0 配置描述块
/// 格式: [MAGIC:4B][item_count:1B][sample_div:1B][reserved:2B][items:N*8B]
fn parse_config_chunk(data: &[u8]) -> Option<ChunkConfig> {
    // 最小长度: 4(magic) + 1(count) + 1(div) + 2(reserved) = 8
    if data.len() < 8 {
        return None;
    }

    // 验证 Magic
    if data[0..4] != CHUNK_MAGIC_CONFIG {
        return None;
    }

    let item_count = data[4];
    let sample_div = data[5];
    // data[6..8] reserved

    // 每个 item 8 字节
    let expected_len = 8 + item_count as usize * 8;
    if data.len() < expected_len {
        warn!(
            "logcat export: Chunk0 too short, expected {}, got {}",
            expected_len,
            data.len()
        );
        return None;
    }

    let mut items = Vec::with_capacity(item_count as usize);
    for i in 0..item_count as usize {
        let base = 8 + i * 8;
        let page = data[base];
        let offset = data[base + 1];
        let width = data[base + 2];
        // data[base + 3] reserved
        let irq_mask = u16::from_le_bytes([data[base + 4], data[base + 5]]);
        // data[base + 6..8] reserved

        items.push(ChunkItemConfig {
            page,
            offset,
            width,
            irq_mask,
        });
    }

    Some(ChunkConfig {
        item_count,
        sample_div,
        items,
    })
}

/// 解析 ChunkN 数据块
/// 格式: [MAGIC:4B][record_count:2B][records:...]
fn parse_data_chunk(data: &[u8], item_count: usize) -> Vec<(u64, u32, u32, Vec<u32>)> {
    // 最小长度: 4(magic) + 2(count) = 6
    if data.len() < 6 {
        return Vec::new();
    }

    // 验证 Magic
    if data[0..4] != CHUNK_MAGIC_DATA {
        return Vec::new();
    }

    let record_count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let records_data = &data[6..];

    // 每条记录大小: ts(8) + seq_id(4) + irq_type(4) + values(item_count * 4)
    let record_size = 8 + 4 + 4 + item_count * 4;

    let mut results = Vec::with_capacity(record_count);
    let mut offset = 0;

    for _ in 0..record_count {
        if offset + record_size > records_data.len() {
            break;
        }

        // 读取时间戳
        let ts = u64::from_le_bytes([
            records_data[offset],
            records_data[offset + 1],
            records_data[offset + 2],
            records_data[offset + 3],
            records_data[offset + 4],
            records_data[offset + 5],
            records_data[offset + 6],
            records_data[offset + 7],
        ]);

        // 读取 seq_id
        let seq_id = u32::from_le_bytes([
            records_data[offset + 8],
            records_data[offset + 9],
            records_data[offset + 10],
            records_data[offset + 11],
        ]);

        // 读取 irq_type
        let irq_type = u32::from_le_bytes([
            records_data[offset + 12],
            records_data[offset + 13],
            records_data[offset + 14],
            records_data[offset + 15],
        ]);

        // 读取 values
        let mut values = Vec::with_capacity(item_count);
        for i in 0..item_count {
            let v_offset = offset + 16 + i * 4;
            if v_offset + 4 <= records_data.len() {
                values.push(u32::from_le_bytes([
                    records_data[v_offset],
                    records_data[v_offset + 1],
                    records_data[v_offset + 2],
                    records_data[v_offset + 3],
                ]));
            }
        }

        results.push((ts, seq_id, irq_type, values));
        offset += record_size;
    }

    results
}

/// 格式化 CSV 行
fn format_reg_row(ts: u64, seq_id: u32, irq_type: u32, values: &[u32]) -> String {
    let mut fields = Vec::with_capacity(3 + values.len());

    // 将毫秒时间戳转换为秒（浮点数），PlotJuggler 更好识别
    let ts_sec = ts as f64 / 1000.0;
    fields.push(format!("{:.3}", ts_sec));
    fields.push(seq_id.to_string());
    fields.push(format!("0x{:04X}", irq_type));

    for v in values {
        fields.push(v.to_string());
    }

    fields.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_chunk() {
        // 构造 Chunk0 数据
        let mut data = Vec::new();

        // Magic "RTC0"
        data.extend_from_slice(&CHUNK_MAGIC_CONFIG);
        // item_count = 2
        data.push(2);
        // sample_div = 1
        data.push(1);
        // reserved
        data.extend_from_slice(&[0u8; 2]);

        // Item 0: page=0, offset=0x04, width=4, irq_mask=0x0002
        data.push(0);
        data.push(0x04);
        data.push(4);
        data.push(0); // reserved
        data.extend_from_slice(&0x0002u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]); // reserved

        // Item 1: page=1, offset=0x10, width=4, irq_mask=0xFFFF
        data.push(1);
        data.push(0x10);
        data.push(4);
        data.push(0);
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]);

        let cfg = parse_config_chunk(&data).unwrap();
        assert_eq!(cfg.item_count, 2);
        assert_eq!(cfg.sample_div, 1);
        assert_eq!(cfg.items.len(), 2);
        assert_eq!(cfg.items[0].page, 0);
        assert_eq!(cfg.items[0].offset, 0x04);
        assert_eq!(cfg.items[0].irq_mask, 0x0002);
        assert_eq!(cfg.items[1].page, 1);
        assert_eq!(cfg.items[1].offset, 0x10);
        assert_eq!(cfg.items[1].irq_mask, 0xFFFF);
    }

    #[test]
    fn test_parse_data_chunk() {
        // 构造 ChunkN 数据: 2条记录，每条2个values
        let mut data = Vec::new();

        // Magic "RTDN"
        data.extend_from_slice(&CHUNK_MAGIC_DATA);
        // record_count = 2
        data.extend_from_slice(&2u16.to_le_bytes());

        // 记录1
        let ts1: u64 = 1700000000000;
        let seq1: u32 = 0;
        let irq1: u32 = 0x0001;
        let values1: [u32; 2] = [0x1234, 0x5678];

        data.extend_from_slice(&ts1.to_le_bytes());
        data.extend_from_slice(&seq1.to_le_bytes());
        data.extend_from_slice(&irq1.to_le_bytes());
        for v in &values1 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        // 记录2
        let ts2: u64 = 1700000001000;
        let seq2: u32 = 1;
        let irq2: u32 = 0x0002;
        let values2: [u32; 2] = [0xAAAA, 0xBBBB];

        data.extend_from_slice(&ts2.to_le_bytes());
        data.extend_from_slice(&seq2.to_le_bytes());
        data.extend_from_slice(&irq2.to_le_bytes());
        for v in &values2 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let records = parse_data_chunk(&data, 2);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, ts1);
        assert_eq!(records[0].1, seq1);
        assert_eq!(records[0].2, irq1);
        assert_eq!(records[0].3, values1.to_vec());
        assert_eq!(records[1].0, ts2);
        assert_eq!(records[1].1, seq2);
        assert_eq!(records[1].2, irq2);
        assert_eq!(records[1].3, values2.to_vec());
    }
}
