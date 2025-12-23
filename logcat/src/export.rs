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

/// 创建带序号的文件路径
fn make_numbered_path(base_dir: &str, name: &str, ext: &str, index: usize) -> String {
    if index == 0 {
        format!("{}/{}.{}", base_dir, name, ext)
    } else {
        format!("{}/{}_{}.{}", base_dir, name, index, ext)
    }
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

    // 统计各通道的条目数
    let ch0_count = entries.iter().filter(|e| e.channel() == 0).count();
    let ch1_count = entries.iter().filter(|e| e.channel() == 1).count();
    let ch1_blocks = entries
        .iter()
        .filter(|e| e.channel() == 1 && e.is_block())
        .count();
    info!(
        "logcat export: read {} entries (ch0={}, ch1={} with {} blocks)",
        entries.len(),
        ch0_count,
        ch1_count,
        ch1_blocks
    );

    // 文件序号，用于分开导出不同 descriptor 的数据
    let mut file_index: usize = 0;

    let logcat_path = format!("{}/ar_logcat.txt", opts.output_dir);
    let reg_csv_path = make_numbered_path(opts.output_dir, "reg_trace", "csv", file_index);
    let reg_desc_path = make_numbered_path(opts.output_dir, "reg_descriptor", "json", file_index);

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

    // 块统计（减少日志）
    let mut ch1_block_count: u64 = 0;
    let mut ch1_subrecord_count: u64 = 0;

    for entry in entries {
        match entry.channel() {
            0 => {
                // 通道0: logcat 文本
                // 检查是否为块模式
                if entry.is_block() {
                    // 解包块内的子记录
                    if let Some(records) = entry.unpack_block() {
                        for data in records {
                            let line = String::from_utf8_lossy(&data);
                            // 不再输出时间戳，因为日志自带时间戳
                            writeln!(logcat_writer, "{}", line.trim_end())?;
                            logcat_rows += 1;
                        }
                    }
                } else if let Some(text) = entry.as_text() {
                    writeln!(logcat_writer, "{}", text)?;
                    logcat_rows += 1;
                } else if let Some(data) = entry.as_binary() {
                    let line = String::from_utf8_lossy(&data);
                    writeln!(logcat_writer, "{}", line.trim_end())?;
                    logcat_rows += 1;
                }
            }
            1 => {
                // 通道1: 寄存器数据
                // 检查是否为块模式（BlockWriter 写入的多条记录打包）
                if entry.is_block() {
                    // 解包块内的子记录
                    if let Some(records) = entry.unpack_block() {
                        ch1_block_count += 1;
                        ch1_subrecord_count += records.len() as u64;
                        for data in records {
                            // 处理每条子记录，检查是否需要创建新文件
                            let need_new_file = process_reg_data(
                                &data,
                                &mut chunk_config,
                                &mut reg_descriptor,
                                &mut reg_header_written,
                                &mut reg_writer,
                                &mut reg_rows,
                                &mut reg_skipped,
                            )?;
                            if need_new_file {
                                // 保存当前 descriptor
                                if let Some(ref desc) = reg_descriptor {
                                    let json = serde_json::to_string_pretty(desc)?;
                                    reg_desc_writer.write_all(json.as_bytes())?;
                                    reg_desc_writer.flush()?;
                                }
                                // 创建新文件
                                file_index += 1;
                                let new_csv_path = make_numbered_path(
                                    opts.output_dir,
                                    "reg_trace",
                                    "csv",
                                    file_index,
                                );
                                let new_desc_path = make_numbered_path(
                                    opts.output_dir,
                                    "reg_descriptor",
                                    "json",
                                    file_index,
                                );
                                info!(
                                    "logcat export: creating new files: {}, {}",
                                    new_csv_path, new_desc_path
                                );
                                reg_writer = BufWriter::new(File::create(&new_csv_path)?);
                                reg_desc_writer = BufWriter::new(File::create(&new_desc_path)?);
                                reg_header_written = false;
                            }
                        }
                    }
                    continue;
                }

                debug!(
                    "logcat export: ch1 non-block, is_text={}, is_binary={}, len={}",
                    entry.is_text(),
                    entry.is_binary(),
                    entry.data.len()
                );

                if entry.is_text() {
                    // 文本记录是 descriptor JSON (人类可读备份)
                    if let Some(text) = entry.as_text() {
                        match serde_json::from_str::<RegTraceDescriptor>(&text) {
                            Ok(desc) => {
                                // 新的 descriptor 出现
                                if reg_descriptor.is_some() {
                                    // 保存当前 descriptor 并创建新文件
                                    if let Some(ref old_desc) = reg_descriptor {
                                        let json = serde_json::to_string_pretty(old_desc)?;
                                        reg_desc_writer.write_all(json.as_bytes())?;
                                        reg_desc_writer.flush()?;
                                    }
                                    file_index += 1;
                                    let new_csv_path = make_numbered_path(
                                        opts.output_dir,
                                        "reg_trace",
                                        "csv",
                                        file_index,
                                    );
                                    let new_desc_path = make_numbered_path(
                                        opts.output_dir,
                                        "reg_descriptor",
                                        "json",
                                        file_index,
                                    );
                                    info!("logcat export: new descriptor found, creating new files: {}, {}", new_csv_path, new_desc_path);
                                    reg_writer = BufWriter::new(File::create(&new_csv_path)?);
                                    reg_desc_writer = BufWriter::new(File::create(&new_desc_path)?);
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

                // 处理单条二进制记录
                let need_new_file = process_reg_data(
                    &data,
                    &mut chunk_config,
                    &mut reg_descriptor,
                    &mut reg_header_written,
                    &mut reg_writer,
                    &mut reg_rows,
                    &mut reg_skipped,
                )?;
                if need_new_file {
                    // 保存当前 descriptor
                    if let Some(ref desc) = reg_descriptor {
                        let json = serde_json::to_string_pretty(desc)?;
                        reg_desc_writer.write_all(json.as_bytes())?;
                        reg_desc_writer.flush()?;
                    }
                    // 创建新文件
                    file_index += 1;
                    let new_csv_path =
                        make_numbered_path(opts.output_dir, "reg_trace", "csv", file_index);
                    let new_desc_path =
                        make_numbered_path(opts.output_dir, "reg_descriptor", "json", file_index);
                    info!(
                        "logcat export: creating new files: {}, {}",
                        new_csv_path, new_desc_path
                    );
                    reg_writer = BufWriter::new(File::create(&new_csv_path)?);
                    reg_desc_writer = BufWriter::new(File::create(&new_desc_path)?);
                    reg_header_written = false;
                }
            }
            _ => {}
        }
    }

    // 打印块统计
    if ch1_block_count > 0 {
        info!(
            "logcat export: processed {} ch1 blocks with {} sub-records total",
            ch1_block_count, ch1_subrecord_count
        );
    }

    // 写入最后一个 descriptor JSON
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

    let total_files = file_index + 1;
    if total_files > 1 {
        info!(
            "logcat export: saved {} logcat lines to {} , {} reg rows to {} files (reg_trace.csv ~ reg_trace_{}.csv)",
            logcat_rows, logcat_path, reg_rows, total_files, file_index
        );
    } else {
        info!(
            "logcat export: saved {} logcat lines to {} , {} reg rows to {}",
            logcat_rows,
            logcat_path,
            reg_rows,
            make_numbered_path(opts.output_dir, "reg_trace", "csv", 0)
        );
    }

    Ok(())
}

/// 处理单条寄存器二进制数据
/// 返回 true 表示检测到新 descriptor，需要创建新文件
fn process_reg_data(
    data: &[u8],
    chunk_config: &mut Option<ChunkConfig>,
    reg_descriptor: &mut Option<RegTraceDescriptor>,
    reg_header_written: &mut bool,
    reg_writer: &mut BufWriter<File>,
    reg_rows: &mut u64,
    reg_skipped: &mut u64,
) -> Result<bool> {
    // 空数据跳过
    if data.is_empty() {
        return Ok(false);
    }

    // 检查是否为 JSON descriptor（以 '{' 开头）
    // 这处理了 BlockWriter 将文本和二进制混合在一起的情况
    if data[0] == b'{' {
        if let Ok(text) = std::str::from_utf8(data) {
            match serde_json::from_str::<RegTraceDescriptor>(text) {
                Ok(desc) => {
                    let need_new_file = reg_descriptor.is_some();
                    *reg_descriptor = Some(desc);
                    return Ok(need_new_file);
                }
                Err(e) => {
                    debug!("logcat export: JSON-like data but parse failed: {}", e);
                }
            }
        }
    }

    // 检查 Magic 判断 Chunk 类型
    if data.len() >= 4 {
        if data[0..4] == CHUNK_MAGIC_CONFIG {
            // Chunk0: 配置描述块
            if let Some(cfg) = parse_config_chunk(data) {
                debug!(
                    "logcat export: parsed Chunk0, {} items, sample_div={}",
                    cfg.item_count, cfg.sample_div
                );
                *chunk_config = Some(cfg);
            } else {
                warn!("logcat export: failed to parse Chunk0");
            }
            return Ok(false);
        } else if data[0..4] == CHUNK_MAGIC_DATA {
            // ChunkN: 数据块
            // 优先使用 chunk_config，fallback 到 reg_descriptor
            let item_count = chunk_config
                .as_ref()
                .map(|c| c.item_count as usize)
                .or_else(|| reg_descriptor.as_ref().map(|d| d.fields.len()));

            if item_count.is_none() {
                *reg_skipped += 1;
                return Ok(false);
            }

            let records = parse_data_chunk(data, item_count.unwrap());
            if records.is_empty() {
                warn!("logcat export: failed to parse ChunkN, len={}", data.len());
                return Ok(false);
            }

            for (ts, seq_id, irq_type, values) in records {
                // 写入 CSV 表头
                if !*reg_header_written {
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
                            header.push(format!("reg_p{}_0x{:02X}", item.page, item.offset));
                        }
                    } else {
                        for i in 0..values.len() {
                            header.push(format!("reg_{}", i));
                        }
                    }
                    writeln!(reg_writer, "{}", header.join(","))?;
                    *reg_header_written = true;
                }

                // 写入 CSV 行
                let row = format_reg_row(ts, seq_id, irq_type, &values);
                writeln!(reg_writer, "{}", row)?;
                *reg_rows += 1;
            }
            return Ok(false);
        }
    }

    // 未知格式，跳过
    if data.len() >= 4 {
        debug!(
            "logcat export: unknown binary format, len={}, magic=[0x{:02X} 0x{:02X} 0x{:02X} 0x{:02X}], skipping",
            data.len(), data[0], data[1], data[2], data[3]
        );
    } else {
        debug!(
            "logcat export: unknown binary format, len={}, skipping",
            data.len()
        );
    }
    *reg_skipped += 1;
    Ok(false)
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
/// 每条记录: ts_us(8) + seq_id(4) + irq_type(2) + data_len(2) + valid_mask(8) + raw_data[...]
/// 返回: Vec<(ts_us, seq_id, irq_type, values)>，values 中 None 表示该时间点该项无数据
fn parse_data_chunk(data: &[u8], item_count: usize) -> Vec<(u64, u32, u32, Vec<Option<u32>>)> {
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

    // 记录头: ts_us(8) + seq_id(4) + irq_type(2) + data_len(2) + valid_mask(8) = 24字节
    const HEADER_SIZE: usize = 24;

    let mut results = Vec::with_capacity(record_count);
    let mut offset = 0;

    for _ in 0..record_count {
        if offset + HEADER_SIZE > records_data.len() {
            break;
        }

        // 读取时间戳 (us)
        let ts_us = u64::from_le_bytes([
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

        // 读取 irq_type (u16)
        let irq_type =
            u16::from_le_bytes([records_data[offset + 12], records_data[offset + 13]]) as u32;

        // 读取 data_len (u16)
        let data_len =
            u16::from_le_bytes([records_data[offset + 14], records_data[offset + 15]]) as usize;

        // 读取 valid_mask (u64)
        let valid_mask = u64::from_le_bytes([
            records_data[offset + 16],
            records_data[offset + 17],
            records_data[offset + 18],
            records_data[offset + 19],
            records_data[offset + 20],
            records_data[offset + 21],
            records_data[offset + 22],
            records_data[offset + 23],
        ]);

        offset += HEADER_SIZE;

        // 按 valid_mask 读取数据，每个有效项占 4 字节
        // 使用 Option<u32> 区分有效值和无效值，无效值在 CSV 中输出为空
        let mut values: Vec<Option<u32>> = Vec::with_capacity(item_count);
        let data_end = offset + data_len;
        for i in 0..item_count {
            if valid_mask & (1 << i) != 0 {
                if offset + 4 <= data_end && offset + 4 <= records_data.len() {
                    values.push(Some(u32::from_le_bytes([
                        records_data[offset],
                        records_data[offset + 1],
                        records_data[offset + 2],
                        records_data[offset + 3],
                    ])));
                    offset += 4;
                } else {
                    values.push(None); // 数据不足，标记为无效
                }
            } else {
                values.push(None); // 该项在此时间点无数据，标记为无效
            }
        }
        // 确保跳过整个数据区
        offset = data_end.max(offset);

        results.push((ts_us, seq_id, irq_type, values));
    }

    results
}

/// 格式化 CSV 行
/// values 中 None 表示该时间点该项无数据，在 CSV 中输出为空（PlotJuggler 会忽略空值）
fn format_reg_row(ts_us: u64, seq_id: u32, irq_type: u32, values: &[Option<u32>]) -> String {
    let mut fields = Vec::with_capacity(3 + values.len());

    // 将微秒时间戳转换为秒（浮点数），PlotJuggler 更好识别
    let ts_sec = ts_us as f64 / 1_000_000.0;
    fields.push(format!("{:.6}", ts_sec));
    fields.push(seq_id.to_string());
    fields.push(format!("0x{:04X}", irq_type));

    for v in values {
        match v {
            Some(val) => fields.push(val.to_string()),
            None => fields.push(String::new()), // 空值，PlotJuggler 会忽略
        }
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
        // 新格式: ts_us(8) + seq_id(4) + irq_type(2) + data_len(2) + valid_mask(8) + data[...]
        let mut data = Vec::new();

        // Magic "RTDN"
        data.extend_from_slice(&CHUNK_MAGIC_DATA);
        // record_count = 2
        data.extend_from_slice(&2u16.to_le_bytes());

        // 记录1
        let ts1: u64 = 1700000000000;
        let seq1: u32 = 0;
        let irq1: u16 = 0x0001;
        let valid_mask1: u64 = 0x03; // 两个配置项都有效
        let values1: [u32; 2] = [0x1234, 0x5678];
        let data_len1: u16 = 8; // 2 * 4 bytes

        data.extend_from_slice(&ts1.to_le_bytes());
        data.extend_from_slice(&seq1.to_le_bytes());
        data.extend_from_slice(&irq1.to_le_bytes());
        data.extend_from_slice(&data_len1.to_le_bytes());
        data.extend_from_slice(&valid_mask1.to_le_bytes());
        for v in &values1 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        // 记录2
        let ts2: u64 = 1700000001000;
        let seq2: u32 = 1;
        let irq2: u16 = 0x0002;
        let valid_mask2: u64 = 0x03; // 两个配置项都有效
        let values2: [u32; 2] = [0xAAAA, 0xBBBB];
        let data_len2: u16 = 8;

        data.extend_from_slice(&ts2.to_le_bytes());
        data.extend_from_slice(&seq2.to_le_bytes());
        data.extend_from_slice(&irq2.to_le_bytes());
        data.extend_from_slice(&data_len2.to_le_bytes());
        data.extend_from_slice(&valid_mask2.to_le_bytes());
        for v in &values2 {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let records = parse_data_chunk(&data, 2);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, ts1);
        assert_eq!(records[0].1, seq1);
        assert_eq!(records[0].2, irq1 as u32);
        assert_eq!(records[0].3, vec![Some(0x1234), Some(0x5678)]);
        assert_eq!(records[1].0, ts2);
        assert_eq!(records[1].1, seq2);
        assert_eq!(records[1].2, irq2 as u32);
        assert_eq!(records[1].3, vec![Some(0xAAAA), Some(0xBBBB)]);
    }

    #[test]
    fn test_parse_data_chunk_partial_valid() {
        // 测试部分有效的情况
        let mut data = Vec::new();

        data.extend_from_slice(&CHUNK_MAGIC_DATA);
        data.extend_from_slice(&1u16.to_le_bytes()); // 1条记录

        let ts: u64 = 1700000000000;
        let seq: u32 = 0;
        let irq: u16 = 0x0001;
        let valid_mask: u64 = 0x01; // 只有第一项有效
        let data_len: u16 = 4; // 只有1个值

        data.extend_from_slice(&ts.to_le_bytes());
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(&irq.to_le_bytes());
        data.extend_from_slice(&data_len.to_le_bytes());
        data.extend_from_slice(&valid_mask.to_le_bytes());
        data.extend_from_slice(&0x1234u32.to_le_bytes());

        let records = parse_data_chunk(&data, 2);
        assert_eq!(records.len(), 1);
        // 第一项有值，第二项为 None
        assert_eq!(records[0].3, vec![Some(0x1234), None]);
    }
}
