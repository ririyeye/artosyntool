use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use ar_dbg_client::osd::set_device_role;
use ar_dbg_client::{DeviceRole, OsdPlot};
use rslog::StreamLog;
use tracing::{info, warn};

use crate::osd_meta::{apply_role_from_payload, build_osd_descriptor, osd_fields, OsdDescriptor};

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
    let osd_csv_path = format!("{}/osd.csv", opts.output_dir);
    let osd_desc_path = format!("{}/osd_descriptor.json", opts.output_dir);

    let mut logcat_writer = BufWriter::new(
        File::create(&logcat_path).with_context(|| format!("create {}", logcat_path))?,
    );
    let mut osd_writer = BufWriter::new(
        File::create(&osd_csv_path).with_context(|| format!("create {}", osd_csv_path))?,
    );
    let mut osd_desc_writer = BufWriter::new(
        File::create(&osd_desc_path).with_context(|| format!("create {}", osd_desc_path))?,
    );

    let mut osd_descriptor: Option<OsdDescriptor> = None;
    let mut osd_header_written = false;
    let mut osd_rows: u64 = 0;
    let mut logcat_rows: u64 = 0;

    for entry in entries {
        match entry.channel() {
            0 => {
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
                if entry.is_text() {
                    if osd_descriptor.is_none() {
                        if let Some(text) = entry.as_text() {
                            if let Ok(desc) = serde_json::from_str::<OsdDescriptor>(&text) {
                                osd_descriptor = Some(desc);
                            }
                        }
                    }
                    continue;
                }

                let Some(data) = entry.as_binary() else {
                    continue;
                };

                // 尝试解析批量格式: 多条 [ts:8B][role:1B][raw_data] 连续存储
                let records = decode_osd_batch(&data, osd_descriptor.as_ref());

                if records.is_empty() {
                    // 回退到单条解析
                    match decode_osd_payload(&data, osd_descriptor.as_ref()) {
                        Some((ts, role, osd)) => {
                            if osd_descriptor.is_none() {
                                osd_descriptor = Some(build_osd_descriptor(role));
                            }

                            if !osd_header_written {
                                let mut header = Vec::with_capacity(osd_fields(role).len() + 1);
                                header.push("timestamp_ms".to_string());
                                header.extend(osd_fields(role).iter().map(|s| (*s).to_string()));
                                writeln!(osd_writer, "{}", header.join(","))?;
                                osd_header_written = true;
                            }

                            let row = format_osd_row(ts, role, &osd);
                            writeln!(osd_writer, "{}", row)?;
                            osd_rows += 1;
                        }
                        None => {
                            warn!(
                                "logcat export: failed to parse OSD payload len={}",
                                data.len()
                            );
                        }
                    }
                } else {
                    for (ts, role, osd) in records {
                        if osd_descriptor.is_none() {
                            osd_descriptor = Some(build_osd_descriptor(role));
                        }

                        if !osd_header_written {
                            let mut header = Vec::with_capacity(osd_fields(role).len() + 1);
                            header.push("timestamp_ms".to_string());
                            header.extend(osd_fields(role).iter().map(|s| (*s).to_string()));
                            writeln!(osd_writer, "{}", header.join(","))?;
                            osd_header_written = true;
                        }

                        let row = format_osd_row(ts, role, &osd);
                        writeln!(osd_writer, "{}", row)?;
                        osd_rows += 1;
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(desc) = osd_descriptor {
        let json = serde_json::to_string_pretty(&desc)?;
        osd_desc_writer.write_all(json.as_bytes())?;
    }

    logcat_writer.flush()?;
    osd_writer.flush()?;
    osd_desc_writer.flush()?;

    info!(
        "logcat export: saved {} logcat lines to {}, {} OSD rows to {}",
        logcat_rows, logcat_path, osd_rows, osd_csv_path
    );

    Ok(())
}

fn role_from_str(value: &str) -> DeviceRole {
    match value.trim().to_ascii_uppercase().as_str() {
        "AP" => DeviceRole::Ap,
        _ => DeviceRole::Dev,
    }
}

fn role_from_byte(b: u8) -> DeviceRole {
    match b {
        1 => DeviceRole::Ap,
        _ => DeviceRole::Dev,
    }
}

/// 解析批量 OSD 数据: 多条 [ts:8B][role:1B][len:2B][raw_data] 连续存储
/// 兼容旧格式: [ts:8B][role:1B][raw_data] (固定MIN_SIZE长度)
fn decode_osd_batch(data: &[u8], _desc: Option<&OsdDescriptor>) -> Vec<(u64, DeviceRole, OsdPlot)> {
    let mut results = Vec::new();

    // 批量格式最小记录大小: 8(ts) + 1(role) + 2(len) + DEV_MIN_SIZE
    let min_record_size = 8 + 1 + 2 + OsdPlot::DEV_MIN_SIZE;

    // 检查是否可能是批量格式（数据足够大且以合理时间戳开头）
    if data.len() < min_record_size {
        return results;
    }

    // 尝试读取第一个时间戳，检查是否合理（2020年以后的毫秒时间戳）
    let first_ts = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    // 2020-01-01 00:00:00 UTC in ms
    const MIN_REASONABLE_TS: u64 = 1577836800000;
    // 2100-01-01 00:00:00 UTC in ms
    const MAX_REASONABLE_TS: u64 = 4102444800000;

    if first_ts < MIN_REASONABLE_TS || first_ts > MAX_REASONABLE_TS {
        return results;
    }

    // 先尝试新格式（带长度字段）
    if let Some(records) = decode_osd_batch_with_len(data) {
        return records;
    }

    // 回退到旧格式（固定MIN_SIZE）
    decode_osd_batch_fixed_size(data)
}

/// 新批量格式解析: [ts:8B][role:1B][len:2B][raw_data:len字节]
fn decode_osd_batch_with_len(data: &[u8]) -> Option<Vec<(u64, DeviceRole, OsdPlot)>> {
    let mut results = Vec::new();
    const MIN_REASONABLE_TS: u64 = 1577836800000;
    const MAX_REASONABLE_TS: u64 = 4102444800000;

    // 最小头部: ts(8) + role(1) + len(2) = 11
    if data.len() < 11 {
        return None;
    }

    let mut offset = 0;
    while offset + 11 <= data.len() {
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

        if ts < MIN_REASONABLE_TS || ts > MAX_REASONABLE_TS {
            break;
        }

        // 读取角色
        let role_byte = data[offset + 8];
        if role_byte > 1 {
            break;
        }
        let role = role_from_byte(role_byte);

        // 读取长度
        let raw_len = u16::from_le_bytes([data[offset + 9], data[offset + 10]]) as usize;

        // 合理性检查：raw_data 长度应该在 MIN_SIZE 到 256 之间
        let min_size = match role {
            DeviceRole::Ap => OsdPlot::AP_MIN_SIZE,
            DeviceRole::Dev => OsdPlot::DEV_MIN_SIZE,
        };
        if raw_len < min_size || raw_len > 256 {
            // 长度不合理，可能是旧格式
            return None;
        }

        let record_end = offset + 11 + raw_len;
        if record_end > data.len() {
            break;
        }

        // 解析 OSD 数据
        let raw_data = &data[offset + 11..record_end];
        set_device_role(role);
        if let Some(osd) = OsdPlot::from_bytes(raw_data) {
            results.push((ts, role, osd));
        } else {
            break;
        }

        offset = record_end;
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// 旧批量格式解析: [ts:8B][role:1B][raw_data]
/// 通过搜索下一个有效时间戳来检测记录大小
fn decode_osd_batch_fixed_size(data: &[u8]) -> Vec<(u64, DeviceRole, OsdPlot)> {
    let mut results = Vec::new();
    const MIN_REASONABLE_TS: u64 = 1577836800000;
    const MAX_REASONABLE_TS: u64 = 4102444800000;

    let min_record_size = 8 + 1 + OsdPlot::DEV_MIN_SIZE;
    if data.len() < min_record_size {
        return results;
    }

    // 读取第一条记录信息
    let first_ts = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    if first_ts < MIN_REASONABLE_TS || first_ts > MAX_REASONABLE_TS {
        return results;
    }

    let role_byte = data[8];
    if role_byte > 1 {
        return results;
    }
    let role = role_from_byte(role_byte);

    // 通过搜索下一个有效时间戳来检测 raw_data 大小
    let min_raw_size = match role {
        DeviceRole::Ap => OsdPlot::AP_MIN_SIZE,
        DeviceRole::Dev => OsdPlot::DEV_MIN_SIZE,
    };
    let max_raw_size = 128; // 合理的最大值

    let mut detected_raw_size = min_raw_size;
    for try_size in min_raw_size..=max_raw_size {
        let next_offset = 9 + try_size; // 9 = ts(8) + role(1)
        if next_offset + 9 > data.len() {
            break;
        }
        let next_ts = u64::from_le_bytes([
            data[next_offset],
            data[next_offset + 1],
            data[next_offset + 2],
            data[next_offset + 3],
            data[next_offset + 4],
            data[next_offset + 5],
            data[next_offset + 6],
            data[next_offset + 7],
        ]);
        let next_role = data[next_offset + 8];
        if next_ts >= MIN_REASONABLE_TS && next_ts <= MAX_REASONABLE_TS && next_role <= 1 {
            detected_raw_size = try_size;
            break;
        }
    }

    let record_size = 9 + detected_raw_size;

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

        if ts < MIN_REASONABLE_TS || ts > MAX_REASONABLE_TS {
            break;
        }

        // 读取角色
        let role_byte = data[offset + 8];
        if role_byte > 1 {
            break;
        }
        let role = role_from_byte(role_byte);

        // 解析 OSD 数据
        let raw_data = &data[offset + 9..offset + 9 + detected_raw_size];
        set_device_role(role);
        if let Some(osd) = OsdPlot::from_bytes(raw_data) {
            results.push((ts, role, osd));
        } else {
            break;
        }

        offset += record_size;
    }

    results
}

fn decode_osd_payload(
    data: &[u8],
    desc: Option<&OsdDescriptor>,
) -> Option<(u64, DeviceRole, OsdPlot)> {
    // 优先使用 descriptor 提供的角色
    if let Some(d) = desc {
        let role = role_from_str(&d.role);
        set_device_role(role);

        // 如果数据是 [role|raw] 格式，去掉前缀
        let payload = if data.len() > OsdPlot::DEV_MIN_SIZE && (data[0] == 0 || data[0] == 1) {
            &data[1..]
        } else {
            data
        };

        if let Some(osd) = OsdPlot::from_bytes(payload) {
            return Some((0, role, osd));
        }
    }

    // 尝试 role + raw 格式
    if data.len() > OsdPlot::DEV_MIN_SIZE && (data[0] == 0 || data[0] == 1) {
        let role = role_from_byte(data[0]);
        let payload = &data[1..];
        set_device_role(role);
        if let Some(osd) = OsdPlot::from_bytes(payload) {
            return Some((0, role, osd));
        }
    }

    // 尝试直接原始 OSD 数据（无前缀）
    if data.len() >= OsdPlot::DEV_MIN_SIZE {
        let role = apply_role_from_payload(data);
        if let Some(osd) = OsdPlot::from_bytes(data) {
            return Some((0, role, osd));
        }
    }

    // 回退: 兼容旧的紧凑 31B 格式 (role + fields)
    if data.len() == 31 {
        return parse_compact_osd(data).map(|(role, osd)| (0, role, osd));
    }

    None
}

fn parse_compact_osd(data: &[u8]) -> Option<(DeviceRole, OsdPlot)> {
    if data.len() != 31 {
        return None;
    }
    let role = role_from_byte(data[0]);
    let mut osd = OsdPlot::default();
    osd.role = role;
    osd.raw_data = Vec::new();

    // layout matches osd_to_bytes (old version): role + DEV + AP + common
    let mut idx = 1;

    // DEV
    osd.br_lock = data[idx];
    idx += 1;
    osd.br_ldpc_error = data[idx];
    idx += 1;
    osd.br_snr_value = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.br_agc_value = [data[idx], data[idx + 1], data[idx + 2], data[idx + 3]];
    idx += 4;
    osd.br_channel = data[idx];
    idx += 1;
    osd.slot_tx_channel = data[idx];
    idx += 1;
    osd.slot_rx_channel = data[idx];
    idx += 1;
    osd.slot_rx_opt_channel = data[idx];
    idx += 1;

    // AP
    osd.fch_lock = data[idx];
    idx += 1;
    osd.slot_lock = data[idx];
    idx += 1;
    osd.slot_ldpc_error = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.slot_snr_value = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.slot_ldpc_after_error = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.slot_agc_value = [data[idx], data[idx + 1], data[idx + 2], data[idx + 3]];
    idx += 4;

    // common
    osd.main_avr_pwr = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.opt_avr_pwr = u16::from_le_bytes([data[idx], data[idx + 1]]);
    idx += 2;
    osd.mcs_value = data[idx];

    Some((role, osd))
}

fn format_osd_row(ts: u64, role: DeviceRole, osd: &OsdPlot) -> String {
    let mut fields = Vec::new();
    fields.push(ts.to_string());
    match role {
        DeviceRole::Dev => {
            fields.push("DEV".to_string());
            fields.push(osd.br_lock.to_string());
            fields.push(osd.br_ldpc_error.to_string());
            fields.push(osd.br_snr_value.to_string());
            fields.push(osd.br_agc_value[0].to_string());
            fields.push(osd.br_agc_value[1].to_string());
            fields.push(osd.br_agc_value[2].to_string());
            fields.push(osd.br_agc_value[3].to_string());
            fields.push(osd.br_channel.to_string());
            fields.push(osd.slot_tx_channel.to_string());
            fields.push(osd.slot_rx_channel.to_string());
            fields.push(osd.slot_rx_opt_channel.to_string());
            fields.push(osd.main_avr_pwr.to_string());
            fields.push(osd.opt_avr_pwr.to_string());
            fields.push(osd.mcs_value.to_string());
        }
        DeviceRole::Ap => {
            fields.push("AP".to_string());
            fields.push(osd.fch_lock.to_string());
            fields.push(osd.slot_lock.to_string());
            fields.push(osd.slot_ldpc_error.to_string());
            fields.push(osd.slot_snr_value.to_string());
            fields.push(osd.slot_ldpc_after_error.to_string());
            fields.push(osd.slot_agc_value[0].to_string());
            fields.push(osd.slot_agc_value[1].to_string());
            fields.push(osd.slot_agc_value[2].to_string());
            fields.push(osd.slot_agc_value[3].to_string());
            fields.push(osd.slot_rx_opt_channel.to_string());
            fields.push(osd.main_avr_pwr.to_string());
            fields.push(osd.opt_avr_pwr.to_string());
            fields.push(osd.mcs_value.to_string());
        }
    }

    fields.join(",")
}
