use ar_dbg_client::osd::set_device_role;
use ar_dbg_client::{DeviceRole, OsdPlot};
use serde::{Deserialize, Serialize};

pub const OSD_FIELDS_DEV: &[&str] = &[
    "role_id",
    "br_lock",
    "br_ldpc_error",
    "br_snr_value",
    "br_agc0",
    "br_agc1",
    "br_agc2",
    "br_agc3",
    "br_channel",
    "slot_tx_channel",
    "slot_rx_channel",
    "slot_rx_opt_channel",
    "main_avr_pwr",
    "opt_avr_pwr",
    "mcs_value",
];

pub const OSD_FIELDS_AP: &[&str] = &[
    "role_id",
    "fch_lock",
    "slot_lock",
    "slot_ldpc_error",
    "slot_snr_value",
    "slot_ldpc_after_error",
    "slot_agc0",
    "slot_agc1",
    "slot_agc2",
    "slot_agc3",
    "slot_rx_opt_channel",
    "main_avr_pwr",
    "opt_avr_pwr",
    "mcs_value",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub description: String,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsdDescriptor {
    pub role: String,
    pub role_id: u8,
    pub fields: Vec<FieldInfo>,
    pub description: String,
    pub timestamp_unit: String,
    pub plotjuggler_notes: String,
}

pub fn osd_fields(role: DeviceRole) -> &'static [&'static str] {
    match role {
        DeviceRole::Dev => OSD_FIELDS_DEV,
        DeviceRole::Ap => OSD_FIELDS_AP,
    }
}

fn field_description(name: &str) -> (&str, &str) {
    match name {
        "role_id" => ("设备角色: 0=DEV(设备端), 1=AP(接入点)", ""),
        "fch_lock" => ("FCH锁定状态", "bool"),
        "slot_lock" => ("时隙锁定状态", "bool"),
        "slot_ldpc_error" => ("时隙LDPC错误计数", "count"),
        "slot_snr_value" => ("时隙信噪比原始值 (SNR dB = 10*log10(value/64))", "raw"),
        "slot_ldpc_after_error" => ("LDPC纠错后错误数", "count"),
        "slot_agc0" | "slot_agc1" | "slot_agc2" | "slot_agc3" => ("AGC增益值", "dB"),
        "slot_rx_opt_channel" => ("接收优选信道", ""),
        "br_lock" => ("广播锁定状态", "bool"),
        "br_ldpc_error" => ("广播LDPC错误计数", "count"),
        "br_snr_value" => ("广播信噪比原始值 (SNR dB = 10*log10(value/64))", "raw"),
        "br_agc0" | "br_agc1" | "br_agc2" | "br_agc3" => ("广播AGC增益值", "dB"),
        "br_channel" => ("广播信道", ""),
        "slot_tx_channel" => ("发送信道", ""),
        "slot_rx_channel" => ("接收信道", ""),
        "main_avr_pwr" => ("主通道平均功率", ""),
        "opt_avr_pwr" => ("优选通道平均功率", ""),
        "mcs_value" => ("MCS调制编码方案", ""),
        _ => ("", ""),
    }
}

pub fn build_osd_descriptor(role: DeviceRole) -> OsdDescriptor {
    let fields: Vec<FieldInfo> = osd_fields(role)
        .iter()
        .map(|s| {
            let (desc, unit) = field_description(s);
            FieldInfo {
                name: s.to_string(),
                description: desc.to_string(),
                unit: unit.to_string(),
            }
        })
        .collect();

    OsdDescriptor {
        role: role.to_string(),
        role_id: match role {
            DeviceRole::Dev => 0,
            DeviceRole::Ap => 1,
        },
        fields,
        description: "OSD字段描述 - PlotJuggler兼容格式".to_string(),
        timestamp_unit: "seconds (Unix epoch)".to_string(),
        plotjuggler_notes: "CSV第一列timestamp为时间轴(秒)，可直接在PlotJuggler中选择作为X轴；role_id: 0=DEV, 1=AP".to_string(),
    }
}

pub fn apply_role_from_payload(osd_data: &[u8]) -> DeviceRole {
    let role = if osd_data.len() >= OsdPlot::AP_MIN_SIZE {
        DeviceRole::Ap
    } else {
        DeviceRole::Dev
    };
    set_device_role(role);
    role
}
