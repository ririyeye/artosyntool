use ar_dbg_client::osd::set_device_role;
use ar_dbg_client::{DeviceRole, OsdPlot};
use serde::{Deserialize, Serialize};

pub const OSD_FIELDS_DEV: &[&str] = &[
    "role",
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
    "role",
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
pub struct OsdDescriptor {
    pub role: String,
    pub fields: Vec<String>,
    pub description: String,
}

pub fn osd_fields(role: DeviceRole) -> &'static [&'static str] {
    match role {
        DeviceRole::Dev => OSD_FIELDS_DEV,
        DeviceRole::Ap => OSD_FIELDS_AP,
    }
}

pub fn build_osd_descriptor(role: DeviceRole) -> OsdDescriptor {
    OsdDescriptor {
        role: role.to_string(),
        fields: osd_fields(role).iter().map(|s| (*s).to_string()).collect(),
        description: "OSD字段顺序，导出时按此表头生成CSV".to_string(),
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
