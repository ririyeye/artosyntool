# Artosyn Debug Service Client (Rust)

用于连接 Artosyn 调试服务（ar_dbg_multi_service）并接收 OSD 数据的 Rust 客户端。

## 功能

- 连接到 ar_dbg_multi_service (TCP 端口 1234)
- 发送启动/停止 OSD 命令
- 接收并解析 OSD 数据（osd_plot_t 结构）
- **自动检测设备角色（AP/DEV）并使用正确的字段映射**
- 显示链路状态、SNR、MCS、LDPC 错误等信息

## 设备角色

系统支持两种设备角色，它们使用不同的 OSD 数据内存布局：

### DEV (设备端) 布局
```
BR_LOCK:0x04, BR_LDPC_ERR:0x05, BR_SNR:0x06-07
BR_AGC0-3:0x08-0x0b, BR_CHN:0x18
SLOT_TX_CHN:0x19, SLOT_RX_CHN:0x1a, SLOT_RX_OPT_CHN:0x1b
MAIN_AVR_PWR:0x24-25, OPT_AVR_PWR:0x26-27, MCS_VALUE:0x28
```

### AP (接入点) 布局
```
FCH_LOCK:0x0c, SLOT_LOCK:0x0d, SLOT_LDPC_ERR:0x0e-0f
SLOT_SNR:0x10-11, SLOT_LDPC_AFTER_ERR:0x12-13
SLOT_AGC0:0x14, SLOT_AGC2:0x15, SLOT_AGC1:0x16, SLOT_AGC3:0x17
SLOT_RX_OPT_CHN:0x27, MAIN_AVR_PWR:0x30-31
OPT_AVR_PWR:0x32-33, MCS_VALUE:0x34
```

## 协议说明

### 消息格式

```
struct ar_dbg_msg {
    header1: u8,      // 0xff
    header2: u8,      // 0x5a
    version: u8,      // 0
    msg_id: u8,       // 0=SYS, 1=REG, 2=BB, 3=CMR
    seq_num: u16,     // 序列号
    msg_len: u32,     // payload 长度
    header_sum: u8,   // 头部校验和
    checksum: u16,    // payload 校验和
    payload: [u8],    // 数据
}
```

### BB 消息格式

发送（请求）:
```
struct bb_msg_header {
    bb_msg_id: u8,    // 命令 ID (如 GET_OSD_INFO = 0x01)
    payload: [u8],    // 命令参数
}
```

接收（响应）:
```
struct bb_rcv_msg_header {
    bb_msg_id: u8,    // 命令 ID
    ret_type: u8,     // 返回类型
    payload: [u8],    // OSD 数据
}
```

### OSD 命令

- 获取设备信息: `bb_msg_id=0x02` (返回角色: 0=DEV, 1=AP)
- 启动 OSD: `bb_msg_id=0x01, payload=[0x01, cycle_cnt, user_id]`
- 停止 OSD: `bb_msg_id=0x01, payload=[0x00, 0x00, 0x00]`

## 编译

```bash
cd tools/ar_dbg_client
cargo build --release
```

## 使用

```bash
# 默认连接并自动检测设备角色
./target/release/ar_dbg_client -H 192.168.1.100

# 强制使用 AP 角色
./target/release/ar_dbg_client --role ap

# 强制使用 DEV 角色
./target/release/ar_dbg_client --role dev

# 调试模式（显示原始 hex dump）
./target/release/ar_dbg_client -d

# 详细输出
./target/release/ar_dbg_client -v

# 原始数据模式
./target/release/ar_dbg_client -r

# 每5秒显示一次摘要
./target/release/ar_dbg_client -s 5
```

### Web 界面模式

```bash
# 启动带 Web 界面的客户端（默认 8080 端口）
./target/release/ar_dbg_web -H 192.168.1.100

# 指定 Web 端口
./target/release/ar_dbg_web -H 192.168.1.100 -w 3000

# 强制指定设备角色
./target/release/ar_dbg_web -H 192.168.1.100 --role ap
```

然后在浏览器中打开 http://localhost:8080 查看实时曲线图。

#### Web 界面功能
- 📈 SNR 信噪比实时曲线
- ⚠️ LDPC 错误实时曲线
- ⚡ 功率曲线（Main/Opt）
- 📊 MCS 值变化曲线
- 🎚️ AGC 增益柱状图（实时）
- 📋 实时数值面板
- 🔒 锁定状态指示
- 支持暂停/继续、清除数据
- 可调节显示时间范围（30秒-5分钟）

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-H, --host` | 目标 IP 地址 | 192.168.1.100 |
| `-p, --port` | 目标端口 | 1234 |
| `--role` | 强制设备角色 (ap/dev) | 自动检测 |
| `-d, --debug` | 调试模式（显示 hex dump） | false |
| `-v, --verbose` | 详细输出 | false |
| `-r, --raw` | 原始数据格式 | false |
| `-s, --summary-interval` | 摘要间隔（秒，0=实时） | 0 |

### Web 版本参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-H, --host` | 目标 IP 地址 | 192.168.1.100 |
| `-p, --port` | 目标端口 | 1234 |
| `-w, --web-port` | Web 服务器端口 | 8080 |
| `--role` | 强制设备角色 (ap/dev) | 自动检测 |
| `-v, --verbose` | 详细输出 | false |
| `-d, --debug` | 调试模式 | false |

## 示例输出

### DEV 模式
```
=== OSD Data (DEV) ===
BR_LOCK: 1 (Locked) | MCS: 7
BR_SNR: 1408 (22.0 dB) | BR_LDPC_ERR: 0
BR_AGC: [45, 46, 45, 47]
Channels: BR=36 SLOT_TX=44 SLOT_RX=44 SLOT_OPT=2
Power: MAIN_AVR=1000 OPT_AVR=800
```

### AP 模式
```
=== OSD Data (AP) ===
FCH_LOCK: 1 | SLOT_LOCK: 1 (Locked) | MCS: 7
SLOT_SNR: 1600 (24.0 dB) | SLOT_LDPC_ERR: 0 | AFTER_ERR: 0
SLOT_AGC: [50, 51, 52, 53]
SLOT_RX_OPT_CHN: 3
Power: MAIN_AVR=1200 OPT_AVR=900
```

## 作为库使用

```rust
use ar_dbg_client::{ArDbgClient, ClientConfig, DeviceRole};
use ar_dbg_client::osd::set_device_role;

#[tokio::main]
async fn main() {
    let config = ClientConfig {
        host: "192.168.1.100".to_string(),
        port: 1234,
    };
    
    let client = ArDbgClient::new(config);
    
    // 自动检测角色并启动 OSD 流
    client.start_osd_stream_auto_role(|osd| {
        println!("Role: {:?}, SNR: {:.1} dB", osd.role, osd.snr_db());
    }).await.unwrap();
}
```
