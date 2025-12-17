# Artosyn Register Trace Client (Rust)

用于连接 Artosyn 寄存器跟踪服务（ar_reg_trace）并采集寄存器数据的 Rust 客户端。

## 功能

- 连接到 ar_reg_trace 服务 (TCP 端口 12345)
- 配置要采集的寄存器项（页号、偏移、宽度、中断掩码）
- 启动/停止采集
- 查询采集状态
- 拉取采集数据（支持新变长格式和旧固定格式）
- 持续监控模式
- **支持服务端主动推送数据 (DATA_PUSH)**
- **支持共享内存零拷贝模式**

## 协议说明

### 消息格式

```
struct reg_trace_msg {
    magic[2]: [u8; 2],    // 0xBB 0xAC
    version: u8,          // 协议版本 (0x01)
    cmd_id: u8,           // 命令ID
    seq_num: u16,         // 序列号 (小端)
    payload_len: u16,     // 负载长度 (小端)
    payload: [u8],        // 负载数据
}
```

### 命令 ID

| 命令 | ID | 说明 |
|------|-----|------|
| Config | 0xB0 | 配置抓取项 |
| Start | 0xB1 | 启动抓取 |
| Stop | 0xB2 | 停止抓取 |
| QueryStatus | 0xB3 | 查询缓冲区状态 |
| FetchData | 0xB4 | 拉取数据 (统一使用共享内存) |
| ClearBuffer | 0xB5 | 清空缓冲区 |
| GetShmInfo | 0xB6 | 获取共享内存信息 |
| FetchDataShm | 0xB7 | [别名] 与 FetchData 相同 |
| GetVersion | 0xB8 | 获取版本信息 |
| Ping | 0xB9 | 心跳检测 |
| **DataPush** | **0xBA** | **服务端主动推送数据 (新增)** |

### 配置项结构 (8字节)

```
struct reg_trace_item {
    page: u8,       // 寄存器页号 (0-5)
    offset: u8,     // 页内偏移地址
    width: u8,      // 读取宽度: 1-32 字节 (支持连续多寄存器读取)
    reserved: u8,   // 保留
    irq_mask: u16,  // 中断触发掩码
    reserved2: u16, // 保留
}
```

### 采集记录结构 (新变长格式)

```
struct trace_record {
    timestamp_us: u64,    // 时间戳(微秒) - 64位不回绕
    seq_id: u32,          // 记录序列号
    irq_type: u16,        // 触发的中断类型
    valid_mask: u16,      // 有效配置项位图: bit[i]=1 表示 item[i] 数据有效
    data_len: u16,        // 数据区长度
    data: [u8],           // 数据区：按 valid_mask 紧凑排列
}
```

### 中断触发掩码 (irq_mask)

| 掩码值   | 中断类型          | 说明                    |
|----------|-------------------|-------------------------|
| 0x0001   | RX_BR_END         | RX BR结束               |
| 0x0002   | TX_BR_END         | TX BR结束               |
| 0x0004   | CSMA_START_ENC    | CSMA开始编码            |
| 0x0008   | FSM_STATE_CHG     | FSM状态变化             |
| 0x0010   | FSM_TRX           | FSM收发                 |
| 0x0020   | SLOT_SOP          | Slot SOP                |
| 0x0040   | TX_PRE_ENC        | TX预编码                |
| 0x0080   | RX_RDOUT          | RX读出                  |
| 0x0100   | FCH_DEC           | FCH解码                 |
| 0x0200   | FREQ_SWEEP        | 扫频                    |
| 0xFFFF   | ALL               | 所有中断                |

## 编译

```bash
cd ar_dbg_client
cargo build --release
```

## 使用

### 流式模式（推荐）

配置后自动接收服务端推送的数据，无需手动轮询：

```bash
# 使用默认配置连接并接收推送数据
./target/release/ar_dbg_client -H 192.168.1.100 stream

# 使用自定义配置
./target/release/ar_dbg_client -H 192.168.1.100 stream -c "0,0x00,4,0x0001;1,0x00,4,0x0006"
```

### 传统模式

```bash
# 心跳测试
./target/release/ar_dbg_client -H 192.168.1.100 ping

# 获取版本
./target/release/ar_dbg_client -H 192.168.1.100 version

# 配置抓取项（页,偏移,宽度,中断掩码）
./target/release/ar_dbg_client -H 192.168.1.100 config "0,0x00,4,0x0001;0,0x04,4,0x0006"

# 使用默认配置（第一页前4个寄存器）
./target/release/ar_dbg_client -H 192.168.1.100 config

# 启动采集（清空缓冲区）
./target/release/ar_dbg_client -H 192.168.1.100 start --clear

# 查询状态
./target/release/ar_dbg_client -H 192.168.1.100 status

# 拉取数据
./target/release/ar_dbg_client -H 192.168.1.100 fetch --count 20

# 停止采集
./target/release/ar_dbg_client -H 192.168.1.100 stop

# 持续监控模式（自动配置、启动、持续拉取）
./target/release/ar_dbg_client -H 192.168.1.100 monitor --interval 1000

# 快速开始（配置默认第一页并启动）
./target/release/ar_dbg_client -H 192.168.1.100 quick-start

# 详细输出
./target/release/ar_dbg_client -H 192.168.1.100 -v status
```

## 命令行参数

```
Usage: ar_dbg_client [OPTIONS] <COMMAND>

Commands:
  ping         心跳检测
  version      获取版本信息
  config       配置抓取项
  start        启动采集
  stop         停止采集
  status       查询状态
  fetch        拉取数据
  clear        清空缓冲区
  shm-info     获取共享内存信息
  monitor      持续监控模式
  quick-start  快速开始（默认配置启动）

Options:
  -H, --host <HOST>        目标主机 IP [default: 192.168.1.100]
  -p, --port <PORT>        目标端口 [default: 12345]
  -t, --timeout <TIMEOUT>  超时时间秒 [default: 5]
  -v, --verbose            详细输出
  -h, --help               显示帮助
```

## 配置项格式

配置字符串格式: `page,offset,width[,irq_mask];page,offset,width[,irq_mask];...`

- `page`: 寄存器页号 (0-5)
- `offset`: 页内偏移，支持十六进制 (0x00-0xFF)
- `width`: 读取宽度 (1-32 字节，支持连续多寄存器读取)
- `irq_mask`: (可选) 中断触发掩码，默认 0xFFFF

示例:
- `"0,0x00,4"` - 页0，偏移0，4字节，所有中断触发
- `"0,0x00,4,0x0001"` - 只在 RX_BR_END 时采集
- `"0,0x00,32;0,0x20,32"` - 连续读取64字节

## 新工作流程 (v1.1+)

### 流式模式 (推荐)

1. 客户端连接并发送 CONFIG 配置
2. 服务端自动合并多客户端配置并下发固件
3. 服务端通过 **DATA_PUSH (0xBA)** 主动推送数据
4. 每个客户端只收到自己配置的寄存器数据
5. 断开连接时自动清理配置

### 传统轮询模式

1. CONFIG → START → 循环 FETCH → STOP

## 默认配置

如果不指定配置项，将使用默认配置：
- 页0，偏移 0x00，4字节
- 页0，偏移 0x04，4字节
- 页0，偏移 0x08，4字节
- 页0，偏移 0x0C，4字节

这对应于第一页的前16个字节（4个32位寄存器）。
