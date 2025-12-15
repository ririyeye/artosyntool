# Artosyn Register Trace Client (Rust)

用于连接 Artosyn 寄存器跟踪服务（ar_reg_trace）并采集寄存器数据的 Rust 客户端。

## 功能

- 连接到 ar_reg_trace 服务 (TCP 端口 12345)
- 配置要采集的寄存器项（页号、偏移、宽度）
- 启动/停止采集
- 查询采集状态
- 拉取采集数据
- 持续监控模式
- **默认采集第一页寄存器**

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
| FetchData | 0xB4 | 拉取数据 |
| ClearBuffer | 0xB5 | 清空缓冲区 |
| GetVersion | 0xB8 | 获取版本信息 |
| Ping | 0xB9 | 心跳检测 |

### 配置项结构

每个配置项 4 字节:
```
struct reg_trace_item {
    page: u8,      // 寄存器页号 (0-5)
    offset: u8,    // 页内偏移地址
    width: u8,     // 读取宽度: 1/2/4 字节
    reserved: u8,  // 保留
}
```

### 采集记录结构

```
struct trace_record {
    timestamp_us: u32,    // 时间戳(微秒)
    seq_id: u32,          // 记录序列号
    values: [u32],        // 寄存器值数组
}
```

## 编译

```bash
cd ar_dbg_client
cargo build --release
```

## 使用

```bash
# 心跳测试
./target/release/ar_dbg_client -H 192.168.1.100 ping

# 获取版本
./target/release/ar_dbg_client -H 192.168.1.100 version

# 配置抓取项（第一页，偏移0和4，各4字节）
./target/release/ar_dbg_client -H 192.168.1.100 config "0,0x00,4;0,0x04,4"

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

配置字符串格式: `page,offset,width;page,offset,width;...`

- `page`: 寄存器页号 (0-5)
- `offset`: 页内偏移，支持十六进制 (0x00-0xFF)
- `width`: 读取宽度 (1, 2, 4)

示例:
- `"0,0x00,4"` - 页0，偏移0，4字节
- `"0,0x00,4;0,0x04,4"` - 两个配置项
- `"1,0x10,4;4,0xDC,4"` - 页1偏移0x10 和 页4偏移0xDC

## 默认配置

如果不指定配置项，将使用默认配置：
- 页0，偏移 0x00，4字节
- 页0，偏移 0x04，4字节
- 页0，偏移 0x08，4字节
- 页0，偏移 0x0C，4字节

这对应于第一页的前16个字节（4个32位寄存器）。
