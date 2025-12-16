# logcat

日志抓取工具 - 使用 `ar_logcat` 抓取日志并存储到 rslog 二进制通道，同时支持寄存器跟踪数据采集。

## 功能

- **本地模式**: 本地执行 `ar_logcat` 命令
- **远程模式**: 通过 SSH 连接到远程机器执行 `ar_logcat`，同时采集寄存器跟踪数据
- 使用 rslog 存储：
  - 通道 0：logcat 文本日志
  - 通道 1：寄存器跟踪数据（二进制格式）
- **导出模式**: 将 rslog 中的数据导出为可读格式

## 使用方法

### 本地模式（默认）

```bash
# 使用默认配置（本地，输出 /factory/rslog.dat，3MB）
logcat

# 指定输出文件和命令
logcat local -c "ar_logcat -v" -o /tmp/log.dat
```

### 远程模式

```bash
# 使用密码认证（不采集寄存器）
logcat remote -H 192.168.1.100 -u root -P password

# 使用密钥认证
logcat remote -H 192.168.1.100 -u root -k ~/.ssh/id_rsa

# 指定寄存器配置文件进行寄存器跟踪
logcat remote -H 192.168.1.100 -u root -P password -C reg_config.json

# 指定自定义命令和寄存器端口
logcat remote -H 192.168.1.100 -u root -P password -c "ar_logcat -v" -r 12345 -C reg_config.json
```

### 导出模式

```bash
# 从已有 rslog 导出
logcat export -i rslog_remote.dat -D ./logcat_export

# 导出结果
# - ar_logcat.txt : ar_logcat 文本（带时间戳）
# - reg_trace.csv : 寄存器数据 CSV（首列时间戳，第二列 seq_id，后续为寄存器值）
# - reg_descriptor.json : 寄存器字段说明（字段名、页、偏移、宽度等）
```

## 寄存器配置文件格式

JSON 格式，示例：

```json
{
  "name": "example_regs",
  "description": "示例寄存器配置",
  "host": "192.168.1.100",
  "port": 12345,
  "sample_div": 1,
  "buffer_depth": 100,
  "items": [
    {
      "page": 0,
      "offset": 0,
      "width": 4,
      "name": "status_reg",
      "description": "状态寄存器",
      "unit": ""
    },
    {
      "page": 0,
      "offset": 4,
      "width": 4,
      "name": "ctrl_reg",
      "description": "控制寄存器",
      "unit": ""
    }
  ]
}
```

## 命令行参数

```
logcat [OPTIONS] [COMMAND]

Options:
  -o, --output <OUTPUT>      输出文件路径（可选，模式默认不同）
  -m, --max-size <MAX_SIZE>  最大存储大小（字节，可选，模式默认不同）
  -v, --verbose              详细输出
  -h, --help                 显示帮助

Commands:
  local   本地模式: 本地执行 ar_logcat
  remote  远程模式: 通过 SSH 远程执行 ar_logcat，同时抓取寄存器数据
  export  导出模式: 输出 ar_logcat 文本与寄存器 CSV
```

### local 子命令

```
logcat local [OPTIONS]

Options:
  -c, --cmd <CMD>  ar_logcat 命令路径 [默认: ar_logcat]

默认值（本地）：
- 输出: /factory/rslog.dat
- 大小: 3MB
```

### remote 子命令

```
logcat remote [OPTIONS]

Options:
  -H, --host <HOST>          SSH 主机地址
  -p, --port <PORT>          SSH 端口 [默认: 22]
  -u, --user <USER>          SSH 用户名 [默认: root]
  -P, --password <PASSWORD>  SSH 密码
  -k, --key <KEY>            SSH 私钥路径
  -c, --cmd <CMD>            ar_logcat 命令路径 [默认: ar_logcat]

默认值（远程）：
- 输出: ./rslog_remote.dat（当前工作目录）
- 大小: 64MB
```

## 数据存储

日志和寄存器跟踪数据使用 rslog 的二进制通道存储：

- **通道 0**: logcat 文本日志
- **通道 1**: 寄存器跟踪数据（二进制格式）

### 寄存器跟踪存储格式

寄存器跟踪数据采用分块（Chunk）存储，所有 Chunk 都经过 LZ4 压缩后写入 rslog 通道 1。

每种 Chunk 类型用 **4 字节 Magic** 区分：

| Chunk 类型 | Magic (ASCII) | Magic (Hex)          | 说明           |
|------------|---------------|----------------------|----------------|
| Chunk0     | "RTC0"        | `0x52 0x54 0x43 0x30` | 配置描述块     |
| ChunkN     | "RTDN"        | `0x52 0x54 0x44 0x4E` | 数据块         |

#### Chunk0 - 配置描述块

首个 Chunk（Chunk0）包含寄存器抓取配置信息，描述后续数据的布局：

```
┌─────────────────────────────────────────────────────────────────┐
│                    Chunk0 - 配置描述块                          │
├─────────────┬───────────┬───────────┬───────────┬──────────────┤
│   Magic     │item_count │sample_div │ reserved  │  items[]     │
│   4 bytes   │  1 byte   │  1 byte   │  2 bytes  │ N * ItemDesc │
│  "RTC0"     │           │           │           │              │
└─────────────┴───────────┴───────────┴───────────┴──────────────┘

ItemDesc 格式 (每项 8 字节):
┌─────────┬─────────┬─────────┬───────────┬───────────┬──────────┐
│  page   │ offset  │  width  │  reserved │ irq_mask  │ reserved │
│ 1 byte  │ 1 byte  │ 1 byte  │  1 byte   │  2 bytes  │ 2 bytes  │
└─────────┴─────────┴─────────┴───────────┴───────────┴──────────┘
```

示例配置:
```
Magic: "RTC0"
item_count = 3
items[0]: page=0, offset=4,  width=4, irq_mask=0x0002 (BR_END)
items[1]: page=1, offset=1,  width=8, irq_mask=0x0004 (CSMA)
items[2]: page=2, offset=16, width=4, irq_mask=0xFFFF (ALL)
```

#### ChunkN - 数据块

后续 Chunk 包含实际的寄存器采样数据，每个 Chunk 包含多条记录（通常几秒钟几百条）：

```
┌─────────────────────────────────────────────────────────────────┐
│                    ChunkN - 数据块                              │
├─────────────┬───────────────────────────────────────────────────┤
│   Magic     │  record_count (2 bytes, LE)                       │
│  "RTDN"     │                                                   │
├─────────────┴───────────────────────────────────────────────────┤
│  Record 0                                                       │
├─────────────────────────────────────────────────────────────────┤
│  Record 1                                                       │
├─────────────────────────────────────────────────────────────────┤
│  ...                                                            │
├─────────────────────────────────────────────────────────────────┤
│  Record N-1                                                     │
└─────────────────────────────────────────────────────────────────┘

单条记录格式:
┌──────────────┬──────────┬──────────┬──────────┬────────────────┐
│ timestamp_ms │  seq_id  │ irq_type │  word0   │ word1 ...      │
│   8 bytes    │ 4 bytes  │ 4 bytes  │ 4 bytes  │ 4*N bytes      │
└──────────────┴──────────┴──────────┴──────────┴────────────────┘
     LE(u64)     LE(u32)    LE(u32)     LE(u32)

- timestamp_ms: 64位毫秒时间戳 (Unix epoch)
- seq_id: 记录序列号
- irq_type: 触发该记录的中断类型
- wordN: 第N个寄存器的值 (固定 4 字节)
```

#### 存储与压缩流程

```
采集端:
  1. 启动时发送 Chunk0 (配置描述, Magic="RTC0") → LZ4压缩 → rslog 通道1
  2. 同时写入 JSON descriptor (便于人工查看)
  3. 采集数据累积到缓冲区
  4. 每隔一段时间或缓冲满时:
     - 封装为 ChunkN (数据块, Magic="RTDN") → LZ4压缩 → rslog 通道1

解码端:
  1. 从 rslog 通道1 读取所有记录
  2. 解压每个记录，检查前 4 字节 Magic:
     - "RTC0" → 解析为 Chunk0，获取配置信息
     - "RTDN" → 解析为 ChunkN，根据配置解析数据记录
  3. 输出为 CSV 格式
```

#### 解码输出

导出时生成以下文件:

- **reg_trace.csv**: 寄存器数据表格
  ```csv
  timestamp_us,reg0_status,reg1_ctrl,reg2_data
  1702728000000000,0x12345678,0xABCD,0x00FF
  1702728000001000,0x12345679,0xABCE,0x00FE
  ...
  ```

- **reg_descriptor.json**: 字段描述信息
  ```json
  {
    "version": 1,
    "item_count": 3,
    "sample_div": 1,
    "items": [
      {"name": "reg0_status", "page": 0, "offset": 4, "width": 4, "irq_mask": 2},
      {"name": "reg1_ctrl", "page": 1, "offset": 1, "width": 8, "irq_mask": 4},
      {"name": "reg2_data", "page": 2, "offset": 16, "width": 4, "irq_mask": 65535}
    ]
  }
  ```

### rslog 工具

可以使用 rslog 工具查看原始存储：

```bash
# 导出日志
rslog dump /factory/rslog.dat

# 查看统计
rslog stats /factory/rslog.dat
```

## 版本历史

- **v1.1** (2025-12-16): 
  - 新增寄存器跟踪功能（通道1）
  - 支持分块压缩存储（Chunk0 配置 + ChunkN 数据）
  - 导出支持 reg_trace.csv 和 reg_descriptor.json

- **v1.0**: 初始版本，仅支持 logcat 文本日志
