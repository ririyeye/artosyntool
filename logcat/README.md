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

日志存储使用 rslog 的二进制通道 0，可以使用 rslog 工具查看：

```bash
# 导出日志
rslog dump /factory/rslog.dat

# 查看统计
rslog stats /factory/rslog.dat
```
