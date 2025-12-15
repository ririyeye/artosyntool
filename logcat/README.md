# logcat

日志抓取工具 - 使用 `ar_logcat` 抓取日志并存储到 rslog 二进制通道。

## 功能

- **本地模式**: 本地执行 `ar_logcat` 命令
- **远程模式**: 通过 SSH 连接到远程机器执行 `ar_logcat`
- 使用 rslog 存储日志到二进制通道 0

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
# 使用密码认证
logcat remote -H 192.168.1.100 -u root -P password

# 使用密钥认证
logcat remote -H 192.168.1.100 -u root -k ~/.ssh/id_rsa

# 指定自定义命令
logcat remote -H 192.168.1.100 -u root -P password -c "ar_logcat -v"
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
  remote  远程模式: 通过 SSH 远程执行 ar_logcat
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
