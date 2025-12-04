# rslog - 嵌入式循环日志存储系统

专为资源受限的嵌入式设备设计的日志存储系统，支持多通道混合数据（文本/二进制）。

## 特性

- **循环存储**: 当空间不足时自动覆盖最旧的日志
- **紧凑格式**: 流式存储，无固定块浪费，适合低频数据
- **断电安全**: CRC32 校验 + SYNC 标记，启动时自动扫描恢复
- **多通道支持**: 最多 16 个通道，支持多数据源混合存储
- **混合数据**: 同时支持文本日志和二进制数据（如传感器数据）
- **可选压缩**: 大文本/二进制自动 LZ4 压缩
- **容错恢复**: 损坏数据可跳过，尽可能恢复有效日志

## 存储格式

### 文件头 (64 bytes)

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | magic | 魔数 `0x52534C47` ("RSLG") |
| 4 | 4 | version | 版本号 |
| 8 | 8 | max_size | 数据区最大大小 |
| 16 | 8 | write_pos | 当前写入位置 |
| 24 | 8 | read_pos | 最旧数据位置 |
| 32 | 8 | global_seq | 全局序列号 |
| 40 | 4 | boot_count | 启动次数 |
| 44 | 20 | reserved | 保留 |

### 日志条目

| 字段 | 大小 | 说明 |
|------|------|------|
| SYNC | 2 | 同步标记 `0xAA55` |
| Len | 2 | 数据长度（不含头尾） |
| Seq | 8 | 序列号 |
| TS_ms | 6 | 毫秒时间戳（范围约8925年） |
| Data | N | 数据（首字节为标记） |
| CRC | 4 | CRC32 校验 |
| END | 2 | 结束标记 `0x55AA` |

每条日志开销：24 字节

### 数据标记字节

每条记录的 Data 首字节是标记字节，格式如下：

```text
字节: 0bCCCC_TC_E
      7654 32 10   (位编号)
      ││││ ││ │
      ││││ ││ └─ bit0: E = 压缩标记 (0=未压缩, 1=LZ4压缩)
      ││││ │└─── bit1: 保留
      ││││ └──── bit2: T = 类型 (0=文本, 1=二进制)
      ││││       bit3: 保留
      └┴┴┴────── bit7-4: CCCC = 通道号 (0-15)
```

**示例：**

| 字节值 | 二进制 | 含义 |
|--------|--------|------|
| `0x00` | `0000_0000` | 通道0, 文本, 未压缩 |
| `0x01` | `0000_0001` | 通道0, 文本, LZ4压缩 |
| `0x04` | `0000_0100` | 通道0, 二进制, 未压缩 |
| `0x14` | `0001_0100` | 通道1, 二进制, 未压缩 |
| `0x25` | `0010_0101` | 通道2, 二进制, LZ4压缩 |

## 编译

```bash
# 开发版本
cargo build

# 发布版本（优化大小）
cargo build --release
```

## 用法

### 命令行工具

```bash
# 默认记录（ar_logcat -> /factory/rslog.dat）
rslog

# 指定命令和输出
rslog record -c "ar_logcat" -o /data/rslog.dat

# 导出日志（按通道输出到目录）
rslog dump /data/rslog.dat
# 输出: /data/rslog.dat.log/0.txt, 1.txt, 2.bin ...

# 显示统计信息（含通道统计）
rslog stats /data/rslog.dat
```

### 作为库使用

```rust
use rslog::{StreamWriter, StreamLog};

// 获取当前毫秒时间戳
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// 写入多通道日志
fn write_logs() -> std::io::Result<()> {
    let mut writer = StreamWriter::new("/data/rslog.dat", 3 * 1024 * 1024)?;
    
    // 写入文本日志（默认通道 0，毫秒时间戳）
    writer.write_text(now_ms(), "main log message")?;
    
    // 写入指定通道的文本
    writer.log_mut().write_text_ch(1, now_ms(), "debug log")?;
    
    // 写入二进制数据（默认通道 0）
    let sensor_data = vec![0x01, 0x02, 0x03, 0x04];
    writer.log_mut().write_binary(now_ms(), &sensor_data)?;
    
    // 写入指定通道的二进制
    writer.log_mut().write_binary_ch(2, now_ms(), &sensor_data)?;
    
    writer.sync()?;
    Ok(())
}

// 读取日志
fn read_logs() -> std::io::Result<()> {
    let mut log = StreamLog::open("/data/rslog.dat", None)?;
    
    // 读取所有条目
    let entries = log.read_all()?;
    for entry in entries {
        let ch = entry.channel();
        let ts_ms = entry.timestamp_ms;  // 毫秒时间戳
        if entry.is_text() {
            if let Some(text) = entry.as_text() {
                println!("[CH{}][{}ms][TEXT] {}", ch, ts_ms, text);
            }
        } else if entry.is_binary() {
            if let Some(data) = entry.as_binary() {
                println!("[CH{}][{}ms][BIN] {:02X?}", ch, ts_ms, data);
            }
        }
    }
    
    // 容错读取（跳过损坏数据）
    let (entries, errors) = log.read_all_tolerant();
    println!("恢复 {} 条，跳过 {} 处损坏", entries.len(), errors);
    
    Ok(())
}
```

## 多通道使用场景

```
通道 0: 主系统日志 (文本)
通道 1: 调试日志 (文本)
通道 2: 传感器数据 (二进制)
通道 3: 网络包 (二进制)
...
通道 15: 备用
```

## 设计考虑

### 断电安全

每条日志独立校验：

- SYNC 标记（0xAA55）+ END 标记（0x55AA）用于定位数据边界
- CRC32 校验确保数据完整
- 启动时自动扫描恢复正确的写入位置
- 最多丢失一条正在写入的日志
- 恢复时自动跳过损坏数据，继续读取后续有效日志

### 循环覆盖

当文件写满时：

- 写入位置回到文件头之后
- 新数据覆盖最旧的日志
- 通过序列号排序，保证读取顺序正确

### 压缩

- 数据 > 256 字节时自动 LZ4 压缩
- 压缩标记存储在数据首字节
- 对重复性强的日志，压缩率约 30-50%

### 内存使用

- 文件头缓存：64 bytes
- 无块索引缓存
- 按需读取，适合低内存设备

## API 参考

### 写入方法

| 方法 | 说明 |
|------|------|
| `write_text(ts_ms, text)` | 写入文本（通道 0）|
| `write_text_ch(ch, ts_ms, text)` | 写入文本（指定通道）|
| `write_text_compressed_ch(ch, ts_ms, text)` | 强制压缩文本 |
| `write_binary(ts_ms, data)` | 写入二进制（通道 0）|
| `write_binary_ch(ch, ts_ms, data)` | 写入二进制（指定通道）|
| `write_binary_compressed_ch(ch, ts_ms, data)` | 强制压缩二进制 |

注：`ts_ms` 为毫秒时间戳（如 `SystemTime::now().duration_since(UNIX_EPOCH).as_millis()`）

### 读取方法

| 方法 | 说明 |
|------|------|
| `entry.channel()` | 获取通道号 0-15 |
| `entry.timestamp_ms` | 获取毫秒时间戳 |
| `entry.is_text()` | 是否文本数据 |
| `entry.is_binary()` | 是否二进制数据 |
| `entry.is_compressed()` | 是否压缩 |
| `entry.as_text()` | 解压并返回文本 |
| `entry.as_binary()` | 解压并返回二进制 |

## 配置建议

| Flash 大小 | 建议日志大小 | 100B 日志条数 |
|-----------|-------------|--------------|
| 4 MB      | 3 MB        | ~24000 条    |
| 8 MB      | 6 MB        | ~48000 条    |
| 16 MB     | 12 MB       | ~97000 条   |

（按每条日志 100 字节 + 24 字节开销计算）

## 许可证

MIT
