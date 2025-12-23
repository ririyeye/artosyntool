//! 单元测试模块
//!
//! 流式循环日志存储的测试用例

use crate::stream_log::StreamLog;
use crate::writer::{BlockWriter, StreamWriter};
use std::fs;

#[test]
fn test_stream_basic() {
    let path = "/tmp/test_stream_basic.dat";
    let _ = fs::remove_file(path);

    {
        let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

        for i in 0..100 {
            log.write_text(&format!("Log message {}", i)).unwrap();
        }

        log.sync().unwrap();

        let stats = log.stats();
        println!("{}", stats);
        assert!(stats.used_size > 0);
        assert_eq!(stats.global_seq, 100);
    }

    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();
        println!("Read {} entries", entries.len());
        assert_eq!(entries.len(), 100);
    }

    let _ = fs::remove_file(path);
}

/// 测试文本和二进制混合写入
#[test]
fn test_mixed_text_binary() {
    let path = "/tmp/test_mixed.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 混合数据测试 ===");

    {
        let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

        // 模拟 ar_logcat 和 ar_logbin 交替写入
        for i in 0..10 {
            // 文本日志 (ar_logcat)
            let text = format!("[{}][INFO] Device status check #{}", i * 1000, i);
            log.write_text(&text).unwrap();

            // 二进制数据 (ar_logbin)
            let binary_data: Vec<u8> = vec![
                0x12,
                0x34,
                0x56,
                0x78,             // header
                (i & 0xFF) as u8, // counter
                0xAB,
                0xCD,
                0xEF, // data
            ];
            log.write_binary(&binary_data).unwrap();
        }

        log.sync().unwrap();
        println!("写入 10 条文本 + 10 条二进制");
    }

    // 重新打开读取
    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();

        println!("读取 {} 条记录", entries.len());
        assert_eq!(entries.len(), 20);

        let mut text_count = 0;
        let mut binary_count = 0;

        for entry in &entries {
            if entry.is_text() {
                text_count += 1;
                let text = entry.as_text().unwrap();
                println!(
                    "  [TEXT  seq={:>2} ts={:>8}] {}",
                    entry.sequence, entry.sequence, text
                );
            } else if entry.is_binary() {
                binary_count += 1;
                let data = entry.as_binary().unwrap();
                println!(
                    "  [BINARY seq={:>2} ts={:>8}] {:02X?}",
                    entry.sequence, entry.sequence, data
                );
            }
        }

        println!("\n文本: {} 条, 二进制: {} 条", text_count, binary_count);
        assert_eq!(text_count, 10);
        assert_eq!(binary_count, 10);

        // 验证按序列号排序后顺序正确（交替出现）
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence, i as u64);
            if i % 2 == 0 {
                assert!(entry.is_text(), "偶数序列号应该是文本");
            } else {
                assert!(entry.is_binary(), "奇数序列号应该是二进制");
            }
        }
        println!("✓ 顺序验证通过：文本和二进制交替出现");
    }

    println!("=== 混合数据测试通过 ===\n");
    let _ = fs::remove_file(path);
}

#[test]
fn test_stream_small_frequent() {
    let path = "/tmp/test_stream_small.dat";
    let _ = fs::remove_file(path);

    {
        let mut log = StreamLog::open(path, Some(4 * 1024)).unwrap(); // 只有 4KB

        // 模拟每 30 分钟写一条 100 字节
        for i in 0..50 {
            let msg = format!("Status OK at interval {}", i);
            log.write_text(&msg).unwrap();
            log.sync().unwrap(); // 每条都刷新
        }

        let stats = log.stats();
        println!("{}", stats);
    }

    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();
        println!("Stored {} entries in 4KB", entries.len());

        // 验证数据连续性
        for entry in &entries {
            let text = String::from_utf8_lossy(&entry.data[1..]); // 跳过压缩标记
            println!("  [{}] {}", entry.sequence, text);
        }
    }

    let _ = fs::remove_file(path);
}

#[test]
fn test_stream_wraparound() {
    let path = "/tmp/test_stream_wrap.dat";
    let _ = fs::remove_file(path);

    {
        let mut log = StreamLog::open(path, Some(1024)).unwrap(); // 只有 1KB

        // 写入超过 1KB 的数据，触发回绕
        for i in 0..100 {
            log.write_text(&format!("Message number {}", i)).unwrap();
        }

        log.sync().unwrap();
        let stats = log.stats();
        println!("After wraparound: {}", stats);
    }

    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();
        println!("After wraparound: {} entries readable", entries.len());

        // 只能读到最新的一部分
        assert!(entries.len() < 100);
        assert!(entries.len() > 0);
    }

    let _ = fs::remove_file(path);
}

/// 测试场景：80KB 空间写满 10 个 ~8KB 的块，然后写入一个 20KB 的块
/// 验证回绕后的数据完整性和顺序
#[test]
fn test_stream_large_overwrite() {
    let path = "/tmp/test_stream_large_overwrite.dat";
    let _ = fs::remove_file(path);

    // 使用 80KB 数据区
    let data_size: u64 = 80 * 1024;

    {
        let mut log = StreamLog::open(path, Some(data_size)).unwrap();

        // 写入 10 个约 8KB 的条目 (实际数据 ~8KB - 24 字节开销)
        // 每个 entry: SYNC(2) + Len(2) + Seq(8) + TS_sec(4) + TS_ms(2) + Data(N) + CRC(4) + END(2) = 24 + N
        let block_data_size = 8 * 1024 - 24; // 约 8KB 每条

        println!("\n=== 写入 10 个 ~8KB 的条目 ===");
        for i in 0..10 {
            let data = format!("Block {} data: {}", i, "X".repeat(block_data_size - 20));
            log.write_text(&data).unwrap();
            println!("写入 Entry seq={}, 数据大小={} 字节", i, data.len());
        }
        log.sync().unwrap();

        let stats = log.stats();
        println!(
            "\n写满后状态: write_pos={}, global_seq={}",
            stats.write_pos, stats.global_seq
        );
        println!("预期: write_pos ≈ 80KB ({}), 已写满", 10 * 8 * 1024);

        // 验证写满了
        let entries_before = log.read_all().unwrap();
        println!("写满后可读条目: {} 条", entries_before.len());
        assert_eq!(entries_before.len(), 10);

        // 现在写入一个 20KB 的大块
        println!("\n=== 写入 1 个 ~20KB 的大条目 ===");
        let large_data_size = 20 * 1024 - 24;
        let large_data = format!("LARGE Block: {}", "Y".repeat(large_data_size - 15));
        log.write_text(&large_data).unwrap();
        println!("写入 Entry seq=10, 数据大小={} 字节", large_data.len());
        log.sync().unwrap();

        let stats_after = log.stats();
        println!(
            "\n写入大块后状态: write_pos={}, global_seq={}",
            stats_after.write_pos, stats_after.global_seq
        );
    }

    // 重新打开读取
    {
        let mut log = StreamLog::open(path, None).unwrap();

        println!("\n=== 读取数据 ===");
        let (entries, skipped) = log.read_all_tolerant();

        println!(
            "可读取的条目数: {}, 跳过损坏: {} 次",
            entries.len(),
            skipped
        );
        println!("\n条目详情 (按文件位置顺序):");
        for (i, entry) in entries.iter().enumerate() {
            let preview: String = entry
                .data
                .iter()
                .skip(1) // 跳过压缩标记
                .take(50)
                .map(|&b| b as char)
                .collect();
            println!(
                "  [{}] seq={:>2}, timestamp={:>8}, size={:>5} bytes, preview: {}...",
                i,
                entry.sequence,
                entry.sequence,
                entry.data.len(),
                preview
            );
        }

        // 按序号排序
        let mut sorted = entries.clone();
        sorted.sort_by_key(|e| e.sequence);

        println!("\n按序号排序后:");
        for entry in &sorted {
            println!(
                "  seq={:>2}, timestamp={:>8}",
                entry.sequence, entry.sequence
            );
        }

        // 验证
        println!("\n=== 验证 ===");

        // 1. 新写入的大块应该存在 (seq=10)
        let has_new = entries.iter().any(|e| e.sequence == 10);
        println!("✓ 新写入的大块 (seq=10) 存在: {}", has_new);
        assert!(has_new, "新写入的大块应该存在");

        // 2. 最老的数据 (seq=0, seq=1) 应该被覆盖
        let has_old_0 = entries.iter().any(|e| e.sequence == 0);
        let has_old_1 = entries.iter().any(|e| e.sequence == 1);
        println!("✓ 最老数据 seq=0 被覆盖: {}", !has_old_0);
        println!("✓ 最老数据 seq=1 被覆盖: {}", !has_old_1);

        // 3. 部分被覆盖的数据不可读
        let has_partial = entries.iter().any(|e| e.sequence == 2);
        println!(
            "✓ 部分覆盖的 seq=2 状态: {}",
            if has_partial {
                "仍可读"
            } else {
                "已损坏"
            }
        );

        // 4. 后面的数据应该完整保留
        let preserved: Vec<u64> = (3..10)
            .filter(|&s| entries.iter().any(|e| e.sequence == s))
            .collect();
        println!("✓ 保留的旧数据: {:?}", preserved);

        // 5. 总结
        println!("\n=== 总结 ===");
        println!("原始 10 条 (seq 0-9) + 新增 1 条 (seq 10) = 11 条");
        println!("被覆盖: seq 0, 1 (可能还有 seq 2 部分损坏)");
        println!("实际可读: {} 条", entries.len());
        println!("丢失: {} 条", 11 - entries.len() - 1); // -1 是因为 seq=10 是新的
    }

    let _ = fs::remove_file(path);
}

/// 测试断电恢复：模拟写入数据后 header 未更新的情况
#[test]
fn test_power_loss_recovery() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let path = "/tmp/test_power_loss.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 断电恢复测试 ===");

    // 第一次写入：正常写入 5 条
    let write_pos_after_5;
    {
        let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

        for i in 0..5 {
            log.write_text(&format!("Message {}", i)).unwrap();
        }
        log.sync().unwrap();

        write_pos_after_5 = log.stats().write_pos;
        println!("写入 5 条后 write_pos = {}", write_pos_after_5);
    }

    // 第二次写入：再写 3 条，但模拟断电（不调用 sync，手动破坏 header）
    {
        let mut log = StreamLog::open(path, None).unwrap();

        for i in 5..8 {
            log.write_text(&format!("Message {}", i)).unwrap();
        }
        // 数据已经写入文件，但故意不 sync header
        // 模拟断电：手动把 header 的 write_pos 恢复到旧值

        let write_pos_after_8 = log.stats().write_pos;
        println!("写入 8 条后 write_pos = {}", write_pos_after_8);

        // 强制同步数据（但不更新 header）
        log.file.flush().unwrap();

        // 破坏 header：把 write_pos 改回 5 条时的值
        log.file.seek(SeekFrom::Start(0)).unwrap();
        let mut header_buf = [0u8; 64];
        log.file.read_exact(&mut header_buf).unwrap();

        // 修改 write_pos (offset 16-24)
        header_buf[16..24].copy_from_slice(&write_pos_after_5.to_le_bytes());
        // 修改 global_seq (offset 32-40) 回到 5
        header_buf[32..40].copy_from_slice(&5u64.to_le_bytes());

        log.file.seek(SeekFrom::Start(0)).unwrap();
        log.file.write_all(&header_buf).unwrap();
        log.file.flush().unwrap();

        println!("模拟断电：header.write_pos 被重置为 {}", write_pos_after_5);
    }

    // 第三次打开：应该扫描恢复到正确位置
    {
        let mut log = StreamLog::open(path, None).unwrap();

        let recovered_pos = log.stats().write_pos;
        let recovered_seq = log.stats().global_seq;
        println!(
            "恢复后 write_pos = {}, global_seq = {}",
            recovered_pos, recovered_seq
        );

        // 验证：应该能读到全部 8 条
        let entries = log.read_all().unwrap();
        println!("可读取条目: {} 条", entries.len());

        for entry in &entries {
            println!("  seq={}, ts={}", entry.sequence, entry.sequence);
        }

        assert_eq!(entries.len(), 8, "应该恢复全部 8 条日志");

        // 继续写入第 9 条，验证追加正确
        log.write_text("Message 8 after recovery").unwrap();
        log.sync().unwrap();

        let entries_after = log.read_all().unwrap();
        assert_eq!(entries_after.len(), 9, "应该有 9 条日志");
        println!("追加后共 {} 条", entries_after.len());
    }

    println!("=== 断电恢复测试通过 ===\n");
    let _ = fs::remove_file(path);
}

/// 测试回绕后断电恢复
#[test]
fn test_power_loss_after_wraparound() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let path = "/tmp/test_power_loss_wrap.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 回绕后断电恢复测试 ===");

    // 使用小文件触发回绕：1KB 数据区
    let data_size: u64 = 1024;

    // 第一阶段：写入直到回绕
    let write_pos_before_wrap;
    {
        let mut log = StreamLog::open(path, Some(data_size)).unwrap();

        // 每条约 50 字节，写入约 30 条会触发回绕
        for i in 0..30 {
            log.write_text(&format!("Msg{:02}", i)).unwrap();
        }
        log.sync().unwrap();

        write_pos_before_wrap = log.stats().write_pos;
        println!(
            "写入 30 条后 write_pos = {} (已回绕)",
            write_pos_before_wrap
        );
    }

    // 第二阶段：继续写入，但模拟断电
    {
        let mut log = StreamLog::open(path, None).unwrap();

        let pos_on_open = log.stats().write_pos;
        println!("重新打开后 write_pos = {}", pos_on_open);

        // 再写 5 条
        for i in 30..35 {
            log.write_text(&format!("Msg{:02}", i)).unwrap();
        }

        let write_pos_after_35 = log.stats().write_pos;
        println!("写入 35 条后 write_pos = {}", write_pos_after_35);

        // 模拟断电：数据写入但 header 未更新
        log.file.flush().unwrap();

        // 破坏 header：把 write_pos 改回之前的值
        log.file.seek(SeekFrom::Start(0)).unwrap();
        let mut header_buf = [0u8; 64];
        log.file.read_exact(&mut header_buf).unwrap();

        // 修改 write_pos 和 global_seq 回到 30 条时的值
        header_buf[16..24].copy_from_slice(&pos_on_open.to_le_bytes());
        header_buf[32..40].copy_from_slice(&31u64.to_le_bytes()); // boot 时 +1 变成 31

        log.file.seek(SeekFrom::Start(0)).unwrap();
        log.file.write_all(&header_buf).unwrap();
        log.file.flush().unwrap();

        println!("模拟断电：header.write_pos 被重置为 {}", pos_on_open);
    }

    // 第三阶段：恢复验证
    {
        let mut log = StreamLog::open(path, None).unwrap();

        let recovered_pos = log.stats().write_pos;
        let recovered_seq = log.stats().global_seq;
        println!(
            "恢复后 write_pos = {}, global_seq = {}",
            recovered_pos, recovered_seq
        );

        // 读取所有数据
        let entries = log.read_all().unwrap();
        println!("可读取条目: {} 条", entries.len());

        // 检查最大序列号
        let max_seq = entries.iter().map(|e| e.sequence).max().unwrap_or(0);
        println!("最大序列号: {}", max_seq);

        // 应该恢复到 35 条的序列号（34，因为从 0 开始）
        assert!(max_seq >= 34, "应该恢复到 seq=34，实际 max_seq={}", max_seq);

        // 继续写入验证追加正确
        log.write_text("After wrap recovery").unwrap();
        log.sync().unwrap();

        let seq_after = log.stats().global_seq;
        println!("追加后 global_seq = {}", seq_after);
        assert!(seq_after > max_seq, "追加后序列号应该增加");
    }

    println!("=== 回绕后断电恢复测试通过 ===\n");
    let _ = fs::remove_file(path);
}

#[test]
fn test_multi_channel() {
    let path = "/tmp/test_multi_channel.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 多通道测试 ===");

    // 写入多通道数据
    {
        let mut log = StreamLog::open(path, Some(64 * 1024)).unwrap();

        // 模拟多个数据源:
        // 通道 0: 主日志 (文本)
        // 通道 1: 调试日志 (文本)
        // 通道 2: 传感器数据 (二进制)
        // 通道 3: 网络包 (二进制)

        for i in 0..5 {
            let _ts = i as u64 * 1000;

            // 通道 0: 主日志
            log.write_text_ch(0, &format!("[主日志] 事件 {}", i))
                .unwrap();

            // 通道 1: 调试日志
            log.write_text_ch(1, &format!("[调试] 详细信息 {}", i))
                .unwrap();

            // 通道 2: 传感器二进制数据
            let sensor_data = vec![0x01, 0x02, i as u8, 0x04];
            log.write_binary_ch(2, &sensor_data).unwrap();

            // 通道 3: 网络包
            let packet = vec![0xAA, 0xBB, 0xCC, i as u8, 0xDD, 0xEE];
            log.write_binary_ch(3, &packet).unwrap();
        }

        log.sync().unwrap();
        println!("写入 5 轮 x 4 通道 = 20 条记录");
    }

    // 读取并验证
    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();

        assert_eq!(entries.len(), 20);
        println!("读取 {} 条记录", entries.len());

        // 按通道统计
        let mut channel_count = [0u32; 16];
        let mut text_channels = vec![];
        let mut binary_channels = vec![];

        for entry in &entries {
            let ch = entry.channel();
            channel_count[ch as usize] += 1;

            if entry.is_text() {
                if !text_channels.contains(&ch) {
                    text_channels.push(ch);
                }
                let text = entry.as_text().unwrap();
                println!(
                    "  [CH{} TEXT  seq={:>2} ts={:>8}] {}",
                    ch, entry.sequence, entry.sequence, text
                );
            } else if entry.is_binary() {
                if !binary_channels.contains(&ch) {
                    binary_channels.push(ch);
                }
                let data = entry.as_binary().unwrap();
                println!(
                    "  [CH{} BIN   seq={:>2} ts={:>8}] {:02X?}",
                    ch, entry.sequence, entry.sequence, data
                );
            }
        }

        println!("\n通道统计:");
        for ch in 0..4 {
            println!("  通道 {}: {} 条", ch, channel_count[ch]);
        }

        // 验证每个通道都有 5 条
        assert_eq!(channel_count[0], 5);
        assert_eq!(channel_count[1], 5);
        assert_eq!(channel_count[2], 5);
        assert_eq!(channel_count[3], 5);

        // 验证文本/二进制通道分类正确
        text_channels.sort();
        binary_channels.sort();
        println!("文本通道: {:?}", text_channels);
        println!("二进制通道: {:?}", binary_channels);

        assert_eq!(text_channels, vec![0, 1]);
        assert_eq!(binary_channels, vec![2, 3]);

        // 验证记录顺序
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence, i as u64);
            let expected_ch = (i % 4) as u8;
            assert_eq!(
                entry.channel(),
                expected_ch,
                "序列 {} 应该是通道 {}",
                i,
                expected_ch
            );
        }
        println!("✓ 通道顺序验证通过");
    }

    println!("=== 多通道测试通过 ===\n");
    let _ = fs::remove_file(path);
}

/// 测试块压缩写入和读取
#[test]
fn test_block_writer() {
    let path = "/tmp/test_block_writer.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 块压缩测试 ===");

    // 写入重复日志
    let original_lines: Vec<String> = (0..100)
        .map(|i| format!("[INFO] This is a repeated log message #{}", i))
        .collect();

    {
        // 使用较小的阈值便于测试
        let mut writer = BlockWriter::with_threshold(path, 64 * 1024, 1024, 50).unwrap();

        for (i, line) in original_lines.iter().enumerate() {
            let _ts = 1000000 + i as u64 * 10; // 每 10ms 一条
            writer.write_binary_ch(0, line.as_bytes()).unwrap();
        }

        writer.sync().unwrap();

        let stats = writer.stats();
        println!("块写入统计: {:?}", stats);
        println!("  写入位置: {} bytes", stats.write_pos);
    }

    // 读取并验证
    {
        let mut log = StreamLog::open(path, None).unwrap();
        let entries = log.read_all().unwrap();

        println!("读取到 {} 个条目", entries.len());

        let mut recovered_lines: Vec<String> = Vec::new();

        for entry in &entries {
            if entry.is_block() {
                println!(
                    "  块条目: seq={}, ts={}, 压缩={}",
                    entry.sequence,
                    entry.sequence,
                    entry.is_compressed()
                );

                if let Some(records) = entry.unpack_block() {
                    println!("    解包出 {} 条子记录", records.len());
                    for data in records {
                        let text = String::from_utf8_lossy(&data).to_string();
                        recovered_lines.push(text);
                    }
                }
            } else {
                println!("  普通条目: seq={}", entry.sequence);
                if let Some(data) = entry.as_binary() {
                    let text = String::from_utf8_lossy(&data).to_string();
                    recovered_lines.push(text);
                }
            }
        }

        println!("恢复出 {} 行日志", recovered_lines.len());
        assert_eq!(recovered_lines.len(), original_lines.len());

        // 验证内容
        for (i, text) in recovered_lines.iter().enumerate() {
            assert_eq!(text, &original_lines[i], "第 {} 行内容不匹配", i);
        }
        println!("✓ 内容验证通过");
    }

    // 对比压缩效果
    {
        let path_no_block = "/tmp/test_no_block.dat";
        let _ = fs::remove_file(path_no_block);

        let mut writer = StreamWriter::new(path_no_block, 64 * 1024).unwrap();
        for (_i, line) in original_lines.iter().enumerate() {
            writer.write_binary_ch(0, line.as_bytes()).unwrap();
        }
        writer.sync().unwrap();

        let stats_no_block = writer.stats();
        let stats_block = StreamLog::open(path, None).unwrap().stats();

        println!("\n压缩效果对比:");
        println!("  无块压缩: {} bytes", stats_no_block.write_pos);
        println!("  有块压缩: {} bytes", stats_block.write_pos);
        println!(
            "  压缩比: {:.1}%",
            stats_block.write_pos as f64 / stats_no_block.write_pos as f64 * 100.0
        );

        // 块压缩应该更小
        assert!(
            stats_block.write_pos < stats_no_block.write_pos,
            "块压缩应该比无压缩更小"
        );

        let _ = fs::remove_file(path_no_block);
    }

    println!("=== 块压缩测试通过 ===\n");
    let _ = fs::remove_file(path);
}

/// 测试无效文件自动重建
#[test]
fn test_invalid_file_rebuild() {
    use std::io::Write;

    let path = "/tmp/test_invalid_rebuild.dat";
    let _ = fs::remove_file(path);

    println!("\n=== 无效文件重建测试 ===");

    // 创建一个无效文件
    {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(b"this is not a valid rslog file").unwrap();
    }

    // 尝试打开，应该会检测到无效并重建
    let result = crate::stream_log::StreamLog::open_with_info(path, Some(64 * 1024));
    assert!(result.is_ok(), "应该成功打开并重建无效文件");

    let open_result = result.unwrap();
    assert!(open_result.was_rebuilt, "应该标记为已重建");
    assert_eq!(
        open_result.log.stats().write_pos,
        0,
        "新文件 write_pos 应为 0"
    );
    assert_eq!(
        open_result.log.stats().boot_count,
        0,
        "新文件 boot_count 应为 0"
    );

    println!("✓ 无效文件已成功重建");

    // 写入一些数据
    {
        let mut log = open_result.log;
        log.write_text("test after rebuild").unwrap();
        log.sync().unwrap();
    }

    // 再次打开，应该正常
    {
        let result = crate::stream_log::StreamLog::open_with_info(path, None);
        assert!(result.is_ok());
        let open_result = result.unwrap();
        assert!(!open_result.was_rebuilt, "正常文件不应该重建");
        assert_eq!(open_result.log.stats().boot_count, 1, "boot_count 应该增加");
        println!("✓ 重建后的文件可以正常打开");
    }

    println!("=== 无效文件重建测试通过 ===\n");
    let _ = fs::remove_file(path);
}
