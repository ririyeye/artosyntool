/*
 * rslog 流式日志格式头文件
 * 用于嵌入式 C 代码读取/写入 rslog 格式
 *
 * 文件格式：
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │ FileHeader (64 bytes)                                       │
 *   ├─────────────────────────────────────────────────────────────┤
 *   │ Entry1 │ Entry2 │ ... │ EntryN │ [空闲] │ Entry1' (覆盖)    │
 *   └─────────────────────────────────────────────────────────────┘
 */

#ifndef RSLOG_H
#define RSLOG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * 常量定义
 *===========================================================================*/

/* 魔数 */
#define RSLOG_MAGIC 0x534C4F47 /* "SLOG" (little-endian) */

/* 版本 */
#define RSLOG_VERSION 1

/* 同步标记 */
#define RSLOG_SYNC_MAGIC 0xAA55 /* 条目起始标记 */
#define RSLOG_END_MAGIC  0x55AA /* 条目结束标记 */

/* 文件头大小 */
#define RSLOG_HEADER_SIZE 64

/* 条目开销: SYNC(2) + Len(2) + Seq(8) + TS_sec(4) + TS_ms(2) + CRC(4) + END(2)
 * = 24 bytes */
#define RSLOG_ENTRY_OVERHEAD 24

/* 默认最大存储大小 3MB */
#define RSLOG_DEFAULT_MAX_SIZE (3 * 1024 * 1024)

/*===========================================================================
 * 数据标记字节 (Data 首字节)
 *===========================================================================*/

/*
 * 格式: 0bCCCC_xTxE
 *   高4位 (bit7-4): 通道号 (0-15)
 *   bit2: 类型 (0=文本, 1=二进制)
 *   bit0: 压缩 (0=未压缩, 1=LZ4压缩)
 *
 * 示例:
 *   0x00 = 通道0, 文本, 未压缩
 *   0x01 = 通道0, 文本, LZ4压缩
 *   0x04 = 通道0, 二进制, 未压缩
 *   0x14 = 通道1, 二进制, 未压缩
 *   0x25 = 通道2, 二进制, LZ4压缩
 */
#define RSLOG_FLAG_COMPRESSED 0x01 /* bit0: LZ4 压缩 */
#define RSLOG_FLAG_BINARY     0x04 /* bit2: 二进制数据 */
#define RSLOG_CHANNEL_SHIFT   4    /* 通道号位移 */
#define RSLOG_CHANNEL_MASK    0xF0 /* 通道号掩码 */

/* 构造数据标记字节 */
#define RSLOG_MAKE_FLAG(channel, is_binary, is_compressed)                                                             \
    ((((channel) & 0x0F) << RSLOG_CHANNEL_SHIFT) | ((is_binary) ? RSLOG_FLAG_BINARY : 0)                               \
     | ((is_compressed) ? RSLOG_FLAG_COMPRESSED : 0))

/* 解析数据标记字节 */
#define RSLOG_GET_CHANNEL(flag)   (((flag) & RSLOG_CHANNEL_MASK) >> RSLOG_CHANNEL_SHIFT)
#define RSLOG_IS_BINARY(flag)     (((flag) & RSLOG_FLAG_BINARY) != 0)
#define RSLOG_IS_COMPRESSED(flag) (((flag) & RSLOG_FLAG_COMPRESSED) != 0)

/*===========================================================================
 * 数据结构
 *===========================================================================*/

/*
 * 文件头 (64 bytes)
 *
 * 偏移  大小  字段        说明
 * 0     4    magic       魔数 0x534C4F47 ("SLOG")
 * 4     4    version     版本号
 * 8     8    max_size    数据区最大大小
 * 16    8    write_pos   当前写入位置（相对于数据区）
 * 24    8    read_pos    最旧数据位置（保留）
 * 32    8    global_seq  全局序列号
 * 40    4    boot_count  启动次数
 * 44    4    flags       标志位
 * 48    16   reserved    保留
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* 魔数 "SLOG" */
    uint32_t version;      /* 版本号 */
    uint64_t max_size;     /* 数据区最大大小 */
    uint64_t write_pos;    /* 当前写入位置 */
    uint64_t read_pos;     /* 最旧数据位置（保留） */
    uint64_t global_seq;   /* 全局序列号 */
    uint32_t boot_count;   /* 启动次数 */
    uint32_t flags;        /* 标志位 */
    uint8_t  reserved[16]; /* 保留 */
} rslog_header_t;

/*
 * 日志条目格式 (变长)
 *
 * ┌──────┬──────┬────────┬──────────┬──────────┬──────┬──────┐
 * │ SYNC │ Len  │ SeqNum │ TS_ms    │ Data ... │ CRC  │ END  │
 * │ 2B   │ 2B   │ 8B     │ 6B       │ N bytes  │ 4B   │ 2B   │
 * └──────┴──────┴────────┴──────────┴──────────┴──────┴──────┘
 *
 * SYNC:     0xAA55 同步标记
 * Len:      数据长度（不含头尾，即 N）
 * SeqNum:   全局序列号
 * TS_ms:    毫秒时间戳 (6字节，范围约8925年)
 * Data:     数据（首字节为标记字节）
 * CRC:      CRC32 校验（从 Len 到 Data 结束）
 * END:      0x55AA 结束标记
 */
typedef struct __attribute__((packed)) {
    uint16_t sync;            /* 同步标记 0xAA55 */
    uint16_t data_len;        /* 数据长度 */
    uint64_t sequence;        /* 全局序列号 */
    uint8_t  timestamp_ms[6]; /* 毫秒时间戳 (little-endian) */
                              /* data[data_len] 紧随其后 */
                              /* uint32_t crc32; */
                              /* uint16_t end; */
} rslog_entry_header_t;

/*===========================================================================
 * 辅助函数
 *===========================================================================*/

/* 验证文件头 */
static inline int rslog_header_valid(const rslog_header_t* header)
{
    return header->magic == RSLOG_MAGIC && header->version == RSLOG_VERSION;
}

/* 验证条目同步标记 */
static inline int rslog_entry_sync_valid(const rslog_entry_header_t* entry)
{
    return entry->sync == RSLOG_SYNC_MAGIC;
}

/* 计算条目总大小 */
static inline uint32_t rslog_entry_total_size(uint16_t data_len)
{
    return RSLOG_ENTRY_OVERHEAD + data_len;
}

/* 计算数据区偏移 */
static inline uint64_t rslog_data_offset(uint64_t pos)
{
    return RSLOG_HEADER_SIZE + pos;
}

/*
 * CRC32 校验范围：从 data_len 字段开始到 data 结束
 * 即：&entry->data_len 到 data[data_len-1]
 * 长度：2(len) + 8(seq) + 6(ts_ms) + data_len = 16 + data_len
 */
#define RSLOG_CRC_OFFSET        2 /* CRC 从 data_len 开始，跳过 sync */
#define RSLOG_CRC_LEN(data_len) (2 + 8 + 6 + (data_len))

#ifdef __cplusplus
}
#endif

#endif /* RSLOG_H */
