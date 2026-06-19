/*****************************************************************************
 * kkma_container.h: KKMA single-file container parser (parser layer)
 *****************************************************************************
 * 阶段 A:明文 .kkma 单文件容器读取层。本头文件只描述容器的"虚拟文件视图"
 * 抽象,不依赖任何 VLC API,以便:
 *   - 在 VLC 之外做单元测试
 *   - 容器格式升级(v2 + per-segment IV)时只动这一层,不影响 access 模块
 *
 * 容器格式(v1)与 drmplayer_encryptor/encryptor/src/container/kkma_packer.{h,cpp}
 * 完全一致,布局:
 *
 *     [Header  20 字节]
 *       'K','K','M','A'    (magic, 4 字节)
 *       version            (uint32_le, 当前 = 1)
 *       index_offset       (uint64_le, 索引表在文件中的字节偏移)
 *       entry_count        (uint32_le, 索引表条目数)
 *
 *     [Data 区]            按 entry 顺序拼接的原始字节
 *
 *     [Index 区]
 *       repeat entry_count 次:
 *         name_len         (uint32_le)
 *         name             (UTF-8, name_len 字节, 不含 \0)
 *         offset           (uint64_le, 在文件中的绝对字节偏移)
 *         length           (uint64_le, entry 字节数)
 *
 * 全部小端序。
 *****************************************************************************/
#ifndef KKMA_CONTAINER_H
#define KKMA_CONTAINER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 容器内单个 entry 的元数据。name 由容器持有,生命周期 = 容器对象。 */
typedef struct kkma_entry
{
    char    *name;     /* UTF-8, '\0' 结尾 */
    uint64_t offset;   /* 在 .kkma 文件中的绝对字节偏移 */
    uint64_t length;   /* entry 字节数 */
} kkma_entry_t;

/* 容器句柄。打开 .kkma 文件、解析 Header + Index Table 后持有所有 entry。 */
typedef struct kkma_container kkma_container_t;

/*
 * 打开 .kkma 文件并解析索引表。container_path 为 UTF-8 绝对路径。
 * 成功返回非 NULL 句柄;失败返回 NULL,如果 *err_msg 非 NULL,会设置一段
 * 静态错误描述(无需调用方释放)。
 *
 * 实现使用 vlc_fopen 兼容的 fopen,因此 Windows 中文路径需要由调用方保证
 * UTF-8 编码(VLC 的 access 层已经做这件事)。
 */
kkma_container_t *kkma_open(const char *container_path, const char **err_msg);

/* 关闭句柄并释放所有资源。传 NULL 安全。 */
void kkma_close(kkma_container_t *c);

/* 在容器中按名字查找 entry。找不到返回 NULL。返回的指针生命周期 = 容器。 */
const kkma_entry_t *kkma_find(const kkma_container_t *c, const char *name);

/*
 * 从指定 entry 的 [pos, pos+want_len) 区间读字节到 buf。返回实际读取的字节数,
 * 0 表示已到该 entry 末尾,负数表示 IO 错误。
 *
 * pos 是 entry 内的相对偏移(不是文件绝对偏移);函数内部会把它换算成
 * `entry->offset + pos` 再 fseek。
 *
 * 这是一个"虚拟文件视图":即使 .kkma 是 1 GB 大文件,VLC 上层看到的也只是
 * 单个 entry 的字节序列,长度 == entry->length。
 */
int64_t kkma_read_entry(kkma_container_t *c, const kkma_entry_t *entry,
                        uint64_t pos, void *buf, size_t want_len);

#ifdef __cplusplus
}
#endif

#endif /* KKMA_CONTAINER_H */
