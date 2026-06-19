/*****************************************************************************
 * kkma_container.c: KKMA single-file container parser (parser layer)
 *****************************************************************************
 * 见 kkma_container.h 的格式描述。本文件只做:
 *   1. 打开文件、读 Header、读 Index Table
 *   2. 通过 entry 名查找
 *   3. 在 entry 字节区间内做 pread 风格的随机读
 *
 * 不依赖 VLC API。线程模型:每个 kkma_container_t 仅由一个调用者使用。
 * VLC adaptive 框架对每个 segment 创建独立 access 实例,天然每实例一个
 * 句柄,因此不需要内部加锁。
 *
 * 实现选择:
 *   - 用标准 C <stdio.h> 的 FILE* + fseeko,避免引入 VLC 的 vlc_fs 依赖。
 *     这样本层在 VLC 外的单元测试中也能直接编译。
 *   - 文件是只读 + 顺序/随机混合访问,不做内存映射。
 *   - 索引读取一次性完成并常驻内存:典型 .kkma 索引表只有几 KB 量级。
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "kkma_container.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  define fseeko _fseeki64
#  define ftello _ftelli64
#endif

#define KKMA_HEADER_SIZE 20  /* 4 magic + 4 version + 8 index_offset + 4 count */
#define KKMA_VERSION_V1  1

struct kkma_container
{
    FILE         *fp;
    uint32_t      version;
    uint64_t      index_offset;
    uint32_t      entry_count;
    kkma_entry_t *entries;     /* 长度 = entry_count */

    /* 性能优化:adaptive 顺序读 segment 时,连续 kkma_read_entry 调用之间
     * 文件位置已经对齐,不需要 fseek。这个字段记 fp 当前真实位置,
     * 调用方请求 entry->offset+pos 与之相等时跳过 fseek。
     * 任何会改 fp 位置的操作必须更新它。 */
    int64_t       fp_pos;
};

/* ---------- 小端序读取辅助 ---------- */

static bool read_u32_le(FILE *fp, uint32_t *out)
{
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) return false;
    *out = ((uint32_t)buf[0])       |
           ((uint32_t)buf[1] << 8)  |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
    return true;
}

static bool read_u64_le(FILE *fp, uint64_t *out)
{
    uint8_t buf[8];
    if (fread(buf, 1, 8, fp) != 8) return false;
    *out = ((uint64_t)buf[0])       |
           ((uint64_t)buf[1] << 8)  |
           ((uint64_t)buf[2] << 16) |
           ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) |
           ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) |
           ((uint64_t)buf[7] << 56);
    return true;
}

/* ---------- 资源释放 ---------- */

static void free_entries(kkma_entry_t *entries, uint32_t count)
{
    if (!entries) return;
    for (uint32_t i = 0; i < count; ++i) {
        free(entries[i].name);
    }
    free(entries);
}

/* ---------- Header / Index 解析 ---------- */

static bool parse_header(kkma_container_t *c, const char **err)
{
    char magic[4];
    if (fread(magic, 1, 4, c->fp) != 4) {
        if (err) *err = "kkma: cannot read magic";
        return false;
    }
    if (magic[0] != 'K' || magic[1] != 'K' ||
        magic[2] != 'M' || magic[3] != 'A') {
        if (err) *err = "kkma: bad magic";
        return false;
    }
    if (!read_u32_le(c->fp, &c->version) ||
        !read_u64_le(c->fp, &c->index_offset) ||
        !read_u32_le(c->fp, &c->entry_count)) {
        if (err) *err = "kkma: short header";
        return false;
    }
    if (c->version != KKMA_VERSION_V1) {
        /* 阶段 A 只接受 v1。v2 在阶段 C 引入,届时按 version 分支扩展。 */
        if (err) *err = "kkma: unsupported version (only v1 supported in stage A)";
        return false;
    }
    return true;
}

static bool parse_index(kkma_container_t *c, const char **err)
{
    if (fseeko(c->fp, (int64_t)c->index_offset, SEEK_SET) != 0) {
        if (err) *err = "kkma: cannot seek to index";
        return false;
    }

    if (c->entry_count == 0) {
        c->entries = NULL;
        return true;
    }

    c->entries = (kkma_entry_t *)calloc(c->entry_count, sizeof(*c->entries));
    if (!c->entries) {
        if (err) *err = "kkma: out of memory";
        return false;
    }

    for (uint32_t i = 0; i < c->entry_count; ++i) {
        uint32_t name_len = 0;
        if (!read_u32_le(c->fp, &name_len)) {
            if (err) *err = "kkma: short index (name_len)";
            return false;
        }
        /* 防御:容器里不应该有超大名字,4KB 已经远超 DASH 的 chunk-streamX-NNNNN.m4s */
        if (name_len > 4096) {
            if (err) *err = "kkma: entry name too large";
            return false;
        }

        char *name = (char *)malloc((size_t)name_len + 1);
        if (!name) { if (err) *err = "kkma: out of memory"; return false; }
        if (name_len > 0 && fread(name, 1, name_len, c->fp) != name_len) {
            free(name);
            if (err) *err = "kkma: short index (name)";
            return false;
        }
        name[name_len] = '\0';

        uint64_t offset = 0, length = 0;
        if (!read_u64_le(c->fp, &offset) || !read_u64_le(c->fp, &length)) {
            free(name);
            if (err) *err = "kkma: short index (offset/length)";
            return false;
        }

        c->entries[i].name   = name;
        c->entries[i].offset = offset;
        c->entries[i].length = length;
    }
    return true;
}

/* ---------- 公共 API ---------- */

kkma_container_t *kkma_open(const char *container_path, const char **err_msg)
{
    if (!container_path) {
        if (err_msg) *err_msg = "kkma: null path";
        return NULL;
    }

    kkma_container_t *c = (kkma_container_t *)calloc(1, sizeof(*c));
    if (!c) { if (err_msg) *err_msg = "kkma: out of memory"; return NULL; }

    /* "rb" 二进制只读;Windows 下 fopen 接 UTF-8 路径需要进程默认 ANSI 兼容,
     * VLC 的 access 层已经把路径转好。如果未来需要支持非 ANSI 中文,改用
     * vlc_fopen 即可——封装在这一层,access 模块不动。 */
    c->fp = fopen(container_path, "rb");
    if (!c->fp) {
        if (err_msg) *err_msg = "kkma: cannot open file";
        free(c);
        return NULL;
    }

    if (!parse_header(c, err_msg) || !parse_index(c, err_msg)) {
        kkma_close(c);
        return NULL;
    }
    return c;
}

void kkma_close(kkma_container_t *c)
{
    if (!c) return;
    if (c->fp) fclose(c->fp);
    free_entries(c->entries, c->entry_count);
    free(c);
}

const kkma_entry_t *kkma_find(const kkma_container_t *c, const char *name)
{
    if (!c || !name) return NULL;
    for (uint32_t i = 0; i < c->entry_count; ++i) {
        if (strcmp(c->entries[i].name, name) == 0)
            return &c->entries[i];
    }
    return NULL;
}

int64_t kkma_read_entry(kkma_container_t *c, const kkma_entry_t *entry,
                        uint64_t pos, void *buf, size_t want_len)
{
    if (!c || !entry || !buf) return -1;
    if (pos >= entry->length) return 0;  /* EOF */

    /* 把读取范围 clamp 在 entry 内,避免越界读到下一段 entry 或索引表。 */
    uint64_t remaining = entry->length - pos;
    size_t   to_read   = (want_len < remaining) ? want_len : (size_t)remaining;

    /* 性能优化:VLC adaptive 顺序读 segment 时,连续两次调用之间 fp 位置
     * 已经对齐(上次读完正好停在这次的起点)。fseeko 即使是 no-op 也会
     * 调用 stdio 的内部 flush + lseek,有可观开销;比对 fp_pos 跳过即可。 */
    const int64_t want_abs = (int64_t)(entry->offset + pos);
    if (c->fp_pos != want_abs) {
        if (fseeko(c->fp, want_abs, SEEK_SET) != 0)
            return -1;
        c->fp_pos = want_abs;
    }

    size_t got = fread(buf, 1, to_read, c->fp);
    if (got == 0 && ferror(c->fp))
        return -1;
    c->fp_pos += (int64_t)got;
    return (int64_t)got;
}
