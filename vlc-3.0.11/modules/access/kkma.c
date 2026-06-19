/*****************************************************************************
 * kkma.c: KKMA single-file container access plugin
 *****************************************************************************
 * 阶段 A:让 VLC adaptive 框架能通过 kkma:// URL 直接读取 .kkma 容器内
 * 任意一个 entry 的字节流。把上层 VLC 看到的"虚拟文件"长度精确等于该 entry
 * 的 length,使得 DASH demuxer 完全无感:它以为自己在读一个普通 .m4s/.mp4。
 *
 *   URL 形态:
 *       kkma://x?container=<URL-encoded abs path>&entry=<URL-encoded entry name>
 *
 *   说明:
 *     - host 段固定占位 'x',目的是让 vlc_UrlParse 能正确产出 query。
 *     - container 必须是绝对路径(URL-encoded UTF-8)。
 *     - entry 是容器内 entry 名,例如 "chunk-stream0-00001.m4s"。
 *
 * 软件设计:
 *   - 本文件只负责 VLC access 接口适配(Open/Read/Seek/Control + URL 解析)。
 *   - 容器解析委托给 kkma_container.{h,c},同样的格式定义在 VLC 之外也能用。
 *   - SRP:URL 解析、容器解析、Seek/Read 三件事互相独立,可单独修改。
 *
 * License:本模块独立实现 VLC access 回调,未抄写 modules/access/file.c 的代码,
 * 仅参考其接口风格,因此不构成 GPL 派生作品问题。本文件授权与 VLC 主仓一致。
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <vlc_common.h>
#include <vlc_plugin.h>
#include <vlc_access.h>
#include <vlc_url.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kkma_container.h"

/* ------------------------------------------------------------------------- */
/* Module declarations                                                       */
/* ------------------------------------------------------------------------- */

static int  KkmaOpen(vlc_object_t *);
static void KkmaClose(vlc_object_t *);

vlc_module_begin()
    set_description(N_("KKMA container access"))
    set_shortname(N_("KKMA"))
    set_category(CAT_INPUT)
    set_subcategory(SUBCAT_INPUT_ACCESS)
    set_capability("access", 60)
    add_shortcut("kkma")
    set_callbacks(KkmaOpen, KkmaClose)
vlc_module_end()

/* ------------------------------------------------------------------------- */
/* access_sys_t: 单个 access 实例的上下文                                    */
/* ------------------------------------------------------------------------- */

struct access_sys_t
{
    kkma_container_t   *container;     /* 拥有 */
    const kkma_entry_t *entry;         /* 不拥有,生命周期 = container */
    uint64_t            offset;        /* entry 内的当前读偏移 */
};

/* ------------------------------------------------------------------------- */
/* URL 解析                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * 在 query 字符串里抽取指定 key 的值,返回新分配的 URL-decoded UTF-8 字符串。
 * 调用方负责 free。找不到返回 NULL。
 *
 * query 形如 "container=...&entry=..."(由 vlc_UrlParse 产出 psz_option,
 * 不含 '?')。这里手写解析而不依赖第三方 querystring 库,避免给 VLC 插件引入
 * 任何额外依赖。
 */
static char *query_get(const char *query, const char *key)
{
    if (!query || !key) return NULL;
    size_t key_len = strlen(key);

    const char *p = query;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        if (!eq) break;
        size_t this_key_len = (size_t)(eq - p);
        if (this_key_len == key_len && strncmp(p, key, key_len) == 0) {
            const char *val_begin = eq + 1;
            size_t val_len = amp ? (size_t)(amp - val_begin) : strlen(val_begin);
            char *raw = (char *)malloc(val_len + 1);
            if (!raw) return NULL;
            memcpy(raw, val_begin, val_len);
            raw[val_len] = '\0';
            char *decoded = vlc_uri_decode_duplicate(raw);
            free(raw);
            return decoded;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* VLC access 回调                                                            */
/* ------------------------------------------------------------------------- */

static ssize_t KkmaRead(stream_t *p_access, void *p_buffer, size_t i_len);
static int     KkmaSeek(stream_t *p_access, uint64_t i_pos);
static int     KkmaControl(stream_t *p_access, int i_query, va_list args);

static int KkmaOpen(vlc_object_t *p_this)
{
    stream_t *p_access = (stream_t *)p_this;

    /* p_access->psz_url 含完整 URL,p_access->psz_location 含 '//' 之后的部分。
     * 用 vlc_UrlParse 拿 host/path/option(query) 三段。 */
    vlc_url_t url;
    if (vlc_UrlParse(&url, p_access->psz_url) || !url.psz_protocol ||
        strcmp(url.psz_protocol, "kkma") != 0) {
        vlc_UrlClean(&url);
        return VLC_EGENERIC;
    }

    char *container_path = query_get(url.psz_option, "container");
    char *entry_name     = query_get(url.psz_option, "entry");
    vlc_UrlClean(&url);

    if (!container_path || !entry_name) {
        msg_Err(p_access, "kkma: URL must have container=... and entry=... query params");
        free(container_path);
        free(entry_name);
        return VLC_EGENERIC;
    }

    const char *err = NULL;
    kkma_container_t *c = kkma_open(container_path, &err);
    if (!c) {
        msg_Err(p_access, "%s (path=%s)", err ? err : "kkma_open failed", container_path);
        free(container_path);
        free(entry_name);
        return VLC_EGENERIC;
    }

    const kkma_entry_t *entry = kkma_find(c, entry_name);
    if (!entry) {
        msg_Err(p_access, "kkma: entry not found: %s", entry_name);
        kkma_close(c);
        free(container_path);
        free(entry_name);
        return VLC_EGENERIC;
    }

    access_sys_t *p_sys = vlc_obj_malloc(p_this, sizeof(*p_sys));
    if (!p_sys) {
        kkma_close(c);
        free(container_path);
        free(entry_name);
        return VLC_ENOMEM;
    }
    p_sys->container = c;
    p_sys->entry     = entry;
    p_sys->offset    = 0;

    p_access->pf_read    = KkmaRead;
    p_access->pf_block   = NULL;
    p_access->pf_seek    = KkmaSeek;
    p_access->pf_control = KkmaControl;
    p_access->p_sys      = p_sys;

    msg_Dbg(p_access, "kkma: opened entry='%s' length=%llu (container=%s)",
            entry_name,
            (unsigned long long)entry->length,
            container_path);

    free(container_path);
    free(entry_name);
    return VLC_SUCCESS;
}

static void KkmaClose(vlc_object_t *p_this)
{
    stream_t     *p_access = (stream_t *)p_this;
    access_sys_t *p_sys    = p_access->p_sys;
    if (!p_sys) return;
    kkma_close(p_sys->container);
    /* p_sys 由 vlc_obj_malloc 分配,VLC 对象销毁时自动回收 */
}

static ssize_t KkmaRead(stream_t *p_access, void *p_buffer, size_t i_len)
{
    access_sys_t *p_sys = p_access->p_sys;

    int64_t got = kkma_read_entry(p_sys->container, p_sys->entry,
                                  p_sys->offset, p_buffer, i_len);
    if (got < 0) {
        msg_Err(p_access, "kkma: read error at offset=%llu len=%zu",
                (unsigned long long)p_sys->offset, i_len);
        return -1;
    }
    p_sys->offset += (uint64_t)got;
    return (ssize_t)got;
}

static int KkmaSeek(stream_t *p_access, uint64_t i_pos)
{
    access_sys_t *p_sys = p_access->p_sys;
    /* clamp 到 entry 长度内,VLC stream 层允许 seek 到 size,会在下一次 read
     * 时立刻返回 0(EOF)。 */
    if (i_pos > p_sys->entry->length)
        i_pos = p_sys->entry->length;
    p_sys->offset = i_pos;
    return VLC_SUCCESS;
}

static int KkmaControl(stream_t *p_access, int i_query, va_list args)
{
    access_sys_t *p_sys = p_access->p_sys;

    switch (i_query) {
    case STREAM_CAN_SEEK:
    case STREAM_CAN_FASTSEEK:
    case STREAM_CAN_PAUSE:
    case STREAM_CAN_CONTROL_PACE:
        *va_arg(args, bool *) = true;
        break;

    case STREAM_GET_SIZE:
        *va_arg(args, uint64_t *) = p_sys->entry->length;
        break;

    case STREAM_GET_PTS_DELAY:
        /* 本地文件,延迟取 file-caching */
        *va_arg(args, int64_t *) =
            INT64_C(1000) * var_InheritInteger(p_access, "file-caching");
        break;

    case STREAM_SET_PAUSE_STATE:
        /* nothing to do for a local file */
        break;

    default:
        return VLC_EGENERIC;
    }
    return VLC_SUCCESS;
}
