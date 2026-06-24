/*****************************************************************************
 * decrypt.c: sample stream decryption filter
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <vlc_common.h>
#include <vlc_plugin.h>
#include <vlc_stream.h>

/* -------------------------------------------------------------------------
 * sys
 * ------------------------------------------------------------------------- */

struct decrypt_sys_t
{
    uint64_t offset;
    /* TODO: key / iv / context */
};

/* -------------------------------------------------------------------------
 * Read   经过测试，这里解密没有效果(2025-1-4)
 * ------------------------------------------------------------------------- */

static ssize_t Read(stream_t *s, void *buf, size_t len)
{
    //printf("preprocess.c Read url = %s, len =  %zu bytes\n", s->psz_url, len);

    struct decrypt_sys_t *sys = s->p_sys;

    ssize_t ret = vlc_stream_Read(s->p_source, buf, len);
    if (ret <= 0)
        return ret;

    /* -------- 解密发生在这里 -------- */
    uint8_t *p = buf;
    for (ssize_t i = 0; i < ret; ++i)
    {
        /* 示例：XOR，占位用 */
        //p[i] ^= 0xAA;

        //p[i] ^= 0x30;
    }
    /* -------------------------------- */

    sys->offset += ret;
    return ret;
}

/* -------------------------------------------------------------------------
 * Seek
 * ------------------------------------------------------------------------- */

static int Seek(stream_t *s, uint64_t offset)
{
    struct decrypt_sys_t *sys = s->p_sys;

    sys->offset = offset;
    return vlc_stream_Seek(s->p_source, offset);
}

/* -------------------------------------------------------------------------
 * Control
 * ------------------------------------------------------------------------- */

static int Control(stream_t *s, int query, va_list args)
{
    return vlc_stream_vaControl(s->p_source, query, args);
}

/* -------------------------------------------------------------------------
 * Open / Close
 * ------------------------------------------------------------------------- */

static int Open(vlc_object_t *obj)
{
    /* 历史 PoC(2025-01):试图在通用 stream_filter 层做字节级解密,内部
     * 一直是空的 XOR 占位(见下面 Read() 里被注释掉的 p[i] ^= 0xAA)。
     * 阶段 B/C 起,真正的解密走 modules/demux/adaptive/encryption/AesCtrSession,
     * 由 DASH ContentProtection 驱动 per-segment 解密。这个 stream_filter
     * 已废弃。
     *
     * 不删模块壳是为了不动 winvlc.sln / vcxproj。直接返回 EGENERIC 让 VLC
     * 在 stream_filter 责任链探测时不再 attach,避免每次开 segment 在日志里
     * 刷一大堆 "looking for stream_filter module matching any" + "stream
     * filter added to" 的空跑噪音(单次播放约 2000+ 行)。
     *
     * 要彻底删:清掉本文件 + 在 winvlc.sln 里移除 preprocess 工程项,
     * 也别再 ship libpreprocess_plugin.dll。 */
    (void)obj;
    return VLC_EGENERIC;

#if 0   /* 旧 PoC 实现,保留作为参考,永远走不到 */
    stream_t *s = (stream_t *)obj;

    /* 你可以在这里判断 URL / mime / magic */
    if (s->p_source == NULL)
        return VLC_EGENERIC;

    struct decrypt_sys_t *sys = malloc(sizeof(*sys));
    if (!sys)
        return VLC_ENOMEM;

    sys->offset = 0;

    s->p_sys = sys;
    s->pf_read = Read;
    s->pf_seek = Seek;
    s->pf_control = Control;

    //msg_Info(s, "decrypt stream filter enabled");
    return VLC_SUCCESS;
#endif
}

static void Close(vlc_object_t *obj)
{
    stream_t *s = (stream_t *)obj;
    free(s->p_sys);
}

/* -------------------------------------------------------------------------
 * Module
 * ------------------------------------------------------------------------- */

vlc_module_begin()
    set_category(CAT_INPUT)
    set_subcategory(SUBCAT_INPUT_STREAM_FILTER)

    /*关键：比 skiptags(30) 高，确保先解密 */
    set_capability("stream_filter", 100)

    set_description(N_("Deprecated decryption stream filter (no-op)"))
    set_callbacks(Open, Close)
vlc_module_end()
