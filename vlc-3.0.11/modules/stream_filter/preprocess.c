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
 * Read
 * ------------------------------------------------------------------------- */

static ssize_t Read(stream_t *s, void *buf, size_t len)
{

    printf("preprocess.c Read url = %s, len =  %zu bytes\n", s->psz_url, len);


    struct decrypt_sys_t *sys = s->p_sys;

    ssize_t ret = vlc_stream_Read(s->p_source, buf, len);
    if (ret <= 0)
        return ret;

    /* -------- 解密发生在这里 -------- */
    uint8_t *p = buf;
    for (ssize_t i = 0; i < ret; ++i)
    {
        /* 示例：XOR，占位用 */
        p[i] ^= 0xAA;
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

    msg_Info(s, "decrypt stream filter enabled");
    return VLC_SUCCESS;
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
    set_capability("stream_filter", 50)

    set_description(N_("Sample decryption stream filter"))
    set_callbacks(Open, Close)
vlc_module_end()
