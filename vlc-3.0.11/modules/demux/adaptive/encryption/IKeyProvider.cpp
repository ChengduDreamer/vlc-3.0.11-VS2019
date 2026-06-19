/*****************************************************************************
 * IKeyProvider.cpp
 *****************************************************************************
 * VlcVariableKeyProvider 实现:从 VLC 对象树继承变量 "yk-aes-key" 取 key。
 * 用户用 `vlc.exe --yk-aes-key=<hex>` 即可注入。
 *
 * v1 备注:
 *   - 不区分 keyid。整个进程一份 key。
 *   - hex 字符串只接受偶数长度 + [0-9a-fA-F]。空字符串视为没设。
 *
 * 关于"为什么是 inherit 不是 get":VLC 的 var_Inherit* 会沿对象树往上找,
 * 即使变量是设在 libvlc instance 顶层(命令行参数的常见落点),
 * 也能在 demux/access 这些深层模块里被找到。
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "IKeyProvider.hpp"

#include <vlc_common.h>
#include <vlc_variables.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

using namespace adaptive::encryption;

namespace
{

    int hex_digit(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    }

    bool decode_hex(const char *s, std::vector<unsigned char> &out)
    {
        out.clear();
        if (!s || !*s) return false;
        size_t len = std::strlen(s);
        if (len & 1u) return false;
        out.reserve(len / 2);
        for (size_t i = 0; i < len; i += 2) {
            int hi = hex_digit(s[i]);
            int lo = hex_digit(s[i + 1]);
            if (hi < 0 || lo < 0) {
                out.clear();
                return false;
            }
            out.push_back(static_cast<unsigned char>((hi << 4) | lo));
        }
        return true;
    }

    class VlcVariableKeyProvider : public IKeyProvider
    {
    public:
        explicit VlcVariableKeyProvider(vlc_object_t *p_obj) : p_obj_(p_obj) {}

        std::vector<unsigned char> GetKey(const std::string &keyid) override
        {
            VLC_UNUSED(keyid);  // v1 不区分 keyid
            std::vector<unsigned char> bytes;
            if (!p_obj_) return bytes;

            char *hex = var_InheritString(p_obj_, "yk-aes-key");
            if (!hex) return bytes;

            if (!decode_hex(hex, bytes)) {
                msg_Warn(p_obj_, "yk-aes-key: bad hex value");
                bytes.clear();
            }
            free(hex);
            return bytes;
        }

    private:
        vlc_object_t *p_obj_;
    };

}  // namespace

namespace adaptive { namespace encryption {

std::unique_ptr<IKeyProvider> CreateVlcVariableKeyProvider(vlc_object_t *p_obj)
{
    return std::unique_ptr<IKeyProvider>(new VlcVariableKeyProvider(p_obj));
}

}}  // namespace adaptive::encryption
