/*****************************************************************************
 * IKeyProvider.hpp
 *****************************************************************************
 * Key 注入抽象。对应 PLAYBACK_LINK_PLAN.md §B.3.4。
 *
 * 设计目标:
 *   AesCtrSession 不直接调 var_InheritString —— 而是依赖一个 IKeyProvider
 *   接口,从外面拿 key。这样:
 *     - v1: VlcVariableKeyProvider     从 --yk-aes-key= 命令行参数 / VLC 变量取
 *     - v2: VlcKeyringKeyProvider      按 KeyId 从 VLC adaptive Keyring 查
 *     - v3: LicenseServiceKeyProvider  调 license 服务派生 key
 *   切换 key 来源时,**不动 AesCtrSession 一行代码**(DIP 落地)。
 *
 * 测试:可以注入 mock provider,不依赖 libvlc 启动。
 *
 * 跨平台:接口本身没有平台耦合;v1 实现里用的 var_InheritString 是 VLC 跨平台 API。
 *****************************************************************************/
#ifndef ADAPTIVE_IKEY_PROVIDER_H
#define ADAPTIVE_IKEY_PROVIDER_H

#include <memory>
#include <string>
#include <vector>

typedef struct vlc_object_t vlc_object_t;

namespace adaptive
{
    namespace encryption
    {
        class IKeyProvider
        {
        public:
            virtual ~IKeyProvider() = default;

            /* 给定 KeyId,返回原始 key 字节。空表示找不到 / 不允许使用。
             * v1 的 VlcVariableKeyProvider 忽略 keyid(整个进程一个 key)。
             * v2+ 实现按 keyid 索引多 key 表。 */
            virtual std::vector<unsigned char> GetKey(const std::string &keyid) = 0;
        };

        /* v1 工厂:从 VLC 对象树继承 "yk-aes-key"(hex 字符串)→ 解码成字节。
         * p_obj 通常是 demux 或更上层的 vlc_object_t。 */
        std::unique_ptr<IKeyProvider> CreateVlcVariableKeyProvider(vlc_object_t *p_obj);
    }
}

#endif
