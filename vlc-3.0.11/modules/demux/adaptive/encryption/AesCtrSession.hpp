/*****************************************************************************
 * AesCtrSession.hpp
 *****************************************************************************
 * yk-aes-ctr 算法族的解密 session。对应 PLAYBACK_LINK_PLAN.md §B.4 任务 #6。
 *
 * 设计要点:
 *   - 继承 CommonEncryptionSession,被 SegmentChunk::decrypt 透明使用。
 *   - 内部按 algo_version switch 路由 v1 / v2 / v3 ...,旧版本永不修改。
 *   - 直接使用 libgcrypt 内置的 GCRY_CIPHER_MODE_CTR:
 *       - cipher handle 在 session 生命周期内只 open 一次,start 时 setkey
 *         + setctr,decrypt 跨调用复用同一 handle。
 *       - gcrypt 自动处理 counter 递增、keystream 缓存、跨调用边界,
 *         我们不需要自己算 offset / block_index / block_offset。
 *     这样 decrypt() 是真正的热路径(每个 segment 数 MB),复用 handle 而不是
 *     每 16 字节重新 open/close,这是性能的关键。
 *   - key 通过 IKeyProvider 注入,session 不感知 key 来源。
 *
 * 安全约束(§B.6):v1 = AES-128 + 单 IV + 写死 key,联调用,不可上线。
 *****************************************************************************/
#ifndef ADAPTIVE_AESCTR_SESSION_HPP
#define ADAPTIVE_AESCTR_SESSION_HPP

#include "CommonEncryption.hpp"
#include "IKeyProvider.hpp"

#include <memory>
#include <stdint.h>

typedef struct vlc_object_t vlc_object_t;

namespace adaptive
{
    namespace encryption
    {
        class AesCtrSession : public CommonEncryptionSession
        {
        public:
            /* p_obj 用于 msg_* 日志 + 给 IKeyProvider 用作变量继承根。
             * 默认会内部构造 VlcVariableKeyProvider;如需测试注入 mock,
             * 可调 SetKeyProvider() 覆盖。 */
            explicit AesCtrSession(vlc_object_t *p_obj);
            ~AesCtrSession() override;

            bool   start(SharedResources*, const CommonEncryption&) override;
            void   close() override;
            size_t decrypt(void *data, size_t len, bool last) override;

            /* 阶段 C v2:接收 SegmentChunk 设来的 rep_id/segment_seq,用于 per-seg IV 派生。 */
            void   setSegmentContext(uint32_t rep_id, uint64_t segment_seq) override;

            /* 测试 / 未来扩展用:替换 key 来源。必须在 start() 之前调。 */
            void SetKeyProvider(std::unique_ptr<IKeyProvider> p);

        private:
            vlc_object_t                  *p_obj_;
            std::unique_ptr<IKeyProvider>  key_provider_;

            int       algo_version_  = 0;
            bool      started_       = false;

            /* gcrypt cipher handle。用 void* 而不是 gcry_cipher_hd_t,
             * 是为了 hpp 不 include <gcrypt.h>(和 CommonEncryptionSession 风格一致),
             * cpp 里 reinterpret_cast 成具体类型。 */
            void     *cipher_ctx_    = nullptr;

            /* v2:每 segment 上下文(setSegmentContext 设入)。 */
            uint32_t  cur_rep_id_    = 0;
            uint64_t  cur_seq_       = 0;
            bool      ctx_set_       = false;

            /* v2:CTR handle 当前绑定的 segment。同一 segment 多次 decrypt 调用
             * 共享 handle 状态(gcrypt 自动推进 counter);仅当 segment 变化时
             * 才 setctr + setkey。避免每次 decrypt setctr 重置 counter 导致解密错位。 */
            uint32_t  bound_rep_id_  = 0xFFFFFFFF;
            uint64_t  bound_seq_     = 0xFFFFFFFFFFFFFFFFULL;
            bool      handle_open_   = false;

            /* v2 派生材料(每视频一次,start_v2 算好缓存,避免每 segment 重算)。 */
            uint8_t   v2_A_[16];        /* 课程密钥(从 IKeyProvider 拿) */
            uint8_t   v2_B_[16];        /* 视频密钥(解 KeyBlob 得) */
            uint8_t   v2_C_[16];        /* C = HMAC(A, B),内容密钥 */
            bool      v2_material_ready_ = false;

            /* 版本分发 */
            bool   start_v1(const CommonEncryption &enc);
            size_t decrypt_v1(void *data, size_t len);
            bool   start_v2(const CommonEncryption &enc);
            size_t decrypt_v2(void *data, size_t len);
        };
    }
}

#endif
