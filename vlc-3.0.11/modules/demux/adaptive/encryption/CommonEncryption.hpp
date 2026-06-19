/*****************************************************************************
 * CommonEncryption.hpp
 *****************************************************************************
 * Copyright (C) 2015-2019 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/
#ifndef COMMONENCRYPTION_H
#define COMMONENCRYPTION_H

#include <vector>
#include <string>
#include <stdint.h>
#define CHACHA20_IMPLEMENTATION
//#include "chacha20.h"

namespace adaptive
{
    class SharedResources;

    namespace encryption
    {
        // CommonEncryption 是 MPD 解析阶段填充的"加密元数据"。
        // 阶段 B 起,我们把 yk-aes-ctr 算法族也接入了同一个数据结构,只是多
        // 出来一个 algo_version 字段告诉 session 走哪条 v 分支。
        // 关于版本化的总体设计见 PLAYBACK_LINK_PLAN.md §B.1 / §B.2.2。
        class CommonEncryption
        {
            public:
                CommonEncryption();
                void mergeWith(const CommonEncryption &);
                enum Method
                {
                    NONE,
                    AES_128,           // DASH 标准 CENC AES-128-CBC
                    AES_SAMPLE,        // 现有,sample-encryption
                    CHACHA_20,         // 现有(测试)
                    AES_CTR,           // 阶段 B 新增 = yk aes-ctr 算法族
                } method;

                // 现有字段(继续被 AES_128 等使用)
                std::string uri;                 // license URI(AES_128 用)
                std::vector<unsigned char> iv;   // 初始/参考 IV

                // ---- 阶段 B 起新增字段(yk-aes-ctr 用) ----
                // 算法族版本号。0 = 未指定;>= 1 = 我们的算法族版本。
                // 来自 MPD 里 schemeIdUri 末段的整数,或 <yk:Encryption algoVersion="N">。
                int algo_version = 0;

                // KeyId 标识(预留多 key 场景)。v1 = "k001"。
                std::string keyid;

                // ---- 预留扩展字段(阶段 C 起按需启用,详见 §B.2.2) ----
                std::string key_derive  = "raw";      // raw / pbkdf2 / hkdf / license
                std::string iv_scheme   = "fixed";    // fixed / per-segment / seq-derived
                std::vector<unsigned char> license_blob;
                std::vector<unsigned char> aad;
                std::vector<unsigned char> kdf_salt;
                uint32_t kdf_iters = 0;
        };

        class CommonEncryptionSession
        {
            public:
                CommonEncryptionSession();
                virtual ~CommonEncryptionSession();

                virtual bool start(SharedResources *, const CommonEncryption &);
                virtual void close();
                virtual size_t decrypt(void *, size_t, bool);

            private:
                std::vector<unsigned char> key;
                CommonEncryption encryption;
                void *ctx;
        };

        class YKChacha20EncryptionSession : public CommonEncryptionSession
        {
        public:
            YKChacha20EncryptionSession();
            ~YKChacha20EncryptionSession();

            bool start(SharedResources*, const CommonEncryption&) override;
            void close() override;
            size_t decrypt(void*, size_t, bool) override;

        private:
            CommonEncryption encryption;

            //ChaCha20_Ctx ctx_;
            bool started_ = false;
            uint64_t offset_ = 0;

        };
    }
}

#endif
