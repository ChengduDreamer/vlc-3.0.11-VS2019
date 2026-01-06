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
#define CHACHA20_IMPLEMENTATION
//#include "chacha20.h"

namespace adaptive
{
    class SharedResources;

    namespace encryption
    {
        class CommonEncryption
        {
            public:
                CommonEncryption();
                void mergeWith(const CommonEncryption &);
                enum Method
                {
                    NONE,
                    AES_128,
                    AES_SAMPLE,
                    CHACHA_20,
                } method;
                std::string uri;
                std::vector<unsigned char> iv;
        };

        class CommonEncryptionSession
        {
            public:
                CommonEncryptionSession();
                ~CommonEncryptionSession();

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
