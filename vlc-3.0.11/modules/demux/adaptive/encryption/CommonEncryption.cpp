/*****************************************************************************
 * CommonEncryption.cpp
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <iostream>

#include "CommonEncryption.hpp"
#include "Keyring.hpp"
#include "../SharedResources.hpp"

#include <vlc_common.h>

#ifdef HAVE_GCRYPT
 #include <gcrypt.h>
 #include <vlc_gcrypt.h>
#endif

using namespace adaptive::encryption;


CommonEncryption::CommonEncryption()
{
    method = CommonEncryption::Method::NONE;
}

void CommonEncryption::mergeWith(const CommonEncryption &other)
{
    if(method == CommonEncryption::Method::NONE &&
       other.method != CommonEncryption::Method::NONE)
        method = other.method;
    if(uri.empty() && !other.uri.empty())
        uri = other.uri;
    if(iv.empty() && !other.iv.empty())
        iv = other.iv;

    // 阶段 B 起新增字段:同样按"自己空才取对方"的合并策略,保证调用方
    // (Segment.cpp::prepareChunk)从 Representation 继承 AdaptationSet 上挂的
    // ContentProtection 时不会丢字段。
    if(algo_version == 0 && other.algo_version != 0)
        algo_version = other.algo_version;
    if(keyid.empty() && !other.keyid.empty())
        keyid = other.keyid;
    if(key_derive == "raw" && other.key_derive != "raw")
        key_derive = other.key_derive;
    if(iv_scheme == "fixed" && other.iv_scheme != "fixed")
        iv_scheme = other.iv_scheme;
    if(license_blob.empty() && !other.license_blob.empty())
        license_blob = other.license_blob;
    if(aad.empty() && !other.aad.empty())
        aad = other.aad;
    if(kdf_salt.empty() && !other.kdf_salt.empty())
        kdf_salt = other.kdf_salt;
    if(kdf_iters == 0 && other.kdf_iters != 0)
        kdf_iters = other.kdf_iters;
    // 阶段 C v2 字段
    if(course_id.empty() && !other.course_id.empty())
        course_id = other.course_id;
    if(key_blob.empty() && !other.key_blob.empty())
        key_blob = other.key_blob;
}

CommonEncryptionSession::CommonEncryptionSession()
{
    ctx = NULL;
}


CommonEncryptionSession::~CommonEncryptionSession()
{
    close();
}

bool CommonEncryptionSession::start(SharedResources *res, const CommonEncryption &enc)
{
    if(ctx)
        close();
    encryption = enc;
#ifdef HAVE_GCRYPT
    if(encryption.method == CommonEncryption::Method::AES_128)
    {
        if(key.empty())
        {
            if(!encryption.uri.empty())
                key = res->getKeyring()->getKey(res, encryption.uri);
            if(key.size() != 16)
                return false;
        }

        vlc_gcrypt_init();
        gcry_cipher_hd_t handle;
        if( gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0) ||
                gcry_cipher_setkey(handle, &key[0], 16) ||
                gcry_cipher_setiv(handle, &encryption.iv[0], 16) )
        {
            gcry_cipher_close(handle);
            ctx = NULL;
            return false;
        }
        ctx = handle;
    }
#endif
    return true;
}

void CommonEncryptionSession::close()
{
#ifdef HAVE_GCRYPT
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(ctx)
        gcry_cipher_close(handle);
    ctx = NULL;
#endif
}

size_t CommonEncryptionSession::decrypt(void *inputdata, size_t inputbytes, bool last)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(inputdata);
    VLC_UNUSED(last);
#else
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(encryption.method == CommonEncryption::Method::AES_128 && ctx)
    {
        if ((inputbytes % 16) != 0 || inputbytes < 16 ||
            gcry_cipher_decrypt(handle, inputdata, inputbytes, NULL, 0))
        {
            inputbytes = 0;
        }
        else if(last)
        {
            /* last bytes */
            /* remove the PKCS#7 padding from the buffer */
            const uint8_t pad = reinterpret_cast<uint8_t *>(inputdata)[inputbytes - 1];
            for(uint8_t i=0; i<pad && i<16; i++)
            {
                if(reinterpret_cast<uint8_t *>(inputdata)[inputbytes - i - 1] != pad)
                    break;
                if(i+1==pad)
                    inputbytes -= pad;
            }
        }
    }
    else
#endif
    if(encryption.method != CommonEncryption::Method::NONE)
    {
        inputbytes = 0;
    }

    return inputbytes;
}

// 阶段 C v2:基类默认空实现。需要 per-segment IV 的 session(AesCtrSession v2)
// 覆盖此方法缓存 rep_id/segment_seq。v1 及 AES_128 不需要,忽略调用。
void CommonEncryptionSession::setSegmentContext(uint32_t, uint64_t)
{
}

YKChacha20EncryptionSession::YKChacha20EncryptionSession()
{
    
}


YKChacha20EncryptionSession::~YKChacha20EncryptionSession()
{
    close();
}

bool YKChacha20EncryptionSession::start(SharedResources* res, const CommonEncryption& enc)
{
    offset_ = 0;
    started_ = true;

    // key / nonce 你现在是“写死”的
    // 实际项目建议：rep_id + segment_seq 派生
    static const uint8_t key[32] = {
        0x21, 0x7A, 0x93, 0xC4, 0x58, 0xE1, 0x6F, 0x0B,
        0xAD, 0x4E, 0xD2, 0x39, 0xF7, 0x81, 0x5C, 0x10,
        0x66, 0xB9, 0x03, 0xAE, 0x2D, 0x90, 0x74, 0xC8,
        0x1F, 0xEA, 0x55, 0x8D, 0xA0, 0xCB, 0x36, 0x99
    };

    static const uint8_t nonce[12] = {
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67
    };

    //ChaCha20_init(&ctx_, key, nonce, /*counter=*/0);

    std::cout << "YKChacha20EncryptionSession::start ChaCha20_init" << std::endl;

    return true;
}

void YKChacha20EncryptionSession::close()
{
    started_ = false;
    offset_ = 0;
}


static const uint8_t XOR_KEY[] = {
    0x13, 0x37, 0xC0, 0xDE, 0x42, 0x99, 0xAA, 0x55
};

void xor_crypt(uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        data[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
}

size_t YKChacha20EncryptionSession::decrypt(void* inputdata, size_t inputbytes, bool last)
{
    if (!started_ || inputbytes == 0) {
        return 0;
    }

    //ChaCha20_xor(&ctx_, static_cast<uint8_t*>(inputdata), inputbytes);



    xor_crypt(static_cast<uint8_t*>(inputdata), inputbytes);

    offset_ += inputbytes;
    return inputbytes;
}