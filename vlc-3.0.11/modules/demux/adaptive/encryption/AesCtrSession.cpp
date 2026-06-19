/*****************************************************************************
 * AesCtrSession.cpp
 *****************************************************************************
 * yk-aes-ctr 解密 session 实现。版本调度框架 + v1 实现。
 *
 * v1 详情:
 *   - 算法 = AES-128-CTR(libgcrypt 原生支持,无需手写)
 *   - IV   = MPD <yk:IV> 提供的 16 字节(全 segment 共用,§B.6 单 IV 风险)
 *   - key  = IKeyProvider.GetKey("k001")。VlcVariableKeyProvider 从
 *            --yk-aes-key=<hex> 取。
 *
 * 性能:cipher handle 只在 start() 打开一次、close() 关闭一次,decrypt()
 * 跨调用复用同一 handle。gcrypt 内部维护 keystream + counter 状态,
 * 跨调用对齐由 gcrypt 处理,无需我们计算 offset。
 *
 * 关于 CTR 模式的等价性:
 *   AES-CTR 加密 = 解密(都是 keystream XOR plaintext/ciphertext),所以
 *   gcry_cipher_decrypt 在 CTR 下做的事就是"生成 keystream + XOR",
 *   和我们之前手写 ECB+counter 等价,但快很多倍。
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "AesCtrSession.hpp"
#include "../SharedResources.hpp"

#include <vlc_common.h>

#ifdef HAVE_GCRYPT
# include <gcrypt.h>
# include <vlc_gcrypt.h>
#endif

#include <cstring>

using namespace adaptive::encryption;

namespace adaptive { namespace encryption {

AesCtrSession::AesCtrSession(vlc_object_t *p_obj)
    : p_obj_(p_obj)
{
    /* 默认 key provider:从 VLC 变量继承。
     * 测试时可调 SetKeyProvider() 注入 mock 覆盖。 */
    key_provider_ = CreateVlcVariableKeyProvider(p_obj_);
}

AesCtrSession::~AesCtrSession()
{
    AesCtrSession::close();
}

void AesCtrSession::SetKeyProvider(std::unique_ptr<IKeyProvider> p)
{
    key_provider_ = std::move(p);
}

bool AesCtrSession::start(SharedResources *res, const CommonEncryption &enc)
{
    VLC_UNUSED(res);

    /* 重 start 前先把上一次的 handle 关掉(防御性) */
    close();

    algo_version_ = enc.algo_version;

    switch (algo_version_) {
    case 1:
        return start_v1(enc);
    /* case 2: return start_v2(enc); */
    /* case 3: return start_v3(enc); */
    default:
        msg_Err(p_obj_, "yk-aes-ctr: unsupported algoVersion=%d (max supported=1)",
                algo_version_);
        return false;
    }
}

bool AesCtrSession::start_v1(const CommonEncryption &enc)
{
#ifndef HAVE_GCRYPT
    msg_Err(p_obj_, "yk-aes-ctr v1: HAVE_GCRYPT not defined");
    return false;
#else
    /* IV: MPD <yk:IV> 解析后存到 enc.iv,16 字节 */
    if (enc.iv.size() != 16) {
        msg_Err(p_obj_, "yk-aes-ctr v1: invalid iv size %zu (need 16)", enc.iv.size());
        return false;
    }

    /* key: 从 IKeyProvider 取。v1 期望 16 字节(AES-128)。 */
    if (!key_provider_) {
        msg_Err(p_obj_, "yk-aes-ctr v1: no key provider");
        return false;
    }
    std::vector<unsigned char> key = key_provider_->GetKey(enc.keyid);
    if (key.size() != 16) {
        msg_Err(p_obj_,
                "yk-aes-ctr v1: key size %zu, need 16. "
                "Provide --yk-aes-key=<32 hex chars>",
                key.size());
        return false;
    }

    vlc_gcrypt_init();

    gcry_cipher_hd_t handle = nullptr;
    gcry_error_t err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128,
                                        GCRY_CIPHER_MODE_CTR, 0);
    if (err) {
        msg_Err(p_obj_, "yk-aes-ctr v1: gcry_cipher_open failed: %s",
                gcry_strerror(err));
        return false;
    }
    err = gcry_cipher_setkey(handle, key.data(), 16);
    if (err) {
        msg_Err(p_obj_, "yk-aes-ctr v1: gcry_cipher_setkey failed: %s",
                gcry_strerror(err));
        gcry_cipher_close(handle);
        return false;
    }
    err = gcry_cipher_setctr(handle, enc.iv.data(), 16);
    if (err) {
        msg_Err(p_obj_, "yk-aes-ctr v1: gcry_cipher_setctr failed: %s",
                gcry_strerror(err));
        gcry_cipher_close(handle);
        return false;
    }

    cipher_ctx_ = handle;
    started_    = true;
    msg_Dbg(p_obj_,
            "yk-aes-ctr v1 started: keyid='%s' keyDerive='%s' ivScheme='%s'",
            enc.keyid.c_str(), enc.key_derive.c_str(), enc.iv_scheme.c_str());
    return true;
#endif
}

void AesCtrSession::close()
{
#ifdef HAVE_GCRYPT
    if (cipher_ctx_) {
        gcry_cipher_close(reinterpret_cast<gcry_cipher_hd_t>(cipher_ctx_));
        cipher_ctx_ = nullptr;
    }
#endif
    started_      = false;
    algo_version_ = 0;
}

size_t AesCtrSession::decrypt(void *data, size_t len, bool last)
{
    VLC_UNUSED(last);
    if (!started_ || len == 0 || data == nullptr) return len;

    switch (algo_version_) {
    case 1:  return decrypt_v1(data, len);
    default: return 0;  /* 不该到这里;start() 已经过滤 */
    }
}

size_t AesCtrSession::decrypt_v1(void *data, size_t len)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(data);
    return 0;
#else
    /* gcrypt CTR 模式:in-place 解密 = 加密(对称),自动维护跨调用的
     * counter / keystream 状态,长度任意(不要求 16 字节对齐)。 */
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(cipher_ctx_);
    gcry_error_t err = gcry_cipher_decrypt(handle, data, len, NULL, 0);
    if (err) {
        msg_Err(p_obj_, "yk-aes-ctr v1: gcry_cipher_decrypt failed: %s",
                gcry_strerror(err));
        return 0;
    }
    return len;
#endif
}

}}  // namespace adaptive::encryption
