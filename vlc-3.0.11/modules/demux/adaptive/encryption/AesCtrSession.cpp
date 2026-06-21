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
    case 2:
        return start_v2(enc);
    /* case 3: return start_v3(enc); */
    default:
        msg_Err(p_obj_, "yk-aes-ctr: unsupported algoVersion=%d (max supported=2)",
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
    started_           = false;
    algo_version_      = 0;
    v2_material_ready_ = false;
    ctx_set_           = false;
    handle_open_       = false;
    bound_rep_id_      = 0xFFFFFFFF;
    bound_seq_         = 0xFFFFFFFFFFFFFFFFULL;
}

size_t AesCtrSession::decrypt(void *data, size_t len, bool last)
{
    VLC_UNUSED(last);
    if (!started_ || len == 0 || data == nullptr) return len;

    switch (algo_version_) {
    case 1:  return decrypt_v1(data, len);
    case 2:  return decrypt_v2(data, len);
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

/* ---- 阶段 C v2 ---- */

void AesCtrSession::setSegmentContext(uint32_t rep_id, uint64_t segment_seq)
{
    cur_rep_id_ = rep_id;
    cur_seq_    = segment_seq;
    ctx_set_    = true;
}

#ifndef HAVE_GCRYPT
/* 占位:start_v2/decrypt_v2 在无 gcrypt 时直接失败 */
#else

/* HMAC-SHA256(key, data)[0:out_len]。与加密器侧 segment_encryptor.cpp 公式一致。 */
static bool YkHmacSha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out, size_t out_len)
{
    if (out_len > 32) return false;
    /* gcrypt 的 HMAC 接口:gcry_md_open(HMAC flag) + setkey + write + read */
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC)) return false;
    if (gcry_md_setkey(hd, key, key_len)) { gcry_md_close(hd); return false; }
    gcry_md_write(hd, data, data_len);
    unsigned char *digest = gcry_md_read(hd, GCRY_MD_SHA256);
    if (!digest) { gcry_md_close(hd); return false; }
    memcpy(out, digest, out_len);
    gcry_md_close(hd);
    return true;
}

/* AES-128-ECB 单块解密(16B → 16B)。用于解 KeyBlob 得 B。
 * 必须与加密器侧 AesEcbEncryptBlock 对应(不是 key wrap / CBC)。 */
static bool YkAesEcbDecryptBlock(const uint8_t key[16],
                                 const uint8_t in[16], uint8_t out[16])
{
    gcry_cipher_hd_t hd;
    if (gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) return false;
    bool ok = false;
    if (gcry_cipher_setkey(hd, key, 16) == 0 &&
        gcry_cipher_decrypt(hd, out, 16, in, 16) == 0)
    {
        ok = true;
    }
    gcry_cipher_close(hd);
    return ok;
}
#endif

bool AesCtrSession::start_v2(const CommonEncryption &enc)
{
#ifndef HAVE_GCRYPT
    msg_Err(p_obj_, "yk-aes-ctr v2: HAVE_GCRYPT not defined");
    return false;
#else
    /* 必须有 KeyBlob(Enc_A(B))。IV 不在 MPD 里(per-seg 派生)。 */
    if (enc.key_blob.size() != 16) {
        msg_Err(p_obj_, "yk-aes-ctr v2: invalid key_blob size %zu (need 16)",
                enc.key_blob.size());
        return false;
    }

    /* A:从 IKeyProvider 取(课程密钥,16B)。 */
    if (!key_provider_) {
        msg_Err(p_obj_, "yk-aes-ctr v2: no key provider");
        return false;
    }
    std::vector<unsigned char> A_vec = key_provider_->GetKey(enc.keyid);
    if (A_vec.size() != 16) {
        msg_Err(p_obj_, "yk-aes-ctr v2: key size %zu, need 16 (course key A)", A_vec.size());
        return false;
    }
    memcpy(v2_A_, A_vec.data(), 16);

    /* B:AES-128-ECB 单块解密 KeyBlob 得 B。 */
    if (!YkAesEcbDecryptBlock(v2_A_, enc.key_blob.data(), v2_B_)) {
        msg_Err(p_obj_, "yk-aes-ctr v2: KeyBlob unwrap failed");
        return false;
    }

    /* C = HMAC(A, B)[0:16] */
    if (!YkHmacSha256(v2_A_, 16, v2_B_, 16, v2_C_, 16)) {
        msg_Err(p_obj_, "yk-aes-ctr v2: C derivation failed");
        return false;
    }

    v2_material_ready_ = true;
    started_ = true;
    /* cipher_ctx_ 不在此 open —— v2 每 segment 要 setctr(派生 IV),handle 在
     * decrypt_v2 里按需 open/复用。详见 decrypt_v2。 */
    msg_Dbg(p_obj_, "yk-aes-ctr v2 started: keyid='%s' course='%s' keyDerive='%s'",
            enc.keyid.c_str(), enc.course_id.c_str(), enc.key_derive.c_str());
    return true;
#endif
}

size_t AesCtrSession::decrypt_v2(void *data, size_t len)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(data); VLC_UNUSED(len);
    return 0;
#else
    if (!v2_material_ready_ || !ctx_set_) {
        msg_Err(p_obj_, "yk-aes-ctr v2: decrypt before context set");
        return 0;
    }

    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(cipher_ctx_);

    /* segment 切换判定:rep_id 或 seq 变化时,重新 setkey + setctr。
     * 同一 segment 内多次 decrypt 调用(gcrypt 自动推进 counter),不重设,
     * 否则 counter 被重置回 IV 起点导致解密错位(花屏)。 */
    const bool seg_changed =
        !handle_open_ || bound_rep_id_ != cur_rep_id_ || bound_seq_ != cur_seq_;

    if (seg_changed) {
        /* IV = HMAC(C, rep_id[4B 大端] ‖ segment_seq[8B 大端])[0:16]
         * 必须与加密器侧公式逐字节一致(§C.4.2 跨模块契约)。 */
        uint8_t iv_input[12];
        iv_input[0] = static_cast<uint8_t>((cur_rep_id_ >> 24) & 0xff);
        iv_input[1] = static_cast<uint8_t>((cur_rep_id_ >> 16) & 0xff);
        iv_input[2] = static_cast<uint8_t>((cur_rep_id_ >> 8) & 0xff);
        iv_input[3] = static_cast<uint8_t>(cur_rep_id_ & 0xff);
        for (int i = 0; i < 8; ++i)
            iv_input[4 + i] = static_cast<uint8_t>((cur_seq_ >> (56 - 8 * i)) & 0xff);

        uint8_t iv[16];
        if (!YkHmacSha256(v2_C_, 16, iv_input, sizeof(iv_input), iv, 16)) {
            msg_Err(p_obj_, "yk-aes-ctr v2: IV derivation failed");
            return 0;
        }

        if (!handle) {
            if (gcry_cipher_open(&handle, GCRY_CIPHER_AES128,
                                 GCRY_CIPHER_MODE_CTR, 0)) {
                msg_Err(p_obj_, "yk-aes-ctr v2: gcry_cipher_open failed");
                return 0;
            }
            cipher_ctx_ = handle;
        }
        if (gcry_cipher_setkey(handle, v2_C_, 16)) {
            msg_Err(p_obj_, "yk-aes-ctr v2: setkey failed");
            return 0;
        }
        if (gcry_cipher_setctr(handle, iv, 16)) {
            msg_Err(p_obj_, "yk-aes-ctr v2: setctr failed");
            return 0;
        }
        bound_rep_id_ = cur_rep_id_;
        bound_seq_    = cur_seq_;
        handle_open_  = true;
    }

    gcry_error_t err = gcry_cipher_decrypt(handle, data, len, NULL, 0);
    if (err) {
        msg_Err(p_obj_, "yk-aes-ctr v2: gcry_cipher_decrypt failed: %s",
                gcry_strerror(err));
        return 0;
    }
    return len;
#endif
}

}}  // namespace adaptive::encryption
