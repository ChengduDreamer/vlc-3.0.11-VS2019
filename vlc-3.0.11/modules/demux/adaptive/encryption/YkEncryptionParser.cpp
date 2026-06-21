/*****************************************************************************
 * YkEncryptionParser.cpp
 *****************************************************************************
 * 解析 urn:com-yk:* 系列 schemeIdUri 的 <ContentProtection> 节点。
 *
 * 期望的 XML 形态(由加密器侧 ContentProtectionInjectorV1 生成):
 *
 *   <ContentProtection schemeIdUri="urn:com-yk:aes-ctr:1"
 *                      xmlns:yk="urn:com-yk:dash-ext:1">
 *       <yk:Encryption algoVersion="1" keyDerive="raw" ivScheme="fixed">
 *           <yk:KeyId>k001</yk:KeyId>
 *           <yk:IV>65666768696a6b6c6d6e6f7071727374</yk:IV>
 *       </yk:Encryption>
 *   </ContentProtection>
 *
 * 注意:adaptive::xml::Node 把 namespace 前缀视作 tag 名一部分,所以子节点
 * 名分别是 "yk:Encryption" / "yk:KeyId" / "yk:IV",直接用全名查找即可。
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "YkEncryptionParser.hpp"

#include "../xml/DOMHelper.h"
#include "../xml/Node.h"

#include <vlc_common.h>

#include <cctype>
#include <cstdlib>
#include <string>

using namespace adaptive::encryption;
using adaptive::xml::Node;
using adaptive::xml::DOMHelper;

namespace
{

const char kYkSchemePrefix[]   = "urn:com-yk:";
const char kAesCtrFamily[]     = "aes-ctr";
/* 未来加 family:CHACHA20_POLY1305 等。 */

/* 把 "urn:com-yk:aes-ctr:1" 拆成 (family="aes-ctr", version=1)。
 * 失败返回 false。 */
bool ParseSchemeUri(const std::string &uri,
                    std::string *family, int *version)
{
    const size_t prefix_len = sizeof(kYkSchemePrefix) - 1;
    if (uri.size() <= prefix_len) return false;
    if (uri.compare(0, prefix_len, kYkSchemePrefix) != 0) return false;

    const std::string body = uri.substr(prefix_len);  // "aes-ctr:1"
    const size_t colon = body.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;

    *family = body.substr(0, colon);
    const std::string ver_str = body.substr(colon + 1);
    if (ver_str.empty()) return false;
    for (char c : ver_str) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    *version = std::atoi(ver_str.c_str());
    if (*version <= 0) return false;
    return true;
}

int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

bool DecodeHex(const std::string &s, std::vector<unsigned char> &out)
{
    out.clear();
    if (s.empty() || (s.size() & 1u)) return false;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_digit(s[i]);
        int lo = hex_digit(s[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

/* 取 child element 文本,找不到返回空。 */
std::string GetChildText(const Node *parent, const char *child_name)
{
    if (!parent) return std::string();
    /* DOMHelper API 要求非 const Node*,这里通过 const_cast 安全使用 ——
     * 该函数只读取子节点,不修改;签名是历史遗留。 */
    Node *c = DOMHelper::getFirstChildElementByName(
        const_cast<Node*>(parent), child_name);
    return c ? c->getText() : std::string();
}

}  // namespace

YkParseResult YkEncryptionParser::ParseFromContentProtection(const Node *cp_node,
                                                              CommonEncryption &enc)
{
    if (!cp_node) return YkParseResult::Malformed;

    /* 1. schemeIdUri 必须是 urn:com-yk:*,否则不是我们的 */
    if (!cp_node->hasAttribute("schemeIdUri")) return YkParseResult::NotOurs;
    const std::string uri = cp_node->getAttributeValue("schemeIdUri");

    std::string family;
    int version_from_uri = 0;
    if (!ParseSchemeUri(uri, &family, &version_from_uri))
        return YkParseResult::NotOurs;

    /* 2. 算法族分发 */
    CommonEncryption::Method method = CommonEncryption::Method::NONE;
    if (family == kAesCtrFamily) {
        method = CommonEncryption::Method::AES_CTR;
    /* } else if (family == "chacha20-poly1305") {
           method = CommonEncryption::Method::CHACHA20_POLY1305; */
    } else {
        /* 我们自己 namespace 下未知 family —— 调用方会打警告 */
        return YkParseResult::UnknownFamily;
    }

    /* 3. 读 yk:Encryption 子节点的属性与子文本 */
    Node *enc_node = DOMHelper::getFirstChildElementByName(
        const_cast<Node*>(cp_node), "yk:Encryption");

    int    algo_version_attr = 0;
    std::string key_derive   = "raw";
    std::string iv_scheme    = "fixed";

    if (enc_node) {
        if (enc_node->hasAttribute("algoVersion")) {
            algo_version_attr = std::atoi(
                enc_node->getAttributeValue("algoVersion").c_str());
        }
        if (enc_node->hasAttribute("keyDerive"))
            key_derive = enc_node->getAttributeValue("keyDerive");
        if (enc_node->hasAttribute("ivScheme"))
            iv_scheme  = enc_node->getAttributeValue("ivScheme");
    }

    /* algoVersion 与 schemeIdUri 末段必须一致。冗余字段是有意设计的容错位
     * (§B.2.1):任一缺失另一个仍能起作用,但同时存在时必须一致,否则
     * MPD 来源可疑。schemeIdUri 是 DASH 规范定义的位置,优先级更高。 */
    if (algo_version_attr > 0 && algo_version_attr != version_from_uri) {
        return YkParseResult::VersionMismatch;
    }
    int algo_version = version_from_uri;

    /* 4. 读 KeyId / IV 子节点(可能在 yk:Encryption 里,也可能直接挂在
     *    ContentProtection 下,兼容两种位置) */
    std::string keyid  = GetChildText(enc_node, "yk:KeyId");
    if (keyid.empty())  keyid  = GetChildText(cp_node,  "yk:KeyId");

    std::string iv_hex = GetChildText(enc_node, "yk:IV");
    if (iv_hex.empty()) iv_hex = GetChildText(cp_node,  "yk:IV");

    std::vector<unsigned char> iv_bytes;
    if (!iv_hex.empty()) {
        if (!DecodeHex(iv_hex, iv_bytes))
            return YkParseResult::InvalidIv;
    }

    /* 4b. v2 字段:CourseId + KeyBlob。
     *    v1 不写这俩(留空);v2 ivScheme="derived" 时无 <yk:IV>,改有 <yk:KeyBlob>。
     *    KeyBlob = Enc_A(B) 的 hex,播放器用 A 做 AES-128-ECB 单块解密得 B。
     *    CourseId 是课程标识(非机密),播放器据此向后台请求该课程的 A/K_idx。 */
    std::string course_id = GetChildText(enc_node, "yk:CourseId");
    if (course_id.empty()) course_id = GetChildText(cp_node, "yk:CourseId");

    std::string key_blob_hex = GetChildText(enc_node, "yk:KeyBlob");
    if (key_blob_hex.empty()) key_blob_hex = GetChildText(cp_node, "yk:KeyBlob");
    std::vector<unsigned char> key_blob;
    if (!key_blob_hex.empty()) {
        if (!DecodeHex(key_blob_hex, key_blob))
            return YkParseResult::InvalidIv;  /* 复用"解码失败"诊断码 */
    }

    /* 5. 写回 enc */
    enc.method       = method;
    enc.algo_version = algo_version;
    enc.keyid        = keyid;
    enc.iv           = iv_bytes;       /* v1 单 IV;v2 ivScheme=derived 时为空 */
    enc.key_derive   = key_derive;
    enc.iv_scheme    = iv_scheme;
    enc.course_id    = course_id;      /* v2 */
    enc.key_blob     = key_blob;       /* v2:Enc_A(B) */
    /* license_blob / aad / kdf_* 等预留字段 v1/v2 不读,留空。 */

    return YkParseResult::Ok;
}
