/*****************************************************************************
 * YkEncryptionParser.hpp
 *****************************************************************************
 * 解析我们自定义 schemeIdUri "urn:com-yk:<algo-family>:<int-version>" 的
 * <ContentProtection> 节点,填充 CommonEncryption。对应 §B.4 任务 #7。
 *
 * SRP:本文件只负责"识别 + 抽字段",不负责创建 session、不负责调用方调度。
 *      调用方在 DASH parser 里 / Segment::prepareChunk 里都可使用。
 *
 * OCP:加新算法族(chacha20-poly1305 等)只需在 ParseFromContentProtection 里
 *      加一个 if 分支,旧分支不动。
 *
 * 输入:`<ContentProtection schemeIdUri="..." ...> <yk:...> </ContentProtection>`
 *      节点(adaptive::xml::Node)
 * 输出:CommonEncryption 字段被填充,返回 true 表示这是我们的 yk scheme。
 *      返回 false 表示不是我们的 scheme(调用方应继续尝试其它解析器)。
 *****************************************************************************/
#ifndef ADAPTIVE_YK_ENCRYPTION_PARSER_HPP
#define ADAPTIVE_YK_ENCRYPTION_PARSER_HPP

#include "CommonEncryption.hpp"

namespace adaptive {
namespace xml { class Node; }

namespace encryption
{
    /* 解析的"诊断码":返回给调用方的细化结果。
     * 阶段 B 只用 OK / NOT_OURS / FAILED;但留 enum 是为 v2+ 区分
     * (例如"识别但缺 IV"等)。 */
    enum class YkParseResult
    {
        Ok,                  /* 解析成功,enc 已填充。 */
        NotOurs,             /* schemeIdUri 不属于 urn:com-yk:*,enc 未变。 */
        UnknownFamily,       /* 是 urn:com-yk:* 但 family 当前未知。 */
        VersionMismatch,     /* schemeIdUri 末段与 algoVersion 不一致。 */
        InvalidIv,           /* IV 字段编码异常。 */
        Malformed            /* 其它格式问题。 */
    };

    class YkEncryptionParser
    {
    public:
        /* 尝试把 <ContentProtection> 节点解析成 yk-* 加密元数据。
         * 命中(scheme 前缀匹配 "urn:com-yk:")时填充 enc 并返回 Ok;
         * 否则 enc 不动,返回相应诊断码。
         *
         * 调用方根据返回值决定:
         *   - Ok / NotOurs:正常(NotOurs 表示这条 ContentProtection 不归我们管)
         *   - 其它:打 msg_Warn 提示用户 MPD 有问题 */
        static YkParseResult ParseFromContentProtection(const xml::Node *cp_node,
                                                        CommonEncryption &enc);
    };
}}  // namespace adaptive::encryption

#endif
