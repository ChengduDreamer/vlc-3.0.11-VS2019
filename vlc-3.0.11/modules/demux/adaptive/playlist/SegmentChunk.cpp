/*
 * SegmentChunk.cpp
 *****************************************************************************
 * Copyright (C) 2014 - 2015 VideoLAN Authors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
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

#include "SegmentChunk.hpp"
#include "Segment.h"
#include "BaseRepresentation.h"
#include "../encryption/CommonEncryption.hpp"

#include <vlc_block.h>

#include <cassert>
#include <cstdlib>

using namespace adaptive::playlist;
using namespace adaptive::encryption;
using namespace adaptive;

SegmentChunk::SegmentChunk(AbstractChunkSource *source, BaseRepresentation *rep_) :
    AbstractChunk(source)
{
    rep = rep_;
    encryptionSession = NULL;
}

SegmentChunk::~SegmentChunk()
{
    delete encryptionSession;
}

bool SegmentChunk::decrypt(block_t **pp_block)
{
    block_t *p_block = *pp_block;

    if(encryptionSession)
    {
        // 阶段 C v2:把当前 segment 上下文(rep_id + 序号)设给 session,
        // 供 per-segment IV 派生。rep_id 取 Representation 的 id 字符串转整数
        // (MPD 里 id="0"/"1");session 不需要时(v1/AES_128)基类空实现忽略。
        // rep_id 整个 segment 不变,首次解析后缓存,避免每次 decrypt 都
        // rep->getID().str() + strtoul(热路径字符串构造)。
        if(!rep_id_cached_)
        {
            if(rep)
            {
                const std::string idstr = rep->getID().str();
                cached_rep_id_ = static_cast<uint32_t>(strtoul(idstr.c_str(), nullptr, 10));
            }
            rep_id_cached_ = true;
        }
        encryptionSession->setSegmentContext(cached_rep_id_, (uint64_t)segment_index);

        bool b_last = isEmpty();
        p_block->i_buffer = encryptionSession->decrypt(p_block->p_buffer,
                                                       p_block->i_buffer, b_last);
        if(b_last)
            encryptionSession->close();
    }

    return true;
}

void SegmentChunk::onDownload(block_t **pp_block)
{
    decrypt(pp_block);
}

StreamFormat SegmentChunk::getStreamFormat() const
{
    if(rep)
        return rep->getStreamFormat();
    else
        return StreamFormat();
}

void SegmentChunk::setEncryptionSession(CommonEncryptionSession *s)
{
    delete encryptionSession;
    encryptionSession = s;
}
