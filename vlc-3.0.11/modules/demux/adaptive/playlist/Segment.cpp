/*
 * Segment.cpp
 *****************************************************************************
 * Copyright (C) 2010 - 2011 Klagenfurt University
 *
 * Created on: Aug 10, 2010
 * Authors: Christopher Mueller <christopher.mueller@itec.uni-klu.ac.at>
 *          Christian Timmerer  <christian.timmerer@itec.uni-klu.ac.at>
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

#include "Segment.h"
#include "BaseAdaptationSet.h"
#include "BaseRepresentation.h"
#include "AbstractPlaylist.hpp"
#include "SegmentChunk.hpp"
#include "../http/BytesRange.hpp"
#include "../http/HTTPConnectionManager.h"
#include "../http/Downloader.hpp"
#include "../SharedResources.hpp"
#include "../encryption/AesCtrSession.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace adaptive::http;
using namespace adaptive::playlist;

const int ISegment::SEQUENCE_INVALID = 0;
const int ISegment::SEQUENCE_FIRST   = 1;

#include <algorithm>
#include <string>

bool endsWith(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}


ISegment::ISegment(const ICanonicalUrl *parent):
    ICanonicalUrl( parent ),
    startByte  (0),
    endByte    (0)
{
    debugName = "Segment";
    classId = CLASSID_ISEGMENT;
    startTime.Set(0);
    duration.Set(0);
    sequence = SEQUENCE_INVALID;
    templated = false;
    discontinuity = false;
}

ISegment::~ISegment()
{
}

#if 0
bool ISegment::prepareChunk(SharedResources *res, SegmentChunk *chunk, BaseRepresentation *rep)
{
    CommonEncryption enc = encryption;
    enc.mergeWith(rep->intheritEncryption());
    /*在这里构建解密逻辑*/
    std::cout << "ISegment::prepareChunk enc.method:" << enc.method << std::endl;
    if(enc.method != CommonEncryption::Method::NONE)
    {
        CommonEncryptionSession *encryptionSession = new CommonEncryptionSession();
        if(!encryptionSession->start(res, enc))
        {
            delete encryptionSession;
            return false;
        }
        chunk->setEncryptionSession(encryptionSession);
    }
    return true;
}
#endif

// 阶段 B:按 ContentProtection 解析出来的 enc.method 路由解密 session。
// 阶段 A 把"按 .m4s 后缀触发 XOR"的 hack 撤了,这里恢复成标准触发结构,
// 并加 yk-aes-ctr 分支。设计见 PLAYBACK_LINK_PLAN.md §B.3.3 / §B.4 任务 #8。
//
// CommonEncryption / CommonEncryptionSession / AesCtrSession 都来自
// adaptive::encryption,通过 Segment.h 头部的 `using namespace encryption`
// 在 playlist namespace 内自动可见,无需在此重复 using。
bool ISegment::prepareChunk(SharedResources* res, SegmentChunk* chunk, BaseRepresentation* rep) {
    CommonEncryption enc = encryption;
    enc.mergeWith(rep->intheritEncryption());

    if (enc.method == CommonEncryption::Method::NONE) {
        return true;  // 该流明文,无需解密
    }

    CommonEncryptionSession* session = nullptr;
    switch (enc.method) {
    case CommonEncryption::Method::AES_CTR:
        // yk-aes-ctr 算法族;具体 v1 / v2 / ... 由 AesCtrSession 内部按
        // enc.algo_version switch。
        session = new AesCtrSession(res ? res->getVlcObject() : nullptr);
        break;
    case CommonEncryption::Method::AES_128:
        // VLC 现有 CENC AES-128-CBC 通用 session
        session = new CommonEncryptionSession();
        break;
    default:
        std::cout << "ISegment::prepareChunk: unsupported enc.method="
                  << enc.method << ", playback will fail" << std::endl;
        return false;
    }

    if (!session->start(res, enc)) {
        std::cout << "ISegment::prepareChunk: session start failed (method="
                  << enc.method << ", algo_version=" << enc.algo_version << ")"
                  << std::endl;
        delete session;
        return false;
    }
    chunk->setEncryptionSession(session);
    return true;
}

SegmentChunk* ISegment::toChunk(SharedResources *res, AbstractConnectionManager *connManager,
                                size_t index, BaseRepresentation *rep)
{
    const std::string url = getUrlSegment().toString(index, rep);

    // 这里能打印m4s文件的url
    std::cout << "ISegment::toChunk url = " << url << std::endl;

    temp_test_url_ = url;

    HTTPChunkBufferedSource *source = new (std::nothrow) HTTPChunkBufferedSource(url, connManager,
                                                                                 rep->getAdaptationSet()->getID());
    if( source )
    {
        if(startByte != endByte)
            source->setBytesRange(BytesRange(startByte, endByte));

        SegmentChunk *chunk = createChunk(source, rep);
        if(chunk)
        {
            chunk->discontinuity = discontinuity;
            if(!prepareChunk(res, chunk, rep))
            {
                delete chunk;
                return NULL;
            }
            connManager->start(source);
            return chunk;
        }
        else
        {
            delete source;
        }
    }
    return NULL;
}

bool ISegment::isTemplate() const
{
    return templated;
}

void ISegment::setByteRange(size_t start, size_t end)
{
    startByte = start;
    endByte   = end;
}

void ISegment::setSequenceNumber(uint64_t seq)
{
    sequence = SEQUENCE_FIRST + seq;
}

uint64_t ISegment::getSequenceNumber() const
{
    return sequence;
}

size_t ISegment::getOffset() const
{
    return startByte;
}

void ISegment::debug(vlc_object_t *obj, int indent) const
{
    std::stringstream ss;
    ss.imbue(std::locale("C"));
    ss << std::string(indent, ' ') << debugName << " #" << getSequenceNumber();
    ss << " url=" << getUrlSegment().toString();
    if(startByte!=endByte)
        ss << " @" << startByte << ".." << endByte;
    if(startTime.Get() > 0)
    	 ss << " stime " << startTime.Get();
    ss << " duration " << duration.Get();
    msg_Dbg(obj, "%s", ss.str().c_str());
}

bool ISegment::contains(size_t byte) const
{
    if (startByte == endByte)
        return false;
    return (byte >= startByte &&
            (!endByte || byte <= endByte) );
}

int ISegment::compare(ISegment *other) const
{
    if(duration.Get())
    {
        if(startTime.Get() > other->startTime.Get())
            return 1;
        else if(startTime.Get() < other->startTime.Get())
            return -1;
    }

    if(startByte > other->startByte)
        return 1;
    else if(startByte < other->startByte)
        return -1;

    if(endByte > other->endByte)
        return 1;
    else if(endByte < other->endByte)
        return -1;

    return 0;
}

void ISegment::setEncryption(CommonEncryption &e)
{
    encryption = e;
}

int ISegment::getClassId() const
{
    return classId;
}

Segment::Segment(ICanonicalUrl *parent) :
        ISegment(parent)
{
    size = -1;
    classId = CLASSID_SEGMENT;
}

SegmentChunk* Segment::createChunk(AbstractChunkSource *source, BaseRepresentation *rep)
{
     /* act as factory */
    return new (std::nothrow) SegmentChunk(source, rep);
}

void Segment::addSubSegment(SubSegment *subsegment)
{
    if(!subsegments.empty())
    {
        /* Use our own sequence number, and since it it now
           uneffective, also for next subsegments numbering */
        subsegment->setSequenceNumber(getSequenceNumber());
        setSequenceNumber(getSequenceNumber());
    }
    subsegments.push_back(subsegment);
}

Segment::~Segment()
{
    std::vector<SubSegment*>::iterator it;
    for(it=subsegments.begin();it!=subsegments.end();++it)
        delete *it;
}

void                    Segment::setSourceUrl   ( const std::string &url )
{
    if ( url.empty() == false )
        this->sourceUrl = Url(url);
}

void Segment::debug(vlc_object_t *obj, int indent) const
{
    if (subsegments.empty())
    {
        ISegment::debug(obj, indent);
    }
    else
    {
        std::string text(indent, ' ');
        text.append("Segment");
        msg_Dbg(obj, "%s", text.c_str());
        std::vector<SubSegment *>::const_iterator l;
        for(l = subsegments.begin(); l != subsegments.end(); ++l)
            (*l)->debug(obj, indent + 1);
    }
}

Url Segment::getUrlSegment() const
{
    if(sourceUrl.hasScheme())
    {
        return sourceUrl;
    }
    else
    {
        Url ret = getParentUrlSegment();
        if (!sourceUrl.empty())
            ret.append(sourceUrl);
        return ret;
    }
}

std::vector<ISegment*> Segment::subSegments()
{
    std::vector<ISegment*> list;
    if(!subsegments.empty())
    {
        std::vector<SubSegment*>::iterator it;
        for(it=subsegments.begin();it!=subsegments.end();++it)
            list.push_back(*it);
    }
    else
    {
        list.push_back(this);
    }
    return list;
}

InitSegment::InitSegment(ICanonicalUrl *parent) :
    Segment(parent)
{
    debugName = "InitSegment";
    classId = CLASSID_INITSEGMENT;
}

IndexSegment::IndexSegment(ICanonicalUrl *parent) :
    Segment(parent)
{
    debugName = "IndexSegment";
    classId = CLASSID_INDEXSEGMENT;
}

SubSegment::SubSegment(ISegment *main, size_t start, size_t end) :
    ISegment(main)
{
    setByteRange(start, end);
    debugName = "SubSegment";
    classId = CLASSID_SUBSEGMENT;
}

SegmentChunk* SubSegment::createChunk(AbstractChunkSource *source, BaseRepresentation *rep)
{
     /* act as factory */
    return new (std::nothrow) SegmentChunk(source, rep);
}

Url SubSegment::getUrlSegment() const
{
    return getParentUrlSegment();
}

std::vector<ISegment*> SubSegment::subSegments()
{
    std::vector<ISegment*> list;
    list.push_back(this);
    return list;
}

void SubSegment::addSubSegment(SubSegment *)
{

}
