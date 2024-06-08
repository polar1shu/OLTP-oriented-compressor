#define DPTC_MIN_OFFSET 8

static size_t dptc_hashPosition(const void* p) 
{
    if (MEM_64bits())
        return dptc_hash5Ptr(p, DPTC_HASHTABLE_PARTITION_LOG);
    return dptc_hash4Ptr(p, DPTC_HASHTABLE_PARTITION_LOG);
}

static void dptc_putPositionOnHash(const BYTE* p, size_t h, U32* hashTable, const BYTE* srcBase)
{
    hashTable[h] = (U32)(p-srcBase);
}

static void dptc_putPosition(const BYTE* p, U32* hashTable, const BYTE* srcBase)
{
    size_t const h = dptc_hashPosition(p);
    dptc_putPositionOnHash(p, h, hashTable, srcBase);
}

static U32 dptc_getPositionOnHashSmall(size_t h, U32* hashTable)
{
    return hashTable[h];
}

static U32 dptc_getPosition(const BYTE* p, U32* hashTable)
{
    size_t const h = dptc_hashPosition(p);
    return dptc_getPositionOnHashSmall(h, hashTable);
}

FORCE_INLINE int dptc_encodeEntry (
    dptc_compressor_t* cpr,
    const BYTE** ip,
    const BYTE** anchor,
    size_t matchLength,
    const BYTE* match,
    size_t matchDataLength,
    const int startLine,
    const int endLine,
    const BYTE* startRowAnchor,
    const int* const ipSize,
    const int* const opSize,
    const int headerLen
    )
{
    size_t length = (size_t)(*ip - *anchor);
    size_t tag_length = 0;
    size_t preDataLength = 0;
    size_t len = 0;
    BYTE* pre_data_length;
    BYTE* data_length;
    BYTE* match_length;
    (void) cpr;

    for (int i = startLine; i < endLine; i++) {
        int lastDataLen = startRowAnchor + headerLen + ipSize[i] - *anchor;
        int lastAlignedDataLen = startRowAnchor + MAXALIGN(headerLen + ipSize[i]) - *anchor;
        int len = lastDataLen;
        if (lastDataLen >= 255) {
            while (len >= 255) {
                *cpr->dataPtr++ = 255;
                len -= 255;
            }
        }
        *cpr->dataPtr++ = len;

        simd_copy16(cpr->dataPtr, *anchor, cpr->dataPtr + lastDataLen);
        cpr->dataPtr += (lastDataLen + MAXALIGN(opSize[i]+headerLen) - opSize[i] - headerLen);

        startRowAnchor += MAXALIGN(headerLen + ipSize[i]);
        *anchor = startRowAnchor;

        simd_copy16(cpr->dataPtr, *anchor, cpr->dataPtr + headerLen);
        cpr->dataPtr += headerLen;
        *anchor += headerLen;

        length -= (lastAlignedDataLen + headerLen);
    }

    len = length;
    if (length >= 255) {
        while (len >= 255) {
            *cpr->dataPtr++ = 255;
            len -= 255;
        }
    }
    data_length = cpr->dataPtr;
    *cpr->dataPtr++ = len;
    if (length > 0) {
        simd_copy16(cpr->dataPtr, *anchor, cpr->dataPtr + length);
        cpr->dataPtr += length;
    }

    preDataLength = 0;
    pre_data_length = match - matchDataLength;
    do {
        tag_length = *pre_data_length;
        pre_data_length++;
        preDataLength += tag_length;
    } while (tag_length == 255);
    tag_length = preDataLength - matchDataLength + 1;
    if (tag_length > matchLength) {
        tag_length = matchLength;
    }

    match += preDataLength / 255;

    if (tag_length <= META_LENGTH && matchLength - tag_length >= MATCH_ENTRY_META_LENGTH) {
        BYTE* matchTmp;
        BYTE* matchAnchor;
        BYTE* match_length_tmp;
        BYTE* offsetPtr;
        size_t matchLengthTmp;
        size_t tagLengthTmp;
        size_t offsetTmp;
        size_t matchLengthNow;
        size_t matchLengthRest;

        if likely(*data_length + tag_length < 255) {
            *data_length += tag_length;
            dptc_copy8(cpr->dataPtr, match);
            cpr->dataPtr += tag_length;
            
            offsetTmp = MEM_readLE16(match+tag_length);
            matchTmp = match+tag_length+2;
            matchAnchor = match+tag_length+2;
            offsetPtr = cpr->dataPtr;
            cpr->dataPtr+=2;

            matchLengthTmp = (*(matchTmp)++) & 127;
            if (matchLengthTmp == 127) {
                matchLengthTmp = *matchTmp;
                if unlikely(matchLengthTmp >= 126) {
                    if (matchLengthTmp == 126) {
                        matchLengthTmp = MEM_readLE16(matchTmp+1);
                        matchTmp += 2;
                    } else {
                        matchLengthTmp = MEM_readLE24(matchTmp+1);
                        matchTmp += 3;
                    }
                }
                matchLengthTmp += 127;
                matchTmp++;
            }
            matchLengthTmp += MINMATCH;

            if (*matchAnchor & 0x80) {
                tagLengthTmp = matchLengthTmp;
            } else {
                tagLengthTmp = *(matchTmp)++;
                if (tagLengthTmp == 255) {
                    tagLengthTmp = *matchTmp;
                    if unlikely(tagLengthTmp >= 254) {
                        if (tagLengthTmp == 254) {
                            tagLengthTmp = MEM_readLE16(matchTmp+1);
                        } else {
                            tagLengthTmp = MEM_readLE24(matchTmp+1);
                        }
                    }
                    tagLengthTmp += 255;
                }
            }

            match_length_tmp = (cpr->dataPtr)++;
            matchLengthRest = matchLength - tag_length;
            matchLengthNow = matchLengthRest - MINMATCH;
            if (matchLengthNow >= 127) {
                *match_length_tmp = 127;
                matchLengthNow -= 127;
                if (matchLengthNow >= (1<<16)) { *(cpr->dataPtr) = 127;  MEM_writeLE24(cpr->dataPtr+1, (U32)(matchLengthNow));  cpr->dataPtr += 4; }
                else if (matchLengthNow >= 126) { *(cpr->dataPtr) = 126;  MEM_writeLE16(cpr->dataPtr+1, (U16)(matchLengthNow));  cpr->dataPtr += 3; }
                else *(cpr->dataPtr)++ = (BYTE)matchLengthNow;
            }
            else *match_length_tmp = matchLengthNow;

            if (tagLengthTmp >= matchLengthRest) {
                MEM_writeLE16(offsetPtr, (U16)(offsetPtr-matchAnchor+offsetTmp+2));
                *match_length_tmp |= 0x80;
            } else if (matchLengthTmp >= matchLengthRest) {
                MEM_writeLE16(offsetPtr, (U16)(offsetPtr-matchAnchor+offsetTmp+2));
                if (tagLengthTmp >= 255) {
                    *(cpr->dataPtr)++ = 255;
                    tagLengthTmp -= 255;
                    if (tagLengthTmp >= (1<<16)) { *(cpr->dataPtr) = 255;  MEM_writeLE24(cpr->dataPtr+1, (U32)(tagLengthTmp));  cpr->dataPtr += 4; }
                    else if (tagLengthTmp >= 254) { *(cpr->dataPtr) = 254;  MEM_writeLE16(cpr->dataPtr+1, (U16)(tagLengthTmp));  cpr->dataPtr += 3; }
                    else *(cpr->dataPtr)++ = (BYTE)tagLengthTmp;
                }
                else *(cpr->dataPtr)++ = tagLengthTmp;
            } else {
                MEM_writeLE16(offsetPtr, (U16)(offsetPtr-match-tag_length+2));
                *(cpr->dataPtr)++ = 0;
            }
            goto _encode_finished;
        }
    }

    MEM_writeLE16(cpr->dataPtr, (U16)(cpr->dataPtr-match+2));
    cpr->dataPtr+=2;
    match_length = (cpr->dataPtr)++;

    if (tag_length > META_LENGTH) {
        matchLength = tag_length;
        length = matchLength - MINMATCH;
        if (length >= 127) {
            *match_length = 127;
            length -= 127;
            if (length >= (1<<16)) { *(cpr->dataPtr) = 127;  MEM_writeLE24(cpr->dataPtr+1, (U32)(length));  cpr->dataPtr += 4; }
            else if (length >= 126) { *(cpr->dataPtr) = 126;  MEM_writeLE16(cpr->dataPtr+1, (U16)(length));  cpr->dataPtr += 3; }
            else *(cpr->dataPtr)++ = (BYTE)length;
        }
        else *match_length = length;
        *match_length |= 0x80;
    } else {
        length = matchLength - MINMATCH;
        if (length >= 127) {
            *match_length = 127;
            length -= 127;
            if (length >= (1<<16)) { *(cpr->dataPtr) = 127;  MEM_writeLE24(cpr->dataPtr+1, (U32)(length));  cpr->dataPtr += 4; }
            else if (length >= 126) { *(cpr->dataPtr) = 126;  MEM_writeLE16(cpr->dataPtr+1, (U16)(length));  cpr->dataPtr += 3; }
            else *(cpr->dataPtr)++ = (BYTE)length;
        }
        else *match_length = length;

        if (tag_length >= 255) {
            *(cpr->dataPtr)++ = 255;
            tag_length -= 255;
            if (tag_length >= (1<<16)) { *(cpr->dataPtr) = 255;  MEM_writeLE24(cpr->dataPtr+1, (U32)(tag_length));  cpr->dataPtr += 4; }
            else if (tag_length >= 254) { *(cpr->dataPtr) = 254;  MEM_writeLE16(cpr->dataPtr+1, (U16)(tag_length));  cpr->dataPtr += 3; }
            else *(cpr->dataPtr)++ = (BYTE)tag_length;
        }
        else *(cpr->dataPtr)++ = tag_length;
    }

_encode_finished:
    *ip += matchLength;
    *anchor = *ip;

    return 0;
}

FORCE_INLINE int dptc_encodeAlignedLastDE (
    dptc_compressor_t* cpr,
    const BYTE** ip,
    const BYTE** anchor,
    const int startLine,
    const int endLine,
    const BYTE* startRowAnchor,
    const int* const ipSize,
    const int* const opSize,
    const int headerLen
    )
{
    size_t length = (int)(*ip - *anchor);
    size_t len = 0;
    for (int i = startLine; i < endLine; i++) {
        int lastDataLen = startRowAnchor + headerLen + ipSize[i] - *anchor;
        int lastAlignedDataLen = startRowAnchor + MAXALIGN(headerLen + ipSize[i]) - *anchor;

        int len = lastDataLen;
        if (lastDataLen >= 255) {
            while (len >= 255) {
                *cpr->dataPtr++ = 255;
                len -= 255;
            }
        }
        *cpr->dataPtr++ = len;

        simd_copy16(cpr->dataPtr, *anchor, cpr->dataPtr + lastDataLen);
        cpr->dataPtr += (lastDataLen + MAXALIGN(opSize[i]+headerLen) - opSize[i] - headerLen);

        startRowAnchor += MAXALIGN(headerLen + ipSize[i]);
        *anchor = startRowAnchor;

        simd_copy16(cpr->dataPtr, *anchor, cpr->dataPtr + headerLen);
        cpr->dataPtr += headerLen;
        *anchor += headerLen;

        length -= (lastAlignedDataLen+headerLen);
    }

    len = length;
    if (length >= 255) {
        while (len >= 255) {
            *cpr->dataPtr++ = 255;
            len -= 255;
        }
    }
    *cpr->dataPtr++ = len;

    memcpy(cpr->dataPtr, *anchor, length);
    cpr->dataPtr += (length + MAXALIGN(opSize[endLine]+headerLen) - opSize[endLine] - headerLen);
    return 0;
}

FORCE_INLINE int dptc_encode(
        dptc_compressor_t* const cpr,
        const BYTE* ip,
        const BYTE* const iend,
        const int* ipSize,
        int* opSize,
        const int batchSize,
        const int headerLen)
{
    size_t forwardH;
    size_t matchIndex;
    size_t cprMatchIndex;
    size_t matchDataLength;
    int nline = 0;
    int rowLimit = ipSize[0];
    int alignOpSize = 0;
    int alignOffset = 0;
    int encodeLine = 0;
    const U32 maxDistance = (1 << DPTC_WINDOW_LOG) - 1;
    const U32 lowLimit = cpr->lowLimit;
    const BYTE* base = cpr->base;
    const U32 indexPadding = cpr->indexPadding;
    const BYTE* const mflimit = iend - MFLIMIT;
    const BYTE* anchor = ip;
    const BYTE* alignAnchor;
    const BYTE* preRowAnchor = ip + headerLen;
    const BYTE* preCmpAnchor = cpr->dataPtr + headerLen;
    const BYTE* encodeRowAnchor = ip;
    const BYTE* matchlimit = MIN(preRowAnchor+rowLimit-1, iend - LASTDATA);

    if ((U32)(iend-ip) < DPTC_INPUT_MIX_LEN) goto _last_data;

    ip += headerLen;
    simd_copy16(cpr->dataPtr, anchor, cpr->dataPtr+headerLen);
    cpr->dataPtr += headerLen;
    anchor = ip;
    alignAnchor = ip;
    dptc_putPosition(ip, cpr->hashTable, base);
    dptc_putPositionOnHash(cpr->dataPtr+(ip-anchor)+1, dptc_hashPosition(ip)+DPTC_COMOFFSET_PARTITION, cpr->hashTable, cpr->dataBase);
    dptc_putPositionOnHash(ip, dptc_hashPosition(ip)+DPTC_TAGLENGTH_PARTITION, cpr->hashTable, alignAnchor);
    ip++; forwardH = dptc_hashPosition(ip);

    for ( ; ; ) {
        const BYTE* match;
        const BYTE* cprmatch;
        size_t matchLength;

        {   const BYTE* forwardIp = ip;
            while (1) {
                size_t const h = forwardH;
                ip = forwardIp;
                forwardIp += 1;

                if (forwardIp - preRowAnchor >= rowLimit - META_LENGTH) {
                    forwardIp = preRowAnchor + MAXALIGN(rowLimit + headerLen);
                    if (anchor < preRowAnchor) {
                        opSize[nline] = ipSize[nline] + ipSize[nline] / 255 + 1;
                    } else {
                        int lastDataLen = preRowAnchor + rowLimit - anchor;
                        opSize[nline] = cpr->dataPtr - preCmpAnchor + lastDataLen + lastDataLen/255 + 1;
                    }
                    alignOpSize = MAXALIGN(headerLen + opSize[nline]);
                    alignOffset = alignOffset + alignOpSize - opSize[nline] - MAXALIGN(ipSize[nline]+headerLen) + ipSize[nline] + (preRowAnchor+rowLimit-alignAnchor)/255 + 1;
                    preCmpAnchor += alignOpSize;
                    nline += 1;
                    rowLimit = ipSize[nline];
                    preRowAnchor = forwardIp;
                    alignAnchor = preRowAnchor;
                    matchlimit = MIN(preRowAnchor+rowLimit-1, iend - LASTDATA);
                    if (unlikely(forwardIp > mflimit)) goto _last_data;
                    continue;
                }

                if (unlikely(forwardIp > mflimit)) goto _last_data;

                matchIndex = dptc_getPositionOnHashSmall(h, cpr->hashTable);
                cprMatchIndex = dptc_getPositionOnHashSmall(h+DPTC_COMOFFSET_PARTITION, cpr->hashTable);
                matchDataLength = dptc_getPositionOnHashSmall(h+DPTC_TAGLENGTH_PARTITION, cpr->hashTable);
                forwardH = dptc_hashPosition(forwardIp);

                if ((matchIndex < lowLimit) || (matchIndex >= (U32)(ip - base))) {
                    dptc_putPositionOnHash(ip, h, cpr->hashTable, base);
                    dptc_putPositionOnHash(cpr->dataPtr+(ip-anchor)+alignOffset+1, h+DPTC_COMOFFSET_PARTITION, cpr->hashTable, cpr->dataBase);
                    dptc_putPositionOnHash(ip, h+DPTC_TAGLENGTH_PARTITION, cpr->hashTable, alignAnchor);
                    continue;
                }
                
                if ((cprMatchIndex >= (U32)(cpr->dataPtr+(ip-anchor)-cpr->dataBase))
                    || ((cpr->dataBase + cprMatchIndex + maxDistance) < (cpr->dataPtr+(ip-anchor)))) {
                    dptc_putPositionOnHash(ip, h, cpr->hashTable, base);
                    dptc_putPositionOnHash(cpr->dataPtr+(ip-anchor)+alignOffset+1, h+DPTC_COMOFFSET_PARTITION, cpr->hashTable, cpr->dataBase);
                    dptc_putPositionOnHash(ip, h+DPTC_TAGLENGTH_PARTITION, cpr->hashTable, alignAnchor);
                    continue;
                }

                if (matchIndex >= indexPadding) {
                    match = base + matchIndex;
#if DPTC_MIN_OFFSET > 0
                    if ((U32)(ip - match) >= DPTC_MIN_OFFSET) {
#endif
                    if (MEM_read32(match) == MEM_read32(ip)) {
                        matchLength = dptc_count(ip+MINMATCH, match+MINMATCH, matchlimit);
                        if (matchLength > 2) {
                            cprmatch = cpr->dataBase + cprMatchIndex;
                            break;
                        }
                    }
#if DPTC_MIN_OFFSET > 0
                    } else {
                        continue;
                    }
#endif
                }
                dptc_putPositionOnHash(ip, h, cpr->hashTable, base);
                dptc_putPositionOnHash(cpr->dataPtr+(ip-anchor)+alignOffset+1, h+DPTC_COMOFFSET_PARTITION, cpr->hashTable, cpr->dataBase);
                dptc_putPositionOnHash(ip, h+DPTC_TAGLENGTH_PARTITION, cpr->hashTable, alignAnchor);
            }
        }

_next_match:
        if (dptc_encodeEntry(cpr, &ip, &anchor, matchLength+MINMATCH, cprmatch, matchDataLength+1, encodeLine, nline, encodeRowAnchor, ipSize, opSize, headerLen)) return 0;
        encodeRowAnchor = preRowAnchor - headerLen;
        encodeLine = nline;
        alignOffset = 0;
        alignAnchor = anchor;
        if (ip > mflimit) break;

        if (ip - preRowAnchor >= rowLimit - 6) {
            ip = preRowAnchor + MAXALIGN(rowLimit + headerLen);
            opSize[nline] = cpr->dataPtr - preCmpAnchor + preRowAnchor + rowLimit - anchor + 1;
            alignOpSize = MAXALIGN(headerLen + opSize[nline]);
            alignOffset = alignOffset + alignOpSize - opSize[nline] - MAXALIGN(ipSize[nline] + headerLen) + ipSize[nline] + 1;
            preCmpAnchor += alignOpSize;
            nline += 1;
            rowLimit = ipSize[nline];
            preRowAnchor = ip;
            alignAnchor = preRowAnchor;
            matchlimit = MIN(preRowAnchor+rowLimit-1, iend - LASTDATA);
            if (unlikely(ip > mflimit)) goto _last_data;
        }

        matchIndex = dptc_getPosition(ip, cpr->hashTable);
        cprMatchIndex = dptc_getPositionOnHashSmall(dptc_hashPosition(ip)+DPTC_COMOFFSET_PARTITION, cpr->hashTable);
        matchDataLength = dptc_getPositionOnHashSmall(dptc_hashPosition(ip)+DPTC_TAGLENGTH_PARTITION, cpr->hashTable);

        if ((matchIndex >= lowLimit) && (matchIndex < (U32)(ip - base))
        && (cprMatchIndex < (U32)(cpr->dataPtr+(ip-anchor)-cpr->dataBase))
        && (cpr->dataBase + cprMatchIndex + maxDistance > cpr->dataPtr+(ip-anchor)))
        {
            if (matchIndex >= indexPadding) {
                match = base + matchIndex;
                cprmatch = cpr->dataBase + cprMatchIndex;
#if DPTC_MIN_OFFSET > 0
                if ((U32)(ip - match) >= DPTC_MIN_OFFSET) {
#endif
                if (MEM_read32(match) == MEM_read32(ip)) {
                    matchLength = dptc_count(ip+MINMATCH, match+MINMATCH, matchlimit);
                    if (matchLength > 2)
                        goto _next_match;
                }
#if DPTC_MIN_OFFSET > 0
                } else {
                    goto _next_loop;
                }
#endif
            }
        }

        dptc_putPosition(ip, cpr->hashTable, base);
        dptc_putPositionOnHash(cpr->dataPtr+(ip-anchor)+alignOffset+1, dptc_hashPosition(ip)+DPTC_COMOFFSET_PARTITION, cpr->hashTable, cpr->dataBase);
        dptc_putPositionOnHash(ip, dptc_hashPosition(ip)+DPTC_TAGLENGTH_PARTITION, cpr->hashTable, alignAnchor);

_next_loop:
        ip++;
        if (ip - preRowAnchor >= rowLimit - 6) {
            ip = preRowAnchor + MAXALIGN(rowLimit + headerLen);
            if (anchor < preRowAnchor) {
                opSize[nline] = ipSize[nline] + ipSize[nline] / 255 + 1;
            } else {
                opSize[nline] = cpr->dataPtr - preCmpAnchor + preRowAnchor + rowLimit - anchor + 1;
            }
            alignOpSize = MAXALIGN(headerLen + opSize[nline]);
            alignOffset = alignOffset + alignOpSize - opSize[nline] - MAXALIGN(ipSize[nline] + headerLen) + ipSize[nline] + 1;
            preCmpAnchor += alignOpSize;
            nline += 1;
            rowLimit = ipSize[nline];
            preRowAnchor = ip;
            alignAnchor = preRowAnchor;
            matchlimit = MIN(preRowAnchor+rowLimit-1, iend - LASTDATA);
            if (unlikely(ip > mflimit)) goto _last_data;
        }

        forwardH = dptc_hashPosition(ip);
    }

_last_data:
    ip = iend;
    if (anchor < preRowAnchor) {
        opSize[nline] = ipSize[nline] + ipSize[nline]/255 + 1;
    } else {
        int lastDataLen = preRowAnchor + rowLimit - anchor;
        opSize[nline] = cpr->dataPtr - preCmpAnchor + lastDataLen + lastDataLen/255 + 1;
    }

    while (nline < batchSize - 1) {
        nline++;
        opSize[nline] = ipSize[nline] + 1;
    }
    
    if (dptc_encodeAlignedLastDE(cpr, &ip, &anchor, encodeLine, nline, encodeRowAnchor, ipSize, opSize, headerLen)) return 0;

    return 1;
}
