void dptc_copy_rec(BYTE* match, intptr_t length, BYTE** op, int needcopy) {
    BYTE* matchAnchor;
    intptr_t offset;
    intptr_t matchLength;
    intptr_t tagLength;
    intptr_t dataLength;
    intptr_t tmpLength;
    BYTE* cpy;
    while(length != 0) {
        if (needcopy) {
            dataLength = 0;
            do {
                tmpLength = *match;
                match++;
                dataLength += tmpLength;
            } while (tmpLength == 255);

            dataLength = MIN(dataLength, length);
            cpy = *op + dataLength;
            simd_copy16(*op, match, cpy);
            *op = cpy;

            match += dataLength;
            length -= dataLength;
        }
        if (length == 0) return ;

        offset = MEM_readLE16(match); 
        match += 2;
        matchAnchor = match;

        matchLength = (*(match)++) & 127;
        if unlikely(matchLength == 127) {
            matchLength = *match;
            if unlikely(matchLength >= 126) {
                if (matchLength == 126) {
                    matchLength = MEM_readLE16(match+1);
                    match += 2;
                } else {
                    matchLength = MEM_readLE24(match+1);
                    match += 3;
                }
            }
            matchLength += 127;
            match++;
        }
        matchLength += MINMATCH;

        if (*matchAnchor & 0x80) {
            tagLength = matchLength;
        } else {
            tagLength = *(match)++;
            if unlikely(tagLength == 255) {
                tagLength = *match;
                if unlikely(tagLength >= 254) {
                    if (tagLength == 254) {
                        tagLength = MEM_readLE16(match+1);
                        match += 2;
                    } else {
                        tagLength = MEM_readLE24(match+1);
                        match += 3;
                    }
                }
                tagLength += 255;
                match++;
            }
        }

        matchLength = MIN(matchLength, length);
        length -= matchLength;

        needcopy = 1;
        if (matchLength <= tagLength) {
            cpy = *op + matchLength;
            simd_copy16(*op, matchAnchor - offset, cpy);
            *op = cpy;
        } else {
            cpy = *op + tagLength;
            simd_copy16(*op, matchAnchor - offset, cpy);
            *op = cpy;
            dptc_copy_rec(matchAnchor - offset + tagLength, matchLength - tagLength, op, 0);
        }
    }
}

FORCE_INLINE int dptc_decode(dptc_decompressor_t* depr, BYTE* const dest, int outputSize)
{
    const BYTE* const iend = depr->dataEnd;
    BYTE* op = dest;
    BYTE* const oend = op + outputSize;
    BYTE* cpy = NULL;
    BYTE* matchAnchor;
    intptr_t length = 0;
    intptr_t dataLength = 0;
    intptr_t tagLength = 0;
    intptr_t tmpLength = 0;

    while (depr->dataPtr < depr->dataEnd) {
        const BYTE* match;
        size_t offset;

        dataLength = 0;
        do {
            tmpLength = *depr->dataPtr;
            depr->dataPtr++;
            dataLength += tmpLength;
        } while (tmpLength == 255);

        dataLength = MIN(dataLength, depr->dataEnd - depr->dataPtr);
        cpy = op + dataLength;
        simd_copy16(op, depr->dataPtr, cpy);
        op = cpy;

        depr->dataPtr += dataLength;
        if unlikely(depr->dataPtr >= depr->dataEnd) {
            break;
        }

        offset = MEM_readLE16(depr->dataPtr); 
        depr->dataPtr += 2;
        matchAnchor = depr->dataPtr;

        length = (*(depr->dataPtr)++) & 127;
        if unlikely(length == 127) {
            length = *depr->dataPtr;
            if unlikely(length >= 126) {
                if (length == 126) {
                    length = MEM_readLE16(depr->dataPtr+1);
                    depr->dataPtr += 2;
                } else {
                    length = MEM_readLE24(depr->dataPtr+1);
                    depr->dataPtr += 3;
                }
            }
            length += 127;
            depr->dataPtr++;
            if (unlikely((size_t)(op+length)<(size_t)(op))) return -1;
        }
        length += MINMATCH;

        if (*matchAnchor & 0x80) {
            tagLength = length;
        } else {
            tagLength = *(depr->dataPtr)++;
            if unlikely(tagLength == 255) {
                tagLength = *depr->dataPtr;
                if unlikely(tagLength >= 254) {
                    if (tagLength == 254) {
                        tagLength = MEM_readLE16(depr->dataPtr+1);
                        depr->dataPtr += 2;
                    } else {
                        tagLength = MEM_readLE24(depr->dataPtr+1);
                        depr->dataPtr += 3;
                    }
                }
                tagLength += 255;
                if unlikely(++(depr->dataPtr) == depr->dataEnd) {
                    depr->dataPtr--;
                }
                if (unlikely((size_t)(op+tagLength)<(size_t)(op))) return -1;
            }
        }
        match = matchAnchor - offset;

        if (length <= tagLength) {
            cpy = op + length;
            simd_copy16(op, match, cpy);
            op = cpy;
        } else {
            cpy = op + tagLength;
            simd_copy16(op, match, cpy);
            op = cpy;
            dptc_copy_rec(match + tagLength, length - tagLength, &op, 0);
        }
    }

    length = depr->dataEnd - depr->dataPtr;
    cpy = op + length;
    if ((length < 0) || (depr->dataPtr+length != iend) || (cpy > oend)) return -1;
    memcpy(op, depr->dataPtr, length);
    depr->dataPtr += length;
    op += length;

    return (int) (op-dest);
}
