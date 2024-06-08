#if defined (__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mem.h"
#include "compiler.h"
#include <emmintrin.h>

#define MINMATCH 4
#define DATA_ENTRY_TAG 0
#define DPTC_INDEX_PADDING       (1<<24)
#define STEPSIZE sizeof(size_t)
#define META_LENGTH 5
#define MATCH_ENTRY_META_LENGTH 4
#define SSE_COPY_LENGTH      16
#define LASTDATA SSE_COPY_LENGTH
#define MFLIMIT (SSE_COPY_LENGTH+MINMATCH)
#define DPTC_INPUT_MIX_LEN  MFLIMIT
#define DPTC_INPUT_BUF_MAX      (1<<16)
#define DPTC_COMPRESS_BUF_MAX      (DPTC_INPUT_BUF_MAX+DPTC_INPUT_BUF_MAX/(MFLIMIT+1))
#define DPTC_WINDOW_LOG   16
#define DPTC_HASHTABLE_LOG   14
#define DPTC_HASHTABLE_PARTITION_LOG    12
#define DPTC_COMOFFSET_PARTITION    (1<<12)
#define DPTC_TAGLENGTH_PARTITION    (1<<13)
#define TYPEALIGN(ALIGNVAL, LEN) (((uintptr_t)(LEN) + ((ALIGNVAL)-1)) & ~((uintptr_t)((ALIGNVAL)-1)))
#define MAXALIGN(LEN) TYPEALIGN(8, (LEN))
#ifndef MIN
	#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

struct dptc_compressor_s
{
    const BYTE* base;
    U32   indexPadding;
    U32   lowLimit;
    U32   hashTableSize;
    U32*  hashTable;
    BYTE*  dataBase;
    BYTE*  dataPtr;
};

struct dptc_decompressor_s
{
    const BYTE*  dataPtr;
    const BYTE*  dataEnd;
};


MEM_STATIC void dptc_copy8(void* dst, const void* src)
{
    memcpy(dst,src,8);
}

MEM_STATIC void simd_copy16(BYTE* dstPtr, const BYTE* srcPtr, BYTE* dstEnd)
{
    do {
        _mm_storeu_si128((__m128i*)dstPtr,
            _mm_loadu_si128((__m128i*)srcPtr));
        dstPtr += 16;
        srcPtr += 16;
    }
    while (dstPtr < dstEnd);
}

MEM_STATIC unsigned dptc_NbCommonBytes (register size_t val)
{
    if (MEM_isLittleEndian()) {
        if (MEM_64bits()) {
#       if defined(_MSC_VER) && defined(_WIN64)
            unsigned long r = 0;
            _BitScanForward64( &r, (U64)val );
            return (int)(r>>3);
#       elif (defined(__clang__) || (DPTC_GCC_VERSION >= 304))
            return (__builtin_ctzll((U64)val) >> 3);
#       else
            static const int DeBruijnBytePos[64] = { 0, 0, 0, 0, 0, 1, 1, 2, 0, 3, 1, 3, 1, 4, 2, 7, 0, 2, 3, 6, 1, 5, 3, 5, 1, 3, 4, 4, 2, 5, 6, 7, 7, 0, 1, 2, 3, 3, 4, 6, 2, 6, 5, 5, 3, 4, 5, 6, 7, 1, 2, 4, 6, 4, 4, 5, 7, 2, 6, 5, 7, 6, 7, 7 };
            return DeBruijnBytePos[((U64)((val & -(long long)val) * 0x0218A392CDABBD3FULL)) >> 58];
#       endif
        } else {
#       if defined(_MSC_VER)
            unsigned long r;
            _BitScanForward( &r, (U32)val );
            return (int)(r>>3);
#       elif (defined(__clang__) || (DPTC_GCC_VERSION >= 304))
            return (__builtin_ctz((U32)val) >> 3);
#       else
            static const int DeBruijnBytePos[32] = { 0, 0, 3, 0, 3, 1, 3, 0, 3, 2, 2, 1, 3, 2, 0, 1, 3, 3, 1, 2, 2, 2, 2, 0, 3, 1, 2, 0, 1, 0, 1, 1 };
            return DeBruijnBytePos[((U32)((val & -(S32)val) * 0x077CB531U)) >> 27];
#       endif
        }
    } else {
        if (MEM_64bits()) {
#       if defined(_MSC_VER) && defined(_WIN64)
            unsigned long r = 0;
            _BitScanReverse64( &r, val );
            return (unsigned)(r>>3);
#       elif (defined(__clang__) || (DPTC_GCC_VERSION >= 304))
            return (__builtin_clzll((U64)val) >> 3);
#       else
            unsigned r;
            if (!(val>>32)) { r=4; } else { r=0; val>>=32; }
            if (!(val>>16)) { r+=2; val>>=8; } else { val>>=24; }
            r += (!val);
            return r;
#       endif
        } else {
#       if defined(_MSC_VER)
            unsigned long r = 0;
            _BitScanReverse( &r, (unsigned long)val );
            return (unsigned)(r>>3);
#       elif (defined(__clang__) || (DPTC_GCC_VERSION >= 304))
            return (__builtin_clz((U32)val) >> 3);
#       else
            unsigned r;
            if (!(val>>16)) { r=2; val>>=8; } else { r=0; val>>=24; }
            r += (!val);
            return r;
#       endif
        }
    }
}

MEM_STATIC unsigned dptc_count(const BYTE* pIn, const BYTE* pMatch, const BYTE* pInLimit)
{
    const BYTE* const pStart = pIn;

    while (likely(pIn<pInLimit-(STEPSIZE-1))) {
        size_t diff = MEM_readST(pMatch) ^ MEM_readST(pIn);
        if (!diff) { pIn+=STEPSIZE; pMatch+=STEPSIZE; continue; }
        pIn += dptc_NbCommonBytes(diff);
        return (unsigned)(pIn - pStart);
    }

    if (MEM_64bits()) if ((pIn<(pInLimit-3)) && (MEM_read32(pMatch) == MEM_read32(pIn))) { pIn+=4; pMatch+=4; }
    if ((pIn<(pInLimit-1)) && (MEM_read16(pMatch) == MEM_read16(pIn))) { pIn+=2; pMatch+=2; }
    if ((pIn<pInLimit) && (*pMatch == *pIn)) pIn++;
    return (unsigned)(pIn - pStart);
}

#if defined (__cplusplus)
}
#endif
