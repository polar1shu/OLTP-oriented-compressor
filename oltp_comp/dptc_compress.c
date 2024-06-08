#include <stdio.h>
#include <stdint.h>
#include "dptc.h"
#include "dptc_compress.h"

static const U32 prime4bytes = 2654435761U;
static const U64 prime5bytes = 889523592379ULL;
static U32 dptc_hash4(U32 u, U32 h) { return (u * prime4bytes) >> (32-h) ; }
static size_t dptc_hash4Ptr(const void* ptr, U32 h) { return dptc_hash4(MEM_read32(ptr), h); }
static size_t dptc_hash5(U64 u, U32 h) { return (size_t)((u * prime5bytes) << (64-40) >> (64-h)) ; }
static size_t dptc_hash5Ptr(const void* p, U32 h) { return dptc_hash5(MEM_read64(p), h); }


FORCE_INLINE int dptc_writeCmpBuf(dptc_compressor_t* cpr, const BYTE* ip, uint32_t inputSize, BYTE** op,  
                                    BYTE* oend, int* ipSize, int* opSize, int batchSize, int headerLen)
{
    int res;
    uint32_t dataLen = (uint32_t)(cpr->dataPtr - cpr->dataBase);
    uint32_t unalignedDataLen = headerLen * batchSize;

    for (int i = 0; i < batchSize; i++) unalignedDataLen += opSize[i]; 

    if ((dataLen < SSE_COPY_LENGTH) || (unalignedDataLen > inputSize)) {
        for (int i = 0; i < batchSize; i++) {
            opSize[i] = ipSize[i] + ipSize[i] / 255 + 1;
            memcpy(*op, ip, headerLen);
            *op += headerLen;

            int len = ipSize[i];
            if (ipSize[i] >= 255) {
                while (len >= 255) {
                    *(*op)++ = 255;
                    len -= 255;
                }
            }
            *(*op)++ = len;
            memcpy(*op, ip+headerLen, ipSize[i]);
            ip += MAXALIGN(ipSize[i] + headerLen);
            *op += MAXALIGN(opSize[i] + headerLen) - headerLen - ipSize[i] / 255 - 1;
        }
        return 0;
    }

    if (*op + dataLen > oend) return 1;
    memcpy(*op, cpr->dataBase, dataLen);
    *op += dataLen;
    return 0;
}

#include "dptc_encode.h"

FORCE_INLINE dptc_compressor_t* dptc_initCompressor(dptc_compressor_t* cpr, const BYTE* start) 
{ 
    U32 hashTableSize;
    void *tempPtr;

    hashTableSize = (U32)(sizeof(U32)*(((size_t)1 << DPTC_HASHTABLE_LOG)));
    
    if (!cpr) {
        cpr = (dptc_compressor_t*)malloc(sizeof(dptc_compressor_t) + hashTableSize + DPTC_COMPRESS_BUF_MAX);
        if (!cpr) return 0;
    }
    
    tempPtr = cpr;
    cpr->base = start - DPTC_INDEX_PADDING;
    cpr->indexPadding = DPTC_INDEX_PADDING;
    cpr->lowLimit = DPTC_INDEX_PADDING;
    cpr->hashTable = (U32*)(tempPtr) + sizeof(dptc_compressor_t)/4;
    cpr->hashTableSize = hashTableSize;
    memset(cpr->hashTable, 0, cpr->hashTableSize);
    cpr->dataBase = (BYTE*)cpr->hashTable + cpr->hashTableSize;

    return cpr;
}

FORCE_INLINE int dptc_compressInner(
    void* compressor,
    const char* source,
    char* dest,
    int* inputSize,
    int* outputSize,
    int totalInputSize,
    int maxOutputSize,
    int batchSize,
    int compressedSize,
    int headerLen)
{
    dptc_compressor_t* cpr = (dptc_compressor_t*) compressor;
    const BYTE* ip = (const BYTE*) source;
    BYTE* op = (BYTE*) dest;
    BYTE* const oend = op + maxOutputSize;
    int res;

    if (totalInputSize > DPTC_INPUT_BUF_MAX) return 0;

    cpr->dataPtr = cpr->dataBase + compressedSize;
    res = dptc_encode(cpr, ip, ip+totalInputSize, inputSize, outputSize, batchSize, headerLen);
    if (res <= 0) return res;

    cpr->dataBase += compressedSize;
    if (dptc_writeCmpBuf(cpr, ip, totalInputSize, &op, oend, inputSize, outputSize, batchSize, headerLen)) return 0;
    cpr->dataBase -= compressedSize;

    return (int)(op-(BYTE*)dest);
}


int dptc_compress(const char* source, char* dest,
                    int* inputSize, int* outputSize, 
                    int maxOutputSize, int batchSize,
                    int headerLen)
{

    int totalInputSize = 0;
    for (int i = 0; i < batchSize; i++) {
        totalInputSize += MAXALIGN(headerLen + inputSize[i]);
    }
    totalInputSize = totalInputSize - (MAXALIGN(headerLen + inputSize[batchSize-1]) - headerLen - inputSize[batchSize-1]);

    dptc_compressor_t* dptcCompressor = dptc_initCompressor(NULL, source);
    if (!dptcCompressor) return 0;

    int res = dptc_compressInner(dptcCompressor, source, dest, inputSize, outputSize, totalInputSize, maxOutputSize, batchSize, 0, headerLen);

    free(dptcCompressor);
    return res;
}
