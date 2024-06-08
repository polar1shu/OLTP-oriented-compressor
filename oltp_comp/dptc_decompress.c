#include "dptc_compress.h"
#include "dptc_decompress.h"
#include "dptc.h"
#include <stdio.h>
#include <stdint.h>
#include "dptc_decode.h"

int dptc_decompress(const char* source, char* const dest, int inputSize, int outputSize)
{
    const BYTE* ip = (const BYTE*) source, *istart = (const BYTE*) source;
    BYTE* op = (BYTE*) dest;
    dptc_decompressor_t depr;
    int res;

    depr.dataPtr = istart;
    depr.dataEnd = istart + inputSize;

    res = dptc_decode(&depr, op, outputSize);
    
    op += res;
    return (int)(op-(BYTE*)dest);
}

