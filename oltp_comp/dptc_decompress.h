#if defined (__cplusplus)
extern "C" {
#endif

typedef struct dptc_decompressor_s dptc_decompressor_t;

int dptc_decompress (const char* source, char* dest, int compressedSize, int maxDecompressedSize);

#if defined (__cplusplus)
}
#endif


