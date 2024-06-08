#if defined (__cplusplus)
extern "C" {
#endif

typedef struct dptc_compressor_s dptc_compressor_t;

int dptc_compress (const char* source, char* dest, int* inputSize, int* outputSize, int maxOutputSize, int batchSize, int headerLen);


#if defined (__cplusplus)
}
#endif