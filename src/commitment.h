#include <stdlib.h>

#define COMMITMENT_SIZE 32

void commit_hmac_sha256(const unsigned char* key, const unsigned char* data, size_t data_size, unsigned char* out);
