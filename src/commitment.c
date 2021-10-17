#include "commitment.h"

#ifndef __WASM__

#include <assert.h>
#include <openssl/hmac.h>

static inline void hmac_sha256(const unsigned char* key,
                               const unsigned char* data, size_t data_size,
                               unsigned char* out) {
  unsigned char* ret =
      HMAC(EVP_sha256(), key, COMMITMENT_SIZE, data, data_size, out, NULL);
  assert(ret == out);
}

#else

__attribute__((import_module("crypto"), import_name("hmacSHA256"))) extern void
hmac_sha256(const unsigned char* key, const unsigned char* data,
            size_t data_size, unsigned char* out);

#endif

void commit_hmac_sha256(const unsigned char* key, const unsigned char* data,
                        size_t data_size, unsigned char* out) {
  hmac_sha256(key, data, data_size, out);
}
