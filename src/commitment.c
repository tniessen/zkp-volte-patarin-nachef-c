#include "commitment.h"

#include <assert.h>

#include <openssl/hmac.h>

void commit_hmac_sha256(const unsigned char* key, const unsigned char* data, size_t data_size, unsigned char* out) {
  unsigned char* ret = HMAC(EVP_sha256(), key, COMMITMENT_SIZE, data, data_size, out, NULL);
  assert(ret == out);
}
