#include "random.h"

#include <limits.h>

#ifndef __WASM__

#include <assert.h>
#include <openssl/rand.h>

static inline void crypto_rand_bytes(unsigned char* ptr, size_t n) {
  int ret = RAND_bytes(ptr, n);
  assert(ret);
}

#else

__attribute__((import_module("crypto"), import_name("randomBytes"))) extern void
crypto_rand_bytes(unsigned char* ptr, size_t n);

#endif

void memset_random(void* ptr, size_t n) {
  crypto_rand_bytes((unsigned char*) ptr, n);
}

static inline int is_unbiased(unsigned int value, unsigned int excl_max) {
  return value <= (UINT_MAX - (UINT_MAX % excl_max) - 1);
}

unsigned int rand_less_than(unsigned int excl_max) {
  unsigned int ret;
  do {
    memset_random(&ret, sizeof(ret));
  } while (!is_unbiased(ret, excl_max));
  return ret % excl_max;
}
