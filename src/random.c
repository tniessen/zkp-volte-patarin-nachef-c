#include "random.h"

#include <assert.h>

#include <openssl/rand.h>

void memset_random(void* ptr, size_t n) {
  int ret = RAND_bytes((unsigned char*) ptr, n);
  assert(ret);
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
