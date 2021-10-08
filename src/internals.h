#include <assert.h>

#include <zkp-volte-patarin-nachef/protocol.h>

#include "random.h"

typedef struct {
  unsigned int* mapping;
  unsigned int domain;
} permutation;

typedef struct {
  const unsigned int* base;
  unsigned int domain;
  unsigned int count;
} permutation_array;

#define STACK_ALLOC_PERMUTATION(name, domain_n)                                \
  permutation name = { .domain = (domain_n) };                                 \
  unsigned int __perm_##name##__mapping[name.domain];                          \
  do {                                                                         \
    name.mapping = __perm_##name##__mapping;                                   \
  } while (0)

#define PERMUTATION_SET(perm, index, value)                                    \
  do {                                                                         \
    (perm)->mapping[((index)) - 1] = value;                                    \
  } while (0)

#define PERMUTATION_GET(perm, index) ((perm)->mapping[((index)) - 1])

#define PERMUTATION_ARRAY_GET(perm_array, perm_index, index)                   \
  ((perm_array)->base[(perm_array)->count * (((index)) - 1) + (perm_index)])

#define PERMUTATION_ARRAY_BASE_SET(perm_array, base, perm_index, index, value) \
  do {                                                                         \
    ((base)[(perm_array)->count * (((index)) - 1) + (perm_index)]) = (value);  \
  } while (0)

static inline void identity_permutation(permutation* perm) {
  for (unsigned int i = 1; i <= perm->domain; i++) {
    PERMUTATION_SET(perm, i, i);
  }
}

static inline void copy_permutation_into(permutation* dst,
                                         const permutation* src) {
  // TODO: ensure that both permutations have the same domain
  for (unsigned int i = 0; i < src->domain; i++) {
    dst->mapping[i] = src->mapping[i];
  }
}

static inline void inverse_of_permutation(permutation* p) {
  STACK_ALLOC_PERMUTATION(t, p->domain);
  for (unsigned int i = 1; i <= t.domain; i++) {
    PERMUTATION_SET(&t, PERMUTATION_GET(p, i), i);
  }
  copy_permutation_into(p, &t);
}

static inline void multiply_permutation(permutation* p, const permutation* f) {
  assert(p->domain != 0 && p->domain == f->domain);
  STACK_ALLOC_PERMUTATION(t, p->domain);
  for (unsigned int i = 1; i <= t.domain; i++) {
    PERMUTATION_SET(&t, i, PERMUTATION_GET(f, PERMUTATION_GET(p, i)));
  }
  copy_permutation_into(p, &t);
}

static inline void multiply_permutation_from_array(permutation* p,
                                                   const permutation_array* f,
                                                   unsigned int perm_index) {
  // TODO: ensure domain is the same
  STACK_ALLOC_PERMUTATION(t, p->domain);
  for (unsigned int i = 1; i <= t.domain; i++) {
    PERMUTATION_SET(
        &t, i, PERMUTATION_ARRAY_GET(f, perm_index, PERMUTATION_GET(p, i)));
  }
  copy_permutation_into(p, &t);
}

static inline void copy_permutation_from_array(permutation* dst,
                                               const permutation_array* src,
                                               unsigned int perm_index) {
  // TODO: ensure domain is the same
  for (unsigned int i = 1; i <= dst->domain; i++) {
    PERMUTATION_SET(dst, i, PERMUTATION_ARRAY_GET(src, perm_index, i));
  }
}

static inline void store_permutation_interleaved(const permutation_array* array,
                                                 unsigned int* base,
                                                 unsigned int perm_index,
                                                 const permutation* src) {
  for (unsigned int i = 1; i <= src->domain; i++) {
    PERMUTATION_ARRAY_BASE_SET(array, base, perm_index, i,
                               PERMUTATION_GET(src, i));
  }
}

static inline void multiply_permutation_from_array_inv(
    permutation* p, const permutation_array* f, unsigned int perm_index) {
  // TODO: ensure domain is the same
  // TODO: it should be possible to make this more efficient (without extracting
  // the permutation from the array first)
  STACK_ALLOC_PERMUTATION(t, p->domain);
  copy_permutation_from_array(&t, f, perm_index);
  inverse_of_permutation(&t);
  multiply_permutation(p, &t);
}

static inline int index_of_permutation_in_array(const permutation* p,
                                                const permutation_array* array,
                                                unsigned int* perm_index) {
  // TODO: ensure domain is the same
  for (unsigned int i = 0; i < array->count; i++) {
    unsigned int j;
    for (j = 1; j <= array->domain; j++) {
      // TODO: LIKELY macro
      if (PERMUTATION_GET(p, j) != PERMUTATION_ARRAY_GET(array, i, j)) {
        break;
      }
    }
    if (j > array->domain) {
      *perm_index = i;
      return 1;
    }
  }
  return 0;
}

typedef struct {
  void (*random_element)(permutation* out, const zkp_params* params);
} permutation_group;

struct zkp_params_s {
  unsigned int domain;
  permutation_array F;
  permutation_array H;
  permutation_group G_;
  unsigned int d;
  const char* display_name;
};

struct zkp_private_key_s {
  const zkp_params* params;
  unsigned int* i;
  zkp_private_key* mut_self;
};

struct zkp_public_key_s {
  const zkp_params* params;
  permutation x0;
  zkp_public_key* mut_self;
};

typedef struct {
  unsigned int tau;
  permutation* sigma;
  unsigned char* k;
} zkp_round_secrets;

struct zkp_answer_s {
  unsigned int q;
  // The following members are not a union because we intend to preallocate the
  // entire struct and all of its members, which isn't possible with a union.
  struct {
    unsigned int tau;
    permutation sigma_0;
    unsigned char* k_star;
    unsigned char* k_0;
    unsigned char* k_d;
  } q_eq_0;
  struct {
    unsigned int f;
    permutation sigma_q;
    unsigned char* k_q_minus_1;
    unsigned char* k_q;
  } q_ne_0;
};

struct zkp_proof_s {
  const zkp_private_key* key;
  struct {
    zkp_round_secrets secrets;
    unsigned char* commitments;
    zkp_answer answer;
  } round;
};

struct zkp_verification_s {
  const zkp_public_key* key;
  unsigned int q;
  unsigned int n_successful_rounds;
};

static inline void random_element_F_H(permutation* out,
                                      const zkp_params* params) {
  identity_permutation(out);
  const unsigned int m = params->d * 2;
  // We want F and H to be equally likely so we can choose a small value for m.
  unsigned int f_factor = params->H.count / params->F.count;
  for (unsigned int i = 0; i < m; i++) {
    unsigned int j =
        rand_less_than(params->H.count + f_factor * params->F.count);
    multiply_permutation_from_array(
        out, j < params->H.count ? &params->H : &params->F,
        j < params->H.count ? j : (j - params->H.count) % params->F.count);
  }
}

static inline void random_element_symmetric_group(permutation* out,
                                                  const zkp_params* params) {
  (void) params;
  identity_permutation(out);
  for (unsigned int i = 2; i <= out->domain; i++) {
    unsigned int j = 1 + rand_less_than(i);
    if (j != i) {
      unsigned int t = PERMUTATION_GET(out, i);
      PERMUTATION_SET(out, i, PERMUTATION_GET(out, j));
      PERMUTATION_SET(out, j, t);
    }
  }
}
