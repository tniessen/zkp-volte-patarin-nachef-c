#include <assert.h>
#include <limits.h>
#include <string.h> // TODO: remove if possible

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define Q_UNANSWERED ((unsigned int) -1)

typedef struct {
  unsigned int* mapping;
  unsigned int domain;
} permutation;

static inline void identity_permutation(permutation* perm) {
  for (unsigned int i = 1; i <= perm->domain; i++) {
    perm->mapping[i - 1] = i;
  }
}

typedef struct {
  const unsigned int* base;
  unsigned int domain;
  unsigned int count;
} permutation_array;

typedef struct {
  void (*random_element)(permutation* out, void* context);
  void* context;
} algebraic_group;

typedef struct {
  unsigned int domain;
  permutation_array F;
  permutation_array H;
  algebraic_group G_;
  unsigned int d;
} zkp_params;

typedef struct {
  const zkp_params* params;
  unsigned int* i;
} zkp_secret_key;

typedef struct {
  const zkp_params* params;
  permutation x0;
} zkp_public_key;

typedef struct {
  unsigned int tau;
  permutation* sigma;
  unsigned char* k;
} zkp_round_secrets;

typedef struct {
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
} zkp_answer;

typedef struct {
  const zkp_secret_key* key;
  struct {
    zkp_round_secrets secrets;
    unsigned char* commitments;
    zkp_answer answer;
  } round;
} zkp_proof;

static int preallocate_answer(zkp_proof* proof) {
  const zkp_params* params = proof->key->params;
  zkp_answer* answer = &proof->round.answer;

  answer->q_eq_0.sigma_0.domain = params->domain;
  answer->q_eq_0.sigma_0.mapping = malloc(params->domain * sizeof(unsigned int));
  if (answer->q_eq_0.sigma_0.mapping == NULL) {
    return 0;
  }

  answer->q_eq_0.k_star = malloc(32);
  if (answer->q_eq_0.k_star == NULL) {
    free(answer->q_eq_0.sigma_0.mapping);
    return 0;
  }

  answer->q_eq_0.k_0 = malloc(32);
  if (answer->q_eq_0.k_0 == NULL) {
    free(answer->q_eq_0.sigma_0.mapping);
    free(answer->q_eq_0.k_star);
    return 0;
  }

  answer->q_eq_0.k_d = malloc(32);
  if (answer->q_eq_0.k_d == NULL) {
    free(answer->q_eq_0.sigma_0.mapping);
    free(answer->q_eq_0.k_star);
    free(answer->q_eq_0.k_0);
    return 0;
  }

  // While we cannot use a union for q_eq_0/q_ne_0, we do not need to allocate
  // memory for the remaining nested members in q_ne_0. Instead, we reuse the
  // previous allocations within q_eq_0.
  answer->q_ne_0.sigma_q.domain = params->domain;
  answer->q_ne_0.sigma_q.mapping = answer->q_eq_0.sigma_0.mapping;

  answer->q_ne_0.k_q_minus_1 = answer->q_eq_0.k_0;
  answer->q_ne_0.k_q = answer->q_eq_0.k_d;

  return 1;
}

static void free_preallocated_answer(zkp_proof* proof) {
  zkp_answer* answer = &proof->round.answer;
  free(answer->q_eq_0.sigma_0.mapping);
  free(answer->q_eq_0.k_star);
  free(answer->q_eq_0.k_0);
  free(answer->q_eq_0.k_d);
}

static int preallocate_sigma(zkp_proof* proof) {
  const zkp_params* params = proof->key->params;
  permutation* sigma = proof->round.secrets.sigma;
  for (unsigned int i = 0; i <= params->d; i++) {
    sigma[i].domain = params->domain;
    sigma[i].mapping = malloc(sizeof(unsigned int) * params->domain);
    if (sigma[i].mapping == NULL) {
      while (--i != 0) {
        free(sigma[i].mapping);
      }
      return 0;
    }
  }
  return 1;
}

static void free_preallocated_sigma(zkp_proof* proof) {
  for (unsigned int i = 0; i <= proof->key->params->d; i++) {
    free(proof->round.secrets.sigma[i].mapping);
  }
}

zkp_proof* zkp_new_proof(const zkp_secret_key* key) {
  if (key == NULL) {
    return NULL;
  }

  zkp_proof* proof = malloc(sizeof(zkp_proof));
  if (proof == NULL) {
    return NULL;
  }

  proof->key = key;

  proof->round.secrets.sigma = malloc(sizeof(permutation) * (1 + key->params->d));
  if (proof->round.secrets.sigma == NULL) {
    free(proof);
    return NULL;
  }

  proof->round.secrets.k = malloc(32 * (2 + key->params->d));
  if (proof->round.secrets.k == NULL) {
    free(proof->round.secrets.sigma);
    free(proof);
    return NULL;
  }

  proof->round.commitments = malloc(32 * (2 + key->params->d));
  if (proof->round.commitments == NULL) {
    free(proof->round.secrets.sigma);
    free(proof->round.secrets.k);
    free(proof);
    return NULL;
  }

  if (!preallocate_answer(proof)) {
    free(proof->round.secrets.sigma);
    free(proof->round.secrets.k);
    free(proof->round.commitments);
    free(proof);
    return NULL;
  }

  if (!preallocate_sigma(proof)) {
    free_preallocated_answer(proof);
    free(proof->round.secrets.sigma);
    free(proof->round.secrets.k);
    free(proof->round.commitments);
    free(proof);
    return NULL;
  }

  return proof;
}

void zkp_free_proof(zkp_proof* proof) {
  free(proof->round.secrets.sigma);
  free(proof->round.secrets.k);
  free(proof->round.commitments);
  free_preallocated_answer(proof);
  free_preallocated_sigma(proof);
  free(proof);
}

#define STACK_ALLOC_PERMUTATION(name, domain_n) permutation name = { .domain = (domain_n) }; unsigned int __perm_##name##__mapping[name.domain]; do { name.mapping = __perm_##name##__mapping; } while (0)

#define PERMUTATION_SET(perm, index, value) do { (perm)->mapping[(index) - 1] = value; } while (0)
#define PERMUTATION_GET(perm, index) ((perm)->mapping[(index) - 1])

#define PERMUTATION_ARRAY_GET(perm_array, perm_index, index) ((perm_array)->base[(perm_array)->count * ((index) - 1) + perm_index])

#define PERMUTATION_ARRAY_BASE_SET(perm_array, base, perm_index, index, value) do { ((base)[(perm_array)->count * ((index) - 1) + perm_index]) = value; } while (0)

static inline void copy_permutation_into(permutation* dst, const permutation* src) {
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
  // TODO: ensure domain is the same
  STACK_ALLOC_PERMUTATION(t, p->domain);
  for (unsigned int i = 1; i <= t.domain; i++) {
    PERMUTATION_SET(&t, i, PERMUTATION_GET(f, PERMUTATION_GET(p, i)));
  }
  copy_permutation_into(p, &t);
}

static inline void multiply_permutation_from_array(permutation* p, const permutation_array* f, unsigned int perm_index) {
  // TODO: ensure domain is the same
  STACK_ALLOC_PERMUTATION(t, p->domain);
  for (unsigned int i = 1; i <= t.domain; i++) {
    PERMUTATION_SET(&t, i, PERMUTATION_ARRAY_GET(f, perm_index, PERMUTATION_GET(p, i)));
  }
  copy_permutation_into(p, &t);
}

static inline void copy_permutation_from_array(permutation* dst, const permutation_array* src, unsigned int perm_index) {
  // TODO: ensure domain is the same
  for (unsigned int i = 1; i <= dst->domain; i++) {
    PERMUTATION_SET(dst, i, PERMUTATION_ARRAY_GET(src, perm_index, i));
  }
}

static inline void store_permutation_interleaved(const permutation_array* array, unsigned int* base, unsigned int perm_index, const permutation* src) {
  for (unsigned int i = 1; i <= src->domain; i++) {
    PERMUTATION_ARRAY_BASE_SET(array, base, perm_index, i, PERMUTATION_GET(src, i));
  }
}

static inline void multiply_permutation_from_array_inv(permutation* p, const permutation_array* f, unsigned int perm_index) {
  // TODO: ensure domain is the same
  // TODO: it should be possible to make this more efficient (without extracting the permutation from the array first)
  STACK_ALLOC_PERMUTATION(t, p->domain);
  copy_permutation_from_array(&t, f, perm_index);
  inverse_of_permutation(&t);
  multiply_permutation(p, &t);
}

static inline int index_of_permutation_in_array(const permutation* p, const permutation_array* array, unsigned int* perm_index) {
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

static inline int is_unbiased(unsigned int value, unsigned int excl_max) {
  // TODO: Triple-check this
  return value <= (UINT_MAX - (UINT_MAX % excl_max) - 1);
}

static inline unsigned int random_uint(unsigned int excl_max) {
  unsigned int ret;
  do {
    RAND_bytes((unsigned char*) &ret, sizeof(unsigned int)); // TODO: return value
  } while (!is_unbiased(ret, excl_max));
  return ret % excl_max;
}

zkp_secret_key* zkp_generate_secret_key(const zkp_params* params) {
  zkp_secret_key* key = malloc(sizeof(zkp_secret_key));
  if (key == NULL) {
    return NULL;
  }

  key->params = params;
  key->i = OPENSSL_secure_malloc(params->d * sizeof(unsigned int));
  if (key->i == NULL) {
    free(key);
    return NULL;
  }

  for (unsigned int j = 0; j < params->d; j++) {
    key->i[j] = random_uint(params->F.count);
  }

  return key;
}

void zkp_free_secret_key(zkp_secret_key* key) {
  OPENSSL_secure_clear_free(key->i, key->params->d * sizeof(unsigned int));
  free(key);
}

zkp_public_key* zkp_compute_public_key(const zkp_secret_key* priv) {
  zkp_public_key* pub = malloc(sizeof(zkp_public_key));
  if (pub == NULL) {
    return NULL;
  }

  const zkp_params* params = pub->params = priv->params;

  pub->x0.domain = params->domain;
  pub->x0.mapping = malloc(params->domain * sizeof(unsigned int));
  if (pub->x0.mapping == NULL) {
    free(pub);
    return NULL;
  }

  identity_permutation(&pub->x0);
  for (unsigned int j = 0; j < params->d; j++) {
    multiply_permutation_from_array(&pub->x0, &params->F, priv->i[j]);
  }
  inverse_of_permutation(&pub->x0);

  return pub;
}

void zkp_free_public_key(zkp_public_key* key) {
  free(key->x0.mapping);
  free(key);
}

static void commit(const unsigned char* key, const unsigned char* data, size_t data_size, unsigned char* out) {
  /*printf("commit(");
  for (unsigned int i = 0; i < 32; i++) {
    printf("%02x", key[i]);
  }
  printf(", ");
  for (unsigned int i = 0; i < data_size; i++) {
    printf("%02x", data[i]);
  }
  printf(") = ");*/
  unsigned char* ret = HMAC(EVP_sha256(), key, 32, (unsigned char*) data, data_size, out, NULL); // TODO: return value
  assert(ret != NULL);
  /*for (unsigned int i = 0; i < 32; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");*/
}

void zkp_begin_round(zkp_proof* proof) {
  const zkp_params* params = proof->key->params;
  zkp_round_secrets* secrets = &proof->round.secrets;

  secrets->tau = random_uint(params->H.count);
  params->G_.random_element(&secrets->sigma[0], params->G_.context);

  for (unsigned int j = 1; j <= params->d; j++) {
    // TODO: simplify these operations
    identity_permutation(&secrets->sigma[j]);
    multiply_permutation_from_array_inv(&secrets->sigma[j], &params->H, secrets->tau);
    multiply_permutation_from_array(&secrets->sigma[j], &params->F, proof->key->i[j - 1]);
    multiply_permutation_from_array(&secrets->sigma[j], &params->H, secrets->tau);
    inverse_of_permutation(&secrets->sigma[j]);
    multiply_permutation(&secrets->sigma[j], &secrets->sigma[j - 1]);
  }

  RAND_bytes(secrets->k, 32 * (params->d + 2)); // TODO: check return code

  // TODO: do not encode tau as a string?
  char buf[16];
  sprintf(buf, "%u", secrets->tau);
  commit(secrets->k, (unsigned char*) buf, strlen(buf), proof->round.commitments);

  // TODO: do not MAC the unsigned ints, use bytes (but what about 5x5x5 that has a domain > 255?)
  for (unsigned int i = 0; i <= params->d; i++) {
    commit(secrets->k + (i + 1) * 32, (unsigned char*) secrets->sigma[i].mapping, secrets->sigma[i].domain * sizeof(unsigned int), proof->round.commitments + (i + 1) * 32);
  }

  proof->round.answer.q = Q_UNANSWERED;
}

unsigned int zkp_choose_question(const zkp_params* params) {
  return random_uint(params->d + 1);
}

zkp_answer* zkp_get_answer(zkp_proof* proof, unsigned int q) {
  if (proof->round.answer.q != Q_UNANSWERED) {
    return NULL;
  }

  if (q == 0) {
    proof->round.answer.q_eq_0.tau = proof->round.secrets.tau;
    copy_permutation_into(&proof->round.answer.q_eq_0.sigma_0, &proof->round.secrets.sigma[0]);
    memcpy(proof->round.answer.q_eq_0.k_star, proof->round.secrets.k, 32);
    memcpy(proof->round.answer.q_eq_0.k_0, proof->round.secrets.k + 32, 32);
    memcpy(proof->round.answer.q_eq_0.k_d, proof->round.secrets.k + 32 * (proof->key->params->d + 1), 32);
  } else if (q <= proof->key->params->d) {
    STACK_ALLOC_PERMUTATION(f_i_q_tau, proof->key->params->domain);
    identity_permutation(&f_i_q_tau);
    multiply_permutation_from_array_inv(&f_i_q_tau, &proof->key->params->H, proof->round.secrets.tau);
    multiply_permutation_from_array(&f_i_q_tau, &proof->key->params->F, proof->key->i[q - 1]);
    multiply_permutation_from_array(&f_i_q_tau, &proof->key->params->H, proof->round.secrets.tau);
    int ok = index_of_permutation_in_array(&f_i_q_tau, &proof->key->params->F, &proof->round.answer.q_ne_0.f);
    assert(ok);
    copy_permutation_into(&proof->round.answer.q_ne_0.sigma_q, &proof->round.secrets.sigma[q]);
    memcpy(proof->round.answer.q_ne_0.k_q_minus_1, proof->round.secrets.k + 32 * q, 32);
    memcpy(proof->round.answer.q_ne_0.k_q, proof->round.secrets.k + 32 * (q + 1), 32);
  } else {
    return NULL;
  }

  proof->round.answer.q = q;

  return &proof->round.answer;
}

int zkp_check_answer(const zkp_public_key* key, const unsigned char* commitments, const zkp_answer* answer) {
  if (answer->q == 0) {
    if (answer->q_eq_0.tau >= key->params->H.count) {
      return 0;
    }

    STACK_ALLOC_PERMUTATION(sigma_d, key->params->domain);
    identity_permutation(&sigma_d);
    multiply_permutation_from_array_inv(&sigma_d, &key->params->H, answer->q_eq_0.tau);
    multiply_permutation(&sigma_d, &key->x0);
    multiply_permutation_from_array(&sigma_d, &key->params->H, answer->q_eq_0.tau);
    multiply_permutation(&sigma_d, &answer->q_eq_0.sigma_0);

    unsigned char md[32];
    // TODO: do not encode tau as a string?
    char buf[16];
    sprintf(buf, "%u", answer->q_eq_0.tau);
    commit(answer->q_eq_0.k_star, (const unsigned char*) buf, strlen(buf), md);
    if (memcmp(md, commitments, 32) != 0) {
      return 0;
    }

    commit(answer->q_eq_0.k_0, (unsigned char*) answer->q_eq_0.sigma_0.mapping, answer->q_eq_0.sigma_0.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + 32, 32) != 0) {
      return 0;
    }

    commit(answer->q_eq_0.k_d, (unsigned char*) sigma_d.mapping, sigma_d.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + 32 * (1 + key->params->d), 32) != 0) {
      return 0;
    }
  } else if (answer->q <= key->params->d) {
    if (answer->q_ne_0.f >= key->params->F.count) {
      return 0;
    }

    STACK_ALLOC_PERMUTATION(sigma_q_minus_1, key->params->domain);
    copy_permutation_from_array(&sigma_q_minus_1, &key->params->F, answer->q_ne_0.f);
    multiply_permutation(&sigma_q_minus_1, &answer->q_ne_0.sigma_q);

    unsigned char md[32];

    commit(answer->q_ne_0.k_q, (unsigned char*) answer->q_ne_0.sigma_q.mapping, answer->q_ne_0.sigma_q.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + 32 * (1 + answer->q), 32) != 0) {
      return 0;
    }

    commit(answer->q_ne_0.k_q_minus_1, (unsigned char*) sigma_q_minus_1.mapping, sigma_q_minus_1.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + 32 * answer->q, 32) != 0) {
      return 0;
    }
  } else {
    return 0;
  }

  return 1;
}

#define PARAMS_3X3X3_F_INTERLEAVED \
   3, 17,  1,  1, 14,  1,  \
   5,  2,  2,  2, 12,  2,  \
   8,  3,  3, 38,  9,  3,  \
   2, 20,  4,  4,  4,  4,  \
   7,  5,  5, 36,  5,  5,  \
   1, 22, 25,  6,  6,  6,  \
   4,  7, 28,  7,  7,  7,  \
   6,  8, 30, 33,  8,  8,  \
  33, 11,  9,  9, 46,  9,  \
  34, 13, 10, 10, 10, 10,  \
  35, 16,  8, 11, 11, 11,  \
  12, 10, 12, 12, 47, 12,  \
  13, 15,  7, 13, 13, 13,  \
  14,  9, 14, 14, 48, 22,  \
  15, 12, 15, 15, 15, 23,  \
  16, 14,  6, 16, 16, 24,  \
   9, 41, 19, 17, 17, 17,  \
  10, 18, 21, 18, 18, 18,  \
  11, 19, 24,  3, 19, 19,  \
  20, 44, 18, 20, 20, 20,  \
  21, 21, 23,  5, 21, 21,  \
  22, 46, 17, 22, 22, 30,  \
  23, 23, 20, 23, 23, 31,  \
  24, 24, 22,  8, 24, 32,  \
  17, 25, 43, 27, 25, 25,  \
  18, 26, 26, 29, 26, 26,  \
  19, 27, 27, 32,  1, 27,  \
  28, 28, 42, 26, 28, 28,  \
  29, 29, 29, 31,  2, 29,  \
  30, 30, 41, 25, 30, 38,  \
  31, 31, 31, 28, 31, 39,  \
  32, 32, 32, 30,  3, 40,  \
  25, 33, 33, 48, 35, 33,  \
  26, 34, 34, 34, 37, 34,  \
  27,  6, 35, 35, 40, 35,  \
  36, 36, 36, 45, 34, 36,  \
  37,  4, 37, 37, 39, 37,  \
  38, 38, 38, 43, 33, 14,  \
  39, 39, 39, 39, 36, 15,  \
  40,  1, 40, 40, 38, 16,  \
  41, 40, 11, 41, 41, 43,  \
  42, 42, 13, 42, 42, 45,  \
  43, 43, 16, 19, 43, 48,  \
  44, 37, 44, 44, 44, 42,  \
  45, 45, 45, 21, 45, 47,  \
  46, 35, 46, 46, 32, 41,  \
  47, 47, 47, 47, 29, 44,  \
  48, 48, 48, 24, 27, 46   \

#define PARAMS_3X3X3_H_INTERLEAVED \
   1,  8, 48, 41, 22, 19, 35, 38, 32, 25, 16,  9,  6,  3, 46, 43, 30, 27, 11, 14, 40, 33, 24, 17,  \
   2,  7, 47, 42, 20, 21, 37, 36, 31, 26, 15, 10,  4,  5, 44, 45, 28, 29, 13, 12, 39, 34, 23, 18,  \
   3,  6, 46, 43, 17, 24, 40, 33, 30, 27, 14, 11,  1,  8, 41, 48, 25, 32, 16,  9, 38, 35, 22, 19,  \
   4,  5, 45, 44, 23, 18, 34, 39, 29, 28, 13, 12,  7,  2, 47, 42, 31, 26, 10, 15, 37, 36, 21, 20,  \
   5,  4, 44, 45, 18, 23, 39, 34, 28, 29, 12, 13,  2,  7, 42, 47, 26, 31, 15, 10, 36, 37, 20, 21,  \
   6,  3, 43, 46, 24, 17, 33, 40, 27, 30, 11, 14,  8,  1, 48, 41, 32, 25,  9, 16, 35, 38, 19, 22,  \
   7,  2, 42, 47, 21, 20, 36, 37, 26, 31, 10, 15,  5,  4, 45, 44, 29, 28, 12, 13, 34, 39, 18, 23,  \
   8,  1, 41, 48, 19, 22, 38, 35, 25, 32,  9, 16,  3,  6, 43, 46, 27, 30, 14, 11, 33, 40, 17, 24,  \
   9, 25, 32, 16, 41,  8,  1, 48, 38, 19, 22, 35, 17, 33, 40, 24, 43,  3,  6, 46, 14, 27, 30, 11,  \
  10, 26, 31, 15, 42,  7,  2, 47, 36, 21, 20, 37, 18, 34, 39, 23, 45,  5,  4, 44, 12, 29, 28, 13,  \
  11, 27, 30, 14, 43,  6,  3, 46, 33, 24, 17, 40, 19, 35, 38, 22, 48,  8,  1, 41,  9, 32, 25, 16,  \
  12, 28, 29, 13, 44,  5,  4, 45, 39, 18, 23, 34, 20, 36, 37, 21, 42,  2,  7, 47, 15, 26, 31, 10,  \
  13, 29, 28, 12, 45,  4,  5, 44, 34, 23, 18, 39, 21, 37, 36, 20, 47,  7,  2, 42, 10, 31, 26, 15,  \
  14, 30, 27, 11, 46,  3,  6, 43, 40, 17, 24, 33, 22, 38, 35, 19, 41,  1,  8, 48, 16, 25, 32,  9,  \
  15, 31, 26, 10, 47,  2,  7, 42, 37, 20, 21, 36, 23, 39, 34, 18, 44,  4,  5, 45, 13, 28, 29, 12,  \
  16, 32, 25,  9, 48,  1,  8, 41, 35, 22, 19, 38, 24, 40, 33, 17, 46,  6,  3, 43, 11, 30, 27, 14,  \
  17, 33, 24, 40, 30, 11, 27, 14,  3, 43,  6, 46, 25,  9, 32, 16, 38, 19, 35, 22,  1, 48,  8, 41,  \
  18, 34, 23, 39, 28, 13, 29, 12,  5, 45,  4, 44, 26, 10, 31, 15, 36, 21, 37, 20,  2, 47,  7, 42,  \
  19, 35, 22, 38, 25, 16, 32,  9,  8, 48,  1, 41, 27, 11, 30, 14, 33, 24, 40, 17,  3, 46,  6, 43,  \
  20, 36, 21, 37, 31, 10, 26, 15,  2, 42,  7, 47, 28, 12, 29, 13, 39, 18, 34, 23,  4, 45,  5, 44,  \
  21, 37, 20, 36, 26, 15, 31, 10,  7, 47,  2, 42, 29, 13, 28, 12, 34, 23, 39, 18,  5, 44,  4, 45,  \
  22, 38, 19, 35, 32,  9, 25, 16,  1, 41,  8, 48, 30, 14, 27, 11, 40, 17, 33, 24,  6, 43,  3, 46,  \
  23, 39, 18, 34, 29, 12, 28, 13,  4, 44,  5, 45, 31, 15, 26, 10, 37, 20, 36, 21,  7, 42,  2, 47,  \
  24, 40, 17, 33, 27, 14, 30, 11,  6, 46,  3, 43, 32, 16, 25,  9, 35, 22, 38, 19,  8, 41,  1, 48,  \
  25,  9, 16, 32,  8, 41, 48,  1, 19, 38, 35, 22, 33, 17, 24, 40,  3, 43, 46,  6, 27, 14, 11, 30,  \
  26, 10, 15, 31,  7, 42, 47,  2, 21, 36, 37, 20, 34, 18, 23, 39,  5, 45, 44,  4, 29, 12, 13, 28,  \
  27, 11, 14, 30,  6, 43, 46,  3, 24, 33, 40, 17, 35, 19, 22, 38,  8, 48, 41,  1, 32,  9, 16, 25,  \
  28, 12, 13, 29,  5, 44, 45,  4, 18, 39, 34, 23, 36, 20, 21, 37,  2, 42, 47,  7, 26, 15, 10, 31,  \
  29, 13, 12, 28,  4, 45, 44,  5, 23, 34, 39, 18, 37, 21, 20, 36,  7, 47, 42,  2, 31, 10, 15, 26,  \
  30, 14, 11, 27,  3, 46, 43,  6, 17, 40, 33, 24, 38, 22, 19, 35,  1, 41, 48,  8, 25, 16,  9, 32,  \
  31, 15, 10, 26,  2, 47, 42,  7, 20, 37, 36, 21, 39, 23, 18, 34,  4, 44, 45,  5, 28, 13, 12, 29,  \
  32, 16,  9, 25,  1, 48, 41,  8, 22, 35, 38, 19, 40, 24, 17, 33,  6, 46, 43,  3, 30, 11, 14, 27,  \
  33, 17, 40, 24, 11, 30, 14, 27, 43,  3, 46,  6,  9, 25, 16, 32, 19, 38, 22, 35, 48,  1, 41,  8,  \
  34, 18, 39, 23, 13, 28, 12, 29, 45,  5, 44,  4, 10, 26, 15, 31, 21, 36, 20, 37, 47,  2, 42,  7,  \
  35, 19, 38, 22, 16, 25,  9, 32, 48,  8, 41,  1, 11, 27, 14, 30, 24, 33, 17, 40, 46,  3, 43,  6,  \
  36, 20, 37, 21, 10, 31, 15, 26, 42,  2, 47,  7, 12, 28, 13, 29, 18, 39, 23, 34, 45,  4, 44,  5,  \
  37, 21, 36, 20, 15, 26, 10, 31, 47,  7, 42,  2, 13, 29, 12, 28, 23, 34, 18, 39, 44,  5, 45,  4,  \
  38, 22, 35, 19,  9, 32, 16, 25, 41,  1, 48,  8, 14, 30, 11, 27, 17, 40, 24, 33, 43,  6, 46,  3,  \
  39, 23, 34, 18, 12, 29, 13, 28, 44,  4, 45,  5, 15, 31, 10, 26, 20, 37, 21, 36, 42,  7, 47,  2,  \
  40, 24, 33, 17, 14, 27, 11, 30, 46,  6, 43,  3, 16, 32,  9, 25, 22, 35, 19, 38, 41,  8, 48,  1,  \
  41, 48,  8,  1, 38, 35, 19, 22,  9, 16, 25, 32, 43, 46,  3,  6, 14, 11, 27, 30, 17, 24, 33, 40,  \
  42, 47,  7,  2, 36, 37, 21, 20, 10, 15, 26, 31, 45, 44,  5,  4, 12, 13, 29, 28, 18, 23, 34, 39,  \
  43, 46,  6,  3, 33, 40, 24, 17, 11, 14, 27, 30, 48, 41,  8,  1,  9, 16, 32, 25, 19, 22, 35, 38,  \
  44, 45,  5,  4, 39, 34, 18, 23, 12, 13, 28, 29, 42, 47,  2,  7, 15, 10, 26, 31, 20, 21, 36, 37,  \
  45, 44,  4,  5, 34, 39, 23, 18, 13, 12, 29, 28, 47, 42,  7,  2, 10, 15, 31, 26, 21, 20, 37, 36,  \
  46, 43,  3,  6, 40, 33, 17, 24, 14, 11, 30, 27, 41, 48,  1,  8, 16,  9, 25, 32, 22, 19, 38, 35,  \
  47, 42,  2,  7, 37, 36, 20, 21, 15, 10, 31, 26, 44, 45,  4,  5, 13, 12, 28, 29, 23, 18, 39, 34,  \
  48, 41,  1,  8, 35, 38, 22, 19, 16,  9, 32, 25, 46, 43,  6,  3, 11, 14, 30, 27, 24, 17, 40, 33   \

static const unsigned int params_3x3x3_f[] = { PARAMS_3X3X3_F_INTERLEAVED };
static const unsigned int params_3x3x3_h[] = { PARAMS_3X3X3_H_INTERLEAVED };

#define PARAMS_5X5X5_F_INTERLEAVED \
    1,  44,  49,   1,   5,   1,   1,   1,   1,   1,   1,   1,  \
    2,  39,   2,   2,  10,   2,   2,   2,  50,   2,   2,   2,  \
    3,  35,   3,   3,  14,   3,   3,   3,   3,   3,   3,   3,  \
    4,  30,   4,   4,  19,   4,   4,   4,   4, 117,   4,   4,  \
    5,  25,   5, 116,  24,   5,   5,   5,   5,   5,   5,   5,  \
    6,   6,  54,   6,   4,   6,   6,  45,   6,   6,   6,   6,  \
    7,   7,   7,   7,   9,   7,   7,  40,  55,   7,   7,   7,  \
    8,   8,   8,   8,  13,   8,   8,  36,   8,   8,   8,   8,  \
    9,   9,   9,   9,  18,   9,   9,  31,   9, 112,   9,   9,  \
   10,  10,  10, 111,  23,  10,  10,  26,  10,  10,  10,  10,  \
   11,  11,  59,  11,   3,  11,  11,  11,  11,  11,  11,  11,  \
   12,  12,  12,  12,   8,  12,  12,  12,  60,  12,  12,  12,  \
   13,  13,  13,  13,  17,  13,  13,  13,  13, 108,  13,  13,  \
   14,  14,  14, 107,  22,  14,  14,  14,  14,  14,  14,  14,  \
   15,  15,  63,  15,   2,  15,  74,  15,  15,  15,  15,  15,  \
   16,  16,  16,  16,   7,  16,  79,  16,  64,  16,  16,  16,  \
   17,  17,  17,  17,  12,  17,  84,  17,  17,  17,  17,  17,  \
   18,  18,  18,  18,  16,  18,  88,  18,  18, 103,  18,  18,  \
   19,  19,  19, 102,  21,  19,  93,  19,  19,  19,  19,  19,  \
   73,  20,  68,  20,   1,  20,  20,  20,  20,  20,  20,  20,  \
   78,  21,  21,  21,   6,  21,  21,  21,  69,  21,  21,  21,  \
   83,  22,  22,  22,  11,  22,  22,  22,  22,  22,  22,  22,  \
   87,  23,  23,  23,  15,  23,  23,  23,  23,  98,  23,  23,  \
   92,  24,  24,  97,  20,  24,  24,  24,  24,  24,  24,  24,  \
   25, 140,  29,  25,  97,  25,  25,  25,  25,  25,  25,  25,  \
   26,  26,  34,  26,  98,  26,  26, 135,  26,  26,  26,  26,  \
   27,  27,  38,  27,  99,  27,  27,  27,  27,  27,  27,  27,  \
   28,  28,  43,  28, 100,  28,  19,  28,  28,  28,  28,  28,  \
   24,  29,  48,  29, 101,  29,  29,  29,  29,  29,  29,  29,  \
   30, 141,  28,  30,  30,  30,  30,  30,  30,  30, 102,  30,  \
   31,  31,  33,  31,  31,  31,  31, 136,  31,  31, 103,  31,  \
   32,  32,  37,  32,  32,  32,  32,  32,  32,  32, 104,  32,  \
   33,  33,  42,  33,  33,  33,  18,  33,  33,  33, 105,  33,  \
   23,  34,  47,  34,  34,  34,  34,  34,  34,  34, 106,  34,  \
   35, 142,  27,  35,  35,  35,  35,  35,  35,  35,  35,  35,  \
   36,  36,  32,  36,  36,  36,  36, 137,  36,  36,  36,  36,  \
   37,  37,  41,  37,  37,  37,  17,  37,  37,  37,  37,  37,  \
   22,  38,  46,  38,  38,  38,  38,  38,  38,  38,  38,  38,  \
   39, 143,  26,  39,  39,  39,  39,  39,  39,  39,  39,  63,  \
   40,  40,  31,  40,  40,  40,  40, 138,  40,  40,  40,  64,  \
   41,  41,  36,  41,  41,  41,  41,  41,  41,  41,  41,  65,  \
   42,  42,  40,  42,  42,  42,  16,  42,  42,  42,  42,  66,  \
   21,  43,  45,  43,  43,  43,  43,  43,  43,  43,  43,  67,  \
   44, 144,  25,  44,  44,  68,  44,  44,  44,  44,  44,  44,  \
   45,  45,  30,  45,  45,  69,  45, 139,  45,  45,  45,  45,  \
   46,  46,  35,  46,  46,  70,  46,  46,  46,  46,  46,  46,  \
   47,  47,  39,  47,  47,  71,  15,  47,  47,  47,  47,  47,  \
   20,  48,  44,  48,  48,  72,  48,  48,  48,  48,  48,  48,  \
   53,  49, 121,  49,  25,  49,  49,  49,  49,  49,  49,  49,  \
   58,  50,  50,  50,  26,  50,  50,  50, 122,  50,  50,  50,  \
   62,  51,  51,  51,  27,  51,  51,  51,  51,  51,  51,  51,  \
   67,  52,  52,  52,  28,  52,  52,  52,  52,   4,  52,  52,  \
   72,  53,  53,   5,  29,  53,  53,  53,  53,  53,  53,  53,  \
   52,  54, 126,  54,  54,  54,  54,  54,  54,  54,  30,  54,  \
   57,  55,  55,  55,  55,  55,  55,  55, 127,  55,  31,  55,  \
   61,  56,  56,  56,  56,  56,  56,  56,  56,  56,  32,  56,  \
   66,  57,  57,  57,  57,  57,  57,  57,  57,   9,  33,  57,  \
   71,  58,  58,  10,  58,  58,  58,  58,  58,  58,  34,  58,  \
   51,  59, 131,  59,  59,  59,  59,  59,  59,  59,  59,  59,  \
   56,  60,  60,  60,  60,  60,  60,  60, 132,  60,  60,  60,  \
   65,  61,  61,  61,  61,  61,  61,  61,  61,  13,  61,  61,  \
   70,  62,  62,  14,  62,  62,  62,  62,  62,  62,  62,  62,  \
   50,  63, 135,  63,  63,  63,  63,  63,  63,  63,  63,  87,  \
   55,  64,  64,  64,  64,  64,  64,  64, 136,  64,  64,  88,  \
   60,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  89,  \
   64,  66,  66,  66,  66,  66,  66,  66,  66,  18,  66,  90,  \
   69,  67,  67,  19,  67,  67,  67,  67,  67,  67,  67,  91,  \
   49,  68, 140,  68,  68,  92,  68,  68,  68,  68,  68,  68,  \
   54,  69,  69,  69,  69,  93,  69,  69, 141,  69,  69,  69,  \
   59,  70,  70,  70,  70,  94,  70,  70,  70,  70,  70,  70,  \
   63,  71,  71,  71,  71,  95,  71,  71,  71,  23,  71,  71,  \
   68,  72,  72,  24,  72,  96,  72,  72,  72,  72,  72,  72,  \
  125,  73,  73,  77,  49,  73,  73,  73,  73,  73,  73,  73,  \
   74,  74,  74,  82,  50,  74, 130,  74,  74,  74,  74,  74,  \
   75,  75,  75,  86,  51,  75,  75,  75,  75,  75,  75,  75,  \
   76,  76,  76,  91,  52,  76,  76,   6,  76,  76,  76,  76,  \
   77,   1,  77,  96,  53,  77,  77,  77,  77,  77,  77,  77,  \
  124,  78,  78,  76,  78,  78,  78,  78,  78,  78,  54,  78,  \
   79,  79,  79,  81,  79,  79, 129,  79,  79,  79,  55,  79,  \
   80,  80,  80,  85,  80,  80,  80,  80,  80,  80,  56,  80,  \
   81,  81,  81,  90,  81,  81,  81,   7,  81,  81,  57,  81,  \
   82,   2,  82,  95,  82,  82,  82,  82,  82,  82,  58,  82,  \
  123,  83,  83,  75,  83,  83,  83,  83,  83,  83,  83,  83,  \
   84,  84,  84,  80,  84,  84, 128,  84,  84,  84,  84,  84,  \
   85,  85,  85,  89,  85,  85,  85,   8,  85,  85,  85,  85,  \
   86,   3,  86,  94,  86,  86,  86,  86,  86,  86,  86,  86,  \
  122,  87,  87,  74,  87,  87,  87,  87,  87,  87,  87, 111,  \
   88,  88,  88,  79,  88,  88, 127,  88,  88,  88,  88, 112,  \
   89,  89,  89,  84,  89,  89,  89,  89,  89,  89,  89, 113,  \
   90,  90,  90,  88,  90,  90,  90,   9,  90,  90,  90, 114,  \
   91,   4,  91,  93,  91,  91,  91,  91,  91,  91,  91, 115,  \
  121,  92,  92,  73,  92, 116,  92,  92,  92,  92,  92,  92,  \
   93,  93,  93,  78,  93, 117, 126,  93,  93,  93,  93,  93,  \
   94,  94,  94,  83,  94, 118,  94,  94,  94,  94,  94,  94,  \
   95,  95,  95,  87,  95, 119,  95,  10,  95,  95,  95,  95,  \
   96,   5,  96,  92,  96, 120,  96,  96,  96,  96,  96,  96,  \
   97, 101,  97, 144,  73,  97,  97,  97,  97,  97,  97,  97,  \
   98, 106,  98,  98,  74,  98,  98,  98,  98, 143,  98,  98,  \
   99, 110,  99,  99,  75,  99,  99,  99,  99,  99,  99,  99,  \
  100, 115, 100, 100,  76, 100, 100, 100,  21, 100, 100, 100,  \
  101, 120,  20, 101,  77, 101, 101, 101, 101, 101, 101, 101,  \
  102, 100, 102, 139, 102, 102, 102, 102, 102, 102,  78, 102,  \
  103, 105, 103, 103, 103, 103, 103, 103, 103, 138,  79, 103,  \
  104, 109, 104, 104, 104, 104, 104, 104, 104, 104,  80, 104,  \
  105, 114, 105, 105, 105, 105, 105, 105,  16, 105,  81, 105,  \
  106, 119,  15, 106, 106, 106, 106, 106, 106, 106,  82, 106,  \
  107,  99, 107, 134, 107, 107, 107, 107, 107, 107, 107, 107,  \
  108, 104, 108, 108, 108, 108, 108, 108, 108, 133, 108, 108,  \
  109, 113, 109, 109, 109, 109, 109, 109,  12, 109, 109, 109,  \
  110, 118,  11, 110, 110, 110, 110, 110, 110, 110, 110, 110,  \
  111,  98, 111, 130, 111, 111, 111, 111, 111, 111, 111,  39,  \
  112, 103, 112, 112, 112, 112, 112, 112, 112, 129, 112,  40,  \
  113, 108, 113, 113, 113, 113, 113, 113, 113, 113, 113,  41,  \
  114, 112, 114, 114, 114, 114, 114, 114,   7, 114, 114,  42,  \
  115, 117,   6, 115, 115, 115, 115, 115, 115, 115, 115,  43,  \
  116,  97, 116, 125, 116,  44, 116, 116, 116, 116, 116, 116,  \
  117, 102, 117, 117, 117,  45, 117, 117, 117, 124, 117, 117,  \
  118, 107, 118, 118, 118,  46, 118, 118, 118, 118, 118, 118,  \
  119, 111, 119, 119, 119,  47, 119, 119,   2, 119, 119, 119,  \
  120, 116,   1, 120, 120,  48, 120, 120, 120, 120, 120, 120,  \
   29, 121, 120, 121, 121, 125, 121, 121, 121, 121, 121, 121,  \
   34, 122, 122, 122, 122, 130, 122, 122, 119, 122, 122, 122,  \
   38, 123, 123, 123, 123, 134, 123, 123, 123, 123, 123, 123,  \
   43, 124, 124, 124, 124, 139, 124, 124, 124,  52, 124, 124,  \
   48, 125, 125,  53, 125, 144, 125, 125, 125, 125, 125, 125,  \
  126, 126, 115, 126, 126, 124,  28, 126, 126, 126, 126, 126,  \
  127, 127, 127, 127, 127, 129,  33, 127, 114, 127, 127, 127,  \
  128, 128, 128, 128, 128, 133,  37, 128, 128, 128, 128, 128,  \
  129, 129, 129, 129, 129, 138,  42, 129, 129,  57, 129, 129,  \
  130, 130, 130,  58, 130, 143,  47, 130, 130, 130, 130, 130,  \
  131, 131, 110, 131, 131, 123, 131, 131, 131, 131, 131, 131,  \
  132, 132, 132, 132, 132, 128, 132, 132, 109, 132, 132, 132,  \
  133, 133, 133, 133, 133, 137, 133, 133, 133,  61, 133, 133,  \
  134, 134, 134,  62, 134, 142, 134, 134, 134, 134, 134, 134,  \
  135, 135, 106, 135, 135, 122, 135,  95, 135, 135, 135, 135,  \
  136, 136, 136, 136, 136, 127, 136,  90, 105, 136, 136, 136,  \
  137, 137, 137, 137, 137, 132, 137,  85, 137, 137, 137, 137,  \
  138, 138, 138, 138, 138, 136, 138,  81, 138,  66, 138, 138,  \
  139, 139, 139,  67, 139, 141, 139,  76, 139, 139, 139, 139,  \
  140,  96, 101, 140, 140, 121, 140, 140, 140, 140, 140, 140,  \
  141,  91, 141, 141, 141, 126, 141, 141, 100, 141, 141, 141,  \
  142,  86, 142, 142, 142, 131, 142, 142, 142, 142, 142, 142,  \
  143,  82, 143, 143, 143, 135, 143, 143, 143,  71, 143, 143,  \
  144,  77, 144,  72, 144, 140, 144, 144, 144, 144, 144, 144,  \
  145, 145, 145, 145, 145, 145, 145, 188, 193, 145, 149, 145,  \
  146, 146, 194, 146, 146, 146, 146, 183, 146, 146, 154, 146,  \
  147, 147, 147, 147, 147, 147, 147, 179, 147, 147, 158, 147,  \
  148, 148, 148, 261, 148, 148, 148, 174, 148, 148, 163, 148,  \
  149, 149, 149, 149, 149, 149, 149, 169, 149, 260, 168, 149,  \
  150, 189, 150, 150, 150, 150, 150, 150, 198, 150, 148, 150,  \
  151, 184, 199, 151, 151, 151, 151, 151, 151, 151, 153, 151,  \
  152, 180, 152, 152, 152, 152, 152, 152, 152, 152, 157, 152,  \
  153, 175, 153, 256, 153, 153, 153, 153, 153, 153, 162, 153,  \
  154, 170, 154, 154, 154, 154, 154, 154, 154, 255, 167, 154,  \
  155, 155, 155, 155, 155, 155, 155, 155, 203, 155, 147, 155,  \
  156, 156, 204, 156, 156, 156, 156, 156, 156, 156, 152, 156,  \
  157, 157, 157, 252, 157, 157, 157, 157, 157, 157, 161, 157,  \
  158, 158, 158, 158, 158, 158, 158, 158, 158, 251, 166, 158,  \
  218, 159, 159, 159, 159, 159, 159, 159, 207, 159, 146, 159,  \
  223, 160, 208, 160, 160, 160, 160, 160, 160, 160, 151, 160,  \
  228, 161, 161, 161, 161, 161, 161, 161, 161, 161, 156, 161,  \
  232, 162, 162, 247, 162, 162, 162, 162, 162, 162, 160, 162,  \
  237, 163, 163, 163, 163, 163, 163, 163, 163, 246, 165, 163,  \
  164, 164, 164, 164, 164, 164, 217, 164, 212, 164, 145, 164,  \
  165, 165, 213, 165, 165, 165, 222, 165, 165, 165, 150, 165,  \
  166, 166, 166, 166, 166, 166, 227, 166, 166, 166, 155, 166,  \
  167, 167, 167, 242, 167, 167, 231, 167, 167, 167, 159, 167,  \
  168, 168, 168, 168, 168, 168, 236, 168, 168, 241, 164, 168,  \
  169, 169, 169, 169, 169, 169, 169, 284, 173, 169, 241, 169,  \
  170, 279, 170, 170, 170, 170, 170, 170, 178, 170, 242, 170,  \
  171, 171, 171, 171, 171, 171, 171, 171, 182, 171, 243, 171,  \
  163, 172, 172, 172, 172, 172, 172, 172, 187, 172, 244, 172,  \
  173, 173, 173, 173, 173, 173, 168, 173, 192, 173, 245, 173,  \
  174, 174, 174, 174, 246, 174, 174, 285, 172, 174, 174, 174,  \
  175, 280, 175, 175, 247, 175, 175, 175, 177, 175, 175, 175,  \
  176, 176, 176, 176, 248, 176, 176, 176, 181, 176, 176, 176,  \
  162, 177, 177, 177, 249, 177, 177, 177, 186, 177, 177, 177,  \
  178, 178, 178, 178, 250, 178, 167, 178, 191, 178, 178, 178,  \
  179, 179, 179, 179, 179, 179, 179, 286, 171, 179, 179, 179,  \
  180, 281, 180, 180, 180, 180, 180, 180, 176, 180, 180, 180,  \
  161, 181, 181, 181, 181, 181, 181, 181, 185, 181, 181, 181,  \
  182, 182, 182, 182, 182, 182, 166, 182, 190, 182, 182, 182,  \
  183, 183, 183, 183, 183, 207, 183, 287, 170, 183, 183, 183,  \
  184, 282, 184, 184, 184, 208, 184, 184, 175, 184, 184, 184,  \
  185, 185, 185, 185, 185, 209, 185, 185, 180, 185, 185, 185,  \
  160, 186, 186, 186, 186, 210, 186, 186, 184, 186, 186, 186,  \
  187, 187, 187, 187, 187, 211, 165, 187, 189, 187, 187, 187,  \
  188, 188, 188, 188, 188, 188, 188, 288, 169, 188, 188, 212,  \
  189, 283, 189, 189, 189, 189, 189, 189, 174, 189, 189, 213,  \
  190, 190, 190, 190, 190, 190, 190, 190, 179, 190, 190, 214,  \
  159, 191, 191, 191, 191, 191, 191, 191, 183, 191, 191, 215,  \
  192, 192, 192, 192, 192, 192, 164, 192, 188, 192, 192, 216,  \
  193, 193, 193, 193, 193, 193, 197, 193, 265, 193, 169, 193,  \
  194, 194, 266, 194, 194, 194, 202, 194, 194, 194, 170, 194,  \
  195, 195, 195, 195, 195, 195, 206, 195, 195, 195, 171, 195,  \
  196, 196, 196, 148, 196, 196, 211, 196, 196, 196, 172, 196,  \
  197, 197, 197, 197, 197, 197, 216, 197, 197, 149, 173, 197,  \
  198, 198, 198, 198, 174, 198, 196, 198, 270, 198, 198, 198,  \
  199, 199, 271, 199, 175, 199, 201, 199, 199, 199, 199, 199,  \
  200, 200, 200, 200, 176, 200, 205, 200, 200, 200, 200, 200,  \
  201, 201, 201, 153, 177, 201, 210, 201, 201, 201, 201, 201,  \
  202, 202, 202, 202, 178, 202, 215, 202, 202, 154, 202, 202,  \
  203, 203, 203, 203, 203, 203, 195, 203, 275, 203, 203, 203,  \
  204, 204, 276, 204, 204, 204, 200, 204, 204, 204, 204, 204,  \
  205, 205, 205, 157, 205, 205, 209, 205, 205, 205, 205, 205,  \
  206, 206, 206, 206, 206, 206, 214, 206, 206, 158, 206, 206,  \
  207, 207, 207, 207, 207, 231, 194, 207, 279, 207, 207, 207,  \
  208, 208, 280, 208, 208, 232, 199, 208, 208, 208, 208, 208,  \
  209, 209, 209, 209, 209, 233, 204, 209, 209, 209, 209, 209,  \
  210, 210, 210, 162, 210, 234, 208, 210, 210, 210, 210, 210,  \
  211, 211, 211, 211, 211, 235, 213, 211, 211, 163, 211, 211,  \
  212, 212, 212, 212, 212, 212, 193, 212, 284, 212, 212, 236,  \
  213, 213, 285, 213, 213, 213, 198, 213, 213, 213, 213, 237,  \
  214, 214, 214, 214, 214, 214, 203, 214, 214, 214, 214, 238,  \
  215, 215, 215, 167, 215, 215, 207, 215, 215, 215, 215, 239,  \
  216, 216, 216, 216, 216, 216, 212, 216, 216, 168, 216, 240,  \
  217, 217, 217, 217, 217, 217, 269, 217, 217, 221, 193, 217,  \
  274, 218, 218, 218, 218, 218, 218, 218, 218, 226, 194, 218,  \
  219, 219, 219, 219, 219, 219, 219, 219, 219, 230, 195, 219,  \
  220, 150, 220, 220, 220, 220, 220, 220, 220, 235, 196, 220,  \
  221, 221, 221, 221, 221, 221, 221, 145, 221, 240, 197, 221,  \
  222, 222, 222, 222, 198, 222, 268, 222, 222, 220, 222, 222,  \
  273, 223, 223, 223, 199, 223, 223, 223, 223, 225, 223, 223,  \
  224, 224, 224, 224, 200, 224, 224, 224, 224, 229, 224, 224,  \
  225, 151, 225, 225, 201, 225, 225, 225, 225, 234, 225, 225,  \
  226, 226, 226, 226, 202, 226, 226, 146, 226, 239, 226, 226,  \
  227, 227, 227, 227, 227, 227, 267, 227, 227, 219, 227, 227,  \
  272, 228, 228, 228, 228, 228, 228, 228, 228, 224, 228, 228,  \
  229, 152, 229, 229, 229, 229, 229, 229, 229, 233, 229, 229,  \
  230, 230, 230, 230, 230, 230, 230, 147, 230, 238, 230, 230,  \
  231, 231, 231, 231, 231, 255, 266, 231, 231, 218, 231, 231,  \
  271, 232, 232, 232, 232, 256, 232, 232, 232, 223, 232, 232,  \
  233, 233, 233, 233, 233, 257, 233, 233, 233, 228, 233, 233,  \
  234, 153, 234, 234, 234, 258, 234, 234, 234, 232, 234, 234,  \
  235, 235, 235, 235, 235, 259, 235, 148, 235, 237, 235, 235,  \
  236, 236, 236, 236, 236, 236, 265, 236, 236, 217, 236, 260,  \
  270, 237, 237, 237, 237, 237, 237, 237, 237, 222, 237, 261,  \
  238, 238, 238, 238, 238, 238, 238, 238, 238, 227, 238, 262,  \
  239, 154, 239, 239, 239, 239, 239, 239, 239, 231, 239, 263,  \
  240, 240, 240, 240, 240, 240, 240, 149, 240, 236, 240, 264,  \
  241, 241, 241, 241, 241, 241, 241, 245, 241, 288, 217, 241,  \
  242, 242, 242, 287, 242, 242, 242, 250, 242, 242, 218, 242,  \
  243, 243, 243, 243, 243, 243, 243, 254, 243, 243, 219, 243,  \
  244, 244, 165, 244, 244, 244, 244, 259, 244, 244, 220, 244,  \
  245, 245, 245, 245, 245, 245, 245, 264, 164, 245, 221, 245,  \
  246, 246, 246, 246, 222, 246, 246, 244, 246, 283, 246, 246,  \
  247, 247, 247, 282, 223, 247, 247, 249, 247, 247, 247, 247,  \
  248, 248, 248, 248, 224, 248, 248, 253, 248, 248, 248, 248,  \
  249, 249, 160, 249, 225, 249, 249, 258, 249, 249, 249, 249,  \
  250, 250, 250, 250, 226, 250, 250, 263, 159, 250, 250, 250,  \
  251, 251, 251, 251, 251, 251, 251, 243, 251, 278, 251, 251,  \
  252, 252, 252, 277, 252, 252, 252, 248, 252, 252, 252, 252,  \
  253, 253, 156, 253, 253, 253, 253, 257, 253, 253, 253, 253,  \
  254, 254, 254, 254, 254, 254, 254, 262, 155, 254, 254, 254,  \
  255, 255, 255, 255, 255, 183, 255, 242, 255, 274, 255, 255,  \
  256, 256, 256, 273, 256, 184, 256, 247, 256, 256, 256, 256,  \
  257, 257, 257, 257, 257, 185, 257, 252, 257, 257, 257, 257,  \
  258, 258, 151, 258, 258, 186, 258, 256, 258, 258, 258, 258,  \
  259, 259, 259, 259, 259, 187, 259, 261, 150, 259, 259, 259,  \
  260, 260, 260, 260, 260, 260, 260, 241, 260, 269, 260, 188,  \
  261, 261, 261, 268, 261, 261, 261, 246, 261, 261, 261, 189,  \
  262, 262, 262, 262, 262, 262, 262, 251, 262, 262, 262, 190,  \
  263, 263, 146, 263, 263, 263, 263, 255, 263, 263, 263, 191,  \
  264, 264, 264, 264, 264, 264, 264, 260, 145, 264, 264, 192,  \
  265, 265, 265, 265, 265, 265, 173, 265, 264, 265, 265, 269,  \
  266, 266, 263, 266, 266, 266, 178, 266, 266, 266, 266, 274,  \
  267, 267, 267, 267, 267, 267, 182, 267, 267, 267, 267, 278,  \
  268, 268, 268, 196, 268, 268, 187, 268, 268, 268, 268, 283,  \
  269, 269, 269, 269, 269, 269, 192, 269, 269, 197, 269, 288,  \
  172, 270, 270, 270, 270, 270, 270, 270, 259, 270, 270, 268,  \
  177, 271, 258, 271, 271, 271, 271, 271, 271, 271, 271, 273,  \
  181, 272, 272, 272, 272, 272, 272, 272, 272, 272, 272, 277,  \
  186, 273, 273, 201, 273, 273, 273, 273, 273, 273, 273, 282,  \
  191, 274, 274, 274, 274, 274, 274, 274, 274, 202, 274, 287,  \
  275, 275, 275, 275, 275, 275, 275, 275, 254, 275, 275, 267,  \
  276, 276, 253, 276, 276, 276, 276, 276, 276, 276, 276, 272,  \
  277, 277, 277, 205, 277, 277, 277, 277, 277, 277, 277, 281,  \
  278, 278, 278, 278, 278, 278, 278, 278, 278, 206, 278, 286,  \
  279, 239, 279, 279, 279, 279, 279, 279, 250, 279, 279, 266,  \
  280, 234, 249, 280, 280, 280, 280, 280, 280, 280, 280, 271,  \
  281, 229, 281, 281, 281, 281, 281, 281, 281, 281, 281, 276,  \
  282, 225, 282, 210, 282, 282, 282, 282, 282, 282, 282, 280,  \
  283, 220, 283, 283, 283, 283, 283, 283, 283, 211, 283, 285,  \
  284, 284, 284, 284, 284, 284, 284, 240, 245, 284, 284, 265,  \
  285, 285, 244, 285, 285, 285, 285, 235, 285, 285, 285, 270,  \
  286, 286, 286, 286, 286, 286, 286, 230, 286, 286, 286, 275,  \
  287, 287, 287, 215, 287, 287, 287, 226, 287, 287, 287, 279,  \
  288, 288, 288, 288, 288, 288, 288, 221, 288, 216, 288, 284   \

#define PARAMS_5X5X5_H_INTERLEAVED \
    1,   5,  20, 120,  49, 145,  24, 116,  53, 149, 101,  68, 164,  96,  48, 121, 264,  25,  73, 193,  97,  72, 168,  92,  44, 125, 260,  29,  77, 197, 140, 245, 212, 240, 192, 265, 169, 217, 144, 241, 216, 236, 188, 269, 173, 221, 284, 288,  \
    2,  10,  15, 119,  50, 146,  23, 111,  58, 154, 106,  63, 159,  95,  47, 122, 263,  26,  74, 194,  98,  71, 167,  87,  39, 130, 255,  34,  82, 202, 135, 250, 207, 239, 191, 266, 170, 218, 143, 242, 215, 231, 183, 274, 178, 226, 279, 287,  \
    3,  14,  11, 118,  51, 147,  22, 107,  62, 158, 110,  59, 155,  94,  46, 123, 262,  27,  75, 195,  99,  70, 166,  83,  35, 134, 251,  38,  86, 206, 131, 254, 203, 238, 190, 267, 171, 219, 142, 243, 214, 227, 179, 278, 182, 230, 275, 286,  \
    4,  19,   6, 117,  52, 148,  21, 102,  67, 163, 115,  54, 150,  93,  45, 124, 261,  28,  76, 196, 100,  69, 165,  78,  30, 139, 246,  43,  91, 211, 126, 259, 198, 237, 189, 268, 172, 220, 141, 244, 213, 222, 174, 283, 187, 235, 270, 285,  \
    5,  24,   1, 116,  53, 149,  20,  97,  72, 168, 120,  49, 145,  92,  44, 125, 260,  29,  77, 197, 101,  68, 164,  73,  25, 144, 241,  48,  96, 216, 121, 264, 193, 236, 188, 269, 173, 221, 140, 245, 212, 217, 169, 288, 192, 240, 265, 284,  \
    6,   4,  21, 115,  54, 150,  19, 117,  52, 148, 100,  69, 165,  91,  43, 126, 259,  30,  78, 198, 102,  67, 163,  93,  45, 124, 261,  28,  76, 196, 141, 244, 213, 235, 187, 270, 174, 222, 139, 246, 211, 237, 189, 268, 172, 220, 285, 283,  \
    7,   9,  16, 114,  55, 151,  18, 112,  57, 153, 105,  64, 160,  90,  42, 127, 258,  31,  79, 199, 103,  66, 162,  88,  40, 129, 256,  33,  81, 201, 136, 249, 208, 234, 186, 271, 175, 223, 138, 247, 210, 232, 184, 273, 177, 225, 280, 282,  \
    8,  13,  12, 113,  56, 152,  17, 108,  61, 157, 109,  60, 156,  89,  41, 128, 257,  32,  80, 200, 104,  65, 161,  84,  36, 133, 252,  37,  85, 205, 132, 253, 204, 233, 185, 272, 176, 224, 137, 248, 209, 228, 180, 277, 181, 229, 276, 281,  \
    9,  18,   7, 112,  57, 153,  16, 103,  66, 162, 114,  55, 151,  88,  40, 129, 256,  33,  81, 201, 105,  64, 160,  79,  31, 138, 247,  42,  90, 210, 127, 258, 199, 232, 184, 273, 177, 225, 136, 249, 208, 223, 175, 282, 186, 234, 271, 280,  \
   10,  23,   2, 111,  58, 154,  15,  98,  71, 167, 119,  50, 146,  87,  39, 130, 255,  34,  82, 202, 106,  63, 159,  74,  26, 143, 242,  47,  95, 215, 122, 263, 194, 231, 183, 274, 178, 226, 135, 250, 207, 218, 170, 287, 191, 239, 266, 279,  \
   11,   3,  22, 110,  59, 155,  14, 118,  51, 147,  99,  70, 166,  86,  38, 131, 254,  35,  83, 203, 107,  62, 158,  94,  46, 123, 262,  27,  75, 195, 142, 243, 214, 230, 182, 275, 179, 227, 134, 251, 206, 238, 190, 267, 171, 219, 286, 278,  \
   12,   8,  17, 109,  60, 156,  13, 113,  56, 152, 104,  65, 161,  85,  37, 132, 253,  36,  84, 204, 108,  61, 157,  89,  41, 128, 257,  32,  80, 200, 137, 248, 209, 229, 181, 276, 180, 228, 133, 252, 205, 233, 185, 272, 176, 224, 281, 277,  \
   13,  17,   8, 108,  61, 157,  12, 104,  65, 161, 113,  56, 152,  84,  36, 133, 252,  37,  85, 205, 109,  60, 156,  80,  32, 137, 248,  41,  89, 209, 128, 257, 200, 228, 180, 277, 181, 229, 132, 253, 204, 224, 176, 281, 185, 233, 272, 276,  \
   14,  22,   3, 107,  62, 158,  11,  99,  70, 166, 118,  51, 147,  83,  35, 134, 251,  38,  86, 206, 110,  59, 155,  75,  27, 142, 243,  46,  94, 214, 123, 262, 195, 227, 179, 278, 182, 230, 131, 254, 203, 219, 171, 286, 190, 238, 267, 275,  \
   15,   2,  23, 106,  63, 159,  10, 119,  50, 146,  98,  71, 167,  82,  34, 135, 250,  39,  87, 207, 111,  58, 154,  95,  47, 122, 263,  26,  74, 194, 143, 242, 215, 226, 178, 279, 183, 231, 130, 255, 202, 239, 191, 266, 170, 218, 287, 274,  \
   16,   7,  18, 105,  64, 160,   9, 114,  55, 151, 103,  66, 162,  81,  33, 136, 249,  40,  88, 208, 112,  57, 153,  90,  42, 127, 258,  31,  79, 199, 138, 247, 210, 225, 177, 280, 184, 232, 129, 256, 201, 234, 186, 271, 175, 223, 282, 273,  \
   17,  12,  13, 104,  65, 161,   8, 109,  60, 156, 108,  61, 157,  80,  32, 137, 248,  41,  89, 209, 113,  56, 152,  85,  37, 132, 253,  36,  84, 204, 133, 252, 205, 224, 176, 281, 185, 233, 128, 257, 200, 229, 181, 276, 180, 228, 277, 272,  \
   18,  16,   9, 103,  66, 162,   7, 105,  64, 160, 112,  57, 153,  79,  31, 138, 247,  42,  90, 210, 114,  55, 151,  81,  33, 136, 249,  40,  88, 208, 129, 256, 201, 223, 175, 282, 186, 234, 127, 258, 199, 225, 177, 280, 184, 232, 273, 271,  \
   19,  21,   4, 102,  67, 163,   6, 100,  69, 165, 117,  52, 148,  78,  30, 139, 246,  43,  91, 211, 115,  54, 150,  76,  28, 141, 244,  45,  93, 213, 124, 261, 196, 222, 174, 283, 187, 235, 126, 259, 198, 220, 172, 285, 189, 237, 268, 270,  \
   20,   1,  24, 101,  68, 164,   5, 120,  49, 145,  97,  72, 168,  77,  29, 140, 245,  44,  92, 212, 116,  53, 149,  96,  48, 121, 264,  25,  73, 193, 144, 241, 216, 221, 173, 284, 188, 236, 125, 260, 197, 240, 192, 265, 169, 217, 288, 269,  \
   21,   6,  19, 100,  69, 165,   4, 115,  54, 150, 102,  67, 163,  76,  28, 141, 244,  45,  93, 213, 117,  52, 148,  91,  43, 126, 259,  30,  78, 198, 139, 246, 211, 220, 172, 285, 189, 237, 124, 261, 196, 235, 187, 270, 174, 222, 283, 268,  \
   22,  11,  14,  99,  70, 166,   3, 110,  59, 155, 107,  62, 158,  75,  27, 142, 243,  46,  94, 214, 118,  51, 147,  86,  38, 131, 254,  35,  83, 203, 134, 251, 206, 219, 171, 286, 190, 238, 123, 262, 195, 230, 182, 275, 179, 227, 278, 267,  \
   23,  15,  10,  98,  71, 167,   2, 106,  63, 159, 111,  58, 154,  74,  26, 143, 242,  47,  95, 215, 119,  50, 146,  82,  34, 135, 250,  39,  87, 207, 130, 255, 202, 218, 170, 287, 191, 239, 122, 263, 194, 226, 178, 279, 183, 231, 274, 266,  \
   24,  20,   5,  97,  72, 168,   1, 101,  68, 164, 116,  53, 149,  73,  25, 144, 241,  48,  96, 216, 120,  49, 145,  77,  29, 140, 245,  44,  92, 212, 125, 260, 197, 217, 169, 288, 192, 240, 121, 264, 193, 221, 173, 284, 188, 236, 269, 265,  \
   25,  97,  49,  44,  29, 169,  73, 144,  24, 241,   1, 121, 193, 116,  68,  48, 188, 101,  53, 173,  77,  92, 217, 125, 140,  72, 288,  20,   5, 168, 120, 145, 265, 260, 212, 192, 245, 197,  96, 221, 236, 269, 284, 216, 164, 149, 264, 240,  \
   26,  98,  50,  39,  34, 170,  74, 143,  23, 242,   2, 122, 194, 111,  63,  47, 183, 106,  58, 178,  82,  87, 218, 130, 135,  71, 287,  15,  10, 167, 119, 146, 266, 255, 207, 191, 250, 202,  95, 226, 231, 274, 279, 215, 159, 154, 263, 239,  \
   27,  99,  51,  35,  38, 171,  75, 142,  22, 243,   3, 123, 195, 107,  59,  46, 179, 110,  62, 182,  86,  83, 219, 134, 131,  70, 286,  11,  14, 166, 118, 147, 267, 251, 203, 190, 254, 206,  94, 230, 227, 278, 275, 214, 155, 158, 262, 238,  \
   28, 100,  52,  30,  43, 172,  76, 141,  21, 244,   4, 124, 196, 102,  54,  45, 174, 115,  67, 187,  91,  78, 220, 139, 126,  69, 285,   6,  19, 165, 117, 148, 268, 246, 198, 189, 259, 211,  93, 235, 222, 283, 270, 213, 150, 163, 261, 237,  \
   29, 101,  53,  25,  48, 173,  77, 140,  20, 245,   5, 125, 197,  97,  49,  44, 169, 120,  72, 192,  96,  73, 221, 144, 121,  68, 284,   1,  24, 164, 116, 149, 269, 241, 193, 188, 264, 216,  92, 240, 217, 288, 265, 212, 145, 168, 260, 236,  \
   30, 102,  54,  45,  28, 174,  78, 139,  19, 246,   6, 126, 198, 117,  69,  43, 189, 100,  52, 172,  76,  93, 222, 124, 141,  67, 283,  21,   4, 163, 115, 150, 270, 261, 213, 187, 244, 196,  91, 220, 237, 268, 285, 211, 165, 148, 259, 235,  \
   31, 103,  55,  40,  33, 175,  79, 138,  18, 247,   7, 127, 199, 112,  64,  42, 184, 105,  57, 177,  81,  88, 223, 129, 136,  66, 282,  16,   9, 162, 114, 151, 271, 256, 208, 186, 249, 201,  90, 225, 232, 273, 280, 210, 160, 153, 258, 234,  \
   32, 104,  56,  36,  37, 176,  80, 137,  17, 248,   8, 128, 200, 108,  60,  41, 180, 109,  61, 181,  85,  84, 224, 133, 132,  65, 281,  12,  13, 161, 113, 152, 272, 252, 204, 185, 253, 205,  89, 229, 228, 277, 276, 209, 156, 157, 257, 233,  \
   33, 105,  57,  31,  42, 177,  81, 136,  16, 249,   9, 129, 201, 103,  55,  40, 175, 114,  66, 186,  90,  79, 225, 138, 127,  64, 280,   7,  18, 160, 112, 153, 273, 247, 199, 184, 258, 210,  88, 234, 223, 282, 271, 208, 151, 162, 256, 232,  \
   34, 106,  58,  26,  47, 178,  82, 135,  15, 250,  10, 130, 202,  98,  50,  39, 170, 119,  71, 191,  95,  74, 226, 143, 122,  63, 279,   2,  23, 159, 111, 154, 274, 242, 194, 183, 263, 215,  87, 239, 218, 287, 266, 207, 146, 167, 255, 231,  \
   35, 107,  59,  46,  27, 179,  83, 134,  14, 251,  11, 131, 203, 118,  70,  38, 190,  99,  51, 171,  75,  94, 227, 123, 142,  62, 278,  22,   3, 158, 110, 155, 275, 262, 214, 182, 243, 195,  86, 219, 238, 267, 286, 206, 166, 147, 254, 230,  \
   36, 108,  60,  41,  32, 180,  84, 133,  13, 252,  12, 132, 204, 113,  65,  37, 185, 104,  56, 176,  80,  89, 228, 128, 137,  61, 277,  17,   8, 157, 109, 156, 276, 257, 209, 181, 248, 200,  85, 224, 233, 272, 281, 205, 161, 152, 253, 229,  \
   37, 109,  61,  32,  41, 181,  85, 132,  12, 253,  13, 133, 205, 104,  56,  36, 176, 113,  65, 185,  89,  80, 229, 137, 128,  60, 276,   8,  17, 156, 108, 157, 277, 248, 200, 180, 257, 209,  84, 233, 224, 281, 272, 204, 152, 161, 252, 228,  \
   38, 110,  62,  27,  46, 182,  86, 131,  11, 254,  14, 134, 206,  99,  51,  35, 171, 118,  70, 190,  94,  75, 230, 142, 123,  59, 275,   3,  22, 155, 107, 158, 278, 243, 195, 179, 262, 214,  83, 238, 219, 286, 267, 203, 147, 166, 251, 227,  \
   39, 111,  63,  47,  26, 183,  87, 130,  10, 255,  15, 135, 207, 119,  71,  34, 191,  98,  50, 170,  74,  95, 231, 122, 143,  58, 274,  23,   2, 154, 106, 159, 279, 263, 215, 178, 242, 194,  82, 218, 239, 266, 287, 202, 167, 146, 250, 226,  \
   40, 112,  64,  42,  31, 184,  88, 129,   9, 256,  16, 136, 208, 114,  66,  33, 186, 103,  55, 175,  79,  90, 232, 127, 138,  57, 273,  18,   7, 153, 105, 160, 280, 258, 210, 177, 247, 199,  81, 223, 234, 271, 282, 201, 162, 151, 249, 225,  \
   41, 113,  65,  37,  36, 185,  89, 128,   8, 257,  17, 137, 209, 109,  61,  32, 181, 108,  60, 180,  84,  85, 233, 132, 133,  56, 272,  13,  12, 152, 104, 161, 281, 253, 205, 176, 252, 204,  80, 228, 229, 276, 277, 200, 157, 156, 248, 224,  \
   42, 114,  66,  33,  40, 186,  90, 127,   7, 258,  18, 138, 210, 105,  57,  31, 177, 112,  64, 184,  88,  81, 234, 136, 129,  55, 271,   9,  16, 151, 103, 162, 282, 249, 201, 175, 256, 208,  79, 232, 225, 280, 273, 199, 153, 160, 247, 223,  \
   43, 115,  67,  28,  45, 187,  91, 126,   6, 259,  19, 139, 211, 100,  52,  30, 172, 117,  69, 189,  93,  76, 235, 141, 124,  54, 270,   4,  21, 150, 102, 163, 283, 244, 196, 174, 261, 213,  78, 237, 220, 285, 268, 198, 148, 165, 246, 222,  \
   44, 116,  68,  48,  25, 188,  92, 125,   5, 260,  20, 140, 212, 120,  72,  29, 192,  97,  49, 169,  73,  96, 236, 121, 144,  53, 269,  24,   1, 149, 101, 164, 284, 264, 216, 173, 241, 193,  77, 217, 240, 265, 288, 197, 168, 145, 245, 221,  \
   45, 117,  69,  43,  30, 189,  93, 124,   4, 261,  21, 141, 213, 115,  67,  28, 187, 102,  54, 174,  78,  91, 237, 126, 139,  52, 268,  19,   6, 148, 100, 165, 285, 259, 211, 172, 246, 198,  76, 222, 235, 270, 283, 196, 163, 150, 244, 220,  \
   46, 118,  70,  38,  35, 190,  94, 123,   3, 262,  22, 142, 214, 110,  62,  27, 182, 107,  59, 179,  83,  86, 238, 131, 134,  51, 267,  14,  11, 147,  99, 166, 286, 254, 206, 171, 251, 203,  75, 227, 230, 275, 278, 195, 158, 155, 243, 219,  \
   47, 119,  71,  34,  39, 191,  95, 122,   2, 263,  23, 143, 215, 106,  58,  26, 178, 111,  63, 183,  87,  82, 239, 135, 130,  50, 266,  10,  15, 146,  98, 167, 287, 250, 202, 170, 255, 207,  74, 231, 226, 279, 274, 194, 154, 159, 242, 218,  \
   48, 120,  72,  29,  44, 192,  96, 121,   1, 264,  24, 144, 216, 101,  53,  25, 173, 116,  68, 188,  92,  77, 240, 140, 125,  49, 265,   5,  20, 145,  97, 168, 288, 245, 197, 169, 260, 212,  73, 236, 221, 284, 269, 193, 149, 164, 241, 217,  \
   49,  25,  73,   1, 121, 193,  97,  44,  29, 169,  77,  92, 217,   5,  20, 120, 145, 140, 125, 265, 144,  24, 241, 116,  68,  48, 188, 101,  53, 173,  96, 221, 236, 149, 164, 264, 284, 269,  72, 288, 168, 260, 212, 192, 245, 197, 240, 216,  \
   50,  26,  74,   2, 122, 194,  98,  39,  34, 170,  82,  87, 218,  10,  15, 119, 146, 135, 130, 266, 143,  23, 242, 111,  63,  47, 183, 106,  58, 178,  95, 226, 231, 154, 159, 263, 279, 274,  71, 287, 167, 255, 207, 191, 250, 202, 239, 215,  \
   51,  27,  75,   3, 123, 195,  99,  35,  38, 171,  86,  83, 219,  14,  11, 118, 147, 131, 134, 267, 142,  22, 243, 107,  59,  46, 179, 110,  62, 182,  94, 230, 227, 158, 155, 262, 275, 278,  70, 286, 166, 251, 203, 190, 254, 206, 238, 214,  \
   52,  28,  76,   4, 124, 196, 100,  30,  43, 172,  91,  78, 220,  19,   6, 117, 148, 126, 139, 268, 141,  21, 244, 102,  54,  45, 174, 115,  67, 187,  93, 235, 222, 163, 150, 261, 270, 283,  69, 285, 165, 246, 198, 189, 259, 211, 237, 213,  \
   53,  29,  77,   5, 125, 197, 101,  25,  48, 173,  96,  73, 221,  24,   1, 116, 149, 121, 144, 269, 140,  20, 245,  97,  49,  44, 169, 120,  72, 192,  92, 240, 217, 168, 145, 260, 265, 288,  68, 284, 164, 241, 193, 188, 264, 216, 236, 212,  \
   54,  30,  78,   6, 126, 198, 102,  45,  28, 174,  76,  93, 222,   4,  21, 115, 150, 141, 124, 270, 139,  19, 246, 117,  69,  43, 189, 100,  52, 172,  91, 220, 237, 148, 165, 259, 285, 268,  67, 283, 163, 261, 213, 187, 244, 196, 235, 211,  \
   55,  31,  79,   7, 127, 199, 103,  40,  33, 175,  81,  88, 223,   9,  16, 114, 151, 136, 129, 271, 138,  18, 247, 112,  64,  42, 184, 105,  57, 177,  90, 225, 232, 153, 160, 258, 280, 273,  66, 282, 162, 256, 208, 186, 249, 201, 234, 210,  \
   56,  32,  80,   8, 128, 200, 104,  36,  37, 176,  85,  84, 224,  13,  12, 113, 152, 132, 133, 272, 137,  17, 248, 108,  60,  41, 180, 109,  61, 181,  89, 229, 228, 157, 156, 257, 276, 277,  65, 281, 161, 252, 204, 185, 253, 205, 233, 209,  \
   57,  33,  81,   9, 129, 201, 105,  31,  42, 177,  90,  79, 225,  18,   7, 112, 153, 127, 138, 273, 136,  16, 249, 103,  55,  40, 175, 114,  66, 186,  88, 234, 223, 162, 151, 256, 271, 282,  64, 280, 160, 247, 199, 184, 258, 210, 232, 208,  \
   58,  34,  82,  10, 130, 202, 106,  26,  47, 178,  95,  74, 226,  23,   2, 111, 154, 122, 143, 274, 135,  15, 250,  98,  50,  39, 170, 119,  71, 191,  87, 239, 218, 167, 146, 255, 266, 287,  63, 279, 159, 242, 194, 183, 263, 215, 231, 207,  \
   59,  35,  83,  11, 131, 203, 107,  46,  27, 179,  75,  94, 227,   3,  22, 110, 155, 142, 123, 275, 134,  14, 251, 118,  70,  38, 190,  99,  51, 171,  86, 219, 238, 147, 166, 254, 286, 267,  62, 278, 158, 262, 214, 182, 243, 195, 230, 206,  \
   60,  36,  84,  12, 132, 204, 108,  41,  32, 180,  80,  89, 228,   8,  17, 109, 156, 137, 128, 276, 133,  13, 252, 113,  65,  37, 185, 104,  56, 176,  85, 224, 233, 152, 161, 253, 281, 272,  61, 277, 157, 257, 209, 181, 248, 200, 229, 205,  \
   61,  37,  85,  13, 133, 205, 109,  32,  41, 181,  89,  80, 229,  17,   8, 108, 157, 128, 137, 277, 132,  12, 253, 104,  56,  36, 176, 113,  65, 185,  84, 233, 224, 161, 152, 252, 272, 281,  60, 276, 156, 248, 200, 180, 257, 209, 228, 204,  \
   62,  38,  86,  14, 134, 206, 110,  27,  46, 182,  94,  75, 230,  22,   3, 107, 158, 123, 142, 278, 131,  11, 254,  99,  51,  35, 171, 118,  70, 190,  83, 238, 219, 166, 147, 251, 267, 286,  59, 275, 155, 243, 195, 179, 262, 214, 227, 203,  \
   63,  39,  87,  15, 135, 207, 111,  47,  26, 183,  74,  95, 231,   2,  23, 106, 159, 143, 122, 279, 130,  10, 255, 119,  71,  34, 191,  98,  50, 170,  82, 218, 239, 146, 167, 250, 287, 266,  58, 274, 154, 263, 215, 178, 242, 194, 226, 202,  \
   64,  40,  88,  16, 136, 208, 112,  42,  31, 184,  79,  90, 232,   7,  18, 105, 160, 138, 127, 280, 129,   9, 256, 114,  66,  33, 186, 103,  55, 175,  81, 223, 234, 151, 162, 249, 282, 271,  57, 273, 153, 258, 210, 177, 247, 199, 225, 201,  \
   65,  41,  89,  17, 137, 209, 113,  37,  36, 185,  84,  85, 233,  12,  13, 104, 161, 133, 132, 281, 128,   8, 257, 109,  61,  32, 181, 108,  60, 180,  80, 228, 229, 156, 157, 248, 277, 276,  56, 272, 152, 253, 205, 176, 252, 204, 224, 200,  \
   66,  42,  90,  18, 138, 210, 114,  33,  40, 186,  88,  81, 234,  16,   9, 103, 162, 129, 136, 282, 127,   7, 258, 105,  57,  31, 177, 112,  64, 184,  79, 232, 225, 160, 153, 247, 273, 280,  55, 271, 151, 249, 201, 175, 256, 208, 223, 199,  \
   67,  43,  91,  19, 139, 211, 115,  28,  45, 187,  93,  76, 235,  21,   4, 102, 163, 124, 141, 283, 126,   6, 259, 100,  52,  30, 172, 117,  69, 189,  78, 237, 220, 165, 148, 246, 268, 285,  54, 270, 150, 244, 196, 174, 261, 213, 222, 198,  \
   68,  44,  92,  20, 140, 212, 116,  48,  25, 188,  73,  96, 236,   1,  24, 101, 164, 144, 121, 284, 125,   5, 260, 120,  72,  29, 192,  97,  49, 169,  77, 217, 240, 145, 168, 245, 288, 265,  53, 269, 149, 264, 216, 173, 241, 193, 221, 197,  \
   69,  45,  93,  21, 141, 213, 117,  43,  30, 189,  78,  91, 237,   6,  19, 100, 165, 139, 126, 285, 124,   4, 261, 115,  67,  28, 187, 102,  54, 174,  76, 222, 235, 150, 163, 244, 283, 270,  52, 268, 148, 259, 211, 172, 246, 198, 220, 196,  \
   70,  46,  94,  22, 142, 214, 118,  38,  35, 190,  83,  86, 238,  11,  14,  99, 166, 134, 131, 286, 123,   3, 262, 110,  62,  27, 182, 107,  59, 179,  75, 227, 230, 155, 158, 243, 278, 275,  51, 267, 147, 254, 206, 171, 251, 203, 219, 195,  \
   71,  47,  95,  23, 143, 215, 119,  34,  39, 191,  87,  82, 239,  15,  10,  98, 167, 130, 135, 287, 122,   2, 263, 106,  58,  26, 178, 111,  63, 183,  74, 231, 226, 159, 154, 242, 274, 279,  50, 266, 146, 250, 202, 170, 255, 207, 218, 194,  \
   72,  48,  96,  24, 144, 216, 120,  29,  44, 192,  92,  77, 240,  20,   5,  97, 168, 125, 140, 288, 121,   1, 264, 101,  53,  25, 173, 116,  68, 188,  73, 236, 221, 164, 149, 241, 269, 284,  49, 265, 145, 245, 197, 169, 260, 212, 217, 193,  \
   73,  49,  97,  77,  92, 217,  25,   1, 121, 193, 144,  24, 241,  53, 101,  96, 221,  68, 116, 236,  44,  29, 169,   5,  20, 120, 145, 140, 125, 265,  72, 288, 168, 197, 245, 240, 212, 260,  48, 188, 173, 149, 164, 264, 284, 269, 216, 192,  \
   74,  50,  98,  82,  87, 218,  26,   2, 122, 194, 143,  23, 242,  58, 106,  95, 226,  63, 111, 231,  39,  34, 170,  10,  15, 119, 146, 135, 130, 266,  71, 287, 167, 202, 250, 239, 207, 255,  47, 183, 178, 154, 159, 263, 279, 274, 215, 191,  \
   75,  51,  99,  86,  83, 219,  27,   3, 123, 195, 142,  22, 243,  62, 110,  94, 230,  59, 107, 227,  35,  38, 171,  14,  11, 118, 147, 131, 134, 267,  70, 286, 166, 206, 254, 238, 203, 251,  46, 179, 182, 158, 155, 262, 275, 278, 214, 190,  \
   76,  52, 100,  91,  78, 220,  28,   4, 124, 196, 141,  21, 244,  67, 115,  93, 235,  54, 102, 222,  30,  43, 172,  19,   6, 117, 148, 126, 139, 268,  69, 285, 165, 211, 259, 237, 198, 246,  45, 174, 187, 163, 150, 261, 270, 283, 213, 189,  \
   77,  53, 101,  96,  73, 221,  29,   5, 125, 197, 140,  20, 245,  72, 120,  92, 240,  49,  97, 217,  25,  48, 173,  24,   1, 116, 149, 121, 144, 269,  68, 284, 164, 216, 264, 236, 193, 241,  44, 169, 192, 168, 145, 260, 265, 288, 212, 188,  \
   78,  54, 102,  76,  93, 222,  30,   6, 126, 198, 139,  19, 246,  52, 100,  91, 220,  69, 117, 237,  45,  28, 174,   4,  21, 115, 150, 141, 124, 270,  67, 283, 163, 196, 244, 235, 213, 261,  43, 189, 172, 148, 165, 259, 285, 268, 211, 187,  \
   79,  55, 103,  81,  88, 223,  31,   7, 127, 199, 138,  18, 247,  57, 105,  90, 225,  64, 112, 232,  40,  33, 175,   9,  16, 114, 151, 136, 129, 271,  66, 282, 162, 201, 249, 234, 208, 256,  42, 184, 177, 153, 160, 258, 280, 273, 210, 186,  \
   80,  56, 104,  85,  84, 224,  32,   8, 128, 200, 137,  17, 248,  61, 109,  89, 229,  60, 108, 228,  36,  37, 176,  13,  12, 113, 152, 132, 133, 272,  65, 281, 161, 205, 253, 233, 204, 252,  41, 180, 181, 157, 156, 257, 276, 277, 209, 185,  \
   81,  57, 105,  90,  79, 225,  33,   9, 129, 201, 136,  16, 249,  66, 114,  88, 234,  55, 103, 223,  31,  42, 177,  18,   7, 112, 153, 127, 138, 273,  64, 280, 160, 210, 258, 232, 199, 247,  40, 175, 186, 162, 151, 256, 271, 282, 208, 184,  \
   82,  58, 106,  95,  74, 226,  34,  10, 130, 202, 135,  15, 250,  71, 119,  87, 239,  50,  98, 218,  26,  47, 178,  23,   2, 111, 154, 122, 143, 274,  63, 279, 159, 215, 263, 231, 194, 242,  39, 170, 191, 167, 146, 255, 266, 287, 207, 183,  \
   83,  59, 107,  75,  94, 227,  35,  11, 131, 203, 134,  14, 251,  51,  99,  86, 219,  70, 118, 238,  46,  27, 179,   3,  22, 110, 155, 142, 123, 275,  62, 278, 158, 195, 243, 230, 214, 262,  38, 190, 171, 147, 166, 254, 286, 267, 206, 182,  \
   84,  60, 108,  80,  89, 228,  36,  12, 132, 204, 133,  13, 252,  56, 104,  85, 224,  65, 113, 233,  41,  32, 180,   8,  17, 109, 156, 137, 128, 276,  61, 277, 157, 200, 248, 229, 209, 257,  37, 185, 176, 152, 161, 253, 281, 272, 205, 181,  \
   85,  61, 109,  89,  80, 229,  37,  13, 133, 205, 132,  12, 253,  65, 113,  84, 233,  56, 104, 224,  32,  41, 181,  17,   8, 108, 157, 128, 137, 277,  60, 276, 156, 209, 257, 228, 200, 248,  36, 176, 185, 161, 152, 252, 272, 281, 204, 180,  \
   86,  62, 110,  94,  75, 230,  38,  14, 134, 206, 131,  11, 254,  70, 118,  83, 238,  51,  99, 219,  27,  46, 182,  22,   3, 107, 158, 123, 142, 278,  59, 275, 155, 214, 262, 227, 195, 243,  35, 171, 190, 166, 147, 251, 267, 286, 203, 179,  \
   87,  63, 111,  74,  95, 231,  39,  15, 135, 207, 130,  10, 255,  50,  98,  82, 218,  71, 119, 239,  47,  26, 183,   2,  23, 106, 159, 143, 122, 279,  58, 274, 154, 194, 242, 226, 215, 263,  34, 191, 170, 146, 167, 250, 287, 266, 202, 178,  \
   88,  64, 112,  79,  90, 232,  40,  16, 136, 208, 129,   9, 256,  55, 103,  81, 223,  66, 114, 234,  42,  31, 184,   7,  18, 105, 160, 138, 127, 280,  57, 273, 153, 199, 247, 225, 210, 258,  33, 186, 175, 151, 162, 249, 282, 271, 201, 177,  \
   89,  65, 113,  84,  85, 233,  41,  17, 137, 209, 128,   8, 257,  60, 108,  80, 228,  61, 109, 229,  37,  36, 185,  12,  13, 104, 161, 133, 132, 281,  56, 272, 152, 204, 252, 224, 205, 253,  32, 181, 180, 156, 157, 248, 277, 276, 200, 176,  \
   90,  66, 114,  88,  81, 234,  42,  18, 138, 210, 127,   7, 258,  64, 112,  79, 232,  57, 105, 225,  33,  40, 186,  16,   9, 103, 162, 129, 136, 282,  55, 271, 151, 208, 256, 223, 201, 249,  31, 177, 184, 160, 153, 247, 273, 280, 199, 175,  \
   91,  67, 115,  93,  76, 235,  43,  19, 139, 211, 126,   6, 259,  69, 117,  78, 237,  52, 100, 220,  28,  45, 187,  21,   4, 102, 163, 124, 141, 283,  54, 270, 150, 213, 261, 222, 196, 244,  30, 172, 189, 165, 148, 246, 268, 285, 198, 174,  \
   92,  68, 116,  73,  96, 236,  44,  20, 140, 212, 125,   5, 260,  49,  97,  77, 217,  72, 120, 240,  48,  25, 188,   1,  24, 101, 164, 144, 121, 284,  53, 269, 149, 193, 241, 221, 216, 264,  29, 192, 169, 145, 168, 245, 288, 265, 197, 173,  \
   93,  69, 117,  78,  91, 237,  45,  21, 141, 213, 124,   4, 261,  54, 102,  76, 222,  67, 115, 235,  43,  30, 189,   6,  19, 100, 165, 139, 126, 285,  52, 268, 148, 198, 246, 220, 211, 259,  28, 187, 174, 150, 163, 244, 283, 270, 196, 172,  \
   94,  70, 118,  83,  86, 238,  46,  22, 142, 214, 123,   3, 262,  59, 107,  75, 227,  62, 110, 230,  38,  35, 190,  11,  14,  99, 166, 134, 131, 286,  51, 267, 147, 203, 251, 219, 206, 254,  27, 182, 179, 155, 158, 243, 278, 275, 195, 171,  \
   95,  71, 119,  87,  82, 239,  47,  23, 143, 215, 122,   2, 263,  63, 111,  74, 231,  58, 106, 226,  34,  39, 191,  15,  10,  98, 167, 130, 135, 287,  50, 266, 146, 207, 255, 218, 202, 250,  26, 178, 183, 159, 154, 242, 274, 279, 194, 170,  \
   96,  72, 120,  92,  77, 240,  48,  24, 144, 216, 121,   1, 264,  68, 116,  73, 236,  53, 101, 221,  29,  44, 192,  20,   5,  97, 168, 125, 140, 288,  49, 265, 145, 212, 260, 217, 197, 245,  25, 173, 188, 164, 149, 241, 269, 284, 193, 169,  \
   97,  73,  25, 144,  24, 241,  49,  77,  92, 217,  44,  29, 169, 125, 140,  72, 288,  20,   5, 168,   1, 121, 193,  53, 101,  96, 221,  68, 116, 236,  48, 188, 173, 269, 284, 216, 164, 149, 120, 145, 265, 197, 245, 240, 212, 260, 192, 264,  \
   98,  74,  26, 143,  23, 242,  50,  82,  87, 218,  39,  34, 170, 130, 135,  71, 287,  15,  10, 167,   2, 122, 194,  58, 106,  95, 226,  63, 111, 231,  47, 183, 178, 274, 279, 215, 159, 154, 119, 146, 266, 202, 250, 239, 207, 255, 191, 263,  \
   99,  75,  27, 142,  22, 243,  51,  86,  83, 219,  35,  38, 171, 134, 131,  70, 286,  11,  14, 166,   3, 123, 195,  62, 110,  94, 230,  59, 107, 227,  46, 179, 182, 278, 275, 214, 155, 158, 118, 147, 267, 206, 254, 238, 203, 251, 190, 262,  \
  100,  76,  28, 141,  21, 244,  52,  91,  78, 220,  30,  43, 172, 139, 126,  69, 285,   6,  19, 165,   4, 124, 196,  67, 115,  93, 235,  54, 102, 222,  45, 174, 187, 283, 270, 213, 150, 163, 117, 148, 268, 211, 259, 237, 198, 246, 189, 261,  \
  101,  77,  29, 140,  20, 245,  53,  96,  73, 221,  25,  48, 173, 144, 121,  68, 284,   1,  24, 164,   5, 125, 197,  72, 120,  92, 240,  49,  97, 217,  44, 169, 192, 288, 265, 212, 145, 168, 116, 149, 269, 216, 264, 236, 193, 241, 188, 260,  \
  102,  78,  30, 139,  19, 246,  54,  76,  93, 222,  45,  28, 174, 124, 141,  67, 283,  21,   4, 163,   6, 126, 198,  52, 100,  91, 220,  69, 117, 237,  43, 189, 172, 268, 285, 211, 165, 148, 115, 150, 270, 196, 244, 235, 213, 261, 187, 259,  \
  103,  79,  31, 138,  18, 247,  55,  81,  88, 223,  40,  33, 175, 129, 136,  66, 282,  16,   9, 162,   7, 127, 199,  57, 105,  90, 225,  64, 112, 232,  42, 184, 177, 273, 280, 210, 160, 153, 114, 151, 271, 201, 249, 234, 208, 256, 186, 258,  \
  104,  80,  32, 137,  17, 248,  56,  85,  84, 224,  36,  37, 176, 133, 132,  65, 281,  12,  13, 161,   8, 128, 200,  61, 109,  89, 229,  60, 108, 228,  41, 180, 181, 277, 276, 209, 156, 157, 113, 152, 272, 205, 253, 233, 204, 252, 185, 257,  \
  105,  81,  33, 136,  16, 249,  57,  90,  79, 225,  31,  42, 177, 138, 127,  64, 280,   7,  18, 160,   9, 129, 201,  66, 114,  88, 234,  55, 103, 223,  40, 175, 186, 282, 271, 208, 151, 162, 112, 153, 273, 210, 258, 232, 199, 247, 184, 256,  \
  106,  82,  34, 135,  15, 250,  58,  95,  74, 226,  26,  47, 178, 143, 122,  63, 279,   2,  23, 159,  10, 130, 202,  71, 119,  87, 239,  50,  98, 218,  39, 170, 191, 287, 266, 207, 146, 167, 111, 154, 274, 215, 263, 231, 194, 242, 183, 255,  \
  107,  83,  35, 134,  14, 251,  59,  75,  94, 227,  46,  27, 179, 123, 142,  62, 278,  22,   3, 158,  11, 131, 203,  51,  99,  86, 219,  70, 118, 238,  38, 190, 171, 267, 286, 206, 166, 147, 110, 155, 275, 195, 243, 230, 214, 262, 182, 254,  \
  108,  84,  36, 133,  13, 252,  60,  80,  89, 228,  41,  32, 180, 128, 137,  61, 277,  17,   8, 157,  12, 132, 204,  56, 104,  85, 224,  65, 113, 233,  37, 185, 176, 272, 281, 205, 161, 152, 109, 156, 276, 200, 248, 229, 209, 257, 181, 253,  \
  109,  85,  37, 132,  12, 253,  61,  89,  80, 229,  32,  41, 181, 137, 128,  60, 276,   8,  17, 156,  13, 133, 205,  65, 113,  84, 233,  56, 104, 224,  36, 176, 185, 281, 272, 204, 152, 161, 108, 157, 277, 209, 257, 228, 200, 248, 180, 252,  \
  110,  86,  38, 131,  11, 254,  62,  94,  75, 230,  27,  46, 182, 142, 123,  59, 275,   3,  22, 155,  14, 134, 206,  70, 118,  83, 238,  51,  99, 219,  35, 171, 190, 286, 267, 203, 147, 166, 107, 158, 278, 214, 262, 227, 195, 243, 179, 251,  \
  111,  87,  39, 130,  10, 255,  63,  74,  95, 231,  47,  26, 183, 122, 143,  58, 274,  23,   2, 154,  15, 135, 207,  50,  98,  82, 218,  71, 119, 239,  34, 191, 170, 266, 287, 202, 167, 146, 106, 159, 279, 194, 242, 226, 215, 263, 178, 250,  \
  112,  88,  40, 129,   9, 256,  64,  79,  90, 232,  42,  31, 184, 127, 138,  57, 273,  18,   7, 153,  16, 136, 208,  55, 103,  81, 223,  66, 114, 234,  33, 186, 175, 271, 282, 201, 162, 151, 105, 160, 280, 199, 247, 225, 210, 258, 177, 249,  \
  113,  89,  41, 128,   8, 257,  65,  84,  85, 233,  37,  36, 185, 132, 133,  56, 272,  13,  12, 152,  17, 137, 209,  60, 108,  80, 228,  61, 109, 229,  32, 181, 180, 276, 277, 200, 157, 156, 104, 161, 281, 204, 252, 224, 205, 253, 176, 248,  \
  114,  90,  42, 127,   7, 258,  66,  88,  81, 234,  33,  40, 186, 136, 129,  55, 271,   9,  16, 151,  18, 138, 210,  64, 112,  79, 232,  57, 105, 225,  31, 177, 184, 280, 273, 199, 153, 160, 103, 162, 282, 208, 256, 223, 201, 249, 175, 247,  \
  115,  91,  43, 126,   6, 259,  67,  93,  76, 235,  28,  45, 187, 141, 124,  54, 270,   4,  21, 150,  19, 139, 211,  69, 117,  78, 237,  52, 100, 220,  30, 172, 189, 285, 268, 198, 148, 165, 102, 163, 283, 213, 261, 222, 196, 244, 174, 246,  \
  116,  92,  44, 125,   5, 260,  68,  73,  96, 236,  48,  25, 188, 121, 144,  53, 269,  24,   1, 149,  20, 140, 212,  49,  97,  77, 217,  72, 120, 240,  29, 192, 169, 265, 288, 197, 168, 145, 101, 164, 284, 193, 241, 221, 216, 264, 173, 245,  \
  117,  93,  45, 124,   4, 261,  69,  78,  91, 237,  43,  30, 189, 126, 139,  52, 268,  19,   6, 148,  21, 141, 213,  54, 102,  76, 222,  67, 115, 235,  28, 187, 174, 270, 283, 196, 163, 150, 100, 165, 285, 198, 246, 220, 211, 259, 172, 244,  \
  118,  94,  46, 123,   3, 262,  70,  83,  86, 238,  38,  35, 190, 131, 134,  51, 267,  14,  11, 147,  22, 142, 214,  59, 107,  75, 227,  62, 110, 230,  27, 182, 179, 275, 278, 195, 158, 155,  99, 166, 286, 203, 251, 219, 206, 254, 171, 243,  \
  119,  95,  47, 122,   2, 263,  71,  87,  82, 239,  34,  39, 191, 135, 130,  50, 266,  10,  15, 146,  23, 143, 215,  63, 111,  74, 231,  58, 106, 226,  26, 178, 183, 279, 274, 194, 154, 159,  98, 167, 287, 207, 255, 218, 202, 250, 170, 242,  \
  120,  96,  48, 121,   1, 264,  72,  92,  77, 240,  29,  44, 192, 140, 125,  49, 265,   5,  20, 145,  24, 144, 216,  68, 116,  73, 236,  53, 101, 221,  25, 173, 188, 284, 269, 193, 149, 164,  97, 168, 288, 212, 260, 217, 197, 245, 169, 241,  \
  121, 140, 125,  49, 120, 265, 144,  68, 101, 284,  53, 116, 269,  25,  73,   1, 193,  96,  48, 264,  72,  97, 288,  44,  92,  20, 212,  77,  29, 245,   5, 197, 260, 169, 217, 145, 240, 192,  24, 216, 241, 188, 236, 164, 221, 173, 149, 168,  \
  122, 135, 130,  50, 119, 266, 143,  63, 106, 279,  58, 111, 274,  26,  74,   2, 194,  95,  47, 263,  71,  98, 287,  39,  87,  15, 207,  82,  34, 250,  10, 202, 255, 170, 218, 146, 239, 191,  23, 215, 242, 183, 231, 159, 226, 178, 154, 167,  \
  123, 131, 134,  51, 118, 267, 142,  59, 110, 275,  62, 107, 278,  27,  75,   3, 195,  94,  46, 262,  70,  99, 286,  35,  83,  11, 203,  86,  38, 254,  14, 206, 251, 171, 219, 147, 238, 190,  22, 214, 243, 179, 227, 155, 230, 182, 158, 166,  \
  124, 126, 139,  52, 117, 268, 141,  54, 115, 270,  67, 102, 283,  28,  76,   4, 196,  93,  45, 261,  69, 100, 285,  30,  78,   6, 198,  91,  43, 259,  19, 211, 246, 172, 220, 148, 237, 189,  21, 213, 244, 174, 222, 150, 235, 187, 163, 165,  \
  125, 121, 144,  53, 116, 269, 140,  49, 120, 265,  72,  97, 288,  29,  77,   5, 197,  92,  44, 260,  68, 101, 284,  25,  73,   1, 193,  96,  48, 264,  24, 216, 241, 173, 221, 149, 236, 188,  20, 212, 245, 169, 217, 145, 240, 192, 168, 164,  \
  126, 141, 124,  54, 115, 270, 139,  69, 100, 285,  52, 117, 268,  30,  78,   6, 198,  91,  43, 259,  67, 102, 283,  45,  93,  21, 213,  76,  28, 244,   4, 196, 261, 174, 222, 150, 235, 187,  19, 211, 246, 189, 237, 165, 220, 172, 148, 163,  \
  127, 136, 129,  55, 114, 271, 138,  64, 105, 280,  57, 112, 273,  31,  79,   7, 199,  90,  42, 258,  66, 103, 282,  40,  88,  16, 208,  81,  33, 249,   9, 201, 256, 175, 223, 151, 234, 186,  18, 210, 247, 184, 232, 160, 225, 177, 153, 162,  \
  128, 132, 133,  56, 113, 272, 137,  60, 109, 276,  61, 108, 277,  32,  80,   8, 200,  89,  41, 257,  65, 104, 281,  36,  84,  12, 204,  85,  37, 253,  13, 205, 252, 176, 224, 152, 233, 185,  17, 209, 248, 180, 228, 156, 229, 181, 157, 161,  \
  129, 127, 138,  57, 112, 273, 136,  55, 114, 271,  66, 103, 282,  33,  81,   9, 201,  88,  40, 256,  64, 105, 280,  31,  79,   7, 199,  90,  42, 258,  18, 210, 247, 177, 225, 153, 232, 184,  16, 208, 249, 175, 223, 151, 234, 186, 162, 160,  \
  130, 122, 143,  58, 111, 274, 135,  50, 119, 266,  71,  98, 287,  34,  82,  10, 202,  87,  39, 255,  63, 106, 279,  26,  74,   2, 194,  95,  47, 263,  23, 215, 242, 178, 226, 154, 231, 183,  15, 207, 250, 170, 218, 146, 239, 191, 167, 159,  \
  131, 142, 123,  59, 110, 275, 134,  70,  99, 286,  51, 118, 267,  35,  83,  11, 203,  86,  38, 254,  62, 107, 278,  46,  94,  22, 214,  75,  27, 243,   3, 195, 262, 179, 227, 155, 230, 182,  14, 206, 251, 190, 238, 166, 219, 171, 147, 158,  \
  132, 137, 128,  60, 109, 276, 133,  65, 104, 281,  56, 113, 272,  36,  84,  12, 204,  85,  37, 253,  61, 108, 277,  41,  89,  17, 209,  80,  32, 248,   8, 200, 257, 180, 228, 156, 229, 181,  13, 205, 252, 185, 233, 161, 224, 176, 152, 157,  \
  133, 128, 137,  61, 108, 277, 132,  56, 113, 272,  65, 104, 281,  37,  85,  13, 205,  84,  36, 252,  60, 109, 276,  32,  80,   8, 200,  89,  41, 257,  17, 209, 248, 181, 229, 157, 228, 180,  12, 204, 253, 176, 224, 152, 233, 185, 161, 156,  \
  134, 123, 142,  62, 107, 278, 131,  51, 118, 267,  70,  99, 286,  38,  86,  14, 206,  83,  35, 251,  59, 110, 275,  27,  75,   3, 195,  94,  46, 262,  22, 214, 243, 182, 230, 158, 227, 179,  11, 203, 254, 171, 219, 147, 238, 190, 166, 155,  \
  135, 143, 122,  63, 106, 279, 130,  71,  98, 287,  50, 119, 266,  39,  87,  15, 207,  82,  34, 250,  58, 111, 274,  47,  95,  23, 215,  74,  26, 242,   2, 194, 263, 183, 231, 159, 226, 178,  10, 202, 255, 191, 239, 167, 218, 170, 146, 154,  \
  136, 138, 127,  64, 105, 280, 129,  66, 103, 282,  55, 114, 271,  40,  88,  16, 208,  81,  33, 249,  57, 112, 273,  42,  90,  18, 210,  79,  31, 247,   7, 199, 258, 184, 232, 160, 225, 177,   9, 201, 256, 186, 234, 162, 223, 175, 151, 153,  \
  137, 133, 132,  65, 104, 281, 128,  61, 108, 277,  60, 109, 276,  41,  89,  17, 209,  80,  32, 248,  56, 113, 272,  37,  85,  13, 205,  84,  36, 252,  12, 204, 253, 185, 233, 161, 224, 176,   8, 200, 257, 181, 229, 157, 228, 180, 156, 152,  \
  138, 129, 136,  66, 103, 282, 127,  57, 112, 273,  64, 105, 280,  42,  90,  18, 210,  79,  31, 247,  55, 114, 271,  33,  81,   9, 201,  88,  40, 256,  16, 208, 249, 186, 234, 162, 223, 175,   7, 199, 258, 177, 225, 153, 232, 184, 160, 151,  \
  139, 124, 141,  67, 102, 283, 126,  52, 117, 268,  69, 100, 285,  43,  91,  19, 211,  78,  30, 246,  54, 115, 270,  28,  76,   4, 196,  93,  45, 261,  21, 213, 244, 187, 235, 163, 222, 174,   6, 198, 259, 172, 220, 148, 237, 189, 165, 150,  \
  140, 144, 121,  68, 101, 284, 125,  72,  97, 288,  49, 120, 265,  44,  92,  20, 212,  77,  29, 245,  53, 116, 269,  48,  96,  24, 216,  73,  25, 241,   1, 193, 264, 188, 236, 164, 221, 173,   5, 197, 260, 192, 240, 168, 217, 169, 145, 149,  \
  141, 139, 126,  69, 100, 285, 124,  67, 102, 283,  54, 115, 270,  45,  93,  21, 213,  76,  28, 244,  52, 117, 268,  43,  91,  19, 211,  78,  30, 246,   6, 198, 259, 189, 237, 165, 220, 172,   4, 196, 261, 187, 235, 163, 222, 174, 150, 148,  \
  142, 134, 131,  70,  99, 286, 123,  62, 107, 278,  59, 110, 275,  46,  94,  22, 214,  75,  27, 243,  51, 118, 267,  38,  86,  14, 206,  83,  35, 251,  11, 203, 254, 190, 238, 166, 219, 171,   3, 195, 262, 182, 230, 158, 227, 179, 155, 147,  \
  143, 130, 135,  71,  98, 287, 122,  58, 111, 274,  63, 106, 279,  47,  95,  23, 215,  74,  26, 242,  50, 119, 266,  34,  82,  10, 202,  87,  39, 255,  15, 207, 250, 191, 239, 167, 218, 170,   2, 194, 263, 178, 226, 154, 231, 183, 159, 146,  \
  144, 125, 140,  72,  97, 288, 121,  53, 116, 269,  68, 101, 284,  48,  96,  24, 216,  73,  25, 241,  49, 120, 265,  29,  77,   5, 197,  92,  44, 260,  20, 212, 245, 192, 240, 168, 217, 169,   1, 193, 264, 173, 221, 149, 236, 188, 164, 145,  \
  145, 149, 164, 264, 193,   1, 168, 260, 197,   5, 245, 212,  20, 240, 192, 265, 120, 169, 217,  49, 241, 216,  24, 236, 188, 269, 116, 173, 221,  53, 284, 101,  68,  96,  48, 121,  25,  73, 288,  97,  72,  92,  44, 125,  29,  77, 140, 144,  \
  146, 154, 159, 263, 194,   2, 167, 255, 202,  10, 250, 207,  15, 239, 191, 266, 119, 170, 218,  50, 242, 215,  23, 231, 183, 274, 111, 178, 226,  58, 279, 106,  63,  95,  47, 122,  26,  74, 287,  98,  71,  87,  39, 130,  34,  82, 135, 143,  \
  147, 158, 155, 262, 195,   3, 166, 251, 206,  14, 254, 203,  11, 238, 190, 267, 118, 171, 219,  51, 243, 214,  22, 227, 179, 278, 107, 182, 230,  62, 275, 110,  59,  94,  46, 123,  27,  75, 286,  99,  70,  83,  35, 134,  38,  86, 131, 142,  \
  148, 163, 150, 261, 196,   4, 165, 246, 211,  19, 259, 198,   6, 237, 189, 268, 117, 172, 220,  52, 244, 213,  21, 222, 174, 283, 102, 187, 235,  67, 270, 115,  54,  93,  45, 124,  28,  76, 285, 100,  69,  78,  30, 139,  43,  91, 126, 141,  \
  149, 168, 145, 260, 197,   5, 164, 241, 216,  24, 264, 193,   1, 236, 188, 269, 116, 173, 221,  53, 245, 212,  20, 217, 169, 288,  97, 192, 240,  72, 265, 120,  49,  92,  44, 125,  29,  77, 284, 101,  68,  73,  25, 144,  48,  96, 121, 140,  \
  150, 148, 165, 259, 198,   6, 163, 261, 196,   4, 244, 213,  21, 235, 187, 270, 115, 174, 222,  54, 246, 211,  19, 237, 189, 268, 117, 172, 220,  52, 285, 100,  69,  91,  43, 126,  30,  78, 283, 102,  67,  93,  45, 124,  28,  76, 141, 139,  \
  151, 153, 160, 258, 199,   7, 162, 256, 201,   9, 249, 208,  16, 234, 186, 271, 114, 175, 223,  55, 247, 210,  18, 232, 184, 273, 112, 177, 225,  57, 280, 105,  64,  90,  42, 127,  31,  79, 282, 103,  66,  88,  40, 129,  33,  81, 136, 138,  \
  152, 157, 156, 257, 200,   8, 161, 252, 205,  13, 253, 204,  12, 233, 185, 272, 113, 176, 224,  56, 248, 209,  17, 228, 180, 277, 108, 181, 229,  61, 276, 109,  60,  89,  41, 128,  32,  80, 281, 104,  65,  84,  36, 133,  37,  85, 132, 137,  \
  153, 162, 151, 256, 201,   9, 160, 247, 210,  18, 258, 199,   7, 232, 184, 273, 112, 177, 225,  57, 249, 208,  16, 223, 175, 282, 103, 186, 234,  66, 271, 114,  55,  88,  40, 129,  33,  81, 280, 105,  64,  79,  31, 138,  42,  90, 127, 136,  \
  154, 167, 146, 255, 202,  10, 159, 242, 215,  23, 263, 194,   2, 231, 183, 274, 111, 178, 226,  58, 250, 207,  15, 218, 170, 287,  98, 191, 239,  71, 266, 119,  50,  87,  39, 130,  34,  82, 279, 106,  63,  74,  26, 143,  47,  95, 122, 135,  \
  155, 147, 166, 254, 203,  11, 158, 262, 195,   3, 243, 214,  22, 230, 182, 275, 110, 179, 227,  59, 251, 206,  14, 238, 190, 267, 118, 171, 219,  51, 286,  99,  70,  86,  38, 131,  35,  83, 278, 107,  62,  94,  46, 123,  27,  75, 142, 134,  \
  156, 152, 161, 253, 204,  12, 157, 257, 200,   8, 248, 209,  17, 229, 181, 276, 109, 180, 228,  60, 252, 205,  13, 233, 185, 272, 113, 176, 224,  56, 281, 104,  65,  85,  37, 132,  36,  84, 277, 108,  61,  89,  41, 128,  32,  80, 137, 133,  \
  157, 161, 152, 252, 205,  13, 156, 248, 209,  17, 257, 200,   8, 228, 180, 277, 108, 181, 229,  61, 253, 204,  12, 224, 176, 281, 104, 185, 233,  65, 272, 113,  56,  84,  36, 133,  37,  85, 276, 109,  60,  80,  32, 137,  41,  89, 128, 132,  \
  158, 166, 147, 251, 206,  14, 155, 243, 214,  22, 262, 195,   3, 227, 179, 278, 107, 182, 230,  62, 254, 203,  11, 219, 171, 286,  99, 190, 238,  70, 267, 118,  51,  83,  35, 134,  38,  86, 275, 110,  59,  75,  27, 142,  46,  94, 123, 131,  \
  159, 146, 167, 250, 207,  15, 154, 263, 194,   2, 242, 215,  23, 226, 178, 279, 106, 183, 231,  63, 255, 202,  10, 239, 191, 266, 119, 170, 218,  50, 287,  98,  71,  82,  34, 135,  39,  87, 274, 111,  58,  95,  47, 122,  26,  74, 143, 130,  \
  160, 151, 162, 249, 208,  16, 153, 258, 199,   7, 247, 210,  18, 225, 177, 280, 105, 184, 232,  64, 256, 201,   9, 234, 186, 271, 114, 175, 223,  55, 282, 103,  66,  81,  33, 136,  40,  88, 273, 112,  57,  90,  42, 127,  31,  79, 138, 129,  \
  161, 156, 157, 248, 209,  17, 152, 253, 204,  12, 252, 205,  13, 224, 176, 281, 104, 185, 233,  65, 257, 200,   8, 229, 181, 276, 109, 180, 228,  60, 277, 108,  61,  80,  32, 137,  41,  89, 272, 113,  56,  85,  37, 132,  36,  84, 133, 128,  \
  162, 160, 153, 247, 210,  18, 151, 249, 208,  16, 256, 201,   9, 223, 175, 282, 103, 186, 234,  66, 258, 199,   7, 225, 177, 280, 105, 184, 232,  64, 273, 112,  57,  79,  31, 138,  42,  90, 271, 114,  55,  81,  33, 136,  40,  88, 129, 127,  \
  163, 165, 148, 246, 211,  19, 150, 244, 213,  21, 261, 196,   4, 222, 174, 283, 102, 187, 235,  67, 259, 198,   6, 220, 172, 285, 100, 189, 237,  69, 268, 117,  52,  78,  30, 139,  43,  91, 270, 115,  54,  76,  28, 141,  45,  93, 124, 126,  \
  164, 145, 168, 245, 212,  20, 149, 264, 193,   1, 241, 216,  24, 221, 173, 284, 101, 188, 236,  68, 260, 197,   5, 240, 192, 265, 120, 169, 217,  49, 288,  97,  72,  77,  29, 140,  44,  92, 269, 116,  53,  96,  48, 121,  25,  73, 144, 125,  \
  165, 150, 163, 244, 213,  21, 148, 259, 198,   6, 246, 211,  19, 220, 172, 285, 100, 189, 237,  69, 261, 196,   4, 235, 187, 270, 115, 174, 222,  54, 283, 102,  67,  76,  28, 141,  45,  93, 268, 117,  52,  91,  43, 126,  30,  78, 139, 124,  \
  166, 155, 158, 243, 214,  22, 147, 254, 203,  11, 251, 206,  14, 219, 171, 286,  99, 190, 238,  70, 262, 195,   3, 230, 182, 275, 110, 179, 227,  59, 278, 107,  62,  75,  27, 142,  46,  94, 267, 118,  51,  86,  38, 131,  35,  83, 134, 123,  \
  167, 159, 154, 242, 215,  23, 146, 250, 207,  15, 255, 202,  10, 218, 170, 287,  98, 191, 239,  71, 263, 194,   2, 226, 178, 279, 106, 183, 231,  63, 274, 111,  58,  74,  26, 143,  47,  95, 266, 119,  50,  82,  34, 135,  39,  87, 130, 122,  \
  168, 164, 149, 241, 216,  24, 145, 245, 212,  20, 260, 197,   5, 217, 169, 288,  97, 192, 240,  72, 264, 193,   1, 221, 173, 284, 101, 188, 236,  68, 269, 116,  53,  73,  25, 144,  48,  96, 265, 120,  49,  77,  29, 140,  44,  92, 125, 121,  \
  169, 241, 193, 188, 173,  25, 217, 288, 168,  97, 145, 265,  49, 260, 212, 192,  44, 245, 197,  29, 221, 236,  73, 269, 284, 216, 144, 164, 149,  24, 264,   1, 121, 116,  68,  48, 101,  53, 240,  77,  92, 125, 140,  72,  20,   5, 120,  96,  \
  170, 242, 194, 183, 178,  26, 218, 287, 167,  98, 146, 266,  50, 255, 207, 191,  39, 250, 202,  34, 226, 231,  74, 274, 279, 215, 143, 159, 154,  23, 263,   2, 122, 111,  63,  47, 106,  58, 239,  82,  87, 130, 135,  71,  15,  10, 119,  95,  \
  171, 243, 195, 179, 182,  27, 219, 286, 166,  99, 147, 267,  51, 251, 203, 190,  35, 254, 206,  38, 230, 227,  75, 278, 275, 214, 142, 155, 158,  22, 262,   3, 123, 107,  59,  46, 110,  62, 238,  86,  83, 134, 131,  70,  11,  14, 118,  94,  \
  172, 244, 196, 174, 187,  28, 220, 285, 165, 100, 148, 268,  52, 246, 198, 189,  30, 259, 211,  43, 235, 222,  76, 283, 270, 213, 141, 150, 163,  21, 261,   4, 124, 102,  54,  45, 115,  67, 237,  91,  78, 139, 126,  69,   6,  19, 117,  93,  \
  173, 245, 197, 169, 192,  29, 221, 284, 164, 101, 149, 269,  53, 241, 193, 188,  25, 264, 216,  48, 240, 217,  77, 288, 265, 212, 140, 145, 168,  20, 260,   5, 125,  97,  49,  44, 120,  72, 236,  96,  73, 144, 121,  68,   1,  24, 116,  92,  \
  174, 246, 198, 189, 172,  30, 222, 283, 163, 102, 150, 270,  54, 261, 213, 187,  45, 244, 196,  28, 220, 237,  78, 268, 285, 211, 139, 165, 148,  19, 259,   6, 126, 117,  69,  43, 100,  52, 235,  76,  93, 124, 141,  67,  21,   4, 115,  91,  \
  175, 247, 199, 184, 177,  31, 223, 282, 162, 103, 151, 271,  55, 256, 208, 186,  40, 249, 201,  33, 225, 232,  79, 273, 280, 210, 138, 160, 153,  18, 258,   7, 127, 112,  64,  42, 105,  57, 234,  81,  88, 129, 136,  66,  16,   9, 114,  90,  \
  176, 248, 200, 180, 181,  32, 224, 281, 161, 104, 152, 272,  56, 252, 204, 185,  36, 253, 205,  37, 229, 228,  80, 277, 276, 209, 137, 156, 157,  17, 257,   8, 128, 108,  60,  41, 109,  61, 233,  85,  84, 133, 132,  65,  12,  13, 113,  89,  \
  177, 249, 201, 175, 186,  33, 225, 280, 160, 105, 153, 273,  57, 247, 199, 184,  31, 258, 210,  42, 234, 223,  81, 282, 271, 208, 136, 151, 162,  16, 256,   9, 129, 103,  55,  40, 114,  66, 232,  90,  79, 138, 127,  64,   7,  18, 112,  88,  \
  178, 250, 202, 170, 191,  34, 226, 279, 159, 106, 154, 274,  58, 242, 194, 183,  26, 263, 215,  47, 239, 218,  82, 287, 266, 207, 135, 146, 167,  15, 255,  10, 130,  98,  50,  39, 119,  71, 231,  95,  74, 143, 122,  63,   2,  23, 111,  87,  \
  179, 251, 203, 190, 171,  35, 227, 278, 158, 107, 155, 275,  59, 262, 214, 182,  46, 243, 195,  27, 219, 238,  83, 267, 286, 206, 134, 166, 147,  14, 254,  11, 131, 118,  70,  38,  99,  51, 230,  75,  94, 123, 142,  62,  22,   3, 110,  86,  \
  180, 252, 204, 185, 176,  36, 228, 277, 157, 108, 156, 276,  60, 257, 209, 181,  41, 248, 200,  32, 224, 233,  84, 272, 281, 205, 133, 161, 152,  13, 253,  12, 132, 113,  65,  37, 104,  56, 229,  80,  89, 128, 137,  61,  17,   8, 109,  85,  \
  181, 253, 205, 176, 185,  37, 229, 276, 156, 109, 157, 277,  61, 248, 200, 180,  32, 257, 209,  41, 233, 224,  85, 281, 272, 204, 132, 152, 161,  12, 252,  13, 133, 104,  56,  36, 113,  65, 228,  89,  80, 137, 128,  60,   8,  17, 108,  84,  \
  182, 254, 206, 171, 190,  38, 230, 275, 155, 110, 158, 278,  62, 243, 195, 179,  27, 262, 214,  46, 238, 219,  86, 286, 267, 203, 131, 147, 166,  11, 251,  14, 134,  99,  51,  35, 118,  70, 227,  94,  75, 142, 123,  59,   3,  22, 107,  83,  \
  183, 255, 207, 191, 170,  39, 231, 274, 154, 111, 159, 279,  63, 263, 215, 178,  47, 242, 194,  26, 218, 239,  87, 266, 287, 202, 130, 167, 146,  10, 250,  15, 135, 119,  71,  34,  98,  50, 226,  74,  95, 122, 143,  58,  23,   2, 106,  82,  \
  184, 256, 208, 186, 175,  40, 232, 273, 153, 112, 160, 280,  64, 258, 210, 177,  42, 247, 199,  31, 223, 234,  88, 271, 282, 201, 129, 162, 151,   9, 249,  16, 136, 114,  66,  33, 103,  55, 225,  79,  90, 127, 138,  57,  18,   7, 105,  81,  \
  185, 257, 209, 181, 180,  41, 233, 272, 152, 113, 161, 281,  65, 253, 205, 176,  37, 252, 204,  36, 228, 229,  89, 276, 277, 200, 128, 157, 156,   8, 248,  17, 137, 109,  61,  32, 108,  60, 224,  84,  85, 132, 133,  56,  13,  12, 104,  80,  \
  186, 258, 210, 177, 184,  42, 234, 271, 151, 114, 162, 282,  66, 249, 201, 175,  33, 256, 208,  40, 232, 225,  90, 280, 273, 199, 127, 153, 160,   7, 247,  18, 138, 105,  57,  31, 112,  64, 223,  88,  81, 136, 129,  55,   9,  16, 103,  79,  \
  187, 259, 211, 172, 189,  43, 235, 270, 150, 115, 163, 283,  67, 244, 196, 174,  28, 261, 213,  45, 237, 220,  91, 285, 268, 198, 126, 148, 165,   6, 246,  19, 139, 100,  52,  30, 117,  69, 222,  93,  76, 141, 124,  54,   4,  21, 102,  78,  \
  188, 260, 212, 192, 169,  44, 236, 269, 149, 116, 164, 284,  68, 264, 216, 173,  48, 241, 193,  25, 217, 240,  92, 265, 288, 197, 125, 168, 145,   5, 245,  20, 140, 120,  72,  29,  97,  49, 221,  73,  96, 121, 144,  53,  24,   1, 101,  77,  \
  189, 261, 213, 187, 174,  45, 237, 268, 148, 117, 165, 285,  69, 259, 211, 172,  43, 246, 198,  30, 222, 235,  93, 270, 283, 196, 124, 163, 150,   4, 244,  21, 141, 115,  67,  28, 102,  54, 220,  78,  91, 126, 139,  52,  19,   6, 100,  76,  \
  190, 262, 214, 182, 179,  46, 238, 267, 147, 118, 166, 286,  70, 254, 206, 171,  38, 251, 203,  35, 227, 230,  94, 275, 278, 195, 123, 158, 155,   3, 243,  22, 142, 110,  62,  27, 107,  59, 219,  83,  86, 131, 134,  51,  14,  11,  99,  75,  \
  191, 263, 215, 178, 183,  47, 239, 266, 146, 119, 167, 287,  71, 250, 202, 170,  34, 255, 207,  39, 231, 226,  95, 279, 274, 194, 122, 154, 159,   2, 242,  23, 143, 106,  58,  26, 111,  63, 218,  87,  82, 135, 130,  50,  10,  15,  98,  74,  \
  192, 264, 216, 173, 188,  48, 240, 265, 145, 120, 168, 288,  72, 245, 197, 169,  29, 260, 212,  44, 236, 221,  96, 284, 269, 193, 121, 149, 164,   1, 241,  24, 144, 101,  53,  25, 116,  68, 217,  92,  77, 140, 125,  49,   5,  20,  97,  73,  \
  193, 169, 217, 145, 265,  49, 241, 188, 173,  25, 221, 236,  73, 149, 164, 264,   1, 284, 269, 121, 288, 168,  97, 260, 212, 192,  44, 245, 197,  29, 240,  77,  92,   5,  20, 120, 140, 125, 216, 144,  24, 116,  68,  48, 101,  53,  96,  72,  \
  194, 170, 218, 146, 266,  50, 242, 183, 178,  26, 226, 231,  74, 154, 159, 263,   2, 279, 274, 122, 287, 167,  98, 255, 207, 191,  39, 250, 202,  34, 239,  82,  87,  10,  15, 119, 135, 130, 215, 143,  23, 111,  63,  47, 106,  58,  95,  71,  \
  195, 171, 219, 147, 267,  51, 243, 179, 182,  27, 230, 227,  75, 158, 155, 262,   3, 275, 278, 123, 286, 166,  99, 251, 203, 190,  35, 254, 206,  38, 238,  86,  83,  14,  11, 118, 131, 134, 214, 142,  22, 107,  59,  46, 110,  62,  94,  70,  \
  196, 172, 220, 148, 268,  52, 244, 174, 187,  28, 235, 222,  76, 163, 150, 261,   4, 270, 283, 124, 285, 165, 100, 246, 198, 189,  30, 259, 211,  43, 237,  91,  78,  19,   6, 117, 126, 139, 213, 141,  21, 102,  54,  45, 115,  67,  93,  69,  \
  197, 173, 221, 149, 269,  53, 245, 169, 192,  29, 240, 217,  77, 168, 145, 260,   5, 265, 288, 125, 284, 164, 101, 241, 193, 188,  25, 264, 216,  48, 236,  96,  73,  24,   1, 116, 121, 144, 212, 140,  20,  97,  49,  44, 120,  72,  92,  68,  \
  198, 174, 222, 150, 270,  54, 246, 189, 172,  30, 220, 237,  78, 148, 165, 259,   6, 285, 268, 126, 283, 163, 102, 261, 213, 187,  45, 244, 196,  28, 235,  76,  93,   4,  21, 115, 141, 124, 211, 139,  19, 117,  69,  43, 100,  52,  91,  67,  \
  199, 175, 223, 151, 271,  55, 247, 184, 177,  31, 225, 232,  79, 153, 160, 258,   7, 280, 273, 127, 282, 162, 103, 256, 208, 186,  40, 249, 201,  33, 234,  81,  88,   9,  16, 114, 136, 129, 210, 138,  18, 112,  64,  42, 105,  57,  90,  66,  \
  200, 176, 224, 152, 272,  56, 248, 180, 181,  32, 229, 228,  80, 157, 156, 257,   8, 276, 277, 128, 281, 161, 104, 252, 204, 185,  36, 253, 205,  37, 233,  85,  84,  13,  12, 113, 132, 133, 209, 137,  17, 108,  60,  41, 109,  61,  89,  65,  \
  201, 177, 225, 153, 273,  57, 249, 175, 186,  33, 234, 223,  81, 162, 151, 256,   9, 271, 282, 129, 280, 160, 105, 247, 199, 184,  31, 258, 210,  42, 232,  90,  79,  18,   7, 112, 127, 138, 208, 136,  16, 103,  55,  40, 114,  66,  88,  64,  \
  202, 178, 226, 154, 274,  58, 250, 170, 191,  34, 239, 218,  82, 167, 146, 255,  10, 266, 287, 130, 279, 159, 106, 242, 194, 183,  26, 263, 215,  47, 231,  95,  74,  23,   2, 111, 122, 143, 207, 135,  15,  98,  50,  39, 119,  71,  87,  63,  \
  203, 179, 227, 155, 275,  59, 251, 190, 171,  35, 219, 238,  83, 147, 166, 254,  11, 286, 267, 131, 278, 158, 107, 262, 214, 182,  46, 243, 195,  27, 230,  75,  94,   3,  22, 110, 142, 123, 206, 134,  14, 118,  70,  38,  99,  51,  86,  62,  \
  204, 180, 228, 156, 276,  60, 252, 185, 176,  36, 224, 233,  84, 152, 161, 253,  12, 281, 272, 132, 277, 157, 108, 257, 209, 181,  41, 248, 200,  32, 229,  80,  89,   8,  17, 109, 137, 128, 205, 133,  13, 113,  65,  37, 104,  56,  85,  61,  \
  205, 181, 229, 157, 277,  61, 253, 176, 185,  37, 233, 224,  85, 161, 152, 252,  13, 272, 281, 133, 276, 156, 109, 248, 200, 180,  32, 257, 209,  41, 228,  89,  80,  17,   8, 108, 128, 137, 204, 132,  12, 104,  56,  36, 113,  65,  84,  60,  \
  206, 182, 230, 158, 278,  62, 254, 171, 190,  38, 238, 219,  86, 166, 147, 251,  14, 267, 286, 134, 275, 155, 110, 243, 195, 179,  27, 262, 214,  46, 227,  94,  75,  22,   3, 107, 123, 142, 203, 131,  11,  99,  51,  35, 118,  70,  83,  59,  \
  207, 183, 231, 159, 279,  63, 255, 191, 170,  39, 218, 239,  87, 146, 167, 250,  15, 287, 266, 135, 274, 154, 111, 263, 215, 178,  47, 242, 194,  26, 226,  74,  95,   2,  23, 106, 143, 122, 202, 130,  10, 119,  71,  34,  98,  50,  82,  58,  \
  208, 184, 232, 160, 280,  64, 256, 186, 175,  40, 223, 234,  88, 151, 162, 249,  16, 282, 271, 136, 273, 153, 112, 258, 210, 177,  42, 247, 199,  31, 225,  79,  90,   7,  18, 105, 138, 127, 201, 129,   9, 114,  66,  33, 103,  55,  81,  57,  \
  209, 185, 233, 161, 281,  65, 257, 181, 180,  41, 228, 229,  89, 156, 157, 248,  17, 277, 276, 137, 272, 152, 113, 253, 205, 176,  37, 252, 204,  36, 224,  84,  85,  12,  13, 104, 133, 132, 200, 128,   8, 109,  61,  32, 108,  60,  80,  56,  \
  210, 186, 234, 162, 282,  66, 258, 177, 184,  42, 232, 225,  90, 160, 153, 247,  18, 273, 280, 138, 271, 151, 114, 249, 201, 175,  33, 256, 208,  40, 223,  88,  81,  16,   9, 103, 129, 136, 199, 127,   7, 105,  57,  31, 112,  64,  79,  55,  \
  211, 187, 235, 163, 283,  67, 259, 172, 189,  43, 237, 220,  91, 165, 148, 246,  19, 268, 285, 139, 270, 150, 115, 244, 196, 174,  28, 261, 213,  45, 222,  93,  76,  21,   4, 102, 124, 141, 198, 126,   6, 100,  52,  30, 117,  69,  78,  54,  \
  212, 188, 236, 164, 284,  68, 260, 192, 169,  44, 217, 240,  92, 145, 168, 245,  20, 288, 265, 140, 269, 149, 116, 264, 216, 173,  48, 241, 193,  25, 221,  73,  96,   1,  24, 101, 144, 121, 197, 125,   5, 120,  72,  29,  97,  49,  77,  53,  \
  213, 189, 237, 165, 285,  69, 261, 187, 174,  45, 222, 235,  93, 150, 163, 244,  21, 283, 270, 141, 268, 148, 117, 259, 211, 172,  43, 246, 198,  30, 220,  78,  91,   6,  19, 100, 139, 126, 196, 124,   4, 115,  67,  28, 102,  54,  76,  52,  \
  214, 190, 238, 166, 286,  70, 262, 182, 179,  46, 227, 230,  94, 155, 158, 243,  22, 278, 275, 142, 267, 147, 118, 254, 206, 171,  38, 251, 203,  35, 219,  83,  86,  11,  14,  99, 134, 131, 195, 123,   3, 110,  62,  27, 107,  59,  75,  51,  \
  215, 191, 239, 167, 287,  71, 263, 178, 183,  47, 231, 226,  95, 159, 154, 242,  23, 274, 279, 143, 266, 146, 119, 250, 202, 170,  34, 255, 207,  39, 218,  87,  82,  15,  10,  98, 130, 135, 194, 122,   2, 106,  58,  26, 111,  63,  74,  50,  \
  216, 192, 240, 168, 288,  72, 264, 173, 188,  48, 236, 221,  96, 164, 149, 241,  24, 269, 284, 144, 265, 145, 120, 245, 197, 169,  29, 260, 212,  44, 217,  92,  77,  20,   5,  97, 125, 140, 193, 121,   1, 101,  53,  25, 116,  68,  73,  49,  \
  217, 193, 241, 221, 236,  73, 169, 145, 265,  49, 288, 168,  97, 197, 245, 240,  77, 212, 260,  92, 188, 173,  25, 149, 164, 264,   1, 284, 269, 121, 216, 144,  24,  53, 101,  96,  68, 116, 192,  44,  29,   5,  20, 120, 140, 125,  72,  48,  \
  218, 194, 242, 226, 231,  74, 170, 146, 266,  50, 287, 167,  98, 202, 250, 239,  82, 207, 255,  87, 183, 178,  26, 154, 159, 263,   2, 279, 274, 122, 215, 143,  23,  58, 106,  95,  63, 111, 191,  39,  34,  10,  15, 119, 135, 130,  71,  47,  \
  219, 195, 243, 230, 227,  75, 171, 147, 267,  51, 286, 166,  99, 206, 254, 238,  86, 203, 251,  83, 179, 182,  27, 158, 155, 262,   3, 275, 278, 123, 214, 142,  22,  62, 110,  94,  59, 107, 190,  35,  38,  14,  11, 118, 131, 134,  70,  46,  \
  220, 196, 244, 235, 222,  76, 172, 148, 268,  52, 285, 165, 100, 211, 259, 237,  91, 198, 246,  78, 174, 187,  28, 163, 150, 261,   4, 270, 283, 124, 213, 141,  21,  67, 115,  93,  54, 102, 189,  30,  43,  19,   6, 117, 126, 139,  69,  45,  \
  221, 197, 245, 240, 217,  77, 173, 149, 269,  53, 284, 164, 101, 216, 264, 236,  96, 193, 241,  73, 169, 192,  29, 168, 145, 260,   5, 265, 288, 125, 212, 140,  20,  72, 120,  92,  49,  97, 188,  25,  48,  24,   1, 116, 121, 144,  68,  44,  \
  222, 198, 246, 220, 237,  78, 174, 150, 270,  54, 283, 163, 102, 196, 244, 235,  76, 213, 261,  93, 189, 172,  30, 148, 165, 259,   6, 285, 268, 126, 211, 139,  19,  52, 100,  91,  69, 117, 187,  45,  28,   4,  21, 115, 141, 124,  67,  43,  \
  223, 199, 247, 225, 232,  79, 175, 151, 271,  55, 282, 162, 103, 201, 249, 234,  81, 208, 256,  88, 184, 177,  31, 153, 160, 258,   7, 280, 273, 127, 210, 138,  18,  57, 105,  90,  64, 112, 186,  40,  33,   9,  16, 114, 136, 129,  66,  42,  \
  224, 200, 248, 229, 228,  80, 176, 152, 272,  56, 281, 161, 104, 205, 253, 233,  85, 204, 252,  84, 180, 181,  32, 157, 156, 257,   8, 276, 277, 128, 209, 137,  17,  61, 109,  89,  60, 108, 185,  36,  37,  13,  12, 113, 132, 133,  65,  41,  \
  225, 201, 249, 234, 223,  81, 177, 153, 273,  57, 280, 160, 105, 210, 258, 232,  90, 199, 247,  79, 175, 186,  33, 162, 151, 256,   9, 271, 282, 129, 208, 136,  16,  66, 114,  88,  55, 103, 184,  31,  42,  18,   7, 112, 127, 138,  64,  40,  \
  226, 202, 250, 239, 218,  82, 178, 154, 274,  58, 279, 159, 106, 215, 263, 231,  95, 194, 242,  74, 170, 191,  34, 167, 146, 255,  10, 266, 287, 130, 207, 135,  15,  71, 119,  87,  50,  98, 183,  26,  47,  23,   2, 111, 122, 143,  63,  39,  \
  227, 203, 251, 219, 238,  83, 179, 155, 275,  59, 278, 158, 107, 195, 243, 230,  75, 214, 262,  94, 190, 171,  35, 147, 166, 254,  11, 286, 267, 131, 206, 134,  14,  51,  99,  86,  70, 118, 182,  46,  27,   3,  22, 110, 142, 123,  62,  38,  \
  228, 204, 252, 224, 233,  84, 180, 156, 276,  60, 277, 157, 108, 200, 248, 229,  80, 209, 257,  89, 185, 176,  36, 152, 161, 253,  12, 281, 272, 132, 205, 133,  13,  56, 104,  85,  65, 113, 181,  41,  32,   8,  17, 109, 137, 128,  61,  37,  \
  229, 205, 253, 233, 224,  85, 181, 157, 277,  61, 276, 156, 109, 209, 257, 228,  89, 200, 248,  80, 176, 185,  37, 161, 152, 252,  13, 272, 281, 133, 204, 132,  12,  65, 113,  84,  56, 104, 180,  32,  41,  17,   8, 108, 128, 137,  60,  36,  \
  230, 206, 254, 238, 219,  86, 182, 158, 278,  62, 275, 155, 110, 214, 262, 227,  94, 195, 243,  75, 171, 190,  38, 166, 147, 251,  14, 267, 286, 134, 203, 131,  11,  70, 118,  83,  51,  99, 179,  27,  46,  22,   3, 107, 123, 142,  59,  35,  \
  231, 207, 255, 218, 239,  87, 183, 159, 279,  63, 274, 154, 111, 194, 242, 226,  74, 215, 263,  95, 191, 170,  39, 146, 167, 250,  15, 287, 266, 135, 202, 130,  10,  50,  98,  82,  71, 119, 178,  47,  26,   2,  23, 106, 143, 122,  58,  34,  \
  232, 208, 256, 223, 234,  88, 184, 160, 280,  64, 273, 153, 112, 199, 247, 225,  79, 210, 258,  90, 186, 175,  40, 151, 162, 249,  16, 282, 271, 136, 201, 129,   9,  55, 103,  81,  66, 114, 177,  42,  31,   7,  18, 105, 138, 127,  57,  33,  \
  233, 209, 257, 228, 229,  89, 185, 161, 281,  65, 272, 152, 113, 204, 252, 224,  84, 205, 253,  85, 181, 180,  41, 156, 157, 248,  17, 277, 276, 137, 200, 128,   8,  60, 108,  80,  61, 109, 176,  37,  36,  12,  13, 104, 133, 132,  56,  32,  \
  234, 210, 258, 232, 225,  90, 186, 162, 282,  66, 271, 151, 114, 208, 256, 223,  88, 201, 249,  81, 177, 184,  42, 160, 153, 247,  18, 273, 280, 138, 199, 127,   7,  64, 112,  79,  57, 105, 175,  33,  40,  16,   9, 103, 129, 136,  55,  31,  \
  235, 211, 259, 237, 220,  91, 187, 163, 283,  67, 270, 150, 115, 213, 261, 222,  93, 196, 244,  76, 172, 189,  43, 165, 148, 246,  19, 268, 285, 139, 198, 126,   6,  69, 117,  78,  52, 100, 174,  28,  45,  21,   4, 102, 124, 141,  54,  30,  \
  236, 212, 260, 217, 240,  92, 188, 164, 284,  68, 269, 149, 116, 193, 241, 221,  73, 216, 264,  96, 192, 169,  44, 145, 168, 245,  20, 288, 265, 140, 197, 125,   5,  49,  97,  77,  72, 120, 173,  48,  25,   1,  24, 101, 144, 121,  53,  29,  \
  237, 213, 261, 222, 235,  93, 189, 165, 285,  69, 268, 148, 117, 198, 246, 220,  78, 211, 259,  91, 187, 174,  45, 150, 163, 244,  21, 283, 270, 141, 196, 124,   4,  54, 102,  76,  67, 115, 172,  43,  30,   6,  19, 100, 139, 126,  52,  28,  \
  238, 214, 262, 227, 230,  94, 190, 166, 286,  70, 267, 147, 118, 203, 251, 219,  83, 206, 254,  86, 182, 179,  46, 155, 158, 243,  22, 278, 275, 142, 195, 123,   3,  59, 107,  75,  62, 110, 171,  38,  35,  11,  14,  99, 134, 131,  51,  27,  \
  239, 215, 263, 231, 226,  95, 191, 167, 287,  71, 266, 146, 119, 207, 255, 218,  87, 202, 250,  82, 178, 183,  47, 159, 154, 242,  23, 274, 279, 143, 194, 122,   2,  63, 111,  74,  58, 106, 170,  34,  39,  15,  10,  98, 130, 135,  50,  26,  \
  240, 216, 264, 236, 221,  96, 192, 168, 288,  72, 265, 145, 120, 212, 260, 217,  92, 197, 245,  77, 173, 188,  48, 164, 149, 241,  24, 269, 284, 144, 193, 121,   1,  68, 116,  73,  53, 101, 169,  29,  44,  20,   5,  97, 125, 140,  49,  25,  \
  241, 217, 169, 288, 168,  97, 193, 221, 236,  73, 188, 173,  25, 269, 284, 216, 144, 164, 149,  24, 145, 265,  49, 197, 245, 240,  77, 212, 260,  92, 192,  44,  29, 125, 140,  72,  20,   5, 264,   1, 121,  53, 101,  96,  68, 116,  48, 120,  \
  242, 218, 170, 287, 167,  98, 194, 226, 231,  74, 183, 178,  26, 274, 279, 215, 143, 159, 154,  23, 146, 266,  50, 202, 250, 239,  82, 207, 255,  87, 191,  39,  34, 130, 135,  71,  15,  10, 263,   2, 122,  58, 106,  95,  63, 111,  47, 119,  \
  243, 219, 171, 286, 166,  99, 195, 230, 227,  75, 179, 182,  27, 278, 275, 214, 142, 155, 158,  22, 147, 267,  51, 206, 254, 238,  86, 203, 251,  83, 190,  35,  38, 134, 131,  70,  11,  14, 262,   3, 123,  62, 110,  94,  59, 107,  46, 118,  \
  244, 220, 172, 285, 165, 100, 196, 235, 222,  76, 174, 187,  28, 283, 270, 213, 141, 150, 163,  21, 148, 268,  52, 211, 259, 237,  91, 198, 246,  78, 189,  30,  43, 139, 126,  69,   6,  19, 261,   4, 124,  67, 115,  93,  54, 102,  45, 117,  \
  245, 221, 173, 284, 164, 101, 197, 240, 217,  77, 169, 192,  29, 288, 265, 212, 140, 145, 168,  20, 149, 269,  53, 216, 264, 236,  96, 193, 241,  73, 188,  25,  48, 144, 121,  68,   1,  24, 260,   5, 125,  72, 120,  92,  49,  97,  44, 116,  \
  246, 222, 174, 283, 163, 102, 198, 220, 237,  78, 189, 172,  30, 268, 285, 211, 139, 165, 148,  19, 150, 270,  54, 196, 244, 235,  76, 213, 261,  93, 187,  45,  28, 124, 141,  67,  21,   4, 259,   6, 126,  52, 100,  91,  69, 117,  43, 115,  \
  247, 223, 175, 282, 162, 103, 199, 225, 232,  79, 184, 177,  31, 273, 280, 210, 138, 160, 153,  18, 151, 271,  55, 201, 249, 234,  81, 208, 256,  88, 186,  40,  33, 129, 136,  66,  16,   9, 258,   7, 127,  57, 105,  90,  64, 112,  42, 114,  \
  248, 224, 176, 281, 161, 104, 200, 229, 228,  80, 180, 181,  32, 277, 276, 209, 137, 156, 157,  17, 152, 272,  56, 205, 253, 233,  85, 204, 252,  84, 185,  36,  37, 133, 132,  65,  12,  13, 257,   8, 128,  61, 109,  89,  60, 108,  41, 113,  \
  249, 225, 177, 280, 160, 105, 201, 234, 223,  81, 175, 186,  33, 282, 271, 208, 136, 151, 162,  16, 153, 273,  57, 210, 258, 232,  90, 199, 247,  79, 184,  31,  42, 138, 127,  64,   7,  18, 256,   9, 129,  66, 114,  88,  55, 103,  40, 112,  \
  250, 226, 178, 279, 159, 106, 202, 239, 218,  82, 170, 191,  34, 287, 266, 207, 135, 146, 167,  15, 154, 274,  58, 215, 263, 231,  95, 194, 242,  74, 183,  26,  47, 143, 122,  63,   2,  23, 255,  10, 130,  71, 119,  87,  50,  98,  39, 111,  \
  251, 227, 179, 278, 158, 107, 203, 219, 238,  83, 190, 171,  35, 267, 286, 206, 134, 166, 147,  14, 155, 275,  59, 195, 243, 230,  75, 214, 262,  94, 182,  46,  27, 123, 142,  62,  22,   3, 254,  11, 131,  51,  99,  86,  70, 118,  38, 110,  \
  252, 228, 180, 277, 157, 108, 204, 224, 233,  84, 185, 176,  36, 272, 281, 205, 133, 161, 152,  13, 156, 276,  60, 200, 248, 229,  80, 209, 257,  89, 181,  41,  32, 128, 137,  61,  17,   8, 253,  12, 132,  56, 104,  85,  65, 113,  37, 109,  \
  253, 229, 181, 276, 156, 109, 205, 233, 224,  85, 176, 185,  37, 281, 272, 204, 132, 152, 161,  12, 157, 277,  61, 209, 257, 228,  89, 200, 248,  80, 180,  32,  41, 137, 128,  60,   8,  17, 252,  13, 133,  65, 113,  84,  56, 104,  36, 108,  \
  254, 230, 182, 275, 155, 110, 206, 238, 219,  86, 171, 190,  38, 286, 267, 203, 131, 147, 166,  11, 158, 278,  62, 214, 262, 227,  94, 195, 243,  75, 179,  27,  46, 142, 123,  59,   3,  22, 251,  14, 134,  70, 118,  83,  51,  99,  35, 107,  \
  255, 231, 183, 274, 154, 111, 207, 218, 239,  87, 191, 170,  39, 266, 287, 202, 130, 167, 146,  10, 159, 279,  63, 194, 242, 226,  74, 215, 263,  95, 178,  47,  26, 122, 143,  58,  23,   2, 250,  15, 135,  50,  98,  82,  71, 119,  34, 106,  \
  256, 232, 184, 273, 153, 112, 208, 223, 234,  88, 186, 175,  40, 271, 282, 201, 129, 162, 151,   9, 160, 280,  64, 199, 247, 225,  79, 210, 258,  90, 177,  42,  31, 127, 138,  57,  18,   7, 249,  16, 136,  55, 103,  81,  66, 114,  33, 105,  \
  257, 233, 185, 272, 152, 113, 209, 228, 229,  89, 181, 180,  41, 276, 277, 200, 128, 157, 156,   8, 161, 281,  65, 204, 252, 224,  84, 205, 253,  85, 176,  37,  36, 132, 133,  56,  13,  12, 248,  17, 137,  60, 108,  80,  61, 109,  32, 104,  \
  258, 234, 186, 271, 151, 114, 210, 232, 225,  90, 177, 184,  42, 280, 273, 199, 127, 153, 160,   7, 162, 282,  66, 208, 256, 223,  88, 201, 249,  81, 175,  33,  40, 136, 129,  55,   9,  16, 247,  18, 138,  64, 112,  79,  57, 105,  31, 103,  \
  259, 235, 187, 270, 150, 115, 211, 237, 220,  91, 172, 189,  43, 285, 268, 198, 126, 148, 165,   6, 163, 283,  67, 213, 261, 222,  93, 196, 244,  76, 174,  28,  45, 141, 124,  54,   4,  21, 246,  19, 139,  69, 117,  78,  52, 100,  30, 102,  \
  260, 236, 188, 269, 149, 116, 212, 217, 240,  92, 192, 169,  44, 265, 288, 197, 125, 168, 145,   5, 164, 284,  68, 193, 241, 221,  73, 216, 264,  96, 173,  48,  25, 121, 144,  53,  24,   1, 245,  20, 140,  49,  97,  77,  72, 120,  29, 101,  \
  261, 237, 189, 268, 148, 117, 213, 222, 235,  93, 187, 174,  45, 270, 283, 196, 124, 163, 150,   4, 165, 285,  69, 198, 246, 220,  78, 211, 259,  91, 172,  43,  30, 126, 139,  52,  19,   6, 244,  21, 141,  54, 102,  76,  67, 115,  28, 100,  \
  262, 238, 190, 267, 147, 118, 214, 227, 230,  94, 182, 179,  46, 275, 278, 195, 123, 158, 155,   3, 166, 286,  70, 203, 251, 219,  83, 206, 254,  86, 171,  38,  35, 131, 134,  51,  14,  11, 243,  22, 142,  59, 107,  75,  62, 110,  27,  99,  \
  263, 239, 191, 266, 146, 119, 215, 231, 226,  95, 178, 183,  47, 279, 274, 194, 122, 154, 159,   2, 167, 287,  71, 207, 255, 218,  87, 202, 250,  82, 170,  34,  39, 135, 130,  50,  10,  15, 242,  23, 143,  63, 111,  74,  58, 106,  26,  98,  \
  264, 240, 192, 265, 145, 120, 216, 236, 221,  96, 173, 188,  48, 284, 269, 193, 121, 149, 164,   1, 168, 288,  72, 212, 260, 217,  92, 197, 245,  77, 169,  29,  44, 140, 125,  49,   5,  20, 241,  24, 144,  68, 116,  73,  53, 101,  25,  97,  \
  265, 284, 269, 193, 264, 121, 288, 212, 245, 140, 197, 260, 125, 169, 217, 145,  49, 240, 192, 120, 216, 241, 144, 188, 236, 164,  68, 221, 173, 101, 149,  53, 116,  25,  73,   1,  96,  48, 168,  72,  97,  44,  92,  20,  77,  29,   5,  24,  \
  266, 279, 274, 194, 263, 122, 287, 207, 250, 135, 202, 255, 130, 170, 218, 146,  50, 239, 191, 119, 215, 242, 143, 183, 231, 159,  63, 226, 178, 106, 154,  58, 111,  26,  74,   2,  95,  47, 167,  71,  98,  39,  87,  15,  82,  34,  10,  23,  \
  267, 275, 278, 195, 262, 123, 286, 203, 254, 131, 206, 251, 134, 171, 219, 147,  51, 238, 190, 118, 214, 243, 142, 179, 227, 155,  59, 230, 182, 110, 158,  62, 107,  27,  75,   3,  94,  46, 166,  70,  99,  35,  83,  11,  86,  38,  14,  22,  \
  268, 270, 283, 196, 261, 124, 285, 198, 259, 126, 211, 246, 139, 172, 220, 148,  52, 237, 189, 117, 213, 244, 141, 174, 222, 150,  54, 235, 187, 115, 163,  67, 102,  28,  76,   4,  93,  45, 165,  69, 100,  30,  78,   6,  91,  43,  19,  21,  \
  269, 265, 288, 197, 260, 125, 284, 193, 264, 121, 216, 241, 144, 173, 221, 149,  53, 236, 188, 116, 212, 245, 140, 169, 217, 145,  49, 240, 192, 120, 168,  72,  97,  29,  77,   5,  92,  44, 164,  68, 101,  25,  73,   1,  96,  48,  24,  20,  \
  270, 285, 268, 198, 259, 126, 283, 213, 244, 141, 196, 261, 124, 174, 222, 150,  54, 235, 187, 115, 211, 246, 139, 189, 237, 165,  69, 220, 172, 100, 148,  52, 117,  30,  78,   6,  91,  43, 163,  67, 102,  45,  93,  21,  76,  28,   4,  19,  \
  271, 280, 273, 199, 258, 127, 282, 208, 249, 136, 201, 256, 129, 175, 223, 151,  55, 234, 186, 114, 210, 247, 138, 184, 232, 160,  64, 225, 177, 105, 153,  57, 112,  31,  79,   7,  90,  42, 162,  66, 103,  40,  88,  16,  81,  33,   9,  18,  \
  272, 276, 277, 200, 257, 128, 281, 204, 253, 132, 205, 252, 133, 176, 224, 152,  56, 233, 185, 113, 209, 248, 137, 180, 228, 156,  60, 229, 181, 109, 157,  61, 108,  32,  80,   8,  89,  41, 161,  65, 104,  36,  84,  12,  85,  37,  13,  17,  \
  273, 271, 282, 201, 256, 129, 280, 199, 258, 127, 210, 247, 138, 177, 225, 153,  57, 232, 184, 112, 208, 249, 136, 175, 223, 151,  55, 234, 186, 114, 162,  66, 103,  33,  81,   9,  88,  40, 160,  64, 105,  31,  79,   7,  90,  42,  18,  16,  \
  274, 266, 287, 202, 255, 130, 279, 194, 263, 122, 215, 242, 143, 178, 226, 154,  58, 231, 183, 111, 207, 250, 135, 170, 218, 146,  50, 239, 191, 119, 167,  71,  98,  34,  82,  10,  87,  39, 159,  63, 106,  26,  74,   2,  95,  47,  23,  15,  \
  275, 286, 267, 203, 254, 131, 278, 214, 243, 142, 195, 262, 123, 179, 227, 155,  59, 230, 182, 110, 206, 251, 134, 190, 238, 166,  70, 219, 171,  99, 147,  51, 118,  35,  83,  11,  86,  38, 158,  62, 107,  46,  94,  22,  75,  27,   3,  14,  \
  276, 281, 272, 204, 253, 132, 277, 209, 248, 137, 200, 257, 128, 180, 228, 156,  60, 229, 181, 109, 205, 252, 133, 185, 233, 161,  65, 224, 176, 104, 152,  56, 113,  36,  84,  12,  85,  37, 157,  61, 108,  41,  89,  17,  80,  32,   8,  13,  \
  277, 272, 281, 205, 252, 133, 276, 200, 257, 128, 209, 248, 137, 181, 229, 157,  61, 228, 180, 108, 204, 253, 132, 176, 224, 152,  56, 233, 185, 113, 161,  65, 104,  37,  85,  13,  84,  36, 156,  60, 109,  32,  80,   8,  89,  41,  17,  12,  \
  278, 267, 286, 206, 251, 134, 275, 195, 262, 123, 214, 243, 142, 182, 230, 158,  62, 227, 179, 107, 203, 254, 131, 171, 219, 147,  51, 238, 190, 118, 166,  70,  99,  38,  86,  14,  83,  35, 155,  59, 110,  27,  75,   3,  94,  46,  22,  11,  \
  279, 287, 266, 207, 250, 135, 274, 215, 242, 143, 194, 263, 122, 183, 231, 159,  63, 226, 178, 106, 202, 255, 130, 191, 239, 167,  71, 218, 170,  98, 146,  50, 119,  39,  87,  15,  82,  34, 154,  58, 111,  47,  95,  23,  74,  26,   2,  10,  \
  280, 282, 271, 208, 249, 136, 273, 210, 247, 138, 199, 258, 127, 184, 232, 160,  64, 225, 177, 105, 201, 256, 129, 186, 234, 162,  66, 223, 175, 103, 151,  55, 114,  40,  88,  16,  81,  33, 153,  57, 112,  42,  90,  18,  79,  31,   7,   9,  \
  281, 277, 276, 209, 248, 137, 272, 205, 252, 133, 204, 253, 132, 185, 233, 161,  65, 224, 176, 104, 200, 257, 128, 181, 229, 157,  61, 228, 180, 108, 156,  60, 109,  41,  89,  17,  80,  32, 152,  56, 113,  37,  85,  13,  84,  36,  12,   8,  \
  282, 273, 280, 210, 247, 138, 271, 201, 256, 129, 208, 249, 136, 186, 234, 162,  66, 223, 175, 103, 199, 258, 127, 177, 225, 153,  57, 232, 184, 112, 160,  64, 105,  42,  90,  18,  79,  31, 151,  55, 114,  33,  81,   9,  88,  40,  16,   7,  \
  283, 268, 285, 211, 246, 139, 270, 196, 261, 124, 213, 244, 141, 187, 235, 163,  67, 222, 174, 102, 198, 259, 126, 172, 220, 148,  52, 237, 189, 117, 165,  69, 100,  43,  91,  19,  78,  30, 150,  54, 115,  28,  76,   4,  93,  45,  21,   6,  \
  284, 288, 265, 212, 245, 140, 269, 216, 241, 144, 193, 264, 121, 188, 236, 164,  68, 221, 173, 101, 197, 260, 125, 192, 240, 168,  72, 217, 169,  97, 145,  49, 120,  44,  92,  20,  77,  29, 149,  53, 116,  48,  96,  24,  73,  25,   1,   5,  \
  285, 283, 270, 213, 244, 141, 268, 211, 246, 139, 198, 259, 126, 189, 237, 165,  69, 220, 172, 100, 196, 261, 124, 187, 235, 163,  67, 222, 174, 102, 150,  54, 115,  45,  93,  21,  76,  28, 148,  52, 117,  43,  91,  19,  78,  30,   6,   4,  \
  286, 278, 275, 214, 243, 142, 267, 206, 251, 134, 203, 254, 131, 190, 238, 166,  70, 219, 171,  99, 195, 262, 123, 182, 230, 158,  62, 227, 179, 107, 155,  59, 110,  46,  94,  22,  75,  27, 147,  51, 118,  38,  86,  14,  83,  35,  11,   3,  \
  287, 274, 279, 215, 242, 143, 266, 202, 255, 130, 207, 250, 135, 191, 239, 167,  71, 218, 170,  98, 194, 263, 122, 178, 226, 154,  58, 231, 183, 111, 159,  63, 106,  47,  95,  23,  74,  26, 146,  50, 119,  34,  82,  10,  87,  39,  15,   2,  \
  288, 269, 284, 216, 241, 144, 265, 197, 260, 125, 212, 245, 140, 192, 240, 168,  72, 217, 169,  97, 193, 264, 121, 173, 221, 149,  53, 236, 188, 116, 164,  68, 101,  48,  96,  24,  73,  25, 145,  49, 120,  29,  77,   5,  92,  44,  20,   1   \

static const unsigned int params_5x5x5_f[] = { PARAMS_5X5X5_F_INTERLEAVED };
static const unsigned int params_5x5x5_h[] = { PARAMS_5X5X5_H_INTERLEAVED };

void random_element_F_H(permutation* out, void* context) {
  zkp_params* params = context;
  identity_permutation(out);
  const unsigned int m = 48;
  // We want F and H to be equally likely so we can choose a small-ish value for m.
  unsigned int f_factor = params->H.count / params->F.count;
  for (unsigned int i = 0; i < m; i++) {
    unsigned int j = random_uint(params->H.count + f_factor * params->F.count);
    multiply_permutation_from_array(out, j < params->H.count ? &params->H : &params->F, j < params->H.count ? j : (j - params->H.count) % params->F.count);
  }
}

void random_element_symmetric_group(permutation* out, void* context) {
  (void) context;
  identity_permutation(out);
  for (unsigned int i = 2; i <= out->domain; i++) {
    unsigned int j = 1 + random_uint(i);
    if (j != i) {
      unsigned int t = PERMUTATION_GET(out, i);
      PERMUTATION_SET(out, i, PERMUTATION_GET(out, j));
      PERMUTATION_SET(out, j, t);
    }
  }
}

static void print_permutation(const permutation* p) {
  for (unsigned int i = 1; i <= p->domain; i++) {
    printf("%s%u", (i > 1) ? "," : "", PERMUTATION_GET(p, i));
  }
}

static void print_32_bytes(const unsigned char* ptr) {
  for (unsigned int j = 0; j < 32; j++) {
    printf("%02x", ptr[j]);
  }
}

int main(void) {
  RAND_poll();  // TODO: verify this usage, error handling etc

  zkp_params params_3x3x3;
  params_3x3x3.domain = 48;
  params_3x3x3.d = 24;
  params_3x3x3.F.domain = 48;
  params_3x3x3.F.count = 6;
  params_3x3x3.F.base = params_3x3x3_f;
  params_3x3x3.H.domain = 48;
  params_3x3x3.H.count = 24;
  params_3x3x3.H.base = params_3x3x3_h;
  params_3x3x3.G_.random_element = random_element_F_H;
  params_3x3x3.G_.context = &params_3x3x3;

  zkp_params params_5x5x5;
  params_5x5x5.domain = 288;
  params_5x5x5.d = 42;
  params_5x5x5.F.domain = 288;
  params_5x5x5.F.count = 12;
  params_5x5x5.F.base = params_5x5x5_f;
  params_5x5x5.H.domain = 288;
  params_5x5x5.H.count = 48;
  params_5x5x5.H.base = params_5x5x5_h;
  params_5x5x5.G_.random_element = random_element_F_H;
  params_5x5x5.G_.context = &params_5x5x5;

  zkp_params params;
  params.domain = 41;
  params.d = 5;
  params.G_.random_element = random_element_symmetric_group;
  params.G_.context = &params;

  unsigned int* params_s41_h = malloc(9240 * 41 * sizeof(unsigned int));
  assert(params_s41_h != NULL);
  params.H.domain = 41;
  params.H.count = 9240;
  params.H.base = params_s41_h;

  unsigned int s41_h_mapping[] = { 14, 2, 36, 23, 13, 7, 10, 24, 8, 6, 9, 40, 30, 39, 38, 25, 26, 37, 31, 34, 28, 29, 20, 15, 17, 35, 11, 12, 22, 33, 18, 21, 5, 16, 3, 4, 1, 41, 19, 32, 27 };
  permutation s41_h;
  s41_h.domain = 41;
  s41_h.mapping = s41_h_mapping;
  STACK_ALLOC_PERMUTATION(acc, 41);
  identity_permutation(&acc);
  for (unsigned int exp = 0; exp < 9240; exp++) {
    store_permutation_interleaved(&params.H, params_s41_h, exp, &acc);
    multiply_permutation(&acc, &s41_h);
  }
  for (unsigned int i = 1; i <= 41; i++) {
    assert(PERMUTATION_GET(&acc, i) == i);
  }

  unsigned int* params_s41_f = malloc(9240 * 41 * sizeof(unsigned int));
  assert(params_s41_f != NULL);
  params.F.domain = 41;
  params.F.count = 9240;
  params.F.base = params_s41_f;

  unsigned int s41_f_1_mapping[] = { 11, 20, 14, 28, 27, 17, 29, 23, 30, 40, 31, 4, 26, 5, 38, 37, 34, 1, 10, 41, 18, 12, 2, 22, 24, 8, 32, 3, 36, 9, 6, 13, 33, 25, 21, 7, 39, 16, 35, 15, 19 };
  permutation s41_f_1;
  s41_f_1.domain = 41;
  s41_f_1.mapping = s41_f_1_mapping;
  for (unsigned int exp = 0; exp < 9240; exp++) {
    identity_permutation(&acc);
    multiply_permutation_from_array_inv(&acc, &params.H, exp);
    multiply_permutation(&acc, &s41_f_1);
    multiply_permutation_from_array(&acc, &params.H, exp);
    store_permutation_interleaved(&params.F, params_s41_f, exp, &acc);
  }

  zkp_secret_key* key = zkp_generate_secret_key(&params);
  zkp_public_key* public_key = zkp_compute_public_key(key);

  zkp_proof* proof = zkp_new_proof(key);

  for (unsigned int round = 0; round < 100000; round++) {
    zkp_begin_round(proof);
    unsigned int q = zkp_choose_question(&params);
    zkp_answer* answer = zkp_get_answer(proof, q);
    int ok = zkp_check_answer(public_key, proof->round.commitments, answer);
    assert(ok);

    printf("round %u\n", round);
    printf("public key = ");
    print_permutation(&public_key->x0);
    printf("\ntau = %u\n", proof->round.secrets.tau);
    printf("sigma =\n");
    for (unsigned int i = 0; i <= params.d; i++) {
      printf("  ");
      print_permutation(proof->round.secrets.sigma + i);
      printf("\n");
    }
    printf("keys =\n");
    for (unsigned int i = 0; i <= params.d + 1; i++) {
      printf("  ");
      print_32_bytes(proof->round.secrets.k + 32 * i);
      printf("\n");
    }
    printf("commitments =\n");
    for (unsigned int i = 0; i <= params.d + 1; i++) {
      printf("  ");
      print_32_bytes(proof->round.commitments + 32 * i);
      printf("\n");
    }
    printf("\nq = %u\n", q);
    printf("answer =\n");
    if (q == 0) {
      printf("  tau = %u\n", answer->q_eq_0.tau);
      printf("  sigma0 = ");
      print_permutation(&answer->q_eq_0.sigma_0);
      printf("\n  k* = ");
      print_32_bytes(answer->q_eq_0.k_star);
      printf("\n  k0 = ");
      print_32_bytes(answer->q_eq_0.k_0);
      printf("\n  kd = ");
      print_32_bytes(answer->q_eq_0.k_d);
      printf("\n");
    } else {
      printf("  f = %u\n", answer->q_ne_0.f);
      printf("  sigmaq = ");
      print_permutation(&answer->q_ne_0.sigma_q);
      printf("\n  kqm1 = ");
      print_32_bytes(answer->q_ne_0.k_q_minus_1);
      printf("\n  kq = ");
      print_32_bytes(answer->q_ne_0.k_q);
      printf("\n");
    }
    printf("\n");
  }

  zkp_free_proof(proof);
  zkp_free_public_key(public_key);
  zkp_free_secret_key(key);

  return 0;
}
