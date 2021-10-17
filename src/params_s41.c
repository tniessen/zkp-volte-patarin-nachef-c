#include <zkp-volte-patarin-nachef/params.h>

#include <assert.h>

#include "internals.h"

#define PARAMS_S41_H_GENERATOR                                                 \
  14, 2, 36, 23, 13, 7, 10, 24, 8, 6, 9, 40, 30, 39, 38, 25, 26, 37, 31, 34,   \
      28, 29, 20, 15, 17, 35, 11, 12, 22, 33, 18, 21, 5, 16, 3, 4, 1, 41, 19,  \
      32, 27

#define PARAMS_S41_F_1                                                         \
  11, 20, 14, 28, 27, 17, 29, 23, 30, 40, 31, 4, 26, 5, 38, 37, 34, 1, 10, 41, \
      18, 12, 2, 22, 24, 8, 32, 3, 36, 9, 6, 13, 33, 25, 21, 7, 39, 16, 35,    \
      15, 19

static int initialized = 0;

static zkp_params params = {
  .domain = ZKP_PARAMS_S41_DOMAIN,
  .d = ZKP_PARAMS_S41_D,
  .F = { .base = NULL,
         .count = ZKP_PARAMS_S41_ALPHA,
         .domain = ZKP_PARAMS_S41_DOMAIN },
  .H = { .base = NULL,
         .count = ZKP_PARAMS_S41_H_ORDER,
         .domain = ZKP_PARAMS_S41_DOMAIN },
  .G_ = { .random_element = random_element_symmetric_group },
  .display_name = "S41",
};

static inline void init_dynamically_allocated(void) {
  uint16_t* params_s41_h =
      malloc(ZKP_PARAMS_S41_H_ORDER * ZKP_PARAMS_S41_DOMAIN * sizeof(uint16_t));
  assert(params_s41_h != NULL);
  params.H.base = params_s41_h;

  unsigned int s41_h_mapping[] = { PARAMS_S41_H_GENERATOR };

  permutation s41_h;
  s41_h.domain = ZKP_PARAMS_S41_DOMAIN;
  s41_h.mapping = s41_h_mapping;
  STACK_ALLOC_PERMUTATION(acc, ZKP_PARAMS_S41_DOMAIN);
  identity_permutation(&acc);
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S41_H_ORDER; exp++) {
    store_permutation_interleaved(&params.H, params_s41_h, exp, &acc);
    multiply_permutation(&acc, &s41_h);
  }
  for (unsigned int i = 1; i <= ZKP_PARAMS_S41_DOMAIN; i++) {
    assert(PERMUTATION_GET(&acc, i) == i);
  }

  uint16_t* params_s41_f =
      malloc(ZKP_PARAMS_S41_ALPHA * ZKP_PARAMS_S41_DOMAIN * sizeof(uint16_t));
  assert(params_s41_f != NULL);
  params.F.base = params_s41_f;

  unsigned int s41_f_1_mapping[] = { PARAMS_S41_F_1 };

  permutation s41_f_1;
  s41_f_1.domain = ZKP_PARAMS_S41_DOMAIN;
  s41_f_1.mapping = s41_f_1_mapping;
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S41_ALPHA; exp++) {
    identity_permutation(&acc);
    multiply_permutation_from_array_inv(&acc, &params.H, exp);
    multiply_permutation(&acc, &s41_f_1);
    multiply_permutation_from_array(&acc, &params.H, exp);
    store_permutation_interleaved(&params.F, params_s41_f, exp, &acc);
  }
}

const zkp_params* zkp_params_s41(void) {
  if (!initialized) {
    init_dynamically_allocated();
    initialized = 1;
  }

  return &params;
}
