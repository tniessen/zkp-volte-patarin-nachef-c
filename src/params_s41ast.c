#include <zkp-volte-patarin-nachef/params.h>

#include <assert.h>

#include "internals.h"

#define PARAMS_S41_AST_H_GENERATOR                                             \
  33, 16, 28, 39, 10, 34, 17, 11, 4, 13, 25, 32, 5, 7, 23, 14, 38, 35, 24, 21, \
      3, 18, 30, 36, 22, 8, 40, 19, 31, 2, 37, 15, 26, 6, 41, 20, 1, 12, 27,   \
      9, 29

#define PARAMS_S41_AST_F_1                                                     \
  4, 8, 5, 36, 20, 39, 27, 28, 32, 15, 10, 25, 24, 1, 3, 13, 33, 30, 7, 34,    \
      17, 21, 16, 29, 41, 35, 2, 26, 22, 18, 14, 40, 38, 11, 9, 31, 23, 37,    \
      19, 6, 12

static int initialized = 0;

static zkp_params params = {
  .domain = ZKP_PARAMS_S41_AST_DOMAIN,
  .d = ZKP_PARAMS_S41_AST_D,
  .F = { .base = NULL,
         .count = ZKP_PARAMS_S41_AST_ALPHA,
         .domain = ZKP_PARAMS_S41_AST_DOMAIN },
  .H = { .base = NULL,
         .count = ZKP_PARAMS_S41_AST_H_ORDER,
         .domain = ZKP_PARAMS_S41_AST_DOMAIN },
  .G_ = { .random_element = random_element_symmetric_group },
  .display_name = "S41*",
};

static inline void init_dynamically_allocated(void) {
  uint16_t* params_s41ast_h =
      malloc(ZKP_PARAMS_S41_AST_H_ORDER * ZKP_PARAMS_S41_AST_DOMAIN *
             sizeof(uint16_t));
  assert(params_s41ast_h != NULL);
  params.H.base = params_s41ast_h;

  unsigned int s41ast_h_mapping[] = { PARAMS_S41_AST_H_GENERATOR };

  permutation s41ast_h;
  s41ast_h.domain = ZKP_PARAMS_S41_AST_DOMAIN;
  s41ast_h.mapping = s41ast_h_mapping;
  STACK_ALLOC_PERMUTATION(acc, ZKP_PARAMS_S41_AST_DOMAIN);
  identity_permutation(&acc);
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S41_AST_H_ORDER; exp++) {
    store_permutation_interleaved(&params.H, params_s41ast_h, exp, &acc);
    multiply_permutation(&acc, &s41ast_h);
  }
  for (unsigned int i = 1; i <= ZKP_PARAMS_S41_AST_DOMAIN; i++) {
    assert(PERMUTATION_GET(&acc, i) == i);
  }

  uint16_t* params_s41ast_f = malloc(
      ZKP_PARAMS_S41_AST_ALPHA * ZKP_PARAMS_S41_AST_DOMAIN * sizeof(uint16_t));
  assert(params_s41ast_f != NULL);
  params.F.base = params_s41ast_f;

  unsigned int s41ast_f_1_mapping[] = { PARAMS_S41_AST_F_1 };

  permutation s41ast_f_1;
  s41ast_f_1.domain = ZKP_PARAMS_S41_AST_DOMAIN;
  s41ast_f_1.mapping = s41ast_f_1_mapping;
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S41_AST_ALPHA; exp++) {
    identity_permutation(&acc);
    multiply_permutation_from_array_inv(&acc, &params.H, exp);
    multiply_permutation(&acc, &s41ast_f_1);
    multiply_permutation_from_array(&acc, &params.H, exp);
    store_permutation_interleaved(&params.F, params_s41ast_f, exp, &acc);
  }
}

const zkp_params* zkp_params_s41ast(void) {
  if (!initialized) {
    init_dynamically_allocated();
    initialized = 1;
  }

  return &params;
}
