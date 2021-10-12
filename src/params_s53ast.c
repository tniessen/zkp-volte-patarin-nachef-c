#include <zkp-volte-patarin-nachef/params.h>

#include <assert.h>

#include "internals.h"

#define PARAMS_S53_AST_H_GENERATOR                                             \
  26, 4, 50, 14, 40, 42, 45, 28, 21, 11, 1, 3, 38, 51, 52, 31, 39, 27, 12, 48, \
      33, 5, 7, 32, 19, 18, 35, 13, 24, 49, 41, 20, 34, 36, 6, 9, 17, 46, 8,   \
      15, 2, 10, 47, 16, 53, 37, 23, 43, 25, 30, 22, 44, 29

#define PARAMS_S53_AST_F_1                                                     \
  52, 36, 1, 31, 8, 22, 3, 16, 27, 41, 26, 7, 34, 44, 48, 11, 19, 30, 24, 42,  \
      49, 39, 17, 40, 38, 37, 28, 23, 32, 51, 45, 10, 43, 33, 18, 6, 53, 5, 4, \
      12, 13, 46, 47, 29, 2, 15, 14, 21, 20, 35, 50, 9, 25

static int initialized = 0;

static zkp_params params = {
  .domain = ZKP_PARAMS_S53_AST_DOMAIN,
  .d = ZKP_PARAMS_S53_AST_D,
  .F = { .base = NULL,
         .count = ZKP_PARAMS_S53_AST_ALPHA,
         .domain = ZKP_PARAMS_S53_AST_DOMAIN },
  .H = { .base = NULL,
         .count = ZKP_PARAMS_S53_AST_H_ORDER,
         .domain = ZKP_PARAMS_S53_AST_DOMAIN },
  .G_ = { .random_element = random_element_symmetric_group },
  .display_name = "S53*",
};

static inline void init_dynamically_allocated(void) {
  unsigned int* params_s53ast_h =
      malloc(ZKP_PARAMS_S53_AST_H_ORDER * ZKP_PARAMS_S53_AST_DOMAIN *
             sizeof(unsigned int));
  assert(params_s53ast_h != NULL);
  params.H.base = params_s53ast_h;

  unsigned int s53ast_h_mapping[] = { PARAMS_S53_AST_H_GENERATOR };

  permutation s53ast_h;
  s53ast_h.domain = ZKP_PARAMS_S53_AST_DOMAIN;
  s53ast_h.mapping = s53ast_h_mapping;
  STACK_ALLOC_PERMUTATION(acc, ZKP_PARAMS_S53_AST_DOMAIN);
  identity_permutation(&acc);
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S53_AST_H_ORDER; exp++) {
    store_permutation_interleaved(&params.H, params_s53ast_h, exp, &acc);
    multiply_permutation(&acc, &s53ast_h);
  }
  for (unsigned int i = 1; i <= ZKP_PARAMS_S53_AST_DOMAIN; i++) {
    assert(PERMUTATION_GET(&acc, i) == i);
  }

  unsigned int* params_s53ast_f =
      malloc(ZKP_PARAMS_S53_AST_ALPHA * ZKP_PARAMS_S53_AST_DOMAIN *
             sizeof(unsigned int));
  assert(params_s53ast_f != NULL);
  params.F.base = params_s53ast_f;

  unsigned int s53ast_f_1_mapping[] = { PARAMS_S53_AST_F_1 };

  permutation s53ast_f_1;
  s53ast_f_1.domain = ZKP_PARAMS_S53_AST_DOMAIN;
  s53ast_f_1.mapping = s53ast_f_1_mapping;
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S53_AST_ALPHA; exp++) {
    identity_permutation(&acc);
    multiply_permutation_from_array_inv(&acc, &params.H, exp);
    multiply_permutation(&acc, &s53ast_f_1);
    multiply_permutation_from_array(&acc, &params.H, exp);
    store_permutation_interleaved(&params.F, params_s53ast_f, exp, &acc);
  }
}

const zkp_params* zkp_params_s53ast(void) {
  if (!initialized) {
    init_dynamically_allocated();
    initialized = 1;
  }

  return &params;
}
