#include <zkp-volte-patarin-nachef/params.h>

#include <assert.h>

#include "internals.h"

#define PARAMS_S43_AST_H_GENERATOR                                             \
  22, 26, 41, 32, 12, 30, 4, 42, 18, 13, 1, 25, 31, 11, 38, 9, 7, 40, 34, 2,   \
      5, 24, 35, 39, 20, 14, 23, 37, 28, 36, 33, 17, 8, 6, 27, 3, 15, 29, 21,  \
      10, 19, 43, 16

#define PARAMS_S43_AST_F_1                                                     \
  13, 23, 26, 1, 3, 11, 37, 18, 38, 43, 33, 35, 27, 41, 42, 25, 19, 16, 21,    \
      22, 40, 14, 28, 6, 15, 4, 24, 10, 12, 34, 39, 20, 5, 8, 17, 7, 36, 31,   \
      9, 29, 32, 2, 30

static int initialized = 0;

static zkp_params params = {
  .domain = ZKP_PARAMS_S43_AST_DOMAIN,
  .d = ZKP_PARAMS_S43_AST_D,
  .F = { .base = NULL,
         .count = ZKP_PARAMS_S43_AST_ALPHA,
         .domain = ZKP_PARAMS_S43_AST_DOMAIN },
  .H = { .base = NULL,
         .count = ZKP_PARAMS_S43_AST_H_ORDER,
         .domain = ZKP_PARAMS_S43_AST_DOMAIN },
  .G_ = { .random_element = random_element_symmetric_group },
  .display_name = "S43*",
};

static inline void init_dynamically_allocated(void) {
  uint16_t* params_s43ast_h =
      malloc(ZKP_PARAMS_S43_AST_H_ORDER * ZKP_PARAMS_S43_AST_DOMAIN *
             sizeof(uint16_t));
  assert(params_s43ast_h != NULL);
  params.H.base = params_s43ast_h;

  unsigned int s43ast_h_mapping[] = { PARAMS_S43_AST_H_GENERATOR };

  permutation s43ast_h;
  s43ast_h.domain = ZKP_PARAMS_S43_AST_DOMAIN;
  s43ast_h.mapping = s43ast_h_mapping;
  STACK_ALLOC_PERMUTATION(acc, ZKP_PARAMS_S43_AST_DOMAIN);
  identity_permutation(&acc);
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S43_AST_H_ORDER; exp++) {
    store_permutation_interleaved(&params.H, params_s43ast_h, exp, &acc);
    multiply_permutation(&acc, &s43ast_h);
  }
  for (unsigned int i = 1; i <= ZKP_PARAMS_S43_AST_DOMAIN; i++) {
    assert(PERMUTATION_GET(&acc, i) == i);
  }

  uint16_t* params_s43ast_f = malloc(
      ZKP_PARAMS_S43_AST_ALPHA * ZKP_PARAMS_S43_AST_DOMAIN * sizeof(uint16_t));
  assert(params_s43ast_f != NULL);
  params.F.base = params_s43ast_f;

  unsigned int s43ast_f_1_mapping[] = { PARAMS_S43_AST_F_1 };

  permutation s43ast_f_1;
  s43ast_f_1.domain = ZKP_PARAMS_S43_AST_DOMAIN;
  s43ast_f_1.mapping = s43ast_f_1_mapping;
  for (unsigned int exp = 0; exp < ZKP_PARAMS_S43_AST_ALPHA; exp++) {
    identity_permutation(&acc);
    multiply_permutation_from_array_inv(&acc, &params.H, exp);
    multiply_permutation(&acc, &s43ast_f_1);
    multiply_permutation_from_array(&acc, &params.H, exp);
    store_permutation_interleaved(&params.F, params_s43ast_f, exp, &acc);
  }
}

const zkp_params* zkp_params_s43ast(void) {
  if (!initialized) {
    init_dynamically_allocated();
    initialized = 1;
  }

  return &params;
}
