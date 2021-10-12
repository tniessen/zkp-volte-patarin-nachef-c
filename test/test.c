#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include <zkp-volte-patarin-nachef/params.h>
#include <zkp-volte-patarin-nachef/protocol.h>

#include "vectors_3x3x3.h"
#include "vectors_5x5x5.h"
#include "vectors_s41.h"
#include "vectors_s41ast.h"
#include "vectors_s43ast.h"
#include "vectors_s53ast.h"

static void test_params(const zkp_params* params, unsigned int n_rounds) {
  const zkp_private_key* private_key = zkp_generate_private_key(params);
  assert(private_key);

  const zkp_public_key* public_key = zkp_compute_public_key(private_key);
  assert(public_key);

  assert(zkp_is_key_pair(private_key, public_key));

  zkp_proof* proof = zkp_new_proof(private_key);
  assert(proof);

  zkp_verification* verification = zkp_new_verification(public_key);
  assert(verification);

  for (unsigned int round = 1; round <= n_rounds; round++) {
    assert(zkp_get_impersonation_probability(verification) > pow(2, -30));
    const unsigned char* commitments = zkp_begin_round(proof);
    unsigned int q = zkp_choose_question(verification);
    zkp_answer* answer = zkp_get_answer(proof, q);
    int ok = zkp_verify(verification, commitments, answer);
    assert(ok);
  }

  assert(zkp_get_impersonation_probability(verification) < pow(2, -30));

  zkp_free_verification(verification);
  zkp_free_proof(proof);
  zkp_free_public_key(public_key);
  zkp_free_private_key(private_key);
}

static void test_is_key_pair(const zkp_params* params) {
  const zkp_private_key* a_priv = zkp_generate_private_key(params);
  assert(a_priv);
  const zkp_public_key* a_pub = zkp_compute_public_key(a_priv);
  assert(a_pub);

  const zkp_private_key* b_priv = zkp_generate_private_key(params);
  assert(b_priv);
  const zkp_public_key* b_pub = zkp_compute_public_key(b_priv);
  assert(b_pub);

  assert(zkp_is_key_pair(a_priv, a_pub));
  assert(!zkp_is_key_pair(a_priv, b_pub));
  assert(!zkp_is_key_pair(b_priv, a_pub));
  assert(zkp_is_key_pair(b_priv, b_pub));

  zkp_free_private_key(a_priv);
  zkp_free_public_key(a_pub);
  zkp_free_private_key(b_priv);
  zkp_free_public_key(b_pub);
}

static void test_import_export(const zkp_params* params) {
  const zkp_private_key* private_key = zkp_generate_private_key(params);
  assert(private_key);

  const zkp_public_key* public_key = zkp_compute_public_key(private_key);
  assert(public_key);

  assert(zkp_is_key_pair(private_key, public_key));

  unsigned int size = zkp_get_public_key_size(params);

  unsigned char exported_public_key[size];
  zkp_export_public_key(public_key, exported_public_key);
  zkp_free_public_key(public_key);

  public_key = zkp_import_public_key(params, exported_public_key);
  assert(public_key);

  unsigned char exported_public_key_2[size];
  zkp_export_public_key(public_key, exported_public_key_2);
  assert(memcmp(exported_public_key, exported_public_key_2, size) == 0);

  assert(zkp_is_key_pair(private_key, public_key));

  zkp_free_public_key(public_key);
  zkp_free_private_key(private_key);
}

static void test_precomputed_vectors_3x3x3(void) {
  const unsigned char mat[] = { TEST_3X3X3_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_3x3x3()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_3x3x3(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_3X3X3_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_3X3X3_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_3x3x3_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_3x3x3(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_3x3x3()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

static void test_precomputed_vectors_5x5x5(void) {
  const unsigned char mat[] = { TEST_5X5X5_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_5x5x5()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_5x5x5(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_5X5X5_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_5X5X5_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_5x5x5_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_5x5x5(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_5x5x5()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

static void test_precomputed_vectors_s41(void) {
  const unsigned char mat[] = { TEST_S41_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_s41()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_s41(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_S41_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_S41_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_s41_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_s41(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_s41()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

static void test_precomputed_vectors_s41ast(void) {
  const unsigned char mat[] = { TEST_S41_AST_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_s41ast()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_s41ast(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_S41_AST_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_S41_AST_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_s41ast_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_s41ast(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_s41ast()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

static void test_precomputed_vectors_s43ast(void) {
  const unsigned char mat[] = { TEST_S43_AST_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_s43ast()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_s43ast(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_S43_AST_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_S43_AST_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_s43ast_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_s43ast(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_s43ast()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

static void test_precomputed_vectors_s53ast(void) {
  const unsigned char mat[] = { TEST_S53_AST_PUBLIC_KEY };
  assert(sizeof(mat) == zkp_get_public_key_size(zkp_params_s53ast()));

  const zkp_public_key* key = zkp_import_public_key(zkp_params_s53ast(), mat);
  assert(key);

  zkp_verification* verification = zkp_new_verification(key);
  assert(verification);

  const unsigned char commitments[] = { TEST_S53_AST_COMMITMENTS };

  uint64_t remaining_q = ((uint64_t) 1 << (ZKP_PARAMS_S53_AST_D + 1)) - 1;

  while (remaining_q != 0) {
    unsigned int q = zkp_choose_question(verification);
    unsigned int answer_size = 0;
    const unsigned char* answer = test_s53ast_get_answer(q, &answer_size);
    assert(answer_size == zkp_get_answer_size(zkp_params_s53ast(), q));
    assert(answer_size <= zkp_get_max_answer_size(zkp_params_s53ast()));
    int ok = zkp_import_verify(verification, commitments, answer, answer_size);
    assert(ok);
    remaining_q &= ~(1 << q);
  }

  zkp_free_verification(verification);
  zkp_free_public_key(key);
}

int main(void) {
  const unsigned int n_rounds_3x3x3 = 510;
  test_params(zkp_params_3x3x3(), n_rounds_3x3x3);
  test_is_key_pair(zkp_params_3x3x3());
  test_import_export(zkp_params_3x3x3());

  const unsigned int n_rounds_5x5x5 = 884;
  test_params(zkp_params_5x5x5(), n_rounds_5x5x5);
  test_is_key_pair(zkp_params_5x5x5());
  test_import_export(zkp_params_5x5x5());

  const unsigned int n_rounds_s41 = 260;
  test_params(zkp_params_s41(), n_rounds_s41);
  test_is_key_pair(zkp_params_s41());
  test_import_export(zkp_params_s41());

  const unsigned int n_rounds_s41ast = 239;
  test_params(zkp_params_s41ast(), n_rounds_s41ast);
  test_is_key_pair(zkp_params_s41ast());
  test_import_export(zkp_params_s41ast());

  const unsigned int n_rounds_s43ast = 219;
  test_params(zkp_params_s43ast(), n_rounds_s43ast);
  test_is_key_pair(zkp_params_s43ast());
  test_import_export(zkp_params_s43ast());

  const unsigned int n_rounds_s53ast = 260;
  test_params(zkp_params_s53ast(), n_rounds_s53ast);
  test_is_key_pair(zkp_params_s53ast());
  test_import_export(zkp_params_s53ast());

  test_precomputed_vectors_3x3x3();
  test_precomputed_vectors_5x5x5();
  test_precomputed_vectors_s41();
  test_precomputed_vectors_s41ast();
  test_precomputed_vectors_s43ast();
  test_precomputed_vectors_s53ast();

  return 0;
}
