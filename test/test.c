#include <assert.h>
#include <math.h>

#include <zkp-volte-patarin-nachef/params.h>
#include <zkp-volte-patarin-nachef/protocol.h>

static void test_params(const zkp_params* params, unsigned int n_rounds) {
  const zkp_private_key* private_key = zkp_generate_private_key(params);
  assert(private_key);

  const zkp_public_key* public_key = zkp_compute_public_key(private_key);
  assert(public_key);

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

int main(void) {
  const unsigned int n_rounds_3x3x3 = 510;
  test_params(zkp_params_3x3x3(), n_rounds_3x3x3);

  const unsigned int n_rounds_5x5x5 = 884;
  test_params(zkp_params_5x5x5(), n_rounds_5x5x5);

  const unsigned int n_rounds_s41 = 260;
  test_params(zkp_params_s41(), n_rounds_s41);

  return 0;
}
