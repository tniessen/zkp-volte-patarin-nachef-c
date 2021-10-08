#include "commitment.h"
#include "internals.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define Q_NONE ((unsigned int) -1)

const char* zkp_get_params_name(const zkp_params* params) {
  return params->display_name;
}

static int preallocate_answer(zkp_proof* proof) {
  const zkp_params* params = proof->key->params;
  zkp_answer* answer = &proof->round.answer;

  answer->q_eq_0.sigma_0.domain = params->domain;
  answer->q_eq_0.sigma_0.mapping =
      malloc(params->domain * sizeof(unsigned int));
  if (answer->q_eq_0.sigma_0.mapping == NULL) {
    return 0;
  }

  answer->q_eq_0.k_star = malloc(COMMITMENT_SIZE);
  if (answer->q_eq_0.k_star == NULL) {
    free(answer->q_eq_0.sigma_0.mapping);
    return 0;
  }

  answer->q_eq_0.k_0 = malloc(COMMITMENT_SIZE);
  if (answer->q_eq_0.k_0 == NULL) {
    free(answer->q_eq_0.sigma_0.mapping);
    free(answer->q_eq_0.k_star);
    return 0;
  }

  answer->q_eq_0.k_d = malloc(COMMITMENT_SIZE);
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
      while (i-- != 0) {
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

zkp_proof* zkp_new_proof(const zkp_private_key* key) {
  if (key == NULL) {
    return NULL;
  }

  zkp_proof* proof = malloc(sizeof(zkp_proof));
  if (proof == NULL) {
    return NULL;
  }

  proof->key = key;

  proof->round.secrets.sigma =
      malloc(sizeof(permutation) * (1 + key->params->d));
  if (proof->round.secrets.sigma == NULL) {
    free(proof);
    return NULL;
  }

  proof->round.secrets.k = malloc(COMMITMENT_SIZE * (2 + key->params->d));
  if (proof->round.secrets.k == NULL) {
    free(proof->round.secrets.sigma);
    free(proof);
    return NULL;
  }

  proof->round.commitments = malloc(COMMITMENT_SIZE * (2 + key->params->d));
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
  free(proof->round.secrets.k);
  free(proof->round.commitments);
  free_preallocated_answer(proof);
  free_preallocated_sigma(proof);
  free(proof->round.secrets.sigma);
  free(proof);
}

const zkp_private_key* zkp_generate_private_key(const zkp_params* params) {
  zkp_private_key* key = malloc(sizeof(zkp_private_key));
  if (key == NULL) {
    return NULL;
  }

  key->mut_self = key;

  key->params = params;
  key->i = malloc(params->d * sizeof(unsigned int));
  if (key->i == NULL) {
    free(key);
    return NULL;
  }

  for (unsigned int j = 0; j < params->d; j++) {
    key->i[j] = rand_less_than(params->F.count);
  }

  return key;
}

void zkp_free_private_key(const zkp_private_key* key) {
  memset(key->i, 0, key->params->d * sizeof(unsigned int));
  free(key->i);
  free(key->mut_self);
}

const zkp_public_key* zkp_compute_public_key(const zkp_private_key* priv) {
  zkp_public_key* pub = malloc(sizeof(zkp_public_key));
  if (pub == NULL) {
    return NULL;
  }

  pub->mut_self = pub;

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

void zkp_free_public_key(const zkp_public_key* key) {
  free(key->x0.mapping);
  free(key->mut_self);
}

const unsigned char* zkp_begin_round(zkp_proof* proof) {
  const zkp_params* params = proof->key->params;
  zkp_round_secrets* secrets = &proof->round.secrets;

  secrets->tau = rand_less_than(params->H.count);
  params->G_.random_element(&secrets->sigma[0], params->G_.context);

  for (unsigned int j = 1; j <= params->d; j++) {
    // TODO: simplify these operations
    identity_permutation(&secrets->sigma[j]);
    multiply_permutation_from_array_inv(&secrets->sigma[j], &params->H,
                                        secrets->tau);
    multiply_permutation_from_array(&secrets->sigma[j], &params->F,
                                    proof->key->i[j - 1]);
    multiply_permutation_from_array(&secrets->sigma[j], &params->H,
                                    secrets->tau);
    inverse_of_permutation(&secrets->sigma[j]);
    multiply_permutation(&secrets->sigma[j], &secrets->sigma[j - 1]);
  }

  memset_random(secrets->k, COMMITMENT_SIZE * (params->d + 2));

  // TODO: do not MAC the unsigned int
  commit_hmac_sha256(secrets->k, (unsigned char*) &secrets->tau,
                     sizeof(secrets->tau), proof->round.commitments);

  // TODO: do not MAC the unsigned ints, use bytes (but what about 5x5x5 that
  // has a domain > 255?)
  for (unsigned int i = 0; i <= params->d; i++) {
    commit_hmac_sha256(secrets->k + (i + 1) * COMMITMENT_SIZE,
                       (unsigned char*) secrets->sigma[i].mapping,
                       secrets->sigma[i].domain * sizeof(unsigned int),
                       proof->round.commitments + (i + 1) * COMMITMENT_SIZE);
  }

  proof->round.answer.q = Q_NONE;

  return proof->round.commitments;
}

zkp_verification* zkp_new_verification(const zkp_public_key* key) {
  zkp_verification* verification = malloc(sizeof(zkp_verification));
  if (verification == NULL) {
    return NULL;
  }

  verification->key = key;
  verification->q = Q_NONE;
  verification->n_successful_rounds = 0;

  return verification;
}

unsigned int zkp_choose_question(zkp_verification* verification) {
  return (verification->q = rand_less_than(verification->key->params->d + 1));
}

zkp_answer* zkp_get_answer(zkp_proof* proof, unsigned int q) {
  if (proof->round.answer.q != Q_NONE) {
    return NULL;
  }

  if (q == 0) {
    proof->round.answer.q_eq_0.tau = proof->round.secrets.tau;
    copy_permutation_into(&proof->round.answer.q_eq_0.sigma_0,
                          &proof->round.secrets.sigma[0]);
    memcpy(proof->round.answer.q_eq_0.k_star, proof->round.secrets.k,
           COMMITMENT_SIZE);
    memcpy(proof->round.answer.q_eq_0.k_0,
           proof->round.secrets.k + COMMITMENT_SIZE, COMMITMENT_SIZE);
    memcpy(
        proof->round.answer.q_eq_0.k_d,
        proof->round.secrets.k + COMMITMENT_SIZE * (proof->key->params->d + 1),
        COMMITMENT_SIZE);
  } else if (q <= proof->key->params->d) {
    STACK_ALLOC_PERMUTATION(f_i_q_tau, proof->key->params->domain);
    identity_permutation(&f_i_q_tau);
    multiply_permutation_from_array_inv(&f_i_q_tau, &proof->key->params->H,
                                        proof->round.secrets.tau);
    multiply_permutation_from_array(&f_i_q_tau, &proof->key->params->F,
                                    proof->key->i[q - 1]);
    multiply_permutation_from_array(&f_i_q_tau, &proof->key->params->H,
                                    proof->round.secrets.tau);
    int ok = index_of_permutation_in_array(&f_i_q_tau, &proof->key->params->F,
                                           &proof->round.answer.q_ne_0.f);
    assert(ok);
    copy_permutation_into(&proof->round.answer.q_ne_0.sigma_q,
                          &proof->round.secrets.sigma[q]);
    memcpy(proof->round.answer.q_ne_0.k_q_minus_1,
           proof->round.secrets.k + COMMITMENT_SIZE * q, COMMITMENT_SIZE);
    memcpy(proof->round.answer.q_ne_0.k_q,
           proof->round.secrets.k + COMMITMENT_SIZE * (q + 1), COMMITMENT_SIZE);
  } else {
    return NULL;
  }

  proof->round.answer.q = q;

  return &proof->round.answer;
}

int zkp_verify(zkp_verification* verification, const unsigned char* commitments,
               const zkp_answer* answer) {
  const zkp_params* params = verification->key->params;

  if (answer->q != verification->q) {
    return 0;
  }

  if (answer->q == 0) {
    if (answer->q_eq_0.tau >= params->H.count) {
      return 0;
    }

    STACK_ALLOC_PERMUTATION(sigma_d, params->domain);
    identity_permutation(&sigma_d);
    multiply_permutation_from_array_inv(&sigma_d, &params->H,
                                        answer->q_eq_0.tau);
    multiply_permutation(&sigma_d, &verification->key->x0);
    multiply_permutation_from_array(&sigma_d, &params->H, answer->q_eq_0.tau);
    multiply_permutation(&sigma_d, &answer->q_eq_0.sigma_0);

    unsigned char md[COMMITMENT_SIZE];
    // TODO: do not MAC the unsigned int
    commit_hmac_sha256(answer->q_eq_0.k_star,
                       (const unsigned char*) &answer->q_eq_0.tau,
                       sizeof(answer->q_eq_0.tau), md);
    if (memcmp(md, commitments, COMMITMENT_SIZE) != 0) {
      return 0;
    }

    commit_hmac_sha256(
        answer->q_eq_0.k_0, (unsigned char*) answer->q_eq_0.sigma_0.mapping,
        answer->q_eq_0.sigma_0.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + COMMITMENT_SIZE, COMMITMENT_SIZE) != 0) {
      return 0;
    }

    commit_hmac_sha256(answer->q_eq_0.k_d, (unsigned char*) sigma_d.mapping,
                       sigma_d.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + COMMITMENT_SIZE * (1 + params->d),
               COMMITMENT_SIZE) != 0) {
      return 0;
    }
  } else if (answer->q <= params->d) {
    if (answer->q_ne_0.f >= params->F.count) {
      return 0;
    }

    STACK_ALLOC_PERMUTATION(sigma_q_minus_1, params->domain);
    copy_permutation_from_array(&sigma_q_minus_1, &params->F, answer->q_ne_0.f);
    multiply_permutation(&sigma_q_minus_1, &answer->q_ne_0.sigma_q);

    unsigned char md[COMMITMENT_SIZE];

    commit_hmac_sha256(
        answer->q_ne_0.k_q, (unsigned char*) answer->q_ne_0.sigma_q.mapping,
        answer->q_ne_0.sigma_q.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + COMMITMENT_SIZE * (1 + answer->q),
               COMMITMENT_SIZE) != 0) {
      return 0;
    }

    commit_hmac_sha256(answer->q_ne_0.k_q_minus_1,
                       (unsigned char*) sigma_q_minus_1.mapping,
                       sigma_q_minus_1.domain * sizeof(unsigned int), md);
    if (memcmp(md, commitments + COMMITMENT_SIZE * answer->q,
               COMMITMENT_SIZE) != 0) {
      return 0;
    }
  } else {
    return 0;
  }

  verification->n_successful_rounds++;

  return 1;
}

double zkp_get_impersonation_probability(zkp_verification* verification) {
  unsigned int d = verification->key->params->d;
  double p = (double) d / (double) (d + 1);
  return pow(p, verification->n_successful_rounds);
}

void zkp_free_verification(zkp_verification* verification) {
  free(verification);
}
