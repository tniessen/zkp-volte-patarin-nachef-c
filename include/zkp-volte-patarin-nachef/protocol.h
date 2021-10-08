#ifndef ZKP_VOLTE_PATARIN_NACHEF_PROTOCOL_H
#define ZKP_VOLTE_PATARIN_NACHEF_PROTOCOL_H

/**
 * Represents parameters for the protocol.
 */
typedef struct zkp_params_s zkp_params;

/**
 * A private key held by the prover.
 */
typedef struct zkp_private_key_s zkp_private_key;

/**
 * A public key, computed by the prover and shared with verifiers.
 */
typedef struct zkp_public_key_s zkp_public_key;

/**
 * Represents an in-progress proof from the perspective of the prover.
 */
typedef struct zkp_proof_s zkp_proof;

/**
 * Represents an in-progress proof from the perspective of the verifier.
 */
typedef struct zkp_verification_s zkp_verification;

/**
 * Represents the answer that is sent by the prover to the verifier.
 */
typedef struct zkp_answer_s zkp_answer;

/**
 * Returns the human-readable name associated with a given parameter set.
 *
 * @param params the parameters
 * @return the display name
 */
const char* zkp_get_params_name(const zkp_params* params);

/**
 * Generates a private key for the given parameters.
 *
 * @param params the parameters
 * @return the generated private key
 */
const zkp_private_key* zkp_generate_private_key(const zkp_params* params);

/**
 * Frees a private key.
 *
 * @param key the private key
 */
void zkp_free_private_key(const zkp_private_key* key);

/**
 * Computes the public key from a private key.
 *
 * @param key the private key
 * @return the computed public key
 */
const zkp_public_key* zkp_compute_public_key(const zkp_private_key* priv);

/**
 * Frees a public key.
 *
 * @param key the public key
 */
void zkp_free_public_key(const zkp_public_key* key);

/**
 * Creates a new instance of the zkp_proof struct and initializes it for use
 * with the given private key.
 *
 * The returned object must be deallocated using zkp_free_proof.
 *
 * @param key the private key
 * @return the created zkp_proof object
 */
zkp_proof* zkp_new_proof(const zkp_private_key* key);

/**
 * Initializes a new round within the given in-progress proof.
 *
 * @param proof the zkp_proof instance
 * @return the generated commitments
 */
const unsigned char* zkp_begin_round(zkp_proof* proof);

/**
 * Produces an answer in response to a question.
 *
 * @param proof the zkp_proof instance
 * @param q the question (challenge)
 * @return the produced answer
 */
zkp_answer* zkp_get_answer(zkp_proof* proof, unsigned int q);

/**
 * Releases resources that were allocated for a proof.
 *
 * @param proof the zkp_proof instance
 */
void zkp_free_proof(zkp_proof* proof);

/**
 * Creates a new instance of the zkp_verification struct and initializes it for
 * use with the given public key.
 *
 * The returned object must be deallocated using zkp_free_verification.
 *
 * @param key the public key
 * @return the created zkp_verification instance
 */
zkp_verification* zkp_new_verification(const zkp_public_key* key);

/**
 * Randomly chooses a question (challenge) for the current round.
 *
 * @param verification the zkp_verification instance
 * @return the question (challenge)
 */
unsigned int zkp_choose_question(zkp_verification* verification);

/**
 * Verifies received commitments against a received answer.
 *
 * @param verification the zkp_verification instance
 * @param commitments the previously received commitments
 * @param answer the received answer
 * @return one of the answer is valid, zero if it is not
 */
int zkp_verify(zkp_verification* verification, const unsigned char* commitments,
               const zkp_answer* answer);

/**
 * Returns an upper bound on the estimated impersonation probability based on
 * the number successful of rounds.
 *
 * @param verification the zkp_verification instance
 * @return the impersonation probability
 */
double zkp_get_impersonation_probability(zkp_verification* verification);

/**
 * Releases resources that were allocated for a verification.
 *
 * @param verification the zkp_verification instance
 */
void zkp_free_verification(zkp_verification* verification);

#endif  // ZKP_VOLTE_PATARIN_NACHEF_PROTOCOL_H
