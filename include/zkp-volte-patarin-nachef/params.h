#ifndef ZKP_VOLTE_PATARIN_NACHEF_PARAMS_H
#define ZKP_VOLTE_PATARIN_NACHEF_PARAMS_H

#include "protocol.h"

#define ZKP_PARAMS_3X3X3_DOMAIN 48
#define ZKP_PARAMS_3X3X3_ALPHA 6
#define ZKP_PARAMS_3X3X3_H_ORDER 24
#define ZKP_PARAMS_3X3X3_D 24

/**
 * Returns zkp_params representing the 3x3x3 Rubik's cube.
 *
 * @return an instance of zkp_params that represent the 3x3x3 Rubik's cube
 */
const zkp_params* zkp_params_3x3x3(void);

#define ZKP_PARAMS_5X5X5_DOMAIN 288
#define ZKP_PARAMS_5X5X5_ALPHA 12
#define ZKP_PARAMS_5X5X5_H_ORDER 48
#define ZKP_PARAMS_5X5X5_D 48

/**
 * Returns zkp_params representing the 5x5x5 Rubik's cube.
 *
 * @return an instance of zkp_params that represent the 5x5x5 Rubik's cube
 */
const zkp_params* zkp_params_5x5x5(void);

#define ZKP_PARAMS_S41_DOMAIN 41
#define ZKP_PARAMS_S41_ALPHA 9240
#define ZKP_PARAMS_S41_H_ORDER 9240
#define ZKP_PARAMS_S41_D 12

/**
 * Returns zkp_params representing the S41 puzzle.
 *
 * @return an instance of zkp_params that represent the S41 puzzle
 */
const zkp_params* zkp_params_s41(void);

#endif  // ZKP_VOLTE_PATARIN_NACHEF_PARAMS_H
