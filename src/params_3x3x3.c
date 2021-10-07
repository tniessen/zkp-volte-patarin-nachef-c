#include <zkp-volte-patarin-nachef/params.h>

#include "internals.h"

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

static const zkp_params params = {
  .domain = ZKP_PARAMS_3X3X3_DOMAIN,
  .d = ZKP_PARAMS_3X3X3_D,
  .F = {
    .base = params_3x3x3_f,
    .count = ZKP_PARAMS_3X3X3_ALPHA,
    .domain = ZKP_PARAMS_3X3X3_DOMAIN
  },
  .H = {
    .base = params_3x3x3_h,
    .count = ZKP_PARAMS_3X3X3_H_ORDER,
    .domain = ZKP_PARAMS_3X3X3_DOMAIN
  },
  .G_ = {
    .random_element = random_element_F_H,
    .context = (void*) &params
  },
  .display_name = "3x3x3 Rubik's Cube"
};

const zkp_params* zkp_params_3x3x3(void) {
  return &params;
}