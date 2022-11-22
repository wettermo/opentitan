// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_PTRS_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_PTRS_H_

#include <stddef.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/sigverify/rsa_key.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * Key types.
 *
 * The life cycle states in which a key can be used depend on its type.
 *
 * Encoding generated with
 * $ ./util/design/sparse-fsm-encode.py -d 6 -m 3 -n 32 \
 *     -s 1985033815 --language=c
 *
 * Minimum Hamming distance: 15
 * Maximum Hamming distance: 18
 * Minimum Hamming weight: 13
 * Maximum Hamming weight: 16
 */
typedef enum sigverify_key_type {
  /**
   * A key used for manufacturing, testing, and RMA.
   *
   * Keys of this type can be used only in TEST_UNLOCKED* and RMA life cycle
   * states.
   */
  kSigverifyKeyTypeTest = 0x3ff0c819,
  /**
   * A production key.
   *
   * Keys of this type can be used in all operational life cycle states, i.e.
   * states in which CPU execution is enabled.
   */
  kSigverifyKeyTypeProd = 0x43a839ad,
  /**
   * A development key.
   *
   * Keys of this type can be used only in the DEV life cycle state.
   */
  kSigverifyKeyTypeDev = 0x7a01a471,
} sigverify_key_type_t;

/**
 * An RSA public key stored in ROM.
 */
typedef struct sigverify_rom_key {
  /**
   * An RSA public key.
   */
  sigverify_rsa_key_t key;
  /**
   * Type of the key.
   */
  sigverify_key_type_t key_type;
} sigverify_rom_key_t;

/**
 * Number of RSA public keys.
 */
extern const size_t kSigverifyRsaKeysCnt;

/**
 * Step size to use when checking RSA public keys.
 *
 * This must be coprime with and less than `kSigverifyNumRsaKeys`.
 * Note: Step size is not applicable when `kSigverifyNumRsaKeys` is 1.
 */
extern const size_t kSigverifyRsaKeysStep;

/**
 * Public keys for signature verification.
 */
extern const sigverify_rom_key_t kSigverifyRsaKeys[];

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_PTRS_H_
