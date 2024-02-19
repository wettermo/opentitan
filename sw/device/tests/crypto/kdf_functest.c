// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/impl/integrity.h"
#include "sw/device/lib/crypto/impl/keyblob.h"
#include "sw/device/lib/crypto/include/datatypes.h"
#include "sw/device/lib/crypto/include/kdf.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('t', 's', 't')

/**
 * Represents a test for KDF.
 */
typedef struct kdf_test_vector {
  /**
   * Kdf mode for KDF (e.g. kOtcryptoKeyModeKdfCtrHmac).
   */
  otcrypto_key_mode_t kdf_mode;
  /**
   * Key mode for KDF (e.g. kOtcryptoKeyModeHmacSha256).
   */
  otcrypto_key_mode_t key_mode;
  /**
   * Input key derivation key.
   */
  uint32_t *key_derivation_key;
  /**
   * Length of key derivation key in bytes.
   */
  size_t kdk_bytelen;
  /**
   * Context string.
   */
  uint8_t *kdf_context;
  /**
   * Length of context in bytes.
   */
  size_t kdf_context_bytelen;
  /**
   * Label string.
   */
  uint8_t *kdf_label;
  /**
   * Length of label in bytes.
   */
  size_t kdf_label_bytelen;
  /**
   * Expected output keying material.
   */
  uint32_t *keying_material;
  /**
   * Length of keying material in bytes.
   */
  size_t km_bytelen;
} kdf_test_vector_t;

// TODO: don't know if applicable
// Random value for masking, as large as the longest test key. This value
// should not affect the result.
static const uint32_t kTestMask[] = {
    0x8cb847c3, 0xc6d34f36, 0x72edbf7b, 0x9bc0317f, 0x8f003c7f, 0x1d7ba049,
    0xfd463b63, 0xbb720c44, 0x784c215e, 0xeb101d65, 0x35beb911, 0xab481345,
    0xa7ebc3e3, 0x04b2a1b9, 0x764a9630, 0x78b8f9c5, 0x3f2a1d8e, 0x8cb847c3,
    0xc6d34f36, 0x72edbf7b, 0x9bc0317f, 0x8f003c7f, 0x1d7ba049, 0xfd463b63,
    0xbb720c44, 0x784c215e, 0xeb101d65, 0x35beb911, 0xab481345, 0xa7ebc3e3,
    0x04b2a1b9, 0x764a9630, 0x78b8f9c5, 0x3f2a1d8e,
};

/**
 * Call KDF through the API and check the result.
 *
 * @param test Test vector to run.
 * @return Result (OK or error).
 */
static status_t run_test(kdf_test_vector_t *test) {
  if (test->kdk_bytelen > sizeof(kTestMask)) {
    // If we get this error, we probably just need to make `kTestMask` longer.
    return OUT_OF_RANGE();
  }

  // Construct the input key derivation key.
  otcrypto_key_config_t kdk_config = {
      .version = kOtcryptoLibVersion1,
      .key_mode = test->key_mode,
      .key_length = test->kdk_bytelen,
      .hw_backed = kHardenedBoolFalse,
      .exportable = kHardenedBoolFalse,
      .security_level = kOtcryptoKeySecurityLevelLow,
  };
  uint32_t kdk_keyblob[keyblob_num_words(kdk_config)];
  TRY(keyblob_from_key_and_mask(test->key_derivation_key, kTestMask, kdk_config,
                                kdk_keyblob));
  otcrypto_blinded_key_t kdk = {
      .config = kdk_config,
      .keyblob = kdk_keyblob,
      .keyblob_length = sizeof(kdk_keyblob),
  };
  kdk.checksum = integrity_blinded_checksum(&kdk);

  // Construct a blinded key struct for the output keying material. The key mode
  // here doesn't really matter, it just needs to be some symmetric key.
  otcrypto_key_config_t km_config = {
      .version = kOtcryptoLibVersion1,
      .key_mode = kOtcryptoKeyModeAesCtr,
      .key_length = test->km_bytelen,
      .hw_backed = kHardenedBoolFalse,
      .exportable = kHardenedBoolFalse,
      .security_level = kOtcryptoKeySecurityLevelLow,
  };
  uint32_t km_keyblob[keyblob_num_words(km_config)];
  otcrypto_blinded_key_t km = {
      .config = km_config,
      .keyblob = km_keyblob,
      .keyblob_length = sizeof(km_keyblob),
  };

  // Construct a buffer for the context.
  otcrypto_const_byte_buf_t context = {
      .data = test->kdf_context,
      .len = test->kdf_context_bytelen,
  };

  // Construct a buffer for the label.
  otcrypto_const_byte_buf_t label = {
      .data = test->kdf_label,
      .len = test->kdf_label_bytelen,
  };

  // Run the KDF specified by the key mode.
  switch (test->kdf_mode) {
    case kOtcryptoKeyModeKdfCtrHmacSha256:
    case kOtcryptoKeyModeKdfCtrHmacSha384:
    case kOtcryptoKeyModeKdfCtrHmacSha512:
      TRY(otcrypto_kdf_hmac_ctr(kdk, label, context, km.config.key_length,
                                &km));
      break;
    case kOtcryptoKeyModeKdfKmac128:
      TRY(otcrypto_kdf_kmac(kdk, kOtcryptoKmacModeKmac128, label, context,
                            km.config.key_length, &km));
      break;
    case kOtcryptoKeyModeKdfKmac256:
      TRY(otcrypto_kdf_kmac(kdk, kOtcryptoKmacModeKmac256, label, context,
                            km.config.key_length, &km));
      break;
    default:
      LOG_INFO("Should never end up here.");
      return INVALID_ARGUMENT();
  }

  LOG_INFO("KDF operation completed.");

  // Unmask the output key value and compare to the expected value.
  uint32_t *km_share0;
  uint32_t *km_share1;

  TRY(keyblob_to_shares(&km, &km_share0, &km_share1));
  uint32_t unmasked_km[keyblob_share_num_words(km_config)];
  for (size_t i = 0; i < ARRAYSIZE(unmasked_km); i++) {
    unmasked_km[i] = km_share0[i] ^ km_share1[i];
  }

  // TODO ignore the unmasked_km for now, use km.keyblob
  TRY_CHECK_ARRAYS_EQ((unsigned char *)unmasked_km,
                      (unsigned char *)test->keying_material, test->km_bytelen);
  return OK_STATUS();
}

/**
 * Test case 1:
 *
 * Basic test case with HMAC
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 32
 *
 * KM       = 0xfa6d7a61 (4 octets)
 */
static status_t func_test1(void) {
  uint32_t kdk_data[] = {
      0x00000000,
  };
  uint8_t context_data[] = {
      0x03,
  };
  uint8_t label_data[] = {
      0x02,
  };
  uint32_t km_data[] = {
      0xfa6d7a61,
  };
  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfCtrHmacSha256,
      .key_mode = kOtcryptoKeyModeHmacSha256,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 4,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 4,
  };
  return run_test(&test);
}

/**
 * Test case 2:
 *
 * Basic test case with HMAC
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 256
 *
 * KM       = 0xd1c92a5e1940f781dbf366885d2e8e11
 *              fcd77ff36ee7d2b46d2bd220393d2014 (32 octets)
 */
static status_t func_test2(void) {
  uint32_t kdk_data[] = {
      0x00000000,
  };
  uint8_t context_data[] = {
      0x03,
  };
  uint8_t label_data[] = {
      0x02,
  };
  uint32_t km_data[] = {0xd1c92a5e, 0x1940f781, 0xdbf36688, 0x5d2e8e11,
                        0xfcd77ff3, 0x6ee7d2b4, 0x6d2bd220, 0x393d2014};
  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfCtrHmacSha256,
      .key_mode = kOtcryptoKeyModeHmacSha256,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 4,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 32,
  };
  return run_test(&test);
}

/**
 * Test case 3:
 *
 * Basic test case with HMAC 384
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 512
 *
 * KM       = 0xb51b43f331f9b85f52a562278f3c0c397
 *              6ed91d2fdfbdc99c365866ddbf52315cc
 *              aad572acc901cfe9a0bf703e726c5327f
 *              9acd8951cc061b4e0fdc6235b60b0 (64 octets)
 */
static status_t func_test3(void) {
  uint32_t kdk_data[] = {
      0x00000000,
  };
  uint8_t context_data[] = {
      0x03,
  };
  uint8_t label_data[] = {
      0x02,
  };
  uint32_t km_data[] = {
      0x7a45f822, 0x45da8700, 0x25d6ec38, 0x67c14c83, 0xc9223ddd, 0xa5c203e6,
      0xc8b11340, 0x4c6c7612, 0x29adf1b8, 0x98c9e923, 0x2646c72e, 0xaae17b17,
      0x281d9390, 0xf2516d35, 0xb7a6d7ab, 0xeb51d65a,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfCtrHmacSha384,
      .key_mode = kOtcryptoKeyModeHmacSha384,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 4,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 64,
  };
  return run_test(&test);
}

/**
 * Test case 4:
 *
 * Basic test case with HMAC
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0 (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L = 1024
 *
 * KM       = 0x0eef0fae7fb8d1cb002492331a1750f9
 *              78c55aad9c86a805c47f7c3c429bb456
 *              142ae91df39166fe247f18940f91a0c3
 *              b0aaf279d71da4cf9500e9e4eb569089
 *              fc89d80183500469b2d337cd19d712e9
 *              ab8db3bf3620eda6b167767afe3590fb
 *              02b0842d24c15c33a94e8cdcf0a85ad1
 *              d5c7e27c33af4368044b094c67e5c4ab (128 octets)
 */
static status_t func_test4(void) {
  uint32_t kdk_data[] = {
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
  };
  uint8_t context_data[] = {
      0x01,
      0x02,
      0x03,
      0x04,
  };
  uint8_t label_data[] = {
      0x05,
      0x06,
      0x07,
      0x08,
  };
  uint32_t km_data[] = {
      0x0eef0fae, 0x7fb8d1cb, 0x00249233, 0x1a1750f9, 0x78c55aad, 0x9c86a805,
      0xc47f7c3c, 0x429bb456, 0x142ae91d, 0xf39166fe, 0x247f1894, 0x0f91a0c3,
      0xb0aaf279, 0xd71da4cf, 0x9500e9e4, 0xeb569089, 0xfc89d801, 0x83500469,
      0xb2d337cd, 0x19d712e9, 0xab8db3bf, 0x3620eda6, 0xb167767a, 0xfe3590fb,
      0x02b0842d, 0x24c15c33, 0xa94e8cdc, 0xf0a85ad1, 0xd5c7e27c, 0x33af4368,
      0x044b094c, 0x67e5c4ab,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfCtrHmacSha256,
      .key_mode = kOtcryptoKeyModeHmacSha256,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 48,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 128,
  };
  return run_test(&test);
}

/**
 * Test case 5:
 *
 * Basic test case with HMAC
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0 (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L = 1024
 *
 * KM       = 0x0eef0fae7fb8d1cb002492331a1750f9
 *              78c55aad9c86a805c47f7c3c429bb456
 *              142ae91df39166fe247f18940f91a0c3
 *              b0aaf279d71da4cf9500e9e4eb569089
 *              fc89d80183500469b2d337cd19d712e9
 *              ab8db3bf3620eda6b167767afe3590fb
 *              02b0842d24c15c33a94e8cdcf0a85ad1
 *              d5c7e27c33af4368044b094c67e5c4ab (128 octets)
 */
static status_t func_test5(void) {
  uint32_t kdk_data[] = {
      0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe,
      0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe,
      0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe,
      0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe,
      0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe,
      0xfefefefe, 0xfefefefe,
  };
  uint8_t context_data[] = {
      0x01,
      0x02,
      0x03,
      0x04,
  };
  uint8_t label_data[] = {
      0x05,
      0x06,
      0x07,
      0x08,
  };
  uint32_t km_data[] = {
      0x7855821a, 0x993293ce, 0xae4b4ccf, 0x31907097, 0xd2f6884d, 0x5c34aa97,
      0x3e753f1a, 0xa5c222ce, 0xfa0e11ed, 0xe7c9a118, 0xd6946058, 0x7e55a11f,
      0xcf7d3119, 0x22721012, 0x693c68de, 0x80761df7, 0x76dcbeac, 0x060daaa0,
      0x83556ee4, 0x144d4c08, 0xa34f2255, 0x845b82d2, 0x6752b04c, 0xe7689370,
      0xcdbdf311, 0x07b5e476, 0xfb946cf0, 0x6ed244ac, 0xc91245a4, 0x8c2c6417,
      0xa07d19ec, 0xec844e1a, 0xb57d34ad, 0xf90479d4, 0xca6d887b, 0x4f19a4e8,
      0xb70f90df, 0x186ae805, 0xc2c35982, 0x06bd4c63, 0xf205de6a, 0xdbe56adb,
      0x5da034ed, 0x3cc7a4ec, 0xd6ebc3c4, 0xd164bb36, 0x2a950a7c, 0xa8d5c2d6,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfCtrHmacSha512,
      .key_mode = kOtcryptoKeyModeHmacSha512,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 128,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 192,
  };
  return run_test(&test);
}

/**
 * Test case 6:
 *
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0xb0b0b0b0... (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L        = 1024
 *
 * KM       = 0x... (128 octets)
 */
static status_t func_test6(void) {
  uint32_t kdk_data[] = {
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
  };
  uint8_t context_data[] = {
      0x01,
      0x02,
      0x03,
      0x04,
  };
  uint8_t label_data[] = {
      0x05,
      0x06,
      0x07,
      0x08,
  };
  uint32_t km_data[] = {
      0xa10e8bcb, 0xcc91127d, 0x1f73a4f8, 0x59f02e86, 0xbe06bed5, 0xf56a76f4,
      0x3241b0c9, 0x2bc02b00, 0x2b2d9c29, 0xf3aba5aa, 0xd645a87e, 0xadcd72b6,
      0x17c15e5d, 0x52994546, 0x9c668651, 0x10dfd6dd, 0x3ca68f62, 0x3a6ab492,
      0x030690d7, 0x3dd62e58, 0x10cff69d, 0x26c58170, 0x9c7e5be7, 0x82872105,
      0x8ffb9628, 0xecf5aed2, 0xabd35711, 0x8fefb35a, 0xb28b2002, 0x08c9722b,
      0x009118a6, 0x9b31d802,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfKmac128,
      .key_mode = kOtcryptoKeyModeKmac128,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 48,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 128,
  };
  return run_test(&test);
}

/**
 * Test case 7:
 *
 * Basic test case with KMAC256
 *
 * KDF Mode = KMAC256
 * KDK      = 0xb0b0b0b0... (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L        = 512
 *
 * KM       = 0... (64 octets)
 */
static status_t func_test7(void) {
  uint32_t kdk_data[] = {
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
      0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
  };
  uint8_t context_data[] = {
      0x01,
      0x02,
      0x03,
      0x04,
  };
  uint8_t label_data[] = {
      0x05,
      0x06,
      0x07,
      0x08,
  };
  uint32_t km_data[] = {
      0xa5d5eccd, 0x0fe295d4, 0x4009f9b3, 0xa2ca8e11, 0x77c7bcdb, 0x1a55575d,
      0x09f35f1d, 0xbd891c43, 0x215cfb2d, 0x57c36f47, 0x347c815a, 0xf49e6a70,
      0x1e6f9ea8, 0xdecf767f, 0xddbc7258, 0x042381f6,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfKmac256,
      .key_mode = kOtcryptoKeyModeKmac256,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 48,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 64,
  };
  return run_test(&test);
}

/**
 * Test case 8:
 *
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0x... (128 octets)
 * context  = 0xdeadbeef (4 octets)
 * label    = 0xbadebadebadebadebadebadebadebade (16 octets)
 * L        = 3072
 *
 * KM       = 0x... (384 octets)
 */
static status_t func_test8(void) {
  uint32_t kdk_data[] = {
      0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
      0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
      0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
  };
  uint8_t context_data[] = {
      0xde,
      0xad,
      0xbe,
      0xef,
  };
  uint8_t label_data[] = {
      0xba, 0xde, 0xba, 0xde, 0xba, 0xde, 0xba, 0xde,
      0xba, 0xde, 0xba, 0xde, 0xba, 0xde, 0xba, 0xde,
  };
  uint32_t km_data[] = {
      0xdebd6f0c, 0xaf81ef5c, 0x7d7f0733, 0xb904c32c, 0x5d886eb8, 0xfb506215,
      0x3dd5863d, 0xbd29e428, 0xb2e86d61, 0xe4919f85, 0x142f84ce, 0x3d9d69fa,
      0x7c9cd079, 0x4deccd52, 0xfa60bde6, 0x64e34e60, 0xa3b84228, 0xcbcd9386,
      0x6255b009, 0x98faeb82, 0x1c794275, 0xaec8172b, 0x5ac09a67, 0x9d307a0a,
      0xe4767bfe, 0xdb5f8a4e, 0xe49eda91, 0x78b21e04, 0xc7771f5a, 0x57c16039,
      0x99913a79, 0xa306b2a8, 0x433d4e66, 0x4633db36, 0x7a39f036, 0xb30d5f7b,
      0x228ccb91, 0x6ec1024f, 0x603735c8, 0xcd80f315, 0x7d4f7782, 0x6fcfeaf9,
      0x653ea9ca, 0x979551fd, 0x35525075, 0x94ae39ec, 0xdad0edbf, 0xc098e3b0,
      0x640b0325, 0x8ba526d6, 0x2a2994bf, 0x0c9bdc69, 0x276275ea, 0xcc26c443,
      0x329e7d96, 0xe2cb3181, 0xf3e72ad9, 0x24b138eb, 0xfa2c6ae2, 0xf4fc6d93,
      0x1a5c45c7, 0xdfc84350, 0x0ff11db6, 0x9984cc42, 0xf02b0fcf, 0x81b9b1a4,
      0xd82277e8, 0xd74a81cf, 0x4357274b, 0xb1e85592, 0xf5a4e451, 0x3239bd9f,
      0xac07618e, 0xc301e2be, 0x61fc5a49, 0x0a3a240a, 0xb1689317, 0x0f9717f9,
      0x6a66e742, 0x2d4aaa96, 0xdce4a7f5, 0x3395a93d, 0xbc1bcf7d, 0xb502234f,
      0x497d9069, 0x04cee46f, 0xca150fa6, 0x4ea32145, 0xc3054fff, 0x95272e6b,
      0xdc086319, 0x0237a53e, 0xc80eb29c, 0xa408791f, 0xf97dc6d2, 0x6b875e21,
  };

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfKmac128,
      .key_mode = kOtcryptoKeyModeKmac128,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 64,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 384,
  };
  return run_test(&test);
}

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  // Start the entropy complex.
  CHECK_STATUS_OK(entropy_complex_init());

  status_t test_result = OK_STATUS();
  EXECUTE_TEST(test_result, func_test1);
  EXECUTE_TEST(test_result, func_test2);
  EXECUTE_TEST(test_result, func_test3);
  EXECUTE_TEST(test_result, func_test4);
  EXECUTE_TEST(test_result, func_test5);
  EXECUTE_TEST(test_result, func_test6);
  EXECUTE_TEST(test_result, func_test7);
  EXECUTE_TEST(test_result, func_test8);
  return status_ok(test_result);
}
