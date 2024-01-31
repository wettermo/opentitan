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
   * Key mode for KDF (e.g. kOtcryptoKeyModeKdfCtrHmac).
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
  switch (test->key_mode) {
    case kOtcryptoKeyModeKdfCtrHmac:
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
 * KDK      = 0x00 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 42
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test1(void) {
  uint32_t kdk_data[] = {
      0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x00000b0b,
  };
  uint8_t context_data[] = {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
  };
  uint8_t label_data[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint32_t km_data[] = {
      0x255fb23c, 0x7ad5acfa, 0x644f4390, 0x2a2f36d0, 0x900a2d2d, 0x4c5a1acf,
      0x562db05d, 0xbfc5c4ec, 0x08720034, 0x1887b8d5, 0x00006558,
  };
  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeKdfCtrHmac,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 22,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 42,
  };
  return run_test(&test);
}

/**
 * Test case 2:
 *
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0x00 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 82
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test2(void) {
  uint32_t kdk_data[] = {
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110,
      0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x23222120, 0x27262524,
      0x2b2a2928, 0x2f2e2d2c, 0x33323130, 0x37363534, 0x3b3a3938,
      0x3f3e3d3c, 0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
  };
  uint8_t context_data[] = {
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
      0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
      0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
      0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  };
  uint8_t label_data[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint32_t km_data[] = {
      0x8d391eb1, 0xa12703c8, 0x8cf7e7c8, 0x34496a59, 0xda2e014f, 0xd8fa4e2d,
      0x4ccc50a0, 0x7ca9af19, 0x995a0459, 0x7282c7ca, 0xc641cb71, 0x090e595e,
      0x607532da, 0xb8092f0c, 0xa9937736, 0x71dba3ac, 0x81c530cc, 0x873eec79,
      0xd5014cc1, 0x4f43f3c1, 0x0000871d,

  };
  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeKdfCtrHmac,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 80,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 82,
  };
  return run_test(&test);
}

/**
 * Test case 3:
 *
 * Basic test case with KMAC256
 *
 * KDF Mode = KMAC256
 * KDK      = 0x00 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 42
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test3(void) {
  uint32_t kdk_data[] = {
      0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x00000b0b,
  };
  uint8_t label_data[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint32_t km_data[] = {
      0x75e7a48d, 0x8fc163a5, 0x2a805f71, 0x315a3c06, 0x5c1fa1b8, 0x9e87e15e,
      0x5f4e45c3, 0x2d8d733c, 0x9513209d, 0x1ab6a4fa, 0x0000c896,
  };
  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeKdfCtrHmac,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 22,
      .kdf_context = NULL,
      .kdf_context_bytelen = 0,
      .kdf_label = label_data,
      .kdf_label_bytelen = ARRAYSIZE(label_data),
      .keying_material = km_data,
      .km_bytelen = 42,
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
  return status_ok(test_result);
}
