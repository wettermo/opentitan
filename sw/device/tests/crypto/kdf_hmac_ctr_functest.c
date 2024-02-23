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
    case kOtcryptoKeyModeHmacSha256:
    case kOtcryptoKeyModeHmacSha384:
    case kOtcryptoKeyModeHmacSha512:
      TRY(otcrypto_kdf_hmac_ctr(kdk, label, context, km.config.key_length,
                                &km));
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
 * Basic test case with HMAC SHA256
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 32
 *
 * KM       = 0x617a6dfa (4 octets)
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
 * Basic test case with HMAC SHA256
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 256
 *
 * KM       = 0x5e2ac9d181f740198866f3db118e2e5d
 *              f37fd7fcb4d2e76e20d22b6d14203d39 (32 octets)
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
  uint32_t km_data[] = {
      0xd1c92a5e, 0x1940f781, 0xdbf36688, 0x5d2e8e11,
      0xfcd77ff3, 0x6ee7d2b4, 0x6d2bd220, 0x393d2014,
  };

  kdf_test_vector_t test = {
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
 * Basic test case with HMAC SHA384
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x00000000 (4 octets)
 * context  = 0x03 (1 octets)
 * label    = 0x02 (1 octets)
 * L        = 512
 *
 * KM       = 0x22f8457a0087da4538ecd625834cc167
 *              dd3d22c9e603c2a54013b1c812766c4c
 *              b8f1ad2923e9c9982ec74626177be1aa
 *              90931d28356d51f2abd7a6b75ad651eb (64 octets)
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
 * Basic test case with HMAC SHA256
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0 (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L = 1024
 *
 * KM       = 0x5c1a4a238fea1872cec881f7b382674f
 *              f202cd574bc4924e5c8c17f9a0cbb879
 *              86bce83bf0d688b1442d81830ead502d
 *              bb8ded1411953a0fd51e7be8a5f5b14f
 *              52df3ab6a3dde567a4406ea94ba10a90
 *              2ce9adff6ede3a6681eb926c20f6975c (128 octets)
 */
static status_t func_test4(void) {
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
      0x234a1a5c, 0x7218ea8f, 0xf781c8ce, 0x4f6782b3, 0x57cd02f2, 0x4e92c44b,
      0xf9178c5c, 0x79b8cba0, 0x3be8bc86, 0xb188d6f0, 0x83812d44, 0x2d50ad0e,
      0x14ed8dbb, 0x0f3a9511, 0xe87b1ed5, 0x4fb1f5a5, 0xb63adf52, 0x67e5dda3,
      0xa96e40a4, 0x900aa14b, 0xffade92c, 0x663ade6e, 0x6c92eb81, 0x5c97f620,
  };

  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeHmacSha256,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 48,
      .kdf_context = context_data,
      .kdf_context_bytelen = sizeof(context_data),
      .kdf_label = label_data,
      .kdf_label_bytelen = sizeof(label_data),
      .keying_material = km_data,
      .km_bytelen = 96,
  };
  return run_test(&test);
}

/**
 * Test case 5:
 *
 * Basic test case with HMAC SHA512
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0 (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L = 1024
 *
 * KM       = 0x1a825578ce933299cf4c4bae97709031
 *              4d88f6d297aa345c1a3f753ece22c2a5
 *              ed110efa18a1c9e7586094d61fa1557e
 *              19317dcf12107222de683c69f71d7680
 *              acbedc76a0aa0d06e46e5583084c4d14
 *              55224fa3d2825b844cb05267709368e7
 *              11f3bdcd76e4b507f06c94fbac44d26e
 *              a44512c917642c8cec197da01a4e84ec
 *              ad347db5d47904f97b886dcae8a4194f
 *              df900fb705e86a188259c3c2634cbd06
 *              6ade05f2db6ae5dbed34a05deca4c73c
 *              c4c3ebd636bb64d17c0a952ad6c2d5a8 (128 octets)
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
  return status_ok(test_result);
}
