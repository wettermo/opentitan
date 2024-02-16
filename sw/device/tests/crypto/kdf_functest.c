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

  // TODO unmasked_km changed to km.keyblob for now
  TRY_CHECK_ARRAYS_EQ((unsigned char *)km.keyblob,
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
 * L        = 128
 *
 * KM       = 0x00 (x octets)
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
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0x00 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 0
 *
 * KM       = 0x00 (x octets)
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
      0x00000000,
  };
  uint8_t context_data[] = {
      0x03,
  };
  uint8_t label_data[] = {
      0x02,
  };
  uint32_t km_data[] = {
      0xb51b43f3, 0x31f9b85f, 0x52a56227, 0x8f3c0c39, 0x76ed91d2, 0xfdfbdc99,
      0xc365866d, 0xdbf52315, 0xccaad572, 0xacc901cf, 0xe9a0bf70, 0x3e726c53,
      0x27f9acd8, 0x951cc061, 0xb4e0fdc6, 0x235b60b0,
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
      .km_bytelen = 64,
  };
  return run_test(&test);
}

/**
 * Test case 4:
 *
 * Basic test case with HMAC256
 *
 * KDF Mode = HMAC256
 * KDK      = 0xb0b0b0b0 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 42
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test4(void) {
  uint32_t kdk_data[] = {
    0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0,
     0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0, 0xb0b0b0b0
  };
  uint8_t context_data[] = {
      0x01, 0x02, 0x03, 0x04,
  };
  uint8_t label_data[] = {
      0x05, 0x06, 0x07, 0x08,
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

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  // Start the entropy complex.
  CHECK_STATUS_OK(entropy_complex_init());

  status_t test_result = OK_STATUS();
  EXECUTE_TEST(test_result, func_test1);
  EXECUTE_TEST(test_result, func_test2);
  EXECUTE_TEST(test_result, func_test3);
  EXECUTE_TEST(test_result, func_test4);
  return status_ok(test_result);
}
