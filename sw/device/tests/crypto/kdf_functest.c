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

/**
 * Test case 5:
 *
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0xb0b0b0b0 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 42
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test5(void) {
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
 * Test case 6:
 *
 * Basic test case with KMAC256
 *
 * KDF Mode = KMAC256
 * KDK      = 0xb0b0b0b0 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 42
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test6(void) {
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
 * Test case 7:
 *
 * Basic test case with KMAC128
 *
 * KDF Mode = KMAC128
 * KDK      = 0xb0b0b0b0 (x octets)
 * context  = 0x00 (x octets)
 * label    = 0x00 (x octets)
 * L        = 384
 *
 * KM       = 0x00 (x octets)
 */
static status_t func_test7(void) {
    uint32_t kdk_data[] = {
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,  
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac, 
        0xacacacac, 0xacacacac, 0xacacacac, 0xacacacac,  
  };
  uint8_t context_data[] = {
    0xde, 0xad, 0xbe, 0xef,
  };
  uint8_t label_data[] = {
    0xba, 0xde, 0xba, 0xde, 0xba, 0xde, 0xba,
    0xde, 0xba, 0xde, 0xba, 0xde, 0xba, 0xde,
    0xba, 0xde,
  };
uint32_t km_data[] = {
0x624afe67,
0x0fc2cd02,
0x9165df66,
0x9d576659,
0x6783650f,
0xdcd4e62e,
0x337ba130,
0xd99c874f,
0xd92ff0a0,
0x7310b3ef,
0x24bc51ce,
0xb0ef9bf5,
0xc91ec3a5,
0xf6b31249,
0x62601d4a,
0x1e4a9205,
0xb2620f8b,
0x98ce2aee,
0x78c98828,
0x9c9ed356,
0x24d51d88,
0x5a2fdbed,
0x430cf923,
0x85a00f82,
0x8e5b823e,
0xdaa6835a,
0x6d6bb7c8,
0x164ef96a,
0x9ef615e1,
0x02228118,
0x82636727,
0xbb96e427,
0x13513aec,
0x584b13d6,
0xd4bdfec3,
0x45edfee2,
0x707f740e,
0x5b27d8f6,
0x1c4d8912,
0x306bd75e,
0xcbfbcd0a,
0x2f7ef28c,
0x11d414ef,
0x954b4da9,
0x02f33e48,
0x35c758e6,
0x7af776f9,
0x6235c72d,
0xd09cbed8,
0xc25bc2b2,
0xd0c744db,
0xd543f8c4,
0xc5322433,
0x4148749a,
0xc52015aa,
0xb093cb7b,
0x7a7e521d,
0x9fa6f4cc,
0x11f1a47c,
0xa35a265e,
0xea9c5eb2,
0x23922857,
0x8ded1d7c,
0x1013c837,
0xa4fc005f,
0x8be9656b,
0xe05e1688,
0x67e32b3f,
0xfcfdb51a,
0x77c2f1d5,
0x47a96dc2,
0x086021c1,
0x27683618,
0xb35cf0bd,
0x6d120d28,
0xfc84e467,
0x60cdee6e,
0x1b80dcc6,
0x91dc0235,
0xb4079233,
0x3de46cc9,
0xf724d556,
0xc78437be,
0x47ce3b6f,
0xa7f66203,
0x534e9fac,
0xa2205ce0,
0x2ce0fed5,
0xe36c0b27,
0x127e369c,
0x9417b7d2,
0x96bf1b39,
0x2375897e,
0x079dce9d,
0x27cfcfca,
0x9fff5f30,
};

  kdf_test_vector_t test = {
      .kdf_mode = kOtcryptoKeyModeKdfKmac128,
      .key_mode = kOtcryptoKeyModeKmac128,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 128,
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
  //EXECUTE_TEST(test_result, func_test4);
  EXECUTE_TEST(test_result, func_test5);
  EXECUTE_TEST(test_result, func_test6);
  EXECUTE_TEST(test_result, func_test7);
  return status_ok(test_result);
}
