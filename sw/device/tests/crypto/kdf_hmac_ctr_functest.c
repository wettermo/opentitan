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
 * KDK      = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
 *              0b0b0b0b0b0b0b (22 octets)
 * context  = 0x0102030405060708090a0b0c (12 octets)
 * label    = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
 * L        = 336
 *
 * KM       = 0x54cd4b8b3ad19e565a8542764afb6c
 *              cca4c5ea81832bacf39846d108c5b8
 *              c83dfda9bb6f40be8a4f8e0e0000 (42 octets)
 */
static status_t func_test1(void) {
  uint32_t kdk_data[] = {
      0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x00000b0b,
  };
  uint8_t context_data[] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  };
  uint8_t label_data[] = {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
  };
  uint32_t km_data[] = {
      0x8b4bcd54, 0x569ed13a, 0x7642855a, 0xcc6cfb4a, 0x81eac5a4, 0xf3ac2b83,
      0x08d14698, 0x3dc8b8c5, 0x6fbba9fd, 0x4f8abe40, 0x00000e8e,
  };

  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeHmacSha256,
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
 * Basic test case with HMAC SHA256
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x000102030405060708090a0b0c0d0e0f
 *              101112131415161718191a1b1c1d1e1f
 *              202122232425262728292a2b2c2d2e2f
 *              303132333435363738393a3b3c3d3e3f
 *              404142434445464748494a4b4c4d4e4f (80 octets)
 * context  = 0x606162636465666768696a6b6c6d6e6f
 *              707172737475767778797a7b7c7d7e7f
 *              808182838485868788898a8b8c8d8e8f
 *              909192939495969798999a9b9c9d9e9f
 *              a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
 * label    = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
 *              c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
 *              d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
 *              e0e1e2e3e4e5e6e7e8e9eaebecedeeef
 *              f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
 * L        = 656
 *
 * KM       = 0xfa061438f57a9901b95e8332b3c6a1
 *              94229196bad78d8ece1607d360d9e0
 *              3d4ab3d089b483f91bfe8177faed7a
 *              d4d9bd1ec875e4281a38d0008fcea9
 *              1b09fc8126fd74d56c8197ed9c0a81
 *              ebd5fffc999018 (82 octets)
 */
static status_t func_test2(void) {
  uint32_t kdk_data[] = {
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110,
      0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x23222120, 0x27262524,
      0x2b2a2928, 0x2f2e2d2c, 0x33323130, 0x37363534, 0x3b3a3938,
      0x3f3e3d3c, 0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
  };
  uint8_t context_data[] = {
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
      0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
      0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
      0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  };
  uint8_t label_data[] = {
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
      0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
      0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
      0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  };
  uint32_t km_data[] = {
      0x381406fa, 0x01997af5, 0x32835eb9, 0x94a1c6b3, 0xba969122, 0xce8e8dd7,
      0x60d30716, 0x4a3de0d9, 0xb489d0b3, 0xfe1bf983, 0xedfa7781, 0xbdd9d47a,
      0xe475c81e, 0xd0381a28, 0xa9ce8f00, 0x81fc091b, 0xd574fd26, 0xed97816c,
      0xeb810a9c, 0x99fcffd5, 0x00001890,
  };

  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeHmacSha256,
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
 * Basic test case with HMAC SHA384
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
 *              0b0b0b0b0b0b (22 octets)
 * context  = (0 octets)
 * label    = (0 octets)
 * L        = 336
 *
 * KM       = 0x1f242b13cf0780398a52b84919ebd4b0
 *              d28d5992b49b439f9943e8ae61f2bb6e
 *              eadd33288590a4c8c8610000 (42 octets)
 */
static status_t func_test3(void) {
  uint32_t kdk_data[] = {
      0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x00000b0b,
  };
  uint32_t km_data[] = {
      0x132b241f, 0x398007cf, 0x49b8528a, 0xb0d4eb19, 0x92598dd2, 0x9f439bb4,
      0xaee84399, 0x6ebbf261, 0x2833ddea, 0xc8a49085, 0x000061c8,
  };
  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeHmacSha384,
      .key_derivation_key = kdk_data,
      .kdk_bytelen = 22,
      .kdf_context = NULL,
      .kdf_context_bytelen = 0,
      .kdf_label = NULL,
      .kdf_label_bytelen = 0,
      .keying_material = km_data,
      .km_bytelen = 42,
  };
  return run_test(&test);
}

/**
 * Test case 4:
 *
 * Basic test case with HMAC SHA384
 *
 * KDF Mode = HMAC Counter
 * KDK      = 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
 *              b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0 (48 octets)
 * context  = 0x01020304 (4 octets)
 * label    = 0x05060708 (4 octets)
 * L        = 768
 *
 * KM       = 0xfebfd966ec77e3d8674bd348e3078605
 *              d4ea32e70b416c38031e4a6d130c37dc
 *              edb9c8d0ee740e9110ac3b6799c1ba29
 *              18c6362c2bac3c6321c5db0b4058b339
 *              4d111ac00dbbc23fd09879b1c12b3441
 *              1809d62a371c41beb57639a2a4ec1dbe (96 octets)
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
      0x66d9bffe, 0xd8e377ec, 0x48d34b67, 0x058607e3, 0xe732ead4, 0x386c410b,
      0x6d4a1e03, 0xdc370c13, 0xd0c8b9ed, 0x910e74ee, 0x673bac10, 0x29bac199,
      0x2c36c618, 0x633cac2b, 0x0bdbc521, 0x39b35840, 0xc01a114d, 0x3fc2bb0d,
      0xb17998d0, 0x41342bc1, 0x2ad60918, 0xbe411c37, 0xa23976b5, 0xbe1deca4,
  };

  kdf_test_vector_t test = {
      .key_mode = kOtcryptoKeyModeHmacSha384,
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
 * L        = 1536
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
