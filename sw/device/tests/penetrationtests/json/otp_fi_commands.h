// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_OTP_FI_COMMANDS_H_
#define OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_OTP_FI_COMMANDS_H_
#include "sw/device/lib/ujson/ujson_derive.h"
#ifdef __cplusplus
extern "C" {
#endif

// clang-format off

#define OTPFI_SUBCOMMAND(_, value) \
    value(_, Init) \
    value(_, BitFlip)
UJSON_SERDE_ENUM(OtpFiSubcommand, otp_fi_subcommand_t, OTPFI_SUBCOMMAND);

// #define OTPFI_TEST_RESULT(field, string) \
//     field(result_comp, uint32_t, 458) \
//     field(result_fi, uint32_t, 458) \
//     field(otp_status_codes, uint32_t) \
//     field(otp_error_causes, uint8_t, 10) \
//     field(alerts, uint32_t, 3)
// UJSON_SERDE_STRUCT(OtpFiTestResult, otp_fi_test_result_t, OTPFI_TEST_RESULT);

#define OTPFI_TEST_RESULT(field, string) \
    field(result_comp, uint32_t, 258) \
    field(result_fi, uint32_t, 258)
UJSON_SERDE_STRUCT(OtpFiTestResult, otp_fi_test_result_t, OTPFI_TEST_RESULT);

// #define OTPFI_TEST_RESULT(field, string) \
//     field(result_comp, uint32_t, 1) \
//     field(result_fi, uint32_t, 1)
// UJSON_SERDE_STRUCT(OtpFiTestResult, otp_fi_test_result_t, OTPFI_TEST_RESULT);

// clang-format on

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_OTP_FI_COMMANDS_H_
