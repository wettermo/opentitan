// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_RNG_FI_COMMANDS_H_
#define OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_RNG_FI_COMMANDS_H_
#include "sw/device/lib/ujson/ujson_derive.h"
#ifdef __cplusplus
extern "C" {
#endif

// clang-format off

#define RNGFI_SUBCOMMAND(_, value) \
    value(_, Init)
UJSON_SERDE_ENUM(RngFiSubcommand, rng_fi_subcommand_t, RNGFI_SUBCOMMAND);

#define RNGFI_TEST_RESULT(field, string) \
    field(result, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t)
UJSON_SERDE_STRUCT(RngFiTestResult, rng_fi_test_result_t, RNGFI_TEST_RESULT);

#define RNGFI_TEST_RESULT_MULT(field, string) \
    field(result1, uint32_t) \
    field(result2, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t)
UJSON_SERDE_STRUCT(RngFiTestResultMult, rng_fi_test_result_mult_t, RNGFI_TEST_RESULT_MULT);

#define RNGFI_LOOP_COUNTER_OUTPUT(field, string) \
    field(loop_counter, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t)
UJSON_SERDE_STRUCT(RngFiLoopCounterOutput, rng_fi_loop_counter_t, RNGFI_LOOP_COUNTER_OUTPUT);

#define RNGFI_LOOP_COUNTER_MIRRORED_OUTPUT(field, string) \
    field(loop_counter1, uint32_t) \
    field(loop_counter2, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t)
UJSON_SERDE_STRUCT(RngFiLoopCounterMirroredOutput, rng_fi_loop_counter_mirrored_t, RNGFI_LOOP_COUNTER_MIRRORED_OUTPUT);

// clang-format on

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_RNG_FI_COMMANDS_H_
