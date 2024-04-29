// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/tests/penetrationtests/firmware/fi/otp_fi.h"

#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otp_ctrl.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/otp_ctrl_testutils.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/sca/lib/sca.h"
#include "sw/device/tests/penetrationtests/firmware/lib/sca_lib.h"
#include "sw/device/tests/penetrationtests/json/otp_fi_commands.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "otp_ctrl_regs.h"  // Generated.

// OTP memory dump size: 1032 bytes (CREATOR_SW_CFG is not readable on CW310)
#define DUMP_SIZE                                                      \
  OTP_CTRL_PARAM_VENDOR_TEST_SIZE + OTP_CTRL_PARAM_OWNER_SW_CFG_SIZE + \
      OTP_CTRL_PARAM_HW_CFG_SIZE + OTP_CTRL_PARAM_LIFE_CYCLE_SIZE

// #define DUMP_SIZE OTP_CTRL_PARAM_LIFE_CYCLE_SIZE

// NOP macros.
#define NOP1 "addi x0, x0, 0\n"
#define NOP10 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1
#define NOP100 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10
#define NOP1000 \
  NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100

static dif_otp_ctrl_t otp;
uint32_t otp_read32_result_comp[DUMP_SIZE / 4];
uint32_t otp_read32_result_fi[DUMP_SIZE / 4];

void init_otp_mem_dump_buffers(void) {
  for (uint32_t i = 0; i < DUMP_SIZE / 4; i++) {
    otp_read32_result_comp[i] = 0x00000001;
    otp_read32_result_fi[i] = 0x00000001;
  }
}

status_t otp_memory_dump(uint32_t buffer[DUMP_SIZE]) {
  uint32_t buffer_ctr = 0;

  // Read VENDOR_TEST partition
  if (buffer_ctr >= DUMP_SIZE / 4) {
    return OUT_OF_RANGE();
  }
  TRY(otp_ctrl_testutils_dai_read32_array(&otp, kDifOtpCtrlPartitionVendorTest,
                                          0, &buffer[buffer_ctr],
                                          OTP_CTRL_PARAM_VENDOR_TEST_SIZE / 4));
  buffer_ctr += OTP_CTRL_PARAM_VENDOR_TEST_SIZE / 4;

  // Read OWNER_SW_CFG partition
  if (buffer_ctr >= DUMP_SIZE / 4) {
    return OUT_OF_RANGE();
  }
  TRY(otp_ctrl_testutils_dai_read32_array(
      &otp, kDifOtpCtrlPartitionOwnerSwCfg, 0, &buffer[buffer_ctr],
      OTP_CTRL_PARAM_OWNER_SW_CFG_SIZE / 4));
  buffer_ctr += OTP_CTRL_PARAM_OWNER_SW_CFG_SIZE / 4;

  // Read HW_CFG partition
  if (buffer_ctr >= DUMP_SIZE / 4) {
    return OUT_OF_RANGE();
  }
  TRY(otp_ctrl_testutils_dai_read32_array(&otp, kDifOtpCtrlPartitionHwCfg, 0,
                                          &buffer[buffer_ctr],
                                          OTP_CTRL_PARAM_HW_CFG_SIZE / 4));
  buffer_ctr += OTP_CTRL_PARAM_HW_CFG_SIZE / 4;

  // Read LIFE_CYCLE partition
  if (buffer_ctr >= DUMP_SIZE / 4) {
    return OUT_OF_RANGE();
  }
  TRY(otp_ctrl_testutils_dai_read32_array(&otp, kDifOtpCtrlPartitionLifeCycle,
                                          0, &buffer[buffer_ctr],
                                          OTP_CTRL_PARAM_LIFE_CYCLE_SIZE / 4));
  buffer_ctr += OTP_CTRL_PARAM_LIFE_CYCLE_SIZE / 4;

  return OK_STATUS();
}

status_t handle_otp_fi_bit_flip(ujson_t *uj) {
  // Clear registered alerts in alert handler.
  // sca_registered_alerts_t reg_alerts = sca_get_triggered_alerts();

  // Read the OTP memory before FI
  TRY(otp_memory_dump(otp_read32_result_comp));

  // FI code target.
  sca_set_trigger_high();

  // Point for FI
  for (uint32_t i = 0; i < 0xffff; i++) {
    NOP1000;
    NOP1000;
    NOP1000;
    NOP1000;
  }

  // Read the OTP memory after FI
  TRY(otp_memory_dump(otp_read32_result_fi));

  sca_set_trigger_low();

  // Get registered alerts from alert handler.
  // reg_alerts = sca_get_triggered_alerts();

  // Get OTP CTRL status
  dif_otp_ctrl_status_t status;
  TRY(dif_otp_ctrl_get_status(&otp, &status));

  // Send result & status codes to host.
  otp_fi_test_result_t uj_output;
  for (uint32_t i = 0; i < DUMP_SIZE / 4; i++) {
    uj_output.result_comp[i] = otp_read32_result_comp[i];
    uj_output.result_fi[i] = otp_read32_result_fi[i];
  }
  // uj_output.otp_status_codes = status.codes;
  // memcpy(uj_output.otp_error_causes, (uint8_t *)status.causes,
  //        kDifOtpCtrlStatusCodeHasCauseLast + 1);
  // uj_output.alerts[0] = reg_alerts.alerts[0];
  // uj_output.alerts[1] = reg_alerts.alerts[1];
  // uj_output.alerts[2] = reg_alerts.alerts[2];
  RESP_OK(ujson_serialize_otp_fi_test_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_otp_fi_init(ujson_t *uj) {
  sca_select_trigger_type(kScaTriggerTypeSw);
  // As we are using the software defined trigger, the first argument of
  // sca_init is not needed. kScaTriggerSourceAes is selected as a placeholder.
  sca_init(kScaTriggerSourceAes,
           kScaPeripheralIoDiv4 | kScaPeripheralEdn | kScaPeripheralCsrng |
               kScaPeripheralEntropy | kScaPeripheralAes | kScaPeripheralHmac |
               kScaPeripheralKmac | kScaPeripheralOtbn);

  // Configure the alert handler. Alerts triggered by IP blocks are captured
  // and reported to the test.
  sca_configure_alert_handler();

  // Disable the instruction cache and dummy instructions for FI attacks.
  sca_configure_cpu();

  TRY(dif_otp_ctrl_init(
      mmio_region_from_addr(TOP_EARLGREY_OTP_CTRL_CORE_BASE_ADDR), &otp));

  init_otp_mem_dump_buffers();

  return OK_STATUS();
}

status_t handle_otp_fi(ujson_t *uj) {
  otp_fi_subcommand_t cmd;
  TRY(ujson_deserialize_otp_fi_subcommand_t(uj, &cmd));
  switch (cmd) {
    case kOtpFiSubcommandInit:
      return handle_otp_fi_init(uj);
    case kOtpFiSubcommandBitFlip:
      return handle_otp_fi_bit_flip(uj);
    default:
      LOG_ERROR("Unrecognized OTP FI subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
