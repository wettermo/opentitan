// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_BOOT_POLICY_PTRS_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_BOOT_POLICY_PTRS_H_

#include "sw/device/lib/base/global_mock.h"
#include "sw/device/silicon_creator/rom/boot_policy_ptrs.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace rom_test {
namespace internal {

/**
 * Mock class for boot_policy_ptrs.h
 */
class MockBootPolicyPtrs : public global_mock::GlobalMock<MockBootPolicyPtrs> {
 public:
  MOCK_METHOD(const manifest_t *, ManifestA, ());
  MOCK_METHOD(const manifest_t *, ManifestB, ());
};

}  // namespace internal

using MockBootPolicyPtrs = testing::StrictMock<internal::MockBootPolicyPtrs>;

}  // namespace rom_test

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_BOOT_POLICY_PTRS_H_
