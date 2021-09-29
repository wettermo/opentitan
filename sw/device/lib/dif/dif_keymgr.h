// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_LIB_DIF_DIF_KEYMGR_H_
#define OPENTITAN_SW_DEVICE_LIB_DIF_DIF_KEYMGR_H_

/**
 * @file
 * @brief <a href="/hw/ip/keymgr/doc/">Key Manager</a> Device Interface
 * Functions
 */

#include <stdint.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_base.h"

#include "sw/device/lib/dif/autogen/dif_keymgr_autogen.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * Enumeration for side load slot clearing.
 */
typedef enum dif_keymgr_sideload_clr {
  kDifKeyMgrSideLoadClearNone,
  kDifKeyMgrSideLoadClearAes,
  kDifKeyMgrSideLoadClearHmac,
  kDifKeyMgrSideLoadClearKmac,
  kDifKeyMgrSideLoadClearOtbn,
  kDifKeyMgrSideLoadClearAll,
} dif_keymgr_sideload_clr_t;

/**
 * Runtime configuration for key manager.
 *
 * This struct describes runtime information for one-time configuration of the
 * hardware.
 */
typedef struct dif_keymgr_config {
  /**
   * Number of key manager cycles before the entropy is reseeded.
   *
   * Key manager uses random values generated by the entropy source for
   * initializing its state and clearing sideload keys. This value determines
   * the frequency at which this random value is updated.
   */
  uint16_t entropy_reseed_interval;
} dif_keymgr_config_t;

/**
 * Key manager alerts.
 *
 * Key manager generates alerts when it encounters a hardware or software
 * error. Clients can use `dif_keymgr_get_status_codes()` to determine the type
 * of error that occurred.
 */
typedef enum dif_keymgr_alert {
  /**
   * A hardware error occurred.
   *
   * This alert is triggered when the hardware encounters an error condition
   * that cannot be caused by the software, e.g. invalid KMAC commands, states,
   * or outputs.
   */
  kDifKeymgrAlertHardware,
  /**
   * A software error occurred.
   *
   * This alert is triggered when the software attempts to start an invalid
   * operation, e.g. attempting to generate keys when the key manager is at
   * Initialized state, or use invalid inputs, e.g. a key with a forbidden
   * version.
   */
  kDifKeymgrAlertSoftware,

  /**
   * \internal Last key manager alert.
   */
  kDifKeymgrAlertLast = kDifKeymgrAlertSoftware,
} dif_keymgr_alert_t;

/**
 * Key manager states.
 *
 * Key manager has seven states that control its operation. During secure boot,
 * key manager transitions between these states sequentially and these
 * transitions are irreversible until a power cycle.
 *
 * The secret value of key manager changes at each state transition in a
 * well-defined manner, thus its meaning is tied to the current state of key
 * manager.
 *
 * The functionality of key manager is directly tied to the life cycle
 * controller peripheral and it is explicitly disabled during specific life
 * cycle stages. If key manager has not been initialized, it cannot be
 * initialized until it is enabled by life cycle controller. If key manager is
 * disabled by life cycle controller while it is in an operational state, it
 * immediately wipes its contents and transitions to Disabled state.
 */
typedef enum dif_keymgr_state {
  /**
   * Reset state.
   *
   * This is the initial state of key manager after PoR. At this state, the
   * secret value of key manager is non-deterministic, i.e. some value based on
   * the physical characteristics of the device and environment conditions.
   */
  kDifKeymgrStateReset,
  /**
   * Initialized state.
   *
   * Secret value of key manager is initialized with random values generated by
   * the entropy source. This is not an operational state and the key manager
   * state must be advanced one more time before keys or identity seeds can be
   * generated.
   */
  kDifKeymgrStateInitialized,
  /**
   * CreatorRootKey state.
   *
   * This is the first operational state of key manager. At this state, key
   * manager can generate a versioned creator key or a creator identity seed
   * that can be used to generate a creator identity using an asymmetric KDF.
   */
  kDifKeymgrStateCreatorRootKey,
  /**
   * OwnerIntermediateKey state.
   *
   * This is the second operational state of key manager. At this state, key
   * manager can generate a versioned intermediate owner key or an intermediate
   * owner identity seed that can be used to generate an intermediate owner
   * identity using an asymmetric KDF.
   */
  kDifKeymgrStateOwnerIntermediateKey,
  /**
   * OwnerRootKey state.
   *
   * This is the last operational state of key manager. At this state, key
   * manager can generate a versioned owner key or an owner identity seed that
   * can be used to generate an owner identity using an asymmetric KDF.
   */
  kDifKeymgrStateOwnerRootKey,
  /**
   * Disabled state.
   *
   * This is a terminal state where key manager is no longer operational. At
   * this state, the secret value of key manager is a random value.
   */
  kDifKeymgrStateDisabled,
  /**
   * Invalid state.
   *
   * Keymgr is in an invalid state and must be reset.
   */
  kDifKeymgrStateInvalid,
} dif_keymgr_state_t;

/**
 * Creates a new handle for key manager.
 *
 * This function does not actuate the hardware and must be called to initialize
 * the handle that must be passed to other functions in this library in each
 * boot stage. A typical usage of this library during different secure boot
 * stages is as follows:
 *
 * - In Mask ROM:
 *   - Create a new handle: `dif_keymgr_init()`.
 *   - Configure hardware: `dif_keymgr_configure()`.
 *   - Initialize state: `dif_keymgr_advance_state()`,
 *   `dif_keymgr_get_status_codes()`, `dif_keymgr_get_state()`.
 *   - Advance state: `dif_keymgr_advance_state()`,
 *     `dif_keymgr_get_status_codes()`, `dif_keymgr_get_state()`.
 * - In subsequent boot stages, i.e. ROM_EXT, BL0, kernel:
 *   - Create a new handle: `dif_keymgr_init()`.
 *   - Generate keys and/or identity seeds:
 *     `dif_keymgr_generate_versioned_key()`,
 *     `dif_keymgr_generate_identity_seed()`, `dif_keymgr_get_status_codes()`.
 *   - Read output (if applicable): `dif_keymgr_read_output()`.
 *   - Advance state: `dif_keymgr_advance_state()`,
 *     `dif_keymgr_get_status_codes()`, `dif_keymgr_get_state()`.
 *
 * @param base_addr Hardware instantiation base address.
 * @param[out] keymgr Out-param for the initialized handle.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_init(mmio_region_t base_addr, dif_keymgr_t *keymgr);

/**
 * Configures key manager with runtime information.
 *
 * This function should need to be called once for the lifetime of `keymgr`.
 *
 * @param keymgr A key manager handle.
 * @param config Runtime configuration parameters.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_configure(const dif_keymgr_t *keymgr,
                                  dif_keymgr_config_t config);

/**
 * Parameters for a key manager state.
 */
typedef struct dif_keymgr_state_params {
  /**
   * This value is used by key manager to derive secret values and can be either
   * a value that represents the contents of a boot stage, e.g. a (truncated)
   * hash, or a tag.
   *
   * If it is a hash, changes in a boot stage will change the secret value, and
   * consequently the versioned keys and identity seeds generated at subsequent
   * boot stages. If it is a tag, those secret values, versioned keys, and
   * identity seeds will be preserved across updates of the boot stage as long
   * as the tag remains the same.
   */
  uint32_t binding_value[8];

  /**
   * Maximum allowed version for keys generated at a state.
   */
  uint32_t max_key_version;
} dif_keymgr_state_params_t;

/**
 * Advances key manager state.
 *
 * This function instructs key manager to transition to the next state, i.e.
 * Reset -> Initialized -> CreatorRootKey -> OwnerIntermediateKey ->
 * OwnerRootKey -> Disabled. Once a state transition starts, key manager locks
 * the control register until the transition is complete. State transitions are
 * irreversible until a power cycle.
 *
 * The entropy source must be initialized before this function is called. After
 * PoR, key manager is in Reset state with a non-deterministic secret value. The
 * first call to this function after PoR causes key manager to initialize its
 * secret value using the random values generated by the entropy source and
 * transition to Initialized state.
 *
 * `params` is required when the next state is an operational state,
 * i.e. `CreatorRootKey`, `OwnerIntermediateKey`, or `OwnerRootKey`. It must be
 * `NULL` for all other cases.
 *
 * This is an asynchronous function because key manager state transitions
 * involve KMAC operations that can take some time to complete. Clients must
 * check the status of key manager using `dif_keymgr_get_status_codes()` before
 * calling other functions in this library.
 *
 * @param keymgr A key manager handle.
 * @param params The binding and max key version value for the next state.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_advance_state(const dif_keymgr_t *keymgr,
                                      const dif_keymgr_state_params_t *params);

/**
 * Disables key manager.
 *
 * This function disables key manager until the next power cycle by making it
 * transition to Disabled state. Disabled state is a terminal state where key
 * manager is no longer operational and its secret value is a random value.
 *
 * @param keymgr A key manager handle.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_disable(const dif_keymgr_t *keymgr);

/**
 * Status code bit flags.
 *
 * See also: `dif_keymgr_status_codes_t`.
 */
typedef enum dif_keymgr_status_code {
  /**
   * Key manager is idle.
   */
  kDifKeymgrStatusCodeIdle = 1 << 0,
  /**
   * Software invoked an invalid operation.
   */
  kDifKeymgrStatusCodeInvalidOperation = 1 << 1,
  /**
   * Key manager issued invalid data to KMAC interface.
   */
  kDifKeymgrStatusCodeInvalidKmacInput = 1 << 2,
  /**
   * Software performed an invalid shadow update.
   */
  kDifKeymgrStatusCodeInvalidKmacOutput = 1 << 3,
  /**
   * Key manager encountered invalid state
   */
  kDifKeymgrStatusCodeInvalidState = 1 << 4,

} dif_keymgr_status_code_t;

/**
 * A bit vector of status codes.
 *
 * The following snippet can be used to check if key manager is idle:
 *
 *   bool is_idle = (status_codes & kDifKeymgrStatusCodeIdle);
 *
 * The following snippet can be used to check if key manager is idle and
 * error-free:
 *
 *   bool is_idle_and_ok = (status_codes == kDifKeymgrStatusCodeIdle);
 *
 * See also: `dif_keymgr_status_code_t`.
 */
typedef uint8_t dif_keymgr_status_codes_t;

/**
 * Gets the operational status of key manager.
 *
 * This function also clears OP_STATUS and ERR_CODE registers after reading
 * them.
 *
 * @param keymgr A key manager handle.
 * @param[out] status_codes Out-param for key manager status codes.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_get_status_codes(
    const dif_keymgr_t *keymgr, dif_keymgr_status_codes_t *status_codes);

/**
 * Gets the current state of key manager.
 *
 * @param keymgr A key manager handle.
 * @param[out] state Out-param for current key manager state.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_get_state(const dif_keymgr_t *keymgr,
                                  dif_keymgr_state_t *state);

/**
 * Generates an identity seed.
 *
 * This function requests key manager to generate an identity seed using its
 * current secret value. Clients must first verify that the operation was
 * successful using `dif_keymgr_get_status_codes()` before reading the generated
 * identity seed using `dif_keymgr_read_output()`.
 *
 * The generated seed can be used to generate an identity using an asymmetric
 * KDF.
 *
 * @param keymgr A key manager handle.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_generate_identity_seed(const dif_keymgr_t *keymgr);

/**
 * Destination of a versioned key generation operation.
 *
 * Key manager can make the output of a versioned key generation operation
 * available to software or sideload it directly to a peripheral device. When
 * the destination is a peripheral device, the output of the operation is not
 * visible to software and a different derivation constant is used for each
 * peripheral.
 */
typedef enum dif_keymgr_versioned_key_dest {
  /**
   * Store the generated versioned key in software visible registers.
   *
   * The generated versioned key can be read by calling
   * `dif_keymgr_read_output()` after verifying that the operation was
   * successful using `dif_keymgr_get_status_codes()`.
   */
  kDifKeymgrVersionedKeyDestSw,
  /**
   * Sideload the generated versioned key to AES device.
   */
  kDifKeymgrVersionedKeyDestAes,
  /**
   * Sideload the generated versioned key to KMAC device.
   */
  kDifKeymgrVersionedKeyDestKmac,
  /**
   * \internal Last key destination.
   */
  kDifKeymgrVersionedKeyDestLast = kDifKeymgrVersionedKeyDestKmac,
} dif_keymgr_versioned_key_dest_t;

/**
 * Parameters for generating a versioned key.
 */
typedef struct dif_keymgr_versioned_key_params {
  /**
   * Destination of the generated versioned key.
   *
   * See also: `dif_keymgr_versioned_key_dest_t`.
   */
  dif_keymgr_versioned_key_dest_t dest;
  /**
   * Salt value to use for key generation.
   */
  uint32_t salt[8];
  /**
   * Version value to use for key generation.
   */
  uint32_t version;
} dif_keymgr_versioned_key_params_t;

/**
 * Generates a versioned key.
 *
 * This function requests key manager to generate a versioned key using its
 * current secret value and the provided parameters. The generated key can be
 * sideloaded directly to a peripheral device or made visible to software using
 * `params.dest`. If the destination is software, clients must first verify that
 * the operation was successful using `dif_keymgr_get_status_codes()` before
 * reading the generated key using `dif_keymgr_read_output()`.
 *
 * @param keymgr A key manager handle.
 * @param params Key generation parameters.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_generate_versioned_key(
    const dif_keymgr_t *keymgr, dif_keymgr_versioned_key_params_t params);

/**
 * Starts or stops clearing of sideload keys.
 *
 * When a key is generated to be sideloaded to a hardware peripheral, key
 * manager stores it in a set of storage registers. Calling this function with
 * `state` set to `kDifKeymgrToggleEnabled` causes key manager to clear sideload
 * keys continously using random values from the entropty source. Callers must
 * disable clearing of sideload keys to resume normal sideload operation.
 *
 * @param keymgr A key manager handle.
 * @param state The new toggle state for sideload clear.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_sideload_clear_set_enabled(const dif_keymgr_t *keymgr,
                                                   dif_toggle_t state);

/**
 * Checks whether clearing of sideload keys is enabled or not.
 *
 * @param keymgr A key manager handle.
 * @param[out] Out-param for the current toggle state of sideload clear.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_sideload_clear_get_enabled(const dif_keymgr_t *keymgr,
                                                   dif_toggle_t *state);

/**
 * Output of a key manager operation.
 *
 * Key manager outputs are in two-shares.
 */
typedef struct dif_keymgr_output {
  uint32_t value[2][8];
} dif_keymgr_output_t;

/**
 * Reads the output of the last key manager operation.
 *
 * After starting a key manager operation, clients must verify that the
 * operation was successful using `dif_keymgr_get_status_codes()` before calling
 * this function.
 *
 * When key manager is used for versioned key generation, the output of this
 * function is valid only if the destination of the operation was
 * `kDifKeymgrVersionedKeyDestSw`.
 *
 * See also: `dif_keymgr_output_t`.
 *
 * @param keymgr A key manager handle.
 * @param[out] output Out-param for key manager output.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_read_output(const dif_keymgr_t *keymgr,
                                    dif_keymgr_output_t *output);

/**
 * Forces a particular alert as if hardware had asserted it.
 *
 * @param keymgr A key manager handle.
 * @param alert An alert type.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
dif_result_t dif_keymgr_alert_force(const dif_keymgr_t *keymgr,
                                    dif_keymgr_alert_t alert);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_LIB_DIF_DIF_KEYMGR_H_
