/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file vmstate.h
 *  @brief VMCS configuration APIs
 *
 * A mechanism for handling the configuration of a VMCS. It ensures the integrity of the VMCS state.
 * The api configures the VMCS structure in 3 independent stages:
 *  - VMCS Guest state configuration
 *  - VMCS Control Fields state configuration
 *  - VMCS Host state configuration
 *
 * Each stage can be bypassed/customized by setting the appropriate option
 * in the VMCS_CONFIGURE_SETTINGS structure supplied to the interface.
 *
 */

 /// \defgroup vmcs VMCS handling support
 /// @{

#ifndef __VMSTATE_H__
#define __VMSTATE_H__

#include "core.h"

typedef struct _VCPU VCPU;

/** @name Structures and definitions used to drive the vmcs configuration logic
 */
///@{
/// @brief Bypasses/configures the way the vmcs guest fields should be set.
typedef enum _VMCS_GUEST_STATE_OPTIONS {
    VMCS_GUEST_NO_UPDATE,           ///< The guest state in the vmcs is not modified.

    VMCS_GUEST_BOOT_STATE,          ///< The guest state in the vmcs is set according to the boot option. For UEFI the boot state is retrieved for ech CPU for Legacy boot the bsp is placed in 16 bit real mode with the rip pointing to the first boot sector and APs are in wait for sipi state.

    VMCS_GUEST_REAL_MODE            ///< The guest state in the vmcs is set to real mode. Cs, Ip, Ss, Sp and the active state are loaded from the supplied VMCS_GUEST_REAL_MODE_PARAMETERS structure.

} VMCS_GUEST_OPTIONS;

/// @brief Bypasses/configures the way the vmcs control fields should be set.
typedef enum _VMCS_CONTROLS_STATE_OPTIONS {

    VMCS_CONTROLS_NO_UPDATE,                ///< The control fields in the vmcs are not modified.

    VMCS_CONTROLS_APPLY_CHANGES_ONLY,       ///< The control fields are updated with the requested features

    VMCS_CONTROLS_RESET_ONLY,               ///< The control fields are reset to default values

    VMCS_CONTROLS_RESET_AND_CHANGES,        ///< The control fields are set to default and requested features are applied

    VMCS_CONTROLS_CUSTOM                    ///< The control fields in the vmcs are set according to the custom state supplied

} VMCS_CONTROLS_OPTIONS;

/// @brief Bypasses/configures the way the vmcs host fields should be set.
typedef enum _VMCS_HOST_STATE_OPTIONS {

    VMCS_HOST_NO_UPDATE,            ///< The host state in the vmcs is not modified.

    VMCS_HOST_DEFAULT               ///< The host state in the vmcs is set to the current values of the HV.

} VMCS_HOST_OPTIONS;

/// @brief Identifies the logical processor's activity state.
typedef enum _VMCS_GUEST_ACTIVITY_STATE_VALUE {
    VMCS_GUEST_ACTIVITY_STATE_ACTIVE        = 0,    ///< The logical processor is executing instructions normally.
    VMCS_GUEST_ACTIVITY_STATE_HLT           = 1,    ///< The logical processor is inactive because it executed the HLT instruction.
    VMCS_GUEST_ACTIVITY_STATE_SHUTDOWN      = 2,    ///< The logical processor is inactive because it incurred a triple fault or some other serious error.
    VMCS_GUEST_ACTIVITY_STATE_WAIT_FOR_SIPI = 3     ///< The logical processor is inactive because it is waiting for a startup-IPI (SIPI).
} VMCS_GUEST_ACTIVITY_STATE_VALUE;

/**
 *  @brief For VMCS_GUEST_REAL_MODE this structure determines the CS:IP address at which the
 *  guest will run, the SS:SP address for the guest stack and the guest activity state.
 */
typedef struct _VMCS_GUEST_REAL_MODE_STATE {

    // The CS:IP address for the guest
    CX_UINT16 Cs;
    CX_UINT16 Ip;

    // The SS:SP address for the guest's stack
    CX_UINT16 Ss;
    CX_UINT16 Sp;

    VMCS_GUEST_ACTIVITY_STATE_VALUE ActivityState;

} VMCS_GUEST_REAL_MODE_STATE;

/// @brief   The requested state for a particular control field feature
typedef enum _VMCS_CONTROL_FEATURE_STATE {
    VMCS_CONTROL_FEATURE_NO_UPDATE,         ///< No action needed
    VMCS_CONTROL_FEATURE_ENABLE,            ///< Enable the specified features
    VMCS_CONTROL_FEATURE_DISABLE            ///< Disable the specified features
} VMCS_CONTROL_FEATURE_STATE;

/**
 *  @brief If the #VMCS_CONTROLS_CUSTOM option is set,
 *  the Control Field state is configured according to the required features
 */
typedef struct _VMCS_CONTROL_FEATURE_CONFIGURATION {

    struct FeaturePreemptionTimer
    {
        VMCS_CONTROL_FEATURE_STATE PreemptionTimerEnableState;
        VMCS_CONTROL_FEATURE_STATE PreemptionTimerSaveState;
    };

    VMCS_CONTROL_FEATURE_STATE  FeatureCr3LoadExit;
    VMCS_CONTROL_FEATURE_STATE  FeatureDescriptorExit;
    VMCS_CONTROL_FEATURE_STATE  FeatureExitOnHalt;
    VMCS_CONTROL_FEATURE_STATE  FeatureExitAllIoPorts;
    VMCS_CONTROL_FEATURE_STATE  FeatureExitAllMsrs;
    VMCS_CONTROL_FEATURE_STATE  FeatureSpptp;
    VMCS_CONTROL_FEATURE_STATE  FeatureBreakpointExit;

    VMCS_CONTROL_FEATURE_STATE  FeatureVeInfoPageSet;
    CX_UINT64                   FeatureVeInfoPageHpa;

} VMCS_CONTROL_FEATURE_CONFIGURATION;

/// @brief   Used to differentiate between VMCS_GUEST_CUSTOM custom state and VMCS_GUEST_REAL_MODE custom state.
typedef union _VMCS_GUEST_CONFIGURATION
{
    VMCS_GUEST_REAL_MODE_STATE RealModeState;       ///< Used with VMCS_GUEST_REAL_MODE option. Describes the guest's real mode state.
} VMCS_GUEST_CONFIGURATION;

/// @brief   Structure used for customizing the resulting VMCS state
typedef struct _VMCS_CONFIGURE_SETTINGS {

    union {
        struct {
            CX_UINT8 InitVmcs               : 1;    ///< Determines the clearing of the Vmcs structure and related cached information in the corresponding vcpu structure
            CX_UINT8 ActivateGuestDomain    : 1;    ///< Determines the setting of ept domain
            CX_UINT8 ClearVmcsFromCpu       : 1;    ///< Apply vmclear if set
            CX_UINT8 SetNewVmcs             : 1;    ///< Apply vmptrld on the VCPU specific vmcs area
        };
        CX_UINT8 VmcsRawUpdateOptions;
    };

    struct VmcsGuestSettings
    {
        VMCS_GUEST_OPTIONS GuestOptions;            ///< Determines the way in which the vmcs guest state is set
        VMCS_GUEST_CONFIGURATION GuestConfig;
    };

    struct VmcsControlSettings
    {
        VMCS_CONTROLS_OPTIONS ControlsOptions;
        VMCS_CONTROL_FEATURE_CONFIGURATION ControlsConfigState;
    };

    VMCS_HOST_OPTIONS HostOptions;

} VMCS_CONFIGURE_SETTINGS;
///@}

/** @name Presets for VMCS_CONFIGURE_SETTINGS structure
 */
///@{

/// @brief      Default value for creating the boot vmcs structure
#define VMCS_CONFIGURE_SETTINGS_BOOT &(VMCS_CONFIGURE_SETTINGS){            \
                        .InitVmcs = CX_TRUE,                                \
                        .ActivateGuestDomain = CX_TRUE,                     \
                        .GuestOptions = VMCS_GUEST_BOOT_STATE,              \
                        .ControlsOptions = VMCS_CONTROLS_RESET_ONLY,        \
                        .HostOptions = VMCS_HOST_DEFAULT,                   \
                        .ClearVmcsFromCpu = CX_TRUE,                        \
                        .SetNewVmcs = CX_TRUE                               \
                        }

/// @brief      Update only the host state in the given Vcpu, everything else stays the same
#define VMCS_CONFIGURE_SETTINGS_INIT_HOST_STATE &(VMCS_CONFIGURE_SETTINGS){     \
                        .InitVmcs = CX_FALSE,                                   \
                        .ActivateGuestDomain = CX_FALSE,                        \
                        .GuestOptions = VMCS_GUEST_NO_UPDATE,                   \
                        .ControlsOptions = VMCS_CONTROLS_NO_UPDATE,             \
                        .HostOptions = VMCS_HOST_DEFAULT,                       \
                        .ClearVmcsFromCpu = CX_FALSE,                           \
                        .SetNewVmcs = CX_TRUE                                   \
                        }
///@}

/**
 *   @brief  Interface exposed by the algorithm for managing the configuration of a vmcs structure.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *   @param[in]   Options                           Pointer to a VMCS_CONFIGURE_SETTINGS structure. Used to guide the vmcs creation logic.
 *
 *   @retval  CX_STATUS_SUCCESS                     The control fields have successfully been flushed to vmcs.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_2         The given Options pointer is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmclear or vmptrld instructions failed.
 *   @retval  otherwise                             The algorithm failed internally.
 */
CX_STATUS
VmstateConfigureVmcs(
    _In_ VCPU* Vcpu,
    _In_ VMCS_CONFIGURE_SETTINGS *Options
);

/**
*    @brief       Controls the activating of the NMI window exiting VMCS feature. Used for injection of pending NMIs.
*
*    @param[in]   Enable                           TRUE to enable NMI window exiting, FALSE otherwise
*/
VOID
VmstateControlNMIWindowExiting(
    _In_ BOOLEAN Enable
);

/**
 *   @brief Routine that update vmcs according to the requirements of the Introspection Engine
 *
 *  Introspection may have some preferences on how to configure the vmcs.
 *  For example: they may want exits on CR3 changes, exits on breakpoints, activated \c \#VE feature, etc.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *   @param[in]   Force                             If TRUE, apply the changes on the selected VCPU even if in the bitmask where the VCPUs to which the intro requests are to be applied are specified, this vcpu is not selected
 *   @param[in]   LoadAndClearVmcsFromCpu           Set to TRUE if VMCS is to be cleared from and loaded in the current VCPU, FALSE otherwise
 *
 *   @retval  CX_STATUS_SUCCESS                     Update performed without errors
 *   @retval  other error statuses that may come from the VmstateConfigureVmcs function call
 */
CX_STATUS
VmstateUpdateVmcsForIntrospection(
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL Force,
    _In_ CX_BOOL LoadAndClearVmcsFromCpu
);

/// @}
#endif //__VMSTATE_H__
