/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file intromsrhook.h
*   @brief INTROMSRHOOK -  NAPOCA hypervisor glue layer, MSR hook support
*
*/

#ifndef _INTROMSRHOOK_H_
#define _INTROMSRHOOK_H_

#include "glueiface.h"

///
/// @brief  Enables VMEXIT events for a MSR
///
/// Will enable MSR exiting on MSR writes, by setting the corresponding bit inside the
/// MSR bitmap. OldValue will contain on exit TRUE if exits were already activated
/// on that MSR, or FALSE if not.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Msr             The MSR for which the exit is enabled
/// @param[out] OldValue        True if the exit was already enabled, False otherwise
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if OldValue is NULL.
///
NTSTATUS
GuestIntNapEnableMsrExit(
    _In_ PVOID Guest,
    _In_ DWORD Msr,
    _Out_ BOOLEAN* OldValue
);

///
/// @brief  Disable VMEXIT events for a MSR
///
/// Will disable VM exit on MSR writes on the given MSR, by reseting the corresponding bit
/// inside the MSR bitmap. OldValue will contain on exit TRUE if exits on that MSR were
/// active, or FALSE if not.
///
/// NOTE: The caller must interpret OldValue bit and re-enable/disable exiting if necessarily.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Msr             The MSR for which the exit is disabled
/// @param[out] OldValue        True if the exit was enabled before this call, False otherwise
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if OldValue is NULL.
///
NTSTATUS
GuestIntNapDisableMsrExit(
    _In_ PVOID Guest,
    _In_ DWORD Msr,
    _Out_ BOOLEAN* OldValue
);

///
/// @brief  Registers a MSR exit handler
///
/// Registers a callback that will be called whenever a MSR violation takes place.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on MSR violation exits
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Callback is NULL.
/// @returns    CX_STATUS_ALREADY_INITIALIZED       - if the callback was already initialized, but not uninitialized
///
/// @remarks    If multiple callbacks are registered, only the last one will be considered valid
///
NTSTATUS
GuestIntNapRegisterMsrHandler(
    _In_ PVOID Guest,
    _In_ PFUNC_IntMSRViolationCallback Callback
);

///
/// @brief  Unregisters the current MSR exit callback, unsubscribing introcore from MSR violation events
///
/// Will unregister the callback for MSR violations. The introspection engine
/// will not be notified anymore when MSR violations take place.
///
/// @param[in]  Guest           Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT      - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterMsrHandler(
    _In_ PVOID Guest
);

#endif // _INTROMSRHOOK_H_

///@}