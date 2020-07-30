/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introreghook.h
*   @brief INTROREGHOOK -  NAPOCA hypervisor glue layer, registers hook functions
*
*/

#ifndef _INTROREGHOOK_H_
#define _INTROREGHOOK_H_

#include "glueiface.h"

///
/// @brief  Enables VMEXIT events for a control register
///
/// Only enables for CR3, the rest is discarded.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Cr              The control register for which the exit is enabled
///
/// @returns    CX_STATUS_SUCCESS               - if successful or discarded.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2    - if CR is not 0, 3 or 4
///
NTSTATUS
GuestIntNapEnableCrWriteExit(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr
);

///
/// @brief  Disable VMEXIT events for a control register
///
/// Only disables for CR3, the rest is discarded.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Cr              The control register for which the exit is disabled
///
/// @returns    CX_STATUS_SUCCESS               - if successful or discarded.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2    - if CR is not 0, 3 or 4
///
NTSTATUS
GuestIntNapDisableCrWriteExit(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr
);

///
/// @brief  Registers a control register write callback
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on CR write violation exits
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2    - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED   - if the Introspection already registered one.
///
NTSTATUS
GuestIntNapRegisterCrWriteHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntCrWriteCallback Callback
);

///
/// @brief  Unregisters the current control register write callback, unsubscribing introcore from CR events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT  - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterCrWriteHandler(
    _In_ PVOID GuestHandle
);

///
/// @brief  Registers a descriptor table access callback
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on DTR violation exits
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2    - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED   - if the Introspection already registered one.
///
NTSTATUS
GuestIntNapRegisterDescriptorTableHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroDescriptorTableCallback Callback
);

///
/// @brief  Unregisters the current descriptor table access callback, unsubscribing introcore from DTR events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT  - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterDescriptorTableHandler(
    _In_ PVOID GuestHandle
);

///
/// @brief  Registers an extended control register write callback
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on XCR write violation exits
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2    - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED   - if the Introspection already registered one.
///
NTSTATUS
GuestIntNapRegisterXcrWriteHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntXcrWriteCallback Callback
);

///
/// @brief  Unregisters the current extended control register write callback, unsubscribing introcore from XCR events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS               - if successful.
/// @returns    CX_STATUS_INVALID_PARAMETER1    - if GuestHandle is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT  - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterXcrWriteHandler(
    _In_ PVOID GuestHandle
);

#endif // _INTROREGHOOK_H_

///@}