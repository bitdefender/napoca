/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introhvcall.h
*   @brief INTROHVCALL -  NAPOCA hypervisor glue layer, generic VM/HV call functions.
*
*/

#ifndef _INTROHVCALL_H_
#define _INTROHVCALL_H_

#include "glueiface.h"

///
/// @brief  Registers a VMCALL exit handler
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on VMCALL exits
///
/// @returns    CX_STATUS_SUCCESS                   - if the registration was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED       - if the callback was already registered by introcore, but no unregister was called.
///
NTSTATUS
GuestIntNapRegisterIntroCallHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroCallCallback Callback
);

///
/// @brief  Unregisters the current VMCALL exit callback, un-subscribing introcore from VMCALL events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the unregistration was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT      - if the callback was never registered or it was already un-registered.
///
NTSTATUS
GuestIntNapUnregisterIntroCallHandler(
    _In_ PVOID GuestHandle
);

#endif // _INTROHVCALL_H_

///@}