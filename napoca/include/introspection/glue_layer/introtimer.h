/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introtimer.h
*   @brief INTROTIMER -  NAPOCA hypervisor glue layer, generic timing facilities.
*
*/

#ifndef _INTROTIMER_H_
#define _INTROTIMER_H_

#include "glueiface.h"


///
/// @brief  Registers a timer callback, subscribing introcore to VMX timer events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback
///
/// @returns    CX_STATUS_SUCCESS                   - if the registration was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED       - if the callback was already registered by introcore, but no unregister was called.
///
NTSTATUS
GuestIntNapRegisterVmxTimerHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroTimerCallback Callback
);

///
/// @brief  Unregisters the current timer callback, un-subscribing introcore from VMX timer events
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the un-registration was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT      - if the callback was never registered or it was already un-registered.
///
NTSTATUS
GuestIntNapUnregisterVmxTimerHandler(
    _In_ PVOID GuestHandle
);

#endif // _INTROTIMER_H_

///@}