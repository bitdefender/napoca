/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file intromisc.h
 *  @brief INTROMISC - NAPOCA hypervisor glue layer, other events callback handlers registration functions
 */

#ifndef _INTROMISC_H_
#define _INTROMISC_H_

#include "glueiface.h"

///
/// @brief  Registers a break point event callback coming from introspection.
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on break point exits
///
/// @returns    CX_STATUS_SUCCESS               - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if GuesHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2   - if the callback pointer is invalid.
/// @returns    CX_STATUS_ALREADY_INITIALIZED   - if the callback was already initialized, but not uninitialized
///
NTSTATUS
GuestIntNapRegisterBreakpointHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntBreakpointCallback Callback
);

///
/// @brief  Unregisters the current break point event callback, unsubscribing introcore from BP events
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS               - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if GuesHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT  - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterBreakpointHandler(
    _In_ PVOID GuestHandle
);

///
/// @brief  Registers an event injection callback
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked when an exception is injected inside the guest
///
/// @returns    CX_STATUS_SUCCESS               - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if GuesHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2   - if the callback pointer is invalid.
/// @returns    CX_STATUS_ALREADY_INITIALIZED   - if the callback was already initialized, but not uninitialized
///
NTSTATUS
GuestIntNapRegisterEventInjectionHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntEventInjectionCallback Callback
);

///
/// @brief  Unregisters the current event injection callback
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS               - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if GuesHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT  - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterEventInjectionHandler(
    _In_ PVOID GuestHandle
);

#endif // _INTROMISC_H_

///@}