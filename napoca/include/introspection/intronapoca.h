/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introinterfaceinit
///@{

/** @file intronapoca.h
*   @brief INTRONAPOCA - NAPOCA hypervisor glue layer, interface initializations for introspection
*
*/

#ifndef _INTRONAPOCA_H_
#define _INTRONAPOCA_H_

#include "core.h"

///
/// @brief Initializes the GlueInterface, completes the callbacks necessary for introspection usage.

///
/// @param[in, out] GlueInterfaceBuffer     The buffer containing the GlueIfaca which has to be initialized
/// @param[in] BufferLength                 The buffer length of GleuInterfaceBuffer
/// @param[in] RequestedIfaceVersion        The requested interface version.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GlueInterfaceBuffer is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if BufferLegnth is smaller than the latest GLUE_IFACE structures size.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if RequestedIfaceVersion is not the latest version.
///
/// @remark     For now we support only one single version of the GLUE_IFACE, the latest.
///
NTSTATUS
IntNapInitGlueInterface(
    _Inout_ PVOID GlueInterfaceBuffer,
    _In_    DWORD BufferLength,
    _In_    DWORD RequestedIfaceVersion
    );

///
/// @brief Initializes the UpperInterface, completes the callbacks necessary for introspection usage.

///
/// @param[in, out] UpperInterfaceBuffer    The buffer containing the UpperIfaca which has to be initialized
/// @param[in] BufferLength                 The buffer length of UpperInterfaceBuffer
/// @param[in] RequestedIfaceVersion        The requested interface version.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if UpperInterfaceBuffer is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if BufferLegnth is smaller than the latest UPPER_IFACE structures size.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if RequestedIfaceVersion is not the latest version.
///
/// @remark     For now we support only one single version of the GLUE_IFACE, the latest.
///
NTSTATUS
IntNapInitUpperInterface(
    _Inout_ PVOID UpperInterfaceBuffer,
    _In_    DWORD BufferLength,
    _In_    DWORD RequestedIfaceVersion
    );

#endif // _INTRONAPOCA_H_


///@}