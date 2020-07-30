/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// FASTMAP - fast VA-to-PA mapping support
/// @ingroup fastmap
/// @{
#ifndef _FASTMAP_H_
#define _FASTMAP_H_


void
FmPreinit(
    void
    );

NTSTATUS
FmInit(
    void
    );

NTSTATUS
FmUninit(
    void
    );

NTSTATUS
FmReserveRange(
    _In_ DWORD PageCount,
    _Out_ PVOID *VaPtr,
    _Out_ PQWORD *PtPtr
    );

NTSTATUS
FmFreeRange(
    _Inout_ PVOID *VaPtr,
    _Inout_ PQWORD *PtPtr
    );

NTSTATUS
FmDumpStats(
    _In_ DWORD Flags
    );

#endif // _FASTMAP_H_

/// @}