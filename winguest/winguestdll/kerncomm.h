/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _KERNCOMM_H_
#define _KERNCOMM_H_

extern "C" {
#include "common/communication/commands.h"
}
#include "common/boot/cpu_features.h"

NTSTATUS
KernCommInit(
    void
    );

NTSTATUS
KernCommUninit(
    void
    );

NTSTATUS
KernCommSendMessage(
    _In_ COMMAND_CODE CommandId,
    _In_ COMM_COMPONENT Destination,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize
    );

NTSTATUS
KernCommReceiveMessage(
    _In_ HANDLE Client,
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_opt_ DWORD* BytesReturned
    );

NTSTATUS
KernCommNewClientConnected(
    _In_ HANDLE Client
    );

NTSTATUS
KernCommClientDisconnected(
    _In_ HANDLE Client
    );

//////////////////////////////////////////////////////////////////////////
/// Specific communication
//////////////////////////////////////////////////////////////////////////

NTSTATUS
GetHostCpuAndVirtFeatures(
    _Inout_ CPU_ENTRY *CpuEntry,
    _Inout_ VIRTUALIZATION_FEATURES *VirtFeatures,
    _Inout_ SMX_CAPABILITIES *SmxCapabilities
    );

NTSTATUS
GetHostCpuCrValues(
    _Inout_ QWORD* Cr0,
    _Inout_ QWORD* Cr4
    );

#endif
