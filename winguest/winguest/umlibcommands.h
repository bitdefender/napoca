/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _UMLIBCOMMANDS_H_
#define _UMLIBCOMMANDS_H_

#include "common/communication/commands.h"

NTSTATUS
UmCmdGetHvStatus(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetCpuFeatures(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdUmCheckCompatibilityWithDrv(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdCommandThreadCount(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetCpuSmxAndVirtFeatures(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetCrValues(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetComponentVersion(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetCompatibility(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdGetLogs(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
UmCmdUpdateComponent(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
);

NTSTATUS
UmCmdQueryComponent(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
);

#endif //_UMLIBCOMMANDS_H_