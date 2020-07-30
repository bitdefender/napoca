/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __CXQUEUEUSER_H__
#define __CXQUEUEUSER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "cxqueuetypes.h"

typedef
NTSTATUS
(*PFUNC_CommClientConnectedU)(
    _In_ HANDLE ClientId
    );

typedef
NTSTATUS
(*PFUNC_CommClientDisconectedU)(
    _In_ HANDLE ClientId
    );

typedef
NTSTATUS
(*PFUNC_CommReceiveDataU)(
    _In_ HANDLE ClientId,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_opt_ DWORD* BytesReturned
    );

typedef
__drv_allocatesMem(Mem)
PVOID
(*PFUNC_CommAlloc)(
    _In_ DWORD Size
    );

typedef
VOID
(*PFUNC_CommFree)(
    _Pre_valid_ _Post_invalid_ __drv_freesMem(Mem) PVOID Buffer
    );

#pragma pack (push, 8)
typedef struct _COMM_INIT_DATA_U
{
    DWORD Version;          // version information
    DWORD Flags;            // Customization flags
    PWCHAR Name;            // Device name in the form \\.\\xxxxx - used in CreateFile

    DWORD MessageSize;      // Default message size to be used for INVERTED calls - ioctls that stay pending in KM
    DWORD ThreadCount;      // How many threads to be created and used for INVERTED calls - KM to UM comm

    PFUNC_CommAlloc Alloc;  // Memory allocation function - optional
    PFUNC_CommFree Free;    // Memory free function - optional

    // some custom callbacks here
    PFUNC_CommClientConnectedU CommClientConnected;         // legacy stuff maybe not needed ????
    PFUNC_CommClientDisconectedU CommClientDisconnected;    // legacy stuff maybe not needed ????
    PFUNC_CommReceiveDataU CommReceiveDataU;                // Notification that data is available from km to um
}COMM_INIT_DATA_U, *PCOMM_INIT_DATA_U;
#pragma pack(pop)

NTSTATUS
CommInitializeCommunicationU(
    _In_ PCOMM_INIT_DATA_U CommInitData,
    _Out_ PHANDLE CommHandle
    );

NTSTATUS
CommUninitializeCommunicationU(
    _In_ HANDLE CommHandle
    );

NTSTATUS
CommStartQueueCommunicationU(
    _In_ HANDLE CommHandle
    );

NTSTATUS
CommStopQueueCommunicationU(
    _In_ HANDLE CommHandle
    );

NTSTATUS
CommSendQueueDataU(
    _In_ HANDLE CommHandle,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize
    );

NTSTATUS
CommSendQueueDataUEx(
    _In_ HANDLE CommHandle,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize,
    _In_ DWORD Timeout
);

#ifdef __cplusplus
}
#endif


#endif //__CXQUEUEUSER_H__
