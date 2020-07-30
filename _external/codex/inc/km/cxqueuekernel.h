/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __CXQUEUEKERNEL_H__
#define __CXQUEUEKERNEL_H__

#include "cxqueuetypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef
NTSTATUS
(*PFUNC_CommClientConnected)(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ ULONG ProcessId
    );

typedef
NTSTATUS
(*PFUNC_CommClientDisconected)(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject
    );

typedef
NTSTATUS
(*PFUNC_CommReceiveData) (
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ UINT32 OutputBufferLength,
    _Out_ UINT32* BytesReturned
    );

#pragma pack(push, 8)

typedef struct _COMM_INIT_DATA
{
    UINT32 Version;                  // version information
    UINT32 Flags;                    // Customization flags
    PWCHAR NativeDeviceName;        // Device name in the form \device\xxxxx
    PWCHAR UserDeviceName;          // Device name in the form \\.\\xxxxx

    PFUNC_CommClientConnected CommClientConnected;          // Notification for a new client that is connected - CreateFile
    PFUNC_CommClientDisconected CommClientDisconnected;     // Notification for a client that is disconnected - CloseHandle
    PFUNC_CommReceiveData CommReceiveData;                  // Notification for data that is available - sent from user mode
    PFUNC_CommReceiveData CommReceiveDataInternal;          // Notification for data that is available - sent from kernel mode
}COMM_INIT_DATA, *PCOMM_INIT_DATA;
#pragma pack(pop)

NTSTATUS
CommInitializeQueueCommunication(
    _In_ WDFDRIVER Driver,
    _In_ PCOMM_INIT_DATA CommInitData
    );

NTSTATUS
CommStartQueueCommunication(
    );

NTSTATUS
CommStopQueueCommunication(
    );

NTSTATUS
CommSendQueueData(
    _In_ PVOID/*WDFFILEOBJECT*/ FileObject, // treat this as a "client id"; it is provided in COMM_INIT_DATACommClientConnected callback
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferSize,
    _Inout_opt_ PVOID OutputBuffer,
    _Inout_opt_ UINT32 OutputBufferSize,
    _Out_opt_ UINT32 *ActualOutputBufferSize,
    _In_opt_ UINT64 Timeout
    );

NTSTATUS
CommUninitializeQueueCommunication(
    void
    );

#ifdef __cplusplus
}
#endif


#endif //__CXQUEUEKERNEL_H__
