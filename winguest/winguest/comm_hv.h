/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _COMM_HV_H_
#define _COMM_HV_H_

#include "common/communication/commands.h"

NTSTATUS
HvVmcallSafe(
    _In_ SIZE_T MessageType,
    _In_ SIZE_T Param1,
    _In_ SIZE_T Param2,
    _In_ SIZE_T Param3,
    _In_ SIZE_T Param4,
    _Out_opt_ SIZE_T* OutParam1,
    _Out_opt_ SIZE_T* OutParam2,
    _Out_opt_ SIZE_T* OutParam3,
    _Out_opt_ SIZE_T* OutParam4
);

BOOLEAN
HVStarted(
    void
    );

NTSTATUS
HVCommInit(
    void
    );

NTSTATUS
HVCommUninit(
    void
    );

NTSTATUS
HVCommConnectHv(
    void
    );

NTSTATUS
HVCommDisconnectHv(
    _In_ BOOLEAN WaitForQueueToBeEmpty
    );

NTSTATUS
HVCommForwardMessage(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
);

typedef NTSTATUS (*PFUNC_HvReceiveMessageCallback)(_In_ PCOMM_MESSAGE InputBuffer);

#endif //_COMM_HV_H_