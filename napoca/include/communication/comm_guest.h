/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _COMM_GUEST_H_
#define _COMM_GUEST_H_

#include "common/communication/commands.h"

typedef struct _VCPU VCPU;

NTSTATUS
VxhVmCallGuestMessage(
    _In_ VCPU* Vcpu,
    _In_ BOOLEAN Privileged,
    _In_ COMMAND_CODE CommandCode,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_ QWORD *OutParam1,
    _Out_ QWORD *OutParam2,
    _Out_ QWORD *OutParam3,
    _Out_ QWORD *OutParam4
    );

NTSTATUS
GuestClientConnected(
    _In_ COMM_COMPONENT Component,
    _Out_ QWORD *OutSharedMemGPA,
    _Out_ QWORD *OutSharedMemSize
    );

NTSTATUS
GuestClientDisconnected(
    _In_ COMM_COMPONENT Component
    );

NTSTATUS
CommGuestForwardMessage(
    _In_ PCOMM_MESSAGE Msg
    );

NTSTATUS
CommPrepareMessage(
    _In_ COMMAND_CODE CommandCode,
    _In_ WORD CommandFlags,
    _In_ COMM_COMPONENT DstComponent,
    _In_ DWORD Size,
    _Out_ PCOMM_MESSAGE *Message
    );

NTSTATUS
CommPostMessage(
    _In_ PCOMM_MESSAGE Message
    );

NTSTATUS
CommDestroyMessage(
    _In_ PCOMM_MESSAGE Message
    );

NTSTATUS
CommSetupHostRingBuffer(
    void
    );

VOID
CommIntroCheckPendingAlerts(
    _In_ VCPU* Vcpu,
    _In_ BOOLEAN ForcedFlush
);

__forceinline
BOOLEAN
CommIsComponentConnected(
    _In_ COMM_COMPONENT CommComponent
);

#endif //_COMM_GUEST_H_
