/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _KERNCOMM_INT_
#define _KERNCOMM_INT_

#include "winguestdll.h"

NTSTATUS
InitMessageConsumers(
    void
    );

NTSTATUS
UninitMessageConsumers(
    void
    );

NTSTATUS
IntrospectionErrorReceive(
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
    );

NTSTATUS
InstrospectionAlertReceive(
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
    );

NTSTATUS
InternalPowerStateChanged(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,      // this includes the size of any msg header
    __out_opt PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

NTSTATUS
ResumeCallbackProcess(
    BOOLEAN ResumeVolatileSettings
);

typedef struct _INTRO_HASH_INFO
{
    QWORD FirstSeen;
    QWORD LastSeen;
    DWORD Count;
}INTRO_HASH_INFO;

void
CleanupThrottleHashmap(
    void
);

#endif //_KERNCOMM_INT_