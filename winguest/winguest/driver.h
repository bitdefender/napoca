/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DRIVER_H_
#define _DRIVER_H_

#include "version.h"
#include "winguest_status.h"
#include "winguest_types.h"

#define APIC_ID_CACHE_CLEAR CX_UINT8_MAX_VALUE
extern CX_UINT8 gSavedApicIdForCpu[255];

int
WinguestExceptionFilter(
    _In_ struct _EXCEPTION_POINTERS *ep,
    _In_ PCHAR File,
    _In_ DWORD Line
    );

NTSTATUS
WinguestLockDevice(
    void
    );

NTSTATUS
WinguestUnlockDevice(
    void
    );

#endif //_WINGUEST_H_