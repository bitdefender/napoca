/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __WINGUEST_INIT_H__
#define __WINGUEST_INIT_H__

#include "winguest_types.h"

NTSTATUS
WinguestInitialize(
    _In_ struct _DRIVER_OBJECT *DriverObject
    );

NTSTATUS
WinguestDelayedInitialization(
    void
    );

NTSTATUS
WinguestUninitialize(
    void
    );

#endif //__WINGUEST_INIT_H__
