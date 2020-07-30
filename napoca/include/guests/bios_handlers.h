/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _BIOS_HANDLERS_H_
#define _BIOS_HANDLERS_H_

/// \addtogroup hooks
/// @{

#include "core.h"

typedef struct _BIOS_INT_HOOK BIOS_INT_HOOK;
typedef struct _VCPU VCPU;

/// @brief Hook used to detect the activation of the video mode by the guest (so we can disable ours)
CX_STATUS
BhInt0x10(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    );

/// @brief Hook used to intercept the guest OS's queries to the legacy memory map(INT15(AX=0xE820)), in order to be able to hide the hypervisor's memory
CX_STATUS
BhInt0x15(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    );

/// @brief Hook used to trace a given legacy interrupt
CX_STATUS
BhIntTraceOnly(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    );

/// @}

#endif //_BIOS_HANDLERS_H_
