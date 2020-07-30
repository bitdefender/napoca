/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup spp
/// @{
#ifndef _SPP_H_
#define _SPP_H_

#include "core.h"
#include "base/cx_sal.h"
#include "wrappers/cx_winsal.h"
#include "memory/tas.h"

NTSTATUS
SppSetPageProtection(
    _In_    MEM_ALIGNED_PA      GuestPhysicalAddress,
    _In_    QWORD               SppValue
    );

NTSTATUS
SppGetPageProtection(
    _In_    MEM_ALIGNED_PA      GuestPhysicalAddress,
    _Out_   QWORD               *SppValue
    );

#endif // _SPP_H_
/// @}