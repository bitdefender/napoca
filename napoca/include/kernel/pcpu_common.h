/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file pcpu_common.h
*   @brief Common declarations needed for handling per-processor state globally (throughout the whole project)
*/
#ifndef _PCPU_COMMON_H_
#define _PCPU_COMMON_H_
#include "core.h"

typedef struct _PCPU PCPU;

/// @brief Get the PCPU from the global array(#gCpuPointersArray)
///
/// @param[in] BootCpuIndex     Index of the PCPU that we are interested in
///
/// @returns Pointer to the asked PCPU, NULL if something went wrong
PCPU*
HvGetCpu(
    _In_ CX_UINT32 BootCpuIndex
);

#define HvGetCurrentCpu()               ((PCPU*)__readgsqword(FIELD_OFFSET(PCPU, Self)))
#define HvGetCurrentApicId()            ((CX_UINT32)__readgsdword(FIELD_OFFSET(PCPU, Id)))
#define HvGetCurrentCpuIndex()          ((CX_UINT32)__readgsdword(FIELD_OFFSET(PCPU, BootInfoIndex)))

#define HvGetCurrentVcpu()              ((VCPU*)__readgsqword(FIELD_OFFSET(PCPU, Vcpu)))

#define HvGetCurrentGuest()             ((GUEST*)((HvGetCurrentVcpu())?(HvGetCurrentVcpu()->Guest):(NULL)))
#define HvGetCurrentGuestId()           ((CX_UINT32)(HvGetCurrentGuest()->Index)) // There is no other safe value that can be returned here, page-fault it

#define HvGetCurrentVcpuApicId()        (CX_UINT32)(HvGetCurrentVcpu()->LapicId)
#define HvDoWeHaveValidCpu()            (HvGetCurrentCpu() != 0)

BOOLEAN HvDoWeHaveIpcQueues(
    VOID
);


#endif // _PCPU_COMMON_H_

