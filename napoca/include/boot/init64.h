/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INIT64_H_
#define _INIT64_H_

/// \addtogroup phase0
/// @{

#include "memory/tas.h"
#include "memory/memmgr.h"

// init64 global phase signaling variables
extern volatile BOOLEAN gBasicInitDoneByBSP;
extern volatile BOOLEAN gStageOneCanProceedOnAps;
extern volatile DWORD gStageOneInitedCpuCount;
extern volatile BOOLEAN gStageTwoCanProceedOnAps;
extern volatile DWORD gStageTwoInitedCpuCount;
extern volatile BOOLEAN gStageThreeCanProceedOnAps;
extern volatile DWORD gCpuReachedInit64;

/// @brief Callback used for allocating paging structures, only used in the early phases of the hypervisor's boot. Uses pages provided by the loader
CX_STATUS
IniBootAllocPagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ CX_UINT8 TableDepth,
    _Out_ MEM_ALIGNED_VA* Va,
    _Out_ MEM_ALIGNED_PA* Pa
);

/// @brief Callback used for freeing paging structures, only used in the early phases of the hypervisor's boot
///
/// WARNING: No actual freeing, technically leaks the pages allocated from the loader
CX_STATUS
IniBootFreePagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ MEM_ALIGNED_VA Va,
    _In_ MEM_ALIGNED_PA Pa
);

/// @brief Callback used for allocating virtual addresses, only used in the early phases of the hypervisor's boot.
///
/// Simple, incremental allocation from the preassigned virtual address space
CX_STATUS
IniBootAllocVaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA* Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

/// @brief Callback used for allocating virtual addresses, only used in the early phases of the hypervisor's boot.
///
/// WARNING: No actual freeing, technically leaks the virtual address space
CX_STATUS
IniBootFreeVaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA* Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

/// @brief Callback used for allocating physical pages, only used in the early phases of the hypervisor's boot. Uses pages provided by the loader
CX_STATUS
IniBootAllocPaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _Out_ MDL* Mdl,
    _Out_ MM_ALIGNED_PA* Pa,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _In_ CX_BOOL Continuous,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

/// @brief Callback used for freeing physical pages, only used in the early phases of the hypervisor's boot
///
/// WARNING: No actual freeing, technically leaks the pages allocated from the loader
CX_STATUS
IniBootFreePaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MDL* Mdl,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

/// @}

#endif // _INIT64_H_
