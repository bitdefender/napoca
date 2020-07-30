/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introheap.c
*   @brief INTROHEAP - NAPOCA hypervisor glue layer, heap utilities offered/implemented for the introspection engine.
*
*   The implementation.
*
*/

#include "kernel/kernel.h"
#include "introstatus.h"
#include "introspection/glue_layer/introheap.h"
#include "guests/intro.h"
#include "memory/heap.h"


NTSTATUS
GuestIntNapQueryHeapSize(
    _Out_ SIZE_T* TotalHeapSize,
    _Out_ SIZE_T* FreeHeapSize
)
{
    if (TotalHeapSize == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (FreeHeapSize == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    NTSTATUS status = HpQuerySize(TotalHeapSize, FreeHeapSize);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

NTSTATUS
GuestIntNapHpAllocWithTagAndInfo(
    _Outptr_result_bytebuffer_(Size) PVOID* Address,
    _In_ size_t Size,
    _In_ DWORD Tag
)
{
    NTSTATUS status = HpAllocWithTag(Address, Size, Tag);

    return HV_STATUS_TO_INTRO_STATUS(status);
}


NTSTATUS
GuestIntNapHpFreeWithTagAndInfo(
    _Inout_ _At_(*Address, _Post_null_) PVOID* Address,
    _In_ DWORD Tag
)
{
    NTSTATUS status = HpFreeAndNullWithTag(Address, Tag);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

///@}