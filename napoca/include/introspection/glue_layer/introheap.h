/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introheap.h
*   @brief INTROHEAP - NAPOCA hypervisor glue layer, heap utilities offered/implemented for the introspection engine.
*
*/

#ifndef _INTROHEAP_H_
#define _INTROHEAP_H_

#include "glueiface.h"

///
/// @brief  Get the available free memory to introcore from Napoca.
///
/// This function is used by introcore to determine if certain operations can
/// be attempted. In low memory conditions, certain operations will not be attempted.
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[out] TotalHeapSize   The total size of the heap, in bytes
/// @param[out] FreeHeapSize    The size of the remaining free heap, in bytes
///
/// @returns    CX_STATUS_SUCCESS   - operation completed successfully
/// @returns    OTHER               - an appropriate STATUS error value
///
NTSTATUS
GuestIntNapQueryHeapSize(
    _Out_ SIZE_T* TotalHeapSize,
    _Out_ SIZE_T* FreeHeapSize
);

///
/// @brief  Allocates a block of memory from the heap.
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  Address     If successful, will contain a pointer to the allocated memory region
/// @param[in]  Size        The size of the block
/// @param[in]  Tag         The tag of the allocation
///
/// @returns    CX_STATUS_SUCCESS                 - if the allocation succeeded
/// @returns    CX_STATUS_INSUFFICIENT_RESOURCES  - if there is not enough memory available
/// @returns    OTHER                             - other potential internal STATUS error value
///
NTSTATUS
GuestIntNapHpAllocWithTagAndInfo(
    _Outptr_result_bytebuffer_(Size) PVOID* Address,
    _In_ size_t Size,
    _In_ DWORD Tag
);

///
/// @brief  Frees a memory block previously allocated with GuestIntNapHpAllocWithTagAndInfo.
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  Address     Pointer to the memory address of the allocated block. On successful calls,
///                         it will be set to NULL
/// @param[in]  Tag         The tag of the allocation. Must match the one provided by the GuestIntNapHpAllocWithTagAndInfo call.
///
/// @returns    CX_STATUS_SUCCESS   - if the allocation was successfully freed.
/// @returns    OTHER               - other potential internal STATUS error value
///
NTSTATUS
GuestIntNapHpFreeWithTagAndInfo(
    _Inout_ _At_(*Address, _Post_null_) PVOID* Address,
    _In_ DWORD Tag
);

#endif // _INTROHEAP_H_

///@}