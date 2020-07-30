/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup heap
/// @{
#ifndef _HEAP_H_
#define _HEAP_H_

#include "core.h"
#include "memory/memtags.h"

#define HpAllocWithTag(Address, Len, Tag)       HpAllocWithTagAndInfo(Address, Len, 0, Tag)
#define HpFreeAndNullWithTag(Address, Tag)      HpFreeWithTagAndInfo(Address, Tag)
#define HpReallocWithTag(Address, Len, Tag)     HpReallocWithTagAndInfo(Address, Len, Tag)

// for core components that must be able to allocate memory even in low resources conditions
#define HpAllocWithTagCore(Address, Len, Tag)       HpAllocWithTagAndInfo(Address, Len, HEAP_FLAG_ALLOC_MUST_SUCCEED, Tag)

/// @brief Heap selection behavior
typedef enum _HP_RUNOUT_BEHAVIOR {
    HpDefault = 0,
    HpNextWhenRunout = 0,           ///< When a heap runs out, choose the next non empty heap index
    HpFreestWhenRunout = 1,         ///< When a heap runs out, choose the freest heap
    HpRestrictToAssigned = 2,       ///< When runs out, does not search for another heap
    HpDbgAlwaysSingle = 100,        ///< Used only for testing: restricts all CPU's to use a single Heap (runs out faster)
    HpDbgAlwaysNext = 101,          ///< Used only for testing: use a round-robin mechanism for each allocation
    HpDbgAlwaysFreest = 102,        ///< Used only for testing: always search the freest heap when allocating
} HP_RUNOUT_BEHAVIOR;


#define HEAP_FLAG_ALLOC_MUST_SUCCEED    0x00000001  ///< Indicates that this allocation must succeed as it is part of a critical subsystem

/// @brief Perform basic pre-initialization steps
/// Initializes global data and prepares global parallel heap allocators if needed
void
HpPreinit(
    void
    );

/// @brief Perform heap initialization
///
/// This function will allocate needed memory for heap usage and will map it into hypervisor virtual space at predetermined virtual addresses
///
/// @param Behavior             Heap selection behavior
/// @return CX_STATUS_XXX       For internal errors
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpInitHeap(
    _In_ HP_RUNOUT_BEHAVIOR Behavior
    );

/// @brief Checks if heap is properly initialized
/// @return     TRUE if heap is initialized; FALSE otherwise
BOOLEAN
HpInitialized(
    void
    );

/// @brief Allocates a block of memory from the heap
///
/// Allocates a block of memory that is by default aligned to 1 byte from the heap. Allocation address is automatically aligned to the specified alignment.
/// There may be waste of memory due to alignment requirements. Also in case of small allocations it is possible that the allocation will be performed
/// by a stack based fast allocator and an address from the range of fast allocators will be provided
/// This process is transparent for the caller and freeing of such allocations will be done by normally calling #HpFreeWithTagAndInfo function.
///
/// @param Address              Pointer where to store the address of the newly allocated block
/// @param Size                 Requested allocation size
/// @param Flags                Flags for the allocation process. Eg: #HEAP_FLAG_ALLOC_MUST_SUCCEED
/// @param Tag                  Identifier for allocation; for debugging purposes only
/// @return CX_STATUS_XXX       For internal errors
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpAllocWithTagAndInfo(
    _Out_ VOID** Address,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_ DWORD Tag
    );

/// @brief Allocates a block of memory from the heap
///
/// Allocates an aligned block of memory from the heap. Allocation address is automatically aligned to the specified alignment.
/// There may be waste of memory due to alignment requirements. Also in case of small allocations that specify an alignment of 1 byte
/// it is possible that the allocation will be performed by a stack based fast allocator and an address from the range of fast allocators will be provided
/// This process is transparent for the caller and freeing of such allocations will be done by normally calling #HpFreeWithTagAndInfo function.
///
/// @param Address      Pointer where to store the address of the newly allocated block
/// @param Size         Requested allocation size
/// @param Flags        Flags for the allocation process. Eg: #HEAP_FLAG_ALLOC_MUST_SUCCEED
/// @param Tag          Identifier for allocation; for debugging purposes only
/// @param Alignment    Alignment in bytes
///
/// @return CX_STATUS_INVALID_PARAMETER_1           Address is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3           Tag is invalid
/// @return CX_STATUS_INVALID_PARAMETER_4           Alignment is 0
/// @return STATUS_HEAP_LAST_FIT_INDEX_NOT_SET      No heap is fit for this allocation
/// @return STATUS_HEAP_NO_FREE_CHUNK_FOUND         There is no free block of memory or requested size and no other block can be split or coalesced to satisfy the request
/// @return CX_STATUS_INSUFFICIENT_RESOURCES        There is no more memory available on heap
/// @return CX_STATUS_SUCCESS                       On success
NTSTATUS
HpAllocWithTagAndInfoAligned(
    _Out_ VOID** Address,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_ DWORD Tag,
    _In_ DWORD Alignment
    );


/// @brief Free a block of memory allocated from the heap
/// @param Address      Address to be freed
/// @param Tag          Allocation tag
/// @return CX_STATUS_INVALID_PARAMETER_1   Address is NULL or it specifies an address that is not from the heap
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpFreeWithTagAndInfo(
    _Inout_ VOID** Address,
    _In_ DWORD Tag
    );


/// @brief Reallocates a block of memory
///
/// This function will allocate a block of memory with the requested size, copy the existing content to the new memory buffer and then free the old allocation
///
/// @param Address      Pointer to the allocation address that needs to be reallocated; On output it will contain the address of the new allocated block
/// @param NewSize      New size in bytes
/// @param Tag          Allocation tag
/// @return                     See #HpReallocWithTagAndInfoAligned
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpReallocWithTagAndInfo(
    _Inout_ VOID** Address,
    _In_ DWORD NewSize,
    _In_ DWORD Tag
    );

/// @brief Reallocates a block of memory
///
/// This function will allocate a block of memory with the requested size, copy the existing content to new memory buffer and then free the old allocation
///
/// @param Address      Pointer to the allocation address that needs to be reallocated; On output it will contain the address of the new allocated block
/// @param NewSize      New size in bytes
/// @param Tag          Allocation tag
/// @param Alignment    Alignment in bytes that is required for the allocation
/// @return                     See #HpAllocWithTagAndInfoAligned and #HpFreeWithTagAndInfo for possible error codes
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpReallocWithTagAndInfoAligned(
    _Inout_ VOID** Address,
    _In_ DWORD NewSize,
    _In_ DWORD Tag,
    _In_ DWORD Alignment
    );


/// @brief Retrieves the actual size of an allocation
/// If the allocation was redirected to a stack based fast-allocator due to its size, this function will return FALSE.
///
/// @param Address      Allocation address
/// @param Size         Pointer where the allocation size will be stored
/// @return CX_STATUS_INVALID_PARAMETER_1   Address is NULL or not a valid heap address
/// @return CX_STATUS_INVALID_PARAMETER_1   Size is NULL
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpGetAllocationSize(
    _In_ VOID* Address,
    _Out_ DWORD* Size
    );


/// @brief Check if an address is a valid heap address - is in the range of virtual addresses that heap manages.
/// A valid address does not mean that it is allocated (usable). If the allocation was redirected to a stack based fast-allocator
/// due to its size, this function will return FALSE.
/// @param Address      Address to check
/// @return             TRUE if address is a valid heap address; FALSE otherwise
BOOLEAN
HpIsValidHeapAddress(
    _In_ VOID* Address
    );

/// @brief Print heap allocation statistics for debugging
/// Allocations that were redirected to a stack-based fast-allocator will not be counted by this function
void
HpDumpHeapAllocStats(
    void
    );


/// @brief Retrieves info about heap resources
/// @param TotalSize    Pointer where to store total size in bytes of memory available for heap allocations
/// @param FreeSize     Pointer where to store free size in bytes of memory available for heap allocations
/// @return CX_STATUS_INVALID_PARAMETER_1   TotalSize is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   FreeSize is NULL
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
HpQuerySize(
    _Out_ SIZE_T *TotalSize,
    _Out_ SIZE_T *FreeSize
    );


/// @brief Print heap information for debugging purposes
VOID
HpiDumpHeaps(
    void
    );



//
// heap tag stats
//

// special macro to switch TAGs into form suitable for binary ordering
#define SWAPTAG(x)      ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
                         (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

typedef struct _HTS_ENTRY {
    DWORD   Tag;
    INT32   AllocCount;
    QWORD   TotalBytes;
} HTS_ENTRY, * PHTS_ENTRY;

#define MAX_HTS_ENTRY_COUNT         100

#define HTS_FLAG_OVERFLOW           0x00000100
#define HTS_FLAG_HEAP_INDEX_MASK    0x000000FF

typedef struct _HTS_VECTOR {
    INT32       TagCount;
    union {
        DWORD   Flags;
        INT8    HeapIndex;
    };
    HTS_ENTRY   Tag[MAX_HTS_ENTRY_COUNT];
} HTS_VECTOR;

NTSTATUS
HpGenerateHeapTagStats(
    _In_ INT8 HeapIndex,
    _Inout_ HTS_VECTOR* Hts
    );

NTSTATUS
HpWalkHeapByTag(
    _In_ INT8 HeapIndex,
    _In_ DWORD Tag
);

#endif // _HEAP_H_
/// @}
