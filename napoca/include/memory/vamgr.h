/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup vamgr
/// @{
#ifndef _VAMGR_H_
#define _VAMGR_H_
#include "core.h"

//
// Virtual-address space management support
//
typedef CX_VOID     *VAMGR_ALIGNED_VA;
typedef CX_VOID     *VAMGR_UNALIGNED_VA;
typedef CX_UINT64   VAMGR_ALIGNED_PA;
typedef CX_UINT64   VAMGR_UNALIGNED_PA;
typedef CX_UINT32   VAMGR_PAGE_COUNT;
typedef CX_UINT64   VAMGR_SIZE_IN_BYTES;
typedef CX_UINT32   VAMGR_TAG;

/// @brief Allocator selection behavior
typedef enum
{
    MEM_ALLOCATOR_HINT_DEFAULT          = 0,    ///< same as VAMGR_ALLOCATOR_HINT_ROUNDROBIN
    MEM_ALLOCATOR_HINT_ROUNDROBIN       = 1,    ///< allocate from the next pre-designed allocator
    MEM_ALLOCATOR_HINT_MAXFREE          = 2,    ///< allocate from the highest availability VA pool
    MEM_ALLOCATOR_HINT_MAX_VALID_HINT   = 2     ///< only for type-validation purposes
}VAMGR_ALLOCATOR_HINT;

/// @brief Allocator identifier based on id or behavior
typedef union
{
    struct
    {
        union
        {
            CX_UINT32 Index;                ///< index of allocator
            VAMGR_ALLOCATOR_HINT Hint;      ///< behavior or allocator
        };
        CX_BOOL IsDefinedByIndex;           ///< indicates if this id is defined by index or by behavior
    };

    QWORD Raw;                              ///< raw value of allocator id
}VAMGR_ALLOCATOR_ID;


#define VAMGR_DEFAULT_ALLOCATOR     gVamgrDefaultAllocator          ///< Helper for default allocator id
#define VAMGR_ROUNDROBIN_ALLOCATOR  gVamgrRoundRobinAllocator       ///< Helper for round robin allocator id
#define VAMGR_MAXFREE_ALLOCATOR     gVamgrMaxFreeAllocator          ///< Helper for max free allocator id
#define VAMGR_ALLOCATOR_BY_INDEX(i) VaMgrGetAllocatorByIndex(i)     ///< Helper for selection by index


extern const VAMGR_ALLOCATOR_ID     gVamgrDefaultAllocator;
extern const VAMGR_ALLOCATOR_ID     gVamgrRoundRobinAllocator;
extern const VAMGR_ALLOCATOR_ID     gVamgrMaxFreeAllocator;

/// @brief Retrieves and va allocator by its index
/// @param AllocatorIndex   Desired allocator index
/// @return an allocator id defined by allocator index
__forceinline
VAMGR_ALLOCATOR_ID
VaMgrGetAllocatorByIndex(
    _In_ CX_UINT32 AllocatorIndex
)
{
    VAMGR_ALLOCATOR_ID result = { 0 };
    result.IsDefinedByIndex = CX_TRUE;
    result.Index = AllocatorIndex;
    return result;
}

/// @brief Perform basic pre-initialization steps for the va allocator
VOID
VaMgrPreinitAllocator(
    VOID
);

/// @brief Perform va allocator initialization
///
/// This function initializes global data structures used by the va allocator.
///
/// @return CX_STATUS_XXX       On internal errors
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
VaMgrInitAllocator(
    VOID
);


/// @brief Perform uninit steps for the va allocator
/// @return CX_STATUS_XXX       On internal errors
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
VaMgrUninitAllocator(
    VOID
);


/// @brief Indicates if the va allocator is initialized
/// @return     TRUE if initialized; FALSE otherwise
BOOLEAN
VaMgrIsInitialized(
    VOID
);

/// @brief Marks a range of virtual addresses as being in use
///
/// This function will only allocate virtual address space, it does NOT consume other resources, it only reserves virtual addresses.
///
/// @param NumberOfPages            Number of requested pages
/// @param Va                       Pointer that will contain the start of allocated virtual address space
/// @param ActuallyReservedPages    Pointer that will hold the number of pages that were successfully reserved
/// @param Allocator                An allocator id that identifies the allocator that will be used
/// @param Tag                      Allocation tag
/// @return CX_STATUS_INVALID_PARAMETER_1       Invalid number of pages requested
/// @return CX_STATUS_INVALID_PARAMETER_2       Va is NULL
/// @return CX_STATUS_INSUFFICIENT_RESOURCES    Not enough resources; va space run out due to many allocs without free
/// @return CX_STATUS_SUCCESS                   On success
NTSTATUS
VaMgrAllocPages(
    _In_ VAMGR_PAGE_COUNT       NumberOfPages,
    _Out_ VAMGR_ALIGNED_VA      *Va,
    __out_opt VAMGR_PAGE_COUNT  *ActuallyReservedPages,
    _In_ VAMGR_ALLOCATOR_ID     Allocator,
    _In_ DWORD                  Tag
);


/// @brief Marks a range of virtual addresses as being free to use
/// @param Address          Start of va allocation
/// @param Tag              Tag of allocation
/// @param PageCount        Pointer that receives the number of pages that were marked as free
/// @return CX_STATUS_INVALID_PARAMETER_1       Address is NULL
/// @return CX_STATUS_ALIGNMENT_INCONSISTENCY   Address is not page aligned
/// @return STATUS_NOT_A_VALID_DYNAMIC_VA       Address is not in range managed by this allocator
/// @return CX_STATUS_DATA_NOT_FOUND            This address was not found as allocated by this allocator
/// @return CX_STATUS_SUCCESS                   On success
NTSTATUS
VaMgrFreePages(
    _In_ VAMGR_ALIGNED_VA       Address,
    _In_ DWORD                  Tag,
    __out_opt VAMGR_PAGE_COUNT  *PageCount
);



// debugging and statistics
NTSTATUS
VaMgrDumpWalkByTagInfo(
    _In_ INT8 VaIndex,
    _In_ DWORD Tag
);


typedef struct _HTS_VECTOR HTS_VECTOR;
NTSTATUS
VaMgrGenerateDebugTagStats(
    _In_ INT8 VaIndex,
    _Inout_ HTS_VECTOR* Hts
);

void
VaMgrDumpVaAllocStats(
    void
);

#endif
/// @}
