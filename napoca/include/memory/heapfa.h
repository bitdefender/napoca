/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file heapfa.h
///  @brief Defines the settings of the fast allocators used by the heap as a performance boost for the most commonly used allocation sizes
///

/// @ingroup heapfa
/// @ingroup heap
/// @{

#ifndef _HEAPFA_H_
#define _HEAPFA_H_
#include "napoca.h"

//
// General settings for the fast allocators used to optimize the heap performance
//

#define HP_USE_FAST_ALLOCATORS                      1       ///< defined as 1 to enable or 0 to disable the dynamic usage of fast allocators for frequently allocated sizes

// relative memory resources to use for the heap, fast allocators and as free pagepool for low level memory operations
// also, when HP_USE_FAST_ALLOCATORS is 0 use its memory as heap
#if HP_USE_FAST_ALLOCATORS
#define HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT     1       ///< defines how much of the memory (as a relative weight) should be dedicated to the fast allocators
#define HP_PAGE_POOL_FOR_HEAP_AMOUNT                1       ///< relative weight for the amount of memory resources dedicated to the heap
#define HP_PAGE_POOL_LEAVE_FREE_AMOUNT              1       ///< weight for the quantity of memory to leave as free page-pool physical pages
#define HP_PAGE_POOL_SUM                           (HP_PAGE_POOL_FOR_HEAP_AMOUNT + HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT + HP_PAGE_POOL_LEAVE_FREE_AMOUNT)
///< total weight of memory resources reserved for all the competing purposes
#else
#define HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT     0
#define HP_PAGE_POOL_FOR_HEAP_AMOUNT                2
#define HP_PAGE_POOL_LEAVE_FREE_AMOUNT              1
#define HP_PAGE_POOL_SUM                            (HP_PAGE_POOL_FOR_HEAP_AMOUNT + HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT + HP_PAGE_POOL_LEAVE_FREE_AMOUNT)
#endif

#define HP_FAST_ALLOCATORS_ABSOLUTE_MIN_THRESHOLD   256     ///< minimum number of allocations of a given size needed before considering setting up a dedicated fast allocator
#define HP_FAST_ALLOCATORS_MIN_PERMILLE             10      ///< at least #/1000 of total allocations should be of given size before retargeting the allocations of said size to a fast allocator
#define HP_MAX_FAST_ALLOCATION_SIZE                 4096    ///< allocations strictly above this size will not be taken into considered for optimizing by the use of fast allocators

typedef struct _HP_FAST_STATS
{
    volatile QWORD AllocCount;                              ///< number of heap allocations of this size, used to detect the most used allocation sizes
    CX_ONCE_INIT0 Initialized;                              ///< synchronization variable used to avoid multiple concurrent creation/initialization tries on an allocator
}HP_FAST_ALLOCATORS_STATS;


typedef struct _HP_FAST_ALLOCATORS_DATA
{
    CX_ONCE_INIT0               VaReservedSpaceInitialized;                 ///< field used to avoid any race conditions when the entire VA space is reserved (right when the very first allocator is initialized)
    HP_FAST_ALLOCATORS_STATS    StatsPerSize[HP_MAX_FAST_ALLOCATION_SIZE];  ///< allocation size statistics

    struct
    {
        PBYTE                   Start;                                      ///< start of VA memory region reserved by all allocators
        CX_UINT32               PerAllocator;                               ///< fixed size of VA space reserved for each individual allocator
        CX_UINT64               Total;                                      ///< total memory reserved for all allocators
    } ReservedVa;

    struct
    {
        volatile CX_UINT64      TotalAllocations;                           ///< total number of heap allocations
        volatile CX_UINT64      TotalFastAllocations;                       ///< total number of fast allocations (hit/miss ratio stats can be derived from these fields)
        volatile CX_UINT64      TotalPhysicalPagesUsed;                     ///< total number of physical pages used by allocators
    } Stats;
}HP_FAST_ALLOCATORS_DATA;   ///< defines the internal data needed for managing a collection of fast allocators used instead of the heap, allocators that are set up automatically based on the most popular allocation sizes

extern HP_FAST_ALLOCATORS_DATA gHpFastData;

NTSTATUS
HpInitFastAllocator(
    _In_ DWORD Size
);


//
// Logic needed by the heap for offloading allocations to the list of fast allocators
//

static
__forceinline
BOOLEAN
_HpAboveThreshold(
    _In_ QWORD ThisSizeAmount,
    _In_ QWORD TotalAmount
)
///
/// Verify if a given allocation size was seen frequent enough to warrant a specialized fast allocator being
/// used for handling further such allocations
///
{
    // frequently called -- use a fast approximation for the percent calculation:
    // 1024 * count / total =~ 10 * (100 * count / total) => compare this to 10 * threshold percent
    BOOLEAN result = (ThisSizeAmount > HP_FAST_ALLOCATORS_ABSOLUTE_MIN_THRESHOLD) &&        // absolute threshold
        (((ThisSizeAmount << 10ull) / TotalAmount) > (HP_FAST_ALLOCATORS_MIN_PERMILLE));    // relative threshold
    return result;
}

NTSTATUS
HpFastAlloc(
    _Out_ PVOID *Address,
    _In_ DWORD Size
);

NTSTATUS
HpFastFree(
    _Out_ PVOID *Address
);


//
// Provide the compile-time symbols needed by the fast allocator implementation
//
#define FA_LOCK                         SPINLOCK            ///< define a data type for the locks used by falloc.c/falloc.h
#define FA_LOG(...)                     LOG(__VA_ARGS__)    ///< provide a means for logging information from the falloc implementation
#define FA_DBG(...)                     // LOG(...)         ///< debug messages expand to calls to the body of this macro
#define FA_LOG_FUNC_FAIL(Fn, Status)    LOG_FUNC_FAIL(Fn, Status) ///< provide standardized-format error messages on failed function calls made by the the implementation of the fast allocator
#define FA_ERROR(...)                   ERROR(__VA_ARGS__)  ///< output explicit error messages on fast allocator operation failures
#endif // _HEAPFA_H_
/// @}