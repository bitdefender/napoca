/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file heapfa.c
///  @brief Implements the support functions needed for using the falloc.h fast allocators to aid to the performance of the heap implementation.
///

/// @defgroup heapfa
/// @ingroup heap
/// @{

#include "kernel/kernel.h"
#include "memory/heapfa.h"
#include "memory/falloc.h"

//
// Heap data structures and functions needed for forwarding allocations to a list of fast allocators
//

HP_FAST_ALLOCATORS_DATA gHpFastData = { 0 };

static
__forceinline
DWORD
_HpGetAllocatorVaSize(
    _In_ DWORD Size
)
// Returns the size of the VA memory range associated with an allocator
{
    UNREFERENCED_PARAMETER(Size); // for now they all have the same size for the VA reserved space
    return gHpFastData.ReservedVa.PerAllocator;
}

static
__forceinline
FA_ALLOCATOR*
_HpGetAllocatorBySize(
    _In_ DWORD Size
)
// what's the starting VA address interval for a given allocation size
{
    FA_ALLOCATOR* result = (FA_ALLOCATOR*)(gHpFastData.ReservedVa.Start + (QWORD)_HpGetAllocatorVaSize(Size) * (QWORD)Size);
    return result;
}


static
__forceinline
FA_ALLOCATOR*
_HpGetAllocatorByAllocatedAddress(
    _In_ PVOID AllocatedAddress,
    _Out_opt_ CX_UINT16* AllocationSize
)
// returns the allocator associated with a given allocated address or NULL for foreign addresses
{
    if (((PBYTE)AllocatedAddress < gHpFastData.ReservedVa.Start) || ((PBYTE)AllocatedAddress > gHpFastData.ReservedVa.Start + gHpFastData.ReservedVa.Total))
    {
        return NULL;
    }

    // find the allocator index (equal to the presumed allocation size)
    CX_UINT16 size = (CX_UINT16)(((QWORD)AllocatedAddress - (QWORD)gHpFastData.ReservedVa.Start) / (QWORD)gHpFastData.ReservedVa.PerAllocator);
    if (AllocationSize)
    {
        *AllocationSize = size;
    }
    return _HpGetAllocatorBySize(size);
}



static
__forceinline
NTSTATUS
_HpPrepareVaLayout(
    VOID
)
//
// On the very first created allocator only -- prepare a continuous VA memory layout for all possible/supported fast allocators
// On other calls, just return asap
//
{
    NTSTATUS status;
    BOOLEAN needToEndInit = FALSE;
    if ((!gHpFastData.VaReservedSpaceInitialized) && (CxInterlockedBeginOnce(&gHpFastData.VaReservedSpaceInitialized)))
    {
        needToEndInit = TRUE;

        // consider the highest supported allocation size and reserve as much space for each possible allocator
        status = FaGetMemRequirements(&gHpFastData.ReservedVa.PerAllocator, NULL, NULL, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("FaGetMemRequirements", status);
            goto cleanup;
        }

        gHpFastData.ReservedVa.Start = (PBYTE)NAPOCA_FAST_ALLOCATORS_VA_BASE;
        gHpFastData.ReservedVa.Total = (QWORD)HP_MAX_FAST_ALLOCATION_SIZE * (QWORD)gHpFastData.ReservedVa.PerAllocator;
        if (gHpFastData.ReservedVa.Total > NAPOCA_FAST_ALLOCATORS_VA_SIZE)
        {
            ERROR("the VA space assigned for the fast allocators is not large enough!\n");
            goto cleanup;
        }
        LOG("Reserved and/or using VA space from %p up to %p for all possible fast allocators, 0x%X per allocator\n", gHpFastData.ReservedVa.Start, gHpFastData.ReservedVa.Start + gHpFastData.ReservedVa.Total - 1, gHpFastData.ReservedVa.PerAllocator);
    }
    else if (!CxInterlockedPerformedOnce(&gHpFastData.VaReservedSpaceInitialized))
    {
        return CX_STATUS_OUT_OF_RESOURCES;
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    if (needToEndInit)
    {
        if (!SUCCESS(status))
        {
            CxInterlockedFailOnce(&gHpFastData.VaReservedSpaceInitialized);
        }
        else
        {
            if (!CxInterlockedEndOnce(&gHpFastData.VaReservedSpaceInitialized))
                return CX_STATUS_SYNCHRONIZATION_INCONSISTENCY;
        }
    }
    return status;
}



///
/// @brief        On the very first call for given size will prepare a new allocator and register it into the global heap fast allocators list, otherwise return the preexisting one
/// @param[in]    Size                             Allocation size of all allocations available through this allocator
/// @returns      CX_STATUS_OUT_OF_RESOURCES       - There are not enough memory resources available for configuring the virtual memory and physical pages needed for the requested allocator
/// @returns      CX_STATUS_SYNCHRONIZATION_INCONSISTENCY - There was a race condition with code running on another thread/CPU, code that didn't properly un/initialized the altered allocator
/// @returns      CX_STATUS_SUCCESS                on success
///
NTSTATUS
HpInitFastAllocator(
    _In_ DWORD Size
)
{
    NTSTATUS status;
    BOOLEAN needToEndInit = FALSE;

    if (CxInterlockedBeginOnce(&gHpFastData.StatsPerSize[Size].Initialized))
    {
        needToEndInit = TRUE;

        // plan the global VA layout for the allocators (if not already done)
        status = _HpPrepareVaLayout();
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_HpPrepareVaLayout", status);
            goto cleanup;
        }

        // find out the actual VA memory space requirements given the considered size
        CX_UINT32 vaReserve;
        status = FaGetMemRequirements(&vaReserve, NULL, NULL, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("FaGetMemRequirements", status);
            goto cleanup;
        }

        // reserve that much memory space at the planned VA
        status = MmReserveVa(&gHvMm, _HpGetAllocatorBySize(Size), vaReserve, TAG_FAST_ALLOC, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmReserveVa", status);
            ERROR("reservation for %d pages failed\n", PAGE_COUNT(NULL, vaReserve));
            goto cleanup;
        }

        // create an initially empty fast allocator at the very beginning the the reserved space
        status = FaCreate(NULL, (CX_UINT16)Size, _HpGetAllocatorBySize(Size), _HpGetAllocatorVaSize(Size));
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("FaCreate", status);
            goto cleanup;
        }

        LOG("Added dedicated allocator for size %4d, VA space %5d pages at [%p - %p) (%lld/%lld allocations were of this size)\n",
            Size, PAGE_COUNT(NULL, vaReserve), _HpGetAllocatorBySize(Size), (PBYTE)_HpGetAllocatorBySize(Size) + vaReserve,
            gHpFastData.StatsPerSize[Size].AllocCount, gHpFastData.Stats.TotalAllocations);
    }
    else if (!CxInterlockedPerformedOnce(&gHpFastData.StatsPerSize[Size].Initialized))
    {
        return CX_STATUS_OUT_OF_RESOURCES;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    if (needToEndInit)
    {
        if (!SUCCESS(status))
        {
            CxInterlockedFailOnce(&gHpFastData.StatsPerSize[Size].Initialized);
        }
        else
        {
            if (!CxInterlockedEndOnce(&gHpFastData.StatsPerSize[Size].Initialized))
                return CX_STATUS_SYNCHRONIZATION_INCONSISTENCY;
        }
    }
    return status;
}



///
/// @brief        Low-level function, use the heap.h API wherever possible instead! Gather allocation statistics and either handle the allocation with one of the fast allocators when this is a frequently encountered size or return an error, leaving the allocation to be handled by the standard heap implementation
/// @param[out]   Address                          Address of a pointer to be filled-in with the allocated element's address
/// @param[in]    Size                             How much memory to allocate
/// @returns      CX_STATUS_OUT_OF_RESOURCES       - The fast allocator for this element size does exist but it has no available memory for the allocation (not an actual issue as the allocation will be handled by the heap)
/// @returns      CX_STATUS_NOT_INITIALIZED        - A dedicated fast allocator for the allocation Size is not yet deemed necessary or isn't initialized/ready yet, the allocation must be handled by the heap
/// @returns      CX_STATUS_SUCCESS                on success
///
NTSTATUS
HpFastAlloc(
    _Out_ PVOID* Address,
    _In_ DWORD Size
)
{
    NTSTATUS status;

    // this is an internal function so we assume that boundary checks done by the caller
    if (!gHpFastData.StatsPerSize[Size].Initialized)
    {
        if (!_HpAboveThreshold(gHpFastData.StatsPerSize[Size].AllocCount, gHpFastData.Stats.TotalAllocations))
        {
            // account the allocation just in case it might get above the threshold later
            CxInterlockedIncrement64(&gHpFastData.StatsPerSize[Size].AllocCount);
            return CX_STATUS_NOT_INITIALIZED;
        }

        // we're above the threshold, create a new allocator (if some other "thread" doesn't or didn't do it first)
        status = HpInitFastAllocator(Size);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpInitFastAllocator", status);
            goto cleanup;
        }
    }

    // if we got to this point, there should exist an initialized allocator for this size
    if (!CxInterlockedPerformedOnce(&gHpFastData.StatsPerSize[Size].Initialized))
    {
        return CX_STATUS_NOT_INITIALIZED;
    }

    status = FaAlloc(_HpGetAllocatorBySize(Size), Address);
    if (SUCCESS(status))
    {
        FA_DBG("+[%d:%p => %p]\n", Size, _HpGetAllocatorBySize(Size), *Address);
        CxInterlockedIncrement64(&gHpFastData.Stats.TotalFastAllocations);
    }
    else if (status != CX_STATUS_OUT_OF_RESOURCES)
    {
        // out of resources is an expected (non-fatal) error, only tell about other errors
        LOG_FUNC_FAIL("FaAlloc", status);
    }

cleanup:
    return status;
}



///
/// @brief        Low-level specialized function, use the heap.h API instead when possible! Handle a free operation by its dedicated allocator
/// @param[out]   Address                          Address of the pointer to the memory to be freed (will be NULLed upon return)
/// @returns      CX_STATUS_NOT_FOUND              - The address is foreign to the fast allocators (it needs to be handled by the heap instead)
/// @returns      CX_STATUS_SUCCESS                on success
///
NTSTATUS
HpFastFree(
    _Out_ PVOID* Address
)
{
    CX_UINT16 size;
    FA_ALLOCATOR* allocator;

    allocator = _HpGetAllocatorByAllocatedAddress(*Address, &size);
    if (!allocator) return CX_STATUS_NOT_FOUND;

    NTSTATUS status = FaFree(allocator, *Address);
    if (SUCCESS(status))
    {
        FA_DBG("-[%d:%p => %p]\n", size, allocator, *Address);
        *Address = NULL;
        return CX_STATUS_SUCCESS;
    }
    else
    {
        LOG_FUNC_FAIL("FaFree", status);
    }
    return status;
}



///
/// @brief        Dump debug statistics about the current fast allocators and their memory usage
///
VOID
DumpFastAllocatorStats(
    VOID
)
{
    CX_UINT16 allocators = 0;
    CX_UINT64 totalSize = 0;
    for (CX_UINT16 i = 0; i < HP_MAX_FAST_ALLOCATION_SIZE; i++)
    {
        if (gHpFastData.StatsPerSize[i].Initialized == 2)
        {
            allocators++;
            FA_ALLOCATOR* allocator = _HpGetAllocatorBySize(i);
            totalSize += allocator->Header.ManagedAllocations.TotalSize;
        }
    }

    LOGN("Total fast allocators: %d, hit rate=%2.2f%%, total mem = %lldKB\n", allocators, (100 * (float)gHpFastData.Stats.TotalFastAllocations) / (float)gHpFastData.Stats.TotalAllocations, totalSize / KILO);
    LOGN("%-8s | %-8s | %-8s | %-8s | %-8s | %-8s | [%-16s - %16s)\n", "Size", "In Use%", "Hit%", "Mem", "Entries", "Resizes", "VaStart", "VaStop");

    for (CX_UINT16 i = 0; i < HP_MAX_FAST_ALLOCATION_SIZE; i++)
    {
        if (gHpFastData.StatsPerSize[i].Initialized != 2)
            continue;

        CX_UINT32 actualVaSize;
        FaGetMemRequirements(&actualVaSize, NULL, NULL, NULL);

        FA_ALLOCATOR* allocator = _HpGetAllocatorBySize(i);
        LOGN("%8d | %8.2f | %8.2f | %8d | %8d | %8d | [%18p - %18p)\n",
            allocator->Header.ManagedAllocations.RawElementSize,
            (float)100 - (100 * ((float)allocator->Header.PushCount - (float)allocator->Header.PopCount)) / (float)allocator->Header.ManagedAllocations.TotalEntries,
            (100 * (float)allocator->Header.PopCount / (float)gHpFastData.Stats.TotalAllocations),
            allocator->Header.ManagedAllocations.TotalSize,
            allocator->Header.ManagedAllocations.TotalEntries,
            allocator->Header.Reallocs.Counter,
            allocator,
            (PBYTE)allocator + actualVaSize);
    }

    LOGN("Fast allocators pagepool usage: total %d vs max %d pages",
        gHpFastData.Stats.TotalPhysicalPagesUsed, gHypervisorGlobalData.MemInfo.PerPpaPageCount * HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT / HP_PAGE_POOL_SUM);
}



//
// Napoca heap implementation for the interface functions required by falloc (the API described by falloc.h)
//
///
/// @brief        Implementation for the FaReserveVa function needed by (see) falloc.h, don't call this function directly!
/// @param[in]    Va                               Address of the pointer whose value is to be written
/// @param[in]    PageCount                        Number of 4K pages needed to be reserved (and only reserved, no memory needs to be committed yet)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS FaReserveVa(_Out_ CX_VOID** Va, _In_ CX_UINT32 PageCount)
{
    // no invalidation, this is only a memory reservation
    NTSTATUS status = MmReserveVa(&gHvMm, NULL, PAGE_SIZE * PageCount, TAG_FAST_ALLOC, Va);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmReserveVa", status);
        ERROR("reservation for %d pages failed\n", PageCount);
        goto cleanup;
    }
    else
    {
        FA_DBG("Reserved %p - %p\n", *Va, (PBYTE)(*Va) + PageCount * PAGE_SIZE - 1);
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



///
/// @brief        Implementation for the FaFreeVa function needed by (see) falloc.h, don't call this function directly!
/// @param[in]    Va                               The start of the address of the virtual memory range
/// @param[in]    Size                             Size in bytes of the memory region to be freed
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS FaFreeVa(_In_ CX_VOID* Va, _In_ CX_UINT32 Size)
{
    UNREFERENCED_PARAMETER(Size);

    // no invalidation, the free is only called when the VA is reserved but we fail at mapping
    // (actual cleanup/free of allocators is not supported)
    NTSTATUS status = MmUnmapMem(&gHvMm, TRUE, TAG_FAST_ALLOC, &Va);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmUnmapMem", status);
    }
    return status;
}



///
/// @brief        Implementation for the FaAllocAndMapPages function needed by (see) falloc.h, don't call this function directly!
/// @param[in]    Va                               Starting virtual address (page aligned) where allocated phyical pages must be mapped to
/// @param[in]    PageCount                        Number of (both) phyical pages and virtual pages to process
/// @returns      CX_STATUS_INSUFFICIENT_RESOURCES - Could not allocate the necessary memory, either there is no more memory available or the allocator has reached its internal limit
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS FaAllocAndMapPages(_In_ CX_VOID* Va, _In_ CX_UINT32 PageCount)
{
    NTSTATUS status;
    CX_UINT64 newPageCount;

    newPageCount = CxInterlockedAdd64(&gHpFastData.Stats.TotalPhysicalPagesUsed, PageCount);
    if (newPageCount > gHypervisorGlobalData.MemInfo.PerPpaPageCount * HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT / HP_PAGE_POOL_SUM)
    {
        FA_DBG("%d pages: total %d vs max %d pages",
            PageCount, newPageCount, gHypervisorGlobalData.MemInfo.PerPpaPageCount * HP_PAGE_POOL_FOR_FAST_ALLOCATORS_AMOUNT / HP_PAGE_POOL_SUM);

        return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = MmAlloc(&gHvMm, Va, 0, NULL, PageCount * PAGE_SIZE, TAG_FAST_ALLOC, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAlloc", status);
        goto cleanup;
    }

    FA_DBG("Mapped %d pages => [%p - %p)\n", PageCount, Va, (PBYTE)(Va) + PageCount * PAGE_SIZE);

    FA_DBG("Fast allocators now using 0x%llx pages!\n", newPageCount);

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



///
/// @brief        Implementation for the FaInitSpinlock function needed by (see) falloc.h, don't call this function directly!
/// @param[out]   Lock                             Address of the spinlock data/structure
/// @param[in?]   Name                             Provides a name for the newly initialized spinlock, the implementation may choose to ignore this parameter
///
CX_VOID FaInitSpinlock(_Out_ FA_LOCK *Lock, char *Name)
{
    HvInitSpinLock(Lock, Name, NULL);
    return;
}



///
/// @brief        Implementation for the FaLock function needed by (see) falloc.h, don't call this function directly!
/// @param[in, out] Lock                           Address of the lock data/structure
///
CX_VOID FaLock(_Inout_ FA_LOCK *Lock)
{
    HvAcquireSpinLock(Lock);
    return;
}



///
/// @brief        Implementation for the FaUnlock function needed by (see) falloc.h, don't call this function directly!
/// @param[in, out] Lock                           Address of the lock data/structure
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_VOID FaUnlock(_Inout_ FA_LOCK *Lock)
{
    HvReleaseSpinLock(Lock);
    return;
}
/// @}
