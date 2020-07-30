/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file falloc.c
///  @brief Implements a fast allocator of constant-size memory elements. Each allocator assumes a continuous virtual-address memory space that contains both the metadata and room for the actual elements, it starts with a minimal amount of actual physical memory and expands the used physical memory automatically based on pool usage, never releasing it back.
///

/// @defgroup falloc Fast allocation for small sized buffers
/// @ingroup memory

#include "napoca.h"
#include "kernel/kernel.h"
#include "memory/memmgr.h"
#include "kernel/kerneldefs.h"
#include "memory/memtags.h"
#include "memory/falloc.h"
#define DEBUG_FALLOC 0

// define some macros for debugging the implementation
#if DEBUG_FALLOC
#define FA_DUMP_USAGE(Allocator) FA_LOG("[%p]ManagedAllocations.TotalEntries=%d\n",\
    Allocator, Allocator->Header.ManagedAllocations.TotalEntries);
#define FA_DBG FA_LOG
#define FA_DBG_FUNC_FAIL(Fn, Status) FA_LOG_FUNC_FAIL(Fn, Status)
#else
#define FA_DUMP_USAGE(Allocator)
#define FA_DBG(...)
#define FA_DBG(...)
#define FA_DBG_FUNC_FAIL(Fn, Status)
#endif



__forceinline
static
CX_STATUS
_FaInit(
    _Inout_ FA_ALLOCATOR *Allocator,
    _In_ CX_UINT16 ElementSize
)
{
    FA_LOG("Init allocator at %p\n", Allocator);
    memzero(Allocator, sizeof(Allocator->Header));
    Allocator->Header.ManagedAllocations.ElementSize = CX_MAX(sizeof(FA_STACK_LIST), ElementSize); // at least sizeof(FA_STACK_LIST) bytes are always needed
    Allocator->Header.ManagedAllocations.RawElementSize = ElementSize;
    Allocator->Header.Reallocs.NextAllocationsBuffer = Allocator->Allocations;     // this is where the first allocated memory buffer should be mapped
    Allocator->Header.Tos.Empty = CX_TRUE;
    FaInitSpinlock(&Allocator->Header.Lock, "FALOCK");
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Reserve VA space for both the structure and the array of entries (each page aligned)map and initialize the structure to reflect
/// @param[out]   Allocator                        Allocator to setup (allowed to be missing if AlreadyReservedVa is given)
/// @param[in]    ElementSize                      Allocation granularity (the size of every allocation from this allocator)
/// @param[in]    AlreadyReservedVa                Starting virtual address for the managed memory and metadata
/// @param[in]    AlreadyReservedVaSize            Size of the available virtual address space available for the managed memory and metadata
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - AlreadyReservedVaSize is too small for fitting an allocator
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
FaCreate(
    _Out_opt_ FA_ALLOCATOR **Allocator,
    _In_ CX_UINT16 ElementSize,
    _In_opt_ CX_VOID *AlreadyReservedVa,
    _In_opt_ CX_UINT32 AlreadyReservedVaSize
)
{
    CX_VOID *ptr;
    CX_UINT32 vaReserve, vaCommit;
    CX_STATUS status = FaGetMemRequirements(&vaReserve, NULL, NULL, &vaCommit);
    if (!CX_SUCCESS(status))
    {
        FA_LOG_FUNC_FAIL("FaGetMemRequirements", status);
        return status;
    }

    if (AlreadyReservedVa)
    {
        // verify the given VA space
        if (AlreadyReservedVaSize < vaReserve)
        {
            return CX_STATUS_DATA_BUFFER_TOO_SMALL;
        }
        ptr = AlreadyReservedVa;
    }
    else
    {
        // or simply reserve VA space for everything
        status = FaReserveVa(&ptr, CX_PAGE_COUNT_4K(0, vaReserve));
        if (!CX_SUCCESS(status))
        {
            FA_LOG_FUNC_FAIL("FaReserveVa", status);
            return status;
        }
    }

    // and, for now, only map the min mandatory part right at the beginning of the VA range
    status = FaAllocAndMapPages(ptr, (CX_UINT32)CX_PAGE_COUNT_4K((CX_SIZE_T)ptr, vaCommit));
    if (!CX_SUCCESS(status))
    {
        FA_LOG_FUNC_FAIL("FaAllocAndMapPages", status);
        FaFreeVa(ptr, vaReserve);
        return status;
    }
    if (Allocator) *Allocator = (FA_ALLOCATOR*) ptr;
    return _FaInit(ptr, ElementSize);
}



__forceinline
static
CX_STATUS
_FaPushLinked(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *EntryDataPointer,
    _In_ CX_UINT32 EntryIndex
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    FA_STACK_LIST *addedElement = (FA_STACK_LIST *)EntryDataPointer;
    FA_STACK_LIST newTos;
    newTos.Empty = 0;
    newTos.Index = EntryIndex;

    FaLock(&Allocator->Header.Lock);
    *addedElement = Allocator->Header.Tos;
    Allocator->Header.Tos = newTos;
    FaUnlock(&Allocator->Header.Lock);

    CxInterlockedIncrement64(&Allocator->Header.PushCount);
    return status;
}



__forceinline
static
CX_STATUS
_FaPopLinked(
    _In_ FA_ALLOCATOR *Allocator,
    _Out_ CX_VOID **Entry
)
{
    FA_STACK_LIST *entry;

    FaLock(&Allocator->Header.Lock);
    if (Allocator->Header.Tos.Empty)
    {
        FaUnlock(&Allocator->Header.Lock);
        return CX_STATUS_OUT_OF_RESOURCES;
    }
    entry = (FA_STACK_LIST *)(Allocator->Allocations + Allocator->Header.Tos.Index * Allocator->Header.ManagedAllocations.ElementSize);
    Allocator->Header.Tos = *entry;
    FaUnlock(&Allocator->Header.Lock);

    CxInterlockedIncrement64(&Allocator->Header.PopCount);
    *Entry = entry;
    return CX_STATUS_SUCCESS;
}



__forceinline
static
CX_STATUS
_FaEnlargeBuffer(
    _In_ CX_UINT32              AddedBytes,
    _In_ CX_UINT32              BufferElementSize,
    _Inout_ volatile CX_UINT8   **BufferPointer,
    _Inout_ volatile CX_UINT32  *BufferSize,
    _Inout_ volatile CX_UINT32  *BufferElementCount
)
//
// Alloc and map more memory at the end of a buffer (BufferPointer points to the yet to be filled-in memory space)
// and update the state of the currently populated addresses in the given buffer
//
{
    // we always add some multiple of PAGE_SIZE bytes => find out the min amount of pages needed
    CX_UINT32 addedPageCount = (CX_UINT32)CX_PAGE_COUNT_4K((CX_SIZE_T)(*BufferPointer), AddedBytes);

    // readjust the added bytes value to reflect the page boundary round-up
    AddedBytes = addedPageCount * CX_PAGE_SIZE_4K;

    // perform the allocation and map the new pages at the end of the old region
    CX_STATUS status = FaAllocAndMapPages((CX_VOID*)*BufferPointer, addedPageCount);
    if (!CX_SUCCESS(status))
    {
        // unlock any waiters and return the error
        FA_LOG_FUNC_FAIL("FaAllocAndMapPages", status);
        return status;
    }

    // reuse any left-over space of ((*BufferSize) % BufferElementSize) bytes from the previous allocation (if any) to keep the entries array continuous
    CX_UINT32 addedEntries = (AddedBytes + ((*BufferSize) % BufferElementSize)) / BufferElementSize;

    // reflect the new buffer pointer, buffer size and the new element count
    *BufferPointer += AddedBytes;
    *BufferSize += AddedBytes;
    *BufferElementCount += addedEntries;
    return CX_STATUS_SUCCESS;
}



__forceinline
static
CX_STATUS
_FaEnlargeMemory(
    _Inout_ FA_ALLOCATOR *Allocator
)
//
// validate & double the stack size if necessary and possible or return error
//
{
    CX_UINT16 numberOfReallocs = (CX_UINT16)Allocator->Header.Reallocs.Counter;

    // find out the memory requirements of this stack
    CX_UINT32 maxDataVaSpace;
    CX_STATUS status = FaGetMemRequirements(NULL, NULL, &maxDataVaSpace, NULL);
    if (!CX_SUCCESS(status))
    {
        FA_LOG_FUNC_FAIL("FaGetMemRequirements", status);
        return status;
    }

    // did we already reach the mex allowed entries or maximum supported resizes or VA space?
    if (numberOfReallocs >= FA_MAX_REALLOCS)
    {
        FA_ERROR("numberOfReallocs >= FA_MAX_REALLOCS (0x%x >= 0x%x)\n", numberOfReallocs, FA_MAX_REALLOCS);
        return CX_STATUS_OUT_OF_RESOURCES;
    }

    BOOLEAN needToEndOnce = FALSE;

    // make sure only one caller gets to actually expand the stack, others will wait for the update to finish
    if (CxInterlockedBeginOnce(&Allocator->Header.Reallocs.Init[numberOfReallocs]))
    {
        FA_DBG("[%d]BEGIN_UPDATE[%d]\n", Allocator->Header.ManagedAllocations.RawElementSize, numberOfReallocs);
        needToEndOnce = TRUE;

        if (maxDataVaSpace <= Allocator->Header.ManagedAllocations.TotalSize)
        {
            FA_ERROR("maxDataVaSpace <= Allocator->Header.ManagedAllocations.TotalSize (0x%x < 0x%x) RawElementSize 0x%x\n",
                maxDataVaSpace, Allocator->Header.ManagedAllocations.TotalSize, Allocator->Header.ManagedAllocations.RawElementSize);
            status = CX_STATUS_OUT_OF_RESOURCES;
            goto cleanup;
        }

        // decide how much memory we should add by fallowing a 4K -> 8K -> 16K increments pattern but staying in VA limits
        CX_UINT32 addedDataSize = Allocator->Header.ManagedAllocations.TotalSize? Allocator->Header.ManagedAllocations.TotalSize : CX_PAGE_SIZE_4K;
        addedDataSize = CX_MIN(addedDataSize, maxDataVaSpace - Allocator->Header.ManagedAllocations.TotalSize); // '-' is safe, tested above^

        if (!addedDataSize)
        {
            FA_ERROR("!addedDataSize\n");
            status = CX_STATUS_OUT_OF_RESOURCES;
            goto cleanup;
        }

        // apply the memory increment
        CX_UINT32 entriesBefore = Allocator->Header.ManagedAllocations.TotalEntries;
        status = _FaEnlargeBuffer(
                                    addedDataSize,
                                    Allocator->Header.ManagedAllocations.ElementSize,
                                    &Allocator->Header.Reallocs.NextAllocationsBuffer,
                                    &Allocator->Header.ManagedAllocations.TotalSize,
                                    &Allocator->Header.ManagedAllocations.TotalEntries);
        if (!CX_SUCCESS(status))
        {
            FA_LOG_FUNC_FAIL("_FaEnlargeBuffer", status);
            goto cleanup;
        }

        CX_UINT32 newlyAddedEntries = Allocator->Header.ManagedAllocations.TotalEntries - entriesBefore;

        // now that we have the data entries, push all the new indexes into the stack so they can be allocated/used
        CX_UINT32 firstNewDataEntryIndex = entriesBefore;                           // add from this very first index
        CX_UINT32 lastNewDataEntryIndex = entriesBefore + newlyAddedEntries - 1;    // and up to this entry (inclusive)

        for (CX_UINT32 entryIndex = firstNewDataEntryIndex; entryIndex <= lastNewDataEntryIndex; entryIndex++)
        {
            status = FaFreeEx(Allocator, Allocator->Allocations + entryIndex * Allocator->Header.ManagedAllocations.ElementSize);
            if (!CX_SUCCESS(status))
            {
                FA_LOG_FUNC_FAIL("FaFreeEx", status);
                goto cleanup;
            }
        }
        FA_DBG("[%p] Resized[%d] by adding +%d entries (total: entries=%d, mem=%d)\n", Allocator, numberOfReallocs, newlyAddedEntries, Allocator->Header.ManagedAllocations.TotalEntries, Allocator->Header.ManagedAllocations.TotalSize);
    }
    else if (!CxInterlockedPerformedOnce(&Allocator->Header.Reallocs.Init[numberOfReallocs]))
    {
        // this operation has already fail when tried by another "thread"
        FA_DBG("CxInterlockedPerformedOnce has failed: %d\n", Allocator->Header.Reallocs.Init[numberOfReallocs]);
        status = CX_STATUS_OUT_OF_RESOURCES;
    }

cleanup:
    if (needToEndOnce)
    {
        if (!CX_SUCCESS(status))
        {
            FA_DBG("[%d]FAIL_UPDATE[%d]\n", Allocator->Header.ManagedAllocations.RawElementSize, numberOfReallocs);
            CxInterlockedFailOnce(&Allocator->Header.Reallocs.Init[numberOfReallocs]);
        }
        else
        {
            FA_DBG("[%d]END_UPDATE[%d]\n", Allocator->Header.ManagedAllocations.RawElementSize, numberOfReallocs);
            if (CxInterlockedEndOnce(&Allocator->Header.Reallocs.Init[numberOfReallocs]))
            {
                CxInterlockedIncrement32(&Allocator->Header.Reallocs.Counter);
            }
            else
            {
                status = CX_STATUS_SYNCHRONIZATION_INCONSISTENCY; // overwrite original status with a critical one
            }
        }
    }

    return status;
}



__forceinline
static
CX_STATUS
_FaAllocLinkedStack(
    _In_ FA_ALLOCATOR *Allocator,
    _Out_ CX_VOID **Data
)
{
    CX_STATUS status;

    // try allocating a data entry
    CX_VOID *Entry;
    status = _FaPopLinked(Allocator, &Entry);
    if (status == CX_STATUS_OUT_OF_RESOURCES)
    {
        // get more memory if needed and possible
        if (Allocator->Header.Reallocs.Failed)
        {
            return status;
        }

        CX_STATUS enlargeStatus;
        do
        {
            enlargeStatus = _FaEnlargeMemory(Allocator);
            if (!CX_SUCCESS(enlargeStatus))
            {
                FA_DBG_FUNC_FAIL("_FaEnlargeMemory", enlargeStatus);
                CxInterlockedExchange8(&Allocator->Header.Reallocs.Failed, CX_TRUE);
                return status;
            }

            // retry now that we have more memory
            status = _FaPopLinked(Allocator, &Entry);
        } while (!CX_SUCCESS(status) && CX_SUCCESS(enlargeStatus));

        if (!CX_SUCCESS(status))
        {
            FA_LOG_FUNC_FAIL("_FaPopLinked", status);
            FA_DUMP_USAGE(Allocator);
            return status;
        }
    }
    *Data = Entry;
    return CX_STATUS_SUCCESS;
}



__forceinline
static
CX_STATUS
_FaFreeLinkedStack(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *Data
)
{
    if ((CX_SIZE_T)Data < (CX_SIZE_T)Allocator->Allocations)
    {
        FA_ERROR("Data=%p < Allocator->Allocations=%p\n", Data, Allocator->Allocations);
        return CX_STATUS_DATA_NOT_FOUND;
    }
    CX_SIZE_T freedIndex = ((CX_SIZE_T)Data - (CX_SIZE_T)Allocator->Allocations) / Allocator->Header.ManagedAllocations.ElementSize;
    if (freedIndex >= Allocator->Header.ManagedAllocations.TotalEntries)
    {
        FA_ERROR("(freedIndex=%lld >= Allocator->Header.ManagedAllocations.TotalEntries=%d)\n", (CX_UINT64)freedIndex, Allocator->Header.ManagedAllocations.TotalEntries);
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    return _FaPushLinked(Allocator, Allocator->Allocations + freedIndex * Allocator->Header.ManagedAllocations.ElementSize, (CX_UINT32)freedIndex);
}



///
/// @brief        Low-level memory allocation function, fills-in the Data pointer's value with the address of a new allocation from the given Allocator
/// @param[in]    Allocator                        Address of the allocator descriptor of the memory pool to allocate from
/// @param[out]   Data                             Output pointer to receive the address of the allocated element
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
FaAllocEx(
    _In_ FA_ALLOCATOR *Allocator,
    _Out_ CX_VOID **Data
)
{
    return _FaAllocLinkedStack(Allocator, Data);
}



///
/// @brief        Low-level function for freeing up an address allocated previously by a call to FaAllocEx
/// @param[in]    Allocator                        Address of the allocator descriptor that manages the memory pool
/// @param[in]    Data                             Address of the allocated memory that is to be freed
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
FaFreeEx(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *Data
)
{
    return _FaFreeLinkedStack(Allocator, Data);
}
/// @}