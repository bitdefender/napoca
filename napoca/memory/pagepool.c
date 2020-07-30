/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup pagepool Page-pool physical memory management
/// @ingroup memory
/// @{
#include "napoca.h"
#include "memory/pagepool.h"
#include "memory/memmgr.h"
#include "kernel/spinlock.h"
#include "kernel/kerneldefs.h"
#include "debug/debugger.h"
#include "boot/boot.h"
#include "base/ilockrr.h"

/// @brief Page-Pool allocator header. Contains internal data for each page-pool allocator that may be created in case of parallel usage.
#pragma warning(disable:4200)   // disable zero-sized array in struct/union warning
typedef struct _PPA_HEADER {
    SPINLOCK        Lock;           ///< Lock used to serialize access to this page-pool allocator
    DWORD           Size;           ///< Size in bytes of this header
    INT32           PageCount;      ///< Total number of pages managed by this allocator
    INT32           FreeCount;      ///< Free pages available and managed by this page-pool allocator
    BYTE*           FirstPage;      ///< Virtual address that maps the first physical page managed by this allocator in HvVa range
    BYTE*           LastVa;         ///< Virtual address that maps the last physical page managed by this allocator in HvVa range
    INT32           FirstFreeHint;  ///< Hint to the first free page
    QWORD           MinPhyAddr;     ///< Address of first physical page managed by this allocator
    QWORD           MaxPhyAddr;     ///< Address of last physical page managed by this allocator
    QWORD           Bitmap[];       ///< Bitmap that marks the used/free pages that are managed by this allocator
} PPA_HEADER;
#pragma warning(default:4200)   // set to default zero-sized array in struct/union warning

/// @brief Global data that manages all page-pool allocators. It has a fixed size of 1 page always, at the start of the PP zone
typedef struct _PPA_GLOBAL {
    BYTE*           PagePoolBase;                               ///< Virtual address that maps all physical pages available in page-pool
    DWORD           Pc;                                         ///< Number of parallel allocation supported
    DWORD           Size;                                       ///< Size in bytes of this header
    PPA_HEADER*     PpAllocator[NAPOCA_MAX_PARALLELIZATION];    ///< Page-pool allocators for parallel access
    ILOCK_RR        RrHint;                                     ///< ROUND ROBIN hint
    BOOLEAN         Initialized;                                ///< Indicates that all page-pool allocators are initialized
    QWORD           PagePoolLength;                             ///< Length in bytes of entire page pool
} PPA_GLOBAL;

/// @brief Global page-pool allocator instance
static
PPA_GLOBAL* gPpAllocator = NULL;


/// @brief Retrieves an index to corresponding allocator that is identified by the provided selector
/// @param Allocator        Allocator selector
/// @param PpaIndex         corresponding index
/// @return CX_STATUS_INVALID_PARAMETER_1       If selector is invalid
/// @return CX_STATUS_SUCCESS                   On success
__forceinline
static
NTSTATUS
_PpGetAllocator(
    _In_ PP_ALLOCATOR Allocator,
    _Out_ INT32 *PpaIndex
)
{
    INT32 ppaIndex = 0;
    if (Allocator.Type == PP_ALLOCATOR_BY_INDEX)
    {
        if (Allocator.Value.ByIndex >= 0 && (Allocator.Value.ByIndex < (INT32)gPpAllocator->Pc))
        {
            ppaIndex = Allocator.Value.ByIndex;
        }
        else
        {
            ERROR("Allocator index is outside of range!\n");
            return CX_STATUS_INVALID_PARAMETER_1;
        }
    }
    else if ((Allocator.Value.ByType == PP_ALLOCATOR_ROUNDROBIN) || (Allocator.Value.ByType == PP_ALLOCATOR_INIT))
    {
        // use ROUND-ROBIN hint
        ppaIndex = IrrGetNext(&gPpAllocator->RrHint);
    }
    else if (Allocator.Value.ByType == PP_ALLOCATOR_MAXFREE)
    {
        INT32 t;
        INT32 maxFree, maxIndex;

        maxFree = gPpAllocator->PpAllocator[0]->FreeCount;
        maxIndex = 0;

        for (t = 1; t <= (INT32)gPpAllocator->Pc - 1; t++)
        {
            if (gPpAllocator->PpAllocator[t]->FreeCount > maxFree)
            {
                maxFree = gPpAllocator->PpAllocator[t]->FreeCount;
                maxIndex = t;
            }
        }

        ppaIndex = maxIndex;
    }
    else
    {
        ERROR("Allocator not in (PP_ALLOCATOR_ROUNDROBIN|PP_ALLOCATOR_INIT|PP_ALLOCATOR_MAXFREE)\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    *PpaIndex = ppaIndex;
    return CX_STATUS_SUCCESS;
}

/// @brief Resolves the mapping of a physical address from page pool to its corresponding virtual address.
///
/// The virtual address is in range 1T -\> 1T + \<TotalMemSizeForHv\>
///
/// @param Pa       Physical address to be resolved
/// @param Va       corresponding virtual address
/// @return         TRUE if a mapping is available
/// @return         FALSE if a mapping is not available
static
__forceinline
BOOLEAN
_PpPaToVa(
    _In_ QWORD Pa,
    _Out_ QWORD *Va
)
{
    BOOLEAN found = FALSE;
    QWORD va = 0;
    QWORD delta = 0;
    DWORD i = 0;

    if (NULL == Va) return FALSE;

    // for now, just do a plain linear search on HvMemMap; this assumes HvMemMap is strictly ordered
    // now, we must find out in which HvZone chunk does delta fit into?
    for (i = 0; i < gBootInfo->HvMemMap->HvZoneCount; i++)
    {
        if ((Pa >= gBootInfo->HvMemMap->Entries[i].StartAddress) &&
            (Pa < (gBootInfo->HvMemMap->Entries[i].StartAddress + gBootInfo->HvMemMap->Entries[i].Length - 1)))
        {
            // bingo, chunk found
            va = NAPOCA_KERNEL_BASE + delta + Pa - gBootInfo->HvMemMap->Entries[i].StartAddress;

            found = TRUE;
            break;
        }

        // sum up all chunk sizes into delta
        delta = delta + gBootInfo->HvMemMap->Entries[i].Length;
    }

    *Va = va;

    return found;
}



void
PpPreinitAllocator(
    _In_ VOID* PagePoolBase,
    __out_opt VOID** PagePoolAllocator
)

{
    gPpAllocator = (PPA_GLOBAL*)PagePoolBase;
    gPpAllocator->PagePoolBase = PagePoolBase;

    memzero(gPpAllocator, ROUND_UP(sizeof(PPA_GLOBAL), PAGE_SIZE));

    gPpAllocator->Initialized = FALSE;

    if (PagePoolAllocator) *PagePoolAllocator = gPpAllocator;
}



NTSTATUS
PpInitAllocator(
    _In_ QWORD PagePoolLength,
    _In_ DWORD MaxParallel,
    _Out_ QWORD* PerAllocatorPageCount
)
{
    // basic initialization
    gPpAllocator->Pc = MaxParallel;
    gPpAllocator->PagePoolLength = PagePoolLength;
    gPpAllocator->Size = ROUND_UP(sizeof(PPA_GLOBAL), PAGE_SIZE);

    // distribute PP pool between serialized PP allocators
    {
        QWORD globalHeaderPageCount;
        QWORD totalPageCount;
        QWORD nextFreePageIndex;
        QWORD totalPagesRemaining;
        QWORD maxPagePerPpa;
        QWORD requiredBitmapLength;
        QWORD totalHeaderSize;
        QWORD headerPageCount;
        QWORD allocablePageCount;

        globalHeaderPageCount = ROUND_UP(gPpAllocator->Size, PAGE_SIZE) / PAGE_SIZE;
        nextFreePageIndex = globalHeaderPageCount;                          // skip global header

        totalPageCount = (PagePoolLength / PAGE_SIZE) - globalHeaderPageCount;

        maxPagePerPpa = (totalPageCount) / gPpAllocator->Pc;

        // now, we know that up to maxPagePerPpa we can have in a serialized PP allocator (this is a gross upper limit, because headers and round-down apply)
        requiredBitmapLength = ROUND_UP((maxPagePerPpa-1), 4) / 4;      // 4 pages / BYTE  (2 bits / page)
        totalHeaderSize = sizeof(PPA_HEADER) + requiredBitmapLength;
        headerPageCount = ROUND_UP(totalHeaderSize, PAGE_SIZE) / PAGE_SIZE;
        allocablePageCount = ROUND_DOWN((maxPagePerPpa - headerPageCount), (256 * 1024 / PAGE_SIZE));   // allocablePageCount must be multiple of 256K

        // store this value in global kernel vars
        *PerAllocatorPageCount = allocablePageCount;

        // good, now we know the exact size of each serialized PP allocator header and allocable page zone ==> setup them (except the last one)
        for (DWORD i = 0; i < gPpAllocator->Pc - 1; i++)
        {
            PPA_HEADER* head;
            NTSTATUS status;

            head = (PPA_HEADER*)( (BYTE*)gPpAllocator + nextFreePageIndex * PAGE_SIZE);
            nextFreePageIndex += headerPageCount;                           // consume headerPageCount

            memzero(head, ROUND_UP(totalHeaderSize, PAGE_SIZE));
            head->Size = (DWORD)ROUND_UP(totalHeaderSize, PAGE_SIZE);
            gPpAllocator->PpAllocator[i] = head;

            HvInitSpinLock(&gPpAllocator->PpAllocator[i]->Lock, "PPA_HEADER->Lock", gPpAllocator->PpAllocator[i]);

            head->FirstPage = (BYTE*)gPpAllocator + nextFreePageIndex * PAGE_SIZE;
            head->PageCount = (INT32)allocablePageCount;
            head->LastVa = head->FirstPage + head->PageCount * PAGE_SIZE - 1;
            head->FreeCount = head->PageCount;
            head->FirstFreeHint = 0;
            nextFreePageIndex += allocablePageCount;                        // consume allocablePageCount

            status = MmQueryPa(&gHvMm, head->FirstPage, &head->MinPhyAddr);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmQueryPa", status);
                return status;
            }

            status = MmQueryPa(&gHvMm, head->LastVa, &head->MaxPhyAddr);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmQueryPa", status);
                return status;
            }
        }

        // calc space for the last allocator (use as much as we can from all pages that remain)
        totalPagesRemaining = totalPageCount - nextFreePageIndex;
        requiredBitmapLength = ROUND_UP((totalPagesRemaining-1), 4) / 4;    // 4 pages / BYTE  (2 bits / page)
        totalHeaderSize = sizeof(PPA_HEADER) + requiredBitmapLength;
        headerPageCount = ROUND_UP(totalHeaderSize, PAGE_SIZE) / PAGE_SIZE;
        allocablePageCount = ROUND_DOWN((totalPagesRemaining - headerPageCount), (256 * 1024 / PAGE_SIZE));   // allocablePageCount must be multiple of 256K

        // now setup the last serialized allocator
        {
            PPA_HEADER* head;
            NTSTATUS status;

            DWORD i = gPpAllocator->Pc - 1;

            head = (PPA_HEADER*)( (BYTE*)gPpAllocator + nextFreePageIndex * PAGE_SIZE);
            nextFreePageIndex += headerPageCount;                           // consume headerPageCount
            memzero(head, ROUND_UP(totalHeaderSize, PAGE_SIZE));
            head->Size = (DWORD)ROUND_UP(totalHeaderSize, PAGE_SIZE);
            gPpAllocator->PpAllocator[i] = head;

            HvInitSpinLock(&gPpAllocator->PpAllocator[i]->Lock, "PPA_HEADER->Lock", gPpAllocator->PpAllocator[i]);

            head->FirstPage = (BYTE*)gPpAllocator + nextFreePageIndex * PAGE_SIZE;
            head->PageCount = (INT32)allocablePageCount;
            head->LastVa = head->FirstPage + head->PageCount * PAGE_SIZE - 1;
            head->FreeCount = head->PageCount;
            head->FirstFreeHint = 0;
            nextFreePageIndex += allocablePageCount;                        // consume allocablePageCount
            status = MmQueryPa(&gHvMm, head->FirstPage, &head->MinPhyAddr);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmQueryPa", status);
                return status;
            }
            status = MmQueryPa(&gHvMm, head->LastVa, &head->MaxPhyAddr);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmQueryPa", status);
                return status;
            }
        }
    }

    IrrInit(&gPpAllocator->RrHint, (INT32)gPpAllocator->Pc);

    gPpAllocator->Initialized = TRUE;

    return CX_STATUS_SUCCESS;
}


//
// special macros to handle red/blue mappings for PP allocator
//
#define PP_IS_FREE(bitmap, index)       (0 == ((*((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL)))) & BIT_AT((index) & 0x3F)))
#define PP_SET_FREE(bitmap, index)      *((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL))) &= ~BIT_AT((index) & 0x3F)
#define PP_SET_ALLOC(bitmap, index)     *((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL))) |= BIT_AT((index) & 0x3F)
#define PP_IS_CHAINED(bitmap, index)    (0 != ((*((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL) + 8))) & BIT_AT((index) & 0x3F)))
#define PP_SET_CHAINED(bitmap, index)   *((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL) + 8)) |= BIT_AT((index) & 0x3F)
#define PP_SET_LAST(bitmap, index)      *((QWORD*)(((BYTE*)(bitmap)) + (((index) >> 2) & 0xFFFFFFFFFFFFFFF0ULL) + 8)) &= ~BIT_AT((index) & 0x3F)



NTSTATUS
PpAlloc(
    _In_ MDL* Mdl,
    _In_ DWORD NumberOfPages,
    _In_ PP_OPTIONS Options,
    _In_ PP_ALLOCATOR Allocator,
    __out_opt VOID** HvVa
)
{
    NTSTATUS status;
    PPA_HEADER* ppa;
    BOOLEAN allocated;
    INT32 ppaIndex, ppaIndexBarrier;
    VOID* va;
    MDL* mdl;

    ppa = NULL;
    allocated = FALSE;
    ppaIndex = -1;
    ppaIndexBarrier = -1;
    va = NULL;

    if (!gPpAllocator->Initialized) return CX_STATUS_NOT_INITIALIZED;

    if (NULL == Mdl) return CX_STATUS_INVALID_PARAMETER_1;

    mdl = Mdl;

    // check that we have at least one entry in the MDL
    if (mdl->AllocCount <= 0) return CX_STATUS_INVALID_PARAMETER_1;

    if (NumberOfPages == 0) return CX_STATUS_INVALID_PARAMETER_2;

    status = _PpGetAllocator(Allocator, &ppaIndex);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_PpGetAllocator", status);
        return CX_STATUS_INVALID_PARAMETER_4;
    }

    // get first serialized PP allocator
    ppaIndexBarrier = ppaIndex;
    ppa = gPpAllocator->PpAllocator[ppaIndex];

    if (NULL != HvVa) *HvVa = NULL;

    // preinit MDL
    mdl->EntryCount = 0;
    mdl->TotalPageCount = 0;
    mdl->Entry[0].PageCount = 0;
    mdl->MappedVa = NULL;

    // try to allocate from several PP allocators if needed
    for (;;)
    {
        allocated = FALSE;

        // can we try to allocate from currently selected Ppa ?
        if (ppa->FreeCount >= (INT32)NumberOfPages)
        {
            INT32 i;
            DWORD k;
            DWORD mdlEntryIndex;

            HvAcquireSpinLock(&ppa->Lock);

            if ((ppa->FreeCount < (INT32)NumberOfPages) ||
                (ppa->FirstFreeHint + (INT32)NumberOfPages - 1 >= ppa->PageCount))
            {
                HvReleaseSpinLock(&ppa->Lock);
                goto try_another_serialized_pp_allocator;
            }

            // if we need physically continuous pages, we MUST do a lookup first
            if (Options.Continuos)
            {
                BOOLEAN found;

                found = TRUE;
                i = ppa->FirstFreeHint;
                for (;;)
                {
                    QWORD thisPa = 0, prevPa;

                    // do we have enough pages left until the end of the pool?
                    if (i + (INT32)NumberOfPages > ppa->PageCount)
                    {
                        found = FALSE;
                        break;
                    }

                    found = TRUE;
                    prevPa = 0;
                    for (k = i; k < i + NumberOfPages; k++)
                    {
                        if (!PP_IS_FREE(ppa->Bitmap, k))        // if a single NOT-free found ==> we surely can't find enough continuous pages starting at i
                        {                                       // keep in mind, that this check is only for HV-VA continuity...
                            i = k + 1;
                            found = FALSE;
                            break;
                        }

                        // we must also check, that this page is physically continuous with the previous page
                        status = MmQueryPa(&gHvMm, (VOID*)((QWORD)ppa->FirstPage + k * PAGE_SIZE), &thisPa);
                        if (!SUCCESS(status))
                        {
                            break;
                        }

                        if ((INT32)k > i)
                        {
                            if (thisPa != (prevPa + PAGE_SIZE))
                            {
                                i = k + 1;
                                found = FALSE;
                                break;
                            }
                        }
                        prevPa = thisPa;
                    }

                    // if enough free pages found ==> stop, otherwise continue search from k+1
                    if (found) break;
                }

                if (!found)
                {
                    HvReleaseSpinLock(&ppa->Lock);
                    allocated = FALSE;
                    goto try_another_serialized_pp_allocator;
                }
                // give back also HvVa, if needed
                if (NULL != HvVa) va = ppa->FirstPage + i * PAGE_SIZE;
            }
            else
            {
                // if it is NOT required to be physically continuous, we just start processing at FirstFreeHint
                i = ppa->FirstFreeHint;

                while ((i < ppa->PageCount) && (!PP_IS_FREE(ppa->Bitmap, i)))
                {
                    i++;
                }
                if (!PP_IS_FREE(ppa->Bitmap, i))
                {
                    HvReleaseSpinLock(&ppa->Lock);
                    return STATUS_PP_INCONSISTENCY;
                }
            }

            // if we found what we need ==> proceed and allocate, as much as we can (all, or until the MDL is full)
            mdl->PpAllocHint = ppaIndex;            // this is important for free

            k = 0;
            mdlEntryIndex = 0;

            while (k < NumberOfPages)
            {
                QWORD pa = 0;

                // allocate one page from i
                PP_SET_ALLOC(ppa->Bitmap, i);
                PP_SET_LAST(ppa->Bitmap, i);        // just unchain it, this is an MDL based alloc
                ppa->FreeCount--;

                status = MmQueryPa(&gHvMm, (VOID*)(((QWORD)ppa->FirstPage) + i * PAGE_SIZE), &pa);
                if (!SUCCESS(status))
                {
                    return status;
                }

                // place that page into the MDL (might need to switch to another MDL entry, or break out if MDL is full)
                if (0 == mdl->Entry[mdlEntryIndex].PageCount)
                {
                    // this is the first page from a new MDL entry - setup the MDL entry
                    mdl->Entry[mdlEntryIndex].BaseAddress = MDL_PAGE_BASE(pa);
                    mdl->Entry[mdlEntryIndex].PageCount = 1;
                    mdl->EntryCount++;
                }
                else if ((MDL_PAGE_BASE(mdl->Entry[mdlEntryIndex].BaseAddress) + mdl->Entry[mdlEntryIndex].PageCount * PAGE_SIZE == pa) &&
                    (mdl->Entry[mdlEntryIndex].PageCount < MDL_MAX_PAGES_PER_ENTRY))
                {
                    // this is a continuous PA page and we can add one more page to the MDL entry ==> add it
                    mdl->Entry[mdlEntryIndex].PageCount++;
                }
                else
                {
                    // can we setup a new MDL entry?
                    if (mdl->EntryCount >= mdl->AllocCount)
                    {
                        BOOLEAN reallocDone;

                        reallocDone = FALSE;

                        // can we realloc a dynamic MDL?
                        if (0 == (mdl->Flags & MDL_FLAG_STATIC))
                        {
                            status = MdlRealloc(&mdl, 2*mdl->AllocCount);
                            if (!SUCCESS(status))
                            {
                                LOG("ERROR: MdlRealloc failed, status=%s\n", NtStatusToString(status));
                            }
                            else
                            {
                                reallocDone = TRUE;
                            }
                        }

                        if (!reallocDone)
                        {
                            PP_SET_FREE(ppa->Bitmap, i);
                            ppa->FreeCount++;

                            if (!Options.AcceptIncompleteAllocation)
                            {
                                HvReleaseSpinLock(&ppa->Lock);
                                PpFree(mdl);
                                MdlReset(mdl);
                                return CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            }
                            break;
                        }
                    }

                    mdlEntryIndex++;
                    mdl->EntryCount++;

                    mdl->Entry[mdlEntryIndex].BaseAddress = MDL_PAGE_BASE(pa);
                    mdl->Entry[mdlEntryIndex].PageCount = 1;
                }

                // count this page
                k++;

                if (k >= NumberOfPages) break;

                // go to next page
                if (Options.Continuos)
                {
                    i = i + 1;    // this was the easy case
                }
                else
                {
                    // and the hard case: we must increment i until we reach another free page
                    while ((i < ppa->PageCount) && (!PP_IS_FREE(ppa->Bitmap, i)))
                    {
                        i++;
                    }
                    if (!PP_IS_FREE(ppa->Bitmap, i))
                    {
                        HvReleaseSpinLock(&ppa->Lock);
                        return STATUS_PP_INCONSISTENCY;
                    }
                }
            } // while (k < NumberOfPages)

            mdl->TotalPageCount = k;        // might be less than NumberOfPages
            allocated = TRUE;

            // update first-free hint
            if (ppa->FreeCount > 0)
            {
                // we need to check the current FirstFreeHint; if not free anymore, then bump i++ until we get a free page
                if (!PP_IS_FREE(ppa->Bitmap, ppa->FirstFreeHint))
                {
                    i = ppa->FirstFreeHint+1;
                    while (i < ppa->PageCount)
                    {
                        // if i is free, then use it as first-free-hint
                        if (PP_IS_FREE(ppa->Bitmap, i))
                        {
                            ppa->FirstFreeHint = i;
                            break;
                        }
                        i++;
                    }
                    if (i == ppa->PageCount)            // this shall never happen, actually
                    {
                        ppa->FirstFreeHint = ppa->PageCount-1;
                    }
                }
            }
            else
            {
                ppa->FirstFreeHint = ppa->PageCount-1;
            }

            HvReleaseSpinLock(&ppa->Lock);
        }

        // if successfully allocated ==> give back
        if (allocated)
        {
            if (Options.Continuos && HvVa) *HvVa = va;
            break;
        }

        //
        // if not successfully allocated, try to select another Ppa
        //
try_another_serialized_pp_allocator:

        // go to next index
        ppaIndex = ppaIndex + 1;
        if (ppaIndex >= (INT32)gPpAllocator->Pc) ppaIndex = 0;

        // did we get back to the original Ppa?
        if (ppaIndex == ppaIndexBarrier) break;

        ppa = gPpAllocator->PpAllocator[ppaIndex];
    }

    // determine final status
    if (allocated)
    {
        if (mdl->TotalPageCount < NumberOfPages)
        {
            status = STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW;
        }
        else
        {
            if (!SUCCESS(status)) status = CX_STATUS_SUCCESS;
        }
    }
    else
    {
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}


/// @brief Retrieves a page-pool allocator based on a physical address. The physical address must be in range of physical pages managed by an allocator.
/// @param PhysicalAddress      Physical address for which the corresponding allocator is requested
/// @param Allocator            corresponding allocator
/// @return CX_STATUS_DATA_NOT_FOUND    No allocator manages the given physical address
/// @return CX_STATIS_SUCCESS           On success
static
__forceinline
NTSTATUS
_PpGetAllocatorByPa(
    _In_ QWORD PhysicalAddress,
    _Out_ PPA_HEADER* *Allocator
)
{
    DWORD i;
    PhysicalAddress = PAGE_BASE_PA(PhysicalAddress);

    // lookup Ppa corresponding to this pointer
    for (i = 0; i < gPpAllocator->Pc; i++)
    {
        if ((PhysicalAddress >= gPpAllocator->PpAllocator[i]->MinPhyAddr) && (PhysicalAddress <= gPpAllocator->PpAllocator[i]->MaxPhyAddr))
        {
            *Allocator = gPpAllocator->PpAllocator[i];
            return CX_STATUS_SUCCESS;
        }
    }
    return CX_STATUS_DATA_NOT_FOUND;
}


NTSTATUS
PpFree(
    _In_ MDL* Mdl
)
{
    NTSTATUS status;
    PPA_HEADER* ppa;
    DWORD i, k;
    DWORD pageCount;

    ppa = NULL;
    pageCount = 0;

    if (NULL == Mdl) return CX_STATUS_INVALID_PARAMETER_1;
    if ((Mdl->AllocCount <= 0) || (Mdl->EntryCount <= 0)) return STATUS_INVALID_MDL;

    // process all entries from the MDL...
    for (i = 0; i < Mdl->EntryCount; i++)
    {
        QWORD addr = PAGE_BASE_PA(Mdl->Entry[i].BaseAddress);
        // find out the proper allocator
        status = _PpGetAllocatorByPa(addr, &ppa);
        if (!SUCCESS(status))
        {
            WARNING("Can't locate the PP allocator for pa=%p\n", addr);
            return STATUS_INVALID_MDL;
        }

        HvAcquireSpinLock(&ppa->Lock);

        // process each page from an entry
        for (k = 0; k < Mdl->Entry[i].PageCount; k++)
        {
            QWORD va = 0;
            INT32 idx;

            // make sure we're not getting outside the address range of the allocator
            if (addr > ppa->MaxPhyAddr)
            {
                HvReleaseSpinLock(&ppa->Lock);
                status = _PpGetAllocatorByPa(addr, &ppa);
                if (!SUCCESS(status)) return STATUS_INVALID_MDL;
                HvAcquireSpinLock(&ppa->Lock);
            }

            // determine the index of this page; for this we need the PFN, but keep in mind, this is limited only to HV-VA zone
            if (FALSE == _PpPaToVa(addr, &va))
            {
                HvReleaseSpinLock(&ppa->Lock);
                return STATUS_ADDRESS_NOT_FOUND_IN_PFN;
            }

            idx = (INT32)((va - (QWORD)ppa->FirstPage) / PAGE_SIZE);

            // update first-free hint, if needed
            if (idx < ppa->FirstFreeHint) ppa->FirstFreeHint = idx;

            // free this page and update free page count
            PP_SET_FREE(ppa->Bitmap, idx);
            ppa->FreeCount += 1;
            pageCount++;
            addr += PAGE_SIZE;

            // also unchain this page (this is NOT strictly required, but keeps bitmap clean and simple)
            PP_SET_LAST(ppa->Bitmap, idx);
        }

        HvReleaseSpinLock(&ppa->Lock);
    }

    // everything has been done just fine
    status = CX_STATUS_SUCCESS;

    return status;
}

void
PpDumpAllocStats(
    void
)
{
    DWORD i;

    LOG("dumping %d serialized PP allocators...\n", gPpAllocator->Pc);
    for (i = 0; i < gPpAllocator->Pc; i++)
    {
        PPA_HEADER* ppa;

        ppa = gPpAllocator->PpAllocator[i];

        LOGN("%03d header %018p, firstpage %018p, 4K pagecount %d    lock %d\n", i, ppa, ppa->FirstPage, ppa->PageCount, ppa->Lock);
        LOGN("    minphy %018p  -  maxphy %018p     freepages %d  firstfreehint %d\n", ppa->MinPhyAddr, ppa->MaxPhyAddr, ppa->FreeCount, ppa->FirstFreeHint);
    }
}
/// @}
