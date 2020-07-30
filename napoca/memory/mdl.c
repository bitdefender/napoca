/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup mdl Mdl support
/// @ingroup memory
/// @{
// MDL - MDL support
#include "napoca.h"
#include "memory/heap.h"
#include "memory/mdl.h"
#include "memory/memtags.h"

//
// Platform abstraction: define a list of link-time necessary functions
//
#define MDL_LOG(...)                        LOG(__VA_ARGS__)
#define MDL_LOGN(...)                       LOGN(__VA_ARGS__)
#define MDL_WARNING(...)                    WARNING("[WARNING] " __VA_ARGS__)
#define MDL_ERROR(...)                      ERROR("[ERROR] " __VA_ARGS__)
#define MDL_LOG_FUNC_FAIL(fn, status)       LOG_FUNC_FAIL(fn, status)


#pragma warning(disable:4477) // ignore slightly improper argument types for printf...

static
CX_STATUS
_MdlInitDynamic(
    _In_ MDL* StaticMdl,
    _In_ CX_UINT32 TotalBytesInclHeader
);


/// @brief  Preinitializes a memory buffer as an MDL.
/// @param Mdl                              pointer to the memory zone to format as an MDL
/// @param TotalBytesInclHeader             number of bytes available at Mdl to be used for MDL entries
/// @param KeepMdlProperties                make it empty without altering any other fields of the (pre-initialized) MDL
/// @param IsStaticMdl                      ignored if KeepMdlProperties is true
/// @return CX_STATUS_SUCCESS               On success
__forceinline
static
CX_STATUS
_MdlInitEx(
    _In_ MDL *Mdl,
    _In_ CX_UINT32 TotalBytesInclHeader,
    _In_ CX_BOOL KeepMdlProperties,
    _In_opt_ CX_BOOL IsStaticMdl
)
{
    if (!KeepMdlProperties)
    {
        memzero(Mdl, TotalBytesInclHeader);

        Mdl->Flags = (IsStaticMdl? MDL_FLAG_STATIC : 0);
        Mdl->AllocCount = (TotalBytesInclHeader - sizeof(MDL)) / sizeof(MDL_ENTRY);
        Mdl->Size = TotalBytesInclHeader;                   // might also include any bogus bytes at the end
        Mdl->PpAllocHint = -1;                              // pages of this MDL are NOT linked to any PP allocator
        Mdl->MappedVa = CX_NULL;
    }

    // reset the entry count and clear any entry data
    Mdl->TotalPageCount = 0;
    Mdl->EntryCount = 0;
    memzero(Mdl->Entry, Mdl->AllocCount * sizeof(MDL_ENTRY));

    return CX_STATUS_SUCCESS;
}



CX_STATUS
MdlInit(
    _In_ MDL* StaticMdl,
    _In_ CX_UINT32 TotalBytesInclHeader
    )

{
    if (!StaticMdl)  return CX_STATUS_INVALID_PARAMETER_1;
    if (TotalBytesInclHeader < SINGLE_ENTRY_MDL_SIZE) return CX_STATUS_INVALID_PARAMETER_2;

    return _MdlInitEx(StaticMdl, TotalBytesInclHeader, CX_FALSE, CX_TRUE);
}


/// @brief Preinitializes a memory buffer as a dynamic MDL.
/// @param Mdl                          pointer to the memory zone to format as an MDL
/// @param TotalBytesInclHeader         number of bytes available at StaticMdl to be used for MDL entries
/// @return CX_STATUS_INVALID_PARAMETER_1       Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2       TotalBytesInclHeader too small; at least one entry must be available
/// @return CX_STATUS_SUCCESS                   On success
static
CX_STATUS
_MdlInitDynamic(
    _In_ MDL* Mdl,
    _In_ CX_UINT32 TotalBytesInclHeader
)
{
    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;
    if (TotalBytesInclHeader < SINGLE_ENTRY_MDL_SIZE) return CX_STATUS_INVALID_PARAMETER_2;

    return _MdlInitEx(Mdl, TotalBytesInclHeader, CX_FALSE, CX_FALSE);
}


/// @brief Returns the address of the PageIndex-th 4K page according to the entries of an MDL.
///
/// @param Mdl          the MDL we will be doing page-walking on
/// @param PageIndex    page index, 0 based and continuous throughout all the entries
/// @param Address      the address corresponding to the PageIndex-th page
///
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   PageIndex is invalid; bigger than the total number of pages described by the Mdl
/// @return CX_STATUS_INVALID_PARAMETER_3   Address is NULL
/// @return STATUS_INVALID_MDL                  if the MDL does NOT contain sufficient entries to cover the PageIndex-th page
/// @return CX_STATUS_SUCCESS                   On success
static
CX_STATUS
_MdlGetPa(
    _In_ MDL* Mdl,
    _In_ CX_UINT32 PageIndex,
    _Out_ CX_VOID **Address
    )
{
    CX_STATUS status;
    CX_UINT32 entryIdx, pageIdx;
    CX_UINT32 k, d;

    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;
    if (PageIndex >= Mdl->TotalPageCount) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Address) return CX_STATUS_INVALID_PARAMETER_3;

    entryIdx = 0;
    pageIdx = 0;
    status = CX_STATUS_SUCCESS;

    // use 1-by-1-entry walking mechanism (instead of page-by-page)
    k = 0;
    while (k < PageIndex)
    {
        // how much pages we need to 'consume' from this entry?
        d = (CX_UINT32)CX_MIN(Mdl->Entry[entryIdx].PageCount, PageIndex-k);

        if (d == Mdl->Entry[entryIdx].PageCount)
        {
            if ((entryIdx+1) < Mdl->EntryCount)
            {
                // 'consume' whole entry
                k = k + d;
                entryIdx++;
                continue;
            }
            else
            {
                status = STATUS_INVALID_MDL;
                break;
            }
        }
        else
        {
            // bingo, we found the last entry, get pageIdx
            pageIdx = d;
            break;
        }
    }

    if (CX_SUCCESS(status)) *Address = (CX_VOID*)(CX_SIZE_T)((MDL_PAGE_BASE(Mdl->Entry[entryIdx].BaseAddress)) + ((CX_UINT64)pageIdx) * CX_PAGE_SIZE_4K);

    return status;
}



CX_STATUS
MdlDump(
    _In_opt_ CX_INT8 *Message,
    _In_ MDL* Mdl
    )
{
    CX_STATUS status;
    CX_UINT32 i;
    CX_UINT64 totalPageCount;

    totalPageCount = 0;

    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;

    MDL_LOGN("dump MDL %s with %d out of %d entries follows...\n", (CX_NULL != Message)?Message:"", Mdl->EntryCount, Mdl->AllocCount);

    for (i = 0; i < Mdl->EntryCount; i++)
    {
        MDL_ENTRY* entry;

        entry = &(Mdl->Entry[i]);
        totalPageCount = totalPageCount + entry->PageCount;

        MDL_LOGN("entry %03d / %018llX - %018llX  (%d pages)\n", i, MDL_PAGE_BASE(entry->BaseAddress),
            MDL_PAGE_BASE(entry->BaseAddress) + entry->PageCount * CX_PAGE_SIZE_4K - 1, entry->PageCount);
    }

    MDL_LOGN("total length of memory covered by MDL is %018llX  (%d pages)\n", totalPageCount * CX_PAGE_SIZE_4K, totalPageCount);

    // validate total MDL page count
    if (totalPageCount != Mdl->TotalPageCount)
    {
        MDL_LOGN("!!! inconsistent MDL total page count field, %d vs %d\n", Mdl->TotalPageCount, totalPageCount);
        status = STATUS_INVALID_MDL;
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



CX_STATUS
MdlReset(
    _Inout_ MDL *Mdl
)
{
    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;

    return _MdlInitEx(Mdl, Mdl->Size, CX_TRUE, 0);
}



CX_STATUS
MdlAlloc(
    _Out_ MDL** Mdl,
    _In_ CX_UINT32 NumberOfEntries
    )
{
    CX_STATUS status;

    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;
    if (!NumberOfEntries) return CX_STATUS_INVALID_PARAMETER_2;

    status = HpAllocWithTagAndInfo(Mdl, N_ENTRY_MDL_SIZE(NumberOfEntries), 0, TAG_MDL);
    if (!CX_SUCCESS(status))
    {
        *Mdl = CX_NULL;
        return status;
    }

    status = _MdlInitDynamic(*Mdl, N_ENTRY_MDL_SIZE(NumberOfEntries));
    if (!CX_SUCCESS(status)) HpFreeWithTagAndInfo(Mdl, TAG_MDL);

    return status;
}



CX_STATUS
MdlRealloc(
    _Inout_ MDL** Mdl,
    _In_ CX_UINT32 NewNumberOfEntries
    )
{
    CX_STATUS status;
    MDL* mdl;

    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;

    mdl = *Mdl;

    if ((mdl->Flags & MDL_FLAG_STATIC)) return STATUS_CANT_FREE_A_STATIC_MDL;

    if ((!NewNumberOfEntries) || (NewNumberOfEntries < mdl->EntryCount)) return CX_STATUS_INVALID_PARAMETER_2;

    status = HpReallocWithTagAndInfo(&mdl, sizeof(MDL) + NewNumberOfEntries * sizeof(MDL_ENTRY), TAG_MDL);
    if (!CX_SUCCESS(status))
    {
        return status;
    }

    mdl->AllocCount = NewNumberOfEntries;
    *Mdl = mdl;

    return status;
}



CX_STATUS
MdlFree(
    _Inout_ MDL** Mdl
    )

{
    CX_STATUS status;
    MDL* mdl;

    mdl = CX_NULL;

    if (!Mdl) return CX_STATUS_INVALID_PARAMETER_1;

    mdl = *Mdl;

    if ((mdl->Flags & MDL_FLAG_STATIC)) return STATUS_CANT_FREE_A_STATIC_MDL;

    status = HpFreeWithTagAndInfo(&mdl, TAG_MDL);
    if (!CX_SUCCESS(status)) return status;

    *Mdl = CX_NULL;

    return status;
}



CX_STATUS
MdlAddRange(
    _In_ MDL* Mdl,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT64 NumberOfBytes
)
{
    CX_UINT64 numberOfPages;
    CX_UINT64 i;

    numberOfPages = CX_PAGE_COUNT_4K(PhysicalAddress, NumberOfBytes);

    if (!Mdl || !Mdl->AllocCount) return CX_STATUS_INVALID_PARAMETER_1;

    PhysicalAddress = CX_PAGE_BASE_4K(PhysicalAddress);

    for (i = 0; i < numberOfPages; i++)
    {
        // the address is invalid when the there are unexpected bits set in the high part of the address
        if (CpuGetMaxPhysicalAddress() <= PhysicalAddress) return STATUS_INVALID_PHYSICAL_ADDRESS;

        // find out if we need a new mdl entry
        CX_BOOL newEntry =
            // new entry is needed when there's no entry allocated yet
            (0 == Mdl->EntryCount) ||
            // new entry is needed when the new address isn't right at the end of the range described by current entry
            (PhysicalAddress != CX_PAGE_BASE_4K(Mdl->Entry[Mdl->EntryCount - 1].BaseAddress) + (CX_PAGE_SIZE_4K * Mdl->Entry[Mdl->EntryCount - 1].PageCount)) ||
            // new entry is needed when the PageCount would otherwise overflow
            (Mdl->Entry[Mdl->EntryCount - 1].PageCount == MDL_MAX_PAGES_PER_ENTRY);

        if (newEntry)
        {
            if (Mdl->EntryCount == Mdl->AllocCount)
            {
                if (Mdl->Flags & MDL_FLAG_STATIC)
                {
                    return STATUS_STATIC_MDL_TOO_SMALL;
                }
                else
                {
                    CX_STATUS status = MdlRealloc(&Mdl, 2 * Mdl->AllocCount);
                    if (!CX_SUCCESS(status))
                    {
                        MDL_LOG_FUNC_FAIL("MdlRealloc", status);
                        return status;
                    }
                }
            }

            Mdl->EntryCount++;
            memzero(&Mdl->Entry[Mdl->EntryCount - 1], sizeof(MDL_ENTRY));
            Mdl->Entry[Mdl->EntryCount - 1].BaseAddress = PhysicalAddress;
        }

        Mdl->Entry[Mdl->EntryCount - 1].PageCount++;

        // can't safely advance to the next page -- the MDL can't hold any additional pages
        if (Mdl->TotalPageCount + 1 < Mdl->TotalPageCount) return STATUS_STATIC_MDL_TOO_SMALL;

        Mdl->TotalPageCount++;
        PhysicalAddress += CX_PAGE_SIZE_4K; // can't wrap-around as the most significant bits of the CX_UINT64 are zero
    }

    return CX_STATUS_SUCCESS;
}



CX_STATUS
MdlIterate(
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT64 NumberOfBytes,
    _Inout_ MDL_ITERATE_CONTEXT *Context
)
{
    CX_STATUS status;
    if (!Context) return CX_STATUS_INVALID_PARAMETER_3;

    if (!Context->Started)
    {
        // first call: initialize everything and start processing the data
        Context->Started = CX_TRUE;
        Context->Address = CX_PAGE_BASE_4K(PhysicalAddress);
        Context->PageIndex = 0;
        Context->ChunkInProgress = 0;
        Context->PageCount = (CX_UINT32)CX_PAGE_COUNT_4K(PhysicalAddress, NumberOfBytes);
        if (!Context->Mdl)
        {
            Context->Mdl = (MDL*)&Context->StaticMdlZone;
            MdlInit(Context->Mdl, sizeof(Context->StaticMdlZone));
        }
    }
    else
    {
        // subsequent call, is there more data for current chunk?
        if (Context->ChunkInProgress)
        {
            // more addresses: reset the mdl for the next memory chunk and continue the iteration (the for)
            status = MdlReset(Context->Mdl);
            if (!CX_SUCCESS(status))
            {
                MDL_LOG_FUNC_FAIL("MdlReset", status);
                goto error;
            }
        }
        else
        {
            if (CX_PAGE_BASE_4K(PhysicalAddress) == Context->Address || NumberOfBytes == 0)
            {
                // done, free the mdl and return a proper status for stopping the iteration
                memzero(Context, sizeof(MDL_ITERATE_CONTEXT));
                return CX_STATUS_NO_MORE_ENTRIES;
            }
            else
            {
                // a new chunk was given: keep the mdl, reinitialize the context data and start processing it
                Context->Address = CX_PAGE_BASE_4K(PhysicalAddress);
                Context->PageIndex = 0;
                Context->ChunkInProgress = 0;
            }
        }
    }
    if (!NumberOfBytes)
    {
        memzero(Context, sizeof(MDL_ITERATE_CONTEXT));
        return CX_STATUS_NO_MORE_ENTRIES;
    }
    // begin/continue adding to the MDL from PageIndex until we hit the pageCount
    for (; Context->PageIndex < Context->PageCount; Context->PageIndex++)
    {
        status = MdlAddRange(Context->Mdl, Context->Address + CX_PAGE_SIZE_4K * Context->PageIndex, 1);
        if (status == STATUS_STATIC_MDL_TOO_SMALL)
        {
            // the MDL is full, return to caller WITHOUT freeing anything, we will continue with retrying adding the same Address
            Context->ChunkInProgress = CX_TRUE; // at least one page is not yet processed
            return CX_STATUS_DATA_BUFFER_TOO_SMALL;
        }
        else if (!CX_SUCCESS(status))
        {
            MDL_LOG_FUNC_FAIL("MdlAddRange", status);
            goto error;
        }
    }

    // current address range was covered
    Context->ChunkInProgress = CX_FALSE;
    return CX_STATUS_SUCCESS;

error:
    return status;
}


/// @brief Indicates if an MDL is valid
/// @param Mdl              MDL to validate
/// @param AcceptEmpty      TRUE if an empty MDL is treated as valid
/// @return                 TRUE if Mdl is valid; FALSE otherwise
static
__forceinline
CX_BOOL
_MdlIsValid(
    _In_ const MDL*     Mdl,
    _In_ CX_BOOL        AcceptEmpty
)
// valid and containing at least one page
{
    if (!Mdl) return CX_FALSE;

    if (!(AcceptEmpty || (Mdl->EntryCount && Mdl->TotalPageCount))) return CX_FALSE;

    if ((Mdl->EntryCount > Mdl->AllocCount) || (Mdl->EntryCount > (Mdl->Size - sizeof(MDL)) / sizeof(MDL_ENTRY)))
    {
        MDL_ERROR("Inconsistent MDL %018p  EC %d  TPC %d  AC %d\n", Mdl, Mdl->EntryCount, Mdl->TotalPageCount, Mdl->AllocCount);
        return CX_FALSE;
    }

    CX_UINT64 totalPages = 0;
    for (CX_UINT32 i = 0; i < Mdl->EntryCount; i++)
    {
        totalPages = totalPages + Mdl->Entry[i].PageCount;
    }

    if (totalPages != Mdl->TotalPageCount)
    {
        MDL_ERROR("Inconsistent MDL %018p  counted count %d  TPC %d  AC %d\n", Mdl, totalPages, Mdl->TotalPageCount, Mdl->AllocCount);
        return CX_FALSE;
    }
    // no need to check totalPages != 0 when !AcceptEmpty as TotalPageCount has already been checked to be nonzero and the fields are consistent

    return CX_TRUE;
}



CX_BOOL
MdlIsValid(
    _In_ const MDL*     Mdl,
    _In_ CX_BOOL        AcceptEmpty
)
{
    return _MdlIsValid(Mdl, AcceptEmpty);
}



CX_BOOL
MdlIsPopulated(
    _In_ const MDL*     Mdl
)
{
    return _MdlIsValid(Mdl, CX_FALSE);
}



CX_BOOL
MdlIsUsable(
    _In_ const MDL*     Mdl
)
{
    return _MdlIsValid(Mdl, CX_TRUE);
}
/// @}
