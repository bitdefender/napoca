/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file memmgr.c
///  @brief Implements the HV memory management (virtual/physical allocation, mapping, access rights management) subsystem
///

/// @defgroup memmgr
/// @ingroup memory
/// @{

#include "napoca.h"
#include "kernel/kernel.h"
#include "boot/boot.h"
#include "kernel/queue_ipc.h"
#include "memory/memmgr.h"

/// @brief Defines the maximum continuous supported allocation size (which entails a max number of MDL entries filled-in by the physical address allocator) -- 64MB is 9 MDL entries (QWORDS on stack)
#define MM_MAX_CONTINUOUS_PA_ALLOCATION_SIZE        (64 * CX_MEGA)
///< @brief Defines the maximum continuous physical pages supported internally
#define MM_MAX_CONTINUOUS_PA_PAGES                  (CX_PAGE_COUNT_4K(0, MM_MAX_CONTINUOUS_PA_ALLOCATION_SIZE))
///< @brief Defines the internal maximum supported MDL entries for PA allocations
#define MM_MAX_CONTINUOUS_PA_MDL_ENTRIES            ((CX_ROUND_UP(MM_MAX_CONTINUOUS_PA_PAGES, MDL_MAX_PAGES_PER_ENTRY)) / MDL_MAX_PAGES_PER_ENTRY)


MM_DESCRIPTOR gHvMm = { 0 };                        ///< provide a globally available dynamic memory manager descriptor
MM_DESCRIPTOR gHvLowerMem = { 0 };                  ///< provide a globally available memory manager that uses the loader-provided memory buffer (can be below 4GB, based on the loader's implementation)


#define MM_LOG_FUNC_FAIL    LOG_FUNC_FAIL
#define MM_LOG              LOG
#define MM_WARNING          WARNING
#define MM_ERROR            ERROR


const MM_RIGHTS      gMmRo = {.Read = 1};                           ///< read(only) MM_RIGHTS constant
const MM_RIGHTS      gMmRw = { .Read = 1,.Write = 1 };              ///< read and write MM_RIGHTS constant
const MM_RIGHTS      gMmRx = { .Read = 1,.Execute = 1 };            ///< read and execute MM_RIGHTS constant
const MM_RIGHTS      gMmRwx = { .Read = 1,.Write = 1,.Execute = 1 };///< read, write and execute MM_RIGHTS constant



///
/// @brief        Bind callbacks and setup a memory manager descriptor
/// @param[in]    TasDescriptor                    The internal TAS descriptor to be used for managing the page tables
/// @param[in]    AllocVa                          VA allocator callback function, called when a range of virtual addresses is needed
/// @param[in]    AllocVaContext                   AllocVa callback context
/// @param[in]    FreeVa                           Va allocator callback function for freeing virtual addresses allocated through the AllocVa callback
/// @param[in]    FreeVaContext                    Custom-data for the FreeVa callback function
/// @param[in]    AllocPa                          Physical memory allocation routine to be used by this memory manager
/// @param[in]    AllocPaContext                   Callback-defined data to send to the AllocPa function
/// @param[in]    FreePa                           Physical memory dealocation callback function
/// @param[in]    FreePaContext                    FreePa callback context data
/// @param[out]   Descriptor                       Memory manager descriptor to initialize
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - A non-null TAS descriptor is needed
/// @returns      CX_STATUS_INVALID_PARAMETER_10   - The memory manager descriptor pointer can't be NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmInitDescriptor(
    _In_ TAS_DESCRIPTOR             *TasDescriptor,
    _In_ MM_ALLOC_VA                AllocVa,
    _In_opt_ CX_VOID                *AllocVaContext,
    _In_ MM_FREE_VA                 FreeVa,
    _In_opt_ CX_VOID                *FreeVaContext,
    _In_ MM_ALLOC_PA                AllocPa,
    _In_opt_ CX_VOID                *AllocPaContext,
    _In_ MM_FREE_PA                 FreePa,
    _In_opt_ CX_VOID                *FreePaContext,
    _Out_ MM_DESCRIPTOR             *Descriptor
)
{
    if (!TasDescriptor) return CX_STATUS_INVALID_PARAMETER_1;

    if (!Descriptor) return CX_STATUS_INVALID_PARAMETER_10;

    Descriptor->Tas = TasDescriptor;

    Descriptor->AllocVa = AllocVa;
    Descriptor->AllocVaContext = AllocVaContext;
    Descriptor->FreeVa = FreeVa;
    Descriptor->FreeVaContext = FreeVaContext;
    Descriptor->AllocPa = AllocPa;
    Descriptor->AllocPaContext = AllocPaContext;
    Descriptor->FreePa = FreePa;
    Descriptor->FreePaContext = FreePaContext;

    return CX_STATUS_SUCCESS;
}



///
/// @brief        Placeholder function for tracking virtual-address space usage, unused but can be populated with instrumentation code for debugging purposes
/// @param[in]    Va                               Virtual address for the memory region that's being registered (probably some newly allocated VA space)
/// @param[in]    Size                             Size of the virtual memory region
/// @param[in]    FormatString                     printf-like format string
/// @returns      CX_STATUS_OPERATION_NOT_IMPLEMENTED - This is the hard-coded returned code while no debugging implementation is being provided
/// @returns      CX_STATUS_SUCCESS                - The expected returned code when an implementation is provided and the operation succeeds
///
CX_STATUS
MmRegisterVaInfo(
    _In_ MM_UNALIGNED_VA            Va,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ const char                 *FormatString,
    ...)
{
    UNREFERENCED_PARAMETER((Va, Size, FormatString));
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}



///
/// @brief        Given the rights, caching and an initial TAS_PROPERTIES template, compute the TAS_PROPERTIES value that accounts for the rights and caching values
/// @param[in]    InitialProperties                An input TAS_PROPERTIES value to build upon
/// @param[in]    Rights                           Rights to be applied
/// @param[in]    Caching                          Caching to be applied
/// @param[out]   Properties                       The resulting TAS_PROPERTIES, build by customizing the InitialProperties with the information specified by Rights and Caching
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmGetAllocationTasProperties(
    _In_ TAS_PROPERTIES             InitialProperties,
    _In_ MM_RIGHTS                  Rights,
    _In_ MM_CACHING                 Caching,
    _Out_ TAS_PROPERTIES            *Properties
)
{
    // setup the TAS_PROPERTIES for mapping with specific caching bits
    TAS_PROPERTIES props = InitialProperties;
    HVA_PTE_CACHING_BITS cachingBits;
    CX_STATUS status = HvaCachingTypeToPteBits(Caching, &cachingBits);
    if (!CX_SUCCESS(status))
    {
        MM_LOG("PAT=%p, caching=%d\n", HvaGetPat(), Caching);
        MM_LOG_FUNC_FAIL("HvaCachingTypeToPteBits", status);
        return status;
    }

    props.Caching = cachingBits.Raw;

    // set the TAS rights
    props.Read = Rights.Read;
    props.Write = Rights.Write;
    props.Execute = Rights.Execute;
    *Properties = props;
    return CX_STATUS_SUCCESS;
}


static
__forceinline
CX_STATUS
_FillMdlThroughCallback(
    _In_ VAMGR_ALIGNED_VA           Va,
    _In_ MDL                        *Mdl,
    _In_ MM_PAGE_COUNT              PagesToTranslate,
    _In_ MM_PAGE_COUNT              PageIndex,
    _In_ MM_PA_ALLOCATION           *PaAllocation,
    _Out_ MM_ALIGNED_PA             *LeftoverPage   // avoid re-translation of the very first page that would overflow the MDL
)
{
    MM_ALIGNED_PA pa;
    CX_UINT64 currentVa = (CX_UINT64)Va;
    CX_STATUS status = CX_STATUS_SUCCESS;

    for (MM_PAGE_COUNT i = 0; i < PagesToTranslate; i++)
    {
        status = PaAllocation->Pa.Callback.Function(PaAllocation->Pa.Callback.CallbackContext, currentVa, PageIndex, &pa);
        if (!CX_SUCCESS(status))
        {
            ///MM_LOG_FUNC_FAIL("PaAllocation->Pa.Callback", status);
            goto cleanup;
        }

        status = MdlAddRange(Mdl, pa, 1);
        if (!CX_SUCCESS(status))
        {
            if (status != STATUS_STATIC_MDL_TOO_SMALL)
            {
                MM_LOG_FUNC_FAIL("MdlAddRange", status);
                goto cleanup;
            }

            // we're done, successfully, with a left-over page for the next time we're called
            *LeftoverPage = pa;
            status = CX_STATUS_SUCCESS;
            goto cleanup;
        }

        currentVa += CX_PAGE_SIZE_4K;
    }

cleanup:
    return status;
}


static
CX_STATUS
_MmFreePaByMdlCallback(
    _In_ MDL* Mdl,                                          // (partial) mdl describing the backing PA pages for a VA mapping
    _In_ CX_BOOL First,                                     // only set when this is the last mdl for the given operation
    _In_ CX_BOOL Last,                                      // only set when this is the last mdl for the given operation
    _In_ CX_VOID* CallbackContext                           // user data for the callback
);


static
__forceinline
CX_STATUS
_MmAllocEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_SIZE_IN_BYTES           Size,           // this does NOT include the guard page/s!
    _In_ TAS_PROPERTIES             Properties,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa             // only useful for a single page or when the memory is physically continuous
)
// Internal implementation for all the allocation routines
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    MEM_PAGE_COUNT totalMappedPages = 0;

    MM_PA_ALLOCATION* paAllocation = &((MM_PA_ALLOCATION) { .PaType = MM_PA_DYNAMIC });
    if (PaAllocation) paAllocation = PaAllocation;
    CX_BOOL returnedContinuousPa = CX_FALSE;
    CX_UINT8 mdlBuffer[N_ENTRY_MDL_SIZE(MM_MAX_CONTINUOUS_PA_MDL_ENTRIES)];
    MDL* mdl = (MDL*)mdlBuffer;

    // handle the VA allocation if needed, some VA space is mandatory for/by any MmAllocEx() call
    VAMGR_ALIGNED_VA usedVa = VaAllocation->FixedVa;
    CX_BOOL needToFreeVa = CX_FALSE;
    CX_BOOL needToFreePa = CX_FALSE;
    if (VaAllocation->VaType.Dynamic)
    {
        status = Mm->AllocVa(
            Mm,
            (VAMGR_PAGE_COUNT)CX_PAGE_COUNT_4K(0, Size + CX_PAGE_SIZE_4K * (!!VaAllocation->VaType.LeftGuard + !!VaAllocation->VaType.RightGuard)),
            &usedVa,
            VaAllocation->DynamicVa.AllocatorId,
            VaAllocation->DynamicVa.Tag
        );
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("Mm->VaAllocator", status);
            goto cleanup;
        }
        needToFreeVa = CX_TRUE;
    }

    if (VaAllocation->VaType.LeftGuard) usedVa = (VAMGR_ALIGNED_VA)((CX_UINT64)usedVa + CX_PAGE_SIZE_4K);

    // allocate the physical memory if needed
    if (
        (paAllocation->PaType == MM_PA_DYNAMIC) ||
        (paAllocation->PaType == MM_PA_DYNAMIC_CONTINUOUS) ||
        (paAllocation->PaType == MM_PA_CALLBACK)
        )
    {

        CX_UINT64 lastVa = (CX_UINT64)usedVa;
        CX_UINT64 lastAlienAddress = CX_PAGE_BASE_4K(PaAllocation->Pa.Callback.AlienAddress); // not necessary valid
        MM_PAGE_COUNT remainingPages = (MM_PAGE_COUNT)CX_PAGE_COUNT_4K(0, Size);
        MEM_PAGE_COUNT numberOfNewlyMappedPages = 0;
        TAS_PROPERTIES fillPageFrames = { .PageFrame = 1,.PagingStructures = 1 };

        CX_BOOL firstChunk = CX_TRUE;
        MM_ALIGNED_PA leftoverPa = 0;

        while (remainingPages)
        {

            // re/init the mdl for allocating a bunch of physical pages
            status = MdlInit(mdl, sizeof(mdlBuffer));
            if (!CX_SUCCESS(status))
            {
                MM_LOG_FUNC_FAIL("MdlInit", status);
                goto cleanup;
            }

            // fill-in the mdl with as many pages as possible
            if (paAllocation->PaType == MM_PA_CALLBACK)
            {
                if (!firstChunk)
                {
                    // first, add any leftover pages from previous calls
                    status = MdlAddRange(mdl, leftoverPa, 1);
                    if (!CX_SUCCESS(status))
                    {
                        MM_LOG_FUNC_FAIL("MdlAddRange", status);
                        goto cleanup;
                    }
                }
                if (firstChunk || remainingPages > 1)
                {
                    // add as many as possible / necessary translated alien addresses to the mdl
                    // care must be taken for the left-over page that's not yet mapped
                    status = _FillMdlThroughCallback(
                        (VAMGR_ALIGNED_VA)(lastAlienAddress + (firstChunk ? 0 : PAGE_SIZE)), // skip the page that was already translated on prev. iteration
                        mdl,
                        remainingPages - (firstChunk ? 0 : 1), // one page might have already been translated at this point, account for it correctly
                        totalMappedPages,
                        paAllocation,
                        &leftoverPa);
                    if (!CX_SUCCESS(status))
                    {
                        ///LOG_FUNC_FAIL("_FillMdlThroughCallback", status);
                        goto cleanup;
                    }
                }
            }
            else
            {
                MM_ALIGNED_PA pa = 0;
                status = Mm->AllocPa(Mm, mdl, &pa, remainingPages, paAllocation->PaType == MM_PA_DYNAMIC_CONTINUOUS, paAllocation->Pa.DynamicPa.AllocatorId, paAllocation->Pa.DynamicPa.Tag);
                // on failures, abort a MM_PA_DYNAMIC_CONTINUOUS allocation always or otherwise abort if the error is not STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW
                if (!CX_SUCCESS(status) && ((paAllocation->PaType == MM_PA_DYNAMIC_CONTINUOUS) || (status != STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW)))
                {
                    MM_LOG_FUNC_FAIL("Mm->PaAllocator", status);
                    goto cleanup;
                }
                needToFreePa = CX_TRUE;

                // if a PA was returned we can (and should) ignore the mdl
                if (pa)
                {
                    LOG("Got %p\n", pa);
                    if (!firstChunk)
                    {
                        // the allocator is acting strange, for the same arguments we received different output types and we don't have proper handling for this case!
                        return CX_STATUS_INVALID_COMPONENT_STATE;
                    }
                    status = TasMapRange(Mm->Tas, (MEM_UNALIGNED_VA)lastVa, remainingPages * CX_PAGE_SIZE_4K, fillPageFrames, pa);
                    if (!CX_SUCCESS(status))
                    {
                        MM_LOG_FUNC_FAIL("TasMapRange", status);
                        goto cleanup;
                    }

                    if (Pa) *Pa = pa;
                    returnedContinuousPa = CX_TRUE;
                    numberOfNewlyMappedPages = remainingPages;
                }
            }

            if (!returnedContinuousPa)
            {
                // fill-in the start PA in case continuous PA is needed
                if (Pa && firstChunk && (paAllocation->PaType == MM_PA_DYNAMIC_CONTINUOUS)) *Pa = MDL_PAGE_BASE(mdl->Entry[0].BaseAddress);

                // remember the allocated pages by linking them into the paging structures (without setting any other bits)
                status = TasMapMdlEx(Mm->Tas, (MEM_ALIGNED_VA)lastVa, fillPageFrames, gTasMapClearProps, gTasMapHaveProps, gTasMapLackProps, mdl, &numberOfNewlyMappedPages);
                if (!CX_SUCCESS(status))
                {
                    MM_LOG_FUNC_FAIL("TasMapMdlEx", status);
                    goto cleanup;
                }
            }

            // advance inside the VA space
            CX_UINT64 newlyMappedBytes = (CX_UINT64)numberOfNewlyMappedPages * CX_PAGE_SIZE_4K;
            lastVa += newlyMappedBytes;
            lastAlienAddress += newlyMappedBytes;
            totalMappedPages += numberOfNewlyMappedPages;
            remainingPages -= numberOfNewlyMappedPages;

            firstChunk = CX_FALSE;
        }

        // now that the memory has been allocated and the page frames set, configure the access and chaining bits
        TAS_PROPERTIES commit = Properties;
        commit.PageFrame = 0; // don't overwrite/touch the already filled-in page frames
        status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)usedVa, Size, commit, gTasMapClearProps, gTasMapHaveProps, (TAS_PROPERTIES) { 0 }, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);
            goto cleanup;
        }
        //MM_LOG("Granted access to %lld bytes at %p\n", Size, usedVa);
    }
    else if (paAllocation->PaType == MM_PA_FIXED)
    {
        status = TasMapRange(Mm->Tas, (MEM_UNALIGNED_VA)usedVa, Size, Properties, paAllocation->Pa.FixedPa);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasMapRange", status);
            goto cleanup;
        }
        //MM_LOG("Mapped fixed PA=%p to %p, size=%lld\n", paAllocation->Pa.FixedPa, usedVa, Size);
        if (Pa) *Pa = paAllocation->Pa.FixedPa;
    }
    else if (paAllocation->PaType == MM_PA_MDL)
    {
        status = TasMapMdl(Mm->Tas, (MEM_ALIGNED_VA)usedVa, Properties, paAllocation->Pa.Mdl);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasMapMdl", status);
            goto cleanup;
        }
        MM_LOG("Mapped mdl to %p, size=%lld\n", usedVa, Size);
        if (Pa) *Pa = paAllocation->Pa.FixedPa;
    }
    else if (paAllocation->PaType == MM_PA_NONE)
    {
        status = TasReserveRange(&gHva, (MEM_UNALIGNED_VA)usedVa, Size);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasReserveRange", status);
            goto cleanup;
        }
    }

    if (Va) *Va = usedVa;

cleanup:
    if (!CX_SUCCESS(status))
    {
        CX_STATUS cleanupStatus;
        if (needToFreePa)
        {
            if (returnedContinuousPa)
            {
                // there's a boot-time (irreversible allocator) limitation, at least print a message to know some memory is leaking
                MM_WARNING("Mm->FreePa supports only MDL-described pages and can't free pages returned by their starting address!\n");
            }
            else
            {
                // free any pending PAs left in the mdl
                if (MdlIsPopulated(mdl))
                {
                    cleanupStatus = Mm->FreePa(Mm, mdl, paAllocation->Pa.DynamicPa.AllocatorId, paAllocation->Pa.DynamicPa.Tag);
                    if (!CX_SUCCESS(cleanupStatus)) MM_LOG_FUNC_FAIL("Mm->FreePa", cleanupStatus);
                }
                // free the PAs found in the page-tables as partially mapped
                cleanupStatus = TasWalkPagesEx(
                    Mm->Tas,
                    CX_PAGE_BASE_4K((CX_UINT64)usedVa),
                    totalMappedPages,
                    gTasQuerySetProps,
                    gTasQueryClearProps,
                    (TAS_PROPERTIES) {.PageFrame = 1, .PagingStructures = 1}, // only the paging structures and the page frame PTE field are needed for freeing the target PAs
                    gTasQueryLackProps,
                    _MmFreePaByMdlCallback,
                    Mm,
                    CX_NULL,
                    CX_NULL,
                    CX_NULL,
                    CX_NULL);
                if (!CX_SUCCESS(cleanupStatus)) MM_LOG_FUNC_FAIL("TasWalkPagesEx", cleanupStatus);
            }
        }
        if (needToFreeVa)
        {
            usedVa = (MM_ALIGNED_VA)CX_PAGE_BASE_4K((CX_UINT64)usedVa);

            cleanupStatus = Mm->FreeVa(
                Mm,
                (VAMGR_PAGE_COUNT)CX_PAGE_COUNT_4K(0, Size + CX_PAGE_SIZE_4K * (!!VaAllocation->VaType.LeftGuard + !!VaAllocation->VaType.RightGuard)),
                usedVa,
                VaAllocation->DynamicVa.AllocatorId,
                VaAllocation->DynamicVa.Tag
            );
            if (!CX_SUCCESS(cleanupStatus)) MM_LOG_FUNC_FAIL("Mm->FreeVa", cleanupStatus);
        }
    }
    return status;
}


static
CX_STATUS
_MmFreePaByMdlCallback(
    _In_ MDL        *Mdl,                                  // (partial) mdl describing the backing PA pages for a VA mapping
    _In_ CX_BOOL    First,                                 // only set when this is the first mdl for the given operation
    _In_ CX_BOOL    Last,                                  // only set when this is the last mdl for the given operation
    _In_ CX_VOID    *CallbackContext                       // user data for the callback
)
{
    UNREFERENCED_PARAMETER((First, Last));
    MM_DESCRIPTOR *mm = (MM_DESCRIPTOR *)CallbackContext;

    CX_STATUS status = mm->FreePa(mm, Mdl, NULL, TAG_NONE);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("mm->FreePa", status);

        /// let the code continue execution without signaling a failure
    }
    return status;
}



static
__forceinline
CX_STATUS
_MmFreeEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_UNALIGNED_VA            Va  // a Va argument is needed due to the dynamic va case
)
// Internal implementation for all free-like routines
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    // when PaAllocation is NULL it is treated as a MM_PA_DYNAMIC allocation, both when allocating memory and when freeing it
    if (!PaAllocation || (PaAllocation->PaType == MM_PA_DYNAMIC) || (PaAllocation->PaType == MM_PA_DYNAMIC_CONTINUOUS))
    {
        // free the PAs while we still have the VA space
        status = TasWalkPagesEx(
            Mm->Tas,
            CX_PAGE_BASE_4K((CX_UINT64)Va),
            0,
            gTasQuerySetProps,
            gTasQueryClearProps,
            gTasQueryHaveProps,
            gTasQueryLackProps,
            _MmFreePaByMdlCallback,
            Mm,
            CX_NULL,
            CX_NULL,
            CX_NULL,
            CX_NULL);

        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasWalkPagesEx", status);
            goto cleanup;
        }
    }

    // destroy the existing page-table mappings
    MEM_PAGE_COUNT pageCount;
    status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)Va, 0, gTasUnmapSetProps, gTasUnmapClearProps, gTasUnmapHaveProps, gTasUnmapLackProps, &pageCount);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);
        goto cleanup;
    }

    // invalidate the changes
    status = HvaInvalidateTlbRange((CX_VOID *)Va, pageCount, CX_TRUE, CX_FALSE);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
        goto cleanup;
    }

    // and free the address range itself
    if (VaAllocation->VaType.Dynamic)
    {
        HVA_ALIGNED_VA vaToFree = (HVA_ALIGNED_VA)(CX_PAGE_BASE_4K((CX_UINT64)Va - (VaAllocation->VaType.LeftGuard ? CX_PAGE_SIZE_4K : 0)));

        (vaToFree, VaAllocation->DynamicVa.Tag, CX_NULL);
        status = Mm->FreeVa(Mm, pageCount + !!VaAllocation->VaType.LeftGuard + !!VaAllocation->VaType.RightGuard, vaToFree, VaAllocation->DynamicVa.AllocatorId, VaAllocation->DynamicVa.Tag);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("Mm->FreeVa", status);
            goto cleanup;
        }
    }

cleanup:
    if (!CX_SUCCESS(status)) MM_LOG_FUNC_FAIL("_MmFree", status);
    return status;
}



///
/// @brief        Only use this function when no higher-abstraction level API is available for the needed operation -- this is the most powerful but very low-level function offered (the downside in using it is being really complex to use)
/// @param[in]    Mm                               Descriptor for the memory manager to perform the operation upon
/// @param[in]    VaAllocation                     Specifies the virtual memory associated with the allocation
/// @param[in]    PaAllocation                     Specifies the physical memory associated with the allocation
/// @param[in]    Size                             Allocation size (any guard pages are added automatically if necessary)
/// @param[in]    Properties                       VA to PA mapping properties to set for the new allocation
/// @param[out]   Va                               The resulting VA where the allocated memory is mapped to
/// @param[out]   Pa                               The starting PA for the allocation (only useful for single-page or physically continuous allocations)
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm can't be NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - VaAllocation information needs to be specified (VaAllocation can't be NULL)
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - Size is 0
/// @returns      CX_STATUS_INVALID_PARAMETER_6    - The output Va argument is NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAllocEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ TAS_PROPERTIES             Properties,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!VaAllocation) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_4;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_6;
    return _MmAllocEx(Mm, VaAllocation, PaAllocation, CX_ROUND_UP(Size, CX_PAGE_SIZE_4K), Properties, Va, Pa);
}



///
/// @brief        Free some memory allocated by calling MmAllocEx()
/// @param[in]    Mm                               Memory manager that allocated the memory
/// @param[in]    VaAllocation                     VaAllocation argument that was sent to the MmAllocEx routine
/// @param[in]    PaAllocation                     PaAllocation argument that was sent to the MmAllocEx routine
/// @param[in]    Va                               The virtual address obtained when MmAllocEx was called
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The Mm argument needs a non-null pointer value
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - VaAllocation argument was NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - Va was NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmFreeEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_ALIGNED_VA              Va // a Va argument is needed due to the dynamic va case
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!VaAllocation) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_4;
    return _MmFreeEx(Mm, VaAllocation, PaAllocation, Va);
}


static
__forceinline
CX_STATUS
_MmAlloc(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,    // if null, new VA space will be dynamically allocated
    _In_opt_ MM_UNALIGNED_PA        FixedPa,    // Pa XOR Mdl XOR Callback is needed
    _In_opt_ MDL                    *Mdl,
    _In_opt_ MM_GET_PA_CALLBACK     Callback,   // the PAs might correspond to a translated VA space, GVA, GPA etc
    _In_opt_ CX_UINT64              AlienAddress, // the callback will be used to walk this alien address space
    _In_opt_ CX_VOID                *CallbackContext,
    _In_ MM_SIZE_IN_BYTES           Size,       //
    _In_opt_ MM_TAG                 Tag,        // needed if a Va is not given and allocated dynamically
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,      // a non-null FixedVa has to already have room for any guard pages required
    _In_opt_ MM_GLUE                Glue,       // send 0 or MM_GLUE_NONE unless you need to glue partial mappings into a single one
    _Out_opt_ MM_UNALIGNED_VA       *Va,        // returns the usable VA space resulting after allocation/s and mapping
    _Out_opt_ MM_UNALIGNED_PA       *Pa         // when not null the allocated PA will be continuous!
)
// The lowest-level function that's expected to be needed in corner-cases (recommended over MmAllocEx)
{
    // describe the VA allocation info
    MM_VA_ALLOCATION va = { 0 };
    CX_UINT64 pageOffsetVa = 0;
    CX_UINT64 pageOffsetPa = 0;
    CX_UINT64 additionalAlignmentSize = 0;
    if (FixedVa)
    {
        va.FixedVa = (MM_ALIGNED_VA)(CX_PAGE_BASE_4K((CX_UINT64)FixedVa));
        pageOffsetVa = CX_PAGE_OFFSET_4K((CX_UINT64)FixedVa);
        additionalAlignmentSize = pageOffsetVa;
    }
    else
    {
        va = (MM_VA_ALLOCATION) { .VaType = { .Dynamic = 1 } };
        va.DynamicVa.Tag = Tag;
    }

    if (Guard)
    {
        va.VaType.LeftGuard = !!(Guard & MM_GUARD_LEFT);
        va.VaType.RightGuard = !!(Guard & MM_GUARD_RIGHT);
    }

    // describe the PA allocation info
    MM_PA_ALLOCATION pa = { .PaType = { MM_PA_DYNAMIC } };
    pa.Pa.DynamicPa.Tag = Tag;
    if (FixedPa)
    {
        pa.PaType = MM_PA_FIXED;
        pa.Pa.FixedPa = CX_PAGE_BASE_4K(FixedPa);
        pageOffsetPa = CX_PAGE_OFFSET_4K(FixedPa);
        additionalAlignmentSize = pageOffsetPa;
    }
    else if (Mdl)
    {
        pa.PaType = MM_PA_MDL;
        pa.Pa.Mdl = Mdl;
    }
    else if (Callback)
    {
        pa.PaType = MM_PA_CALLBACK;
        pa.Pa.Callback.Function = Callback;
        pa.Pa.Callback.CallbackContext = CallbackContext;
        pa.Pa.Callback.AlienAddress = AlienAddress;
    }
    else if (Pa) // PA needs to be allocated and the actual physical address is needed => allocate a continuous region
        pa.PaType = MM_PA_DYNAMIC_CONTINUOUS;

    if (pageOffsetVa && pageOffsetPa && (pageOffsetVa != pageOffsetPa)) return CX_STATUS_ALIGNMENT_INCONSISTENCY;

    TAS_PROPERTIES props;
    CX_STATUS status = MmGetAllocationTasProperties(gTasMapSetProps, Rights, Caching, &props);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        return status;
    }
    if (Glue)
    {
        props.ChainLimit = 0;
        props.CompleteChain = 0;
        props.Chained = 1;
    }

    status = _MmAllocEx(Mm, &va, &pa, Size + additionalAlignmentSize, props, Va, Pa);
    if (!CX_SUCCESS(status))
    {
        ///MM_LOG_FUNC_FAIL("_MmAllocEx", status);
        return status;
    }

    // if at least one of the offsets is needed, use it for both the va and the pa
    CX_UINT64 offset = (pageOffsetVa ? pageOffsetVa : pageOffsetPa);
    if (offset)
    {
        if (Va) *Va = (MM_UNALIGNED_VA)((CX_UINT64)*Va + offset);
        if (Pa) *Pa = (MM_UNALIGNED_PA)((CX_UINT64)*Pa + offset);
    }

    return status;
}



///
/// @brief        Marks a VA region as fully mapped, complete and with proper chaining/boundaries (although it might have been built part-by-part through muliple memmgr API calls)
/// @param[in]    Mm                               Memory manager of the input VA region
/// @param[in]    Va                               Starting virtual address
/// @param[in]    Size                             Size of the region
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - Va is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Size is 0
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmMarkMappingComplete(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_ MM_SIZE_IN_BYTES           Size
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_3;

    TAS_PROPERTIES setLimit = { .ChainLimit = 1 };
    TAS_PROPERTIES clearChaining = { .Chained = 1 };

    CX_UINT64 pages = CX_PAGE_COUNT_4K((QWORD)Va, Size);
    CX_STATUS status;

    // and on the last page we have to set the limit AND clear the right-most chained bit
    status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)((CX_UINT64)Va + (pages - 1) * PAGE_SIZE), 1, setLimit, clearChaining, gTasQueryHaveProps, gTasQueryLackProps, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);
        goto cleanup;
    }

    // if there's only one page, it's both left and right (and no additional operation is needed)
    if (pages > 1)
    {
        // on the very first page we only have to set the chain limit bit (nothing to clear)
        status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)Va, 1, setLimit, (TAS_PROPERTIES) { 0 }, gTasQueryHaveProps, gTasQueryLackProps, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);
            goto cleanup;
        }
    }

cleanup:
    return status;
}



///
/// @brief        Allocate memory with full control over all of its characteristics
/// @param[in]    Mm                               Memory manager descriptor
/// @param[in]    FixedVa                          if null, new VA space will be dynamically allocated, otherwise use it as the start of the virtual-address space for the new allocation
/// @param[in]    FixedPa                          (Optional) don't allocate new physical memory and instead use a continuous range of pages starting at FixedPa
/// @param[in]    Mdl                              (Optional) don't allocate new physical pages, use the ones described by this MDL
/// @param[in]    Size                             Allocation size
/// @param[in]    Tag                              (Optional) needed when FixedVa is NULL (when the VA space is allocated dynamically)
/// @param[in]    Rights                           Access rights for the newly allocated memory
/// @param[in]    Caching                          Caching for the allocated memory
/// @param[in]    Guard                            Configure optional guard pages outside the allocation to detect under/overflows (a non-null FixedVa has to already have room for the needed guard pages when Guard is TRUE)
/// @param[in]    Glue                             send 0 or MM_GLUE_NONE unless you need to glue this allocation with other partial mappings into a single (VA-continuous) one
/// @param[out]   Va                               (page-aligned when non-fixed) returns the usable VA space resulting after the allocation
/// @param[out]   Pa                               (Optional) returns the resulting (page-aligned when non-fixed) PA. If non-null, the allocated physical memory will be automatically continuous!
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAlloc(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_opt_ MDL                    *Mdl,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _In_opt_ MM_GLUE                Glue,
    _Out_opt_ MM_UNALIGNED_VA       *Va,
    _Out_opt_ MM_UNALIGNED_PA       *Pa
)
{
    return _MmAlloc(Mm, FixedVa, FixedPa, Mdl, CX_NULL, 0, CX_NULL, Size, Tag, Rights, Caching, Guard, Glue, Va, Pa);
}


static
__forceinline
CX_STATUS
_MmFree(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,    // Only used for determining if the VA space was allocated by MmAlloc
    _In_opt_ CX_BOOL                FixedPa,    // Only used for determining if the physical memory was allocated by MmAlloc
    _In_opt_ MM_TAG                 Tag,        // needed when MmAlloc didn't receive a FixedVa
    _In_opt_ MM_GUARD               Guard,      // ignored for FixedVa (as no VA was allocated by MmAlloc and neither will be freed by MmFree)
    _Inout_ MM_UNALIGNED_VA         *Va         // mandatory even when a FixedVa is given
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_6;

    // describe the VA allocation info
    MM_VA_ALLOCATION va = { 0 };
    if (!FixedVa)
    {
        va = (MM_VA_ALLOCATION) { .VaType = { .Dynamic = 1 } };
        va.DynamicVa.Tag = Tag;
    }

    if (Guard)
    {
        va.VaType.LeftGuard = !!(Guard & MM_GUARD_LEFT);
        va.VaType.RightGuard = !!(Guard & MM_GUARD_RIGHT);
    }

    // describe the PA allocation info
    MM_PA_ALLOCATION pa = { .PaType = { MM_PA_DYNAMIC } };
    if (FixedPa)
    {
        pa.PaType = MM_PA_FIXED;
        pa.Pa.FixedPa = FixedPa;
    }

    // it does not metter if the PA was continuous or not
    CX_STATUS status = _MmFreeEx(Mm, &va, &pa, *Va);
    *Va = CX_NULL;

    return status;
}



///
/// @brief        Free a memory allocation obtained by a call to MmAlloc()
/// @param[in]    Mm                               Memory manager that allocated the memory
/// @param[in]    FixedVa                          (Optional) the FixedVa sent to MmAlloc, otherwise, if the virtual memory has been allocated automatically (dynamically) by MmAlloc, set this parameter to NULL
/// @param[in]    FixedPa                          Optional parameter specifying the fixed physical address originally sent to MmAlloc, send NULL if the physical memory has been allocated automatically by MmAlloc
/// @param[in]    Tag                              Optional, only needed when the virtual address space was automatically allocated by MmAlloc (and the Tag value has to match the original one sent to MmAlloc)
/// @param[in]    Guard                            Specifies what guard pages were set in place by MmAlloc; ignored for FixedVa (as no VA was allocated by MmAlloc and neither will be freed by MmFree)
/// @param[out]   Va                               Starting virtual address of the allocated memory, mandatory even if a non-null FixedVa is given!
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmFree(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,
    _In_opt_ CX_BOOL                FixedPa,
    _In_opt_ MM_TAG                 Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_UNALIGNED_VA         *Va
)
{
    return _MmFree(Mm, FixedVa, FixedPa, Tag, Guard, Va);
}



///
/// @brief        Reserve virtual memory at a given fixed VA or automatically allocate the VA space and mark it as reserved.
/// @param[in]    Mm                               Memory manager
/// @param[in]    FixedVa                          Optional pre-allocated (or hardcoded) virtual address to reserve memory to
/// @param[in]    Size                             How much memory to reserve
/// @param[in]    Tag                              Optional tag for the dynamically allocated VA space (i.e. when FixedVa is NULL)
/// @param[out]   Va                               (Optional) the resulting virtual address (guaranteed to be page-aligned when the FixedVa is NULL)
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm can't be NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Non-zero Size value is needed
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmReserveVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _Out_ MM_UNALIGNED_VA           *Va
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_3;

    MM_VA_ALLOCATION va = { 0 };
    if (FixedVa)
    {
        va.FixedVa = FixedVa; // not dynamic and without page guards
    }
    else
    {
        va = (MM_VA_ALLOCATION) { .VaType = { .Dynamic = 1 } };
        va.DynamicVa.Tag = Tag;
    }

    MM_PA_ALLOCATION pa = { 0 };
    pa.PaType = MM_PA_NONE;

    MM_ALIGNED_VA resultedVa;
    CX_STATUS status = _MmAllocEx(Mm, &va, &pa, Size, gTasReserveSetProps, &resultedVa, CX_NULL);
    if (Va)
    {
        *Va = (MM_UNALIGNED_VA)((CX_UINT64)resultedVa + CX_PAGE_OFFSET_4K((CX_UINT64)FixedVa)); // works for NULL FixedVa too
    }
    return status;
}



///
/// @brief        Reverse the effects of a MmReserveVa() call
/// @param[in]    Mm                               Memory manager that reserved the VA space originally
/// @param[in]    FixedVa                          The value of the FixedVa argument sent to MmReserveVa (only used to signal a "do not free" for the VA space)
/// @param[in]    Tag                              Original tag value sent to MmReserveVa (only relevant when not given a fixed Va)
/// @param[out]   Va                               Mandatory pointer to the Va returned by the original call to MmReserveVa()
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - Va is NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmUnreserveVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,    // use only to signal a "do not free" for the Va space
    _In_opt_ MM_TAG                 Tag,        // only relevant when not given a fixed Va
    _Inout_ MM_UNALIGNED_VA         *Va         // needed both for dynamic and fixed VA
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_4;

    MM_PA_ALLOCATION pa = { .PaType = MM_PA_FIXED }; // no PA to free
    MM_VA_ALLOCATION va = { 0 };
    if (!FixedVa)
    {
        va = (MM_VA_ALLOCATION) { .VaType = { .Dynamic = 1 } };
        va.DynamicVa.Tag = Tag;
    }

    CX_STATUS status = _MmFreeEx(Mm, &va, &pa, (MM_ALIGNED_VA)CX_PAGE_BASE_4K((CX_UINT64)*Va));
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("_MmFreeEx", status);
        return status;
    }

    *Va = NULL;

    return status;
}



///
/// @brief        Block a virtual-address interval from being mapped to some actual physical pages
/// @param[in]    Mm                               Memory manager descriptor to perform the locking
/// @param[in]    FixedVa                          Virtual address interval start
/// @param[in]    Size                             Virtual address interval length
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Size must not be zero
/// @returns      CX_STATUS_SUCCESS                on succcess
///
CX_STATUS
MmLockVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_3;
    // set the range as being in used and clear any pre-existing rights
    TAS_PROPERTIES setProps = { .InUse = 1, .PagingStructures = 1 }; // but don't set any page frames
    TAS_PROPERTIES clearProps = { .Read = 1, .Write = 1, .Execute = 1 };

    MEM_PAGE_COUNT pageCount = 0;
    CX_STATUS status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)FixedVa, Size, setProps, clearProps, (TAS_PROPERTIES) { 0 }, (TAS_PROPERTIES) { 0 }, &pageCount);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasAlterRangeEx", status);
        goto cleanup;
    }

    // invalidate the changes in case the VA space was in use
    status = HvaInvalidateTlbRange((CX_VOID *)FixedVa, pageCount, CX_TRUE, CX_FALSE);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
        goto cleanup;
    }

cleanup:
    return status;
}



///
/// @brief        Reverse the effects of a MmLockVa() call, making the VA available for other use
/// @param[in]    Mm                               Memory manager that performed the locking
/// @param[in]    FixedVa                          Starting address of the locked region
/// @param[in]    Size                             Locked region size
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm was NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Size was 0
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmUnLockVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_3;
    // set the range as being in used and clear any pre-existing rights
    TAS_PROPERTIES setProps = { 0 }; // but don't set any page frames
    TAS_PROPERTIES clearProps = { .InUse = 1, .Read = 1, .Write = 1, .Execute = 1 };

    return TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)FixedVa, Size, setProps, clearProps, (TAS_PROPERTIES) { 0 }, (TAS_PROPERTIES) { 0 }, CX_NULL);
    // no invalidation is needed as we are surely not constraining the access rights by this change
}


static
__forceinline
CX_STATUS
_MmAllocMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa     // when not null the allocated PA will be continuous!
)
{
    MM_VA_ALLOCATION va = { 0 };
    va = (MM_VA_ALLOCATION) { .VaType = { .Dynamic = 1 } };
    va.DynamicVa.Tag = Tag;
    if (Guard)
    {
        va.VaType.LeftGuard = !!(Guard & MM_GUARD_LEFT);
        va.VaType.RightGuard = !!(Guard & MM_GUARD_RIGHT);
    }

    MM_PA_ALLOCATION pa = { .PaType = { MM_PA_DYNAMIC } };
    if (Pa) pa.PaType = MM_PA_DYNAMIC_CONTINUOUS;

    TAS_PROPERTIES props;
    CX_STATUS status = MmGetAllocationTasProperties(gTasMapSetProps, Rights, Caching, &props);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        return status;
    }

    return _MmAllocEx(Mm, &va, &pa, Size, props, Va, Pa);
}



///
/// @brief        A flexible memory allocation routine for allocating memory with custom cache and rights
/// @param[in]    Mm                               Memory allocator to allocate from
/// @param[in]    Size                             Number of needed bytes
/// @param[in]    Tag                              Tag for the virtual memory of this allocation
/// @param[in]    Rights                           Access rights
/// @param[in]    Caching                          Caching policy
/// @param[in]    Guard                            Defines if the resulting allocation is to be guarded by trap pages
/// @param[out]   Va                               Resulting virtual address of the newly allocated memory
/// @param[out]   Pa                               (Optional) resulting physical address. Note: a non-null Pa value implies a PA continuous allocation constraint for the page-pool
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - Size can't be 0
/// @returns      CX_STATUS_INVALID_PARAMETER_7    - a non-null pointer for the resulting Va needs to be provided
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAllocMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_7;

    return _MmAllocMemEx(Mm, Size, Tag, Rights, Caching, Guard, Va, Pa);
}


static
__forceinline
CX_STATUS
_MmFreeMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_ALIGNED_VA           *Va
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;

    if (!Va || !*Va) return CX_STATUS_INVALID_PARAMETER_4;

    MM_PA_ALLOCATION pa = { .PaType = MM_PA_DYNAMIC };
    MM_VA_ALLOCATION va = { .VaType = { .Dynamic = 1 } };
    va.DynamicVa.Tag = Tag;
    if (Guard)
    {
        va.VaType.LeftGuard = !!(Guard & MM_GUARD_LEFT);
        va.VaType.RightGuard = !!(Guard & MM_GUARD_RIGHT);
    }

    CX_STATUS status = _MmFreeEx(Mm, &va, &pa, *Va);
    *Va = CX_NULL;
    return status;
}



///
/// @brief        Free a memory allocation resulting from a MmAllocMemEx() call
/// @param[in]    Mm                               Memory manager that performed the original allocation
/// @param[in]    Tag                              Tag for the virtual memory of the allocation
/// @param[in]    Guard                            Guard pages policy, as originally sent to MmAllocMemEx
/// @param[out]   Va                               Address of the Va pointer returned by MmAllcMemEx (or of a copy of said pointer), it will be cleared on return
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmFreeMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_ALIGNED_VA           *Va
)
{
    return _MmFreeMemEx(Mm, Tag, Guard, Va);
}



///
/// @brief        Allocate conventional memory with read and write access rights
/// @param[in]    Mm                               Memory manager descriptor address
/// @param[in]    Size                             Number of bytes needed
/// @param[in]    Tag                              Tag for the virtual memory resulting from the allocation
/// @param[out]   Va                               Pointer to receive the starting virtual address of the newly allocated memory
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm can't be NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - Size must be non-zero
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - The Va pointer can't be NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAllocMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_ALIGNED_VA             *Va
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_4;

    return _MmAllocMemEx(Mm, Size, Tag, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, Va, CX_NULL);
}



///
/// @brief        Free some memory allocated with MmAllocMem()
/// @param[in]    Mm                               Memory manager that allocated the memory
/// @param[in]    Tag                              The tag of the virtual memory
/// @param[out]   Va                               Address of the pointer containing the starting address of the allocated memory, it will be cleared on return
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmFreeMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_ALIGNED_VA           *Va
)
{
    return _MmFreeMemEx(Mm, Tag, MM_GUARD_NONE, Va);
}



///
/// @brief        Allocate device (uncacheable) virtual memory and the backing physical pages and return a usable virtual address
/// @param[in]    Mm                               Memory manager to allocate from
/// @param[in]    Size                             Allocation size
/// @param[in]    Tag                              Tag for the virtual memory space resulting from the allocation
/// @param[out]   Va                               Resulted virtual address
/// @param[out]   Pa                               Resulting starting physical address (always page-aligned)
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mm is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - Size is 0
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - Va is NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAllocDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
)
{
    if (!Mm) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_4;

    return _MmAllocMemEx(Mm, Size, Tag, MM_RIGHTS_RW, MM_CACHING_UC, MM_GUARD_NONE, Va, Pa);
}



///
/// @brief        Free a device memory allocation performed through a call to MmAllocDevMem()
/// @param[in]    Mm                               Memory manager that allocated the memory
/// @param[in]    Tag                              Allocation virtual-address space tag value
/// @param[out]   Va                               Address of the pointer (or a copy of it) returned by MmAllcDevMem, it will be cleared on return
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmFreeDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_ALIGNED_VA           *Va
)
{
    return _MmFreeMemEx(Mm, Tag, MM_GUARD_NONE, Va);
}



///
/// @brief        Create a new mapping between some virtual and physical addresses with full control over all the resulting properties. Use this function only if the other available API doesn't cover this particular use-case!
/// @param[in]    Mm                               Memory manager that will perform the operation
/// @param[in]    FixedVa                          If null, new VA space will be dynamically allocated, otherwise this will be used as the starting virtual address for the new mappings
/// @param[in]    FixedPa                          FixedPa XOR Mdl XOR Callback needs to be TRUE if the physical memory is already known/allocated when called, otherwise new physical pages will be allocated and mapped
/// @param[in]    Mdl                              Mdl containing the pre-allocated physical pages to be mapped
/// @param[in]    Callback                         Optional callback that will return page-by-page the physical memory to be mapped (for example, the PAs might correspond to another translated VA space, GVA, GPA etc)
/// @param[in]    AlienAddress                     Optional argument for the Callback function, specifies the alien address argument that the callback function has to translate to physical address/es
/// @param[in]    CallbackContext                  Optional custom-data to send to the Callback function
/// @param[in]    Size                             How much memory to map (does not need to accommodate for any needed guard page/s as they're considered outside of the mapping)
/// @param[in]    Tag                              Needed if a Va is not given and allocated dynamically
/// @param[in]    Rights                           Access rights
/// @param[in]    Caching                          Caching
/// @param[in]    Guard                            If and what kind of guard pages to setup (if a FixedVa is sent it has to already have room for any guard pages required)
/// @param[in]    Glue                             Send 0 or MM_GLUE_NONE unless you need to glue partial mappings into a single large (and continuous) one
/// @param[out]   Va                               Returns the usable VA space resulting after allocation of needed resources and final mapping
/// @param[out]   Pa                               Returns the resulted physical address of the new mappings (when not null it also entails continuous PA if the physical memory needs to be allocated automatically)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmMap(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_opt_ MDL                    *Mdl,
    _In_opt_ MM_GET_PA_CALLBACK     Callback,
    _In_opt_ CX_UINT64              AlienAddress,
    _In_opt_ CX_VOID                *CallbackContext,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _In_opt_ MM_GLUE                Glue,
    _Out_opt_ MM_UNALIGNED_VA       *Va,
    _Out_opt_ MM_UNALIGNED_PA       *Pa
)
{
    return _MmAlloc(Mm, FixedVa, FixedPa, Mdl, Callback, AlienAddress, CallbackContext, Size, Tag, Rights, Caching, Guard, Glue, Va, Pa);
}



///
/// @brief        Reverse the effects of a MmMap operation.
/// @param[in]    Mm                               Memory manager that built the mappings
/// @param[in]    FixedVa                          Only used for determining if the virtual memory was allocated dynamically or not
/// @param[in]    FixedPa                          Only used for determining if the physical memory was allocated dynamically or not
/// @param[in]    Tag                              Tag for the virtual address space, needed only when MmMap didn't receive a FixedVa
/// @param[in]    Guard                            Original Guard policy specified at MmMap, ignored for FixedVa (as no VA was allocated by MmAlloc and neither will be freed by MmFree)
/// @param[out]   Va                               Pointer to the VA resulted after the mapping operation, mandatory even if a FixedVa is given! (note: it will be cleared on return)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmUnmap(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,
    _In_opt_ CX_BOOL                FixedPa,
    _In_opt_ MM_TAG                 Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_UNALIGNED_VA         *Va
)
{
    return _MmFree(Mm, FixedVa, FixedPa, Tag, Guard, Va);
}



///
/// @brief        Map some conventional memory to newly allocated (or already allocated or hardcoded) virtual addresses with read and write access rights and write-back caching
/// @param[in]    Mm                               Memory manager descriptor
/// @param[in]    FixedPa                          (Optional) Starting physical memory to map. If 0, the physical memory is to be automatically allocated
/// @param[in]    Size                             Number of bytes to map
/// @param[in]    Tag                              Tag for the allocated virtual memory
/// @param[out]   Va                               Returns the usable VA space resulting after allocation/s and mapping
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmMapMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_UNALIGNED_VA           *Va
)
{
    return _MmAlloc(Mm, CX_NULL, FixedPa, CX_NULL, CX_NULL, 0, CX_NULL, Size, Tag, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, Va, CX_NULL);
}



///
/// @brief        Unmap some memory that was mapped by MmMapMem
/// @param[in]    Mm                               Memory manager that created the mappings
/// @param[in]    FixedPa                          Optional used only for determining if the physical memory needs to be freed (if it was allocated automatically)
/// @param[in]    Tag                              Tag for the virtual memory
/// @param[out]   Va                               Address of the Va value returned by MmMapMem, it will be cleared on return
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmUnmapMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ CX_BOOL                    FixedPa,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_UNALIGNED_VA         *Va
)
{
    return _MmFree(Mm, CX_FALSE, FixedPa, Tag, MM_GUARD_NONE, Va);
}



///
/// @brief        Create uncacheable mappings for some device physical memory range inside the virtual address space, with read&write access rights
/// @param[in]    Mm                               Memory manager to use
/// @param[in]    FixedPa                          Optional, address of the start of the device memory; if NULL, new physical pages will be allocated
/// @param[in]    Size                             How many bytes to map
/// @param[in]    Tag                              Tag for the virtual memory dedicated to this mapping
/// @param[out]   Va                               Returns the usable VA space resulting after allocation/s and mapping
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmMapDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_UNALIGNED_VA           *Va
)
{
    return _MmAlloc(Mm, CX_NULL, FixedPa, CX_NULL, CX_NULL, 0, CX_NULL, Size, Tag, MM_RIGHTS_RW, MM_CACHING_UC, MM_GUARD_NONE, MM_GLUE_NONE, Va, CX_NULL);
}



///
/// @brief        Unmap device memory previously mapped by a call to MmMapDevMem()
/// @param[in]    Mm                               Memory manager that created the device memory mappings
/// @param[in]    FixedPa                          Optional, specifies the predetermined physical address used for the mappings, or, if NULL, it signals that the physical memory has been automatically allocated and it's now to be freed
/// @param[in]    Tag                              Virtual memory tag for the mapping
/// @param[out]   Va                               Address of the Va received from MmMapDevMem, it will be cleared on return
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmUnmapDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ CX_BOOL                    FixedPa,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_UNALIGNED_VA         *Va
)
{
    return _MmFree(Mm, CX_FALSE, FixedPa, Tag, MM_GUARD_NONE, Va);
}



///
/// @brief        Adjust the pre-existing access rights for some memory region
/// @param[in]    Mm                               Memory manager for the input memory region
/// @param[in]    Va                               Starting virtual address to act upon
/// @param[in]    Size                             Optional size in bytes for the memory that needs access rights adjustments or 0 to apply to all memory up to the end of the allocation/mapping pointed by Va
/// @param[in]    Rights                           The new access rights value to apply
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAlterRights(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_RIGHTS                  Rights
)
{
    TAS_PROPERTIES set = { 0 }, clear = { 0 };

    CX_STATUS status = MmGetAllocationTasProperties(set, Rights, MM_CACHING_WB, &set);
    if (!SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        goto cleanup;
    }

    clear.Read = ~set.Read;
    clear.Write = ~set.Write;
    clear.Execute = ~set.Execute;

    MEM_PAGE_COUNT pageCount = 0;
    status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)Va, Size, set, clear, gTasQueryHaveProps, gTasQueryLackProps, &pageCount);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);
        goto cleanup;
    }

    // if we might have removed ANY rights an invalidation is needed
    if (clear.Raw)
    {
        status = HvaInvalidateTlbRange((CX_VOID *)Va, pageCount, CX_TRUE, CX_FALSE);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
            goto cleanup;
        }
    }
cleanup:
    return status;
}



///
/// @brief        Modify the caching policy for a given memory region
/// @param[in]    Mm                               Memory manager that allocated or mapped the region
/// @param[in]    Va                               Virtual address to the first byte to be affected
/// @param[in]    Size                             Optional number of bytes to act upon or 0 to apply to all memory up to the end of the allocation/mapping pointed by Va
/// @param[in]    Caching                          New caching value to apply
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAlterCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_CACHING                 Caching
)
{
    TAS_PROPERTIES set = { 0 }, clear = { 0 };

    CX_STATUS status = MmGetAllocationTasProperties(set, MM_RIGHTS_RW, Caching, &set);
    if (!SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        goto cleanup;
    }
    clear.Caching = ~set.Caching;

    MEM_PAGE_COUNT pageCount = 0;
    status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)Va, Size, set, clear, gTasQueryHaveProps, gTasQueryLackProps, &pageCount);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasAlterRangeEx", status);
        goto cleanup;
    }

    // invalidate the change in case any caching behavior is forbidden due to the change
    if (Caching != MM_CACHING_WB)
    {
        status = HvaInvalidateTlbRange((CX_VOID *)Va, pageCount, CX_TRUE, CX_FALSE);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
            goto cleanup;
        }
    }

cleanup:
    return status;
}



///
/// @brief        Modify both the access rights and the caching policy of an existing mapping or allocation
/// @param[in]    Mm                               Memory manager descriptor
/// @param[in]    Va                               Starting virtual address to apply the changes to
/// @param[in]    Size                             Optional number of bytes in the memory region that will suffer the changes or 0 to apply the changes to all memory up to the end of the allocation/mapping pointed by Va
/// @param[in]    Rights                           New access rights
/// @param[in]    Caching                          New caching type
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmAlterRightsAndCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_RIGHTS                  Rights,
    _In_ MM_CACHING                 Caching
)
{
    TAS_PROPERTIES set = { 0 }, clear = { 0 };

    CX_STATUS status = MmGetAllocationTasProperties(set, Rights, Caching, &set);
    if (!SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        goto cleanup;
    }

    clear.Read = ~set.Read;
    clear.Write = ~set.Write;
    clear.Execute = ~set.Execute;
    clear.Caching = ~set.Caching;

    MEM_PAGE_COUNT pageCount = 0;
    status = TasAlterRangeEx(Mm->Tas, (MEM_UNALIGNED_VA)Va, Size, set, clear, gTasQueryHaveProps, gTasQueryLackProps, &pageCount);
    if (!CX_SUCCESS(status)) MM_LOG_FUNC_FAIL("TasAlterRangeEx", status);

    // if we might have removed ANY rights an invalidation is needed
    if (clear.Raw || (Caching != MM_CACHING_WB))
    {
        status = HvaInvalidateTlbRange((CX_VOID *)Va, pageCount, CX_TRUE, CX_FALSE);
        if (!CX_SUCCESS(status))
        {
            MM_LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
            goto cleanup;
        }
    }
cleanup:
    return status;
}


static
__forceinline
CX_STATUS
_MmQuery(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_opt_ MM_RIGHTS             *Rights,
    _Out_opt_ MM_CACHING            *Caching,
    _Out_opt_ MM_ALIGNED_PA         *StartPa,
    _Out_opt_ MM_PAGE_COUNT         *ChainedPages
)
{
    TAS_PROPERTIES props;
    MEM_ALIGNED_PA pa;
    CX_STATUS status = TasQueryRangeProperties(Mm->Tas, (MEM_UNALIGNED_VA)Va, Size, &props, &pa, ChainedPages);
    if (!CX_SUCCESS(status))
    {
        MM_LOG_FUNC_FAIL("TasQueryRangeProperties", status);
        goto cleanup;
    }
    if (Rights)
    {
        Rights->Execute = (CX_UINT8)props.Execute;
        Rights->Read = (CX_UINT8)props.Read;
        Rights->Write = (CX_UINT8)props.Write;
    }
    if (Caching)
    {
        HVA_PAT_INDEX patIndex;
        patIndex.Raw = *Caching;
        *Caching = HvaGetCachingType(patIndex);
    }
    if (StartPa) *StartPa = pa + CX_PAGE_OFFSET_4K((CX_UINT64)Va);
cleanup:
    return status;
}



///
/// @brief        Request the access rights, caching, starting physical address and/or the number of physical for the mappings defined for a given virtual address interval
/// @param[in]    Mm                               Memory manager that will perform the operation
/// @param[in]    Va                               Starting virtual address
/// @param[in]    Size                             (Optional) number of bytes in the queried region or 0 to use the chaining information and process all the memory of the allocation/mapping pointed by Va
/// @param[out]   Rights                           Output, the access rights that are granted for the whole region (if even a single page is missing an access right, that access right is reported as missing for the whole region)
/// @param[out]   Caching                          Optional, will return the caching (as a whole) for the entire region (an uncacheable page will make the whole region to be reported as uncacheable)
/// @param[out]   StartPa                          Options, returns the starting physical address of the first memory page mapped to Va
/// @param[out]   ChainedPages                     Optional, returns the number of pages found chained together while traversing the address space
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmQuery(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_opt_ MM_RIGHTS             *Rights,
    _Out_opt_ MM_CACHING            *Caching,
    _Out_opt_ MM_ALIGNED_PA         *StartPa,
    _Out_opt_ MM_PAGE_COUNT         *ChainedPages
)
{
    return _MmQuery(Mm, Va, Size, Rights, Caching, StartPa, ChainedPages);
}



///
/// @brief        Query the access rights available as a whole for the entire memory region specified by Va and Size
/// @param[in]    Mm                               Memory manager that is to perform the operation
/// @param[in]    Va                               Virtual address to query
/// @param[in]    Size                             Optional number of bytes from Va to query or 0 to query all memory up to the end of the allocation/mapping pointed by Va
/// @param[out]   Rights                           The resulting access rights that are available for the region as a whole (a single page missing some rights makes the whole region reported as missing the said right)
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - the Rights parameter has to be non-null
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmQueryRights(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_ MM_RIGHTS                 *Rights
)
{
    if (!Rights) return CX_STATUS_INVALID_PARAMETER_4;
    return _MmQuery(Mm, Va, Size, Rights, CX_NULL, CX_NULL, CX_NULL);
}



///
/// @brief        Query the caching type for the memory defined by Va and Size
/// @param[in]    Mm                               Memory manager descriptor
/// @param[in]    Va                               Starting address of the memory region to investigate
/// @param[in]    Size                             Optional number of bytes from Va to query or 0 to query all memory up to the end of the allocation/mapping pointed by Va
/// @param[out]   Caching                          Resulting caching type
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - the Caching parameter was NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmQueryCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_ MM_CACHING                *Caching
)
{
    if (!Caching) return CX_STATUS_INVALID_PARAMETER_4;
    return _MmQuery(Mm, Va, Size, CX_NULL, Caching, CX_NULL, CX_NULL);
}



///
/// @brief        Retrieve the physical address backing a virtual address
/// @param[in]    Mm                               Memory manager
/// @param[in]    Va                               Virtual address to query
/// @param[out]   Pa                               Resulting physical address
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Pa must be non-null
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
MmQueryPa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _Out_ MM_UNALIGNED_PA           *Pa
)
{
    if (!Pa) return CX_STATUS_INVALID_PARAMETER_3;

    CX_UINT16 pageOffset = (CX_UINT16)(CX_PAGE_OFFSET_4K((CX_UINT64)Va));
    CX_STATUS status = _MmQuery(Mm, (MM_UNALIGNED_VA)(CX_PAGE_BASE_4K((CX_UINT64)Va)), 1, CX_NULL, CX_NULL, Pa, CX_NULL);

    *Pa += pageOffset;

    return status;
}



///
/// @brief        Callback function of type #MM_GET_PA_CALLBACK that can be used indirectly through MmMap over an alien memory space that's actually the host virtual address memory space
/// @param[in]    Context                          Custom callback data passed-through to the callback at each iteration step
/// @param[in]    AlienAddress                     This is the current address (in some custom/alien address-space) to process for which we need the PA
/// @param[in]    PageIndex                        Inside the allocation/mapping in progress, this AlienAddress is located at PageIndex
/// @param[out]   Pa                               Response to be filled-in by the callback: the AlienAddress corresponds to this Pa
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - This specific callback for MmMap expects a non-null callback context being sent to MmMap (and then forwarded here)
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - The input alien address is zero
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - No room to save the result was specified (Pa is NULL)
/// @returns      CX_STATUS_SUCCESS                on success
///
NTSTATUS
MmGetHpaForHvaCallback(
    _In_ CX_VOID                    *Context,
    _In_ CX_UINT64                  AlienAddress,
    _In_ MM_PAGE_COUNT              PageIndex,
    _Out_ MM_ALIGNED_PA             *Pa
)
{

    UNREFERENCED_PARAMETER(PageIndex);

    if (!Context) return CX_STATUS_INVALID_PARAMETER_1;
    if (!AlienAddress) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Pa) return CX_STATUS_INVALID_PARAMETER_4;

    MM_GET_HPA_FOR_HVA_CALLBACK_CONTEXT *ctx = (MM_GET_HPA_FOR_HVA_CALLBACK_CONTEXT *)Context;
    return TasQueryRangeProperties(ctx->Mm->Tas, (MEM_UNALIGNED_VA)AlienAddress, 1, CX_NULL, (MEM_ALIGNED_PA*)Pa, CX_NULL);
}

/// @}
