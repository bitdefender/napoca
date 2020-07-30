/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// FASTMAP - fast VA-to-PA mapping support
/// @defgroup fastmap Fast mapping support
/// @ingroup memory

#include "napoca.h"
#include "memory/memmgr.h"
#include "kernel/spinlock.h"
#include "memory/fastmap.h"
#include "kernel/kerneldefs.h"
#include "base/bitmaps.h"

BOOLEAN gFastmapInitialized = FALSE;
DWORD gFastmapSlotCount = 0;
CHAIN_BITMAP gFastmapBitmap;
SPINLOCK gFastmapLock;
PVOID gFastmapPtr = NULL;



void
FmPreinit(
    void
    )
//
/// ...
//
{
    CbPreinit(&gFastmapBitmap);

    gFastmapSlotCount = NAPOCA_FASTMAP_LENGTH / NAPOCA_FASTMAP_SLOT_LENGTH;

    HvInitSpinLock(&gFastmapLock, "gFastmapLock", NULL);
}



NTSTATUS
FmInit(
    void
    )
//
/// ...
//
/// \ret CX_STATUS_ALREADY_INITIALIZED ...
//
{
    NTSTATUS status;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-

    if (gFastmapInitialized)
    {
        return CX_STATUS_ALREADY_INITIALIZED;  // ERROR
    }

    status = CbInit(&gFastmapBitmap, NULL, gFastmapSlotCount);
    if (!SUCCESS(status))
    {
        LOG("ERROR: CbInit failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    status = MmReserveVa(&gHvMm, (PVOID)(QWORD)NAPOCA_FASTMAP_BASE, NAPOCA_FASTMAP_LENGTH, TAG_FMAP, &gFastmapPtr);
    if (!SUCCESS(status))
    {
        LOG("ERROR: MmReserveVa / NAPOCA_FASTMAP_BASE failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    gFastmapInitialized = TRUE;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



NTSTATUS
FmUninit(
    void
    )
//
/// ...
//
/// \ret CX_STATUS_NOT_INITIALIZED_HINT ...
//
{
    NTSTATUS status;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-

    if (!gFastmapInitialized)
    {
        return CX_STATUS_NOT_INITIALIZED_HINT;
    }

    gFastmapInitialized = FALSE;

    status = MmUnmapMem(&gHvMm, TRUE, TAG_FMAP, &gFastmapPtr);
    if (!SUCCESS(status))
    {
        LOG("ERROR: MmUnmapMem / NAPOCA_FASTMAP_BASE failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    status = CbUninit(&gFastmapBitmap);
    if (!SUCCESS(status))
    {
        LOG("ERROR: CbUninit failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



NTSTATUS
FmReserveRange(
    _In_ DWORD PageCount,                   /// ...
    _Out_ PVOID *VaPtr,                     /// ...
    _Out_ PQWORD *PtPtr                     /// ...
    )
//
/// ...
//
/// \ret CX_STATUS_NOT_INITIALIZED ...
//
{
    NTSTATUS status;
    SPINLOCK *lock;
    DWORD startIndex;
    PVOID rangeVa;
    QWORD ptVa;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-
    lock = NULL;
    startIndex = 0;
    rangeVa = NULL;
    ptVa = 0;

    if (0 == PageCount)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (PageCount > (NAPOCA_FASTMAP_SLOT_LENGTH / PAGE_SIZE))
    {
        // IMPORTANT: we can't allocate more than 2M VA in a fastmap range, to be sure we have a single
        // corresponding PT table to a VA range; we also need to allocate ranges alligned to 2M VA boundary
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == VaPtr)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    *VaPtr = NULL;

    if (NULL == PtPtr)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    *PtPtr = NULL;

    if (!gFastmapInitialized)
    {
        return CX_STATUS_NOT_INITIALIZED;  // ERROR
    }

    // acquire fastmap lock
    lock = &gFastmapLock;
    HvAcquireSpinLock(lock);

    status = CbAllocRange(&gFastmapBitmap, 1, &startIndex);
    if (!SUCCESS(status))
    {
        LOG("ERROR: CbAllocRange / gFastmapBitmap failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // determine VA of range and VA of corresponding page table
    rangeVa = (PVOID)(NAPOCA_FASTMAP_BASE + NAPOCA_FASTMAP_SLOT_LENGTH * startIndex);
    TAS_PAGING_STRUCTURE_INFO path[HVA_PAGING_DEPTH];

    // todo: a faster mechanism might prove useful (either technically similar to TasGetPagingPathInfo but without filling-in info
    // that's useless for this purpose or we can switch to using a pml4e linked to the pml4 + round-trips through that entry
    // for locating tables entries at any depth
    status = TasGetPagingPathInfo(&gHva, (MEM_UNALIGNED_VA)rangeVa, FALSE, FALSE, FALSE, 0, path, NULL, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
        goto cleanup;
    }
    ptVa = (QWORD)(path[3].TableEntryVa);

    // return values
    *VaPtr = rangeVa;
    *PtPtr = (PQWORD)ptVa;

    // release fastmap lock
    HvReleaseSpinLock(lock);
    lock = NULL;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    if (NULL != lock)
    {
        HvReleaseSpinLock(lock);
        lock = NULL;
    }

    return status;
}



NTSTATUS
FmFreeRange(
    _Inout_ PVOID *VaPtr,                   /// ...
    _Inout_ PQWORD *PtPtr                   /// ...
    )
//
/// ...
//
/// \ret STATUS_NOT_A_VALID_POINTER ...
/// \ret CX_STATUS_NOT_INITIALIZED ...
//
{
    NTSTATUS status;
    SPINLOCK *lock;
    DWORD startIndex;
    PVOID rangeVa;
    QWORD ptVa;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-
    lock = NULL;
    startIndex = 0;
    rangeVa = NULL;
    ptVa = 0;

    if (NULL == VaPtr)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == PtPtr)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    if (!gFastmapInitialized)
    {
        return CX_STATUS_NOT_INITIALIZED;  // ERROR
    }

    // get and validate VA pointer (range and allignment)
    rangeVa = *VaPtr;
    ptVa = (QWORD)*PtPtr;

    if (((QWORD)rangeVa < NAPOCA_FASTMAP_BASE) ||
        ((QWORD)rangeVa >= (NAPOCA_FASTMAP_BASE + NAPOCA_FASTMAP_LENGTH)) ||
        (0 != ((QWORD)rangeVa & (NAPOCA_FASTMAP_SLOT_LENGTH - 1))))
    {
        return STATUS_NOT_A_VALID_POINTER;
    }

    // get and validate PT address (must be the address of the PT corresponding to the specified range)
    TAS_PAGING_STRUCTURE_INFO path[HVA_PAGING_DEPTH];

    // todo: a faster mechanism might prove useful (either technically similar to TasGetPagingPathInfo but without filling-in info
    // that's useless for this purpose or we can switch to using a pml4e linked to the pml4 + round-trips through that entry
    // for locating tables entries at any depth
    status = TasGetPagingPathInfo(&gHva, (MEM_UNALIGNED_VA)rangeVa, FALSE, FALSE, FALSE, 0, path, NULL, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
        goto cleanup;
    }
    if ((QWORD)(path[3].TableEntryVa) != ptVa)
    {
        return STATUS_NOT_A_VALID_POINTER;
    }

    // simply zero down the pointers
    *VaPtr = NULL;
    *PtPtr = NULL;

    // acquire fastmap lock
    lock = &gFastmapLock;
    HvAcquireSpinLock(lock);

    // determine bitmap start index
    startIndex = (DWORD)((QWORD)rangeVa - NAPOCA_FASTMAP_BASE) / NAPOCA_FASTMAP_SLOT_LENGTH;

    status = CbFreeRange(&gFastmapBitmap, startIndex);
    if (!SUCCESS(status))
    {
        LOG("ERROR: CbFreeRange / gFastmapBitmap failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // release fastmap lock
    HvReleaseSpinLock(lock);
    lock = NULL;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    if (NULL != lock)
    {
        HvReleaseSpinLock(lock);
        lock = NULL;
    }

    return status;
}



NTSTATUS
FmDumpStats(
    _In_ DWORD Flags                        /// ...
    )
//
/// ...
//
/// \ret CX_STATUS_OPERATION_NOT_IMPLEMENTED ...
//
{
    UNREFERENCED_PARAMETER(Flags);

    /// ...TBD/FIXME...

    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

/// @}