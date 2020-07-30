/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introphysmem.c
*   @brief INTROPHYSMEM - NAPOCA hypervisor glue layer, physical memory access support offered for introspection
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introphysmem.h"
#include "guests/intro.h"
#include "guests/guests.h"
#include "kernel/kernel.h"
#include "memory/cachemap.h"
#include "memory/fastmap.h"


NTSTATUS
GuestIntNapGpaToHpa(
    _In_ PVOID GuestHandle,
    _In_ QWORD Gpa,
    _Out_ QWORD* Hpa
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Hpa == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    NTSTATUS status = ChmGpaToHpa(GuestHandle, Gpa, Hpa);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

NTSTATUS
GuestIntNapPhysMemMapToHost(
    _In_ PVOID GuestHandle,
    _In_ QWORD PhysAddress,
    _In_ DWORD Length,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) PVOID* HostPtr
)
{
    NTSTATUS status;
    GUEST* guest;
    QWORD hostVa;

    hostVa = 0;

    UNREFERENCED_PARAMETER(Flags);

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    guest = GuestHandle;

    if (HostPtr == NULL) return CX_STATUS_INVALID_PARAMETER_5;

    status = ChmMapContinuousGuestGpaPagesToHost(guest, PhysAddress & PAGE_MASK, PAGE_COUNT(PhysAddress, Length),
        CHM_FLAG_MAP_ONLY_WB_MEM, (PVOID)&hostVa, NULL, TAG_INTR);
    if (SUCCESS(status))
    {
        *HostPtr = (PVOID)(hostVa + ((QWORD)PhysAddress & ~PAGE_MASK));
    }

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapPhysMemUnmap(
    _In_ PVOID GuestHandle,
    _Inout_ _At_(*HostPtr, _Post_null_) PVOID* HostPtr
)
{
    QWORD p;
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (HostPtr == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    p = *(QWORD*)HostPtr;
    p = (p & PAGE_MASK);

    if (p == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    status = ChmUnmapContinuousGuestGpaPagesFromHost((PVOID*)&p, TAG_INTR);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("ChmUnmapContinuousGuestGpaPagesFromHost", status);

    *HostPtr = NULL;

    return status;
}



NTSTATUS
GuestIntNapGetPhysicalPageTypeFromMtrrs(
    _In_ PVOID GuestHandle,                 // Guest handle.
    _In_ QWORD Gpa,                         // GPA whose caching attributes will be extracted from the MTRRs.
    _Out_ IG_MEMTYPE* MemType               // Will contain the memory type upon exit.
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (MemType == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    NTSTATUS status = ChmGetPhysicalPageTypeFromMtrrs(GuestHandle, Gpa, (BYTE*)MemType);

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapReserveVaSpaceWithPt(
    _In_ PVOID GuestHandle,                 // Guest handle
    _Outptr_ PVOID* FirstPageBase,          // The virtual address of the first virtual address space reserved
    _Out_ DWORD* PagesCount,                // The number of reserved pages
    _Outptr_ PVOID* PtBase                  // Pointer to the base of the page tables
)
{
    NTSTATUS status;
    DWORD pageCount;
    PVOID pageBase = NULL;
    PQWORD ptBase = NULL;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (FirstPageBase == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (PagesCount == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (PtBase == NULL) return CX_STATUS_INVALID_PARAMETER_4;

    pageCount = NAPOCA_FASTMAP_SLOT_LENGTH / PAGE_SIZE;
    status = FmReserveRange(pageCount, &pageBase, &ptBase);
    if (!SUCCESS(status))
    {
        LOG("ERROR: FmReserveRange failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // return values
    *FirstPageBase = pageBase;
    *PagesCount = pageCount;
    *PtBase = ptBase;

    // save for cleanup
    gHypervisorGlobalData.Introspection.FastmapVaPtr = pageBase;
    gHypervisorGlobalData.Introspection.FastmapPtPtr = ptBase;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return HV_STATUS_TO_INTRO_STATUS(status);
}


///@}