/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introphysmem.h
*   @brief INTROPHYSMEM - NAPOCA hypervisor glue layer, physical memory access support offered for introspection
*
*/

#ifndef _INTROPHYSMEM_H_
#define _INTROPHYSMEM_H_

#include "glueiface.h"

///
/// @brief  Translates a guest physical address to a host physical address
///
/// Will map, using the cachemap function, the GPA page pointed by Gpa.
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Gpa             Guest physical address to be translated
/// @param[out] Hpa             Host physical address at which the GPA is mapped
///
/// @returns    CX_STATUS_SUCCESS                   - on success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Hpa is an invalid pointer.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if EptGetGuestMapping returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if EptGetGuestMapping returns STATUS_PAGE_NOT_PRESENT
/// @returns    STATUS_XXX                          - on errors. See EptGetGuestMapping for possible return codes.
///
NTSTATUS
GuestIntNapGpaToHpa(
    _In_ PVOID GuestHandle,
    _In_ QWORD Gpa,
    _Out_ QWORD* Hpa
);

///
/// @brief  Maps a guest physical address to the host virtual space
///
/// Will map minimum Length bytes from PhysAddress. It uses the cachemap
/// function ChmMapContinuousGuestGpaPagesToHost.
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  PhysAddress     The guest physical address that must be mapped
/// @param[in]  Length          The size of the region that must be mapped, in bytes
/// @param[in]  Flags           Additional flags. Currently, the only available flag is IG_PHYSMAP_NO_CACHE
/// @param[out] HostPtr         A pointer to the pointer that will map the physical memory area.
///                             This pointer must remain valid until introcore calls GLUE_IFACE.PhysMemUnmap
///
/// @returns    CX_STATUS_SUCCESS                   - on success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - if HostPtr is an invalid pointer.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if ChmMapContinuousGuestGpaPagesToHost returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if ChmMapContinuousGuestGpaPagesToHost returns STATUS_PAGE_NOT_PRESENT
/// @returns    STATUS_XXX                          - on errors. See ChmMapContinuousGuestGpaPagesToHost for possible return codes.
///
NTSTATUS
GuestIntNapPhysMemMapToHost(
    _In_ PVOID GuestHandle,
    _In_ QWORD PhysAddress,
    _In_ DWORD Length,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) PVOID* HostPtr
);

///
/// @brief  Frees any resources allocated by a GLUE_IFACE.PhysMemMap call (GuestIntNapPhysMemMapToHost).
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in, out] HostPtr     A pointer to the pointer that maps the physical memory previously mapped
///
/// @returns    CX_STATUS_SUCCESS                   - on success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if HostPtr is an invalid pointer.
NTSTATUS
GuestIntNapPhysMemUnmap(
    _In_ PVOID GuestHandle,
    _Inout_ _At_(*HostPtr, _Post_null_) PVOID* HostPtr
);

///
/// @brief  Returns the memory type of a guest physical page, as taken from the MTRRs
///
/// This function implements the corresponding service from the UPPER_IFACE interface.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Gpa             The guest physical address for which the memory type is requested
/// @param[out] MemType         The memory type of the Gpa
///
/// @returns    CX_STATUS_SUCCESS                   - on success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if MemType is an invalid pointer.
/// @returns    STATUS_INVALID_MEMORY_TYPE          - if the MTRR covering this address contains an invalid bit combination.
/// @returns    CX_STATUS_DATA_NOT_FOUND            - if no MTRR converts the given address.
/// @returns    STATUS_XXX                          - on errors. See ChmGetPhysicalPageTypeFromMtrrs for possible return codes.
///
NTSTATUS
GuestIntNapGetPhysicalPageTypeFromMtrrs(
    _In_ PVOID GuestHandle,
    _In_ QWORD Gpa,
    _Out_ IG_MEMTYPE* MemType
);

///
/// @brief  Reserves a dedicated memory region inside the hypervisor page tables. This API is optional
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[out] FirstPageBase   The virtual address of the first virtual address space reserved
/// @param[out] PagesCount      The number of reserved pages
/// @param[out] PtBase          Pointer to the base of the page tables
///
/// @returns    CX_STATUS_SUCCESS                   - on success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if FirstPageBase is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if PagesCount is an invalid pointer.
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if PtBase is an invalid pointer.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if FmReserveRange returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if FmReserveRange returns STATUS_PAGE_NOT_PRESENT
/// @returns    CX_STATUS_XXX                       - on errors. See FmReserveRange for possible return codes.
///
NTSTATUS
GuestIntNapReserveVaSpaceWithPt(
    _In_ PVOID GuestHandle,
    _Outptr_ PVOID* FirstPageBase,
    _Out_ DWORD* PagesCount,
    _Outptr_ PVOID* PtBase
);

#endif // _INTROPHYSMEM_H_

///@}