/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup cachemap
/// @{
// CACHEMAP - GPA/GVA-to-HPA-to-HVA mapping and per-guest cache support

#ifndef _CACHEMAP_H_
#define _CACHEMAP_H_

#include "core.h"
#include "memory/cachedef.h"

typedef struct _VCPU VCPU;

/// @brief Flags that control the behavior of cache map functions
typedef enum
{
    CHM_FLAG_ACCEPT_EPT_GAPS    = 1,    ///< accept gaps in EPT when mapping a range of memory
    CHM_FLAG_AUTO_ALIGN         = 2,    ///< automatically convert/handle unaligned addresses, use it if you don't want to manually adjust the addresses
    CHM_FLAG_MAP_ONLY_WB_MEM    = 4     ///< enforces check on final physical address to have cache type Write-Back (all maps from introspection, basically)
}CHM_FLAGS;

///
/// @brief Invalidates guest virtual address cache
///
/// This function will invalidate all guest virtual addresses translated to guest and host physical address. This function
/// is called before returning to guest because it is not very safe to use cached translations from one exit to another
/// due to guest swap/remap behavior
///
/// @param Vcpu     The Vcpu for which all cached translations will be invalidated
/// @return CX_STATUS_INVALID_PARAMETER_1   Vcpu is NULL
/// @return CX_STATUS_SUCCESS               On success
NTSTATUS
ChmInvalidateVACache(
    _In_    VCPU*               Vcpu
);


/// @brief Retrieves the guest physical address to host physical address mapping
///
/// This function will use the EPT tables to translate a guest physical address to corresponding host physical address.
/// It is a wrapper over #EptGetHpa EPT function.
///
/// @param Guest    The guest for which translation is performed
/// @param Gpa      Guest physical address to be translated. It is not page aligned it will be aligned internally.
/// @param Hpa      Corresponding page aligned host physical address.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   Guest is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3   Hpa is NULL
/// @return CX_STATUS_SUCCESS               On Success
/// @return CX_STATUS_XXX                   Other #TasQueryRangeProperties statuses
NTSTATUS
ChmGpaToHpa(
    _In_    GUEST*              Guest,
    _In_    QWORD               Gpa,
    _Out_   QWORD               *Hpa
    );

/// @brief Retrieves corresponding guest physical address and host physical address for a given guest virtual address
///
/// This function will translate the given guest virtual address through guest page-tables to retrieve the associated guest physical address.
/// Once the guest physical address is retrieved it will be translated through EPT to retrieve the associated host physical address.
///
/// @param Vcpu         Vcpu for which translation will be attempted
/// @param Gva          Guest virtual address to be translated.
/// @param Gpa          corresponding guest physical address found in guest page-tables
/// @param Hpa          corresponding host physical address found in EPT
///
/// @return CX_STATUS_INVALID_PARAMETER_1   Vcpu is NULL or it is not associated with any guest
/// @return CX_STATUS_INVALID_PARAMETER_4   Hpa is NULL
NTSTATUS
ChmGvaToGpaAndHpa(
    _In_    VCPU*               Vcpu,
    _In_    QWORD               Gva,
    __out_opt QWORD             *Gpa,
    _Out_   QWORD               *Hpa
    );

/// @brief Retrieves corresponding guest physical address and host physical address for a given guest virtual address
///
/// This function will translate the given guest virtual address through guest page-tables to retrieve the associated guest physical address.
/// Once the guest physical address is retrieved it will be translated through EPT to retrieve the associated host physical address.
///
/// @param Vcpu         Vcpu for which translation will be attempted
/// @param Gva          Guest virtual address to be translated.
/// @param Gpa          corresponding guest physical address found in guest page-tables
/// @param Hpa          corresponding host physical address found in EPT
/// @param PtEntryHva   Host virtual address that points to the guest page-table that contains the mapping; Must be unmapped by caller on success.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   Vcpu is NULL or it is not associated with any guest
/// @return CX_STATUS_INVALID_PARAMETER_4   Hpa is NULL
/// @return STATUS_NO_MAPPING_STRUCTURES    There is no mapping available
/// @return STATUS_PAGE_NOT_PRESENT         Page is not present. Maybe it is swapped out.
NTSTATUS
ChmGvaToGpaAndHpaEx(
    _In_    VCPU                *Vcpu,
    _In_    QWORD               Gva,
    __out_opt QWORD             *Gpa,
    _Out_   QWORD               *Hpa,
    __out_opt PVOID             *PtEntryHva
    );

/// @brief Retrieves the physical memory cache type as provided by MTRRs. Both fixed and variable MTRRs are considered.
/// @param Guest        Guest for which info will be provided
/// @param Gpa          GPA whose caching attributes will be extracted from the MTRRs.
/// @param MemType      Memory caching type found in MTRRs
/// @return STATUS_INVALID_MEMORY_TYPE  If the MTRR covering this address contains an invalid bit combination.
/// @return CX_STATUS_DATA_NOT_FOUND    If no MTRR covers the given address.
/// @return CX_STATUS_SUCCESS           On success.
NTSTATUS
ChmGetPhysicalPageTypeFromMtrrs(
    _In_    GUEST*              Guest,
    _In_    QWORD               Gpa,
    _Out_   PBYTE               MemType
    );

/// @brief Maps a range of continuous guest physical addresses to host virtual address space
///
/// @param Guest                Guest for which mapping is to be performed
/// @param GuestPhysAddress     Guest physical address that starts the range.
/// @param PageCount            Number or consecutive pages to map
/// @param Options              A combination of CHM_FLAG_XXX flags that control the behavior of this function
/// @param HostVa               Address where the range is mapped in host virtual address
/// @param TargetReservedHostVa An already reserved and mapped address for the given range. If not NULL, HostVa will be ignored.
/// @param Tag                  Identifier for this mapping for tracking purposes
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmMapContinuousGuestGpaPagesToHost(
    _In_    GUEST*              Guest,
    _In_    QWORD               GuestPhysAddress,
    _In_    DWORD               PageCount,
    _In_    CHM_FLAGS           Options,
    _Out_   PVOID               *HostVa,
    _In_opt_ VOID               *TargetReservedHostVa,
    _In_    DWORD               Tag
    );

/// @brief Unmaps an address that was previously mapped with #ChmMapContinuousGuestGpaPagesToHost
///
/// @param HostVa   Host virtual address to be unmapped.
/// @param Tag      Identifier of this address. Must be the same as the one provided at map time.
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
ChmUnmapContinuousGuestGpaPagesFromHost(
    _Inout_ PVOID               *HostVa,
    _In_    DWORD               Tag
    );


/// @brief Maps a range of continuous guest virtual pages to host virtual address space
///
/// This function will iterate guest page-tables to get the guest physical address and then it will iterate
/// EPT associated with guest to find the host physical address that is associated and then will
/// map it to host virtual address space
///
/// @param Vcpu                 Vcpu for which the mapping will be done
/// @param GuestVirtAddress     Starting guest virtual address
/// @param PageCount            Number of pages to map
/// @param Options              A combination of CHM_FLAG_XXX flags that control the behavior of this function
/// @param HostVa               Address where the range is mapped in host virtual address
/// @param TargetReservedHostVa An already reserved and mapped address for the given range. If not NULL, HostVa will be ignored.
/// @param Tag                  Identifier for this mapping for tracking purposes
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmMapGuestGvaPagesToHost(
    _In_    VCPU*               Vcpu,
    _In_    QWORD               GuestVirtAddress,
    _In_    DWORD               PageCount,
    _In_    CHM_FLAGS           Options,
    _Out_   PVOID               *HostVa,
    _In_opt_ VOID               *TargetReservedHostVa,
    _In_    DWORD               Tag
    );

/// @brief Unmaps an address that was previously mapped with #ChmMapGuestGvaPagesToHost
///
/// @param HostVa   Host virtual address to be unmapped.
/// @param Tag      Identifier of this address. Must be the same as the one provided at map time.
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmUnmapGuestGvaPages(
    _Inout_ PVOID               *HostVa,
    _In_    DWORD               Tag
    );


//
// Higher level API for easy access
//


/// @brief Maps a range of bytes starting at a given guest virtual pages to host virtual address space
///
/// This function will iterate guest page-tables to get the guest physical address and then it will iterate
/// EPT associated with guest to find the host physical address that is associated and then will
/// map it to host virtual address space. This function may map several pages to accommodate the required size to be mapped.
///
/// @param Vcpu                 Vcpu for which the mapping will be done
/// @param GuestVirtAddress     Starting guest virtual address; may not be page-aligned
/// @param NumberOfBytesToMap   Number of bytes to map.
/// @param Options              A combination of CHM_FLAG_XXX flags that control the behavior of this function
/// @param HostVa               Address where the range is mapped in host virtual address
/// @param TargetReservedHostVa An already reserved and mapped address for the given range. If not NULL, HostVa will be ignored.
/// @param Tag                  Identifier for this mapping for tracking purposes
/// @return CX_STATUS_SUCCESS   On success
NTSTATUS
ChmMapGvaRange(
    _In_    VCPU*               Vcpu,
    _In_    QWORD               GuestVirtAddress,
    _In_    QWORD               NumberOfBytesToMap,
    _In_    CHM_FLAGS           Options,
    _Out_   PVOID               *HostVa,
    _In_opt_ VOID               *TargetReservedHostVa,
    _In_    DWORD               Tag
    );

/// @brief Unmaps an address that was previously mapped with #ChmMapGvaRange
///
/// @param HostVa   Host virtual address to be unmapped.
/// @param Tag      Identifier of this address. Must be the same as the one provided at map time.
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmUnmapGvaRange(
    _In_    PVOID               *HostVa,
    _In_    DWORD               Tag
    );

/// @brief Maps a range of bytes starting at a given guest physical addresses to host virtual address space
///
/// @param Vcpu                 Vcpu for which mapping is to be performed
/// @param GuestPhysAddress     Guest physical address that starts the range.
/// @param NumberOfBytesToMap   Number or consecutive pages to map
/// @param Options              A combination of CHM_FLAG_XXX flags that control the behavior of this function
/// @param HostVa               Address where the range is mapped in host virtual address
/// @param TargetReservedHostVa An already reserved and mapped address for the given range. If not NULL, HostVa will be ignored.
/// @param Tag                  Identifier for this mapping for tracking purposes
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmMapGpaRange(
    _In_    VCPU*               Vcpu,
    _In_    QWORD               GuestPhysAddress,
    _In_    QWORD               NumberOfBytesToMap,
    _In_    CHM_FLAGS           Options,
    _Out_   PVOID               *HostVa,
    _In_opt_ VOID               *TargetReservedHostVa,
    _In_    DWORD               Tag
    );

/// @brief Unmaps an address that was previously mapped with #ChmMapGpaRange
///
/// @param HostVa   Host virtual address to be unmapped.
/// @param Tag      Identifier of this address. Must be the same as the one provided at map time.
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
NTSTATUS
ChmUnmapGpaRange(
    _In_    PVOID               *HostVa,
    _In_    DWORD               Tag
    );

#endif // _CACHEMAP_H_
/// @}
