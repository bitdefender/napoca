/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introept.h
*   @brief INTROEPTHOOK -  NAPOCA hypervisor glue layer, EPT hook support and SPP hook support
*
*/
#ifndef _INTROEPT_H_
#define _INTROEPT_H_

#include "glueiface.h"

//
// EPT hook
//


///
/// @brief  Returns the EPT access rights for a guest physical page
///
/// Will extract the EPT page attributes for the given GPA. On exit, Read, Write & Execute will contain
/// values that indicate if the EPT page is readable, writable or executable.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EptIndex        The EPTP index of the EPT for which the query is done.
///                             Can be IG_CURRENT_EPT to signal that the currently loaded EPT should be used
/// @param[in]  Address         The guest physical address for which the access rights are requested
/// @param[out] Read            1 if the page is readable, 0 otherwise. Ignored on unsuccessful calls
/// @param[out] Write           1 if the page is writable, 0 otherwise. Ignored on unsuccessful calls
/// @param[out] Execute         1 if the page is executable, 0 otherwise. Ignored on unsuccessful calls
///
/// @returns    CX_STATUS_SUCCESS                   - if the query was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    CX_STATUS_NOT_SUPPORTED             - if the memory is not valid for the introspection engine
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if EptGetRights returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if EptGetRights returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapGetEPTPageProtection(
    _In_ PVOID GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BYTE* Read,
    _Out_ BYTE* Write,
    _Out_ BYTE* Execute
);

///
/// @brief  Sets the EPT access rights for a guest physical page
///
/// Will modify the EPT attributes of the given GPA to the new supplied attributes
/// represented by Read, Write & Execute.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EptIndex        The EPTP index of the EPT for which the query is done.
///                             Can be IG_CURRENT_EPT to signal that the currently loaded EPT should be used
/// @param[in]  Address         The guest physical address for which the access rights are requested
/// @param[in]  Read            1 if the read permission is granted, 0 if not
/// @param[in]  Write           1 if the write permission is granted, 0 if not
/// @param[in]  Execute         1 if the execute permission is granted, 0 if not
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    CX_STATUS_NOT_SUPPORTED             - if the memory is not valid for the introspection engine
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if EptSetRights returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if EptSetRights returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapSetEPTPageProtection(
    _In_ PVOID GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BYTE Read,
    _In_ BYTE Write,
    _In_ BYTE Execute
);

///
/// @brief  Get the convertible status of a guest physical page
///
/// Retrieves if for a page in EPT, the EPT violation is convertible to Virtualization Exception or not
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EptIndex        The index of the EPT for which the query is done. Can be IG_CURRENT_EPT.
/// @param[in]  Address         The guest physical address for which the query is done
/// @param[out] Convertible     True if the page is convertible, False if it is not
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    CX_STATUS_NOT_SUPPORTED             - if the memory is not valid for the introspection engine
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if EptGetRights returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if EptGetRights returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapGetEPTPageConvertible(
    _In_ PVOID GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BOOLEAN* Convertible
);

///
/// @brief  Set the convertible status of a guest physical page
///
/// Modifies the mapping in EPT for the requested GPA to be convertible or not.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EptIndex        The index of the EPT for which the query is done. Can be IG_CURRENT_EPT
/// @param[in]  Address         The guest physical address for which the query is done
/// @param[in]  Convertible     True if the page will be made convertible, False if it will be made not convertible
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    CX_STATUS_NOT_SUPPORTED             - if the memory is not valid for the introspection engine
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if EptAlterMappings returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if EptAlterMappings returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapSetEPTPageConvertible(
    _In_ PVOID GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BOOLEAN Convertible
);

///
/// @brief  Creates a new EPT
///
/// Creates a new EPT by cloning the original and filling with RWX access everywhere.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[out] EptIndex        The EPTP index for the newly created EPT
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if GstCreateMemoryDomain returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if GstCreateMemoryDomain returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapCreateEPT(
    _In_ PVOID Guest,
    _Out_ DWORD* EptIndex
);

///
/// @brief  Destroys an EPT
///
/// Destroys an entire ept by freeing and unmapping every page allocated fot the tables.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  EptIndex        The EPTP index of the EPT that will be deleted
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if GstDestroyMemoryDomain returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if GstDestroyMemoryDomain returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapDestroyEPT(
    _In_ PVOID Guest,
    _In_ DWORD EptIndex
);

///
/// @brief  Switches the currently loaded EPT
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  NewEptIndex     The index of the EPT that will be loaded
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if NewEptIndex is greater than GstGetMemoryDomainsCount
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapSwitchEPT(
    _In_ PVOID Guest,
    _In_ DWORD NewEptIndex
);

///
/// @brief  Set the virtualization exception info page
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  CpuNumber       The VCPU Number for which the setting is done
/// @param[in]  VeInfoGpa       The guest physical address at which the info page resides
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*       - if parameters are NULL pointers or have invalid values.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the EptIndex was not allocated yet
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if any mapping function returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if any mapping function returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapSetVEInfoPage(
    _In_ PVOID Guest,
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoGpa
);

///
/// @brief  Registers an EPT exit callback
///
/// Will register a callback that will be called whenever an EPT violation is generated.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Callback        The callback that must be invoked on EPT violation exits
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Callback is NULL
/// @returns    CX_STATUS_ALREADY_INITIALIZED       - if the callback was already initialized, but not uninitialized
///
NTSTATUS
GuestIntNapRegisterEptHandler(
    _In_ PVOID Guest,
    _In_ PFUNC_IntEPTViolationCallback Callback
);

///
/// @brief  Unregisters the current EPT exit callback, unsubscribing introcore from EPT violation events
///
/// Will unregister the callback for EPT violations. This way, the introspection engine
/// will not be notified anymore when EPT violations occurred.
///
/// @param[in]  Guest           Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED_HINT      - if the callback was not registered before calling this function.
///
NTSTATUS
GuestIntNapUnregisterEptHandler(
    _In_ PVOID Guest
);

//
// SPP hooks
//

///
/// @brief  Returns the SPP protection rights for a guest physical address.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Address         The guest physical address for which the query is done
/// @param[out] SppValue        On success, will contain the SPP table entry for Address
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Address is not 4KB page-aligned
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if SppValue is NULL.
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if SppGetPageProtection returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if SppGetPageProtection returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapGetSPPPageProtection(
    _In_ PVOID Guest,
    _In_ QWORD Address,
    _Out_ QWORD* SppValue
);

///
/// @brief  Set the SPP protection rights for a guest physical address.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Address         The guest physical address for which the query is done
/// @param[out] SppValue        The SPP table entry for Address
///
/// @returns    CX_STATUS_SUCCESS                   - if the change was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Address is not 4KB page-aligned
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if SppSetPageProtection returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if SppSetPageProtection returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised during operations with EPT.
///
NTSTATUS
GuestIntNapSetSPPPageProtection(
    _In_ PVOID GuestHandle,
    _In_ QWORD Address,
    _In_ QWORD SppValue
);

#endif // _INTROEPT_H_

///@}