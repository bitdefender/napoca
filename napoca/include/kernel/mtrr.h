/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __MTRR_H__
#define __MTRR_H__

#include "core.h"
#include "kernel/kerneltypes.h"
#include "common/kernel/vmxdefs.h"

/// @brief Build MTRR state
///
/// Builds machine MTRR state by reading the MSRs related to MTRR. It will read
/// MTRR configuration MSRs and then fixed range MTRRs and variable length MTRRs
///
/// @param MtrrState    location where the MTRR state will be stored; preallocated by the caller
/// @return CX_STATUS_SUCCESS       On success
NTSTATUS
MtrrBuildState(
    _Inout_ MTRR_STATE* MtrrState
    );


/// @brief Regenerate the memory map covered by MTRRs
///
/// Generates a kernel specific memory map from the given MTRR_STATE. It will allocate the MTRR_STATE::Map if it is not already allocated.
/// If MTRR_STATE::Map is allocated then its content will be overwritten with new items derived from the MTRR_STATE provided.
/// The function will make sure that there are no overlapping memory ranges in the generated memory map and their caching
/// type is correctly set.
///
/// @param Mtrr         pointer to a memory area where details about the given MTRR will be stored; preallocated by the caller
/// @return CX_STATUS_INVALID_PARAMETER_1   If Mtrr is NULL
/// @return CX_STATUS_SUCCESS               On success
NTSTATUS
MtrrGenerateMapFromState(
    _In_ MTRR_STATE* Mtrr
    );


/// @brief Retrieves details about fixed MTRR range entry
///
/// Retrieves the entry associated with a given fixed MTRR. Optionally it returns the index in the MTRR_STATE::Fixed array
/// where the entry for the given MTRR can be found.
///
/// @param MtrrState        pointer to a MTRR state where to look for fixed range MTRRs
/// @param Mtrr             Msr that identifies the MTRR
/// @param FixedEntryIndex  will store the index in the MTRR_STATE::Fixed array where the entry for the given MTRR can be found
/// @return                 NULL if the parameters are invalid or there is no entry associated with the given MTRR
/// @return                 a pointer to the entry associated with the given MTRR
MTRR_FIX_ENTRY*
MtrrGetFixedRangeEntryAndIndex(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Mtrr,
    __out_opt DWORD* FixedEntryIndex
    );


/// @brief Retrieves details about variable MTRR range entry
///
/// Retrieves the entry associated with a given variable MTRR. Optionally it returns the index in the MTRR_STATE::Var array
/// where the entry for the given MTRR can be found.
///
/// @param MtrrState                  pointer to a MTRR state where to look for variable range MTRRs
/// @param Mtrr                       Msr that identifies the MTRR
/// @param VarEntryIndex              will store index in the MTRR_STATE::Var array where the entry for the given MTRR can be found
/// @return                           NULL if the parameters are invalid or there is no entry associated with the given MTRR
/// @return                           a pointer to the entry associated with the given MTRR
MTRR_VAR_ENTRY*
MtrrGetVarRangeEntryAndIndex(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Mtrr,
    __out_opt DWORD* VarEntryIndex
    );


/// @brief  Determines if a MTRR is a fixed-range MTRR
/// @param Mtrr     Mtrr msr value
/// @return         TRUE if Mtrr represents a fixed-range MTRR; FALSE otherwise
__forceinline
BOOL
MtrrIsFixed(
    _In_ QWORD Mtrr
    )
{
    return ( (Mtrr == MSR_IA32_MTRR_FIX64K_00000) || (Mtrr == MSR_IA32_MTRR_FIX16K_A0000) || (Mtrr == MSR_IA32_MTRR_FIX16K_80000) || ( (Mtrr >= MSR_IA32_MTRR_FIX4K_C0000) && (Mtrr <= MSR_IA32_MTRR_FIX4K_F8000)));
}

/// @brief  Determines if a MTRR is a variable-range MTRR
/// @param Mtrr     Mtrr msr value
/// @return         TRUE if Mtrr represents a variable-range MTRR; FALSE otherwise
__forceinline
BOOL
MtrrIsVariable(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Mtrr
    )
{
    return ( (Mtrr >= MSR_IA32_MTRR_PHYSBASE0) && (Mtrr <= (MSR_IA32_MTRR_PHYSBASE0 + ((MtrrState->VarCount * 2) -1))) );
}


/// @brief Retrieve the value for a fixed MTRR range
///
/// Returns the raw value of the given MTRR. The MTRR must be a fixed range MTRR
///
/// @param MtrrState              pointer to a MTRR state where to look for fixed range MTRRs
/// @param Msr                    a valid fixed range MTRR value
/// @param Value                  location where to store the raw value of the given MTRR
/// @return CX_STATUS_DATA_NOT_FOUND            The given MTRR cannot be found.
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   Given MTRR is not a fixed MTRR
/// @return CX_STATUS_INVALID_PARAMETER_1           MtrrState is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3           Value is NULL
/// @return CX_STATUS_SUCCESS                   On success
NTSTATUS
MtrrGetFixedRangeValue(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Msr,
    _Out_ QWORD* Value
    );


/// @brief Retrieve the value for a variable MTRR range
///
/// Returns the raw value of the given MTRR. The MTRR must be a variable range MTRR
///
/// @param MtrrState                 pointer to a MTRR state where to look for fixed range MTRRs
/// @param Msr                       a valid variable range MTRR value
/// @param Value                     location where to store the raw value of the given MTRR
/// @return CX_STATUS_DATA_NOT_FOUND                The given MTRR cannot be found.
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED       Given MTRR is not a variable MTRR
/// @return CX_STATUS_INVALID_PARAMETER_1           Mtrr is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3           Value is NULL
/// @return CX_STATUS_SUCCESS                       On success
NTSTATUS
MtrrGetVarRangeValue(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Msr,
    _Out_ QWORD* Value
    );


/// @brief Update maximum physical address covered by MTRR
///
/// Updates the maximum physical memory address that is covered by the given MTRR state.
///
/// @param MtrrState                      pointer to a memory area where details about the given MTRR will be stored; preallocated by the caller
/// @param OldMaxPhysicalAddress          location where to store the old value of the maximum physical memory address covered by the given MTRR state
/// @return CX_STATUS_INVALID_PARAMETER_1           Mtrr is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3           Value is NULL
/// @return CX_STATUS_SUCCESS               On success
NTSTATUS
MtrrUpdateMaxPhysicalAddressInState(
    _In_ MTRR_STATE* MtrrState,
    _Out_ QWORD* OldMaxPhysicalAddress
    );

#endif // __MTRR_H__
