/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __MSRCALLBACKS_H__
#define __MSRCALLBACKS_H__

/// \addtogroup hooks
/// @{

#include "core.h"


/// @brief Reads the virtualized values for the given MTRR
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the virtual MSR value was returned
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - Value can not be CX_NULL
/// @returns    STATUS_NO_HOOK_MATCHED              - There is no action that can be performed by this callback for the given MTRR
/// @returns    OTHER                               - Any other internal issue
CX_STATUS
VirtMtrrReadCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64 *Value,
    _In_opt_ CX_VOID* Context
    );

/// @brief Writes the virtualized values for the given MTRR, and updates the internal structures if needed (ex. EPT caching, MTRR maps, ...)
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the virtual MSR value was updated alongside the additional updates
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE    - The internal state of the MTRR related information is invalid
/// @returns    STATUS_NO_HOOK_MATCHED              - There is no action that can be performed by this callback for the given MTRR
/// @returns    OTHER                               - Any other internal issue
CX_STATUS
VirtMtrrWriteCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    );

///@brief Executed as a response to a guest attempt to read the TSC MSR. It will return the virtualized TSC of the guest.
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtMsrReadTscCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64 *Value,
    _In_opt_ CX_VOID* Context
    );

/// @brief Executed as a response to a guest attempt to write the TSC MSR. Writes the given value to the virtual TSC MSR.
///
/// Also used for triggering the delayed exposure of the Microsoft Hypervisor Interface on Win7 with UEFI boot
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtMsrWriteTscCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    );


/// @brief Ignores the writes from MSR_IA32_MISC_ENABLE, as it should be, based on the MTLF specification
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtMsrWriteMiscEnable(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    );

/// @brief Used for triggering the OS scan needed for the delayed exposure of the Microsoft Hypervisor Interface
///
/// @returns    STATUS_NO_HOOK_MATCHED              - Always (to allow bare metal execution)
CX_STATUS
VirtMsrWriteLstar(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
);

/// @brief Used for triggering the OS scan needed for the delayed exposure of the Microsoft Hypervisor Interface
///
/// @returns    STATUS_NO_HOOK_MATCHED              - Always (to allow bare metal execution)
CX_STATUS
VirtMsrWriteSysEnter(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
);

/// @brief Used for tracing/hiding a few performance monitor related MSRs
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtPerfCntWriteCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
);

/// @brief Used for tracing/hiding a few performance monitor related MSRs
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtPerfCntReadCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64* Value,
    _In_opt_ CX_VOID* Context
);

/// @brief Used for tracing a few power management related MSRs
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtWritePowerAndPerf(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
);

/// @brief Used for tracing a few power management related MSRs
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
VirtReadPowerAndPerf(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64 *Value,
    _In_opt_ CX_VOID* Context
);

/// @}

#endif //__MSRCALLBACKS_H__
