/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file os_detect.h
*   @brief Support to detect the guest OS version
*/

#ifndef OS_DETECT_H
#define OS_DETECT_H

#include "base/cx_sal.h"
#include "base/cx_defs.h"
#include "base/cx_types.h"

typedef struct _VCPU VCPU;

/**
 *  @brief Define a windows version
 */
typedef enum _OS_SCAN_VERDICTS
{
    OS_SCAN_INVALID = 0,
    OS_SCAN_WIN7 = 1,
    OS_SCAN_WIN8 = 2,
    OS_SCAN_WIN10 = 3,
    OS_SCAN_NOTHING_DETECTED = 0xFFFFFFFF
}OS_SCAN_VERDICT;

///
/// @brief Detect guest OS Windows version
///
///
/// @param[in]  Vcpu                    running VCPU
/// @param[out] Verdict                 guest OS Windows version
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if VCPU is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Verdict is NULL
///
CX_STATUS
OdCheckOsSignatures(
    _In_  VCPU            *Vcpu,
    _Out_ OS_SCAN_VERDICT *Verdict
);

NTSTATUS
OdDetectGuestOs(
    _Inout_ GUEST* Guest,
    _In_ VCPU* Vcpu
);


#endif //OS_DETECT_H
