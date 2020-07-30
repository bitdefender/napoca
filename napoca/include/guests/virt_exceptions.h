/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file virt_exceptions.h
 *  @brief Support for injecting exceptions into the guest
 */

 /// \defgroup virt_exceptions EVENT INJECTION - Support for injecting exceptions into GUEST software
 /// @{

#ifndef _VIRT_EXCEPTIONS_H_
#define _VIRT_EXCEPTIONS_H_

#include "kernel/exceptions.h"

typedef struct _VCPU VCPU;

/**
 *  @brief The structure that maintains information about a certain exception
 *  that must be injected inside the GUEST on a certain VCPU.
 */
typedef struct _EXCEPTION_INFO
{
    // Common fields here
    DWORD   ExceptionErrorCode;         ///< Exception error code. Error codes are not pushed on the stack for all exceptions.

    union
    {
        struct
        {
            QWORD   VirtualAddress;     ///< Value to set CR2. When a page fault occurs, the address the program attempted to access is stored in the CR2. */
        }PageFaultSpecific;
    } SpecificInfo;                     ///< Specific fields per exception here. If the boolean HasSpecificInfo is set in global vector gExceptionDetails, then a structure specific to that exception must be found in this union.
}EXCEPTION_INFO;

///
/// @brief  Injects an exception inside the guest
///
/// More precisely, the function does not actually inject into the guest the exception.
/// The exception is prepared to be injected into the GUEST and in the exit handling routine
/// the VirtExcHandlePendingExceptions function is called, which will decide according to the priority
/// which exception will be injected when the entry is made back in the GUEST.
///
/// @param[in]  GuestHandle     Guest pointer. Not used, for now we only support one GUEST.
/// @param[in]  Vcpu            The VCPU on which the injection will be done
/// @param[in]  ExceptionNumber The exception number
/// @param[in]  ErrorCode       The error code, for exceptions that have one
/// @param[in]  Cr2             For page fault injections, the value of the CR2, ignored for other types
///
/// @returns    CX_STATUS_SUCCESS                   - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Vcpu is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if ExceptionNumber is not valid
///
NTSTATUS
VirtExcInjectException(
    _In_ PVOID      GuestHandle,
    _In_ VCPU*      Vcpu,
    _In_ EXCEPTION  ExceptionNumber,
    _In_ DWORD      ErrorCode,
    _In_opt_ QWORD  Cr2
);

///
/// @brief  Resets the fact that an exception must be injected into the GUEST.
///
/// @param[in]  Vcpu            The VCPU on which the exception will no longer be injected
/// @param[in]  ExceptionNumber The exception number
///
/// @returns    CX_STATUS_SUCCESS                   - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Vcpu is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if ExceptionNumber is not valid
///
NTSTATUS
VirtExcResetPendingException(
    _In_ VCPU*      Vcpu,
    _In_ EXCEPTION  ExceptionNumber
);

///
/// @brief  Effectively injects exceptions into the guest
///
/// This function is called to an exit from the guest on each VCPU.
/// Each VCPU has in its queue (or not) one or more exceptions that must be injected into the guest.
/// Depending on the priority, this function will decide which exception will be injected in this exit.
///
/// @param[in]  Vcpu            The VCPU on which the injection will be done
///
/// @returns    CX_STATUS_SUCCESS                   - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER         - if Vcpu is NULL or not the running VCPU
/// @returns    OTHER                               - other potential internal STATUS error value raised during injection into the Guest.
///
NTSTATUS
VirtExcHandlePendingExceptions(
    _In_ VCPU* Vcpu
);

///
/// @brief  Check if an exception needs to be reinjected and do so if necessary
///
/// @returns    TRUE                                - if any exception has been reinjected
/// @returns    FALSE                               - if nothing has been reinjected
///
BOOLEAN
VirtExcReinjectPendingExceptions(
    VOID
);

///
/// @brief  Resets all exceptions from a VCPU queue
///
/// @param[in]  Vcpu            The VCPU whose exception queue needs to be reset
///
/// @returns    CX_STATUS_SUCCESS                   - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER         - if Vcpu is NULL
///
NTSTATUS
VirtExcResetPendingExceptions(
    VCPU* Vcpu
);

/// @}

#endif // _VIRT_EXCEPTIONS_H_