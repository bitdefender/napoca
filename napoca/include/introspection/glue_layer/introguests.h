/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introguests.h
*   @brief INTROGUESTS -  NAPOCA hypervisor glue layer, generic guest and glue related functions
*
*/

#ifndef _INTROGUESTS_H_
#define _INTROGUESTS_H_

#include "glueiface.h"

///
/// @brief      API exposed by Napoca that allows introcore to obtain various information about the guest.
///
/// Based on the InfoClass value, the functions should get or set different guest attributes, as follows. See IG_QUERY_INFO_CLASS
/// for possible classes of information.
/// Information may be: register status, MSR value, IDT/GDT tables, number of CPUs. The content of the buffer will depend on the
/// info class queried, and it will be:
/// - PINTRO_ARCH_REGS for register status.
/// - PIG_QUERY_MSR    for MSR value.
/// - PQWORD           for IDT base.
/// - PQWORD           for GDT base.
/// - PQWORD           for CPU count.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  InfoClass       Can be any of the IG_QUERY_INFO_CLASS values. The other parameters
///                             have different meanings based on the value of this parameter
/// @param[in]  InfoParam       For IG_QUERY_INFO_CLASS values that specify a VCPU number, it is the VCPU number. For the others
///                             it is not used. It can be IG_CURRENT_VCPU for the current VCPU
/// @param[in, out] Buffer      It has different meanings based on InfoClass. See above for details
/// @param[in]  BufferLength    The size of Buffer, in bytes
///
/// @returns    CX_STATUS_SUCCESS                 - if the query was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1     - if GuesHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3     - if TargetVcpuIndex is bigger than the available VCPUs in the Guest.
/// @returns    CX_STATUS_INVALID_PARAMETER_4     - if Query Buffer is NULL
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED - if an unimplemented info class is requested.
/// @returns    OTHER                             - other potential internal STATUS error value raised during IPC sending to other CPUs.
///
NTSTATUS
GuestIntNapQueryGuestInfo(
    _In_ PVOID GuestHandle,
    _In_ DWORD InfoClass,
    _In_opt_ PVOID InfoParam,
    _When_(InfoClass == IG_QUERY_INFO_CLASS_SET_REGISTERS, _In_reads_bytes_(BufferLength))
    _When_(InfoClass != IG_QUERY_INFO_CLASS_SET_REGISTERS, _Out_writes_bytes_(BufferLength))
    PVOID Buffer,
    _In_ DWORD BufferLength
);

///
/// @brief   Will send the notification received from the introspection engine to the guest.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EventClass      One of the INTRO_EVENT_TYPE values, specifying the type of event
/// @param[in]  Parameters      A pointer to a event specific structure. Once this function returns,
///                             the Parameters buffer is no longer valid
/// @param[in]  EventSize       The size of the Parameters buffer
///
/// @returns    CX_STATUS_SUCCESS                 - if the query was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1     - if GuesHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3     - if Parameters is NULL
/// @returns    OTHER                             - other potential internal STATUS error value raised during message sending to Guest.
///
NTSTATUS
GuestIntNapIntroEventNotify(
    _In_ PVOID GuestHandle,
    _In_ DWORD EventClass,
    _In_opt_ PVOID Parameters,
    _In_ size_t EventSize
);

///
/// @brief  The introspection signals an unrecoverable error.
///
/// On DEBUG builds it will try to enter the debugger, on RELEASE build it will simply Disable the Introspection engine.
/// Make sure to handle the case when it does RETURN to caller when/if you're using it.
///
void
GuestIntNapBugCheck(
    void
);

///
/// @brief Tries to break into the debugger.
///
/// On DEBUG builds it will try to enter the debugger, on RELEASE build it will simply Disable the Introspection engine.
/// Make sure to handle the case when it does RETURN to caller when/if you're using it :)
///
void
GuestIntNapEnterDebugger(
    void
);

///
/// @brief  Notifies the integrator that the introspection engine is active
///
/// @param[in]  Guest        Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                 - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER1      - if Guest is NULL
///
NTSTATUS
GuestIntNapNotifyIntrospectionActivated(
    _In_ PVOID Guest
);

///
/// @brief  Notifies the integrator that the introspection engine is no longer active
///
/// @param[in]  Guest         Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                 - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER1      - if Guest is NULL
///
NTSTATUS
GuestIntNapNotifyIntrospectionDeactivated(
    _In_ PVOID Guest
);

///
/// @brief  Notifies the integrator about an error encountered by the introspection engine
///
/// After receiving the error, the Hypervisor forwards to the Guest and saves the error state.
/// This API will be called by introspection only in case of an error and cannot be initialized.
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Error           The encountered error
/// @param[in]  Context         Error specific context. Not all INTRO_ERROR_STATE values have a
///                             context. Once this function returns, the Context pointer is no longer valid
///
/// @returns    CX_STATUS_SUCCESS                 - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER1      - if Guest is NULL
/// @returns    OTHER                             - other potential internal STATUS error value raised during message sending to Guest.
///
NTSTATUS
GuestIntNapNotifyIntrospectionErrorState(
    _In_ PVOID Guest,
    _In_ INTRO_ERROR_STATE Error,
    _In_opt_ PINTRO_ERROR_CONTEXT Context
);

///
/// @brief   Introspection notifies us that the buffer for CAMI can be freed.
///
/// This is primarily used by the CAMI update mechanism to notify the integrator when the
/// CAMI buffer can safely be freed.
/// As we don't want to free in order to not lose the content of the module, we just bypass this.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Buffer          The buffer to be freed
/// @param[in]  Size            The size of the buffer
///
/// @returns    CX_STATUS_SUCCESS                 - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER1      - if Guest is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2      - if Buffer is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER3      - if Size is 0
///
NTSTATUS
GuestIntNapReleaseBuffer(
    _In_ PVOID GuestHandle,
    _In_ PVOID Buffer,
    _In_ DWORD Size
);

///
/// @brief  Notifies the integrator that the introspection engine detected an operating system
///
/// Also, it logs the Startup Time of the Guest.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  GuestInfo       Information about the type and version of the detected operating system
///
/// @returns    CX_STATUS_SUCCESS                 - if successful
/// @returns    CX_STATUS_INVALID_PARAMETER1      - if GuestHandle is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER2      - if GuestInfo is NULL
///
NTSTATUS
GuestIntNapNotifyGuestDetectedOs(
    _In_ PVOID GuestHandle,
    _In_ GUEST_INFO* GuestInfo
);

/// @brief  Injects an exception inside the guest
///
/// In current implementation, HVI will only inject a trap on the current VCPU,
/// so CpuNumber argument will always be either the actual current VCPU number or IG_CURRENT_VCPU.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  CpuNumber       The VCPU on which the injection will be done
/// @param[in]  TrapNumber      The exception number
/// @param[in]  ErrorCode       The error code, for exceptions that have one
/// @param[in]  Cr2             For page fault injections, the value of the CR2, ignored for other types
///
/// @returns    CX_STATUS_SUCCESS                   - if successful
/// @returns    CX_STATUS_OPERATION_NOT_IMPLEMENTED - if Introspection tries to inject to another VCPU, not the current one
/// @returns    OTHER                               - other potential internal STATUS error value raised during message
///                                                 sending to Guest.
///
NTSTATUS
GuestIntNapInjectTrap(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ BYTE TrapNumber,
    _In_ DWORD ErrorCode,
    _In_opt_ QWORD Cr2
);

#endif // _INTROGUESTS_H_

///@}