/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup introspectioncallbacks
///@{

/** @file intro_cb_wrappers.h
*   @brief INTRO_CB_WRAPPERS -  NAPOCA hypervisor callback wrapper layer for introspections on-the-fly registered callbacks (callbacks registered by
*   the GLUE functions.
*
*/
#ifndef _INTRO_CB_WRAPPERS_H_
#define _INTRO_CB_WRAPPERS_H_

#include "glueiface.h"

///
/// Callback that must be invoked on EPT violation VMEXITs. The introspection engines
/// registers a callback of this type with the GLUE_IFACE.RegisterEPTHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  PhysicalAddress     The physical address for which the exit was triggered
/// @param[in]  Length              The size of the access that triggered exit
/// @param[in]  VirtualAddress      The guest linear address for which the exit was triggered
/// @param[in]  CpuNumber           The virtual CPU for which the exit was triggered
/// @param[out] Action              The action that must be taken
/// @param[in]  Type                The type of the access. Can be a combination of IG_EPT_HOOK_TYPE values
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the EptViolation
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntEPTViolationCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD VirtualAddress,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION* Action,
    _In_ IG_EPT_ACCESS Type
);

///
/// Callback that must be invoked on MSR violation VMEXITs. The introspection engines
/// registers a callback of this type with the GLUE_IFACE.RegisterMSRHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  Msr                 The physical MSR for which the exit was triggered
/// @param[in]  Flags               Flags describing the access
/// @param[out] Action              The action that must be taken
/// @param[in]  OriginalValue       The original value of the MSR
/// @param[out] NewValue            The new value of the MSR, after introcore handled the access
/// @param[in]  CpuNumber           The virtual CPU for which the exit was triggered
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the MsrViolation
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntMSRViolationCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Msr,
    _In_ IG_MSR_HOOK_TYPE Flags,
    _Out_ INTRO_ACTION* Action,
    _In_opt_ QWORD OriginalValue,
    _Out_ QWORD* NewValue,
    _In_ DWORD CpuNumber
);

///
/// Callback that must be invoked when the guest executes a VMCALL. The introspection engine
/// registers a callback of this type with the GLUE_IFACE.RegisterIntroCallHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  Rip                 The guest linear address of the VMCALL instruction
/// @param[in]  Cpu                 The VCPU number on which the VMCALL was executed
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the IntroCall
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntIntroCallCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD Rip,
    _In_ DWORD Cpu
);

///
/// A periodic timer callback that must be invoked once per second. The introspection engine
/// registers a callback of this type with the GLUE_IFACE.RegisterIntroTimerHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the Timer
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntIntroTimerCallbackWrapper(
    _In_ PVOID GuestHandle
);

///
/// Callback that must be invoked when the guest accesses a descriptor table register. The introspection
/// engine registers a callback of this type with the GLUE_IFACE.RegisterDtrHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  Flags               Flags that describe the access. Can be a combination of IG_DESC_ACCESS values
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
/// @param[out] Action              Action that must be taken
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the DescriptorTable
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntIntroDescriptorTableCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Flags,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
);

///
/// Callback that must be invoked when the guest tries to modify a control register. The introspection
/// engine registers a callback of this type with the GLUE_IFACE.RegisterCrWriteHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  Cr                  The control register that was accessed
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
/// @param[in]  OldValue            The original value of the register
/// @param[in]  NewValue            The value that the guest attempted to write
/// @param[out] Action              The action that must be taken
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the CrWrite
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntCrWriteCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr,
    _In_ DWORD CpuNumber,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
);

///
/// Callback that must be invoked when the guest tries to modify an extended control register.
/// The introspection engine registers a callback of this type with the GLUE_IFACE.RegisterXcrWriteHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
/// @param[out] Action              The action that must be taken
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the XcrWrite
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntXcrWriteCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
);

///
/// Callback that must be invoked when the guest hits a breakpoint. The introspection engine
/// registers a callback of this type with the GLUE_IFACE.RegisterBreakpointHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  GuestPhysicalAddress The guest physical address at which the instruction that triggered
///                                 the breakpoint is located
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the Breakpoint
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntBreakpointCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD GuestPhysicalAddress,
    _In_ DWORD CpuNumber
);

///
/// Callback that must be invoked when an exception is successfully injected inside the guest.
/// The introspection engine registers a callback of this type with the
/// GLUE_IFACE.RegisterEventInjectionHandler API.
/// This is a generic wrapper above the callback registered by the introspection engine,
/// if the error handling should be done different then the generic LOCK_AND_CALL way, then
/// it is recommended to make the raw call and write the specific error-handling.
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  Vector              The exception vector that was injected
/// @param[in]  ErrorCode           The error code of the injected exception, if it exists
/// @param[in]  Cr2                 The Cr3 value. This parameter is valid only for page fault injections
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    OTHER                               - other introspection statuses returned by the EventInjection
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
IntEventInjectionCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Vector,
    _In_ QWORD ErrorCode,
    _In_ QWORD Cr2,
    _In_ DWORD CpuNumber
);

#endif //_INTRO_CB_WRAPPERS_H_

///@}