/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup introspectioncallbacks Introspection callbacks and call support for dynamically registered callbacks
/// @ingroup hvcallintro
///@{

/** @file intro_cb_wrappers.c
*   @brief INTRO_CB_WRAPPERS -  NAPOCA hypervisor callback wrapper layer for introspections on-the-fly registered callbacks (callbacks registered by
*   the GLUE functions.
*
*/

#include "napoca.h"
#include "guests/guests.h"
#include "guests/intro.h"
#include "introspection/intro_cb_wrappers.h"

/// @brief Macro for generic intro callback calling mechanism with implicit lock taking and actions based on return values
///
/// Takes the IntroCallbacksLock (race condition where init or un-init is in place on some other CPU), calls the callback and
/// checks for all the generic errors given back by intro and disables introspection if the engine raises the need for this
/// resulting from the callback.
///
#define LOCK_AND_CALL(UnloadIfError, OrigCb, Guest, ...)                                                                        \
    GUEST* guest = (GUEST*)Guest;                                                                                               \
    NTSTATUS status = CX_STATUS_COMPONENT_NOT_INITIALIZED;                                                                      \
                                                                                                                                \
    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);                                                                \
    if (guest->Intro.IntrospectionEnabled && guest->Intro.OrigCb)                                                               \
    {                                                                                                                           \
        status = guest->Intro.OrigCb(guest, __VA_ARGS__);                                                                       \
    }                                                                                                                           \
    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);                                                                \
                                                                                                                                \
    if ((UnloadIfError                                                                                                          \
        && (status == INT_STATUS_FATAL_ERROR                                                                                    \
            || status == INT_STATUS_UNINIT_BUGCHECK                                                                             \
            || guest->Intro.IntroReportedErrorStates & INTRO_FATAL_ERROR_STATES                                                 \
            ))                                                                                                                  \
        || guest->Intro.IntroRequestedToBeDisabled)                                                                             \
    {                                                                                                                           \
        LOG("Introspection callback returned 0x%x! Requested to be disabled: %d. Disable introspection for this guest!\n",      \
            status, guest->Intro.IntroRequestedToBeDisabled);                                                                   \
        NTSTATUS unloadStatus = NapIntDisable(guest, IG_DISABLE_IGNORE_SAFENESS);                                               \
        if (!SUCCESS(unloadStatus))                                                                                             \
        {                                                                                                                       \
            LOG_FUNC_FAIL("NapIntDisable", unloadStatus);                                                                       \
        }                                                                                                                       \
        guest->Intro.IntroRequestedToBeDisabled = FALSE;                                                                        \
        guest->Intro.IntroReportedErrorStates = 0;                                                                              \
        guest->Intro.IntrospectionActivated = FALSE;                                                                            \
    }

NTSTATUS
IntEPTViolationCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD VirtualAddress,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION * Action,
    _In_ IG_EPT_ACCESS Type
    )
{
    LOCK_AND_CALL(FALSE, RawIntroEptCallback, GuestHandle, PhysicalAddress, Length, VirtualAddress, CpuNumber, Action, Type);
    return status;
}

NTSTATUS
IntMSRViolationCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Msr,
    _In_ IG_MSR_HOOK_TYPE Flags,
    _Out_ INTRO_ACTION* Action,
    _In_opt_ QWORD OriginalValue,
    _Out_ QWORD* NewValue,
    _In_ DWORD CpuNumber
    )
{
    LOCK_AND_CALL(FALSE, RawIntroMsrCallback, GuestHandle, Msr, Flags, Action, OriginalValue, NewValue, CpuNumber);
    return status;
}


NTSTATUS
IntIntroCallCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD Rip,
    _In_ DWORD Cpu
    )
{
    LOCK_AND_CALL(TRUE, RawIntroCallCallback, GuestHandle, Rip, Cpu);
    return status;
}

NTSTATUS
IntIntroTimerCallbackWrapper(
    _In_ PVOID GuestHandle
    )
{
    LOCK_AND_CALL(TRUE, RawIntroTimerCallback, GuestHandle);
    return status;
}


NTSTATUS
IntIntroDescriptorTableCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Flags,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    )
{
    LOCK_AND_CALL(TRUE, RawIntroDescriptorTableCallback, GuestHandle, Flags, CpuNumber, Action);
    return status;
}

NTSTATUS
IntCrWriteCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr,
    _In_ DWORD CpuNumber,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
{
    LOCK_AND_CALL(TRUE, RawIntroCrCallback, GuestHandle, Cr, CpuNumber, OldValue, NewValue, Action);
    return status;
}

NTSTATUS
IntXcrWriteCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    )
{
    LOCK_AND_CALL(TRUE, RawIntroXcrCallback, GuestHandle, CpuNumber, Action);
    return status;
}

NTSTATUS
IntBreakpointCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ QWORD GuestPhysicalAddress,
    _In_ DWORD CpuNumber
    )
{
    LOCK_AND_CALL(TRUE, RawIntroBreakpointCallback, GuestHandle, GuestPhysicalAddress, CpuNumber);
    return status;
}

NTSTATUS
IntEventInjectionCallbackWrapper(
    _In_ PVOID GuestHandle,
    _In_ DWORD Vector,
    _In_ QWORD ErrorCode,
    _In_ QWORD Cr2,
    _In_ DWORD CpuNumber
    )
{
    LOCK_AND_CALL(FALSE, RawIntroEventInjectionCallback, GuestHandle, Vector, ErrorCode, Cr2, CpuNumber);
    return status;
}


///@}