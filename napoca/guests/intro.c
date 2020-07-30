/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup hvcallintro Introspection support for hypervisor -> introspection engine calls
/// @ingroup introspection
///@{

/** @file intro.c
*   @brief INTRO -  NAPOCA hypervisor glue layer, introspection engine utilities, glue functions with semantic of hypervisor -> introspection
*
*/
#include "napoca.h"
#include "kernel/kernel.h"
#include "guests/guests.h"
#include "guests/intro.h"


VOID
ValidateIntroCallbacksLockEx(
    _In_ RW_SPINLOCK *RwLock,
    _In_ char *File,
    _In_ char *Function,
    _In_ DWORD Line
)
{
    SPINLOCK_STATE state = HvGetRwSpinlockState(RwLock);
    if (!(state & SPINLOCK_STATE_ACQUIRED_EXCLUSIVE))
    {
        ERROR("IntroCallbacksLock is not acquired exclusively when changing callback at %s:%d in %s\n", File, Line, Function);
    }
    if ((state & SPINLOCK_STATE_LAST_OWNER_OTHER))
    {
        WARNING("IntroCallbacksLock is acquired exclusively by someone else when changing callback at %s:%d in %s\n", File, Line, Function);
    }
}


NTSTATUS
NapIntNotifyAboutNewGuest(
    _In_ PVOID Guest,
    _In_ QWORD Options,
    _In_reads_(BufferLength) PBYTE UpdateBuffer,
    _In_ DWORD BufferLength
)
{
    NTSTATUS status;
    GUEST* guest = (GUEST*)Guest;

    if (guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (gHypervisorGlobalData.Introspection.GlueIface.NewGuestNotification == NULL)
    {
        ERROR("gHypervisorGlobalData.Introspection.GlueIface.NewGuestNotification not initialized!\n");
        return CX_STATUS_NOT_INITIALIZED;
    }

    if (UpdateBuffer == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (BufferLength == 0) return CX_STATUS_INVALID_PARAMETER_4;

    if (guest->Intro.IntrospectionEnabled)
    {
        LOG("Introspection is already enabled\n");
        status = CX_STATUS_ALREADY_INITIALIZED_HINT;
    }
    else
    {
        HvAcquireRwSpinLockExclusive(&guest->Intro.IntroCallbacksLock);

        LOG("Requested to enable introspection on physical CPU index: %d and apic id: %d\n", HvGetCurrentCpuIndex(), HvGetCurrentCpu()->Id);

        QWORD start = 0, end = 0;

        guest->Intro.IntroRequestedToBeDisabled = FALSE;

        LOG("Will try to enable introspection with 0x%x\n", Options);
        start = HvGetLinearTimeInMicroseconds();
        status = gHypervisorGlobalData.Introspection.GlueIface.NewGuestNotification(guest, Options, UpdateBuffer, BufferLength);
        end = HvGetLinearTimeInMicroseconds();

        LOG("Introspection initialization steps took %d miliseconds\n", (end - start) / MICROSECONDS_PER_MILISECOND);
        if (!NT_SUCCESS(status))
        {
            LOG("Introspection not enabled! (0x%x)\n", status);
        }
        else
        {
            LOG("Introspection enabled with 0x%x\n", Options);
            guest->Intro.IntrospectionEnabled = TRUE;
        }

        HvReleaseRwSpinLockExclusive(&guest->Intro.IntroCallbacksLock);
    }

    return status;
}

NTSTATUS
NapIntDisable(
    _In_ PVOID GuestHandle,
    _In_ QWORD Flags
)
{
    GUEST *guest = GuestHandle;
    NTSTATUS status;

    if (guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

       HvAcquireRwSpinLockExclusive(&guest->Intro.IntroCallbacksLock);
    if (guest->Intro.IntrospectionEnabled && gHypervisorGlobalData.Introspection.GlueIface.DisableIntro)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.DisableIntro(GuestHandle, Flags);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.DisableIntro", status);
        }
        else
        {
            guest->Intro.IntrospectionEnabled = FALSE;
        }
    }
    else if (!guest->Intro.IntrospectionEnabled)
    {
        LOG("Introspection is not enabled\n");
        status = CX_STATUS_NOT_INITIALIZED_HINT;
    }
    else
    {
        ERROR("gHypervisorGlobalData.Introspection.GlueIface.DisableIntro is NULL!\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockExclusive(&guest->Intro.IntroCallbacksLock);

    return status;
}


NTSTATUS
NapIntNotifyGuestPowerStateChange(
    _In_           PVOID                Guest,
    _In_           BOOLEAN              Resume,
    _In_opt_       BYTE                 AcpiPowerState
)
{
    NTSTATUS status;
    GUEST* guest = (GUEST*)Guest;

    if (guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (!((GUEST*)Guest)->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    if (gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange)
    {
        HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

        if (Resume)
        {
            LOG("Notify introspection about power state transition. State: 0x%x\n", intGuestPowerStateResume);
            status = gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange(Guest, intGuestPowerStateResume);
        }
        else
        {
            if (AcpiPowerState == ACPI_STATE_S1 || AcpiPowerState == ACPI_STATE_S3)
            {
                VCPULOG(HvGetCurrentVcpu(), "Notify introspection about power state transition. State: 0x%x\n", intGuestPowerStateSleep);
                status = gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange(Guest, intGuestPowerStateSleep);
            }
            else if (AcpiPowerState == ACPI_STATE_S4 || AcpiPowerState == ACPI_STATE_S5)
            {
                VCPULOG(HvGetCurrentVcpu(), "Notify introspection about power state transition. State: 0x%x\n", intGuestPowerStateShutDown);
                status = gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange(Guest, intGuestPowerStateShutDown);
            }
            else
            {
                VCPULOG(HvGetCurrentVcpu(), "Notify introspection about power state transition. State: 0x%x\n", intGuestPowerStateSleep);
                status = gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange(Guest, intGuestPowerStateSleep);
            }
        }

        HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.NotifyGuestPowerStateChange", status);
            return status;
        }

        return CX_STATUS_SUCCESS;
    }
    else return CX_STATUS_NOT_INITIALIZED;
}

NTSTATUS
NapIntDebugProcessCommand(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ DWORD Argc,
    _In_ CHAR* Argv[]
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
    if (gHypervisorGlobalData.Introspection.GlueIface.DebugProcessCommand == NULL)
    {
        ERROR("gHypervisorGlobalData.Introspection.GlueIface.DebugProcessCommand not initialized!\n");
        HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
        return CX_STATUS_NOT_INITIALIZED;
    }
    else
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.DebugProcessCommand(GuestHandle, CpuNumber, Argc, Argv);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL(" gHypervisorGlobalData.Introspection.GlueIface.DebugProcessCommand", status);
    }
    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntUpdateExceptions(
    _In_ PVOID GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
)
{
    NTSTATUS status;
    GUEST* guest = (GUEST*)GuestHandle;

    if (guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (gHypervisorGlobalData.Introspection.GlueIface.UpdateExceptions == NULL)
    {
        LOG("gHypervisorGlobalData.Introspection.GlueIface.UpdateExceptions not initialized!\n");
        return CX_STATUS_NOT_INITIALIZED;
    }

    if (Buffer == NULL)
    {
        LOG("[INFO] UpdateExceptions/Exceptions module not set... We cannot update exceptions...\n");
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_3;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    status = gHypervisorGlobalData.Introspection.GlueIface.UpdateExceptions(guest, Buffer, Length, Flags);
    if (!NT_SUCCESS(status))
    {
        ERROR("UpdateExceptions failed, with: %s\n", NtStatusToString(status));
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntGetExceptionsVersion(
    _In_ PVOID GuestHandle,
    _Out_ WORD* Major,
    _Out_ WORD* Minor,
    _Out_ DWORD* BuildNumber
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (Major == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (Minor == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (BuildNumber == NULL) return CX_STATUS_INVALID_PARAMETER_4;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.GetExceptionsVersion != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.GetExceptionsVersion(GuestHandle, Major, Minor, BuildNumber);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.GetExceptionsVersion", status);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.GetExceptionsVersion == NULL)\n");
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntGetGuestInfo(
    _In_ PVOID GuestHandle,
    _Out_ GUEST_INFO* GuestInfo
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (GuestInfo == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.GetGuestInfo != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.GetGuestInfo(GuestHandle, GuestInfo);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.GetGuestInfo", status);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.GetGuestInfo == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntSetIntroAbortStatus(
    _In_ PVOID GuestHandle,
    _In_ BOOLEAN Abort
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.SetIntroAbortStatus != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.SetIntroAbortStatus(GuestHandle, Abort);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.SetIntroAbortStatus", status);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.SetIntroAbortStatus == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntAddExceptionFromAlert(
    _In_ PVOID GuestHandle,
    _In_ const void* Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Event == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.AddExceptionFromAlert != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.AddExceptionFromAlert(GuestHandle, Event, Type, Exception, Context);
        if (!SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.AddExceptionFromAlert", status);
        else VCPULOG(HvGetCurrentVcpu(), "Exception added from alert (Context: 0x%llX).\n", Context);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.AddExceptionFromAlert == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntRemoveException(
    _In_ PVOID GuestHandle,
    _In_opt_ QWORD Context
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.RemoveException != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.RemoveException(GuestHandle, Context);
        if (!SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.RemoveException", status);
        else LOG("Exception removed (Context: 0x%llX)\n", Context);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.RemoveException == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntFlushAlertExceptions(
    _In_ PVOID GuestHandle
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.FlushAlertExceptions != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.FlushAlertExceptions(GuestHandle);
        if (!SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.FlushAlertExceptions", status);
        else LOG("Exceptions added from alerts FLUSHED");
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.FlushAlertExceptions == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntAddRemoveProtectedProcess(
    _In_ PVOID GuestHandle,
    _In_z_ const WCHAR* FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (FullPath == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.AddRemoveProtectedProcessUtf16 != NULL)
    {
        if (Add) INFO("Adding protected process '%S' with mask 0x%08x.\n", FullPath, ProtectionMask);
        else INFO("Removing protected process '%S'.\n", FullPath);

        status = gHypervisorGlobalData.Introspection.GlueIface.AddRemoveProtectedProcessUtf16(GuestHandle, FullPath, ProtectionMask, Add, Context);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("AddRemoveProtectedProcessUtf16", status);
        }
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.AddRemoveProtectedProcessUtf16 == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntRemoveAllProtectedProcesses(
    _In_ PVOID GuestHandle
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.RemoveAllProtectedProcesses != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.RemoveAllProtectedProcesses(GuestHandle);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.RemoveAllProtectedProcesses", status);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.RemoveAllProtectedProcesses == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntModifyDynamicOptions(
    _In_ PVOID GuestHandle,
    _In_ QWORD NewDynamicOptions
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (!((GUEST*)GuestHandle)->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    if (gHypervisorGlobalData.Introspection.GlueIface.ModifyDynamicOptions != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.ModifyDynamicOptions(GuestHandle, NewDynamicOptions);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.ModifyDynamicOptions", status);
        }
        else
        {
            CfgFeaturesIntrospectionOptions = NewDynamicOptions;
            LOG("Introspection flags dynamically updated with 0x%llx\n", NewDynamicOptions);
        }
    }
    else
    {
        ERROR("Introspection not present(? - ModifyDynagHypervisorGlobalData.Introspection.GlueIface.ModifyDynamicOptionsmicOptions == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    return status;
}

NTSTATUS
NapIntGetCurrentIntroOptions(
    _In_  PVOID GuestHandle,
    _Out_ QWORD* IntroOptions
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (IntroOptions == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (!((GUEST*)GuestHandle)->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    if (gHypervisorGlobalData.Introspection.GlueIface.GetCurrentIntroOptions != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.GetCurrentIntroOptions(GuestHandle, IntroOptions);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.GetCurrentIntroOptions", status);
            *IntroOptions = 0;
        }
    }
    else
    {
        ERROR("Introspection not present(? - GetCurrentIntroOptions == NULL)\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }

    return status;
}

NTSTATUS
NapIntUpdateSupport(
    _In_ PVOID GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Buffer == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_3;

    GUEST *guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (guest->Intro.IntrospectionEnabled)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.UpdateSupport(GuestHandle, Buffer, Length);
        if (!NT_SUCCESS(status)) ERROR("Intro UpdateSupport callback failed with status = %s\n", NtStatusToString(status));
    }
    else status = CX_STATUS_NOT_INITIALIZED;

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntGetSupportVersion(
    _In_ PVOID GuestHandle,
    _Out_ DWORD* MajorVersion,
    _Out_ DWORD* MinorVersion,
    _Out_ DWORD* BuildNumber
)
{
    NTSTATUS status;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (MajorVersion == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (MinorVersion == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (BuildNumber == NULL) return CX_STATUS_INVALID_PARAMETER_4;

    GUEST* guest = GuestHandle;

    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.GetSupportVersion != NULL)
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.GetSupportVersion(GuestHandle, MajorVersion, MinorVersion, BuildNumber);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.GetSupportVersion", status);
    }
    else
    {
        ERROR("Introspection not present(? - gHypervisorGlobalData.Introspection.GlueIface.GetSupportVersion == NULL)\n");
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

NTSTATUS
NapIntUpdateIntrospectionVerbosityLogs(
    _In_  PVOID        Guest,
    _In_  IG_LOG_LEVEL LogLevel
)
{
    NTSTATUS status;
    GUEST *guest = (GUEST*)Guest;

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.SetLogLevel == NULL)
    {
        ERROR("gHypervisorGlobalData.Introspection.GlueIface.SetLogLevel not initialized!\n");
    }
    else
    {
        LOG("VerbosityLevel = %d\n", LogLevel);

        status = gHypervisorGlobalData.Introspection.GlueIface.SetLogLevel(Guest, LogLevel);
        if (!SUCCESS(status))
        {
            ERROR("SetLogLevel Error with status %s!\n", NtStatusToString(status));
        }
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    // return SUCCESS as for the cases when intro is not initialized but we still want to change the CFG inside the command line, so that
    // intro will start with the right level of verbosity
    return CX_STATUS_SUCCESS;
}

NTSTATUS
NapIntGetGuestVersionString(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR* FullString,
    _Out_ CHAR* VersionString
)
{
    if (FullStringSize == 0) return CX_STATUS_INVALID_PARAMETER_1;
    if (VersionStringSize == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (FullString == NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (VersionString == NULL) return CX_STATUS_INVALID_PARAMETER_4;

    GUEST *guest = HvGetCurrentGuest();
    NTSTATUS status;

    if (!guest) return CX_STATUS_INVALID_INTERNAL_STATE;
    if (!guest->Intro.IntrospectionActivated) return CX_STATUS_NOT_INITIALIZED;

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (gHypervisorGlobalData.Introspection.GlueIface.GetVersionString == NULL)
    {
        ERROR("gHypervisorGlobalData.Introspection.GlueIface.GetVersionString not initialized!\n");
        status = CX_STATUS_NOT_INITIALIZED;
    }
    else
    {
        status = gHypervisorGlobalData.Introspection.GlueIface.GetVersionString(FullStringSize, VersionStringSize, FullString, VersionString);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("gHypervisorGlobalData.Introspection.GlueIface.GetVersionString", status);
    }

    HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}

///@}