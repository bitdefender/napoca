/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file umlibcommands.c
*   @brief Handlers for messages from user mode
*/

#include "winguest_types.h"
#include "umlibcommands.h"
#include "winguest_status.h"
#include "comm_hv.h"
#include "winguest_types.h"
#include "reg_opts.h"
#include "memory.h"
#include "umlibcomm.h"
#include "common/kernel/napoca_version.h"
#include "common/kernel/napoca_compatibility.h"
#include "updates.h"
#include "version.h"
#include "misc_utils.h"
#include "trace.h"
#include "umlibcommands.tmh"

/**
 * @brief Handler for #cmdGetHvStatus
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetHvStatus(
    _In_opt_ PCMD_GET_HV_STATUS Request,
    _In_opt_ DWORD RequestLength,
    _Out_ PCMD_GET_HV_STATUS Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_GET_HV_STATUS))
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (NULL == BytesReturned)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    UNREFERENCED_PARAMETER((Request, RequestLength));

    Reply->Started = gDrv.HypervisorStarted;
    Reply->Connected = gDrv.HvCommConnected;

    if (gDrv.HypervisorStarted)
    {
        Reply->BootMode = gDrv.HvBootMode;
    }

    *BytesReturned = sizeof(CMD_GET_HV_STATUS);

    return STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdUmCheckCompatibilityWithDrv
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdUmCheckCompatibilityWithDrv(
    _In_ PCMD_CHECK_COMPATIBILITY Request,
    _In_ DWORD RequestLength,
    _Out_ PCMD_CHECK_COMPATIBILITY Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NAPOCA_VERSION reqVer = {0};

    if (NULL == Request)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_CHECK_COMPATIBILITY))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_CHECK_COMPATIBILITY))
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (NULL == BytesReturned)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    __try
    {
        MakeVersion(&reqVer, WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS);

        status = CheckCompatibility((NAPOCA_VERSION *)&Request->Version, &reqVer);
        if (!NT_SUCCESS(status))
        {
            LogError("WINGUEST.DLL %d.%d.%d.%d is not compatible with WINGUEST.SYS which requires %d.%d.%d.%d\n",
                Request->Version.High, Request->Version.Low, Request->Version.Revision, Request->Version.Build,
                WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS_MJ, WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS_MN, WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS_REV, WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS_BLD
                );
        }

        Reply->Version.High = WINGUEST_VERSION_HIGH;
        Reply->Version.Low = WINGUEST_VERSION_LOW;
        Reply->Version.Revision = WINGUEST_VERSION_REVISION;
        Reply->Version.Build = WINGUEST_VERSION_BUILD;

        *(NAPOCA_VERSION *)&Reply->CompatVersion = reqVer;

        *BytesReturned = sizeof(CMD_CHECK_COMPATIBILITY);
    }
    __except (WINGUEST_EXCEPTION_FILTER)
    {
        status = GetExceptionCode();
        LogError("Exception 0x%08x while working with buffers\n", status);
    }

    return status;
}

/**
 * @brief Handler for #cmdCommandThreadCount
 *
 * @param[in] Request               Message Input Buffer
 * @param[in] RequestLength         Size of input message (including common header)
 * @param[in] Reply                 Buffer where reply message will be stored
 * @param[in] ReplyLength           Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdCommandThreadCount(
    _In_ PCMD_COMMAND_THREAD_COUNT Request,
    _In_ DWORD RequestLength,
    _Out_ PCMD_COMMAND_THREAD_COUNT Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    if (NULL == Request)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_COMMAND_THREAD_COUNT))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_COMMAND_THREAD_COUNT))
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (NULL == BytesReturned)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    KeAcquireGuardedMutex(&gDrv.CommandLock);
    gDrv.CommandCountLimit = (DWORD)Request->ThreadCount;
    KeReleaseGuardedMutex(&gDrv.CommandLock);

    // notify HV communication thread that we have processing threads available
    KeSetEvent(&gDrv.HvEventThreadWorkUm, IO_NO_INCREMENT, FALSE);

    *BytesReturned = sizeof(CMD_COMMAND_THREAD_COUNT);

    return STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdGetCpuSmxAndVirtFeatures
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetCpuSmxAndVirtFeatures(
    _In_opt_ PVOID Request,
    _In_opt_ DWORD RequestLength,
    _Out_ PCMD_GET_CPU_SMX_VIRT_FEATURES Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3 ;
    }
    if (ReplyLength < sizeof(CMD_GET_CPU_SMX_VIRT_FEATURES))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    UNREFERENCED_PARAMETER((Request, RequestLength));

    Reply->CpuEntry = gDrv.CpuEntry;
    Reply->VirtFeatures = gDrv.VirtualizationFeatures;
    Reply->SmxCaps.SmxCapabilities0Raw = gDrv.SmxCaps.SmxCapabilities0Raw;

    *BytesReturned = sizeof(CMD_GET_CPU_SMX_VIRT_FEATURES);

    return STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdCmdGetCrValues
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetCrValues(
    _In_opt_ PCMD_GET_CR_VALUES Request,
    _In_opt_ DWORD RequestLength,
    _Out_ PCMD_GET_CR_VALUES Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3 ;
    }
    if (ReplyLength < sizeof(CMD_GET_CR_VALUES))
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (NULL == BytesReturned)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    UNREFERENCED_PARAMETER((Request, RequestLength));

    Reply->Cr0 = (QWORD)__readcr0();
    Reply->Cr4 = (QWORD)__readcr4();

    *BytesReturned = sizeof(CMD_GET_CR_VALUES);

    return STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdComponentVersionFromHv
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  Reply                Buffer where reply message will be stored
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
_GetComponentVersionFromHv(
    _In_ PCMD_GET_COMPONENT_VERSION Request,
    _Out_ PCMD_GET_COMPONENT_VERSION Reply
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN lockAcquired = FALSE;
    PCMD_GET_COMPONENT_VERSION cmd;

    __try
    {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);

        lockAcquired = TRUE;

        status = CommAllocMessage(gDrv.SharedHvMem, cmdGetComponentVersion, 0,
            TargetNapoca, TargetWinguestKm, (DWORD)sizeof(CMD_GET_COMPONENT_VERSION), (PCOMM_MESSAGE*)&cmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        cmd->Component = Request->Component;

        status = CommSendMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)cmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        RtlCopyMemory(Reply, cmd, sizeof(CMD_GET_COMPONENT_VERSION));

        CommFreeMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)cmd);
    }
    __finally
    {
        if (lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();

            lockAcquired = FALSE;
        }
    }

    return status;
}

/**
 * @brief Handler for #cmdGetComponentVersion
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetComponentVersion(
    _In_ PCMD_GET_COMPONENT_VERSION Request,
    _In_ DWORD RequestLength,
    _Out_ PCMD_GET_COMPONENT_VERSION Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (NULL == Request)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_GET_COMPONENT_VERSION))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_GET_COMPONENT_VERSION))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    __try
    {
        switch (Request->Component)
        {
        case compWinguestSys:
        {
            Reply->VersionHigh     = WINGUEST_VERSION_HIGH;
            Reply->VersionLow      = WINGUEST_VERSION_LOW;
            Reply->VersionRevision = WINGUEST_VERSION_REVISION;
            Reply->VersionBuild    = WINGUEST_VERSION_BUILD;

            status = STATUS_SUCCESS;
            break;
        }

        case compNapoca:
        {
            Reply->VersionHigh     = gDrv.NapocaVer.High;
            Reply->VersionLow      = gDrv.NapocaVer.Low;
            Reply->VersionRevision = gDrv.NapocaVer.Revision;
            Reply->VersionBuild    = gDrv.NapocaVer.Build;

            status = STATUS_SUCCESS;
            break;
        }

        case compIntro:
        {
            // if the version was never cached
            if (gDrv.IntroVer.VersionInfo.Major == 0 &&
                gDrv.IntroVer.VersionInfo.Minor == 0 &&
                gDrv.IntroVer.VersionInfo.Revision == 0 &&
                gDrv.IntroVer.VersionInfo.Build == 0)
            {
                // ask HV
                status = _GetComponentVersionFromHv(Request, Reply);
                if (NT_SUCCESS(status))
                {
                    // cache it
                    gDrv.IntroVer.VersionInfo.Major    = (WORD)Reply->VersionHigh;
                    gDrv.IntroVer.VersionInfo.Minor    = (WORD)Reply->VersionLow;
                    gDrv.IntroVer.VersionInfo.Build    = (WORD)Reply->VersionBuild;
                    gDrv.IntroVer.VersionInfo.Revision = (WORD)Reply->VersionRevision;
                }
            }
            else
            {
                // return the cached version
                Reply->VersionHigh     = gDrv.IntroVer.VersionInfo.Major;
                Reply->VersionLow      = gDrv.IntroVer.VersionInfo.Minor;
                Reply->VersionRevision = gDrv.IntroVer.VersionInfo.Revision;
                Reply->VersionBuild    = gDrv.IntroVer.VersionInfo.Build;

                status = STATUS_SUCCESS;
            }
            break;
        }
       case compExceptions:
        {
           if (gDrv.ExceptionsVerHigh == 0 &&
               gDrv.ExceptionsVerLow == 0 &&
               gDrv.ExceptionsVerBuild == 0)
            {
                // ask HV
                status = _GetComponentVersionFromHv(Request, Reply);
                if (NT_SUCCESS(status))
                {
                    // cache it
                    gDrv.ExceptionsVerHigh  = (WORD)Reply->VersionHigh;
                    gDrv.ExceptionsVerLow   = (WORD)Reply->VersionLow;
                    gDrv.ExceptionsVerBuild = (WORD)Reply->VersionBuild;
                }
            }
           else
           {
                // the versions are already cached
               Reply->VersionHigh     = gDrv.ExceptionsVerHigh;
               Reply->VersionLow      = gDrv.ExceptionsVerLow;
               Reply->VersionRevision = 0;
               Reply->VersionBuild    = gDrv.ExceptionsVerBuild;

               status = STATUS_SUCCESS;
           }
            break;
        }
        case compIntroLiveUpdt:
        {
            // if the version was never cached
            if (gDrv.LiveSupportVerHigh == 0 &&
                gDrv.LiveSupportVerLow == 0 &&
                gDrv.LiveSupportVerBuild == 0)
            {
                // ask HV
                status = _GetComponentVersionFromHv(Request, Reply);
                if (NT_SUCCESS(status))
                {
                    // cache it
                    gDrv.LiveSupportVerHigh = Reply->VersionHigh;
                    gDrv.LiveSupportVerLow = Reply->VersionLow;
                    gDrv.LiveSupportVerBuild = Reply->VersionBuild;
                }
            }
            else
            {
                // return the cached version
                Reply->VersionHigh = gDrv.LiveSupportVerHigh;
                Reply->VersionLow = gDrv.LiveSupportVerLow;
                Reply->VersionRevision = 0;
                Reply->VersionBuild = gDrv.LiveSupportVerBuild;

                status = STATUS_SUCCESS;
            }
            break;
        }

        default:
            status = STATUS_COMPONENT_NOT_KNOWN;
        }

        *BytesReturned = sizeof(CMD_GET_COMPONENT_VERSION);
    }
    __except (WINGUEST_EXCEPTION_FILTER)
    {
        status = GetExceptionCode();
        LogError("Exception 0x%08x while working with buffers\n", status);
    }

    return status;
}

/**
 * @brief Handler for #cmdGetCompatibility
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetCompatibility(
    _In_ PCMD_GET_COMPATIBILITY Request,
    _In_ DWORD RequestLength,
    _Out_ PCMD_GET_COMPATIBILITY Reply,
    _In_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status;
    NAPOCA_VERSION reqVer = { 0 };

    if (NULL == Request)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_GET_COMPATIBILITY))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_GET_COMPATIBILITY))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    __try
    {
        if (Request->Component1 == Request->Component2)
        {
            Reply->VersionHigh     = 0;
            Reply->VersionLow      = 0;
            Reply->VersionRevision = 0;
            Reply->VersionBuild    = 0;

            status = STATUS_SUCCESS;
        }
        else if (Request->Component1 == compWinguestSys && Request->Component2 == compNapoca)
        {
            MakeVersion(&reqVer, NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS);

            Reply->VersionHigh     = reqVer.High;
            Reply->VersionLow      = reqVer.Low;
            Reply->VersionRevision = reqVer.Revision;
            Reply->VersionBuild    = reqVer.Build;

            status = gDrv.HypervisorIncompatible ? STATUS_VERSION_INCOMPATIBLE : STATUS_SUCCESS;
        }
        else if (Request->Component1 == compNapoca && Request->Component2 == compWinguestSys)
        {
            Reply->VersionHigh     = gDrv.WinguestSysRequiredByHv.High;
            Reply->VersionLow      = gDrv.WinguestSysRequiredByHv.Low;
            Reply->VersionRevision = gDrv.WinguestSysRequiredByHv.Revision;
            Reply->VersionBuild    = gDrv.WinguestSysRequiredByHv.Build;

            status = gDrv.HypervisorIncompatible ? STATUS_VERSION_INCOMPATIBLE : STATUS_SUCCESS;
        }
        else if (Request->Component1 == compWinguestSys && Request->Component2 == compWinguestDll)
        {
            MakeVersion(&reqVer, WINGUESTDLL_VERSION_REQUIRED_BY_WINGUESTSYS);

            Reply->VersionHigh     = reqVer.High;
            Reply->VersionLow      = reqVer.Low;
            Reply->VersionRevision = reqVer.Revision;
            Reply->VersionBuild    = reqVer.Build;

            status = STATUS_SUCCESS; // if we received the message, we are compatible :)
        }
        else
        {
            Reply->VersionHigh     = 0;
            Reply->VersionLow      = 0;
            Reply->VersionRevision = 0;
            Reply->VersionBuild    = 0;

            status = STATUS_COMPONENT_NOT_KNOWN;
        }

        *BytesReturned = sizeof(CMD_GET_COMPATIBILITY);
    }
    __except (WINGUEST_EXCEPTION_FILTER)
    {
        status = GetExceptionCode();
        LogError("Exception 0x%08x while working with buffers\n", status);
    }

    return status;
}
//--------
NTSTATUS
GetSetIntroFlags(
    _Inout_ QWORD *Flags,
    _In_ BOOLEAN Write
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_INTRO_FLAGS *cmdFlags = NULL;
    BOOLEAN lockAcquired = FALSE;

    __try
    {
        if (gDrv.HvCommConnected == FALSE)
        {
            status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            __leave;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        status = CommAllocMessage(gDrv.SharedHvMem, cmdIntroFlags, 0,
            TargetNapoca, TargetWinguestKm, sizeof(CMD_INTRO_FLAGS), (PCOMM_MESSAGE*)&cmdFlags);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        cmdFlags->Flags = *Flags;
        cmdFlags->Write = Write;

        status = CommSendMessage(gDrv.SharedHvMem, &cmdFlags->Command);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        status = cmdFlags->Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        if (!Write) *Flags = cmdFlags->Flags;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (NULL != cmdFlags)
        {
            CommFreeMessage(gDrv.SharedHvMem, &cmdFlags->Command);
        }

        if (TRUE == lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }
    }

    return status;
}

/**
 * @brief Handler for #cmdUpdateComponent
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdUpdateComponent(
    _In_ PCMD_UPDATE_COMPONENT Request,
    _In_ DWORD RequestLength,
    _Out_opt_ PCMD_UPDATE_COMPONENT Reply,
    _In_opt_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING filePath = { 0 };
    DECLARE_CONST_UNICODE_STRING(prefix, L"\\??\\");
    UNICODE_STRING umFilePath;
    NAPOCA_VERSION newVersion = { 0 };

    UNREFERENCED_PARAMETER(Reply);

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_UPDATE_COMPONENT))
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    __try
    {
        __try
        {
            if (Request->PathSize != 0)
            {
                umFilePath.Buffer = (PWCH)(Request->Buffer);
                umFilePath.Length = umFilePath.MaximumLength = (USHORT)Request->PathSize;

                status = CreateUnicodeString(&filePath, UNICODE_LEN(prefix) + UNICODE_LEN(umFilePath));
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "CreateUnicodeString");
                    __leave;
                }

                status = RtlUnicodeStringCopy(&filePath, &prefix);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "RtlUnicodeStringCopy");
                    __leave;
                }

                status = RtlUnicodeStringCat(&filePath, &umFilePath);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "RtlUnicodeStringCat");
                    __leave;
                }
            }

            switch (Request->Component)
            {
            case compIntro:
            {
                QWORD currentFlags = 0;
                SIZE_T enabled;
                PINTRO_CONTROL_MODULE_DATA icmd = (PINTRO_CONTROL_MODULE_DATA)(Request->Buffer + Request->PathSize);

                status = HvVmcallSafe(OPT_GET_MEMORY_INTRO_STATUS,
                    0, 0, 0, 0,
                    &enabled, NULL, NULL, NULL);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "HvVmcallSafe");
                    __leave;
                }

                if (enabled)
                {
                    // get the current flags to be able to decide the following
                    status = GetSetIntroFlags(&currentFlags, FALSE);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "GetSetIntroFlags");
                        __leave;
                    }
                }

                // If a module from disk is given or state change is requested or update a non-dynamic flag is updated
                // proceeeding with full reinit of the introspection
                if (Request->PathSize ||
                    ((icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_STATE) && (enabled != icmd->ControlData.Enable)) ||
                    (enabled && (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_OPTIONS) && ((icmd->ControlData.Options ^ (DWORD)currentFlags) & ~INTRO_OPT_DYNAMIC_OPTIONS_MASK))
                )
                {
                    if (!(icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_STATE))
                    {
                        icmd->ControlData.Enable = !!enabled;
                        icmd->ControlFieldsToApply |= FLAG_INTRO_CONTROL_STATE;
                    }

                    status = UpdateModule(Request->PathSize ? &filePath : NULL, LD_MODID_INTRO_CORE, Request->Buffer + Request->PathSize, Request->DataSize, &newVersion);
                    if (!NT_SUCCESS(status))
                    {
                        if (status == STATUS_NOT_SUPPORTED)
                        {
                            // convert the error the an explicit one
                            status = STATUS_INTROSPECTION_OPERATION_NOT_SUPPORTED;
                        }

                        LogFuncErrorStatus(status, "UpdateModule");
                        __leave;
                    }

                    gDrv.IntroVer.VersionInfo.Major = (WORD)newVersion.High;
                    gDrv.IntroVer.VersionInfo.Minor = (WORD)newVersion.Low;
                    gDrv.IntroVer.VersionInfo.Revision = (WORD)newVersion.Revision;
                    gDrv.IntroVer.VersionInfo.Build = (WORD)newVersion.Build;

                    // reset the loaded exception version (we no longer have any exceptions loaded)
                    gDrv.ExceptionsVerHigh = 0;
                    gDrv.ExceptionsVerLow = 0;
                    gDrv.ExceptionsVerBuild = 0;

                    // reset the loaded live update support version (version must be asked once more after a new update)
                    gDrv.LiveSupportVerHigh = 0;
                    gDrv.LiveSupportVerLow = 0;
                    gDrv.LiveSupportVerBuild = 0;

                    status = STATUS_INTROSPECTION_ENGINE_RESTARTED;
                }
                // Else update only the requested part
                else
                {
                    if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_VERBOSITY) //If we requested to update only the verbosity
                    {
                        status = HvVmcallSafe(OPT_SET_INTRO_VERBOSITY,
                            icmd->ControlData.Verbosity, 0, 0, 0,
                            NULL, NULL, NULL, NULL);
                        if (!NT_SUCCESS(status))
                        {
                            LogFuncErrorStatus(status, "HvVmcallSafe");
                            __leave;
                        }
                    }

                    if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_OPTIONS)
                    {
                        status = GetSetIntroFlags(&icmd->ControlData.Options, TRUE);
                        if (!NT_SUCCESS(status))
                        {
                            LogFuncErrorStatus(status, "GetSetIntroFlags");
                            __leave;
                        }
                    }
                }

                break;
            }

            case compExceptions:
            {
                status = UpdateModule(&filePath, LD_MODID_INTRO_EXCEPTIONS, NULL, 0, &newVersion);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "UpdateModule");
                    __leave;
                }

                gDrv.ExceptionsVerHigh = (WORD)newVersion.High;
                gDrv.ExceptionsVerLow = (WORD)newVersion.Low;
                gDrv.ExceptionsVerBuild = newVersion.Build;

                break;
            }

            case compIntroLiveUpdt:
            {
                status = UpdateModule(&filePath, LD_MODID_INTRO_LIVE_UPDATE, NULL, 0, &newVersion);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "UpdateModule");
                    __leave;
                }

                gDrv.LiveSupportVerHigh = newVersion.High;
                gDrv.LiveSupportVerLow = newVersion.Low;
                gDrv.LiveSupportVerBuild = newVersion.Build;

                break;
            }

            default:
                status = STATUS_COMPONENT_NOT_KNOWN;
                __leave;
            }
        }
        __finally
        {
            *BytesReturned = ReplyLength;

            if (Request->PathSize != 0)
            {
                FreeUnicodeString(&filePath);
            }
        }
    }
    __except (WINGUEST_EXCEPTION_FILTER)
    {
        status = GetExceptionCode();
        LogError("Exception 0x%08x while working with buffers\n", status);
    }

    return status;
}

/**
 * @brief Handler for #cmdQueryComponent
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdQueryComponent(
    _In_ PCMD_QUERY_COMPONENT Request,
    _In_ DWORD RequestLength,
    _Out_opt_ PCMD_QUERY_COMPONENT Reply,
    _In_opt_ DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_QUERY_COMPONENT))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (Reply == NULL)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_QUERY_COMPONENT))
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (BytesReturned == NULL)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    __try
    {
        __try
        {
            switch (Request->Component)
            {
            case compIntro:
            {
                SIZE_T enabled;
                PINTRO_QUERY_MODULE_DATA iqmd = (PINTRO_QUERY_MODULE_DATA)(Reply->Buffer);

                status = HvVmcallSafe(OPT_GET_MEMORY_INTRO_STATUS,
                    0, 0, 0, 0,
                    &enabled, NULL, NULL, NULL);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "HvVmcallSafe - OPT_GET_MEMORY_INTRO_STATUS");
                    __leave;
                }

                iqmd->Enabled = !!enabled;

                if (enabled)
                {
                    status = GetSetIntroFlags(&iqmd->Options, FALSE);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "GetSetIntroFlags");
                        __leave;
                    }
                }
                else
                {
                    iqmd->Options = 0;
                }

                break;
            }

            default:
                status = STATUS_COMPONENT_NOT_KNOWN;
                __leave;
            }

            status = STATUS_SUCCESS;
        }
        __finally
        {
            *BytesReturned = ReplyLength;
        }
    }
    __except (WINGUEST_EXCEPTION_FILTER)
    {
        status = GetExceptionCode();
        LogError("Exception 0x%08x while working with buffers\n", status);
    }

    return status;
}

/**
 * @brief Validate the UEFI loader log buffer
 *
 * @param[in]  Address              Physical address of UEFIloader memory log
 * @param[in]  Size                 Size of log buffer
 * @param[out] Valid                TRUE: Log Address ans Size passed checks. FALSE: Address or Size of log are invalid
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
ValidateUefiLogAddress(
    _In_ QWORD Address,
    _In_ DWORD Size,
    _Out_ PBOOLEAN Valid
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    MEM_MAP_ENTRY phyMemMap[BOOT_MAX_PHY_MEM_COUNT];
    WORD phyMemCount = 0;
    DWORD i = 0;

    if (0 == Address)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (0 == Size)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Valid)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Valid = FALSE;

    __try
    {
        LogInfo("Reading system physical memory data from registry...\n");
        status = ParseRegistryMemoryMap(REG_KEY_LOADER_RESERVED_PHYSICAL_MEMORY_MAP, REG_VALUE_LOADER_RESERVED_MEMORY_MAP, BOOT_MEM_TYPE_DISABLED, NULL, phyMemMap, &phyMemCount);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ParseRegistryMemoryMap");
            __leave;
        }

        // check that the buffer is located in firmware reserved memory
        for (i = 0; i < phyMemCount; i++)
        {
            if (Address >= phyMemMap[i].StartAddress
                && Address + Size <= phyMemMap[i].StartAddress + phyMemMap[i].Length)
            {
                *Valid = TRUE;
                break;
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Handler for #cmdCmdGetLogs
 *
 * @param[in]  Request              Message Input Buffer
 * @param[in]  RequestLength        Size of input message (including common header)
 * @param[in]  Reply                Buffer where reply message will be stored
 * @param[in]  ReplyLength          Size of reply message buffer (including common header)
 * @param[Out] BytesReturned        Actual number of bytes written in Reply
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UmCmdGetLogs(
    _In_  PCMD_GET_LOGS Request,
    _In_  DWORD RequestLength,
    _Out_ PCMD_GET_LOGS Reply,
    _In_  DWORD ReplyLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HV_FEEDBACK_HEADER *feedbackHead = NULL;
    PHYSICAL_ADDRESS pa = {0};

    if (NULL == Request)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RequestLength < sizeof(CMD_GET_LOGS))
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Reply)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (ReplyLength < sizeof(CMD_GET_LOGS))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    __try
    {
        switch (Request->Type)
        {
            case logUefiLoader:
            {
                BOOLEAN valid = FALSE;

                if (Request->PhysicalAddress == 0 && Request->PhysicalSize == 0)
                {
                    LogError("Invalid log request!");
                    status = STATUS_REQUEST_NOT_ACCEPTED;
                    __leave;
                }

                // check to see that the buffer is in reserved memory
                status = ValidateUefiLogAddress(Request->PhysicalAddress, Request->PhysicalSize, &valid);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "ValidateUefiLogAddress");
                    __leave;
                }
                if (!valid)
                {
                    LogError("Something supplied an uefi log address that doesn't seem to be in uefi memory space!");
                    __leave;
                }

                __try
                {
                    status = STATUS_UNSUCCESSFUL;

                    pa.QuadPart = Request->PhysicalAddress;

                    feedbackHead = MmMapIoSpace(pa, Request->PhysicalSize, MmCached);
                    if (feedbackHead == NULL)
                    {
                        status = STATUS_LOG_SPACE_RESERVED_INVALID;
                        __leave;
                    }

                    // check to see if data appears valid
                    if (Request->PhysicalSize != feedbackHead->Logger.BufferSize + sizeof(HV_FEEDBACK_HEADER)
                        || feedbackHead->Logger.BufferSize != feedbackHead->Logger.BufferWritePos)
                    {
                        status = STATUS_LOG_METADATA_INVALID;
                        MmUnmapIoSpace(feedbackHead, Request->PhysicalSize);
                        feedbackHead = NULL; // data appears to be corrupted
                        __leave;
                    }
                }
                __except (WINGUEST_EXCEPTION_FILTER) // doesn't seem to be too useful :/
                {
                    if (feedbackHead != NULL)
                    {
                        status = STATUS_LOG_SECTOR_INVALID;
                        MmUnmapIoSpace(feedbackHead, Request->PhysicalSize);
                        feedbackHead = NULL;
                    }
                }

                if (!feedbackHead)
                {
                    __leave;
                }

                // we have logs available. can answer here
                if (0 == Request->Size)
                {
                    // size was requested
                    status = GetLogInfo(&feedbackHead->Logger, &Request->Offset, &Request->Size);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "GetLogInfo");
                        __leave;
                    }
                }
                else
                {
                    // log data was requested
                    status = GetLogChunk(&feedbackHead->Logger, Request->Offset, Request->Size, Request->Buffer);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "GetLogChunk");
                        __leave;
                    }
                }

                break;
            }

            case logHypervisor:
            {
                BOOLEAN lockAcquired = FALSE;
                PCMD_GET_LOGS hvcmd = NULL;

                if (!HVStarted())
                {
                    status = STATUS_HYPERVISOR_NOT_STARTED;
                    __leave;
                }

                __try
                {
                    if (gDrv.HvCommConnected == FALSE)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        __leave;
                    }

                    KeEnterCriticalRegion();
                    ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
                    lockAcquired = TRUE;

                    status = CommAllocMessage(gDrv.SharedHvMem, cmdGetLogsHv, 0,
                        TargetNapoca, TargetWinguestKm, (DWORD)sizeof(CMD_GET_LOGS) + sizeof(MEMORY_LOG) + Request->Size, (PCOMM_MESSAGE*)&hvcmd);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "CommAllocMessage");
                        __leave;
                    }

                    hvcmd->Type = Request->Type;
                    hvcmd->Offset = Request->Offset;
                    hvcmd->Size = Request->Size;

                    status = CommSendMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)hvcmd);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "CommSendMessage");
                        __leave;
                    }

                    status = hvcmd->Command.ProcessingStatus;
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "cmdGetLogsHv");
                        __leave;
                    }

                    if (Request->Size)
                    {
                        RtlCopyMemory(Request->Buffer, hvcmd->Buffer, hvcmd->Size);
                    }

                    Reply->Size = hvcmd->Size;
                    Reply->Offset = hvcmd->Offset;
                }
                __finally
                {
                    if (NULL != hvcmd)
                    {
                        CommFreeMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)hvcmd);
                    }

                    if (TRUE == lockAcquired)
                    {
                        ExReleaseResourceLite(&gDrv.HvCommLock);
                        KeLeaveCriticalRegion();
                    }
                }

                break;
            }

            default:
                status = STATUS_NOT_FOUND;

        }

        *BytesReturned = ReplyLength;
    }
    __finally
    {
        if (Request->Type == logUefiPreloader && feedbackHead != NULL)
        {
            MmUnmapIoSpace(feedbackHead, Request->PhysicalSize);
        }
    }

    return status;
}
