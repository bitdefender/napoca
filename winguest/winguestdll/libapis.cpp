/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file ccom_mgr.cpp
*   @brief Main library APIs exposed to integrators
*/

/// @defgroup integration Integration APIs - user mode interface to hypervisor configuration and management
///@{
#include <thread>
#include <shared_mutex>
#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "json.hpp"

#include "kerncomm.h"
#include "libapis.h"
#include "libapis_int.h"
#include "libapis_private.h"
#include "consts.h"
#include "winguestdll.h"
#include "winguest_status.h"
#include "version.h"
#include "feedback.h"
#include "helpers.h"
#include "deploy_validation.h"
#include "reg_opts.h"
#include "load_monitor.h"
#include "common/kernel/napoca_compatibility.h"
#include "common/communication/commands.h"
#include "intro_types.h"
#include "event_timer.h"
#include "deploy.h"
#include "deploy_uefi.h"
#include "deploy_legacy.h"
#include "common/debug/memlog.h"
#include "cxqueuetypes.h"
#include "trace.h"
#include "libapis.tmh"
#include "kerncomm_int.h"

using json = nlohmann::json;

#define UEFI_PRELOADER_LOG      L"BdHvPreloaderLog"
#define UEFI_LOADER_LOG_PHYS    L"BdHvLog"

extern BOOLEAN gInitialized;
extern BOOLEAN gConnected;
extern BOOLEAN gDriverIncompatible;
extern BOOLEAN gHypervisorStarted;
extern BOOLEAN gHypervisorConnected;
extern BOOT_MODE gHypervisorBootMode;
extern FEEDBACK_OPTIONS gFeedbackCfg;
extern bool volatile gCloudUploadConfigured;
extern EVENT_TIMER gWinguestTimer;
KNOWN_VERSIONS gVersions;
extern std::wstring gFeedbackFolder;

UM_CALLBACKS gCallbacks;
UM_CONTEXTS gContexts;
std::mutex gCallbacksMutex;

DWORD gHvLogOffset = MEMLOG_NO_OFFSET;

extern BOOLEAN  gHypervisorConfigured;
extern std::wstring gSdkDirs[];

CPU_ENTRY gCpu = { 0 };
SMX_CAPABILITIES gSmxCap = { 0 };
VIRTUALIZATION_FEATURES gVirtFeat = { 0 };
QWORD   gHostCr0 = 0;
QWORD   gHostCr4 = 0;

//
// HELPERS
//

/**
 * @brief Get various logs
 *
 * @param[in]     Type                  Which log is requested
 * @param[out]    FeedbackBuffer        Buffer to store the log
 * @param[out]    LogSize               Log size
 * @param[in,out] OffsetFrom            Offset from where to read new information in existing logs
 * @param[in]     PhysicalAddress       Physical address of log
 * @param[in]     PhysicalSize          Size of PhysicalAddress log
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
WinguestGetLogs(
    _In_        LOG_TYPE Type,
    _Out_       std::unique_ptr<CHAR[]> &FeedbackBuffer,
    _Out_       DWORD &LogSize,
    _Inout_opt_ PDWORD OffsetFrom,
    _In_opt_    QWORD PhysicalAddress,
    _In_opt_    DWORD PhysicalSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD bytesReturned = 0;

    std::unique_ptr<CHAR[]> hvFeedbackBuffer;
    DWORD hvFeedbackBufferSize = 0;
    DWORD currentOffset = 0;
    DWORD recorded = 0;

    if ((PhysicalAddress == 0) != (PhysicalSize == 0))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE);
    CMD_GET_LOGS* pCmd = reinterpret_cast<CMD_GET_LOGS*>(cmdBuf.get());

    memset(pCmd, 0, sizeof(*pCmd));

    pCmd->Type = Type;

    // first of all get the log size
    pCmd->Size = 0;

    if (OffsetFrom)
    {
        pCmd->Offset = *OffsetFrom;
    }
    else
    {
        pCmd->Offset = MEMLOG_NO_OFFSET;
    }

    if (PhysicalAddress)
    {
        pCmd->PhysicalAddress = PhysicalAddress;
        pCmd->PhysicalSize = PhysicalSize;
    }

    status = KernCommSendMessage(
        cmdGetLogs,
        TargetWinguestKm,
        pCmd,
        CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE,
        pCmd,
        CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE,
        &bytesReturned
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = pCmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdGetLogs");
        return status;
    }

    hvFeedbackBufferSize = pCmd->Size;

    if (0 == hvFeedbackBufferSize)
    {
        status = STATUS_SUCCESS;
        return status;
    }

    hvFeedbackBuffer = std::make_unique<CHAR[]>(hvFeedbackBufferSize);

    memset(hvFeedbackBuffer.get(), 0, hvFeedbackBufferSize);

    currentOffset = pCmd->Offset;

    while (recorded < hvFeedbackBufferSize)
    {
        pCmd->Command.CommandCode = cmdGetLogs;
        pCmd->Type = Type;
        pCmd->Offset = currentOffset;
        pCmd->Size = min(hvFeedbackBufferSize - recorded, CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE - sizeof(CMD_GET_LOGS));

        status = KernCommSendMessage(
            cmdGetLogs,
            TargetWinguestKm,
            pCmd,
            CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE,
            pCmd,
            CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE,
            &bytesReturned
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
            break;
        }

        status = pCmd->Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdGetLogs");
            return status;
        }

        memcpy(&hvFeedbackBuffer[recorded], pCmd->Buffer, pCmd->Size);
        recorded += pCmd->Size;

        currentOffset += pCmd->Size;
    }

    LogSize = hvFeedbackBufferSize;
    FeedbackBuffer.swap(hvFeedbackBuffer);
    if (OffsetFrom)
    {
        *OffsetFrom = currentOffset;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Check if new Napoca log available and print it
 *
 * This is a Event Timer Event thread
 */
static
NTSTATUS
CheckAppendHvLog(
    void
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::unique_ptr<CHAR[]> hvLog;
    DWORD logSize = 0;
    PCHAR lineStart = NULL;
    std::string line;
    PCHAR pos = NULL;
    const DWORD maxLineSize = 4 * ONE_KILOBYTE;

    if (!gHypervisorConnected)
    {
        gHvLogOffset = MEMLOG_NO_OFFSET; // make sure position is reset
        return STATUS_SUCCESS;
    }

    status = WinguestGetLogs(logHypervisor, hvLog, logSize, &gHvLogOffset, 0, 0);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetLogs");
        goto cleanup;
    }

    if (NULL != hvLog && logSize > 0)
    {
        for (pos = lineStart = hvLog.get(); pos < &hvLog[logSize]; pos++)
        {
            if (*pos != '\n' && *pos != '\0' && (DWORD)(pos - lineStart) < maxLineSize - 1)
            {
                continue;
            }

            if (pos > lineStart)
            {
                line = std::string(lineStart, pos - lineStart);

                LogHv("%s", line.c_str());
            }

            lineStart = pos + 1;
        }

        if (&hvLog[logSize] > lineStart)
        {
            line = std::string(lineStart, &hvLog[logSize] - lineStart);

            LogHv("%s", line.c_str());
        }
    }

cleanup:
    return status;
}

/**
 * @brief Get Uefi Loader log
 *
 * @param[out] PreloaderLog         Loader log
 * @param[out] PreLogSize           Loader log size
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
GetUefiLoaderLogFromPhysMem(                // Preferred; Attempt to get from physical memory
    __out std::unique_ptr<CHAR[]> &LoaderLog,
    __out DWORD &LogSize
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    QWORD varData[2] = { 0 };
    DWORD ret = 0;

    ret = GetFirmwareEnvironmentVariable(UEFI_LOADER_LOG_PHYS, NAPOCAHV_UEFI_GUID, &varData, sizeof(varData));
    if (0 == ret)
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "GetFirmwareEnvironmentVariable");
        return WIN32_TO_NTSTATUS(lastErr);
    }

    status = WinguestGetLogs(logUefiLoader, LoaderLog, LogSize, NULL, varData[0], (DWORD)varData[1]);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetLogs");
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Get Uefi Preloader log
 *
 * @param[out] PreloaderLog         Preloader log
 * @param[out] PreLogSize           Preloader log size
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
GetUefiPreloaderLog(
    __out std::unique_ptr<CHAR[]> &PreloaderLog,
    __out DWORD &PreLogSize
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    DWORD lastErr = ERROR_SUCCESS;
    std::unique_ptr<CHAR[]> preLog;
    DWORD ret = 0;

    for (BYTE i = 1; i <= 5; i++)
    {
        preLog = std::make_unique<CHAR[]>(i * ONE_MEGABYTE);

        ret = GetFirmwareEnvironmentVariable(UEFI_PRELOADER_LOG, NAPOCAHV_UEFI_GUID, preLog.get(), i * ONE_MEGABYTE);
        if (0 == ret)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
            {
                LogFuncErrorLastErr(lastErr, "GetFirmwareEnvironmentVariable");
                return status;
            }

            continue;
        }

        PreLogSize = ret;
        PreloaderLog.swap(preLog);
        return STATUS_SUCCESS;
    }

    return status;
}

/**
 * @brief Get Napoca Hypervisor status
 *
 * @param[out] Started      If Napoca is started
 * @param[out] Connected    If Napoca is connected
 * @param[out] BootMode     Boot mode of Napoca
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
WinguestGetHvStatusInternal(
    _Out_opt_ BOOLEAN* Started,
    _Out_opt_ BOOLEAN* Connected,
    _Out_opt_ BOOT_MODE* BootMode
)
{
    NTSTATUS status;
    CMD_GET_HV_STATUS getStatus;
    DWORD bytesReturned = 0;

    if (Started == NULL && BootMode == NULL)
    {
        return STATUS_SUCCESS;
    }

    if (Started != NULL) *Started = FALSE;
    if (BootMode != NULL) *BootMode = bootUnknown;

    getStatus.Command.CommandCode = cmdGetHvStatus;
    getStatus.Started = FALSE;
    getStatus.BootMode = bootUnknown;

    status = KernCommSendMessage(
        cmdGetHvStatus,
        TargetWinguestKm,
        &getStatus,
        sizeof(getStatus),
        &getStatus,
        sizeof(getStatus),
        &bytesReturned
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = getStatus.Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdGetHvStatus");
        return status;
    }

    if (Started != NULL) *Started = getStatus.Started;
    if (Connected != NULL) *Connected = getStatus.Connected;
    if (BootMode != NULL) *BootMode = getStatus.BootMode;

    return status;
}

/**
 * @brief Request a component version from the driver
 *
 * @param[in]  Component                Component identifier
 * @param[out] VersionHigh              High version
 * @param[out] VersionLow               Low version
 * @param[out] VersionRevision          Revision
 * @param[out] VersionBuild             Build number
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
RequestComponentVersionFromDriver(
    _In_ BIN_COMPONENT Component,
    _Out_opt_ PDWORD VersionHigh,
    _Out_opt_ PDWORD VersionLow,
    _Out_opt_ PDWORD VersionRevision,
    _Out_opt_ PDWORD VersionBuild
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_GET_COMPONENT_VERSION cmd = { 0 };
    DWORD bytesReturned = 0;

    cmd.Component = Component;

    status = KernCommSendMessage(
        cmdGetComponentVersion,
        TargetWinguestKm,
        &cmd,
        sizeof(cmd),
        &cmd,
        sizeof(cmd),
        &bytesReturned
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd.Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdGetComponentVersion");
        return status;
    }

    if (VersionHigh)     *VersionHigh = cmd.VersionHigh;
    if (VersionLow)      *VersionLow = cmd.VersionLow;
    if (VersionRevision) *VersionRevision = cmd.VersionRevision;
    if (VersionBuild)    *VersionBuild = cmd.VersionBuild;

    return status;
}

//
// WINGUEST targeted APIs
//

WINGUEST_DLL_API
NTSTATUS
WinguestConnectToDriver(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    DWORD interval = 0;
    DWORD dwordSize = sizeof(DWORD);

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    if (gConnected)
    {
        return STATUS_SUCCESS;
    }

    LogInfo("Connecting to the driver");

    // initialize kernel communication
    status = KernCommInit();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommInit");
        goto cleanup;
    }

    status = WinguestGetHvStatusInternal(&gHypervisorStarted, &gHypervisorConnected, &gHypervisorBootMode);
    if (!NT_SUCCESS(status))
    {
        gHypervisorStarted = FALSE;
        gHypervisorConnected = FALSE;
        LogFuncErrorStatus(status, "WinguestGetHvStatusInternal");
    }

    status = GetHostCpuAndVirtFeatures(&gCpu, &gVirtFeat, &gSmxCap);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetHostCpuAndVirtFeatures");
        goto cleanup;
    }

    status = GetHostCpuCrValues(&gHostCr0, &gHostCr4);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetHostCpuCrValues");
        goto cleanup;
    }

    status = CheckLoadMonitor();
    if (!NT_SUCCESS(status))
    {
        if (status != STATUS_NOT_PROPERLY_CONFIGURED)
        {
            LogFuncErrorStatus(status, "CheckLoadMonitor");
        }
        status = STATUS_SUCCESS;
    }

    status = RegisterEvent(
        &gWinguestTimer,
        "hvlog",
        10,
        CheckAppendHvLog
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "RegisterEvent");
        status = STATUS_SUCCESS;
    }

    // Try to read Hv configuration check interval from registry
    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_HV_CONFIG_CHECK_INTERVAL,
        RRF_RT_REG_DWORD,
        NULL,
        &interval,
        &dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        interval = EVENT_TIMER_DEFAULT_HV_CONFIGURATION_CHECK_INTERVAL;
        error = RegSetKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_HV_CONFIG_CHECK_INTERVAL,
            REG_DWORD,
            &interval,
            dwordSize
        );
    }

    // setup hv configuration validator
    status = RegisterEvent(
        &gWinguestTimer,
        "hv_config_checker",
        interval,
        CheckCurrentHvConfigurationTimerCallback
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "RegisterEvent");
        status = STATUS_SUCCESS;
    }

    RequestComponentVersionFromDriver(
        compNapoca,
        (DWORD*)&gVersions.Napoca.High,
        (DWORD*)&gVersions.Napoca.Low,
        (DWORD*)&gVersions.Napoca.Revision,
        (DWORD*)&gVersions.Napoca.Build
        );

    RequestComponentVersionFromDriver(
        compIntro,
        (DWORD*)&gVersions.Intro.High,
        (DWORD*)&gVersions.Intro.Low,
        (DWORD*)&gVersions.Intro.Revision,
        (DWORD*)&gVersions.Intro.Build
        );

    RequestComponentVersionFromDriver(
        compIntroLiveUpdt,
        &gVersions.LiveSupportHigh,
        &gVersions.LiveSupportLow,
        NULL,
        &gVersions.LiveSupportBuild
        );

    RequestComponentVersionFromDriver(
        compExceptions,
        &gVersions.ExceptionsHigh,
        &gVersions.ExceptionsLow,
        NULL,
        &gVersions.ExceptionsBuild
        );

    status = STATUS_SUCCESS;

cleanup:
    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestDisconnectFromDriver(
    void
    )
{
    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    LogInfo("Disconnecting from the driver");

    UnregisterEvent(&gWinguestTimer, "hvlog");

    KernCommUninit();

    gVersions.WinguestSys= { 0 };
    gVersions.WinguestDllRequiredByWinguestSys = { 0 };
    gHypervisorStarted = FALSE;
    gHypervisorConnected = FALSE;

    RtlSecureZeroMemory(&gCpu, sizeof(gCpu));
    RtlSecureZeroMemory(&gVirtFeat, sizeof(gVirtFeat));
    RtlSecureZeroMemory(&gSmxCap, sizeof(gSmxCap));

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestRegisterCallback(
    __in WINGUEST_CALLBACK_ID CallbackId,
    __in WINGUEST_CALLBACK Callback,
    __in PVOID Context
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    LogInfo("Registering callback of type %d with address %p and context %p\n", CallbackId, Callback.IncompatCallback, Context);

    std::lock_guard<std::mutex> guard(gCallbacksMutex);

    switch (CallbackId)
    {
    case wgCallbackIntroError:
        gCallbacks.IntrospectionErrorCallback = Callback.IntrospectionErrorCallback;
        gContexts.IntrospectionErrorCallbackContext = Context;
        break;

    case wgCallbackIntroAlert:
        gCallbacks.IntrospectionAlertCallback = Callback.IntrospectionAlertCallback;
        gContexts.IntrospectionAlertCallbackContext = Context;
        break;

    case wgCallbackIncompatibleHvConfig:
        gCallbacks.IncompatibleHvConfigurationCallback = Callback.IncompatCallback;
        gContexts.IncompatibleHvConfigurationContext = Context;
        break;

    case wgCallbackResumeComplete:
        gCallbacks.VolatileSettingsRequestCallback = Callback.VolatileSettingsRequestCallback;
        gContexts.VolatileSettingsRequestContex = Context;
        break;

    default:
        status = STATUS_INVALID_WG_CALLBACK_ID;
        break;
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetDriverMessageThreadCount(
    _In_ DWORD Count
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_COMMAND_THREAD_COUNT threadCountCmd = { 0 };
    DWORD bytesReturned = 0;

    LogVerbose("Setting Driver Communication Thread Count: %d", Count);

    __try
    {
        threadCountCmd.ThreadCount = Count;

        status = KernCommSendMessage(
            cmdCommandThreadCount,
            TargetWinguestKm,
            &threadCountCmd,
            sizeof(threadCountCmd),
            &threadCountCmd,
            sizeof(threadCountCmd),
            &bytesReturned
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
            __leave;
        }

        status = threadCountCmd.Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdCommandThreadCount");
            __leave;
        }

        if (bytesReturned < sizeof(threadCountCmd))
        {
            LogError("Invalid size returned for reply buffer. bytesReturned = %d, should have been %d\n", bytesReturned, sizeof(threadCountCmd));
            status = STATUS_INVALID_BUFFER_SIZE;
            __leave;
        }
    }
    __finally
    {
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestConfigureLoadMonitor(
    _In_opt_ DWORD *AllowedCount,
    _In_ BOOLEAN ResetFailCount
)
{
    NTSTATUS status = STATUS_SUCCESS;

    LogVerbose("Configuring Load Monitor. Reset: %d, Allowed: %s", ResetFailCount, AllowedCount ? std::to_string(*AllowedCount).c_str() : "null");

    status = UpdateLoadMonitorData(ResetFailCount ? reset : noAction, AllowedCount);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "UpdateLoadMonitorData");
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestReadLoadMonitor(
    _In_opt_ DWORD *AllowedCount,
    _In_opt_ DWORD *FailCount
)
{
    NTSTATUS status = STATUS_SUCCESS;

    LogInfo("Requesting Load Monitor Data");

    __try
    {
        status = GetLoadMonitorData(AllowedCount, FailCount, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetLoadMonitorData");
            __leave;
        }
    }
    __finally
    {
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestFastOpt(
    _In_ DWORD Opt,
    _In_opt_ COMM_COMPONENT Destination,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_opt_ QWORD *OutParam1,
    _Out_opt_ QWORD *OutParam2,
    _Out_opt_ QWORD *OutParam3,
    _Out_opt_ QWORD *OutParam4
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_FAST_OPTION fastOpt = { 0 };
    DWORD bytesReturned = 0;

    LogVerbose("FastOpt 0x%08X\n", Opt);

    __try
    {
        fastOpt.MsgId = Opt;
        fastOpt.Param1 = Param1;
        fastOpt.Param2 = Param2;
        fastOpt.Param3 = Param3;
        fastOpt.Param4 = Param4;

        // send the message to winguest
        status = KernCommSendMessage(
            cmdFastOpt,
            MESSAGE_TO_TARGET(Opt) == TargetAny ? Destination : MESSAGE_TO_TARGET(Opt),
            &fastOpt,
            sizeof(fastOpt),
            &fastOpt,
            sizeof(fastOpt),
            &bytesReturned
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
            __leave;
        }

        status = fastOpt.Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogError("WinguestSetOpt (0x%x) failed, status from driver 0x%08x\n", Opt, status);
            __leave;
        }

        if (bytesReturned < sizeof(fastOpt))
        {
            LogError("Invalid size returned for reply buffer of opt 0x%x. bytesReturned = %d, should have been %d\n", Opt, bytesReturned, sizeof(fastOpt));
            status = STATUS_INVALID_BUFFER_SIZE;
            __leave;
        }

        if (OutParam1) *OutParam1 = fastOpt.OutParam1;
        if (OutParam2) *OutParam2 = fastOpt.OutParam2;
        if (OutParam3) *OutParam3 = fastOpt.OutParam3;
        if (OutParam4) *OutParam4 = fastOpt.OutParam4;
    }
    __finally
    {
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestGetHvStatus(
    _Out_opt_ BOOLEAN *Configured,
    _Out_opt_ BOOLEAN *Started,
    _Out_opt_ BOOT_MODE *BootMode
    )
{
    if (!gConnected)
        return STATUS_USERMODE_DRIVER_NOT_CONNECTED;

    if (gHypervisorStarted && !gHypervisorConnected)
        return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;

    if (Configured != NULL) *Configured = gHypervisorConfigured;
    if (Started != NULL) *Started = gHypervisorStarted;
    if (BootMode != NULL) *BootMode = gHypervisorBootMode;

    LogInfo("Requested Hv Status: conf: %d started: %d bootmode: %d", gHypervisorConfigured, gHypervisorStarted, gHypervisorBootMode);

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestDumpUefiLogs()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::wstring fileName;
    std::unique_ptr<CHAR[]> preloader;
    std::unique_ptr<CHAR[]> loader;
    DWORD preloaderSize = 0;
    DWORD loaderSize = 0;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    DWORD nrOfBytes = 0;
    std::string separator = "\n\npreloader above / loader below\n\n";

    if (gFeedbackFolder.empty())
    {
        LogError("invalid feedback folder!\n");
        status = STATUS_NOT_PROPERLY_CONFIGURED;
        goto cleanup;
    }

    fileName = gFeedbackFolder + L"uefi_logs_" + std::to_wstring(time(nullptr)) + L".log";

    status = GetUefiPreloaderLog(preloader, preloaderSize);
    if (!NT_SUCCESS(status))
    {
        preloaderSize = 0;
        LogFuncErrorStatus(status, "GetUefiPreloaderLog");
    }

    status = GetUefiLoaderLogFromPhysMem(loader, loaderSize);
    if (!NT_SUCCESS(status))
    {
        loaderSize = 0;
        LogFuncErrorStatus(status, "GetUefiLoaderLogFromPhysMem");
    }

    fileHandle = CreateFile(
        fileName.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (INVALID_HANDLE_VALUE == fileHandle)
    {
        LogError("Unable to create the file %S with %d\n", fileName.c_str(), GetLastError());
        goto cleanup;
    }

    if (preloaderSize > 0)
    {
        if (!WriteFile(fileHandle, preloader.get(), preloaderSize, &nrOfBytes, NULL))
        {
            LogError("Unable write to the file %S with %d\n", fileName.c_str(), GetLastError());
            goto cleanup;
        }
    }

    if (!WriteFile(fileHandle, separator.c_str(), static_cast<DWORD>(separator.length()), &nrOfBytes, NULL))
    {
        LogError("Unable write to the file %S with %d\n", fileName.c_str(), GetLastError());
        goto cleanup;
    }

    if (loaderSize > 0)
    {
        if (!WriteFile(fileHandle, loader.get(), loaderSize, &nrOfBytes, NULL))
        {
            LogError("Unable write to the file %S with %d\n", fileName.c_str(), GetLastError());
            goto cleanup;
        }
    }

cleanup:
    if (INVALID_HANDLE_VALUE != fileHandle)
    {
        CloseHandle(fileHandle);
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestGetMissingFeatures(
    _Out_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!MissingFeatures)
    {
        status = STATUS_INVALID_PARAMETER_3;
        goto cleanup;
    }

    memset(MissingFeatures, 0, sizeof(HV_CONFIGURATION_MISSING_FEATURES));

    status = ValidateHvConfiguration(MissingFeatures);

    LogInfo("Requested missing features: %d %d %d %d", MissingFeatures->MissingFeatures[0], MissingFeatures->MissingFeatures[1], MissingFeatures->MissingFeatures[2], MissingFeatures->MissingFeatures[3]);

    status = STATUS_SUCCESS;
cleanup:
    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestSetPath(
    _In_ CONFIG_PATH PathId,
    _In_z_ PWCHAR Path
)
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    DWORD length;
    std::wstring regKey;

    if (Path == NULL)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    LogVerbose("Setting %d path to: %S\n", PathId, Path);

    switch (PathId)
    {
    case ConfigPathBase:
        regKey = REG_VALUE_SDK_BASE_PATH;
        break;
    case ConfigPathUpdatesIntro:
        regKey = REG_VALUE_UPDATES_INTRO_PATH;
        break;
    case ConfigPathFeedback:
        regKey = REG_VALUE_FEEDBACK_PATH;
        break;
    default:
        status = STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }

    length = (DWORD)wcslen(Path);

    if (wcscmp(Path, L"") != 0)
    {
        error = RegSetKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            regKey.c_str(),
            REG_SZ,
            Path,
            (length + 1) * sizeof(WCHAR)
        );
        if (error != ERROR_SUCCESS)
        {
            status = WIN32_TO_NTSTATUS(error);
            LogFuncErrorLastErr(error, "RegSetKeyValue");
        }
    }
    else
    {
        error = RegDeleteKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            regKey.c_str()
        );
        if (error != ERROR_SUCCESS)
        {
            status = WIN32_TO_NTSTATUS(error);
            LogFuncErrorLastErr(error, "RegDeleteKeyValue");
        }
    }

    switch (PathId)
    {
    case ConfigPathBase:
        SetSDKPath(std::wstring(Path, length));
        break;
    case ConfigPathUpdatesIntro:
        SetUpdatesIntroDir(std::wstring(Path, length));
        break;
    case ConfigPathFeedback:
        {
            if (wcscmp(Path, L"") == 0)
                gFeedbackFolder.clear();
            else
                gFeedbackFolder = std::wstring(Path, length);

            break;
        }
    default:
        status = STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }
    status = STATUS_SUCCESS;

cleanup:
    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestConfigureHypervisor(
    _In_ BOOLEAN Enable,
    _In_opt_z_ const PCHAR CmdLine
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    LogInfo("%sonfiguring hypervisor: %s", Enable ? "C" : "Dec", CmdLine ? CmdLine : "<NONE>");

    // must have paths
    if (   gSdkDirs[SDK_DIR_HV].empty()
        || gSdkDirs[SDK_DIR_UPDATES_INTRO].empty())
    {
        LogError("Invalid updates path!\n");
        status = STATUS_INVALID_SDK_FOLDER;
        goto cleanup;
    }

    // deconfigure any current settings
    status = ConfigureBoot(FALSE);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "ConfigureBoot");
        goto cleanup;
    }

    gHypervisorConfigured = FALSE;

    if (Enable)
    {
        status = CreateFinalConfigData(FALSE, CmdLine ? CmdLine : "");
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateFinalConfigData");
            goto cleanup;
        }

        status = ConfigureBoot(Enable);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ConfigureBoot");
            goto cleanup;
        }
    }
    // at this point everything should be done.
    // store the new values

    gHypervisorConfigured = Enable;

cleanup:
    LSTATUS error;
    DWORD dwordSize = sizeof(DWORD);
    DWORD hypervisorConfigured = 0;

    // in case of error reset the hv configuration
    if (!NT_SUCCESS(status))
    {
        NTSTATUS status2;

        LogError("Could not configure the hypervisor. Deconfiguring...\n");

        status2 = ConfigureBoot(FALSE);
        if (!NT_SUCCESS(status2))
        {
            LogFuncErrorStatus(status2, "ConfigureBoot");
        }

        gHypervisorConfigured = FALSE;
    }

    // always update the result in the registry
    hypervisorConfigured = gHypervisorConfigured;

    error = RegSetKeyValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_HV_CONFIGURATION,
        REG_DWORD,
        &hypervisorConfigured,
        dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        LogFuncErrorLastErr(error, "RegSetValue");
    }

    // dry run of update - just to cache the initial hash values for components
    if (hypervisorConfigured)
    {
        DetermineUpdateStatus(STATUS_SUCCESS, 0);
    }

    LogInfo("WinguestConfigureHypervisor finishing with status %!STATUS!\n", status);

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestConfigureFeedback(
    _In_opt_ FEEDBACK_CONFIG_TYPES const * Generation,
    _In_opt_ QWORD const * Flags,
    _In_opt_ QWORD const * LocalBackupDuration,
    _In_opt_ QWORD const * ThrottleTime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Flags)
    {
        LogVerbose("Setting feedback flags to 0x%llx.", *Flags);

        gFeedbackCfg.Internal = !!(*Flags & FLAG_FEEDBACK_INTERNAL);
    }

    if (LocalBackupDuration)
    {
        LogVerbose("Setting local feedback duration to %lld.", *LocalBackupDuration);

        gFeedbackCfg.LocalBackupDuration = *LocalBackupDuration;
    }

    if (Generation)
    {
        LogVerbose("Setting feedback generation to %d.", Generation->FileIntro);

        gFeedbackCfg.Files[feedbackIntroEpt].Generate
            = gFeedbackCfg.Files[feedbackIntroMsr].Generate
            = gFeedbackCfg.Files[feedbackIntroCr].Generate
            = gFeedbackCfg.Files[feedbackIntroXcr].Generate
            = gFeedbackCfg.Files[feedbackIntroIntegrity].Generate
            = gFeedbackCfg.Files[feedbackIntroTranslation].Generate
            = gFeedbackCfg.Files[feedbackIntroMemcopy].Generate
            = gFeedbackCfg.Files[feedbackIntroDtr].Generate
            = gFeedbackCfg.Files[feedbackIntroProcessCreation].Generate
            = gFeedbackCfg.Files[feedbackIntroModuleLoad].Generate
            = Generation->FileIntro;
    }

    if (ThrottleTime)
    {
        QWORD throttleTime = *ThrottleTime;

        if (*ThrottleTime)
        {

            status = RegisterEvent(
                &gWinguestTimer,
                EVENT_TAG_HASHMAP_THROTTLE_CLEANUP,
                EVENT_TIMER_DEFAULT_INTRO_THROTTLE_HASHMAP_CLEANUP,
                CleanupThrottleHashmap
            );
            if ((status != STATUS_ALREADY_REGISTERED) && (!NT_SUCCESS(status)))
            {
                LogFuncErrorStatus(status, "RegisterEvent");
                throttleTime = 0;
                goto _cleanup;
            }

            throttleTime = max(throttleTime, DEFAULT_THROTTLE_TIME);

            LogVerbose("Setting ThrottleTime to %llu seconds\n", throttleTime);

            status = STATUS_SUCCESS;
        }
        else
        {
            LogVerbose("Deactivating throttling for introspection alerts\n");
            UnregisterEvent(&gWinguestTimer, EVENT_TAG_HASHMAP_THROTTLE_CLEANUP);
        }

    _cleanup:
        gFeedbackCfg.ThrottleTime = throttleTime;
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestGenerateCompatFeedback(
    _In_opt_ CHAR* FeedbackBuffer,
    _Inout_opt_ DWORD* FeedbackBufferSize,
    _In_opt_ const WCHAR* FeedbackBufferFilePath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    json jsonRoot;
    std::string fullBuffer;

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized!\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    if (FeedbackBuffer && !FeedbackBufferSize)
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    LogVerbose("Generating compatibility feedback");

    try
    {
        jsonRoot["Type"] = "Compat";

        status = FeedbackWriteCompatHwInfo(jsonRoot["Info"]);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "FeedbackWriteStatusFile");
            goto cleanup;
        }

        fullBuffer = jsonRoot.dump();

        // save to file
        if (FeedbackBufferFilePath != NULL)
        {
            DWORD written = 0;

            hFile = CreateFile(FeedbackBufferFilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "CreateFile");
                goto cleanup;
            }

            if (!WriteFile(hFile, fullBuffer.c_str(), (DWORD)fullBuffer.length(), &written, NULL))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "WriteFile");
                goto cleanup;
            }
        }

        // return the buffer
        if (FeedbackBufferSize != NULL)
        {
            if (FeedbackBuffer == NULL)
            {
                *FeedbackBufferSize = (DWORD)(fullBuffer.length() + fullBuffer.length() / 10);
            }
            else
            {
                if (*FeedbackBufferSize < fullBuffer.length() + 1)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                    goto cleanup;
                }

                strcpy_s(FeedbackBuffer, *FeedbackBufferSize, fullBuffer.c_str());
                *FeedbackBufferSize = (DWORD)(fullBuffer.length() + 1);
            }
        }

        status = STATUS_SUCCESS;
    }
    catch (json::exception &ex)
    {
        LogError("json exception %d: %s", ex.id, ex.what());
        status = STATUS_JSON_EXCEPTION_ENCOUNTERED;
    }

cleanup:

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestGetComponentVersion(
    __in BIN_COMPONENT Component,
    __inout PDWORD VersionHigh,
    __inout PDWORD VersionLow,
    __inout PDWORD VersionRevision,
    __inout PDWORD VersionBuild
    )
{
    LogVerbose("Requesting version for %d", Component);

    switch (Component)
    {
        case compWinguestDll:
        {
            if (VersionHigh)     *VersionHigh     = WINGUESTDLL_VERSION_HIGH;
            if (VersionLow)      *VersionLow      = WINGUESTDLL_VERSION_LOW;
            if (VersionRevision) *VersionRevision = WINGUESTDLL_VERSION_REVISION;
            if (VersionBuild)    *VersionBuild    = WINGUESTDLL_VERSION_BUILD;

            return STATUS_SUCCESS;
        }

        case compWinguestSys:
        {
            if (VersionHigh)     *VersionHigh     = gVersions.WinguestSys.High;
            if (VersionLow)      *VersionLow      = gVersions.WinguestSys.Low;
            if (VersionRevision) *VersionRevision = gVersions.WinguestSys.Revision;
            if (VersionBuild)    *VersionBuild    = gVersions.WinguestSys.Build;

            return STATUS_SUCCESS;
        }

        case compNapoca:
        {
            if (VersionHigh)     *VersionHigh     = gVersions.Napoca.High;
            if (VersionLow)      *VersionLow      = gVersions.Napoca.Low;
            if (VersionRevision) *VersionRevision = gVersions.Napoca.Revision;
            if (VersionBuild)    *VersionBuild    = gVersions.Napoca.Build;

            return STATUS_SUCCESS;
        }

        case compIntro:
        {
            if (VersionHigh)     *VersionHigh     = gVersions.Intro.High;
            if (VersionLow)      *VersionLow      = gVersions.Intro.Low;
            if (VersionRevision) *VersionRevision = gVersions.Intro.Revision;
            if (VersionBuild)    *VersionBuild    = gVersions.Intro.Build;

            return STATUS_SUCCESS;
        }

        case compExceptions:
        {
            if (VersionHigh)     *VersionHigh     = gVersions.ExceptionsHigh;
            if (VersionLow)      *VersionLow      = gVersions.ExceptionsLow;
            if (VersionRevision) *VersionRevision = 0;
            if (VersionBuild)    *VersionBuild    = gVersions.ExceptionsBuild;

            return STATUS_SUCCESS;
        }

        case compIntroLiveUpdt:
        {
            if (VersionHigh)     *VersionHigh     = gVersions.LiveSupportHigh;
            if (VersionLow)      *VersionLow      = gVersions.LiveSupportLow;
            if (VersionRevision) *VersionRevision = 0;
            if (VersionBuild)    *VersionBuild    = gVersions.LiveSupportBuild;

            return STATUS_SUCCESS;
        }

        default:
            return CX_STATUS_INVALID_PARAMETER_1;
    }
}

WINGUEST_DLL_API
NTSTATUS
WinguestGetCompatibility(
    __in    BIN_COMPONENT Component1,
    __in    BIN_COMPONENT Component2,
    __inout PDWORD VersionHigh,
    __inout PDWORD VersionLow,
    __inout PDWORD VersionRevision,
    __inout PDWORD VersionBuild
    )
{
    NTSTATUS status;

    LogVerbose("Requestig compatibility between %d and %d", Component1, Component2);

    if (Component1 == Component2)
    {
        if (VersionHigh)     *VersionHigh     = 0;
        if (VersionLow)      *VersionLow      = 0;
        if (VersionRevision) *VersionRevision = 0;
        if (VersionBuild)    *VersionBuild    = 0;

        status = STATUS_SUCCESS;
    }
    else if (Component1 == compWinguestDll && Component2 == compWinguestSys)
    {
        NAPOCA_VERSION reqVer = { 0 };

        MakeVersion(&reqVer, WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL);

        if (VersionHigh)     *VersionHigh     = reqVer.High;
        if (VersionLow)      *VersionLow      = reqVer.Low;
        if (VersionRevision) *VersionRevision = reqVer.Revision;
        if (VersionBuild)    *VersionBuild    = reqVer.Build;

        status = gDriverIncompatible ? STATUS_VERSION_INCOMPATIBLE : STATUS_SUCCESS;
    }
    else if (Component1 == compWinguestSys && Component2 == compWinguestDll)
    {
        if (VersionHigh)     *VersionHigh     = gVersions.WinguestDllRequiredByWinguestSys.High;
        if (VersionLow)      *VersionLow      = gVersions.WinguestDllRequiredByWinguestSys.Low;
        if (VersionRevision) *VersionRevision = gVersions.WinguestDllRequiredByWinguestSys.Revision;
        if (VersionBuild)    *VersionBuild    = gVersions.WinguestDllRequiredByWinguestSys.Build;

        status = gDriverIncompatible ? STATUS_VERSION_INCOMPATIBLE : STATUS_SUCCESS;
    }
    else
    {
        CMD_GET_COMPATIBILITY cmd = { 0 };
        DWORD bytesReturned = 0;

        cmd.Component1 = Component1;
        cmd.Component2 = Component2;

        status = KernCommSendMessage(
            cmdGetCompatibility,
            TargetWinguestKm,
            &cmd,
            sizeof(cmd),
            &cmd,
            sizeof(cmd),
            &bytesReturned
            );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
            return status;
        }

        status = cmd.Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdGetCompatibility");
            return status;
        }

        if (VersionHigh)     *VersionHigh      = cmd.VersionHigh;
        if (VersionLow)      *VersionLow       = cmd.VersionLow;
        if (VersionRevision) *VersionRevision  = cmd.VersionRevision;
        if (VersionBuild)    *VersionBuild     = cmd.VersionBuild;
    }

    return status;
}

WINGUEST_DLL_API
PCHAR
WinguestNtStatusToString(
    __in NTSTATUS Status
    )
{
    switch (Status)
    {
        // WINGUEST SPECIFIC ERROR STATUS
    case STATUS_VERSION_INCOMPATIBLE:
        return "STATUS_VERSION_INCOMPATIBLE";
    case STATUS_HYPERVISOR_ALREADY_STARTED:
        return "STATUS_HYPERVISOR_ALREADY_STARTED";
    case STATUS_HYPERVISOR_NOT_STARTED:
        return "STATUS_HYPERVISOR_NOT_STARTED";
    case STATUS_USERMODE_DRIVER_NOT_CONNECTED:
        return "STATUS_USERMODE_DRIVER_NOT_CONNECTED";
    case STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED:
        return "STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED";
    case STATUS_DRIVER_CONNECTION_ACTIVE:
        return "STATUS_DRIVER_CONNECTION_ACTIVE";
    case STATUS_HV_CONFIGURATION_NOT_SUPPORTED:
        return "STATUS_HV_CONFIGURATION_NOT_SUPPORTED";
    case STATUS_HYPERVISOR_NOT_CONFIGURED:
        return "STATUS_HYPERVISOR_NOT_CONFIGURED";
    case STATUS_NOT_PROPERLY_CONFIGURED:
        return "STATUS_NOT_PROPERLY_CONFIGURED";
    case STATUS_INTROSPECTION_OPERATION_NOT_SUPPORTED:
        return "STATUS_INTROSPECTION_OPERATION_NOT_SUPPORTED";
    case STATUS_INVALID_SDK_FOLDER:
        return "STATUS_INVALID_SDK_FOLDER";
    case STATUS_COMPONENT_NOT_KNOWN:
        return "STATUS_COMPONENT_NOT_KNOWN";
    case STATUS_UNKNOWN_HW_ID:
        return "STATUS_UNKNOWN_HW_ID";
    case STATUS_INVALID_WG_CALLBACK_ID:
        return "STATUS_INVALID_WG_CALLBACK_ID";
    case STATUS_WG_NOT_INITIALIZED:
        return "STATUS_WG_NOT_INITIALIZED";
    case STATUS_WG_ALREADY_INITIALIZED:
        return "STATUS_WG_ALREADY_INITIALIZED";
    case STATUS_WINGUEST_EXCEPTION_ENCOUNTERED:
        return "STATUS_WINGUEST_EXCEPTION_ENCOUNTERED";
    case STATUS_JSON_EXCEPTION_ENCOUNTERED:
        return "STATUS_JSON_EXCEPTION_ENCOUNTERED";

    case STATUS_UPDATE_RECOMMENDS_REBOOT:
        return "STATUS_UPDATE_RECOMMENDS_REBOOT";
    case STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE:
        return "STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE";
    case STATUS_UPDATE_REQUIRES_REBOOT:
        return "STATUS_UPDATE_REQUIRES_REBOOT";
    case STATUS_UPDATE_FILE_ERROR:
        return "STATUS_UPDATE_FILE_ERROR";

        // WINGUEST error status related to required features for hv
    case STATUS_UNSUPPORTED_PLATFORM:
        return "STATUS_UNSUPPORTED_PLATFORM";
    case STATUS_UNSUPPORTED_CPU:
        return "STATUS_UNSUPPORTED_CPU";
    case STATUS_VMX_FEATURES_LOCKED_DISABLED:
        return "STATUS_VMX_FEATURES_LOCKED_DISABLED";
    case STATUS_VIRTUALIZATION_FEATURES_NOT_AVAILABLE:
        return "STATUS_VIRTUALIZATION_FEATURES_NOT_AVAILABLE";
    case STATUS_GRUB_FILES_MISSING:
        return "STATUS_GRUB_FILES_MISSING";
    case STATUS_MBR_CONFIGURATION_NOT_SUPPORTED:
        return "STATUS_MBR_CONFIGURATION_NOT_SUPPORTED";
    case STATUS_NOT_SUPPORTED_WHILE_IN_VM:
        return "STATUS_NOT_SUPPORTED_WHILE_IN_VM";
    case STATUS_SDK_FILES_MISSING:
        return "STATUS_SDK_FILES_MISSING";
    case STATUS_OS_VERSION_NOT_SUPPORTED:
        return "STATUS_OS_VERSION_NOT_SUPPORTED";
    case STATUS_CANNOT_GET_SYSTEM_CONFIGURATION:
        return "STATUS_CANNOT_GET_SYSTEM_CONFIGURATION";
    case STATUS_PREVIOUS_GRUB_FILES_DETECTED:
        return "STATUS_PREVIOUS_GRUB_FILES_DETECTED";
    case STATUS_BOOT_ORDER_OVERRIDEN:
        return "STATUS_BOOT_ORDER_OVERRIDEN";
    case STATUS_INSUFFICIENT_PHYSICAL_MEMORY:
        return "STATUS_INSUFFICIENT_PHYSICAL_MEMORY";

        // WINGUEST SPECIFIC WARNING STATUS
    case STATUS_DEVICE_INSTALL_REQUIRES_RESTART:
        return "STATUS_DEVICE_INSTALL_REQUIRES_RESTART";
    case STATUS_DEVICE_UNINSTALL_REQUIRES_RESTART:
        return "STATUS_DEVICE_UNINSTALL_REQUIRES_RESTART";

        // WINGUEST SPECIFIC INFORMATIONAL STATUS
    case STATUS_CONFIGURATION_REQUIRES_RESTART:
        return "STATUS_CONFIGURATION_REQUIRES_RESTART";
    case STATUS_INTROSPECTION_ENGINE_RESTARTED:
        return "STATUS_INTROSPECTION_ENGINE_RESTARTED";

        break;
    default:
        return "UNKNOWN WINGUEST STATUS";
    }
}

//
// HYPERVISOR targeted APIs
//

WINGUEST_DLL_API
NTSTATUS
WinguestGetCfgItemData(
    __inout PCFG_ITEM_DATA CfgItemData
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD nameLen = 0;

    if (CfgItemData == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    // check for Name to be in array range
    nameLen = (DWORD)strnlen_s(CfgItemData->Name, sizeof(CfgItemData->Name));

    LogVerbose("Requesting value for %s", CfgItemData->Name);

    // init out member of this structure
    CfgItemData->ValueType = CfgValueTypeUnknown;
    memset(&CfgItemData->Value, 0, sizeof(CfgItemData->Value));

    std::unique_ptr<CMD_GET_CFG_ITEM_DATA> cmd = std::make_unique<CMD_GET_CFG_ITEM_DATA>();

    RtlSecureZeroMemory(cmd.get(), sizeof(CMD_GET_CFG_ITEM_DATA));

    cmd->CfgItemData = *CfgItemData;

    status = KernCommSendMessage(
        cmdGetCfgItemData,
        TargetNapoca,
        cmd.get(),
        sizeof(CMD_GET_CFG_ITEM_DATA),
        cmd.get(),
        sizeof(CMD_GET_CFG_ITEM_DATA),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdGetCfgItemData");
        return status;
    }

    *CfgItemData = cmd->CfgItemData;

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestSetCfgVar(
    __in const CHAR* Cmdline
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD cmdlineLen;
    DWORD cmdLen;
    std::string cmdExpaneded;
    LD_INSTALL_FILE_FLAGS flags;
    BOOLEAN configured = FALSE, started = FALSE;
    BOOT_MODE bootMode = BOOT_MODE::bootUnknown;

    if (Cmdline == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    LogVerbose("Setting variable: %s", Cmdline);

    status = ExpandCmdlineMacros(Cmdline, cmdExpaneded);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "ExpandCmdlineMacros");
        return status;
    }

    cmdlineLen = (DWORD)cmdExpaneded.size();
    cmdLen = sizeof(CMD_SET_CFG_ITEM_DATA) + cmdlineLen * sizeof('\0');
    if (cmdLen > MAX_MESSAGE_SIZE)
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    status = WinguestGetHvStatus(&configured, &started, &bootMode);

    // do not alloc / forward to sys/hv if not started / not  connected
    if ((status != STATUS_USERMODE_DRIVER_NOT_CONNECTED) && (status != STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED))
    {
        std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(cmdLen);
        CMD_SET_CFG_ITEM_DATA *cmd = reinterpret_cast<CMD_SET_CFG_ITEM_DATA*>(cmdBuf.get());

        memset(cmd, 0, cmdLen);

        cmd->CmdlineLength = cmdlineLen;
        strcpy_s(cmd->Cmdline, cmdlineLen + 1, cmdExpaneded.c_str());

        status = KernCommSendMessage(
            cmdSetCfgItemData,
            TargetNapoca,
            cmd,
            cmdLen,
            cmd,
            cmdLen,
            NULL
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
        }
        else
        {
            status = cmd->Command.ProcessingStatus;
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "cmdSetCfgItemData");
            }
        }
    }
    else
    {
        LogWarning("Request not forwarded to hypervisor! configured %d started %d bootMode %d! Status 0x%x\n",
            configured, started, bootMode, status);
    }

    // ignore persistence errors because we agreed that
    // functional requirement to update the module is stronger than
    // persistence of settings - which is less prone to failures at this point
    if (configured)
    {
        NTSTATUS persistStatus = CreateFinalConfigData(TRUE, Cmdline);
        if (!NT_SUCCESS(persistStatus))
        {
            LogFuncErrorStatus(persistStatus, "CreateFinalConfigData");
        }
        else
        {
            flags.Raw = 0;
            flags.FinalCmdLine = 1;

            persistStatus = IsUefiBootedOs()
                ? DeployUefiBootFiles(flags)
                : DeployGrubBootFiles(flags, FALSE);

            if (!NT_SUCCESS(persistStatus))
            {
                LogFuncErrorStatus(persistStatus, "DeployBootFiles");
            }
        }
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestPerformUpdate(
    _In_ DWORD Components
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN uefi = IsUefiBootedOs();
    LD_INSTALL_FILE_FLAGS flags;
    //BOOLEAN needHviSettingsAgain = FALSE;

    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized!\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    if (!gHypervisorConfigured)
    {
        LogError("Hypervisor not configured!\n");
        return STATUS_HYPERVISOR_NOT_CONFIGURED;
    }

    LogVerbose("Updating %d", Components);

    // files are copied only when a special flag is set
    if (Components & FLAG_INSTALL_BOOT_FILES
        /*|| (Components & FLAG_UPDATE_COMPONENT_BASE
            && Components & FLAG_UPDATE_COMPONENT_INTRO_UPDATES)*/
        )
    {
        status = CreateFinalConfigData(FALSE); // override the modified cmdline that was used until now with the new one delivered in the update
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateFinalConfigData");
            goto cleanup;
        }

        // just upgrade everything
        flags.Raw = 0;
        uefi ? flags.Efi = 1 : flags.Mbr = 1;

        status = UpdateBootFiles(flags);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "UpdateBootFiles");
            status = STATUS_UPDATE_FILE_ERROR;
            goto cleanup;
        }
    }
    else
    {
        // no hv nor hvi files are copied when updating and a special flag is set
        /*if (Components & FLAG_UPDATE_COMPONENT_BASE)
        {
            flags.Raw = 0;
            uefi ? flags.Efi = 1 : flags.Mbr = 1;
            flags.UpdateBase = 1;

            status = UpdateBootFiles(flags);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "UpdateBootFiles");
                status = STATUS_UPDATE_FILE_ERROR;
                goto cleanup;
            }
        }*/

        // hvi exceptions are considered for "copy" and "on the fly" update
        // hvi live updates are considered for "copy" and "on the fly" update
        if (Components & FLAG_UPDATE_COMPONENT_INTRO_UPDATES)
        {
            flags.Raw = 0;
            uefi ? flags.Efi = 1 : flags.Mbr = 1;
            flags.UpdateIntro = 1;

            status = UpdateBootFiles(flags);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "UpdateBootFiles");
                status = STATUS_UPDATE_FILE_ERROR;
                goto cleanup;
            }
        }
    }

    // if the special flag is set then a mandatory reboot must be performed in order to load the new files
    // notify this using a special status
    if (Components & FLAG_INSTALL_BOOT_FILES)
    {
        status = STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE;
        goto cleanup;
    }

    if (!gHypervisorConnected)
    {
        status = STATUS_SUCCESS;
        goto cleanup;
    }

    /*if (Components & FLAG_UPDATE_COMPONENT_BASE)
    {
        INTRO_CONTROL_MODULE_DATA controlData = { 0 };
        DWORD oldIntrospectionOptions;
        DWORD oldIntrospectionState;

        status = LoadConfigData(finalCmdLine);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "LoadConfigData");
            goto cleanup;
        }

        oldIntrospectionOptions = (DWORD)CfgFeaturesIntrospectionOptions;
        oldIntrospectionState = (DWORD)CfgFeaturesIntrospectionEnabled;

        status = CreateFinalConfigData(FALSE);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateFinalConfigData");
            goto cleanup;
        }

        controlData.Enable = oldIntrospectionState == 2 ? 0 : 1;
        controlData.Options = oldIntrospectionOptions;

        unsigned long long flag = MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK;
        status = DetermineIntroUpdate(&flag);// no need to verify status, error would be reported 2 times then

        status = WinguestControlModule(compIntro, &controlData, sizeof(controlData), flag);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WinguestControlModule");
            //status = STATUS_UPDATE_RECOMMENDS_REBOOT;
            goto cleanup;
        }

        // if HVI is reloaded from disk
        //  - full reinit for hvi engine
        //  - settings (protected processes, custom exceptions...) are lost
        needHviSettingsAgain = (status == STATUS_INTROSPECTION_ENGINE_RESTARTED);
    }*/

    // hvi exceptions are considered for "copy" and "on the fly" update
    // hvi live updates are considered for "copy" and "on the fly" update
    if (Components & FLAG_UPDATE_COMPONENT_INTRO_UPDATES)
    {
        status = WinguestControlModule(compIntroLiveUpdt, NULL, 0, MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WinguestControlModule");
            //status = STATUS_UPDATE_RECOMMENDS_REBOOT;
            goto cleanup;
        }

        RequestComponentVersionFromDriver(
            compIntroLiveUpdt,
            &gVersions.LiveSupportHigh,
            &gVersions.LiveSupportLow,
            NULL,
            &gVersions.LiveSupportBuild
            );

        status = WinguestControlModule(compExceptions, NULL, 0, MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WinguestControlModule");
            //status = STATUS_UPDATE_RECOMMENDS_REBOOT;
            goto cleanup;
        }

        RequestComponentVersionFromDriver(
            compExceptions,
            &gVersions.ExceptionsHigh,
            &gVersions.ExceptionsLow,
            NULL,
            &gVersions.ExceptionsBuild
            );
    }

    //////////////////////////////////////////////////////////////////////////
    // All files copied successfully since we get here
    // All "on the fly" updates are successfully applied since we are here
    status = STATUS_SUCCESS;

cleanup:
    // any file copy error means that the update is not successfully done and another attempt needs to be performed
    // otherwise we need to detect if reboot is required/recommended or not
    // this is done by checking if all on the fly updates were successfully done or if there are any updates
    // that cannot be done on the fly
    if (status != STATUS_UPDATE_FILE_ERROR)
    {
        NTSTATUS status2 = DetermineUpdateStatus(status, Components);

        // we always need to compute the hashes but sometimes we can discard the status
        if (status != STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE)
        {
            status = status2;
        }
    }

    LogInfo("Update called with Components: %d -> status 0x%x", Components, status);

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestControlModule(
    __in BIN_COMPONENT ModuleId,
    __in PVOID ModuleCustomData,
    __in DWORD ModuleCustomDataSize,
    __in QWORD Flags
    )
{
    NTSTATUS status;

    LogVerbose("Control Module: %d", ModuleId);

    // validation per module
    switch (ModuleId)
    {
    case compIntro:
    {
        if (ModuleCustomData == NULL)
        {
            LogError("Invalid custom data (should not be NULL)");
            return STATUS_INVALID_PARAMETER_2;
        }
        if (ModuleCustomDataSize != sizeof(INTRO_CONTROL_MODULE_DATA))
        {
            LogError("Invalid custom data size (%u != %u)", ModuleCustomDataSize, sizeof(INTRO_CONTROL_MODULE_DATA));
            return STATUS_INVALID_PARAMETER_3;
        }

        INTRO_CONTROL_MODULE_DATA * icmd = (INTRO_CONTROL_MODULE_DATA *)ModuleCustomData;

        if ((icmd->ControlFieldsToApply > FLAG_INTRO_CONTROL_ALL) ||
            (icmd->ControlFieldsToApply == 0))
        {
            LogError("ControlFieldsToApply filed is not in the accepted value range");
            return STATUS_INVALID_PARAMETER_2;
        }
        break;
    }
    case compExceptions:
    case compIntroLiveUpdt:
    {
        // only allowed operation is load
        if (!(Flags & MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK))
        {
            LogError("Invalid operation flag\n");
            return STATUS_INVALID_PARAMETER_4;
        }
        if (ModuleCustomData != NULL)
        {
            LogError("Invalid custom data(must be NULL)");
            return STATUS_INVALID_PARAMETER_2;
        }
        if (ModuleCustomDataSize != 0)
        {
            LogError("Invalid custom data size(must be 0)");
            return STATUS_INVALID_PARAMETER_3;
        }
        break;
    }
    default:
        LogError("Invalid/unsupported component %u", ModuleId);
        return STATUS_INVALID_PARAMETER_1;
    }

    if (!gConnected)
    {
        return STATUS_USERMODE_DRIVER_NOT_CONNECTED;
    }

    status = STATUS_UNSUCCESSFUL;

    LD_INSTALL_FILE *instFile;
    LD_UNIQUE_ID uniqueId = undefinedId;
    DWORD cmdSize;
    DWORD pathSize;
    std::wstring fileFullPath;

    if (Flags & MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK)
    {
        switch (ModuleId)
        {
        case compIntro:
            uniqueId = introcorebin;
            break;

        case compExceptions:
            uniqueId = exceptionsbin;
            break;
        case compIntroLiveUpdt:
            uniqueId = introliveupdtbin;
            break;
        }

        instFile = GetInstallFileForUniqueId(uniqueId);
        if (!instFile)
        {
            status = STATUS_FILE_NOT_AVAILABLE;
            LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
            return status;
        }

        if (gSdkDirs[instFile->SourceDir].empty())
        {
            status = STATUS_NOT_PROPERLY_CONFIGURED;
            LogFuncErrorStatus(status, "missing dir");
            return status;
        }

        fileFullPath = gSdkDirs[instFile->SourceDir];
        fileFullPath += instFile->SourceFileName;

        pathSize = static_cast<DWORD>(fileFullPath.length()) * sizeof(WCHAR);
    }
    else
    {
        // no reload needed
        pathSize = 0;
    }

    cmdSize = (DWORD)(sizeof(CMD_UPDATE_COMPONENT) + pathSize + ModuleCustomDataSize - sizeof(CMD_UPDATE_COMPONENT::Buffer));

    std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(cmdSize);
    CMD_UPDATE_COMPONENT *cmd = reinterpret_cast<CMD_UPDATE_COMPONENT *>(cmdBuf.get());

    cmd->Component = ModuleId;
    cmd->PathSize = pathSize;
    cmd->DataSize = ModuleCustomDataSize;

    if (pathSize != 0)
    {
        memcpy(cmd->Buffer, fileFullPath.c_str(), cmd->PathSize);
    }
    if (ModuleCustomData != NULL)
    {
        memcpy_s(cmd->Buffer + cmd->PathSize, cmd->DataSize, ModuleCustomData, ModuleCustomDataSize);
    }
    status = KernCommSendMessage(
        cmdUpdateComponent,
        TargetWinguestKm,
        cmd,
        cmdSize,
        cmd,
        cmdSize,
        NULL
    );
    if (status != STATUS_HYPERVISOR_NOT_STARTED)
    {
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessage");
            return status;
        }

        status = cmd->Command.ProcessingStatus;
        if (status != STATUS_HYPERVISOR_NOT_STARTED)
        {
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "cmdUpdateComponent");
                return status;
            }
        }
    }

    //if (Flags & MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK)
    {
        if (ModuleId == compIntro)
        {
            INTRO_CONTROL_MODULE_DATA *icmd = (INTRO_CONTROL_MODULE_DATA *)ModuleCustomData;
            std::string customCmd;
            BOOLEAN needsComma = FALSE;
            LD_INSTALL_FILE_FLAGS flags;
            NTSTATUS persistStatus;

            if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_OPTIONS)
            {
                CHAR hexVal[20];
                sprintf_s(hexVal, "%llx", icmd->ControlData.Options);
                customCmd += "CfgFeaturesIntrospectionOptions=0x";
                customCmd += hexVal;
                needsComma = TRUE;
            }

            if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_STATE)
            {
                if (needsComma)
                {
                    customCmd += ",";
                    needsComma = FALSE;
                }

                customCmd += "CfgFeaturesIntrospectionEnabled=";
                customCmd += icmd->ControlData.Enable ? "1" : "2";
                needsComma = TRUE;
            }

            if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_VERBOSITY)
            {
                if (needsComma)
                {
                    customCmd += ",";
                    needsComma = FALSE;
                }

                customCmd += "CfgFeaturesIntrospectionVerbosity=" + std::to_string(icmd->ControlData.Verbosity);
            }

            LogInfo("Write in file: %s", customCmd.c_str());

            // ignore persistence errors because we agreed that
            // functional requirement to update the module is stronger than
            // persistence of settings - which is less prone to failures at this point
            {
                persistStatus = CreateFinalConfigData(TRUE, customCmd);
                if (!NT_SUCCESS(persistStatus))
                {
                    LogFuncErrorStatus(persistStatus, "CreateFinalConfigData");
                    goto cleanup_persist;
                }

                flags.Raw = 0;
                IsUefiBootedOs() ? flags.Efi = 1 : flags.Mbr = 1;

                // In case of enable / disable introspection, copy all UpdateIntro files
                if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_STATE)
                {
                    flags.UpdateIntro = 1;
                }
                // In case of update verbosity / options copy only final cmd line
                else
                {
                    flags.FinalCmdLine = 1;
                }

                persistStatus = UpdateBootFiles(flags);
                if (!NT_SUCCESS(persistStatus))
                {
                    LogFuncErrorStatus(persistStatus, "UpdateBootFiles");
                    goto cleanup_persist;
                }
            cleanup_persist:;
            }
        }
    }

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestQueryModule(
    __in BIN_COMPONENT ModuleId,
    __out PVOID ModuleQueryData,
    __in DWORD ModuleQueryDataSize,
    __in QWORD Flags
)
{
    BYTE retryCount;
    WORD retryDelay;

    UNREFERENCED_PARAMETER(Flags);

    LogVerbose("Query Module: %d", ModuleId);

    if (ModuleQueryData == NULL)
    {
        LogError("Invalid query data (should not be NULL)");
        return STATUS_INVALID_PARAMETER_2;
    }

    switch (ModuleId)
    {
        case compIntro:
        {
            if (ModuleQueryDataSize != sizeof(INTRO_QUERY_MODULE_DATA))
            {
                LogError("Invalid module data size (%u != %u)", ModuleQueryDataSize, sizeof(INTRO_QUERY_MODULE_DATA));
                return STATUS_INVALID_PARAMETER_3;
            }

            retryCount = 5;
            retryDelay = 1000; // in miliseconds

            break;
        }
        default:
        {
            LogError("Invalid/unsupported component %u", ModuleId);

            retryCount = 1;
            retryDelay = 0; // in milliseconds

            return STATUS_INVALID_PARAMETER_1;
        }
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cmdSize = (DWORD)sizeof(CMD_QUERY_COMPONENT) + ModuleQueryDataSize - sizeof(CMD_QUERY_COMPONENT::Buffer);
    std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(cmdSize);
    CMD_QUERY_COMPONENT* cmd = reinterpret_cast<CMD_QUERY_COMPONENT*>(cmdBuf.get());

    while (retryCount--)
    {
        DWORD bytesReturned;

        memset(cmd, 0, cmdSize);
        cmd->Component = ModuleId;

        status = KernCommSendMessage(
            cmdQueryComponent,
            TargetWinguestKm,
            cmd,
            cmdSize,
            cmd,
            cmdSize,
            &bytesReturned
        );
        if (!NT_SUCCESS(status) || bytesReturned != cmdSize)
        {
            LogError("KernCommSendMessage failed with 0x%08x(or byteReturned: %u != %u)", status, bytesReturned, cmdSize);
            goto cleanup_try;
        }

        status = cmd->Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdUpdateComponent");
            goto cleanup_try;
        }

        memcpy_s(ModuleQueryData, ModuleQueryDataSize, cmd->Buffer, ModuleQueryDataSize);

    cleanup_try:
        if (NT_SUCCESS(status))
        {
            if (ModuleId == compIntro)
            {
                INTRO_QUERY_MODULE_DATA* qd = (INTRO_QUERY_MODULE_DATA*)ModuleQueryData;

                if (qd->Enabled)
                {
                    break;
                }
                else
                {
                    Sleep(retryDelay);
                }
            }
        }
    }

    return status;
}

//
// INTROSPECTION targeted APIs
//

WINGUEST_DLL_API
NTSTATUS
WinguestSetProtectedProcess(
    _In_ PWCHAR ProcessPath,
    _In_ DWORD Mask,
    _In_ QWORD Context
)
{
    if (ProcessPath == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    LogInfo("Setting protected process: %S %d %lld", ProcessPath, Mask, Context);

    DWORD pathLen = (DWORD)wcslen(ProcessPath);

    DWORD cmdLen = sizeof(CMD_SET_PROTECTED_PROCESS) + pathLen * sizeof(WCHAR); // CMD_SET_PROTECTED_PROCESS already includes one WCHAR for the NULL terminator

    if (cmdLen > MAX_MESSAGE_SIZE)
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(cmdLen);
    CMD_SET_PROTECTED_PROCESS *cmd = reinterpret_cast<CMD_SET_PROTECTED_PROCESS *>(cmdBuf.get());

    memset(cmd, 0, cmdLen);

    cmd->Mask = Mask;
    cmd->Context = Context;
    cmd->PathLen = pathLen + 1;
    wcscpy_s(cmd->Path, cmd->PathLen, ProcessPath);

    NTSTATUS status = KernCommSendMessage(
        cmdSetProtectedProcess,
        TargetNapoca,
        cmd,
        cmdLen,
        cmd,
        cmdLen,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdSetProtectedProcess");
        return status;
    }

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestRemoveAllProtectedProcesses(
    VOID
)
{
    LogVerbose("Removing all protected processes");

    return WinguestFastOpt(
        OPT_REM_ALL_PROTECTED_PROCESSES, 0,
        0, 0, 0, 0,
        NULL, NULL, NULL, NULL
    );
}

WINGUEST_DLL_API
NTSTATUS
WinguestGetGuestInfo(
    __inout PGUEST_INFO GuestInfo
    )
{
    if (GuestInfo == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    LogVerbose("Requesting guest info");

    std::unique_ptr<CMD_GUEST_INFO> cmd = std::make_unique<CMD_GUEST_INFO>();

    memset(cmd.get(), 0, sizeof(CMD_GUEST_INFO));

    NTSTATUS status = KernCommSendMessage(
        cmdIntroGuestInfo,
        TargetNapoca,
        cmd.get(),
        sizeof(CMD_GUEST_INFO),
        cmd.get(),
        sizeof(CMD_GUEST_INFO),
        NULL
        );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdIntroGuestInfo");
        return status;
    }

    *GuestInfo = cmd->GuestInfo;

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestAddExceptionFromAlert(
    __in PVOID AlertData,
    __in DWORD AlertSize,
    __in INTRO_EVENT_TYPE AlertType,
    __in BOOLEAN IsException,
    __in_opt QWORD Context
)
{
    DWORD cmdSize = sizeof(CMD_ADD_EXCEPTION_FROM_ALERT) + AlertSize;

    if (AlertData == NULL)
    {
        LogError("Invalid alert data (should not be NULL)");
        return STATUS_INVALID_PARAMETER_1;
    }
    if (AlertSize == 0 || AlertSize > sizeof(INTROSPECTION_EVENT)) // sanity size check (with a hammer)
    {
        LogError("Invalid alert size: %u", AlertSize);
        return STATUS_INVALID_PARAMETER_2;
    }

    LogVerbose("Adding exception from alert");

    std::unique_ptr<BYTE[]> cmdBuf = std::make_unique<BYTE[]>(cmdSize);
    CMD_ADD_EXCEPTION_FROM_ALERT *cmd = reinterpret_cast<CMD_ADD_EXCEPTION_FROM_ALERT*>(cmdBuf.get());

    memcpy(cmd->AlertData, AlertData, AlertSize);
    cmd->AlertSize = AlertSize;
    cmd->AlertType = AlertType;
    cmd->IsException = IsException;
    cmd->Context = Context;

    NTSTATUS status = KernCommSendMessage(
        cmdAddExceptionFromAlert,
        TargetNapoca,
        cmd,
        cmdSize,
        cmd,
        cmdSize,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdAddExceptionFromAlert");
        return status;
    }

    LogInfo("Exception add request succeeded (Context: 0x%llX)", Context);

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestRemoveException(
    _In_ QWORD Context
)
{
    LogVerbose("Removing exception with context %lld", Context);

    std::unique_ptr<CMD_REMOVE_EXCEPTION> cmd = std::make_unique<CMD_REMOVE_EXCEPTION>();

    cmd->Context = Context;

    NTSTATUS status = KernCommSendMessage(
        cmdRemoveException,
        TargetNapoca,
        cmd.get(),
        sizeof(CMD_REMOVE_EXCEPTION),
        cmd.get(),
        sizeof(CMD_REMOVE_EXCEPTION),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "KernCommSendMessage");
        return status;
    }

    status = cmd->Command.ProcessingStatus;
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "cmdRemoveException");
        return status;
    }

    LogInfo("Exception remove request succeeded (Context: 0x%llX)", Context);

    return STATUS_SUCCESS;
}

WINGUEST_DLL_API
NTSTATUS
WinguestFlushAlertExceptions(
    VOID
)
{
    LogVerbose("Flushing alert exceptions");

    return WinguestFastOpt(
        OPT_FLUSH_EXCEPTIONS_FROM_ALERTS, 0,
        0, 0, 0, 0,
        NULL, NULL, NULL, NULL
    );
}

/// @}