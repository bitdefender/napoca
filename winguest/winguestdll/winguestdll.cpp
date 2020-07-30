/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file winguestdll.cpp
*   @brief Main winguestdll library entry point and (un)initialization
*/

#include <string>
#include <sstream>

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <windows.h>
#include <Wbemidl.h>
#include <VersionHelpers.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "winguestdll.h"
#include "kerncomm_int.h"
#include "version.h"
#include "libapis.h"
#include "winguest_status.h"
#include "feedback.h"
#include "helpers.h"
#include "reg_opts.h"
#include "deploy_validation.h"
#include "event_timer.h"
#include "deploy.h"
#include "common/debug/memlog.h"
#include "trace.h"
#include "winguestdll.tmh"

BOOLEAN gInitialized;
BOOLEAN gHypervisorStarted;
BOOLEAN gHypervisorConnected;
BOOT_MODE gHypervisorBootMode;
extern BOOLEAN gHypervisorConfigured;

EVENT_TIMER gWinguestTimer;

extern std::wstring gFeedbackFolder;

static
void
_WinguestApplyLoaderLockHangHack(
    void
);

static
NTSTATUS
_UninitializeWinguestInternal(
    void
    );

/**
 * @brief Main DLL entry point
 *
 * @param[in] hModule
 * @param[in] ul_reason_for_call
 * @param[in] lpReserved
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
BOOL APIENTRY
DllMain(
    __in HMODULE hModule,
    __in DWORD ul_reason_for_call,
    __in LPVOID lpReserved
    )
{
    UNREFERENCED_PARAMETER((hModule, lpReserved));

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        WPP_INIT_TRACING(NULL);
        break;

    case DLL_PROCESS_DETACH:
        WPP_CLEANUP();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

WINGUEST_DLL_API
NTSTATUS
WinguestResetHvConfiguration(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    std::wstring basePath;
    DWORD  basePathLen = 0;

    LogInfo("Requested emergency hypervisor deconfiguration");

    DetectFirmwareInfo();

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_SDK_BASE_PATH,
        RRF_RT_REG_SZ,
        NULL,
        NULL,
        &basePathLen
    );
    if (error != ERROR_SUCCESS)
    {
        status = WIN32_TO_NTSTATUS(error);
        LogFuncErrorLastErr(error, "RegGetValue");
        goto cleanup;
    }

    basePath.resize(basePathLen / sizeof(WCHAR));

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_SDK_BASE_PATH,
        RRF_RT_REG_SZ,
        NULL,
        &basePath[0],
        &basePathLen
    );
    if (error != ERROR_SUCCESS)
    {
        LogFuncErrorStatus(status, "WinguestRegQueryValueString");
        goto cleanup;
    }

    basePath.resize(basePathLen / sizeof(WCHAR) - 1);

    SetSDKPath(basePath);

    return ConfigureBoot(FALSE);

cleanup:
    return status;
}

/**
 * @brief Request required process privileges
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
SetProcessPrivileges(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp = {0};
    DWORD ret = 0;

    __try
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "OpenProcessToken");
            __leave;
        }

        ret = LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &tkp.Privileges[0].Luid);
        if (0 == ret)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "LookupPrivilegeValue");
            __leave;
        }

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        ret = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        if (0 == ret)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "AdjustTokenPrivileges");
            __leave;
        }
    }
    __finally
    {
        if (NULL != hToken)
        {
            CloseHandle(hToken);
            hToken = NULL;
        }
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestInitialize(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    DWORD interval = 0;
    std::wstring sdkPath;
    DWORD sdkPathLen = 0;
    DWORD dwordSize = sizeof(DWORD);
    DWORD feedbackFolderSize = 0;
    DWORD hypervisorConfigured = 0;

    if (gInitialized)
    {
        LogError("Winguest DLL already initialized\n");
        return STATUS_WG_ALREADY_INITIALIZED;
    }

    _WinguestApplyLoaderLockHangHack();

    LogInfo("Initializing winguestdll %d.%d.%d.%d, build time: %s %s\n",
        WINGUESTDLL_VERSION_HIGH,
        WINGUESTDLL_VERSION_LOW,
        WINGUESTDLL_VERSION_REVISION,
        WINGUESTDLL_VERSION_BUILD,
        __TIME__, __DATE__
    );

    status = SetProcessPrivileges();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "SetProcessPrivileges");
    }

    // detect firmware type
    status = DetectFirmwareInfo();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DetectFirmwareInfo");
    }

    // Try to read any currently hv configuration

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_HV_CONFIGURATION,
        RRF_RT_REG_DWORD,
        NULL,
        &hypervisorConfigured,
        &dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        hypervisorConfigured = 0;
    }

    gHypervisorConfigured = !!hypervisorConfigured;

    // Try to read Event Timer Granularity from registry

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_EVENT_TIMER_GRANULARITY,
        RRF_RT_REG_DWORD,
        NULL,
        &interval,
        &dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        interval = EVENT_TIMER_DEFAULT_GRANULARITY;     // set a default value
        error = RegSetKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_EVENT_TIMER_GRANULARITY,
            REG_DWORD,
            &interval,
            dwordSize
        );
    }

    status = InitializeTimer(&gWinguestTimer, interval);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "InitializeTimer");
        goto cleanup;
    }

    // read feedback folder if available
    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_FEEDBACK_PATH,
        RRF_RT_REG_SZ,
        NULL,
        NULL,
        &feedbackFolderSize
    );
    if (error == ERROR_SUCCESS)
    {
        gFeedbackFolder.resize(feedbackFolderSize / sizeof(WCHAR));

        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_FEEDBACK_PATH,
            RRF_RT_REG_SZ,
            NULL,
            &gFeedbackFolder[0],
            &feedbackFolderSize
        );
        if (error != ERROR_SUCCESS)
        {
            status = WIN32_TO_NTSTATUS(error);
            LogFuncErrorLastErr(error, "RegGetValue");
            goto cleanup;
        }

        gFeedbackFolder.resize(feedbackFolderSize / sizeof(WCHAR) - 1);

        LogVerbose("Creating dir: %S\n", gFeedbackFolder.c_str());
        status = CreateDirectoryFullPath(gFeedbackFolder);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateDirectoryFullPath");
        }
    }

    // read feedback cleanup interval
    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_FEEDBACK_CLEANUP_GRANULARITY,
        RRF_RT_REG_DWORD,
        NULL,
        &interval,
        &dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        interval = EVENT_TIMER_DEFAULT_FEEDBACK_CLEANUP_GRANULARITY;     // set a default value
        error = RegSetKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_FEEDBACK_CLEANUP_GRANULARITY,
            REG_DWORD,
            &interval,
            dwordSize
        );
    }

    status = RegisterEvent(&gWinguestTimer, "fdbk_clean", interval, CleanupFeedbackFolder);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "RegisterEvent");
    }

    // callback to clean the hashmap used by throttling mechanism
    interval = EVENT_TIMER_DEFAULT_INTRO_THROTTLE_HASHMAP_CLEANUP;
    status = RegisterEvent(&gWinguestTimer, EVENT_TAG_HASHMAP_THROTTLE_CLEANUP, interval, CleanupThrottleHashmap);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "RegisterEvent");
    }

    // retrieve SDK base path if available
    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_SDK_BASE_PATH,
        RRF_RT_REG_SZ,
        NULL,
        NULL,
        &sdkPathLen
    );
    if (error == ERROR_SUCCESS)
    {
        sdkPath.resize(sdkPathLen / sizeof(WCHAR));

        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_SDK_BASE_PATH,
            RRF_RT_REG_SZ,
            NULL,
            &sdkPath[0],
            &sdkPathLen
        );
        if (error != ERROR_SUCCESS)
        {
            LogFuncErrorStatus(status, "RegGetValue");
            status = STATUS_SUCCESS;
            goto cleanup;
        }
        sdkPath.resize(sdkPathLen / sizeof(WCHAR) - 1);

        SetSDKPath(sdkPath);
    }

    // retrieve intro updates path if available
    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_UPDATES_INTRO_PATH,
        RRF_RT_REG_SZ,
        NULL,
        NULL,
        &sdkPathLen
    );
    if (error == ERROR_SUCCESS)
    {
        sdkPath.resize(sdkPathLen / sizeof(WCHAR));

        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_UPDATES_INTRO_PATH,
            RRF_RT_REG_SZ,
            NULL,
            &sdkPath[0],
            &sdkPathLen
        );
        if (error != ERROR_SUCCESS)
        {
            LogFuncErrorStatus(status, "RegGetValue");
            status = STATUS_SUCCESS;
        }
        sdkPath.resize(sdkPathLen / sizeof(WCHAR) - 1);

        SetUpdatesIntroDir(sdkPath);
    }
    memset(&gCallbacks, 0, sizeof(UM_CALLBACKS));
    memset(&gContexts, 0, sizeof(UM_CONTEXTS));

    gInitialized = TRUE;

    status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(status))
    {
        _UninitializeWinguestInternal();
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestUninitialize(
    void
)
{
    if (!gInitialized)
    {
        LogError("Winguest DLL not initialized yet\n");
        return STATUS_WG_NOT_INITIALIZED;
    }

    LogInfo("Uninitializing winguest");

    return _UninitializeWinguestInternal();
}

/**
 * @brief Internal version of #WinguestUninitialize that bypasses initialization check
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
_UninitializeWinguestInternal(
    void
    )
{
    UnregisterEvent(&gWinguestTimer, "fdbk_clean");
    UnregisterEvent(&gWinguestTimer, EVENT_TAG_HASHMAP_THROTTLE_CLEANUP);
    WinguestDisconnectFromDriver();
    UninitializeTimer(&gWinguestTimer);

    memset(&gCallbacks, 0, sizeof(UM_CALLBACKS));
    memset(&gContexts, 0, sizeof(UM_CONTEXTS));

    gHypervisorStarted = FALSE;
    gHypervisorConnected = FALSE;
    gHypervisorBootMode = bootUnknown;
    gHypervisorConfigured = FALSE;

    gInitialized = FALSE;

    return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
//
// BEGIN WINDOWS 7 LOADERLOCK HACK
//
// THIS HACK IS ONLY FOR WINDOWS 7
// WE NEED THIS BECAUSE ON WINDOWS 7 THERE IS A RACE CONDITION THAT LEADS
// TO A DEADLOCK WITH THE LOADERLOCK
//
//////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(NTAPI *ProcLdrLockLoaderLock)   (
    _In_    ULONG Flags,
    _In_    ULONG *State,
    _Out_   UINT_PTR* Cookie);

typedef NTSTATUS(NTAPI *ProcLdrUnlockLoaderLock) (
    _In_ ULONG Flags,
    _In_ UINT_PTR);

static ProcLdrLockLoaderLock    fnLockLoaderLock = nullptr;
static ProcLdrUnlockLoaderLock  fnUnlockLoaderLock = nullptr;
static HMODULE                  gNtDll = nullptr;
static boolean                  gAlreadyHacked = false;
static std::unique_ptr<std::stringstream>        gHackStringStream;

static
void
_WinguestGetLoaderLockProcedures()
{
    if (gNtDll == nullptr || fnLockLoaderLock == nullptr || fnUnlockLoaderLock == nullptr)
    {
        gNtDll = GetModuleHandle(TEXT("ntdll.dll"));

        if (gNtDll == nullptr)
        {
            throw std::exception("Cannot get ntdll.dll module");
        }

        fnLockLoaderLock = (ProcLdrLockLoaderLock)GetProcAddress(gNtDll, "LdrLockLoaderLock");
        fnUnlockLoaderLock = (ProcLdrUnlockLoaderLock)GetProcAddress(gNtDll, "LdrUnlockLoaderLock");

        if (fnLockLoaderLock == nullptr)
        {
            fnUnlockLoaderLock = nullptr;
            throw std::exception("Cannot get LdrLockLoaderLock function");
        }
        if (fnUnlockLoaderLock == nullptr)
        {
            fnLockLoaderLock = nullptr;
            throw std::exception("Cannot get LdrUnlockLoaderLock function");
        }
    }
}

static
void
_WinguestApplyLoaderLockHangHack(void)
{
    auto status = STATUS_SUCCESS;
    UINT_PTR cookie = 0;

    // only for windows 7
    if (!(IsWindows7OrGreater() && !IsWindows8OrGreater()))
    {
        return;
    }

    if (!gAlreadyHacked)
    {
        try
        {
            if (!fnLockLoaderLock) _WinguestGetLoaderLockProcedures();
            // this will throw exception
            // both methods are threated simultaneously,
            // this means if we have lock, we have unlock too
            // and the other way around

            status = (*fnLockLoaderLock)(0, nullptr, &cookie);
            if (status != 0)
            {
                throw std::exception("Cannot lock LoaderLock");
            }

            gHackStringStream = std::make_unique<std::stringstream>();

            status = (*fnUnlockLoaderLock)(0, cookie);
            if (status != 0)
            {
                throw std::exception("Unable to unlock LoaderLock");
            }

            gAlreadyHacked = true;
        }
        catch (std::exception &ex)
        {
            LogError("Error applying loader lock hack! Will continue! Text %s\n", ex.what());
        }
    }
}
//////////////////////////////////////////////////////////////////////////
//
// END WINDOWS 7 LOADERLOCK HACK
//
//////////////////////////////////////////////////////////////////////////
