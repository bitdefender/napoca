/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "imports.h"
#include <ntstatus.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>

static HMODULE      WinguestdllHandle;
WINGUEST_IMPORTS    Winguest;

/* Static functions */
static __forceinline BOOLEAN _IsComponentInited(VOID);

/**/
NTSTATUS
ImportsInit(
    VOID
)
{
    NTSTATUS status = STATUS_SUCCESS;

    // We assume that winguestdll.dll is in the same directory.
    WinguestdllHandle = LoadLibraryW(L"winguestdll.dll");
    if (!WinguestdllHandle)
    {
        wprintf(L"LoadLibrary failed! GetLastError = 0x%x\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup;
    }

    // Effectively importing the functions from dll
    Winguest.Initialize = (PFUNC_WinguestInitialize)GetProcAddress(WinguestdllHandle, "WinguestInitialize");
    Winguest.Uninitialize = (PFUNC_WinguestUninitialize)GetProcAddress(WinguestdllHandle, "WinguestUninitialize");
    Winguest.InstallDriver = (PFUNC_WinguestInstallDriver)GetProcAddress(WinguestdllHandle, "WinguestInstallDriver");
    Winguest.UninstallDriver = (PFUNC_WinguestUninstallDriver)GetProcAddress(WinguestdllHandle, "WinguestUninstallDriver");
    Winguest.SetPath = (PFUNC_WinguestSetPath)GetProcAddress(WinguestdllHandle, "WinguestSetPath");
    Winguest.ConfigureHypervisor = (PFUNC_WinguestConfigureHypervisor)GetProcAddress(WinguestdllHandle, "WinguestConfigureHypervisor");
    Winguest.ConnectToDriver = (PFUNC_WinguestConnectToDriver)GetProcAddress(WinguestdllHandle, "WinguestConnectToDriver");
    Winguest.DisconnectFromDriver = (PFUNC_WinguestDisconnectFromDriver)GetProcAddress(WinguestdllHandle, "WinguestDisconnectFromDriver");
    Winguest.SetProtectedProcess = (PFUNC_WinguestSetProtectedProcess)GetProcAddress(WinguestdllHandle, "WinguestSetProtectedProcess");
    Winguest.ConfigureLoadMonitor = (PFUNC_WinguestConfigureLoadMonitor)GetProcAddress(WinguestdllHandle, "WinguestConfigureLoadMonitor");
    Winguest.ControlModule = (PFUNC_WinguestControlModule)GetProcAddress(WinguestdllHandle, "WinguestControlModule");
    Winguest.QueryModule = (PFUNC_WinguestQueryModule)GetProcAddress(WinguestdllHandle, "WinguestQueryModule");
    Winguest.GetHvStatus = (PFUNC_WinguestGetHvStatus)GetProcAddress(WinguestdllHandle, "WinguestGetHvStatus");
    Winguest.NtStatusToString = (PFUNC_WinguestNtStatusToString)GetProcAddress(WinguestdllHandle, "WinguestNtStatusToString");
    Winguest.GetMissingFeatures = (PFUNC_WinguestGetMissingFeatures)GetProcAddress(WinguestdllHandle, "WinguestGetMissingFeatures");
    Winguest.ConfigureFeedback = (PFUNC_WinguestConfigureFeedback)GetProcAddress(WinguestdllHandle, "WinguestConfigureFeedback");
    Winguest.RegisterCallback = (PFUNC_WinguestRegisterCallback)GetProcAddress(WinguestdllHandle, "WinguestRegisterCallback");

    // Check that at least one function has not been imported. If so, fail
    if (
        !Winguest.Initialize ||
        !Winguest.Uninitialize ||
        !Winguest.InstallDriver ||
        !Winguest.UninstallDriver ||
        !Winguest.SetPath ||
        !Winguest.ConfigureHypervisor ||
        !Winguest.ConnectToDriver ||
        !Winguest.DisconnectFromDriver ||
        !Winguest.SetProtectedProcess ||
        !Winguest.ConfigureLoadMonitor ||
        !Winguest.ControlModule ||
        !Winguest.QueryModule ||
        !Winguest.GetHvStatus ||
        !Winguest.NtStatusToString ||
        !Winguest.GetMissingFeatures ||
        !Winguest.ConfigureFeedback ||
        !Winguest.RegisterCallback
        )
    {
        wprintf(L"At least one function failed to import!");
        status = STATUS_DLL_INIT_FAILED;
        goto cleanup;
    }

    // Initialize winguestdll.dll
    status = Winguest.Initialize();
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestInitialize failed with status = %S\n", Winguest.NtStatusToString(status));
        goto cleanup;
    }

cleanup:
    if (!NT_SUCCESS(status))
    {
        if (WinguestdllHandle)
        {
            FreeLibrary(WinguestdllHandle);
            WinguestdllHandle = NULL;
        }
    }

    return status;
}

/**/
NTSTATUS
ImportsUninit(
    VOID
)
{
    if (!_IsComponentInited()) { return STATUS_SUCCESS; }

    // Uninitialize winguestdll
    Winguest.Uninitialize();

    FreeLibrary(WinguestdllHandle);
    WinguestdllHandle = NULL;

    return STATUS_SUCCESS;
}

/* Static functions */
static
__forceinline
BOOLEAN
_IsComponentInited(
    VOID
)
{
    return WinguestdllHandle != NULL;
}