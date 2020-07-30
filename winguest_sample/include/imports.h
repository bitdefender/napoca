/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _IMPORTS_H_
#define _IMPORTS_H_

//
// Here you will find all the functions imported from winguestdll.dll
//

#ifndef QWORD
#define QWORD unsigned __int64
#endif

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include "winguestdll.h"
#include "drvinstall.h"

#pragma warning(disable:4214)   // disable bit field types other than int warning
#pragma warning(disable:4201)   // disable nameless struct warning
#include "libapis.h"
#pragma warning(default:4201)   // enable nameless struct warning
#pragma warning(default:4214)   // enable bit field types other than int warning

typedef struct _WINGUEST_IMPORTS
{
    //
    // winguestdll.h
    //
    PFUNC_WinguestInitialize            Initialize;
    PFUNC_WinguestUninitialize          Uninitialize;

    //
    // drvinstall.h
    //
    PFUNC_WinguestInstallDriver         InstallDriver;
    PFUNC_WinguestUninstallDriver       UninstallDriver;

    //
    // libapis.h
    //
    PFUNC_WinguestNtStatusToString      NtStatusToString;
    PFUNC_WinguestSetPath               SetPath;
    PFUNC_WinguestConfigureHypervisor   ConfigureHypervisor;
    PFUNC_WinguestConnectToDriver       ConnectToDriver;
    PFUNC_WinguestDisconnectFromDriver  DisconnectFromDriver;
    PFUNC_WinguestSetProtectedProcess   SetProtectedProcess;
    PFUNC_WinguestConfigureLoadMonitor  ConfigureLoadMonitor;
    PFUNC_WinguestControlModule         ControlModule;
    PFUNC_WinguestGetHvStatus           GetHvStatus;
    PFUNC_WinguestQueryModule           QueryModule;
    PFUNC_WinguestGetMissingFeatures    GetMissingFeatures;
    PFUNC_WinguestConfigureFeedback     ConfigureFeedback;
    PFUNC_WinguestRegisterCallback      RegisterCallback;
}WINGUEST_IMPORTS;
extern WINGUEST_IMPORTS Winguest;

/**/ NTSTATUS ImportsInit(VOID);
/**/ NTSTATUS ImportsUninit(VOID);

#endif // !_IMPORTS_H_
