/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file feedback.cpp
*   @brief Feedback generation
*/

#include "json.hpp"

#include <string>
#include <vector>
#include <ctime>
#include <codecvt>
#include <shared_mutex>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;


#include <Powerbase.h>
#include <intrin.h>

#include "winguest_status.h"
#include "dacia_types.h"
#include "feedback.h"
#include "smbios.h"
#include "common/boot/cpu_features.h"
#include "deploy_validation.h"
#include "load_monitor.h"
#include "version.h"
#include "base64.h"
#include "consts.h"
#include "reg_opts.h"
#include "helpers.h"
#include "libapis.h"
#include "event_timer.h"
#include "trace.h"
#include "feedback.tmh"

using json = nlohmann::json;

std::wstring            gFeedbackFolder;
static LONG volatile    gGeneratedFiles = 0;
extern EVENT_TIMER      gWinguestTimer;

FEEDBACK_OPTIONS gFeedbackCfg =
{
    FALSE,
    0,
    {
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE },
        { FEEDBACK_EXT_INTRO, FALSE }
    },
    {DEFAULT_THROTTLE_TIME}
};

extern BOOLEAN          gHypervisorConfigured;
extern bool volatile    gCloudUploadConfigured;

extern CPU_ENTRY               gCpu;
extern SMX_CAPABILITIES        gSmxCap;
extern VIRTUALIZATION_FEATURES gVirtFeat;


//////////////////////////////////////////////////////////////////////////
// FEEDBACK HELPERS
//

/**
 * @brief Save feedback to JSON file
 *
 * @param[in] Json                  Feedback json
 * @param[in] Config                Feedback per file type configuration
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
ProcessFeedbackJson(
    json &Json,
    FEEDBACK_FILE_CONFIG const * Config
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring filePath;
    LONG fileId = InterlockedIncrement(&gGeneratedFiles);
    std::string jsonContent;
    HANDLE jsonFile = INVALID_HANDLE_VALUE;
    DWORD writtenBytes = 0;

    // dump to disk

    if (gFeedbackCfg.LocalBackupDuration == 0)
    {
        status = STATUS_SUCCESS;
        goto cleanup;
    }

    if (gFeedbackFolder.empty())
    {
        LogError("no feedback folder configured");
        status = STATUS_OBJECT_PATH_SYNTAX_BAD;
        goto cleanup;
    }

    filePath = std::to_wstring(WINGUESTDLL_VERSION_REVISION) + L"-" + std::to_wstring(fileId) + L"-" + std::to_wstring(time(nullptr)) + L"." + CHAR_TO_WIDE(Config->Extension);

    LogInfo("Creating feedback file %S", filePath.c_str());

    jsonContent = Json.dump(4);

    filePath = gFeedbackFolder + filePath;

    jsonFile = CreateFile(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (jsonFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err != ERROR_PATH_NOT_FOUND)
        {
            LogFuncErrorLastErr(err, "CreateFile");
            status = WIN32_TO_NTSTATUS(err);
            goto cleanup;
        }

        // try to create the directory structure
        status = CreateDirectoryFullPath(gFeedbackFolder);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateDirectoryFullPath");
            goto cleanup;
        }

        jsonFile = CreateFile(
            filePath.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (jsonFile == INVALID_HANDLE_VALUE)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "CreateFile");
            goto cleanup;
        }
    }

    if (!WriteFile(jsonFile, jsonContent.c_str(), (DWORD)jsonContent.length(), &writtenBytes, NULL))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "WriteFile");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (jsonFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(jsonFile);
    }

    return status;
}

/**
 * @brief Clean up Feedback Folder thread
 *
 * This is a Event Timer Event thread
 */
void
CleanupFeedbackFolder(void)
{
    DWORD lastErr;
    HANDLE  hFind = INVALID_HANDLE_VALUE;
    SYSTEMTIME systemTime = {};
    FILETIME currentTime = {};
    LARGE_INTEGER currentVal = {};
    QWORD delta = gFeedbackCfg.LocalBackupDuration * 10000000;
    WIN32_FIND_DATA findFileData;
    std::wstring fileMask;
    std::wstring filePath;

    static std::shared_mutex cleanupMutex;
    std::unique_lock<std::shared_mutex> lock(cleanupMutex);

    GetSystemTime(&systemTime);

    if (SystemTimeToFileTime(&systemTime, &currentTime))
    {
        currentVal.HighPart = currentTime.dwHighDateTime;
        currentVal.LowPart  = currentTime.dwLowDateTime;
    }
    else
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SystemTimeToFileTime");
    }

    if (gFeedbackFolder.empty())
    {
        LogError("No feedback folder configured");
        goto cleanup;
    }

    fileMask = gFeedbackFolder;
    fileMask += L"*.*";

    hFind = FindFirstFile(fileMask.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        goto cleanup;
    }

    do
    {
        if (StopTimerPending(&gWinguestTimer))
        {
            break;
        }

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            continue;
        }

        filePath = gFeedbackFolder + findFileData.cFileName;

        // check if it is a feedback file
        for (INT32 i = 0; i < _countof(gFeedbackCfg.Files); i++)
        {
            BOOL deleteFile = FALSE;
            HANDLE file = INVALID_HANDLE_VALUE;
            DWORD extLength = (DWORD)strlen(gFeedbackCfg.Files[i].Extension);
            DWORD fileNameLength = (DWORD)wcslen(findFileData.cFileName);

            if (StopTimerPending(&gWinguestTimer))
            {
                break;
            }

            if (fileNameLength <= extLength
                || 0 != wcscmp(findFileData.cFileName + fileNameLength - extLength, CHAR_TO_WIDE(gFeedbackCfg.Files[i].Extension))
                || findFileData.cFileName[fileNameLength - extLength - 1] != '.') // avoid partial matches
            {
                continue;
            }

            {
                FILETIME creationTime = {};
                FILETIME accessTime = {};
                FILETIME writeTime = {};
                LARGE_INTEGER oldestVal;

                if (gFeedbackCfg.LocalBackupDuration == 0)
                {
                    deleteFile = TRUE;
                    goto cleanup_file;
                }

                file = CreateFile(
                    filePath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL
                );
                if (INVALID_HANDLE_VALUE == file)
                {
                    lastErr = GetLastError();
                    LogFuncErrorLastErr(lastErr, "CreateFile");
                    goto cleanup_file;
                }

                if (!GetFileTime(file, &creationTime, &accessTime, &writeTime))
                {
                    lastErr = GetLastError();
                    LogFuncErrorLastErr(lastErr, "GetFileTime");
                    goto cleanup_file;
                }

                oldestVal.HighPart = creationTime.dwHighDateTime;
                oldestVal.LowPart  = creationTime.dwLowDateTime;

                if ((UINT32)oldestVal.HighPart > accessTime.dwHighDateTime
                    || ((UINT32)oldestVal.HighPart == accessTime.dwHighDateTime && (UINT32)oldestVal.LowPart > accessTime.dwLowDateTime))
                {
                    oldestVal.HighPart = accessTime.dwHighDateTime;
                    oldestVal.LowPart  = accessTime.dwLowDateTime;
                }

                if ((UINT32)oldestVal.HighPart > writeTime.dwHighDateTime
                    || ((UINT32)oldestVal.HighPart == writeTime.dwHighDateTime && (UINT32)oldestVal.LowPart > writeTime.dwLowDateTime))
                {
                    oldestVal.HighPart = writeTime.dwHighDateTime;
                    oldestVal.LowPart  = writeTime.dwLowDateTime;
                }

                if ((UINT64)oldestVal.QuadPart + delta <= (UINT64)currentVal.QuadPart)
                {
                    deleteFile = TRUE;
                }
            }

        cleanup_file:
            if (INVALID_HANDLE_VALUE != file)
            {
                CloseHandle(file);
                file = INVALID_HANDLE_VALUE;
            }

            if (deleteFile)
            {
                if (!DeleteFile(filePath.c_str()))
                {
                    LogWarning("Failed to delete file. Register for reboot.");
                    if (!MoveFileEx(filePath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        lastErr = GetLastError();
                        LogFuncErrorLastErr(lastErr, "MoveFileEx");
                    }
                }
            }

            break;
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

cleanup:
    if (INVALID_HANDLE_VALUE != hFind)
    {
        FindClose(hFind);
    }
}

//////////////////////////////////////////////////////////////////////////
// COMMON FEEDBACK DATA HELPERS
//

/**
 * @brief Dump OS information
 *
 * @return json object
 */
static
json
AddOsInfo(
    )
{
    json root;
    std::string winName;
    BOOLEAN hasSP = FALSE;
    DWORD majorVersion = 0;
    DWORD minorVersion = 0;
    WORD servicePack = 0;
    DWORD buildNumber = 0;
    DWORD updateBuildRevision = 0;
    BYTE productType = 0;
    WORD suiteMask = 0;
    BOOLEAN is32 = FALSE;

    GetWindowsVersion(&majorVersion, &minorVersion, &servicePack, &buildNumber, &updateBuildRevision, &productType, &suiteMask, &is32);

    switch (majorVersion)
    {
        case 6: // Vista, 7, 8, 8.1 / Server 2008 (R2), 2012 (R2)
        {
            switch (minorVersion)
            {
            case 0:
                winName = productType == VER_NT_WORKSTATION ? "Vista" : "Server 2008";
                hasSP = TRUE;
                break;

            case 1:
                winName = productType == VER_NT_WORKSTATION ? "7" : "Server 2008 R2";
                hasSP = TRUE;
                break;

            case 2:
                winName = productType == VER_NT_WORKSTATION ? "8" : "Server 2012";
                break;

            case 3:
                winName = productType == VER_NT_WORKSTATION ? "8.1" : "Server 2012 R2";
                break;
            }
        }
        break;

        case 10: // 10 / Server 2016
        {
            switch (minorVersion)
            {
            case 0:
                winName = productType == VER_NT_WORKSTATION ? "10" : "Server 2016+";
                break;
            }
        }
        break;
    }


    root["Name"] = winName.empty() ? std::string("Windows ") + winName : "Windows";

    root["Version"] =
        std::to_string(majorVersion)
        + "." +
        std::to_string(minorVersion)
        + "." +
        std::to_string(buildNumber)
        + "." +
        std::to_string(updateBuildRevision);

    root["Build"] = buildNumber;

    if (hasSP)
    {
        root["ServicePack"] = servicePack;
    }

    root["Bits"] = is32 ? 32 : 64;

    root["ProductType"] = productType;
    root["SuiteMask"] = suiteMask;

    return root;
}

/**
 * @brief Dump Environment information
 *
 * @return json object
 */
static
json
GetEnvironmentInfo()
{
    NTSTATUS status;
    json root;
    DWORD verHigh = 0;
    DWORD verLow = 0;
    DWORD verRevision = 0;
    DWORD verBuild = 0;
    CHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD computerNameSize = _countof(computerName);
    BOOLEAN inVm = FALSE;
    SYSTEMTIME time = {};

    GetSystemTime(&time);
    root["Time"] =
        std::to_string(time.wHour)
        + ":" +
        std::to_string(time.wMinute)
        + ":" +
        std::to_string(time.wSecond)
        + "."+
        std::to_string(time.wMilliseconds);

    root["Date"] =
        std::to_string(time.wDay)
        + "." +
        std::to_string(time.wMonth)
        + "." +
        std::to_string(time.wYear);

#ifdef DEBUG
    root["DebugBuild"] = true;
#else
    root["DebugBuild"] = false;
#endif

    root["InternalFeedback"] = !!gFeedbackCfg.Internal;

#ifndef DEBUG
    if (gFeedbackCfg.Internal)
#endif
    {
        if (GetComputerNameA(computerName, &computerNameSize))
        {
            root["ComputerName"] = computerName;
        }
    }

    root["OperatingSystem"] = AddOsInfo();

    CheckInVm(&inVm);
    root["InVM"] = !!inVm;

    root["UefiBoot"] = !!IsUefiBootedOs();
    root["SecureBoot"] = !!IsSecureBootEnabled();

    status = WinguestGetComponentVersion(compWinguestDll, &verHigh, &verLow, &verRevision, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verRevision = 0;
        verBuild = 0;
    }

    root["Versions"]["WinguestDllVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verRevision)
        + "." +
        std::to_string(verBuild);

    status = WinguestGetComponentVersion(compWinguestSys, &verHigh, &verLow, &verRevision, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verRevision = 0;
        verBuild = 0;
    }

    root["Versions"]["WinguestSysVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verRevision)
        + "." +
        std::to_string(verBuild);

    status = WinguestGetComponentVersion(compNapoca, &verHigh, &verLow, &verRevision, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verRevision = 0;
        verBuild = 0;
    }

    root["Versions"]["NapocaVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verRevision)
        + "." +
        std::to_string(verBuild);

    status = WinguestGetComponentVersion(compIntro, &verHigh, &verLow, &verRevision, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verRevision = 0;
        verBuild = 0;
    }

    root["Versions"]["IntroVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verRevision)
        + "." +
        std::to_string(verBuild);

    status = WinguestGetComponentVersion(compIntroLiveUpdt, &verHigh, &verLow, NULL, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verBuild = 0;
    }

    root["Versions"]["IntroLiveUpdateVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verBuild);

    status = WinguestGetComponentVersion(compExceptions, &verHigh, &verLow, NULL, &verBuild);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "WinguestGetComponentVersion");
        verHigh = 0;
        verLow = 0;
        verBuild = 0;
    }

    root["Versions"]["ExceptionsVer"] =
        std::to_string(verHigh)
        + "." +
        std::to_string(verLow)
        + "." +
        std::to_string(verBuild);

    return root;
}

/**
 * @brief Dump CPU information
 *
 * @param[out] Json     Json object
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
AddCpuInfo(
    _In_ json &Json
)
{
    NTSTATUS status;
    CPUID_REGS cpuidRegs;
    CHAR hvName[13];    // 12 bytes + '\0'
    CHAR cpuName[49];   // 48 bytes + '\0'
    DWORD i = 0;
    POWER_PLATFORM_ROLE powerPlatformRole;

    try
    {
        // Check if system is inside a hypervisor.
        __cpuid((int*)&cpuidRegs, 0x1);
        Json["HypervisorPresent"] = !!(cpuidRegs.Ecx & HYPERVISOR_PRESENT_BIT);

        if (cpuidRegs.Ecx & HYPERVISOR_PRESENT_BIT)
        {
            json &hvNode = Json["HypervisorInfo"];

            __cpuid((int*)&cpuidRegs, 0x40000000);

            ((DWORD*)hvName)[0] = cpuidRegs.Ebx;
            ((DWORD*)hvName)[1] = cpuidRegs.Ecx;
            ((DWORD*)hvName)[2] = cpuidRegs.Edx;
            hvName[12] = '\0';    // string end

            hvNode["Name"] = hvName;

            json &cpuidNodeHv = hvNode["CPUID_40000000h"];

            cpuidNodeHv["Eax"] = cpuidRegs.Eax;
            cpuidNodeHv["Ebx"] = cpuidRegs.Ebx;
            cpuidNodeHv["Ecx"] = cpuidRegs.Ecx;
            cpuidNodeHv["Edx"] = cpuidRegs.Edx;

            __cpuid((int*)&cpuidRegs, 0x40000001);

            hvNode["CPUID_40000001h"]["Eax"] = cpuidRegs.Eax;
        }

        json &cpuidNode0 = Json["CPUID_00h"];

        __cpuid((int*)&cpuidRegs, 0x0);

        cpuidNode0["Eax"] = cpuidRegs.Eax;
        cpuidNode0["Ebx"] = cpuidRegs.Ebx;
        cpuidNode0["Ecx"] = cpuidRegs.Ecx;
        cpuidNode0["Edx"] = cpuidRegs.Edx;

        json &cpuidNode1 = Json["CPUID_01h"];

        __cpuid((int*)&cpuidRegs, 0x1);

        cpuidNode1["Eax"] = cpuidRegs.Eax;
        cpuidNode1["Ebx"] = cpuidRegs.Ebx;
        cpuidNode1["Ecx"] = cpuidRegs.Ecx;
        cpuidNode1["Edx"] = cpuidRegs.Edx;

        Json["Manufacturer"] = gCpu.Name;

        for (i = 0; i < 3; i++) // 0x80000002 -> 0x80000004
        {
            __cpuid((int*)&cpuidRegs, 0x80000002 + i);
            ((DWORD*)cpuName)[0 + (i * 4)] = cpuidRegs.Eax;
            ((DWORD*)cpuName)[1 + (i * 4)] = cpuidRegs.Ebx;
            ((DWORD*)cpuName)[2 + (i * 4)] = cpuidRegs.Ecx;
            ((DWORD*)cpuName)[3 + (i * 4)] = cpuidRegs.Edx;
        }
        cpuName[48] = '\0'; // string end

        Json["Brand"] = cpuName;

        if (gCpu.ProcessorType.Intel)
        {
            Json["Vendor"] = "Intel";

            Json["VMX"] = (DWORD)gCpu.MiscIntelFeatures.VMX;
            Json["x64"] = (DWORD)gCpu.MiscIntelFeatures.x64;
            Json["EPT"] = (DWORD)gCpu.MiscIntelFeatures.EPT;
            Json["VPID"] = (DWORD)gCpu.MiscIntelFeatures.VPID;
            Json["x2APIC"] = (DWORD)gCpu.MiscIntelFeatures.x2APIC;
            Json["x2APICEn"] = (DWORD)gCpu.MiscIntelFeatures.x2APICEn;
            Json["DMT"] = (DWORD)gCpu.MiscIntelFeatures.DMT;
            Json["InvariantTSC"] = (DWORD)gCpu.MiscIntelFeatures.InvariantTSC;
            Json["XCR0"] = (DWORD)gCpu.MiscIntelFeatures.XCR0;
            Json["CMPXCHG16B"] = (DWORD)gCpu.MiscIntelFeatures.CMPXCHG16B;
            Json["AVX"] = (DWORD)gCpu.MiscIntelFeatures.AVX;
            Json["Page1GB"] = (DWORD)gCpu.MiscIntelFeatures.Page_1GB;
            Json["APICv"] = (DWORD)gCpu.MiscIntelFeatures.APICv;
            Json["ApicRegVirt"] = (DWORD)gCpu.MiscIntelFeatures.ApicRegVirt;
            Json["EptVe"] = (DWORD)gCpu.MiscIntelFeatures.EptVe;

            Json["SMX"] = (DWORD)gCpu.IntelFeatures.Ecx.SMX;
            Json["SmxCapabilities"] = gSmxCap.SmxCapabilities0Raw;
            Json["TXT"] = (DWORD)gSmxCap.SmxCapabilities0.TxtChipsetPresent;

            Json["ApicBase"] = gCpu.LocalApicBase;
            Json["Stepping"] = (DWORD)gCpu.FamilyFields.Stepping;
            Json["Model"] = (DWORD)gCpu.FamilyFields.Model;
            Json["Family"] = (DWORD)gCpu.FamilyFields.Family;
            Json["ExtendedModel"] = (DWORD)gCpu.FamilyFields.ExtendedModel;
            Json["ExtendedFamily"] = (DWORD)gCpu.FamilyFields.ExtendedFamily;
            Json["PhysicalAddressWidth"] = gCpu.Addressability.PhysicalAddressWidth;
            Json["VirtualAddressWidth"] = gCpu.Addressability.VirtualAddressWidth;

            Json["VmxBasic"] = gVirtFeat.VmxBasic.Raw;
            Json["VmxPinBased"] = gVirtFeat.VmxPinBased.Raw;
            Json["VmxProcBased"] = gVirtFeat.VmxProcBased.Raw;
            Json["VmxProcBased2"] = gVirtFeat.VmxProcBased2.Raw;
            Json["VmxEntry"] = gVirtFeat.VmxEntry.VmxEntryRaw;
            Json["VmxExit"] = gVirtFeat.VmxExit.VmxExitRaw;
            Json["VmxMisc"] = gVirtFeat.VmxMisc.VmxMiscRaw;
            Json["MsrFeatureControl"] = gVirtFeat.MsrFeatureControl;
            Json["MsrEptVpid"] = gVirtFeat.EptVpidFeatures.Raw;
        }
        else if (gCpu.ProcessorType.AMD)
        {
            Json["Vendor"] = "AMD";

            Json["SVM"] = (DWORD)gCpu.MiscAmdFeatures.SVM;
            Json["x64"] = (DWORD)gCpu.MiscAmdFeatures.x64;
            Json["NP"] = (DWORD)gCpu.MiscAmdFeatures.NP;
            Json["ASID"] = (DWORD)gCpu.MiscAmdFeatures.ASID;
            Json["x2APIC"] = (DWORD)gCpu.MiscAmdFeatures.x2APIC;
            Json["x2APICEn"] = (DWORD)gCpu.MiscAmdFeatures.x2APICEn;
            Json["DMT"] = (DWORD)gCpu.MiscAmdFeatures.DMT;
            Json["InvariantTSC"] = (DWORD)gCpu.MiscAmdFeatures.InvariantTSC;
            Json["XCR0"] = (DWORD)gCpu.MiscAmdFeatures.XCR0;
            Json["CMPXCHG16B"] = (DWORD)gCpu.MiscAmdFeatures.CMPXCHG16B;
            Json["AVX"] = (DWORD)gCpu.MiscAmdFeatures.AVX;
            Json["Page1GB"] = (DWORD)gCpu.MiscAmdFeatures.Page_1GB;

        }
        else
        {
            Json["Vendor"] = "Unknown";
        }

        Json["ConnectedStandby"] = !!GetConnectedStandbySupport();

        GetPowerPlatformRole(&powerPlatformRole);
        Json["PowerPlatformRole"] = powerPlatformRole;

        status = STATUS_SUCCESS;
    }
    catch (json::exception &ex)
    {
        LogError("json exception %d: %s", ex.id, ex.what());
        status = STATUS_JSON_EXCEPTION_ENCOUNTERED;
    }

    return status;
}

/**
 * @brief Dump SMBIOS information
 *
 * @param[out] Json     Json object
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
AddSmBiosInfo(
    _In_ json &Json
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    LSTATUS error;

    std::vector<BYTE> data;

    try
    {
        DWORD dataSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (0 == dataSize)
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "GetSystemFirmwareTable");
            goto cleanup_firmware;
        }

        data.resize(dataSize);

        dataSize = GetSystemFirmwareTable('RSMB', 0, data.data(), static_cast<DWORD>(data.size()));
        if (0 == dataSize)
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "GetSystemFirmwareTable");
            goto cleanup_firmware;
        }

        status = STATUS_SUCCESS;

    cleanup_firmware:

        if (!NT_SUCCESS(status)) // we couldn't get data from Firmware Tables directly, try from registry
        {
            error = RegGetValue(
                HKEY_LOCAL_MACHINE,
                REG_SUBKEY_SMBIOS,
                L"SMBiosData",
                RRF_RT_REG_BINARY,
                NULL,
                NULL,
                &dataSize
            );
            if (error != ERROR_SUCCESS)
            {
                LogFuncErrorHr(error, "RegGetValue");
                status = WIN32_TO_NTSTATUS(error);
                goto cleanup;
            }

            data.resize(dataSize);

            error = RegGetValue(
                HKEY_LOCAL_MACHINE,
                REG_SUBKEY_SMBIOS,
                L"SMBiosData",
                RRF_RT_REG_BINARY,
                NULL,
                &data[0],
                &dataSize
            );
            if (error != ERROR_SUCCESS)
            {
                LogFuncErrorHr(error, "RegGetValue");
                status = WIN32_TO_NTSTATUS(error);
                goto cleanup;
            }
        }

        SMBIOS_WIN_ENTRY_POINT const* start = reinterpret_cast<SMBIOS_WIN_ENTRY_POINT*>(data.data());

        Json["Major"] = start->SMBIOSMajorVersion;
        Json["Minor"] = start->SMBIOSMinorVersion;

        json &biosNode = Json["Bios"];

        SMBIOS_STRUCTURE_POINTER const *table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 0, 0);

        biosNode["Vendor"] = SmbiosGetString(table, table->Type0.Vendor);
        biosNode["Version"] = SmbiosGetString(table, table->Type0.BiosVersion);
        biosNode["Date"] = SmbiosGetString(table, table->Type0.BiosReleaseDate);


        json &systemNode = Json["System"];

        table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 1, 0);

        systemNode["Manufacturer"] = SmbiosGetString(table, table->Type1.Manufacturer);
        systemNode["ProductName"] = SmbiosGetString(table, table->Type1.ProductName);
        systemNode["FamilyData"] = SmbiosGetString(table, table->Type1.Family);

        json &mainboardNode = Json["Mainboard"];

        table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 2, 0);

        mainboardNode["Manufacturer"] = SmbiosGetString(table, table->Type2.Manufacturer);
        mainboardNode["ProductName"] = SmbiosGetString(table, table->Type2.ProductName);
        mainboardNode["Family"] = SmbiosGetString(table, table->Type2.Version);

        json &chassisNode = Json["Chassis"];

        table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 3, 0);

        chassisNode["Manufacturer"] = SmbiosGetString(table, table->Type3.Manufacturer);
        chassisNode["Type"] = table->Type3.Type;

        json &cpuNode = Json["CPU"];
        DWORD index = 0;

        table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 4, index);
        while (NULL != table)
        {
            json childNode;

            childNode["Socket"] = SmbiosGetString(table, table->Type4.Socket);
            childNode["Manufacturer"] = SmbiosGetString(table, table->Type4.ProcessorManufacture);
            childNode["Version"] = SmbiosGetString(table, table->Type4.ProcessorVersion);
            childNode["Family"] = (QWORD)table->Type4.ProcessorFamily;
            childNode["Features"] =(QWORD)table->Type4.ProcessorId.FeatureFlags;

            if (start->SMBIOSMajorVersion == 2 && start->SMBIOSMinorVersion >= 5 || start->SMBIOSMajorVersion > 2)
            {
                childNode["Cores"] = (QWORD)table->Type4.CoreCount;
                childNode["EnCores"] = (QWORD)table->Type4.EnabledCoreCount;
                childNode["Threads"] = (QWORD)table->Type4.ThreadCount;
            }

            cpuNode.push_back(childNode);

            index += 1;
            table = SmbiosGetTableFromType(start->SMBIOSTableData, start->Length, 4, index);
        }

        status = STATUS_SUCCESS;
    }
    catch (json::exception &ex)
    {
        LogError("json exception %d: %s", ex.id, ex.what());
        status = STATUS_JSON_EXCEPTION_ENCOUNTERED;
    }

cleanup:

    return status;
}

/**
 * @brief Dump Hardware information
 *
 * @param[out] Json     Json object
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
AddHardwareInfo(
    _In_ json &Json
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    MEMORYSTATUSEX memStatus = {};

    try
    {
        memStatus.dwLength = sizeof(memStatus);

        if (GlobalMemoryStatusEx(&memStatus))
        {
            Json["RAMPresent"] = ROUND_UP(memStatus.ullTotalPhys, 8 * ONE_MEGABYTE); // rounded up to 8MB to avoid small variations (caused by debug flag, etc)
            Json["RAMUsable"] = memStatus.ullAvailPhys;
        }
        else
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "GlobalMemoryStatusEx");
        }

        status = AddSmBiosInfo(Json["SmBios"]);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "AddSmBiosInfo");
        }

        status = AddCpuInfo(Json["CpuFeatures"]);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "AddCpuInfo");
            goto cleanup;
        }

        status = STATUS_SUCCESS;
    }
    catch (json::exception &ex)
    {
        LogError("json exception %d: %s", ex.id, ex.what());
        status = STATUS_JSON_EXCEPTION_ENCOUNTERED;
    }

cleanup:
    return status;
}

/**
 * @brief Generate compatibility feedback (computer hardware and software information)
 *
 * @param[out] jsonRoot     Json object
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
FeedbackWriteCompatHwInfo(
    _In_ json &jsonRoot
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN hvStarted = FALSE;
    BOOT_MODE bootMode = bootUnknown;
    HV_CONFIGURATION_MISSING_FEATURES features = {};

    try
    {
        jsonRoot["Environment"] = GetEnvironmentInfo();

        status = AddHardwareInfo(jsonRoot);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "AddHardwareInfo");
            goto cleanup;
        }

        status = WinguestGetHvStatus(NULL, &hvStarted, &bootMode);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WinguestGetHvStatus");
        }

        jsonRoot["HvStarted"] = !!hvStarted;

        jsonRoot["HvBootMode"] = bootMode;

        status = ValidateHvConfiguration(&features);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetLoadMonitorData");
        }

        jsonRoot["MissingFeatures0"] = features.MissingFeatures[0];
        jsonRoot["MissingFeatures1"] = features.MissingFeatures[1];
        jsonRoot["MissingFeatures2"] = features.MissingFeatures[2];
        jsonRoot["MissingFeatures3"] = features.MissingFeatures[3];

        jsonRoot["HVConfigured"] = !!gHypervisorConfigured;

        status = STATUS_SUCCESS;
    }
    catch (json::exception &ex)
    {
        LogError("json exception %d: %s", ex.id, ex.what());
        status = STATUS_JSON_EXCEPTION_ENCOUNTERED;
    }
cleanup:
    return status;
}


//////////////////////////////////////////////////////////////////////////
// INTROSPECTION FEEDBACK
//

// We have some asserts to catch struct changes. Best Effort. Won't error on all changes.
// Will not catch changes where the size of the struct stays constant and can not test for changes in enums.

/**
 * @brief Serialize WCHAR strings. Will convert to CHAR string and also dump words to enable reconstruction
 *
 * @param[out] JsonObj      Json object
 * @param[in]  Key          Key in json
 * @param[in]  String       String value
 */
template < size_t Size >
static
void
IntroSerializeWchar(
    _Inout_ json &JsonObj,
    _In_ std::string const& Key,
    _In_ WCHAR const (&String)[Size]
    )
{
    JsonObj[Key + "_truncated"] = WIDE_TO_CHAR(String);

    bool ascii = true;

    for (size_t i = 0; i < Size && String[i] && ascii; ascii = String[i++] <= 0x7F);

    if (ascii)
        return;

    // place array of words in order to be able to reconstruct the text
    for (size_t i = 0; i < Size && String[i]; i++)
    {
        JsonObj[Key][i] = String[i];
    }
}

/**
 * @brief Serialize buffers into BASE64
 *
 * @param[in]  Buffer       Buffer to convert
 *
 * @return BASE64 string
 */
template < size_t Size >
static
std::string
IntroSerializeToBase64(
    _In_ BYTE const (&Buffer)[Size]
)
{
    CHAR base64[GetToBase64Size(Size)] = {};
    NTSTATUS status = Tobase64(base64, Buffer, Size, sizeof(base64));
    if (NT_SUCCESS(status))
    {
        return base64;
    }

    return "";
}

/**
 * @brief Serialize INTRO_ACTION
 *
 * @param[in] Action
 *
 * @return string
 */
static
std::string
IntroSerializeAction(
    INTRO_ACTION const& Action
)
{
    switch (Action)
    {
    case introGuestAllowed:
        return "introGuestAllowed";

    case introGuestAllowedVirtual:
        return "introGuestAllowedVirtual";

    case introGuestAllowedPatched:
        return "introGuestAllowedPatched";

    case introGuestNotAllowed:
        return "introGuestNotAllowed";

    case introGuestIgnore:
        return "introGuestIgnore";

    case introGuestRetry:
        return "introGuestRetry";

    default:
        LogWarning("Received alert with unknown Header.Action: %d", Action);
        return std::to_string(Action);
    }
}

/**
 * @brief Serialize INTRO_ACTION_REASON
 *
 * @param[in] Reason
 *
 * @return string
 */
static
std::string
IntroSerializeActionReason(
    INTRO_ACTION_REASON const& Reason
)
{
    static_assert(introReasonUnknown == 14, "Serialization of INTRO_ACTION_REASON must be updated!");

    switch (Reason)
    {
    case introReasonAllowed:
        return "introReasonAllowed";

    case introReasonAllowedFeedback:
        return "introReasonAllowedFeedback";

    case introReasonSignatureNotMatched:
        return "introReasonSignatureNotMatched";

    case introReasonNoException:
        return "introReasonNoException";

    case introReasonExtraChecksFailed:
        return "introReasonExtraChecksFailed";

    case introReasonExceptionsNotLoaded:
        return "introReasonExceptionsNotLoaded";

    case introReasonInternalError:
        return "introReasonInternalError";

    case introReasonValueCodeNotMatched:
        return "introReasonValueCodeNotMatched";

    case introReasonValueNotMatched:
        return "introReasonValueNotMatched";

    case introReasonExportNotMatched:
        return "introReasonExportNotMatched";

    case introReasonIdtNotMatched:
        return "introReasonIdtNotMatched";

    case introReasonVersionOsNotMatched:
        return "introReasonVersionOsNotMatched";

    case introReasonVersionIntroNotMatched:
        return "introReasonVersionIntroNotMatched";

    case introReasonProcessCreationNotMatched:
        return "introReasonProcessCreationNotMatched";

    case introReasonUnknown:
        return "introReasonUnknown";

    default:
        LogWarning("Received alert with unknown Reason: %d", Reason);
        return std::to_string(Reason);
    }
}

/**
 * @brief Serialize INTRO_OBJECT_TYPE
 *
 * @param[in] Type
 *
 * @return string
 */
static
std::string
IntroSerializeObjectType(
    INTRO_OBJECT_TYPE const& Type
)
{
    static_assert(introObjectTypeTest == 35, "Serialization of INTRO_OBJECT_TYPE must be updated!");

    switch (Type)
    {
    case introObjectTypeRaw:
        return "introObjectTypeRaw";

    case introObjectTypeInternal:
        return "introObjectTypeInternal";

    case introObjectTypeSsdt:
        return "introObjectTypeSsdt";

    case introObjectTypeFastIoDispatch:
        return "introObjectTypeFastIoDispatch";

    case introObjectTypeDriverObject:
        return "introObjectTypeDriverObject";

    case introObjectTypeKmModule:
        return "introObjectTypeKmModule";

    case introObjectTypeIdt:
        return "introObjectTypeIdt";

    case introObjectTypeGdt:
        return "introObjectTypeGdt";

    case introObjectTypeKmUnpack:
        return "introObjectTypeKmUnpack";

    case introObjectTypeProcess:
        return "introObjectTypeProcess";

    case introObjectTypeUmInternal:
        return "introObjectTypeUmInternal";

    case introObjectTypeUmUnpack:
        return "introObjectTypeUmUnpack";

    case introObjectTypeUmHeap:
        return "introObjectTypeUmHeap";

    case introObjectTypeUmStack:
        return "introObjectTypeUmStack";

    case introObjectTypeUmGenericNxZone:
        return "introObjectTypeUmGenericNxZone";

    case introObjectTypeUmModule:
        return "introObjectTypeUmModule";

    case introObjectTypeDetourRead:
        return "introObjectTypeDetourRead";

    case introObjectTypeTokenPtr:
        return "introObjectTypeTokenPtr";

    case introObjectTypeHalDispatchTable:
        return "introObjectTypeHalDispatchTable";

    case introObjectTypeHalIntController:
        return "introObjectTypeHalIntController";

    case introObjectTypeSelfMapEntry:
        return "introObjectTypeSelfMapEntry";

    case introObjectTypeHalHeap:
        return "introObjectTypeHalHeap";

    case introObjectTypeVdso:
        return "introObjectTypeVdso";

    case introObjectTypeVsyscall:
        return "introObjectTypeVsyscall";

    case introObjectTypeExTable:
        return "introObjectTypeExTable";

    case introObjectTypeVeAgent:
        return "introObjectTypeVeAgent";

    case introObjectTypeIdtr:
        return "introObjectTypeIdtr";

    case introObjectTypeGdtr:
        return "introObjectTypeGdtr";

    case introObjectTypeProcessCreation:
        return "introObjectTypeProcessCreation";

    case introObjectTypeExecSuspiciousDll:
        return "introObjectTypeExecSuspiciousDll";

    case introObjectTypeKmLoggerContext:
        return "introObjectTypeKmLoggerContext";

    case introObjectTypeProcessCreationDpi:
        return "introObjectTypeProcessCreationDpi";

    case introObjectTypeTokenPrivs:
        return "introObjectTypeTokenPrivs";

    case introObjectTypeSharedUserData:
        return "introObjectTypeSharedUserData";

    case introObjectTypeTest:
        return "introObjectTypeTest";

    default:
        LogWarning("Received alert with unknown Victim.Type: %d", Type);
        return std::to_string(Type);
    }
}

/**
 * @brief Serialize TRANS_VIOLATION_TYPE
 *
 * @param[in] Type
 *
 * @return string
 */
static
std::string
IntroSerializeTransViolationType(
    TRANS_VIOLATION_TYPE const& Type
)
{
    switch (Type)
    {
    case transViolationPageHash:
        return "transViolationPageHash";

    case transViolationProcessCr3:
        return "transViolationProcessCr3";

    case transViolationSelfMap:
        return "transViolationSelfMap";

    case transViolationWatchdog:
        return "transViolationWatchdog";

    case transViolationVeAgent:
        return "transViolationVeAgent";

    default:
        LogWarning("Received alert with unknown Type: %d", Type);
        return std::to_string(Type);
    }
}

/**
 * @brief Serialize MEMCOPY_VIOLATION_TYPE
 *
 * @param[in] Type
 *
 * @return string
 */
static
std::string
IntroSerializeMemCopyViolationType(
    MEMCOPY_VIOLATION_TYPE const& Type
)
{
    switch (Type)
    {
    case memCopyViolationWrite:
        return "memCopyViolationWrite";

    case memCopyViolationRead:
        return "memCopyViolationRead";

    case memCopyViolationSetContextThread:
        return "memCopyViolationSetContextThread";

    case memCopyViolationQueueApcThread:
        return "memCopyViolationQueueApcThread";

    default:
        LogWarning("Received alert with unknown Type: %d", Type);
        return std::to_string(Type);
    }
}

/**
 * @brief Serialize INTRO_PC_VIOLATION_TYPE
 *
 * @param[in] Type
 *
 * @return string
 */
static
std::string
IntroSerializePcViolationType(
    INTRO_PC_VIOLATION_TYPE const& Type
)
{
    switch (Type)
    {
    case INT_PC_VIOLATION_NORMAL_PROCESS_CREATION:
        return "INT_PC_VIOLATION_NORMAL_PROCESS_CREATION";

    case INT_PC_VIOLATION_DPI_DEBUG_FLAG:
        return "INT_PC_VIOLATION_DPI_DEBUG_FLAG";

    case INT_PC_VIOLATION_DPI_PIVOTED_STACK:
        return "INT_PC_VIOLATION_DPI_PIVOTED_STACK";

    case INT_PC_VIOLATION_DPI_STOLEN_TOKEN:
        return "INT_PC_VIOLATION_DPI_STOLEN_TOKEN";

    case INT_PC_VIOLATION_DPI_HEAP_SPRAY:
        return "INT_PC_VIOLATION_DPI_HEAP_SPRAY";

    case INT_PC_VIOLATION_DPI_TOKEN_PRIVS:
        return "INT_PC_VIOLATION_DPI_TOKEN_PRIVS";

    case INT_PC_VIOLATION_DPI_THREAD_START:
        return "INT_PC_VIOLATION_DPI_THREAD_START";

    default:
        LogWarning("Received alert with unknown Type: %d", Type);
        return std::to_string(Type);
    }
}

/**
 * @brief Serialize INTRO_TOKEN_PRIVILEGES
 *
 * @param[in] Privileges
 *
 * @return json object
 */
static
json
IntroSerializeTokenPrivileges(
    _In_ INTRO_TOKEN_PRIVILEGES const& Privileges
    )
{
    static_assert(sizeof(INTRO_TOKEN_PRIVILEGES) == 24, "Serialization of INTRO_TOKEN_PRIVILEGES must be updated!");

    json root;

    // copied from hvmi -> visibility.c
    static const CHAR* privilegesToString[] = {
        /* 00 */ NULL,
        /* 01 */ NULL,
        /* 02 */ "SeCreateTokenPrivilege",
        /* 03 */ "SeAssignPrimaryTokenPrivilege",
        /* 04 */ "SeLockMemoryPrivilege",
        /* 05 */ "SeIncreaseQuotaPrivilege",
        /* 06 */ "SeMachineAccountPrivilege",
        /* 07 */ "SeTcbPrivilege",
        /* 08 */ "SeSecurityPrivilege",
        /* 09 */ "SeTakeOwnershipPrivilege",
        /* 10 */ "SeLoadDriverPrivilege",
        /* 11 */ "SeSystemProfilePrivilege",
        /* 12 */ "SeSystemtimePrivilege",
        /* 13 */ "SeProfileSingleProcessPrivilege",
        /* 14 */ "SeIncreaseBasePriorityPrivilege",
        /* 15 */ "SeCreatePagefilePrivilege",
        /* 16 */ "SeCreatePermanentPrivilege",
        /* 17 */ "SeBackupPrivilege",
        /* 18 */ "SeRestorePrivilege",
        /* 19 */ "SeShutdownPrivilege",
        /* 20 */ "SeDebugPrivilege",
        /* 21 */ "SeAuditPrivilege",
        /* 22 */ "SeSystemEnvironmentPrivilege",
        /* 23 */ "SeChangeNotifyPrivilege",
        /* 24 */ "SeRemoteShutdownPrivilege",
        /* 25 */ "SeUndockPrivilege",
        /* 26 */ "SeSyncAgentPrivilege",
        /* 27 */ "SeEnableDelegationPrivilege",
        /* 28 */ "SeManageVolumePrivilege",
        /* 29 */ "SeImpersonatePrivilege",
        /* 30 */ "SeCreateGlobalPrivilege",
        /* 31 */ "SeTrustedCredManAccessPrivilege",
        /* 32 */ "SeRelabelPrivilege",
        /* 33 */ "SeIncreaseWorkingSetPrivilege",
        /* 34 */ "SeTimeZonePrivilege",
        /* 35 */ "SeCreateSymbolicLinkPrivilege",
    };

    for (DWORD i = 2; i < _countof(privilegesToString); i++)
        if (Privileges.Present & ((QWORD)1 << i))
            root["Present"].push_back(privilegesToString[i]);

    for (DWORD i = 2; i < _countof(privilegesToString); i++)
        if (Privileges.Enabled & ((QWORD)1 << i))
            root["Enabled"].push_back(privilegesToString[i]);

    for (DWORD i = 2; i < _countof(privilegesToString); i++)
        if (Privileges.EnabledByDefault & ((QWORD)1 << i))
            root["EnabledByDefault"].push_back(privilegesToString[i]);

    return root;
}

/**
 * @brief Serialize INTRO_WIN_SID
 *
 * @param[in] Sid
 *
 * @return json object
 */
static
json
IntroSerializeWinSid(
    INTRO_WIN_SID const& Sid
)
{
    static_assert(sizeof(INTRO_WIN_SID) == 12, "Serialization of INTRO_WIN_SID must be updated!");

    json root;

    root["Revision"] = Sid.Revision;
    root["SubAuthorityCount"] = Sid.SubAuthorityCount;

    for (DWORD i = 0; i < _countof(Sid.IdentifierAuthority); i++)
        root["IdentifierAuthority"][i] = Sid.IdentifierAuthority[i];

    root["SubAuthority"][0] = Sid.SubAuthority[0];

    return root;
}

/**
 * @brief Serialize INTRO_SID_ATTRIBUTES
 *
 * @param[in] SidAttr
 *
 * @return json object
 */
static
json
IntroSerializeSidAttributes(
    INTRO_SID_ATTRIBUTES const& SidAttr
)
{
    static_assert(sizeof(INTRO_SID_ATTRIBUTES) == 76, "Serialization of INTRO_SID_ATTRIBUTES must be updated!");

    json root;
    PCHAR sid = NULL;

    root["IsRestricted"] = !!SidAttr.IsRestricted;

    if (SidAttr.Attributes & SE_GROUP_MANDATORY)            root["Attributes"].push_back("SE_GROUP_MANDATORY");
    if (SidAttr.Attributes & SE_GROUP_ENABLED_BY_DEFAULT)   root["Attributes"].push_back("SE_GROUP_ENABLED_BY_DEFAULT");
    if (SidAttr.Attributes & SE_GROUP_ENABLED)              root["Attributes"].push_back("SE_GROUP_ENABLED");
    if (SidAttr.Attributes & SE_GROUP_OWNER)                root["Attributes"].push_back("SE_GROUP_OWNER");
    if (SidAttr.Attributes & SE_GROUP_USE_FOR_DENY_ONLY)    root["Attributes"].push_back("SE_GROUP_USE_FOR_DENY_ONLY");
    if (SidAttr.Attributes & SE_GROUP_INTEGRITY)            root["Attributes"].push_back("SE_GROUP_INTEGRITY");
    if (SidAttr.Attributes & SE_GROUP_INTEGRITY_ENABLED)    root["Attributes"].push_back("SE_GROUP_INTEGRITY_ENABLED");
    if (SidAttr.Attributes & SE_GROUP_LOGON_ID)             root["Attributes"].push_back("SE_GROUP_LOGON_ID");
    if (SidAttr.Attributes & SE_GROUP_RESOURCE)             root["Attributes"].push_back("SE_GROUP_RESOURCE");

    if (ConvertSidToStringSidA(const_cast<BYTE*>(SidAttr.RawBuffer), &sid))
    {
        root["Sid"] = sid;
        LocalFree(sid);
    }
    else
    {
        DWORD lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "ConvertSidToStringSid");

        root["Sid"] = IntroSerializeWinSid(SidAttr.Sid);
    }

    return root;
}

/**
 * @brief Serialize INTRO_WIN_TOKEN
 *
 * @param[in] Token
 *
 * @return json object
 */
static
json
IntroSerializeWinToken(
    INTRO_WIN_TOKEN const& Token
)
{
    static_assert(sizeof(INTRO_WIN_TOKEN) == 656, "Serialization of INTRO_WIN_TOKEN must be updated!");

    json root;

    root["Valid"] = !!Token.Valid;

    if (!Token.Valid)
    {
        return root;
    }

    root["ImpersonationToken"] = !!Token.ImpersonationToken;

    root["Privileges"] = IntroSerializeTokenPrivileges(Token.Privileges);

    root["SidCount"] = Token.SidCount;
    for (DWORD i = 0; i < Token.SidCount; i++)
    {
        root["SidsAndAttributes"][i] = IntroSerializeSidAttributes(Token.SidsAndAttributes[i]);
    }

    root["RestrictedSidCount"] = Token.RestrictedSidCount;
    for (DWORD i = 0; i < Token.RestrictedSidCount; i++)
    {
        root["RestrictedSids"][i] = IntroSerializeSidAttributes(Token.RestrictedSids[i]);
    }

    root["SidsBufferTooSmall"] = !!Token.SidsBufferTooSmall;
    root["RestrictedSIdsBufferTooSmall"] = !!Token.RestrictedSIdsBufferTooSmall;

    return root;
}

/**
 * @brief Serialize INTRO_TOKEN
 *
 * @param[in] Token
 *
 * @return json object
 */
static
json
IntroSerializeToken(
    INTRO_TOKEN const& Token
)
{
    static_assert(sizeof(INTRO_TOKEN) == 656, "Serialization of INTRO_TOKEN must be updated!");

    json root;

    root["WindowsToken"] = IntroSerializeWinToken(Token.WindowsToken);

    return root;
}

/**
 * @brief Serialize INTRO_PROCESS
 *
 * @param[in] Process
 *
 * @return json object
 */
static
json
IntroSerializeProcess(
    _In_ INTRO_PROCESS const& Process
    )
{
    static_assert(sizeof(INTRO_PROCESS) == 1744, "Serialization of INTRO_PROCESS must be updated!");

    json root;

    root["Valid"] = !!Process.Valid;

    if (!Process.Valid)
    {
        return root;
    }

    root["Pid"] = Process.Pid;
    root["Cr3"] = Process.Cr3;
    root["CreationTime"] = Process.CreationTime;
    root["ImageName"] = Process.ImageName;
    IntroSerializeWchar(root, "Path", Process.Path);
    root["SecurityInfo"] = IntroSerializeToken(Process.SecurityInfo);
    root["CmdLine"] = Process.CmdLine;
    root["Context"] = Process.Context;
    root["Wow64"] = Process.Wow64;

    return root;
}

/**
 * @brief Serialize INTRO_MODULE
 *
 * @param[in] Module
 *
 * @return json object
 */
static
json
IntroSerializeModule(
    _In_ INTRO_MODULE const& Module
    )
{
    static_assert(sizeof(INTRO_MODULE) == 1064, "Serialization of INTRO_MODULE must be updated!");

    json root;
    root["Valid"] = !!Module.Valid;

    if (!Module.Valid)
    {
        return root;
    }

    root["Base"] = Module.Base;
    root["Size"] = Module.Size;
    root["TimeDateStamp"] =  Module.TimeDateStamp;
    IntroSerializeWchar(root, "Name", Module.Name);
    IntroSerializeWchar(root, "Path", Module.Path);

    return root;
}

/**
 * @brief Serialize INTRO_DRVOBJ
 *
 * @param[in] Drvobj
 *
 * @return json object
 */
static
json
IntroSerializeDrvobj(
    _In_ INTRO_DRVOBJ const& Drvobj
)
{
    static_assert(sizeof(INTRO_DRVOBJ) == 544, "Serialization of INTRO_DRVOBJ must be updated!");

    json root;
    root["Valid"] = !!Drvobj.Valid;

    if (!Drvobj.Valid)
    {
        return root;
    }

    root["Address"] = Drvobj.Address;
    IntroSerializeWchar(root, "Name", Drvobj.Name);
    root["Owner"] = Drvobj.Owner;

    return root;
}

/**
 * @brief Serialize INTRO_WRITE_INFO
 *
 * @param[in] WriteInfo
 *
 * @return json object
 */
static
json
IntroSerializeWriteInfo(
    _In_ INTRO_WRITE_INFO const& WriteInfo
    )
{
    static_assert(sizeof(INTRO_WRITE_INFO) == 136, "Serialization of INTRO_WRITE_INFO must be updated!");

    json root;

    for (DWORD i = 0; i < _countof(WriteInfo.OldValue); i++)
        root["OldValue"][i] = WriteInfo.OldValue[i];

    for (DWORD i = 0; i < _countof(WriteInfo.NewValue); i++)
        root["NewValue"][i] = WriteInfo.NewValue[i];

    root["Size"] = WriteInfo.Size;

    return root;
}

/**
 * @brief Serialize INTRO_EXEC_INFO
 *
 * @param[in] ExecInfo
 *
 * @return json object
 */
static
json
IntroSerializeExecInfo(
    _In_ INTRO_EXEC_INFO const& ExecInfo
)
{
    static_assert(sizeof(INTRO_EXEC_INFO) == 32, "Serialization of INTRO_EXEC_INFO must be updated!");

    json root;

    root["Rsp"] = ExecInfo.Rsp;
    root["StackBase"] = ExecInfo.StackBase;
    root["StackLimit"] = ExecInfo.StackLimit;
    root["Length"] = ExecInfo.Length;

    return root;
}

/**
 * @brief Serialize INTRO_CODEBLOCKS
 *
 * @param[in] Codeblocks
 *
 * @return json object
 */
static
json
IntroSerializeCodeblocks(
    _In_ INTRO_CODEBLOCKS const& Codeblocks
    )
{
    static_assert(sizeof(INTRO_CODEBLOCKS) == 544, "Serialization of INTRO_CODEBLOCKS must be updated!");

    json root;
    root["Valid"] = !!Codeblocks.Valid;

    if (!Codeblocks.Valid)
    {
        return root;
    }

    root["StartAddress"] = Codeblocks.StartAddress;
    root["Rip"] = Codeblocks.Rip;
    root["RipCbIndex"] = Codeblocks.RipCbIndex;

    root["Count"] = Codeblocks.Count;

    for (DWORD i = 0; i < Codeblocks.Count; i++)
    {
        root["Codeblocks"][i]["Offset"] = Codeblocks.CodeBlocks[i].Offset;
        root["Codeblocks"][i]["Pivot"]  = Codeblocks.CodeBlocks[i].Pivot;
        root["Codeblocks"][i]["Value"]  = Codeblocks.CodeBlocks[i].Value;
    }

    return root;
}

/**
 * @brief Serialize INTRO_GPRS
 *
 * @param[in] Gprs
 *
 * @return json object
 */
static
json
IntroSerializeGprs(
    INTRO_GPRS const& Gprs
)
{
    static_assert(sizeof(INTRO_GPRS) == 160, "Serialization of INTRO_GPRS must be updated!");

    json root;

    root["RegRax"]   = Gprs.RegRax;
    root["RegRcx"]   = Gprs.RegRcx;
    root["RegRdx"]   = Gprs.RegRdx;
    root["RegRbx"]   = Gprs.RegRbx;
    root["RegRsp"]   = Gprs.RegRsp;
    root["RegRbp"]   = Gprs.RegRbp;
    root["RegRsi"]   = Gprs.RegRsi;
    root["RegRdi"]   = Gprs.RegRdi;
    root["RegR8"]    = Gprs.RegR8;
    root["RegR9"]    = Gprs.RegR9;
    root["RegR10"]   = Gprs.RegR10;
    root["RegR11"]   = Gprs.RegR11;
    root["RegR12"]   = Gprs.RegR12;
    root["RegR13"]   = Gprs.RegR13;
    root["RegR14"]   = Gprs.RegR14;
    root["RegR15"]   = Gprs.RegR15;
    root["RegCr2"]   = Gprs.RegCr2;
    root["RegFlags"] = Gprs.RegFlags;
    root["RegDr7"]   = Gprs.RegDr7;
    root["RegRip"]   = Gprs.RegRip;

    return root;
}

/**
 * @brief Serialize INTRO_EXEC_CONTEXT
 *
 * @param[in] ExecContext
 *
 * @return json object
 */
static
json
IntroSerializeExecContext(
    _In_ INTRO_EXEC_CONTEXT const& ExecContext
    )
{
    static_assert(sizeof(INTRO_EXEC_CONTEXT) == 4264, "Serialization of INTRO_EXEC_CONTEXT must be updated!");

    json root;

    root["CsType"] = ExecContext.CsType;
    root["Registers"] = IntroSerializeGprs(ExecContext.Registers);
    root["RipCode"] = IntroSerializeToBase64(ExecContext.RipCode);

    return root;
}

/**
 * @brief Serialize INTRO_DPI_EXTRA_INFO
 *
 * @param[in] DpiExtraInfo
 *
 * @return json object
 */
static
json
IntroSerializeDpiExtraInfo(
    INTRO_DPI_EXTRA_INFO const& DpiExtraInfo
)
{
    static_assert(sizeof(INTRO_DPI_EXTRA_INFO) == 8320, "Serialization of INTRO_DPI_EXTRA_INFO must be updated!");

    json root;

    root["DpiDebugFlag"]["Debugger"] = IntroSerializeProcess(DpiExtraInfo.DpiDebugFlag.Debugger);

    root["DpiPivotedStack"]["CurrentStack"] = DpiExtraInfo.DpiPivotedStack.CurrentStack;
    root["DpiPivotedStack"]["StackBase"] = DpiExtraInfo.DpiPivotedStack.StackBase;
    root["DpiPivotedStack"]["StackLimit"] = DpiExtraInfo.DpiPivotedStack.StackLimit;
    root["DpiPivotedStack"]["Wow64CurrentStack"] = DpiExtraInfo.DpiPivotedStack.Wow64CurrentStack;
    root["DpiPivotedStack"]["Wow64StackBase"] = DpiExtraInfo.DpiPivotedStack.Wow64StackBase;
    root["DpiPivotedStack"]["Wow64StackLimit"] = DpiExtraInfo.DpiPivotedStack.Wow64StackLimit;
    root["DpiPivotedStack"]["TrapFrameContent"] = IntroSerializeToBase64(DpiExtraInfo.DpiPivotedStack.TrapFrameContent);

    root["DpiStolenToken"]["StolenFrom"] = IntroSerializeProcess(DpiExtraInfo.DpiStolenToken.StolenFrom);

    for (int i = 0; i < 0xF; i++)
    {
        root["DpiHeapSpray"]["HeapPages"][i]["Mapped"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].Mapped;
        root["DpiHeapSpray"]["HeapPages"][i]["Detected"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].Detected;
        root["DpiHeapSpray"]["HeapPages"][i]["HeapValCount"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].HeapValCount;
        root["DpiHeapSpray"]["HeapPages"][i]["Offset"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].Offset;
        root["DpiHeapSpray"]["HeapPages"][i]["Executable"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].Executable;
        root["DpiHeapSpray"]["HeapPages"][i]["Reserved"] = DpiExtraInfo.DpiHeapSpray.HeapPages[i].Reserved;
    }

    root["DpiHeapSpray"]["ShellcodeFlags"] = DpiExtraInfo.DpiHeapSpray.ShellcodeFlags;

    root["DpiHeapSpray"]["DetectedPage"] = IntroSerializeToBase64(DpiExtraInfo.DpiHeapSpray.DetectedPage);
    root["DpiHeapSpray"]["MaxHeapValPageContent"] = IntroSerializeToBase64(DpiExtraInfo.DpiHeapSpray.MaxHeapValPageContent);

    root["DpiTokenPrivs"]["OldEnabled"] = DpiExtraInfo.DpiTokenPrivs.OldEnabled;
    root["DpiTokenPrivs"]["NewEnabled"] = DpiExtraInfo.DpiTokenPrivs.NewEnabled;
    root["DpiTokenPrivs"]["OldPresent"] = DpiExtraInfo.DpiTokenPrivs.OldPresent;
    root["DpiTokenPrivs"]["NewPresent"] = DpiExtraInfo.DpiTokenPrivs.NewPresent;

    root["DpiThreadStart"]["ShellcodeFlags"] = DpiExtraInfo.DpiThreadStart.ShellcodeFlags;
    root["DpiThreadStart"]["StartAddress"] = DpiExtraInfo.DpiThreadStart.StartAddress;
    root["DpiThreadStart"]["StartPage"] = IntroSerializeToBase64(DpiExtraInfo.DpiThreadStart.StartPage);

    return root;
}

/**
 * @brief Serialize INTRO_VERSION_INFO
 *
 * @param[in] Version
 *
 * @return json object
 */
static
json
IntroSerializeVersionInfo(
    INTRO_VERSION_INFO const& Version
)
{
    static_assert(sizeof(INTRO_VERSION_INFO) == 40, "Serialization of INTRO_VERSION_INFO must be updated!");

    json root;

    root["ExceptionMajor"] = Version.ExceptionMajor;
    root["ExceptionMinor"] = Version.ExceptionMinor;
    root["ExceptionBuild"] = Version.ExceptionBuild;

    root["IntroMajor"] = Version.IntroMajor;
    root["IntroMinor"] = Version.IntroMinor;
    root["IntroRevision"] = Version.IntroRevision;
    root["IntroBuildNumber"] = Version.IntroBuildNumber;

    root["CamiMajor"] = Version.CamiMajor;
    root["CamiMinor"] = Version.CamiMinor;
    root["CamiBuildNumber"] = Version.CamiBuildNumber;

    root["OsVer"] = Version.OsVer;

    return root;
}

/**
 * @brief Serialize INTRO_CPUCTX
 *
 * @param[in] CpuCtx
 *
 * @return json object
 */
static
json
IntroSerializeCpuctx(
    INTRO_CPUCTX const& CpuCtx
)
{
    static_assert(sizeof(INTRO_CPUCTX) == 152, "Serialization of INTRO_CPUCTX must be updated!");

    json root;

    root["Valid"] = !!CpuCtx.Valid;

    if (!CpuCtx.Valid)
    {
        return root;
    }

    root["Cpu"] = CpuCtx.Cpu;
    root["Rip"] = CpuCtx.Rip;
    root["Cr3"] = CpuCtx.Cr3;
    root["Instruction"] = CpuCtx.Instruction;

    return root;
}

/**
 * @brief Serialize INTRO_VIOLATION_HEADER
 *
 * @param[in] Header
 *
 * @return json object
 */
static
json
IntroSerializeViolationHeader(
    _In_ INTRO_VIOLATION_HEADER const& Header
    )
{
    static_assert(sizeof(INTRO_VIOLATION_HEADER) == 2224, "Serialization of INTRO_VIOLATION_HEADER must be updated!");

    json root;

    root["ViolationVersion"] = Header.ViolationVersion;
    root["VerInfo"] = IntroSerializeVersionInfo(Header.VerInfo);
    root["Action"] = IntroSerializeAction(Header.Action);
    root["Reason"] = IntroSerializeActionReason(Header.Reason);
    root["CpuContext"] = IntroSerializeCpuctx(Header.CpuContext);
    root["CurrentProcess"] = IntroSerializeProcess(Header.CurrentProcess);

    if (Header.Flags & ALERT_FLAG_BETA)             root["Flags"].push_back("BETA");
    if (Header.Flags & ALERT_FLAG_ANTIVIRUS)        root["Flags"].push_back("ANTIVIRUS");
    if (Header.Flags & ALERT_FLAG_SYSPROC)          root["Flags"].push_back("SYSPROC");
    if (Header.Flags & ALERT_FLAG_NOT_RING0)        root["Flags"].push_back("NOT_RING0");
    if (Header.Flags & ALERT_FLAG_ASYNC)            root["Flags"].push_back("ASYNC");
    if (Header.Flags & ALERT_FLAG_LINUX)            root["Flags"].push_back("LINUX");
    if (Header.Flags & ALERT_FLAG_FROM_ENGINES)     root["Flags"].push_back("FROM_ENGINES");
    if (Header.Flags & ALERT_FLAG_FEEDBACK_ONLY)    root["Flags"].push_back("FEEDBACK_ONLY");
    if (Header.Flags & ALERT_FLAG_DEP_VIOLATION)    root["Flags"].push_back("DEP_VIOLATION");
    if (Header.Flags & ALERT_FLAG_PROTECTED_VIEW)   root["Flags"].push_back("PROTECTED_VIEW");

    root["MitreID"] = Header.MitreID;

    root["ExHeader"]["Valid"] = !!Header.ExHeader.Valid;
    if (Header.ExHeader.Valid)
    {
        root["ExHeader"]["Version"] = Header.ExHeader.Version;
        root["ExHeader"]["ViolationFlags"] = Header.ExHeader.ViolationFlags;

        root["Exception"] = IntroSerializeToBase64(Header.Exception);
    }

    return root;
}

/**
 * @brief Serialize EVENT_EPT_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertEptViolation(
    _In_ EVENT_EPT_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_EPT_VIOLATION) == 10656, "Serialization of EVENT_EPT_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.EPTViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["Type"] = IntroSerializeObjectType(Event.Victim.Type);

         if (Event.Victim.Type == introObjectTypeDriverObject)  alertRoot["Victim"]["DriverObject"] = IntroSerializeDrvobj(Event.Victim.DriverObject);
    else if (Event.Victim.Type == introObjectTypeIdt)           alertRoot["Victim"]["IdtEntry"] = Event.Victim.IdtEntry;
    else                                                        alertRoot["Victim"]["Module"] = IntroSerializeModule(Event.Victim.Module);

    if (Event.Violation == INTRO_EPT_WRITE)
    {
        alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);
    }
    else if (Event.Violation == INTRO_EPT_EXECUTE)
    {
        alertRoot["ExecInfo"] = IntroSerializeExecInfo(Event.ExecInfo);
    }

    alertRoot["CodeBlocks"] = IntroSerializeCodeblocks(Event.CodeBlocks);

    switch (Event.Violation)
    {
    case INTRO_EPT_NONE:
        alertRoot["Violation"] = "IG_EPT_HOOK_NONE";
        break;

    case INTRO_EPT_READ:
        alertRoot["Violation"] = "IG_EPT_HOOK_READ";
        break;

    case INTRO_EPT_WRITE:
        alertRoot["Violation"] = "IG_EPT_HOOK_WRITE";
        break;

    case INTRO_EPT_EXECUTE:
        alertRoot["Violation"] = "IG_EPT_HOOK_EXECUTE";
        break;

    default:
        LogWarning("Received alert with unknown Violation: %d", Event.Violation);
        alertRoot["Violation"] = std::to_string(Event.Violation);
    }

    alertRoot["HookStartVirtual"] = Event.HookStartVirtual;
    alertRoot["HookStartPhysical"] = Event.HookStartPhysical;

    alertRoot["VirtualPage"] = Event.VirtualPage;
    alertRoot["PhysicalPage"] = Event.PhysicalPage;
    alertRoot["Offset"] = Event.Offset;

    alertRoot["ZoneTypes"] = Event.ZoneTypes;

    alertRoot["RipSectionName"] = Event.RipSectionName;

    alertRoot["ReturnRip"] = Event.ReturnRip;
    alertRoot["ReturnRipSectionName"] = Event.ReturnRipSectionName;

    alertRoot["ModifiedSectionName"] = Event.ModifiedSectionName;
    alertRoot["FunctionName"] = Event.FunctionName;
    alertRoot["FunctionNameHash"] = Event.FunctionNameHash;
    alertRoot["Delta"] = Event.Delta;

    for (int i = 0; i < _countof(Event.Export.Name); i++)
    {
        alertRoot["Export"]["Name"][i] = Event.Export.Name[i];
    }

    for (int i = 0; i < _countof(Event.Export.Hash); i++)
    {
        alertRoot["Export"]["Hash"][i] = Event.Export.Hash[i];
    }

    alertRoot["Export"]["Delta"] = Event.Export.Delta;

    alertRoot["ExecContext"] = IntroSerializeExecContext(Event.ExecContext);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_MSR_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertMsrViolation(
    _In_ EVENT_MSR_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_MSR_VIOLATION) == 9304, "Serialization of EVENT_MSR_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.MSRViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["Msr"] = Event.Victim.Msr;

    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["CodeBlocks"] = IntroSerializeCodeblocks(Event.CodeBlocks);

    alertRoot["ExecContext"] = IntroSerializeExecContext(Event.ExecContext);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_CR_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertCrViolation(
    _In_ EVENT_CR_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_CR_VIOLATION) == 9304, "Serialization of EVENT_CR_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.CRViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["Cr"] = Event.Victim.Cr;


    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["Codeblocks"] = IntroSerializeCodeblocks(Event.CodeBlocks);

    alertRoot["ExecContext"] = IntroSerializeExecContext(Event.ExecContext);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_XCR_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertXcrViolation(
    _In_ EVENT_XCR_VIOLATION const& Event
)
{
    static_assert(sizeof(EVENT_XCR_VIOLATION) == 9304, "Serialization of EVENT_XCR_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.XCRViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["Xcr"] = Event.Victim.Xcr;

    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["CodeBlocks"] = IntroSerializeCodeblocks(Event.CodeBlocks);

    alertRoot["ExecContext"] = IntroSerializeExecContext(Event.ExecContext);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_INTEGRITY_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertIntegrityViolation(
    _In_ EVENT_INTEGRITY_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_INTEGRITY_VIOLATION) == 7464, "Serialization of EVENT_INTEGRITY_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.IntegrityViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["Process"] = IntroSerializeProcess(Event.Originator.Process);

    alertRoot["Victim"]["Type"] = IntroSerializeObjectType(Event.Victim.Type);

    IntroSerializeWchar(alertRoot["Victim"], "Name", Event.Victim.Name);

            if (Event.Victim.Type == introObjectTypeTokenPtr)   alertRoot["Victim"]["Process"] = IntroSerializeProcess(Event.Victim.Process);
    else if (Event.Victim.Type == introObjectTypeDriverObject)  alertRoot["Victim"]["DriverObject"] = IntroSerializeDrvobj(Event.Victim.DriverObject);
    else if (Event.Victim.Type == introObjectTypeIdt)           alertRoot["Victim"]["IdtEntry"] = Event.Victim.IdtEntry;

    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["BaseAddress"] = Event.BaseAddress;
    alertRoot["VirtualAddress"] = Event.VirtualAddress;
    alertRoot["Size"] = Event.Size;

    return alertRoot;
}

/**
 * @brief Serialize EVENT_TRANSLATION_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertTranslationViolation(
    _In_ EVENT_TRANSLATION_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_TRANSLATION_VIOLATION) == 4504, "Serialization of EVENT_TRANSLATION_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.TranslationViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["VirtualAddress"] = Event.Victim.VirtualAddress;

    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["ViolationType"] = IntroSerializeTransViolationType(Event.ViolationType);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_MEMCOPY_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertMemcopyViolation(
    _In_ EVENT_MEMCOPY_VIOLATION const& Event
    )
{
    static_assert(sizeof(EVENT_MEMCOPY_VIOLATION) == 7504, "Serialization of EVENT_MEMCOPY_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.InjectionViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Process"] = IntroSerializeProcess(Event.Originator.Process);

    alertRoot["Victim"]["Process"] = IntroSerializeProcess(Event.Victim.Process);
    alertRoot["Victim"]["Module"] = IntroSerializeModule(Event.Victim.Module);

    alertRoot["SourceVirtualAddress"] = Event.SourceVirtualAddress;
    alertRoot["DestinationVirtualAddress"] = Event.DestinationVirtualAddress;

    alertRoot["CopySize"] = Event.CopySize;

    alertRoot["ViolationType"] = IntroSerializeMemCopyViolationType(Event.ViolationType);

    alertRoot["DumpValid"] = Event.DumpValid;
    if (Event.DumpValid)
    {
        alertRoot["RawDump"] = IntroSerializeToBase64(Event.RawDump);
    }

    alertRoot["FunctionName"] = Event.FunctionName;
    alertRoot["FunctionNameHash"] = Event.FunctionNameHash;
    alertRoot["Delta"] = Event.Delta;

    for (int i = 0; i < _countof(Event.Export.Name); i++)
    {
        alertRoot["Export"]["Name"][i] = Event.Export.Name[i];
    }

    for (int i = 0; i < _countof(Event.Export.Hash); i++)
    {
        alertRoot["Export"]["Hash"][i] = Event.Export.Hash[i];
    }

    alertRoot["Export"]["Delta"] = Event.Export.Delta;

    return alertRoot;
}

/**
 * @brief Serialize EVENT_DTR_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertDtrViolation(
    _In_ EVENT_DTR_VIOLATION const& Event
)
{
    static_assert(sizeof(EVENT_DTR_VIOLATION) == 9304, "Serialization of EVENT_DTR_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.DTRViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["Victim"]["Type"] = IntroSerializeObjectType(Event.Victim.Type);

    alertRoot["WriteInfo"] = IntroSerializeWriteInfo(Event.WriteInfo);

    alertRoot["CodeBlocks"] = IntroSerializeCodeblocks(Event.CodeBlocks);

    alertRoot["ExecContext"] = IntroSerializeExecContext(Event.ExecContext);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_PROCESS_CREATION_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertProcessCreationViolation(
    _In_ EVENT_PROCESS_CREATION_VIOLATION const& Event
)
{
    static_assert(sizeof(EVENT_PROCESS_CREATION_VIOLATION) == 14040, "Serialization of EVENT_PROCESS_CREATION_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.ProcessCreationViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Victim"] = IntroSerializeProcess(Event.Victim);
    alertRoot["Originator"] = IntroSerializeProcess(Event.Originator);

    alertRoot["PcType"] = IntroSerializePcViolationType(Event.PcType);

    alertRoot["DpiExtraInfo"] = IntroSerializeDpiExtraInfo(Event.DpiExtraInfo);

    return alertRoot;
}

/**
 * @brief Serialize EVENT_MODULE_LOAD_VIOLATION
 *
 * @param[in] Event
 *
 * @return json object
 */
static
json
IntroAlertModuleLoadViolation(
    _In_ EVENT_MODULE_LOAD_VIOLATION const& Event
)
{
    static_assert(sizeof(EVENT_MODULE_LOAD_VIOLATION) == 6120, "Serialization of EVENT_MODULE_LOAD_VIOLATION must be updated!");

    json alertRoot;
    alertRoot["@name"] = "Introspection.ModuleLoadViolation";

    // Serialize the struct:

    alertRoot["Header"] = IntroSerializeViolationHeader(Event.Header);

    alertRoot["Victim"] = IntroSerializeProcess(Event.Victim);

    alertRoot["Originator"]["Module"] = IntroSerializeModule(Event.Originator.Module);
    alertRoot["Originator"]["ReturnModule"] = IntroSerializeModule(Event.Originator.ReturnModule);

    alertRoot["ReturnRip"] = Event.ReturnRip;
    alertRoot["ReturnRipSectionName"] = Event.ReturnRipSectionName;
    alertRoot["RipSectionName"] = Event.RipSectionName;

    return alertRoot;
}

/**
 * @brief Generate introspection alert feedback
 *
 * @param[out] IntroAlert   Introspection Alert
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
FeedbackWriteIntroAlertFile(
    __in INTROSPECTION_ALERT const& IntroAlert
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    try
    {
        json alertRoot;
        FEEDBACK_FILE_CONFIG *config = nullptr;

        switch (IntroAlert.Type)
        {
            case introEventEptViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroEpt];

                if (config->Generate) alertRoot = IntroAlertEptViolation(IntroAlert.Event.EptViolation);

                break;
            }

            case introEventMsrViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroMsr];

                if (config->Generate) alertRoot = IntroAlertMsrViolation(IntroAlert.Event.MsrViolation);

                break;
            }

            case introEventCrViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroCr];

                if (config->Generate) alertRoot = IntroAlertCrViolation(IntroAlert.Event.CrViolation);

                break;
            }

            case introEventXcrViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroXcr];

                if (config->Generate) alertRoot = IntroAlertXcrViolation(IntroAlert.Event.XcrViolation);

                break;
            }

            case introEventIntegrityViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroIntegrity];

                if (config->Generate) alertRoot = IntroAlertIntegrityViolation(IntroAlert.Event.IntegrityViolation);

                break;
            }

            case introEventTranslationViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroTranslation];

                if (config->Generate) alertRoot = IntroAlertTranslationViolation(IntroAlert.Event.TranslationViolation);

                break;
            }

            case introEventInjectionViolation:  // MemCopy Violation
            {
                config = &gFeedbackCfg.Files[feedbackIntroMemcopy];

                if (config->Generate) alertRoot = IntroAlertMemcopyViolation(IntroAlert.Event.MemcopyViolation);

                break;
            }

            case introEventDtrViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroDtr];

                if (config->Generate) alertRoot = IntroAlertDtrViolation(IntroAlert.Event.DtrViolation);

                break;
            }

            case introEventProcessCreationViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroProcessCreation];

                if (config->Generate) alertRoot = IntroAlertProcessCreationViolation(IntroAlert.Event.ProcessCreationViolation);

                break;
            }

            case introEventModuleLoadViolation:
            {
                config = &gFeedbackCfg.Files[feedbackIntroModuleLoad];

                if (config->Generate) alertRoot = IntroAlertModuleLoadViolation(IntroAlert.Event.ModuleLoadViolation);

                break;
            }

            case introEventMessage:
            case introEventProcessEvent:
            case introEventAgentEvent:
            case introEventModuleEvent:
            case introEventCrashEvent:
            case introEventExceptionEvent:
            case introEventConnectionEvent:
            case introEventEnginesDetectionViolation:
                break; // we do not send feedback for these events

            default:
                LogError("Unrecognized introspection event! Type: %d", IntroAlert.Type);
        }

        if (config && config->Generate)
        {
            alertRoot["Hypervisor"] = "Napoca";

            alertRoot["Environment"] = GetEnvironmentInfo();

            status = ProcessFeedbackJson(alertRoot, config);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ProcessFeedbackJson");
                goto cleanup;
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
    return status;
}