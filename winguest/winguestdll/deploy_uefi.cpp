/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file deploy_uefi.cpp
*   @brief Hypervisor deployment on UEFI systems
*/

#include <mutex>
#include <stdlib.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#include <comdef.h>
#include <Wbemidl.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <atlcomcli.h>
#include "wmi.h"
#include "bcd.h"

#include "deploy_uefi.h"
#include "winguest_status.h"
#include "helpers.h"
#include "utils_kernel.h"
extern "C" {
#include "autogen/efi_cmdline.h"
}
#include "deploy.h"
#include "consts.h"
#include "trace.h"
#include "deploy_uefi.tmh"

#define BCD_OBJECT_DESCRIPTION      L"Napoca Hypervisor"

#define EFI_PATH                    L"EFI\\NapocaHv\\"
#define UEFI_PRELOADER_FILE         L"BdHvPreloader.efi"
#define UEFI_LOADER_FILE            L"BdHvLoader.efi"
#define UEFI_CRL_FILE               L"CRL.bin"
#define UEFI_CONFIG_FILE            L"config.cfg"

extern LD_INSTALL_FILE gInstallFiles[];
extern DWORD gInstallFilesCount;

static UD_VAR_INFO UefiCommandLineVariablesInfo[] = UD_VAR_INFO_TABLE;

extern BOOLEAN gOverrideBootx64;

/**
 * @brief Get Load Monitor data on UEFI firmwares
 *
 * @param[out] AllowedRetries       How many attempts to boot the Hypervisor before simply passing execution to the OS loader
 * @param[out] FailCount            Number of failed attempts
 * @param[out] Boot                 The hypervisor attempted booting
 * @param[out] Crash                The hypervisor may have crashed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GetLoadMonitorDataUefi(
    _Out_opt_ PDWORD AllowedRetries,
    _Out_opt_ PDWORD FailCount,
    _Out_opt_ PBOOLEAN Boot,
    _Out_opt_ PBOOLEAN Crash
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring cfgFullPath;
    HANDLE cfgFile = INVALID_HANDLE_VALUE;
    std::string fileData;
    LARGE_INTEGER fileSize;
    DWORD readBytes;

    UD_NUMBER consumed = 0;
    UEFI_LOAD_CONTROL_DATA loadControlData = { 0 };

    std::vector<std::wstring> partitions;

    if (AllowedRetries) *AllowedRetries = 0;
    if (FailCount)      *FailCount = 0;
    if (Crash)          *Crash = FALSE;
    if (Boot)           *Boot = FALSE;

    if (AllowedRetries)
    {
        status = EnumEfiPartitions(partitions);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "EnumEfiPartitions");
            goto cleanup_all;
        }

        for (DWORD i = 0; i < partitions.size(); i++)
        {
            cfgFullPath = partitions[i] + EFI_PATH UEFI_CONFIG_FILE;

            cfgFile = CreateFile(
                cfgFullPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (cfgFile == INVALID_HANDLE_VALUE)
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "CreateFile");
                goto cleanup_partition;
            }

            if (!GetFileSizeEx(cfgFile, &fileSize))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "GetFileSizeEx");
                goto cleanup_partition;
            }

            if (fileSize.HighPart != 0 || fileSize.LowPart == 0 || fileSize.LowPart > 4 * ONE_MEGABYTE)
            {
                status = STATUS_FILE_CORRUPT_ERROR;
                goto cleanup_partition;
            }

            fileData.resize(fileSize.LowPart);

            if (!ReadFile(cfgFile, &fileData[0], fileSize.LowPart, &readBytes, NULL))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "ReadFile");
                goto cleanup_partition;
            }

            if (!UdMatchVariablesFromText(UefiCommandLineVariablesInfo, _countof(UefiCommandLineVariablesInfo), const_cast<char*>(fileData.c_str()), fileSize.LowPart, &consumed))
            {
                status = STATUS_FILE_CORRUPT_ERROR;
                goto cleanup_partition;
            }

            *AllowedRetries = (DWORD)max(*AllowedRetries, CfgAllowedRetries);

            status = STATUS_SUCCESS;

        cleanup_partition:
            if (cfgFile != INVALID_HANDLE_VALUE)
            {
                CloseHandle(cfgFile);
            }
        }
    }

    if (FailCount || Crash || Boot)
    {
        if (!GetFirmwareEnvironmentVariable(
            UEFI_LOAD_CONTROL,
            NAPOCAHV_UEFI_GUID,
            &loadControlData,
            sizeof(UEFI_LOAD_CONTROL_DATA)
            ))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "GetFirmwareEnvironmentVariable");
            goto cleanup_all;
        }

        if (FailCount) *FailCount = loadControlData.FailCount;
        if (Crash)     *Crash = !!loadControlData.Crash;
        if (Boot)      *Boot = !!loadControlData.Boot;
    }

    status = STATUS_SUCCESS;

cleanup_all:
    return status;
}

/**
 * @brief Update Load Monitor data on UEFI firmwares
 *
 * @param[in] AllowedRetries        How many attempts to boot the Hypervisor before before simply passing execution to the OS loader
 * @param[in] FailCount             Number of failed attempts
 * @param[in] Boot                  The hypervisor attempted booting
 * @param[in] Crash                 The hypervisor may have crashed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
SetLoadMonitorDataUefi(
    _In_opt_ PDWORD AllowedRetries,
    _In_opt_ PDWORD FailCount,
    _In_opt_ PBOOLEAN Boot,
    _In_opt_ PBOOLEAN Crash
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring cfgFullPath;
    HANDLE cfgFile = INVALID_HANDLE_VALUE;
    std::string fileData;
    LARGE_INTEGER fileSize;
    DWORD readBytes;
    QWORD newSize = 0;
    QWORD consumed = 0;
    UEFI_LOAD_CONTROL_DATA loadControlData = { 0 };

    std::vector<std::wstring> partitions;

    if (AllowedRetries)
    {
        status = EnumEfiPartitions(partitions);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "EnumEfiPartitions");
            goto cleanup_all;
        }

        for (DWORD i = 0; i < partitions.size(); i++)
        {
            cfgFullPath = partitions[i] + EFI_PATH UEFI_CONFIG_FILE;

            cfgFile = CreateFile(
                cfgFullPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (cfgFile == INVALID_HANDLE_VALUE)
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "CreateFile");
                goto cleanup_partition;
            }

            if (!GetFileSizeEx(cfgFile, &fileSize))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "GetFileSizeEx");
                goto cleanup_partition;
            }

            if (fileSize.HighPart != 0 || fileSize.LowPart == 0 || fileSize.LowPart > 4 * ONE_MEGABYTE)
            {
                status = STATUS_FILE_CORRUPT_ERROR;
                goto cleanup_partition;
            }

            fileData.resize(fileSize.LowPart);

            if (!ReadFile(cfgFile, &fileData[0], fileSize.LowPart, &readBytes, NULL))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "ReadFile");
                goto cleanup_partition;
            }

            CloseHandle(cfgFile);
            cfgFile = INVALID_HANDLE_VALUE;

            if (!UdMatchVariablesFromText(UefiCommandLineVariablesInfo, _countof(UefiCommandLineVariablesInfo), const_cast<char*>(fileData.c_str()), (UD_NUMBER)fileSize.LowPart, (UD_NUMBER*)&consumed))
            {
                status = STATUS_FILE_CORRUPT_ERROR;
                goto cleanup_partition;
            }

            CfgAllowedRetries = *AllowedRetries;

            UdDumpVariablesToText(UefiCommandLineVariablesInfo, _countof(UefiCommandLineVariablesInfo), NULL, 0, &newSize);
            if (newSize <= 1 || newSize > 4 * ONE_MEGABYTE)
            {
                status = STATUS_DATA_OVERRUN;
                goto cleanup_partition;
            }

            fileData.resize(static_cast<size_t>(newSize));

            if (!UdDumpVariablesToText(UefiCommandLineVariablesInfo, _countof(UefiCommandLineVariablesInfo), &fileData[0], newSize, (UD_NUMBER*)&consumed))
            {
                status = STATUS_DATA_ERROR;
                goto cleanup_partition;
            }

            cfgFile = CreateFile(
                cfgFullPath.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (cfgFile == INVALID_HANDLE_VALUE)
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "CreateFile");
                goto cleanup_partition;
            }

            if (!WriteFile(cfgFile, fileData.c_str(), static_cast<DWORD>(newSize) - 1, &readBytes, NULL))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                LogFuncErrorLastErr(lastErr, "WriteFile");
                goto cleanup_partition;
            }

            FlushFileBuffers(cfgFile);

            status = STATUS_SUCCESS;

        cleanup_partition:
            if (cfgFile != INVALID_HANDLE_VALUE)
            {
                CloseHandle(cfgFile);
            }
        }
    }

    if (FailCount || Crash || Boot)
    {
        if (!GetFirmwareEnvironmentVariable(
            UEFI_LOAD_CONTROL,
            NAPOCAHV_UEFI_GUID,
            &loadControlData,
            sizeof(UEFI_LOAD_CONTROL_DATA)
            ))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "GetFirmwareEnvironmentVariable");
            goto cleanup_all;
        }

        if (FailCount) loadControlData.FailCount = *FailCount;
        if (Boot) loadControlData.Crash = *Boot;
        if (Crash) loadControlData.Boot = *Crash;

        if (!SetFirmwareEnvironmentVariable(
            UEFI_LOAD_CONTROL,
            NAPOCAHV_UEFI_GUID,
            &loadControlData,
            sizeof(UEFI_LOAD_CONTROL_DATA)
            ))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "SetFirmwareEnvironmentVariable");
            goto cleanup_all;
        }
    }

    status = STATUS_SUCCESS;

cleanup_all:
    return status;
}

/**
 * @brief Copy files required for UEFI boot
 *
 * @param[in] Flags             Flags that determine which files to copy
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
DeployUefiBootFiles(
    LD_INSTALL_FILE_FLAGS Flags
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::vector<std::wstring> partitions;
    LD_INSTALL_FILE *efiBackupEntry = NULL;
    LD_INSTALL_FILE *efiPreloaderEntry = NULL;
    std::wstring destPath;

    status = EnumEfiPartitions(partitions);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "EnumEfiPartitions");
        return status;
    }

    for (DWORD i = 0; i < partitions.size(); i++)
    {
        // Make the folder

        destPath = partitions[i] + EFI_PATH;

        if (!CreateDirectory(destPath.c_str(), NULL))
        {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
            {
                lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr, "CreateDirectory");
                return WIN32_TO_NTSTATUS(lastErr);
            }
        }

        // Copy the necessary files
        LogVerbose("Copying files\n");
        status = CopyListOfFiles(
            gInstallFiles,
            gInstallFilesCount,
            destPath,
            Flags
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CopyListOfFiles");
            return status;
        }

        if (gOverrideBootx64)
        {
            std::wstring efiPreloaderPath = destPath;
            std::wstring bootx64Path = partitions[i];
            std::wstring bootx64BackupPath = partitions[i];

            efiPreloaderEntry = GetInstallFileForUniqueId(efiPreloader);
            if (!efiPreloaderEntry)
            {
                status = STATUS_FILE_NOT_AVAILABLE;
                LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
                return status;
            }

            efiBackupEntry = GetInstallFileForUniqueId(efiLoaderBackup);
            if (!efiBackupEntry)
            {
                status = STATUS_FILE_NOT_AVAILABLE;
                LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
                return status;
            }

            efiPreloaderPath += efiPreloaderEntry->DestinationFileName;
            bootx64Path = bootx64Path + L"\\" + efiBackupEntry->SourceFileName;
            bootx64BackupPath = bootx64BackupPath + L"\\" + efiBackupEntry->DestinationFileName;

            if (!CopyFile(bootx64Path.c_str(), bootx64BackupPath.c_str(), FALSE))
            {
                lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr, "CopyFile");
                return WIN32_TO_NTSTATUS(lastErr);
            }

            if (!CopyFile(efiPreloaderPath.c_str(), bootx64Path.c_str(), FALSE))
            {
                lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr, "CopyFile");
                return WIN32_TO_NTSTATUS(lastErr);
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Delete files required for UEFI boot
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
RemoveUefiBootFiles(
    void
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::vector<std::wstring> partitions;
    std::wstring folder;
    LD_INSTALL_FILE *efiBackupEntry = NULL;

    status = EnumEfiPartitions(partitions);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "EnumEfiPartitions");
        return status;
    }

    for (DWORD i = 0; i < partitions.size(); i++)
    {
        folder = partitions[i] + EFI_PATH;
        folder.pop_back(); // remove last L'\\'

        if (gOverrideBootx64)
        {
            std::wstring bootx64Path = partitions[i];
            std::wstring bootx64BackupPath = partitions[i];

            efiBackupEntry = GetInstallFileForUniqueId(efiLoaderBackup);
            if (!efiBackupEntry)
            {
                status = STATUS_FILE_NOT_AVAILABLE;
                LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
                return status;
            }

            bootx64Path = bootx64Path + L"\\" + efiBackupEntry->SourceFileName;
            bootx64BackupPath = bootx64BackupPath + L"\\" + efiBackupEntry->DestinationFileName;

            if (!MoveFileEx(bootx64BackupPath.c_str(), bootx64Path.c_str(), MOVEFILE_REPLACE_EXISTING))
            {
                DWORD lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr , "MoveFileEx");
            }
        }

        status = DeleteDirectoryAndContent(folder);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "DeleteDirectoryAndContent");
            return status;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Configure BCD entry for Napoca Hypervisor
 *
 * @param[in] Result        Operation result
 *
 */
static
void
UefiConfigureHvBcdBoot2(
    HRESULT& Result
    )
{
    HRESULT hr = E_FAIL;

    std::wstring ourGuid = L"";

    BcdStore   sysBcdStore;
    BcdObject* fwBootMgr = NULL;
    BcdObject* bootEntry = NULL;

    SAFEARRAY* bootList = NULL;
    LONG upperBound = 0, lowerBound = 0;
    LONG index = 0;
    INT32 currentPos = -1;
    CComBSTR dispId;

    LogInfo("Starting BCD operations through WMI on configure\n");

    hr = sysBcdStore.OpenStore(L"");
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenStore");
        goto cleanup;
    }

    LogVerbose("Opened store\n");

    hr = sysBcdStore.CopyObject(BCD_GUID_BOOTMGR, ourGuid);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "CopyObject");
        goto cleanup;
    }

    LogVerbose("Copied object with ourGuid [%S]\n", ourGuid.c_str());

    hr = sysBcdStore.OpenObject(ourGuid, bootEntry);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    LogVerbose("Opened object BOOTMGR\n");

    hr = bootEntry->SetStringElement(BcdLibraryString_Description, BCD_OBJECT_DESCRIPTION);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SetStringElement");
        goto cleanup;
    }

    LogVerbose("Set BcdLibraryString_Description\n");

    hr = bootEntry->SetStringElement(BcdLibraryString_ApplicationPath, EFI_PATH UEFI_PRELOADER_FILE);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SetStringElement");
        goto cleanup;
    }

    LogVerbose("Set BcdLibraryString_ApplicationPath\n");

    // check that the new entry was added and first in the boot list of the {fwbootmgr}

    hr = sysBcdStore.OpenObject(BCD_GUID_FWBOOTMGR, fwBootMgr);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    LogVerbose("Opened object FWBOOTMGR\n");

    hr = fwBootMgr->GetObjectListElement((DWORD)BcdBootMgrObjectList_DisplayOrder, bootList);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetObjectListElement");
        goto cleanup;
    }

    LogVerbose("Got DisplayOrder\n");

    if (SafeArrayGetDim(bootList) != 1)
    {
        hr = E_UNEXPECTED;
        LogFuncErrorHr(hr, "SafeArrayGetDim");
        goto cleanup;
    }

    LogVerbose("Got safe array DIM\n");

    hr = SafeArrayGetLBound(bootList, 1, &lowerBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetLBound");
        goto cleanup;
    }

    LogVerbose("Got safe array lower bound\n");

    hr = SafeArrayGetUBound(bootList, 1, &upperBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetUBound");
        goto cleanup;
    }

    LogVerbose("Got safe array upper bound\n");

    // search for current position

    for (index = lowerBound; index <= upperBound; index++)
    {
        hr = SafeArrayGetElement(bootList, &index, &dispId);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayGetElement");
            goto cleanup;
        }

        if (std::wstring(dispId) == ourGuid)
        {
            currentPos = index;
            break;
        }

        dispId.Empty();
    }

    LogVerbose("Finished search for current position\n");

    if (currentPos == lowerBound) // entry already added on first position
    {
        hr = S_OK;
        goto cleanup;
    }

    if (currentPos == -1) // not already present
    {
        // resize array
        SAFEARRAYBOUND newBound = { 0 };

        upperBound++;
        newBound.cElements = upperBound - lowerBound + 1;
        newBound.lLbound = lowerBound;

        hr = SafeArrayRedim(bootList, &newBound);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayRedim");
            goto cleanup;
        }

        LogVerbose("Redimensioned array\n");

        currentPos = upperBound;
    }

    for (index = currentPos - 1; index >= lowerBound; index--) // push others down
    {
        hr = SafeArrayGetElement(bootList, &index, &dispId);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayGetElement");
            goto cleanup;
        }

        index++;
        hr = SafeArrayPutElement(bootList, &index, dispId);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayPutElement");
            goto cleanup;
        }
        index--;

        dispId.Empty();
    }

    LogVerbose("Finished pushes\n");

    index = lowerBound;
    hr = SafeArrayPutElement(bootList, &index, _bstr_t(ourGuid.c_str()).GetBSTR()); // set on top
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayPutElement");
        goto cleanup;
    }

    LogVerbose("Finished set on top\n");

    hr = fwBootMgr->SetObjectListElement((DWORD)BcdBootMgrObjectList_DisplayOrder, bootList);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SetObjectListElement");
        goto cleanup;
    }

    LogVerbose("Finished setting the display order\n");

cleanup:
    LogInfo("Finished BCD operations through WMI on configure\n");

    if (FAILED(hr))
    {
        sysBcdStore.DeleteObject(ourGuid);
    }

    SafeArrayDestroy(bootList);
    sysBcdStore.DisposeOfObject(fwBootMgr);
    sysBcdStore.DisposeOfObject(bootEntry);
    sysBcdStore.CloseStore();

    Result = hr;
    return;
}

/**
 * @brief Wrapper that calls #UefiConfigureHvBcdBoot2 on a new thread
 *
 * @return Result        Operation result
 *
 */
static
HRESULT
UefiConfigureHvBcdBoot(
    void
    )
{
    HRESULT caleeStatus = E_FAIL;

    LogInfo("Will start UefiConfigureHvBcdBoot2 thread\n");

    try
    {
        std::thread efiThread(UefiConfigureHvBcdBoot2, std::ref(caleeStatus));
        efiThread.join();

        LogInfo("Finished wait on UefiConfigureHvBcdBoot2 thread\n");
    }
    catch (std::system_error& ex)
    {
        LogError("Exception while configuring UEFI boot! 0x%x", ex.code().value());
    }

    return caleeStatus;
}

/**
 * @brief Remove BCD entry for Napoca Hypervisor
 *
 * @param[in] Result        Operation result
 *
 */
static
void
UefiUnconfigureHvBcdBoot2(
    HRESULT& Result
    )
{
    HRESULT hr = E_FAIL;

    BcdStore  sysBcdStore;
    BcdObject* fwBootMgr = NULL;
    BcdObject* bootEntry = NULL;

    SAFEARRAY* bootList = NULL;
    LONG upperBound = 0, lowerBound = 0;
    std::vector<BcdObject*> allObjects;
    CComBSTR guid;
    DWORD type = 0;
    std::wstring applicationPath;
    std::wstring objGuid;
    std::wstring preloader(UEFI_PRELOADER_FILE);

    LogInfo("Starting BCD operations through WMI on unconfigure\n");

    hr = sysBcdStore.OpenStore(L"");
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenStore");
        goto cleanup;
    }

    LogVerbose("Opened store\n");

    // Delete our objects found in {fwbootmgr}

    hr = sysBcdStore.OpenObject(BCD_GUID_FWBOOTMGR, fwBootMgr);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    LogVerbose("Opened object BCD_GUID_FWBOOTMGR\n");

    hr = fwBootMgr->GetObjectListElement((DWORD)BcdBootMgrObjectList_DisplayOrder, bootList);
    if (SUCCEEDED(hr))
    {
        LogVerbose("Got DisplayOrder\n");

        if (SafeArrayGetDim(bootList) != 1)
        {
            hr = E_UNEXPECTED;
            if (FAILED(hr))
            {
                LogFuncErrorHr(hr, "SafeArrayGetDim");
                goto cleanup;
            }
        }

        LogVerbose("Got safe array DIM\n");

        hr = SafeArrayGetLBound(bootList, 1, &lowerBound);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayGetLBound");
            goto cleanup;
        }

        LogVerbose("Got safe array lower bound\n");

        hr = SafeArrayGetUBound(bootList, 1, &upperBound);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayGetUBound");
            goto cleanup;
        }

        LogVerbose("Got safe array upper bound\n");

        for (LONG index = lowerBound; index <= upperBound; index++)
        {
            hr = SafeArrayGetElement(bootList, &index, &guid);
            if (FAILED(hr))
            {
                LogFuncErrorHr(hr, "SafeArrayGetElement");
                goto cleanup;
            }

            hr = sysBcdStore.OpenObject(guid.m_str, bootEntry);
            if (FAILED(hr))
            {
                LogFuncErrorHr(hr, "OpenObject");
                goto cleanup;
            }

            hr = bootEntry->GetType(type);

            if (SUCCEEDED(hr) && type == (BcdObj_Application | BcdObjApplication_Firmware | BcdObjApp_WindowsBootManager))
            {

                hr = bootEntry->GetStringElement(BcdLibraryString_ApplicationPath, applicationPath);
                if (FAILED(hr))
                {
                    LogFuncErrorHr(hr, "GetStringElement");
                    goto cleanup;
                }

                if (applicationPath.length() > preloader.length())
                {
                    std::wstring appSuffix = applicationPath.substr(applicationPath.length() - preloader.length());

                    if (equal(appSuffix.begin(), appSuffix.end(),
                        preloader.begin(), preloader.end(),
                        [](wchar_t c1, wchar_t c2) {return tolower(c1) == tolower(c2); }))
                    {
                        hr = sysBcdStore.DeleteObject(guid.m_str);
                        if (FAILED(hr))
                        {
                            LogFuncErrorHr(hr, "DeleteObject");
                            goto cleanup;
                        }
                    }
                }
            }

            sysBcdStore.DisposeOfObject(bootEntry);

            guid.Empty();
        }

        LogVerbose("Finished search and destruction of our boot entry\n");
    }
    else
    {
        LogFuncErrorHr(hr, "GetObjectListElement");
    }

    // Delete other leftovers from BCD that match our loader caused by stupid firmware
    LogVerbose("Will enumerate BcdObj_Application\n");

    hr = sysBcdStore.EnumerateObjects(BcdObj_Application, allObjects);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "EnumerateObjects");
        goto cleanup;
    }

    LogVerbose("Finished enumerating BcdObj_Application\n");

    for (DWORD index = 0; index < allObjects.size(); index++)
    {
        hr = allObjects[index]->GetType(type);
        if (!SUCCEEDED(hr))
        {
            LogFuncErrorHr(hr, "GetType");
            continue;
        }

        if ((type & (BcdObj_Application | BcdObjApplication_Firmware)) != (BcdObj_Application | BcdObjApplication_Firmware)) // 0x101fffff
        {
            continue;
        }

        hr = allObjects[index]->GetStringElement(BcdLibraryString_ApplicationPath, applicationPath);
        if (SUCCEEDED(hr))
        {
            if (applicationPath.length() > preloader.length())
            {
                std::wstring appSuffix = applicationPath.substr(applicationPath.length() - preloader.length());

                if (equal(appSuffix.begin(), appSuffix.end(),
                    preloader.begin(), preloader.end(),
                    [](wchar_t c1, wchar_t c2) {return tolower(c1) == tolower(c2); }))
                {
                    hr = allObjects[index]->GetGuid(objGuid);
                    if (!SUCCEEDED(hr))
                    {
                        LogFuncErrorHr(hr, "GetGuid");
                        continue;
                    }

                    hr = sysBcdStore.DeleteObject(objGuid);
                    if (!SUCCEEDED(hr))
                    {
                        LogFuncErrorHr(hr, "DeleteObject");
                        continue;
                    }
                }
            }
        }
    }

    LogVerbose("Finished enumerating BCD leftovers\n");

    hr = S_OK;

cleanup:
    LogInfo("Finished BCD operations through WMI on unconfigure\n");

    for (DWORD index = 0; index < allObjects.size(); index++)
    {
        sysBcdStore.DisposeOfObject(allObjects[index]);
    }

    SafeArrayDestroy(bootList);
    sysBcdStore.DisposeOfObject(bootEntry);
    sysBcdStore.DisposeOfObject(fwBootMgr);
    sysBcdStore.CloseStore();

    Result = hr;
    return;
}

/**
 * @brief Wrapper that calls #UefiUnconfigureHvBcdBoot2 on a new thread
 *
 * @return Result        Operation result
 *
 */
static
HRESULT
UefiUnconfigureHvBcdBoot(
    void
    )
{
    HRESULT caleeStatus = E_FAIL;

    LogVerbose("Will start UefiUnconfigureHvBcdBoot2 thread\n");

    try
    {
        std::thread efiThread(UefiUnconfigureHvBcdBoot2, std::ref(caleeStatus));
        efiThread.join();

        LogVerbose("Finished wait for UefiUnconfigureHvBcdBoot2 thread\n");
    }
    catch (std::system_error& ex)
    {
        LogError("Exception while deconfiguring UEFI boot! 0x%x", ex.code().value());
    }


    return caleeStatus;
}

/**
 * @brief Check UEFI Configuration integrity
 *
 * @param[in] Result        Operation result
 *
 */
static
void
UefiCheckConfigurationIntegrity2(
    HRESULT& Result
    )
{
    HRESULT hr = E_FAIL;

    std::wstring ourGuid = L"";

    BcdStore   sysBcdStore;
    BcdObject* fwBootMgr = NULL;
    BcdObject* bootEntry = NULL;

    SAFEARRAY* bootList = NULL;
    LONG upperBound = 0, lowerBound = 0;
    BOOLEAN foundOk = FALSE;
    CComBSTR guid;
    DWORD type = 0;
    std::wstring applicationPath;
    std::wstring preloader(UEFI_PRELOADER_FILE);

    hr = sysBcdStore.OpenStore(L"");
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenStore");
        goto cleanup;
    }

    // check that the new entry was added and first in the boot list of the {fwbootmgr}

    hr = sysBcdStore.OpenObject(BCD_GUID_FWBOOTMGR, fwBootMgr);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    hr = fwBootMgr->GetObjectListElement((DWORD)BcdBootMgrObjectList_DisplayOrder, bootList);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetObjectListElement");
        goto cleanup;
    }

    if (SafeArrayGetDim(bootList) != 1)
    {
        hr = E_UNEXPECTED;
        LogFuncErrorHr(hr, "SafeArrayGetDim");
        goto cleanup;
    }

    hr = SafeArrayGetLBound(bootList, 1, &lowerBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetLBound");
        goto cleanup;
    }

    hr = SafeArrayGetUBound(bootList, 1, &upperBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetUBound");
        goto cleanup;
    }

    // open and check the first element in the array

    hr = SafeArrayGetElement(bootList, &lowerBound, &guid);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetElement");
        goto cleanup;
    }

    hr = sysBcdStore.OpenObject(guid.m_str, bootEntry);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    hr = bootEntry->GetType(type);

    if (SUCCEEDED(hr) && type == (BcdObj_Application | BcdObjApplication_Firmware | BcdObjApp_WindowsBootManager))
    {
        hr = bootEntry->GetStringElement(BcdLibraryString_ApplicationPath, applicationPath);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "GetStringElement");
            goto cleanup;
        }

        if (applicationPath.length() > preloader.length())
        {
            std::wstring appSuffix = applicationPath.substr(applicationPath.length() - preloader.length());

            if (equal(appSuffix.begin(), appSuffix.end(),
                preloader.begin(), preloader.end(),
                [](wchar_t c1, wchar_t c2) {return tolower(c1) == tolower(c2); }))
            {
                foundOk = TRUE;
            }
        }
    }

    hr = foundOk ? S_OK : E_NOT_SET;

cleanup:
    SafeArrayDestroy(bootList);
    sysBcdStore.DisposeOfObject(bootEntry);
    sysBcdStore.DisposeOfObject(fwBootMgr);
    sysBcdStore.CloseStore();

    Result = hr;

    return;
}

/**
 * @brief Wrapper that calls #UefiCheckConfigurationIntegrity2 on a new thread
 *
 * @return Result        Operation result
 *
 */
HRESULT
UefiCheckConfigurationIntegrity(
    void
    )
{
    HRESULT caleeStatus = E_FAIL;

    try
    {
        std::thread efiThread(UefiCheckConfigurationIntegrity2, std::ref(caleeStatus));
        efiThread.join();
    }
    catch (std::system_error& ex)
    {
        LogError("Exception while checking UEFI boot! 0x%x", ex.code().value());
    }

    return caleeStatus;
}

/**
 * @brief Configure / Deconfigure Napoca Hypervisor on systems with UEFI firmware
 *
 * @param[in] Install           true -> Confugure, False -> Deconfigure
 *
 */
NTSTATUS
ConfigureUefiBoot(
    _In_ BOOLEAN Install
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD lastErr = ERROR_SUCCESS;
    HRESULT hr = E_FAIL;
    UEFI_LOAD_CONTROL_DATA loadControlData = {0};
    LD_INSTALL_FILE_FLAGS flags = { 0 };

    static std::mutex uefiCfgmutex;
    std::lock_guard<std::mutex> lock(uefiCfgmutex);

    LogInfo("Starting ConfigureUefiBoot with install set to %u\n", Install);

    if (Install)
    {
        LogVerbose("Will deploy UEFI boot files\n");

        flags.Efi = 1;
        status = DeployUefiBootFiles(flags);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "DeployUefiBootFiles");
            goto cleanup;
        }

        LogVerbose("Will configure HV boot\n");

        hr = UefiConfigureHvBcdBoot();
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "UefiConfigureHvBcdBoot");
            status = WIN32_TO_NTSTATUS(hr);
            goto cleanup;
        }

        LogVerbose("Will set EFI variable\n");

        if (!SetFirmwareEnvironmentVariable(
            UEFI_LOAD_CONTROL,
            NAPOCAHV_UEFI_GUID,
            &loadControlData,
            sizeof(UEFI_LOAD_CONTROL_DATA)
            ))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "SetFirmwareEnvironmentVariable");
            goto cleanup;
        }

        LogVerbose("Successfully finished install operations\n");
    }
    else
    {
        LogVerbose("Will unconfigure UEFI\n");

        hr = UefiUnconfigureHvBcdBoot();
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "UefiUnconfigureHvBcdBoot");
            status = WIN32_TO_NTSTATUS(hr);
            goto cleanup;
        }

        LogVerbose("Will remove EFI boot files\n");

        status = RemoveUefiBootFiles();
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RemoveUefiBootFiles");
        }

        LogVerbose("Successfully removed UEFI boot files\n");
    }

    status = STATUS_SUCCESS;

cleanup:
    if (Install && status != STATUS_SUCCESS)
    {
        RemoveUefiBootFiles();
    }

    LogInfo("UEFI %sinstaller completed with status: 0x%x\n", Install ? "" : "un", status);

    return status;
}

/**
 * @brief Check if UEFI configuration is supported
 *
 * @return true         UEFI configuration supported
 * @return false        UEFI configuration not supported
 *
 */
BOOLEAN
ConfigUefiSupported(
    void
    )
{
    return TRUE; // !IsSecureBootEnabled();
}
