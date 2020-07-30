/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file helpers.cpp
*   @brief Various helpers and common utilities
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <shlwapi.h>
#include <Shlobj.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "helpers.h"
#include "reg_opts.h"
#include "winguest_status.h"
#include "trace.h"
#include "helpers.tmh"

typedef NTSTATUS(WINAPI *FUNC_RtlGetVersion)(
    PRTL_OSVERSIONINFOW
    );

/**
 * @brief Create a full hierarchical folder path
 *
 * @param[in]  FullPath         Full path to folder that must be created
  *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
CreateDirectoryFullPath(
    __in std::wstring const& FullPath
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    std::wstring path = FullPath;

    if (path.back() == L'\\')
        path.pop_back();

    // skip first path separator
    auto position = path.find(L'\\', 0);
    if (position == std::string::npos)
    {
        status = STATUS_SUCCESS;
        goto cleanup;
    }
    position++;

    while(position != std::string::npos)
    {
        position = path.find(L'\\', position);
        if (position != std::string::npos) path[position] = L'\0';

        if (!CreateDirectory(path.c_str(), NULL))
        {
            lastErr = GetLastError();
            if (lastErr != ERROR_ALREADY_EXISTS)
            {
                status = WIN32_TO_NTSTATUS(lastErr);
                LogFuncErrorLastErr(lastErr, "CreateDirectory");
                goto cleanup;
            }
        }

        if (position != std::string::npos)
        {
            path[position] = L'\\';
            position++;
        }
    }

    status = STATUS_SUCCESS;

cleanup:
    return status;
}

/**
 * @brief Delete a folder and all content
 *
 * @param[in] Directory         Full path to directory that must be deleted
  *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
DeleteDirectoryAndContent(
    _In_ std::wstring const& Directory
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring path;
    WIN32_FIND_DATA findData = { 0 };
    HANDLE fileHandle = INVALID_HANDLE_VALUE;

    if (!PathFileExistsW(Directory.c_str()))
    {
        return STATUS_SUCCESS;
    }

    path = Directory + L"\\*";

    fileHandle = FindFirstFile(path.c_str(), &findData);
    if (INVALID_HANDLE_VALUE == fileHandle)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "FindFirstFile");
        goto cleanup;
    }

    // loop through the files of the directory and delete them
    for (;;)
    {
        if (!wcscmp(findData.cFileName, L".")
            || !wcscmp(findData.cFileName, L".."))
        {
            goto next;
        }

        path = Directory + L"\\" + findData.cFileName;

        LogVerbose("deleting: %S\n", path.c_str());

        if (GetFileAttributes(path.c_str()) & FILE_ATTRIBUTE_DIRECTORY)
        {
            status = DeleteDirectoryAndContent(path);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "DeleteDirectoryAndContent");
            }
        }
        else
        {
            if (!SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_NORMAL))
            {
                lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr, "SetFileAttributes");
            }

            if (!DeleteFile(path.c_str()))
            {
                status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
                if (lastErr != ERROR_NOT_FOUND)
                {
                    LogFuncErrorLastErr(lastErr, "DeleteFile");
                    goto cleanup;
                }
            }
        }

    next:
        if (!FindNextFile(fileHandle, &findData))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            if (lastErr != ERROR_NO_MORE_FILES)
            {
                LogFuncErrorLastErr(lastErr, "FindNextVolume");
                goto cleanup;
            }
            break;
        }
    }

    path = Directory + L"\\";

    if (!SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_NORMAL))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetFileAttributes");
    }

    // finally, remove the directory
    LogVerbose("Deleting directory: %S\n", path.c_str());
    if (!RemoveDirectory(path.c_str()))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "RemoveDirectory");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != fileHandle) FindClose(fileHandle);

    return status;
}

/**
 * @brief Get Windows detailed version information
 *
 * @param[out] Major                Major Version
 * @param[out] Minor                Minor Version
 * @param[out] ServicePack          Service Pack
 * @param[out] BuildNumber          Build Number
 * @param[out] UpdateBuildRevision  Windows 10 Update Build Revision
 * @param[out] ProductType          Product Type
 * @param[out] SuiteMask            Suite Mask
 * @param[out] Is32                 True in 32 bit systen, False if 64 bit system
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
GetWindowsVersion(
    _Out_     DWORD* Major,
    _Out_     DWORD* Minor,
    _Out_opt_ WORD* ServicePack,
    _Out_opt_ DWORD* BuildNumber,
    _Out_opt_ DWORD* UpdateBuildRevision,
    _Out_opt_ BYTE* ProductType,
    _Out_opt_ WORD* SuiteMask,
    _Out_opt_ BOOLEAN *Is32
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    RTL_OSVERSIONINFOEXW osVer = { 0 };

    if (!Major) return STATUS_INVALID_PARAMETER_1;
    if (!Minor) return STATUS_INVALID_PARAMETER_2;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return STATUS_APISET_NOT_PRESENT;

    FUNC_RtlGetVersion pfnRtlGetVersion = (FUNC_RtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!pfnRtlGetVersion) return STATUS_APISET_NOT_PRESENT;

    status = STATUS_SUCCESS;

    __try
    {
        // GetVersionEx was neutered in Windows 8.1 so we have to use RtlGetVersion

        osVer.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

        status = pfnRtlGetVersion((RTL_OSVERSIONINFOW*)&osVer);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RtlGetVersion");
            __leave;
        }

        *Major = osVer.dwMajorVersion;
        *Minor = osVer.dwMinorVersion;
        if (ServicePack) *ServicePack = osVer.wServicePackMajor;
        if (ProductType) *ProductType = osVer.wProductType;
        if (BuildNumber) *BuildNumber = osVer.dwBuildNumber;
        if (SuiteMask)   *SuiteMask   = osVer.wSuiteMask;

        if (Is32)        *Is32        = (GetSystemWow64Directory(NULL, 0) == 0) && (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);

        status = STATUS_SUCCESS;

        // Get additional info from the registry

        if (UpdateBuildRevision)
        {
            *UpdateBuildRevision = 0;

            if (osVer.dwMajorVersion >= 10)
            {
                LSTATUS error;
                DWORD value = 0;
                DWORD valueSize = sizeof(DWORD);

                error = RegGetValue(HKEY_LOCAL_MACHINE, REG_SUBKEY_WINDOWS_VERSION, REG_VALUE_UPDATE_BUILD_REVISION, RRF_RT_DWORD, NULL, &value, &valueSize);
                if (error == ERROR_SUCCESS)
                {
                    *UpdateBuildRevision = value;
                }
                else
                {
                    LogFuncErrorLastErr(error, "RegGetValue");
                }
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}
