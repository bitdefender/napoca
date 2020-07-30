/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <codecvt>
#include "common/kernel/napoca_version.h"

#define STATIC_LEN(String)      (_countof(String) - 1)

#define STRINGIFY2(s)   #s
#define STRINGIFY(s)    STRINGIFY2(s)   // two steps needed in order to expand nested macros before conversion

#define WIDEN2(s)       L ## s
#define WIDEN(s)        WIDEN2(s)       // two steps needed in order to expand nested macros before conversion

#define WIDE_TO_CHAR(wstr)              ((std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(wstr)).c_str())
#define CHAR_TO_WIDE(str)               ((std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(str)).c_str())

struct KNOWN_VERSIONS
{
    NAPOCA_VERSION  WinguestSys;
    NAPOCA_VERSION  Napoca;
    NAPOCA_VERSION  Intro;
    DWORD           LiveSupportHigh;
    DWORD           LiveSupportLow;
    DWORD           LiveSupportBuild;
    DWORD           ExceptionsHigh;
    DWORD           ExceptionsLow;
    DWORD           ExceptionsBuild;
    NAPOCA_VERSION  WinguestDllRequiredByWinguestSys;
};

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
    );

NTSTATUS
CreateDirectoryFullPath(
    _In_ std::wstring const& FullPath
    );

NTSTATUS
DeleteDirectoryAndContent(
    _In_ std::wstring const& Directory
);

#endif //_HELPERS_H_
