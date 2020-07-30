/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEPLOY_H_
#define _DEPLOY_H_

#include "dacia_types.h"
#include "common/boot/loader_interface.h"

#include <vector>
#include <string>

typedef struct _CHANGED_ITEM
{
    QWORD Id;           ///< Unique Id
    QWORD PrevHash;     ///< Previous Hash
    QWORD CurrentHash;  ///< Current Hash
}CHANGED_ITEM;


// we use std::vector in order to be able to serialize / deserialize the buffer easy
typedef std::vector<CHANGED_ITEM> CHANGED_LIST;

LD_INSTALL_FILE*
GetInstallFileForUniqueId(
    _In_ LD_UNIQUE_ID UniqueId
);

LD_INSTALL_FILE*
GetInstallFileForModId(
    _In_ LD_MODID LdModId,
    _In_opt_ LD_INSTALL_FILE_FLAGS* WantedFlags,
    _In_opt_ LD_INSTALL_FILE_FLAGS* UnwantedFlags,
    _Inout_opt_ DWORD* Continuation
);

NTSTATUS
CopyListOfFiles(
    _In_ LD_INSTALL_FILE *List,
    _In_ DWORD NumberOfElements,
    _In_ std::wstring const& DestinationDir,
    _In_ LD_INSTALL_FILE_FLAGS Flags
);

NTSTATUS
GetChangesListFromRegistry(
    _In_ const std::wstring& SubKey,
    _In_ const std::wstring& Value,
    _Out_ CHANGED_LIST& ChangedList
);

NTSTATUS
PutChangesListInRegistry(
    _In_ const std::wstring& SubKey,
    _In_ const std::wstring& Value,
    _In_ const CHANGED_LIST& ChangedList
);

NTSTATUS
UpdateChangesList(
    _In_ const LD_INSTALL_FILE* InstallFiles,
    _In_ DWORD InstallFilesCount,
    _Out_ CHANGED_LIST& ChangedList
);

CHANGED_ITEM*
GetChangedItemForId(
    _In_ CHANGED_LIST& List,
    _In_ LD_UNIQUE_ID UniqueId
);

NTSTATUS
DetermineUpdateStatus
(
    _In_ NTSTATUS InitialStatus,
    _In_ DWORD Components
);

NTSTATUS
DetermineIntroUpdate(
    _Out_   unsigned long long  *Flag
);

void
SetSDKPath(
    std::wstring const& SDKPath
);

void
SetUpdatesIntroDir(
    std::wstring const& UpdatesIntroPath
);

NTSTATUS
ExpandCmdlineMacros(
    _In_ std::string const &Input,
    _Out_ std::string &Result
);

NTSTATUS
LoadConfigData(
    LD_UNIQUE_ID CmdLine
);

NTSTATUS
CreateFinalConfigData(
    _In_ BOOLEAN Update,
    _In_opt_ std::string const& CmdLine = ""
);

NTSTATUS
ConfigureBoot(
    _In_ BOOLEAN Enable
);

NTSTATUS
UpdateBootFiles(
    LD_INSTALL_FILE_FLAGS Flags
);


#endif // _DEPLOY_H_
