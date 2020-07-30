/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file deploy.cpp
*   @brief Hypervisor common deployment
*/

#include <string>
#include <regex>
#include <fstream>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "winguest_status.h"
#include "deploy.h"
#include "deploy_validation.h"
#include "deploy_legacy.h"
#include "deploy_uefi.h"
#include "helpers.h"
#include "reg_opts.h"
#include "crc32.h"
#include "consts.h"

extern "C" {
#include "_external/buildsystem/interface/c/userdata.h"
#include "autogen/napoca_cmdline.h"
}

#include "trace.h"
#include "deploy.tmh"

#define EFI_CONFIG_BINARIES_FOLDER          L"Efi\\"
#define LEGACY_CONFIG_BINARIES_FOLDER       L"Legacy\\"

LD_INSTALL_FILE gInstallFiles[] =
{
#include "autogen/install_files.h"
};
DWORD gInstallFilesCount = _countof(gInstallFiles);

BOOLEAN gHypervisorConfigured;
std::wstring gSdkDirs[SDK_DIR_MAX_ID];

typedef struct _LM_CMDLINE_MACRO
{
    char* Name;
    char* Body;
}LM_CMDLINE_MACRO;

static LM_CMDLINE_MACRO gCmdlineMacros[] =
{
    #include "autogen/cmdline_templates.h"
};

static UD_VAR_INFO HvCommandLineVariablesInfo[] = UD_VAR_INFO_TABLE;

/**
 * @brief Copy a list of files
 *
 * @param[in] List                      List of installation files and metadata
 * @param[in] NumberOfElements          Count of items in List
 * @param[in] DestinationDir            Folder where the files will be copied
 * @param[in] Flags                     Flags that must be matched in order to copy the files. A file must have all required flags set in order to be copied
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
CopyListOfFiles(
    _In_ LD_INSTALL_FILE *List,
    _In_ DWORD NumberOfElements,
    _In_ std::wstring const& DestinationDir,
    _In_ LD_INSTALL_FILE_FLAGS Flags
    )
{
    std::wstring sourceFullPath;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring destinationFullPath;
    BOOLEAN uefi = IsUefiBootedOs();

    // copy each file
    for (DWORD i = 0; i < NumberOfElements; i++)
    {
        if ((List[i].Flags.Raw & Flags.Raw) != Flags.Raw && Flags.Raw != 0)
        {
            continue;
        }

        if (gSdkDirs[List[i].SourceDir].empty() || gSdkDirs[List[i].SourceDir][0] == L'\0')
        {
            continue;
        }

        if (List[i].DestinationFileName == NULL || List[i].SourceFileName == NULL || gSdkDirs[List[i].SourceDir].empty())
        {
            return STATUS_FILE_INVALID;
        }

        sourceFullPath = gSdkDirs[List[i].SourceDir] + List[i].SourceFileName;
        destinationFullPath = DestinationDir + List[i].DestinationFileName;

        if (!uefi)
        {
            SetFileAttributes(destinationFullPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        }

        LogVerbose("Copying %S -> %S\n", sourceFullPath.c_str(), destinationFullPath.c_str());
        if (!CopyFile(sourceFullPath.c_str(), destinationFullPath.c_str(), FALSE))
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "CopyFile");
            return WIN32_TO_NTSTATUS(lastErr);
        }

        if (!uefi)
        {
            if (!SetFileAttributes(destinationFullPath.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
            {
                lastErr = GetLastError();
                LogFuncErrorLastErr(lastErr, "SetFileAttributes");
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Retrieve a file from the installation list by the unique identifier
 *
 * @param[in] UniqueId              Identifier that uniquely identifies a file in the list
 *
 * @return File                     The requested file
 * @return NULL                     No file matched the id
 */
LD_INSTALL_FILE*
GetInstallFileForUniqueId(
    _In_ LD_UNIQUE_ID UniqueId
)
{
    for (DWORD i = 0; i < gInstallFilesCount; i++)
        if (gInstallFiles[i].UniqueId == UniqueId)
            return &gInstallFiles[i];

    return NULL;
}

/**
 * @brief Retrieve files from the installation list by their module identifier and flags
 *
 * @param[in] LdModId               Identifier that identifies the module for which the files can be used
 * @param[in] WantedFlags           Flags that must be matched by the files
 * @param[in] UnwantedFlags         Flags that must not be matched by the files
 * @param[in] Continuation          The last retrieved file for a new point to start the search in case more than one is required
 *
 * @return File                     The requested file
 * @return NULL                     No (new) file matched the id
 */
LD_INSTALL_FILE*
GetInstallFileForModId(
    _In_ LD_MODID LdModId,
    _In_opt_ LD_INSTALL_FILE_FLAGS* WantedFlags,
    _In_opt_ LD_INSTALL_FILE_FLAGS* UnwantedFlags,
    _Inout_opt_ DWORD* Continuation
)
{
    DWORD start = Continuation ? *Continuation : 0;

    if (Continuation)
    {
        start = *Continuation;
    }

    for (DWORD i = start; i < gInstallFilesCount; i++)
    {
        if (gInstallFiles[i].LdModId == LdModId)
        {
            if (
                ((!WantedFlags) || ((WantedFlags->Raw & gInstallFiles[i].Flags.Raw) == WantedFlags->Raw)) &&
                ((!UnwantedFlags) || ((UnwantedFlags->Raw & gInstallFiles[i].Flags.Raw) == 0))
                )
            {
                if (Continuation)
                {
                    *Continuation = i + 1;
                }

                return &gInstallFiles[i];
            }
        }
    }

    return NULL;
}

/**
 * @brief Retrieve a file from a custom list by the unique identifier
 *
 * @param[in] List                  Custom file list
 * @param[in] UniqueId              Identifier that uniquely identifies a file in the list
 *
 * @return File                     The requested file
 * @return NULL                     No file matched the id
 */
CHANGED_ITEM*
GetChangedItemForId(
    _In_ CHANGED_LIST& List,
    _In_ LD_UNIQUE_ID UniqueId
)
{
    for (DWORD i = 0; i < List.size(); i++)
        if (List[i].Id == UniqueId)
            return &List[i];

    return NULL;
}

/**
 * @brief Retrieve version metadata from the registry in order to check which files changed after an update
 *
 * @param[in]  SubKey               Registry Key where the data is stored
 * @param[in]  Value                Registry Value where the data is stored
 * @param[out] ChangedList          List of files with version metadata
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
GetChangesListFromRegistry(
    _In_ const std::wstring& SubKey,
    _In_ const std::wstring& Value,
    _Out_ CHANGED_LIST& ChangedList
)
{
    LONG retCode = ERROR_SUCCESS;

    ChangedList.clear();

    //
    // Request the size of the binary data, in bytes
    //
    DWORD dataSize{};
    retCode = RegGetValue(
        HKEY_LOCAL_MACHINE,
        SubKey.c_str(),
        Value.c_str(),
        RRF_RT_ANY, //REG_BINARY, //RRF_RT_REG_BINARY,
        nullptr,
        nullptr,
        &dataSize);
    if (retCode == ERROR_SUCCESS)
    {
        //
        // Allocate room for the result binary data
        //
        ChangedList.resize(dataSize / sizeof(CHANGED_ITEM)); // we need number of elements

        //
        // Read the binary data from the registry into the vector object
        //
        retCode = RegGetValue(
            HKEY_LOCAL_MACHINE,
            SubKey.c_str(),
            Value.c_str(),
            RRF_RT_ANY, //REG_BINARY, //RRF_RT_REG_BINARY,
            nullptr,
            &ChangedList[0],
            &dataSize);
    }
    else if (retCode == ERROR_FILE_NOT_FOUND)
    {
        retCode = ERROR_SUCCESS;
    }

    return (retCode == ERROR_SUCCESS) ? STATUS_SUCCESS : STATUS_UPDATE_FILE_ERROR;
}

/**
 * @brief Store version metadata from the registry in order to check which files changed after an update
 *
 * @param[in]  SubKey               Registry Key where the data is stored
 * @param[in]  Value                Registry Value where the data is stored
 * @param[out] ChangedList          List of files with version metadata
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
PutChangesListInRegistry(
    _In_ const std::wstring& SubKey,
    _In_ const std::wstring& Value,
    _In_ const CHANGED_LIST& ChangedList
)
{
    LONG retCode = ERROR_SUCCESS;

    retCode = RegSetKeyValue(
        HKEY_LOCAL_MACHINE,
        SubKey.c_str(),
        Value.c_str(),
        RRF_RT_ANY,//REG_BINARY,
        &ChangedList[0],
        (DWORD)(ChangedList.size() * sizeof(CHANGED_ITEM)));

    return (retCode == ERROR_SUCCESS) ? STATUS_SUCCESS : STATUS_UPDATE_FILE_ERROR;
}

/**
 * @brief Update version metadata in order to check which files changed after an update
 *
 * @param[in]  InstallFiles         List of installation files
 * @param[in]  InstallFilesCount    Count of InstallFiles
 * @param[out] ChangedList          List of files with version metadata
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
UpdateChangesList(
    _In_ const LD_INSTALL_FILE* InstallFiles,
    _In_ DWORD InstallFilesCount,
    _Out_ CHANGED_LIST& ChangedList
)
{
    NTSTATUS status = STATUS_SUCCESS;
    const LD_INSTALL_FILE* oneFile = NULL;
    std::wstring sourceFullPath;

    for (DWORD i = 0; i < InstallFilesCount; i++)
    {
        std::ifstream inFile;
        oneFile = &InstallFiles[i];

        if (gSdkDirs[oneFile->SourceDir].empty() || gSdkDirs[oneFile->SourceDir][0] == L'\0')
        {
            continue;
        }

        if (oneFile->SourceFileName == NULL || gSdkDirs[oneFile->SourceDir].empty())
        {
            continue;
        }

        sourceFullPath = gSdkDirs[oneFile->SourceDir] + oneFile->SourceFileName;

        inFile.open(sourceFullPath.c_str(), std::ios::in | std::ios::binary);

        if (inFile.is_open())
        {
            // Stop eating new lines in binary mode!!!
            inFile.unsetf(std::ios::skipws);

            // get its size:
            std::streampos fileSize;

            inFile.seekg(0, std::ios::end);
            fileSize = inFile.tellg();
            inFile.seekg(0, std::ios::beg);

            // reserve capacity
            std::vector<unsigned char> vec;
            vec.reserve((std::vector<unsigned char>::size_type)(fileSize));

            vec.insert(vec.begin(),
                std::istream_iterator<unsigned char>(inFile),
                std::istream_iterator<unsigned char>()
            );

            // update hash if an entry exists
            bool found = false;
            for (auto&& chgItem : ChangedList)
            {
                if (chgItem.Id == oneFile->UniqueId)
                {
                    chgItem.CurrentHash = Crc32(0, vec.data(), vec.size());
                    found = true;
                    break;
                }
            }

            // add a new entry if one is not found
            if (!found)
            {
                CHANGED_ITEM chgItem;
                chgItem.Id = oneFile->UniqueId;
                chgItem.CurrentHash = Crc32(0, vec.data(), vec.size());
                chgItem.PrevHash = chgItem.CurrentHash;

                ChangedList.push_back(chgItem);
            }

            inFile.close();
        }
    }

    for (const CHANGED_ITEM& chgItem : ChangedList)
    {
        LogInfo("Id 0x%llx PrevHash 0x%llx CurrentHash 0x%llx\n", chgItem.Id, chgItem.PrevHash, chgItem.CurrentHash);
    }

    return status;
}

/**
 * @brief Get an update completion status that can be returned to the integrator
 *
 * @param[in]  InitialStatus        Status returned by update APIs
 * @param[in]  Components           Flags that identify which components were updated
 *
 * @return STATUS_UPDATE_RECOMMENDS_REBOOT          A reboot should be performed after the update in order to fully load the updates because they could not be updated due to unforseen circumstances
 * @return STATUS_UPDATE_REQUIRES_REBOOT            A reboot must be performed after the update in order to load the updates or fix critical security vulnerabilities
 * @return STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE  A reboot should be performed in order to finish the update
 * @return STATUS_UPDATE_FILE_ERROR                 Inconsistent internal file metadata
 * @return OTHER                                    Other potential internal error
 */
NTSTATUS
DetermineUpdateStatus(
    _In_ NTSTATUS InitialStatus,
    _In_ DWORD Components
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CHANGED_LIST changedList = {};

    // Determine a list of different files since previous successful update
    status = GetChangesListFromRegistry(REG_SUBKEY_GENERAL_SETTINGS, REG_VALUE_CHANGES_LIST, changedList);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetChangesListFromRegistry");
        return status;
    }

    // update the list with new hashes
    status = UpdateChangesList(gInstallFiles, gInstallFilesCount, changedList);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "UpdateChangesList");
        return status;
    }

    if (Components != 0)
    {
        switch (InitialStatus)
        {
        case STATUS_UPDATE_RECOMMENDS_REBOOT:
        case STATUS_UPDATE_REQUIRES_REBOOT:
        case STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE:
            status = InitialStatus;
            LogInfo("Override initial status 0x%x to 0x%x\n", InitialStatus, status);
            break;
        case CX_STATUS_NOT_SUPPORTED:                      // intro / exceptii incompatibile cu hv / hvi => reboot ar trebui sa rezolve
        case CX_STATUS_INSUFFICIENT_RESOURCES:             // nu mai avem memorie in hv sa facem update => dupa reboot se rezolva
            // add here other technology error codes that might be resolved by a reboot
            status = STATUS_UPDATE_RECOMMENDS_REBOOT;
            LogInfo("Override initial status 0x%x to 0x%x\n", InitialStatus, status);
            break;
        case CX_STATUS_OBJECT_TYPE_MISMATCH:       // fisiere invalide (exceptii) => reboot nu rezolva nimic
//          case STATUS_INVALID_OBJECT_TYPE:        // fisiere invalide (exceptii) => reboot nu rezolva nimic
//          case STATUS_INCONSISTENT_DATA_VALUE:    // fisiere invalide (exceptii) => reboot nu rezolva nimic
        default:
            // add here any other technology error codes that will not be resolved by a reboot
            // these errors will be forwarded to integrators
            if (!NT_SUCCESS(InitialStatus))
            {
                LogFuncErrorStatus(InitialStatus, "DetermineUpdateStatus");
                return InitialStatus;
            }
        }

        for (DWORD i = undefinedId; i < maxuniqueid; i++)
        {
            CHANGED_ITEM* item = NULL;

            item = GetChangedItemForId(changedList, static_cast<LD_UNIQUE_ID>(i));
            switch (i)
            {
            case napocabin:
            case introcorebin:
                if ((Components & FLAG_UPDATE_COMPONENT_BASE) == 0)
                {
                    break;
                }

                if (item == NULL)
                {
                    status = STATUS_UPDATE_FILE_ERROR;
                    break;
                }

                // in this case we need to recommend a reboot since napoca, intro cannot be updated on the fly
                if (item->PrevHash != item->CurrentHash)
                {
                    status = min(status, STATUS_UPDATE_RECOMMENDS_REBOOT);

                    item->PrevHash = item->CurrentHash;
                }
                break;

            break;
                break;
            case exceptionsbin:
            case introliveupdtbin:
                if ((Components & FLAG_UPDATE_COMPONENT_INTRO_UPDATES) == 0)
                {
                    break;
                }

                if (item == NULL)
                {
                    status = STATUS_UPDATE_FILE_ERROR;
                    break;
                }

                // same as for introcore
                if (item->PrevHash != item->CurrentHash)
                {
                    item->PrevHash = item->CurrentHash;
                }
                break;
            default:
                break;
            }
        }
    }

    // discard errors
    PutChangesListInRegistry(REG_SUBKEY_GENERAL_SETTINGS, REG_VALUE_CHANGES_LIST, changedList);

    return status;
}

/**
 * @brief Load version metadata from the registry and compute changed metadata for installation files
 *
 * @param[out] ChangedList          List of files with version metadata
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
_DetermineChangedList(
    _Out_ CHANGED_LIST* ChangedList
)
{
    NTSTATUS status;
    // We assume ChangedList is not NULL, this function being an internal function.

    // Determine a list of different files since previous successful update
    status = GetChangesListFromRegistry(REG_SUBKEY_GENERAL_SETTINGS, REG_VALUE_CHANGES_LIST, *ChangedList);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetChangesListFromRegistry");
        return status;
    }

    // update the list with new hashes
    status = UpdateChangesList(gInstallFiles, gInstallFilesCount, *ChangedList);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "UpdateChangesList");
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Check if the introspection engine must be reloaded from the disk because there is a new version
 *
 * @param[out] Flag             Will add MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK to the flags in request module updates
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
DetermineIntroUpdate(
    _Out_   unsigned long long  *Flag
)
{
    // We assume Flag is not NULL, this function being an internal function.
    NTSTATUS status = STATUS_SUCCESS;
    CHANGED_LIST changedList;
    status = _DetermineChangedList(&changedList);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DetermineChangedList");
        *Flag = MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK;
    }
    else
    {
        CHANGED_ITEM* item = NULL;
        item = GetChangedItemForId(changedList, introcorebin);
        if (item->PrevHash == item->CurrentHash)
        {
            // hashes are the same, so do not reload introcore
            *Flag = 0;
        }
        else
        {
            // hashes changed, so reload introcorebin from disk, flag remains MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK
            *Flag = MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK;
        }
    }
    return status;
}

/**
 * @brief Set the path where the Napoca SDK is located in order to be able to locate required files
 *
 * @param[in] SDKPath           Path to the Napoca SDK
 */
void
SetSDKPath(
    std::wstring const& SDKPath
)
{
    auto uefi = IsUefiBootedOs();

    gSdkDirs[SDK_DIR_HV] = SDKPath;
    gSdkDirs[uefi ? SDK_DIR_EFI : SDK_DIR_MBR] = gSdkDirs[SDK_DIR_HV] + (uefi ? EFI_CONFIG_BINARIES_FOLDER : LEGACY_CONFIG_BINARIES_FOLDER);
}

/**
 * @brief Set the path where the Introspection updates are located in order to be able to locate required files
 *
 * @param[in] UpdatesIntroPath      Path to the Introspection updates
 */
void
SetUpdatesIntroDir(
    std::wstring const& UpdatesIntroPath
)
{
    gSdkDirs[SDK_DIR_UPDATES_INTRO] = UpdatesIntroPath;
}

/**
 * @brief Expand Napoca HV command line macros to full variable names
 *
 * @param[in]  Input             Command line containing macros
 * @param[out] Result            Updated command line with expanded macros
 *
 * @return STATUS_SUCCESS
 * @return OTHER                 Other potential internal error
 */
NTSTATUS
ExpandCmdlineMacros(
    _In_  std::string const &Input,
    _Out_ std::string &Result
)
{
    std::regex rx;
    std::string result = Input;

    for (DWORD i = 0; i < _countof(gCmdlineMacros); i++)
    {
        rx = std::string("\\b(") + gCmdlineMacros[i].Name + ")\\b";
        result = std::regex_replace(result, rx, gCmdlineMacros[i].Body);
    }

    Result.swap(result);

    return STATUS_SUCCESS;
}

/**
 * @brief Load a command line from disk
 *
 * @param[in]  CmdLine           Unique identifier to know which command line is required
 *
 * @return STATUS_SUCCESS
 * @return OTHER                 Other potential internal error
 */
NTSTATUS
LoadConfigData(
    _In_ LD_UNIQUE_ID CmdLine
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    LD_INSTALL_FILE* cmd = NULL;
    std::wstring cmdPath;
    HANDLE cmdFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER cmdFileSize;
    std::string cmdDefaultBuf;
    DWORD nrOfBytes = 0;
    UD_NUMBER consumed;

    // get the filepath for the final cmd line

    cmd = GetInstallFileForUniqueId(CmdLine);
    if (!cmd)
    {
        status = STATUS_FILE_NOT_AVAILABLE;
        LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
        return status;
    }

    cmdPath = gSdkDirs[cmd->SourceDir];
    cmdPath += cmd->SourceFileName;

    cmdFile = CreateFile(
        cmdPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (cmdFile == INVALID_HANDLE_VALUE)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        goto cleanup;
    }

    if (!GetFileSizeEx(cmdFile, &cmdFileSize))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "GetFileSizeEx");
        goto cleanup;
    }

    if (cmdFileSize.HighPart != 0 || cmdFileSize.LowPart == 0 || cmdFileSize.LowPart > 4 * ONE_MEGABYTE)
    {
        status = STATUS_FILE_CORRUPT_ERROR;
        goto cleanup;
    }

    cmdDefaultBuf.resize(cmdFileSize.LowPart);

    if (!ReadFile(cmdFile, &cmdDefaultBuf[0], cmdFileSize.LowPart, &nrOfBytes, NULL))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "ReadFile");
        goto cleanup;
    }

    if (!UdMatchVariablesFromText(HvCommandLineVariablesInfo, _countof(HvCommandLineVariablesInfo), const_cast<char*>(cmdDefaultBuf.c_str()), cmdFileSize.LowPart, &consumed))
    {
        status = STATUS_FILE_CORRUPT_ERROR;
        LogFuncErrorStatus(status, "UdMatchVariablesFromText");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (cmdFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(cmdFile);
    }

    return status;
}

/**
 * @brief Create the final command line module file from the default one and overrides
 *
 * @param[in]  Update           If TRUE, use the previous final command line as a starting point, otherwise use the defaults
 * @param[in] CustomCmdLine     Custom overrides to be applied to the command line
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
CreateFinalConfigData(
    _In_ BOOLEAN Update,
    _In_opt_ std::string const& CustomCmdLine
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD lastErr = ERROR_SUCCESS;
    LD_INSTALL_FILE* defaultCmd = NULL;
    LD_INSTALL_FILE* finalCmd = NULL;
    std::wstring defaultCmdPath;
    std::wstring finalCmdPath;
    HANDLE cmdDefaultFile = INVALID_HANDLE_VALUE;
    HANDLE cmdFinalFile = INVALID_HANDLE_VALUE;
    std::string cmdFinalBuf;
    UD_NUMBER consumed = 0;
    QWORD newSize = 0;
    DWORD nrOfBytes = 0;

    finalCmd = GetInstallFileForUniqueId(finalCmdLine);
    if (!finalCmd)
    {
        status = STATUS_FILE_NOT_AVAILABLE;
        LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
        goto cleanup;
    }

    defaultCmd = Update
        ? finalCmd
        : GetInstallFileForUniqueId(defaultCmdLine);
    if (!defaultCmd)
    {
        status = STATUS_FILE_NOT_AVAILABLE;
        LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
        goto cleanup;
    }

    defaultCmdPath = gSdkDirs[defaultCmd->SourceDir];
    defaultCmdPath += defaultCmd->SourceFileName;

    finalCmdPath = gSdkDirs[finalCmd->SourceDir];
    finalCmdPath += finalCmd->SourceFileName;

    if (defaultCmd != finalCmd && CustomCmdLine.empty())
    {
        // We don't need to alter the default command line. Just copy it and return.
        if (!CopyFile(defaultCmdPath.c_str(), finalCmdPath.c_str(), FALSE))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "CopyFile");
            goto cleanup;
        }

        goto cleanup;
    }

    if (Update)
    {
        status = LoadConfigData(finalCmdLine);
        if (!NT_SUCCESS(status))
        {
            LogWarning("Failed to load final cmd line\n");
        }
    }
    // if is NOT an update or we failed to load the finalcmdline -> load the default one
    if (!Update || !NT_SUCCESS(status))
    {
        status = LoadConfigData(defaultCmdLine);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "LoadConfigData");
            goto cleanup;
        }
    }

    if (!CustomCmdLine.empty())
    {
        std::string expandedCmdline;
        status = ExpandCmdlineMacros(CustomCmdLine, expandedCmdline);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ExpandCmdlineMacros");
            goto cleanup;
        }

        if (expandedCmdline.length() > 0)
        {
            if (!UdMatchVariablesFromText(HvCommandLineVariablesInfo, _countof(HvCommandLineVariablesInfo), (char*)expandedCmdline.c_str(), expandedCmdline.length(), &consumed))
            {
                status = STATUS_FILE_CORRUPT_ERROR;
                LogFuncErrorStatus(status,  "UdMatchVariablesFromText");
                goto cleanup;
            }
        }
    }

    UdDumpVariablesToText(HvCommandLineVariablesInfo, _countof(HvCommandLineVariablesInfo), NULL, 0, &newSize);
    if (newSize <= 1 || newSize > 4 * ONE_MEGABYTE)
    {
        status = STATUS_INVALID_BUFFER_SIZE;
        LogFuncErrorStatus(status, "UdDumpVariablesToText");
        goto cleanup;
    }

    cmdFinalBuf.resize(static_cast<DWORD>(newSize) - 1);

    if (!UdDumpVariablesToText(HvCommandLineVariablesInfo, _countof(HvCommandLineVariablesInfo), &cmdFinalBuf[0], newSize, (UD_NUMBER*)&consumed))
    {
        status = STATUS_VARIABLE_NOT_FOUND;
        LogFuncErrorStatus(status, "UdDumpVariablesToText");
        goto cleanup;
    }

    cmdFinalFile = CreateFile(
        finalCmdPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (cmdFinalFile == INVALID_HANDLE_VALUE)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        goto cleanup;
    }

    if (!WriteFile(cmdFinalFile, cmdFinalBuf.c_str(), static_cast<DWORD>(cmdFinalBuf.size()), &nrOfBytes, NULL))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "WriteFile");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (cmdFinalFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(cmdFinalFile);
    }

    if (cmdDefaultFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(cmdDefaultFile);
    }

    return status;
}

/**
 * @brief Deploy/Remove the hypervisor (UEFI/legacy boot)
 *
 * @param[in] Enable            If TRUE, install the hypervisor. IF FALSE, uninstall.
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
ConfigureBoot(
    __in BOOLEAN Enable
)
{
    LogVerbose("%sconfiguring hypervisor", Enable ? "" : "de");

    return IsUefiBootedOs()
        ? ConfigureUefiBoot(Enable)
        : ConfigureLegacyBoot(Enable);
}

/**
 * @brief Update only installed files without full reconfiguration
 *
 * @param[in] Flags             Flags that specify which files must be updated
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
UpdateBootFiles(
    LD_INSTALL_FILE_FLAGS Flags
)
{
    if (!gHypervisorConfigured)
        return STATUS_SUCCESS;

    return IsUefiBootedOs()
        ? DeployUefiBootFiles(Flags)
        : DeployGrubBootFiles(Flags, FALSE);
}
