/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file utils_kernel.cpp
*   @brief APIs that use Ntdll.dll APIs
*/

#include <string>
#include <vector>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#include <winioctl.h>
#include <shlwapi.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "helpers.h"

#include "winguest_status.h"
#include "trace.h"
#include "utils_kernel.tmh"
#include "reg_opts.h"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#define PARTITION_SYSTEM_GUID               {0xc12a7328, 0xf81f, 0x11d2, {0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}}

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsVolumeFlagsInformation,// 10
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _FILE_FS_DEVICE_INFORMATION {
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

#define OBJ_INHERIT                     0x00000002L
#define OBJ_PERMANENT                   0x00000010L
#define OBJ_EXCLUSIVE                   0x00000020L
#define OBJ_CASE_INSENSITIVE            0x00000040L
#define OBJ_OPENIF                      0x00000080L
#define OBJ_OPENLINK                    0x00000100L
#define OBJ_KERNEL_HANDLE               0x00000200L
#define OBJ_FORCE_ACCESS_CHECK          0x00000400L
#define OBJ_VALID_ATTRIBUTES            0x000007F2L

#define DIRECTORY_QUERY                 0x00000001
#define DIRECTORY_TRAVERSE              0x00000002
#define DIRECTORY_CREATE_OBJECT         0x00000004
#define DIRECTORY_CREATE_SUBDIRECTORY   0x00000008

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef NTSTATUS(NTAPI *FUNC_NtQueryDirectoryObject)(
    IN HANDLE               DirectoryObjectHandle,
    OUT POBJECT_DIRECTORY_INFORMATION DirObjInformation,
    IN ULONG                BufferLength,
    IN BOOLEAN              GetNextIndex,
    IN BOOLEAN              IgnoreInputIndex,
    IN OUT PULONG           ObjectIndex,
    OUT PULONG              DataWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* FUNC_NtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI *FUNC_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

typedef NTSTATUS(NTAPI* FUNC_NtQueryVolumeInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    DWORD FsInformationClass
    );

typedef NTSTATUS(NTAPI *FUNC_NtClose)(
    HANDLE Handle
    );

#define STATIC_WSTR_TO_UNICODE(ConstString)     {sizeof(ConstString)-sizeof(L""), sizeof(ConstString), (ConstString)}

#define EFI_PARTITION_SYMBOLIC_LINK     L"\\\\?\\SystemPartition\\"

#define MAX_REG_QUERY_SIZE              sizeof(L"\\Device\\HarddiskVolumeXYZ")
#define REG_QUERY_PREFIX                L"\\Device\\HarddiskVolume"
#define REG_QUERY_PREFIX_LEN            STATIC_LEN(REG_QUERY_PREFIX)

#define GLOBAL_ACCESS_PREFIX            L"\\\\?"
#define GLOBAL_ACCESS_PREFIX_LEN        STATIC_LEN(GLOBAL_ACCESS_PREFIX)

#define DEVICE_PREFIX                   L"\\Device"
#define DEVICE_PREFIX_LEN               STATIC_LEN(DEVICE_PREFIX)

/**
 * @brief Retrieve backed up Efi Partition Path from the registry
 *
 * @param[out]    Buffer                Buffer to store the path
 * @param[in,out] BufferSizeInBytes     Size of Buffer
 *
 * @return pointer              Pointer to requested table
 * @return NULL                 No table found that matches the type or not enough tables to reach the index
 */
static
NTSTATUS
_GetEfiPartitionFromRegistry(
    _Out_   WCHAR       *Buffer,
    _Inout_ DWORD       *BufferSizeInBytes
)
{
    LSTATUS lStatus = ERROR_SUCCESS;

    lStatus = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_SYSTEM_PARTITION,
        REG_VALUE_SYSTEM_PARTITION,
        RRF_RT_REG_SZ,
        NULL,
        (BYTE *)Buffer,
        BufferSizeInBytes);

    return (lStatus == ERROR_SUCCESS) ? STATUS_SUCCESS : WIN32_TO_NTSTATUS(lStatus);
}

/**
 * @brief Get a Symbolic Link path from a Partition path
 *
 * @param[in]  PartitionPath                Path to partition
 * @param[in]  PartitionPathSizeInBytes     Size of PartitionPath
 * @param[out] SymbolicPath                 Buffer to store the computed symbolic link
 *
 * @return TRUE              successful
 * @return FALSE             unsuccessful
 */
static
BOOL
_GetSymbolicLinkFromPartitionPath(
    _In_    const WCHAR     *PartitionPath,
    _In_    DWORD           PartitionPathSizeInBytes,
    _Out_   WCHAR           *SymbolicPath
)
{
    if (wcsncmp(PartitionPath, REG_QUERY_PREFIX, REG_QUERY_PREFIX_LEN) != 0) return FALSE;

    wmemcpy(SymbolicPath, GLOBAL_ACCESS_PREFIX, GLOBAL_ACCESS_PREFIX_LEN);
    memmove(SymbolicPath + GLOBAL_ACCESS_PREFIX_LEN, PartitionPath + DEVICE_PREFIX_LEN, PartitionPathSizeInBytes - DEVICE_PREFIX_LEN * sizeof(WCHAR));

    return TRUE;
}

/**
 * @brief Get Active EFI Partition Path
 *
 * @param[out] Partition            Path to active EFI partition
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
_GetActiveEfiPartition(
    _Out_   std::wstring& Partition
)
{
    NTSTATUS status = STATUS_FILE_NOT_AVAILABLE;
    PWCHAR efiPartition = NULL;

    __try
    {
        // try opening the symbolic link
        if (PathFileExistsW(EFI_PARTITION_SYMBOLIC_LINK))
        {
            status = STATUS_SUCCESS;
            efiPartition = EFI_PARTITION_SYMBOLIC_LINK;
            __leave;
        }

        LogWarning("_IsPathValid failed for path [%S]. Will try to query the registry - probably OS older than RS2\n", EFI_PARTITION_SYMBOLIC_LINK);

        WCHAR regPartition[MAX_REG_QUERY_SIZE / sizeof(WCHAR)];
        DWORD bufferSize = MAX_REG_QUERY_SIZE;
        status = _GetEfiPartitionFromRegistry(regPartition, &bufferSize);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "_GetEfiPartitionFromRegistry");
            __leave;
        }

        // If we're here we'll have a path '\\Device\\HarddiskVolumeX'
        // => we need to convert it to     '\\\\?\\HarddiskVolumeX'
        if (!_GetSymbolicLinkFromPartitionPath(regPartition, bufferSize, regPartition))
        {
            LogError("Couldn't 'convert' [%S] to symbolic link!\n", regPartition);
            status = STATUS_REPARSE_POINT_NOT_RESOLVED;
            __leave;
        }

        wcscat_s(regPartition, L"\\");

        if (PathFileExistsW(regPartition))
        {
            status = STATUS_SUCCESS;
            efiPartition = regPartition;
            __leave;
        }

        LogWarning("_IsPathValid failed for path [%S]. This should work!\n", regPartition);

        status = STATUS_FILE_NOT_AVAILABLE;
    }
    __finally
    {
        if (NT_SUCCESS(status))
        {
            Partition = efiPartition;
        }
    }

    return status;
}

/**
 * @brief Enumerate all EFI partitions in the system
 *
 * @param[out] Partitions           Vector of EFI Partition Paths
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
EnumEfiPartitions(
    std::vector<std::wstring> &Partitions
)
{
    // note: FindFirstVolume and friends will not list EFI partitions!!!

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE rootHandle = NULL;
    OBJECT_ATTRIBUTES attr = {};
    DWORD written = 0;
    DWORD queryContext = 0;
    BOOLEAN queryRestart = TRUE;
    DWORD returned = 0;
    HANDLE devHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    FILE_FS_DEVICE_INFORMATION fsInfo = {};
    PARTITION_INFORMATION_EX info = {};
    GUID efiPartition = PARTITION_SYSTEM_GUID;

    UNICODE_STRING typeDevice = STATIC_WSTR_TO_UNICODE(L"Device");
    UNICODE_STRING rootDir = STATIC_WSTR_TO_UNICODE(L"\\Device");
    UNICODE_STRING volumePrefix = STATIC_WSTR_TO_UNICODE(L"HarddiskVolume");
    UNICODE_STRING devicePathUS = {};
    WCHAR devicePath[MAX_PATH] = { 0 };
    std::wstring devicePathUm;

    Partitions.clear();

    // Before we enum all the EFI partitions we try to see if we can
    // determine the active one
    // 1. Try to open the symbolic link \\\\?\\SystemPartition
    // 2. Try to query the REG_SZ from HKLM\SYSTEM\SETUP\SystemPartition
    //    and convert it from \\Device\\HarddiskVolumeXYZ -> \\\\?\\HardiskVolumeXYZ
    status = _GetActiveEfiPartition(devicePathUm);
    if (NT_SUCCESS(status))
    {
        Partitions.push_back(devicePathUm);
        return STATUS_SUCCESS;
    }
    else
    {
        LogWarning("_GetActiveEfiPartition failed with status %!STATUS! Will fallback to the standard enumeration\n", status);
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return STATUS_APISET_NOT_PRESENT;

    FUNC_NtQueryDirectoryObject pfnNtQueryDirectoryObject = (FUNC_NtQueryDirectoryObject)GetProcAddress(hNtdll, "NtQueryDirectoryObject");
    FUNC_NtOpenDirectoryObject pfnOpenDirectoryObject = (FUNC_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    FUNC_NtCreateFile pfnNtCreateFile = (FUNC_NtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    FUNC_NtQueryVolumeInformationFile pfnNtQueryVolumeInformationFile = (FUNC_NtQueryVolumeInformationFile)GetProcAddress(hNtdll, "NtQueryVolumeInformationFile");
    FUNC_NtClose pfnNtClose = (FUNC_NtClose)GetProcAddress(hNtdll, "NtClose");

    if (
        (!pfnNtQueryDirectoryObject)
        || (!pfnOpenDirectoryObject)
        || (!pfnNtCreateFile)
        || (!pfnNtQueryVolumeInformationFile)
        || (!pfnNtClose)
        )
    {
        return STATUS_APISET_NOT_PRESENT;
    }

    LogVerbose("Starting EFI partition enum\n");

    DWORD objInfoSz = 4096;
    std::unique_ptr<BYTE[]> objInfoBuf = std::make_unique<BYTE[]>(objInfoSz);

    // sometimes NtQueryDirectoryObject fails to list all devices.
    for (DWORD i = 0; i < 5 && !NT_SUCCESS(status); i++)
    {
        LogVerbose("Starting loop %u\n", i);

        InitializeObjectAttributes(&attr, &rootDir, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = pfnOpenDirectoryObject(&rootHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attr);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ZwOpenDirectoryObject");
            goto cleanup_directory;
        }

        queryRestart = TRUE;

        for (;;)
        {
            memset(objInfoBuf.get(), 0, objInfoSz);

            status = pfnNtQueryDirectoryObject(rootHandle, reinterpret_cast<OBJECT_DIRECTORY_INFORMATION*>(objInfoBuf.get()), objInfoSz, TRUE, queryRestart, &queryContext, &written);
            if (!NT_SUCCESS(status))
            {
                if (STATUS_BUFFER_OVERFLOW == status)
                {
                    objInfoSz *= 2;
                    objInfoBuf = std::make_unique<BYTE[]>(objInfoSz);
                    continue;
                }
                else
                {
                    if (status != STATUS_NO_MORE_ENTRIES) LogFuncErrorStatus(status, "NtQueryDirectoryObject");
                    break;
                }
            }

            queryRestart = FALSE;

            OBJECT_DIRECTORY_INFORMATION *objInfo = reinterpret_cast<OBJECT_DIRECTORY_INFORMATION *>(objInfoBuf.get());

            if (typeDevice.Length != objInfo->TypeName.Length
                || 0 != wcsncmp(typeDevice.Buffer, objInfo->TypeName.Buffer, typeDevice.Length / sizeof(WCHAR)))
            {
                continue; // We only need devices
            }

            if (volumePrefix.Length > objInfo->Name.Length
                || 0 != wcsncmp(volumePrefix.Buffer, objInfo->Name.Buffer, volumePrefix.Length / sizeof(WCHAR)))
            {
                continue; // Try only "HarddiskVolume"s because sometimes some devices can crash when opened and hopefully Windows uses consistent names
            }

            _set_errno(0);
            if ((DWORD)-1 == swprintf_s(devicePath, L"%wZ\\%wZ", rootDir, objInfo->Name))
            {
                LogFuncError(errno, "swprintf_s");
                status = WIN32_TO_NTSTATUS(errno);
                goto cleanup_directory;
            }

            devicePathUS.Buffer = devicePath;
            devicePathUS.Length = rootDir.Length + objInfo->Name.Length + sizeof(WCHAR);
            devicePathUS.MaximumLength = _countof(devicePath);

            InitializeObjectAttributes(&attr, &devicePathUS, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = pfnNtCreateFile(
                &devHandle,
                GENERIC_READ,
                &attr,
                &ioStatus,
                NULL,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_ATTRIBUTE_NORMAL,
                NULL,
                0
            );
            if (!NT_SUCCESS(status))
            {
                goto cleanup_device;
            }

            RtlSecureZeroMemory(&ioStatus, sizeof(ioStatus));
            status = pfnNtQueryVolumeInformationFile(devHandle, &ioStatus, &fsInfo, sizeof(FILE_FS_DEVICE_INFORMATION), FileFsDeviceInformation);
            if (!NT_SUCCESS(status))
            {
                goto cleanup_device;
            }

            if (FILE_DEVICE_DISK != fsInfo.DeviceType) goto cleanup_device;

            RtlSecureZeroMemory(&info, sizeof(info));
            if (DeviceIoControl(devHandle, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &info, sizeof(info), &returned, NULL))
            {
                if (RtlEqualMemory(&info.Gpt.PartitionType, &efiPartition, sizeof(GUID)))
                {
                    devicePathUm = (std::wstring)L"\\\\?\\" + std::wstring(objInfo->Name.Buffer, objInfo->Name.Length / sizeof(WCHAR)) + L"\\";

                    Partitions.push_back(devicePathUm);
                }
            }

        cleanup_device:
            if (NULL != devHandle)
            {
                pfnNtClose(devHandle);
                devHandle = NULL;
            }
        }

        status = STATUS_SUCCESS;

    cleanup_directory:
        if (!NT_SUCCESS(status))
        {
            Partitions.clear();
        }

        if (NT_SUCCESS(status) && Partitions.empty())
        {
            LogError("No partitions were found!\n");
            status = STATUS_NOT_FOUND;
        }
    }

    LogVerbose("Finished EFI partition enum\n");

    return status;
}