/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file deploy_legacy.cpp
*   @brief Hypervisor deployment on legacy systems
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <winioctl.h>
#include <shlwapi.h>

#include "deploy_legacy.h"
#include "helpers.h"
#include "winguest_status.h"
#include "libapis.h"
#include "deploy_validation.h"
#include "reg_opts.h"
#include "grub_env.h"
#include "deploy.h"
#include "trace.h"
#include "deploy_legacy.tmh"

#define SECTOR_SIZE 512

#define DRIVE_PATH_GENERIC "\\\\.\\PhysicalDrive"           // used for paths like "\\\\.\\PhysicalDrive0", etc

// Multiboot hypervisor modules
#define MODULE_COMMAND_LINE_STRING      "commandLine"
#define MODULE_LEGACY_BOOT_STRING       "settings"
#define MODULE_EXCEPTIONS_STRING        "exceptions"
#define MODULE_GUEST_LOADER_STRING      "guestLoader"

// Files and folders for installation
#define NAPOCAHV_BOOT_DIRECTORY         "NapocaHv"
#define GRUB_CONFIG_NAME                "grub.cfg"
#define DEFAULT_SETTINGS_NAME           "boot.module"
#define RECOVERY_SETTINGS_NAME          "recovery.module"
#define GRUB_ENVIRONMENT_NAME           "bdenv"

// Grub 2 Environment definitions
#define GRUB_ENVIRONMENT_SIGNATURE      "# GRUB Environment Block"
#define GRUB_VAR_CURRENT_ATTEMPT        "current_attempt"
#define GRUB_VAR_MAX_ATTEMPTS           "max_attempts"
#define GRUB_VAR_LM_BOOT                "monitor_boot"
#define GRUB_VAR_LM_CRASH               "monitor_crash"

#define GRUB_NUMBER_OF_LOADER_SECTORS       18          // currently grub-2.02 seems to write 18 sectors
#define MBR_WINDOWS_CODE_SECTION_LENGTH     0x164       // BUGS: Should be 0x163, and this is valid only for Win7+, can be extrated from the MBR to be compatible with Win2k+

#define INVALID_HARDDISK                    0xFFFFFFFF

// Checksums for known Windows MBRs
#define WINDOWS_XP_MBR_CHECKSUM_1           0x0a585640
#define WINDOWS_XP_MBR_CHECKSUM_2           0x08016b30

#define WINDOWS_7_8_10_MBR_CHECKSUM_1       0x0ab75f3c
#define WINDOWS_7_8_10_MBR_CHECKSUM_2       0x0850f650

#define WINDOWS_SERVER_MBR_CHECKSUM_1       0x0105a6d0
#define WINDOWS_SERVER_MBR_CHECKSUM_2       0xfe936082

#define WINDOWS_7_8_COMPACT_MBR_CHECKSUM_1  0x444c039c
#define WINDOWS_7_8_COMPACT_MBR_CHECKSUM_2  0x4021b2be

static std::wstring gPartitionVolumeGuid;

extern LD_INSTALL_FILE gInstallFiles[];
extern DWORD gInstallFilesCount;
extern std::wstring gSdkDirs[];

typedef struct _MBR_POS
{
    WORD Offset;
    BYTE Value;
} MBR_POS;

// GRUB 2 Signature - based on grub-2.02
// we change these bytes to identify that the GRUB MBR was installed by us
static const MBR_POS GRUB_SIGNATURE[] = { {0x2, 0xF4}, {0x66, 0xF5}, {0x67, 0xF5} };
// offset       original value      new value       description
// 0x02         0x90 (NOP)          0xF4 (HLT)      never executed as it follows the first JMP
// 0x66         0x90 (NOP)          0xF5 (CMC)      2 consecutive CMCs have no effect
// 0x67         0x90 (NOP)          0xF5 (CMC)      see above

#define GRUB_SIGNATURE_STRING           "GRUB "
#define GRUB_SIGNATURE_STRING_OFFSET    0x180   // based on grub-2.02


#pragma pack(push, 1)
typedef struct
{
    BYTE Status;
    BYTE ChsFirst[3];
    BYTE PartitionType;
    BYTE ChsLast[3];
    DWORD Lba;
    DWORD NumberOfSectors;
} PARTITION_ENTRY_LAYOUT, *PPARTITION_ENTRY_LAYOUT;

typedef struct
{
    BYTE BootStrapCodeArea[0x1BE];
    PARTITION_ENTRY_LAYOUT Partitions[4];
    WORD Signature;
} MBR_LAYOUT;
#pragma pack(pop)

#define MBR_SIGNATURE                   0xAA55
#define PARTITION_TYPE_DYNAMIC_EXTENDED 0x42
#define PARTITION_TYPE_GPT              0xEE


static
NTSTATUS
GetInstallationInfoFromRegistry(
    void
);

//////////////////////////////////////////////////////////////////////////
/// FILESYSTEM OPERATIONS
//////////////////////////////////////////////////////////////////////////

/**
 * @brief Flush System Partition writes to limit corruption
 *
 * @param[in] SystemRoot            Path to system partition
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
FlushSystemPartition(
    std::wstring const& SystemRoot
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    HANDLE volume = INVALID_HANDLE_VALUE;

    __try
    {
        volume = CreateFile(
            SystemRoot.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (INVALID_HANDLE_VALUE == volume)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "CreateFile");
            __leave;
        }

        if (!FlushFileBuffers(volume))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "FlushFileBuffers");
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != volume)
        {
            CloseHandle(volume);
        }
    }

    return status;
}

/**
 * @brief Determine the physical location properties of the volume (disk number, starting offset, length)
 *
 * @param[in]  VolumeGuid       GUID path of volume
 * @param[out] DiskExtent       Disk properties
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetVolumeDiskExtents(
    _In_ std::wstring const& VolumeGuid,
    _Out_ PDISK_EXTENT DiskExtent
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE driveHandle = INVALID_HANDLE_VALUE;
    DWORD lpBytesReturned = 0;
    DWORD nrOfDiskExtents = 1;

    if (!DiskExtent)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    driveHandle = CreateFile(
        VolumeGuid.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );
    if (INVALID_HANDLE_VALUE == driveHandle)
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "CreateFile(%S)", VolumeGuid.c_str());
        return WIN32_TO_NTSTATUS(lastErr);
    }

    std::unique_ptr<BYTE[]> diskExtentsBuf = std::make_unique<BYTE[]>(sizeof(VOLUME_DISK_EXTENTS) + nrOfDiskExtents * sizeof(DISK_EXTENT));
    memset(diskExtentsBuf.get(), 0, sizeof(VOLUME_DISK_EXTENTS) + nrOfDiskExtents * sizeof(DISK_EXTENT));

    do
    {
        status = DeviceIoControl(
            driveHandle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            NULL,
            0,
            diskExtentsBuf.get(),
            sizeof(VOLUME_DISK_EXTENTS) + nrOfDiskExtents * sizeof(DISK_EXTENT),
            &lpBytesReturned,
            NULL
            );
        if (0 == status)
        {
            lastErr = GetLastError();
            if ((lastErr == ERROR_INSUFFICIENT_BUFFER) || (lastErr == ERROR_MORE_DATA))
            {
                nrOfDiskExtents <<= 1;

                diskExtentsBuf = std::make_unique<BYTE[]>(sizeof(VOLUME_DISK_EXTENTS) + nrOfDiskExtents * sizeof(DISK_EXTENT));
                memset(diskExtentsBuf.get(), 0, sizeof(VOLUME_DISK_EXTENTS) + nrOfDiskExtents * sizeof(DISK_EXTENT));
            }
            else
            {
                status = WIN32_TO_NTSTATUS(lastErr);
                LogFuncErrorLastErr(lastErr, "DeviceIoControl");
                goto cleanup;
            }
        }
    } while (status == STATUS_SUCCESS);

    VOLUME_DISK_EXTENTS* diskExtents = reinterpret_cast<VOLUME_DISK_EXTENTS*>(diskExtentsBuf.get());

    // we do not support volumes that span over multiple disks
    if (diskExtents->NumberOfDiskExtents != 1)
    {
        LogError("This volume is spanned over multiple disks!\n");
        status = STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
        goto cleanup;
    }

    *DiskExtent = diskExtents->Extents[0];

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != driveHandle)
    {
        CloseHandle(driveHandle);
    }

    return status;
}

/**
 * @brief Given a DISK_EXENT structure of a partition, determine the volume GUID to be able to manipulate it
 *
 * @param[out] VolumeGuid       GUID path of volume
 * @param[in]  DiskExtent       Disk properties
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetVolumeGuidForPartition(
    _Out_ std::wstring &VolumeGuid,
    _In_ PDISK_EXTENT DiskExtent
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE searchHandle = INVALID_HANDLE_VALUE;
    std::wstring volGuid;
    DISK_EXTENT diskExtent = { 0 };

    if (!DiskExtent)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    volGuid.resize(MAX_PATH);

    searchHandle = FindFirstVolume(&volGuid[0], static_cast<DWORD>(volGuid.size()));
    if (INVALID_HANDLE_VALUE == searchHandle)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "FindFirstVolume");
        goto cleanup;
    }

    for (;;)
    {
        volGuid.resize(wcslen(volGuid.c_str()));

        if (volGuid.substr(0, 4) != L"\\\\?\\"
         || volGuid.back() != L'\\')
        {
            LogError("FindFirstVolume/FindNextVolume returned a bad path %S!\n", volGuid.c_str());
            break;
        }

        volGuid.pop_back();

        status = GetVolumeDiskExtents(volGuid, &diskExtent);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetVolumeDiskExtents");
            goto next;
        }

        if ((DiskExtent->DiskNumber == diskExtent.DiskNumber)
            && (DiskExtent->StartingOffset.QuadPart == diskExtent.StartingOffset.QuadPart)
            && (DiskExtent->ExtentLength.QuadPart == diskExtent.ExtentLength.QuadPart)
            )
        {
            LogVerbose("Active partition found %S\n", volGuid.c_str());

            VolumeGuid.swap(volGuid);

            status = STATUS_SUCCESS;
            goto cleanup;
        }

    next:
        volGuid.resize(MAX_PATH);

        if (!FindNextVolume(searchHandle, &volGuid[0], static_cast<DWORD>(volGuid.size())))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            if (lastErr!= ERROR_NO_MORE_FILES)
            {
                LogFuncErrorLastErr(lastErr, "FindNextVolume");
                goto cleanup;
            }
            break;
        }
    }
cleanup:
    if (INVALID_HANDLE_VALUE != searchHandle)
    {
        FindVolumeClose(searchHandle);
    }

    return status;
}

//////////////////////////////////////////////////////////////////////////
/// MBR
//////////////////////////////////////////////////////////////////////////

/**
 * @brief Read / Write the Master Boot Record
 *
 * @param[in]     HardDiskIndex     Index of Disk with MBR
 * @param[in]     NumberOfSectors   Number of sectors to copy
 * @param[in,out] Buffer            Buffer where MBR is stored
 * @param[in]     Write             true -> Write MBR from Buffer, false -> read MBR to buffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
ReadWriteMbr(
    _In_ DWORD HardDiskIndex,
    _In_ DWORD NumberOfSectors,
    _Inout_ PBYTE Buffer,
    _In_ bool Write
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring driveName;
    HANDLE diskHandle = INVALID_HANDLE_VALUE;
    DWORD nrOfBytes = 0;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (NumberOfSectors > GRUB_NUMBER_OF_LOADER_SECTORS)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (!Buffer)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    driveName = std::wstring(WIDEN(DRIVE_PATH_GENERIC)) + std::to_wstring(HardDiskIndex);

    diskHandle = CreateFile(
        driveName.c_str(),
        Write ? GENERIC_WRITE : GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );
    if (INVALID_HANDLE_VALUE == diskHandle)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        goto cleanup;
    }

    if (Write
        ? !WriteFile(
            diskHandle,
            (LPVOID)Buffer,
            NumberOfSectors * SECTOR_SIZE,
            &nrOfBytes,
            NULL
            )
        : !ReadFile(
            diskHandle,
            (LPVOID)Buffer,
            NumberOfSectors * SECTOR_SIZE,
            &nrOfBytes,
            NULL
            )
        )
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "%sFile(pos=%d)", Write ? "Write" : "Read", nrOfBytes);
        goto cleanup;
    }

    if (Write)
    {
        FlushFileBuffers(diskHandle);
    }

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != diskHandle)
    {
        CloseHandle(diskHandle);
    }

    return status;
}

/**
 * @brief Backup / Restore the Master Boot Record to/from file
 *
 * This routine makes sure the partition layout remains unchanged. Not just the first sector will be copied.
 *
 * @param[in] HardDiskIndex     Index of Disk with MBR
 * @param[in] Filename          Path of backup file
 * @param[in] Restore           true -> restore, false -> backup

 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
BackupRestoreMbrFull(
    _In_ DWORD HardDiskIndex,
    _In_ std::wstring const& Filename,
    _In_ bool Restore
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE backupFile = INVALID_HANDLE_VALUE;
    DWORD nrOfBytesRead = 0;
    DWORD nrOfBytesWritten = 0;
    DWORD const bufferSize = SECTOR_SIZE * GRUB_NUMBER_OF_LOADER_SECTORS;
    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(bufferSize);
    MBR_LAYOUT origMbr;
    DWORD fileSize = 0;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    backupFile = CreateFile(
        Filename.c_str(),
        Restore ? GENERIC_READ : GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        Restore ? OPEN_EXISTING : CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );
    if (backupFile == INVALID_HANDLE_VALUE)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        LogError("file: %S\n", Filename.c_str());
        goto cleanup;
    }

    if (Restore)
    {
        fileSize = GetFileSize(backupFile, NULL);
        if (fileSize != SECTOR_SIZE * GRUB_NUMBER_OF_LOADER_SECTORS)
        {
            status = STATUS_FILE_CORRUPT_ERROR;
            goto cleanup;
        }

        if (!ReadFile(
            backupFile,
            buffer.get(),
            bufferSize,
            &nrOfBytesRead,
            NULL
        ))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "ReadFile");
            goto cleanup;
        }

        status = ReadWriteMbr(HardDiskIndex, 1, (PBYTE)&origMbr, false);
        if (!NT_SUCCESS(status))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "ReadWriteMbr");
            goto cleanup;
        }

        memcpy_s(reinterpret_cast<MBR_LAYOUT*>(buffer.get())->Partitions, sizeof(MBR_LAYOUT::Partitions), origMbr.Partitions, sizeof(origMbr.Partitions));

        status = ReadWriteMbr(HardDiskIndex, GRUB_NUMBER_OF_LOADER_SECTORS, buffer.get(), true);
        if (!NT_SUCCESS(status))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "ReadWriteMbr");
            goto cleanup;
        }
    }
    else
    {
        status = ReadWriteMbr(HardDiskIndex, GRUB_NUMBER_OF_LOADER_SECTORS, buffer.get(), false);
        if (!NT_SUCCESS(status))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "ReadWriteMbr");
            goto cleanup;
        }

        status = WriteFile(
            backupFile,
            buffer.get(),
            bufferSize,
            &nrOfBytesWritten,
            NULL
        );
        if (!NT_SUCCESS(status))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "WriteFile");
            goto cleanup;
        }
    }

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != backupFile)
    {
        CloseHandle(backupFile);
    }

    return status;
}

/**
 * @brief Perform a custom checksum on the MBR buffer
 *
 * @param[in] Buffer        MBR Buffer
 * @param[in] Length        Length of Buffer
 *
 * @return checksum
 */
static
DWORD
MbrChecksum(
    _In_ PBYTE Buffer,
    _In_ DWORD Length
    )
{
    DWORD i = 0;
    DWORD checksum = 0;

    if (!Buffer)
    {
        return (DWORD)-1;
    }

    for (i = 0; i < Length; i++)
    {
        checksum = checksum + 719 * Buffer[i] * Buffer[i] + 929 * Buffer[i] + 131;
    }

    return checksum;
}

/**
 * @brief Check if the MBR belongs to Microsoft Windows OS
 *
 * @param[in] HardDiskIndex     Index of Disk with MBR
 *
 * @return STATUS_SUCCESS
 * @return STATUS_NOT_FOUND     Windows MBR not found
 * @return OTHER                Other potential internal error
 */
static
NTSTATUS
IsWindowsMbr(
    _In_ DWORD HardDiskIndex
    )
{
    // https://thestarman.pcministry.com/asm/mbr/

    DWORD sum1 = 0;
    DWORD sum2 = 0;
    BYTE mbr[SECTOR_SIZE];
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    __try
    {
        status = ReadWriteMbr(HardDiskIndex, 1, mbr, false);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ReadWriteMbr");
            __leave;
        }

        sum1 = MbrChecksum(mbr, MBR_WINDOWS_CODE_SECTION_LENGTH);
        sum2 = MbrChecksum(mbr + 4, MBR_WINDOWS_CODE_SECTION_LENGTH); // BUG: starting at +4 but using same size

        if ((((DWORD)-1) == sum1) || (((DWORD)-1) == sum2))
        {
            status = STATUS_INVALID_PARAMETER_1;
            LogFuncErrorStatus(status, "MbrChecksum");
            __leave;
        }

        status = STATUS_SUCCESS; // assume we recognize the MBR

        if ((sum1 == WINDOWS_7_8_10_MBR_CHECKSUM_1) && (sum2 == WINDOWS_7_8_10_MBR_CHECKSUM_2))
        {
            LogInfo("Windows7/8/10 MBR\n");
            __leave;
        }

        if ((sum1 == WINDOWS_XP_MBR_CHECKSUM_1) && (sum2 == WINDOWS_XP_MBR_CHECKSUM_2))
        {
            LogInfo("Windows XP MBR\n");
            __leave;
        }

        if ((sum1 == WINDOWS_SERVER_MBR_CHECKSUM_1) && (sum2 == WINDOWS_SERVER_MBR_CHECKSUM_2))
        {
            LogInfo("Windows Server MBR\n");
            __leave;
        }

        if ((sum1 == WINDOWS_7_8_COMPACT_MBR_CHECKSUM_1) && (sum2 == WINDOWS_7_8_COMPACT_MBR_CHECKSUM_2))
        {
            LogInfo("Windows7/8 compact MBR\n");
            __leave;
        }

        status = STATUS_NOT_FOUND; // we didn't recognize it
        LogWarning("HD%u checksum mismatch: %x-%x\n", HardDiskIndex, sum1, sum2);
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check if the MBR belongs to NAPOCA Hypervisor (custom GRUB) or Patch the standard GRUB with our signature
 *
 * @param[in] HardDiskIndex     Index of Disk with MBR
 * @param[in] Validate          true -> check our MBR, false -> patch standard GRUB MBR
 *
 * @return STATUS_SUCCESS
 * @return STATUS_NOT_FOUND     GRUB MBR not found
 * @return OTHER                Other potential internal error
 */
static
NTSTATUS
PatchOrCheckGrubMbr(
    _In_ DWORD HardDiskIndex,
    _In_ bool Validate
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BYTE mbr[SECTOR_SIZE];

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    __try
    {
        status = ReadWriteMbr(HardDiskIndex, 1, mbr, false);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ReadWriteMbr");
            __leave;
        }

        if (strcmp((char*)(mbr + GRUB_SIGNATURE_STRING_OFFSET), GRUB_SIGNATURE_STRING))
        {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        for (DWORD i = 0; i < _countof(GRUB_SIGNATURE); i++)
        {
            if (Validate)
            {
                if (mbr[GRUB_SIGNATURE[i].Offset] != GRUB_SIGNATURE[i].Value)
                {
                    status = STATUS_NOT_FOUND;
                    __leave;
                }
            }
            else
            {
                mbr[GRUB_SIGNATURE[i].Offset] = GRUB_SIGNATURE[i].Value;
            }
        }

        if (!Validate)
        {
            status = ReadWriteMbr(HardDiskIndex, 1, mbr, true);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ReadWriteMbr");
                __leave;
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check if the MBR is a valid legacy MBR
 *
 * -it is located on a valid fixed disk
 * -it is not UEFI
 * -it has a valid partition
 *
 * @param[in] HardDiskIndex     Index of Disk with MBR
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
ValidMbr(
    _In_ DWORD HardDiskIndex
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD activePartitions = 0;
    MBR_LAYOUT mbr;
    bool isValid = false;
    bool invalid = false;
    std::wstring driveRootName;
    PARTITION_ENTRY_LAYOUT zeroMemory = { 0 };
    DWORD driveType = DRIVE_UNKNOWN;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    driveRootName = std::wstring(WIDEN(DRIVE_PATH_GENERIC)) + std::to_wstring(HardDiskIndex) + L"\\";

    driveType = GetDriveType(driveRootName.c_str());
    if (DRIVE_FIXED != driveType)
    {
        LogError("GetDriveType failed with drive type: %u\n", driveType);
        status = STATUS_NOT_FOUND;
        if (DRIVE_NO_ROOT_DIR != driveType)
        {
            LogInfo("Skipping drive of type: %u\n", driveType);
        }
        goto cleanup;
    }

    status = ReadWriteMbr(HardDiskIndex, 1, (PBYTE)(&mbr), false);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "ReadWriteMbr");
        goto cleanup;
    }

    if (mbr.Signature != MBR_SIGNATURE)
    {
        LogInfo("No valid MBR on %S", driveRootName.c_str());
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }

    isValid = true;

    for (DWORD i = 0; i < 4; i++)
    {
        if (mbr.Partitions[i].Status & 0x80)
        {
            activePartitions++;
        }
    }
    if (!activePartitions)
    {
        LogInfo("No active partition found, %S will be skipped!\n", driveRootName.c_str());
        isValid = false;
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }

    if (PARTITION_TYPE_GPT == mbr.Partitions[0].PartitionType)
    {
        for (DWORD i = 1; i < 4; i++)
        {
            if (memcmp(&mbr.Partitions[i], &zeroMemory, sizeof(zeroMemory)))
            {
                invalid = true;
            }
        }
        if (!invalid)
        {
            LogInfo("EFI disk found, %S will be skipped", driveRootName.c_str());
            isValid = false;
            status = STATUS_NOT_FOUND;
            goto cleanup;
        }
    }

    status = isValid ? STATUS_SUCCESS : STATUS_NOT_FOUND;

cleanup:
    // LogVerbose("is valid returned %d for drive: %u\n", isValid, HardDiskIndex);
    return status;
}

//////////////////////////////////////////////////////////////////////////
/// (Un)Installation
//////////////////////////////////////////////////////////////////////////

/**
 * @brief Get Load Monitor data on legacy BIOS firmwares
 *
 * @param[out] AllowedRetries       How many attempts to boot the Hypervisor before giving up
 * @param[out] FailCount            Number of failed attempts
 * @param[out] Boot                 The hypervisor attempted booting
 * @param[out] Crash                The hypervisor may have crashed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GetLoadMonitorDataMbr(
    _Out_opt_ PDWORD AllowedRetries,
    _Out_opt_ PDWORD FailCount,
    _Out_opt_ PBOOLEAN Boot,
    _Out_opt_ PBOOLEAN Crash
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring filePath;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0;
    std::string buffer;
    DWORD nrOfBytes = 0;
    PVOID context = NULL;
    std::string valueText;

    status = GetInstallationInfoFromRegistry();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetInstallationInfoFromRegistry");
        goto cleanup;
    }

    filePath = gPartitionVolumeGuid + L"\\" WIDEN(NAPOCAHV_BOOT_DIRECTORY) L"\\grub\\" WIDEN(GRUB_ENVIRONMENT_NAME);

    file = CreateFile(
        filePath.c_str(),
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (INVALID_HANDLE_VALUE == file)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        goto cleanup;
    }

    fileSize = GetFileSize(file, NULL);
    if (0 == fileSize)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "GetFileSize");
        goto cleanup;
    }

    buffer.resize(fileSize);

    if (!ReadFile(
            file,
            &buffer[0],
            static_cast<DWORD>(buffer.size()),
            &nrOfBytes,
            NULL
        ))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "ReadFile");
        goto cleanup;
    }

    status = GrubEnvironmentParseRaw(&context, buffer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GrubEnvironmentParseRaw");
        goto cleanup;
    }

    if (FailCount)
    {
        status = GrubEnvironmentGetValue(context, GRUB_VAR_CURRENT_ATTEMPT, valueText);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "GrubEnvironmentGetValue");
            goto cleanup;
        }

        *FailCount = STATUS_NOT_FOUND == status ? 0 : static_cast<DWORD>(valueText.length());
    }

    if (AllowedRetries)
    {
        status = GrubEnvironmentGetValue(context, GRUB_VAR_MAX_ATTEMPTS, valueText);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "GrubEnvironmentGetValue");
            goto cleanup;
        }

        *AllowedRetries = STATUS_NOT_FOUND == status ? 0 : static_cast<DWORD>(valueText.length());
    }

    if (Boot)
    {
        status = GrubEnvironmentGetValue(context, GRUB_VAR_LM_BOOT, valueText);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "GrubEnvironmentGetValue");
            goto cleanup;
        }

        *Boot = STATUS_NOT_FOUND == status ? FALSE : valueText == "1";
    }

    if (Crash)
    {
        status = GrubEnvironmentGetValue(context, GRUB_VAR_LM_BOOT, valueText);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "GrubEnvironmentGetValue");
            goto cleanup;
        }

        *Crash = STATUS_NOT_FOUND == status ? FALSE : valueText == "1";
    }

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != file)
    {
        CloseHandle(file);
    }

    GrubEnvironmentFree(&context);

    return status;
}

/**
 * @brief Update Load Monitor data on legacy BIOS firmwares
 *
 * @param[in] AllowedRetries        How many attempts to boot the Hypervisor before giving up
 * @param[in] FailCount             Number of failed attempts
 * @param[in] Boot                  The hypervisor attempted booting
 * @param[in] Crash                 The hypervisor may have crashed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
SetLoadMonitorDataMbr(
    _In_opt_ PDWORD AllowedRetries,
    _In_opt_ PDWORD FailCount,
    _In_opt_ PBOOLEAN Boot,
    _In_opt_ PBOOLEAN Crash
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring filePath;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0;
    std::string buffer;
    DWORD nrOfBytes = 0;
    PVOID context = NULL;
    std::string textValue;

    status = GetInstallationInfoFromRegistry();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetInstallationInfoFromRegistry");
        goto cleanup;
    }

    filePath = gPartitionVolumeGuid + L"\\" WIDEN(NAPOCAHV_BOOT_DIRECTORY) L"\\grub\\" WIDEN(GRUB_ENVIRONMENT_NAME);

    if (!SetFileAttributes(filePath.c_str(), FILE_ATTRIBUTE_NORMAL))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetFileAttributes");
    }

    file = CreateFile(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (INVALID_HANDLE_VALUE == file)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateFile");
        goto cleanup;
    }

    fileSize = GetFileSize(file, NULL);
    if (0 == fileSize)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "GetFileSize");
        goto cleanup;
    }

    buffer.resize(fileSize);

    if (!ReadFile(
        file,
        &buffer[0],
        fileSize,
        &nrOfBytes,
        NULL
    ))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "ReadFile");
        goto cleanup;
    }

    status = GrubEnvironmentParseRaw(&context, buffer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GrubEnvironmentParseRaw");
        goto cleanup;
    }

    if (FailCount)
    {
        textValue.clear();

        for (DWORD count = *FailCount; count; count--)
        {
            textValue += "1";
        }

        status = GrubEnvironmentSetValue(context, GRUB_VAR_CURRENT_ATTEMPT, textValue);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GrubEnvironmentSetValue");
            goto cleanup;
        }
    }

    if (AllowedRetries)
    {
        textValue.clear();

        for (DWORD count = *AllowedRetries; count; count--)
        {
            textValue += "1";
        }

        status = GrubEnvironmentSetValue(context, GRUB_VAR_MAX_ATTEMPTS, textValue);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GrubEnvironmentSetValue");
            goto cleanup;
        }
    }

    if (Boot)
    {
        status = GrubEnvironmentSetValue(context, GRUB_VAR_LM_BOOT, *Boot ? "1" : "0");
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GrubEnvironmentSetValue");
            goto cleanup;
        }
    }

    if (Crash)
    {
        status = GrubEnvironmentSetValue(context, GRUB_VAR_LM_CRASH, *Crash? "1" : "0");
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GrubEnvironmentSetValue");
            goto cleanup;
        }
    }

    status = GrubEnvironmentGetRaw(context, buffer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GrubEnvironmentGetRaw");
        goto cleanup;
    }

    if (INVALID_SET_FILE_POINTER == SetFilePointer(
        file,
        0,
        NULL,
        FILE_BEGIN))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetFilePointer");
        goto cleanup;
    }

    if (!WriteFile(
        file,
        buffer.c_str(),
        static_cast<DWORD>(buffer.length()),
        &nrOfBytes,
        NULL))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "WriteFile");
        goto cleanup;
    }

    if (!SetEndOfFile(file))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetEndOfFile");
        goto cleanup;
    }

    if (!SetFileAttributes(filePath.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetFileAttributes");
    }

cleanup:
        if (INVALID_HANDLE_VALUE != file)
        {
            CloseHandle(file);
        }

        GrubEnvironmentFree(&context);

    return status;
}

/**
 * @brief Install the GRUB bootloader on a given disk
 *
 * Install GRUB via grub-install.exe
 *
 * @param[in] HardDiskIndex     Index of Disk where to install
 * @param[in] SystemRoot        Path to system partition
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
static
NTSTATUS
InstallBootloader(
    _In_ DWORD HardDiskIndex,
    _In_ std::wstring const& SystemRoot
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    DWORD exitCode = 0;
    std::wstring grubInstaller;
    std::wstring commandBuffer;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (!PathFileExistsW(gSdkDirs[SDK_DIR_MBR].c_str()))
    {
        LogError("Invalid folder provided: %S, error: %x\n", gSdkDirs[SDK_DIR_MBR].c_str(), GetLastError());
        status = STATUS_INVALID_SDK_FOLDER;
        goto cleanup;
    }

    grubInstaller = gSdkDirs[SDK_DIR_MBR] + L"grub\\grub-install.exe";

    if (!PathFileExistsW(grubInstaller.c_str()))
    {
        LogError("file %S not found\n", grubInstaller.c_str());
        status = STATUS_GRUB_FILES_MISSING;
        goto cleanup;
    }

    commandBuffer = gSdkDirs[SDK_DIR_MBR] + L"grub\\grub-install.exe"
        L" --target=i386-pc"
        L" --boot-directory=" + SystemRoot + L"\\" WIDEN(NAPOCAHV_BOOT_DIRECTORY) L"\\ " WIDEN(DRIVE_PATH_GENERIC) + std::to_wstring(HardDiskIndex) +
        L" --install-modules=\"legacycfg test chain loadenv multiboot\"",

    si.cb = sizeof(si);
    si.wShowWindow = SW_HIDE;

    LogInfo("Running: %S\n", commandBuffer.c_str());

    if (!CreateProcess(NULL, const_cast<WCHAR*>(commandBuffer.c_str()), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateProcess");
        goto cleanup;
    }

    // wait for process to complete
    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0)
    {
        if (GetExitCodeProcess(pi.hProcess, &exitCode))
        {
            if (exitCode)
            {
                LogError("Process terminated with error code 0x%x!\n", exitCode);
                status = WIN32_TO_NTSTATUS(exitCode);
                goto cleanup;
            }
        }
        else
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "GetExitCodeProcess");
            goto cleanup;
        }
    }
    else
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "WaitForSingleObject");
        goto cleanup;
    }

    status = FlushSystemPartition(SystemRoot);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "FlushSystemPartition");
    }

    status = PatchOrCheckGrubMbr(HardDiskIndex, false);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "PatchOrCheckGrubMbr");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (pi.hThread)
    {
        CloseHandle(pi.hThread);
    }
    if (pi.hProcess)
    {
        CloseHandle(pi.hProcess);
    }

    return status;
}

/**
 * @brief Validate that drive partitioning is compatible with Napoca Hypervisor
 *
 * Make sure that there are no dynamic partitions, as they are not supported by the grub loader
 *
 * @param[in] HardDiskIndex     Index of Disk with MBR
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
ValidatePartitions(
    DWORD HardDiskIndex
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    MBR_LAYOUT mbr = {0};
    DWORD i = 0;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    __try
    {
        status = ReadWriteMbr(HardDiskIndex, 1, (PBYTE)(&mbr), false);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ReadWriteMbr");
            __leave;
        }

        for (i = 0; i < 4; i++)
        {
            if (PARTITION_TYPE_DYNAMIC_EXTENDED == mbr.Partitions[i].PartitionType)
            {
                status = STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
                __leave;
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Determine which is the active partition on the disk based on the partition table in the MBR and return a crafted DISK_EXTENT structure
 *
 * @param[in]  HardDiskIndex    Index of Disk with MBR
 * @param[out] DiskExtent       Disk properties
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetActivePartition(
    _In_ DWORD HardDiskIndex,
    _Out_ PDISK_EXTENT DiskExtent
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    MBR_LAYOUT mbr = { 0 };
    DWORD i = 0;
    DISK_EXTENT diskExtent = { 0 };
    bool found = false;

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (!DiskExtent)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    __try
    {
        status = ReadWriteMbr(HardDiskIndex, 1, (PBYTE)(&mbr), false);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ReadWriteMbr");
            __leave;
        }

        for (i = 0; i < 4; i++)
        {
            if (mbr.Partitions[i].Status & 0x80)
            {
                found = true;
                diskExtent.DiskNumber = HardDiskIndex;
                diskExtent.StartingOffset.QuadPart = (LONGLONG)mbr.Partitions[i].Lba * SECTOR_SIZE;
                diskExtent.ExtentLength.QuadPart = (LONGLONG)mbr.Partitions[i].NumberOfSectors * SECTOR_SIZE;
            }
        }

        if (found)
        {
            *DiskExtent = diskExtent;
        }
        else
        {
            LogError("Active partition on hd %u not found!\n", HardDiskIndex);
            status = STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }
    return status;
}

/**
 * @brief Get the active partition volume GUID path given a physical drive index
 *
 * @param[out] VolumeGuid       Volume GUID path
 * @param[in]  HardDiskIndex    Index of Disk with MBR
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetActivePartitionVolume(
    _Out_ std::wstring &VolumeGuid,
    _In_ DWORD HardDiskIndex
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DISK_EXTENT diskExtent = { 0 };

    if (HardDiskIndex == INVALID_HARDDISK)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    __try
    {
        status = GetActivePartition(HardDiskIndex, &diskExtent);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetActivePartition");
            __leave;
        }

        status = GetVolumeGuidForPartition(VolumeGuid, &diskExtent);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetVolumeGuidForPartition");
            __leave;
        }
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Get the Windows partition volume GUID path
 *
 * @param[out] VolumeGuid       Volume GUID path
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetWindowsPartitionVolume(
    _Out_ std::wstring &VolumeGuid
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring windowsDrive;
    std::wstring guid;

    windowsDrive.resize(MAX_PATH);
    if (0 == GetWindowsDirectory(&windowsDrive[0], static_cast<UINT>(windowsDrive.size())))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "GetWindowsDirectory");
        goto cleanup;
    }

    windowsDrive.resize(3); // only keep drive letter and first backslash

    guid.resize(MAX_PATH);
    if (!GetVolumeNameForVolumeMountPoint(windowsDrive.c_str(), &guid[0], static_cast<DWORD>(guid.size())))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "GetVolumeNameForVolumeMountPoint");
        goto cleanup;
    }

    guid.resize(wcslen(guid.c_str()));

    guid.pop_back(); // remove trailing L'\\'
    VolumeGuid.swap(guid);

    status = STATUS_SUCCESS;

cleanup:
    return status;
}

/**
 * @brief Iterate through all the partitions on the disk and check whether there are any old installation files, in order to delete them
 *
 * This makes sure that the boot flow is not altered in any way by the old installation files that were not properly deleted
 *
 * @param[in]  HardDiskIndex    Index of Disk with MBR
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CleanPreviousInstallation(
    _In_ DWORD HardDiskIndex
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    HANDLE searchHandle = INVALID_HANDLE_VALUE;
    std::wstring volGuid;
    std::wstring grubLoaderPath;
    DISK_EXTENT diskExtent = { 0 };
    DWORD driveType = DRIVE_UNKNOWN;

    if (INVALID_HARDDISK == HardDiskIndex)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    volGuid.resize(MAX_PATH);

    searchHandle = FindFirstVolume(&volGuid[0], static_cast<DWORD>(volGuid.size()));
    if (INVALID_HANDLE_VALUE == searchHandle)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "FindFirstVolume");
        goto cleanup;
    }

    for (;;)
    {
        volGuid.resize(wcslen(volGuid.c_str()));

        if (volGuid.substr(0, 4) != L"\\\\?\\"
            || volGuid.back() != L'\\')
        {
            LogError("FindFirstVolume/FindNextVolume returned a bad path %S!\n", volGuid.c_str());
            break;
        }

        driveType = GetDriveType(volGuid.c_str());
        if (DRIVE_FIXED != driveType)
        {
            //LogVerbose("Skipping drive of type: %u\n", driveType);
            goto next;
        }

        volGuid.pop_back();

        //LogVerbose("Getting volume disk extents for: %S\n", volGuid);

        status = GetVolumeDiskExtents(volGuid, &diskExtent);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetVolumeDiskExtents");
            goto next;
        }

        if (diskExtent.DiskNumber != HardDiskIndex)
        {
            LogVerbose("Skipping hard disk %u because it is not %u!\n", diskExtent.DiskNumber, HardDiskIndex);
            goto next;
        }

        grubLoaderPath = volGuid + L"\\" WIDEN(NAPOCAHV_BOOT_DIRECTORY);

        if (PathFileExistsW(grubLoaderPath.c_str()))
        {
            LogVerbose("Previous grub files detected!\n");

            status = DeleteDirectoryAndContent(grubLoaderPath);
            if (!NT_SUCCESS(status))
            {
                status = STATUS_PREVIOUS_GRUB_FILES_DETECTED;
                goto cleanup;
            }
        }

    next:
        volGuid.resize(MAX_PATH);

        if (!FindNextVolume(searchHandle, &volGuid[0], static_cast<DWORD>(volGuid.size())))
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

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != searchHandle)
    {
        FindVolumeClose(searchHandle);
    }

    return status;
}

/**
 * @brief Scan legacy formatted hard drives to see if Napoca configuration is possible
 *
 *   Routine description:
 *      Determine the number of Grub MBRs and the number of Windows MBRs
 *      Validate that the system meets certain installation criteria
 *
 *  If success is returned, the following hold true for INSTALL:
 *      - there is only one valid MBR on the system
 *      - this MBR belong either to Windows or to Grub
 *      - HardDiskIndex contains the hard disk with the valid MBR on it (either Windows MBR or Grub Mbr)
 *
 *
 * @param[in]  HardDiskIndex        Index of Disk where NAPOCA is/can be installed
 * @param[out] NrOfOurGrubMbrs      Count of Windows MBRs
 * @param[out] NrOfWindowsMbrs      Count of GRUB MBRs patched with out signature
 * @param[in]  Install              If an installation is currently performed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GetSystemLegacyConfiguration(
    _Out_opt_ PDWORD HardDiskIndex,
    _Out_opt_ PDWORD NrOfOurGrubMbrs,
    _Out_opt_ PDWORD NrOfWindowsMbrs,
    _In_ BOOLEAN Install
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    DWORD hardDiskIndex = INVALID_HARDDISK;
    DWORD firstWindowsHardDisk = INVALID_HARDDISK;
    DWORD firstGrubHardDiskIndex = INVALID_HARDDISK;
    DWORD nrOfWindowsMbrs = 0;
    DWORD nrOfGrubMbrs = 0;
    DWORD nrOfValidMbrs = 0;
    DWORD buffSize = 0x4000;
    std::unique_ptr<WCHAR[]> physicalNames;
    std::wstring driveRootName;
    PWCHAR name = NULL;
    DWORD len = 0;

    // try to find all disks which has a valid Windows MBR
    // iterate through the disks and determine which ones are valid for installation

    do
    {
        physicalNames = std::make_unique<WCHAR[]>(buffSize);

        len = QueryDosDevice(NULL, physicalNames.get(), buffSize / sizeof(WCHAR));
        if (len != 0)
        {
            break;
        }

        buffSize *= 2;
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER && buffSize <= 0x1'000'000);

    if (len == 0)
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "QueryDosDevice");
        return WIN32_TO_NTSTATUS(lastErr);
    }

    for (name = physicalNames.get(); *name && name < physicalNames.get() + len; name += wcslen(name) + 1)
    {
        if (!wcsstr(name, L"PhysicalDrive"))
        {
            continue;
        }

        hardDiskIndex = wcstol(name + _countof("PhysicalDrive") - 1, NULL, 10);

        driveRootName = std::wstring(WIDEN(DRIVE_PATH_GENERIC)) + std::to_wstring(hardDiskIndex);

        // extra check because for Windows some fixed drives can still be removable
        HANDLE hDrive = CreateFile(driveRootName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDrive != INVALID_HANDLE_VALUE)
        {
            DWORD ioctlDataSize;
            STORAGE_HOTPLUG_INFO ioctlData = { 0 };

            ioctlData.Size = sizeof(STORAGE_HOTPLUG_INFO);

            bool result = DeviceIoControl(hDrive, IOCTL_STORAGE_GET_HOTPLUG_INFO, 0, 0, &ioctlData, sizeof(ioctlData), &ioctlDataSize, NULL);

            CloseHandle(hDrive);

            if (result && (ioctlData.MediaRemovable || ioctlData.DeviceHotplug))
                continue; // removable
        }

        driveRootName += L"\\";

        if (GetDriveType(driveRootName.c_str()) != DRIVE_FIXED)
        {
            continue;
        }

        // does this physical drive contain a valid mbr?
        status = ValidMbr(hardDiskIndex);
        if (NT_SUCCESS(status))
        {
            nrOfValidMbrs++;
        }
        else if (status == STATUS_NOT_FOUND)
        {
            // if STATUS_NOT_FOUND is returned, ignore this physical drive
            continue;
        }
        else
        {
            LogFuncErrorStatus(status, "ValidMbr");
            LogError("Could not check MBR on drive: %S\n", driveRootName.c_str());
            continue;
        }

        status = IsWindowsMbr(hardDiskIndex);
        if (NT_SUCCESS(status))
        {
            if (nrOfWindowsMbrs == 0) firstWindowsHardDisk = hardDiskIndex;
            nrOfWindowsMbrs++;
        }
        else if (status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "IsWindowsMbr");
            return STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
        }

        status = PatchOrCheckGrubMbr(hardDiskIndex, true);
        if (NT_SUCCESS(status))
        {
            if (nrOfGrubMbrs == 0) firstGrubHardDiskIndex = hardDiskIndex;
            nrOfGrubMbrs++;
        }
        else if (status != STATUS_NOT_FOUND)
        {
            LogFuncErrorStatus(status, "PatchOrCheckGrubMbr");
            return STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
        }
    }

    // only 1 valid mbr is allowed, multiple disks are not supported
    if ((Install) && (1 != nrOfValidMbrs))
    {
        LogError("System has %u valid mbrs (should be 1) \n", nrOfValidMbrs);
        return STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
    }

    // the valid mbr should belong to either Windows or Grub
    if ((Install) && (1 != nrOfWindowsMbrs + nrOfGrubMbrs))
    {
        LogError("The valid MBR is neither Windows nor our Grub (windows mbrs: %u, grub mbrs: %u)\n", nrOfWindowsMbrs, nrOfGrubMbrs);
        return STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
    }

    // only 1 grub mbr is allowed to exist when we are at uninstall
    if ((!Install) && (nrOfGrubMbrs > 1))
    {
        LogError("At uninstall there were %u number of grub MBRs\n", nrOfGrubMbrs);
        return STATUS_MBR_CONFIGURATION_NOT_SUPPORTED;
    }

    // perform additional validations at install
    if (Install)
    {
        status = nrOfWindowsMbrs > 0
                    ? ValidatePartitions(firstWindowsHardDisk)
                    : nrOfGrubMbrs > 0
                        ? ValidatePartitions(firstGrubHardDiskIndex)
                        : STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
        if (!NT_SUCCESS(status))
        {
            if (STATUS_MBR_CONFIGURATION_NOT_SUPPORTED == status)
            {
                LogError("Partition table not supported!\n");
            }
            else
            {
                status = STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
            }
            return status;
        }
    }

    if (HardDiskIndex)
    {
        if (Install && nrOfWindowsMbrs > 0)
        {
            // at install if we have a windows MBR
            *HardDiskIndex = firstWindowsHardDisk;
        }
        else if (nrOfGrubMbrs > 0)
        {
            // at reinstall (we have a grub MBR) or at uninstall
            *HardDiskIndex = firstGrubHardDiskIndex;
        }
        else
        {
            // most probably 2 consecutive uninstalls were tried
            LogInfo("We are at uninstall, but there is nothing to do\n");
            *HardDiskIndex = INVALID_HARDDISK;
        }
    }

    if (NrOfOurGrubMbrs) *NrOfOurGrubMbrs = nrOfGrubMbrs;
    if (NrOfWindowsMbrs) *NrOfWindowsMbrs = nrOfWindowsMbrs;    // there should be exactly 1 disk with a valid windows mbr

    return STATUS_SUCCESS;
}

/**
 * @brief Validate that the grub installation folder is present on a partition
 *
 * @param[in]     SystemRoot        Partition to check
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckForLegacyFiles(
    _In_ std::wstring const& SystemRoot,
    _In_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    std::wstring destination;

    destination = SystemRoot + L"\\" + WIDEN(NAPOCAHV_BOOT_DIRECTORY) + L"\\grub";

    if (!PathFileExistsW(destination.c_str()))
    {
        if (!StatusToFeaturesBitmask(STATUS_SDK_FILES_MISSING, MissingFeatures))
        {
            return STATUS_SDK_FILES_MISSING;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Check if legacy MBR configuration is supported
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
ConfigGrubSupported(
    _In_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD nrOfGrubMbrs = 0;
    DWORD nrOfWindowsMbrs = 0;
    DWORD hardDiskIndex = INVALID_HARDDISK;
    std::wstring systemRoot;
    std::wstring windowsRoot;

    // make sure we have a Windows or a Grub MBR
    status = GetSystemLegacyConfiguration(&hardDiskIndex, &nrOfGrubMbrs, &nrOfWindowsMbrs, TRUE);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetSystemLegacyConfiguration");
        if (!StatusToFeaturesBitmask(status, MissingFeatures))
        {
            goto cleanup;
        }
    }

    status = GetActivePartitionVolume(systemRoot, hardDiskIndex);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetActivePartitionVolume");
        status = STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
        if (!StatusToFeaturesBitmask(status, MissingFeatures))
        {
            goto cleanup;
        }
    }

    status = GetWindowsPartitionVolume(windowsRoot);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetActivePartitionVolume");
        status = STATUS_CANNOT_GET_SYSTEM_CONFIGURATION;
        if (!StatusToFeaturesBitmask(status, MissingFeatures))
        {
            goto cleanup;
        }
    }

    // if we have a grub mbr, make sure the necessary files are still present
    if (1 == nrOfGrubMbrs)
    {
        status = CheckForLegacyFiles(systemRoot, MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CheckForLegacyFiles");
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                goto cleanup;
            }
        }
    }

    status = STATUS_SUCCESS;

cleanup:
    return status;
}

/**
 * @brief Create GRUB configuration menu
 *
 * It creates 3 entries and lists the modules that need to be loaded for each:
 *   - Boot with hypervisor
 *   - Boot without hypervisor
 *   - Restore original MBR
 *
 * @param[in]  List                 List of installation files
 * @param[in]  NumberOfElements     Count of List
 * @param[out] Config               Grub configuration
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CreateGrubConfiguration(
    _In_ LD_INSTALL_FILE *List,
    _In_ DWORD NumberOfElements,
    _Out_ std::string &Config
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::string grubConfig;
    LD_INSTALL_FILE *file;

    if (NULL == List)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    // write the global settings
    grubConfig =
        "set timeout_style=hidden\n"
        "set timeout=3\n"
        "set default=0\n"
        "set bdenv=/" NAPOCAHV_BOOT_DIRECTORY "/grub/" GRUB_ENVIRONMENT_NAME "\n\n";


    // prepare strings for GRUB: Boot with hypervisor
    {
        grubConfig +=
            "menuentry 'Boot with NapocaHv Hypervisor protection' {\n"
            "  set fallback=1\n"
            "\n"
            "  if [ -s $bdenv ]; then\n"
            "    load_env -f $bdenv\n"
            "\n"
            "    set " GRUB_VAR_LM_CRASH "=$" GRUB_VAR_LM_BOOT "\n"
            "    save_env -f $bdenv " GRUB_VAR_LM_CRASH "\n"
            "\n"
            "    set " GRUB_VAR_LM_BOOT "=1\n"
            "    save_env -f $bdenv " GRUB_VAR_LM_BOOT "\n"
            "\n"
            "    if [ \"${" GRUB_VAR_MAX_ATTEMPTS "}\" != \"\" ]; then\n"
            "      if [ \"${" GRUB_VAR_CURRENT_ATTEMPT "}\" = \"${" GRUB_VAR_MAX_ATTEMPTS "}\" ]; then\n"
            "        chainloader +1\n"
            "        boot\n"
            "      fi\n"
            "\n"
            "      set " GRUB_VAR_CURRENT_ATTEMPT "=1$" GRUB_VAR_CURRENT_ATTEMPT "\n"
            "      save_env -f $bdenv " GRUB_VAR_CURRENT_ATTEMPT "\n"
            "    fi\n"
            "  fi\n"
            "\n";

        // main module
        file = GetInstallFileForUniqueId(napocabin);
        if (!file)
        {
            status = STATUS_FILE_NOT_AVAILABLE;
            LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
            goto cleanup;
        }

        grubConfig = grubConfig +
            "  legacy_kernel --no-mem-option --type=multiboot '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "'\n";

        // register the multiboot modules
        for (DWORD i = 0; i < NumberOfElements; i++)
        {
            file = &List[i];

            if (!file->Flags.GrubBoot)
            {
                continue;
            }

            grubConfig = grubConfig +
                "  legacy_initrd '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '" + file->MultibootName + "'\n";
        }
        grubConfig += "}\n\n";
    }

    // prepare strings for GRUB: Boot without hypervisor
    {
        grubConfig +=
            "menuentry 'Boot without NapocaHv Hypervisor protection' {\n"
            "  if [ -s $bdenv ]; then\n"
            "    set monitor_boot=0\n"
            "    save_env -f $bdenv monitor_boot\n"
            "  fi\n"
            "\n"
            "  chainloader +1\n"
            "}\n\n";
    }

    // prepare strings for GRUB: MBR recovery
    {
        grubConfig +=
            "menuentry 'Recover previous bootloader' {\n"
            "  set fallback=1\n";

        // main module
        file = GetInstallFileForUniqueId(napocabin);
        if (!file)
        {
            status = STATUS_FILE_NOT_AVAILABLE;
            LogFuncErrorStatus(status, "GetInstallFileForUniqueId");
            goto cleanup;
        }

        grubConfig = grubConfig +
            "  legacy_kernel --no-mem-option --type=multiboot '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "'\n";

        // register the multiboot modules
        for (DWORD i = 0; i < NumberOfElements; i++)
        {
            file = &List[i];

            if (!file->Flags.GrubRecovery)
            {
                continue;
            }

            grubConfig = grubConfig +
                "  legacy_initrd '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '/" NAPOCAHV_BOOT_DIRECTORY "/" + WIDE_TO_CHAR(file->DestinationFileName) + "' '" + file->MultibootName + "'\n";
        }
        grubConfig += "}\n";
    }

    for (DWORD i = 0; i < grubConfig.length(); i++)
    {
        if (grubConfig[i] == '\\')
        {
            grubConfig[i] = '/';
        }
    }

    Config.swap(grubConfig);
    status = STATUS_SUCCESS;

cleanup:
    return status;
}

/**
 * @brief Backup the GUID path of the installation partition to the registry
 *
 * @param[in] VolumeGuid     Volume GUID path
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
AddInstallationInfoToRegistry(
    _In_ std::wstring const& VolumeGuid
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    LSTATUS error;

    __try
    {
        gPartitionVolumeGuid = VolumeGuid;

        error = RegSetKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_CONFIG_LEGACY_INSTALL_PARTITION,
            REG_SZ,
            VolumeGuid.c_str(),
            static_cast<DWORD>(VolumeGuid.length() + 1) * sizeof(WCHAR)
        );
        if (error != ERROR_SUCCESS)
        {
            status = WIN32_TO_NTSTATUS(error);
            LogFuncErrorLastErr(error, "RegSetKeyValue");
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Delete the GUID path of the installation partition from the registry
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
RemoveInstallationInfoFromRegistry(
    void
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    LSTATUS error;

    __try
    {
        error = RegDeleteKeyValue(
            HKEY_LOCAL_MACHINE,
            REG_SUBKEY_GENERAL_SETTINGS,
            REG_VALUE_CONFIG_LEGACY_INSTALL_PARTITION
        );
        if (error != ERROR_SUCCESS)
        {
            status = WIN32_TO_NTSTATUS(error);
            LogFuncErrorLastErr(error, "RegDeleteKeyValue");
            __leave;
        }

        gPartitionVolumeGuid[0] = L'\0';

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Get the GUID path of the installation partition backup from the registry
 *
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetInstallationInfoFromRegistry(
    void
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    LSTATUS error;
    std::wstring partitionGuidReg;
    DWORD partitionGuidRegSize = 0;

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_CONFIG_LEGACY_INSTALL_PARTITION,
        RRF_RT_REG_SZ,
        NULL,
        NULL,
        &partitionGuidRegSize
    );
    if (error != ERROR_SUCCESS)
    {
        status = WIN32_TO_NTSTATUS(error);
        LogFuncErrorLastErr(error, "RegGetValue");
        goto cleanup;
    }

    partitionGuidReg.resize(partitionGuidRegSize / sizeof(WCHAR));

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_GENERAL_SETTINGS,
        REG_VALUE_CONFIG_LEGACY_INSTALL_PARTITION,
        RRF_RT_REG_SZ,
        NULL,
        &partitionGuidReg[0],
        &partitionGuidRegSize
    );
    if (error != ERROR_SUCCESS)
    {
        status = WIN32_TO_NTSTATUS(error);
        LogFuncErrorLastErr(error, "RegGetValue");
        goto cleanup;
    }
    partitionGuidReg.resize(partitionGuidRegSize / sizeof(WCHAR) - 1);

    gPartitionVolumeGuid = partitionGuidReg;
    status = STATUS_SUCCESS;

cleanup:
    return status;
}

/**
 * @brief Save data to a file required for GRUB boot
 *
 * @param[in] FilePath          File Path
 * @param[in] Data              Data to be saved to file
 * @param[in] DataSizeInBytes   Size of Data
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
SaveDataToFile(
    _In_ std::wstring const& FilePath,
    _In_ PVOID Data,
    _In_ DWORD DataSizeInBytes
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    DWORD written = 0;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;

    __try
    {
        SetFileAttributes(FilePath.c_str(), FILE_ATTRIBUTE_NORMAL);

        fileHandle = CreateFile(
            FilePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (INVALID_HANDLE_VALUE == fileHandle)
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "CreateFile");
            __leave;
        }

        if (!WriteFile(fileHandle, Data, DataSizeInBytes, &written, NULL))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "WriteFile");
            __leave;
        }

        CloseHandle(fileHandle);
        fileHandle = INVALID_HANDLE_VALUE;

        if (!SetFileAttributes(FilePath.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "SetFileAttributes");
        }
        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != fileHandle)
        {
            CloseHandle(fileHandle);
        }
    }
    return status;
}

/**
 * @brief Copy files required for UEFI boot
 *
 * @param[in] Flags                 Flags that determine which files to copy
 * @param[in] CreateDynamicFiles    If dynamically genberated files should be recreated (These can be skipped at update)
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
DeployGrubBootFiles(
    _In_ LD_INSTALL_FILE_FLAGS Flags,
    _In_ BOOLEAN CreateDynamicFiles
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;
    std::wstring destinationDir;
    std::wstring grubDir;
    std::wstring systemRoot;
    DWORD hardDiskIndex;
    LD_CONFIGURATION_OPTIONS config = { 0 };
    std::string grubEnv;
    std::string grubConf;

    status = GetSystemLegacyConfiguration(&hardDiskIndex, NULL, NULL, TRUE);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetSystemLegacyConfiguration");
        goto cleanup;
    }

    status = GetActivePartitionVolume(systemRoot, hardDiskIndex);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetActivePartitionVolume");
        goto cleanup;
    }

    LogVerbose("Creating installation folders\n");

    destinationDir = systemRoot + L"\\" + WIDEN(NAPOCAHV_BOOT_DIRECTORY) + L"\\";

    if (!CreateDirectory(destinationDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        LogError("Directory %S cannot be created!\n", destinationDir.c_str());
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateDirectory");
        goto cleanup;
    }

    if (!SetFileAttributes(destinationDir.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetFileAttributes");
    }

    grubDir = destinationDir + L"grub\\";

    if (!CreateDirectory(grubDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        LogError("Directory %S cannot be created!\n", grubDir.c_str());
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateDirectory");
        goto cleanup;
    }

    if (!SetFileAttributes(grubDir.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetFileAttributes");
    }

    LogVerbose("Copying static files\n");
    status = CopyListOfFiles(
        gInstallFiles,
        gInstallFilesCount,
        destinationDir,
        Flags
        );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "CopyListOfFiles");
        goto cleanup;
    }

    {
        std::wstring fullPath;

        LogInfo("grub config\n");
        // create a configuration for the Grub menu

        status = CreateGrubConfiguration(
            gInstallFiles,
            gInstallFilesCount,
            grubConf);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateGrubConfiguration");
            goto cleanup;
        }

        fullPath = grubDir + WIDEN(GRUB_CONFIG_NAME);

        status = SaveDataToFile(fullPath, const_cast<char*>(grubConf.c_str()), static_cast<DWORD>(grubConf.length()));
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "SaveDataToFile");
            goto cleanup;
        }
    }


    if (!CreateDynamicFiles)
    {
        status = STATUS_SUCCESS;
        goto cleanup;
    }

    LogVerbose("Creating dynamic files\n");

    {
        LD_INSTALL_FILE *file;

        // save the original first sectors of the disk

        file = GetInstallFileForModId(LD_MODID_ORIG_MBR, NULL, NULL, NULL);
        if (!file) status = STATUS_FILE_NOT_AVAILABLE;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetInstallFileForModId");
            goto cleanup;
        }

        std::wstring fullPath = destinationDir + file->DestinationFileName;
        LogVerbose("Bootloader backup to %S\n", fullPath.c_str());

        status = BackupRestoreMbrFull(hardDiskIndex, fullPath, false);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "BackupRestoreMbrFull");
            goto cleanup;
        }

        if (!SetFileAttributes(fullPath.c_str(), LEGACY_INSTALL_FILES_FILE_ATTRIBUTES))
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "SetFileAttributes");
        }
    }

    {
        LD_INSTALL_FILE *file;
        LD_INSTALL_FILE_FLAGS unwanted = { 0 };
        std::wstring fullPath;

        // create settings module: hypervisor boot

        unwanted.GrubRecovery = 1;
        file = GetInstallFileForModId(LD_MODID_MBR_SETTINGS, NULL, &unwanted, NULL);
        if (!file) status = STATUS_FILE_NOT_AVAILABLE;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetInstallFileForModId");
            goto cleanup;
        }

        memset((PVOID)&config, 0, sizeof(config));
        config.GrubBoot = TRUE;
        config.RecoveryEnabled = FALSE;

        fullPath = destinationDir + file->DestinationFileName;
        LogVerbose("mbr settings: boot the HV: %S\n", fullPath.c_str());

        status = SaveDataToFile(fullPath, &config, sizeof(config));
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "SaveDataToFile");
            goto cleanup;
        }
    }

    {
        LD_INSTALL_FILE *file;
        LD_INSTALL_FILE_FLAGS wanted = { 0 };
        std::wstring fullPath;

        // create settings module: MBR recovery

        wanted.GrubRecovery = 1;
        file = GetInstallFileForModId(LD_MODID_MBR_SETTINGS, &wanted, NULL, NULL);
        if (!file) status = STATUS_FILE_NOT_AVAILABLE;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetInstallFileForModId");
            goto cleanup;
        }

        memset((PVOID)&config, 0, sizeof(config));
        config.GrubBoot = TRUE;
        config.RecoveryEnabled = TRUE;

        fullPath = destinationDir + file->DestinationFileName;
        LogVerbose("mbr settings: recovery: %S\n", fullPath.c_str());

        status = SaveDataToFile(fullPath, &config, sizeof(config));
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "SaveDataToFile");
            goto cleanup;
        }
    }

    {
        std::wstring fullPath;

        // create Grub environment for persistent data

        grubEnv =
            GRUB_ENVIRONMENT_SIGNATURE "\n"
            GRUB_VAR_MAX_ATTEMPTS "=111\n"
            GRUB_VAR_CURRENT_ATTEMPT "=\n"
            GRUB_VAR_LM_BOOT "=\n"
            GRUB_VAR_LM_CRASH "=\n";

        if (grubEnv.length() < 1024)
            grubEnv.resize(1024, '#');

        fullPath = grubDir + WIDEN(GRUB_ENVIRONMENT_NAME);
        LogVerbose("grub env vars: %S\n", fullPath.c_str());

        status = SaveDataToFile(fullPath, const_cast<char*>(grubEnv.c_str()), static_cast<DWORD>(grubEnv.length()));
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "SaveDataToFile");
            goto cleanup;
        }
    }

    // save the active partition's GUID in the registry
    status = AddInstallationInfoToRegistry(systemRoot);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "AddInstallationInfoToRegistry");
    }

    status = STATUS_SUCCESS;

cleanup:
    if (NT_SUCCESS(status))
    {
        FlushSystemPartition(systemRoot);
    }

    return status;
}

/**
 * @brief Determine the install partition by querying the registry
 *
 * @param[out] VolumeGuid       Volume GUID path
 * @param[out] HardDiskIndex    Index of Disk
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
GetInstallPartition(
    _Out_ std::wstring &VolumeGuid,
    _Out_ DWORD &HardDiskIndex
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DISK_EXTENT diskExtent = { 0 };

    if (gPartitionVolumeGuid.empty())
    {
        status = GetInstallationInfoFromRegistry();
        if (gPartitionVolumeGuid.empty())
        {
            return STATUS_NOT_FOUND;
        }
        else if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetInstallationInfoFromRegistry");
            return STATUS_NOT_FOUND;
        }
    }

    status = GetVolumeDiskExtents(gPartitionVolumeGuid, &diskExtent);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetVolumeDiskExtents");
        return status;
    }

    VolumeGuid = gPartitionVolumeGuid;
    HardDiskIndex = diskExtent.DiskNumber;

    return STATUS_SUCCESS;
}

/**
 * @brief Configure Napoca Hypervisor on systems with legacy BIOS firmware
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
InstallGrub(
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::wstring systemRoot;
    DWORD hardDiskIndex = INVALID_HARDDISK;
    DWORD nrOfGrubMbrs = 0;
    LD_INSTALL_FILE_FLAGS flags = { 0 };

    LogVerbose("Starting InstallGrub\n");

    // determine the system's configuration
    status = GetSystemLegacyConfiguration(&hardDiskIndex, &nrOfGrubMbrs, NULL, TRUE);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetSystemLegacyConfiguration");
        goto cleanup;
    }

    LogVerbose("GetSystemLegacyConfiguration finished\n");

    // determine the active partition
    status = GetActivePartitionVolume(systemRoot, hardDiskIndex);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetActivePartitionVolume");
        goto cleanup;
    }

    LogVerbose("GetActivePartitionVolume finished\n");

    // check for old installation files and delete them
    status = CleanPreviousInstallation(hardDiskIndex);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "CheckPreviousInstallation");
        goto cleanup;
    }

    LogVerbose("CheckPreviousInstallation finished\n");

    // copy the necessary files on the active partition
    flags.Mbr = 1;
    status = DeployGrubBootFiles(flags, TRUE);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DeployGrubBootFiles");
        goto cleanup;
    }

    LogVerbose("DeployGrubBootFiles finished\n");

    // if the grub MBR is already present, don't overwrite it
    if (0 == nrOfGrubMbrs)
    {
        status = InstallBootloader(hardDiskIndex, systemRoot);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "InstallBootloader");
            goto cleanup;
        }

        LogVerbose("InstallBootloader finished\n");
    }

    status = STATUS_SUCCESS;

cleanup:
    LogVerbose("Finishing InstallGrub\n");

    return status;
}

/**
 * @brief Deconfigure Napoca Hypervisor on systems with legacy BIOS firmware
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
UninstallGrub()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::wstring installFolder;
    DWORD hardDiskIndex = INVALID_HARDDISK;
    DWORD nrOfGrubMbrs = 0;

    LogVerbose("Starting UninstallGrub\n");

    // determine the partition on which we were installed
    status = GetInstallPartition(installFolder, hardDiskIndex);
    if (!NT_SUCCESS(status))
    {
        if (STATUS_NOT_FOUND != status)
        {
            LogFuncErrorStatus(status, "GetInstallPartition");
        }

        // make sure we have a fallback option in case the registry information is not reliable
        LogInfo("No registry info, fallback to heuristic checks!\n");
        status = GetSystemLegacyConfiguration(&hardDiskIndex, &nrOfGrubMbrs, NULL, FALSE);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetSystemLegacyConfiguration");
            return status;
        }

        if (!nrOfGrubMbrs)
        {
            LogInfo("No grub mbr and no registry information, nothing to do...\n");
            return STATUS_SUCCESS;
        }

        status = GetActivePartitionVolume(installFolder, hardDiskIndex);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetActivePartitionVolume");
            return status;
        }
    }

    LogVerbose("GetInstallPartition finished\n");

    installFolder = installFolder + L"\\" + WIDEN(NAPOCAHV_BOOT_DIRECTORY);

    // determine if there still is a grub MBR
    status = PatchOrCheckGrubMbr(hardDiskIndex, true);
    if (NT_SUCCESS(status))
    {
        // restore the original sectors that were saved at install

        LD_INSTALL_FILE* file;

        file = GetInstallFileForModId(LD_MODID_ORIG_MBR, NULL, NULL, NULL);
        if (!file) status = STATUS_FILE_NOT_AVAILABLE;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetInstallFileForModId");
            return status;
        }

        std::wstring guestLoader = installFolder + L"\\" + file->DestinationFileName;

        status = BackupRestoreMbrFull(hardDiskIndex, guestLoader, true);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "BackupRestoreMbrFull");
            return status;
        }
        else
        {
            LogInfo("Restored the original mbr successfully!\n");
        }
    }
    else
    {
        LogWarning("We have registry information but MBR is not Grub.\n");
    }

    LogVerbose("PatchOrCheckGrubMbr finished\n");

    // remove the registry information
    status = RemoveInstallationInfoFromRegistry();
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "RemoveInstallationInfoFromRegistry");
    }

    LogVerbose("RemoveInstallationInfoFromRegistry finished\n");

    // delete the NapocaHv boot directory
    status = DeleteDirectoryAndContent(installFolder);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DeleteDirectoryAndContent");
        return status;
    }

    LogVerbose("DeleteDirectoryAndContent finished\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Configure / Deconfigure Napoca Hypervisor on systems with legacy BIOS firmware
 *
 * @param[in] Install           true -> Confugure, False -> Deconfigure
 *
 */
NTSTATUS
ConfigureLegacyBoot(
    _In_ BOOLEAN Install
    )
{
    return Install
        ? InstallGrub()
        : UninstallGrub();
}
