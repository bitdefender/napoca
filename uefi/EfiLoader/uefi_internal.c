/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// global variables and other internal stuff

#include <Uefi.h>
#include <Library\UefiLib.h>
#include "uefi_internal.h"
//#include "io/gop.h"
#include <Library\DevicePathLib.h>
#include <Protocol\LoadFile.h>
#include "debug.h"
#include <Library/SynchronizationLib.h>
#include "FileOperationsLib/FileOperationsLib.h"
#include "autogen/efi_cmdline.h"
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/BlockIo.h>
#include <Guid/EventLegacyBios.h>
#include <Guid/EventGroup.h>

EFI_GUID gEfiCertX509Guid = EFI_CERT_X509_GUID;
EFI_GUID gEfiFirmwareVolume2ProtocolGuid = EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID;
EFI_GUID gEfiBlockIoProtocolGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
EFI_GUID gEfiCertPkcs7Guid = EFI_CERT_TYPE_PKCS7_GUID;
EFI_GUID gEfiCertSha256Guid = EFI_CERT_SHA256_GUID;
EFI_GUID gEfiImageSecurityDatabaseGuid = EFI_IMAGE_SECURITY_DATABASE_GUID;
EFI_GUID gEfiCertSha1Guid = EFI_CERT_SHA1_GUID;
EFI_GUID gEfiEventLegacyBootGuid = EFI_EVENT_LEGACY_BOOT_GUID;
EFI_GUID gEfiEventReadyToBootGuid = EFI_EVENT_GROUP_READY_TO_BOOT;

EFI_SYSTEM_TABLE                        *UefiSystemTable;
EFI_BOOT_SERVICES                       *UefiBootServices;
EFI_RUNTIME_SERVICES                    *UefiRuntimeServices;
EFI_HANDLE                              UefiImageHandle;

EFI_GUID                                UefiMpServicesGuid              = EFI_MP_SERVICES_PROTOCOL_GUID;
EFI_GUID                                UefiFramewordkMpServicesGuid    = FRAMEWORK_EFI_MP_SERVICES_PROTOCOL_GUID;
EFI_MP_SERVICES_PROTOCOL                *UefiMpProtocol                 = NULL;
FRAMEWORK_EFI_MP_SERVICES_PROTOCOL      *UefiFrameworkMpProtocol        = NULL;
volatile BOOLEAN                        UefiVirtualized                 = FALSE;
QWORD                                   UefiTotalHvMemory;

#if (CFG_UEFI_MEMLOG_OUT)
    MD_LOG_BUFFER *gLog = NULL;
#endif


DWORD
UefiGetLocalApicId (
    void )
{
    int regs[4];
    __cpuid(regs, 1);
    return (regs[1] >> 24);
}


void *
UefiAlloc(
    _In_ UINT64 Amount )
{
    EFI_STATUS status;
    void *pointer;
    status = UefiBootServices->AllocatePool(EfiReservedMemoryType, Amount, &pointer);
    if (EFI_ERROR(status))
    {
        return NULL;
    }
    return pointer;
}

void
UefiFree(
    _In_ void * Buffer)
{
    UefiBootServices->FreePool(Buffer);
}

void *
UefiAllocHv(
    _In_ UINT64 Amount,
    _In_ BOOLEAN Initialized
    )
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS pa;
    UINTN pages = (Amount+PAGE_SIZE-1) / PAGE_SIZE;
    if (!CfgFilesEfiHvEnabled)
    {
        status = UefiBootServices->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, pages, &pa);
    }
    else
    {
        status = UefiBootServices->AllocatePages(AllocateAnyPages, EfiBootServicesData, pages, &pa);
    }
    if (EFI_ERROR(status))
    {
        ERR("UefiBootServices->AllocatePages", status);
        return NULL;
    }

    if (Initialized)
    {
        UefiBootServices->SetMem((PVOID)(SIZE_T)pa, pages*PAGE_SIZE, 0);
    }
    UefiTotalHvMemory += Amount;
    return (PVOID)(SIZE_T)pa;
}





EFI_STATUS
UefiGetMemoryMap(
    _Out_       EFI_MEMORY_DESCRIPTOR **MemoryMap,
    _Out_       UINT64 *DescriptorSize,
    _Out_       UINT64 *NumberOfMemoryDescriptors,
    __out_opt   UINT64 *TotalConventionalMemAvailable)
{
    BOOLEAN                 memoryMapIsBad;
    BOOLEAN                 memoryAllocated;
    UINT64                  i, totalConventionalMemAvailable;
    UINTN                   memoryMapSize = 0;
    EFI_MEMORY_DESCRIPTOR   *memoryMap = NULL;
    UINTN                   mapKey;
    UINTN                   descriptorSize;
    UINT32                  descriptorVersion;
    EFI_STATUS              status;

    if ((NULL == MemoryMap) || (NULL == DescriptorSize) || (NULL == NumberOfMemoryDescriptors))
    {
        TRACE(L"Invalid param for UefiGetMemoryMap!\r\n");
        return EFI_INVALID_PARAMETER;
    }

    //
    // Allocate buffers until the map fits
    //
    memoryMapIsBad = FALSE;
    memoryAllocated = FALSE;
    i = 0;
    do
    {
        // call GetMemoryMap only for finding out how much memory it needs to return
        status = UefiBootServices->GetMemoryMap(
                                        &memoryMapSize,
                                        memoryMap,
                                        &mapKey,
                                        &descriptorSize,
                                        &descriptorVersion);
        memoryMapIsBad = EFI_ERROR(status);
        i++;

        if (EFI_ERROR(status) && (EFI_BUFFER_TOO_SMALL != status))
        {
            // failed..
            TRACE(L"GetMemoryMap returned status=%S, required mem = %d\r\n", UefiStatusToText(status), memoryMapSize);
            return status;
        }

        if (EFI_BUFFER_TOO_SMALL == status)
        {
            // free the old buffer..
            if (memoryAllocated)
            {
                UefiBootServices->FreePool(memoryMap);  // if EFI_ERROR(status) we've got some system memory leak, not critical
            }

            // allocate the necessary amount of memory
            status = UefiBootServices->AllocatePool(EfiReservedMemoryType, memoryMapSize, &memoryMap);
            if (EFI_ERROR(status))
            {
                // failed..
                TRACE(L"AllocatePool returned status=%S\r\n", UefiStatusToText(status));
                return status;
            }
            memoryAllocated = TRUE;
        }
    } while ((i<10) && (memoryMapIsBad));


    //
    // Find out the amount of free memory
    //
    if (NULL != TotalConventionalMemAvailable)
    {
        UINT64                  mapIndex;
        EFI_MEMORY_DESCRIPTOR   *descriptor;

        totalConventionalMemAvailable = 0;

        for (mapIndex = 0; mapIndex < (memoryMapSize / descriptorSize); mapIndex++)
        {
            descriptor = (EFI_MEMORY_DESCRIPTOR*) ((BYTE*)memoryMap + (mapIndex * descriptorSize));
            if (descriptor->Type == EfiConventionalMemory)
            {
                totalConventionalMemAvailable += (descriptor->NumberOfPages * PAGE_SIZE);
            }
        }
        *TotalConventionalMemAvailable = totalConventionalMemAvailable;
    }


    //
    // Set the return values
    //
    *MemoryMap = memoryMap;
    *DescriptorSize = descriptorSize;
    *NumberOfMemoryDescriptors = memoryMapSize / descriptorSize;

    return EFI_SUCCESS;
}


EFI_STATUS
UefiExecuteEfiFile(
    _In_ CHAR16 *FileName )
{
    EFI_GUID loadedImageProtocolGUID    = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_LOADED_IMAGE_PROTOCOL           *loadedImage = NULL;
    EFI_STATUS                          status;
    EFI_HANDLE                          handle;
    EFI_BOOT_SERVICES                   *bs = UefiBootServices;
    EFI_DEVICE_PATH_PROTOCOL            *fullPath;

    // get an EFI_LOADED_IMAGE_PROTOCOL pointer
    status = bs->HandleProtocol (UefiImageHandle, &loadedImageProtocolGUID, (VOID*)&loadedImage);
    if (EFI_ERROR(status))
    {
        return status;
    }
    else if (NULL == loadedImage)
    {
        return EFI_NO_RESPONSE;
    }

    // construct a complete file path
    fullPath = FileDevicePath (loadedImage->DeviceHandle, FileName);
    if (NULL == fullPath)
    {
        return EFI_NOT_FOUND;
    }

    // load the efi file
    status = UefiBootServices->LoadImage(FALSE, UefiImageHandle, fullPath, NULL, 0, &handle);
    if (EFI_ERROR(status))
    {
        UefiBootServices->FreePool (fullPath);
        return status;
    }

    // start it
    status = UefiBootServices->StartImage(handle, NULL, NULL);
    if (EFI_ERROR(status))
    {
        UefiBootServices->FreePool (fullPath);
        return status;
    }
    // done
    UefiBootServices->FreePool (fullPath);
    return EFI_SUCCESS;
}


EFI_STATUS
UefiExecuteEfiFileA(
    _In_ char *FileName
    )
{
    CHAR16 *temp;
    EFI_STATUS status;

    if (NULL == FileName)
    {
        return EFI_INVALID_PARAMETER;
    }

    temp = (CHAR16*) UefiAlloc((AsciiStrLen (FileName) + 1) * sizeof (CHAR16));
    if (NULL == temp)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    AsciiStrToUnicodeStr(FileName, temp);
    status = UefiExecuteEfiFile(temp);
    UefiFree(temp);
    return status;
}




void
InternalInit(
    _In_ EFI_SYSTEM_TABLE *SystemTable,
    _In_ EFI_HANDLE ImageHandle)
{
    UefiSystemTable         = SystemTable;
    UefiImageHandle         = ImageHandle;
    UefiBootServices        = UefiSystemTable->BootServices;
    UefiRuntimeServices     = UefiSystemTable->RuntimeServices;

    // locate a MP protocol
    if (EFI_SUCCESS != UefiBootServices->LocateProtocol(&UefiMpServicesGuid, NULL, &UefiMpProtocol))
    {
        if (EFI_SUCCESS != UefiBootServices->LocateProtocol(&UefiFramewordkMpServicesGuid, NULL, &UefiFrameworkMpProtocol))
        {
            TRACE(L"ERROR: no MP protocol is available!\n");
        }
        else
        {
            DBG("MP operations will be performed by UefiFrameworkMpProtocol\n");
        }
    }
    else
    {
        DBG("MP operations will be performed by UefiMpProtocol\n");
    }
}


EFI_STATUS
InternalGetCpuCount(
    _Out_ UINTN *NumberOfProcessors
    )
{
    EFI_STATUS status;
    UINTN total, enabled;

    total = 0;

    if (NULL == NumberOfProcessors)
    {
        return EFI_INVALID_PARAMETER;
    }

    if (NULL != UefiMpProtocol)
    {
        // number of CPUs
        status = UefiMpProtocol->GetNumberOfProcessors(
            UefiMpProtocol,
            &total,
            &enabled);
        if (EFI_ERROR(status))
        {
            TRACE(L"[bsp]Failed to get the logical CPU count\r\n");
            goto cleanup;
        }
    }
    else if (NULL != UefiFrameworkMpProtocol)
    {
        // number of CPUs
        status = UefiFrameworkMpProtocol->GetGeneralMPInfo(
            UefiFrameworkMpProtocol,                // this
            &total,                                 // NumberOfCPUs including disabled cpus
            NULL,                                   // MaximumNumberOfCPUs supported by the system
            &enabled,                               // NumberOfEnabledCPUs
            NULL,                                   // RendezvousIntNumber
            NULL);                                  // RendezvousProcLength
        if (EFI_ERROR(status))
        {
            TRACE(L"[bsp]Failed to get the logical CPU count\r\n");
            goto cleanup;
        }
    }
    else
    {
        status = EFI_DEVICE_ERROR;
        goto cleanup;
    }
    status = EFI_SUCCESS;
cleanup:
    *NumberOfProcessors = total;

    return status;
}


EFI_STATUS
InternalStartupAllApProcessors(
    void (*ApProc) (void *Buffer),
    void *Buffer,
    __inout_opt EFI_EVENT ApEvent
    )
{
    EFI_STATUS status;
    UINTN cpus;
    UINTN i;

    status = InternalGetCpuCount(&cpus);
    if (EFI_ERROR(status))
    {
        TRACE(L"Failed to get the CPU count\n");
        goto cleanup;
    }
    // UEFI_LOG(L"Number of CPUS:%d\n", cpus);
    if (cpus == 1)
    {
        return EFI_SUCCESS;
    }

    if (NULL != UefiMpProtocol)
    {
        EFI_PROCESSOR_INFORMATION info;

        // try to enabled any disabled but healthy APs
        for (i = 0; i < cpus; i++)
        {
            status = UefiMpProtocol->GetProcessorInfo(UefiMpProtocol, i, &info);
            if (EFI_ERROR(status))
            {
                TRACE(L"Failed UefiMpProtocol->GetProcessorInfo for cpu[%d]\n", i);
            }
            else
            {
                /// BSP  ENABLED  HEALTH  Description
                /// 0      0       1     Healthy Disabled AP.
                if ((info.StatusFlag & 7) == 4)
                {
                    // enable the AP
                    status = UefiMpProtocol->EnableDisableAP(UefiMpProtocol, i, TRUE, NULL);
                    if (EFI_ERROR(status))
                    {
                        TRACE(L"Failed UefiMpProtocol->EnableDisableAP for cpu[%d]\n", i);
                    }
                }
            }
        }

        TRACE(L"UefiMpProtocol->StartupAllAPs...\n");
        // broadcast our code to all APs
        status = UefiMpProtocol->StartupAllAPs(
            UefiMpProtocol,             // this
            ApProc,                     // proc
            FALSE,                      // single thread
            ApEvent,                    // wait event
            ///15*ONE_SECOND,              // 0 = infinite, -1 = almost infinite....
            0,
            Buffer,                     // ap params
            NULL);                      // failed cpus list
        if (EFI_ERROR(status))
        {
            TRACE(L"[bsp]UefiMpProtocol->StartupAllAPs failed with status = %S\r\n", UefiStatusToText(status));
            goto cleanup;
        }
        while(gNumberOfCpusPrepared < cpus - 1)
        {

        }

        TRACE(L"Startup all APs successful!\n");
    }
    else if (NULL != UefiFrameworkMpProtocol)
    {
        TRACE(L"UefiFrameworkMpProtocol->StartupAllAPs...\n");
        // broadcast our code to all APs
        status = UefiFrameworkMpProtocol->StartupAllAPs(
            UefiFrameworkMpProtocol,    // this
            ApProc,                     // Procedure
            FALSE,                      // SingleThread
            ApEvent,                    // WaitEvent
            ///15*ONE_SECOND,              // TimeoutInMicroSecs 0 = infinite, -1 = almost infinite... (due to some buggy firmware)
            0,
            Buffer,                     // ProcArguments
            NULL);                      // FailedCPUList
        if (EFI_ERROR(status))
        {
            TRACE(L"[bsp]UefiFrameworkMpProtocol->StartupAllAPs failed with status = %S\r\n", UefiStatusToText(status));
            goto cleanup;
        }

        while(gNumberOfCpusPrepared < cpus - 1)
        {

        }
        TRACE(L"Startup all APs successful!\n");
    }
    else
    {
        TRACE(L"[WARNING] No MP protocol was found, probably single CPU ?\n");
    }
    status = EFI_SUCCESS;
cleanup:
    return status;
}



//
// synchronization routines
//
volatile QWORD gOutputLock = 0;
volatile QWORD gHvOutputLock = 0;

/// there's a UEFI runtime InterlockedIncrement function but IT'S NOT MP SAFE... by design :)
DWORD
UefiInterlockedIncrement(
    _Inout_ volatile DWORD *volatile Variable )
{
    DWORD value, result;
    do
    {
        value = *Variable;
        result = InterlockedCompareExchange32((DWORD*)Variable, value, value+1);
    } while (result != value);
    return value+1;
}

DWORD
UefiInterlockedDecrement(
    _Inout_ volatile DWORD *volatile Variable )
{
    DWORD value, result;
    do
    {
        value = *Variable;
        result = InterlockedCompareExchange32((DWORD*)Variable, value, value-1);
    } while (result != value);
    return value-1;
}


DWORD
UefiAcquireLock(
    _Inout_ volatile DWORD *volatile Lock )
{
    DWORD tmp;
    do
    {
        tmp = InterlockedCompareExchange32((DWORD*)Lock, 0, 1);
    } while (tmp != 0);
    return *Lock;
}


DWORD UefiReleaseLock(
    _Inout_ volatile DWORD *volatile Lock )
{
    *Lock = 0;
    return *Lock;
}


//
// debug routines
//

CHAR16*
UefiStatusToText(
    _In_ EFI_STATUS Status )
{
    switch(Status)
    {
        case EFI_SUCCESS:
                return L"EFI_SUCCESS";
        case EFI_LOAD_ERROR:
                return L"EFI_LOAD_ERROR";
        case EFI_INVALID_PARAMETER:
                return L"EFI_INVALID_PARAMETER";
        case EFI_UNSUPPORTED:
                return L"EFI_UNSUPPORTED";
        case EFI_BAD_BUFFER_SIZE:
                return L"EFI_BAD_BUFFER_SIZE";
        case EFI_BUFFER_TOO_SMALL:
                return L"EFI_BUFFER_TOO_SMALL";
        case EFI_NOT_READY:
                return L"EFI_NOT_READY";
        case EFI_DEVICE_ERROR:
                return L"EFI_DEVICE_ERROR";
        case EFI_WRITE_PROTECTED:
                return L"EFI_WRITE_PROTECTED";
        case EFI_OUT_OF_RESOURCES:
                return L"EFI_OUT_OF_RESOURCES";
        case EFI_VOLUME_CORRUPTED:
                return L"EFI_VOLUME_CORRUPTED";
        case EFI_VOLUME_FULL:
                return L"EFI_VOLUME_FULL";
        case EFI_NO_MEDIA:
                return L"EFI_NO_MEDIA";
        case EFI_MEDIA_CHANGED:
                return L"EFI_MEDIA_CHANGED";
        case EFI_NOT_FOUND:
                return L"EFI_NOT_FOUND";
        case EFI_ACCESS_DENIED:
                return L"EFI_ACCESS_DENIED";
        case EFI_NO_RESPONSE:
                return L"EFI_NO_RESPONSE";
        case EFI_NO_MAPPING:
                return L"EFI_NO_MAPPING";
        case EFI_TIMEOUT:
                return L"EFI_TIMEOUT";
        case EFI_NOT_STARTED:
                return L"EFI_NOT_STARTED";
        case EFI_ALREADY_STARTED:
                return L"EFI_ALREADY_STARTED";
        case EFI_ABORTED:
                return L"EFI_ABORTED";
        case EFI_ICMP_ERROR:
                return L"EFI_ICMP_ERROR";
        case EFI_TFTP_ERROR:
                return L"EFI_TFTP_ERROR";
        case EFI_PROTOCOL_ERROR:
                return L"EFI_PROTOCOL_ERROR";
        case EFI_INCOMPATIBLE_VERSION:
                return L"EFI_INCOMPATIBLE_VERSION";
        case EFI_SECURITY_VIOLATION:
                return L"EFI_SECURITY_VIOLATION";
        case EFI_CRC_ERROR:
                return L"EFI_CRC_ERROR";
        case EFI_END_OF_MEDIA:
                return L"EFI_END_OF_MEDIA";
        case EFI_END_OF_FILE:
                return L"EFI_END_OF_FILE";
        case EFI_WARN_UNKNOWN_GLYPH:
                return L"EFI_WARN_UNKNOWN_GLYPH";
        case EFI_WARN_DELETE_FAILURE:
                return L"EFI_WARN_DELETE_FAILURE";
        case EFI_WARN_WRITE_FAILURE:
                return L"EFI_WARN_WRITE_FAILURE";
        case EFI_WARN_BUFFER_TOO_SMALL:
                return L"EFI_WARN_BUFFER_TOO_SMALL";
    }
    return L"!UNKNOWN EFI_STATUS!";
}


void
UefiWaitKey(
    void )
{
    EFI_INPUT_KEY key;
    EFI_STATUS status;

    TRACE(L"Press any key to continue with the next step...\r\n");
    do
    {
        status = UefiSystemTable->ConIn->ReadKeyStroke(UefiSystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
}

char
UefiGetKey(
    void
    )
{
    EFI_INPUT_KEY key;
    EFI_STATUS status;
    do
    {
        status = UefiSystemTable->ConIn->ReadKeyStroke(UefiSystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
    return (char)key.UnicodeChar;
}

void
UefiWaitKeyMsg(
    _In_ CHAR16 *Message )
{
    EFI_INPUT_KEY key;
    EFI_STATUS status;
    TRACE(Message);
    do
    {
        status = UefiSystemTable->ConIn->ReadKeyStroke(UefiSystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
}




EFI_STATUS
UefiCheckUserHvBypass(
    VOID
    )
{
    EFI_INPUT_KEY key;
    EFI_STATUS efiStatus;
    if (!CfgUserInterractionAllowKeyboardBypass)
    {
        return EFI_UNSUPPORTED;
    }

    // check for the presence of the hotkey scancode inside the keyboard buffer
    do
    {
        efiStatus = UefiSystemTable->ConIn->ReadKeyStroke(UefiSystemTable->ConIn, &key);
        if (!EFI_ERROR(efiStatus))
        {
            TRACE(L"Got scancode = %d vs %d\n", key.ScanCode, CfgUserInterractionBypassOnScanCode);
            if (key.ScanCode == CfgUserInterractionBypassOnScanCode)
            {
                // the hotkey has been pressed, bypass...
                TRACE(L"Aborted on user behalf\n");
                efiStatus = EFI_ABORTED;
                goto cleanup;
            }
        }
    } while ((efiStatus != EFI_NOT_READY) && ( efiStatus != EFI_DEVICE_ERROR)); // while the keyboard buffer is not empty
                                                                                //       and the keyboard is present
cleanup:
    return efiStatus;
}


void
UefiAsciiDumper(
    _In_ UINT8 *Buffer,
    _In_ UINT32 Length,
    _In_ BOOLEAN PromptOnFullScreen)
{
    UINT32 i, n = 1;

    for (i = 0; i < Length; i++)
    {
        if (Buffer[i] == '\r' || Buffer[i] == '\n')
        {
            LOG(L"\r\n");
            if (i + 1 < Length && (Buffer[i] == '\r' && Buffer[i] == '\n' || Buffer[i] == '\n' && Buffer[i] == '\r'))
            {
                i++;
            }
            if (n % 5 == 0)
            {
                UefiWaitKeyMsg(L"Press any key to continue the dump");
            }
            n++;
        }
        else
        {
            LOG(L"%c", Buffer[i]);
        }
    }

}

void
UefiMemDumper(
    _In_ void *Buffer,
    _In_ UINT32 Length,
    _In_ BOOLEAN PromptOnFullScreen)
{
#define UEFIDIGIT16(x) (((x) < 10) ? (x) + '0' : (x)-10 + 'A')

    UINT8 *b = (UINT8 *) Buffer;
    UINT32 i, j, line = 0;
    CHAR16 buffer[5*16];
    for (j = 0; j < 4*16 + 1; j++)
    {
        buffer[j] = ' ';
    }
    buffer[j++] = '\0';


    TRACE(L"\r\n[00]: ");
    for (i = 0; i < Length; i++)
    {
        if (((i % 16) == 0) && (i != 0))
        {
            if ((line % 24 == 0) && (line != 0) && (PromptOnFullScreen))
            {
                UefiWaitKeyMsg(L"Press any key to continue the dump");
            }

            TRACE(L"%S\r\n[%02X]: ", buffer, i);
            line++;
            for (j = 0; j < 4*16 + 1; j++)
            {
                buffer[j] = ' ';
            }
        }

        buffer[3*(i % 16)] = UEFIDIGIT16(b[i]>>4);
        buffer[3*(i % 16) + 1] = UEFIDIGIT16(b[i] & 0xF);
        buffer[3*(i % 16) + 2] = ' ';

        if ((b[i]>=32) && (b[i] < 127))
        {
            buffer[16*3 + 1 + (i % 16)] = b[i];
        }
        else
        {
            buffer[16*3 + 1 + (i % 16)] = '.';
        }
    }
    TRACE(L"%S\r\n", buffer);
    TRACE(L"\r\n");
}
