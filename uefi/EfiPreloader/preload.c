/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include <Uefi.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/PeImage.h>
#include <Library/PeCoffLib.h>
#include <Library/DxeCoreEntryPoint.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseCryptLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <MemDebugLib/MemDebugLib.h>
#include <Library/PrintLib.h>
#include <Guid\GlobalVariable.h>
#include <Pi\PiFirmwareFile.h>
#include <Pi\PiFirmwareVolume.h>
#include "MemDebugLib/MemDebugLib.c"
#include <Guid/EventLegacyBios.h>
#include <Guid/EventGroup.h>
#include "autogen/efi_buildconfig.h"
#include "hvefi.h"

//
// We run on any UEFI Specification
//
extern CONST UINT32 _gUefiDriverRevision = 0;

CHAR8 *gEfiCallerBaseName = "Bdhv";

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE ImageHandle
)
{
    //
    // This code should be compiled out and never called
    //
    //ASSERT(FALSE);
}


//
// Global definitions and configuration preprocessor symbols
//

#pragma warning(push )
#pragma warning(disable: 4005) // Macro Redefinition for Kilo/Mega
#define KILO                    1024
#define MEGA                    (KILO*KILO)
#define PAGE_SIZE               (4*KILO)
#define MIN_VALID_FILE_SIZE     PAGE_SIZE
#define MAX_VALID_FILE_SIZE     (16*MEGA)
#pragma warning(pop)

// loader and standard fallback paths used to load the HV or the OS in case of failure
#define LOADER_FILE_NAME        L"EFI\\NapocaHv\\BDHVLOADER.efi"
#define FALLBACK_FILE_NAME1     L"EFI\\Microsoft\\Boot\\BOOTMGFW.EFI"
#define FALLBACK_FILE_NAME2     L"EFI\\Boot\\BOOTx64.EFI"
#define FALLBACK_FILE_NAME3     L"EFI\\Boot\\BOOTIA32.EFI"
#define FALLBACK_BACKUP_NAME    L"EFI\\NapocaHv\\origboot.efi"

// all settings are addressing this specific preloader version, used for breaking compatibility (disabling a preloader)
#define PRELOADER_VERSION       1

// name of the efi volatile variable that should contain the last preloader log
#define VAR_PRELOADER_LOG_NAME  L"BdHvPreloaderLog"
#define VAR_FAILCOUNT           L"BdHvPreloaderFailCount"

// all the variables we use or create are using this vendor GUID
EFI_GUID gBdHvGuid = HVSEC_BDHV_GUID;

// memory log to use
MD_LOG_BUFFER* gLog = NULL;
#define DBG(...)                MD_TRACE(gLog, __VA_ARGS__)

EFI_STATUS
EFIAPI
PrSetFailCount(
    IN UINT32 FailCount
)
{
    return gRT->SetVariable(
        VAR_FAILCOUNT,
        &gBdHvGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        sizeof(UINT32),
        &FailCount
    );
};

EFI_STATUS
EFIAPI
PrGetFailCount(
    IN UINT32 *FailCount
)
{
    EFI_STATUS status;
    UINTN numberOfBytes;

    if (NULL == FailCount)
    {
        return EFI_INVALID_PARAMETER;
    }

    numberOfBytes = sizeof(UINT32);
    status = gRT->GetVariable(
        VAR_FAILCOUNT,
        &gBdHvGuid,
        NULL,
        &numberOfBytes, // will read at most its initial value bytes
        FailCount
    );

    // consider FailCount = 0 if it is not defined or if we have troubles reading it
    // (we can protect against boot 'DoS' but we need a firmware at least capable of managing a 4 byte variable for us...)
    if ((EFI_ERROR(status)) || (numberOfBytes != sizeof(UINT32)))
    {
        *FailCount = 0;
    }

    return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
//
// Try to load and validate with custom signatures an EFI file
// or let the firmware load the original boot loader image as a fallback
//
{

    EFI_STATUS                      status;
    EFI_LOADED_IMAGE_PROTOCOL*      loadedImage;
    BOOLEAN                         origLoaderReplaced;


    EFI_DEVICE_PATH_PROTOCOL*       fullPath;
    EFI_HANDLE                      newImage;
    UINTN                           exitDataSize;
    UINT32                          failCount;

    MdLibConstructor(ImageHandle, SystemTable);

    // get the current fail counter value
    status = PrGetFailCount(&failCount);
    if (EFI_ERROR(status))
    {
        // fail count protection expects a firmware able to at least handle a nonvolatile DWORD variable..
        failCount = 0;
    }

    //if (failCount >= 3)
    //{
    //    // we don't know what exactly led us to this situation, could have been our cleanup/fallback code
    //    // so avoid doing anything more and let the firmware try the next boot option or handle the issue as it desires
    //    return EFI_ABORTED;
    //}


    // persistently increment the failCount (will reset it if we get to the point of giving control to the HV or original OS)
    failCount++;
    PrSetFailCount(failCount);  // ignore status, we'll just start with no failCount protection if the firmware can't handle it

                                // let the log creation silently fail if that's the case
    MdCreateLog(16 * KILO, 1 * KILO, &gLog);

    origLoaderReplaced = TRUE;  // until we can check, suppose we were installed by replacing the original bootx64/ia32 file

                                //
                                // Get the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL for the boot volume (we're never installed on non EFI compliant
                                // volumes so EFI_SIMPLE_FILE_SYSTEM_PROTOCOL has to be installed for the boot device)
                                //

                                // get the EFI_LOADED_IMAGE_PROTOCOL for this image
    status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, &loadedImage);
    if (EFI_ERROR(status))
    {
        DBG("ERROR: %d %r\n", status, status);
        goto bootManager; // we can't load anything without the LOADED_IMAGE_PROTOCOL
    }

    if (NULL == loadedImage)
    {
        status = EFI_UNSUPPORTED;
        DBG("ERROR: %d %r\n", status, status);
        goto bootManager; // we can't load anything without the LOADED_IMAGE_PROTOCOL
    }

    {
        EFI_HANDLE loaderHandle = NULL;
        fullPath = FileDevicePath(loadedImage->DeviceHandle, LOADER_FILE_NAME);
        if (!fullPath) goto fallback;

        status = gBS->LoadImage(TRUE, ImageHandle, fullPath, NULL, 0, &loaderHandle);
        if (!EFI_ERROR(status))
        {
            DBG("Loaded image...\n");
            status = gBS->StartImage(loaderHandle, &exitDataSize, NULL);
            if (EFI_ERROR(status))
            {
                DBG("ERROR: %d %r\n", status, status);
                gBS->UnloadImage(loaderHandle);
            }
            else
            {
                DBG("Started loader...\n");
            }
        }
        else
        {
            DBG("ERROR: %d %r\n", status, status);
        }

        if (fullPath)
        {
            gBS->FreePool(fullPath);
            fullPath = NULL;
        }

        goto fallback;
    }

fallback:
    // if the boot process has failed and returned to us continue with the fallbacks
    status = EFI_SUCCESS;

    // flush the current log to the efi variable (we don't care about the result of the operation)
    MdSaveLogToVariable(gLog, VAR_PRELOADER_LOG_NAME, &gBdHvGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

    // free the log
    MdFreeLog(gLog);
    gLog = NULL;

    // try booting the system from any of the configured fallback paths
    fullPath = FileDevicePath(loadedImage->DeviceHandle, FALLBACK_FILE_NAME1);
    if (NULL == fullPath)
    {
        return EFI_NOT_FOUND;
    }


    // consider this preloader session a success as we've just finished executing our code and we're givin control to the OS loader
    PrSetFailCount(0);  // ignore the return value, the fail count protection is a 'best effort' at most

    status = gBS->LoadImage(TRUE, ImageHandle, fullPath, NULL, 0, &newImage);
    if (!EFI_ERROR(status))
    {
        exitDataSize = 0;
        status = gBS->StartImage(newImage, &exitDataSize, NULL);
        // free resources if it didn't succeed
        status = gBS->UnloadImage(newImage);
        gBS->FreePool(fullPath);
    }
    else
    {
        // undo, we're back to executing our code
        PrSetFailCount(failCount);  // ignore the return value, the fail count protection is a 'best effort' at most
        gBS->FreePool(fullPath);
    }


    if (origLoaderReplaced)
    {
        // try to load the backup copy of the original file
        fullPath = FileDevicePath(loadedImage->DeviceHandle, FALLBACK_BACKUP_NAME);
        if (NULL == fullPath)
        {
            return EFI_NOT_FOUND;
        }

        // consider this preloader session a success as we've just finished executing our code and we're givin control to the OS loader
        PrSetFailCount(0);  // ignore the return value, the fail count protection is a 'best effort' at most

        status = gBS->LoadImage(TRUE, ImageHandle, fullPath, NULL, 0, &newImage);
        if (!EFI_ERROR(status))
        {
            exitDataSize = 0;
            status = gBS->StartImage(newImage, &exitDataSize, NULL);
            // free resources if it didn't succeed
            status = gBS->UnloadImage(newImage);
            gBS->FreePool(fullPath);
        }
        else
        {
            // undo, we're back to executing our code
            PrSetFailCount(failCount);  // ignore the return value, the fail count protection is a 'best effort' at most
            gBS->FreePool(fullPath);
        }
    }
    else
    {
        // try the FALLBACK_FILE_NAME2 and FALLBACK_FILE_NAME3 (as we know we did not replace them at installation)
        fullPath = FileDevicePath(loadedImage->DeviceHandle, FALLBACK_FILE_NAME2);
        if (NULL == fullPath)
        {
            return EFI_NOT_FOUND;
        }

        // consider this preloader session a success as we've just finished executing our code and we're givin control to the OS loader
        PrSetFailCount(0);  // ignore the return value, the fail count protection is a 'best effort' at most

        status = gBS->LoadImage(TRUE, ImageHandle, fullPath, NULL, 0, &newImage);
        if (!EFI_ERROR(status))
        {
            exitDataSize = 0;
            status = gBS->StartImage(newImage, &exitDataSize, NULL);
            // free resources if it didn't succeed
            status = gBS->UnloadImage(newImage);
            gBS->FreePool(fullPath);
        }
        else
        {
            // undo, we're back to executing our code
            PrSetFailCount(failCount);  // ignore the return value, the fail count protection is a 'best effort' at most
            gBS->FreePool(fullPath);
        }


        fullPath = FileDevicePath(loadedImage->DeviceHandle, FALLBACK_FILE_NAME3);
        if (NULL == fullPath)
        {
            return EFI_NOT_FOUND;
        }

        // consider this preloader session a success as we've just finished executing our code and we're givin control to the OS loader
        PrSetFailCount(0);  // ignore the return value, the fail count protection is a 'best effort' at most

        status = gBS->LoadImage(TRUE, ImageHandle, fullPath, NULL, 0, &newImage);
        if (!EFI_ERROR(status))
        {
            exitDataSize = 0;
            status = gBS->StartImage(newImage, &exitDataSize, NULL);
            // free resources if it didn't succeed
            status = gBS->UnloadImage(newImage);
            gBS->FreePool(fullPath);
        }
        else
        {
            // undo, we're back to executing our code
            PrSetFailCount(failCount);  // ignore the return value, the fail count protection is a 'best effort' at most
            gBS->FreePool(fullPath);
        }
    }


bootManager:
    // if every other attempt to boot the system has failed return to the boot manager to continue its process

    // consider this preloader session a success (we're exiting to the Boot Manager)
    PrSetFailCount(0);  // ignore the return value, there's nothing else we can do at this point

                        /// "If the boot via Boot#### returns with a status of EFI_SUCCESS the boot manager will
                        /// stop processing the BootOrder variable and present a boot manager menu to the user
                        /// If a boot via Boot#### returns a status other than EFI_SUCCESS, the boot has failed and the next
                        /// Boot#### in the BootOrder variable will be tried until all possibilities are exhausted"
    return status;
}
