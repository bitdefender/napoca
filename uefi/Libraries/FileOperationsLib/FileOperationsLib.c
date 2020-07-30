/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include <Uefi.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Library/DevicePathLib.h>
#include "FileOperationsLib.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Library/MemoryAllocationLib.h>

#ifndef __LOADER_IMPORTS__
#ifdef __DEBUG__
//#define UEFI_LOG Print
#define DBG(...) AsciiPrint("%a:%d ", __FUNCTION__, __LINE__), AsciiPrint(__VA_ARGS__)
#define ERR(...) DBG("ERROR: " __VA_ARGS__)
#define LOG(...) AsciiPrint(__VA_ARGS__)
#else
//#define UEFI_LOG
#define DBG(...)
#define ERR(...)
#define LOG(...)
#endif
#endif

EFI_LOADED_IMAGE_PROTOCOL        *FoLoadedImageProtocol;
EFI_SYSTEM_TABLE                 *FoSystemTable;
#define AllocatePool AllocatePool
#define FreePool FreePool

EFI_STATUS
EFIAPI
FoLibConstructor(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    return FoInitialize (ImageHandle,SystemTable);
}


EFI_STATUS
FoInitialize(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_LOADED_IMAGE_PROTOCOL *loadedImage;
    EFI_STATUS status;

    status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, &loadedImage);

    if (EFI_ERROR(status))
    {
        return status;
    }

    if (NULL == loadedImage)
    {
        status = EFI_UNSUPPORTED;
        return status;
    }

    FoLoadedImageProtocol = loadedImage;
    FoSystemTable = SystemTable;
    return EFI_SUCCESS;
}


void
FoWaitKey(
    void )
{
    EFI_INPUT_KEY key;
    EFI_STATUS status;

    Print(L"Press any key to continue with the next step...\r\n");
    do
    {
        status = FoSystemTable->ConIn->ReadKeyStroke(FoSystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
}



EFI_STATUS
FoFileOperation(
    IN        CHAR16 *FileName,
    IN OUT     void **Buffer,      // in for write operations, out for reads, ignored otherwise
    IN OUT     UINTN *BufferSize,  // in for write operations, out for reads, ignored otherwise
    IN OPTIONAL    UINTN ForcedBufferSize, // used only for reads
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT OPTIONAL   EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    )
{
    EFI_STATUS                      status, returnStatus;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *efiSimpleFileSystemProtocol;
    EFI_GUID                        efiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_PROTOCOL               *rootFileProtocol, *targetFileProtocol;
    UINT64                          fileSize;

    returnStatus = EFI_SUCCESS;
    if ( (NULL == FileName) || (NULL == BufferSize) || (NULL == Buffer) )
    {
        return EFI_INVALID_PARAMETER;
    }
    fileSize = *BufferSize;

    // try to get the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL for the EFI partition FS
    status = gBS->HandleProtocol(FoLoadedImageProtocol->DeviceHandle,
                                                &efiSimpleFileSystemProtocolGuid, &efiSimpleFileSystemProtocol);
    if (EFI_ERROR(status))
    {
        return status;
    }

    // get a SIMPLE_FILE_SYSTEM_PROTOCOL for the volume (root)
    status = efiSimpleFileSystemProtocol->OpenVolume(efiSimpleFileSystemProtocol, &rootFileProtocol);
    if (EFI_ERROR(status))
    {
        DBG("OpenVolume failed with %r\n", status);
        return status;
    }

    // open the target file
    status = rootFileProtocol->Open(rootFileProtocol, &targetFileProtocol, FileName, AccessType, 0);
    if (EFI_ERROR(status))
    {
        returnStatus = status;
        DBG("rootFileProtocol->Open(rootFileProtocol[%p], &targetFileProtocol[%p], FileName[%p], AccessType[%p], 0); %r\n",
            rootFileProtocol, &targetFileProtocol, FileName, AccessType, status);
        goto volume_cleanup;
    }

    if (0 == (AccessType & EFI_FILE_MODE_CREATE))
    {
        // get file size
        //"Seeking to position 0xFFFFFFFFFFFFFFFF causes the current position to be set to the end of the file"
        status = targetFileProtocol->SetPosition(targetFileProtocol, 0xFFFFFFFFFFFFFFFF);
        if (EFI_ERROR(status))
        {
            returnStatus = status;
            goto file_cleanup;
        }

        // get the file size
        status = targetFileProtocol->GetPosition(targetFileProtocol, &fileSize);
        if (EFI_ERROR(status))
        {
            returnStatus = status;
            goto file_cleanup;
        }

        // get back to the beginning of the file
        status = targetFileProtocol->SetPosition(targetFileProtocol, 0);
        if (EFI_ERROR(status))
        {
            returnStatus = status;
            goto file_cleanup;
        }
    }
    else
    {
        status = targetFileProtocol->Delete(targetFileProtocol);
        if (EFI_ERROR(status))
        {
            returnStatus = status;
            DBG("targetFileProtocol->Delete(rootFileProtocol[%p], &targetFileProtocol[%p], FileName[%p], AccessType[%p], 0); %r\n",
                rootFileProtocol, &targetFileProtocol, FileName, AccessType, status);
            //goto volume_cleanup;
        }
        else
        {
            status = rootFileProtocol->Open(rootFileProtocol, &targetFileProtocol, FileName, AccessType, 0);
            if (EFI_ERROR(status))
            {
                returnStatus = status;
                DBG("rootFileProtocol->Open(rootFileProtocol[%p], &targetFileProtocol[%p], FileName[%p], AccessType[%p], 0); %r\n",
                    rootFileProtocol, &targetFileProtocol, FileName, AccessType, status);
                goto volume_cleanup;
            }
        }
    }

    // write the buffer data
    if ((NULL != Buffer) && (NULL != *Buffer) && (NULL != BufferSize) && (0 != *BufferSize) &&
        (AccessType & EFI_FILE_MODE_WRITE))
    {
        status = targetFileProtocol->Write(targetFileProtocol, BufferSize, *Buffer);
        if (EFI_ERROR(status))
        {
            returnStatus = status;
            DBG("Writing %dKB has failed with %r\n", *BufferSize/1024, status);
            goto file_cleanup;
        }
        goto file_cleanup;
    }

    *BufferSize = (UINTN)fileSize;
    // read the file content
    if (AccessType & EFI_FILE_MODE_READ)
    {
        if (ForcedBufferSize == 0)
        {
            ForcedBufferSize = (UINTN)fileSize;
        }
        else if (ForcedBufferSize < fileSize)
        {
            returnStatus = EFI_BAD_BUFFER_SIZE;
            goto file_cleanup;
        }

        // allocate the buffer
        status = gBS->AllocatePages(
            AllocateAnyPages,
            EfiRuntimeServicesData,
            (ForcedBufferSize + 4095) / 4096,
            (EFI_PHYSICAL_ADDRESS*) Buffer);
        //status = gBS->AllocatePool(EfiBootServicesData, *BufferSize, Buffer);
        if (EFI_ERROR(status))
        {
            DBG("Failed to allocate memory for HV file!\r\n");
            returnStatus = status;
            goto file_cleanup;
        }

        // read the file
        status = targetFileProtocol->Read(targetFileProtocol, BufferSize, *Buffer);
        if (EFI_ERROR(status))
        {
            DBG("Failed reading the HV file!\r\n");
            returnStatus = status;
            goto buffer_cleanup;
        }

        goto file_cleanup;                              // done, close the file+volume but keep the buffer
    }

buffer_cleanup:
    // we don't care if the next api fails, no way to force it
    gBS->FreePages((EFI_PHYSICAL_ADDRESS) *Buffer, (ForcedBufferSize + 4095) / 4096);
    *Buffer = NULL;

file_cleanup:
    if (File == NULL)
    {
        targetFileProtocol->Close(targetFileProtocol);  // we don't care if this api fails, no way to force it
    }
    else
    {
        *File = targetFileProtocol;
    }

volume_cleanup:
    if (File == NULL)
    {
        rootFileProtocol->Close(rootFileProtocol);      // we don't care if this api fails, no way to force it
    }

    return returnStatus;                                    // return the most recent status, either the encountered error or EFI_SUCCESS
}


EFI_STATUS
FoFileOperationA(
    IN        char *FileName,
    IN OUT     void **Buffer,      // in for write operations, out for reads, ignored otherwise
    IN OUT     UINTN *BufferSize,  // in for write operations, out for reads, ignored otherwise
    IN OPTIONAL    UINTN ForcedBufferSize, // used only for reads
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT OPTIONAL   EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    )
{
    CHAR16 *temp;
    EFI_STATUS status;

    if (NULL == FileName)
    {
        return EFI_INVALID_PARAMETER;
    }

    temp = (CHAR16*) AllocatePool((AsciiStrLen (FileName) + 1) * sizeof (CHAR16));
    if (NULL == temp)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    AsciiStrToUnicodeStr(FileName, temp);
    status = FoFileOperation(temp, Buffer, BufferSize, ForcedBufferSize, AccessType, File);
    FreePool(temp);
    return status;
}

EFI_STATUS
FoOpenFile(
    IN        CHAR16 *FileName,
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT       EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    )
{
    if (NULL == File)
    {
        return EFI_INVALID_PARAMETER;
    }
    return FoFileOperation(FileName, NULL, NULL, 0, AccessType, File);
}

EFI_STATUS
FoOpenFileA(
    IN        char *FileName,
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT       EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    )
{
    if (NULL == File)
    {
        return EFI_INVALID_PARAMETER;
    }
    return FoFileOperationA(FileName, NULL, NULL, 0, AccessType, File);
}


EFI_STATUS
FoStoreFile(
    IN CHAR16 *FileName,
    IN void *Buffer,
    IN UINTN BufferSize
    )
{
    return  FoFileOperation(
        FileName,
        &Buffer,        // in for write operations, out for reads
        &BufferSize,    // in for write operations, out for reads
        0,
        EFI_FILE_MODE_CREATE|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_READ,
        NULL
        );
}


EFI_STATUS
FoStoreFileA(
    IN char *FileName,
    IN void *Buffer,
    IN UINTN BufferSize
    )
{
    return  FoFileOperationA(
        FileName,
        &Buffer,        // in for write operations, out for reads
        &BufferSize,    // in for write operations, out for reads
        0,
        EFI_FILE_MODE_CREATE|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_READ,
        NULL
        );
}

EFI_STATUS
FoLoadFile(
    IN CHAR16 *FileName,
    OUT void **Buffer,
    IN UINTN *BufferSize,
    IN OPTIONAL UINTN ForcedBufferSize
    )
{
    return  FoFileOperation(
            FileName,
            Buffer,     // in for write operations, out for reads
            BufferSize, // in for write operations, out for reads
            ForcedBufferSize,
            EFI_FILE_MODE_READ,
            NULL
            );
}

EFI_STATUS
FoUnloadFile(
    IN void *Buffer,
    IN UINTN BufferSize
)
{
    return gBS->FreePages((EFI_PHYSICAL_ADDRESS)Buffer, (BufferSize + 4095 / 4096));
}
EFI_STATUS
FoLoadFileA(
    IN        char *FileName,
    OUT       void **Buffer,
    OUT       UINTN *BufferSize,
    IN OPTIONAL    UINTN ForcedBufferSize
    )
{
    return  FoFileOperationA(
        FileName,
        Buffer,     // in for write operations, out for reads
        BufferSize, // in for write operations, out for reads
        ForcedBufferSize,
        EFI_FILE_MODE_READ,
        NULL
        );
}

EFI_STATUS
FoDumpMemory(
    IN OPTIONAL CHAR8 *Message,
    IN VOID *Address,
    IN UINTN Length
    )
{
    UINT8 *p;
    UINTN i;
    CHAR8 line[17];

    p = Address;

    if (NULL != Message)
    {
        AsciiPrint("Dumping %d bytes from %p - %a\n", Length, Address, Message);
    }

    for (i = 0; i < Length; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                line[16] = 0;
                AsciiPrint("%a\n", line);
            }
            AsciiPrint("%018p: ", p);

        }
        line[i % 16] = *p;
        if ((line[i % 16] < 32) || (line[i % 16] >= 127))
        {
            line [i % 16] = '.';
        }
        AsciiPrint("%02X ", *p);
        p++;
    }

    while ((i % 16) != 0)
    {
        AsciiPrint("XX ");
        line [i % 16] = ' ';
        i++;
    }
    line[16] = 0;
    AsciiPrint("%a\n", line);
    return EFI_SUCCESS;
}
