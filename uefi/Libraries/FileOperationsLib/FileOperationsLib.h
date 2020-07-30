/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _FILEOPERATIONSLIB_H_
#define _FILEOPERATIONSLIB_H_

#include <Uefi.h>
#include <Protocol/Hash.h>
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

extern EFI_LOADED_IMAGE_PROTOCOL        *FoLoadedImageProtocol;
extern EFI_SYSTEM_TABLE                 *FoSystemTable;

EFI_STATUS
EFIAPI
FoLibConstructor(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    );

EFI_STATUS
FoInitialize(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    );

void
FoWaitKey(
    void
    );

EFI_STATUS
FoFileOperation(
    IN        CHAR16 *FileName,
    IN OUT     void **Buffer,      // in for write operations, out for reads, ignored otherwise
    IN OUT     UINTN *BufferSize,  // in for write operations, out for reads, ignored otherwise
    IN OPTIONAL    UINTN ForcedBufferSize, // used only for reads
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT OPTIONAL   EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    );

EFI_STATUS
FoFileOperationA(
    IN        char *FileName,
    IN OUT     void **Buffer,      // in for write operations, out for reads, ignored otherwise
    IN OUT     UINTN *BufferSize,  // in for write operations, out for reads, ignored otherwise
    IN OPTIONAL    UINTN ForcedBufferSize, // used only for reads
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT OPTIONAL   EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    );

EFI_STATUS
FoOpenFile(
    IN        CHAR16 *FileName,
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT       EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    );


EFI_STATUS
FoOpenFileA(
    IN        char *FileName,
    IN        UINT64 AccessType,  // EFI_FILE_MODE_READ...
    OUT       EFI_FILE_PROTOCOL **File // resulted pointer to the file protocol
    );

EFI_STATUS
FoStoreFile(
    IN CHAR16 *FileName,
    IN void *Buffer,
    IN UINTN BufferSize
    );


EFI_STATUS
FoStoreFileA(
    IN char *FileName,
    IN void *Buffer,
    IN UINTN BufferSize
    );

EFI_STATUS
FoLoadFile(
    IN CHAR16 *FileName,
    OUT void **Buffer,
    IN UINTN *BufferSize,
    IN OPTIONAL UINTN ForcedBufferSize
    );

EFI_STATUS
FoLoadFileA(
    IN        char *FileName,
    OUT       void **Buffer,
    OUT       UINTN *BufferSize,
    IN OPTIONAL    UINTN ForcedBufferSize
    );

EFI_STATUS
FoUnloadFile(
    IN void *Buffer,
    IN UINTN BufferSize
);

EFI_STATUS
FoDumpMemory(
    IN OPTIONAL CHAR8 *Message,
    IN VOID *Address,
    IN UINTN Length
    );
#endif