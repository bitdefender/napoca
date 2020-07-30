/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _MEMDEBUGLIB_H_
#define _MEMDEBUGLIB_H_

#include <Uefi.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/SimpleFileSystem.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Library/PrintLib.h>

#define VAR_HV_LOG_NAME                 L"BdHvLog"

#define MD_LOG(Log, ...)                (MdIsValidLog(Log) && \
                                        (AsciiSPrint((Log)->Temp, (Log)->TempSize, __VA_ARGS__), MdFlushLine(Log)))
#define MD_ULOG(Log, ...)               (MdIsValidLog(Log) && \
                                        (AsciiSPrintUnicodeFormat((Log)->Temp, (Log)->TempSize, __VA_ARGS__), MdFlushLine(Log)))

#define MD_TRACE(Log, ...)              ((MD_LOG(Log, "%a:%d ", __FUNCTION__, __LINE__), MD_LOG(Log, __VA_ARGS__)))
#define MD_UTRACE(Log, ...)             ((MD_LOG(Log, "%a:%d ", __FUNCTION__, __LINE__), MD_ULOG(Log, __VA_ARGS__)))
#define MD_ERR(Log, ...)                (MD_LOG(Log, "ERROR: " __VA_ARGS__))
#define MD_UERR(Log, ...)               (MD_ULOG(Log, "ERROR: " __VA_ARGS__))

#define MD_TRACE_DUMP_MEMORY(Log, ...)  (MD_TRACE(Log, ""), MdDumpMemory(Log, __VA_ARGS__))
#define MD_TRACE_WAIT_KEY(Log, ...)     (MD_TRACE(Log, ""), MdWaitKey(Log, __VA_ARGS__))


typedef struct _MD_LOG_BUFFER
{
    BOOLEAN IsReady;        // consider all pointers safe if IsReady
    BOOLEAN Full;           // buffer is full, now start pointer == pos
    UINT8 *Buffer;          // actual memory for logging (a circular buffer)
    UINTN Size;             // size of the Buffer field
    UINT8 *Temp;            // temporary (linear) memory for vsprintf
    UINTN TempSize;         // size of temp buffer
    UINTN Pos;              // Pos % Size == index in Buffer
}MD_LOG_BUFFER, *PMD_LOG_BUFFER;


BOOLEAN
EFIAPI
MdIsValidLog(
    IN MD_LOG_BUFFER *Log
    );


EFI_STATUS
EFIAPI
MdLibConstructor(
    IN EFI_HANDLE           ImageHandle,
    IN EFI_SYSTEM_TABLE     *SystemTable
    );


EFI_STATUS
EFIAPI
MdCreateLog(
    IN UINTN                LogSize,        // total memory space for logging
    IN UINTN                TempBufferSize, // memory space for single vsprintf calls
    OUT MD_LOG_BUFFER       **Log           // resulted structure
    );


EFI_STATUS
EFIAPI
MdFreeLog(
    IN OUT MD_LOG_BUFFER    *Log
    );


EFI_STATUS
EFIAPI
MdSaveLogToBuffer(
    IN MD_LOG_BUFFER        *Log,
    IN OPTIONAL OUT CHAR8   **Buffer,     // if NULL == *Buffer try to allocate one, otherwise use the sent one
    IN OPTIONAL OUT UINTN   *BufferSize   // ignore as input unless NULL!=Buffer, returns the amount of necessary/used memory
    );

EFI_STATUS
EFIAPI
MdGetBufferFromUefiVariable(
    IN CHAR8                *Buffer,
    IN OUT UINTN            *BufferSize,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    OUT UINT32              *VariableAttributes
    );

EFI_STATUS
EFIAPI
MdSaveBufferToUefiVariable(
    IN CHAR8                *Buffer,
    IN UINTN                BufferSize,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    IN UINT32                VariableAttributes
    );

EFI_STATUS
EFIAPI
MdSaveLogToVariable(
    IN MD_LOG_BUFFER        *Log,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    IN UINT32                VariableAttributes
    );

UINT16
EFIAPI
MdWaitKey(
    IN MD_LOG_BUFFER        *Log
    );


EFI_STATUS
EFIAPI
MdDumpMemory(
    IN MD_LOG_BUFFER        *Log,
    IN OPTIONAL CHAR8       *Message,
    IN VOID                 *Address,
    IN UINTN                Length
    );


EFI_STATUS
EFIAPI
MdFlushLine(
    IN MD_LOG_BUFFER        *Log
    );

#endif