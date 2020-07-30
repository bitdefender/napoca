/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include <Uefi.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include "MemDebugLib.h"
#include <Library/PrintLib.h>

// globals initialized by the library constructor
EFI_HANDLE          MdImageHandle;
EFI_SYSTEM_TABLE    *MdSystemTable;



EFI_STATUS
EFIAPI
MdLibConstructor(
    IN EFI_HANDLE           ImageHandle,
    IN EFI_SYSTEM_TABLE     *SystemTable
    )
//
// Capture the the values of the application entry point parameters
//
{
    MdImageHandle = ImageHandle;
    MdSystemTable = SystemTable;

    return EFI_SUCCESS;
}


BOOLEAN
EFIAPI
MdIsValidLog(
    IN MD_LOG_BUFFER *Log
    )
//
// Validate if Log is perfectly safe for use
//
{
    if (NULL == Log)
    {
        return FALSE;
    }
    if (FALSE == Log->IsReady)
    {
        return FALSE;
    }
    if ((NULL == Log->Buffer) || (NULL == Log->Temp))
    {
        return FALSE;
    }
    if ((0 == Log->Size) || (0 == Log->TempSize))
    {
        return FALSE;
    }
    return TRUE;
}



EFI_STATUS
EFIAPI
MdCreateLog(
    IN UINTN                LogSize,
    IN UINTN                TempBufferSize,
    OUT MD_LOG_BUFFER       **Log
    )
//
// Create a new log structure
//
{
    MD_LOG_BUFFER *log;
    EFI_STATUS status;

    if (NULL == Log)
    {
        return EFI_INVALID_PARAMETER;
    }

    status = EFI_OUT_OF_RESOURCES;

    // allocate both the structure and the two buffers
    log = (MD_LOG_BUFFER*) AllocateZeroPool(sizeof(MD_LOG_BUFFER));
    if (NULL == log)
    {
        goto cleanup;
    }

    log->Buffer = AllocatePool(LogSize);
    log->Size = LogSize;
    if (NULL == log->Buffer)
    {
        goto cleanup;
    }

    log->Temp = AllocatePool(LogSize);
    log->TempSize = LogSize;
    if (NULL == log->Temp)
    {
        goto cleanup;
    }

    // start with an empty string of 1 null byte
    log->Buffer[0] = 0;
    log->Full = FALSE;
    log->Pos = 1;

    log->IsReady = TRUE;
    *Log = log;
    return EFI_SUCCESS;

cleanup:
    if (NULL != log->Buffer)
    {
        FreePool(log->Buffer);
    }
    if (NULL != log->Temp)
    {
        FreePool(log->Temp);
    }
    if (NULL != log)
    {
        FreePool(log);
    }
    *Log = NULL;

    return status;
}


EFI_STATUS
EFIAPI
MdFreeLog(
    IN OUT MD_LOG_BUFFER    *Log
    )
//
// Free resources associated with a log
//
{
    if (NULL == Log)
    {
        return EFI_INVALID_PARAMETER;
    }

    if (NULL != Log->Buffer)
    {
        FreePool(Log->Buffer);
    }
    if (NULL != Log->Temp)
    {
        FreePool(Log->Temp);
    }
    if (NULL != Log)
    {
        FreePool(Log);
    }
    return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
MdFlushLine(
    IN MD_LOG_BUFFER       *Log
    )
//
// Flush the temporary buffer data to the circular log buffer
//
{
    UINTN i;
    if (!MdIsValidLog(Log))
    {
        return EFI_INVALID_PARAMETER;
    }

    // overwrite the old string terminator (MdCreateLog prepares an initial one)
    Log->Pos--;

    // copy the new string to the circular buffer
    for (i = 0; ((0 != Log->Temp[i]) && (i < Log->TempSize)); i++, Log->Pos++)
    {
        Log->Buffer[Log->Pos % Log->Size] = Log->Temp[i];
    }

    // add the new string terminator
    Log->Buffer[Log->Pos % Log->Size] = 0;
    Log->Pos++;

    // we can only flip to TRUE the Full flag
    if (Log->Pos >= Log->Size)
    {
        Log->Pos = Log->Pos % Log->Size;
        Log->Full = TRUE;
    }
    return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
MdSaveLogToBuffer(
    IN MD_LOG_BUFFER        *Log,
    IN OPTIONAL OUT CHAR8   **Buffer,     // if NULL == *Buffer try to allocate one, otherwise use the sent one
    IN OPTIONAL OUT UINTN   *BufferSize   // ignore as input unless NULL!=Buffer, returns the amount of necessary/used memory
    )
//
// write the circular buffer data to a standard/liniar buffer
//
{
    UINTN numberOfBytes;
    UINTN start;

    if (!MdIsValidLog(Log))
    {
        return EFI_INVALID_PARAMETER;
    }

    // data starts either at zero or right after Log->Pos if overflow
    start = 0;
    if (Log->Full)
    {
        start = Log->Pos;
    }

    // find out the length of the data
    numberOfBytes = 0;
    while ((numberOfBytes < Log->Size) && (Log->Buffer[((start + numberOfBytes) % Log->Size)] != 0))
    {
        numberOfBytes++;
    }

    // account for the zero terminator
    numberOfBytes++;

    // if a buffer was sent make sure there's enough room
    if ((NULL != *Buffer) && (*BufferSize < numberOfBytes))
    {
        *BufferSize = numberOfBytes;
        return EFI_BUFFER_TOO_SMALL;
    }

    // prepare a new buffer if none was sent
    if (NULL == *Buffer)
    {
        *BufferSize = 0;
        *Buffer = (CHAR8*) AllocatePool(numberOfBytes);
        if (NULL == *Buffer)
        {
            return EFI_OUT_OF_RESOURCES;
        }

        *BufferSize = numberOfBytes;
    }

    // copy the actual data
    numberOfBytes = 0;
    while ((numberOfBytes < Log->Size) && (Log->Buffer[((start + numberOfBytes) % Log->Size)] != 0))
    {
        (*Buffer)[numberOfBytes] = Log->Buffer[((start + numberOfBytes) % Log->Size)];
        numberOfBytes++;
    }

    // add the null terminator
    (*Buffer)[numberOfBytes] = 0;

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MdGetBufferFromUefiVariable(
    IN CHAR8                *Buffer,
    IN OUT UINTN            *BufferSize,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    OUT UINT32              *VariableAttributes
    )
//
// Load a buffer from an EFI variable
//
{
    if ((NULL == Buffer) || (NULL == VariableName) || (NULL == VendorGuid))
    {
        return EFI_INVALID_PARAMETER;
    }

    // set the variable
    return gRT->GetVariable(
        VariableName,
        VendorGuid,
        VariableAttributes,
        BufferSize,
        Buffer
        );
}

EFI_STATUS
EFIAPI
MdSaveBufferToUefiVariable(
    IN CHAR8                *Buffer,
    IN UINTN                BufferSize,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    IN UINT32                VariableAttributes
    )
//
// Save a buffer as an EFI variable
//
{
    if ((NULL == Buffer) || (0 == BufferSize) || (NULL == VariableName) || (NULL == VendorGuid))
    {
        return EFI_INVALID_PARAMETER;
    }

    // set the variable
    return gRT->SetVariable(
        VariableName,
        VendorGuid,
        VariableAttributes,
        BufferSize,
        Buffer
        );
}

EFI_STATUS
EFIAPI
MdSaveLogToVariable(
    IN MD_LOG_BUFFER        *Log,
    IN CHAR16               *VariableName,
    IN EFI_GUID             *VendorGuid,
    IN UINT32                VariableAttributes
    )
//
// Save a log as an EFI variable
//
{
    CHAR8 *buffer;
    UINTN bufferSize;
    EFI_STATUS status;

    if ((!MdIsValidLog(Log)) || (NULL == VariableName) || (NULL == VendorGuid))
    {
        return EFI_INVALID_PARAMETER;
    }

    // get the current buffer data
    buffer = NULL;
    bufferSize = 0;
    status = MdSaveLogToBuffer(Log, &buffer, &bufferSize);
    if (EFI_ERROR(status))
    {
        return status;
    }

    // set the variable
    status = gRT->SetVariable(
        VariableName,
        VendorGuid,
        VariableAttributes,
        bufferSize,
        buffer
        );

    FreePool(buffer);
    return status;
}



EFI_STATUS
EFIAPI
MdDumpMemory(
    IN MD_LOG_BUFFER        *Log,
    IN OPTIONAL CHAR8       *Message,
    IN VOID                 *Address,
    IN UINTN                Length
    )
//
// Log a memory dump (probably won't be used in production code)
//
{
    UINT8 *bytePtr;
    UINTN index;
    CHAR8 characters[17];

    if ((!MdIsValidLog(Log)) || (NULL == Address))
    {
        return EFI_INVALID_PARAMETER;
    }

    bytePtr = Address;

    if (NULL != Message)
    {
        MD_LOG(Log, "Dumping %d bytes from %p - %a\n", Length, Address, Message);
    }

    for (index = 0; index < Length; index++)
    {
        // treat the end of a 16 bytes group
        if ((index % 16) == 0)
        {
            if (index != 0)
            {
                characters[16] = 0;
                MD_LOG(Log, "%a\n", characters); // flush the old characters line
            }
            MD_LOG(Log, "%018p: ", bytePtr);
        }

        // add current character representation in buffer
        if ((*bytePtr < 32) || (*bytePtr >= 127))
        {
            characters [index % 16] = '.';
        }
        else
        {
            characters [index % 16] = *bytePtr;
        }

        // output the hex value
        MD_LOG(Log, "%02X ", *bytePtr);
        bytePtr++;
    }

    // add spaces to fill the final line
    while ((index % 16) != 0)
    {
        MD_LOG(Log, "   ");
        characters [index % 16] = ' ';
        index++;
    }

    // print the last characters line
    characters[16] = 0;
    MD_LOG(Log, "%a\n", characters);

    return EFI_SUCCESS;
}



UINT16
EFIAPI
MdWaitKey(
    IN MD_LOG_BUFFER        *Log
    )
//
// Debug function (must not be used in production code)
//
{
    EFI_INPUT_KEY key;
    EFI_STATUS status;
    if (!MdIsValidLog(Log))
    {
        return 0;
    }

    MD_LOG(Log, "Press any key to continue...\n");
    do
    {
        status = MdSystemTable->ConIn->ReadKeyStroke(MdSystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);

    return key.ScanCode;
}



