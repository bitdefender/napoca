/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#include "operation.h"
#include "context.h"
#include "fileprot.h"


//
// WinguestPreCreateCallback
//
FLT_PREOP_CALLBACK_STATUS
WinguestPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,        /// ...
    _In_ PCFLT_RELATED_OBJECTS FltObjects,  /// ...
    __deref_out_opt PVOID *CompletionContext /// ...
    )
//
// Routine Description:
//     Will compare the file name with the internally set name and fail if
//     the name is the same
//
// Arguments:
//     Data  -
//     FltObjects -
//     CompletionContext -
//
// Return Value:
//     STATUS_SUCCESS - always
//
/// \ret FLT_PREOP_COMPLETE ...
/// \ret FLT_PREOP_SUCCESS_NO_CALLBACK ...
//
{
    PTSTATUS status;
    PUNICODE_STRING fileName;
    BOOLEAN fileMatch;
    PINSTANCE_CONTEXT instContext;


    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    fileName = NULL;
    fileMatch = FALSE;
    instContext = NULL;

    if (FALSE == gDrv.FileProtectionEnbled)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try
    {
        PTASSERT(NULL != FltObjects->Instance);
        PTASSERT(NULL != FltObjects->Volume);
        status = FltGetInstanceContext(FltObjects->Instance, &instContext);
        if (!PT_SUCCESS(status) || NULL == instContext)
        {
            PTRACE2("[ERROR]FltGetInstanceContext failed for with status: 0x%x\n", status);
            __leave;
        }
        fileName = &Data->Iopb->TargetFileObject->FileName;
        status = FileProtFindFileNameInList(instContext, fileName);
        //PTRACE2("[INFO]File name: %S\n", fileName->Buffer);
        if (!PT_SUCCESS(status))
        {
            PTRACE2("[ERROR] : WinguestFindFileNameInProtectedFiles failed with status: 0x%x\n", status);
            __leave;
        }
        if (STATUS_FOUND == status)
        {
            PTRACE2("File name match\n");
            fileMatch = TRUE;
        }
    }
    __finally
    {
        if (NULL != instContext)
        {
            FltReleaseContext(instContext);
        }
    }
    if (TRUE == fileMatch)
    {
        //we'll fail
        Data->IoStatus.Information = FILE_DOES_NOT_EXIST;
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

PTSTATUS
ReadFromProtectedFile(
    _In_ PLARGE_INTEGER ByteOffset,         /// ...
    _In_ ULONG Length,                      /// ...
    _Out_ PVOID Buffer,                     /// ...
    _Out_ PULONG BytesRead,                 /// ...
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK Callback, /// ...
    _In_opt_ PVOID Context                  /// ...
    )
//
/// ...
//
/// \ret STATUS_NOT_INITIALIZED ...
//
{
    PTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioSb;
    PFILE_OBJECT fileObj;

    status = STATUS_SUCCESS;
    fileObj = NULL;
    RtlZeroMemory(&objAttr, sizeof(objAttr));

    if (NULL == gDrv.ProtectedFileHandle)
    {
        if (FALSE != gDrv.ProtectedFileNameSet)
        {
            InitializeObjectAttributes(&objAttr, &gDrv.KernelImagePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
            while (1 == InterlockedCompareExchange((long*)&gDrv.ProtectedFileHandleLock, 1, 0));
            status = FltCreateFile(gDrv.Filter,
                                   gDrv.SystemInstance,
                                   &gDrv.ProtectedFileHandle,
                                   FILE_READ_DATA | FILE_WRITE_DATA,
                                   &objAttr,
                                   &ioSb,
                                   NULL,
                                   FILE_ATTRIBUTE_NORMAL,
                                   0, //FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   FILE_OPEN,
                                   FILE_WRITE_THROUGH | FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE,
                                   NULL,
                                   0,
                                   0);
            gDrv.ProtectedFileHandleLock = 0;
            if (!PT_SUCCESS(status))
            {
                PTRACE2("[ERROR]FltCreateFile failed for with status: 0x%x\n", status);
                return status;
            }
        }
        else
        {
            return STATUS_NOT_INITIALIZED;
        }
    }
    __try
    {
        status = ObReferenceObjectByHandle(gDrv.ProtectedFileHandle, 0, NULL, KernelMode, &fileObj, NULL);
        if (!PT_SUCCESS(status))
        {
            PTRACE2("[ERROR] : ObReferenceObjectByHandle failed with status: 0x%x\n", status);
            __leave;
        }
        status = FltReadFile(gDrv.SystemInstance,
                             fileObj,
                             ByteOffset,
                             Length,
                             Buffer,
                             0,
                             BytesRead,
                             Callback,
                             Context);
        if (!PT_SUCCESS(status))
        {
            PTRACE2("[ERROR] : FltReadFile failed with status: 0x%x\n", status);
            __leave;
        }
        //status = STATUS_SUCCESS;
    }
    __finally
    {
        if (NULL != fileObj)
        {
            ObDereferenceObject(fileObj);
        }
    }

    return status;
}

PTSTATUS
WriteToProtectedFile(
    _In_ PLARGE_INTEGER ByteOffset,         /// ...
    _In_ ULONG Length,                      /// ...
    _Out_ PVOID Buffer,                     /// ...
    _Out_ PULONG BytesWritten,              /// ...
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK Callback, /// ...
    _In_opt_ PVOID Context                  /// ...
    )
//
/// ...
//
/// \ret STATUS_NOT_INITIALIZED ...
//
{
    PTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioSb;
    PFILE_OBJECT fileObj;

    status = STATUS_SUCCESS;
    fileObj = NULL;
    RtlZeroMemory(&objAttr, sizeof(objAttr));

    if (NULL == gDrv.ProtectedFileHandle)
    {
        if (FALSE != gDrv.ProtectedFileNameSet)
        {
            InitializeObjectAttributes(&objAttr, &gDrv.KernelImagePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
            while (1 == InterlockedCompareExchange((long*)&gDrv.ProtectedFileHandleLock, 1, 0));
            status = FltCreateFile(gDrv.Filter,
                                   gDrv.SystemInstance,
                                   &gDrv.ProtectedFileHandle,
                                   FILE_READ_DATA | FILE_WRITE_DATA,
                                   &objAttr,
                                   &ioSb,
                                   NULL,
                                   FILE_ATTRIBUTE_NORMAL,
                                   0, //FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   FILE_OPEN,
                                   FILE_WRITE_THROUGH | FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE,
                                   NULL,
                                   0,
                                   0);
            gDrv.ProtectedFileHandleLock = 0;
            if (!PT_SUCCESS(status))
            {
                PTRACE2("[ERROR]FltCreateFile failed for with status: 0x%x\n", status);
                return status;
            }
        }
        else
        {
            return STATUS_NOT_INITIALIZED;
        }
    }
    __try
    {
        status = ObReferenceObjectByHandle(gDrv.ProtectedFileHandle, 0, NULL, KernelMode, &fileObj, NULL);
        if (!PT_SUCCESS(status))
        {
            PTRACE2("[ERROR] : ObReferenceObjectByHandle failed with status: 0x%x\n", status);
            __leave;
        }
        status = FltWriteFile(gDrv.SystemInstance,
                              fileObj,
                              ByteOffset,
                              Length,
                              Buffer,
                              0,
                              BytesWritten,
                              Callback,
                              Context);
        if (!PT_SUCCESS(status))
        {
            PTRACE2("[ERROR] : FltWriteFile failed with status: 0x%x\n", status);
            __leave;
        }
        //status = STATUS_SUCCESS;
    }
    __finally
    {
        if (NULL != fileObj)
        {
            ObDereferenceObject(fileObj);
        }
    }

    return status;
}
