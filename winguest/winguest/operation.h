/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _OPERATION_H_
#define _OPERATION_H_

#include "fltKernel.h"
#include "driver.h"

FLT_PREOP_CALLBACK_STATUS
WinguestPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

PTSTATUS
WriteToProtectedFile(
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesWritten,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

PTSTATUS
ReadFromProtectedFile(
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesRead,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

#endif //