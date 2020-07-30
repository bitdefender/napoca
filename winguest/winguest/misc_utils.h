/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _MISC_UTILS_H_
#define _MISC_UTILS_H_

typedef enum _HvParameter
{
    hvParamUnknown = 0,
    hvParamReinitRoutineCallCount,
    hvParamReserveHvLogBuffer
}HvParameter;

#define STATIC_WSTR_TO_UNICODE(ConstString)     {sizeof(ConstString)-sizeof(L""), sizeof(ConstString), (ConstString)}
#define UNICODE_LEN(String)                     ((String).Length >> 1)

_At_(String->Buffer, __drv_allocatesMem(Mem))
_At_(String->Buffer, _Post_writable_size_(Length))
NTSTATUS
CreateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_  USHORT Length
);

_At_(String->Buffer, __drv_freesMem(Mem))
_At_(String->Buffer, _Post_ptr_invalid_)
VOID
FreeUnicodeString(
    _Inout_ PUNICODE_STRING String
);

NTSTATUS
WinhostReadHvParameter(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HvParameter Param,
    _Out_writes_bytes_all_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize
);

NTSTATUS
ParseRegistryMemoryMap(
    _In_ PWCHAR RegKey,
    _In_ PWCHAR RegValue,
    _In_ BYTE MemTypeHint,
    _Out_opt_ QWORD* MemorySize,
    _Inout_ MEM_MAP_ENTRY* PhyMemMap,
    _Inout_ WORD *PhyMemCount
);

#endif // _MISC_UTILS_H_
