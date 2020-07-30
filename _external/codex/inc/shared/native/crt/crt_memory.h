/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_MEMORY_H_
#define _CRT_MEMORY_H_
#include "cx_native.h"


CX_VOID* __cdecl
crt_memcpy(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size);

CX_INT32 __cdecl
crt_memcmp(
    __in_bcount_opt(Size) const CX_VOID *Source1,
    __in_bcount_opt(Size) const CX_VOID *Source2,
    _In_ CX_SIZE_T Size);

CX_VOID* __cdecl
crt_memset(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_INT32 Value,
    _In_ CX_SIZE_T Size);

CX_VOID* __cdecl
crt_memcpy_s(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T SizeInBytes,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size);

CX_VOID* __cdecl
crt_memzero(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size);


#endif // _CRT_MEMORY_H_
