/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_CONV_H_
#define _CRT_CONV_H_

CX_INT32 __cdecl 
crt_strtol(
    _In_z_ const CX_INT8 *nptr, 
    __out_opt CX_INT8 **endptr, 
    _In_ CX_INT32 ibase );

CX_UINT32 __cdecl
crt_strtoul(
    _In_z_ const CX_INT8 *nptr, 
    __out_opt CX_INT8 **endptr, 
    _In_ CX_INT32 ibase );

CX_INT64 __cdecl 
crt_strtoll(
    _In_z_ const CX_INT8 *nptr, 
    __out_opt CX_INT8 **endptr, 
    _In_ CX_INT32 ibase );

CX_UINT64 __cdecl
crt_strtoull(
    _In_z_ const CX_INT8 *nptr, 
    __out_opt CX_INT8 **endptr, 
    _In_ CX_INT32 ibase );

#define crt_strtoq crt_strtoull

#endif // _CRT_CONV_H_
