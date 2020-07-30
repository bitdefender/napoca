/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_VARARGS_H_
#define _CRT_VARARGS_H_
#include "cx_native.h"

typedef CX_INT8 *  crt_va_list;

#ifdef  __cplusplus
#define _CRT_ADDRESSOF(v)           ( &reinterpret_cast<const CX_INT8 &>(v) )
#else
#define _CRT_ADDRESSOF(v)           ( &(v) )
#endif

#if defined(CX_ARCH64)

// the __crt_va_start is exported by the compiler, but with different names

#ifdef CX_GNUC
#define __crt_va_start __builtin_va_start
#else
#ifdef CX_CLANG
#define __crt_va_start __builtin_va_start
#else
#ifdef CX_MSVC
#define __crt_va_start __va_start
extern CX_VOID __cdecl __va_start(_Out_ crt_va_list *, ...);       // is this exported by VC compiler?
#endif
#endif
#endif

#define _crt_va_start(ap, x)    ( __crt_va_start(&ap, x) )
#define _crt_va_arg(ap, t)      ( ( sizeof(t) > sizeof(CX_INT64) || ( sizeof(t) & (sizeof(t) - 1) ) != 0 ) \
                                    ? **(t **)( ( ap += sizeof(CX_INT64) ) - sizeof(CX_INT64) ) \
                                    :  *(t  *)( ( ap += sizeof(CX_INT64) ) - sizeof(CX_INT64) ) )
#define _crt_va_end(ap)         ( ap = (crt_va_list)0 )

#else

// a guess at the proper definitions for other platforms

#define _CRT_INTSIZEOF(n)           ( (sizeof(n) + sizeof(CX_INT32) - 1) & ~(sizeof(CX_INT32) - 1) )

#define _crt_va_start(ap,v)     ( ap = (crt_va_list)_CRT_ADDRESSOF(v) + _CRT_INTSIZEOF(v) )
#define _crt_va_arg(ap,t)       ( *(t *)((ap += _CRT_INTSIZEOF(t)) - _CRT_INTSIZEOF(t)) )
#define _crt_va_end(ap)         ( ap = (crt_va_list)0 )

#endif

#define crt_va_start _crt_va_start
#define crt_va_arg _crt_va_arg
#define crt_va_end _crt_va_end

#endif // _CRT_VARARGS_H_

