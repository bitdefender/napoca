/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef CRT_INC_SETTINGS_WRAPPER_CRT_MEMORY_C
#include CRT_INC_SETTINGS_WRAPPER_CRT_MEMORY_C // define it to some .h file name/path if you want to provide settings
#endif


#include "crt/crt_crt.h"
#include "base/cx_env.h"
#include "crt/crt_memory.h"

#ifdef CX_MSVC
// those are the non-intrinsic fallback functions
#ifdef CX_RELEASE_BUILD
#pragma function(memcpy, memcmp, memset)
#endif
#endif

#if ( !defined(CRT_SKIP_DEF_MEMCPY) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_MEMORY_C_DEF) || defined(CRT_WANT_DEF_MEMCPY))  )
CX_VOID* __cdecl
memcpy(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
)
{
    return crt_memcpy(Dest, Source, Size);
}
#endif


#if ( !defined(CRT_SKIP_DEF_MEMCMP) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_MEMORY_C_DEF) || defined(CRT_WANT_DEF_MEMCMP))  )
CX_INT32 __cdecl
memcmp(
    __in_bcount_opt(Size) const CX_VOID *Source1,
    __in_bcount_opt(Size) const CX_VOID *Source2,
    _In_ CX_SIZE_T Size
)
{
    return crt_memcmp(Source1, Source2, Size);
}
#endif


#if ( !defined(CRT_SKIP_DEF_MEMSET) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_MEMORY_C_DEF) || defined(CRT_WANT_DEF_MEMSET))  )
#ifdef CX_GNUC
__attribute__((optimize(2)))
#endif
CX_VOID* __cdecl
memset(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_INT32 Value,
    _In_ CX_SIZE_T Size
)
{
    return crt_memset(Dest, Value, Size);
}
#endif

#if ( !defined(CRT_SKIP_DEF_MEMCPY_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_MEMORY_C_DEF) || defined(CRT_WANT_DEF_MEMCPY_S))  )
CX_VOID* __cdecl
memcpy_s(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T SizeInBytes,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size)
{
    return crt_memcpy_s(Dest, SizeInBytes, Source, Size);
}
#endif


#if ( !defined(CRT_SKIP_DEF_MEMZERO) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_MEMORY_C_DEF) || defined(CRT_WANT_DEF_MEMZERO))  )
CX_VOID* __cdecl
memzero(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
)
{
    return crt_memzero(Dest, Size);
}
#endif


