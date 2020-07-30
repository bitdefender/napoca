/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "crt/crt_crt.h"
#include "base/cx_env.h"
#include "base/cx_mem.h"
#include "crt/crt_memory.h"

/// Note: this file assumes defined CX_USE_SSE2 or CX_USE_MMX for optimized versions of provided functions!

CX_VOID* __cdecl
crt_memcpy(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
)
{
    CX_VOID *ret = Dest;

    crt_assert(CX_NULL != Dest);
    crt_assert(CX_NULL != Source);

    if ((CX_NULL == Dest) || (CX_NULL == Source))
    {
        return CX_NULL;        // On release crt_assert doesn't build
    }

    CxMemCopyFast(Dest, Source, Size);
    return(ret);
}

CX_INT32 __cdecl
crt_memcmp(
    __in_bcount_opt(Size) const CX_VOID *Source1,
    __in_bcount_opt(Size) const CX_VOID *Source2,
    _In_ CX_SIZE_T Size
)
{
    crt_assert(CX_NULL != Source1);
    crt_assert(CX_NULL != Source2);
    crt_assert(Size > 0);

    if ((CX_NULL == Source1) || (CX_NULL == Source2) || (Size <= 0))
    {
        return 0;           // There's no better return value, even if 0 might be confusing.
                            // We must return a value for release builds, because crt_assert builds only for debug.
    }

    return (CX_INT32) CxMemCompareFast(Source1, Source2, Size);
}

#ifdef CX_GNUC
__attribute__((optimize(2)))
#endif
CX_VOID* __cdecl
crt_memset(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_INT32 Value,
    _In_ CX_SIZE_T Size
)
{
    CX_VOID *start = Dest;

    crt_assert(CX_NULL != Dest);

    if (CX_NULL == Dest)
    {
        return CX_NULL;
    }

    CxMemSet8Fast(Dest, Size, (CX_UINT8)Value);
    return(start);
}

CX_VOID* __cdecl
crt_memcpy_s(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T SizeInBytes,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size)
{
    if (0 == Size)
    {
        return CX_NULL;
    }

    if ((CX_NULL == Source) || (SizeInBytes < Size))
    {
        crt_memzero(Dest, Size);
        return CX_NULL;
    }

    crt_memcpy(Dest, Source, Size);

    return Dest;
}

CX_VOID* __cdecl
crt_memzero(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
)
{
#if defined(CX_DEBUG_BUILD) && defined(CX_MSVC)
    CX_VOID *start = Dest;

    crt_assert(CX_NULL != Dest);

    if (CX_NULL == Dest)
    {
        return CX_NULL;
    }

    CxMemZeroFast(Dest, Size);
    return(start);
#else
    // this is faster on release builds, uses intrinsic
    return crt_memset(Dest, 0, Size);
#endif
}


