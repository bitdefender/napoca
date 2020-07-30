/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_MSVC_MEM_H_
#include "base/cx_env.h"
#include "base/cx_sal.h"
#include "base/cx_types.h"

/// Note: this file assumes defined CX_USE_SSE2 or CX_USE_MMX for optimized versions of provided functions!

#ifdef CX_ARCH32

//
// Ia32-specific function declarations
//
CX_VOID*
__cdecl
CxMemCopyBasic32(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemCopyMmx32(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemCopySse232(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_SSIZE_T
__cdecl
CxMemCompareBasic32(
    _In_reads_bytes_(Length) const CX_VOID *DestinationBuffer,
    _In_reads_bytes_(Length) const CX_VOID  *SourceBuffer,
    _In_ CX_SIZE_T Length
);

CX_VOID*
__cdecl
CxMemSet8Basic32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet8Mmx32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet8Sse232(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet16Basic32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet16Mmx32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet16Sse232(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet32Basic32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet32Mmx32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet32Sse232(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet64Basic32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemSet64Mmx32(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemSet64Sse232(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemZeroBasic32(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemZeroMmx32(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemZeroSse232(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

//
// Define the actual used functions based on what hardware is available
//
#define CxMemCompareFast CxMemCompareBasic32
#ifdef CX_USE_SSE2
#define CxMemCopyFast CxMemCopySse232
#define CxMemSet8Fast CxMemSet8Sse232
#define CxMemSet16Fast CxMemSet16Sse232
#define CxMemSet32Fast CxMemSet32Sse232
#define CxMemSet64Fast CxMemSet64Sse232
#define CxMemZeroFast CxMemZeroSse232
#else
#ifdef CX_USE_MMX
#define CxMemCopyFast CxMemCopyMmx32
#define CxMemSet8Fast CxMemSet8Mmx32
#define CxMemSet16Fast CxMemSet16Mmx32
#define CxMemSet32Fast CxMemSet32Mmx32
#define CxMemSet64Fast CxMemSet64Mmx32
#define CxMemZeroFast CxMemZeroMmx32
#else
#define CxMemCopyFast CxMemCopyBasic32
#define CxMemSet8Fast CxMemSet8Basic32
#define CxMemSet16Fast CxMemSet16Basic32
#define CxMemSet32Fast CxMemSet32Basic32
#define CxMemSet64Fast CxMemSet64Basic32
#define CxMemZeroFast CxMemZeroBasic32
#endif // CX_USE_MMX
#endif // CX_USE_SSE2
#endif // CX_ARCH32


#ifdef CX_ARCH64

//
// X64-specific function declarations
//

CX_VOID*
__cdecl
CxMemCopyBasic64(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemCopyMmx64(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemCopySse264(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_reads_bytes_(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

CX_SSIZE_T
__cdecl
CxMemCompareBasic64(
    _In_reads_bytes_(Length) const CX_VOID *DestinationBuffer,
    _In_reads_bytes_(Length) const CX_VOID  *SourceBuffer,
    _In_ CX_SIZE_T Length
);

CX_VOID*
__cdecl
CxMemSet8Basic64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet8Mmx64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet8Sse264(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT8 Value
);

CX_VOID*
__cdecl
CxMemSet16Basic64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet16Mmx64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet16Sse264(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT16 Value
);

CX_VOID*
__cdecl
CxMemSet32Basic64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet32Mmx64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet32Sse264(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT32 Value
);

CX_VOID*
__cdecl
CxMemSet64Basic64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemSet64Mmx64(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemSet64Sse264(
    _Out_writes_bytes_all_(Length) CX_VOID *Buffer,
    _In_ CX_SIZE_T Length,
    _In_ CX_UINT64 Value
);

CX_VOID*
__cdecl
CxMemZeroBasic64(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemZeroMmx64(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

CX_VOID*
__cdecl
CxMemZeroSse264(
    _Out_writes_bytes_all_(Size) CX_VOID *Dest,
    _In_ CX_SIZE_T Size
);

//
// Define the actual used functions based on what hardware is available
//
#define CxMemCompareFast CxMemCompareBasic64
#ifdef CX_USE_SSE2
#define CxMemCopyFast CxMemCopySse264
#define CxMemSet8Fast CxMemSet8Sse264
#define CxMemSet16Fast CxMemSet16Sse264
#define CxMemSet32Fast CxMemSet32Sse264
#define CxMemSet64Fast CxMemSet64Sse264
#define CxMemZeroFast CxMemZeroSse264
#else
#ifdef CX_USE_MMX
#define CxMemCopyFast CxMemCopyMmx64
#define CxMemSet8Fast CxMemSet8Mmx64
#define CxMemSet16Fast CxMemSet16Mmx64
#define CxMemSet32Fast CxMemSet32Mmx64
#define CxMemSet64Fast CxMemSet64Mmx64
#define CxMemZeroFast CxMemZeroMmx64
#else
#define CxMemCopyFast CxMemCopyBasic64
#define CxMemSet8Fast CxMemSet8Basic64
#define CxMemSet16Fast CxMemSet16Basic64
#define CxMemSet32Fast CxMemSet32Basic64
#define CxMemSet64Fast CxMemSet64Basic64
#define CxMemZeroFast CxMemZeroBasic64
#endif // CX_USE_MMX
#endif // CX_USE_SSE2
#endif // CX_ARCH64


#endif // _CX_MSVC_MEM_H_

