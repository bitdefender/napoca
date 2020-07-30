/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _STACKDUMP_H_
#define _STACKDUMP_H_

#include "base/cx_defs.h"
#include "base/cx_types.h"

#define DVTC_BLOB_PREFIX                    "$$$stack$$$"
#define DVTC_BLOB_MAGIC_HEXENCODED          "DVTC_HEX"
#define DVTC_BLOB_SUFFIX                    "###stack###"

//
// basic BLOB structures and definitions
//
#define DVTC_BLOB_TYPE_STACKWALK            0x00000001
#define DVTC_BLOB_TYPE_DUMPTYPE             0x00000002

//
// flags that can be used with DVTC_BLOB_TYPE_STACKWALK
//
#define DVTC_FLAG_STACKWALK_BASIC_INFO          0x00000001  // windbg k-like stack dump
#define DVTC_FLAG_STACKWALK_PARAM_INFO          0x00000002  // windbg kv-like stack dump
#define DVTC_FLAG_STACKWALK_LOCAL_INFO          0x00000004  // windbg kv-like stack dump + locals for each function

#pragma pack(push)
#pragma pack(1)

#pragma warning(push)
#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union

typedef struct _DVTC_BLOB_HEADER
{
    CX_UINT32       BlobSize;               // in bytes, including this header + suffix & prefix
    CX_UINT32       Type;                   // DVTC_BLOB_TYPE_xxx
} DVTC_BLOB_HEADER;

typedef struct _DVTC_BLOB_STACKWALK
{
    DVTC_BLOB_HEADER        Header;
    CX_UINT64               CpuBootIndex;
    CX_UINT64               Rsp;
    CX_UINT64               Rip;
    CX_UINT64               Rdi;
    CX_UINT32               Flags;
    CX_UINT32               RawStackLength; // in bytes
    CX_UINT8                RawStack[];
} DVTC_BLOB_STACKWALK;

#define DVTC_BLOB_NEEDED_SIZE_HEXENCODED(StructType, PayloadLength)                             \
            ((sizeof(DVTC_BLOB_PREFIX) - 1) + (sizeof(DVTC_BLOB_MAGIC_HEXENCODED) - 1) +        \
             (sizeof(StructType) + (PayloadLength)) * 2 + (sizeof(DVTC_BLOB_SUFFIX) - 1))

#pragma warning(pop)
#pragma pack(pop)

#endif
