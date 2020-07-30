/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"

typedef struct _HV_CODE_SIG
{
    CX_UINT32 Hash;         ///< First 4 bytes from a buffer sent to HvScanBuffer
    CX_UINT32 Verdict;      ///< User-defined data returned by a successful match against this signature entry
    CX_UINT16 Length;       ///< Number of bytes that were covered by the checksum
    CX_UINT64 Checksum;     ///< A simple but fast and safe 64-bit checksum value
}HV_CODE_SIG;

typedef struct _HV_CODE_SIGNATURES
{
    HV_CODE_SIG *Signatures;
    CX_UINT32 NumberOfSignatures;
}HV_CODE_SIG_PACKAGE;



CX_STATUS
HvScanBuffer(
    _In_ HV_CODE_SIG_PACKAGE *SigPackage,
    _In_ CX_VOID *Buffer,
    _In_ CX_UINT32 BufferSize,
    __out_opt CX_UINT32 *Verdict // only set on a successful match
    );
