/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/simplechecksum.h"

CX_UINT64
HvChecksum64Ex(
    _In_ CX_UINT8 *Buffer,
    _In_ CX_UINT64 Size,
    _In_ CX_UINT64 Start
)
{
    CX_UINT64 hash = Start;

    while (Size--)
        hash = (hash * 33) + *Buffer++;

    return hash + (hash >> 5);
}

CX_UINT64
HvChecksum64(
    _In_ CX_UINT8 *Buffer,
    _In_ CX_UINT64 Size
)
{
    return HvChecksum64Ex(Buffer, Size, 0);
}