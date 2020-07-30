/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRC32_H_
#define _CRC32_H_

DWORD
Crc32(
    _In_ DWORD ContinuationValue,
    _In_ VOID* Buffer,
    _In_ QWORD BufferSize
);

#endif // _CRC32_H_