/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __HV_SIMPLECHECKSUM__
#define __HV_SIMPLECHECKSUM__

#include "kernel/kerneldefs.h"

/**
 * @brief Computes a simple checksum on a given buffer. Should not be used for security hashes
 *
 * @param[in] Buffer        Pointer to the buffer on which to perform the checksum
 * @param[in] Size          Size of the memory area on which to perform the checksum
 * @param[in] Start         Starting value for the checksum
 *
 * @returns The checksum
*/
CX_UINT64
HvChecksum64Ex(
    _In_ CX_UINT8* Buffer,
    _In_ CX_UINT64 Size,
    _In_ CX_UINT64 Start
);

/**
 * @brief Wrapper for HvChecksum64Ex
 *
 * @param[in] Buffer        Pointer to the buffer on which to perform the checksum
 * @param[in] Size          Size of the memory area on which to perform the checksum
 *
 * @returns The checksum
*/
CX_UINT64
HvChecksum64(
    _In_ CX_UINT8* Buffer,
    _In_ CX_UINT64 Size
);

#endif