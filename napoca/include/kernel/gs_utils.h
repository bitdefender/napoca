/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once

/**
 * @brief Moves the old stack security cookie structure in a new stack location
 *
 * @param[in] OldStackTop                   Pointer to the buffer on which to perform the checksum
 * @param[in] NewStackTop                   Size of the memory area on which to perform the checksum
 * @param[in] StackSize                     Offset within the buffer
 *
 * @returns CX_STATUS_SUCCESS               If the stack was moved successfully
 * @returns STATUS_GS_INVALID_OLD_STACK     If the old stack address is invalid
 * @returns STATUS_GS_INVALID_NEW_STACK     If the new stack address is invalid
 * @returns STATUS_GS_INEQUAL_STACK_OFFSETS If the two stacks have different offsets
*/
CX_STATUS
GsUtilsNotifyStackChange(
    _In_ _Inout_updates_bytes_(StackSize)
          CX_VOID      *OldStackTop,
    _In_ _Inout_updates_bytes_(StackSize)
          CX_VOID      *NewStackTop,
    _In_  CX_UINT64       StackSize
);
