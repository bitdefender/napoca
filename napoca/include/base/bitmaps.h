/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _BITMAPS_H_
#define _BITMAPS_H_

/** @file bitmaps.h
 * @brief BITMAPS - chained bitmaps interface
 *
 * IMPORTANT: chained bitmaps are NOT thread safe (do NOT use any synch primitives)
*/

#pragma pack(push)
#pragma pack(8)
typedef struct _CHAIN_BITMAP {
    BOOLEAN         Initialized;        ///< TRUE if the bitmap was initialized
    BOOLEAN         Allocated;          ///< TRUE if the bitmap was allocated
    QWORD*          Bitmap;             ///< A pointer to the bitmap itself
    DWORD           LengthInBits;       ///< Total size needed for buffer at Bitmap is ROUND_UP((LengthInBits x 2), 64) / 8 bytes
    volatile DWORD  FreeCount;          ///< Number of free bits (slots)
    volatile DWORD  FirstFreeHint;      ///< Can be used as a hint to the first plausible-to-be-free page
    // statistics counters
    volatile INT32  SuccAlloc;          ///< Number of successful allocations
    volatile INT32  FailedAlloc;        ///< Number of failed allocation attempts
    volatile INT32  SuccFree;           ///< Number of successful free ops
} CHAIN_BITMAP;                         ///< Bitmap data structure definition
#pragma pack(pop)

/**
 * @brief Initialize the basic CHAIN_BITMAP structure fields.
 *
 * At this stage the bitmap itself is not allocated, the Bitmap field in the ChBmp is set to NULL.
 *
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP to be preinitialized
 */
void
CbPreinit(
    _In_ CHAIN_BITMAP* ChBmp
    );

/**
 * @brief   Allocates or sets a custom bitmap area in the CHAIN_BITMAP structure. The bitmap area is memzero'd.
 *
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP to be initialized
 * @param[in]   StaticBitmap                                An optional custom bitmap address for the CHAIN_BITMAP to operate on. If this parameter is null, the bitmap is allocated on the heap.
 * @param[in]   LengthInBits                                The length of the bitmap in bits.
 *
 * @return CX_STATUS_SUCCESS                                Initialization was successful
 * @return CX_STATUS_INVALID_PARAMETER_1                    ChBmp is null
 * @return CX_STATUS_INVALID_PARAMETER_3                    LengthInBits is 0 or a StaticBitmap was provided and LengthInBits is not multiple of QWORD.
 * @return CX_STATUS_ALREADY_INITIALIZED                    The given ChBmp structure is already initialized
 * @return OTHER                                            Internal error
 */
NTSTATUS
CbInit(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_opt_ QWORD* StaticBitmap,
    _In_ DWORD LengthInBits
    );

/**
 * @brief   Frees the bitmap area and clears the data in the given CHAIN_BITMAP structure.
 *
 *  Inverse of CbInit. If the bitmap area was allocated at initialization,
 *  it is freed together with all information stored in the CHAIN_BITMAP structure.
 *
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP structure to be uninitialized
 *
 * @return CX_STATUS_SUCCESS                                Uninitialization was successful
 * @return OTHER                                            Internal error
 */
NTSTATUS
CbUninit(
    _In_ CHAIN_BITMAP* ChBmp
    );

/**
 * @brief   Allocates a bit sequence of dimension NeededBits in the bitmap area of the given CHAIN_BITMAP structure.
 *
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP structure
 * @param[in]   NeededBits                                  Number of bits required
 * @param[out]  StartIndex                                  Index within the bitmap area at which the sequence of bits starts
 *
 * @return CX_STATUS_SUCCESS                                A suitable bit sequence of required size was allocated at index StartIndex
 * @return CX_STATUS_INVALID_PARAMETER_1                    ChBmp is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    NeededBits is 0
 * @return CX_STATUS_INVALID_PARAMETER_3                    StartIndex is null
 * @return CX_STATUS_NOT_INITIALIZED                        The ChBmp structure was not initialized
 * @return CX_STATUS_INSUFFICIENT_RESOURCES                 No suitable bit sequence of required size is available in the bitmap
 */
NTSTATUS
CbAllocRange(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_ DWORD NeededBits,
    _Out_ DWORD *StartIndex
    );

/**
 * @brief   Free a previously allocated bit sequence from the given CHAIN_BITMAP structure.
 *
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP structure
 * @param[in]   StartIndex                                  Start index of the bit sequence to be freed
 *
 * @return CX_STATUS_SUCCESS                                The bit sequence was successfully freed
 * @return CX_STATUS_INVALID_PARAMETER_1                    ChBmp is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The StartIndex is outside of the CHAIN_BITMAP range
 * @return CX_STATUS_NOT_INITIALIZED                        The ChBmp structure was not initialized
 */
NTSTATUS
CbFreeRange(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_ DWORD StartIndex
    );

/**
 * @brief   Dumps the given CHAIN_BITMAP structure.
 *
 * @param[in]   Message                                     An optional message to be displayed at the beginning of the dump.
 * @param[in]   ChBmp                                       Address of the CHAIN_BITMAP structure to be dumped
 *
 * @return CX_STATUS_SUCCESS                                The CHAIN_BITMAP was successfully dumped
 * @return CX_STATUS_INVALID_PARAMETER_2                    ChBmp is null
 * @return CX_STATUS_NOT_INITIALIZED                        The ChBmp structure was not initialized
 */
NTSTATUS
CbDumpBitmap(
    _In_opt_ CHAR* Message,
    _In_ CHAIN_BITMAP* ChBmp
    );

#endif // _BITMAPS_H_