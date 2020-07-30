/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file bitmaps.c
 * @brief BITMAPS - implementation for the bitmaps.h interface
*/

#include "napoca.h"
#include "base/bitmaps.h"
#include "memory/heap.h"


void
CbPreinit(
    _In_ CHAIN_BITMAP* ChBmp
    )
{
    assert(ChBmp != NULL);

    ChBmp->Initialized = FALSE;
    ChBmp->Allocated = FALSE;
    ChBmp->Bitmap = NULL;
    ChBmp->LengthInBits = 0;
    ChBmp->FreeCount = 0;
    ChBmp->FirstFreeHint = 0;
}


NTSTATUS
CbInit(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_opt_ QWORD* StaticBitmap,
    _In_ DWORD LengthInBits
    )
{
    NTSTATUS status;
    DWORD lengthInBytes;

    if (ChBmp == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (LengthInBits == 0) return CX_STATUS_INVALID_PARAMETER_3;
    if (ChBmp->Initialized) return CX_STATUS_ALREADY_INITIALIZED;

    assert(ChBmp->Bitmap == NULL);

    // determine how much bytes we need to store all bits; round up to multiple-of-QWORDs
    lengthInBytes = ROUND_UP((2 * LengthInBits), 64);

    if (StaticBitmap != NULL)
    {
        // for static bitmaps 2*LengthInBits MUST be multiple of 64 (QWORD)
        if ((2 * LengthInBits) != ROUND_UP((2 * LengthInBits), 64)) return CX_STATUS_INVALID_PARAMETER_3;

        ChBmp->Bitmap = StaticBitmap;
        ChBmp->Allocated = FALSE;
    }
    else
    {
        status = HpAllocWithTag(&ChBmp->Bitmap, lengthInBytes, TAG_BMP);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTag", status);
            goto cleanup;
        }
        ChBmp->Allocated = TRUE;
    }

    assert(ChBmp->Bitmap != NULL);

    // we need to zero-down all bits
    memzero(ChBmp->Bitmap, lengthInBytes);

    ChBmp->LengthInBits = LengthInBits;
    ChBmp->FreeCount = ChBmp->LengthInBits;
    ChBmp->FirstFreeHint = 0;

    ChBmp->SuccAlloc = 0;
    ChBmp->FailedAlloc = 0;
    ChBmp->SuccFree = 0;

    ChBmp->Initialized = TRUE;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
CbUninit(
    _In_ CHAIN_BITMAP* ChBmp
    )
{
    NTSTATUS status;

    if (ChBmp == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (!ChBmp->Initialized) return CX_STATUS_NOT_INITIALIZED_HINT;

    ChBmp->Initialized = FALSE;
    ChBmp->LengthInBits = 0;
    ChBmp->FreeCount = 0;
    ChBmp->FirstFreeHint = 0;

    if (ChBmp->Allocated)
    {
        status = HpFreeAndNullWithTag(&ChBmp->Bitmap, TAG_BMP);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpFreeAndNullWithTag", status);
            goto cleanup;
        }
        ChBmp->Allocated = FALSE;
    }
    else ChBmp->Bitmap = NULL;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
CbAllocRange(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_ DWORD NeededBits,
    _Out_ DWORD *StartIndex
    )
{
    NTSTATUS status;
    DWORD index, k;
    BOOLEAN isFree;

    if (ChBmp == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (!ChBmp->Initialized) return CX_STATUS_NOT_INITIALIZED;
    if (NeededBits == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (StartIndex == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    // just a gross check, because this doesn't ensure we really have sufficient non-fragmented bits to acquire
    if (NeededBits > ChBmp->FreeCount)
    {
        ChBmp->FailedAlloc++;
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    // lookup a range of free bits, using First-Fit matching
    index = ChBmp->FirstFreeHint;
    isFree = FALSE;

    while (!isFree && (index < ChBmp->LengthInBits - NeededBits + 1))
    {
        isFree = TRUE;

        for (k = 0; k < NeededBits; k++)
        {
            QWORD qwIdx, bitIdx;

            // get qword and bit index; note, we have a 2* because we use 2 bits for every slot
            qwIdx = ((2*(index + k)) >> 6);         // div 64
            bitIdx = ((2*(index + k)) & 0x3f);      // mod 64

            if ((ChBmp->Bitmap[qwIdx] & BIT_AT(bitIdx)) != 0)
            {
                isFree = FALSE;
                index = index + k + 1;
                break;
            }
        }
    }

    if (!isFree)
    {
        ChBmp->FailedAlloc++;
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    // bingo, we have NeededBits free for allocation starting at index; mark range as used
    for (k = 0; k < NeededBits; k++)
    {
        QWORD qwIdx, bitIdx, tmp;

        // get qword and bit index; note, we have a 2* because we use 2 bits for every slot
        qwIdx = ((2*(index + k)) >> 6);         // div 64
        bitIdx = ((2*(index + k)) & 0x3f);      // mod 64

        tmp = ChBmp->Bitmap[qwIdx];
        tmp = tmp | BIT_AT(bitIdx);             // set the first bit to 1 - mark slot as allocated
        if (k < NeededBits-1) tmp = tmp | BIT_AT(bitIdx + 1);     // set the second bit to 1 - mark slot as chained
        else tmp = tmp & ~BIT_AT(bitIdx + 1);                     // set the second bit to 0 - mark slot as NOT-chained (last entry from chain)

        ChBmp->Bitmap[qwIdx] = tmp;
    }

    ChBmp->FreeCount -= NeededBits;
    ChBmp->SuccAlloc++;

    // update FirstFreeHint and ensure it points always to the first free bit
    if (index == ChBmp->FirstFreeHint)
    {
        QWORD qwIdx, bitIdx;

        ChBmp->FirstFreeHint = ChBmp->FirstFreeHint + NeededBits;

        // if the new hint doesn't point to a free bit ==> search for a new free one
        // or until we reach the end of the bitmap (might be sub-optimal, but it is safe)
        while (ChBmp->FirstFreeHint < ChBmp->LengthInBits)
        {
            // get qword and bit index; note, we have a 2* because we use 2 bits for every slot
            qwIdx = ((2*(ChBmp->FirstFreeHint)) >> 6);          // div 64
            bitIdx = ((2*(ChBmp->FirstFreeHint)) & 0x3f);       // mod 64

            // TODO: to optimize this, we could do lookups one-QWORD-at-a-time

            if ((ChBmp->Bitmap[qwIdx] & BIT_AT(bitIdx)) != 0) break;

            ChBmp->FirstFreeHint++;
        }
    }

    *StartIndex = index;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
CbFreeRange(
    _In_ CHAIN_BITMAP* ChBmp,
    _In_ DWORD StartIndex
    )
{
    DWORD index;

    if (ChBmp == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (!ChBmp->Initialized) return CX_STATUS_NOT_INITIALIZED;
    if (StartIndex >= ChBmp->LengthInBits) return CX_STATUS_INVALID_PARAMETER_2;

    // free all chained slots starting from StartIndex
    index = StartIndex;
    while (index < ChBmp->LengthInBits)
    {
        QWORD qwIdx, bitIdx, tmp;

        // get qword and bit index; note, we have a 2* because we use 2 bits for every slot
        qwIdx = ((2*index) >> 6);           // div 64
        bitIdx = ((2*index) & 0x3f);        // mod 64

        tmp = ChBmp->Bitmap[qwIdx];
        tmp = tmp & ~BIT_AT(bitIdx);       // set the first bit to 0 - mark slot as free
        ChBmp->Bitmap[qwIdx] = tmp;

        ChBmp->FreeCount++;

        // is the next slot is not chained, stop
        if ((tmp & BIT_AT(bitIdx + 1)) == 0) break;

        index++;
    }

    ChBmp->SuccFree++;

    // update FirstFreeHint
    if (StartIndex < ChBmp->FirstFreeHint) ChBmp->FirstFreeHint = StartIndex;

    // everything done just fine
    return CX_STATUS_SUCCESS;
}


NTSTATUS
CbDumpBitmap(
    _In_opt_ CHAR* Message,
    _In_ CHAIN_BITMAP* ChBmp
    )
{
    DWORD lengthInBytes;
    DWORD bitsProcessed;
    CHAR buffer[66];

    if (ChBmp == NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if (!ChBmp->Initialized) return CX_STATUS_NOT_INITIALIZED;

    if (Message != NULL) LOGN("dumping bitmap%s\n", Message);

    LOGN("LengthInBits %d  /  FreeCount %d  /  SuccAlloc %d  /  FailedAlloc %d  /  SuccFree %d  /  FirstFreeHint %d\n",
        ChBmp->LengthInBits, ChBmp->FreeCount, ChBmp->SuccAlloc, ChBmp->FailedAlloc, ChBmp->SuccFree, ChBmp->FirstFreeHint);

    lengthInBytes = ROUND_UP((2 * ChBmp->LengthInBits), 64);
    bitsProcessed = 0;

    for (DWORD i = 0; i < (lengthInBytes >> 3); i++)
    {
        QWORD t;

        t = ChBmp->Bitmap[i];
        buffer[64] = 0;
        buffer[65] = 0;

        for (DWORD k = 0; k < 64; k++)
        {
            buffer[k] = ((t & BIT_AT(k)) != 0) ? '1' : '0';

            if ((++bitsProcessed) >= (2 * ChBmp->LengthInBits))
            {
                buffer[k+1] = 0;
                break;
            }
        }

        if (bitsProcessed < (2 * ChBmp->LengthInBits)) buffer[64] = '`';

        LOGN(buffer);
    }

    LOGN("\n");

    return CX_STATUS_SUCCESS;
}
