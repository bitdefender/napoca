/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// ILOCKRR - interlocked round-robin indexing support

#ifndef _ILOCKRR_H_
#define _ILOCKRR_H_


typedef struct _ILOCK_RR {
    volatile INT32  Index;
    INT32           Limit;
} ILOCK_RR, *PILOCK_RR;


__forceinline
void
IrrInit(
    _In_ PILOCK_RR  Irr,
    _In_ INT32      Limit
    )
{
    assert(NULL != Irr);

    Irr->Limit = Limit;
    Irr->Index = Limit-1;
}


__forceinline
INT32
IrrGetNext(
    _In_ PILOCK_RR  Irr
    )
{
    register INT32 current;
    register INT32 next;

    assert(NULL != Irr);

    do
    {
        current = Irr->Index;
        next = current + 1;

        if (next >= Irr->Limit)
        {
            next = 0;
        }

    } while (current != _InterlockedCompareExchange((long volatile*)&Irr->Index, next, current));

    return next;
}


#endif // _ILOCKRR_H_