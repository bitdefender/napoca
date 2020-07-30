/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// IDVECTOR - lockless unique ID selection vector

#ifndef _IDVECTOR_
#define _IDVECTOR_

#include "napoca.h"
#define MAX_IDV_COUNT           10000

typedef volatile PVOID IDV_ITEM;
typedef IDV_ITEM ID_VECTOR, *PID_VECTOR;

#pragma pack(push)
#pragma pack(1)
typedef union _ID_VECTOR_HEAD {
    struct {
        volatile INT16      MaxCount;
        volatile INT16      FreeCount;
    };
    IDV_ITEM        Items;
} ID_VECTOR_HEAD, *PID_VECTOR_HEAD;
#pragma pack(pop)

//
// IMPORTANT: an IDV always has N+1 items, the first item, with index 0 beeing used to store
// MaxCount and FreeCount; an IDV can't hold more than 10,000 items!
//
// to decleare an IDV one needs simply to do like 'ID_VECTOR myVector[101] = {0};', for ex to
// have an 100 usable item vector, then do IdvInit(myVector, 101)
//


//
// prototypes
//
NTSTATUS
IdvInit(
    _Inout_ PID_VECTOR Vector,
    _In_ INT16 MaxCountPlusOne
    );

NTSTATUS
IdvAllocId(
    _Inout_ PID_VECTOR Vector,
    _In_ PVOID Item,
    _Out_ INT16 *Id
    );

NTSTATUS
IdvFreeAndNullId(
    _Inout_ PID_VECTOR Vector,
    _Inout_ INT16 *Id
    );

#endif // _IDVECTOR_