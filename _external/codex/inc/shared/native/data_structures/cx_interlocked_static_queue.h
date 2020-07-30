/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Offers a CX_QUEUE_INTERFACE as an interlocked statically (pre) allocated queue, 
// implemented as a circular buffer / ring buffer
//
#ifndef _CX_INTERLOCKED_STATIC_QUEUE_H_
#define _CX_INTERLOCKED_STATIC_QUEUE_H_

#include "cx_native.h"
#include "base/cx_synchronization.h"

#include "interfaces/data_structures/cx_addremove_interface.h"
#include "interfaces/data_structures/cx_queue_interface.h"

#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
typedef union
{
    // pack the relevant fields into a UINT64 bitfield to support interlocked operations
    volatile CX_UINT64                  Raw;
    struct
    {
        volatile CX_UINT64              NumberOfPopulatedEntries : 21; // 2^21 = 2 mega entries
        volatile CX_UINT64              Head : 21;
        volatile CX_UINT64              Tail : 21;
        volatile CX_UINT64              _reserved : 1; // 21 * 3 = 63 bits
    }BitField;
}CX_INTERLOCKED_STATIC_QUEUE_CONTROL_DATA;
#pragma warning(pop)


typedef struct _CX_INTERLOCKED_STATIC_QUEUE_DATA
{
    CX_QUEUE_INTERFACE                  Interface;
    CX_UINT64                           *QueueBuffer;
    CX_INTERLOCKED_STATIC_QUEUE_CONTROL_DATA ControlData;
    CX_UINT32                           NumberOfEntries;
    CX_ONCE_INIT0                       Initialized;
}CX_INTERLOCKED_STATIC_QUEUE_DATA;


CX_STATUS
CxInterlockedStaticQueueInit(
    _Out_ CX_INTERLOCKED_STATIC_QUEUE_DATA *LocklessStaticQueue,    // you must allocate such an item and this function will initialize it
    _In_ PCX_VOID                       QueueBuffer,                // your data buffer for the table
    _In_ CX_UINT32                      QueueBufferSizeInBytes,
    __out_opt CX_QUEUE_INTERFACE        **Queue                     // receive a generic queue 'object'
    );



// a macro for correctly finding out how much memory such a queue requires
#define CX_INTERLOCKED_STATIC_QUEUE_BUFFER_SIZE(NumberOfElements) (sizeof(CX_UINT64) * (NumberOfElements))

#endif // _CX_INTERLOCKED_STATIC_QUEUE_H_
