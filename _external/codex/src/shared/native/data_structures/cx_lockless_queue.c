/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "cx_native.h"
#include "base/cx_synchronization.h"
#include "crt/crt_memory.h"
#include "data_structures/cx_lockless_queue.h"


//                  Pivot->| > > > > > Occupied Shifting Right > > > > > > >
//          +--------------+--------------+-----------------+--------------+--------------+
//          |              |              |                 |              |              |
//          |     Free     |   Outgoing   |     Waiting     |   Incoming   |     Free     |
//          |              |              |                 |              |              |
//          +--------------+--------------+-----------------+--------------+--------------+
//                                       <|REM|                           <|ADD|
//          
//          New elements enter Waiting through Incoming
//          Existing elements leave Waiting through Outgoing
//          Waiting (with O & I) keeps shifting right and wraps around and so does the Pivot
//          Passings from Incoming to Waiting and from Outgoing to Free are serialized

CX_STATUS
CxLlQueueInitialize(
    _Out_ CX_LLQUEUE *Queue,
    _In_  CX_UINT32 ElementCount,
    _In_  CX_UINT32 ElementSize,
    _In_  CX_VOID *StorageBuffer,
    _In_  CX_UINT32 BufferSize
)
{
    // If the buffer cannot accommodate the maximum number of elements, return an error
    if (BufferSize < CX_LLQUEUE_STORAGE_REQUREMENT(ElementCount, ElementSize)) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    // Set initial queue state
    Queue->NumberOfElements = ElementCount;
    Queue->ElementSize = ElementSize;
    Queue->Position.Raw = 0;
    Queue->QueueData = (CX_UINT8 *)StorageBuffer;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
CxLlQueueAdd(
    _In_ CX_LLQUEUE *Queue,
    _In_ CX_VOID *Data,
    _In_ CX_UINT32 DataSize,
    _In_ CX_BOOL8 Blocking
)
{
    CX_LLQUEUE_POSITION oldPos;
    CX_LLQUEUE_POSITION newPos;
    CX_UINT64 relPos;
    CX_UINT64 absPos;

    // If the given element is not of default queue size, return an error
    if (DataSize != Queue->ElementSize) return CX_STATUS_INVALID_DATA_SIZE;

    for (;;)
    {
        // Get the current queue position
        oldPos.Raw = newPos.Raw = Queue->Position.Raw;

        // Compute the index of the last element from the incoming part of the queue, there we will want to insert the new element
        relPos = (CX_UINT64)oldPos.Outgoing + oldPos.Waiting + oldPos.Incoming;

        // If the queue is full, depending on the Blocking value either wait for the queue to have more space for insertion or return an error
        if (relPos >= Queue->NumberOfElements)
            if (Blocking) continue;
            else return CX_STATUS_OUT_OF_RESOURCES;

        // Try securing space in the incoming part of the queue for the element to be copied in.
        newPos.Incoming++;

        // Try committing the secured space in the queue. If this doesn't succeed due to other
        // cpus enqueueing their elements first, try repeating the algorithm. If successfully commited, proceed copying the element into the queue.
        if (oldPos.Raw == CxInterlockedCompareExchange64(&Queue->Position.Raw, newPos.Raw, oldPos.Raw))
            break;
    }

    // Compute the absolute location in the queue buffer
    absPos = (oldPos.Pivot + relPos) % Queue->NumberOfElements;

    // Copy the element from the given data into the queue
    crt_memcpy(&Queue->QueueData[absPos * Queue->ElementSize], Data, Queue->ElementSize);

    // Serialization: make sure everything that WAS Incoming WHEN AQUIRING a cell already passed to Waiting (doesn't matter if other new stuff is Incoming)
    do
    {
        oldPos.Raw = Queue->Position.Raw;

    } while ((oldPos.Pivot + oldPos.Outgoing + oldPos.Waiting) % Queue->NumberOfElements != absPos);

    // Move the element into the waiting area of the queue
    do
    {
        oldPos.Raw = newPos.Raw = Queue->Position.Raw;

        newPos.Incoming--;
        newPos.Waiting++;

    } while (oldPos.Raw != CxInterlockedCompareExchange64(&Queue->Position.Raw, newPos.Raw, oldPos.Raw));

    return CX_STATUS_SUCCESS;
}

CX_STATUS
CxLlQueueRemove(
    _In_  CX_LLQUEUE *Queue,
    _Out_ CX_VOID *Data,
    _In_  CX_UINT32 DataSize,
    _In_  CX_BOOL8 Blocking
)
{
    CX_LLQUEUE_POSITION oldPos;
    CX_LLQUEUE_POSITION newPos;
    CX_UINT64 relPos;
    CX_UINT64 absPos;

    // If the buffer for copying the dqueue data is too small, return an error
    if (DataSize < Queue->ElementSize) return CX_STATUS_INVALID_DATA_SIZE;

    for (;;)
    {
        // Get the current queue position
        oldPos.Raw = newPos.Raw = Queue->Position.Raw;

        // If the queue is empty, depending on the Blocking parameter value, either return an error or retry until an element is available
        if (oldPos.Waiting == 0)
            if (Blocking) continue;
            else return CX_STATUS_DATA_NOT_READY;

        // Move the queue element index in the outgoing part of the queue to mark the dequeueing
        newPos.Waiting--;
        newPos.Outgoing++;

        // Try committing the modification in order to ensure the element is acknowledged as dequeued.
        // If it doesn't succeed due to other threads dequeueing the element first, retry. Otherwise proceed copying the element data into the given buffer.
        if (oldPos.Raw == CxInterlockedCompareExchange64(&Queue->Position.Raw, newPos.Raw, oldPos.Raw))
            break;
    }

    // Compute the absolute location in the queue buffer
    relPos = oldPos.Outgoing;
    absPos = (oldPos.Pivot + relPos) % Queue->NumberOfElements;
    // Copy the element from the decoded address to the buffer
    crt_memcpy(Data, &Queue->QueueData[absPos * Queue->ElementSize], Queue->ElementSize);

    // Serialization: make sure everything that WAS Outgoing WHEN AQUIRING a cell already passed by Pivot (doesn't matter if other new stuff is Outgoing)
    while (Queue->Position.Pivot != absPos);

    // Free the element from the outgoing area
    do
    {
        oldPos.Raw = newPos.Raw = Queue->Position.Raw;

        newPos.Outgoing--;
        newPos.Pivot = (newPos.Pivot + 1) % Queue->NumberOfElements;

    } while (oldPos.Raw != CxInterlockedCompareExchange64(&Queue->Position.Raw, newPos.Raw, oldPos.Raw));

    return CX_STATUS_SUCCESS;
}
