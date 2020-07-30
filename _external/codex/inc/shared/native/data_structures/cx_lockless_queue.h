/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_LOCKLESS_QUEUE_
#define _CX_LOCKLESS_QUEUE_

#include "cx_native.h"

#ifndef CX_MSVC
#error "This file is only known to be usable with MSVC"
#endif //CX_MSVC

#define CX_LLQUEUE_STORAGE_REQUREMENT(ElementCount, ElementSize)    ((ElementCount) * (ElementSize))


typedef union
{
    struct
    {
        volatile CX_UINT16 Pivot;
        volatile CX_UINT16 Outgoing;
        volatile CX_UINT16 Waiting;
        volatile CX_UINT16 Incoming;
#pragma warning(suppress: 4201) // nonstandard extension used: nameless struct/union
    };
    volatile CX_UINT64 Raw;
}CX_LLQUEUE_POSITION;

typedef struct
{
    CX_UINT32 NumberOfElements;
    CX_UINT32 ElementSize;
    volatile CX_LLQUEUE_POSITION Position;
    CX_UINT8 *QueueData;
}CX_LLQUEUE;

/**
 * @brief           Creates a new lockless queue.
 *
 * @param[out]      Queue                               The newly created lockless queue.
 * @param[in]       ElementCount                        Maximum number of elements in the queue.
 * @param[in]       ElementSize                         Default queue element size.
 * @param[in]       StorageBuffer                       Pointer to the buffer on which the queue will operate.
 * @param[in]       BufferSize                          Size of the StorageBuffer.
 *
 * @returns         CX_STATUS_SUCCESS                   If the lockless queue was successfully created
 * @returns         CX_STATUS_DATA_BUFFER_TOO_SMALL     If the maximum number of elements do not fit the given buffer.
 */
CX_STATUS
CxLlQueueInitialize(
    _Out_ CX_LLQUEUE *Queue,
    _In_  CX_UINT32 ElementCount,
    _In_  CX_UINT32 ElementSize,
    _In_  CX_VOID *StorageBuffer,
    _In_  CX_UINT32 BufferSize
);

/**
 * @brief           Enqueues an element to a given lockless queue.
 *
 * @param[in]       Queue                               Pointer to the queue in which the enqueue will be performed.
 * @param[in]       Data                                Pointer to the elemnent data.
 * @param[in]       DataSize                            Size of the given element.
 * @param[in]       Blocking                            If TRUE will block execution until there's enough space to enqueue the elemen, otherwise, if the queue if full an error is returned.
 *
 * @returns         CX_STATUS_SUCCESS                   The element was successfully enqueued
 * @returns         CX_STATUS_OUT_OF_RESOURCES          Returned if Blocking is FALSE and there is not enough room to enqueue the element.
 * @returns         CX_STATUS_INVALID_DATA_SIZE         Returned if the given element does not have the standard queue element size.
 */
CX_STATUS
CxLlQueueAdd(
    _In_ CX_LLQUEUE *Queue,
    _In_ CX_VOID *Data,
    _In_ CX_UINT32 DataSize,
    _In_ CX_BOOL8 Blocking
);

/**
 * @brief           Dequeues an element from a given lockless queue.
 *
 * @param[in]       Queue                               Pointer to the queue in which the dequeue will be performed.
 * @param[out]      Data                                A buffer in which the dequeued data will be copied.
 * @param[in]       DataSize                            Size of the given Data buffer.
 * @param[in]       Blocking                            If TRUE will block execution until the queue has at least one element, otherwise, if the queue if empty, an error is returned.
 *
 * @returns         CX_STATUS_SUCCESS                   The element was successfully dequeued
 * @returns         CX_STATUS_OUT_OF_RESOURCES          Returned if Blocking is FALSE and there are no elements in the queue.
 * @returns         CX_STATUS_INVALID_DATA_SIZE         Returned if the Data buffer is too small to accommodate the dequeued element.
 */
CX_STATUS
CxLlQueueRemove(
    _In_  CX_LLQUEUE *Queue,
    _Out_ CX_VOID *Data,
    _In_  CX_UINT32 DataSize,
    _In_  CX_BOOL8 Blocking
);


/**
 * @brief           Returns the last position in the incoming area of the queue.
 *
 * @param[in]       Queue                               Pointer to the queue to be analyzed.
 *
 * @returns         A 64 bit value representing the last position in the incoming area of the queue.
 */
inline
CX_UINT64
CxLlQueueInstantaneousUsedCount(
    _In_ CX_LLQUEUE *Queue
)
{
    CX_LLQUEUE_POSITION oldPos;
    oldPos.Raw = Queue->Position.Raw;

    return (CX_UINT64)oldPos.Waiting + oldPos.Incoming;
}

/**
 * @brief           Returns the number of free elements in the queue.
 *
 * @param[in]       Queue                               Pointer to the queue to be analyzed.
 *
 * @returns         A 64 bit value representing the number of free elements in the queue.
 */
inline
CX_UINT64
CxLlQueueInstantaneousFreeCount(
    _In_ CX_LLQUEUE* Queue
)
{
    CX_LLQUEUE_POSITION oldPos;
    oldPos.Raw = Queue->Position.Raw;

    return Queue->NumberOfElements - ((CX_UINT64)oldPos.Waiting + oldPos.Incoming);
}

/**
 * @brief           Computes the percent of used queue memory.
 *
 * @param[in]       Queue                               Pointer to the queue to be analyzed.
 *
 * @returns         A byte representing the percentage of used queue memory
 */
inline
CX_UINT8
CxLlQueueInstantaneousUsedPercent(
    _In_ CX_LLQUEUE *Queue
)
{
    return (CX_UINT8)((100 * CxLlQueueInstantaneousUsedCount(Queue)) / Queue->NumberOfElements);
}

/**
 * @brief           Computes the percent of free queue memory.
 *
 * @param[in]       Queue                               Pointer to the queue to be analyzed.
 *
 * @returns         A byte representing the percentage of free queue memory
 */
inline
CX_UINT8
CxLlQueueInstantaneousFreePercent(
    _In_ CX_LLQUEUE* Queue
)
{
    return (CX_UINT8)((100 * CxLlQueueInstantaneousFreeCount(Queue)) / Queue->NumberOfElements);
}

#endif // _CX_LOCKLESS_QUEUE_