/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// Shared memory ring buffer for HV-guest communication
#include "cx_native.h"
#include "common/communication/ringbuf.h"

#include "external_interface/kernel_interface.h"
#include "external_interface/ringbuf_interface.h"

// the next files are included only for checking for consistency between the externally provided header and the expected documented interface
#include "common/external_interface/kernel_interface.h"
#include "common/external_interface/ringbuf_interface.h"

#define COMM_LOCK_VALUE(ApicId, LockOp) ( 1 | ((CX_UINT8)(CRT_COMPONENT) << 8) | ((CX_UINT8)(ApicId) << 16) | ((CX_UINT8)(LockOp) << 24) )
#define COMM_LOCK_TAKER(LockValue) ((LockValue) & 0xFFFFFF)

#define SHARED_MEM_MAGIC                'mMhS'      ///< Magic value used for basic integrity validation


/**
 * @brief Retrieves the APIC ID
 *
 * @return APIC ID
 */
CX_UINT8
__forceinline
_CommGetApicId(
    void
    )
{
    return (CX_UINT8)CpuGetCurrentApicId();
}

/**
 * @brief Acquire the Shared Memory lock
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[out]  OldIrql             Value of Irql before locking
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommMemLock(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Out_ CPU_IRQL *OldIrql
)
{
    CX_UINT32 lockValue;
    CX_BOOL gotLock;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("_CommMemTryLock() called with CX_NULL SharedMem!\n", SharedMem);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    CpuRaiseIrql(CPU_IRQL_HIGH_LEVEL, OldIrql);

    CX_UINT8 apicId = _CommGetApicId();
    lockValue = COMM_LOCK_VALUE(apicId, 2);

    if (CommBlockingAllowed())
    {
        CommSignalEvent(SharedMem, COMM_EVT_GET_LOCK, 0, (CX_UINT64)&SharedMem->Lock, 0, 0);
        GuestSyncSpinLock(&SharedMem->Lock, lockValue);
        gotLock = CX_TRUE;
    }
    else
    {
        gotLock = GuestSyncTrySpinLock(&SharedMem->Lock, lockValue, CX_NULL);
    }
    CommSignalEvent(SharedMem, COMM_EVT_TRY_LOCK, gotLock, (CX_UINT64)&SharedMem->Lock, 0, 0);

    if (gotLock)
    {
        SharedMem->LockOwner = CRT_COMPONENT;
        return CX_STATUS_SUCCESS;
    }
    else
    {
        CpuLowerIrql(*OldIrql);
        return CX_STATUS_DATA_NOT_READY;
    }
}

/**
 * @brief Release the Shared Memory's lock
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   OldIrql             Value of Irql before locking
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommMemUnlock(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CPU_IRQL *OldIrql
    )
{
    CX_UINT32 oldLockValue;
    CX_UINT32 lockValue;

    if (CX_NULL == SharedMem)
    {
        CpuLowerIrql(*OldIrql);
        COMM_ERROR("CommMemUnlock() called with CX_NULL SharedMem!\n", SharedMem);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!SharedMem->Lock)
    {
        CPU_DEBUG_BREAK();
        COMM_ERROR("Ringbuf spinlock not taken before release!\n");
    }

    CX_UINT8 apicId = _CommGetApicId();
    lockValue = COMM_LOCK_VALUE(apicId, 2);

    CommSignalEvent(SharedMem, COMM_EVT_RLS_LOCK, 0, (CX_UINT64)&SharedMem->Lock, 0, 0);
    oldLockValue = GuestSyncSpinUnlock(&SharedMem->Lock);

    if (COMM_LOCK_TAKER(oldLockValue) != COMM_LOCK_TAKER(lockValue))
    {
        CpuLowerIrql(*OldIrql);
        COMM_FATAL("Released lock taken by different component/APIC: taken as %08X, released by %08X!\n",
                oldLockValue, lockValue);

        return CX_STATUS_INVALID_PARAMETER_1;
    }

    CpuLowerIrql(*OldIrql);
    return CX_STATUS_SUCCESS;
}


/**
 * @brief Check if the message is within valid limits in the queue
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Message             Message that is validated
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return TRUE                     The message is valid
 * @return FALSE                    The message is not valid
 */
CX_BOOL
CommMessageIsInQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    )
{
    CX_BOOL result = CX_FALSE;
    CX_UINT32 offset;

    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        /// Message couldn't possibly be inside an empty queue :)
        goto done;
    }

    if ((((CX_UINT8*)SharedMem + COMM_SHMEM_HEADER_SIZE) > (CX_UINT8*)Message) || (((CX_UINT8*)SharedMem + SharedMem->Size) <= (CX_UINT8*)Message))
    {
        /// Message pointer is invalid (points outside the usable queue space)
        COMM_ERROR("Invalid message address %p: not between %p and %p!",
                Message, (CX_UINT8*)SharedMem + COMM_SHMEM_HEADER_SIZE, (CX_UINT8*)SharedMem + SharedMem->Size);
        goto done;
    }

    /// From this point on, Message pointer can only be invalid if it points inside the queue,

    /// but outside the used queue space => use after free?
    offset = (CX_UINT32)((CX_SIZE_T)Message - (CX_SIZE_T)SharedMem);
    if (SharedMem->Tail > SharedMem->Head)
    {
        if ((offset < SharedMem->Head) || (offset > SharedMem->Tail))
        {
            goto done;
        }
    }
    else if (SharedMem->Tail < SharedMem->Head)
    {
        if ((offset >= SharedMem->Tail) && (offset < SharedMem->Head))
        {
            goto done;
        }
    }
    // else: H == T => queue is full, so Message must point inside the queue

    result = CX_TRUE;

done:

    return result;
}
/**
 * @brief check if the Shared Memory is frozen
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[out]  Frozen              Freeze state
 *
 * @warning Call without acquiring the Shared memory lock
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommIsFrozenSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ CX_BOOL *Frozen
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;


    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (CX_NULL == Frozen)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    status = CommMemLock(SharedMem, oldIrql);
    if (!CX_SUCCESS(status))
    {
        goto done;
    }

    *Frozen = (1 == SharedMem->Frozen);
    CommMemUnlock(SharedMem, oldIrql);

done:
    return CX_STATUS_SUCCESS;
}

/**
 * @brief Freeze the Shared Memory (disable allocation and consumption)
 *
 * @param[in,out]   SharedMem           Shared Memory in use
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommFreezeSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!SharedMem->Lock)

    {
        COMM_FATAL("%s() called without taking the lock!", __FUNCTION__);
        return CX_STATUS_INVALID_DEVICE_REQUEST;
    }

    SharedMem->Frozen = 1;

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Unfreeze the Shared Memory (enable allocation and consumption)
 *
 * @param[in,out]   SharedMem           Shared Memory in use
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommUnfreezeSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    SharedMem->Frozen = 0;

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Initialize the Shared Memory
 *
 * @param[in]   Size                Size of the Shared Memory
 * @param[in,out]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommInitSharedMem(
    _In_ CX_UINT32 Size,
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    memset(SharedMem, 0, Size);

    SharedMem->Lock = 0; // lock is free
    SharedMem->Size = COMM_ALIGN(Size - COMM_EVT_LOG_SIZE);
    SharedMem->Head = 0;
    SharedMem->Tail = COMM_SHMEM_INV_TAIL;
    SharedMem->Magic = SHARED_MEM_MAGIC;
    SharedMem->CrtEventId = COMM_EVT_LOG_EMPTY;
    SharedMem->CrtMsgId = 0;
    SharedMem->CommVersion = COMM_HV_GUEST_PROTOCOL_VER;
    SharedMem->ShmemFlags = 0;
    SharedMem->Initialized = 1;

    CX_STATUS status = CommInitCustom();
    if (!CX_SUCCESS(status))
    {
        COMM_ERROR("CommInitCustom has failed");
        return status;
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Uninitialize the Shared Memory
 *
 * @param[in,out]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommUninitSharedMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    SharedMem->Initialized = 0;
    SharedMem->DenyAlloc = 0;
    SharedMem->Frozen = 0;

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Try to finalize all messages in the Shared Memory even if the messages didn't complete yet
 *
 * @param[in]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
_CommTryFinalizeMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    CX_STATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    volatile PCOMM_MESSAGE CrtMessage = CX_NULL;
    CX_UINT32 offset = 0, prevOffs = 0, prevPrevOffset = 0;

    COMM_COMPONENT dstComponent = 0;

    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory not initialized in call to %s()!\n", __FUNCTION__);
        return CX_STATUS_NOT_INITIALIZED;
    }

    status = CommMemLock(SharedMem, oldIrql);
    if (!CX_SUCCESS(status))
    {
        goto done;
    }

    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        COMM_INFO(" * Queue is empty - no need to cleanup\n");
    }
    else
    {
        if (COMM_SHMEM_FULL(SharedMem))
        {
            COMM_INFO(" * Queue is full!\n");
        }

        COMM_INFO(" * Will try to cleanupt ring buffer\n");

        offset = SharedMem->Head;
        prevOffs = offset - 1;
        do
        {
            CrtMessage = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);

            if ((MSG_TARGET_ANY == (MSG_TARGET_MASK & CrtMessage->CommandCode)))
            {
                dstComponent = CrtMessage->DstComponent;

            }
            else
            {
                dstComponent = MESSAGE_TO_TARGET(CrtMessage->CommandCode);
            }

            if (COMM_STATUS_PROCESSED == CrtMessage->Status)
            {
                goto next_message;
            }

            if (COMM_STATUS_PROCESSING == CrtMessage->Status)
            {
                if ((dstComponent == TargetWinguestKm) ||

                    (dstComponent == TargetWinguestUm)
                    )
                {
                    // only these components know to handle uninit while processing messages
                    CrtMessage->Status = COMM_STATUS_PROCESSED;
                    COMM_INFO("Found processing message for %d - mark as processed\n", dstComponent);
                }
                else
                {
                    COMM_INFO("Found processing message for %d - do nothing\n", dstComponent);
                }

                goto next_message;
            }

            //CommDumpMessageInfo(SharedMem, CrtMessage);

            if (COMM_STATUS_READY == CrtMessage->Status)
            {
                if (COMM_IS_REPLY(CrtMessage))
                {
                    /// should we touch it? - for now let this message be
                    //COMM_INFO("Found ready response - do nothing\n");
                }
                else if (COMM_NEEDS_REPLY(CrtMessage))
                {
                    /// send reply - don't wait for destination to respond
                    /// every message should have a status field to check on reply

                    /// if successfully completed or not - will see where it crashes :)
                    //COMM_INFO("Found ready message watiting for response - send replay directly\n");
                    CommSendReply(CrtMessage);
                }
                else
                {
                    /// freshly allocated message - finalize it - the destination won't see it
                    //COMM_INFO("Found ready message no reply - mark as processed\n");
                    CrtMessage->Status = COMM_STATUS_PROCESSED;
                }

                goto next_message;
            }

            if (COMM_STATUS_INVALID == CrtMessage->Status)
            {
                /// even if invalid message - drop it
                //COMM_INFO(" * Found invalid message no reply - mark as processed\n");
                CrtMessage->Status = COMM_STATUS_PROCESSED;
                goto next_message;
            }

next_message:
            offset = COMM_SHMEM_FIX_OFFSET(SharedMem, offset + COMM_ALIGN(CrtMessage->Size));
            if (offset == prevOffs)
            {
                CommDumpMessageInfo(SharedMem, CrtMessage);
                COMM_ERROR("aditional info CrtMessage->Size = 0x%x COMM_ALIGN(CrtMessage->Size) = 0x%x, offset = 0x%x, prevPrevOffset = 0x%x",
                    CrtMessage->Size,
                    COMM_ALIGN(CrtMessage->Size),
                    offset,
                    prevPrevOffset
                    );

                COMM_ERROR("CommGetNextMessage() fail: offset frozen @0x%05X when cycling through messages @ MSG#%08X!\n \n \n",

                    offset, CrtMessage->SeqNum);

                CommDumpQueue(SharedMem);
                break;
            }

            prevPrevOffset = prevOffs;
            prevOffs = offset;
        }
        while (offset != SharedMem->Tail);
    }
    CommMemUnlock(SharedMem, oldIrql);

    status = CX_STATUS_SUCCESS;

done:
    return status;
}

/**
 * @brief Prepare to uninitialize the Shared Memory (only called from winguest)
 *
 * @param[in]   SharedMem               Shared Memory in use
 * @param[in]   WaitForQueueToBeEmpty   Wait for the queue to empty itself
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommPrepareUninitSharedMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_BOOL WaitForQueueToBeEmpty
    )
{
    CX_BOOL emptyShMem = CX_FALSE;
    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (SharedMem->CommVersion != COMM_HV_GUEST_PROTOCOL_VER)
    {
        COMM_FATAL("Mismatched ringbuffer version: client has %02X, host has %02X!",
                COMM_HV_GUEST_PROTOCOL_VER, SharedMem->CommVersion);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory not initialized in call to %s()!\n", __FUNCTION__);
        return CX_STATUS_NOT_INITIALIZED;
    }

    CommMemLock(SharedMem, oldIrql);
    // deny allocs and cleanup all

    SharedMem->DenyAlloc = 1;
    CommFreezeSharedMem(SharedMem);

    CommMemUnlock(SharedMem, oldIrql);

    _CommTryFinalizeMessages(SharedMem);

    // now wait all messages to be removed
    do {
        CommMemLock(SharedMem, oldIrql);
        CommRemoveAllCompleted(SharedMem);
        emptyShMem = COMM_SHMEM_EMPTY(SharedMem);
        CommMemUnlock(SharedMem, oldIrql);

        if (emptyShMem)
        {
            break;
        }
        if ( !(CommCanAffordToWait() || WaitForQueueToBeEmpty) )
        {
            break;
        }

        // I'm not sure what a component that has nothing else to process here should do (_mm_pause maybe?)
        if (CommCanAffordToWait())
        {
            CpuDelayExecution(CX_FALSE, CX_TRUE, 1);
        }
    } while(!emptyShMem);

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Get the first free offset in the Ring Buffer that fits the message
 *
 * @param[in]       SharedMem           Shared Memory in use
 * @param[in]       Size                Size of required buffer
 * @param[in,out]   Offset              Offset of free buffer
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_INSUFFICIENT_RESOURCES
 * @return OTHER                             Other potential internal error
 */
CX_STATUS
CommGetNextOffset(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT32 Size,
    _Inout_ CX_UINT32 *Offset
    )
{
    CX_STATUS status = CX_STATUS_INSUFFICIENT_RESOURCES;
    PCOMM_MESSAGE msg = CX_NULL;
    CX_UINT32 offset = 0;

    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Size)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    if (CX_NULL == Offset)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    if (!SharedMem->Lock)

    {
        COMM_FATAL("%s() called without taking the lock!", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    Size = COMM_ALIGN(Size);

    /// check if enough *continuous* space is available
    offset = 0;
    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        /// empty queue
        SharedMem->Head = COMM_SHMEM_FIX_OFFSET(SharedMem, COMM_SHMEM_HEADER_SIZE);
        SharedMem->Tail = COMM_SHMEM_FIX_OFFSET(SharedMem, COMM_SHMEM_HEADER_SIZE + Size);
        offset = SharedMem->Head;

        status = CX_STATUS_SUCCESS;
    }
    else if (SharedMem->Head == SharedMem->Tail)
    {
        /// full queue
        CommSignalEvent(SharedMem, COMM_EVT_FULL_QUEUE, *Offset, Size, 0, 0);

        COMM_ERROR("Queue @ %p is full (Head:%d(0x%X); Tail:%d(0x%X)!\n", SharedMem,

            SharedMem->Head, SharedMem->Head, SharedMem->Tail, SharedMem->Tail);
        COMM_LOG("[AFTER-MSG] SharedMem->Head == %X == SharedMem->Tail == %X\n", SharedMem->Head, SharedMem->Tail);
        //CommDumpQueue(SharedMem);

        status = CX_STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (SharedMem->Head > SharedMem->Tail)
    {
        if (SharedMem->Head - SharedMem->Tail >= Size)
        {
            // room between Tail and Head
            offset = SharedMem->Tail;
            SharedMem->Tail += Size;    // does not need COMM_SHMEM_FIX_OFFSET

            status = CX_STATUS_SUCCESS;
        }
    }
    else
    {
        /// Tail > Head
        if (SharedMem->Size - SharedMem->Tail >= Size)
        {
            /// room between Tail and end-of-queue
            offset = SharedMem->Tail;
            SharedMem->Tail = COMM_SHMEM_FIX_OFFSET(SharedMem, SharedMem->Tail + Size);

            status = CX_STATUS_SUCCESS;
        }
        else if (SharedMem->Head - COMM_SHMEM_HEADER_SIZE >= Size)
        {
            /// room between start-of-queue and Head

            if (SharedMem->Size - SharedMem->Tail > 0)
            {
                if (SharedMem->Size - SharedMem->Tail < sizeof(COMM_MESSAGE))
                {
                    /// should never happen, kept here for debugging
                    COMM_FATAL("Misaligned room after tail: .Size = %X, .Tail = %X, sizeof(COMM_MESSAGE) = %X!",
                        SharedMem->Size, SharedMem->Tail, sizeof(COMM_MESSAGE));
                    status = CX_STATUS_INSUFFICIENT_RESOURCES;
                    offset = 0;
                    goto done;
                }
                /// add padding message
                msg = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + SharedMem->Tail);
                msg->DstComponent = TargetAny;
                msg->Size = SharedMem->Size - SharedMem->Tail;
                msg->Status = COMM_STATUS_PROCESSED;
                msg = CX_NULL;     /// shouldn't matter
            }

            /// adjust offset/tail
            offset = COMM_SHMEM_HEADER_SIZE;
            SharedMem->Tail = COMM_SHMEM_HEADER_SIZE + Size;

            status = CX_STATUS_SUCCESS;
        }
    }

done:
    *Offset = offset;

    return status;
}

/**
 * @brief Try to reinsert previously inserted messages. Called on each guest exit.
 *
 * @param[in]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommTryReinsertMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    if (CommIsBufferingEnabled())
        return CommFlushBufferedMessages(SharedMem);

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Initialize a Message
 *
 * @param[in]   Msg                 Message
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   CommandCode         Message Type
 * @param[in]   CommandFlags        Shared Memory Message Flags
 * @param[in]   DstComponent        Destination
 * @param[in]   SrcComponent        Source
 * @param[in]   Size                Size of the Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_VOID
_CommInitMessage(
    _In_ PCOMM_MESSAGE Msg,
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ COMMAND_CODE CommandCode,
    _In_ CX_UINT32 CommandFlags,
    _In_ COMM_COMPONENT DstComponent,
    _In_opt_ COMM_COMPONENT SrcComponent,
    _In_ CX_UINT32 Size
    )
{
    Msg->Status = COMM_STATUS_UNDEFINED;
    Msg->ProcessingStatus = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    Msg->CommandCode = CommandCode;
    Msg->DstComponent = DstComponent;
    Msg->Size = Size;
    Msg->Flags = CommandFlags;
    Msg->SeqNum = (CX_UINT32)_InterlockedIncrement((long*)&SharedMem->CrtMsgId);
    Msg->SrcComponent = SrcComponent;
}

/**
 * @brief Allocate and initialize a Message
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   CommandCode         Message Type
 * @param[in]   CommandFlags        Shared Memory Message Flags
 * @param[in]   DstComponent        Destination
 * @param[in]   SrcComponent        Source
 * @param[in]   Size                Size of the Message
 * @param[out]  Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_INSUFFICIENT_RESOURCES     Insufficient free storage available
 * @return CX_STATUS_ACCESS_DENIED              Shared Memory is frozen
 * @return CX_STATUS_NOT_INITIALIZED            Shared Memory not initialized
 * @return CX_STATUS_OPERATION_NOT_SUPPORTED    Shared Memory version mismatch
 * @return OTHER                                Other potential internal error
 */
CX_STATUS
CommAllocMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ COMMAND_CODE CommandCode,
    _In_ CX_UINT32 CommandFlags,
    _In_ COMM_COMPONENT DstComponent,
    _In_opt_ COMM_COMPONENT SrcComponent,
    _In_ CX_UINT32 Size,
    _Out_ PCOMM_MESSAGE *Message
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    PCOMM_MESSAGE msg = CX_NULL;
    CX_UINT32 offset = 0, size = 0;
    CX_BOOL shMemFrozen = CX_FALSE;
    CX_BOOL availableMem = CX_FALSE;
    CX_BOOL lockAcquired = CX_FALSE;

    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;


    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (SharedMem->CommVersion != COMM_HV_GUEST_PROTOCOL_VER)
    {
        COMM_FATAL("Mismatched ringbuffer version: client has %02X, host has %02X!",
                COMM_HV_GUEST_PROTOCOL_VER, SharedMem->CommVersion);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    CommSignalEvent(SharedMem, COMM_EVT_ALLOC, CommandCode, Size, SrcComponent, DstComponent);

    if (0 == Size)
    {
        COMM_ERROR("Size 0 passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_5;
    }

    if (Size < sizeof(COMM_MESSAGE) )
    {
        COMM_ERROR("Message 0x%08X (%s) doesn't have a body %s()!\n", CommandCode, CommCommandToString(CommandCode), __FUNCTION__);
        return CX_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory not initialized in call to %s()!\n", __FUNCTION__);
        return CX_STATUS_NOT_INITIALIZED;
    }

    status = CommIsFrozenSharedMem(SharedMem, &shMemFrozen);
    if (!CX_SUCCESS(status))
    {
        COMM_FUNC_FAIL("CommIsFrozenSharedMem", status);
        goto done;
    }

    if (shMemFrozen)
    {
        //COMM_ERROR("Shared memory @ %p frozen in call to %s()!\n", SharedMem, __FUNCTION__);
        return CX_STATUS_ACCESS_DENIED;
    }

    size = COMM_ALIGN(Size);

    if (size > COMM_SHMEM_USABLE(SharedMem))
    {
        COMM_ERROR("Message size %d (command %s) passed to %s() is larger than whole queue size (%d)!\n", Size, CommCommandToString(CommandCode), __FUNCTION__, COMM_SHMEM_USABLE(SharedMem));
        //CommDumpQueue(SharedMem);
       return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = CommMemLock(SharedMem, oldIrql);
    if (CX_SUCCESS(status))
    {
        lockAcquired = CX_TRUE;
    }

    if (CommIsBufferingEnabled())
    {
        if (CX_SUCCESS(status))
        {
            // check to see if enough free space available
            CX_UINT32 freeSpace = 0;

            availableMem = CX_FALSE;

            status = CommMemGetFreeMem(SharedMem, &freeSpace, CX_TRUE);
            //INFON("Free space: %d, needed: %d\n", freeSpace, Size);
            if (CX_SUCCESS(status) && freeSpace > size)
            {
                availableMem = CX_TRUE;
            }

            if ((CommandFlags & COMM_FLG_IS_NON_CORE_MESSAGE) && (freeSpace < SHARED_MEM_SIZE / 10))
            {
                availableMem = CX_FALSE;
            }
        }

        if (1 == SharedMem->DenyAlloc)
        {
            //COMM_LOG("Alloc is denied\n");
            status = CX_STATUS_ACCESS_DENIED;
            goto done;
        }

        if ((CX_FALSE == availableMem) || (CX_FALSE == lockAcquired))
        {
            //LOGN("Postpone message: 0x%08X, Locked: %s (val: 0x%08X), Mem: %s\n", CommandCode, lockAcquired?"true":"false", SharedMem->Lock, availableMem?"true":"false");
            if (lockAcquired)
            {
                CommMemUnlock(SharedMem, oldIrql);
                lockAcquired = CX_FALSE;
            }

            status = CommAllocBufferedMessage(Size, &msg);
            if (!CX_SUCCESS(status))
            {
                goto done;
            }

            _CommInitMessage(msg, SharedMem, CommandCode, CommandFlags, DstComponent, SrcComponent, Size);

            status = CommCommitBufferedMessage();
            if (!CX_SUCCESS(status))
            {
                goto done;
            }

            goto msg_allocated;
        }
    }

    if (1 == SharedMem->DenyAlloc)
    {
        //COMM_LOG("Alloc is denied\n");
        status = CX_STATUS_ACCESS_DENIED;
        goto done;
    }

    /// TODO offset
    status = CommGetNextOffset(SharedMem, size, &offset);
    if (!CX_SUCCESS(status))
    {
        COMM_ERROR("Attempted message: %s\n", CommCommandToString(CommandCode));
        offset = 0;
    }

    CommSignalEvent(SharedMem, COMM_EVT_ALLOC_RESULT, offset, 0, CommandFlags, 0);

    if (!offset)
    {
        COMM_ERROR("cannot find any offset\n");
        goto done;
    }

    // COMM_INFO("#Q# new offset:%d => head @ %d\n", offset, SharedMem->Head);

    // at this point we have <size> bytes available at <offset> in buffer
    msg = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);
    _CommInitMessage(msg,SharedMem,CommandCode,CommandFlags,DstComponent,SrcComponent,Size);


msg_allocated:

    status = CX_STATUS_SUCCESS;

    //
    // It is critical to release the inter-guest spinlock only after the message size is set
    // otherwise anyone walking the ringbuffer will be stuck when reaching a message of size 0
    //

done:
    if (lockAcquired)
    {
        CommMemUnlock(SharedMem, oldIrql);
    }

    *Message = msg;
    return status;
}

/**
 * @brief Send a message allocated in Shared Memory
 *
 * @param[in]       SharedMem           Shared Memory in use
 * @param[in,out]   Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommSendMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ PCOMM_MESSAGE Message
    )
//
// Sends a message allocated with CommAllocMessage.
//
{
    if (CX_NULL == SharedMem)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    CommSignalEvent(SharedMem, COMM_EVT_SEND, Message->CommandCode, Message->Size, COMM_IS_REPLY(Message), 0);

    Message->Status = COMM_STATUS_READY;
    return CommSignalMessage(Message->CommandCode, ((CX_SIZE_T)Message - (CX_SIZE_T)SharedMem));
}

/**
 * @brief Marks a message as processed and ready to be processed as a reply
 *
 * @param[in,out]   Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommSendReply(
    _Inout_ PCOMM_MESSAGE Message
    )
//
// Sets a Message up to be processed as a response.
//
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_UINT8 comp;

    Message->Status = COMM_STATUS_PROCESSING;
    comp = Message->DstComponent;
    Message->DstComponent = Message->SrcComponent;
    Message->SrcComponent = comp;
    Message->Flags |= COMM_FLG_IS_REPLY;

    //CommSignalEvent(SharedMem, COMM_EVT_SEND_REPLY, Message->CommandCode, Message->Size, 1, 0);

    Message->Status = COMM_STATUS_READY;

    return status;
}

/**
 * @brief Forward a message to another component
 *
 * @param[in,out]   Message             Message
 * @param[in]       DstComponent        Destination
 *
 * @return CX_STATUS_SUCCESS
 */
CX_STATUS
CommForwardMessage(
    _Inout_ PCOMM_MESSAGE Message,
    _In_ COMM_COMPONENT DstComponent
    )
{
    Message->Status = COMM_STATUS_PROCESSING;
    Message->DstComponent = DstComponent;
    Message->Status = COMM_STATUS_READY;

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Remove all completed messages from the ringbuffer
 *
 * @param[in]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_VOID
CommRemoveAllCompleted(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    PCOMM_MESSAGE Message = CX_NULL;
    CX_UINT32 size = 0;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory not initialized in call to %s()!\n", __FUNCTION__);
        return;
    }

    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        return;
    }

    Message = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + SharedMem->Head);
    while (Message->Status == COMM_STATUS_PROCESSED)
    {
        size = COMM_ALIGN(Message->Size);
        /// move Head
        SharedMem->Head = COMM_SHMEM_FIX_OFFSET(SharedMem, SharedMem->Head + size);

        /// clear out message content
        CommSignalEvent(SharedMem, COMM_EVT_FREE_MOVED_HEAD, 0, 0, 0, 0);
        /// [todo] replace memset() with selectively setting the .Status field every COMM_ALIGNed bytes
        memset((void*)Message, 0, size); // 0x69
        /// jump to next message
        Message = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + SharedMem->Head);
        //COMM_INFO("#Q# moved head to %d -> %p status: %08X\n", SharedMem->Head, Message, Message->Status);
        /// check if tail reached (i.e. emptied queue)
        if (SharedMem->Head == SharedMem->Tail)
        {
            /// removed all messages; properly mark empty queue
            SharedMem->Head = 0;
            SharedMem->Tail = COMM_SHMEM_INV_TAIL;
            CommSignalEvent(SharedMem, COMM_EVT_FREE_EMPTIED, 0, 0, 0, 0);
            break;
        }
    }
}

/**
 * @brief Frees a Message. Marks it as discardable and removes it if all previous are discarded
 *
 * @param[in]       SharedMem           Shared Memory in use
 * @param[in,out]   Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommFreeMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ PCOMM_MESSAGE Message
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_BOOL isInQueue;
    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto done;
    }

    if (CX_NULL == Message)
    {
        COMM_ERROR("CX_NULL Message passed to %s()!\n", __FUNCTION__);
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto done;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory @ %p not initialized in call to %s()!\n", SharedMem, __FUNCTION__);
        status = CX_STATUS_NOT_INITIALIZED;
        goto done;
    }

    //CommDumpQueue(SharedMem);
    CommSignalEvent(SharedMem, COMM_EVT_FREE, Message->CommandCode, Message->Size, COMM_IS_REPLY(Message), 0);

    status = CommMemLock(SharedMem, oldIrql);
    if (!CX_SUCCESS(status))
    {
        goto done;
    }

    isInQueue = CommMessageIsInQueue(SharedMem, Message);

    if (isInQueue)
    {
        Message->Status = COMM_STATUS_PROCESSED;

        /// start from Head, remove all processed messages
        Message = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + SharedMem->Head);
        //COMM_INFO("#Q# starting @ head:%d -> %p (tail:%d) status: %08X\n",

        //    SharedMem->Head, Message, SharedMem->Tail, Message->Status);

        CommRemoveAllCompleted(SharedMem);
    }

    else
    {
        COMM_ERROR("Message @ %p passed to %s() points outside of queue @ %p!\n", Message, __FUNCTION__, SharedMem);
        CommDumpMessageInfo(SharedMem, Message);
        status = CX_STATUS_INVALID_PARAMETER_2;

    }

    CommMemUnlock(SharedMem, oldIrql);

done:

    return status;
}

/**
 * @brief Marks a message as processed. Afterwards it is Freed or sent as a reply if necessary
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommDoneMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    CommSignalEvent(SharedMem, COMM_EVT_DONE_MSG, Message->CommandCode, Message->Size, 0, 0);

    if (COMM_NEEDS_REPLY(Message))
    {
        status = CommSendReply(Message);
        if (!CX_SUCCESS(status))
        {
            COMM_FUNC_FAIL("CommSendReply", status);
            return status;
        }
        status = CommSignalMessage(Message->CommandCode, ((CX_SIZE_T)Message - (CX_SIZE_T)SharedMem));
    }
    else
    {
        status = CommFreeMessage(SharedMem, Message);
        if (!CX_SUCCESS(status))
        {
            COMM_FUNC_FAIL("CommFreeMessage", status);
            return status;
        }
    }

    return status;
}

/**
 * @brief Get the first message in the queue addressed to a specific componentd
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   DstComponent        Destination of the message
 * @param[out]  Message             Message
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_ACCESS_DENIED      Shared Memory is frozen
 * @return CX_STATUS_DATA_NOT_FOUND     No messages available
 * @return CX_STATUS_NOT_INITIALIZED    Shared Memory not initialized
 * @return OTHER                        Other potential internal error
 */
CX_STATUS
CommGetNextMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ COMM_COMPONENT DstComponent,       // destination component for the message
    _Out_ volatile PCOMM_MESSAGE* Message   // next message or CX_NULL if none left
    )
{
    CX_STATUS status = CX_STATUS_DATA_NOT_FOUND;
    CX_UINT32 offset = 0, prevOffs = 0, prevPrevOffset = 0;

    CX_BOOL shMemFrozen = CX_FALSE;
    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == Message)

    {
        COMM_ERROR("CX_NULL Message passed to %s()!\n", __FUNCTION__);
        status = CX_STATUS_INVALID_PARAMETER_3;
        return status;
    }
    *Message = CX_NULL;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto done;
    }

    if (!SharedMem->Initialized)
    {
        COMM_ERROR("Shared memory @ %p not initialized in call to %s()!\n", SharedMem, __FUNCTION__);
        status = CX_STATUS_NOT_INITIALIZED;
        goto done;
    }

    status = CommIsFrozenSharedMem(SharedMem, &shMemFrozen);
    if (!CX_SUCCESS(status))
    {
        COMM_FUNC_FAIL("CommIsFrozenSharedMem", status);
        goto done;
    }

    if (shMemFrozen)
    {
        COMM_ERROR("Shared memory @ %p frozen in call to %s()!\n", SharedMem, __FUNCTION__);
        return CX_STATUS_ACCESS_DENIED;
    }

    CommSignalEvent(SharedMem, COMM_EVT_NEXT, 0, 0, 0, 0);

    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        /// Most of the time code flow should go through here
        goto done;
    }

    //CommDumpQueue(SharedMem);

    status = CommMemLock(SharedMem, oldIrql);
    if (!CX_SUCCESS(status))
    {
        COMM_ERROR("failed to take lock\n");
        goto done;
    }


    status = CX_STATUS_DATA_NOT_FOUND;
    if (!COMM_SHMEM_EMPTY(SharedMem))
    {
        volatile PCOMM_MESSAGE CrtMessage = CX_NULL;

        offset = SharedMem->Head;
        prevOffs = offset - 1;

        do

        {
            CrtMessage = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);
            if ((CrtMessage->DstComponent == DstComponent) && (CrtMessage->Status == COMM_STATUS_READY))
            {
                /// found message
                if ((0 == CrtMessage->Size)||
                    (0 == COMM_ALIGN(CrtMessage->Size)))
                {
                    COMM_ERROR("[CRITICAL] offset = 0x%x prevOffs = 0x%x prevPrevOffset = 0x%x \n",offset,prevOffs,prevPrevOffset);
                    CommDumpMessageInfo(SharedMem,CrtMessage);
                    status = CX_STATUS_INVALID_PARAMETER_1;
                    break;
                }
                *Message = CrtMessage;
                CrtMessage->Status = COMM_STATUS_PROCESSING;
                status = CX_STATUS_SUCCESS;
                break;
            }

            offset = COMM_SHMEM_FIX_OFFSET(SharedMem, offset + COMM_ALIGN(CrtMessage->Size));
            if (offset == prevOffs)
            {
                CommDumpMessageInfo(SharedMem, CrtMessage);
                COMM_ERROR("aditional info CrtMessage->Size = 0x%x COMM_ALIGN(CrtMessage->Size) = 0x%x, offset = 0x%x, prevPrevOffset = 0x%x",
                    CrtMessage->Size,
                    COMM_ALIGN(CrtMessage->Size),
                    offset,
                    prevPrevOffset
                    );

                COMM_ERROR("CommGetNextMessage() fail: offset frozen @0x%05X when cycling through messages @ MSG#%08X!\n \n \n",

                    offset, CrtMessage->SeqNum);

                CommDumpQueue(SharedMem);
                break;
            }
            prevPrevOffset = prevOffs;
            prevOffs = offset;

        } while (offset != SharedMem->Tail);
    }
    CommMemUnlock(SharedMem, oldIrql);
done:

    return status;
}

/**
 * @brief Get the current free memory amount in the Shared Memory
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[out]  FreeSpace           Free Space amount
 * @param[in]   Lockless            Without locking the queue
 *
 * @warning The buffer cannot be filled, so a message the same size as the free memory cannot be allocated
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommMemGetFreeMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ CX_UINT32* FreeSpace,
    _In_ CX_BOOL Lockless
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (CX_NULL == FreeSpace)
    {
        COMM_ERROR("CX_NULL FreeSpace pointer passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    if (!Lockless)
    {
        status = CommMemLock(SharedMem, oldIrql);
        if (!CX_SUCCESS(status))
        {
            return status;
        }
    }

    *FreeSpace = COMM_SHMEM_USABLE(SharedMem);

    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        *FreeSpace = COMM_SHMEM_USABLE(SharedMem);
    }
    else if (COMM_SHMEM_FULL(SharedMem))
    {
        *FreeSpace = 0;
    }
    else if (SharedMem->Head > SharedMem->Tail)
    {
        *FreeSpace = SharedMem->Head - SharedMem->Tail;
    }
    else
    {
        *FreeSpace = COMM_SHMEM_USABLE(SharedMem) - (SharedMem->Tail - SharedMem->Head);
    }

    if (CX_FALSE == Lockless)
    {
        CommMemUnlock(SharedMem, oldIrql);
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Convert a Shared Memory status numeric identifier to string
 *
 * @param[in]   Status              Numerical representation of the component
 *
 * @return String representation of the status
*/
const
char *
CommStatusToString(
    _In_ CX_UINT8 Status
    )
{
    switch (Status)
    {
    case COMM_STATUS_INVALID:
        return "COMM_STATUS_INVALID";
    case COMM_STATUS_PROCESSED:
        return "COMM_STATUS_PROCESSED";
    case COMM_STATUS_PROCESSING:
        return "COMM_STATUS_PROCESSING";
    case COMM_STATUS_READY:
        return "COMM_STATUS_READY";
    case COMM_STATUS_UNDEFINED:
        return "COMM_STATUS_UNDEFINED";
    case COMM_STATUS_WAITING:
        return "COMM_STATUS_WAITING";
    default:
        return "[unknown-status]";
    }
}

/**
 * @brief Get the count of messages in the Shared Memory in all possible states
 *
 * @param[in]   SharedMem               Shared Memory in use
 * @param[out]  UninitedMessages        Count of uninitialized messages
 * @param[out]  ReadyMessages           Count of ready messages
 * @param[out]  InProcessingMessages    Count of currently being processed messages
 * @param[out]  ProcessedMessages       Count of processed messages
 * @param[out]  WaitingMessages         Count of waiting messages
 * @param[out]  InvalidMessages         Count of invalid messages
 * @param[out]  OtherMessages           Count of other messages
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
*/
CX_STATUS
CommCountMessageStatuses(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    __out_opt CX_UINT32 *UninitedMessages,
    __out_opt CX_UINT32 *ReadyMessages,
    __out_opt CX_UINT32 *InProcessingMessages,
    __out_opt CX_UINT32 *ProcessedMessages,
    __out_opt CX_UINT32 *WaitingMessages,
    __out_opt CX_UINT32 *InvalidMessages,
    __out_opt CX_UINT32 *OtherMessages
    )
//
// Call with lock taken!
//
{
    PCOMM_MESSAGE Message;
    volatile CX_UINT32 prevOffs = 0, offset = 0;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (UninitedMessages)
    {
        *UninitedMessages = 0;
    }

    if (ReadyMessages)
    {
        *ReadyMessages = 0;
    }

    if (InProcessingMessages)
    {
        *InProcessingMessages = 0;
    }

    if (ProcessedMessages)
    {
        *ProcessedMessages = 0;
    }

    if (WaitingMessages)
    {
        *WaitingMessages = 0;
    }

    if (InvalidMessages)
    {
        *InvalidMessages = 0;
    }

    if (UninitedMessages)
    {
        *UninitedMessages = 0;
    }

    if (OtherMessages)
    {
        *OtherMessages = 0;
    }

    if (!COMM_SHMEM_EMPTY(SharedMem))
    {
        offset = SharedMem->Head;
        prevOffs = offset - 1;
        do
        {
            Message = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);

            switch (Message->Status)
            {
            case COMM_STATUS_UNDEFINED:
                if (UninitedMessages)
                {
                    (*UninitedMessages)++;
                }
                break;
            case COMM_STATUS_READY:
                if (ReadyMessages)
                {
                    (*ReadyMessages)++;
                }
                break;
            case COMM_STATUS_PROCESSING:
                if (InProcessingMessages)
                {
                    (*InProcessingMessages)++;
                }
                break;
            case COMM_STATUS_PROCESSED:
                if (ProcessedMessages)
                {
                    (*ProcessedMessages)++;
                }
                break;
            case COMM_STATUS_WAITING:
                if (WaitingMessages)
                {
                    (*WaitingMessages)++;
                }
                break;
            case COMM_STATUS_INVALID:
                if (InvalidMessages)
                {
                    (*InvalidMessages)++;
                }
                break;
            default:
                if (OtherMessages)
                {
                    (*OtherMessages)++;
                }

            }

            offset = COMM_SHMEM_FIX_OFFSET(SharedMem, offset + COMM_ALIGN(Message->Size));
            if (offset == prevOffs)
            {
                COMM_ERROR("Failed dumping: offset frozen @0x%05X when cycling through messages!", offset);
                break;
            }
            prevOffs = offset;
        }
        while (offset != SharedMem->Tail);
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Check message status and ensure the ShMem can be freed (all messages are either READY or PROCESSED).
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[out]  CanFree             Shared Memory can be freed
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommCanFreeShMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Out_ PBOOLEAN CanFree
    )
{
    CX_UINT32 uninitedMessages = 0, inProcessingMessages = 0, waitingMessages = 0, invalidMessages = 0, otherMessages = 0;
    CX_STATUS status;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (CX_NULL == CanFree)
    {
        COMM_ERROR("CX_NULL CanFree passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    *CanFree = CX_FALSE;

    status = CommCountMessageStatuses(SharedMem, &uninitedMessages, CX_NULL, &inProcessingMessages,
            CX_NULL, &waitingMessages, &invalidMessages, &otherMessages);
    if (!CX_SUCCESS(status))
    {
        COMM_FUNC_FAIL("CommCountMessageStatuses", status);
        return status;
    }

    *CanFree = 0 == (uninitedMessages + inProcessingMessages + waitingMessages + invalidMessages + otherMessages);

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Print Shared Memory information and content
 *
 * @param[in]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommDumpQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    PCOMM_MESSAGE Message;
    volatile CX_UINT32 prevPrevOffs = 0, prevOffs = 0, offset = 0, lock;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    lock = SharedMem->Lock;

    COMM_INFO("SHMEM-QUEUE@%p: Size=%d(0x%X); Head=%d(0x%X); Tail=%d(0x%x); Lock=%X (by %s); Initialized=%d\n",
            SharedMem, SharedMem->Size, SharedMem->Size, SharedMem->Head, SharedMem->Head,
            SharedMem->Tail, SharedMem->Tail,  lock, CommComponentToString((CX_UINT8)SharedMem->LockOwner),
            SharedMem->Initialized);

    if (lock)
    {
        CX_UINT8 op;
        op = lock >> 24;
        // #define COMM_LOCK_VALUE(ApicId, LockOp) (1 | ((CX_UINT8)(CRT_COMPONENT) << 8) | ((CX_UINT8)(ApicId) << 16) | ((CX_UINT8)(LockOp) << 24))

        COMM_INFO(" - Lock: %s / APIC:%02X, op:%s (%02X)\n",
                CommComponentToString((lock & 0xFF00) >> 8),
                (lock & 0xFF0000) >> 16,
                (op == 1) ? "TryLock" : ((op == 2) ? "GetLock" : "Unknown"),
                op);

    }

    // [todo] locks no longer taken, rewrite to be more defensive
    if (COMM_SHMEM_EMPTY(SharedMem))
    {
        COMM_INFO(" * queue is empty!\n");
    }
    else
    {
        if (COMM_SHMEM_FULL(SharedMem))
        {
            COMM_INFO(" * queue is full!\n");
        }

        offset = SharedMem->Head;
        prevOffs = offset - 1;
        do
        {
            COMM_INFO("head:0x%x tail:0x%x offset:0x%x prevOffset:0x%x \n", SharedMem->Head, SharedMem->Tail, offset, prevPrevOffs);
            Message = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);
            CommDumpMessageInfo(SharedMem, Message);

            offset = COMM_SHMEM_FIX_OFFSET(SharedMem, offset + COMM_ALIGN(Message->Size));
            if (offset == prevOffs)
            {
                COMM_ERROR("Failed dumping: offset frozen @0x%05X when cycling through messages!", offset);
                break;
            }
            prevPrevOffs = prevOffs;
            prevOffs = offset;
        }
        while (offset != SharedMem->Tail);
    }
    if (CommIsBufferingEnabled)
    {
        CommDumpBufferedMessages();
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Check if the message is valid
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Message             Message that is validated
 *
 * @warning Call after acquiring the Shared memory lock
 *
 * @return TRUE                     The message is valid
 * @return FALSE                    The message is not valid
 */
CX_BOOL
CommIsValidMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    )
{
    if (!CommMessageIsInQueue(SharedMem, Message))
    {
        return CX_FALSE;
    }

    // [todo] add more checks

    return CX_TRUE;
}

/**
 * @brief Print Message information
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Message             Message to dump
 */
void
CommDumpMessageInfo(
    _In_opt_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    )
{
    if (SharedMem && (!CommMessageIsInQueue(SharedMem, Message)))
    {
        COMM_INFO(" * Message @%p is not in queue @%p!\n", Message, SharedMem);
        return;
    }

    COMM_INFO(" * %s#%08X @%p: dst=%s: %-20s{%08X}   %-20s{%d}   size:%d    Offset:0x%x  Flags: 0x%08x ",
        COMM_IS_REPLY(Message) ? "REPLY" : "MESSAGE",
        Message->SeqNum,
        Message,
        CommComponentToString(Message->DstComponent),
        CommCommandToString(Message->CommandCode),
        Message->CommandCode,
        CommStatusToString(Message->Status),
        Message->Status,
        Message->Size,
        (CX_NULL != SharedMem) ? ((CX_SIZE_T)Message - (CX_SIZE_T)SharedMem) : 0,
        Message->Flags
        );

    COMM_INFO("\n");
}

/**
 * @brief Check Shared Memory by filling it with buffers and freeing them
 *
 * @param[in]   SharedMem           Shared Memory in use
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommFillQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    CX_STATUS status;
    PCOMM_MESSAGE cmd = CX_NULL, lastcmd = CX_NULL;
    CX_UINT32 size;

    size = SharedMem->Size / 11;

    COMM_INFO("Testing SHMEM@%p with message size %d.\n", SharedMem, size);

    for (CX_UINT32 i = 0; CX_TRUE; i++)
    {
        COMM_INFO("MESSAGE %d:\n", i);
        status = CommAllocMessage(SharedMem, cmdIgnore, 0, TargetWinguestKm, 0, size, &cmd);
        if (!CX_SUCCESS(status))
        {
            COMM_FUNC_FAIL("CommAllocMessage", status);
            break;
        }

        status = CommSendMessage(SharedMem, cmd);
        if (!CX_SUCCESS(status))
        {
            COMM_FUNC_FAIL("CommSendMessage", status);
        }

        cmd->Status = COMM_STATUS_PROCESSED;

        lastcmd = cmd;
    }

    COMM_INFO("Destroying last successfully posted message @%p...\n", lastcmd);
    status = CommFreeMessage(SharedMem, lastcmd);
    if (!CX_SUCCESS(status))
    {
        COMM_FUNC_FAIL("CommFreeMessage", status);
    }

    COMM_INFO("Last test message (after clean):\n");
    status = CommAllocMessage(SharedMem, cmdIgnore, 0, TargetWinguestKm, 0, size, &cmd);
    if (!CX_SUCCESS(status))
    {
        COMM_FUNC_FAIL("CommAllocMessage", status);
    }
    else
    {
        status = CommSendMessage(SharedMem, cmd);
        if (!CX_SUCCESS(status))
        {
            COMM_FUNC_FAIL("CommSendMessage", status);
        }
        else
        {
            status = CommFreeMessage(SharedMem, cmd);
            if (!CX_SUCCESS(status))
            {
                COMM_FUNC_FAIL("CommFreeMessage", status);
            }

        }
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Acquire the Shared Memory lock
 *
 * @param[in,out]   Lock            Lock
 * @param[in]       LockValue       New value for the lock
 *
 * @return The number of attempts required to aquire
 */
CX_UINT32
GuestSyncSpinLock(
    _Inout_ volatile CX_UINT32 *Lock,
    _In_ CX_UINT32 LockValue
    )
{
    CX_UINT32 attempts = 1;

    if (!LockValue)
    {
        COMM_FATAL("LockValue == %d passed to %s", LockValue, __FUNCTION__);
        return CX_FALSE;   // should never reach this point
    }

    if (!Lock)
    {
        COMM_FATAL("CX_NULL Lock pointer passed to %s", __FUNCTION__);
        return CX_FALSE;   // should never reach this point
    }

    if (!GuestSyncTrySpinLock(Lock, LockValue, CX_NULL))
    {
        do
        {
            while (0 != (*Lock))
            {
                _mm_pause();
            }
            attempts++;
        }while (0 != _InterlockedCompareExchange((long *)Lock, LockValue, 0));
    }

    return attempts;
}

/**
 * @brief Try to acquire the Shared Memory lock
 *
 * @param[in,out]   Lock            Lock
 * @param[in]       LockValue       New value for the lock
 * @param[out]      OldLockValue    Current value of the lock
 *
 * @return CX_TRUE  If the lock was acquired
 * @return CX_FALSE If the lock was not acquired
 */
CX_BOOL
GuestSyncTrySpinLock(
    _Inout_ volatile CX_UINT32 *Lock,
    _In_ CX_UINT32 LockValue,
    _In_opt_ CX_UINT32 *OldLockValue
    )
{
    CX_UINT32 oldValue;
    CX_BOOL result;

    if (!LockValue)
    {
        COMM_FATAL("LockValue == 0 passed to %s", __FUNCTION__);
        return CX_FALSE;   // should never reach this point
    }

    if (!Lock)
    {
        COMM_FATAL("CX_NULL lock pointer passed to %s", __FUNCTION__);
        return CX_FALSE;   // should never reach this point
    }

    if (*Lock)
    {
        return CX_FALSE;
    }

    oldValue = (CX_UINT32)_InterlockedCompareExchange((long *)Lock, LockValue, 0);

    if (OldLockValue)
    {
        *OldLockValue = oldValue;
    }

    result = (0 == oldValue);

    if (0 == oldValue)
    {
        if (LockValue != (*Lock))
        {
            COMM_FATAL("Try lock returns SUCCSESS even if not taken by it: taken as %08X, try by %08X!\n",
                    (*Lock), LockValue);
        }
    }

    return result;
}

/**
 * @brief Release the Shared Memory lock
 *
 * @param[in,out]   Lock            Lock
 *
 * @return 0 An error occured
 * @return Old value the lock
 */
CX_UINT32
GuestSyncSpinUnlock(
    _Out_ volatile CX_UINT32 *Lock
    )
{
    CX_UINT32 oldValue;

    if (!Lock)
    {
        COMM_FATAL("CX_NULL lock pointer passed to %s", __FUNCTION__);
        return 0;   // should never reach this point
    }

    oldValue = _InterlockedAnd((long*) Lock, 0);

    if (oldValue == 0)
    {
        COMM_FATAL("Unlocking already-free lock @%p!", Lock);
        return 0;   // should never reach this point
    }

    return oldValue;
}

/**
 * @brief Log a Shared Memory event in the Event Log Queue
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Event               Event to be logged
 * @param[in]   QDetail1            64 bit info
 * @param[in]   QDetail2            64 bit info
 * @param[in]   DDetail1            32 bit info
 * @param[in]   DDetail2            32 bit info
 * @param[in]   CommEvt             The previous event

 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
DbgCommLogEvt(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT8 Event,
    _In_opt_ CX_UINT64 QDetail1,
    _In_opt_ CX_UINT64 QDetail2,
    _In_opt_ CX_UINT32 DDetail1,
    _In_opt_ CX_UINT32 DDetail2,
    __out_opt PCOMM_EVT *CommEvt
    )
{
    CX_UINT32 crtPos;
    PCOMM_EVT evt;

    if (CX_NULL == SharedMem)
    {
        COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    crtPos = (CX_UINT32)_InterlockedIncrement((long *)&SharedMem->CrtEventId);
    evt = COMM_LOG_EVT_ADDR(SharedMem, crtPos);
    if (CommEvt)
    {
        *CommEvt = evt;
    }

    evt->LockValue = SharedMem->Lock;
    evt->Tsc = __rdtsc();
    evt->Comp = CRT_COMPONENT;
    evt->Event = Event;
    evt->VcpuId = (CX_UINT8)CpuGetCurrentApicId();

    evt->QDetails[0] = QDetail1;
    evt->QDetails[1] = QDetail2;
    evt->DDetails[0] = DDetail1;
    evt->DDetails[1] = DDetail2;

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Print the Event Log Queue of the Shared Memory
 *
 * @param[in]   SharedMem           Shared Memory in use
 */
void
DbgCommDumpEvtLog(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    )
{
    CX_UINT32 i, j, crtPos;

    if (SharedMem->CrtEventId == COMM_EVT_LOG_EMPTY)
    {
        COMM_INFO("[COMM-EVT] No events in the log!");
        return;
    }

    crtPos = SharedMem->CrtEventId & COMM_EVT_LOG_SIZE_MASK;

    j = 0;
    for (i = crtPos; ; i--)
    {
        PCOMM_EVT evt = COMM_LOG_EVT_ADDR(SharedMem, i);

        if ((i == ((crtPos + 1) & COMM_EVT_LOG_SIZE_MASK)) || (evt->Event == 0))
        {
            break;
        }

        COMM_INFO("[COMM-EVT-%02X] {%-12s/APIC:%02d} Event <%-16s> @ TSC:0x%016llX (Lock:%08X)",

                evt->Event, CommComponentToString(evt->Comp), evt->VcpuId,
                DbgCommEvtToString(evt->Event), evt->Tsc);

        switch (evt->Event)
        {
        case 0:
            COMM_INFO(" - bad event!\n");
            break;
        case COMM_EVT_GET_LOCK:
        case COMM_EVT_GOT_LOCK:
        case COMM_EVT_RLS_LOCK:
            COMM_INFO(" - Lock @%p\n", evt->QDetails[1]);
            break;
        case COMM_EVT_TRY_LOCK:
            COMM_INFO(" - Succeeded: %d; Lock @%p\n", !!evt->QDetails[0], evt->QDetails[1]);
            break;
        case COMM_EVT_SEND:
        case COMM_EVT_SEND_REPLY:
        case COMM_EVT_FREE:
        case COMM_EVT_DONE_MSG:
            COMM_INFO(" - Command: %s[%d]; IsResponse: %d\n",

                    CommCommandToString((CX_UINT32)evt->QDetails[0]), (CX_UINT32)evt->QDetails[1], !!evt->DDetails[0]);
            break;
        case COMM_EVT_ALLOC:
            COMM_INFO(" - Command: %s[%d]; Src: %s; Dst: %s\n",

                    CommCommandToString((CX_UINT32)evt->QDetails[0]),

                    evt->QDetails[1],

                    CommComponentToString((CX_UINT8)evt->DDetails[0]),

                    CommComponentToString((CX_UINT8)evt->DDetails[1]));
            break;
        case COMM_EVT_ALLOC_RESULT:
            COMM_INFO(" - Allocated @ %d, Handler %p, Flags: %08X\n", (CX_UINT32)evt->QDetails[0], (CX_UINT32)evt->QDetails[1], evt->DDetails[0]);
            break;
        default:
            COMM_INFO("\n");
        }

        j++;
        if (j == COMM_DEFAULT_COUNT_TO_SHOW)
        {
            break;
        }
    }
}

/**
 * @brief Convert a communication event numeric identifier to string
 *
 * @param[in] Event     - Numerical representation of the communication event
 *
 * @return String representation of the communication event
 */
const
char *
DbgCommEvtToString(
    _In_ CX_UINT8 Event
    )
{
    switch (Event)
    {
    case COMM_EVT_ALLOC:
        return "<alloc>";
    case COMM_EVT_ALLOC_RESULT:
        return "<alloc:result>";
    case COMM_EVT_FREE:
        return "<free>";
    case COMM_EVT_FREE_MOVED_HEAD:
        return "<free:move head>";
    case COMM_EVT_FREE_EMPTIED:
        return "<free:emptied>";
    case COMM_EVT_NEXT:
        return "<next>";
    case COMM_EVT_SEND:
        return "<send>";
    case COMM_EVT_SEND_REPLY:
        return "<send-reply>";
    case COMM_EVT_DONE_MSG:
        return "<done-msg>";
    case COMM_EVT_GET_LOCK:
        return "<get lock>";
    case COMM_EVT_GOT_LOCK:
        return "<got lock>";
    case COMM_EVT_TRY_LOCK:
        return "<try lock>";
    case COMM_EVT_RLS_LOCK:
        return "<rls lock>";
    case COMM_EVT_FULL_QUEUE:
        return "<full-queue>";
    default:
        return "<unknown event!>";
    }
}
