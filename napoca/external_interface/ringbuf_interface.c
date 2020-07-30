/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "common/communication/ringbuf.h"
#include "external_interface/kernel_interface.h"
#include "external_interface/ringbuf_interface.h"

// the next files are included only for checking for consistency between the externally provided header and the expected documented interface
#include "common/external_interface/kernel_interface.h"
#include "common/external_interface/ringbuf_interface.h"


// these are actually a single-instance variables as they're included by only a single C (or a handful of C 'common' files at most)
SPINLOCK gCommHvSpinLock;
LIST_HEAD gMessageList;
volatile LONG gMessageListCount;


/**
 * @brief Allocate a buffered message
 *
 * @param[in]   Size                Size of message
 * @param[out]  Message             Allocated message

 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommAllocBufferedMessage(
    _In_ CX_UINT32 Size,
    _Out_ CX_VOID **Message
)
{
    PLST_MESSAGE_ENTRY entry = CX_NULL;
    CX_UINT32 cachedCount = 0;
    CX_STATUS status;

    HvAcquireSpinLock(&gCommHvSpinLock);
    cachedCount = gMessageListCount;
    HvReleaseSpinLock(&gCommHvSpinLock);

    if (100 < cachedCount)
    {
        status = STATUS_SHMEM_LIMIT_REACHED;
        goto done;
    }

    status = HpAllocWithTagAndInfo(&entry, sizeof(LIST_ENTRY) + Size, 0, TAG_COM);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagAndInfo", status);
        goto done;
    }

    HvAcquireSpinLock(&gCommHvSpinLock);
    InsertTailList(&gMessageList, &entry->Entry);

    gMessageListCount++;
    *Message = &entry->Message;

done:
    return status;
}

/**
 * @brief Try to reinsert previously inserted messages. Called on each guest exit.
 *
 * @param[in]   SharedMem           Shared Memory in use

 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
CommFlushBufferedMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    PCOMM_MESSAGE msg = CX_NULL;
    CX_UINT32 offset;
    CX_BOOL availableMem = CX_FALSE;
    CX_UINT32 freeSpace = 0;
    LIST_ENTRY *list;
    CPU_IRQL irql = 0;
    CPU_IRQL *oldIrql = &irql;

    if (CX_NULL == SharedMem)
    {
        //COMM_ERROR("CX_NULL SharedMem passed to %s()!\n", __FUNCTION__);
        status = CX_STATUS_INVALID_PARAMETER_1;
        return status;
    }

    if (!SharedMem->Initialized)
    {
        //COMM_ERROR("Shared memory not initialized in call to %s()!\n", __FUNCTION__);
        status = CX_STATUS_NOT_INITIALIZED;
        return status;
    }

    if (IsListEmpty(&gMessageList))
    {
        return CX_STATUS_SUCCESS;
    }

    HvAcquireSpinLock(&gCommHvSpinLock);
    status = CommMemLock(SharedMem, oldIrql);
    if (!CX_SUCCESS(status))
    {
        goto done;
    }

    CommRemoveAllCompleted(SharedMem);

    if (1 == SharedMem->DenyAlloc)
    {
        //COMM_LOG("Alloc is denied\n");
        status = CX_STATUS_ACCESS_DENIED;
        goto unlock;
    }

    // The lock is taken, so it's safe to iterate the list
    list = gMessageList.Flink;
    ///while(!IsListEmpty(&gMessageList))
    while (list != &gMessageList)
    {
        CX_UINT8 oldMsgStatus = 0;
        ///PLST_MESSAGE_ENTRY entry = (PLST_MESSAGE_ENTRY)RemoveHeadList(&gMessageList);
        PLST_MESSAGE_ENTRY entry = CONTAINING_RECORD(list, LST_MESSAGE_ENTRY, Entry);
        list = list->Flink;

        if (COMM_STATUS_READY != entry->Message.Status)
        {
            // wait until someone is sending the message
            ///InsertHeadList(&gMessageList, &entry->Entry);
            ///break;
            continue;
        }

        availableMem = CX_FALSE;
        status = CommMemGetFreeMem(SharedMem, &freeSpace, CX_TRUE);
        if (CX_SUCCESS(status) && freeSpace > entry->Message.Size)
        {
            availableMem = CX_TRUE;
        }

        if (CX_FALSE == availableMem)
        {
            ///InsertHeadList(&gMessageList, &entry->Entry);
            ///break;
            break;
        }

        /// check if enough *continuous* space is available
        status = CommGetNextOffset(SharedMem, entry->Message.Size, &offset);
        if (!CX_SUCCESS(status))
        {
            ///COMM_ERROR("Attempted message: %s\n", CommCommandToString(entry->Message.CommandCode));
            offset = 0;
            break;
        }

        if (offset)
        {
            msg = (PCOMM_MESSAGE)((CX_UINT8*)SharedMem + offset);
            //LOGN("reinserting message: 0x%08X, offset: 0x%08X\n", entry->Message.CommandCode, offset);
            // set status to undefined
            oldMsgStatus = entry->Message.Status;
            entry->Message.Status = COMM_STATUS_UNDEFINED;

            // copy message body
            memcpy(msg, &entry->Message, entry->Message.Size);

            //restore status
            msg->Status = oldMsgStatus;

            CommGuestForwardMessage(msg);

            RemoveEntryList(&entry->Entry);
            gMessageListCount--;

            status = HpFreeAndNullWithTag(&entry, TAG_COM);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HpFreeAndNullWithTag", status);
            }
        }
        else
        {
            ///InsertHeadList(&gMessageList, &entry->Entry);
            ///break;
            continue;
        }
    }
unlock:
    CommMemUnlock(SharedMem, oldIrql);

done:
    HvReleaseSpinLock(&gCommHvSpinLock);

    return status;
}