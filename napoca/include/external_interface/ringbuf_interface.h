/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file is providing NAPOCA custom declarations and/or definitions needed by the ringbuff.c code
//
#ifndef _RINGBUF_INTERFACE_H_
#define _RINGBUF_INTERFACE_H_

//#include "external_interface/wintypes_interface.h"
//#include "common/external_interface/wintypes_interface.h"
#include "common/communication/ringbuf.h"
#include "napoca.h"
#include "kernel/kernel.h"
#include "external_interface/kernel_interface.h"

#define COMM_INFO           INFO
#define COMM_LOG            LOG
#define COMM_FUNC_FAIL      LOG_FUNC_FAIL
#define COMM_ERROR          ERROR
#define COMM_FATAL(...)     {COMM_ERROR(__VA_ARGS__); HvHalt();}

extern SPINLOCK gCommHvSpinLock;
extern LIST_HEAD gMessageList;
extern volatile LONG gMessageListCount;

typedef struct _LST_MESSAGE_ENTRY {
    LIST_ENTRY Entry;
    COMM_MESSAGE Message;
} LST_MESSAGE_ENTRY, *PLST_MESSAGE_ENTRY;

#define CRT_COMPONENT ((CX_UINT32)TargetNapoca)


/**
 * @brief Check if Shared Memory allows blocking operations
 *
 * @return CX_TRUE  Blocking operations supported
 * @return CX_FALSE Blocking operations not supported
 */
__forceinline
CX_BOOL
CommBlockingAllowed(
    CX_VOID
)
{
    return CX_FALSE;
}

/**
 * @brief Check if Shared Memory allows buffered messages
 *
 * @return CX_TRUE  Buffered messages supported
 * @return CX_FALSE Buffered messages not supported
 */
__forceinline
CX_BOOL
CommIsBufferingEnabled(
    CX_VOID
)
{
    return CX_TRUE;
}
/**
 * @brief Check if Shared Memory operations can wait
 *
 * @return CX_TRUE  Operations can wait
 * @return CX_FALSE Operations cannot wait
 */
__forceinline
CX_BOOL
CommCanAffordToWait(
    CX_VOID
)
{
    return CX_TRUE;
}

#define LOG_COMM_QUEUE_EVENTS               1

/**
 * @brief Announce a message
 *
 * @param[in]   CommandCode         Message type
 * @param[in]   MessageOffset       Message offet in Shared Memory ringbuffer
 *
 * @return CX_STATUS_SUCCESS
 */
__forceinline
CX_STATUS
CommSignalMessage(
    _In_ COMMAND_CODE CommandCode,
    _In_ CX_SIZE_T MessageOffset
)
{
    CX_UNREFERENCED_PARAMETER(CommandCode, MessageOffset);
    return CX_STATUS_SUCCESS;
}

/**
 * @brief Announce an Event log event
 *
 * @param[in]   SharedMem           Shared Memory in use
 * @param[in]   Event               Event to be logged
 * @param[in]   QDetail1            64 bit info
 * @param[in]   QDetail2            64 bit info
 * @param[in]   DDetail1            32 bit info
 * @param[in]   DDetail2            32 bit info
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
__forceinline
CX_STATUS
CommSignalEvent(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT8 Event,
    _In_opt_ CX_UINT64 QDetail1,
    _In_opt_ CX_UINT64 QDetail2,
    _In_opt_ CX_UINT32 DDetail1,
    _In_opt_ CX_UINT32 DDetail2
)
{
    if (Event == COMM_EVT_FULL_QUEUE)
    {
        DbgCommDumpEvtLog(SharedMem);
    }

    return DbgCommLogEvt(SharedMem, Event, QDetail1, QDetail2, DDetail1, DDetail2, CX_NULL);
}

CX_STATUS
CommAllocBufferedMessage(
    _In_ CX_UINT32 Size,
    _Out_ CX_VOID **Message
);


/**
 * @brief Commit Buffered Message
 *
 * @return CX_STATUS_SUCCESS
 */
__forceinline
CX_STATUS
CommCommitBufferedMessage(
    CX_VOID
)
{
    HvReleaseSpinLock(&gCommHvSpinLock);
    return CX_STATUS_SUCCESS;
}

CX_STATUS
CommFlushBufferedMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem
);

/**
 * @brief Print Buffered messages information
 *
 * @return CX_STATUS_SUCCESS
 */
__forceinline
CX_STATUS
CommDumpBufferedMessages(
    CX_VOID
)
{
    if (!IsListEmpty(&gMessageList))
    {

        PLST_MESSAGE_ENTRY entry = (PLST_MESSAGE_ENTRY)gMessageList.Flink;

        HvPrint("In cache ring buffer:\n");
        while ((LIST_ENTRY*)entry != &gMessageList)
        {
            // it's not in shared mem
            CommDumpMessageInfo(CX_NULL, &entry->Message);

            entry = (PLST_MESSAGE_ENTRY)entry->Entry.Flink;
        }
    }
    return CX_STATUS_SUCCESS;
}

/**
 * @brief Custom extra steps for Shared Memory initialization
 *
 * @return CX_STATUS_SUCCESS
 */
__forceinline
CX_STATUS
CommInitCustom(
    CX_VOID
)
{
    HvInitSpinLock(&gCommHvSpinLock, "gCommHvSpinLock", CX_NULL);
    InitializeListHead(&gMessageList);
    gMessageListCount = 0;
    return CX_STATUS_SUCCESS;
}

#endif // _RINGBUF_INTERFACE_H_
