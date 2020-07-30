/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _RINGBUF_INTERFACE_H_
#define _RINGBUF_INTERFACE_H_

#include "driver.h"


#define _EMPTY_(...) __VA_ARGS__

#define COMM_INFO       _EMPTY_
#define COMM_LOG        _EMPTY_
#define COMM_FUNC_FAIL  _EMPTY_
#define COMM_ERROR      _EMPTY_
#define COMM_FATAL      _EMPTY_

#define CRT_COMPONENT ((CX_UINT32)TargetWinguestKm)


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
    return CX_TRUE;
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
    return CX_FALSE;
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
    return !gDrv.HvSleeping;
}

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
    CX_STATUS status = HvVmcall(CommandCode,
        MessageOffset, 0, 0, 0,
        CX_NULL, CX_NULL, CX_NULL, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        PLOG_FUNC_FAIL("HvVmcall", status);
    }
    return status;
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
    return DbgCommLogEvt(SharedMem, Event, QDetail1, QDetail2, DDetail1, DDetail2, CX_NULL);
}

/**
 * @brief Allocate a buffered message
 *
 * @param[in]   Size                Size of message
 * @param[out]  Message             Allocated message

 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
__forceinline
CX_STATUS
CommAllocBufferedMessage(
    _In_ CX_UINT32 Size,
    _Out_ CX_VOID **Message
)
{
    CX_UNREFERENCED_PARAMETER(Size, Message);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

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
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

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
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
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
    CX_UNREFERENCED_PARAMETER(SharedMem);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
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
    return CX_STATUS_SUCCESS;
}

#endif // _RINGBUF_INTERFACE_H_
