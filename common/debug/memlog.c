/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file memlog.c
*   @brief MEMLOG - Memory log support
*
*/
#include "common/debug/memlog.h"

// forward declaration
CX_VOID* __cdecl
memcpy(
    __out_bcount_full_opt(Size) CX_VOID *Dest,
    __in_bcount_opt(Size) const CX_VOID *Source,
    _In_ CX_SIZE_T Size
);

/**
 * @brief Append information to the memory log
 *
 * @param[in]  Log          Memory logger used
 * @param[in]  Buffer       Buffer to append
 * @param[in]  Length       Size of Buffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
CX_STATUS
MemLogAppend(
    _In_ MEMORY_LOG *Log,
    _In_ CX_INT8 *Buffer,
    _In_ CX_UINT32 Length
    )
{
    CX_BOOL rollover = CX_FALSE;

    if (!Log) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Log->Initialized) return CX_STATUS_NOT_INITIALIZED;

    if (Log->Circular && Length > Log->BufferSize)
    {
        Buffer = Buffer + Length - Log->BufferSize;
        Length = Log->BufferSize;
    }

    if ((Log->BufferWritePos + Length) > Log->BufferSize)
    {
        rollover = CX_TRUE;
        if (!Log->Circular) return CX_STATUS_SUCCESS;
    }

    CX_UINT32 freeSpace = Log->BufferSize - Log->BufferWritePos;

    memcpy(Log->Buffer + Log->BufferWritePos, Buffer, rollover ? freeSpace : Length);

    Log->BufferWritePos += rollover ? freeSpace : Length;

    if (!Log->Circular) return CX_STATUS_SUCCESS;

    Length -= rollover ? Log->BufferSize - Log->BufferWritePos : Length;

    if(Length > 0)
    {
        memcpy(Log->Buffer, Buffer, Length);

        Log->BufferWritePos = Length;
        Log->BufferRollover = CX_TRUE;
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Retrieve information about a memory logger (Starting position and size of log)
 *
 * @param[in]     Log           Memory logger used
 * @param[in,out] StartPos      Last read position. If set to MEMLOG_NO_OFFSET, will return the start of the memory log data
 * @param[out]    Length        Size of new information (according to the last read position)
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
CX_STATUS
GetLogInfo(
    _In_    MEMORY_LOG *Log,
    _Inout_ CX_UINT32 *StartPos,
    _Out_   CX_UINT32 *Length
    )
{
    if (!Log) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Log->Initialized) return CX_STATUS_NOT_INITIALIZED;
    if (!StartPos) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Length) return CX_STATUS_INVALID_PARAMETER_3;

    if (*StartPos == MEMLOG_NO_OFFSET)
    {
        if (Log->Circular && Log->BufferRollover)
        {
            *StartPos = Log->BufferWritePos % Log->BufferSize;
            *Length = Log->BufferSize;
        }
        else
        {
            *StartPos = 0;
            *Length = Log->BufferWritePos;
        }
    }
    else
    {
        if (Log->Circular || *StartPos % Log->BufferSize) // without check, linear buffers reset and always return full log.
        {
            *StartPos %= Log->BufferSize;
        }

        if (*StartPos == Log->BufferWritePos || (*StartPos > Log->BufferWritePos && !Log->BufferRollover))
        {
            *Length = 0;
        }
        else
        {
            if(*StartPos < Log->BufferWritePos) *Length = Log->BufferWritePos - *StartPos;
            else *Length = Log->BufferWritePos + (Log->BufferSize - *StartPos);
        }
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Retrieve a piece of the memory log
 *
 * @param[in]  Log              Memory logger used
 * @param[in]  Offset           Position from where the read will start
 * @param[out] Length           Size of information requested
 * @param[out] Buffer           Buffer to store the requested log
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
CX_STATUS
GetLogChunk(
    _In_  MEMORY_LOG *Log,
    _In_  CX_UINT32 Offset,
    _In_  CX_UINT32 Length,
    _Out_ CX_UINT8 *Buffer
    )
{
    if (!Log) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Log->Initialized) return CX_STATUS_NOT_INITIALIZED;
    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_4;

    Offset %= Log->BufferSize;

    if (Offset + Length <= Log->BufferSize)
    {
        memcpy(Buffer, Log->Buffer + Offset, Length);
    }
    else
    {
        memcpy(Buffer, Log->Buffer + Offset, Log->BufferSize - Offset);
        memcpy(Buffer + Log->BufferSize - Offset, Log->Buffer, (Length - (Log->BufferSize - Offset)) % Log->BufferSize);
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Reset a memory logger
 *
 * @param[in]  Log              Memory logger used
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
CX_STATUS
MemLogClear(
    _In_ MEMORY_LOG *Log
    )
{
    if (!Log) return CX_STATUS_INVALID_PARAMETER_1;

    Log->BufferWritePos = 0;
    Log->BufferRollover = CX_FALSE;

    return CX_STATUS_SUCCESS;
}

///@}