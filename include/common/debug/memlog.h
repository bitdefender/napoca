/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file memlog.h
*   @brief MEMLOG - Memory log support
*
*/

#ifndef __MEMLOG_H__
#define __MEMLOG_H__

#include "cx_native.h"

#define FEEDBACK_VERSION        1             ///< feedback version used for validation purposes (denotes the version of the memory logger)
#define MEMLOG_NO_OFFSET        0xFFFFFFFF    ///< used to specify for GetLogInfo to determine automatically the starting offset for the logs (from their start)

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

/// @brief Structure containing a circular buffer for logs stored in memory and everything needed for the management of the buffer.
typedef struct _MEMORY_LOG
{
    CX_UINT32   BufferSize;                 ///< size of the buffer (w/out header)
    CX_UINT32   BufferWritePos;             ///< offset of last byte written in buffer
    union
    {
        CX_UINT8 Flags;
        struct
        {
            CX_UINT8    Initialized : 1;            ///< Buffer initialized
            CX_UINT8    Circular : 1;               ///< Buffer is circular
            CX_UINT8    BufferRollover : 1;         ///< Buffer size exceeded, rollover occurred
        };
    };
    CX_INT8    Buffer[1];                    ///< The memory log buffer containing the logs
} MEMORY_LOG;

/// @brief Hyper-visor feedback header, containing the logs of the HV stored inside a special circular memory buffer and version information
typedef struct _HV_FEEDBACK_HEADER
{
    CX_UINT32   Version;                    ///< version info
    // Add new fields here as MEMORY_LOG contains an undefined sized buffer

    MEMORY_LOG  Logger;                     ///< our memory logger
} HV_FEEDBACK_HEADER;
#pragma warning(pop)



///
/// @brief        Append to the logs stored in memory the logs stored in Buffer.
///
/// @param[in]    Log                              The #MEMORY_LOG which stores the logs in circular buffer
/// @param[in]    Buffer                           The buffer containing the new logs to append inside the circular Log buffer.
/// @param[in]    Length                           The length in bytes of Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the Log is invalid
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - in case the address of the Buffer is invalid
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the address of the Log is not initialized
///
CX_STATUS
MemLogAppend(
    _In_ MEMORY_LOG *Log,
    _In_ CX_INT8 *Buffer,
    _In_ CX_UINT32 Length
);



///
/// @brief        Retrieves the content of the memory logs, either by the starting position given as StartPos or from the start of the buffer.
///
/// @param[in]      Log                            The #MEMORY_LOG which stores the logs in circular buffer
/// @param[in, out] StartPos                       The given starting position inside the buffer or #MEMLOG_NO_OFFSET, the real starting offset is returned after the function completes
/// @param[out]     Length                         The length of the logs starting from StartPos until the end of the #MEMORY_LOG buffer
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the Log is invalid
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - in case the address of the StarPos is invalid
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - in case the address of the Length is invalid
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the address of the Log is not initialized
///
CX_STATUS
GetLogInfo(
    _In_    MEMORY_LOG *Log,
    _Inout_ CX_UINT32 *StartPos,
    _Out_   CX_UINT32 *Length
);



///
/// @brief        Retrieves the content of the memory logs, starting from Offset an entire chunk of Size bytes if possible and copies it to Buffer.
///
/// @param[in]    Log                              The #MEMORY_LOG which stores the logs in circular buffer
/// @param[in]    Offset                           The given starting position inside the buffer, from where to take the chunk
/// @param[in]    Size                             The size in bytes of the retrieved chunk of logs
/// @param[out]   Buffer                           The buffer inside which the chunk will be returned
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the Log is invalid
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - in case the address of the Buffer is invalid
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the address of the Log is not initialized
///
CX_STATUS
GetLogChunk(
    _In_  MEMORY_LOG *Log,
    _In_  CX_UINT32 Offset,
    _In_  CX_UINT32 Size,
    _Out_ CX_UINT8 *Buffer
);



///
/// @brief        Resets the #MEMORY_LOG structure to point to the beginning of the buffer and resets rollover.
///
/// @param[in]    Log                              The #MEMORY_LOG which stores the logs in circular buffer
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the Log is invalid
///
CX_STATUS
MemLogClear(
    _In_ MEMORY_LOG *Log
);

#endif //__MEMLOG_H__

///@}