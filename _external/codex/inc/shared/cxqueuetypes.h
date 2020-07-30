/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __cxqueuetypes_h__
#define __cxqueuetypes_h__

#include "native/cx_status_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "cx_shared.h"

#define COMM_QUEUE_IOCTL_CODE                           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define COMM_QUEUE_INVERTED_IOCTL_CODE                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define COMM_QUEUE_REPLY_IOCTL_CODE                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// for legacy ioctls from petru port
#define LEGACY_PORT_IOCTL_CODE                          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8BD, METHOD_BUFFERED, FILE_ANY_ACCESS)

//for projects integrating Codex for communication, port and device names must
//be defined here, to avoid any possible conflict with other drivers
//talk to Codex developers if new device/port name is needed
#define CODEX_DEVICE_NATIVE_NAME    L"\\Device\\CodexComm"
#define CODEX_DEVICE_USER_NAME      L"\\Global??\\CodexComm"

#define COMM_DEVICE_NATIVE_NAME     L"\\Device\\WinguestComm"
#define COMM_DEVICE_USER_NAME       L"\\Global??\\WinguestComm"

#define WINGUEST_DEVICE_NATIVE_NAME L"\\Device\\WinguestComm"
#define WINGUEST_DEVICE_USER_NAME   L"\\Global??\\WinguestComm"

#define FALX_DEVICE_NATIVE_NAME     L"\\Device\\FalxComm"
#define FALX_DEVICE_USER_NAME       L"\\Global??\\FalxComm"

#define ATC_DEVICE_NATIVE_NAME      L"\\Device\\AtcComm"
#define ATC_DEVICE_USER_NAME        L"\\Global??\\AtcComm"

#define GEMMA_DEVICE_NATIVE_NAME    L"\\Device\\GemmaComm"
#define GEMMA_DEVICE_USER_NAME      L"\\Global??\\GemmaComm"
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
#pragma pack(push, 8)
typedef struct _CX_COMM_MESSSAGE_HEADER
{
    UINT32 MessageCode;         // value used to identify the message that is being sent and provide an indication on what action to be performed
    NTSTATUS MessageStatus;       // value used to provide a status on the processing of this message
}CX_COMM_MESSSAGE_HEADER, *PCX_COMM_MESSSAGE_HEADER;

typedef struct _CX_COMM_MESSAGE
{
    CX_COMM_MESSSAGE_HEADER Header; // mandatory header for all messages; it has meaning only for end-points of the communication channel
    // user data here
}CX_COMM_MESSAGE, *PCX_COMM_MESSAGE;

typedef struct _COMM_INVERTED_HEADER
{
    UINT64 Sequence;                     // message id to be used in replies
    NTSTATUS Status;                    // status from driver in case the buffer is not big enough or a reply is requested
//     UINT32 BufferSize;                   // including header
//     UINT32 RequestedSize;                // including header
}COMM_INVERTED_HEADER, *PCOMM_INVERTED_HEADER;

typedef struct _COMM_INVERTED_MESSAGE
{
    COMM_INVERTED_HEADER Header;
    // user data here
}COMM_INVERTED_MESSAGE, *PCOMM_INVERTED_MESSAGE;
#pragma pack(pop)

#define CX_COMMUNICATION_QUEUE_MIN_MESSAGE_SIZE     32
#define CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE     (256 * 1024)

//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+

/// shouldn't we simply include the CodexNative definition instead of re-defining ?
/// if redefined, there would be compile errors if cx_native.h gets included at some point...
#define CX_STATUS_QUEUE_COMM_SUCCESS                    (0x0L)

// error
#define CX_STATUS_QUEUE_COMM_BUFFER_TO_SMALL            CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x1)
#define CX_STATUS_QUEUE_COMM_REQUEST_REPLY              CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x2)
#define CX_STATUS_QUEUE_COMM_BUFFER_TOO_BIG             CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x3)
#define CX_STATUS_QUEUE_COMM_REPLY_COMPLETE             CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x4)
#define CX_STATUS_QUEUE_COMM_MSG_REPLY_NOT_SUPPORTED    CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x5)
#define CX_STATUS_QUEUE_COMM_REPLY_FAILED               CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x6)

#ifdef __cplusplus
}
#endif

#endif //__cxqueuetypes_h__
