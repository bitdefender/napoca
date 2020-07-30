/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
//  HV-Guest communication
//
//  WARNING! This header is also included in:
//      * winguest.sys (Hypervisor Control guest driver)
//      * falx.sys (Hypervisor Test guest driver)
//      * Napoca (HV)
//  Please keep in mind:
//      * use BDHV-specific prefixes on names so as not to collide with kernel internal names
//      * use standard C datatypes
//      * only define types, constants & structs which are relevant to the host-guest communication
//

#ifndef _RINGBUF_H_
#define _RINGBUF_H_

#include "cx_native.h"
#include "common/boot/loader_interface.h"


#define LOG_COMM_QUEUE_EVENTS               1
#define COMM_HV_GUEST_PROTOCOL_VER          1   ///< Communication protocol version. Increment this whenever the protocol/structs change!


// Shared memory usage
// |--------------------------------------------------------------------|
// |                             32 MB                                  |
// |-------------------+------------------------------------------------|
// | COMM_SHMEM_HEADER |                    Packets                     |
// |-------------------+------------------------------------------------|
// |                   |       |       |     |       |                  |
// |       64 B        | Free  | Pack1 | ... | PackN |       Free       |
// |                   |       |       |     |       |                  |
// |-------------------+------------------------------------------------|
// |                           |<Head           Tail>|                  |
// L--------------------------------------------------------------------|
//


#define MAX_MESSAGE_SIZE                0x0000FFFF          ///< the maximum length of an input message - needed for winguest communication with UM
#define SHARED_MEM_SIZE                 NAPOCA_MEM_SHARED_BUFFER

typedef CX_UINT32                           COMMAND_CODE;
typedef CX_UINT8                            COMM_COMPONENT;

#pragma pack(push)
#pragma pack(8)         // Packing is MANDATORY to be exactly the same for all components involved
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
typedef struct _COMM_SHMEM_HEADER {
    volatile CX_UINT32      Magic;                  ///< Set to #SHARED_MEM_MAGIC for basic integrity validation
    volatile CX_UINT8       CommVersion;            ///< Set to #COMM_HV_GUEST_PROTOCOL_VER
    union {
        volatile CX_UINT8    ShmemFlags;
        struct {
            volatile CX_UINT8   Initialized : 1;    ///< Confirms the shared memory is initialized
            volatile CX_UINT8   Frozen : 1;         ///< Pause Message allocation and consumption
            volatile CX_UINT8   DenyAlloc : 1;      ///< Prevent new message allocations
        };
    };
    CX_UINT8       Reserved1[2];
    volatile CX_UINT32  Size;                       ///< Size of shared memory
    volatile CX_UINT32  Head;                       ///< First occupied offset, 0 if empty
    volatile CX_UINT32  Tail;                       ///< First available offset
    volatile CX_UINT32  Lock;                       ///< Custom spinlock to be used with GuestSyncSpin(Un)Lock
    volatile CX_UINT32  LockOwner;                  ///< Owner of Lock
    volatile CX_UINT32  GuestICR;                   ///< Each client has 1 bit reserved
    volatile CX_UINT32  CrtEventId;                 ///< Increments on each log in the Event Log
    volatile CX_UINT32  CrtMsgId;                   ///< Increments on each message to enable message counting and ordering
             CX_UINT8   Reserved[24];               ///< Alignment to 64
} COMM_SHMEM_HEADER, *PCOMM_SHMEM_HEADER;

static_assert (sizeof(COMM_SHMEM_HEADER) == 64, "size of COMM_SHMEM_HEADER changed");

//
// COMM_MESSAGE: Basic (template) communication message (the CMD_* structures below extend this one).
//
typedef struct _COMM_MESSAGE {
    volatile CX_UINT32      SeqNum;                 ///< Taken from #COMM_SHMEM_HEADER.CrtMsgId
    volatile CX_UINT32      Size;                   ///< Size of full message (containing this embedded COMM_MESSAGE)
    volatile COMMAND_CODE   CommandCode;            ///< Message type identifier
    volatile CX_UINT32      Flags;                  ///< Message Processing related flags
    volatile COMM_COMPONENT SrcComponent;           ///< Source component
    volatile COMM_COMPONENT DstComponent;           ///< Destination component
    volatile CX_UINT8       Status;                 ///< Message delivery status (CMD_STATUS_*)
             CX_UINT8       Reserved1;
    volatile CX_STATUS      ProcessingStatus;       ///< Message processing status
             CX_UINT8       Reserved[8];            ///< align to 32, struct is not tightly packed!
} COMM_MESSAGE, *PCOMM_MESSAGE;

static_assert (sizeof(COMM_MESSAGE) == 32, "size of COMM_MESSAGE changed");
#pragma warning(pop)
#pragma pack(pop)

// ringbuffer internal statuses
#define COMM_STATUS_UNDEFINED           0x00            ///< Allocated, not initialized
#define COMM_STATUS_READY               0x01            ///< Request filled in, ready to be processed
#define COMM_STATUS_PROCESSING          0x02            ///< Request is assigned & being processed
#define COMM_STATUS_PROCESSED           0x03            ///< Freed; waiting to be garbage-collected
#define COMM_STATUS_WAITING             0x04            ///< Waiting for an async complete
#define COMM_STATUS_INVALID             0x05            ///< Invalid; should be acknowledged & freed

// ringbuffer internal flags
#define COMM_FLG_IS_REPLY               0x00000001      ///< The message is a reply
#define COMM_FLG_EXPECTS_REPLY          0x00000002      ///< The message needs a reply
#define COMM_FLG_RECEIVED_REPLY         0x00000004      ///< The message received a reply
#define COMM_FLG_NO_AUTO_FREE           0x00000008      ///< The (reply) message is not automatically freed
#define COMM_FLG_IS_NON_CORE_MESSAGE    0x00000010      ///< The message is less crucial and will not be allocated if ringbuffer is less than 10% free

#define COMM_IS_REPLY(Message) (((PCOMM_MESSAGE)Message)->Flags & COMM_FLG_IS_REPLY)
#define COMM_NEEDS_REPLY(Message) ( (((PCOMM_MESSAGE)Message)->Flags & COMM_FLG_EXPECTS_REPLY) && (!COMM_IS_REPLY(Message)) )


#define COMM_ALIGN(x) CX_ROUND_UP((x), 8)
#define COMM_SHMEM_EMPTY(ShMem) (!(ShMem)->Head)
#define COMM_SHMEM_FULL(ShMem) ((ShMem)->Head && ((ShMem)->Head == (ShMem)->Tail))
#define COMM_SHMEM_HEADER_SIZE ((CX_UINT32)sizeof(COMM_SHMEM_HEADER))
#define COMM_SHMEM_USABLE(ShMem) ((ShMem)->Size - COMM_SHMEM_HEADER_SIZE)
#define COMM_SHMEM_FIX_OFFSET(ShMem, Offset) (COMM_SHMEM_HEADER_SIZE + COMM_ALIGN((((CX_UINT32)(Offset) - COMM_SHMEM_HEADER_SIZE) % COMM_SHMEM_USABLE(ShMem))))

#define COMM_SHMEM_INV_TAIL             1

CX_UINT32
GuestSyncSpinLock(
    _Inout_ volatile CX_UINT32 *Lock,
    _In_ CX_UINT32 LockValue
    );

CX_STATUS
CommGetNextOffset(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT32 Size,
    _Inout_ CX_UINT32 *Offset
);

CX_STATUS
CommMemLock(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Out_ CX_VOID *OldIrql
);

CX_STATUS
CommMemUnlock(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_VOID *OldIrql
);

CX_VOID
CommRemoveAllCompleted(
    _In_ PCOMM_SHMEM_HEADER SharedMem
);

CX_STATUS
CommGuestForwardMessage(
    _In_ PCOMM_MESSAGE Msg
);

CX_STATUS
CommTryReinsertMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_BOOL
GuestSyncTrySpinLock(
    _Inout_ volatile CX_UINT32 *Lock,
    _In_ CX_UINT32 LockValue,
    _In_opt_ CX_UINT32 *OldLockValue
    );

CX_UINT32
GuestSyncSpinUnlock(
    _Out_ volatile CX_UINT32 *Lock
    );


/// shared mem. (ring buffer) API

CX_STATUS
CommInitSharedMem(
    _In_ CX_UINT32 Size,
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommUninitSharedMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommPrepareUninitSharedMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_BOOL WaitForQueueToBeEmpty
    );

CX_STATUS
CommUnfreezeSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommFreezeSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommIsFrozenSharedMem(
    _Inout_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ CX_BOOL *Frozen
    );

CX_STATUS
CommAllocMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ COMMAND_CODE CommandCode,
    _In_ CX_UINT32 CommandFlags,
    _In_ COMM_COMPONENT DstComponent,
    _In_opt_ COMM_COMPONENT SrcComponent,
    _In_ CX_UINT32 Size,
    _Out_ PCOMM_MESSAGE *Message
    );

CX_STATUS
CommForwardMessage(
    _Inout_ PCOMM_MESSAGE Message,
    _In_ COMM_COMPONENT DstComponent
    );

CX_STATUS
CommSendMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ PCOMM_MESSAGE Message
    );

CX_STATUS
CommSendReply(
    _Inout_ PCOMM_MESSAGE Message
    );

CX_STATUS
CommFreeMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ PCOMM_MESSAGE Message
    );

CX_STATUS
CommGetNextMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ COMM_COMPONENT Component,
    _Out_ volatile PCOMM_MESSAGE *Message
    );

CX_STATUS
CommMemGetFreeMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Inout_ CX_UINT32 *FreeSpace,
    _In_ CX_BOOL Lockless
    );

/// debugging

const
char *
CommStatusToString(
    _In_ CX_UINT8 Status
    );

CX_STATUS
CommDumpQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommFillQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
CommDoneMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    );

CX_BOOL
CommMessageIsInQueue(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    );

CX_BOOL
CommIsValidMessage(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    );

void
CommDumpMessageInfo(
    _In_opt_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ PCOMM_MESSAGE Message
    );

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
    );

CX_STATUS
CommCanFreeShMem(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _Out_ CX_BOOL* CanFree
    );

//================= Communication event logging (debugging) ==================//


#if LOG_COMM_QUEUE_EVENTS
#define COMM_EVT_LOG_SIZE               0x1000
#else
#define COMM_EVT_LOG_SIZE               0
#endif


#define COMM_EVT_LOG_EMPTY              0xFFFFFFFF
#define COMM_EVT_LOG_SIZE_MASK          ((COMM_EVT_LOG_SIZE) - 1)
#define COMM_EVT_LOG_OFFS               ((SHARED_MEM_SIZE) - (COMM_EVT_LOG_SIZE))
#define COMM_DEFAULT_COUNT_TO_SHOW      30

#define COMM_EVT_ALLOC                  0x10
#define COMM_EVT_ALLOC_RESULT           0x11
#define COMM_EVT_FREE                   0x20
#define COMM_EVT_FREE_MOVED_HEAD        0x21
#define COMM_EVT_FREE_EMPTIED           0x22
#define COMM_EVT_NEXT                   0x30
#define COMM_EVT_SEND                   0x40
#define COMM_EVT_SEND_REPLY             0x41
#define COMM_EVT_DONE_MSG               0x50
#define COMM_EVT_GET_LOCK               0xF0
#define COMM_EVT_GOT_LOCK               0xF1
#define COMM_EVT_TRY_LOCK               0xF2
#define COMM_EVT_RLS_LOCK               0xF3
#define COMM_EVT_FULL_QUEUE             0xF4

#define COMM_LOG_EVT_ADDR(SharedMem, Index) ((PCOMM_EVT)((CX_UINT8*)SharedMem + COMM_EVT_LOG_OFFS + ((Index) * sizeof(COMM_EVT) & COMM_EVT_LOG_SIZE_MASK)))

#pragma pack(push)
#pragma pack(8)

typedef struct _COMM_EVT {
    CX_UINT64           Tsc;
    CX_UINT64           QDetails[2];
    CX_UINT32           DDetails[2];
    CX_UINT32           LockValue;
    COMM_COMPONENT      Comp;
    CX_UINT8            Event;
    CX_UINT8            VcpuId;
    CX_UINT8            Reserved[25]; // align to 64
} COMM_EVT, *PCOMM_EVT;

static_assert (sizeof(COMM_EVT) == 64, "size of COMM_EVT changed");

#pragma pack(pop)


const
char *
DbgCommEvtToString(
    _In_ CX_UINT8 Event
    );

void
DbgCommDumpEvtLog(
    _In_ PCOMM_SHMEM_HEADER SharedMem
    );

CX_STATUS
DbgCommLogEvt(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT8 Event,
    _In_opt_ CX_UINT64 QDetail1,
    _In_opt_ CX_UINT64 QDetail2,
    _In_opt_ CX_UINT32 DDetail1,
    _In_opt_ CX_UINT32 DDetail2,
    __out_opt PCOMM_EVT *CommEvt
    );

#endif //_RINGBUF_H_
