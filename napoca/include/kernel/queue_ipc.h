/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup ipc
/// @{

#ifndef _QUEUE_IPC_H_
#define _QUEUE_IPC_H_

#include "data_structures/cx_lockless_queue.h"
#include "core.h"
#include "kernel.h"
#include "kernel/interrupt.h"
#include "kernel/pcpu.h"
#include "kernel/queue_ipc_common.h"


#define IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS           (5 * ONE_SECOND_IN_MICROSECONDS)   //< Time for acknowledging queue is not responsive
#define IPC_QUEUE_RESEND_INTERRUPT_TIMEOUT_IN_MICROSECONDS   (1 /* microseconds */ )            //< Time before retrying to interrupt a unresponsive cpu

// Shorthand for IPC destinations
typedef enum
{
    IPC_DESTINATION_CPU_POINTER,                ///< Destination is given as a CPU structure pointer
    IPC_DESTINATION_BOOT_CPU_INDEX,             ///< Destination is given as a Boot CPU index
    IPC_DESTINATION_LAPIC_ID,                   ///< Destination is given as lapic ID
    IPC_DESTINATION_BY_CPU_AFFINITY,            ///< Destination is given as a bitmap denoting the id of the CPUs required to be interrupted
    IPC_DESTINATION_ALL_CPUS_INCLUDING_SELF,    ///< Destination are all CPUs in the system
    IPC_DESTINATION_ALL_CPUS_EXCLUDING_SELF,    ///< Destination are all CPUs in the system excluding the emitting one
    IPC_DESTINATION_SELF                        ///< Destination is the emitter itself
}IPC_DESTINATION_MODE;

typedef struct
{
    IPC_DESTINATION_MODE DestinationMode;
    union
    {
        PVOID CpuPointer;
        DWORD CpuBootIndex;
        DWORD LapicId;
        QWORD CpuAffinity;
        QWORD Raw;
    }Id;
}IPC_CPU_DESTINATION; ///< IPC Destination structure

typedef enum
{
    IPC_WAIT_COMPLETION_NONE,       ///< never wait
    IPC_WAIT_COMPLETION_FORCED,     ///< ALWAYS wait
    IPC_WAIT_COMPLETION_BEST_EFFORT ///< wait only when the cpus are interruptible
}IPC_WAIT_COMPLETION;

#define IpcSendCpuMessage(...) IpcSendCpuMessage2(__VA_ARGS__, __FILE__, __LINE__)  ///< Wrapper for IpcSendCpuMessage2

/**
 * @brief           Sends IPC messages to other CPUs, can be configured to wait for acknowledgement.
 * @brief           The IPC system uses 3 per-CPU message queues, each denoting a priority level.
 * @brief           This method inserts a given message into the queue and potentially waits for a response.
 * @brief           WARNING: This method if not used correctly has the potential of getting stuck in an infinite cycle!
 *
 * @param[in]       *Message                    Message to be sent
 * @param[in]       Destination                 Target CPU of the message
 * @param[in]       MessagePriority             Priority of the message
 * @param[in]       DoInterruptCpus             Send an interrupt to the target CPUs in order to make them process their IPC queues
 * @param[in]       WaitForCompletion           Block the current CPU execution until all targeted CPUs have processed their messages
 * @param[in]       DropMessageOnFullQueue      Allows for the message to be dropped if a target-CPU's message queue is full
 * @param[in]       File                        The file name from where the method was called. Used in logs
 * @param[in]       Line                        The line from where the method was called. Used in logs
 *
 * @return          CX_STATUS_SUCCESS           The method executed successfully
 * @return          CX_STATUS_ABANDONED         The message was inserted in the target CPU(s) queue, but due to external factors, an acknowledgement cannot be waited upon
 * @return          otherwise                   Error
 */
NTSTATUS
IpcSendCpuMessage2(
    _In_ IPC_MESSAGE            *Message,
    _In_ IPC_CPU_DESTINATION    Destination,
    _In_ IPC_PRIORITY           MessagePriority,
    _In_ BOOLEAN                DoInterruptCpus,    // send an interrupt for quicker response
    _In_ IPC_WAIT_COMPLETION    WaitForCompletion,
    _In_ BOOLEAN                DropMessageOnFullQueue,
    _In_ char                   *File,
    _In_ DWORD                  Line
);

/**
 * @brief           Iterates the current cpu's message queues and process each one which comply with the IPC settings
 *
 * @param[in]       Cpu                                 Pointer to the cpu whose message queue is being processed
 *
 * @return          CX_STATUS_SUCCESS                   The method executed successfully
 * @return          otherwise                           Error
 */
NTSTATUS
_IpcProcessCpuMessages(
    _In_ PCPU* Cpu
);

/**
 * @brief           Wrapper method for processing current CPU's message queue
 *
 * @return          CX_STATUS_SUCCESS                   The method executed successfully
 * @return          CX_STATUS_DATA_ALTERED_FROM_OUSIDE  The queue was processed from another source
 * @return          otherwise                           Error
 */
__forceinline
NTSTATUS
IpcProcessCpuMessages(
    VOID
)
{
    if (!HvDoWeHaveValidCpu())
    {
        return CX_STATUS_COMPONENT_NOT_INITIALIZED;
    }

    PCPU* cpu = HvGetCurrentCpu();
    // if there are no pending messages or the queues are already being taken care of return successfully
    if ((!cpu->Ipc.QueueTotalPendingMessages) || (0 != CxInterlockedCompareExchange8(&cpu->Ipc.QueueIsBeingDrained, 1, 0)))
    {
        return CX_STATUS_SUCCESS;
    }

    // dispatch all pending messages
    NTSTATUS status = _IpcProcessCpuMessages(cpu);

    // signal that we've finished processing the queues
    if (1 != CxInterlockedCompareExchange8(&cpu->Ipc.QueueIsBeingDrained, 0, 1))
    {
        return CX_STATUS_DATA_ALTERED_FROM_OUSIDE;
    }
    return status;
}

/**
 * @brief           Handle a message targeting the current CPU
 *
 * @param[in]       Msg                 Pointer to an IPC_MESSAGE structure
*
 * @return          Returns the processed message status
 */
NTSTATUS
IpcDispatchMessage(
    _Inout_ IPC_MESSAGE *Msg
);


typedef enum
{
    IPC_QUEUE_COLLAPSE_CONDITION_ON_QUEUE_USAGE         = BIT(0),
    IPC_QUEUE_COLLAPSE_CONDITION_ON_DROPPED_MESSAGES    = BIT(1),
    IPC_QUEUE_COLLAPSE_CONDITION_FORCED                 = BIT(2),
}IPC_QUEUE_COLLAPSE_CONDITION;

/**
 * @brief           Custom processing of messages that can be grouped into a single callback handling. (Such as TLB invalidation messages).
 *
 * @param[in]       CpuQueue                            Pointer to the currently processed queue
 * @param[in]       CollapseAllFunction                 Callback function for processing collapsed messages
 * @param[in]       ConditionFlags                      Determines the conditions on which messages are collapsed
 * @param[in]       MaxQueueUsagePercent                Used together with ConditionFlags to specify a usage limit on which messages will automatically collapse
 *
 * @return          CX_STATUS_SUCCESS                   The method executed successfully
 * @return          otherwise                           Error
 */
NTSTATUS
IpcQueueCollapseMessages(
    _In_ CPU_IPC_QUEUE *CpuQueue,
    _In_ IPC_QUEUE_COLLAPSE_CALLBACK CollapseAllFunction,
    _In_ IPC_QUEUE_COLLAPSE_CONDITION ConditionFlags,
    _In_opt_ BYTE MaxQueueUsagePercent                   // collapse if usage >= MaxQueueUsagePercent (&& IPC_QUEUE_COLLAPSE_CONDITION_ON_QUEUE_USAGE)
);

/**
 * @brief           Helper function, given a CPU, decide whether it is selected/included by the specified destination
 *
 * @param[in]       Cpu                     Pointer to the cpu structure
 * @param[in]       Destination             Message destination values
 *
 * @return          TRUE                    The message is destined for the cpu
 * @return          FALSE                   The message is not destined for the cpu
 */
__forceinline
BOOLEAN
IpcIsCpuSelectedByDestination(
    _In_ PCPU* Cpu,
    _In_ IPC_CPU_DESTINATION Destination
)
{
    BOOLEAN isSelf = (Cpu == HvGetCurrentCpu());
    switch (Destination.DestinationMode)
    {
    case IPC_DESTINATION_CPU_POINTER:               return Cpu == Destination.Id.CpuPointer;
    case IPC_DESTINATION_BOOT_CPU_INDEX:            return Cpu->BootInfoIndex == Destination.Id.CpuBootIndex;
    case IPC_DESTINATION_LAPIC_ID:                  return Cpu->Id == Destination.Id.LapicId;
    case IPC_DESTINATION_BY_CPU_AFFINITY:           return (BIT_AT(Cpu->BootInfoIndex) & Destination.Id.CpuAffinity) != 0;
    case IPC_DESTINATION_ALL_CPUS_INCLUDING_SELF:   return TRUE;
    case IPC_DESTINATION_ALL_CPUS_EXCLUDING_SELF:   return !isSelf;
    case IPC_DESTINATION_SELF:                      return isSelf;
    }

    ERROR("Unknown destination mode %d\n", Destination.DestinationMode);
    return FALSE;
}


#define IPC_CPU_DESTINATION_SELF                gIpcCpuDestinationSelf
#define IPC_CPU_DESTINATION_ALL_INCLUDING_SELF  gIpcCpuDestinationAllIncludingSelf
#define IPC_CPU_DESTINATION_ALL_EXCLUDING_SELF  gIpcCpuDestinationAllExcludingSelf

extern const IPC_CPU_DESTINATION gIpcCpuDestinationSelf;
extern const IPC_CPU_DESTINATION gIpcCpuDestinationAllIncludingSelf;
extern const IPC_CPU_DESTINATION gIpcCpuDestinationAllExcludingSelf;

#endif //_QUEUE_IPC_H_
/// @}
