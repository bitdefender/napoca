/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup ipc
/// @{

#include "napoca.h"
#include "kernel/queue_ipc.h"
#include "kernel/interrupt.h"

volatile DWORD gTotalCpuYieldCount = 0;

// define queue properties for each CPU queue -- their rightful place would be a pcpu.c...
NTSTATUS HvaTlbInvaldQueueConsumerRoutine(_In_ CPU_IPC_QUEUE *CpuQueue);
NTSTATUS EptInvaldQueueConsumerRoutine(_In_ CPU_IPC_QUEUE *CpuQueue);

const IPC_QUEUE_PROPERTIES gCpuIpcQueueProperties[IPC_PRIORITY_TOTAL_DISTINCT_LEVELS] =
{
    {4096, NULL},                              // IPC_PRIORITY_IPI
    {4, EptInvaldQueueConsumerRoutine },       // IPC_PRIORITY_EPT_INVLD
    {256, HvaTlbInvaldQueueConsumerRoutine }    // IPC_PRIORITY_TLB_INVLD
};

const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowAll =
    { TRUE, TRUE, TRUE, IPC_INTERRUPTS_ENABLED, IPC_ENABLED, IPC_PRIORITY_LOWEST, 0, 0 };
const IPC_INTERRUPTIBILITY_STATE gInterruptibilityBlockAll =
    { TRUE, TRUE, FALSE, IPC_INTERRUPTS_DISABLED, IPC_DISABLED, 0, 0, 0 };
const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowAtCurrentPriority =
    { TRUE, TRUE, FALSE, IPC_INTERRUPTS_ENABLED, IPC_ENABLED, 0, 0, 0 };
const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowHighestPriority =
    { TRUE, TRUE, TRUE, IPC_INTERRUPTS_ENABLED, IPC_ENABLED, IPC_PRIORITY_IPI, 0, 0 };


const IPC_CPU_DESTINATION gIpcCpuDestinationSelf = { IPC_DESTINATION_SELF };
const IPC_CPU_DESTINATION gIpcCpuDestinationAllIncludingSelf = { IPC_DESTINATION_ALL_CPUS_INCLUDING_SELF };
const IPC_CPU_DESTINATION gIpcCpuDestinationAllExcludingSelf = { IPC_DESTINATION_ALL_CPUS_EXCLUDING_SELF };


static volatile DWORD gSequenceNumber;

#define QLOG
#define QLOGN                       NMILOGN
#define QLOG_FUNC_FAIL(fn, status)  NMILOG("%s failed with %s\n", fn, NtStatusToString(status))
#define QWARNING                    NMILOG

// macros for debugging marked messages type
#define QTRACE(MsgPtr, ...) ((MsgPtr) && (MsgPtr)->Trace && LOGN(__VA_ARGS__))
#define QTRACENMI(MsgPtr, ...) ((MsgPtr) && (MsgPtr)->Trace && NMILOGN(__VA_ARGS__))

IPC_STATE
IpcSetPriority(
    _In_ BOOLEAN DoSetEnabledValue,
    _In_ BOOLEAN IpcEnabled,
    _In_ BOOLEAN DoSetIpcPriorityValue,
    _In_ IPC_PRIORITY NewIpcPriority
)
{
    IO_PER_CPU_DATA *cpuData;
    // Get the current CPU data
    NTSTATUS status = IoGetPerCpuData(&cpuData);

    // If the CPU data could not be retrieved, return a default state
    if (!SUCCESS(status) || !cpuData)
    {
        IPC_STATE defaultState = { 0 };
        defaultState.Enabled = TRUE;
        defaultState.Priority = IPC_PRIORITY_LOWEST;
        return defaultState;
    }

    // Save the old cpu data
    IPC_STATE old = cpuData->IpcState;

    // Set the new IPC values
    if (DoSetIpcPriorityValue)
    {
        // Ensure there's no processing done before finalizing the operation
        cpuData->IpcState.Enabled = FALSE;
        cpuData->IpcState.Priority = NewIpcPriority;
    }

    cpuData->IpcState.Enabled = (DoSetEnabledValue ? IpcEnabled : old.Enabled);
    return old;
}

/**
 * @brief           Returns the current cpu's IPC state
 *
 * @return          Returns the current cpu's IPC state
 */
IPC_STATE
IpcGetState(
    VOID
)
{
    IO_PER_CPU_DATA *cpuData;

    // Get the current cpu data
    NTSTATUS status = IoGetPerCpuData(&cpuData);

    // If the current cpu data couldn't be retrieved, return the default IPC state
    if (!SUCCESS(status) || !cpuData)
    {
        IPC_STATE defaultState = { 0 };
        defaultState.Enabled = TRUE;
        defaultState.Priority = IPC_PRIORITY_LOWEST;
        return defaultState;
    }

    // Return the current CPU's IPC state
    return cpuData->IpcState;
}

/**
 * @brief           Checks if the current message queue level is accepted for processing
 *
 * @param[in]       MessagePriority                 Determines if the final IPC Enable state will be modified or not
 * @param[in]       IgnoreQueueBeingDrained         Ignores the draining state of the queue
*
 * @return          Returns TRUE if the message can be processed, FALSE otherwise
 */
__forceinline
static
BOOLEAN
_IpcCanDispatchMessages(
    _In_ IPC_PRIORITY MessagePriority,
    _In_ BOOLEAN IgnoreQueueBeingDrained
)
{
    // Get the IPC state
    IPC_STATE ipcState = IpcGetState();

    // If the IPC queue is being drained and IgnoreQueueBeingDrained was not specified, do not process the message
    if (!IgnoreQueueBeingDrained && HvGetCurrentCpu()->Ipc.QueueIsBeingDrained)
        return FALSE;

    // If the message is nonblocking, process it anyway
    if (MessagePriority >= IPC_PRIORITY_NONBLOCKING_LEVEL)
        return TRUE;

    // If ipc is not enabled or the message priority is less than IPC priority, do not process the message
    if (!ipcState.Enabled || MessagePriority < ipcState.Priority)
        return FALSE;

    return TRUE;
}

NTSTATUS
IpcDispatchMessage(
    _Inout_ IPC_MESSAGE *Msg
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    // There are 2 types of supported messages at this time, IPI handlers and Callbacks
    switch (Msg->MessageType)
    {
        case IPC_MESSAGE_TYPE_IPI_HANDLER:
        {
            // If the message contains a callback function, call it
            if (Msg->OperationParam.IpiHandler.CallbackFunction)
            {
                // Call the message callback and register the status. In case of a fail, log the error.
                status = Msg->OperationParam.IpiHandler.CallbackFunction(Msg->OperationParam.IpiHandler.CallbackContext, NULL);
                if (!SUCCESS(status))
                {
                    QLOG_FUNC_FAIL("msg->OperationParam.Callback.CallbackFunction(&msg)", status);
                }
            }
            break;
        }

        case IPC_MESSAGE_TYPE_CALLBACK:
        {
            // Call the message callback and register the status. In case of a fail, log the error.
            status = Msg->OperationParam.Callback.CallbackFunction(Msg);
            if (!SUCCESS(status))
            {
                QLOG_FUNC_FAIL("msg->OperationParam.Callback.CallbackFunction(&msg)", status);
            }
            break;
        }
        default:
        {
            QWARNING("Unsupported message type %d\n", Msg->MessageType);
        }
    }

    // If the message requires acknowledgement, let the emitter know the completion of this message
    if (Msg->NeedsAcknowledge)
        *Msg->SetThisToAcknowledgeSender = TRUE;

    return status;
}

/**
 * @brief           Try interrupting the Destination cpu(s) to haste message processing, self-interruption is not allowed (simply ignored).
 *
 * @param[in]       Destination                         Target CPU(s) of the interrupt
 *
 * @return          CX_STATUS_SUCCESS                   The method executed successfully
 * @return          CX_STATUS_COMPONENT_NOT_READY       The processors are not in a state in which can be interrupted
 * @return          otherwise                           Error
 */
static
NTSTATUS
_IpcInterruptCpus(
    _In_ IPC_CPU_DESTINATION Destination
)
{
    QWORD computedAffinity = 0;

    // Check if other processors are in a state from which they can be interrupted
    if (INT_IPC_TARGETS_STATE_NONE_SELECTED_REACHABLE == IntQueryIpcTargetsState())
        return CX_STATUS_COMPONENT_NOT_READY;

    // Compute the processors that are required to receive the interrupt
    if (Destination.DestinationMode == IPC_DESTINATION_ALL_CPUS_EXCLUDING_SELF
        || Destination.DestinationMode == IPC_DESTINATION_ALL_CPUS_INCLUDING_SELF)
    {
        // avoid the overhead of self-interruption
        computedAffinity = AFFINITY_ALL_EXCLUDING_SELF;
    }
    else if (Destination.DestinationMode == IPC_DESTINATION_BY_CPU_AFFINITY)
    {
        computedAffinity = Destination.Id.CpuAffinity & AFFINITY_ALL_EXCLUDING_SELF;
    }
    else
    {
        // If no shorthand has been used, deduce the explicit cpus that require interrupts
        for (DWORD cpuIndex = 0; cpuIndex < gBootInfo->CpuCount; cpuIndex++)
        {
            PCPU* cpu = (PCPU*)(NAPOCA_CPU(cpuIndex));

            // If the cpu structure is the one corresponding to the one executing this code, avoid the overhead of self-interruption
            if (cpu == HvGetCurrentCpu())
                continue;

            if (IpcIsCpuSelectedByDestination(cpu, Destination))
                computedAffinity |= BIT_AT(cpu->BootInfoIndex);
        }
    }

    if (!computedAffinity)
        return CX_STATUS_SUCCESS;

    // Send the interrupt
    return IntSendIpcInterrupt(computedAffinity);
}

NTSTATUS
IpcSendCpuMessage2(
    _In_ IPC_MESSAGE            *Message,
    _In_ IPC_CPU_DESTINATION    Destination,
    _In_ IPC_PRIORITY           MessagePriority,
    _In_ BOOLEAN                DoInterruptCpus,
    _In_ IPC_WAIT_COMPLETION    WaitForCompletion,
    _In_ BOOLEAN                DropMessageOnFullQueue,
    _In_ char                   *File,
    _In_ DWORD                  Line
)
{
    BOOLEAN ack[BOOT_MAX_CPU_COUNT] = { 0 };
    NTSTATUS status = CX_STATUS_SUCCESS;

    Message->Sequence = CxInterlockedIncrement32(&gSequenceNumber);
    DWORD neededConfirmationsCount = 0;
    BOOLEAN waitAbandonedDueToExternalReasons = FALSE;
    const PCPU *executingCpu = HvGetCurrentCpu();

    // We can wait for completion only when the CPUs are interruptible
    if ((IPC_WAIT_COMPLETION_BEST_EFFORT == WaitForCompletion) &&
        (INT_IPC_TARGETS_STATE_ALL_SELECTED_REACHABLE != IntQueryIpcTargetsState()))
    {
        waitAbandonedDueToExternalReasons = TRUE;
        WaitForCompletion = IPC_WAIT_COMPLETION_NONE;
    }

    // Add a copy of the message to each targeted queue
    for (DWORD i = 0; i < gBootInfo->CpuCount; i++)
    {
        DWORD cpuIndex = i;
        PCPU* cpu = (PCPU*)(NAPOCA_CPU(cpuIndex));
        BOOLEAN isSelf = (cpu == executingCpu);
        BOOLEAN isMarkedForConfirmation = (!isSelf && WaitForCompletion != IPC_WAIT_COMPLETION_NONE);

        // Check if the current cpu should receive the message
        if (!IpcIsCpuSelectedByDestination(cpu, Destination)) continue;

        // Get the cpu queue in which the message has to be inserted
        CPU_IPC_QUEUE *ipcQueue = CpuGetIpcQueue(cpu, MessagePriority);

        // Prepare the message acknowledgement structure
        Message->SubSequence = i;
        Message->SetThisToAcknowledgeSender = &ack[i];
        Message->NeedsAcknowledge = isMarkedForConfirmation ? CX_TRUE : CX_FALSE;

        // When a message is self-addressed and the current CPU has the queue disabled, bypass the queue and handle it directly
        if (isSelf && !_IpcCanDispatchMessages(MessagePriority, FALSE))
        {
            QLOG("SELF_DISPATCH!\n");
            status = IpcDispatchMessage(Message);
            if (!SUCCESS(status))
            {
                QLOG_FUNC_FAIL("IpcDispatchMessage", status);
            }
            continue;
        }

        // Try sending an interrupt if the target queue is over 80% full
        if (WaitForCompletion &&
            !DropMessageOnFullQueue &&
            (CxLlQueueInstantaneousUsedPercent(&ipcQueue->Queue) > 80))
        {
            // If another cpu has its queue > 80% send an Ipi
            if (!isSelf)
            {
                QTRACE(Message, "![%d:%d]", executingCpu->BootInfoIndex, i);
                IPC_CPU_DESTINATION target = { 0 };
                target.DestinationMode = IPC_DESTINATION_CPU_POINTER;
                target.Id.CpuPointer = cpu;
                _IpcInterruptCpus(target);
            }
            // If the current cpu has its queue > 80%, process queue
            else
            {
                PROCESS_IPCS();
            }
        }

        QTRACE(Message, "+[%d:%d]", executingCpu->BootInfoIndex, i);
        QWORD addTimeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
        NTSTATUS enqueueStatus = CX_STATUS_SUCCESS;
        BOOLEAN messageDroppedDueToFullQueue = FALSE;
        do
        {
            // Try enqueueing the message in the target cpu's message queue
            enqueueStatus = CxLlQueueAdd(&ipcQueue->Queue, Message, sizeof(IPC_MESSAGE), FALSE);
            if (SUCCESS(enqueueStatus))
            {
                // Make sure to signal the message ASAP to reduce processing delays
                CxInterlockedIncrement32(&ipcQueue->TotalPendingMessages);
            }
            else
            {
                // If the message failed to be sent and the timeout passed, log a warning
                if (HvTimeout(addTimeout))
                {
                    QLOG_FUNC_FAIL("HvTimeout", enqueueStatus);
                    QWARNING("[%d]->[%d] drop = %d, abandoned=%d, wait=%d, caller=%p\n",
                        executingCpu->BootInfoIndex, cpu->BootInfoIndex,
                        DropMessageOnFullQueue,
                        waitAbandonedDueToExternalReasons,
                        WaitForCompletion,
                        *((PVOID*)_AddressOfReturnAddress()));

                    IO_PER_CPU_DATA *cpuData = cpu->IoPerCpuData;

                    IPC_STATE ipcState = { 0 };
                    if (cpuData) ipcState = cpuData->IpcState;
                    QWARNING("CPU[%d] (%s) has full queue IPC enabled=%d, IPC priority=%d, lastDrained=%p lastSeen=%p\n",
                        cpu->BootInfoIndex, (isSelf ? "SELF" : "OTHER"), ipcState.Enabled, ipcState.Priority,
                        ipcQueue->LastProcessedTsc, MIN(ipcQueue->LastProcessedTsc, ipcQueue->LastBlockedTsc)
                    );

                    // Reset the timeout in order to log again after 1 Ms
                    addTimeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
                }
                // If messages are allowed to be dropped, log the dropped message and break the loop
                if (DropMessageOnFullQueue)
                {
                    QTRACE(Message, "DROPPED", executingCpu->BootInfoIndex, i);
                    messageDroppedDueToFullQueue = TRUE;
                    if ((WaitForCompletion != IPC_WAIT_COMPLETION_NONE) && (WaitForCompletion != IPC_WAIT_COMPLETION_BEST_EFFORT))
                    {
                        QWARNING("IPC message was dropped (full destination queue) while the caller asked for completion acknowledge!\n");
                    }
                }
            }

            // Give this CPU a chance to process its own message queue, to avoid deadlocks
            CpuYield();

        // If the message was not sent and we do not allow dropped messages, try sending it again
        } while (!messageDroppedDueToFullQueue && !SUCCESS(enqueueStatus));

        if (messageDroppedDueToFullQueue)
        {
            CxInterlockedIncrement64(&ipcQueue->TotalDroppedMessages);
            // avoid counting this message as it was not enqueued
            continue;
        }
        QTRACE(Message, ">[%d:%d]", executingCpu->BootInfoIndex, i);
        QLOG("<%s%d -> +%d.%d -> %d>\n", WaitForCompletion ? "|" : "", executingCpu->BootInfoIndex, Message->Sequence, Message->SubSequence, cpu->BootInfoIndex);
        if (isMarkedForConfirmation) neededConfirmationsCount++;
        CxInterlockedIncrement64(&cpu->Ipc.QueueTotalPendingMessages);
    }

    // process IPCs unconditionally
    PROCESS_IPCS();

    // interrupt the CPU(s) if asked to
    if (DoInterruptCpus)
        _IpcInterruptCpus(Destination);

    // Although the message was sent to the target cpu(s), due to external reasons we cannot wait for the message-processing acknowledgement
    if (waitAbandonedDueToExternalReasons)
    {
        status = CX_STATUS_ABANDONED; // only report this status when WaitForCompletion was specified but it won't be performed
        goto cleanup;
    }

    // If no acknowledgement is required, everything is ok
    if (!neededConfirmationsCount || (WaitForCompletion == IPC_WAIT_COMPLETION_NONE))
    {
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }

    QWORD acknowledgeTimeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
    QWORD reinterruptTimeout = HvGetTimeGuard(IPC_QUEUE_RESEND_INTERRUPT_TIMEOUT_IN_MICROSECONDS);
    BOOLEAN allowReinterruption = TRUE;
    DWORD acknowledgedCount = 0;
    QTRACE(Message, "&[%d]", executingCpu->BootInfoIndex);
    do
    {
        QWORD unresponsiveCpuMask = 0;

        // Count the number of acknowledged messages
        acknowledgedCount = 0;
        for (DWORD i = 0; i < gBootInfo->CpuCount; i++)
        {
            acknowledgedCount += (ack[i] ? 1 : 0);
        }

        BOOLEAN reinterruptTimeoutExpired = HvTimeout(reinterruptTimeout);
        BOOLEAN acknowledgeTimeoutExpired = HvTimeout(acknowledgeTimeout);

        // Check for timeouts
        if (reinterruptTimeoutExpired || acknowledgeTimeoutExpired)
        {
            for (DWORD cpuIndex = 0; cpuIndex < gHypervisorGlobalData.CpuData.CpuCount; cpuIndex++)
            {
                PCPU* cpu = gHypervisorGlobalData.CpuData.Cpu[cpuIndex];
                if ((!IpcIsCpuSelectedByDestination(cpu, Destination) || ack[cpuIndex]) || (cpu == executingCpu))
                    continue;

                // Log acknowledgeTimeout details
                if (acknowledgeTimeoutExpired)
                {
                    IO_PER_CPU_DATA *cpuData = cpu->IoPerCpuData;
                    IPC_STATE ipcState = cpuData->IpcState;
                    CX_LLQUEUE_POSITION currentPos;

                    currentPos.Raw = cpu->Ipc.Queue[MessagePriority].Queue.Position.Raw;

                    QWARNING("%s:%d CPU[%d] -> CPU[%d] didn't complete the IPC[%d] in a timely manner, IPC enabled=%d, IPC priority=%d neededConfirmations %d AckCount %d AttachedVcpu state %d AttachedVcpu flags %d\n    "
                        "Ipc.QueueIsBeingDrained=%d, Ipc.QueueTotalPendingMessages=%lld, TotalPendingMessages=%d, LastBlockedTsc=%llX, LastProcessedTsc=%llX, Incoming=%d, Waiting=%d, Outgoing=%x\n",
                        File, Line, executingCpu->BootInfoIndex, cpuIndex, MessagePriority, ipcState.Enabled, ipcState.Priority, neededConfirmationsCount, acknowledgedCount,
                        cpu->Vcpu->State, cpu->Vcpu->Schedulable,

                        cpu->Ipc.QueueIsBeingDrained, cpu->Ipc.QueueTotalPendingMessages, cpu->Ipc.Queue[MessagePriority].TotalPendingMessages,
                        cpu->Ipc.Queue[MessagePriority].LastBlockedTsc, cpu->Ipc.Queue[MessagePriority].LastProcessedTsc,
                        currentPos.Incoming, currentPos.Waiting, currentPos.Outgoing
                    );
                }
                // Mark the current cpu as unresponsive
                unresponsiveCpuMask |= cpu->Affinity;
            }
            if (acknowledgeTimeoutExpired)
            {
                QWARNING("%s:%d CPU[%d] timeout while waiting for acknowledge! acknowledgedCount=%d, neededConfirmationsCount=%d\n", File, Line, executingCpu->BootInfoIndex, acknowledgedCount, neededConfirmationsCount);
                QLOG_FUNC_FAIL("HvTimeout", status);
                acknowledgeTimeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
            }
            // Try reinterrupting the unresponsive cpus in order to process their ipc queue messages
            if (reinterruptTimeoutExpired)
            {
                IPC_CPU_DESTINATION unresponsiveCpuDestination = { 0 };
                unresponsiveCpuDestination.DestinationMode = IPC_DESTINATION_BY_CPU_AFFINITY;
                unresponsiveCpuDestination.Id.CpuAffinity = unresponsiveCpuMask;
                _IpcInterruptCpus(unresponsiveCpuDestination);

                //reinterruptTimeoutExpired = HvGetTimeGuard(IPC_QUEUE_RESEND_INTERRUPT_TIMEOUT_IN_MILISECONDS);
                allowReinterruption = FALSE;
            }
        }

        // Ensure the current cpu also processes its own ipc queue in order to avoid deadlocks
        PROCESS_IPCS();

    // Retry obtaining acknowledgement from all messages
    } while (acknowledgedCount < neededConfirmationsCount);
    QTRACE(Message, ".[%d]\n", executingCpu->BootInfoIndex);
    QLOG("<%d/%d %d.>\n", acknowledgedCount, neededConfirmationsCount, Message->Sequence);

cleanup:
    return status;
}

/**
 * @brief           Processes as many available messages as possible within a certain time span.
 * @brief           The time span is given by the value of IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS
 *
 * @param[in]       IpcQueue                            Pointer to an IPC Message Queue
 * @param[in]       Cpu                                 Pointer to the cpu whose message queue is being processed
 * @param[out]      TotalDispatchedMessages             Pointer to a counter. Counts the number of processed messages
 *
 * @return          CX_STATUS_SUCCESS                   The method executed successfully
 * @return          CX_STATUS_ABORTED_ON_TIMEOUT        The timeout expired before all messages in the queue could be processed
 * @return          otherwise                           Error
 */
static
__forceinline
NTSTATUS
_IpcProcessQueueMessages(
    _In_ CPU_IPC_QUEUE *IpcQueue,
    _In_ PCPU* Cpu,
    _Out_ DWORD *TotalDispatchedMessages
)
{
    IPC_MESSAGE msg = { 0 };
    NTSTATUS status = CX_STATUS_SUCCESS;

    // We want to process as many messages as possible, ideally all, for a limited amount of time.
    // In order to achieve that we set a timer.
    QWORD timeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
    do
    {
        // Try to retrieve a message from the queue
        status = CxLlQueueRemove(&IpcQueue->Queue, &msg, sizeof(msg), FALSE);
        if (!SUCCESS(status))
        {
            // If there are no messages in the queue, exit with success status
            if (status == CX_STATUS_DATA_NOT_READY)
            {
                status = CX_STATUS_SUCCESS;
            }
            else
            {
                QLOG_FUNC_FAIL("CxLlQueueRemove", status);
            }
            goto cleanup;
        }

        // Increase the number of handled messages
        (*TotalDispatchedMessages)++;

        // Decrease the number of available messages in the queue and log the message
        CxInterlockedDecrement64(&Cpu->Ipc.QueueTotalPendingMessages);
        QLOG("<-%d.%d->%d>\n", msg.Sequence, msg.SubSequence, Cpu->BootInfoIndex);

        // Actually process the message
        NTSTATUS handlingStatus = IpcDispatchMessage(&msg);
        if (!SUCCESS(handlingStatus))
        {
            QLOG_FUNC_FAIL("IpcDispatchMessage", handlingStatus);
            // We cannot afford to fail the function due to failed messages.
            // The best we can do is log the error.
        }

        // Check if there's still time to process another message
        if (HvTimeout(timeout))
        {
            status = CX_STATUS_ABORTED_ON_TIMEOUT;
            QLOG_FUNC_FAIL("HvTimeout", status);
            goto cleanup;
        }

    // While there are no errors / the timer didn't expire, continue processing messages
    } while (SUCCESS(status));

cleanup:
    return status;
}

NTSTATUS
_IpcProcessCpuMessages(
    _In_ PCPU* Cpu
)

{
    NTSTATUS status = CX_STATUS_SUCCESS;
    // Iterate all message queues
    for (DWORD i = IPC_PRIORITY_TOTAL_DISTINCT_LEVELS; i > 0; i--)
    {
        IPC_PRIORITY queuePriority = i - 1;
        // Check if the current queue is required to be processed
        if (_IpcCanDispatchMessages(queuePriority, TRUE))
        {
            // Get the queue
            CPU_IPC_QUEUE *currentQueue = CpuGetIpcQueue(Cpu, queuePriority);

            // Check if there are messages in the queue
            if (!currentQueue->TotalPendingMessages)
                continue;

            // If there is a custom message processing routine, call it instead of the standard one
            if (currentQueue->CustomQueueConsumerRoutine)
            {
                // reset it BEFORE processing, this way it can't happen to have some pending messages and not know about
                CxInterlockedExchange32(&currentQueue->TotalPendingMessages, 0);

                status = currentQueue->CustomQueueConsumerRoutine(currentQueue);
            }
            else
            {
                DWORD total = 0;
                // Call the standard message processing routine
                status = _IpcProcessQueueMessages(currentQueue, Cpu, &total);
                // Sanity check, ensure we didnt process more messages that there actually are in the queue
                if (currentQueue->TotalPendingMessages < total)
                {
                    WARNING("_IpcProcessQueueMessages reported an abnormally high number of processed messages: currentQueue->TotalPendingMessages=%d < processed=%d\n",
                        currentQueue->TotalPendingMessages, total);
                }
                // Decrease the number of messages still available in the queue
                CxInterlockedAdd32(&currentQueue->TotalPendingMessages, 0-total);
            }

            if (!SUCCESS(status))
            {
                QLOG_FUNC_FAIL((currentQueue->CustomQueueConsumerRoutine ? "currentQueue->CustomQueueConsumerRoutine" : "_IpcProcessQueueMessages"), status);
                goto cleanup;
            }
            // Mark the queue processing time
            currentQueue->LastProcessedTsc = HvGetTscTickCount();
        }
        else
        {
            // If processing wasn't allowed, at least mark the time at which it has been tried
            CpuGetIpcQueue(Cpu, queuePriority)->LastBlockedTsc = HvGetTscTickCount();
        }
    }

cleanup:
    return status;
}

NTSTATUS
IpcQueueCollapseMessages(
    _In_ CPU_IPC_QUEUE *CpuQueue,
    _In_ IPC_QUEUE_COLLAPSE_CALLBACK CollapseAllFunction,
    _In_ IPC_QUEUE_COLLAPSE_CONDITION ConditionFlags,
    _In_opt_ BYTE MaxQueueUsagePercent
)

{
    // Deduce if messages should be processed all as a single invalidation (collapsed)
    BOOLEAN collapseAll = (ConditionFlags & IPC_QUEUE_COLLAPSE_CONDITION_FORCED) ||
                          ((ConditionFlags & IPC_QUEUE_COLLAPSE_CONDITION_ON_QUEUE_USAGE) && (CxLlQueueInstantaneousUsedPercent(&CpuQueue->Queue) >= MaxQueueUsagePercent)) ||
                          ((ConditionFlags & IPC_QUEUE_COLLAPSE_CONDITION_ON_DROPPED_MESSAGES) && CpuQueue->TotalDroppedMessages);

    if (ConditionFlags & IPC_QUEUE_COLLAPSE_CONDITION_ON_DROPPED_MESSAGES)
    {
        CxInterlockedExchange64(&CpuQueue->TotalDroppedMessages, 0);
    }

    QWORD timeout = HvApproximateTimeGuardFast(IPC_QUEUE_RESPONSE_TIMEOUT_IN_MICROSECONDS);
    IPC_MESSAGE msg = { 0 };
    volatile BOOLEAN *ack[BOOT_MAX_CPU_COUNT] = { 0 };
    DWORD ackCnt = 0;
    NTSTATUS status;

    // free (consume) all existing entries
    do
    {
        // Get message from the queue
        status = CxLlQueueRemove(&CpuQueue->Queue, &msg, sizeof(msg), FALSE);
        if (!SUCCESS(status))
        {
            if (status == CX_STATUS_DATA_NOT_READY)
            {
                status = CX_STATUS_SUCCESS;
            }
            else
            {
                QLOG_FUNC_FAIL("CxLlQueueRemove", status);
            }
            break;
        }

        // If the message is actually required to be processed, do process it
        if (!collapseAll)
        {
            status = IpcDispatchMessage(&msg);
            if (!SUCCESS(status))
            {
                goto cleanup;
            }
        }
        // Otherwise, just acknowledge it
        else if (msg.NeedsAcknowledge)
        {
            ack[ackCnt++] = msg.SetThisToAcknowledgeSender;
        }

        // If the time has run out, exit the loop
        if (HvTimeout(timeout))
        {
            status = CX_STATUS_ABORTED_ON_TIMEOUT;
            goto cleanup;
        }
    } while (SUCCESS(status));

    // Perform one single full invalidation on collapsed messages
    if (collapseAll)
    {
        status = CollapseAllFunction();
        for (DWORD ackIdx = 0; ackIdx < ackCnt; ackIdx++)
        {
            *ack[ackIdx] = TRUE;
        }
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}
/// @}
