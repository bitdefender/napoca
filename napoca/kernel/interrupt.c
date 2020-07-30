/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup ipc
/// @{

#include "kernel/interrupt.h"
#include "kernel/kernel.h"
#include "kernel/exceptions.h"
#include "kernel/spinlock.h"
#include "apic/ipi.h"
#include "debug/debugger.h"
#include "debug/debugger.h"
#include "kernel/queue_ipc.h"
#include "communication/guestcommands.h"

extern volatile BOOLEAN gInDebugger;
volatile DWORD gCpusInNmiHandler = 0;

#define INTERCPU_MESSAGE_WAIT_TIMEOUT   10  // seconds

#define IPC_MODE_IPI 0
#define IPC_MODE_NMI 1

/**
 * @brief           Marks the VCPU structure as (not) schedulable in order to communicate to the cpu thread-pool (not) to use this
 * @brief           VCPU structure in guest from now on.
 *
 * @param[in]       Vcpu                    Pointer to the cpu structure to be modified
 * @param[in]       Schedule                Boolean, determines if this vcpu structure should be scheaduled from now on.
  */
static
VOID
_HvChangeVcpuSchedulingState(
    _In_ VCPU* Vcpu,
    _In_ BOOLEAN Schedule
    )
{
    // If the vcpu should be schedulable
    if (Schedule)
    {
        // If trasitioning from non schedulable to schedulable, record some performance data
        if (!Vcpu->Schedulable)
        {
            PerfAccountTransition(&Vcpu->PausingStats[VCPU_PAUSING_STATE_PAUSED], Vcpu->LastPauseTransitionTsc, &Vcpu->LastPauseTransitionTsc);
        }
        // Mark the vcpu as schedulable
        Vcpu->Schedulable = TRUE;
    }
    // If the vcpu shouldn't be schedulable
    else
    {
        // If trasitioning from schedulable to non schedulable, record some performance data
        if (Vcpu->Schedulable)
        {
            // vcpu was running before
            PerfAccountTransition(&Vcpu->PausingStats[VCPU_PAUSING_STATE_RUNNING], Vcpu->LastPauseTransitionTsc, &Vcpu->LastPauseTransitionTsc);
            Vcpu->LastPauseTransitionTsc = HvGetTscTickCount();
        }
        // Mark the vcpu as non schedulable
        Vcpu->Schedulable = FALSE;
    }
}

VOID
HvControlInterruptWindowExiting(
    _In_ BOOLEAN    Enable
)
{
    QWORD procCtrl = 0;

    vmx_vmread(VMCS_PROC_BASED_EXEC_CONTROL, &procCtrl);
    procCtrl = (Enable) ? (procCtrl | (QWORD)VMCSFLAG_PROCEXEC_INTERRUPT_WINDOW_EXIT) : (procCtrl & (~(QWORD)VMCSFLAG_PROCEXEC_INTERRUPT_WINDOW_EXIT));
    vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL, procCtrl);
}

static volatile CX_UINT32 _HvPauseCnt = 0;  ///< Debug counter for paused cpus

/**
 * @brief           Debug callback for pausing Vcpus. Increase the _HvPauseCnt on each call.
 *
 * @param[in]       Message                 Pointer to an IPC message, currently not used.
 *
 * @return          CX_STATUS_SUCCESS       The method was successful
 */
static
NTSTATUS
_HvPauseVcpusDebugCallback(
    _In_ struct _IPC_MESSAGE* Message
    )
{
    UNREFERENCED_PARAMETER(Message);
    CxInterlockedIncrement32(&_HvPauseCnt);
    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvPauseVcpus(
    _In_ GUEST* Guest,
    _In_ QWORD VcpuIndexAffinity,
    _In_ BOOLEAN WaitForPause
)
{
    // Validate input parameters
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GstIsSafeToInterrupt(Guest)) return CX_STATUS_SUCCESS;

    // Ensure no two processors try to pause/resume VCPUs at the same time
    HvAcquireRecSpinLock(&Guest->PauseVcpusLock);

    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD interruptCpusAffinity = 0;
    for (DWORD i = 0; i < Guest->VcpuCount; i++)
    {
        // If the current VCPU is not the object of this pause, skip it
        if (!(VCPU_AFFINITY_BY_VCPU_INDEX(i) & VcpuIndexAffinity))
            continue;

        // If the current VCPU is marked as schedulable and the pause count is 0 (the vcpu is schedulable),
        // stop the VCPU from re-entering the guest state and increase the pause count
        if (!Guest->Vcpu[i]->VcpuPauseCount && Guest->Vcpu[i]->Schedulable)
        {
            // Mark the vcpu structure as not schedulable
            _HvChangeVcpuSchedulingState(Guest->Vcpu[i], FALSE);
            // Mark the CPU for interrupt
            interruptCpusAffinity |= Guest->Vcpu[i]->AttachedPcpu->Affinity;
        }
        Guest->Vcpu[i]->VcpuPauseCount++;
    }

    // Actually interrupt the required CPUs
    if (interruptCpusAffinity)
    {
        // Create an IPC message
        IPC_MESSAGE msg = { 0 };
        msg.MessageType = IPC_MESSAGE_TYPE_CALLBACK;
        msg.OperationParam.Callback.CallbackFunction = _HvPauseVcpusDebugCallback;

        // Set the destination cpus
        IPC_CPU_DESTINATION dst = { 0 };
        dst.DestinationMode = IPC_DESTINATION_BY_CPU_AFFINITY;
        dst.Id.CpuAffinity = interruptCpusAffinity;

        _HvPauseCnt = 0;

        // Send the interrupt message to the required CPUs. We want to interrupt the processors to speed up the message processing. If requied,
        // do wait for processors to acknowledge the completion of all messages. After the interrupt the marked VCPU structures and their respective CPUs
        // will no longer be used in guest until a resume command is given.
        status = IpcSendCpuMessage(&msg, dst, IPC_PRIORITY_IPI, TRUE, WaitForPause, FALSE);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("IpcSendCpuMessage", status);
        }

        // If the number of actual paused Cpus is not the same as the messaged CPUs, although acknowlegement was requested, log the error
        if ((__popcnt64(interruptCpusAffinity) != _HvPauseCnt) && WaitForPause)
        {
            ERROR("Not all targeted VCPUS are paused (sent to %p, %llx=>%lld vs %d) after calling IpcSendCpuMessage in BLOCKING mode!\n",
                interruptCpusAffinity, VcpuIndexAffinity, __popcnt64(VcpuIndexAffinity), _HvPauseCnt);
        }
    }

    // Allow other cpus to pause/resume VCPUs
    HvReleaseRecSpinLock(&Guest->PauseVcpusLock);
    return status;
}


NTSTATUS
HvResumeVcpus(
    _In_ GUEST* Guest,
    _In_ QWORD VcpuIndexAffinity
)
{
    // Validate input parameters
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GstIsSafeToInterrupt(Guest)) return CX_STATUS_SUCCESS;

    // Ensure no two processors try to pause/resume VCPUs at the same time
    HvAcquireRecSpinLock(&Guest->PauseVcpusLock);

    for (DWORD i = 0; i < Guest->VcpuCount; i++)
    {
        // If the VCPU is not the object of this resume, skip it
        if (!(VCPU_AFFINITY_BY_VCPU_INDEX(i) & VcpuIndexAffinity))
            continue;

        // Decrease the count of pause-requests for this VCPU
        if (Guest->Vcpu[i]->VcpuPauseCount) Guest->Vcpu[i]->VcpuPauseCount--;

        // If the count is 0, we can mark the VCPU as scheaduable again
        if (!Guest->Vcpu[i]->VcpuPauseCount)
            _HvChangeVcpuSchedulingState(Guest->Vcpu[i], TRUE);
    }

    // Allow other cpus to pause/resume VCPUs
    HvReleaseRecSpinLock(&Guest->PauseVcpusLock);

    return CX_STATUS_SUCCESS;
}


VOID
IntNmiHandler(
    )
{
    PCPU* cpu = HvGetCurrentCpu();

    // Nmi overflow count at the beginning of the handler
    BOOLEAN isPerfNMIOvf = CfgFeaturesNmiPerformanceCounterTicksPerSecond?LapicCheckOverflowPerfNMI():FALSE;

    // Ensure compiler won't reorder/optimize this code
    _ReadBarrier();

    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond && isPerfNMIOvf)
    {
        cpu->NmiWatchDog.OverflowCount++;

        // Handle watchdog NMI - detect exits longer than 1s
        if (cpu->NmiWatchDog.StartingRootModeTsc &&
            HvTscTicksIntervalToMicroseconds(HvGetTscTickCount(), cpu->NmiWatchDog.StartingRootModeTsc) >= LapicGetPerfNMIWatchdogMicroSecondsTimeout()
            )
        {
            // Suspend watchdog while handling an "expiration" and then activate it back
            LapicDisablePerfNMI();

            // Log the NMI handled
            if (!gInDebugger)
            {
                NMILOG("[CPU Index: %d.%d Exit %d] NMI triggered %lld times! Current exit took %lldus.\n",
                    cpu->Vcpu->GuestIndex, cpu->Vcpu->GuestCpuIndex, cpu->Vcpu->ExitCount,
                    cpu->NmiWatchDog.OverflowCount,
                    HvTscTicksIntervalToMicroseconds(HvGetTscTickCount(), HvGetCurrentVcpu()->LastExitTsc));

                cpu->NmiWatchDog.OverflowCount = 0;
                cpu->NmiWatchDog.StartingRootModeTsc = HvGetTscTickCount();
            }

            LapicEnablePerfNMI();
        }

        // Program the counter for a new timeout detection
        LapicResetPerfNMI();
    }

    if ((!gInDebugger) && (!isPerfNMIOvf))
    {
        // In case that there is no overflow on the counter that is used by PerfNMI watchdog
        // then we need to inject this NMI to guest
        VirtExcInjectException(NULL, HvGetCurrentVcpu(), EXCEPTION_NMI, 0, 0);
    }

    return;
}


NTSTATUS
IntSendIpcMessage(
    _In_ PNAPOCA_IPI_HANDLER Handler,
    _In_ PVOID Context,
    _In_ QWORD Affinity,
    _In_ BOOLEAN WaitForCompletion
)
{
    IPC_MESSAGE msg = { 0 };

    msg.MessageType = IPC_MESSAGE_TYPE_IPI_HANDLER;
    msg.OperationParam.IpiHandler.CallbackFunction = Handler;
    msg.OperationParam.IpiHandler.CallbackContext = Context;

    IPC_CPU_DESTINATION dst = { 0 };

    dst.DestinationMode =
        (Affinity == AFFINITY_ALL_INCLUDING_SELF) ? IPC_DESTINATION_ALL_CPUS_INCLUDING_SELF :
        (Affinity == AFFINITY_ALL_EXCLUDING_SELF) ? IPC_DESTINATION_ALL_CPUS_EXCLUDING_SELF : IPC_DESTINATION_BY_CPU_AFFINITY;
    dst.Id.CpuAffinity = Affinity;

    /// NEW COMMUNICATION MECHANISM
    NTSTATUS status = IpcSendCpuMessage(
        &msg,
        dst,
        IPC_PRIORITY_IPI,
        TRUE,
        WaitForCompletion? IPC_WAIT_COMPLETION_FORCED : IPC_WAIT_COMPLETION_NONE,
        FALSE
    );

    return status;
}

INT_IPC_TARGETS_STATE
IntQueryIpcTargetsState(
)
{
    VCPU* vcpu = HvGetCurrentVcpu();
    GUEST* guest = vcpu ? vcpu->Guest : NULL;

    if (vcpu && vcpu->AttachedPcpu->VmxActivated && GstIsSafeToInterrupt(guest))
        return INT_IPC_TARGETS_STATE_ALL_SELECTED_REACHABLE;

    return INT_IPC_TARGETS_STATE_NONE_SELECTED_REACHABLE;
}

NTSTATUS
IntSendIpcInterrupt(
    _In_ QWORD CpuAffinity
)
{
    INT_IPC_TARGETS_STATE state = IntQueryIpcTargetsState();

    if (state != INT_IPC_TARGETS_STATE_ALL_SELECTED_REACHABLE)
        return CX_STATUS_COMPONENT_NOT_READY;

    IpiSendVector(CpuAffinity, NAPOCA_IPC_INIT_VECTOR);

    return CX_STATUS_SUCCESS;
}
/// @}
