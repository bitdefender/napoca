/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \defgroup ipc Inter Process Communication
/// @{

// INTERRUPT - Interrupt Handling

#ifndef _INTERRUPT_H_
#define _INTERRUPT_H_

#include "core.h"
#include "apic/lapic.h"
#include "boot/boot.h"
#include "kernel/exceptions.h"
#include "queue_ipc_common.h"

typedef struct _GUEST GUEST;

typedef struct _VCPU VCPU;

#define NAPOCA_NMI_VECTOR               0x02    ///< Interrupt vector
#define NAPOCA_IPC_INIT_VECTOR          0x01    ///< Init vector for Napoca
#define NAPOCA_LVT_PERF_VECTOR          0xFE

/**
 * @brief           Wrapper over IpcSendCpuMessage2.
 * @brief           Send a NAPOCA specific message to the given physical CPUs specified in Affinity, with IPI delivery mode.
 * @brief           If WaitForCompletion is TRUE, the function will not return until all destination CPUs complete executing the Handler.
 *
 * @param[in]       Handler                 The handler (function) to execute on the target processors.
 * @param[in]       Context                 A parameter that will be given to the handler.
 * @param[in]       Affinity                Target CPUs affinity. Bit 0 is for CPU with BootInfoIndex = 0, and so on.
 * @param[in]       WaitForCompletion       If TRUE, this function doesn't return until all target CPUs finished executing the Handler.
 *
 * @return          IpcSendCpuMessage2 return status
 */
NTSTATUS
IntSendIpcMessage(
    _In_ PNAPOCA_IPI_HANDLER Handler,
    _In_ PVOID Context,
    _In_ QWORD Affinity,
    _In_ BOOLEAN WaitForCompletion
);

/**
 * @brief           Handle for NMI interrupts.
 */
VOID
IntNmiHandler(
);

#define VCPU_AFFINITY_BY_VCPU(Vcpu)                         (1ull << (Vcpu->GuestCpuIndex))     ///< Get the affinity state from an affinity bitmap by the vcpu structure
#define VCPU_AFFINITY_BY_VCPU_INDEX(Index)                  (1ull << (Index))                   ///< Get the affinity state from an affinity bitmap by the vcpu index

#define VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_GUEST(Guest)    (VCPU_AFFINITY_BY_VCPU_INDEX(Guest->VcpuCount) - 1)         ///< Produces an affinity bitmap that denotes all vcpus including the current one in a given guest
#define VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_VCPU(Vcpu)      VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_GUEST(Vcpu->Guest)      ///< Produces an affinity bitmap that denotes all vcpus including the current one in the guest of a given vcpu

#define VCPU_AFFINITY_ALL_EXCLUDING_SELF(Vcpu)              (VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_VCPU(Vcpu) - VCPU_AFFINITY_BY_VCPU(Vcpu))  ///< Produces an affinity bitmap that denotes all vcpus excluding the current one in the guest of a given vcpu

/**
 * @brief           Configures the Interrupt-window exiting bit from the processor based vm execution control field.
 * @brief           If this control is 1, a VM exit occurs at the beginning of any instruction if RFLAGS.IF = 1 and there are no other blocking of interrupts
 * @brief           For more informations see Chapter 24.6 from Intel Manual
 *
 * @param[in]       Enable                  The state in which the Interrupt-window exiting bit will be configured
 */
VOID
HvControlInterruptWindowExiting(
    _In_ BOOLEAN    Enable
);

/**
 * @brief           Method for pausing CPU(s) in host.
 *
 * @param[in]       Guest                   Pointer to the current guest structure.
 * @param[in]       VcpuIndexAffinity       Bitmap used to determine which CPU(s) to pause.
 * @param[in]       WaitForPause            Pointer to an IPC message, currently not used.
 *
 * @return          CX_STATUS_SUCCESS       The method was successful
 */
NTSTATUS
HvPauseVcpus(
    _In_ GUEST* Guest,
    _In_ QWORD VcpuIndexAffinity,
    _In_ BOOLEAN WaitForPause
    );

/**
 * @brief           Method for resuming paused CPU(s).
 *
 * @param[in]       Guest                   Pointer to the current guest structure.
 * @param[in]       VcpuIndexAffinity       Bitmap used to determine which CPU(s) to resume.
 *
 * @return          CX_STATUS_SUCCESS       The method was successful
 */
NTSTATUS
HvResumeVcpus(
    _In_ GUEST* Guest,
    _In_ QWORD VcpuIndexAffinity
    );

// Generic mechanism causing given CPU(s) to check their message queues

/**
 * @brief           Sends interrupts to requested CPU(s) if the guest state permits it
 *
 * @param[in]       CpuAffinity                     The CPU(s) required to be interrupted.
 *
 * @return          CX_STATUS_SUCCESS               If the method succeeded
 * @return          CX_STATUS_COMPONENT_NOT_READY   If the guest state does not permit interrupts
 */
NTSTATUS
IntSendIpcInterrupt(
    _In_ QWORD CpuAffinity
);

// Generic mechanism for finding out if the hardware supports sending an interrupt to the given CPU(s)
typedef enum
{
    INT_IPC_TARGETS_STATE_ALL_SELECTED_REACHABLE,   ///< All specified cpus should be capable of receiving an IPC-related interrupt
    INT_IPC_TARGETS_STATE_SOME_SELECTED_REACHABLE,  ///< Of all specified cpus, some are and some aren't capable of receiving an IPC-related interrupt
    INT_IPC_TARGETS_STATE_NONE_SELECTED_REACHABLE,  ///< None of the specified cpus are capable of receiving an IPC-related interrupt
} INT_IPC_TARGETS_STATE;

/**
 * @brief           Tests if the current vcpu structure is active and the guest is in a position where it can be interrupted
 *
 * @return          INT_IPC_TARGETS_STATE_ALL_SELECTED_REACHABLE if the vcpu can be interruptible
 * @return          INT_IPC_TARGETS_STATE_NONE_SELECTED_REACHABLE otherwise
 */
INT_IPC_TARGETS_STATE
IntQueryIpcTargetsState(
);

#endif // _INTERRUPT_H_
/// @}
