/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file pcpu.h
*   @brief Defines an abstraction / logical view of the physical processors of a system
*/
#ifndef _PCPU_H_
#define _PCPU_H_

#include "core.h"
#include "kernel/kerneldefs.h"
#include "kernel/interrupt.h"
#include "kernel/spinlock.h"
#include "kernel/kerneltypes.h"
#include "data_structures/cx_lockless_queue.h"
#include "io/io.h"
#include "kernel/pcpu_common.h"
#include "kernel/queue_ipc_common.h"

/// use some forward declarations to break dependencies
typedef struct _VCPU VCPU;
typedef struct _IPC_MESSAGE IPC_MESSAGE;
typedef struct _CPU_IPC_QUEUE CPU_IPC_QUEUE;


typedef struct _CPU_IPC_QUEUE
{
    CX_LLQUEUE                  Queue;
    CX_BOOL                     Enabled;
    CX_BOOL                     Initialized;
    IPC_PRIORITY                Priority;
    CX_UINT64                       LastProcessedTsc;
    CX_UINT64                       LastBlockedTsc;
    volatile CX_UINT32              TotalPendingMessages;
    volatile CX_UINT64              TotalDroppedMessages;

    union
    {
        volatile CX_UINT64 TotalTlbEntries; // valid only for the VA TLB invalidation
    } CustomState; // some of the queues might have specific fields here

    IPC_QUEUE_CONSUMER_CALLBACK CustomQueueConsumerRoutine; // only needed for collapsing all messages or other such (custom) optimizations

    BYTE* QueueBuffer;
}CPU_IPC_QUEUE;

typedef struct _PCPU {
#pragma pack(push)
#pragma pack(1)
    struct __CPU_ASM_FIELDS__ // please keep in sync with pcpu.nasm
    {
        CX_VOID* Self;                          ///< Pointer back to this CPU structure
        CX_UINT32 Id;                           ///< Local APIC ID (based on CPUID.01H:EBX[31-24], xAPIC)
        CX_UINT32 BootInfoIndex;                ///< Software index (BSP always has index 0)
        CX_BOOL VmxActivated;                   ///< TRUE if VMXON was successfully done and no VMXOFF was executed
        CX_BOOL IsIntel;                        ///< TRUE for Intel CPUs
        VCPU* Vcpu;                             ///< The 'current' VCPU / VMCS, if any (or NULL), assigned to this CPU
        CX_UINT64 VmxOnPa;                      ///< Opaque VMXON region HPA
        CX_UINT64 TempRCX;                      ///< Temporary storage for RCX on VM EXIT callbacks
        CX_UINT64 TopOfStack;                   ///< RSP for VM EXIT handlers

        CX_BOOL UseXsave;                       ///< If TRUE, then use XSAVE / XRESTOR to save / restore the fpu/mmx/sse/avx state, otherwise use legacy FXSAVE / FXRESTOR
        CX_BOOL UseXsaveopt;                    ///< If TRUE, we will use XSAVEOPT instead of XSAVE
        CX_UINT32 FpuSaveSize;                  ///< The size of the area needed for FXSAVE / XSAVE / XSAVEOPT, dynamically allocated
        union
        {
            struct
            {
                CX_UINT32 Xcr0AvailMaskLow;
                CX_UINT32 Xcr0AvailMaskHigh;
            };

            CX_UINT64 Xcr0AvailMask;            ///< Available and enabled feature set in this CPUs XCR0 (based on CPUID.(EAX=0DH, ECX=0).EDX:EAX)
        };
    };
    // END-OF-ASM-FIELDS
#pragma pack(pop)

    CX_UINT64 Affinity;                         ///< Software affinity (based on BootInfoIndex, 1 << BootInfoIndex)

    INTERRUPT_GATE* IdtBase;                    ///< IDT base

    struct {
        CX_UINT32 OriginalLvtPmcr;              ///< Original value of the LVT Performance Monitor Counter Register on the LAPIC
        CX_UINT64 PerfCounterRate;              ///< PMC rate, in seconds

        CX_UINT64 StartingRootModeTsc;          ///< The last TSC saved when entering root mode (or after reseting it)
        CX_UINT64 OverflowCount;                ///< The number of overflows occured
    }NmiWatchDog;

    struct
    {
        CX_UINT64 DebugBreak : 1;               ///< When TRUE, this CPU will debug break at next exit
        CX_UINT64 HasRepGranularityBug : 1;     ///< We need this for those CPUs on which rep instructions do not exit at expected granularity
    };

    // FPU / MMX / SSE / AVX handling
    CX_UINT32 HostMxcsr;                        ///< Saved Host MXCSR value - might not be needed
    CX_UINT64 StartupXCR0;                      ///< The value of XCR0 when hv is started, no save/restore of fpu context has been done, no VMLAUNCH/RESUME done

    // debug store related fields
    struct
    {
        CX_VOID* BtsBufferBase;
        CX_UINT64 BtsIndex;
        CX_UINT64 BtsAbsolutMaximum;
        CX_UINT64 BtsInterruptThreshold;
    } DebugStore;

    CX_UINT64 Dr7;                              ///< Saved HOST DR7 - might not be needed

    SMX_CAPABILITIES SmxCapabilities;           ///< SMX capabilities for this CPU

    IO_PER_CPU_DATA* IoPerCpuData;              ///< IO DATA - store a pointer to this structure in CPU in order to avoid lookup

    CX_UINT64 StartTsc;                         ///< The value of TSC when hv is started
    CX_UINT64 LastExitTsc;                      ///< The value of TSC entering root mode

    // communication queue
    struct {
        CPU_IPC_QUEUE Queue[IPC_PRIORITY_TOTAL_DISTINCT_LEVELS];
        volatile CX_UINT8 QueueIsBeingDrained;
        volatile CX_UINT64 QueueTotalPendingMessages;
    } Ipc;

    volatile CX_UINT32 CpuIsDead;               ///< TRUE if the HV already tried to unload after catching an unhandled exception

    struct
    {
        NAPOCA_IDT_GDT_TSS* IdtGdtTss;          ///< Layout of the idt + gdt + tss memory
        CX_VOID* Stack;                         ///< Base of root-mode stack
        CX_VOID* DfStack;                       ///< Base of root-mode stack for handling Double-Faults
        CX_VOID* NmiStack;                      ///< Base of root-mode stack for handling NMIs
        CX_VOID* McStack;                       ///< Base of root-mode stack for handling Machine-Check exceptions
        CX_VOID* VmxonRegion;                   ///< Opaque VMXON region HVA
    }MemoryResources;
} PCPU;

typedef struct _DUMMY_CPU
{
    // this should be always NULL
    void            *Self;
} DUMMY_CPU;
static_assert(FIELD_OFFSET(DUMMY_CPU, Self) == FIELD_OFFSET(PCPU, Self),  "These must be equal!\n");

typedef struct
{
    CX_UINT32 NumberOfEntries;
    IPC_QUEUE_CONSUMER_CALLBACK CustomConsumer;
}IPC_QUEUE_PROPERTIES;


extern const IPC_QUEUE_PROPERTIES gCpuIpcQueueProperties[IPC_PRIORITY_TOTAL_DISTINCT_LEVELS];

__forceinline
CPU_IPC_QUEUE *
CpuGetIpcQueue(
    _In_ PCPU* Cpu,
    _In_ IPC_PRIORITY Priority
)
{
    return &Cpu->Ipc.Queue[Priority];
}


__forceinline char CpuPerformVmxon(
    _Inout_ PCPU* Cpu
    )
{
    unsigned char ret = 0;
    if (!Cpu->VmxActivated)
    {
        // turn on CR4.VMXE
        __writecr4(__readcr4() | CR4_VMXE);

        ret = __vmx_on(&Cpu->VmxOnPa);
        if (ret == 0)
        {
            Cpu->VmxActivated = TRUE;
        }
    }

    return ret;
}

__forceinline void CpuPerformVmxoff(
    _Inout_ PCPU* Cpu
)
{
    if (Cpu->VmxActivated)
    {
        Cpu->VmxActivated = FALSE;
        __vmx_off();
        __writecr4(__readcr4() & (~CR4_VMXE));        // X86_CR4_VMXE
    }
}

__forceinline
CX_VOID
CpuBindStructureToGs(
    PCPU *CpuStructureAddress
)
{
    __writemsr(MSR_IA32_GS_BASE, (unsigned __int64)CpuStructureAddress);
}


#endif // _PCPU_H_
