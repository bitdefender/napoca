/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file phase1.h Host system scanning and hypervisor configuration

#ifndef _PHASE1_H_
#define _PHASE1_H_

/// \addtogroup phase1
/// @{

#include "core.h"
#include "kernel/exceptions.h"

typedef struct _PCI_SYSTEM *PPCI_SYSTEM;
typedef struct _PCPU PCPU;


/// @brief Performs the complete PHASE1 initialization on the BSP processor
///
/// Likely the most important for the initialization of the hypervisor
///
/// The following major steps are executed:
///   - validate required features of the CPU on the BSP
///   - set up host registers and initialize FPU
///   - set up a temporary exception handling for the BSP
///   - build an internal MTRR state
///   - get the physical memory map
///   - create the memory map for hypervisor
///   - set up the virtual address space (temporary)
///   - initialize memory allocators (PA, VA, HEAP)
///   - initialize ACPI (partially)
///   - query processor count
///   - initialize memory maps
///   - initialize each CPU (PCPU structure, stacks, IDT, GDT, ...)
///   - switch to final CPU stack
///   - initialize the local APIC for our needs
///   - set up final exception handling
///   - initialize basic debugging
///   - trigger the APs to get to the start of phase 1 and wait for them
///   - preinitialize PCI system (for potential debugging purposes)
///   - scan ACPI table for relevant info
///   - search and mark devices (for potential debugging purposes)
///   - load memory resources from the ACPI tables
///   - initialize FX restoration
///   - trigger APs execute their phase 1
///   - synchronize TSCs on all CPUs
///   - activate VMX
NTSTATUS
Phase1BspStageOne(
    void
    );

/// @brief Performs the PHASE I initialization for the AP processor(s)
///
/// The following major steps are executed:
///   - set up host registers and initialize FPU
///   - load the prepared IDT/GDT/TSS information
///   - switch to final CPU stack
///   - initialize FX restoration
///   - activate VMX
NTSTATUS
Phase1ApStageOne(
    void
    );


/// @brief Initializes the GDT and IDT tables (with basic #0 - #19 exception handlers for the hypervisor) and activates the tables on the BSP.
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, exception handling set up
/// @returns    OTHER                               - Other internal error
NTSTATUS
Phase1InitExceptionHandling(
    void
    );

/// @brief Signal the APs that they can proceed with their phase 1 and wait for them
///
/// @returns    CX_STATUS_SUCCESS                   - Always
NTSTATUS
Phase1TriggerAPsToStartAndWaitForCompletion(
    void
    );

/// @brief Activates VMXE on the current PCPU and initializes the per-PCPU VMXON region according to Intel specs,
/// then effectively performs the __VMX_ON instruction
///
/// @returns    CX_STATUS_SUCCESS                     - All good, virtualization activated
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED     - Unable to activate VMX
NTSTATUS
Phase1InitializePerCpuVmxOnZone(
    void
    );

/// @brief Initialize the CR0, CR4 of the current physical host CPU according to the needs of FXSAVE / XSAVE / XSETBV instructions.
///
/// It also initialize the FPU and disable the interrupts on the CPU.
void
Phase1InitializeHostControlRegisters(
    void
    );

/// @brief Loads the IDTR, GDTR, TR (TSS) registers for the current physical CPU
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, registers set up
/// @returns    OTHER                               - Other internal error
NTSTATUS
Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu(
    VOID
);

/// @brief Wakes up all AP processors and get them ready to continue with the phase 1 initialization
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected
/// @returns    OTHER                               - Other internal error
NTSTATUS
Phase1WakeupAllApProcessorsAndThemIntoPhase1(
    void
    );

/// @brief Initializes the support for FXSAVE / XSAVE / XSAVEOPT for the current PCPU
void
Phase1InitializePerCpuFxRestoration(
    void
    );

/// @brief Set up the queues used for inter process communication
///
/// @param[in]  Cpu             The PCPU for which the queue will be set up
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the queues are set up
/// @returns    OTHER                               - Internal error
NTSTATUS
Phase1SetupCpuIpcQueue(
    _In_ PCPU* Cpu
);

/// @brief Final callback used for allocating paging structures, using final page pool
CX_STATUS
FinalAllocPagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ CX_UINT8 TableDepth,
    _Out_ MEM_ALIGNED_VA* Va,
    _Out_ MEM_ALIGNED_PA* Pa
);

/// @brief Final callback used for freeing paging structures, using final page pool
CX_STATUS
FinalFreePagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ MEM_ALIGNED_VA Va,
    _In_ MEM_ALIGNED_PA Pa
);

/// @brief Final callback used for allocating virtual addresses, using final VA manager
CX_STATUS
FinalAllocVaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA* Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

/// @brief Final callback used for freeing virtual addresses, using final VA manager
CX_STATUS
FinalFreeVaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA* Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
);

// temporary IDT for BSP
extern __declspec(align(16)) INTERRUPT_GATE gTempBspIdt[32];

/// @}

#endif // _PHASE1_H_