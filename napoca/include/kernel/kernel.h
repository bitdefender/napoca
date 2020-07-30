/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file kernel.h
*   @brief Common include file for HV kernel
*/
#ifndef _KERNEL_H_
#define _KERNEL_H_

#include "napoca.h"

#pragma warning (push)
#include "acpi.h"
#pragma warning (pop)

#include "kernel/kerneldefs.h"
#include "kernel/kerneltypes.h"
#include "kernel/cpuops.h"
#include "kernel/time.h"
#include "kernel/spinlock.h"
#include "kernel/rwspinlock.h"
#include "kernel/recspinlock.h"
#include "kernel/exceptions.h"
#include "common/kernel/vmxdefs.h"
#include "kernel/vcpu.h"
#include "kernel/interrupt.h"
#include "kernel/emu.h"
#include "kernel/cleanup.h"
#include "kernel/vmx.h"

#include "memory/memmgr.h"
#include "memory/heap.h"

#include "guests/pci.h"
#include "guests/guests.h"
#include "guests/power.h"

#include "debug/debugger.h"

#include "apic/lapic.h"
#include "apic/ipi.h"

#include "glueiface.h"

/// @brief Array of #UD_VAR_INFO which describe a configuration variable
extern UD_VAR_INFO HvCommandLineVariablesInfo[];
/// @brief Number of configuration variables
extern DWORD HvCommandLineVariablesInfoCount;

#pragma pack(push)
#pragma pack(8)
/// @brief The structure in which all the global data of the hv are maintained
typedef struct _GLOBAL_DATA
{
    // boot flags
    struct
    {
        CX_BOOL IsWakeup;                   ///< TRUE if S3 Wakeup is performed
        CX_BOOL WakeupPerformedAtLeastOnce; ///< TRUE if at least one S3 wakeup was performed
        CX_BOOL IsGrub;                     ///< TRUE if legacy boot where GRUB is used
    }BootFlags;

    // some CPU related global info
    struct
    {
        BOOLEAN     IsIntel;                    ///< TRUE for INTEL CPUs, FALSE for AMD
        DWORD       MaxBasicCpuidInputValue;    ///< Largest value that EAX can be set to before calling CPUID
        DWORD       MaxExtendedCpuidInputValue; ///< Highest Extended Function Implemented

        DWORD       CpuCount;                   ///< Effective BSP + AP count
        DWORD       MaxParallel;                ///< Must be less or equal to NAPOCA_MAX_PARALLELIZATION (same to CpuCount)

        PCPU        *Cpu[BOOT_MAX_CPU_COUNT];   ///< Array of pointers to #PCPU structures
    }CpuData;

    struct
    {
        BOOLEAN     StageFinalMappings;         ///< TRUE, if all CPUS are initialized (GS, stacks, IDT, GDT, TSS, exception handling, etc)
                                                /// and also all memory allocation (PP, VA, HEAP) init was successfully done

        BOOLEAN     StageTwoDone;               ///< TRUE, after EPT, VMX, APIC virtualization and initial GUEST setups are all done
        BOOLEAN     PrimaryGuestInited;         ///< TRUE, after the primary guest structures are initialized
    }BootProgress;

    struct
    {
        QWORD       KernelImageLength;          ///< HV binary length

        QWORD       TotalSystemPhysicalMemory;  ///< The total bytes of available physical RAM in the system
        QWORD       EstimatedHvLength;          ///< Estimated length for HV zone, based on TotalSystemPhysicalMemory
        QWORD       TotalHvLength;              ///< Total memory allocated for HV (might slightly differ from EstimatedHvLength)
        BYTE        *KzBase;                    ///< KZ zone base address
        QWORD       KzLength;                   ///< Length of KZ zone
        BYTE        *PpBase;                    ///< PP zone base address
        QWORD       PpLength;                   ///< Length of PP zone

        MMAP        PhysMap;                    ///< Map of system physical memory
        MMAP        HyperMap;                   ///< Map of Hypervisor memory
        MMAP        AcpiMap;                    ///< ACPI map
        MMAP        GuestAreaMap;               ///< Memory allocated for guest related stuff
        QWORD       TotalGuestSpace;            ///< Total memory reserved for guest machines, except the PRIMARY GUEST
        QWORD       FreeGuestSpace;             ///< Free space for new guests

        BYTE        *ApTrampolineBackup;        ///< Backup for memory used trampoline code for APs

        QWORD       PerPpaPageCount;            ///< Minimum total pages per serialized PP allocator

        MTRR_STATE  MtrrState;                  ///< MTRRs info from host hardware
    }MemInfo;

    // guests
    volatile INT32  GuestCount;                 ///< Number of GUESTs
    GUEST*          Guest[NAPOCA_MAX_GUESTS];   ///< Array of pointers to #Guest structures

    // introspection support
    struct
    {
        GLUE_IFACE      GlueIface;              ///< The glue interface which ties together the introspection engine and Napoca
        UPPER_IFACE     UpperIface;             ///< The upper interface which contains some primitive low-level functions needed by the Introspection engine
        VOID            *FastmapVaPtr;          ///< Base virtual address of the reserved fast allocators memory range for introspection
        QWORD           *FastmapPtPtr;          ///< The base physical address of the Page Table from the FastMap

        QWORD           ExceptionsUpdateVa;     ///< Virtual address of the base of the Exceptions module loaded for introspection
        DWORD           ExceptionsUpdateSize;   ///< The size of the currently loaded Exceptions module loaded for introspection
        QWORD           IntroUpdatesVa;         ///< Virtual address of the base of the Intro Live Updates module loaded for introspection
        DWORD           IntroUpdatesSize;       ///< The size of the currently loaded Intro Live Updates module loaded for introspection
    }Introspection;

    PCI_SYSTEM      *Pci;   ///< PCI infos from host hardware

    // global ring buffer
    struct
    {
        QWORD              SharedBufferHpa;     ///< Physical address of the buffer shared with the guest
        PCOMM_SHMEM_HEADER SharedMem;           ///< Structure which describe the shared memory
        LIST_ENTRY         Ports;               ///< Ports used to communicate
        SPINLOCK           Lock;                ///< Lock used to synchronize communication
    }Comm;

    struct
    {
        // Machine Check handling
        volatile QWORD  McRecvdAffinity;    ///< Mask that determines which CPUs received the EXCEPTION_MACHINE_CHECK exception
        QWORD           AffinifyMask;       ///< Mask with all CPUs
    }Debug;

     struct
    {
        ACPI_TABLE_MCFG *Mcfg;  ///< MCFG table received with the help of ACPICA
        ACPI_TABLE_FADT *Fadt;  ///< FADT table received with the help of ACPICA
        ACPI_TABLE_FACS *Facs;  ///< FACS table received with the help of ACPICA
    }AcpiData;
} GLOBAL_DATA;
#pragma pack(pop)

/// @brief Variable with which we provide direct access to the global data of the hypervisor
extern GLOBAL_DATA gHypervisorGlobalData;

#endif // _KERNEL_H_
