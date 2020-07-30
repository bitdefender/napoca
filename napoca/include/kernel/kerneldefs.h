/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// KERNELDEFS - common kernel definitions

#ifndef _KERNELDEFS_H_
#define _KERNELDEFS_H_

#ifndef NAPOCA_BUILD
#pragma message("This header shouldn't be needed and included outside of the napoca project!")
#else

#include "core.h"
#include "kernel/pcpu_common.h"

#endif // NAPOCA_BUILD


#include "vecommon.h"



#define NAPOCA_MIN_CPU_COUNT                1


//
// ACPI / POWER management specific wake zones
//
///
/// TODO/FIXME: Determine a zone that can be used for Wakeup (resume) code
///

#define NAPOCA_ACPI_WAKE_ZONE32_LENGTH          0x4000                  // 4 page structures are necessary (allow mapping 0-2MB range)


//
// VA space constants
//
#define NAPOCA_USE_DISTINCT_NMI_STACK           0                       // set to 1 to enable a separate NMI stack for each PCPU
#define NAPOCA_KERNEL_BASE                      CX_TERA

//
// This is where dynamically allocated VAs start
//
#define NAPOCA_DYNAMIC_VA_START                 (2 * CX_TERA)
#define NAPOCA_DYNAMIC_VA_END                   ((8 * CX_TERA) - 1)

typedef struct _NAPOCA_IDT_GDT_TSS
{
    CX_UINT8 Idt[CX_PAGE_SIZE_4K];
    CX_UINT8 Gdt[CX_PAGE_SIZE_4K];
    CX_UINT8 Tss[CX_PAGE_SIZE_4K];
}NAPOCA_IDT_GDT_TSS;

#define NAPOCA_CPU(cpuIndex)                    HvGetCpu(cpuIndex)
#define NAPOCA_CPU_STACK_SIZE                   (NAPOCA_USE_DISTINCT_NMI_STACK? 8 * PAGE_SIZE : 16 * PAGE_SIZE)
#define NAPOCA_CPU_NMI_STACK_SIZE               (NAPOCA_USE_DISTINCT_NMI_STACK? 8 * PAGE_SIZE : 0)
#define NAPOCA_CPU_DBF_STACK_SIZE               (8*PAGE_SIZE)
#define NAPOCA_CPU_MC_STACK_SIZE                (8*PAGE_SIZE)
#define NAPOCA_CPU_VMX_ON_SIZE                  (PAGE_SIZE)

#define NAPOCA_GUEST_VMCS_LENGTH                (64 * CX_KILO)          // VA space / VMCS

#define NAPOCA_FASTMAP_BASE                     (9 * TERA)
#define NAPOCA_FASTMAP_LENGTH                   (CX_GIGA)
#define NAPOCA_FASTMAP_SLOT_LENGTH              (2 * CX_MEGA)           // MPORTANT: a slot MUST always be no more than 2M (this ensures we have 1 single PT corresponding)

#define NAPOCA_HEAP_ALLOCATOR_BASE              (16 * CX_TERA)
#define NAPOCA_PER_HEAP_ALLOCATOR_LENGTH        (512 * CX_GIGA)         // up to 16 allocators (?? why/what/who ??)

#define NAPOCA_VA_ALLOCATOR_BASE                (24 * CX_TERA)
#define NAPOCA_PER_VA_ALLOCATOR_LENGTH          (512 * CX_GIGA)         // up to 16 guest dedicated allocators

#define NAPOCA_FAST_ALLOCATORS_VA_BASE          (96 * CX_TERA)
#define NAPOCA_FAST_ALLOCATORS_VA_SIZE          (2 * CX_TERA)

#define NAPOCA_PAGING_STRUCTURES                (98 * CX_TERA)
#define NAPOCA_PAGING_STRUCTURES_SIZE           (16 * CX_TERA)

#define NAPOCA_NEXT_FREE_RANGE                  (114 * CX_TERA)

#define NAPOCA_ABSOLUTE_MAX_VA                  ((127 * CX_TERA) - 1)   // 127T - 1


#define NAPOCA_HIGH_CANONICAL_BASE              0xFFFF800000000000ULL   // 128T, 48 bit canonical VA address space "high half", reserved
#define NAPOCA_HIGH_CANONICAL_LENGTH            0x0000800000000000ULL   // 128T


#define NAPOCA_MAX_PARALLELIZATION              1                       // absolute upper limit for parallelization (shall never exceed 16)

#define NAPOCA_MAX_GUESTS                       4
#define NAPOCA_MAX_PER_GUEST_CPU                BOOT_MAX_CPU_COUNT      // 64

#define NAPOCA_OXFORD_VA_SIZE                   (2 * PAGE_SIZE)         // 2 pages


#endif // _KERNELDEFS_H_
