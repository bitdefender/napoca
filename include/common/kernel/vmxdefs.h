/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// VMXDEFS - Intel VMX specific definitions

#ifndef _VMXDEFS_H_
#define _VMXDEFS_H_
#include "cx_native.h"
//
// VMX related MSRs
//
#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48D
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48E
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48B
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48F
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490
#define MSR_IA32_VMX_MISC                       0x485
///#define MSR_IA32_VMX_CR0_FIXED0                 0x486
///#define MSR_IA32_VMX_CR0_FIXED1                 0x487
///#define MSR_IA32_VMX_CR4_FIXED0                 0x488
///#define MSR_IA32_VMX_CR4_FIXED1                 0x489
///#define MSR_IA32_VMX_VMCS_ENUM                  0x48A
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48C
#define MSR_IA32_VMFUNC                         0x491

#define MSR_IA32_FEATURE_CONTROL                0x3A
#define MSR_IA32_DEBUGCTL                       0x1D9   // check out Intel Vol 3B, Appendix B
#define MSR_IA32_SYSENTER_CS                    0x174
#define MSR_IA32_SYSENTER_RSP                   0x175
#define MSR_IA32_SYSENTER_RIP                   0x176
#define MSR_IA32_PERF_GLOBAL_STATUS             0x38E
#define MSR_IA32_PERF_GLOBAL_CTRL               0x38F
#define MSR_IA32_PERF_GLOBAL_STATUS_RESET       0x390
#define MSR_IA32_PAT                            0x277
#define MSR_IA32_EFER                           0xC0000080

#define MSR_IA32_STAR                           0xC0000081
#define MSR_IA32_LSTAR                          0xC0000082
#define MSR_IA32_CSTAR                          0xC0000083
#define MSR_IA32_FMASK                          0xC0000084

#define MSR_IA32_MTRRCAP                        0x0FE   // check out Intel Vol 3A, 11.11, "Memory Type Range Registers"
#define MSR_IA32_MTRR_PHYSBASE0                 0x200   // + 2 * N for base MSR of MTRR-N
#define MSR_IA32_MTRR_PHYSMASK0                 0x201   // + 2 * N for mask MSR of MTRR-N
#define MSR_IA32_MTRR_DEF_TYPE                  0x2FF
#define MSR_IA32_MTRR_FIX64K_00000              0x250
#define MSR_IA32_MTRR_FIX16K_80000              0x258
#define MSR_IA32_MTRR_FIX16K_A0000              0x259
#define MSR_IA32_MTRR_FIX4K_C0000               0x268
#define MSR_IA32_MTRR_FIX4K_C8000               0x269
#define MSR_IA32_MTRR_FIX4K_D0000               0x26A
#define MSR_IA32_MTRR_FIX4K_D8000               0x26B
#define MSR_IA32_MTRR_FIX4K_E0000               0x26C
#define MSR_IA32_MTRR_FIX4K_E8000               0x26D
#define MSR_IA32_MTRR_FIX4K_F0000               0x26E
#define MSR_IA32_MTRR_FIX4K_F8000               0x26F

#define MSR_IA32_EFER                           0xC0000080
#define MSR_IA32_FS_BASE                        0xC0000100
#define MSR_IA32_GS_BASE                        0xC0000101
#define MSR_IA32_KERNEL_GS_BASE                 0xC0000102
#define MSR_IA32_TSC_AUX                        0xC0000103

#define MSR_IA32_TSC                            0x010
#define MSR_IA32_PLATFORM_ID                    0x017
#define MSR_IA32_APIC_BASE                      0x01B
#define MSR_IA32_BIOS_SIGN_ID                   0x08B

#define MSR_IA32_TSC_DEADLINE                   0x6E0

#define MSR_IA32_PMC0                           0x0C1
#define MSR_IA32_PMC1                           0x0C2
#define MSR_IA32_PMC2                           0x0C3
#define MSR_IA32_PMC3                           0x0C4
#define MSR_IA32_PMC4                           0x0C5
#define MSR_IA32_PMC5                           0x0C6
#define MSR_IA32_PMC6                           0x0C7
#define MSR_IA32_PMC7                           0x0C8

#define MSR_IA32_MPERF                          0x0E7
#define MSR_IA32_APERF                          0x0E8
#define MSR_IA32_MCG_CAP                        0x179
#define MSR_IA32_MCG_STATUS                     0x17a
#define MSR_IA32_PERFEVTSEL0                    0x186
#define MSR_IA32_PERFEVTSEL1                    0x187
#define MSR_IA32_PERFEVTSEL2                    0x188
#define MSR_IA32_PERFEVTSEL3                    0x189
#define MSR_IA32_PERF_STATUS                    0x198
#define MSR_IA32_PERF_CTL                       0x199
#define MSR_IA32_CLOCK_MODULATION               0x19A
#define MSR_IA32_THERM_INTERRUPT                0x19B
#define MSR_IA32_THERM_STATUS                   0x19C
#define MSR_IA32_THERM2_CTL                     0x19D
#define MSR_IA32_MISC_ENABLE                    0x1A0
#define MSR_IA32_PERF_ENERGY_BIAS               0x1B0
#define MSR_IA32_FIXED_CTR_CTRL                 0x38D
#define MSR_IA32_MC0_CTL                        0x400


#define MSR_IA32_PM_ENABLE                      0x770
#define MSR_IA32_HWP_CAPABILITIES               0x771
#define MSR_IA32_HWP_REQUEST_PKG                0x772
#define MSR_IA32_HWP_INTERRUPT                  0x773
#define MSR_IA32_HWP_REQUEST                    0x774
#define MSR_IA32_HWP_PECI_REQUEST_INFO          0x775
#define MSR_IA32_HWP_STATUS                     0x777
#define MSR_IA32_THERM_STATUS                   0x19C  // [bits 15:12]
#define MSR_IA32_PPERF                          0x64E


//
// Machine check
//
#define IA32_MCG_CTL_OFFSET                     0
#define IA32_MCG_STATUS_OFFSET                  1
#define IA32_MCG_ADDRESS_OFFSET                 2
#define IA32_MCG_MISC_OFFSET                    3
#define IA32_MCG_STATUS_VALID                   (1ULL<<63)
#define IA32_MCG_STATUS_OVER                    (1ULL<<62)
#define IA32_MCG_STATUS_UC                      (1ULL<<61)
#define IA32_MCG_STATUS_EN                      (1ULL<<60)
#define IA32_MCG_STATUS_MISC                    (1ULL<<59)
#define IA32_MCG_STATUS_ADDR                    (1ULL<<58)
#define IA32_MCG_STATUS_PCC                     (1ULL<<57)
#define IA32_MCG_STATUS_SC                      (1ULL<<56)
#define IA32_MCG_STATUS_AR                      (1ULL<<55)

// https://patchwork.kernel.org/patch/10145335/
// cpuid ax = 0x7, return rdx bit 26 to indicate presence of this feature
// IA32_SPEC_CTRL(0x48) and IA32_PRED_CMD(0x49)
#define MSR_IA32_SPEC_CTRL                      0x48
#define MSR_IA32_PRED_CMD                       0x49

//
// VMX VMCS offsets, conform Intel Vol 3B, Appendix H
//
#define VMCS_VPID                           0x00000000  // CX_UINT16
#define VMCS_POSTED_INT_NOTIF_VECTOR        0x00000002  // CX_UINT16
#define VMCS_EPTP_INDEX                     0x00000004  // CX_UINT16
#define VMCS_EPTP                           0x0000201A  // CX_UINT64
#define VMCS_SPPTP                          0x00002030  // CX_UINT64

#define VMCS_TSC_OFFSET                     0x00002010  // 64bit control field

#define VMCS_VIRTUAL_APIC_ADDR              0x00002012  // CX_UINT64
#define VMCS_APIC_ACCESS_ADDR               0x00002014  // CX_UINT64
#define VMCS_TPR_THRESHOLD                  0x0000401C  // CX_UINT32

#define VMCS_GUEST_PDPTE0                   0x0000280A  // CX_UINT64
#define VMCS_GUEST_PDPTE1                   0x0000280C  // CX_UINT64
#define VMCS_GUEST_PDPTE2                   0x0000280E  // CX_UINT64
#define VMCS_GUEST_PDPTE3                   0x00002810  // CX_UINT64

#define VMCS_PIN_BASED_EXEC_CONTROL         0x00004000  // CX_UINT32
#define VMCS_PROC_BASED_EXEC_CONTROL        0x00004002  // CX_UINT32
#define VMCS_PROC_BASED_EXEC_CONTROL_2      0x0000401E  // CX_UINT32
#define VMCS_VM_EXIT_CONTROL                0x0000400C  // CX_UINT32
#define VMCS_VM_ENTRY_CONTROL               0x00004012  // CX_UINT32
#define VMCS_EXCEPTION_BITMAP               0x00004004  // CX_UINT32
#define VMCS_PAGE_FAULT_ERROR_CODE_MASK     0x00004006  // CX_UINT32
#define VMCS_PAGE_FAULT_ERROR_CODE_MATCH    0x00004008  // CX_UINT32
#define VMCS_VMX_PREEMPTION_TIMER           0x0000482E  // CX_UINT32

#define VMCS_CR3_TARGET_COUNT               0x0000400A  // CX_UINT32
#define VMCS_CR3_TARGET_VALUE_0             0x00006008  // CX_UINT64
#define VMCS_CR3_TARGET_VALUE_1             0x0000600A  // CX_UINT64
#define VMCS_CR3_TARGET_VALUE_2             0x0000600C  // CX_UINT64
#define VMCS_CR3_TARGET_VALUE_3             0x0000600E  // CX_UINT64

#define VMCS_IO_BITMAP_A                    0x00002000  // CX_UINT64
#define VMCS_IO_BITMAP_B                    0x00002002  // CX_UINT64
#define VMCS_MSR_BITMAP                     0x00002004  // CX_UINT64
#define VMCS_XSS_EXIT_BITMAP                0x0000202C  // CX_UINT64

#define VMCS_VM_EXIT_MSR_STORE_COUNT        0x0000400E  // CX_UINT32
#define VMCS_VM_EXIT_MSR_STORE_ADDRESS      0x00002006  // CX_UINT64
#define VMCS_VM_EXIT_MSR_LOAD_COUNT         0x00004010  // CX_UINT32
#define VMCS_VM_EXIT_MSR_LOAD_ADDRESS       0x00002008  // CX_UINT64
#define VMCS_VM_ENTRY_MSR_LOAD_COUNT        0x00004014  // CX_UINT32
#define VMCS_VM_ENTRY_MSR_LOAD_ADDRESS      0x0000200A  // CX_UINT64

#define VMCS_VM_ENTRY_EVENT_INJECTION       0x00004016  // CX_UINT32
#define VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE  0x00004018  // CX_UINT32
#define VMCS_VM_ENTRY_INSTRUCTION_LENGTH    0x0000401A  // CX_UINT32

#define VMCS_ERROR                          0x00004400  // CX_UINT32
#define VMCS_VM_EXIT_REASON                 0x00004402  // CX_UINT32
#define VMCS_VM_EXIT_QUALIFICATION          0x00006400  // CX_UINT64
#define VMCS_GUEST_LINEAR                   0x0000640A  // CX_UINT64
#define VMCS_GUEST_PHYSICAL                 0x00002400  // CX_UINT64
#define VMCS_VM_EXIT_INTERRUPTION_INFORMATION   0x00004404  // CX_UINT32
#define VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE    0x00004406  // CX_UINT32
#define VMCS_IDT_VECTORING_INFORMATTION         0x00004408  // CX_UINT32
#define VMCS_IDT_VECTORING_ERROR_CODE           0x0000440A  // CX_UINT32
#define VMCS_VM_EXIT_INSTRUCTION_LENGTH         0x0000440C  // CX_UINT32
#define VMCS_VM_EXIT_INSTRUCTION_INFORMATION    0x0000440E  // CX_UINT32

#define VMCS_VM_EXIT_QUALIFICATION_IS_VALID_GLA    0x80     ///< The guest linear-address field is valid for all EPT violations except those resulting from an attempt to load the
                                                            ///< guest PDPTEs as part of the execution of the MOV CR instruction.


// VMFUNC related
#define VMCS_VMFUNC_CONTROL                 0x00002018  // CX_UINT64
#define VMCS_EPTP_LIST_ADDRESS              0x00002024  // CX_UINT64

// #VE related
#define VMCS_VE_INFORMATION_ADDRESS         0x0000202A  // CX_UINT64

// guest related
#define VMCS_GUEST_CR0                      0x00006800  // CX_UINT64
#define VMCS_GUEST_CR3                      0x00006802  // CX_UINT64
#define VMCS_GUEST_CR4                      0x00006804  // CX_UINT64
#define VMCS_GUEST_DR7                      0x0000681A  // CX_UINT64
#define VMCS_GUEST_RSP                      0x0000681C  // CX_UINT64
#define VMCS_GUEST_RIP                      0x0000681E  // CX_UINT64
#define VMCS_GUEST_RFLAGS                   0x00006820  // CX_UINT64

#define VMCS_GUEST_CS                       0x00000802  // CX_UINT16
#define VMCS_GUEST_CS_BASE                  0x00006808  // CX_UINT64
#define VMCS_GUEST_CS_LIMIT                 0x00004802  // CX_UINT32
#define VMCS_GUEST_CS_ACCESS_RIGHTS         0x00004816  // CX_UINT32
#define VMCS_GUEST_SS                       0x00000804  // CX_UINT16
#define VMCS_GUEST_SS_BASE                  0x0000680A  // CX_UINT64
#define VMCS_GUEST_SS_LIMIT                 0x00004804  // CX_UINT32
#define VMCS_GUEST_SS_ACCESS_RIGHTS         0x00004818  // CX_UINT32
#define VMCS_GUEST_DS                       0x00000806  // CX_UINT16
#define VMCS_GUEST_DS_BASE                  0x0000680C  // CX_UINT64
#define VMCS_GUEST_DS_LIMIT                 0x00004806  // CX_UINT32
#define VMCS_GUEST_DS_ACCESS_RIGHTS         0x0000481A  // CX_UINT32
#define VMCS_GUEST_ES                       0x00000800  // CX_UINT16
#define VMCS_GUEST_ES_BASE                  0x00006806  // CX_UINT64
#define VMCS_GUEST_ES_LIMIT                 0x00004800  // CX_UINT32
#define VMCS_GUEST_ES_ACCESS_RIGHTS         0x00004814  // CX_UINT32
#define VMCS_GUEST_FS                       0x00000808  // CX_UINT16
#define VMCS_GUEST_FS_BASE                  0x0000680E  // CX_UINT64
#define VMCS_GUEST_FS_LIMIT                 0x00004808  // CX_UINT32
#define VMCS_GUEST_FS_ACCESS_RIGHTS         0x0000481C  // CX_UINT32
#define VMCS_GUEST_GS                       0x0000080A  // CX_UINT16
#define VMCS_GUEST_GS_BASE                  0x00006810  // CX_UINT64
#define VMCS_GUEST_GS_LIMIT                 0x0000480A  // CX_UINT32
#define VMCS_GUEST_GS_ACCESS_RIGHTS         0x0000481E  // CX_UINT32
#define VMCS_GUEST_TR                       0x0000080E  // CX_UINT16
#define VMCS_GUEST_TR_BASE                  0x00006814  // CX_UINT64
#define VMCS_GUEST_TR_LIMIT                 0x0000480E  // CX_UINT32
#define VMCS_GUEST_TR_ACCESS_RIGHTS         0x00004822  // CX_UINT32
#define VMCS_GUEST_LDTR                     0x0000080C  // CX_UINT16
#define VMCS_GUEST_LDTR_BASE                0x00006812  // CX_UINT64
#define VMCS_GUEST_LDTR_LIMIT               0x0000480C  // CX_UINT32
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS       0x00004820  // CX_UINT32
#define VMCS_GUEST_GDTR_BASE                0x00006816  // CX_UINT64
#define VMCS_GUEST_GDTR_LIMIT               0x00004810  // CX_UINT32
#define VMCS_GUEST_IDTR_BASE                0x00006818  // CX_UINT64
#define VMCS_GUEST_IDTR_LIMIT               0x00004812  // CX_UINT32

#define VMCS_GUEST_IA32_DEBUGCTL            0x00002802  // CX_UINT64
#define VMCS_GUEST_IA32_SYSENTER_CS         0x0000482A  // CX_UINT32
#define VMCS_GUEST_IA32_SYSENTER_RSP        0x00006824  // CX_UINT64
#define VMCS_GUEST_IA32_SYSENTER_RIP        0x00006826  // CX_UINT64
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL    0x00002808  // CX_UINT64
#define VMCS_GUEST_IA32_PAT                 0x00002804  // CX_UINT64
#define VMCS_GUEST_IA32_EFER                0x00002806  // CX_UINT64
#define VMCS_GUEST_SMBASE                   0x00004828  // CX_UINT32

#define VMCS_GUEST_LINK_POINTER             0x00002800  // CX_UINT64
#define VMCS_GUEST_ACTIVITY_STATE           0x00004826  // CX_UINT32
#define VMCS_GUEST_INTERRUPTIBILITY_STATE   0x00004824  // CX_UINT32
#define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS 0x00006822  // CX_UINT64

#define VMCS_GUEST_CR0_MASK                 0x00006000  // CX_UINT64
#define VMCS_GUEST_CR4_MASK                 0x00006002  // CX_UINT64
#define VMCS_GUEST_CR0_READ_SHADOW          0x00006004  // CX_UINT64
#define VMCS_GUEST_CR4_READ_SHADOW          0x00006006  // CX_UINT64

/// ...

// host related
#define VMCS_HOST_CR0                       0x00006C00  // CX_UINT64
#define VMCS_HOST_CR3                       0x00006C02  // CX_UINT64
#define VMCS_HOST_CR4                       0x00006C04  // CX_UINT64
#define VMCS_HOST_RSP                       0x00006C14  // CX_UINT64
#define VMCS_HOST_RIP                       0x00006C16  // CX_UINT64

#define VMCS_HOST_CS                        0x00000C02  // CX_UINT32
#define VMCS_HOST_SS                        0x00000C04  // CX_UINT32
#define VMCS_HOST_DS                        0x00000C06  // CX_UINT32
#define VMCS_HOST_ES                        0x00000C00  // CX_UINT32
#define VMCS_HOST_FS                        0x00000C08  // CX_UINT32
#define VMCS_HOST_FS_BASE                   0x00006C06  // CX_UINT64
#define VMCS_HOST_GS                        0x00000C0A  // CX_UINT32
#define VMCS_HOST_GS_BASE                   0x00006C08  // CX_UINT64
#define VMCS_HOST_TR                        0x00000C0C  // CX_UINT32
#define VMCS_HOST_TR_BASE                   0x00006C0A  // CX_UINT64
#define VMCS_HOST_GDTR_BASE                 0x00006C0C  // CX_UINT64
#define VMCS_HOST_IDTR_BASE                 0x00006C0E  // CX_UINT64

#define VMCS_HOST_IA32_SYSENTER_CS          0x00004C00  // CX_UINT32
#define VMCS_HOST_IA32_SYSENTER_RSP         0x00006C10  // CX_UINT64
#define VMCS_HOST_IA32_SYSENTER_RIP         0x00006C12  // CX_UINT64
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL     0x00002C04  // CX_UINT64
#define VMCS_HOST_IA32_PAT                  0x00002C00  // CX_UINT64
#define VMCS_HOST_IA32_EFER                 0x00002C02  // CX_UINT64

/// ...


//
// VMX / VMCS flags
//
#define VMCSFLAG_PINEXEC_EXTERNAL_INTERRUPT             0x00000001  // vol 3B, 21.6.1, Table 21-5, bit 0
#define VMCSFLAG_PINEXEC_NMI                            0x00000008  // vol 3B, 21.6.1, Table 21-5, bit 3
#define VMCSFLAG_PINEXEC_VIRTUAL_NMIS                   0x00000020  // vol 3B, 21.6.1, Table 21-5, bit 5
#define VMCSFLAG_PINEXEC_PREEMPTION_TIMER               0x00000040  // vol 3B, 21.6.1, Table 21-5, bit 6
#define VMCSFLAG_PINEXEC_PROCESS_POSTED_INTERRUPTS      0x00000100  // intel 2013  24.6.1 Table 24-5, bit 7
/// ...

#define VMCSFLAG_PROCEXEC_INTERRUPT_WINDOW_EXIT         0x00000004  //
#define VMCSFLAG_PROCEXEC_USE_TSC_OFFSETTING            0x00000008  // vol 3B, 21.6.2, Table 21-6, bit 3
#define VMCSFLAG_PROCEXEC_HLT_EXIT                      0x00000080  // vol 3B, 21.6.2, Table 21-6, bit 7
#define VMCSFLAG_PROCEXEC_INVLPG_EXIT                   0x00000200
#define VMCSFLAG_PROCEXEC_MWAIT_EXIT                    0x00000400  // bit 10
#define VMCSFLAG_PROCEXEC_RDPMC_EXIT                    0x00000800  // bit 11
#define VMCSFLAG_PROCEXEC_RDTSC_EXIT                    0x00001000  // bit 12
#define VMCSFLAG_PROCEXEC_CR3_LOAD_EXIT                 0x00008000  // vol 3B, 21.6.2, Table 21-6, bit 15
#define VMCSFLAG_PROCEXEC_CR3_STORE_EXIT                0x00010000  // vol 3B, 21.6.2, Table 21-6, bit 16
///#define VCMSFLAG_PROCEXEC_CR8_LOAD_EXIT                 0x00080000  // vol 3B, 21.6.2, Table 21-6, bit 19
///#define VMCSFLAG_PROCEXEC_CR8_STORE_EXIT                0x00100000  // vol 3B, 21.6.2, Table 21-6, bit 20
#define VMCSFLAG_PROCEXEC_USE_TPR_SHADOW                0x00200000  // vol 3B, 21.6.2, Table 21-6, bit 21
#define VMCSFLAG_PROCEXEC_NMI_WINDOW_EXIT               0x00400000  // vol 3B, 21.6.2, Table 21-6, bit 22
#define VMCSFLAG_PROCEXEC_UNCONDITIONAL_IO_EXIT         0x01000000
#define VMCSFLAG_PROCEXEC_USE_IO_BITMAPS                0x02000000  // vol 3B, 21.6.2, Table 21-6, bit 25
#define VMCSFLAG_PROCEXEC_MONITOR_TRAP_FLAG_EXIT        0x08000000  // bit 27
#define VMCSFLAG_PROCEXEC_USE_MSR_BITMAPS               0x10000000  // vol 3B, 21.6.2, Table 21-6, bit 28
#define VMCSFLAG_PROCEXEC_MONITOR_EXIT                  0x20000000  //
#define VMCSFLAG_PROCEXEC_PAUSE_EXIT                    0x40000000  // bit 30
#define VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2    0x80000000  // vol 3B, 21.6.2, Table 21-6, bit 31
/// ...

#define VMCSFLAG_PROCEXEC2_VIRTUALIZE_APIC_ACCESSES     0x00000001  // vol 3B, 21.6.2, Table 21-7, bit 0
#define VMCSFLAG_PROCEXEC2_ENABLE_EPT                   0x00000002  // vol 3B, 21.6.2, Table 21-7, bit 1
#define VMCSFLAG_PROCEXEC2_DESC_TABLE_EXIT              0x00000004  // bit 2
#define VMCSFLAG_PROCEXEC2_ALLOW_RDTSCP                 0x00000008  // vol 3B, 21.6.2, Table 21-7, bit 3
#define VMCSFLAG_PROCEXEC2_VIRTUALIZE_X2APIC_MODE       0x00000010  // vol 3B, 21.6.2, Table 21-7, bit 4
#define VMCSFLAG_PROCEXEC2_ENABLE_VPID                  0x00000020  // vol 3B, 21.6.2, Table 21-7, bit 5
#define VMCSFLAG_PROCEXEC2_WBINVD_EXIT                  0x00000040  // bit 6
#define VMCSFLAG_PROCEXEC2_UNRESTRICTED_GUEST           0x00000080  // vol 3B, 21.6.2, Table 21-7, bit 7
#define VMCSFLAG_PROCEXEC2_APIC_REG_VIRTUALIZATION      0x00000100  // bit 8
#define VMCSFLAG_PROCEXEC2_VIRT_INTR_DELIVERY           0x00000200  // bit 9
#define VMCSFLAG_PROCEXEC2_PAUSE_LOOP_EXIT              0x00000400  // bit 10
#define VMCSFLAG_PROCEXEC2_RDRAND_EXIT                  0x00000800  // bit 11
#define VMCSFLAG_PROCEXEC2_INVPCID_ENABLE               0x00001000  // bit 12
#define VMCSFLAG_PROCEXEC2_VMFUNC_ENABLE                0x00002000  // bit 13
#define VMCSFLAG_PROCEXEC2_VMCS_SHADOWING               0x00004000  // bit 14
#define VMCSFLAG_PROCEXEC2_UNUSED_15                    0x00008000  // bit 15
#define VMCSFLAG_PROCEXEC2_UNUSED_16                    0x00010000  // bit 16
#define VMCSFLAG_PROCEXEC2_UNUSED_17                    0x00020000  // bit 17
#define VMCSFLAG_PROCEXEC2_EPT_VE                       0x00040000  // bit 18
#define VMCSFLAG_PROCEXEC2_CONCEAL_VMX_FROM_PT          0x00080000  // bit 19
#define VMCSFLAG_PROCEXEC2_ENABLE_XSAVES_XRSTORS        0x00100000  // bit 20
#define VMCSFLAG_PROCEXEC2_SPP                          (1UL<<23)   // bit 23 (duh...)
#define VMCSFLAG_PROCEXEC2_USE_TSC_SCALING              0x02000000  // bit 25
/// ...

// VMFUNC functions.
#define VMCSFLAG_VMFUNC_EPTP_SWITCHING                  0x00000001  // vol 3C, 24.6.14, Table 24-9, bit 0


#define VMCSFLAG_VMEXIT_SAVE_DEBUG_CONTROLS             0x00000004  // vol 3B, 21.7.1, Table 21-9, bit 2
#define VMCSFLAG_VMEXIT_64BIT_HOST                      0x00000200  // vol 3B, 21.7.1, Table 21-9, bit 9
#define VMCSFLAG_VMEXIT_ACKNOWLEDGE_INTERRUPT_ON_EXIT   0x00008000  // vol 3B, 21.7.1, Table 21-9, bit 15
#define VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS           0x00040000  // vol 3B, 21.7.1, Table 21-9, bit 18
#define VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST         0x00080000  // vol 3B, 21.7.1, Table 21-9, bit 19 - added 2012/08/15
#define VMCSFLAG_VMEXIT_SAVE_IA32_EFER_TO_VMCS          0x00100000  // vol 3B, 21.7.1, Table 21-9, bit 20
#define VMCSFLAG_VMEXIT_LOAD_IA32_EFER_FROM_HOST        0x00200000  // vol 3B, 21.7.1, Table 21-9, bit 21
#define VMCSFLAG_VMEXIT_SAVE_TIMER                      0x00400000  // vol 3B, 21.7.1, Table 21-9, bit 22
#define VMCSFLAG_VMEXIT_CONCEAL_VMEXITS_FROM_PT         0x01000000  // vol 3C, 24.7.1, Table 24-10, bit 24 (062US March 2017)
/// ...

#define VMCSFLAG_VMENTRY_LOAD_DEBUG_CONTROLS            0x00000004  // vol 3B, 21.8.1, Table 21-11, bit 2
#define VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA           0x00000200  // vol 3B, 21.8.1, Table 21-11, bit 9
#define VMCSFLAG_VMENTRY_SMM                            0x00000400  // bit 10
#define VMCSFLAG_VMENTRY_DEACTIVATE_DUAL_MONITOR        0x00000800  // bit 11
#define VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS        0x00004000  // vol 3B, 21.8.1, Table 21-11, bit 14
#define VMCSFLAG_VMENTRY_LOAD_IA32_EFER_FROM_VMCS       0x00008000  // vol 3B, 21.8.1, Table 21-11, bit 15
#define VMCSFLAG_VMENTRY_CONCEAL_VMENTRIES_FROM_PT      0x00020000  // vol 3C, 24.8.1, Table 24-12, bit 17 (062US March 2017)
/// ...

#define VMCSFLAG_IRRSTATE_BLOCKING_BY_STI               0x00000001  // vol 3B, 21.4.2, Table 21-3, bit 0
#define VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS            0x00000002
#define VMCSFLAG_IRRSTATE_BLOCKING_BY_NMI               0x00000008
/// ...

#define VMCSFLAG_PENDBGEX_BS                            0x00004000  // vol 3B, 21.4.2, Table 21-4, bit 14
/// ...

#define VMCS_ACTIVITY_STATE_ACTIVE                      0
#define VMCS_ACTIVITY_STATE_HLT                         1
#define VMCS_ACTIVITY_STATE_SHUTDOWN                    2
#define VMCS_ACTIVITY_STATE_WAIT_FOR_SIPI               3

#define EXIT_REASON_VM_ENTRY                            0x8000'0000

/// exit reasons
#define EXIT_REASON_MIN                                 0   // pseudo exit reason to help in iterations
#define EXIT_REASON_EXCEPTION_NMI                       0
#define EXIT_REASON_EXTERNAL_INTERRUPT                  1
#define EXIT_REASON_TRIPLE_FAULT                        2
#define EXIT_REASON_INIT                                3
#define EXIT_REASON_SIPI                                4
#define EXIT_REASON_SMI                                 5
#define EXIT_REASON_OTHER_SMI                           6
#define EXIT_REASON_INTERRUPT_WINDOW                    7
#define EXIT_REASON_NMI_WINDOW                          8
#define EXIT_REASON_TASK_SWITCH                         9
#define EXIT_REASON_CPUID                               10
#define EXIT_REASON_GETSEC                              11
#define EXIT_REASON_HLT                                 12
#define EXIT_REASON_INVD                                13
#define EXIT_REASON_INVLPG                              14
#define EXIT_REASON_RDPMC                               15
#define EXIT_REASON_RDTSC                               16
#define EXIT_REASON_RSM                                 17
#define EXIT_REASON_VMCALL                              18
#define EXIT_REASON_VMCLEAR                             19
#define EXIT_REASON_VMLAUNCH                            20
#define EXIT_REASON_VMPTRLD                             21
#define EXIT_REASON_VMPTRST                             22
#define EXIT_REASON_VMREAD                              23
#define EXIT_REASON_VMRESUME                            24
#define EXIT_REASON_VMWRITE                             25
#define EXIT_REASON_VMOFF                               26
#define EXIT_REASON_VMON                                27
#define EXIT_REASON_CR_ACCESS                           28
#define EXIT_REASON_DR_ACCESS                           29
#define EXIT_REASON_IO_INSTRUCTION                      30
#define EXIT_REASON_MSR_READ                            31
#define EXIT_REASON_MSR_WRITE                           32
#define EXIT_REASON_INVALID_GUEST_STATE                 33
#define EXIT_REASON_MSR_LOADING                         34
#define EXIT_REASON_MWAIT_INSTRUCTION                   36
#define EXIT_REASON_MONITOR_TRAP_FLAG                   37
#define EXIT_REASON_MONITOR                             39
#define EXIT_REASON_PAUSE                               40
#define EXIT_REASON_MACHINE_CHECK                       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD                 43
#define EXIT_REASON_APIC_ACCESS                         44
#define EXIT_REASON_VIRTUALIZED_EOI                     45
#define EXIT_REASON_GDTR_IDTR_ACCESS                    46
#define EXIT_REASON_LDTR_TR_ACCESS                      47
#define EXIT_REASON_EPT_VIOLATION                       48
#define EXIT_REASON_EPT_MISCONFIGURATION                49
#define EXIT_REASON_INVEPT                              50
#define EXIT_REASON_RDTSCP                              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED        52
#define EXIT_REASON_INVVPID                             53
#define EXIT_REASON_WBINVD                              54
#define EXIT_REASON_XSETBV                              55
#define EXIT_REASON_APIC_WRITE                          56
#define EXIT_REASON_RDRAND                              57
#define EXIT_REASON_INVPCID                             58
#define EXIT_REASON_VMFUNC                              59
#define EXIT_REASON_ENCLS                               60
#define EXIT_REASON_RDSEED                              61
#define EXIT_REASON_PAGE_MODIFICATION_LOG_FULL          62
#define EXIT_REASON_XSAVES                              63
#define EXIT_REASON_XRSTORS                             64
#define EXIT_REASON_SPP                                 66
#define EXIT_REASON_UMWAIT                              67
#define EXIT_REASON_TPAUSE                              68

#define EXIT_REASON_MAX                                 EXIT_REASON_TPAUSE  // pseudo exit reason to help in iterations - update this when adding new exit reasons
#define EXIT_REASON_INVALID                             (EXIT_REASON_TPAUSE + 1)


/// VM instruction error numbers
#define VM_INSTRUCTION_ERROR_VMCALL_IN_ROOT                 1
#define VM_INSTRUCTION_ERROR_VMCLEAR_INV_PA                 2
#define VM_INSTRUCTION_ERROR_VMCLEAR_WITH_VMXON_PTR         3
#define VM_INSTRUCTION_ERROR_VMLAUNCH_NON_CLEAR_VMCS        4
#define VM_INSTRUCTION_ERROR_VMRESUME_NON_LAUNCHED_VMCS     5
#define VM_INSTRUCTION_ERROR_VMRESUME_AFTER_VMXOFF          6
#define VM_INSTRUCTION_ERROR_VMENTRY_INV_CTRL_FIELDS        7
#define VM_INSTRUCTION_ERROR_VMENTRY_INV_HOST_FIELDS        8
#define VM_INSTRUCTION_ERROR_VMPTRLD_INV_PA                 9
#define VM_INSTRUCTION_ERROR_VMPTRLD_WITH_VMXON_PTR         10
#define VM_INSTRUCTION_ERROR_VMPTRLD_INV_VMCS_REV_ID        11
#define VM_INSTRUCTION_ERROR_UNSUPPORTED_VMCS_COMP          12
#define VM_INSTRUCTION_ERROR_VMWRITE_TO_READONLY_VMCS_COMP  13
#define VM_INSTRUCTION_ERROR_VMXON_IN_ROOT                  15
#define VM_INSTRUCTION_ERROR_VMENTRY_INV_EXECUTIVE_VMCS_PTR 16
#define VM_INSTRUCTION_ERROR_VMENTRY_NON_LAUNCHED_EXECUTIVE_VMCS    17
#define VM_INSTRUCTION_ERROR_VMENTRY_EXEC_VMCS_PTR_NOT_VMXON_PTR    18
#define VM_INSTRUCTION_ERROR_VMCALL_NON_CLEAR_VMCS          19
#define VM_INSTRUCTION_ERROR_VMCALL_INV_EXIT_CTRL_FIELDS    20
#define VM_INSTRUCTION_ERROR_VMCALL_INV_MSEG_ID             22
#define VM_INSTRUCTION_ERROR_VMXOFF_UNDER_DUAL_MODE         23
#define VM_INSTRUCTION_ERROR_VMCALL_INV_SMM_FEATURES        24
#define VM_INSTRUCTION_ERROR_VMENTRY_INV_EXEC_CTRL_FIELDS   25
#define VM_INSTRUCTION_ERROR_VMENTRY_BLOCKED_BY_MOV_SS      26
#define VM_INSTRUCTION_ERROR_INV_OP_TO_INVEPT_INVVPID       28


//
// INVEPT types
//
typedef enum
{
    INVEPT_TYPE_SINGLE_CONTEXT = 1,
    INVEPT_TYPE_ALL_CONTEXT = 2
}INVEPT_TYPE;

typedef struct _INVEPT_DESCRIPTOR
{
    CX_UINT64 Eptp;
    CX_UINT64 Gpa;
} INVEPT_DESCRIPTOR;

//
// VM entry event interruption type
//
typedef enum _VM_EVENT_INTR_TYPE
{
    VM_EVENT_INTR_EXTERNAL_INT = 0,
    VM_EVENT_INTR_NOT_USED1 = 1,
    VM_EVENT_INTR_NMI = 2,
    VM_EVENT_INTR_HARD_EXCEPTION = 3,
    VM_EVENT_INTR_SOFT_INT = 4,
    VM_EVENT_INTR_PRIV_SOFT_INT = 5,
    VM_EVENT_INTR_SOFT_EXCEPTION = 6,
    VM_EVENT_INTR_NOT_USED7 = 7,
}VM_EVENT_INTR_TYPE;

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

typedef struct __VMCS_GUEST_SEGMENT_ACCESS_RIGHTS
{

    union{
        CX_UINT64 Raw;
        struct{
            CX_UINT32 AccessRights;
            CX_UINT32 Reserved0;
        };
        struct{
            CX_UINT64 SegmentType:4;
            CX_UINT64 S:1;
            CX_UINT64 DPL:2;
            CX_UINT64 P:1;
            CX_UINT64 Reserved1:4;
            CX_UINT64 AVL:1;
            CX_UINT64 L:1;
            CX_UINT64 D_B:1;
            CX_UINT64 Unused:1;
            CX_UINT64 Reserved2:16;
        };
    };
}VMCS_GUEST_SEGMENT_ACCESS_RIGHTS, *PVMCS_GUEST_SEGMENT_ACCESS_RIGHTS;

typedef struct _VMCS_VECTORED_EVENT_INFO
{
    union
    {
        CX_UINT32 Raw;
        struct {
            CX_UINT32 Vector : 8;
            CX_UINT32 Type : 3;
            CX_UINT32 ErrorCodeValid : 1;
            CX_UINT32 NmiUnblockingDueToIret : 1;
            CX_UINT32 Reserved : (31 - 13);
            CX_UINT32 Valid : 1;
        };
    };
    CX_UINT32 Padding;
}VMCS_VECTORED_EVENT_INFO;


#pragma warning(pop)

#endif // _VMXDEFS_H_