/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpu_features.h
*   @brief CPU_FEATURES - Identify CPU features
*/

#ifndef _CPU_FEATURES_H_
#define _CPU_FEATURES_H_

#include "cx_native.h"

#pragma pack(push)
#pragma pack(1)

/// @brief The structure that can be used to get a clearer output when calling the __cpuid function
typedef struct _CPUID_REGS {
    CX_INT32 Eax;
    CX_INT32 Ebx;
    CX_INT32 Ecx;
    CX_INT32 Edx;
} CPUID_REGS;

#pragma pack(pop)
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

/// @brief Structure that captures features present in a CPU
typedef struct _CPU_ENTRY {            // 64 bytes, ***fixed length***
    CX_UINT64                   LocalApicBase;  ///< IA32_APIC_BASE | 0xFFFFFF000 (bits 12-35)
    union {
        CX_UINT64               __padding;
        struct {
            CX_UINT32           Id;             ///< Local APIC id (CPUID.01H:EBX[31-24], both Intel and AMD). For x2APIC, MSR 802H is the Local APIC Id
            struct {
                CX_UINT32    Socket:4;
                CX_UINT32    Core:10;
                CX_UINT32    Thread:4;
                CX_UINT32    IsBsp:1;           ///< 1 = this is the BSP CPU
            } Topology;
        };
    };
    union {
        struct {
            struct {
                CX_UINT32    SSE3:1;         ///<  0: Streaming SIMD Extensions 3 (SSE3).
                CX_UINT32    PCLMULQDQ:1;    ///<  1: PCLMULQDQ
                CX_UINT32    DTES64:1;       ///<  2: 64-bit DS Area
                CX_UINT32    MONITOR:1;      ///<  3: MONITOR/MWAIT
                CX_UINT32    DS_CPL:1;       ///<  4: CPL Qualified Debug Store
                CX_UINT32    VMX:1;          ///<  5: Virtual Machine Extensions
                CX_UINT32    SMX:1;          ///<  6: Safer Mode Extensions
                CX_UINT32    EIST:1;         ///<  7: Enhanced Intel SpeedStep technology
                CX_UINT32    TM2:1;          ///<  8: Thermal Monitor 2.
                CX_UINT32    SSSE3:1;        ///<  9: Supplemental Streaming SIMD Extensions 3 (SSSE3).
                CX_UINT32    CNXT_ID:1;      ///< 10: L1 Context ID.
                CX_UINT32    _reserved11:1;  ///< 11: Reserved.
                CX_UINT32    FMA:1;          ///< 12: FMA extensions using YMM state
                CX_UINT32    CMPXCHG16B:1;   ///< 13: CMPXCHG16B Available
                CX_UINT32    xTPR_UC:1;      ///< 14: xTPR Update Control
                CX_UINT32    PDCM:1;         ///< 15: Perfmon and Debug Capability
                CX_UINT32    _reserved16:1;  ///< 16: Reserved
                CX_UINT32    PCID:1;         ///< 17: Process-context identifiers
                CX_UINT32    DCA:1;          ///< 18: Prefetch data from a memory mapped device
                CX_UINT32    SSE41:1;        ///< 19: SSE 4.1
                CX_UINT32    SSE42:1;        ///< 20: SSE 4.2
                CX_UINT32    x2APIC:1;       ///< 21: x2APIC
                CX_UINT32    MOVBE:1;        ///< 22: MOVBE
                CX_UINT32    POPCNT:1;       ///< 23: POPCNT
                CX_UINT32    TSC_Deadline:1; ///< 24: local APIC timer supports one-shot operation using a TSC deadline value.
                CX_UINT32    AES:1;          ///< 25: AES instructions extensions
                CX_UINT32    XSAVE:1;        ///< 26: XSAVE/XRSTOR processor extended states feature, the XSETBV/XGETBV instructions, and XCR0.
                CX_UINT32    OSXSAVE:1;      ///< 27: the OS has enabled XSETBV/XGETBV instructions to access XCR0, and support for processor extended state management using XSAVE/XRSTOR
                CX_UINT32    AVX:1;          ///< 28: AVX instruction extension
                CX_UINT32    _reserved29:1;  ///< 29: Reserved
                CX_UINT32    RDRAND:1;       ///< 30: RDRAND
                CX_UINT32    _unused31:1;    ///< 31: Unused, always returns 0
            } Ecx;                ///< From CUPID EAX = 1, return of ECX
            struct {
                CX_UINT32    FPU:1;          ///<  0: x87 FPU on Chip
                CX_UINT32    VME:1;          ///<  1: Virtual-8086 Mode Enhancement
                CX_UINT32    DE:1;           ///<  2: Debugging Extensions
                CX_UINT32    PSE:1;          ///<  3: Page Size Extensions
                CX_UINT32    TSC:1;          ///<  4: Time Stamp Counter
                CX_UINT32    MSR:1;          ///<  5: RDMSR and WRMSR Support
                CX_UINT32    PAE:1;          ///<  6: Physical Address Extensions
                CX_UINT32    MCE:1;          ///<  7: Machine Check Exception
                CX_UINT32    CMPXCHG8B:1;    ///<  8: CMPXCHG8B Instruction
                CX_UINT32    APIC:1;         ///<  9: APIC on chip
                CX_UINT32    _reserved10:1;  ///< 10: Reserved
                CX_UINT32    SYSENTEREXIT:1; ///< 11: SYSENTER and SYSEXIT
                CX_UINT32    MTRR:1;         ///< 12: Memory Type Range Registers
                CX_UINT32    PGE:1;          ///< 13: PTE Global Bit
                CX_UINT32    MCA:1;          ///< 14: Machine Check Architecture
                CX_UINT32    CMOV:1;         ///< 15: Conditional Move/Compare Instruction
                CX_UINT32    PAT:1;          ///< 16: Page Attribute Table
                CX_UINT32    PSE_36:1;       ///< 17: 36-bit Page Size Extension
                CX_UINT32    PSN:1;          ///< 18: Processor Serial Number
                CX_UINT32    CLFSH:1;        ///< 19: CFLUSH Instruction
                CX_UINT32    _reserved20:1;  ///< 20: Reserved
                CX_UINT32    DS:1;           ///< 21: DebugStore
                CX_UINT32    ACPI:1;         ///< 22: Thermal Monitor and Clock Ctrl
                CX_UINT32    MMX:1;          ///< 23: MMX Technology
                CX_UINT32    FXSR:1;         ///< 24: FXSAVE/FXRSTOR
                CX_UINT32    SSE:1;          ///< 25: SSE Extensions
                CX_UINT32    SSE2:1;         ///< 26: SSE2 Extensions
                CX_UINT32    SS:1;           ///< 27: Self Snoop
                CX_UINT32    HTT:1;          ///< 28: Hyper-threading technology
                CX_UINT32    TM:1;           ///< 29: Thermal Monitor
                CX_UINT32    _reserved30:1;  ///< 30: Reserved
                CX_UINT32    PBE:1;          ///< 31: Pend. Brk. En.
            } Edx;                ///< From CUPID EAX = 1, return of EDX
        } IntelFeatures;
        struct {
            struct {
                CX_UINT32    SSE3:1;         ///<  0: Streaming SIMD Extensions 3 (SSE3).
                CX_UINT32    PCLMULQDQ:1;    ///<  1: PCLMULQDQ
                CX_UINT32    _reserved02:1;  ///<  2: Reserved
                CX_UINT32    MONITOR:1;      ///<  3: MONITOR/MWAIT
                CX_UINT32    _reserved04:1;  ///<  4: Reserved
                CX_UINT32    _reserved05:1;  ///<  5: Reserved
                CX_UINT32    _reserved06:1;  ///<  6: Reserved
                CX_UINT32    _reserved07:1;  ///<  7: Reserved
                CX_UINT32    _reserved08:1;  ///<  8: Reserved
                CX_UINT32    SSSE3:1;        ///<  9: Supplemental Streaming SIMD Extensions 3 (SSSE3).
                CX_UINT32    _reserved10:1;  ///< 10: Reserved
                CX_UINT32    _reserved11:1;  ///< 11: Reserved
                CX_UINT32    FMA:1;          ///< 12: FMA
                CX_UINT32    CMPXCHG16B:1;   ///< 13: CMPXCHG16B Available
                CX_UINT32    _reserved14:1;  ///< 14: Reserved
                CX_UINT32    _reserved15:1;  ///< 15: Reserved
                CX_UINT32    _reserved16:1;  ///< 16: Reserved
                CX_UINT32    _reserved17:1;  ///< 17: Reserved
                CX_UINT32    _reserved18:1;  ///< 18: Reserved
                CX_UINT32    SSE41:1;        ///< 19: SSE 4.1
                CX_UINT32    SSE42:1;        ///< 20: SSE 4.2
                CX_UINT32    _reserved21:1;  ///< 21: Reserved
                CX_UINT32    _reserved22:1;  ///< 22: Reserved
                CX_UINT32    POPCNT:1;       ///< 23: POPCNT
                CX_UINT32    _reserved24:1;  ///< 24: Reserved
                CX_UINT32    AES:1;          ///< 25: AES
                CX_UINT32    XSAVE:1;        ///< 26: XSAVE
                CX_UINT32    OSXSAVE:1;      ///< 27: OSXSAVE
                CX_UINT32    AVX:1;          ///< 28: AVX
                CX_UINT32    F16C:1;         ///< 29: Half-precision convert instruction support (CVT16)
                CX_UINT32    _reserved30:1;  ///< 30: Reserved
                CX_UINT32    _unused1:1;     ///< 31: Unused, always returns 0
            } Ecx;
            struct {
                CX_UINT32    FPU:1;          ///<  0: x87 FPU on Chip
                CX_UINT32    VME:1;          ///<  1: Virtual-8086 Mode Enhancement
                CX_UINT32    DE:1;           ///<  2: Debugging Extensions
                CX_UINT32    PSE:1;          ///<  3: Page Size Extensions
                CX_UINT32    TSC:1;          ///<  4: Time Stamp Counter
                CX_UINT32    MSR:1;          ///<  5: RDMSR and WRMSR Support
                CX_UINT32    PAE:1;          ///<  6: Physical Address Extensions
                CX_UINT32    MCE:1;          ///<  7: Machine Check Exception
                CX_UINT32    CMPXCHG8B:1;    ///<  8: CMPXCHG8B Instruction
                CX_UINT32    APIC:1;         ///<  9: APIC on chip
                CX_UINT32    _reserved10:1;  ///< 10: Reserved
                CX_UINT32    SYSENTEREXIT:1; ///< 11: SYSENTER and SYSEXIT
                CX_UINT32    MTRR:1;         ///< 12: Memory Type Range Registers
                CX_UINT32    PGE:1;          ///< 13: PTE Global Bit
                CX_UINT32    MCA:1;          ///< 14: Machine Check Architecture
                CX_UINT32    CMOV:1;         ///< 15: Conditional Move/Compare Instruction
                CX_UINT32    PAT:1;          ///< 16: Page Attribute Table
                CX_UINT32    PSE_36:1;       ///< 17: 36-bit Page Size Extension
                CX_UINT32    _reserved18:1;  ///< 18: Reserved
                CX_UINT32    CLFSH:1;        ///< 19: CFLUSH Instruction
                CX_UINT32    _reserved20:1;  ///< 20: Reserved
                CX_UINT32    _reserved21:1;  ///< 21: Reserved
                CX_UINT32    _reserved22:1;  ///< 22: Reserved
                CX_UINT32    MMX:1;          ///< 23: MMX Technology
                CX_UINT32    FXSR:1;         ///< 24: FXSAVE/FXRSTOR
                CX_UINT32    SSE:1;          ///< 25: SSE Extensions
                CX_UINT32    SSE2:1;         ///< 26: SSE2 Extensions
                CX_UINT32    _reserved27:1;  ///< 27: Reserved
                CX_UINT32    HTT:1;          ///< 28: Hyper-threading technology
                CX_UINT32    _reserved29:1;  ///< 29: Reserved
                CX_UINT32    _reserved30:1;  ///< 30: Reserved
                CX_UINT32    _reserved31:1;  ///< 31: Reserved
            } Edx;
        } AmdFeatures;
        struct {
            CX_UINT32 Ecx;
            CX_UINT32 Edx;
        } Features;                                 ///< CPUID Function 01H
    };
    union {
        struct {
            struct {
                CX_UINT32    LAHF_SAHF:1;    ///<  0: LAHF/SAHF available in 64-bit mode
                CX_UINT32    _reserved01:1;  ///<  1: Reserved
                CX_UINT32    _reserved02:1;  ///<  2: Reserved
                CX_UINT32    _reserved03:1;  ///<  3: Reserved
                CX_UINT32    _reserved04:1;  ///<  4: Reserved
                CX_UINT32    _reserved05:1;  ///<  5: Reserved
                CX_UINT32    _reserved06:1;  ///<  6: Reserved
                CX_UINT32    _reserved07:1;  ///<  7: Reserved
                CX_UINT32    _reserved08:1;  ///<  8: Reserved
                CX_UINT32    _reserved09:1;  ///<  9: Reserved
                CX_UINT32    _reserved10:1;  ///< 10: Reserved
                CX_UINT32    _reserved11:1;  ///< 11: Reserved
                CX_UINT32    _reserved12:1;  ///< 12: Reserved
                CX_UINT32    _reserved13:1;  ///< 13: Reserved
                CX_UINT32    _reserved14:1;  ///< 14: Reserved
                CX_UINT32    _reserved15:1;  ///< 15: Reserved
                CX_UINT32    _reserved16:1;  ///< 16: Reserved
                CX_UINT32    _reserved17:1;  ///< 17: Reserved
                CX_UINT32    _reserved18:1;  ///< 18: Reserved
                CX_UINT32    _reserved19:1;  ///< 19: Reserved
                CX_UINT32    _reserved20:1;  ///< 20: Reserved
                CX_UINT32    _reserved21:1;  ///< 21: Reserved
                CX_UINT32    _reserved22:1;  ///< 22: Reserved
                CX_UINT32    _reserved23:1;  ///< 23: Reserved
                CX_UINT32    _reserved24:1;  ///< 24: Reserved
                CX_UINT32    _reserved25:1;  ///< 25: Reserved
                CX_UINT32    _reserved26:1;  ///< 26: Reserved
                CX_UINT32    _reserved27:1;  ///< 27: Reserved
                CX_UINT32    _reserved28:1;  ///< 28: Reserved
                CX_UINT32    _reserved29:1;  ///< 29: Reserved
                CX_UINT32    _reserved30:1;  ///< 30: Reserved
                CX_UINT32    _reserved31:1;  ///< 31: Reserved
            } Ecx;                ///< From CUPID EAX = 80000001H, return of ECX
            struct {
                CX_UINT32    _reserved00:1;  ///<  0: Reserved
                CX_UINT32    _reserved01:1;  ///<  1: Reserved
                CX_UINT32    _reserved02:1;  ///<  2: Reserved
                CX_UINT32    _reserved03:1;  ///<  3: Reserved
                CX_UINT32    _reserved04:1;  ///<  4: Reserved
                CX_UINT32    _reserved05:1;  ///<  5: Reserved
                CX_UINT32    _reserved06:1;  ///<  6: Reserved
                CX_UINT32    _reserved07:1;  ///<  7: Reserved
                CX_UINT32    _reserved08:1;  ///<  8: Reserved
                CX_UINT32    _reserved09:1;  ///<  9: Reserved
                CX_UINT32    _reserved10:1;  ///< 10: Reserved
                CX_UINT32    SYSCALLRET64:1; ///< 11: SYSCALL/SYSRET available (when in 64-bit mode)
                CX_UINT32    _unused12:1;    ///< 12: Unused, always returns 0
                CX_UINT32    _unused13:1;    ///< 13: Unused, always returns 0
                CX_UINT32    _unused14:1;    ///< 14: Unused, always returns 0
                CX_UINT32    _unused15:1;    ///< 15: Unused, always returns 0
                CX_UINT32    _unused16:1;    ///< 16: Unused, always returns 0
                CX_UINT32    _unused17:1;    ///< 17: Unused, always returns 0
                CX_UINT32    _unused18:1;    ///< 18: Unused, always returns 0
                CX_UINT32    _unused19:1;    ///< 19: Unused, always returns 0
                CX_UINT32    NX:1;           ///< 20: Execute Disable Bit available
                CX_UINT32    _unused21:1;    ///< 21: Unused, always returns 0
                CX_UINT32    _unused22:1;    ///< 22: Unused, always returns 0
                CX_UINT32    _unused23:1;    ///< 23: Unused, always returns 0
                CX_UINT32    _unused24:1;    ///< 24: Unused, always returns 0
                CX_UINT32    _unused25:1;    ///< 25: Unused, always returns 0
                CX_UINT32    PAGE_1GB:1;     ///< 26: 1-GByte pages are available if 1
                CX_UINT32    RDTSCP:1;       ///< 27: RDTSCP and IA32_TSC_AUX are available if 1
                CX_UINT32    _unused28:1;    ///< 28: Unused, always returns 0
                CX_UINT32    Intel64:1;      ///< 29: Intel 64 Architecture available if 1
                CX_UINT32    _unused30:1;    ///< 30: Unused, always returns 0
                CX_UINT32    _unused31:1;    ///< 31: Unused, always returns 0
            } Edx;                ///< From CUPID EAX = 80000001H, return of EDX
        } ExtendedIntelFeatures;
        struct {
            struct {
                CX_UINT32    LAHF_SAHF:1;    ///<  0: LAHF and SAHF instruction support in 64-bit mode
                CX_UINT32    CmpLegacy:1;    ///<  1: Core multi-processing legacy mode
                CX_UINT32    SVM:1;          ///<  2: Secure Virtual Machine
                CX_UINT32    ExtApicSpace:1; ///<  3: Extended APIC space. This bit indicates the presence of extended APIC register space starting at offset 400h from the "APIC Base Address Register," as specified in the BKDG
                CX_UINT32    AltMovCr8:1;    ///<  4: LOCK MOV CR0 means MOV CR8
                CX_UINT32    ABM:1;          ///<  5: Advanced bit manipulation. LZCNT instruction support
                CX_UINT32    SSE4A:1;        ///<  6: EXTRQ, INSERTQ, MOVNTSS, and MOVNTSD instruction support
                CX_UINT32    MisAlignSse:1;  ///<  7: Misaligned SSE mode
                CX_UINT32    _3DNowPrefetch:1;///< 8: PREFETCH and PREFETCHW instruction support
                CX_UINT32    OSVW:1;         ///<  9: OS visible workaround. Indicates OS-visible workaround support
                CX_UINT32    IBS:1;          ///< 10: Instruction based sampling
                CX_UINT32    XOP:1;          ///< 11: XOP Instruction support (previously was "SSE5")
                CX_UINT32    SKINIT:1;       ///< 12: SKINIT and STGI are supported, independent of the value of MSRC000_0080[SVME].
                CX_UINT32    WDT:1;          ///< 13: Watch Dog Time support
                CX_UINT32    _reserved14:1;  ///< 14: Reserved
                CX_UINT32    LWP:1;          ///< 15: Lightweight profiling support
                CX_UINT32    FMA4:1;         ///< 16: 4-operand FMA instruction support
                CX_UINT32    _reserved17:1;  ///< 17: Reserved
                CX_UINT32    _reserved18:1;  ///< 18: Reserved
                CX_UINT32    NodeId:1;       ///< 19: Indicates support for MSRC001_100C[NodeId, NodesPerProcessor].
                CX_UINT32    _reserved20:1;  ///< 20: Reserved
                CX_UINT32    TBM:1;          ///< 21: Trailing bit manipulation instruction support.
                CX_UINT32    TopologyExt:1;  ///< 22: Topology extensions support
                CX_UINT32    _reserved23:1;  ///< 23: Reserved
                CX_UINT32    _reserved24:1;  ///< 24: Reserved
                CX_UINT32    _reserved25:1;  ///< 25: Reserved
                CX_UINT32    _reserved26:1;  ///< 26: Reserved
                CX_UINT32    _reserved27:1;  ///< 27: Reserved
                CX_UINT32    _reserved28:1;  ///< 28: Reserved
                CX_UINT32    _reserved29:1;  ///< 29: Reserved
                CX_UINT32    _reserved30:1;  ///< 30: Reserved
                CX_UINT32    _reserved31:1;  ///< 31: Reserved
            } Ecx;
            struct {
                CX_UINT32    FPU:1;          ///<  0: x87 FPU on Chip
                CX_UINT32    VME:1;          ///<  1: Virtual-8086 Mode Enhancement
                CX_UINT32    DE:1;           ///<  2: Debugging Extensions
                CX_UINT32    PSE:1;          ///<  3: Page Size Extensions
                CX_UINT32    TSC:1;          ///<  4: Time Stamp Counter
                CX_UINT32    MSR:1;          ///<  5: RDMSR and WRMSR Support
                CX_UINT32    PAE:1;          ///<  6: Physical Address Extensions
                CX_UINT32    MCE:1;          ///<  7: Machine Check Exception
                CX_UINT32    CMPXCHG8B:1;    ///<  8: CMPXCHG8B Instruction
                CX_UINT32    APIC:1;         ///<  9: APIC on chip
                CX_UINT32    _reserved1:1;   ///< 10: Reserved
                CX_UINT32    SYSCALLRET:1;   ///< 11: SYSCALL / SYSRET
                CX_UINT32    MTRR:1;         ///< 12: Memory Type Range Registers
                CX_UINT32    PGE:1;          ///< 13: PTE Global Bit
                CX_UINT32    MCA:1;          ///< 14: Machine Check Architecture
                CX_UINT32    CMOV:1;         ///< 15: Conditional Move/Compare Instruction
                CX_UINT32    PAT:1;          ///< 16: Page Attribute Table
                CX_UINT32    PSE_36:1;       ///< 17: 36-bit Page Size Extension
                CX_UINT32    _reserved18:1;  ///< 18: Reserved
                CX_UINT32    _reserved19:1;  ///< 19: Reserved
                CX_UINT32    NX:1;           ///< 20: No-Execute page protection
                CX_UINT32    _reserved21:1;  ///< 21: Reserved
                CX_UINT32    MMXExt:1;       ///< 22: AMD extensions to MMX instructions
                CX_UINT32    MMX:1;          ///< 23: MMX Technology
                CX_UINT32    FXSR:1;         ///< 24: FXSAVE/FXRSTOR
                CX_UINT32    FFXSR:1;        ///< 25: FXSAVE and FXRSTOR instruction optimizations
                CX_UINT32    Page_1GB:1;     ///< 26: 1-GB large page support
                CX_UINT32    RDTSCP:1;       ///< 27: RDTSCP instruction.
                CX_UINT32    _reserved28:1;  ///< 28: Reserved
                CX_UINT32    AMD64LM:1;      ///< 29: Long Mode (CX_ARCH64 technology)
                CX_UINT32    _3DNowExt:1;    ///< 30: AMD extensions to 3DNow! instructions
                CX_UINT32    _3DNow:1;       ///< 31: 3DNow! instructions
            } Edx;
        } ExtendedAmdFeatures;
        struct {
            CX_UINT32 Ecx;
            CX_UINT32 Edx;
        } ExtendedFeatures;                                 ///< CPUID Function 80000001H
    };
    union {
        struct {
            CX_UINT32    VMX:1;          ///<  0: VMX / SVM    (Intel: CPUID.01:ECX[5],  AMD: CPUID:80000001H:ECX[2])
            CX_UINT32    x64:1;          ///<  1: 64-bit mode  (Intel: CPUID:80000001H:EDX[29], AMD: CPUID:80000001H:EDX[29])
            CX_UINT32    EPT:1;          ///<  2: Extended Page Table (Intel) / Nested Pages (AMD)
            CX_UINT32    VPID:1;         ///<  3: Virtual Processor Identifier (Intel) / Address Space Identifier (AMD)
            CX_UINT32    x2APIC:1;       ///<  4: x2APIC       (Intel: CPUID.01:ECX[21], AMD: ?)
            CX_UINT32    DMT:1;          ///<  5: Dual Monitor Treatment for SMM and SMI (Intel: IA32_VMX_BASIC[49])
            CX_UINT32    InvariantTSC:1; ///<  6: Invariant TSC (Intel+AMD: CPUID.80000007:EDX[8])
            CX_UINT32    XCR0:1;         ///<  7: XCR0          (Intel+AMD: CPUID.01:ECX[26]; XSAVE/XRSTOR)
            CX_UINT32    CMPXCHG16B:1;   ///<  8: CMPXCHG16B    (Intel+AMD: CPUID.01:ECX[13])
            CX_UINT32    AVX:1;          ///<  9: AVX           (Intel+AMD: CPUID.01:ECX[28])
            CX_UINT32    Page_1GB:1;     ///< 10: 1-GB Pages    (Intel+AMD: CPUID.80000001:EDX[26])
            CX_UINT32    x2APICEn:1;     ///< 11: x2APIC Enabled (Intel: MSR IA32_APIC_BASE[10], AMD: ?)
            CX_UINT32    APICv:1;        ///< 12: APICv present (Virtual Interrupt Delivery is supported - see SDM from Jan 2013)
            CX_UINT32    ApicRegVirt:1;  ///< 13: APIC register virtualization
            CX_UINT32    EptVe:1;        ///< 14: EPT Virtualization Exceptions (\#VE, vector 20)
            CX_UINT32    TscDeadline:1;  ///< 15: TSC Deadline
            CX_UINT32    VMFUNC:1;       ///< 16: VMFUNC
        } MiscIntelFeatures; ///< Features we need. Some are copied from CPUID, some are identified in other ways.
        struct {
            CX_UINT32    SVM:1;          ///<  0: VMX / SVM    (Intel: CPUID.01:ECX[5],  AMD: CPUID:80000001H:ECX[2])
            CX_UINT32    x64:1;          ///<  1: 64-bit mode  (Intel: CPUID:80000001H:EDX[29], AMD: CPUID:80000001H:EDX[29])
            CX_UINT32    NP:1;           ///<  2: Extended Page Table (Intel) / Nested Pages (AMD)
            CX_UINT32    ASID:1;         ///<  3: Virtual Processor Identifier (Intel) / Address Space Identifier (AMD)
            CX_UINT32    x2APIC:1;       ///<  4: x2APIC       (Intel: CPUID.01:ECX[21], AMD: ?)
            CX_UINT32    DMT:1;          ///<  5: Dual Monitor Treatment for SMM and SMI (AMD: MSR HWCR[0])
            CX_UINT32    InvariantTSC:1; ///<  6: Invariant TSC (Intel+AMD: CPUID.80000007.EDX[8])
            CX_UINT32    XCR0:1;         ///<  7: XCR0          (Intel+AMD: CPUID.01:ECX[26])
            CX_UINT32    CMPXCHG16B:1;   ///<  8: CMPXCHG16B    (Intel+AMD: CPUID.01:ECX[13])
            CX_UINT32    AVX:1;          ///<  9: AVX           (Intel+AMD: CPUID.01:ECX[28])
            CX_UINT32    Page_1GB:1;     ///< 10: 1-GB Pages    (Intel+AMD: CPUID.80000001:EDX[26])
            CX_UINT32    x2APICEn:1;     ///< 11: x2APIC Enabled (Intel: CPUID.01:ECX[21], AMD: ?)
        } MiscAmdFeatures; ///< Features we need. Some are copied from CPUID, some are identified in other ways.
        CX_UINT32 MiscFeatures2;
    };

    union {
        struct {
            CX_UINT32    Stepping:4;        ///< Stepping ID is a product revision number assigned due to fixed errata or other changes.
            CX_UINT32    Model:4;           ///< The actual processor model is derived from the Model, Extended Model ID and Family ID fields. If the Family ID field is either 6 or 15, the model is equal to the sum of the Extended Model ID field shifted left by 4 bits and the Model field. Otherwise, the model is equal to the value of the Model field.
            CX_UINT32    Family:4;          ///< The actual processor family is derived from the Family ID and Extended Family ID fields. If the Family ID field is equal to 15, the family is equal to the sum of the Extended Family ID and the Family ID fields. Otherwise, the family is equal to value of the Family ID field.
            CX_UINT32    ProcessorType:2;   ///< 00 = Original OEM Processor; 01 = Intel Overdrive Processor; 10 = Dual processor (not applicable to Intel486 processors); 11 = Reserved
            CX_UINT32    _reserved1:2;
            CX_UINT32    ExtendedModel:4;
            CX_UINT32    ExtendedFamily:8;
            CX_UINT32    _reserved2:4;
        } FamilyFields;
        CX_UINT32   Family; ///< from CPUID EAX = 1, return of EAX
    };
    CX_INT8 Name[14]; ///< plain text name, 12 chars + NULL (GenuineIntel / AuthenticAMD)
    union {
        struct {
            CX_BOOL         Intel;          ///< TRUE if Intel
            CX_BOOL         AMD;            ///< TRUE if AMD
        } ProcessorType;
        CX_UINT16 ProcessorTypeIdentified;       // Must NOT be 0 after initializing this structure
    };
    struct {
        CX_UINT8                PhysicalAddressWidth;   ///< Largest physical address size
        CX_UINT8                VirtualAddressWidth;    ///< Largest virtual address size
    } Addressability;
    CX_UINT16                    Reserved;
} CPU_ENTRY;

/** @name Virtualization features available
 *
 */
///@{
typedef struct  _VIRTUALIZATION_FEATURE_PROC_CTLS
{
    CX_UINT32 Reserved1 : 2;                // 0 - 1
    CX_UINT32 InterruptWindowExiting : 1;   // 2
    CX_UINT32 UseTscOffseting : 1;          // 3
    CX_UINT32 Reserved2 : 3;                // 4 - 6
    CX_UINT32 HltExiting : 1;               // 7
    CX_UINT32 Reserved3 : 1;                // 8
    CX_UINT32 InvlpgExiting : 1;            // 9
    CX_UINT32 MwaitExiing : 1;              // 10
    CX_UINT32 RdpmcExiting : 1;             // 11
    CX_UINT32 RdtscExiting : 1;             // 12
    CX_UINT32 Reserved4 : 2;                // 13 - 14
    CX_UINT32 Cr3LoadExiting : 1;           // 15
    CX_UINT32 Cr3StoreExiting : 1;          // 16
    CX_UINT32 Reserved5 : 2;                // 17 - 18
    CX_UINT32 Cr8LoadExiting : 1;           // 19
    CX_UINT32 Cr8StoreExiting : 1;          // 20
    CX_UINT32 UseTprShadow : 1;             // 21
    CX_UINT32 NmiWindowExiting : 1;         // 22
    CX_UINT32 MovDrExiting : 1;             // 23
    CX_UINT32 UnconditionalIoExiting : 1;   // 24
    CX_UINT32 UseIoBitmaps : 1;             // 25
    CX_UINT32 Reserved6 : 1;                // 26
    CX_UINT32 MonitorTrapFlag : 1;          // 27
    CX_UINT32 UseMsrBitmaps : 1;            // 28
    CX_UINT32 MonitorExiting : 1;           // 29
    CX_UINT32 PauseExiting : 1;             // 30
    CX_UINT32 ActivateSecondaryCtls : 1;    // 31
} VIRTUALIZATION_FEATURE_PROC_CTLS;


typedef struct _VIRTUALIZATION_FEATURE_PROC_CTLS2
{
    CX_UINT32 VirtualizeApicAccesses    : 1;    // 0
    CX_UINT32 EnableEpt                 : 1;    // 1
    CX_UINT32 DescriptorTableExiting    : 1;    // 2
    CX_UINT32 EnableRdtscp              : 1;    // 3
    CX_UINT32 VirtualizeX2ApicMode      : 1;    // 4
    CX_UINT32 EnableVpid                : 1;    // 5
    CX_UINT32 WbinvdExiting             : 1;    // 6
    CX_UINT32 UnrestrictedGuest         : 1;    // 7
    CX_UINT32 ApicRegisterVirtualization: 1;    // 8
    CX_UINT32 VirtualInterruptDelivery  : 1;    // 9
    CX_UINT32 PauseLoopExiting          : 1;    // 10
    CX_UINT32 RdrandExiting             : 1;    // 11
    CX_UINT32 EnableInvpcid             : 1;    // 12
    CX_UINT32 EnableVMFunctions         : 1;    // 13
    CX_UINT32 VmcsShadowing             : 1;    // 14
    CX_UINT32 Reserved1                 : 3;    // 15 - 17
    CX_UINT32 EptViolationCauseException: 1;    // 18
    CX_UINT32 ConcealVmxFromPt          : 1;    // 19
    CX_UINT32 EnableXsavesXrstors       : 1;    // 20
    CX_UINT32 __reserved21              : 1;    // 21
    CX_UINT32 ModeBasedExecution        : 1;    // 22
    CX_UINT32 SPP                       : 1;    // 23
    CX_UINT32 __reserved24              : 1;    // 24
    CX_UINT32 UseTSCScaling             : 1;    // 25
    CX_UINT32 __reserved26_27           : 2;    // 26 - 27
    CX_UINT32 EnableEnclExit            : 1;    // 28
    CX_UINT32 __reserved29_31           : 3;    // 29 - 31
} VIRTUALIZATION_FEATURE_PROC_CTLS2;
static_assert(sizeof(VIRTUALIZATION_FEATURE_PROC_CTLS2) == 4, "Intel Vol3 24.6.2 Processor-Based VM-Execution Controls");

typedef struct _VIRTUALIZATION_FEATURES
{
    union
    {
        CX_UINT64   Raw;
        struct
        {
            CX_UINT64 VmcsRevId             : 31;       // 0 - 30
            CX_UINT64 Reserved1             : 1;        // 31
            CX_UINT64 VmxOnVmcsRegionSize   : 13;       // 32 - 44
            CX_UINT64 Reserved2             : 3;        // 45 - 47
            CX_UINT64 PhyscalAddressWidth   : 1;        // 48
            CX_UINT64 DualMonitorSupport    : 1;        // 49
            CX_UINT64 VmcsMemType           : 4;        // 50 - 53
            CX_UINT64 IoInfoOnVmExit        : 1;        // 54
            CX_UINT64 VmxTrueXxxCtls        : 1;        // 55
        };
    }VmxBasic;

    union
    {
        CX_UINT64   Raw;
        struct
        {
            CX_UINT64 ExternalInterruptExit     : 1;    // 0
            CX_UINT64 Reserved1                 : 2;    // 1 - 2
            CX_UINT64 NmiExit                   : 1;    // 3
            CX_UINT64 Reserved2                 : 1;    // 4
            CX_UINT64 VirtualNmiExit            : 1;    // 5
            CX_UINT64 ActivateVmxPreemptionTimer: 1;    // 6
            CX_UINT64 ProcessPostedInterrupts   : 1;    // 7
        };
    }VmxPinBased;

    union
    {
        CX_UINT64   Raw;
        struct
        {
            VIRTUALIZATION_FEATURE_PROC_CTLS Zero;
            VIRTUALIZATION_FEATURE_PROC_CTLS One;
        }Parsed;
    }VmxProcBased;
    union
    {
        CX_UINT64   Raw;
        struct
        {
            VIRTUALIZATION_FEATURE_PROC_CTLS2 Zero;
            VIRTUALIZATION_FEATURE_PROC_CTLS2 One;
        }Parsed;
    }VmxProcBased2;

    union
    {
        CX_UINT64   VmxMiscRaw;
        struct
        {
            CX_UINT64 TimerRate                 : 5;    // 0 - 4
            CX_UINT64 EferLMABit                : 1;    // 5
            CX_UINT64 SupportedActivityStates   : 3;    // 6 - 8
            CX_UINT64 Reserved1                 : 5;    // 9 - 13
            CX_UINT64 IntelPTInVMX              : 1;    // 14
            CX_UINT64 RdmsrInSmm                : 1;    // 15
            CX_UINT64 Cr3TargetCount            : 9;    // 16 - 24
            CX_UINT64 RecomendedMaxMsrCount     : 3;    // 25 - 27
            CX_UINT64 SmmMonitorCtl             : 1;    // 28
            CX_UINT64 VmwriteOnAnyField         : 1;    // 29
            CX_UINT64 Reserved2                 : 2;    // 30 -31
            CX_UINT64 MsegRev                   : 32;   // 32 - 63
        };
    }VmxMisc;

    union
    {
        CX_UINT64 VmxExitRaw;
    }VmxExit;

    union
    {
        CX_UINT64 VmxEntryRaw;
    }VmxEntry;


    CX_UINT64   MsrFeatureControl;

    union
    {
        CX_UINT64 Raw;
        struct
        {
            CX_UINT64 EptExecuteOnly:1; // 0
            CX_UINT64 Reserved1:5;
            CX_UINT64 EptPageWalkLength4:1; //6
            CX_UINT64 Reserved2:1;
            CX_UINT64 EptUCSupported:1;// 8
            CX_UINT64 Reserved3:5;
            CX_UINT64 EptWBSupport:1; // 14
            CX_UINT64 Reserved4:1;
            CX_UINT64 EptSupport2MbPage:1; // 16
            CX_UINT64 EptSupport1GbPage:1; // 17
            CX_UINT64 Reserved5:2;
            CX_UINT64 InvEptSupported:1; // 20
            CX_UINT64 EptAccessedAndDirtySupported:1; // 21
            CX_UINT64 Reserved6:3;
            CX_UINT64 InvEptSingleContextSupported:1; // 25
            CX_UINT64 InvEptAllContextSupported:1; // 26
            CX_UINT64 Reserved7:5;
            CX_UINT64 InvVpidSupported:1; // 32
            CX_UINT64 Reserved8:7;
            CX_UINT64 InvVpidAddressSupported:1; // 40
            CX_UINT64 InvVpidSingleContextSupported:1; // 41
            CX_UINT64 InvVpidAllContextSupported:1; // 42
            CX_UINT64 InvVpidAllContextRetGlobalsSupported:1; // 43
            CX_UINT64 Reserved9:21;
        }Parsed;
    }EptVpidFeatures;
}VIRTUALIZATION_FEATURES;

typedef struct _SMX_CAPABILITIES{
    union {
        struct {
            CX_UINT32 TxtChipsetPresent:1;
            CX_UINT32 Undefined1:1;
            CX_UINT32 EnterAccs:1;
            CX_UINT32 ExitAc:1;
            CX_UINT32 SEnter:1;
            CX_UINT32 SExit:1;
            CX_UINT32 Parameters:1;
            CX_UINT32 SMCtrl:1;
            CX_UINT32 Wakeup:1;
            CX_UINT32 Reserved2:22;
            CX_UINT32 Extended:1;
        } SmxCapabilities0;
        CX_UINT32 SmxCapabilities0Raw;
    };
}SMX_CAPABILITIES;
#pragma warning(pop)

/// @brief Bit 31 of the ECX register when a cpuid with leaf 1 is made can be set by the hypervisor to declare its presence
#define HYPERVISOR_PRESENT_BIT  (1 << 31)
///@}

///
/// @brief Calls multi-leaf CPUIDs and MSRs read to discover processor features
///
/// @param[out]  CpuEntry                    the structure where the features will be written
///
/// @returns    TRUE                        - if all good.
/// @returns    FALSE                       - if CpuEntry is NULL
///                                         if the cpu is not Intel or AMD
///                                         if local APIC is not enabled
///                                         if Highest Extended Function Implemented is smaller than 0x80000008
///
CX_BOOL
InitCpuEntry(
    _Out_ CPU_ENTRY *CpuEntry
    );

///
/// @brief Read specific MSRs to find out the features available for virtualization
///
/// @param[in,out]  CpuEntry                the structure where the features will be written
/// @param[out]     VirtFeat                the structure where specific virtualization features will be written
///
/// @returns    TRUE                        - if all good.
/// @returns    FALSE                       - if CpuEntry or VirtFeat is NULL
///                                         if VMX not available
///                                         if AMD but not SVM available
///
CX_BOOL
InitCpuVirtualizationFeatures(
    _Inout_ CPU_ENTRY *CpuEntry,
    _Out_ VIRTUALIZATION_FEATURES *VirtFeat
    );

///
/// @brief Check if SMX functionality exists and if so then check features available by calling getsec
///
/// @param[in]      CpuEntry                the structure where informations about this CPU are found
/// @param[in,out]  SmxCapabilities         the structure where the features will be written
///
/// @returns    TRUE                        - if all good.
/// @returns    FALSE                       - if AMD processor
///
CX_BOOL
InitCpuSmxFeatures(
    _In_ CPU_ENTRY *CpuEntry,
    _Inout_ SMX_CAPABILITIES *SmxCapabilities
    );

///
/// @brief Print CPU Misc features
///
/// @param[in]      CpuEntry                the structure where informations about this CPU are found
///
CX_VOID
CpuPrintMiscFeatures(
    _In_ CPU_ENTRY *CpuEntry
    );

///
/// @brief Print CPU features found by CPUID instruction
///
/// @param[in]      CpuEntry                the structure where informations about this CPU are found
///
CX_VOID
CpuPrintCpuidFeatures(
    _In_ CPU_ENTRY *CpuEntry
    );

///
/// @brief Print CPU APIC Id and Local APIC base address
///
/// @param[in]      CpuEntry                the structure where informations about this CPU are found
///
CX_VOID
CpuPrintLocalApic(
    _In_ CPU_ENTRY *CpuEntry
    );

///
/// @brief Execute CPUID with leaf 1 to find the Local APIC id
///
/// @returns    Current CPU Local APIC Id
///
CX_UINT32
CpuGetOriginalApicId(
    void
    );

///
/// @brief Check if the features found meet the minimum requirements to be able to run our hypervisor
///
/// @param[in]      CpuEntry                the structure where informations about this CPU are found
/// @param[in]      VirtFeat                the structure where specific virtualization informations about this CPU are found
///
/// @returns    CX_STATUS_NOT_SUPPORTED     - if the cpu does not meet the requirements for our hypervisor
/// @returns    CX_STATUS_NOT_SUPPORTED     - if requirements are not meet.
///
CX_STATUS
CpuCheckFeatures(
    _In_ CPU_ENTRY *CpuEntry,
    _In_ VIRTUALIZATION_FEATURES *VirtFeat
    );

///
/// @brief Check if Supervisor Mode Execution Prevention is present
///
/// @returns TRUE   - if present
/// @returns FALSE  - if not present
///
CX_BOOL
CpuHasSmep(
    CX_VOID
    );

///
/// @brief Check if Supervisor Mode Access Prevention is present
///
/// @returns TRUE   - if present
/// @returns FALSE  - if not present
///
CX_BOOL
CpuHasSmap(
    CX_VOID
    );

#endif // _CPU_FEATURES_H_
