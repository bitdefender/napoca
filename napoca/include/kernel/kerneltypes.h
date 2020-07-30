/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __KERNEL_TYPES_H__
#define __KERNEL_TYPES_H__

#include "memory/mmap.h"

#pragma pack(push)
#pragma pack(1)

#define VEINFOPAGE_RESERVED_MAGIC (0xFFFFFFFF)

typedef volatile struct _VEINFOPAGE
{
    DWORD ExitReason;
    DWORD Reserved;
    QWORD ExitQualifaction;
    QWORD GuestLinearAddress;
    QWORD GuestPhysicalAddress;
    WORD EptpIndex;
}VEINFOPAGE;


typedef struct _MSR_ENTRY {             // conform Intel "Format of an MSR Entry"
    DWORD           Msr;                // +0x000
    union {
        DWORD       Reserved;           // +0x004
        DWORD       Flags;              // used as Flags for MSRs that are not auto-saved/loaded on VM-exit/VM-entry
    };
    QWORD           Value;              // +0x008
} MSR_ENTRY, *PMSR_ENTRY;

#pragma pack(pop)

//
// MTRR support
//
#define MAX_FIXED_MTRR                  88  // maximum values conform Intel manuals
#define MAX_VARIABLE_MTRR               256

typedef struct _MTRR_FIX_ENTRY {
    QWORD           MinAddr : 20;         // conform Intel docs, FIXED MTRRs are used to map only the 0-1 MB range (so 20 bits are enough)
    QWORD           MaxAddr : 20;
    QWORD           Type : 8;
    QWORD           _Reserved : 16;
} MTRR_FIX_ENTRY;

#define VAR_MTRR_BASE_MASK              0xFFFFFFFFFFFFF000ULL
#define VAR_MTRR_MASK_MASK              0xFFFFFFFFFFFFF000ULL

typedef struct _MTRR_VAR_ENTRY {
    union {
        QWORD       BaseMsr;            // MSR_IA32_MTRR_PHYSBASE(n)
        struct {
            QWORD   Type : 8;
            QWORD   _Reserved1 : 4;
            QWORD   PhysBase : 48;
        };
    };
    union {
        QWORD       MaskMsr;            // MSR_IA32_MTRR_PHYSMASK(n)
        struct {
            QWORD   _Reserved2 : 11;
            QWORD   Valid : 1;
            QWORD   PhysMask : 48;
        };
    };
} MTRR_VAR_ENTRY;

typedef struct _MTRR_STATE {
    union {
        QWORD       MtrrCapMsr;         // MSR_IA32_MTRRCAP
        struct {
            QWORD   VarCount : 8;
            QWORD   FixedSupport : 1;
            QWORD   _Reserved1 : 1;
            QWORD   WcCacheSupport : 1;
            QWORD   SmmrSupport : 1;
            QWORD   _Reserved2 : 52;
        };
    };
    union {
        QWORD       MtrrDefMsr;         // MSR_IA32_MTRR_DEF_TYPE
        struct {
            QWORD   DefType : 8;
            QWORD   _Reserved3 : 2;
            QWORD   FixedEnabled : 1;
            QWORD   Enabled : 1;
            QWORD   _Reserved4 : 52;
        };
    };
    MTRR_FIX_ENTRY  Fixed[MAX_FIXED_MTRR];
    MTRR_VAR_ENTRY  Var[MAX_VARIABLE_MTRR];
    QWORD           MaxAddr;            // maximum PA covered by MTRRs (calculated)
    MMAP            Map;                // MTRR based MAP (used only for the BSP on each guest)
} MTRR_STATE;


typedef union _IA32_PM_ENABLE
{
    struct
    {
        QWORD HwpEnable : 1;
    };
    QWORD Raw;
}IA32_PM_ENABLE;

typedef union _IA32_HWP_CAPABILITIES
{
    struct
    {
        QWORD HighestPerf : 8;
        QWORD GuaranteedPerf : 8;
        QWORD MostEfficientPerf : 8;
        QWORD LowestPerf : 8;
    };
    QWORD Raw;
}IA32_HWP_CAPABILITIES;

typedef union _IA32_HWP_REQUEST
{
    struct
    {
        QWORD MinimumPerf : 8;
        QWORD MaximumPerf : 8;
        QWORD DesiredPerf : 8;
        QWORD EnergyPerfPref : 8;
        QWORD ActivityWindow : 10;
        QWORD PackageControl : 1;
        QWORD Reserved : 16;
        QWORD ActivityWindowValid : 1;
        QWORD EppValid : 1;
        QWORD DesiredValid : 1;
        QWORD MaximumValid : 1;
        QWORD MinimumValid : 1;
    };
    QWORD Raw;
}IA32_HWP_REQUEST;

//
// CPUID support
//

#define CPUID_ECX_ANY       0x000000FF
#define CPUID_RESERVE_NONE  0x00000000


typedef struct _CPUID_LEAF {
    DWORD       EaxIn;
    DWORD       EcxIn;                  // 0xFFFFFFFF if only EAX is used
    union
    {
        struct
        {
            DWORD       EaxOut;
            DWORD       EbxOut;
            DWORD       EcxOut;
            DWORD       EdxOut;
        };

        DWORD           Registers[4];
    };
} CPUID_LEAF, *PCPUID_LEAF;

#define MAX_CPUID_LEAF_COUNT            32

#define CPUID_BASIC_CPUID_INFORMATION           0x0000'0000

#define CPUID_EXTENDED_CPUID_INFORMATION        0x8000'0000

#define CPUID_START_OF_EXTENDED_RANGE           CPUID_EXTENDED_CPUID_INFORMATION

typedef struct _CPUID_STATE {
    DWORD           TotalLeafCount;
    CPUID_LEAF      Leaf[MAX_CPUID_LEAF_COUNT];
} CPUID_STATE, *PCPUID_STATE;

// eax = 1
#define CPUID_01_EAX_FLAG_STEPPING              BITRANGE_MASK(0, 4)
#define CPUID_01_EAX_FLAG_BASEMODEL             BITRANGE_MASK(4, 4)
#define CPUID_01_EAX_FLAG_BASFAMILY             BITRANGE_MASK(8, 4)
#define CPUID_01_EAX_FLAG_PROCTYPE              BITRANGE_MASK(12, 2)
#define CPUID_01_EAX_FLAG_RESERVED14_15         BITRANGE_MASK(14, 2)
#define CPUID_01_EAX_FLAG_EXTENDEDMODEL         BITRANGE_MASK(16, 4)
#define CPUID_01_EAX_FLAG_EXTENDEDFAMILY        BITRANGE_MASK(20, 8)
#define CPUID_01_EAX_FLAG_RESERVED28_31         BITRANGE_MASK(28, 4)
#define CPUID_01_EAX_FLAG_RESERVED              (CPUID_01_EAX_FLAG_RESERVED14_15 | CPUID_01_EAX_FLAG_RESERVED28_31)

#define CPUID_01_EBX_FLAG_BRAND                 BITRANGE_MASK(0, 8)
#define CPUID_01_EBX_FLAG_CL_FLUSH_SIZE         BITRANGE_MASK(8, 8)
#define CPUID_01_EBX_FLAG_MAX_LP_IN_PACK        BITRANGE_MASK(16, 8)
#define CPUID_01_EBX_FLAG_INIT_APIC_ID          BITRANGE_MASK(24, 8)

#define CPUID_01_ECX_FLAG_SSE3                  BIT(0)
#define CPUID_01_ECX_FLAG_PCLMULQDQ             BIT(1)
#define CPUID_01_ECX_FLAG_DTEST                 BIT(2)
#define CPUID_01_ECX_FLAG_MONITORMWAIT          BIT(3)
#define CPUID_01_ECX_FLAG_DSCPL                 BIT(4)
#define CPUID_01_ECX_FLAG_VMX                   BIT(5)            // Intel: CPUID.01H:ECX.VMX[bit 5]
#define CPUID_01_ECX_FLAG_SMX                   BIT(6)
#define CPUID_01_ECX_FLAG_EST                   BIT(7)
#define CPUID_01_ECX_FLAG_TM2                   BIT(8)
#define CPUID_01_ECX_FLAG_SSSE3                 BIT(9)
#define CPUID_01_ECX_FLAG_CNXTID                BIT(10)
#define CPUID_01_ECX_FLAG_SDBG                  BIT(11)
#define CPUID_01_ECX_FLAG_FMA                   BIT(12)
#define CPUID_01_ECX_FLAG_CMPXCHG16B            BIT(13)            // Intel: CPUID.01H:ECX.CMPXCHG16B[bit 13]
#define CPUID_01_ECX_FLAG_XTPR                  BIT(14)
#define CPUID_01_ECX_FLAG_PDCM                  BIT(15)
#define CPUID_01_ECX_FLAG_RESERVED16            BIT(16)
#define CPUID_01_ECX_FLAG_PCID                  BIT(17)
#define CPUID_01_ECX_FLAG_DCA                   BIT(18)
#define CPUID_01_ECX_FLAG_SSE41                 BIT(19)
#define CPUID_01_ECX_FLAG_SSE42                 BIT(20)
#define CPUID_01_ECX_FLAG_X2APIC                BIT(21)
#define CPUID_01_ECX_FLAG_MOVBE                 BIT(22)
#define CPUID_01_ECX_FLAG_POPCNT                BIT(23)
#define CPUID_01_ECX_FLAG_TSCDEADLINE           BIT(24)
#define CPUID_01_ECX_FLAG_AESNI                 BIT(25)
#define CPUID_01_ECX_FLAG_XSAVE                 BIT(26)
#define CPUID_01_ECX_FLAG_OSXSAVE               BIT(27)            // Intel: CPUID.01H:ECX.OSXSAVE[bit 27]
#define CPUID_01_ECX_FLAG_AVX                   BIT(28)
#define CPUID_01_ECX_FLAG_F16C                  BIT(29)
#define CPUID_01_ECX_FLAG_RDRAND                BIT(30)
#define CPUID_01_ECX_FLAG_HYPERVISOR_PRESENT    BIT(31)
#define CPUID_01_ECX_RESERVED                   ( CPUID_01_ECX_FLAG_DTEST \
                                                | 0 \
                                                | CPUID_01_ECX_FLAG_DSCPL \
                                                | CPUID_01_ECX_FLAG_VMX \
                                                | CPUID_01_ECX_FLAG_SMX \
                                                | CPUID_01_ECX_FLAG_SDBG \
                                                | CPUID_01_ECX_FLAG_PDCM \
                                                | CPUID_01_ECX_FLAG_RESERVED16 \
                                                | CPUID_01_ECX_FLAG_DCA \
                                                | CPUID_01_ECX_FLAG_TSCDEADLINE \
                                                )


#define CPUID_01_EDX_FLAG_FPU               BIT(0)
#define CPUID_01_EDX_FLAG_VME               BIT(1)
#define CPUID_01_EDX_FLAG_DE                BIT(2)
#define CPUID_01_EDX_FLAG_PSE               BIT(3)
#define CPUID_01_EDX_FLAG_TSC               BIT(4)
#define CPUID_01_EDX_FLAG_MSR               BIT(5)
#define CPUID_01_EDX_FLAG_PAE               BIT(6)
#define CPUID_01_EDX_FLAG_MCE               BIT(7)
#define CPUID_01_EDX_FLAG_CX8               BIT(8)
#define CPUID_01_EDX_FLAG_APIC              BIT(9)
#define CPUID_01_EDX_FLAG_RESERVED10        BIT(10)
#define CPUID_01_EDX_FLAG_SEP               BIT(11)
#define CPUID_01_EDX_FLAG_MTRR              BIT(12)
#define CPUID_01_EDX_FLAG_PGE               BIT(13)
#define CPUID_01_EDX_FLAG_MCA               BIT(14)
#define CPUID_01_EDX_FLAG_CMOV              BIT(15)
#define CPUID_01_EDX_FLAG_PAT               BIT(16)
#define CPUID_01_EDX_FLAG_PSE36             BIT(17)
#define CPUID_01_EDX_FLAG_PSN               BIT(18)
#define CPUID_01_EDX_FLAG_CLFSH             BIT(19)
#define CPUID_01_EDX_FLAG_RESERVED20        BIT(20)
#define CPUID_01_EDX_FLAG_DS                BIT(21)
#define CPUID_01_EDX_FLAG_ACPI              BIT(22)
#define CPUID_01_EDX_FLAG_MMX               BIT(23)
#define CPUID_01_EDX_FLAG_FXSR              BIT(24)            // Intel: CPUID.01H:EDX.FXSR[bit 24]
#define CPUID_01_EDX_FLAG_SSE               BIT(25)
#define CPUID_01_EDX_FLAG_SSE2              BIT(26)
#define CPUID_01_EDX_FLAG_SS                BIT(27)
#define CPUID_01_EDX_FLAG_HTT               BIT(28)
#define CPUID_01_EDX_FLAG_TM                BIT(29)
#define CPUID_01_EDX_FLAG_RESERVER30        BIT(30)
#define CPUID_01_EDX_FLAG_PBE               BIT(31)
#define CPUID_01_EDX_RESERVED               (CPUID_01_EDX_FLAG_RESERVED10 \
                                            | CPUID_01_EDX_FLAG_PSN \
                                            | CPUID_01_EDX_FLAG_RESERVED20 \
                                            | CPUID_01_EDX_FLAG_DS \
                                            | CPUID_01_EDX_FLAG_RESERVER30 \
                                            )

// eax = 3
#define CPUID_03_EAX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_03_EAX_RESERVED               (CPUID_03_EAX_FLAG_RESERVED0_31)
#define CPUID_03_EBX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_03_EBX_RESERVED               (CPUID_03_EBX_FLAG_RESERVED0_31)
#define CPUID_03_ECX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_03_ECX_RESERVED               (CPUID_03_ECX_FLAG_RESERVED0_31)
#define CPUID_03_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_03_EDX_RESERVED               (CPUID_03_EDX_FLAG_RESERVED0_31)

// eax = 4
#define CPUID_04_EAX_FLAG_RESERVED12_13     BITRANGE_MASK(12, 2)
#define CPUID_04_EAX_RESERVED               (CPUID_04_EAX_FLAG_RESERVED12_13)
#define CPUID_04_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_04_EDX_RESERVED               (CPUID_04_EDX_FLAG_RESERVED0_31)

// eax = 5
#define CPUID_05_EAX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_05_EAX_RESERVED               (CPUID_05_EAX_FLAG_RESERVED0_31)
#define CPUID_05_EBX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_05_EBX_RESERVED               (CPUID_05_EBX_FLAG_RESERVED0_31)
#define CPUID_05_ECX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_05_ECX_RESERVED               (CPUID_05_ECX_FLAG_RESERVED0_31)
#define CPUID_05_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_05_EDX_RESERVED               (CPUID_05_EDX_FLAG_RESERVED0_31)

// eax = 6
#define CPUID_06_EAX_FLAG_DIGITAL_TEMP          BIT(0)
#define CPUID_06_EAX_FLAG_INTEL_TURBO_BOOST     BIT(1)
#define CPUID_06_EAX_FLAG_ARAT                  BIT(2)
#define CPUID_06_EAX_FLAG_RESERVED3             BIT(3)
#define CPUID_06_EAX_FLAG_PLN                   BIT(4)
#define CPUID_06_EAX_FLAG_ECMD                  BIT(5)
#define CPUID_06_EAX_FLAG_PTM                   BIT(6)
#define CPUID_06_EAX_FLAG_HWP                   BIT(7)
#define CPUID_06_EAX_FLAG_HWP_NOTIFICATION      BIT(8)
#define CPUID_06_EAX_FLAG_HWP_ACT_WND           BIT(9)
#define CPUID_06_EAX_FLAG_HWP_EN_PERF_PREF      BIT(10)
#define CPUID_06_EAX_FLAG_HWP_PACK_LVL_REQ      BIT(11)
#define CPUID_06_EAX_FLAG_RESERVED12            BIT(12)
#define CPUID_06_EAX_FLAG_HDC                   BIT(13)
#define CPUID_06_EAX_FLAG_INTEL_TURBO_BOOST3    BIT(14)
#define CPUID_06_EAX_FLAG_HWP_CAPABILITIES      BIT(15)
#define CPUID_06_EAX_FLAG_HWP_PECI              BIT(16)
#define CPUID_06_EAX_FLAG_FLEIXIBLE_HWP         BIT(17)
#define CPUID_06_EAX_FLAG_FAST_ACCESS_HWP_REQ   BIT(18)
#define CPUID_06_EAX_FLAG_RESERVED19            BIT(19)
#define CPUID_06_EAX_FLAG_IGNORE_LP_HWP         BIT(20)
#define CPUID_06_EAX_FLAG_RESERVED21            BIT(21)
#define CPUID_06_EAX_FLAG_RESERVED22            BIT(22)
#define CPUID_06_EAX_FLAG_RESERVED23            BIT(23)
#define CPUID_06_EAX_FLAG_RESERVED24            BIT(24)
#define CPUID_06_EAX_FLAG_RESERVED25            BIT(25)
#define CPUID_06_EAX_FLAG_RESERVED26            BIT(26)
#define CPUID_06_EAX_FLAG_RESERVED27            BIT(27)
#define CPUID_06_EAX_FLAG_RESERVED28            BIT(28)
#define CPUID_06_EAX_FLAG_RESERVED29            BIT(29)
#define CPUID_06_EAX_FLAG_RESERVED30            BIT(30)
#define CPUID_06_EAX_FLAG_RESERVED31            BIT(31)
#define CPUID_06_EAX_RESERVED                   (CPUID_06_EAX_FLAG_RESERVED3 | CPUID_06_EAX_FLAG_RESERVED12 | \
                                                CPUID_06_EAX_FLAG_RESERVED19 | \
                                                CPUID_06_EAX_FLAG_RESERVED21 | CPUID_06_EAX_FLAG_RESERVED22 | \
                                                CPUID_06_EAX_FLAG_RESERVED23 | CPUID_06_EAX_FLAG_RESERVED24 | CPUID_06_EAX_FLAG_RESERVED25 | \
                                                CPUID_06_EAX_FLAG_RESERVED26 | CPUID_06_EAX_FLAG_RESERVED27 | CPUID_06_EAX_FLAG_RESERVED28 | \
                                                CPUID_06_EAX_FLAG_RESERVED29 | CPUID_06_EAX_FLAG_RESERVED30 | CPUID_06_EAX_FLAG_RESERVED31   \
                                                )

#define CPUID_06_EBX_FLAG_NO_OF_INT_TRSH    0x0000000F
#define CPUID_06_EBX_FLAG_RESERVED4         BIT(4)
#define CPUID_06_EBX_FLAG_RESERVED5         BIT(5)
#define CPUID_06_EBX_FLAG_RESERVED6         BIT(6)
#define CPUID_06_EBX_FLAG_RESERVED7         BIT(7)
#define CPUID_06_EBX_FLAG_RESERVED8         BIT(8)
#define CPUID_06_EBX_FLAG_RESERVED9         BIT(9)
#define CPUID_06_EBX_FLAG_RESERVED10        BIT(10)
#define CPUID_06_EBX_FLAG_RESERVED11        BIT(11)
#define CPUID_06_EBX_FLAG_RESERVED12        BIT(12)
#define CPUID_06_EBX_FLAG_RESERVED13        BIT(13)
#define CPUID_06_EBX_FLAG_RESERVED14        BIT(14)
#define CPUID_06_EBX_FLAG_RESERVED15        BIT(15)
#define CPUID_06_EBX_FLAG_RESERVED16        BIT(16)
#define CPUID_06_EBX_FLAG_RESERVED17        BIT(17)
#define CPUID_06_EBX_FLAG_RESERVED18        BIT(18)
#define CPUID_06_EBX_FLAG_RESERVED19        BIT(19)
#define CPUID_06_EBX_FLAG_RESERVED20        BIT(20)
#define CPUID_06_EBX_FLAG_RESERVED21        BIT(21)
#define CPUID_06_EBX_FLAG_RESERVED22        BIT(22)
#define CPUID_06_EBX_FLAG_RESERVED23        BIT(23)
#define CPUID_06_EBX_FLAG_RESERVED24        BIT(24)
#define CPUID_06_EBX_FLAG_RESERVED25        BIT(25)
#define CPUID_06_EBX_FLAG_RESERVED26        BIT(26)
#define CPUID_06_EBX_FLAG_RESERVED27        BIT(27)
#define CPUID_06_EBX_FLAG_RESERVED28        BIT(28)
#define CPUID_06_EBX_FLAG_RESERVED29        BIT(29)
#define CPUID_06_EBX_FLAG_RESERVED30        BIT(30)
#define CPUID_06_EBX_FLAG_RESERVED31        BIT(31)
#define CPUID_06_EBX_RESERVED           (CPUID_06_EBX_FLAG_RESERVED4     | \
                                        CPUID_06_EBX_FLAG_RESERVED5     | \
                                        CPUID_06_EBX_FLAG_RESERVED6     | \
                                        CPUID_06_EBX_FLAG_RESERVED7     | \
                                        CPUID_06_EBX_FLAG_RESERVED8     | \
                                        CPUID_06_EBX_FLAG_RESERVED9     | \
                                        CPUID_06_EBX_FLAG_RESERVED10    | \
                                        CPUID_06_EBX_FLAG_RESERVED11    | \
                                        CPUID_06_EBX_FLAG_RESERVED12    | \
                                        CPUID_06_EBX_FLAG_RESERVED13    | \
                                        CPUID_06_EBX_FLAG_RESERVED14    | \
                                        CPUID_06_EBX_FLAG_RESERVED15    | \
                                        CPUID_06_EBX_FLAG_RESERVED16    | \
                                        CPUID_06_EBX_FLAG_RESERVED17    | \
                                        CPUID_06_EBX_FLAG_RESERVED18    | \
                                        CPUID_06_EBX_FLAG_RESERVED19    | \
                                        CPUID_06_EBX_FLAG_RESERVED20    | \
                                        CPUID_06_EBX_FLAG_RESERVED21    | \
                                        CPUID_06_EBX_FLAG_RESERVED22    | \
                                        CPUID_06_EBX_FLAG_RESERVED23    | \
                                        CPUID_06_EBX_FLAG_RESERVED24    | \
                                        CPUID_06_EBX_FLAG_RESERVED25    | \
                                        CPUID_06_EBX_FLAG_RESERVED26    | \
                                        CPUID_06_EBX_FLAG_RESERVED27    | \
                                        CPUID_06_EBX_FLAG_RESERVED28    | \
                                        CPUID_06_EBX_FLAG_RESERVED29    | \
                                        CPUID_06_EBX_FLAG_RESERVED30    | \
                                        CPUID_06_EBX_FLAG_RESERVED31 \
                                        )


#define CPUID_06_ECX_FLAG_HCFC              BIT(0)
#define CPUID_06_ECX_FLAG_RESERVED1         BIT(1)
#define CPUID_06_ECX_FLAG_RESERVED2         BIT(2)
#define CPUID_06_ECX_FLAG_PERF_ENERGY_BIAS  BIT(3)
#define CPUID_06_ECX_FLAG_RESERVED4         BIT(4)
#define CPUID_06_ECX_FLAG_RESERVED5         BIT(5)
#define CPUID_06_ECX_FLAG_RESERVED6         BIT(6)
#define CPUID_06_ECX_FLAG_RESERVED7         BIT(7)
#define CPUID_06_ECX_FLAG_RESERVED8         BIT(8)
#define CPUID_06_ECX_FLAG_RESERVED9         BIT(9)
#define CPUID_06_ECX_FLAG_RESERVED10        BIT(10)
#define CPUID_06_ECX_FLAG_RESERVED11        BIT(11)
#define CPUID_06_ECX_FLAG_RESERVED12        BIT(12)
#define CPUID_06_ECX_FLAG_RESERVED13        BIT(13)
#define CPUID_06_ECX_FLAG_RESERVED14        BIT(14)
#define CPUID_06_ECX_FLAG_RESERVED15        BIT(15)
#define CPUID_06_ECX_FLAG_RESERVED16        BIT(16)
#define CPUID_06_ECX_FLAG_RESERVED17        BIT(17)
#define CPUID_06_ECX_FLAG_RESERVED18        BIT(18)
#define CPUID_06_ECX_FLAG_RESERVED19        BIT(19)
#define CPUID_06_ECX_FLAG_RESERVED20        BIT(20)
#define CPUID_06_ECX_FLAG_RESERVED21        BIT(21)
#define CPUID_06_ECX_FLAG_RESERVED22        BIT(22)
#define CPUID_06_ECX_FLAG_RESERVED23        BIT(23)
#define CPUID_06_ECX_FLAG_RESERVED24        BIT(24)
#define CPUID_06_ECX_FLAG_RESERVED25        BIT(25)
#define CPUID_06_ECX_FLAG_RESERVED26        BIT(26)
#define CPUID_06_ECX_FLAG_RESERVED27        BIT(27)
#define CPUID_06_ECX_FLAG_RESERVED28        BIT(28)
#define CPUID_06_ECX_FLAG_RESERVED29        BIT(29)
#define CPUID_06_ECX_FLAG_RESERVED30        BIT(30)
#define CPUID_06_ECX_FLAG_RESERVED31        BIT(31)
#define CPUID_06_ECX_RESERVED           (CPUID_06_ECX_FLAG_RESERVED1     | \
                                        CPUID_06_ECX_FLAG_RESERVED2     | \
                                        CPUID_06_ECX_FLAG_RESERVED4     | \
                                        CPUID_06_ECX_FLAG_RESERVED5     | \
                                        CPUID_06_ECX_FLAG_RESERVED6     | \
                                        CPUID_06_ECX_FLAG_RESERVED7     | \
                                        CPUID_06_ECX_FLAG_RESERVED8     | \
                                        CPUID_06_ECX_FLAG_RESERVED9     | \
                                        CPUID_06_ECX_FLAG_RESERVED10    | \
                                        CPUID_06_ECX_FLAG_RESERVED11    | \
                                        CPUID_06_ECX_FLAG_RESERVED12    | \
                                        CPUID_06_ECX_FLAG_RESERVED13    | \
                                        CPUID_06_ECX_FLAG_RESERVED14    | \
                                        CPUID_06_ECX_FLAG_RESERVED15    | \
                                        CPUID_06_ECX_FLAG_RESERVED16    | \
                                        CPUID_06_ECX_FLAG_RESERVED17    | \
                                        CPUID_06_ECX_FLAG_RESERVED18    | \
                                        CPUID_06_ECX_FLAG_RESERVED19    | \
                                        CPUID_06_ECX_FLAG_RESERVED20    | \
                                        CPUID_06_ECX_FLAG_RESERVED21    | \
                                        CPUID_06_ECX_FLAG_RESERVED22    | \
                                        CPUID_06_ECX_FLAG_RESERVED23    | \
                                        CPUID_06_ECX_FLAG_RESERVED24    | \
                                        CPUID_06_ECX_FLAG_RESERVED25    | \
                                        CPUID_06_ECX_FLAG_RESERVED26    | \
                                        CPUID_06_ECX_FLAG_RESERVED27    | \
                                        CPUID_06_ECX_FLAG_RESERVED28    | \
                                        CPUID_06_ECX_FLAG_RESERVED29    | \
                                        CPUID_06_ECX_FLAG_RESERVED30    | \
                                        CPUID_06_ECX_FLAG_RESERVED31    \
                                        )
//eax = 7

#define CPUID_07_00_EAX_FLAG0_31                BITRANGE_MASK(0, 32)
#define CPUID_07_00_EAX_RESERVED                (CPUID_07_00_EAX_FLAG0_31)

#define CPUID_07_00_EBX_FLAG_FSGSBASE           BIT(0)
#define CPUID_07_00_EBX_FLAG_TSC_ADJUST         BIT(1)
#define CPUID_07_00_EBX_FLAG_SGX                BIT(2)
#define CPUID_07_00_EBX_FLAG_BMI1               BIT(3)
#define CPUID_07_00_EBX_FLAG_HLE                BIT(4)
#define CPUID_07_00_EBX_FLAG_AVX2               BIT(5)
#define CPUID_07_00_EBX_FLAG_FDP_EXCPTN_ONLY    BIT(6)
#define CPUID_07_00_EBX_FLAG_SMEP               BIT(7)
#define CPUID_07_00_EBX_FLAG_BMI2               BIT(8)
#define CPUID_07_00_EBX_FLAG_ENH_REPMOVSB       BIT(9)
#define CPUID_07_00_EBX_FLAG_INVPCID            BIT(10)
#define CPUID_07_00_EBX_FLAG_RTM                BIT(11)
#define CPUID_07_00_EBX_FLAG_PQM                BIT(12)
#define CPUID_07_00_EBX_FLAG_DEP_FPU_CS_DS      BIT(13)
#define CPUID_07_00_EBX_FLAG_MPX                BIT(14)
#define CPUID_07_00_EBX_FLAG_PQE                BIT(15)
#define CPUID_07_00_EBX_FLAG_AVC512F            BIT(16)
#define CPUID_07_00_EBX_FLAG_AVX512DQ           BIT(17)
#define CPUID_07_00_EBX_FLAG_RDSEED             BIT(18)
#define CPUID_07_00_EBX_FLAG_ADX                BIT(19)
#define CPUID_07_00_EBX_FLAG_SMAP               BIT(20)
#define CPUID_07_00_EBX_FLAG_AVX512_IFMA        BIT(21)
#define CPUID_07_00_EBX_FLAG_RESERVED22         BIT(22)
#define CPUID_07_00_EBX_FLAG_CLFLUSHOPT         BIT(23)
#define CPUID_07_00_EBX_FLAG_CLWB               BIT(24)
#define CPUID_07_00_EBX_FLAG_INTEL_PROC_TRACE   BIT(25)
#define CPUID_07_00_EBX_FLAG_AVX512PF           BIT(26)
#define CPUID_07_00_EBX_FLAG_AVX512ER           BIT(27)
#define CPUID_07_00_EBX_FLAG_AVX512CD           BIT(28)
#define CPUID_07_00_EBX_FLAG_SHA                BIT(29)
#define CPUID_07_00_EBX_FLAG_AVX512BW           BIT(30)
#define CPUID_07_00_EBX_FLAG_AVX512VL           BIT(31)
#define CPUID_07_00_EBX_RESERVED                ( \
                                                    CPUID_07_00_EBX_FLAG_TSC_ADJUST        | \
                                                    CPUID_07_00_EBX_FLAG_SGX               | \
                                                    CPUID_07_00_EBX_FLAG_HLE               | \
                                                    CPUID_07_00_EBX_FLAG_FDP_EXCPTN_ONLY   | \
                                                    CPUID_07_00_EBX_FLAG_RTM               | \
                                                    CPUID_07_00_EBX_FLAG_PQM               | \
                                                    CPUID_07_00_EBX_FLAG_PQE               | \
                                                    CPUID_07_00_EBX_FLAG_ADX               | \
                                                    CPUID_07_00_EBX_FLAG_RESERVED22        | \
                                                    CPUID_07_00_EBX_FLAG_CLFLUSHOPT          \
                                                )

#define CPUID_07_00_ECX_FLAG_PREFETCHWT1        BIT(0)
#define CPUID_07_00_ECX_FLAG_AVX512_VBMI        BIT(1)
#define CPUID_07_00_ECX_FLAG_UMIP               BIT(2)
#define CPUID_07_00_ECX_FLAG_PKU                BIT(3)
#define CPUID_07_00_ECX_FLAG_OSPKE              BIT(4)
#define CPUID_07_00_ECX_FLAG_RESERVED5          BIT(5)
#define CPUID_07_00_ECX_FLAG_RESERVED6          BIT(6)
#define CPUID_07_00_ECX_FLAG_RESERVED7          BIT(7)
#define CPUID_07_00_ECX_FLAG_RESERVED8          BIT(8)
#define CPUID_07_00_ECX_FLAG_RESERVED9          BIT(9)
#define CPUID_07_00_ECX_FLAG_RESERVED10         BIT(10)
#define CPUID_07_00_ECX_FLAG_RESERVED11         BIT(11)
#define CPUID_07_00_ECX_FLAG_RESERVED12         BIT(12)
#define CPUID_07_00_ECX_FLAG_RESERVED13         BIT(13)
#define CPUID_07_00_ECX_FLAG_RESERVED14         BIT(14)
#define CPUID_07_00_ECX_FLAG_RESERVED15         BIT(15)
#define CPUID_07_00_ECX_FLAG_RESERVED16         BIT(16)
#define CPUID_07_00_ECX_FLAG_RESERVED17         BIT(17)
#define CPUID_07_00_ECX_FLAG_RESERVED18         BIT(18)
#define CPUID_07_00_ECX_FLAG_RESERVED19         BIT(19)
#define CPUID_07_00_ECX_FLAG_RESERVED20         BIT(20)
#define CPUID_07_00_ECX_FLAG_RESERVED21         BIT(21)
#define CPUID_07_00_ECX_FLAG_RDPID              BIT(22)
#define CPUID_07_00_ECX_FLAG_RESERVED23         BIT(23)
#define CPUID_07_00_ECX_FLAG_RESERVED24         BIT(24)
#define CPUID_07_00_ECX_FLAG_RESERVED25         BIT(25)
#define CPUID_07_00_ECX_FLAG_RESERVED26         BIT(26)
#define CPUID_07_00_ECX_FLAG_RESERVED27         BIT(27)
#define CPUID_07_00_ECX_FLAG_RESERVED28         BIT(28)
#define CPUID_07_00_ECX_FLAG_RESERVED29         BIT(29)
#define CPUID_07_00_ECX_FLAG_SGX_LC             BIT(30)
#define CPUID_07_00_ECX_FLAG_RESERVED31         BIT(31)
#define CPUID_07_00_ECX_RESERVED                ( \
                                                    CPUID_07_00_ECX_FLAG_PREFETCHWT1        | \
                                                    CPUID_07_00_ECX_FLAG_UMIP               | \
                                                    CPUID_07_00_ECX_FLAG_PKU                | \
                                                    CPUID_07_00_ECX_FLAG_OSPKE              | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED5          | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED6          | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED7          | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED8          | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED9          | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED10         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED11         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED12         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED13         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED14         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED15         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED16         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED17         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED18         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED19         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED20         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED21         | \
                                                    CPUID_07_00_ECX_FLAG_RDPID              | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED23         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED24         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED25         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED26         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED27         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED28         | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED29         | \
                                                    CPUID_07_00_ECX_FLAG_SGX_LC             | \
                                                    CPUID_07_00_ECX_FLAG_RESERVED31           \
                                                )


#define CPUID_07_00_EDX_FLAG_RESERVED0          BIT(0)
#define CPUID_07_00_EDX_FLAG_RESERVED1          BIT(1)
#define CPUID_07_00_EDX_FLAG_RESERVED2          BIT(2)
#define CPUID_07_00_EDX_FLAG_RESERVED3          BIT(3)
#define CPUID_07_00_EDX_FLAG_RESERVED4          BIT(4)
#define CPUID_07_00_EDX_FLAG_RESERVED5          BIT(5)
#define CPUID_07_00_EDX_FLAG_RESERVED6          BIT(6)
#define CPUID_07_00_EDX_FLAG_RESERVED7          BIT(7)
#define CPUID_07_00_EDX_FLAG_RESERVED8          BIT(8)
#define CPUID_07_00_EDX_FLAG_RESERVED9          BIT(9)
#define CPUID_07_00_EDX_FLAG_RESERVED10         BIT(10)
#define CPUID_07_00_EDX_FLAG_RESERVED11         BIT(11)
#define CPUID_07_00_EDX_FLAG_RESERVED12         BIT(12)
#define CPUID_07_00_EDX_FLAG_RESERVED13         BIT(13)
#define CPUID_07_00_EDX_FLAG_RESERVED14         BIT(14)
#define CPUID_07_00_EDX_FLAG_RESERVED15         BIT(15)
#define CPUID_07_00_EDX_FLAG_RESERVED16         BIT(16)
#define CPUID_07_00_EDX_FLAG_RESERVED17         BIT(17)
#define CPUID_07_00_EDX_FLAG_RESERVED18         BIT(18)
#define CPUID_07_00_EDX_FLAG_RESERVED19         BIT(19)
#define CPUID_07_00_EDX_FLAG_RESERVED20         BIT(20)
#define CPUID_07_00_EDX_FLAG_RESERVED21         BIT(21)
#define CPUID_07_00_EDX_FLAG_RESERVED22         BIT(22)
#define CPUID_07_00_EDX_FLAG_RESERVED23         BIT(23)
#define CPUID_07_00_EDX_FLAG_RESERVED24         BIT(24)
#define CPUID_07_00_EDX_FLAG_RESERVED25         BIT(25)
#define CPUID_07_00_EDX_FLAG_SPEC_SUPPORT       BIT(26)
#define CPUID_07_00_EDX_FLAG_RESERVED27         BIT(27)
#define CPUID_07_00_EDX_FLAG_RESERVED28         BIT(28)
#define CPUID_07_00_EDX_FLAG_RESERVED29         BIT(29)
#define CPUID_07_00_EDX_FLAG_RESERVED30         BIT(30)
#define CPUID_07_00_EDX_FLAG_RESERVED31         BIT(31)
#define CPUID_07_00_EDX_RESERVED                ( \
                                                    CPUID_07_00_EDX_FLAG_RESERVED0          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED1          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED2          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED3          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED4          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED5          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED6          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED7          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED8          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED9          | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED10         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED11         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED12         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED13         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED14         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED15         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED16         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED17         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED18         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED19         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED20         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED21         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED22         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED23         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED24         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED25         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED27         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED28         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED29         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED30         | \
                                                    CPUID_07_00_EDX_FLAG_RESERVED31           \
                                                )

// eax = 8
#define CPUID_08_EAX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_08_EAX_RESEVED                (CPUID_08_EAX_FLAG_RESERVED0_31)
#define CPUID_08_EBX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_08_EBX_RESEVED                (CPUID_08_EBX_FLAG_RESERVED0_31)
#define CPUID_08_ECX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_08_ECX_RESEVED                (CPUID_08_ECX_FLAG_RESERVED0_31)
#define CPUID_08_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_08_EDX_RESEVED                (CPUID_08_EDX_FLAG_RESERVED0_31)


// eax = 9
#define CPUID_09_EAX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_09_EAX_RESEVED                (CPUID_09_EAX_FLAG_RESERVED0_31)
#define CPUID_09_EBX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_09_EBX_RESEVED                (CPUID_09_EBX_FLAG_RESERVED0_31)
#define CPUID_09_ECX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_09_ECX_RESEVED                (CPUID_09_ECX_FLAG_RESERVED0_31)
#define CPUID_09_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_09_EDX_RESEVED                (CPUID_09_EDX_FLAG_RESERVED0_31)

// eax = a
#define CPUID_0A_EAX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_0A_EAX_RESEVED                (CPUID_0A_EAX_FLAG_RESERVED0_31)
#define CPUID_0A_EBX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_0A_EBX_RESEVED                (CPUID_0A_EBX_FLAG_RESERVED0_31)
#define CPUID_0A_ECX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_0A_ECX_RESEVED                (CPUID_0A_ECX_FLAG_RESERVED0_31)
#define CPUID_0A_EDX_FLAG_RESERVED0_31      BITRANGE_MASK(0, 32)
#define CPUID_0A_EDX_RESEVED                (CPUID_0A_EDX_FLAG_RESERVED0_31)


#define CPUID_0D_01_EAX_FLAG_XSAVEOPT           BIT(0)
#define CPUID_0D_01_EAX_FLAG_XSAVEC_SRSTOR      BIT(1)
#define CPUID_0D_01_EAX_FLAG_XGETBV_1           BIT(2)
#define CPUID_0D_01_EAX_FLAG_XSAVES_SRSTORS     BIT(3)
#define CPUID_0D_01_EAX_FLAG_RESERVED4          BIT(4)
#define CPUID_0D_01_EAX_FLAG_RESERVED5          BIT(5)
#define CPUID_0D_01_EAX_FLAG_RESERVED6          BIT(6)
#define CPUID_0D_01_EAX_FLAG_RESERVED7          BIT(7)
#define CPUID_0D_01_EAX_FLAG_RESERVED8          BIT(8)
#define CPUID_0D_01_EAX_FLAG_RESERVED9          BIT(9)
#define CPUID_0D_01_EAX_FLAG_RESERVED10         BIT(10)
#define CPUID_0D_01_EAX_FLAG_RESERVED11         BIT(11)
#define CPUID_0D_01_EAX_FLAG_RESERVED12         BIT(12)
#define CPUID_0D_01_EAX_FLAG_RESERVED13         BIT(13)
#define CPUID_0D_01_EAX_FLAG_RESERVED14         BIT(14)
#define CPUID_0D_01_EAX_FLAG_RESERVED15         BIT(15)
#define CPUID_0D_01_EAX_FLAG_RESERVED16         BIT(16)
#define CPUID_0D_01_EAX_FLAG_RESERVED17         BIT(17)
#define CPUID_0D_01_EAX_FLAG_RESERVED18         BIT(18)
#define CPUID_0D_01_EAX_FLAG_RESERVED19         BIT(19)
#define CPUID_0D_01_EAX_FLAG_RESERVED20         BIT(20)
#define CPUID_0D_01_EAX_FLAG_RESERVED21         BIT(21)
#define CPUID_0D_01_EAX_FLAG_RESERVED22         BIT(22)
#define CPUID_0D_01_EAX_FLAG_RESERVED23         BIT(23)
#define CPUID_0D_01_EAX_FLAG_RESERVED24         BIT(24)
#define CPUID_0D_01_EAX_FLAG_RESERVED25         BIT(25)
#define CPUID_0D_01_EAX_FLAG_RESERVED26         BIT(26)
#define CPUID_0D_01_EAX_FLAG_RESERVED27         BIT(27)
#define CPUID_0D_01_EAX_FLAG_RESERVED28         BIT(28)
#define CPUID_0D_01_EAX_FLAG_RESERVED29         BIT(29)
#define CPUID_0D_01_EAX_FLAG_RESERVED30         BIT(30)
#define CPUID_0D_01_EAX_FLAG_RESERVED31         BIT(31)
#define CPUID_0D_01_EAX_RESERVED                (CPUID_0D_01_EAX_FLAG_RESERVED4  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED5  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED6  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED7  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED8  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED9  | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED10 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED11 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED12 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED13 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED14 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED15 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED16 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED17 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED18 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED19 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED20 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED21 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED22 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED23 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED24 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED25 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED26 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED27 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED28 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED29 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED30 | \
                                                CPUID_0D_01_EAX_FLAG_RESERVED31 \
                                                )

#define CPUID_80000001_ECX_FLAG_LAHFSAHF64         BIT(0)
#define CPUID_80000001_ECX_FLAG_RESERVED1          BIT(1)
#define CPUID_80000001_ECX_FLAG_RESERVED2          BIT(2)
#define CPUID_80000001_ECX_FLAG_RESERVED3          BIT(3)
#define CPUID_80000001_ECX_FLAG_RESERVED4          BIT(4)
#define CPUID_80000001_ECX_FLAG_LZCNT              BIT(5)
#define CPUID_80000001_ECX_FLAG_RESERVED6          BIT(6)
#define CPUID_80000001_ECX_FLAG_RESERVED7          BIT(7)
#define CPUID_80000001_ECX_FLAG_PREFETCHW          BIT(8)
#define CPUID_80000001_ECX_FLAG_RESERVED9          BIT(9)
#define CPUID_80000001_ECX_FLAG_RESERVED10         BIT(10)
#define CPUID_80000001_ECX_FLAG_RESERVED11         BIT(11)
#define CPUID_80000001_ECX_FLAG_RESERVED12         BIT(12)
#define CPUID_80000001_ECX_FLAG_RESERVED13         BIT(13)
#define CPUID_80000001_ECX_FLAG_RESERVED14         BIT(14)
#define CPUID_80000001_ECX_FLAG_RESERVED15         BIT(15)
#define CPUID_80000001_ECX_FLAG_RESERVED16         BIT(16)
#define CPUID_80000001_ECX_FLAG_RESERVED17         BIT(17)
#define CPUID_80000001_ECX_FLAG_RESERVED18         BIT(18)
#define CPUID_80000001_ECX_FLAG_RESERVED19         BIT(19)
#define CPUID_80000001_ECX_FLAG_RESERVED20         BIT(20)
#define CPUID_80000001_ECX_FLAG_RESERVED21         BIT(21)
#define CPUID_80000001_ECX_FLAG_RESERVED22         BIT(22)
#define CPUID_80000001_ECX_FLAG_RESERVED23         BIT(23)
#define CPUID_80000001_ECX_FLAG_RESERVED24         BIT(24)
#define CPUID_80000001_ECX_FLAG_RESERVED25         BIT(25)
#define CPUID_80000001_ECX_FLAG_RESERVED26         BIT(26)
#define CPUID_80000001_ECX_FLAG_RESERVED27         BIT(27)
#define CPUID_80000001_ECX_FLAG_RESERVED28         BIT(28)
#define CPUID_80000001_ECX_FLAG_RESERVED29         BIT(29)
#define CPUID_80000001_ECX_FLAG_RESERVED30         BIT(30)
#define CPUID_80000001_ECX_FLAG_RESERVED31         BIT(31)
#define CPUID_80000001_ECX_RESERVED                 (CPUID_80000001_ECX_FLAG_RESERVED1       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED2       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED3       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED4       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED6       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED7       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED9       | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED10      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED11      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED12      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED13      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED14      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED15      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED16      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED17      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED18      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED19      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED20      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED21      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED22      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED23      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED24      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED25      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED26      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED27      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED28      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED29      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED30      | \
                                                    CPUID_80000001_ECX_FLAG_RESERVED31 \
                                                    )



#define CPUID_80000001_EDX_FLAG_RESERVED0          BIT(0)
#define CPUID_80000001_EDX_FLAG_RESERVED1          BIT(1)
#define CPUID_80000001_EDX_FLAG_RESERVED2          BIT(2)
#define CPUID_80000001_EDX_FLAG_RESERVED3          BIT(3)
#define CPUID_80000001_EDX_FLAG_RESERVED4          BIT(4)
#define CPUID_80000001_EDX_FLAG_RESERVED5          BIT(5)
#define CPUID_80000001_EDX_FLAG_RESERVED6          BIT(6)
#define CPUID_80000001_EDX_FLAG_RESERVED7          BIT(7)
#define CPUID_80000001_EDX_FLAG_RESERVED8          BIT(8)
#define CPUID_80000001_EDX_FLAG_RESERVED9          BIT(9)
#define CPUID_80000001_EDX_FLAG_RESERVED10         BIT(10)
#define CPUID_80000001_EDX_FLAG_SYSCALL_SYSRET_64  BIT(11)
#define CPUID_80000001_EDX_FLAG_RESERVED12         BIT(12)
#define CPUID_80000001_EDX_FLAG_RESERVED13         BIT(13)
#define CPUID_80000001_EDX_FLAG_RESERVED14         BIT(14)
#define CPUID_80000001_EDX_FLAG_RESERVED15         BIT(15)
#define CPUID_80000001_EDX_FLAG_RESERVED16         BIT(16)
#define CPUID_80000001_EDX_FLAG_RESERVED17         BIT(17)
#define CPUID_80000001_EDX_FLAG_RESERVED18         BIT(18)
#define CPUID_80000001_EDX_FLAG_RESERVED19         BIT(19)
#define CPUID_80000001_EDX_FLAG_XD                 BIT(20)
#define CPUID_80000001_EDX_FLAG_RESERVED21         BIT(21)
#define CPUID_80000001_EDX_FLAG_RESERVED22         BIT(22)
#define CPUID_80000001_EDX_FLAG_RESERVED23         BIT(23)
#define CPUID_80000001_EDX_FLAG_RESERVED24         BIT(24)
#define CPUID_80000001_EDX_FLAG_RESERVED25         BIT(25)
#define CPUID_80000001_EDX_FLAG_PAGE_1G            BIT(26)
#define CPUID_80000001_EDX_FLAG_RDTSCP             BIT(27)
#define CPUID_80000001_EDX_FLAG_RESERVED28         BIT(28)
#define CPUID_80000001_EDX_FLAG_IA64               BIT(29)
#define CPUID_80000001_EDX_FLAG_RESERVED30         BIT(30)
#define CPUID_80000001_EDX_FLAG_RESERVED31         BIT(31)
#define CPUID_80000001_EDX_RESERVED                 (CPUID_80000001_EDX_FLAG_RESERVED0   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED1   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED2   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED3   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED4   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED5   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED6   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED7   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED8   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED9   | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED10  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED12  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED13  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED14  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED15  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED16  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED17  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED18  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED19  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED21  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED22  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED23  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED24  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED25  | \
                                                    CPUID_80000001_EDX_FLAG_RDTSCP      | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED28  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED30  | \
                                                    CPUID_80000001_EDX_FLAG_RESERVED31 \
                                                    )


#define CPUID_80000007_EDX_FLAG_RESERVED0          BIT(0)
#define CPUID_80000007_EDX_FLAG_RESERVED1          BIT(1)
#define CPUID_80000007_EDX_FLAG_RESERVED2          BIT(2)
#define CPUID_80000007_EDX_FLAG_RESERVED3          BIT(3)
#define CPUID_80000007_EDX_FLAG_RESERVED4          BIT(4)
#define CPUID_80000007_EDX_FLAG_RESERVED5          BIT(5)
#define CPUID_80000007_EDX_FLAG_RESERVED6          BIT(6)
#define CPUID_80000007_EDX_FLAG_RESERVED7          BIT(7)
#define CPUID_80000007_EDX_FLAG_INVTSC             BIT(8)
#define CPUID_80000007_EDX_FLAG_RESERVED9          BIT(9)
#define CPUID_80000007_EDX_FLAG_RESERVED10         BIT(10)
#define CPUID_80000007_EDX_FLAG_RESERVED11         BIT(11)
#define CPUID_80000007_EDX_FLAG_RESERVED12         BIT(12)
#define CPUID_80000007_EDX_FLAG_RESERVED13         BIT(13)
#define CPUID_80000007_EDX_FLAG_RESERVED14         BIT(14)
#define CPUID_80000007_EDX_FLAG_RESERVED15         BIT(15)
#define CPUID_80000007_EDX_FLAG_RESERVED16         BIT(16)
#define CPUID_80000007_EDX_FLAG_RESERVED17         BIT(17)
#define CPUID_80000007_EDX_FLAG_RESERVED18         BIT(18)
#define CPUID_80000007_EDX_FLAG_RESERVED19         BIT(19)
#define CPUID_80000007_EDX_FLAG_RESERVED20         BIT(20)
#define CPUID_80000007_EDX_FLAG_RESERVED21         BIT(21)
#define CPUID_80000007_EDX_FLAG_RESERVED22         BIT(22)
#define CPUID_80000007_EDX_FLAG_RESERVED23         BIT(23)
#define CPUID_80000007_EDX_FLAG_RESERVED24         BIT(24)
#define CPUID_80000007_EDX_FLAG_RESERVED25         BIT(25)
#define CPUID_80000007_EDX_FLAG_RESERVED26         BIT(26)
#define CPUID_80000007_EDX_FLAG_RESERVED27         BIT(27)
#define CPUID_80000007_EDX_FLAG_RESERVED28         BIT(28)
#define CPUID_80000007_EDX_FLAG_RESERVED29         BIT(29)
#define CPUID_80000007_EDX_FLAG_RESERVED30         BIT(30)
#define CPUID_80000007_EDX_FLAG_RESERVED31         BIT(31)
#define CPUID_80000007_EDX_RESERVED                 (CPUID_80000007_EDX_FLAG_RESERVED0   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED1   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED2   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED3   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED4   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED5   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED6   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED7   | \
                                                    CPUID_80000007_EDX_FLAG_INVTSC      | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED9   | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED10  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED11  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED12  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED13  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED14  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED15  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED16  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED17  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED18  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED19  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED20  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED21  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED22  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED23  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED24  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED25  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED26  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED27  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED28  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED29  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED30  | \
                                                    CPUID_80000007_EDX_FLAG_RESERVED31 \
                                                    )

#endif //__KERNEL_TYPES_H__
