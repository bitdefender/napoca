/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpudefs.h
*   @brief Basic CPU registers
*/
#ifndef _CPU_DEFS_H_
#define _CPU_DEFS_H_

#include "cx_native.h"

/** @name RFLAGS, CR0, CR3, CR4 and EFER flags
 *  @brief Conform Intel Vol 3A, 2.3, "System Flags and Fields in the EFLAGS Register"
 *  Conform Intel Vol 3A, 2.5, "Control Registers" and Figure 2-6
 */
///@{
#define RFLAGS_CF               0x00000001  // 0
#define RFLAGS_MUST_BE_1        0x00000002  // 1
#define RFLAGS_PF               0x00000004  // 2
#define RFLAGS_MUST_BE_0        0xFFFFFFFFFFC08028ULL   // 63-32 | 31-22 | 15 | 5 | 3
#define RFLAGS_AF               0x00000010  // 4
#define RFLAGS_ZF               0x00000040  // 6
#define RFLAGS_SF               0x00000080  // 7
#define RFLAGS_TF               0x00000100  // 8
#define RFLAGS_IF               0x00000200  // 9
#define RFLAGS_DF               0x00000400  // 10
#define RFLAGS_OF               0x00000800  // 11
#define RFLAGS_IOPL             0x00003000  // 12-13
#define RFLAGS_NT               0x00004000  // 14
#define RFLAGS_RF               0x00010000  // 16
#define RFLAGS_VM               0x00020000  // 17
#define RFLAGS_AC               0x00040000  // 18
#define RFLAGS_VIF              0x00080000  // 19
#define RFLAGS_VIP              0x00100000  // 20
#define RFLAGS_ID               0x00200000  // 21

#define CR0_PE                  0x00000001  // 0
#define CR0_MP                  0x00000002  // 1
#define CR0_EM                  0x00000004  // 2
#define CR0_TS                  0x00000008  // 3
#define CR0_ET                  0x00000010  // 4
#define CR0_NE                  0x00000020  // 5
#define CR0_MUST_BE_1           0x00000030  // 5-4
#define CR0_MUST_BE_0           0xFFFFFFFF1FFAFFC0ULL   // 63-32 | 28-19 | 17 | 15-6
#define CR0_WP                  0x00010000  // 16
#define CR0_AM                  0x00040000  // 18
#define CR0_NW                  0x20000000  // 29
#define CR0_CD                  0x40000000  // 30
#define CR0_PG                  0x80000000  // 31

#define CR3_MUST_BE_0           0xFFFFFF0000000FE7ULL   // 63-40 | 11-5 | 2-0
#define CR3_PWT                 0x00000008  // 3
#define CR3_PCD                 0x00000010  // 4
#define CR3_PD_BASE_MASK        0x000000FFFFFFF000ULL   // 39-12

#define CR4_VME                 0x00000001  // 0
#define CR4_PVI                 0x00000002  // 1
#define CR4_TSD                 0x00000004  // 2
#define CR4_DE                  0x00000008  // 3
#define CR4_PSE                 0x00000010  // 4
#define CR4_PAE                 0x00000020  // 5
#define CR4_MCE                 0x00000040  // 6
#define CR4_PGE                 0x00000080  // 7
#define CR4_PCE                 0x00000100  // 8
#define CR4_OSFXSR              0x00000200  // 09
#define CR4_OSXMMEXCPT          0x00000400  // 10
#define CR4_UMIP                0x00000800  // 11
#define CR4_MUST_BE_0           0xFFFFFFFFFFE99800ULL   // 63-32 | 31-21 | 19 | 16-15 | 12-11
#define CR4_VMXE                0x00002000  // 13
#define CR4_SMXE                0x00004000  // 14
#define CR4_PCIDE               0x00020000  // 17
#define CR4_OSXSAVE             0x00040000  // 18
#define CR4_SMEP                0x00100000  // 20
#define CR4_SMAP                0x00200000  // 21
#define CR4_PKE                 0x00400000  // 22
///@}

/** @name XCR0 feature bits.
 *
 */
///@{
#define XCR0_X87                0x00000001
#define XCR0_SSE                0x00000002
#define XCR0_YMM_HI128          0x00000004
#define XCR0_BNDREGS            0x00000008
#define XCR0_BNDCSR             0x00000010
#define XCR0_OPMASK             0x00000020
#define XCR0_ZMM_HI256          0x00000040
#define XCR0_HI16_ZMM           0x00000080
#define XCR0_PT                 0x00000100
#define XCR0_PKRU               0x00000200
///@}

/** @name MSR_IA32_EFER (0xC0000080)
 *  @brief Conform Intel Vol 3B, Appendix B, Table B-2
 */
///@{
#define EFER_SYSCALL_ENABLE     0x00000001ULL           // 0
#define EFER_MUST_BE_0          0xFFFFFFFFFFFFF2FEULL   // 63-32 | 31-12 | 9 | 7-1
#define EFER_IA32E_ENABLE       0x00000100ULL           // 8
#define EFER_IA32E_ACTIVE       0x00000400ULL           // 10
#define EFER_XD_ENABLE          0x00000800ULL           // 11
#define EFER_LME                EFER_IA32E_ENABLE
#define EFER_LMA                EFER_IA32E_ACTIVE
///@}

/** @name IA32_MISC_ENABLE bits
 *
 */
///@{
#define MISC_ENABLE_FAST_STRINGS    (1ULL << 0)
#define MISC_LIMIT_CPUID_MAXVAL     (1ULL << 22)
#define MISC_XD_BIT_DISABLE         (1ULL << 34)
///@}

/** @name DR6 flags
 *  @brief Conform Intel Vol 3A, 16.2, "Debug Registers"
 */
///@{
#define DR6_B0                  0x00000001  // 0
#define DR6_B1                  0x00000002  // 1
#define DR6_B2                  0x00000004  // 2
#define DR6_B3                  0x00000008  // 3
#define DR6_MUST_BE_1           0xFFFF0FF0  // 31-16 | 11-4
#define DR6_MUST_BE_0           0x00001000  // 12
#define DR6_BD                  0x00002000  // 13
#define DR6_BS                  0x00004000  // 14
#define DR6_BT                  0x00008000  // 15
///@}

/** @name Segment flsgs
 *
 */
///@{
#define SEG_TYPE_DATA_RO                                0
#define SEG_TYPE_DATA_RO_ACCESSED                       1
#define SEG_TYPE_DATA_RW                                2
#define SEG_TYPE_DATA_RW_ACCESSED                       3
#define SEG_TYPE_DATA_RO_EXP_DOWN                       4
#define SEG_TYPE_DATA_RO_EXP_DOWN_ACCESSED              5
#define SEG_TYPE_DATA_RW_EXP_DOWN                       6
#define SEG_TYPE_DATA_RW_EXP_DOWN_ACCESSED              7

#define SEG_TYPE_CODE_EXECUTE_ONLY                      8
#define SEG_TYPE_CODE_EXECUTE_ONLY_ACCESSED             9
#define SEG_TYPE_CODE_EXECUTE_READ                      10
#define SEG_TYPE_CODE_EXECUTE_READ_ACCESSED             11
#define SEG_TYPE_CODE_EXECUTE_ONLY_CONFORMING           12
#define SEG_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED  13
#define SEG_TYPE_CODE_EXECUTE_READ_CONFORMING           14
#define SEG_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED  15

#define SEG_PRESENT                                     CX_BIT(7)
#define SEG_DESCRIPTOR_TYPE_SYSTEM                      (~CX_BIT(4))
#define SEG_DESCRIPTOR_TYPE_CODE_OR_DATA                CX_BIT(4)
///@}

#pragma pack(push, 1)
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

/// @brief 32 bit task segment
typedef struct _TSS32 {
    CX_UINT16       PrevTaskLink;   // +0x00
    CX_UINT16       Reserved_02;    // +0x02
    CX_UINT32       ESP0;           // +0x04
    CX_UINT16       SS0;            // +0x08
    CX_UINT16       Reserved_10;    // +0x0A
    CX_UINT32       ESP1;           // +0x0C
    CX_UINT16       SS1;            // +0x10
    CX_UINT16       Reserved_18;    // +0x12
    CX_UINT32       ESP2;           // +0x14
    CX_UINT16       SS2;            // +0x18
    CX_UINT16       Reserved_26;    // +0x1A
    CX_UINT32       CR3;            // +0x1C
    CX_UINT32       EIP;            // +0x20
    CX_UINT32       EFLAGS;
    CX_UINT32       EAX;
    CX_UINT32       ECX;
    CX_UINT32       EDX;
    CX_UINT32       EBX;
    CX_UINT32       ESP;
    CX_UINT32       EBP;
    CX_UINT32       ESI;            // +0x40
    CX_UINT32       EDI;            // +0x44
    CX_UINT16       ES;             // +0x48
    CX_UINT16       Reserved_74;    // +0x4A
    CX_UINT16       CS;             // +0x4C
    CX_UINT16       Reserved_78;
    CX_UINT16       SS;             // +0x50
    CX_UINT16       Reserved_82;
    CX_UINT16       DS;             // +0x54
    CX_UINT16       Reserved_86;
    CX_UINT16       FS;             // +0x58
    CX_UINT16       Reserved_90;
    CX_UINT16       GS;             // +0x5C
    CX_UINT16       Reserved_94;
    CX_UINT16       LDTR;           // +0x60
    CX_UINT16       Reserved_98;
    CX_UINT16       T;              // +0x64
    CX_UINT16       IoMapBase;      // +0x66
} TSS32;

/// @brief Selector register layout
typedef struct _SELECTOR_REGISTER
{
    union{
        CX_UINT16 Raw;
        struct {
            CX_UINT16 Rpl:2;             ///< requested privilege level
            CX_UINT16 TI:1;              ///< table indicator: 0=GDT, 1=LDT
            CX_UINT16 Index:16-3;        ///< = Raw/8
        };
    };
}SELECTOR_REGISTER;

/// @brief Global Descriptor Table Register layout
typedef struct _CPU_GDTR
{
    CX_UINT16 Limit;
    CX_UINT64 Base;
}CPU_GDTR, CPU_IDTR;

#pragma warning(pop)
#pragma pack(pop)


#endif // _CPU_DEFS_H_