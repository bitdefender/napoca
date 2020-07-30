/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file exceptions.h
*   @brief EXCEPTIONS - exception, IDT and interrupt handling
*
*/
#ifndef _EXCEPTIONS_H_
#define _EXCEPTIONS_H_

#include "core.h"
#include "spinlock.h"
typedef struct _PCPU PCPU;

#define NULL_SELECTOR           0x0000          ///< NULL selector inside the GDT
#define CODE64_SELECTOR         0x0008          ///< Selector for 64-bit mode code segment
#define DATA64_SELECTOR         0x0010          ///< Selector for 64-bit mode data segment
#define GS64_SELECTOR           0x0020          ///< Selector for 64-bit GS
#define TSS64_SELECTOR          0x0030          ///< Selector for 64-bit TSS

//
// IST indexes for special stacks
//
#define IST_DF  1                    ///< IST indexes for special Double-Fault exception stack
#define IST_NMI 2                    ///< IST indexes for special NMI stack
#define IST_MC  3                    ///< IST indexes for special Machine-Check exception stack

/// @brief Enumeration of exception types, for details refer to Intel Software Developer Manual Volume 3, Chapter 6.3.1
typedef enum _EXCEPTION
{
    EXCEPTION_DIVIDE_ERROR              =  0,
    EXCEPTION_DEBUG                     =  1,
    EXCEPTION_NMI                       =  2,
    EXCEPTION_BREAKPOINT                =  3,
    EXCEPTION_OVERFLOW                  =  4,
    EXCEPTION_BOUND                     =  5,
    EXCEPTION_INVALID_OPCODE            =  6,
    EXCEPTION_DEVICE_NOT_AVAIL          =  7,
    EXCEPTION_DOUBLE_FAULT              =  8,
    EXCEPTION_COPROC                    =  9,
    EXCEPTION_INVALID_TSS               = 10,
    EXCEPTION_SEGMENT_NOT_PRESENT       = 11,
    EXCEPTION_STACK_FAULT               = 12,
    EXCEPTION_GENERAL_PROTECTION        = 13,
    EXCEPTION_PAGE_FAULT                = 14,
    EXCEPTION_FPU_ERROR                 = 16,
    EXCEPTION_ALIGNMENT_CHECK           = 17,
    EXCEPTION_MACHINE_CHECK             = 18,
    EXCEPTION_SIMD_FLOATING_POINT       = 19,
    EXCEPTION_VIRTUALIZATION_EXCEPTION  = 20,
    EXCEPTION_SX                        = 30,       ///< security exception, only for AMD when redirecting INIT

    EXCEPTION_END
}EXCEPTION;

/// @brief Data structure describing exceptions and the relevant details for them
typedef struct _EXCEPTION_DETAILS
{
    CX_INT8 *Name;           ///< Name of the exception
    CX_BOOL IsAvailable;     ///< if it is available or not injection
    CX_BOOL HasErrorCode;    ///< The exception has an error code pushed on the stack
    CX_BOOL HasSpecificInfo; ///< The exception has other specific information to it (\#PF only)
}EXCEPTION_DETAILS;

extern const EXCEPTION_DETAILS gExceptionDetails[]; ///< Global exception details list, describing all exceptions

#pragma pack(push)
#pragma pack(1)

/// @brief Structure of an interrupt gate, for details refer to Intel Software Developer Manual Volume 3, Chapter 6.14.1
typedef union _INTERRUPT_GATE {
    CX_UINT64           Raw[2];
    struct {
        CX_UINT16        Offset_15_0;
        CX_UINT16        Selector;
        union
        {
            CX_UINT16     Fields;
            struct
            {
                CX_UINT16 Ist : 3;
                CX_UINT16 Zeroes : 5;
                CX_UINT16 Type : 4;
                CX_UINT16 S : 1;
                CX_UINT16 Dpl : 2;
                CX_UINT16 P : 1;
            };
        };
        CX_UINT16       Offset_31_16;
        CX_UINT32       Offset_63_32;
        CX_UINT32       Reserved2;
    };
} INTERRUPT_GATE;

/// @brief Structure of a System Descriptor, for details refer to Intel Software Developer Manual Volume 3, Chapter 5.1
typedef union _SYSTEM_DESCRIPTOR {
    CX_UINT64           Raw[2];
    struct {
        CX_UINT16        Limit_15_0;
        CX_UINT16        Base_15_0;
        CX_UINT8         Base_23_16;
        CX_UINT16        Fields;
        CX_UINT8         Base_31_24;
        CX_UINT32        Base_63_32;
        CX_UINT32        MustBeZero;
    };
} SYSTEM_DESCRIPTOR;

/// @brief Structure for representing the Task-State Segment in 64-bit mode, for details refer to Intel Software Developer Manual Volume 3, Chapter 7.2.1
typedef struct _TSS64 {
    CX_UINT32           Reserved1;
    CX_UINT64           RSP0;
    CX_UINT64           RSP1;
    CX_UINT64           RSP2;
    CX_UINT64           Reserved2;
    CX_UINT64           IST1;
    CX_UINT64           IST2;
    CX_UINT64           IST3;
    CX_UINT64           IST4;
    CX_UINT64           IST5;
    CX_UINT64           IST6;
    CX_UINT64           IST7;
    CX_UINT64           Reserved3;
    CX_UINT16           Reserved4;
    CX_UINT16           IoMapBaseAddr;
} TSS64;

/// @brief Structure representing our Global Descriptor Table, filled with all the used segment descriptors. For additional details,
///        refer to Intel Software Developer Manual Volume 3, Chapter 3.5.1
typedef struct _GDT {
    CX_UINT64               Null;           ///< 0x0000 the NULL segment descriptor
    CX_UINT64               Code64;         ///< 0x0008 64-bit code segment descriptor
    CX_UINT64               Data64;         ///< 0x0010 64-bit data segment descriptor
    CX_UINT64               _Padding;
    SYSTEM_DESCRIPTOR       Gs64;           ///< 0x0020 Segment descriptor for our GS (64-bit)
    SYSTEM_DESCRIPTOR       Tss64;          ///< 0x0030 Task-State Segment descriptor for 64-bit mode
    CX_UINT64               _Reserved1;
    CX_UINT64               Code32Compat;   ///< 0x0040 32-bit code segment descriptor
    CX_UINT64               _Reserved3;
    CX_UINT64               _Reserved4;
} GDT;

/// @brief Structure representing the GDTR register, for additional details refer to Intel Software Developer Manual Volume 3, Chapter 3.5.1
typedef struct _LGDT {
    CX_UINT16       Size;
    CX_UINT64       GdtAddress;
} LGDT;

/// @brief Structure representing the IDTR register, for additional details refer to Intel Software Developer Manual Volume 3, Chapter 6.11
typedef struct _LIDT {
    CX_UINT16       Size;
    CX_UINT64       IdtAddress;
} LIDT;

#pragma pack(pop)

//
// trap frame
//
#pragma pack(push)
#pragma pack(1)

///
/// @brief The Hypervisors trap frame for interrupt and exception handling
/// NOTE : always keep the size of the _HV_TRAP_FRAME 16 bytes aligned
///
typedef struct _HV_TRAP_FRAME
{
    CX_UINT64   P1Home;                ///< Called method 1st param
    CX_UINT64   P2Home;                ///< Called method 2nd param
    CX_UINT64   P3Home;                ///< Called method 3rd param
    CX_UINT64   P4Home;                ///< Called method 4th param
    CX_UINT64   Reserved1;

    CX_UINT64   Self;                  ///< Address of this trap frame

    CX_UINT64   ExceptionCode;         ///< Exception code

    // general purpose registers
    CX_UINT64   Rax;                   ///< General-purpose register RAX
    CX_UINT64   Rbx;                   ///< General-purpose register RBX
    CX_UINT64   Rdx;                   ///< General-purpose register RDX
    CX_UINT64   Rcx;                   ///< General-purpose register RCX
    CX_UINT64   Rsi;                   ///< General-purpose register RSI
    CX_UINT64   Rdi;                   ///< General-purpose register RDI
    CX_UINT64   R8;                    ///< General-purpose register R8
    CX_UINT64   R9;                    ///< General-purpose register R9
    CX_UINT64   R10;                   ///< General-purpose register R10
    CX_UINT64   R11;                   ///< General-purpose register R11
    CX_UINT64   R12;                   ///< General-purpose register R12
    CX_UINT64   R13;                   ///< General-purpose register R13
    CX_UINT64   R14;                   ///< General-purpose register R14
    CX_UINT64   R15;                   ///< General-purpose register R15

    // segment registers
    CX_UINT16    SegDs;                ///< Data segment register
    CX_UINT16    _Fill100;             ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill101;              ///< 4 byte fill-up space because segment register is on 16-bits

    CX_UINT16    SegEs;                ///< Additional Data segment register (ES)
    CX_UINT16    _Fill102;             ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill103;              ///< 4 byte fill-up space because segment register is on 16-bits

    CX_UINT16    SegFs;                ///< Additional Data segment register (FS)
    CX_UINT16    _Fill104;             ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill105;              ///< 4 byte fill-up space because segment register is on 16-bits

    CX_UINT16    SegGs;                ///< Additional Data segment register (GS)
    CX_UINT16    _Fill106;             ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill107;              ///< 4 byte fill-up space because segment register is on 16-bits

    CX_UINT64   Cr2;                   ///< The value in CR2, only valid if exception is page fault (the address causing the PF)
    CX_UINT64   _FillCR2;              ///< 8 byte fill-up space because of the 16 byte alignment
    CX_UINT64   Rbp;                   ///< The Base Pointer Register value (RBP)

    // error code put on the stack by the processor (if applicable)
    // otherwise the address of the asm handler
    union
    {
        CX_UINT64   AsmHandlerAddress; ///< If no exception code than the address of the asm handler
        CX_UINT64   ErrorCode;         ///< The error-code of the exception if applicable
    };

    CX_UINT64   Rip;                   ///< The address of the interrupted instruction

    CX_UINT16    SegCs;                ///< Code segment register
    CX_UINT16    _Fill0;               ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill1;                ///< 4 byte fill-up space because segment register is on 16-bits

    CX_UINT32   EFlags;                ///< The EFLAGS register of the CPU
    CX_UINT32   _Fill2;                ///< 4 byte fill-up space because eflags register is on 32-bits

    CX_UINT64   Rsp;                   ///< The current Stack Pointer of the CPU

    CX_UINT16    SegSs;                ///< Stack segment register
    CX_UINT16    _Fill3;               ///< 2 byte fill-up space because segment register is on 16-bits
    CX_UINT32   _Fill4;                ///< 4 byte fill-up space because segment register is on 16-bits
} HV_TRAP_FRAME;

/// @brief The structure representing an exception error-code, for details refer to Intel Software Developer Manual Volume 3, Chapter 6.13
typedef struct _EXCEPTION_ERROR_CODE
{
    union{
        CX_UINT32 Raw;
        struct
        {
            CX_UINT32 ExternalEvent:1;
            CX_UINT32 IdtNotGdtOrLdt:1;
            CX_UINT32 LdtNotGdt:1;
            CX_UINT32 SelectorIndex:29;
        };
    };
}EXCEPTION_ERROR_CODE;


#pragma pack(pop)

//
// ASM interrupt handlers
//

/// @brief Interrupt handler written in assembly for EXCEPTION_DIVIDE_ERROR
void HvHndDivideError(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_DEBUG
void HvHndDebug(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_NMI
void HvHndNMI(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_BREAKPOINT
void HvHndBreakpoint(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_OVERFLOW
void HvHndOverflow(
    void
    );
/// @brief Interrupt handler written in assembly for EXCEPTION_BOUND

void HvHndBOUND(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_INVALID_OPCODE
void HvHndInvalidOpcode(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_DEVICE_NOT_AVAIL
void HvHndDeviceNotAvailable(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_DOUBLE_FAULT
void HvHndDoubleFault(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_COPROC
void HvHndCoprocessorSegmentOverrun(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_INVALID_TSS
void HvHndInvalidTSS(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_SEGMENT_NOT_PRESENT
void HvHndSegmentNotPresent(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_STACK_FAULT
void HvHndStackFault(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_GENERAL_PROTECTION
void HvHndGeneralProtection(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_PAGE_FAULT
void HvHndPageFault(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_FPU_ERROR
void HvHndFPUError(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_ALIGNMENT_CHECK
void HvHndAlignmentCheck(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_MACHINE_CHECK
void HvHndMachineCheck(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_SIMD_FLOATING_POINT
void HvHndSIMDFloatingPoint(
    void
    );

/// @brief Interrupt handler written in assembly for EXCEPTION_SX
void HvHndSX(
    void
    );

///
/// @brief        Initializes the CPUs GDT, IDT and TSS. Completes the tables with the used descriptors. Also, initializes the exception handlers.
///
/// @param[in]    Cpu                              The PCPU to which the initializations has to be maid.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Cpu is an invalid pointer
///
CX_STATUS
HvInitGdtTssIdt(
    _In_ PCPU *Cpu
    );

///
/// @brief        Loads the GDT, IDT, TR and all the segment descriptors on the CPU.
///
/// @param[in]    Gdt                              Address of the Global Descriptor Table
/// @param[in]    Tss                              Address of Task-State Segment descriptor
/// @param[in]    Idt                              Address of the Interrupt Descriptor Table
/// @param[in]    GsBase                           The GS base address which will be written to the GS base MSR (the address of the PCPU)
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Gdt is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if Tss is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if Idt is an invalid pointer
///
CX_STATUS
HvLoadGdtTssIdtGs(
    _In_ CX_VOID *Gdt,
    _In_ CX_VOID *Tss,
    _In_ CX_VOID *Idt,
    _In_ CX_UINT64 GsBase
    );


///
/// @brief        Initializes every interrupt handler inside the given IDT with our handlers written in except.nasm
///
/// @param[in]    Idt                              The address of the IDT
/// @param[in]    AreFinalStacksAvailable          In case we have the separate stacks prepared for NMI, DF and MC interrupts
///
/// @returns      CX_STATUS_SUCCESS                - always
///
CX_STATUS
HvInitExceptionHandlers(
    _In_ INTERRUPT_GATE *Idt,
    _In_ CX_BOOL AreFinalStacksAvailable
);

///
/// @brief        Modifies the current MXCSR of the platform in order to mask all SIMD floating-point exceptions
///
CX_VOID
HvSetupSseExceptions(
    CX_VOID
);

#endif // _EXCEPTIONS_H_
