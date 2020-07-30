/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _EMU_H_
#define _EMU_H_

#include "core.h"
#include "bddisasm.h"

typedef struct _VCPU VCPU;

// memory type custom flags/bits
#define EMU_MEMTYPE_DEVICE                      0x100  ///< Memory marked with this flag identifies device memory hooked by the hypervisor

//
// Data structures that may be used outside the emulator as helpers.
//
#define ND_MAX_OPERAND_SIZE         64      ///< Maximum size of an operand supported by emulator.

//
// Emulator flags
//
#define ND_FLAG_V8086               0x00000001 ///< We must emulate a V8086 mode instruction
#define ND_FLAG_INTROSPECTION       0x00000002 ///< We will emulate an EPT violation generated due to an Intro hook
#define ND_FLAG_EMU_NO_EXEC         0x00000004 ///< We won't have to make all the validations in order to emulate the instruction,
                                               ///< because the exit was due to an EPT read/write violation; all the chekcs have already
                                               ///< been done, we can safely emulate the instruction (any exception would have been
                                               ///< generated before trying to access the source/destination memory address).

///
/// @brief Emulates an instruction if it is supported by emulator
///
/// The emulator supports:
/// - any form of MOV instruction, (including MOVNTI, MOVNTQ, MOVZX, MOVSX, MOVSXD)
/// - conditional MOV (CMOVcc)
/// - arithmetic instructions (ADD, ADC, SUB, SBB, CMP, INC, DEC)
/// - logic instructions (OR, AND, XOR, TEST)
/// - string operations (MOVS, STOS, LODS)
/// - in-out instructions (IN, OUT, INS, OUTS, etc.)
/// - exchange instructions (XCHG, XADD, CMPXCHG, CMPXCHG8B, CMPXCHG16B)
/// - system instructions (RDMSR, WRMSR, CPUID, INVD, WBINVD, HLT)
/// - bit manipulation instructions (BTS, BTC, BTR, BT)
/// - rotate instructions (ROL, ROR, RCL, RCR)
/// - set instructions (SETcc)
/// - system instructions (LGDT, LIDT, LTR, LLDT, SGDT, SIDT, STR, SLDT)
/// - software interrupt (INT)
///
/// There is support for LOCK prefix; If LOCK is used with a valid instruction or
/// when accessing memory we ensure the atomic access using a lock xchg in cpu.nasm (CpuLockStore function)
/// to memory, and ensuring that while an instruction has LOCK, other instructions can't access the
/// memory. This way, we can ensure atomicty using a fine-grained lock.
/// If an instruction has LOCK prefix, but the destination isn't memory, CX_STATUS_OPERATION_NOT_SUPPORTED will
/// be returned, in order to let the CPU execute the instruction and generate a #UD.
///
/// NOTE: If CX_STATUS_OPERATION_NOT_SUPPORTED is returned, the instruction must be handled by the fallback (re-execution) mechanism.
///

/// @param Vcpu                     Vcpu for which instruction will be emulated
/// @param Instrux                  Decoded instruction.
/// @param Flags                    Flags.
/// @param Context                  Device context, if any.
/// @param Gpa                      Gpa of the address where the EPT violation was generated, if this is the case.


/// @return CX_STATUS_OPERATION_NOT_SUPPORTED       If the emulator does not support this instruction.
/// @return CX_STATUS_SUCCESS                       If the instruction is successfully emulated.
/// @return STATUS_XXX                              On any other error.
///
NTSTATUS
NdEmulateInstruction(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa
);


///
/// @brief Perform page-walk emulation.
///
/// If paging structures of the guest are hooked, EPT violations may be
/// generated with a special exit qualification, which indicates us that the EPT violation took place
/// because the CPU tried to update the A or D flag from inside the page table entry.
///
/// Entire page walk wil be emulated. This is how the situation is handled from now on.
/// In the rare cases where 2 consecutive violations are generated from the same RIP on the same GPA, we
/// will use the re-execution mechanism (those situations should be rare; we assume we did something wrong,
/// or it is an unsupported case).
///
///
/// @param Vcpu             Vcpu for which emulation will be performed
/// @param Gla              Guest linear address for which emulation will be performed
/// @param Qualification    VMX reported exit details
///
NTSTATUS
NdEmulatePageWalk(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Gla,
    _In_ CX_UINT64 Qualification
    );

///
/// @brief Perform initialization steps and allocate any needed resources.
///
/// Will initialize the software emulator. If the trace cache is enabled, will allocate
/// memory space for it.
///
/// @param CpuCount                    Number of cpu cores for which emulator prepares resources
///
/// @return CX_STATUS_SUCCESS      On success.
/// @return STATUS_XXX             On errors
///
NTSTATUS
NdEmuInit(
    _In_ CX_UINT32 CpuCount
    );

#endif // _EMU_H_
