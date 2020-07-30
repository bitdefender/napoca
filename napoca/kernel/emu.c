/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "guests/guests.h"
#include "memory/ept.h"
#include "kernel/vcpu.h"
#include "kernel/emu.h"
#include "common/kernel/vmxdefs.h"
#include "debug/emu_debug.h"

#pragma check_stack(off)

//
// TODO: If the OS fails to load with no explanation, it is most likely due to the fact that the synchronization
//          has been deactivated here, in the emulator, which causes some instruction to be emulated incorrectly.
//      Instructions must modify the CPU context ATOMICALLY! There may be cases where, for example, we modify
//          a register, and when we get to modify the memory, we can't and we must generate an exception; Therefore,
//          memory should always be updated first, in case of exceptions (this way, the state will remain valid).
//      Create nice definitions of various bitfields used throughout this emulator. Some of them should be defined in other places, like cpu.h.

// NOTE: The input arguments are not validated inside the emulation handlers because the emulation handlers
// can only be called by NdEmulateInstruction, which already validated the input arguments. Therefore, in order
// to speed up the emulation process as much as possible, the input args are not validated inside the handlers.

// Supervisor mode: ring = 0, 1, or 2; user mode: ring 3.

#define ENABLE_ALL_EXCEPTION_CHECKS

//
// emulator definitions
//
#define ND_EMU_OP_REG_GPR           1
#define ND_EMU_OP_REG_MMX           2
#define ND_EMU_OP_REG_XMM           3
#define ND_EMU_OP_REG_CR            4
#define ND_EMU_OP_REG_DR            5
#define ND_EMU_OP_REG_SEG           6
#define ND_EMU_OP_REG_FPU           7
#define ND_EMU_OP_MEM               8
#define ND_EMU_OP_IMM               9
#define ND_EMU_OP_FLG               10
#define ND_EMU_OP_REG_YMM           11
#define ND_EMU_OP_REG_ZMM           12
#define ND_EMU_OP_REG_K             13
#define ND_EMU_OP_REG_BND           14
#define ND_EMU_OP_REL_OFFS          15

#define REG_GPRV(ctx, reg)          (*((&(ctx)->RAX) + (reg)))
#define REG_GPRP(ctx, reg)          ((&(ctx)->RAX) + (reg))

#define REG_MMXV(ctx, reg)          (*(&(ctx)->MM0 + (reg)))
#define REG_MMXP(ctx, reg)          (&((ctx)->MM0) + (reg))

#define REG_XMMV(ctx, reg)          (*(&(ctx)->XMM0 + (reg)))
#define REG_XMMP(ctx, reg)          (&((ctx)->XMM0) + (reg))

#ifndef ND_SET_FLAG
#define ND_SET_FLAG(eflags, flag, v){ if (v) { eflags |= (flag); } else { eflags &= ~(flag); } }
#endif
#ifndef ND_GET_FLAG
#define ND_GET_FLAG(eflags, flag)   (((eflags) >> (flag##_SHIFT)) & 1)
#endif
#ifndef ND_GET_SIGN
#define ND_GET_SIGN(sz, x)          ((sz) == 1 ? ((x) & 0x80) >> 7 : (sz) == 2 ? ((x) & 0x8000) >> 15 : (sz) == 4 ? ((x) & 0x80000000) >> 31 : (x) >> 63)
#endif

#define ND_TRIM_ADDR(sz, x)         ((sz) == ND_ADDR_16 ? (x) & 0xFFFF : (sz) == ND_ADDR_32 ? (x) & 0xFFFFFFFF : (x))
//
// Eflags defines
//
#define ND_EFLAG_CF                 0x00000001
#define ND_EFLAG_CF_SHIFT           0x00000000
#define ND_EFLAG_PF                 0x00000004
#define ND_EFLAG_PF_SHIFT           0x00000002
#define ND_EFLAG_AF                 0x00000010
#define ND_EFLAG_AF_SHIFT           0x00000004
#define ND_EFLAG_ZF                 0x00000040
#define ND_EFLAG_ZF_SHIFT           0x00000006
#define ND_EFLAG_SF                 0x00000080
#define ND_EFLAG_SF_SHIFT           0x00000007
#define ND_EFLAG_TF                 0x00000100
#define ND_EFLAG_TF_SHIFT           0x00000008
#define ND_EFLAG_IF                 0x00000200
#define ND_EFLAG_IF_SHIFT           0x00000009
#define ND_EFLAG_DF                 0x00000400
#define ND_EFLAG_DF_SHIFT           0x0000000A
#define ND_EFLAG_OF                 0x00000800
#define ND_EFLAG_OF_SHIFT           0x0000000B


typedef struct _EMU_SEG_AR
{
    union
    {
        CX_UINT64           Raw;            ///< Raw value for access rights
        CX_UINT32           Type : 4;       ///< Segment type
        CX_UINT32           S : 1;          ///< Segment size
        CX_UINT32           Dpl : 2;        ///< Segment dpl
        CX_UINT32           P : 1;          ///< Segment is present
        CX_UINT32           Reserved1 : 4;  ///< Segment reserved bits
        CX_UINT32           Avl : 1;        ///< Segment avl
        CX_UINT32           L : 1;          ///< Segment L bit
        CX_UINT32           DB : 1;         ///< Segment DB bit
        CX_UINT32           G : 1;          ///< Segment G bit
        CX_UINT32           Unusable : 1;   ///< Segment unusable bit
        CX_UINT32           Reserved2 : 15; ///< Segment reserved bits
    };
} EMU_SEG_AR, * PEMU_SEG_AR;

typedef struct _EMU_SEG_REG
{
    CX_UINT8                Segment;        ///< Segment ID (as encoded in the instruction). Check NDR_ES, NDR_CS, etc.
    CX_UINT8                _Reserved;      ///< Padding.
    CX_UINT16                Selector;      ///< Selector.
    CX_UINT64               Base;           ///< Segment base.
    CX_UINT64               Limit;          ///< Segment limit.
    EMU_SEG_AR              AccessRights;   ///< Segment access rights.
} EMU_SEG_REG, * PEMU_SEG_REG;


typedef struct _EMU_OPERAND
{
    CX_UINT64               Size;        ///< Size in bytes of an operand

    ///< The value of the operand. For future compatibility, we will handle up to 512 bit (ZMM registers).
    union
    {
        CX_UINT8            Buffer[ND_MAX_OPERAND_SIZE];
        CX_UINT64           Value;
        CX_UINT64           Value8;
        CX_UINT32           Value4;
        CX_UINT16           Value2;
        CX_UINT8            Value1;
    };

    CX_UINT64               Gva;         ///< Operand virtual address. This is an offset inside the Seg reg.

    union
    {
        CX_UINT64           Address;     ///< Register address, memory address, etc.
        CX_UINT64           Gla;         ///< If the operand is memory, this will be the linear address field (base + offset).
    };

    CX_UINT32               Type;        ///< One of the ND_EMU_OP_X

    EMU_SEG_REG             Seg;        ///< The segment of this operand. This field has meaning only for memory operands.

} EMU_OPERAND, * PEMU_OPERAND;


//
// Emulation flags
//
#define ND_EMU_FLAG_IMPLICIT_LOCK   0x80000000          ///< Flag indicates that the instruction behaves like having LOCK prefix anyway
#define ND_EMU_FLAG_CHECK_REG_FIELD 0x40000000          ///< Will select the emulation handler via the reg field
#define ND_EMU_FLAG_V8086           0x20000000          ///< The instruction is a Virtual 8086 emulated, so treat it carefully

// Page fault flags, also used to check access rights when accessing memory.
#define ND_PF_P                         0x0001
#define ND_PF_RW                        0x0002
#define ND_PF_US                        0x0004
#define ND_PF_RSVD                      0x0008
#define ND_PF_IF                        0x0010
#define ND_PF_PK                        0x0020
#define ND_PF_SGX                       0x8000

// Page table defs.
#define ND_PT_P                         0x1 // Page present.
#define ND_PT_W                         0x2 // Page writable.
#define ND_PT_U                         0x4 // Page user-accessible.
#define ND_PT_A                         0x20 // Accessed
#define ND_PT_D                         0x40 // Dirty
#define ND_PT_PS                        0x80 // Page Size extension.
#define ND_PT_PK                        0x7800000000000000ULL
#define ND_PT_XD                        0x8000000000000000ULL // eXecute Disable


//
// _NdEmuHandlerPageWalk flags
//
#define ND_PW_SET_A                     0x1     ///< Accessed bit will be set.
#define ND_PW_SET_D                     0x2     ///< Dirty bit will be set.
#define ND_PW_SET_D_IF_ALREADY_A        0x4     ///< Dirty bit will be set only if the entry is already marked Accessed.
#define ND_PW_IMPLICIT_SUPER_ACCESS     0x8     ///< The memory access is an implicit supervisory mode access.
#define ND_PW_SUPPRESS_EXCEPTION_CHECKS 0x10    ///< Suppress exception checks during the page-walk. This must be
                                                ///< used only for page-walk emulations as part of an EPT violation
                                                ///< with bit 8 zero.


//
// Vcpu operating modes.
//
#define ND_MODE_UNKNOWN                 0 ///< Unknown operating mode.
#define ND_MODE_REAL                    1 ///< Real mode.
#define ND_MODE_V8086                   2 ///< Virtual V8086 mode.
#define ND_MODE_PROTECTED               3 ///< Protected mode.
#define ND_MODE_COMPAT                  4 ///< Compatibility mode - 32 bit segment in long mode.
#define ND_MODE_LONG                    5 ///< Long mode.
#define ND_MODE_SMM                     6 ///< System Management Mode




static NTSTATUS
_NdEmuHandlerPageWalk(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 GuestLinearAddress,
    _In_ CX_UINT64 AccessSize,
    _In_ CX_UINT32 AccessedDirtyFlags,
    _In_ CX_UINT32 RequiredFlags,
    __out_opt CX_UINT32 *FaultFlags,
    __out_opt CX_UINT64 *GuestPhysicalAddress
    );


static NTSTATUS
_NdEmuHandlerMov(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerMovSse(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandleMovImm(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCmov(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Device,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerPushPop(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Device,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerLogic(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCmps(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerArith(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Device,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerRotate(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Device,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCmpXchg8(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerXadd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerXchg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCmpXchg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerIncDec(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerJump(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerBt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerSet(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static
NTSTATUS
_NdEmuHandlerInOut(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
);

static NTSTATUS
_NdEmuHandlerRdWrMsr(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCpuid(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerInvd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerWbInvd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerInvlpg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerLgdt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerLidt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerSgdt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerSidt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCliSti(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerCarry(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerDirection(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static
NTSTATUS
_NdEmuHandlerSystemSegLoad(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
);

static
NTSTATUS
_NdEmuHandlerSystemSegStore(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
);

static NTSTATUS
_NdEmuHandler0F0100Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F0101Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F0102Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F0103Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F0107Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerArplMovsxd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F10Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F11Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerUd2(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerMovss(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandlerMovapsMovups(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F28Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

static NTSTATUS
_NdEmuHandler0F29Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

typedef NTSTATUS
(*PFUNC_EmulationHandler)(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    );

typedef struct _EMU_HANDLER
{
    PFUNC_EmulationHandler      Handler;
    CX_UINT32                       Flags;          // Passed as an argument to the EmulationHandler, as Aux; High CX_UINT16 contains flags, low
                                                // CX_UINT16 contains emulation-specific flags, like what operation should be emulated
} EMU_HANDLER, *PEMU_HANDLER;

static const EMU_HANDLER gEmuGroup80LUT[] =
{
    /* 0x00 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x01 */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x02 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x03 */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x04 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x05 */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x06 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x07 */ { _NdEmuHandlerArith, 4 },    // CMP
};

static const EMU_HANDLER gEmuGroupC6C7LUT[] =
{
    /* 0x00 */ { _NdEmuHandlerMov, 0 },    // MOV
    /* 0x01 */ { NULL, 0 },
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroupF6F7LUT[] =
{
    /* 0x00 */ { _NdEmuHandlerLogic, 3 },    // TEST
    /* 0x01 */ { NULL, 0 },
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroupFEFFLUT[] =
{
    /* 0x00 */ { _NdEmuHandlerIncDec, 0 },    // INC
    /* 0x01 */ { _NdEmuHandlerIncDec, 1 },    // DEC
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { _NdEmuHandlerJump, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { _NdEmuHandlerPushPop, 0 },   // PUSH
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroup0FC7LUT[] =
{
    /* 0x00 */ { NULL, 0 },
    /* 0x01 */ { _NdEmuHandlerCmpXchg8, 0 },    // CMPXCHG8B/CMPXCHG16B
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroup0FBALUT[] =
{
    /* 0x00 */ { NULL, 0 },
    /* 0x01 */ { NULL, 0 },
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { _NdEmuHandlerBt, 3 }, // BT
    /* 0x05 */ { _NdEmuHandlerBt, 0 },
    /* 0x06 */ { _NdEmuHandlerBt, 1 },
    /* 0x07 */ { _NdEmuHandlerBt, 2 },
};

static const EMU_HANDLER gEmuGroupRotateLUT[] =
{
    /* 0x00 */ { _NdEmuHandlerRotate, 0 },
    /* 0x01 */ { _NdEmuHandlerRotate, 1 },
    /* 0x02 */ { _NdEmuHandlerRotate, 2 },
    /* 0x03 */ { _NdEmuHandlerRotate, 3 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroup8FLUT[] =
{
    /* 0x00 */ { _NdEmuHandlerPushPop, 1 },  // POP [mem]
    /* 0x01 */ { NULL, 1 },
    /* 0x02 */ { NULL, 2 },
    /* 0x03 */ { NULL, 3 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const EMU_HANDLER gEmuGroup0F01LUT[] =
{
    /* 0x00 */ { _NdEmuHandler0F0100Group, 0 },
    /* 0x01 */ { _NdEmuHandler0F0101Group, 0 },
    /* 0x02 */ { _NdEmuHandler0F0102Group, 0 },
    /* 0x03 */ { _NdEmuHandler0F0103Group, 0 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { _NdEmuHandler0F0107Group, 0 },
};

static const EMU_HANDLER gEmuGroup0F00LUT[] =
{
    /* 0x00 */ { _NdEmuHandlerSystemSegStore, 0 },
    /* 0x01 */ { _NdEmuHandlerSystemSegStore, 1 },
    /* 0x02 */ { _NdEmuHandlerSystemSegLoad, ND_EMU_FLAG_V8086 | 0 },
    /* 0x03 */ { _NdEmuHandlerSystemSegLoad, ND_EMU_FLAG_V8086 | 1 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
};

static const PEMU_HANDLER gEmuRedirectionTable[] =
{
    /* 0x00 */ (PEMU_HANDLER)gEmuGroup80LUT,
    /* 0x01 */ (PEMU_HANDLER)gEmuGroupC6C7LUT,
    /* 0x02 */ (PEMU_HANDLER)gEmuGroupFEFFLUT,
    /* 0x03 */ (PEMU_HANDLER)gEmuGroupF6F7LUT,
    /* 0x04 */ (PEMU_HANDLER)gEmuGroup0FC7LUT,
    /* 0x05 */ (PEMU_HANDLER)gEmuGroup0FBALUT,
    /* 0x06 */ (PEMU_HANDLER)gEmuGroupRotateLUT,
    /* 0x07 */ (PEMU_HANDLER)gEmuGroup8FLUT,
    /* 0x08 */ (PEMU_HANDLER)gEmuGroup0F01LUT,
    /* 0x09 */ (PEMU_HANDLER)gEmuGroup0F00LUT,
};

static const EMU_HANDLER gEmu1ByteLUT[] =
{
    /* 0x00 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x01 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x02 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x03 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x04 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x05 */ { _NdEmuHandlerArith, 0 },    // ADD
    /* 0x06 */ { _NdEmuHandlerPushPop, 0 },  // PUSH ES
    /* 0x07 */ { _NdEmuHandlerPushPop, 1 },  // POP ES
    /* 0x08 */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x09 */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x0a */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x0b */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x0c */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x0d */ { _NdEmuHandlerLogic, 0 },    // OR
    /* 0x0e */ { _NdEmuHandlerPushPop, 0 },  // PUSH CS
    /* 0x0f */ { NULL, 0 },
    /* 0x10 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x11 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x12 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x13 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x14 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x15 */ { _NdEmuHandlerArith, 1 },    // ADC
    /* 0x16 */ { _NdEmuHandlerPushPop, 0 },  // PUSH SS
    /* 0x17 */ { _NdEmuHandlerPushPop, 0 },  // POP SS
    /* 0x18 */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x19 */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x1a */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x1b */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x1c */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x1d */ { _NdEmuHandlerArith, 3 },    // SBB
    /* 0x1e */ { _NdEmuHandlerPushPop, 0 },  // PUSH DS
    /* 0x1f */ { _NdEmuHandlerPushPop, 1 },  // POP DS
    /* 0x20 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x21 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x22 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x23 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x24 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x25 */ { _NdEmuHandlerLogic, 1 },    // AND
    /* 0x26 */ { NULL, 0 },
    /* 0x27 */ { NULL, 0 },
    /* 0x28 */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x29 */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x2a */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x2b */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x2c */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x2d */ { _NdEmuHandlerArith, 2 },    // SUB
    /* 0x2e */ { NULL, 0 },
    /* 0x2f */ { NULL, 0 },
    /* 0x30 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x31 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x32 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x33 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x34 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x35 */ { _NdEmuHandlerLogic, 2 },    // XOR
    /* 0x36 */ { NULL, 0 },
    /* 0x37 */ { NULL, 0 },
    /* 0x38 */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x39 */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x3a */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x3b */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x3c */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x3d */ { _NdEmuHandlerArith, 4 },    // CMP
    /* 0x3e */ { NULL, 0 },
    /* 0x3f */ { NULL, 0 },
    /* 0x40 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x41 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x42 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x43 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x44 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x45 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x46 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x47 */ { _NdEmuHandlerIncDec, 0 },
    /* 0x48 */ { _NdEmuHandlerIncDec, 1 },
    /* 0x49 */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4a */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4b */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4c */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4d */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4e */ { _NdEmuHandlerIncDec, 1 },
    /* 0x4f */ { _NdEmuHandlerIncDec, 1 },
    /* 0x50 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x51 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x52 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x53 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x54 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x55 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x56 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x57 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x58 */ { _NdEmuHandlerPushPop, 1 },
    /* 0x59 */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5a */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5b */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5c */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5d */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5e */ { _NdEmuHandlerPushPop, 1 },
    /* 0x5f */ { _NdEmuHandlerPushPop, 1 },
    /* 0x60 */ { NULL, 0 },
    /* 0x61 */ { NULL, 0 },
    /* 0x62 */ { NULL, 0 },
    /* 0x63 */ { _NdEmuHandlerArplMovsxd, 0 },
    /* 0x64 */ { NULL, 0 },
    /* 0x65 */ { NULL, 0 },
    /* 0x66 */ { NULL, 0 },
    /* 0x67 */ { NULL, 0 },
    /* 0x68 */ { _NdEmuHandlerPushPop, 0 },
    /* 0x69 */ { NULL, 0 },
    /* 0x6a */ { _NdEmuHandlerPushPop, 0 },
    /* 0x6b */ { NULL, 0 },
    /* 0x6c */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },
    /* 0x6d */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },
    /* 0x6e */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },
    /* 0x6f */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },    /* 0x70 */ { NULL, 0 },
    /* 0x71 */ { NULL, 0 },
    /* 0x72 */ { NULL, 0 },
    /* 0x73 */ { NULL, 0 },
    /* 0x74 */ { NULL, 0 },
    /* 0x75 */ { NULL, 0 },
    /* 0x76 */ { NULL, 0 },
    /* 0x77 */ { NULL, 0 },
    /* 0x78 */ { NULL, 0 },
    /* 0x79 */ { NULL, 0 },
    /* 0x7a */ { NULL, 0 },
    /* 0x7b */ { NULL, 0 },
    /* 0x7c */ { NULL, 0 },
    /* 0x7d */ { NULL, 0 },
    /* 0x7e */ { NULL, 0 },
    /* 0x7f */ { NULL, 0 },
    /* 0x80 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 0 }, // high word are the flags; low word selects the table used to be indexed with reg field
    /* 0x81 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 0 },
    /* 0x82 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 0 },
    /* 0x83 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 0 },
    /* 0x84 */ { _NdEmuHandlerLogic, 3 },    // TEST
    /* 0x85 */ { _NdEmuHandlerLogic, 3 },    // TEST
    /* 0x86 */ { _NdEmuHandlerXchg, ND_EMU_FLAG_IMPLICIT_LOCK },     // XCHG
    /* 0x87 */ { _NdEmuHandlerXchg, ND_EMU_FLAG_IMPLICIT_LOCK },     // XCHG
    /* 0x88 */ { _NdEmuHandlerMov, 0 },      // MOV
    /* 0x89 */ { _NdEmuHandlerMov, 0 },      // MOV
    /* 0x8a */ { _NdEmuHandlerMov, 0 },      // MOV
    /* 0x8b */ { _NdEmuHandlerMov, 0 },      // MOV
    /* 0x8c */ { NULL, 0 },
    /* 0x8d */ { NULL, 0 },
    /* 0x8e */ { NULL, 0 },
    /* 0x8f */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 7 },
    /* 0x90 */ { NULL, 0 },
    /* 0x91 */ { NULL, 0 },
    /* 0x92 */ { NULL, 0 },
    /* 0x93 */ { NULL, 0 },
    /* 0x94 */ { NULL, 0 },
    /* 0x95 */ { NULL, 0 },
    /* 0x96 */ { NULL, 0 },
    /* 0x97 */ { NULL, 0 },
    /* 0x98 */ { NULL, 0 },
    /* 0x99 */ { NULL, 0 },
    /* 0x9a */ { NULL, 0 },
    /* 0x9b */ { NULL, 0 },
    /* 0x9c */ { _NdEmuHandlerPushPop, 0 },
    /* 0x9d */ { _NdEmuHandlerPushPop, 1 },
    /* 0x9e */ { NULL, 0 },
    /* 0x9f */ { NULL, 0 },
    /* 0xa0 */ { _NdEmuHandlerMov, 0 },    // MOV
    /* 0xa1 */ { _NdEmuHandlerMov, 0 },    // MOV
    /* 0xa2 */ { _NdEmuHandlerMov, 0 },    // MOV
    /* 0xa3 */ { _NdEmuHandlerMov, 0 },    // MOV
    /* 0xa4 */ { _NdEmuHandlerMov, 0 },    // MOVS
    /* 0xa5 */ { _NdEmuHandlerMov, 0 },    // MOVS
    /* 0xa6 */ { _NdEmuHandlerCmps, 0 },   // CMPS
    /* 0xa7 */ { _NdEmuHandlerCmps, 0 },   // CMPS
    /* 0xa8 */ { _NdEmuHandlerLogic, 3 },  // TEST
    /* 0xa9 */ { _NdEmuHandlerLogic, 3 },  // TEST
    /* 0xaa */ { _NdEmuHandlerMov, 0 },    // STOSB
    /* 0xab */ { _NdEmuHandlerMov, 0 },    // STOSW/D/Q
    /* 0xac */ { _NdEmuHandlerMov, 0 },    // LODSB
    /* 0xad */ { _NdEmuHandlerMov, 0 },    // LODSW/D/Q
    /* 0xae */ { NULL, 0 },
    /* 0xaf */ { NULL, 0 },
    /* 0xb0 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb1 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb2 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb3 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb4 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb5 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb6 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb7 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb8 */ { _NdEmuHandleMovImm, 0 },
    /* 0xb9 */ { _NdEmuHandleMovImm, 0 },
    /* 0xba */ { _NdEmuHandleMovImm, 0 },
    /* 0xbb */ { _NdEmuHandleMovImm, 0 },
    /* 0xbc */ { _NdEmuHandleMovImm, 0 },
    /* 0xbd */ { _NdEmuHandleMovImm, 0 },
    /* 0xbe */ { _NdEmuHandleMovImm, 0 },
    /* 0xbf */ { _NdEmuHandleMovImm, 0 },
    /* 0xc0 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xc1 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xc2 */ { NULL, 0 },
    /* 0xc3 */ { NULL, 0 },
    /* 0xc4 */ { NULL, 0 },
    /* 0xc5 */ { NULL, 0 },
    /* 0xc6 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 1 },
    /* 0xc7 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 1 },
    /* 0xc8 */ { NULL, 0 },
    /* 0xc9 */ { NULL, 0 },
    /* 0xca */ { NULL, 0 },
    /* 0xcb */ { NULL, 0 },
    /* 0xcc */ { NULL, 0 },
    /* 0xcd */ { NULL, ND_EMU_FLAG_V8086 },
    /* 0xce */ { NULL, 0 },
    /* 0xcf */ { NULL, 0 },
    /* 0xd0 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xd1 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xd2 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xd3 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 6 },
    /* 0xd4 */ { NULL, 0 },
    /* 0xd5 */ { NULL, 0 },
    /* 0xd6 */ { NULL, 0 },
    /* 0xd7 */ { NULL, 0 },
    /* 0xd8 */ { NULL, 0 },
    /* 0xd9 */ { NULL, 0 },
    /* 0xda */ { NULL, 0 },
    /* 0xdb */ { NULL, 0 },
    /* 0xdc */ { NULL, 0 },
    /* 0xdd */ { NULL, 0 },
    /* 0xde */ { NULL, 0 },
    /* 0xdf */ { NULL, 0 },
    /* 0xe0 */ { NULL, 0 },
    /* 0xe1 */ { NULL, 0 },
    /* 0xe2 */ { NULL, 0 },
    /* 0xe3 */ { NULL, 0 },
    /* 0xe4 */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },    // IN
    /* 0xe5 */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },    // IN
    /* 0xe6 */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },    // OUT
    /* 0xe7 */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },    // OUT
    /* 0xe8 */{ NULL, 0 },
    /* 0xe9 */{ NULL, 0 },
    /* 0xea */{ NULL, 0 },
    /* 0xeb */{ NULL, 0 },
    /* 0xec */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },    // IN
    /* 0xed */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 0 },    // IN
    /* 0xee */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },    // OUT
    /* 0xef */{ _NdEmuHandlerInOut, ND_EMU_FLAG_V8086 | 1 },    // OUT
    /* 0xf0 */{ NULL, 0 },
    /* 0xf1 */{ NULL, 0 },
    /* 0xf2 */{ NULL, 0 },
    /* 0xf3 */{ NULL, 0 },
    /* 0xf4 */{ NULL, ND_EMU_FLAG_V8086 },          // HLT
    /* 0xf5 */ { _NdEmuHandlerCarry, 0 },                        // CMC
    /* 0xf6 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 3 },
    /* 0xf7 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 3 },
    /* 0xf8 */ { _NdEmuHandlerCarry, 1 },                        // CLC
    /* 0xf9 */ { _NdEmuHandlerCarry, 2 },                        // STC
    /* 0xfa */ { _NdEmuHandlerCliSti, 0 },                       // STI
    /* 0xfb */ { _NdEmuHandlerCliSti, 1 },                       // CLI
    /* 0xfc */ { _NdEmuHandlerDirection, 0 },                    // CLD
    /* 0xfd */ { _NdEmuHandlerDirection, 1 },                    // STD
    /* 0xfe */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 2 },
    /* 0xff */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 2 },
};


static const EMU_HANDLER gEmu2ByteLUT[] =
{
    /* 0x00 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 9 }, // LLDT, LTR
    /* 0x01 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 8 }, // LGDT, LIDT, SGDT, SIDT
    /* 0x02 */ { NULL, 0 },
    /* 0x03 */ { NULL, 0 },
    /* 0x04 */ { NULL, 0 },
    /* 0x05 */ { NULL, 0 },
    /* 0x06 */ { NULL, 0 },
    /* 0x07 */ { NULL, 0 },
    /* 0x08 */ { _NdEmuHandlerInvd, 0 },
    /* 0x09 */ { _NdEmuHandlerWbInvd, 0 },
    /* 0x0a */ { NULL, 0 },
    /* 0x0b */ { _NdEmuHandlerUd2, 0 },
    /* 0x0c */ { NULL, 0 },
    /* 0x0d */ { NULL, 0 },
    /* 0x0e */ { NULL, 0 },
    /* 0x0f */ { NULL, 0 },
    /* 0x10 */ { _NdEmuHandler0F10Group, 0 },
    /* 0x11 */ { _NdEmuHandler0F11Group, 0 },
    /* 0x12 */ { NULL, 0 },
    /* 0x13 */ { NULL, 0 },
    /* 0x14 */ { NULL, 0 },
    /* 0x15 */ { NULL, 0 },
    /* 0x16 */ { NULL, 0 },
    /* 0x17 */ { NULL, 0 },
    /* 0x18 */ { NULL, 0 },
    /* 0x19 */ { NULL, 0 },
    /* 0x1a */ { NULL, 0 },
    /* 0x1b */ { NULL, 0 },
    /* 0x1c */ { NULL, 0 },
    /* 0x1d */ { NULL, 0 },
    /* 0x1e */ { NULL, 0 },
    /* 0x1f */ { NULL, 0 },
    /* 0x20 */ { _NdEmuHandlerMov, ND_EMU_FLAG_V8086 },
    /* 0x21 */ { _NdEmuHandlerMov, ND_EMU_FLAG_V8086 },
    /* 0x22 */ { _NdEmuHandlerMov, ND_EMU_FLAG_V8086 },
    /* 0x23 */ { _NdEmuHandlerMov, ND_EMU_FLAG_V8086 },
    /* 0x24 */ { NULL, 0 },
    /* 0x25 */ { NULL, 0 },
    /* 0x26 */ { NULL, 0 },
    /* 0x27 */ { NULL, 0 },
    /* 0x28 */ { _NdEmuHandler0F28Group, 0 },
    /* 0x29 */ { _NdEmuHandler0F29Group, 0 },
    /* 0x2a */ { NULL, 0 },
    /* 0x2b */ { _NdEmuHandlerMovSse, 0 },  // MOVNTPS/MOVNTPD
    /* 0x2c */ { NULL, 0 },
    /* 0x2d */ { NULL, 0 },
    /* 0x2e */ { NULL, 0 },
    /* 0x2f */ { NULL, 0 },
    /// /* 0x30 */ { _NdEmuHandlerRdWrMsr, 1 },
    /* 0x30 */ { NULL, 0 },
    /* 0x31 */ { NULL, 0 },
    /// /* 0x32 */ { _NdEmuHandlerRdWrMsr, 0 },
    /* 0x32 */ { NULL, 0 },
    /* 0x33 */ { NULL, 0 },
    /* 0x34 */ { NULL, 0 },
    /* 0x35 */ { NULL, 0 },
    /* 0x36 */ { NULL, 0 },
    /* 0x37 */ { NULL, 0 },
    /* 0x38 */ { NULL, 0 },
    /* 0x39 */ { NULL, 0 },
    /* 0x3a */ { NULL, 0 },
    /* 0x3b */ { NULL, 0 },
    /* 0x3c */ { NULL, 0 },
    /* 0x3d */ { NULL, 0 },
    /* 0x3e */ { NULL, 0 },
    /* 0x3f */ { NULL, 0 },
    /* 0x40 */ { _NdEmuHandlerCmov, 0 },
    /* 0x41 */ { _NdEmuHandlerCmov, 1 },
    /* 0x42 */ { _NdEmuHandlerCmov, 2 },
    /* 0x43 */ { _NdEmuHandlerCmov, 3 },
    /* 0x44 */ { _NdEmuHandlerCmov, 4 },
    /* 0x45 */ { _NdEmuHandlerCmov, 5 },
    /* 0x46 */ { _NdEmuHandlerCmov, 6 },
    /* 0x47 */ { _NdEmuHandlerCmov, 7 },
    /* 0x48 */ { _NdEmuHandlerCmov, 8 },
    /* 0x49 */ { _NdEmuHandlerCmov, 9 },
    /* 0x4a */ { _NdEmuHandlerCmov, 10 },
    /* 0x4b */ { _NdEmuHandlerCmov, 11 },
    /* 0x4c */ { _NdEmuHandlerCmov, 12 },
    /* 0x4d */ { _NdEmuHandlerCmov, 13 },
    /* 0x4e */ { _NdEmuHandlerCmov, 14 },
    /* 0x4f */ { _NdEmuHandlerCmov, 15 },
    /* 0x50 */ { NULL, 0 },
    /* 0x51 */ { NULL, 0 },
    /* 0x52 */ { NULL, 0 },
    /* 0x53 */ { NULL, 0 },
    /* 0x54 */ { NULL, 0 },
    /* 0x55 */ { NULL, 0 },
    /* 0x56 */ { NULL, 0 },
    /* 0x57 */ { NULL, 0 },
    /* 0x58 */ { NULL, 0 },
    /* 0x59 */ { NULL, 0 },
    /* 0x5a */ { NULL, 0 },
    /* 0x5b */ { NULL, 0 },
    /* 0x5c */ { NULL, 0 },
    /* 0x5d */ { NULL, 0 },
    /* 0x5e */ { NULL, 0 },
    /* 0x5f */ { NULL, 0 },
    /* 0x60 */ { NULL, 0 },
    /* 0x61 */ { NULL, 0 },
    /* 0x62 */ { NULL, 0 },
    /* 0x63 */ { NULL, 0 },
    /* 0x64 */ { NULL, 0 },
    /* 0x65 */ { NULL, 0 },
    /* 0x66 */ { NULL, 0 },
    /* 0x67 */ { NULL, 0 },
    /* 0x68 */ { NULL, 0 },
    /* 0x69 */ { NULL, 0 },
    /* 0x6a */ { NULL, 0 },
    /* 0x6b */ { NULL, 0 },
    /* 0x6c */ { NULL, 0 },
    /* 0x6d */ { NULL, 0 },
    /* 0x6e */ { NULL, 0 },
    /* 0x6f */ { _NdEmuHandlerMovSse, 0 }, // MOVQ/MOVDQA/MOVDQU
    /* 0x70 */ { NULL, 0 },
    /* 0x71 */ { NULL, 0 },
    /* 0x72 */ { NULL, 0 },
    /* 0x73 */ { NULL, 0 },
    /* 0x74 */ { NULL, 0 },
    /* 0x75 */ { NULL, 0 },
    /* 0x76 */ { NULL, 0 },
    /* 0x77 */ { NULL, 0 },
    /* 0x78 */ { NULL, 0 },
    /* 0x79 */ { NULL, 0 },
    /* 0x7a */ { NULL, 0 },
    /* 0x7b */ { NULL, 0 },
    /* 0x7c */ { NULL, 0 },
    /* 0x7d */ { NULL, 0 },
    /* 0x7e */ { NULL, 0 },
    /* 0x7f */ { _NdEmuHandlerMovSse, 0 }, // MOVQ/MOVDQA/MOVDQU
    /* 0x80 */ { NULL, 0 },
    /* 0x81 */ { NULL, 0 },
    /* 0x82 */ { NULL, 0 },
    /* 0x83 */ { NULL, 0 },
    /* 0x84 */ { NULL, 0 },
    /* 0x85 */ { NULL, 0 },
    /* 0x86 */ { NULL, 0 },
    /* 0x87 */ { NULL, 0 },
    /* 0x88 */ { NULL, 0 },
    /* 0x89 */ { NULL, 0 },
    /* 0x8a */ { NULL, 0 },
    /* 0x8b */ { NULL, 0 },
    /* 0x8c */ { NULL, 0 },
    /* 0x8d */ { NULL, 0 },
    /* 0x8e */ { NULL, 0 },
    /* 0x8f */ { NULL, 0 },
    /* 0x90 */ { _NdEmuHandlerSet, 0 },
    /* 0x91 */ { _NdEmuHandlerSet, 1 },
    /* 0x92 */ { _NdEmuHandlerSet, 2 },
    /* 0x93 */ { _NdEmuHandlerSet, 3 },
    /* 0x94 */ { _NdEmuHandlerSet, 4 },
    /* 0x95 */ { _NdEmuHandlerSet, 5 },
    /* 0x96 */ { _NdEmuHandlerSet, 6 },
    /* 0x97 */ { _NdEmuHandlerSet, 7 },
    /* 0x98 */ { _NdEmuHandlerSet, 8 },
    /* 0x99 */ { _NdEmuHandlerSet, 9 },
    /* 0x9a */ { _NdEmuHandlerSet, 10 },
    /* 0x9b */ { _NdEmuHandlerSet, 11 },
    /* 0x9c */ { _NdEmuHandlerSet, 12 },
    /* 0x9d */ { _NdEmuHandlerSet, 13 },
    /* 0x9e */ { _NdEmuHandlerSet, 14 },
    /* 0x9f */ { _NdEmuHandlerSet, 15 },
    /* 0xa0 */ { _NdEmuHandlerPushPop, 0 },
    /* 0xa1 */ { _NdEmuHandlerPushPop, 1 },
    /* 0xa2 */ { _NdEmuHandlerCpuid, 0 },
    /* 0xa3 */ { _NdEmuHandlerBt, 3 },
    /* 0xa4 */ { NULL, 0 },
    /* 0xa5 */ { NULL, 0 },
    /* 0xa6 */ { NULL, 0 },
    /* 0xa7 */ { NULL, 0 },
    /* 0xa8 */ { _NdEmuHandlerPushPop, 0 },
    /* 0xa9 */ { _NdEmuHandlerPushPop, 1 },
    /* 0xaa */ { NULL, 0 },
    /* 0xab */ { _NdEmuHandlerBt, 0 },
    /* 0xac */ { NULL, 0 },
    /* 0xad */ { NULL, 0 },
    /* 0xae */ { NULL, 0 },
    /* 0xaf */ { NULL, 0 },
    /* 0xb0 */ { _NdEmuHandlerCmpXchg, 0 },
    /* 0xb1 */ { _NdEmuHandlerCmpXchg, 0 },
    /* 0xb2 */ { NULL, 0 },
    /* 0xb3 */ { _NdEmuHandlerBt, 1 },
    /* 0xb4 */ { NULL, 0 },
    /* 0xb5 */ { NULL, 0 },
    /* 0xb6 */ { _NdEmuHandlerMov, 1 },    // MOVZX
    /* 0xb7 */ { _NdEmuHandlerMov, 1 },    // MOVZX
    /* 0xb8 */ { NULL, 0 },
    /* 0xb9 */ { NULL, 0 },
    /* 0xba */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 5 },
    /* 0xbb */ { _NdEmuHandlerBt, 2 },
    /* 0xbc */ { NULL, 0 },
    /* 0xbd */ { NULL, 0 },
    /* 0xbe */ { _NdEmuHandlerMov, 0 },    // MOVSX
    /* 0xbf */ { _NdEmuHandlerMov, 0 },    // MOVSX
    /* 0xc0 */ { _NdEmuHandlerXadd, 0 },   // XADD
    /* 0xc1 */ { _NdEmuHandlerXadd, 0 },   // XADD
    /* 0xc2 */ { NULL, 0 },
    /* 0xc3 */ { _NdEmuHandlerMov, 0 },    // MOVNTI
    /* 0xc4 */ { NULL, 0 },
    /* 0xc5 */ { NULL, 0 },
    /* 0xc6 */ { NULL, 0 },
    /* 0xc7 */ { NULL, ND_EMU_FLAG_CHECK_REG_FIELD | 4 },
    /* 0xc8 */ { NULL, 0 },
    /* 0xc9 */ { NULL, 0 },
    /* 0xca */ { NULL, 0 },
    /* 0xcb */ { NULL, 0 },
    /* 0xcc */ { NULL, 0 },
    /* 0xcd */ { NULL, 0 },
    /* 0xce */ { NULL, 0 },
    /* 0xcf */ { NULL, 0 },
    /* 0xd0 */ { NULL, 0 },
    /* 0xd1 */ { NULL, 0 },
    /* 0xd2 */ { NULL, 0 },
    /* 0xd3 */ { NULL, 0 },
    /* 0xd4 */ { NULL, 0 },
    /* 0xd5 */ { NULL, 0 },
    /* 0xd6 */ { NULL, 0 },
    /* 0xd7 */ { NULL, 0 },
    /* 0xd8 */ { NULL, 0 },
    /* 0xd9 */ { NULL, 0 },
    /* 0xda */ { NULL, 0 },
    /* 0xdb */ { NULL, 0 },
    /* 0xdc */ { NULL, 0 },
    /* 0xdd */ { NULL, 0 },
    /* 0xde */ { NULL, 0 },
    /* 0xdf */ { NULL, 0 },
    /* 0xe0 */ { NULL, 0 },
    /* 0xe1 */ { NULL, 0 },
    /* 0xe2 */ { NULL, 0 },
    /* 0xe3 */ { NULL, 0 },
    /* 0xe4 */ { NULL, 0 },
    /* 0xe5 */ { NULL, 0 },
    /* 0xe6 */ { NULL, 0 },
    /* 0xe7 */ { _NdEmuHandlerMovSse, 0 }, // MOVNTQ - mmx
    /* 0xe7 */ { NULL, 0 },
    /* 0xe8 */ { NULL, 0 },
    /* 0xe9 */ { NULL, 0 },
    /* 0xea */ { NULL, 0 },
    /* 0xeb */ { NULL, 0 },
    /* 0xec */ { NULL, 0 },
    /* 0xed */ { NULL, 0 },
    /* 0xee */ { NULL, 0 },
    /* 0xef */ { NULL, 0 },
    /* 0xf0 */ { NULL, 0 },
    /* 0xf1 */ { NULL, 0 },
    /* 0xf2 */ { NULL, 0 },
    /* 0xf3 */ { NULL, 0 },
    /* 0xf4 */ { NULL, 0 },
    /* 0xf5 */ { NULL, 0 },
    /* 0xf6 */ { NULL, 0 },
    /* 0xf7 */ { NULL, 0 },
    /* 0xf8 */ { NULL, 0 },
    /* 0xf9 */ { NULL, 0 },
    /* 0xfa */ { NULL, 0 },
    /* 0xfb */ { NULL, 0 },
    /* 0xfc */ { NULL, 0 },
    /* 0xfd */ { NULL, 0 },
    /* 0xfe */ { NULL, 0 },
    /* 0xff */ { NULL, 0 },
};


static __forceinline BOOLEAN
NdIsAddressCanonical(
    _In_ CX_UINT64 Address
    )
{
    CX_UINT8 s;

    s = (Address >> 47) & 1;

    if (s)
    {
        return (Address & 0xFFFF000000000000) == 0xFFFF000000000000;
    }
    else
    {
        return (Address & 0xFFFF000000000000) == 0x0000000000000000;
    }
}


///
/// @brief Retrieves the vcpu execution ring level.
///
/// @param Vcpu     Vcpu on which operation will be performed
///
/// @return         CPU Ring number based on SS descriptor
static __forceinline CX_UINT8
NdVcpuRing(
    _In_ VCPU* Vcpu
    )
{
    CX_UINT64 ssAr = 0;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    // Force ring3 when VM is enabled.
    if (0 != (Vcpu->ArchRegs.RFLAGS & RFLAGS_VM))
    {
        return 3;
    }

    iface->VmxRead(Vcpu, VMCS_GUEST_SS_ACCESS_RIGHTS, &ssAr);

    // Check the DPL field of the SS.
    return (ssAr >> 5) & 0x3;
}



///
/// @brief Retrieves the vcpu operating mode.
///
/// @param Vcpu                     Vcpu on which operation will be performed
///
/// @return ND_MODE_REAL            Vcpu is operating in REAL mode
/// @return ND_MODE_V8086           Vcpu is operating in VIRTUAL 8086 mode
/// @return ND_MODE_LONG            Vcpu is operating in LONG mode
/// @return ND_MODE_COMPAT          Vcpu is operating in COMPAT mode
/// @return ND_MODE_PROTECTED       Vcpu is operating in PROTECTED mode
/// @return ND_MODE_UNKNOWN         Vcpu is operating in an unknown mode
static __forceinline CX_UINT8
NdVcpuMode(
    _In_ VCPU* Vcpu
    )
{
    if (0 == (Vcpu->ArchRegs.CR0 & CR0_PE) && 0 == (Vcpu->ArchRegs.RFLAGS & RFLAGS_VM))
    {
        // PE flag in CR0 is 0, VM flag in FLAGS is 0 -> real mode.
        return ND_MODE_REAL;
    }
    else if (0 == (Vcpu->ArchRegs.CR0 & CR0_PE) && 0 != (Vcpu->ArchRegs.RFLAGS & RFLAGS_VM))
    {
        // PE flag in CR0 is 0, VM flag in FLAGS is 1 -> V8086 mode.
        return ND_MODE_V8086;
    }
    else if (0 != (Vcpu->ArchRegs.CR0 & CR0_PE))
    {
        if (0 != (Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
        {
            CX_UINT64 csAr = 0;
            EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

            iface->VmxRead(Vcpu, VMCS_GUEST_CS_ACCESS_RIGHTS, &csAr);

            if ((csAr >> 13) & 1)
            {
                return ND_MODE_LONG;
            }
            else
            {
                return ND_MODE_COMPAT;
            }
        }
        else
        {
            // 32 bit protected mode.
            return ND_MODE_PROTECTED;
        }
    }

    return ND_MODE_UNKNOWN;
}

///
/// @brief Validates an operand for a given instruction
///
/// @param Vcpu                     Vcpu on which operation will be performed
/// @param Instrux                  Decoded instruction
/// @param Gla                      Operand to check
/// @param Alignment                Indicates if the operand is source or destination
///
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
/// @return CX_STATUS_SUCCESS               Success
static NTSTATUS
_NdValidateOperand(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ PEMU_OPERAND Operand,
    _In_ BOOLEAN Destination
    )
{
    CX_UINT64 blow, bhigh, seglow, seghigh;
    CX_UINT8 mode;

    mode = NdVcpuMode(Vcpu);

    // #UD If the LOCK prefix is used but the destination is not a memory operand.
    if ((Operand->Type != ND_EMU_OP_MEM) && (Destination) && (Instrux->HasLock))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Not memory - no more checks needed.
    if (ND_EMU_OP_MEM != Operand->Type)
    {
        return CX_STATUS_SUCCESS;
    }

    // First & last CX_UINT8 from the accessed data.
    blow = Operand->Address;
    bhigh = Operand->Address + Operand->Size - 1;

    seglow = Operand->Seg.Base;
    seghigh = Operand->Seg.Base + Operand->Seg.Limit;

    // Check for segment wrap-around.
    if (seglow > seghigh)
    {
        // #GP should be right.
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

#define OP_INSIDE_SEG   (((blow >= seglow) && (blow <= seghigh) && (bhigh >= seglow) && (bhigh <= seghigh)))
#define OP_OUTSIDE_SEG  (!OP_INSIDE_SEG)

    // We get here if and only if the operand is mem.
    if (ND_MODE_LONG == mode)
    {
        // #SS(0) If a memory address referencing the SS segment is in a non-canonical form
        if ((Operand->Seg.Segment == NDR_SS) &&
            ((!NdIsAddressCanonical(blow)) || (!NdIsAddressCanonical(bhigh))))
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_STACK_FAULT, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #GP(0) If the memory address is in a non-canonical form.
        if ((Operand->Seg.Segment != NDR_SS) &&
            ((!NdIsAddressCanonical(blow)) || (!NdIsAddressCanonical(bhigh))))
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #GP If a memory operand effective address is outside the FS or GS segment limit.
        if (((Operand->Seg.Segment == NDR_FS) || (Operand->Seg.Segment == NDR_GS)) &&
            OP_OUTSIDE_SEG)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #PF(fault-code) If a page fault occurs.
        /// This is checked during the PageWalk phase.
    }
    else if ((mode == ND_MODE_PROTECTED) || (mode == ND_MODE_COMPAT))
    {
        // Special checks for expand-down segments.
        if (0x4 == (Operand->Seg.AccessRights.Type & 0xC))
        {
            CX_UINT64 offset, bhighnorm = bhigh;

            offset = Operand->Gva;

            // Check if 16 bits segment.
            if (0 == Operand->Seg.AccessRights.DB)
            {
                bhighnorm = bhigh & 0xFFFF;
            }

            if ((offset <= Operand->Seg.Limit) || (bhighnorm < offset))
            {
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
                return STATUS_EMU_EXCEPTION_INJECTED;
            }
        }
        else
        {
            // #GP If a memory operand effective address is outside the CS, DS, ES, FS, or GS segment limit.
            if ((Operand->Seg.Segment != NDR_SS) && OP_OUTSIDE_SEG)
            {
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
                return STATUS_EMU_EXCEPTION_INJECTED;
            }

            // #SS If a memory operand effective address is outside the SS segment limit.
            if ((Operand->Seg.Segment == NDR_SS) && OP_OUTSIDE_SEG)
            {
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_STACK_FAULT, 0, 0);
                return STATUS_EMU_EXCEPTION_INJECTED;
            }
        }

        // #GP(0) If the destination operand points to a non-writable segment.
        if ((Destination) && (0x0 == ((Operand->Seg.AccessRights.Type & 0xA)))) // Data, non-writable segment
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #GP(0) If the write operand points to a code segment.
        if ((Destination) && (0x8 == ((Operand->Seg.AccessRights.Type & 0x8)))) // Code segment
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #GP(0) If the read operand points to a non-readable code segment.
        if ((0x8 == ((Operand->Seg.AccessRights.Type & 0xA)))) // Code, non-readable segment.
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #GP(0) If the DS, ES, FS, or GS register contains a NULL segment selector.
        if ((Operand->Seg.Segment != NDR_CS) && (Operand->Seg.Segment != NDR_SS) &&
            (Operand->Seg.Selector == 0))
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #PF(fault-code) If a page fault occurs.
        /// This is checked during the PageWalk phase.
    }
    else
    {
        // #GP If a memory operand effective address is outside the CS, DS, ES, FS, or GS segment limit.
        if ((Operand->Seg.Segment != NDR_SS) && OP_OUTSIDE_SEG)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }

        // #SS If a memory operand effective address is outside the SS segment limit.
        if ((Operand->Seg.Segment == NDR_SS) && OP_OUTSIDE_SEG)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_STACK_FAULT, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }
    }

    // #AC(0) If alignment checking is enabled and an unaligned memory reference is made while the
    // current privilege level is 3 or the CPU mode is V8086.
    if ((0 != (Vcpu->ArchRegs.RFLAGS & RFLAGS_AC) && (0 != (Vcpu->ArchRegs.CR0 & CR0_AM)) &&
        (mode != ND_MODE_REAL) && (3 == NdVcpuRing(Vcpu))))
    {
        /// TODO
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief Check alignment constraints for sse operations
///
/// @param Vcpu                     Vcpu on which operation will be performed
/// @param Instrux                  Decoded instruction
/// @param Gla                      Guest linear address that will be checked
/// @param Alignment                Alignment to check
///
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
/// @return CX_STATUS_SUCCESS               Success
static NTSTATUS
_NdCheckSseMemoryAlignment(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT64 Gla,
    _In_ CX_UINT32 Alignment
    )
{
    UNREFERENCED_PARAMETER(Instrux);

    if (Gla % Alignment)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief Retrieve base address of a segment
///
/// Will return via the SegmentBase argument to segment base of the given segment. It will handle
/// every possible operating mode of the given Vcpu.
///
/// @param Vcpu                      Vcpu on which operation will be performed
/// @param Instrux                   Decoded instruction.
/// @param Segment                   Segment ID (as encoded in the instruction).
/// @param SegmentSelector           Segment selector.
/// @param SegmentBase               Will contain upon exit the segment base address.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED If an unsupported operating mode is encoded in Instrux.
/// @return CX_STATUS_SUCCESS On success.
///
static NTSTATUS
_NdGetSegmentBase(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT8 Segment,
    _In_ CX_UINT64 SegmentSelector,
    _Out_ CX_UINT64 *SegmentBase
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(SegmentSelector);

    if ((Instrux->DefCode == ND_CODE_32) || (Instrux->DefCode == ND_CODE_16))
    {
        //
        // 32 bit operating mode, we must get the segment base from either GDT, either LDT, but we can use
        // directly the value stored in the VMCS
        //
        iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_BASE + 2ULL * Segment, SegmentBase);
    }
    else if (Instrux->DefCode == ND_CODE_64)
    {
        //
        // 64 bit operating mode, segmentation ignored/hardware disabled, except for FS & GS
        //
        if ((Segment == NDR_FS) || (Segment == NDR_GS))
        {
            iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_BASE + 2ULL * Segment, SegmentBase);
        }
        else
        {
            // Except for FS & GS, the other segment registers are always forced to a 0x0:0xFFFFFFFF
            *SegmentBase = 0;
        }
    }
    else
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}



///
/// @brief Retrieve segment information from instrunction
///
/// The Seg argument must be partially filled - the Seg.Segment value must be set.
///
/// @param Vcpu,                    Vcpu on which operation wil be performed.
/// @param Instrux                  Decoded instruction.
/// @param SegInfo                  Segment identifier
/// @param Segment                  Will contain the segment information on return
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If an unsupported operating mode is encoded in Instrux.
/// @return CX_STATUS_INVALID_PARAMETER_3       If Segment identifier is invalid (> NDR_GS)
/// @return CX_STATUS_SUCCESS                   On success.
///
static NTSTATUS
_NdGetSegmentInformation(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT8 Segment,
    _Inout_ PEMU_SEG_REG SegInfo
    )
{
    NTSTATUS status;
    CX_UINT64 sel, base, limit, ar;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    // pre-init
    status = CX_STATUS_SUCCESS;
    sel = base = limit = ar = 0;

    if (Segment > NDR_GS)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    if ((Instrux->DefCode == ND_CODE_32) || (Instrux->DefCode == ND_CODE_16))
    {
        //
        // 32 bit operating mode, we must get the segment base from either GDT, either LDT, but we can use
        // directly the value stored in the VMCS
        //
        iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES + 2ULL * Segment, &sel);
        iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_BASE + 2ULL * Segment, &base);
        iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_LIMIT + 2ULL * Segment, &limit);
        iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_ACCESS_RIGHTS + 2ULL * Segment, &ar);
    }
    else if (Instrux->DefCode == ND_CODE_64)
    {
        //
        // 64 bit operating mode, segmentation ignored/hardware disabled, except for FS & GS
        //
        if ((Segment == NDR_FS) || (Segment == NDR_GS))
        {
            iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES + 2ULL * Segment, &sel);
            iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_BASE + 2ULL * Segment, &base);
            iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_LIMIT + 2ULL * Segment, &limit);
            iface->VmxRead(Vcpu, (CX_UINT64)VMCS_GUEST_ES_ACCESS_RIGHTS + 2ULL * Segment, &ar);
        }
        else
        {
            // Except for FS & GS, the other segment registers are always forced to a 0x0:0xFFFFFFFF
            sel = 0;
            base = 0;
            limit = 0xFFFFFFFFFFFFFFFF;
            ar = 0;
        }
    }
    else
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    // Fill in the actual info in the output parameter.
    if (NT_SUCCESS(status))
    {
        SegInfo->Segment = Segment;
        SegInfo->Selector = (CX_UINT16)sel;
        SegInfo->Base = base;
        SegInfo->Limit = limit;
        SegInfo->AccessRights.Raw = ar;
    }

    return status;
}


///
/// @brief Computes resulting flags of an operation
///
/// Given the source operands, the operand size and the result, it will compute the flags values.
/// Upon exit, each out argument will contain 0 if the underlying result would end up reseting
/// that flag, or 1, if the underlying result would set the flag.
///
/// @param Result                    The result of the operation
/// @param Size                      Operands size.
/// @param Operand1                  First operand.
/// @param Operand2                  Second operand.
/// @param Operand3                  Third operand.
/// @param Operand4                  Forth operand.
/// @param Carry                     Carry out.
/// @param Parity                    Parity out.
/// @param Sign                      Sign out.
/// @param Zero                      Zero out.
/// @param Sub                       TRUE if the operation was subtraction, FALSE otherwise.
static __inline CX_VOID
_NdComputeFlags(
    _In_ CX_UINT64 Result,
    _In_ CX_UINT64 Size,
    _In_ CX_UINT64 Operand1,
    _In_ CX_UINT64 Operand2,
    _In_ CX_UINT64 Operand3,
    _In_ CX_UINT64 Operand4,
    _Out_ CX_UINT8 *Carry,
    _Out_ CX_UINT8 *Parity,
    _Out_ CX_UINT8 *Sign,
    _Out_ CX_UINT8 *Zero,
    _In_ BOOLEAN Sub
    )
{
    CX_UINT8 i, p, s, c, z;
    CX_UINT64 op;

    UNREFERENCED_PARAMETER(Operand3);
    UNREFERENCED_PARAMETER(Operand4);

    p = s = c = z = 0;

    op = Result;

    //
    // Parity flag - Set if the least-significant CX_UINT8 of the result
    // contains an even number of 1 bits; cleared otherwise.
    //
    for (i = 0; i < 8; i++)
    {
        if (op & 1)
        {
            // parity
            p++;
        }

        op >>= 1;
    }

    if (Size == 1)
    {
        s = (Result & 0x80) >> 7;
        c = (Result & 0xFFFFFFFFFFFFFF00) != 0;
        z = (Result & 0xFF) == 0;
    }
    else if (Size == 2)
    {
        s = (Result & 0x8000) >> 15;
        c = (Result & 0xFFFFFFFFFFFF0000) != 0;
        z = (Result & 0xFFFF) == 0;
    }
    else if (Size == 4)
    {
        s = (Result & 0x80000000) >> 31;
        c = (Result & 0xFFFFFFFF00000000) != 0;
        z = (Result & 0xFFFFFFFF) == 0;
    }
    else
    {
        s = (Result & 0x8000000000000000) >> 63;
        z = Result == 0;

        if (Sub)
        {
            c = (Operand1 < Operand2);
        }
        else
        {
            c = (Operand1 + Operand2) < Operand1;
        }
    }

    p = (p % 2 == 0);

    *Carry = c;
    *Parity = p;
    *Sign = s;
    *Zero = z;
}


///
/// @brief Computes memory address of a given operand index
///
/// This function will parse the description of the given instruction, in order to retrieve the operand memory address
///
/// @param Vcpu,                    Vcpu for wchich emulation is performed
/// @param Instrux                  Decoded instruction.
/// @param OpIndex                  Zero based operand index (0 - first operand, ...)
/// @param Address                  This will be the address referenced by the operand
/// @param Offset                   This will be the address inside the segment
///
/// @return STATUS_INVALID_INSTRUX              Invalid instruction provided.
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If an unsupported operand encoding is found.
/// @return CX_STATUS_INVALID_PARAMETER_2       If operand type is invalid
/// @return CX_STATUS_INVALID_PARAMETER_3       If OpIndex is not valid.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other errors.
///
static __forceinline NTSTATUS
_NdComputeAddressForMemoryOperand(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT32 OperandIndex,
    _Inout_ CX_UINT64 *Address,
    _Inout_ CX_UINT64 *Offset
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    CX_UINT64 address = 0;
    CX_UINT64 offset = 0;
    CX_UINT64 segmentBase = 0;
    ND_OPERAND* op = NULL;

    if (OperandIndex >= Instrux->OperandsCount)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    op = &Instrux->Operands[OperandIndex];

    if (ND_OP_MEM != op->Type)
    {
        ERROR("The operand with index: %d has type: %d, expected ND_OPM_MEM\n", OperandIndex, op->Type);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    status = _NdGetSegmentBase(Vcpu, Instrux, op->Info.Memory.Seg, 0, &segmentBase);
    if (!NT_SUCCESS(status))
    {
        LOG("_NdGetSegmentBase failed: 0x%x\n", status);
        return status;
    }

    if (op->Info.Memory.IsDirect)
    {
        // address = segment base + displacement
        offset = op->Info.Memory.Disp;

        goto _exit;
    }

    if (op->Info.Memory.HasBase)
    {
        // address = segment base + base register value
        CX_UINT64 base = REG_GPRV(&Vcpu->ArchRegs, op->Info.Memory.Base);

        base &= ND_SIZE_TO_MASK(op->Info.Memory.BaseSize);

        offset = base;
    }

    if (op->Info.Memory.HasIndex)
    {
        CX_UINT64 index = REG_GPRV(&Vcpu->ArchRegs, op->Info.Memory.Index);

        index &= ND_SIZE_TO_MASK(op->Info.Memory.IndexSize);

        offset += index * op->Info.Memory.Scale;
    }

    if (op->Info.Memory.HasDisp)
    {
        offset += op->Info.Memory.Disp;
    }

    if (op->Info.Memory.IsRipRel)
    {
        // address = segment base + next rip + displacement
        offset += Vcpu->ArchRegs.RIP + Instrux->Length;
    }

    if (op->Info.Memory.IsBitbase)
    {
        CX_UINT64 bitbase, op1size, op2size;

        // Sanity check. In order to have bitbase addressing, the source operand must be a GP register.
        if ((Instrux->Operands[1].Type != ND_OP_REG) || (Instrux->Operands[1].Info.Register.Type != ND_REG_GPR))
        {
            return CX_STATUS_INVALID_PARAMETER_2;
        }

        op1size = Instrux->Operands[0].Size;
        op2size = Instrux->Operands[1].Size;

        bitbase = ND_SIGN_EX(op2size, REG_GPRV(&Vcpu->ArchRegs, Instrux->Operands[1].Info.Register.Reg));

        if (ND_GET_SIGN(8, bitbase))
        {
            offset -= ((~bitbase >> 3) & ~(op1size - 1)) + op1size;
        }
        else
        {
            offset += (bitbase >> 3) & ~(op1size - 1);
        }
    }

_exit:
    offset = ND_TRIM(Instrux->AddrMode == ND_ADDR_16 ? 2 : Instrux->AddrMode == ND_ADDR_32 ? 4 : 8, offset);

    address = segmentBase + offset;

    *Address = address;
    *Offset = offset;

    return status;
}


///
/// @brief Retrieves instruction operand
///
/// This function will parse the description of the given instruction, in order to retrieve the operand type, operand size
/// and operand value. Each instruction is described using Intel rules, having the first upper case letter to
/// describe the addressing mode & operand type, and the next lower case letter to describe operand size.
///
/// @param Vcpu,                    Vcpu for wchich emulation is performed
/// @param Instrux,                 Decoded instruction.
/// @param OpIndex,                 Zero based operand index (0 - first operand, ...)
/// @param Operand                  Decoded operand info
///
/// @return STATUS_INVALID_INSTRUX              Invalid instruction provided
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If an unsupported operand encoding is found.
/// @return CX_STATUS_INVALID_PARAMETER_3       If OpIndex is not valid
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other errors.
///
static __forceinline NTSTATUS
_NdEmuGetOperandEx(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT32 OpIndex,
    _Inout_ PEMU_OPERAND Operand
    )
{
    NTSTATUS status;
    ND_OPERAND* pOp;
    CX_UINT64 seg;
    CX_UINT8 segType;

    if (OpIndex >= Instrux->OperandsCount)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    memzero(Operand, sizeof(EMU_OPERAND));

    seg = 0;
    status = CX_STATUS_SUCCESS;
    segType = 0;
    pOp = NULL;

    pOp = &Instrux->Operands[OpIndex];

    /// REG_* enums...
    if (pOp->Info.Memory.HasSeg)
    {
        status = _NdGetSegmentInformation(Vcpu, Instrux, pOp->Info.Memory.Seg, &Operand->Seg);
        if (!NT_SUCCESS(status))
        {
            ERROR("_NdGetSegmentInformation failed: 0x%x\n", status);
            return status;
        }
    }

    // prefetch the operand in the caches.
    //_mm_prefetch(op, 0);

    switch (pOp->Type)
    {
    case ND_OP_NOT_PRESENT:                     // Indicates the absence of any operand.
        LOG("Operand Not Present!\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;

    case ND_OP_REG:                             // The operand is a register.
        Operand->Address = pOp->Info.Register.Reg;

        // what type of register?
        if (ND_REG_GPR == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_GPR;
        }
        else if (ND_REG_SEG == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_SEG;
        }
        else if (ND_REG_FPU == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_FPU;
        }
        else if (ND_REG_MMX == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_MMX;
        }
        else if (ND_REG_SSE == pOp->Info.Register.Type)
        {
            /// Use op->Info.Register.Size to obtain the size of a register. The size of the operand can be
            /// different from the size of the register (for example, 32 bits can be used from a 128 bits XMM reg,
            /// so op->Size will be 4 but op->Info.Register.Size will be 16).
            if (ND_SIZE_128BIT == pOp->Info.Register.Size)
            {
                Operand->Type = ND_EMU_OP_REG_XMM;
            }
            else if (ND_SIZE_256BIT == pOp->Info.Register.Size)
            {
                Operand->Type = ND_EMU_OP_REG_YMM;
            }
            else if (ND_SIZE_512BIT == pOp->Info.Register.Size)
            {
                Operand->Type = ND_EMU_OP_REG_ZMM;
            }
            else
            {
                ERROR("Unknown size for SSE register: 0x%x\n", pOp->Size);
                return CX_STATUS_OPERATION_NOT_SUPPORTED;
            }
        }
        else if (ND_REG_CR == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_CR;
        }
        else if (ND_REG_DR == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_DR;
        }
        else if (ND_REG_TR == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_TR\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_BND == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_BND;
        }
        else if (ND_REG_MSK == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_REG_K;
        }
        else if (ND_REG_MSR == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_MSR\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;

        }
        else if (ND_REG_XCR == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_XCR\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_SYS == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_SYS\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_X87 == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_X87\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_MXCSR == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_MXCSR\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_PKRU == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_PKRU\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else if (ND_REG_FLG == pOp->Info.Register.Type)
        {
            Operand->Type = ND_EMU_OP_FLG;
            Operand->Address = Vcpu->ArchRegs.RFLAGS;
        }
        else if (ND_REG_RIP == pOp->Info.Register.Type)
        {
            ERROR("Don't know how to handle register type ND_REG_RIP\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        else
        {
            ERROR("Unknown register type: 0x%x\n", pOp->Info.Register.Type);
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        break;

    case ND_OP_MEM:                             // The operand is located in memory.
        Operand->Type = ND_EMU_OP_MEM;
        status = _NdComputeAddressForMemoryOperand(Vcpu, Instrux, OpIndex, &Operand->Address, &Operand->Gva);
        if (!NT_SUCCESS(status))
        {
            ERROR("_NdGetMemoryOperandGva failed: 0x%x\n", status);
        }
        break;

    case ND_OP_IMM:                             // The operand is an immediate.
        // only Size bytes are valid, the rest are undefined
        Operand->Address = pOp->Info.Immediate.Imm;
        Operand->Type = ND_EMU_OP_IMM;

        break;

    case ND_OP_OFFS:                            // The operand is a relative offset.
        Operand->Address = pOp->Info.RelativeOffset.Rel;
        Operand->Type = ND_EMU_OP_REL_OFFS;
        break;

    case ND_OP_ADDR:                            // The operand is an absolute address, in the form seg:offset.
        LOG("Don't know how to handle ND_OP_ADDR\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;

    case ND_OP_CONST:                           // The operand is an implicit constant.
        Operand->Address = pOp->Info.Constant.Const;
        Operand->Type = ND_EMU_OP_IMM;
        break;

    case ND_OP_BANK:                            // An entire bank/set of registers are being accessed. Used in
                                                // PUSHA/POPA/XSAVE/LOADALL/etc.
        ERROR("Operand type ND_OP_BANK, don't know what to do with it\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;

    default:
        ERROR("Unknown operand type: %d\n", pOp->Type);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;

    }

    Operand->Size = Instrux->Operands[OpIndex].Size;

    if (!NT_SUCCESS(status))
    {
        CHAR cnd[ND_MIN_BUF_SIZE] = {0};
        NTSTATUS status2 = CX_STATUS_SUCCESS;

        status2 = NdToText(Instrux, 0, ND_MIN_BUF_SIZE, cnd);
        if (!NT_SUCCESS(status2))
        {
            LOG("Failed to parse operand %d from instruction %s\n", OpIndex, Instrux->Mnemonic);
            LOG("NdToText failed: 0x%x\n", status);
        }
        else
        {
            LOG("Failed to parse operand %d from instruction %s\n", OpIndex, cnd);
        }

    }

    return status;
}


///
/// @brief Evaluate condition as part of emulation
///
/// This function will evaluate the condition represented by ConditionCode, in order to see if it is
/// true. For this, several flags inside RFLAGS will be tested.
///
/// @param Vcpu                    Vcpu for which condition will be checked
/// @param Instrux                 Decoded instruction.
/// @param ConditionCode           Condition code, as indicated in Intel manuals.
///
/// @return FALSE          If the condition is FALSE.
/// @return TRUE           If the condition is TRUE.
///
static __forceinline BOOLEAN
_NdEmuEvalCondition(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT8 ConditionCode
    )
{
    UNREFERENCED_PARAMETER(Instrux);

    if (NULL == Vcpu)
    {
        return FALSE;
    }

    // check the condition code; the condition code will be set in the Aux
    switch (ConditionCode)
    {
    case 0:
        // O
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF) == 1)
        {
            return TRUE;
        }
        break;
    case 1:
        // NO
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF) == 0)
        {
            return TRUE;
        }
        break;
    case 2:
        // C/B/NAE
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_CF) == 1)
        {
            return TRUE;
        }
        break;
    case 3:
        // NC/NB/AE
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_CF) == 0)
        {
            return TRUE;
        }
        break;
    case 4:
        // E/Z
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF) == 1)
        {
            return TRUE;
        }
        break;
    case 5:
        // NE/NZ
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF) == 0)
        {
            return TRUE;
        }
        break;
    case 6:
        // BE/NA
        if ((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_CF) | (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF))) == 1)
        {
            return TRUE;
        }
        break;
    case 7:
        // A/NBE
        if ((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_CF) | (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF))) == 0)
        {
            return TRUE;
        }
        break;
    case 8:
        // S
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) == 1)
        {
            return TRUE;
        }
        break;
    case 9:
        // NS
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) == 0)
        {
            return TRUE;
        }
        break;
    case 0xA:
        // P
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_PF) == 1)
        {
            return TRUE;
        }
        break;
    case 0xB:
        // NP
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_PF) == 0)
        {
            return TRUE;
        }
        break;
    case 0xC:
        // L/NGE
        if ((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) ^ ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF)) == 1)
        {
            return TRUE;
        }
        break;
    case 0xD:
        // NL/GE
        if ((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) ^ ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF)) == 0)
        {
            return TRUE;
        }
        break;
    case 0xE:
        // LE/NG
        if (((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) ^ ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF)) |
            (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF))) == 1)
        {
            return TRUE;
        }
        break;
    case 0xF:
        // NLE/G
        if (((ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_SF) ^ ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_OF)) |
            (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF))) == 0)
        {
            return TRUE;
        }
        break;
    }

    return FALSE;
}


///
/// @brief Perform access to a liniar address as part of emulation
///
/// This function will handle memory access to the given address (either read or write). If the Gpa is not NULL, it will assume
/// that the instruction needs to be emulated due to an EPT violation. If this is the case, the memory type of
/// the given address is checked; if it is device memory, then device specific callbacks will be called, which
/// will handle the access. Otherwise, it will map the given page inside host VA space, and it will load the
/// data from there, or store it there, depending on Store value.
///
/// Vcpu,                        Vcpu.
/// Instrux,                     Decoded instruction.
/// Context,                     Device context, if any.
/// Gpa,                         GPA where the violation was generated (for EPT violations only).
/// Gla,                         GLA of the address to be read/written.
/// Data,                        Data to be read/written.
/// Size,                        Size of access.
/// Store,                       TRUE if the operation is store to memory, FALSE if it is a load from memory.
///                              Store to memory means that we will store data inside the guests's memory.
/// UpdateADBits,                If TRUE, the Accessed/Dirty bits will be updated inside the paging structures.
/// ImplicitSupervisoryAccess    If TRUE, this is an implicit supervisory access (such as a segment
///                              descriptor load or an IDT entry lookup).
///
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return CX_STATUS_INVALID_PARAMETER_7   If AccessSize is 0 or greater the 4096 bytes
/// @return STATUS_XXX                      On errors.
///
static NTSTATUS
_NdEmuAccessLinearAddress(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Gla,
    _Out_ CX_VOID* Data,
    _In_ CX_UINT64 Size,
    _In_ BOOLEAN Store,
    _In_ BOOLEAN UpdateADBits,
    _In_ BOOLEAN ImplicitSupervisoryAccess
    )
{
    NTSTATUS status;
    CX_UINT8* page;
    CX_UINT8* res;
    CX_UINT32 memType, pfec, flags;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Instrux);

    // preinit
    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    page = NULL;
    memType = 0;

    if ((Size == 0) || (Size > CX_PAGE_SIZE_4K))
    {
        return CX_STATUS_INVALID_PARAMETER_7;
    }


    // Get mem-type, if GPA provided
    if (Gpa)
    {
        status = iface->GetMemType(Vcpu, Gpa & PAGE_MASK, 1, &memType);
        if (!SUCCESS(status))
        {
            ERROR("iface->GetMemType failed: 0x%08x\n", status);
            return status;
        }
    }

    //
    // case 1 - we access normal memory (non-device memory)
    //
    if (0 == (memType & (EMU_MEMTYPE_DEVICE)))
    {
        CX_UINT64 left, currentGla, currentSize, offset;
        CX_UINT32 pfCode = 0, i, gpasCount;
        // Max 2 different pages for now. We don't support accesses larger than 4K.
#define MAX_SPLIT_PAGES 2
        struct
        {
            CX_UINT64 Gpa;
            CX_UINT8* Map;
        } pages[MAX_SPLIT_PAGES] = {0};

        flags = 0;

        // Now update the Accessed/Dirty bit for this page.
        if (UpdateADBits)
        {
            flags |= ND_PW_SET_A | (Store ? ND_PW_SET_D : 0);
        }

        // And implicit SM access, if any.
        if (ImplicitSupervisoryAccess)
        {
            flags |= ND_PW_IMPLICIT_SUPER_ACCESS;
        }

        // Update required flags for the accessed page(s).
        pfec = ND_PF_P | (Store ? ND_PF_RW : 0) | (NdVcpuRing(Vcpu) == 3 ? ND_PF_US : 0);

        // Init left size to process & current processing gla.
        left = Size;
        currentGla = Gla;
        gpasCount = 0;

        // First we have to do the page walk for each accessed GLA. If one of the paged can't be accessed, we can't
        // do any access (no partial access), and we must inject a page-fault. Once all the accessed GLAs have been
        // successfully translated, we can actually map the GPA pages & access data.
        while (left > 0)
        {
            CX_UINT64 currentGpa = 0;

            currentSize = MIN(left, PAGE_SIZE - (currentGla & 0xFFF));

            // Emulate the page walk. We need this in order to validate permissions & to obtain the GPA.
            status = _NdEmuHandlerPageWalk(Vcpu, currentGla, currentSize, flags, pfec, &pfCode, &currentGpa);
            if (STATUS_EMU_PAGE_FAULT == status)
            {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_PAGE_FAULT, pfCode, currentGla);

                status = STATUS_EMU_EXCEPTION_INJECTED;
#else
                status = CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
                goto no_access;
            }
            else if (!NT_SUCCESS(status))
            {
                ERROR("_NdEmuHandlerPageWalk failed: 0x%08x, GVA = %018p, Access required: %x\n",
                      status, Gla, pfec);
                goto no_access;
            }

            if (gpasCount >= MAX_SPLIT_PAGES)
            {
                ERROR("Accesses splitting across more than %d paged: gla %018p, size %d\n",
                      MAX_SPLIT_PAGES, Gla, Size);
                status = CX_STATUS_OPERATION_NOT_SUPPORTED;
                goto no_access;
            }

            status = iface->MapPhysicalMemory(Vcpu, currentGpa & PAGE_MASK, 1, &page);
            if (!NT_SUCCESS(status))
            {
                ERROR("MapPhysicalMemory failed for %018p: 0x%08x\n", currentGpa, status);
                goto no_access;
            }

            pages[gpasCount].Gpa = currentGpa;
            pages[gpasCount].Map = page + (currentGpa & 0xFFF);

            // Update the number of accessed pages.
            gpasCount++;

            left -= currentSize;

            currentGla += currentSize;
        }


        // We walked all the accessed GLAs and we mapped all the obtained GPAs. We can now access the memory.
        left = Size;
        currentGla = Gla;
        offset = 0;
        i = 0;
        res = (CX_UINT8*)Data;

        while (left > 0)
        {
            currentSize = MIN(left, PAGE_SIZE - (currentGla & 0xFFF));

            page = pages[i++].Map;

            if (Store)
            {
                CpuLockStore(page, res + offset, (CX_UINT8)currentSize);
            }
            else
            {
                // Load from memory, in our internal buffers.
                if (Vcpu->IntroEmu.BufferValid)
                {
                    CpuLockStore(res + offset, Vcpu->IntroEmu.Buffer + offset, (CX_UINT8)currentSize);
                }
                else
                {
                    CpuLockStore(res + offset, page, (CX_UINT8)currentSize);
                }
            }

            left -= currentSize;

            currentGla += currentSize;

            offset += currentSize;
        }

no_access:
        // Make sure we reset the Intro EMU buffer.
        Vcpu->IntroEmu.BufferValid = FALSE;
        Vcpu->IntroEmu.BufferSize = 0;
        Vcpu->IntroEmu.BufferGla = 0;

        // Unmap anything that was mapped.
        for (i = 0; i < gpasCount; i++)
        {
            // The original status contains important error code; do not overwrite it.
            NTSTATUS status2;

            page = pages[i].Map - (pages[i].Gpa & 0xFFF);

            status2 = iface->UnmapPhysicalMemory(&page);
            if (!NT_SUCCESS(status2))
            {
                ERROR("UnmapPhysicalMemory failed: 0x%08x\n", status2);
            }
        }

        gpasCount = 0;

        if (CfgDebugTraceEmulatorEnabled)
        {
            if (NULL == Context)
            {
                EMU_TRACE_ENTRY emuTraceDebugEntry = { 0 };
                emuTraceDebugEntry.EmulatedTargetGva = Gla;

                if (Store)
                {
                    memcpy(&emuTraceDebugEntry.EmulatedTargetValueStore, Data, MIN(8, Size));
                }
                else
                {
                    memcpy(&emuTraceDebugEntry.EmulatedTargetValueLoad, Data, MIN(8, Size));
                }

                emuTraceDebugEntry.EmulatedTargetSize = (CX_UINT8)Size;
                emuTraceDebugEntry.EmulatedRip = Vcpu->ArchRegs.RIP;
                emuTraceDebugEntry.IsValid = emuTraceDebugEntry.EmulatedRip != NULL ? TRUE : FALSE;

                if (emuTraceDebugEntry.IsValid) { EmuDebugInsertTraceEntry(Vcpu->GuestCpuIndex, &emuTraceDebugEntry); }
            }
        }
    }

    //
    // case 2 - we access DEVICE / PCI-CONFIG memory
    //
    else
    {
        if (Store)
        {
            status = iface->WriteDevMem(Vcpu, Context, Gpa, (CX_UINT8)Size, (CX_UINT8*)Data);
        }
        else
        {
            status = iface->ReadDevMem(Vcpu, Context, Gpa, (CX_UINT8)Size, (CX_UINT8*)Data);
        }
    }

    return status;
}



///
/// Will load data from the given GVA, inside Buffer, Size bytes. See NdEmuLoadStore
/// for more information.
///
///
/// @param Vcpu                     Vcpu
/// @param Instrux                  Decoded instruction
/// @param Context                  Device context, if any.
/// @param Gpa                      GPA where the EPT violation was generated, if any.
/// @param Gla                      GLA of the address to be written.
/// @param Data                     Buffer with the data to be stored.
/// @param Size                     Access size.
/// @param UpdateADBits             TRUE if we want to update the Accessed/Dirty bits inside the paging structures.
/// @param ImplicitSuperAccess      TRUE if this is an implicit supervisory access.
///
/// @return Same as _NdEmuAccessLinearAddress
static NTSTATUS
_NdEmuLoadFromLinearAddress(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Gla,
    _Out_ CX_VOID* Data,
    _In_ CX_UINT64 Size,
    _In_ BOOLEAN UpdateADBits,
    _In_ BOOLEAN ImplicitSuperAccess
    )
{
    return _NdEmuAccessLinearAddress(Vcpu, Instrux, Context, Gpa, Gla, Data, Size, FALSE, UpdateADBits, ImplicitSuperAccess);
}


///
/// @brief Store a value to a linear address as part of instruction emulation
///
/// This function will load data from the given GVA, inside Buffer, Size bytes. See NdEmuLoadStore
/// for more information.
///
/// @param Vcpu                     Vcpu
/// @param Instrux                  Decoded instruction
/// @param Context                  Device context, if any.
/// @param Gpa                      GPA where the EPT violation was generated, if any.
/// @param Gla                      GLA of the address to be written.
/// @param Data                     Buffer with the data to be stored.
/// @param Size                     Access size.
/// @param UpdateADBits             TRUE if we want to update the Accessed/Dirty bits inside the paging structures.
/// @param ImplicitSuperAccess      TRUE if this is an implicit supervisory access.
///
/// @return Same as _NdEmuAccessLinearAddress
static NTSTATUS
_NdEmuStoreToLinearAddress(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Gla,
    _In_ CX_VOID* Data,
    _In_ CX_UINT64 Size,
    _In_ BOOLEAN UpdateADBits,
    _In_ BOOLEAN ImplicitSuperAccess
    )
{
    return _NdEmuAccessLinearAddress(Vcpu, Instrux, Context, Gpa, Gla, Data, Size, TRUE, UpdateADBits, ImplicitSuperAccess);
}


///
/// @brief Retrieves operand value as part of instruction emulation
///
/// This function will get the operand value of the given operand. The operand types supported are:
/// - Memory
/// - Immediates
/// - Registers
///   - General purpose registers
///   - Segment registers
///   - Control registers
///   - Debug registers
///   - MMX/XMM registers
/// Depending on the operand type and size, it will copy its value inside the Value argument.
///
/// Vcpu,                    Vcpu.
/// Instrux,                 Decoded instruction.
/// Context,                 Device context, if any.
/// Gpa,                     Gpa of the address where the EPT violation was generated, if this is the case.
/// Address,                 Operand address.
/// Type,                    Operand type.
/// Size,                    Operand size.
/// Value,                   Will contain the operand value upon exit.
/// UpdateADBits             TRUE if we want to update the Accessed/Dirty bits inside the paging structures.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED       Cannot retrieve operand for given instruction
/// @return CX_STATUS_SUCCESS                       On success.
/// @return STATUS_XXX                              On errors.
///
static
NTSTATUS
_NdEmuGetOperandValue(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Address,
    _In_ CX_UINT32 Type,
    _In_ CX_UINT64 Size,
    _Out_ CX_VOID* Value,
    _In_ BOOLEAN UpdateADBits
    )
{
    NTSTATUS status;
    EXTENDED_REGS *pExRegs = (EXTENDED_REGS*)Vcpu->ExtState;

    memset((CX_UINT8*)Value, 0, (int)Size);
    status = CX_STATUS_SUCCESS;

    switch (Type)
    {
    case ND_EMU_OP_MEM:
        status = _NdEmuLoadFromLinearAddress(Vcpu, Instrux, Context, Gpa, Address, Value, Size, UpdateADBits, FALSE);
        break;

    case ND_EMU_OP_REG_GPR:
        if (Size == 1)
        {
            if ((Address >= 4) && ((Instrux->DefCode != ND_CODE_64) || (Instrux->Rex.Rex == 0)))
            {
                // this is ah, ch, dh or bh register, handle them properly
                *(CX_UINT8*)Value = (CX_UINT8)((REG_GPRV(&Vcpu->ArchRegs, Address - 4) >> 8) & 0xFF);
            }
            else
            {
                *(CX_UINT8*)Value = (CX_UINT8)(REG_GPRV(&Vcpu->ArchRegs, Address) & 0xFF);
            }
        }
        else if (Size == 2)
        {
            *(CX_UINT16*)Value = (CX_UINT16)(REG_GPRV(&Vcpu->ArchRegs, Address) & 0xFFFF);
        }
        else if (Size == 4)
        {
            *(CX_UINT32*)Value = (CX_UINT32)(REG_GPRV(&Vcpu->ArchRegs, Address) & 0xFFFFFFFF);
        }
        else if (Size == 8)
        {
            *(CX_UINT64*)Value = REG_GPRV(&Vcpu->ArchRegs, Address);
        }
        else
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
        }
        break;

    case ND_EMU_OP_REG_MMX:
        *((CX_UINT64*)Value) = REG_MMXV(pExRegs, Address)[0];
        break;

    case ND_EMU_OP_REG_XMM:
        ((CX_UINT64*)Value)[0] = REG_XMMV(pExRegs, Address)[0];
        ((CX_UINT64*)Value)[1] = REG_XMMV(pExRegs, Address)[1];
        break;

    case ND_EMU_OP_REG_CR:
        if (Address == 0)
        {
            *(CX_UINT64*)Value = Vcpu->ArchRegs.CR0;
        }
        else if (Address == 2)
        {
            *(CX_UINT64*)Value = Vcpu->ArchRegs.CR2;
        }
        else if (Address == 3)
        {
            *(CX_UINT64*)Value = Vcpu->ArchRegs.CR3;
        }
        else if (Address == 4)
        {
            *(CX_UINT64*)Value = Vcpu->ArchRegs.CR4;
        }
        else if (Address == 8)
        {
            *(CX_UINT64*)Value = Vcpu->ArchRegs.CR8;
        }
        else
        {
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        break;

    case ND_EMU_OP_IMM:
    case ND_EMU_OP_REL_OFFS:
        if (Size == 1)
        {
            *(CX_UINT8*)Value = (CX_UINT8)Address;
        }
        else if (Size == 2)
        {
            *(CX_UINT16*)Value = (CX_UINT16)Address;
        }
        else if (Size == 4)
        {
            *(CX_UINT32*)Value = (CX_UINT32)Address;
        }
        else if (Size == 8)
        {
            *(CX_UINT64*)Value = Address;
        }
        else
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
        }
        break;

    case ND_EMU_OP_FLG:
        *(CX_UINT64*)Value = Vcpu->ArchRegs.RFLAGS;
        break;

    default:
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        break;
    }

    return status;
}


///
/// @brief Sets the value for a given operand as part of instruction emulation
///
/// This function will set the value for the given operand. The operand types supported are:
/// - Memory
/// - Immediate
/// - Registers
///   - General purpose registers
///   - Segment registers
///   - Control registers
///   - Debug registers
///   - MMX/XMM registers
/// Depending on the operand type and size, it will store the value pointed by Value in the operand.
///
/// Vcpu                    Vcpu.
/// Instrux                 Decoded instruction.
/// Context                 Device context, if any.
/// Gpa                     Gpa of the address where the EPT violation was generated, if this is the case.
/// Address                 Operand address.
/// Type                    Operand type.
/// Size                    Operand size.
/// Value                   Will contain the operand value upon exit.
/// UpdateADBits            Indicates if update of A/D bits is requested
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED        Operation is not supported
/// @return CX_STATUS_SUCCESS                        On success.
/// @return STATUS_XXX                               On errors.
///
static
NTSTATUS
_NdEmuSetOperandValue(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Address,
    _In_ CX_UINT32 Type,
    _In_ CX_UINT64 Size,
    _In_ CX_VOID* Value,
    _In_ BOOLEAN UpdateADBits
    )
{
    NTSTATUS status;
    EXTENDED_REGS *exRegs = (EXTENDED_REGS*)Vcpu->ExtState;

    status = CX_STATUS_SUCCESS;

    switch (Type)
    {
    case ND_EMU_OP_MEM:
        status = _NdEmuStoreToLinearAddress(Vcpu, Instrux, Context, Gpa, Address, Value, Size, UpdateADBits, FALSE);
        break;

    case ND_EMU_OP_REG_GPR:
        if (Size == 1)
        {
            if (Address >= 4 && (Instrux->DefCode != ND_CODE_64 || Instrux->Rex.Rex == 0))
            {
                // this is ah, ch, dh or bh register, handle them properly
                *((CX_UINT8*)(REG_GPRP(&Vcpu->ArchRegs, Address - 4)) + 1) = *(CX_UINT8*)Value;
            }
            else
            {
                *(CX_UINT8*)(REG_GPRP(&Vcpu->ArchRegs, Address)) = *(CX_UINT8*)Value;
            }
        }
        else if (Size == 2)
        {
            *(CX_UINT16*)(REG_GPRP(&Vcpu->ArchRegs, Address)) = *(CX_UINT16*)Value;
        }
        else if (Size == 4)
        {
            // Any access of CX_UINT32 register in 64 bit mode will lead to the clearance of the upper 32 bit!!!
            ((CX_UINT32*)(REG_GPRP(&Vcpu->ArchRegs, Address)))[0] = *(CX_UINT32*)Value;
            ((CX_UINT32*)(REG_GPRP(&Vcpu->ArchRegs, Address)))[1] = 0;
        }
        else if (Size == 8)
        {
            *(CX_UINT64*)(REG_GPRP(&Vcpu->ArchRegs, Address)) = *(CX_UINT64*)Value;
        }
        else
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
        }
        break;

    case ND_EMU_OP_REG_MMX:
        ((CX_UINT64*)REG_MMXP(exRegs, Address))[0] = *(CX_UINT64*)Value;
        break;

    case ND_EMU_OP_REG_XMM:
        {
            ((CX_UINT64*)REG_XMMP(exRegs, Address))[0] = ((CX_UINT64*)Value)[0];
            ((CX_UINT64*)REG_XMMP(exRegs, Address))[1] = ((CX_UINT64*)Value)[1];
        }
        break;

    case ND_EMU_OP_REG_CR:
        if (Address == 0)
        {
            Vcpu->ArchRegs.CR0 = *(CX_UINT64*)Value;
        }
        else if (Address == 2)
        {
            Vcpu->ArchRegs.CR2 = *(CX_UINT64*)Value;
        }
        else if (Address == 3)
        {
            Vcpu->ArchRegs.CR3 = *(CX_UINT64*)Value;
        }
        else if (Address == 4)
        {
            Vcpu->ArchRegs.CR4 = *(CX_UINT64*)Value;
        }
        else if (Address == 8)
        {
            Vcpu->ArchRegs.CR8 = *(CX_UINT64*)Value;
        }
        else
        {
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
        break;

    case ND_EMU_OP_FLG:
        Vcpu->ArchRegs.RFLAGS = *(CX_UINT64*)Value;
        break;

    default:
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        break;
    }

    return status;
}



///
/// Emulates the MOV instruction. Also, it will handle any STOS, LODS, MOVS instruction.
/// If Aux is 0, sign extension will be made for operands smaller than destination.
/// If Aux is 1, zero extension will be made for operands smaller than destination.
///
///
/// Vcpu,           Vcpu for which emulation is performed
/// Instrux,        Decoded instruction.
/// Context,        Device context, if any.
/// Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return STATUS_EMU_DONT_ADVANCE_RIP         Partial emulation performed. This is the case for instructions that have the REP prefix.
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerMov(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 value;
    BOOLEAN reloadDest, reloadSrc;
    CX_UINT64 gpaRead, gpaWrite, glaStartRead, glaStartWrite;
    EMU_OPERAND op1 = {0}, op2 = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;
    CX_UINT64   rcx, rsi, rdi;

    value = 0;
    gpaRead = gpaWrite = glaStartRead = glaStartWrite = 0;

    /// TODO: Handle validations for CR/DR access in V8086 mode.
    /// TODO: Handle validations for segment registers access, if they will ever be emulated.

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        ERROR("_NdEmuGetOperandEx failed: 0x%08x\n", status);
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        ERROR("_NdEmuGetOperandEx failed: 0x%08x\n", status);
        return status;
    }

    if ((op1.Type == ND_EMU_OP_MEM) && (op2.Type == ND_EMU_OP_MEM))
    {
        status = iface->TranslateVirtualAddress(Vcpu, op1.Address, &gpaWrite);
        if (!NT_SUCCESS(status))
        {
            WARNING("Failed translating destination GVA %018p to GPA: 0x%08x\n", op1.Address, status);
        }

        status = iface->TranslateVirtualAddress(Vcpu, op2.Address, &gpaRead);
        if (!NT_SUCCESS(status))
        {
            WARNING("Failed translating destination GVA %018p to GPA: 0x%08x\n", op2.Address, status);
        }
    }
    else
    {
        gpaRead = gpaWrite = Gpa;
    }

    reloadDest = reloadSrc = TRUE;

    // Save the first addresses accessed. We will stop the emulation of a REPed instruction when reaching the end of
    // the source or destination page.
    if (op1.Type == ND_EMU_OP_MEM)
    {
        glaStartWrite = op1.Address;
    }

    if (op2.Type == ND_EMU_OP_MEM)
    {
        glaStartRead = op2.Address;
    }

    rcx = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RCX);
    rsi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RSI);
    rdi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RDI);

    for (;;)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
        if (!NT_SUCCESS(status))
        {
            ERROR("_NdValidateOperand failed!\n");
            return status;
        }

        status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
        if (!NT_SUCCESS(status))
        {
            ERROR("_NdValidateOperand failed: 0x%x\n", status);
            return status;
        }
#endif

        // Get source value
        if (reloadSrc)
        {
            status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, gpaRead, op2.Address, op2.Type, op2.Size, (CX_VOID*)&value, TRUE);
            if (! NT_SUCCESS(status))
            {
                ERROR("_NdEmuGetOperandValue failed: 0x%08x\n", status);
                return status;
            }

            // If source is immediate, we need to sign-extend it.
            if ((op1.Size > op2.Size) && (Aux == 0))
            {
                value = ND_TRIM(op1.Size, ND_SIGN_EX(op2.Size, value));
            }
        }

        // Set destination value
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, gpaWrite, op1.Address, op1.Type, op1.Size, (CX_VOID*)&value, TRUE);
        if (! NT_SUCCESS(status))
        {
            ERROR("_NdEmuSetOperandValue failed: 0x%08x\n", status);
            return status;
        }

        {
            //
            // Also handle string instructions - movs, lods, stos, etc.
            //

            reloadDest = reloadSrc = FALSE;

            if (ND_INS_MOVS == Instrux->Instruction)
            {
                // movs
                if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
                {
                    rsi += op1.Size;
                    rdi += op1.Size;
                    gpaRead = gpaRead + op1.Size;
                    gpaWrite = gpaWrite + op1.Size;
                    op1.Address += op1.Size;
                    op2.Address += op1.Size;
                    op1.Gva += op1.Size;
                    op2.Gva += op1.Size;
                }
                else
                {
                    rsi -= op1.Size;
                    rdi -= op1.Size;
                    gpaRead = gpaRead - op1.Size;
                    gpaWrite = gpaWrite - op1.Size;
                    op1.Address -= op1.Size;
                    op2.Address -= op1.Size;
                    op1.Gva -= op1.Size;
                    op2.Gva -= op1.Size;
                }

                reloadDest = reloadSrc = TRUE;
            }

            if (ND_INS_STOS == Instrux->Instruction)
            {
                // stos
                if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
                {
                    rdi += op1.Size;
                    gpaWrite = gpaWrite + op1.Size;
                    op1.Address += op1.Size;
                    op1.Gva += op1.Size;
                }
                else
                {
                    rdi -= op1.Size;
                    gpaWrite = gpaWrite - op1.Size;
                    op1.Address -= op1.Size;
                    op1.Gva -= op1.Size;
                }

                reloadDest = TRUE;
            }

            if (ND_INS_LODS == Instrux->Instruction)
            {
                // lods
                if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
                {
                    rsi += op1.Size;
                    gpaRead = gpaRead + op1.Size;
                    op2.Address += op1.Size;
                    op2.Gva += op1.Size;
                }
                else
                {
                    rsi -= op1.Size;
                    gpaRead = gpaRead - op1.Size;
                    op2.Address -= op1.Size;
                    op2.Gva -= op1.Size;
                }

                reloadSrc = TRUE;
            }

            if (! (reloadSrc || reloadDest))
            {
                break;
            }

            if (Instrux->Rep != ND_PREFIX_G1_REPE_REPZ)
            {
                // no rep, leave
                break;
            }

            rcx--;

            if (rcx == 0)
            {
                break;
            }

            BOOLEAN pageBoundary =
                (((op1.Type == ND_EMU_OP_MEM) && ((glaStartWrite & PAGE_MASK) != (op1.Address & PAGE_MASK))) ||
                ((op2.Type == ND_EMU_OP_MEM) && ((glaStartRead & PAGE_MASK) != (op2.Address & PAGE_MASK))));

            // If we crossed page boundary, bail out OR
            // Stop the emulation if the REP optimization is off. Otherwise, keep going until we either finish, or
            // until RDI/RSI crosses the page boundary.
            if (pageBoundary || Vcpu->Guest->Intro.IntroDisableRepOptimization)
            {
                if (Instrux->AddrMode == ND_ADDR_16)
                {
                    Vcpu->ArchRegs.CX = (CX_UINT16)rcx;
                    Vcpu->ArchRegs.SI = (CX_UINT16)rsi;
                    Vcpu->ArchRegs.DI = (CX_UINT16)rdi;
                }
                else
                {
                    Vcpu->ArchRegs.RCX = rcx & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
                    Vcpu->ArchRegs.RSI = rsi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
                    Vcpu->ArchRegs.RDI = rdi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
                }

                return STATUS_EMU_DONT_ADVANCE_RIP;
            }
        }
    }

    if (Instrux->Rep == ND_PREFIX_G1_REPE_REPZ)
    {
        if (Instrux->AddrMode == ND_ADDR_16)
        {
            Vcpu->ArchRegs.CX = (CX_UINT16)rcx;
            Vcpu->ArchRegs.SI = (CX_UINT16)rsi;
            Vcpu->ArchRegs.DI = (CX_UINT16)rdi;
        }
        else
        {
            Vcpu->ArchRegs.RCX = rcx & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
            Vcpu->ArchRegs.RSI = rsi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
            Vcpu->ArchRegs.RDI = rdi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
        }
    }

    return CX_STATUS_SUCCESS;
}



///
/// Emulates SSE forms of the MOV instructions: MOVQ, MOVDQA, MOVDQU, MOVNTQ, MOVNTPS.
/// Aux is ignored.

/// @param Vcpu,                    Vcpu for wchich emulation is performed
/// @param Instrux,                 Decoded instruction.
/// @param Context,                 Device context, if any.
/// @param Gpa,                     Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux                      Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerMovSse(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 value[4] = {0}; // value is this big in order to support YMM registers.
    EMU_OPERAND op1 = {0}, op2 = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    iface->SaveCpuState(Vcpu, emhvSaveFpuState);

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}

///
/// @brief Handle move with immediate operand
///
/// Emulates MOV instructions with immediate operand.
/// Aux is ignored.
///
/// @param Vcpu,                    Vcpu for wchich emulation is performed
/// @param Instrux,                 Decoded instruction.
/// @param Context,                 Device context, if any.
/// @param Gpa,                     Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux                      Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandleMovImm(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
//
/// ...
//
/// \ret CX_STATUS_OPERATION_NOT_SUPPORTED ...
//
{
    NTSTATUS status;
    CX_UINT64 value;
    EMU_OPERAND op1 = {0}, op2 = {0};

    UNREFERENCED_PARAMETER(Aux);

    value = 0;

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }
#endif

    // Sign extend, if needed.
    if (op1.Size > op2.Size)
    {
        value = ND_TRIM(op1.Size, ND_SIGN_EX(op2.Size, value));
    }

    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief CMOV emulation
///
/// Emulates the CMOV instruction.
/// Aux indicates the condition to test (low nibble from the opcode).
///
/// @param Vcpu,                    Vcpu for wchich emulation is performed
/// @param Instrux,                 Decoded instruction.
/// @param Context,                 Device context, if any.
/// @param Gpa,                     Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux                      Auxiliary parameter. Used to select specific operation.
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerCmov(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 value;
    EMU_OPERAND op1 = {0}, op2 = {0};

    value = 0;

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Check the condition code.
    if (!_NdEmuEvalCondition(Vcpu, Instrux, (CX_UINT8)Aux))
    {
        return CX_STATUS_SUCCESS;
    }

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // If source is immediate, we need to sign-extend it.
    if (op1.Size > op2.Size)
    {
        value = ND_TRIM(op1.Size, ND_SIGN_EX(op2.Size, value));
    }

    // Set destination value
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief PUSH / POP emulation
///
///
/// Emulates the PUSH & POP instructions.
/// Aux is:
///  - 0 -> PUSH
///  - 1 -> POP.
///
/// NOTE: The behavior of the emulator will be identical to the real behavior of a CPU:
/// it will first push the value onto the stack, and adjust [R|E]SP after.
///
/// @param Vcpu,                    Vcpu.
/// @param Instrux,                 Decoded instruction.
/// @param Context,                 Device context, if any.
/// @param Gpa,                     Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux                      Auxiliary parameter. Used to select specific operation.
///
///
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerPushPop(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 value;
    CX_UINT32 wordSize;
    CX_UINT64 ssSelector = 0;
    EMU_OPERAND op1 = {0}, op2 = {0}, stack = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    // preinit
    value = 0;
    wordSize = Instrux->DefCode == ND_CODE_64 ? 8 : Instrux->DefCode == ND_CODE_32 ? 4 : 2;

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    iface->VmxRead(Vcpu, VMCS_GUEST_SS, &ssSelector);

    // Get stack-segment base (relevant only in 32 bit & 16 bit operating modes)
    status = _NdGetSegmentInformation(Vcpu, Instrux, NDR_SS, &stack.Seg);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    stack.Seg.Segment = NDR_SS;
    stack.Seg.Selector = (CX_UINT16)ssSelector;

    stack.Address = stack.Seg.Base + Vcpu->ArchRegs.RSP;
    stack.Size = wordSize;
    stack.Type = ND_EMU_OP_MEM;

    if (Aux == 0)
    {
        // PUSH

        //
        //The PUSH ESP instruction pushes the value of the ESP register as it existed before
        //the instruction was executed (Vol. 2B 4-425)
        //

        stack.Address -= wordSize;

        // Get source operand
        status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op2);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        status = _NdValidateOperand(Vcpu, Instrux, &stack, TRUE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }

        status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }
#endif

        // Get source operand value
        status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa,
                                      op2.Address, op2.Type, op2.Size, (CX_VOID*)&value, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        // If this is an immediate, sign-extend it.
        if (op2.Type == ND_EMU_OP_IMM)
        {
            value = ND_TRIM(wordSize, ND_SIGN_EX(op2.Size, value));
        }

        // We got the stuff, now save it on the stack
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa,
                                      stack.Address, stack.Type, stack.Size, (CX_VOID*)&value, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        Vcpu->ArchRegs.RSP -= wordSize;
    }
    else
    {
        // POP

        // Get destination operand
        status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }

        status = _NdValidateOperand(Vcpu, Instrux, &stack, FALSE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }
#endif

        // Load the data from the stack
        status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa,
                                      stack.Address, stack.Type, stack.Size, (CX_VOID*)&value, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Store the value in the destination
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa,
                                      op1.Address, op1.Type, op1.Size, (CX_VOID*)&value, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Update RSP
        Vcpu->ArchRegs.RSP += wordSize;
    }

    return CX_STATUS_SUCCESS;
}


///
/// Bitwise instructions emulation
///
/// Emulates the OR, AND, XOR, TEST instructions.
/// Aux is:
///  - 0 -> OR
///  - 1 -> AND
///  - 2 -> XOR
///  - 3 -> TEST
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_INVALID_PARAMETER_5       If Aux is not valid
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerLogic(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, result, newflags;
    CX_UINT8 c = 0, p = 0, s = 0, z = 0;
    EMU_OPERAND op1 = {0}, op2 = {0};

    valuesrc = valuedst = 0;
    newflags = Vcpu->ArchRegs.RFLAGS;

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, 3 != Aux); // Destination only if it's not TEST.
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // If source is smaller than the dest, we need to sign-extend it.
    if (op1.Size > op2.Size)
    {
        valuesrc = ND_TRIM(op1.Size, ND_SIGN_EX(op2.Size, valuesrc));
    }

    // Store the result
    if (Aux == 0)
    {
        result = valuedst | valuesrc;
    }
    else if (Aux == 1 || Aux == 3)
    {
        result = valuedst & valuesrc;
    }
    else if (Aux == 2)
    {
        result = valuedst ^ valuesrc;
    }
    else
    {
        return CX_STATUS_INVALID_PARAMETER_5;
    }

    _NdComputeFlags(result, op1.Size, valuedst, valuesrc, 0, 0, &c, &p, &s, &z, FALSE);

    ND_SET_FLAG(newflags, ND_EFLAG_CF, 0);
    ND_SET_FLAG(newflags, ND_EFLAG_OF, 0);
    ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
    ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);


    if (Aux != 3)
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&result, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        status = CX_STATUS_SUCCESS;
    }

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}



///
/// @brief CMPS emulation
///
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Ignored
///
/// @return     CX_STATUS_OPERATION_NOT_SUPPORTED ...
///
static
NTSTATUS
_NdEmuHandlerCmps(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuedst, valuesrc, result, newflags;
    CX_UINT8 p = 0, c = 0, s = 0, z = 0, o;
    EMU_OPERAND op1 = {0}, op2 = {0};
    CX_UINT64 rcx, rsi, rdi;

    UNREFERENCED_PARAMETER(Aux);
    UNREFERENCED_PARAMETER(Gpa);

    valuedst = valuesrc = 0;

    // If lock is present, return unsupported - UD will be generated, so let the CPU handle this
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    rcx = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RCX);
    rsi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RSI);
    rdi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RDI);

    for (;;)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        status = _NdValidateOperand(Vcpu, Instrux, &op1, FALSE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }

        status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdValidateOperand failed!\n");
            return status;
        }
#endif

        // Get destination value
        status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        // Get source value.
        status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&valuesrc, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        // Compare the values.
        result = valuedst - valuesrc;

        // Get old flags.
        newflags = Vcpu->ArchRegs.RFLAGS;

        // Update the flags, according to the comparison result.
        _NdComputeFlags(result, op1.Size, valuedst, valuesrc, 0, 0, &c, &p, &s, &z, TRUE);

        // Adjust OF according to the result.
        o = (ND_GET_SIGN(op1.Size, valuedst) == 0) && (ND_GET_SIGN(op2.Size, valuesrc) == 1) && (ND_GET_SIGN(op1.Size, result) == 1) ||
            (ND_GET_SIGN(op1.Size, valuedst) == 1) && (ND_GET_SIGN(op2.Size, valuesrc) == 0) && (ND_GET_SIGN(op1.Size, result) == 0);

        ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
        ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
        ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
        ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);
        ND_SET_FLAG(newflags, ND_EFLAG_OF, o);

        // adjust flag
        {
            CX_UINT8 a1, a2;

            a1 = valuedst & 0xF;
            a2 = valuesrc & 0xF;

            if (a1 < a2)
            {
                ND_SET_FLAG(newflags, ND_EFLAG_AF, 1);
            }
            else
            {
                ND_SET_FLAG(newflags, ND_EFLAG_AF, 0);
            }
        }

        Vcpu->ArchRegs.RFLAGS = newflags;

        // Advance RDI & RSI.
        if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
        {
            rsi += op2.Size;
            rdi += op1.Size;
            op1.Address += op1.Size;
            op2.Address += op2.Size;
            op1.Gva += op1.Size;
            op2.Gva += op2.Size;
            Gpa = Gpa + op1.Size;
        }
        else
        {
            rsi -= op2.Size;
            rdi -= op1.Size;
            op1.Address -= op1.Size;
            op2.Address -= op2.Size;
            op1.Gva -= op1.Size;
            op2.Gva -= op2.Size;
            Gpa = Gpa - op1.Size;
        }

        // If there is no rep, leave.
        if ((Instrux->Rep != ND_PREFIX_G1_REPE_REPZ) && (Instrux->Rep != ND_PREFIX_G1_REPNE_REPNZ))
        {
            break;
        }


        // Adjust RCX
        rcx -= 1;

        // If RCX is 0, we are done.
        if (0 == rcx)
        {
            break;
        }

        // Check for the termination condition.
        if ((Instrux->Rep == ND_PREFIX_G1_REPE_REPZ) && (0 == ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF)))
        {
            break;
        }
        else if ((Instrux->Rep == ND_PREFIX_G1_REPNE_REPNZ) && (1 == ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_ZF)))
        {
            break;
        }
    }

    if (Instrux->AddrMode == ND_ADDR_16)
    {
        Vcpu->ArchRegs.CX = (CX_UINT16)rcx;
        Vcpu->ArchRegs.SI = (CX_UINT16)rsi;
        Vcpu->ArchRegs.DI = (CX_UINT16)rdi;
    }
    else
    {
        Vcpu->ArchRegs.RCX = rcx & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
        Vcpu->ArchRegs.RSI = rsi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
        Vcpu->ArchRegs.RDI = rdi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief Arithmethic instructions emulation
///
///
/// Emulates the ADD, ADC, SUB, SBB, CMP instructions.
/// Aux is:
///  - 0 -> ADD
///  - 1 -> ADC
///  - 2 -> SUB
///  - 3 -> SBB
///  - 4 -> CMP
///
/// @param Vcpu             Vcpu.
/// @param Instrux          Decoded instruction.
/// @param Context          Device context, if any.
/// @param Gpa              Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux              Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerArith(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, result, newflags;
    // flags
    CX_UINT8 c = 0, s = 0, z = 0, p = 0, o;
    EMU_OPERAND op1 = {0}, op2 = {0};

    valuesrc = valuedst = 0;
    newflags = Vcpu->ArchRegs.RFLAGS;


    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, Aux != 4); // destination only if it's not CMP.
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // If source is smaller than the dest, we need to sign-extend it.
    if (op1.Size > op2.Size)
    {
        valuesrc = ND_TRIM(op1.Size, ND_SIGN_EX(op2.Size, valuesrc));
    }

    if ((Aux == 1) || (Aux == 3))
    {
        // ADC or SBB, adjust source value in order to reflect the CF value.
        valuesrc += (Vcpu->ArchRegs.RFLAGS & ND_EFLAG_CF) ? 1 : 0;
    }

    if (Aux == 0 || Aux == 1)
    {
        //We already took care of Carry flag
        result = valuedst + valuesrc;
    }
    else if ((Aux == 2) || (Aux == 4) || (Aux == 3))
    {
        result = valuedst - valuesrc;
    }
    else
    {
        return CX_STATUS_INVALID_PARAMETER_5;
    }

    //
    // Set the flags
    //


    _NdComputeFlags(result, op1.Size, valuedst, valuesrc, 0, 0, &c, &p, &s, &z, (Aux != 0) && (Aux != 1));
    if ((Aux == 0) || (Aux == 1))
    {
        // Addition - OF will be set if both operands have the same sign, which is different than the results sign.
        o = (ND_GET_SIGN(op1.Size, valuedst) == ND_GET_SIGN(op2.Size, valuesrc)) &&
            (ND_GET_SIGN(op1.Size, valuedst) != ND_GET_SIGN(op1.Size, result));
    }
    else
    {
        // Subtraction
        o = (ND_GET_SIGN(op1.Size, valuedst) == 0) &&
            (ND_GET_SIGN(op2.Size, valuesrc) == 1) &&
            (ND_GET_SIGN(op1.Size, result) == 1) ||
            (ND_GET_SIGN(op1.Size, valuedst) == 1) &&
            (ND_GET_SIGN(op2.Size, valuesrc) == 0) &&
            (ND_GET_SIGN(op1.Size, result) == 0);
    }

    ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
    ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
    ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);
    ND_SET_FLAG(newflags, ND_EFLAG_OF, o);

    // adjust flag
    {
        CX_UINT8 a1, a2;

        a1 = valuedst & 0xF;
        a2 = valuesrc & 0xF;

        if (((Aux == 2 || Aux == 3 || Aux == 4) && a1 < a2) ||
            ((Aux == 0 || Aux == 1) && (a1 + a2) > 0xF))
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 1);
        }
        else
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 0);
        }
    }

    if (Aux != 4)
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, op1.Size, (CX_VOID*)&result, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}


///
/// @brief Bitwise rotate instructions emulation
///
/// Emulates the ROL, ROR, RCL, RCR instructions.
/// Aux is:
///  - 0 -> ROL
///  - 1 -> ROR
///  - 2 -> RCL
///  - 3 -> RCR
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerRotate(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, result, newflags;
    CX_UINT64 tempCount, countMask;
    // flags
    CX_UINT8 c, o, tempCF = 0;
    EMU_OPERAND dest = {0}, src = {0};

    valuesrc = valuedst = 0;
    newflags = Vcpu->ArchRegs.RFLAGS;

    // LOCK is not supported for ROL/ROR/RCL/RCR.
    if (Instrux->HasLock)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dest);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dest, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, dest.Address, dest.Type, dest.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    o = ND_GET_FLAG(newflags, ND_EFLAG_OF);

    tempCount = 0;
    countMask = ((dest.Size == 8) ? 0x3F : 0x1F);

    if (Aux == 2 || Aux == 3)
    {
        //RCL or RCR
        switch (dest.Size)
        {
        case 1:
            tempCount = (valuesrc & 0x1F) % 9;
            break;
        case 2:
            tempCount = (valuesrc & 0x1F) % 17;
            break;
        case 4:
            tempCount = valuesrc & 0x1F;
            break;
        case 8:
            tempCount = valuesrc & 0x3F;
            break;
        default:
            break;
        }
    }
    else
    {
        tempCount = (valuesrc & countMask) % (dest.Size * 8);
    }

    if (Aux == 0)
    {
        // ROL
        result = valuedst;
        while (tempCount)
        {
            tempCF = ND_MSB(dest.Size, result);
            result = (result << 1) + tempCF;
            tempCount--;
        }

        if ((valuesrc & countMask) != 0)
        {
            c = valuedst & 1;
            ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
        }

        if ((valuesrc & countMask) == 1)
        {
            o = ND_MSB(dest.Size, result) ^ ND_GET_FLAG(newflags, ND_EFLAG_CF);
            ND_SET_FLAG(newflags, ND_EFLAG_OF, o);
        }
    }
    else if (Aux == 1)
    {
        // ROR
        result = valuedst;
        while (tempCount)
        {
            tempCF = ND_LSB(dest.Size, result);
            result = (result >> 1) + ((CX_UINT64)tempCF << (dest.Size * 8 - 1));
            tempCount--;
        }

        if ((valuesrc & countMask) != 0)
        {
            c = ND_MSB(dest.Size, result);
            ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
        }

        if ((valuesrc & countMask) == 1)
        {
            o = ND_MSB(dest.Size, result) ^ tempCF;
            ND_SET_FLAG(newflags, ND_EFLAG_OF, o);
        }
    }
    else if (Aux == 2)
    {
        // RCL
        result = valuedst;
        c = ND_GET_FLAG(newflags, ND_EFLAG_CF);

        while (tempCount)
        {
            tempCF = ND_MSB(dest.Size, result);
            result = (result << 1) + c;
            c = tempCF;
            tempCount--;
        }

        ND_SET_FLAG(newflags, ND_EFLAG_CF, c);

        if ((valuesrc & countMask) == 1)
        {
            o = ND_MSB(dest.Size, result) ^ c;
            ND_SET_FLAG(newflags, ND_EFLAG_OF, o);
        }
    }
    else
    {
        // RCR
        c = ND_GET_FLAG(newflags, ND_EFLAG_CF);

        if ((valuesrc & countMask) == 1)
        {
            o = ND_MSB(dest.Size, valuedst) ^ c;
            ND_SET_FLAG(newflags, ND_EFLAG_OF, o);
        }

        result = valuedst;

        while (tempCount)
        {
            tempCF = ND_LSB(dest.Size, result); //In Manual it says that it is LSB(SRC), but that is wrong
            result = (result >> 1) + ((CX_UINT64)c << (dest.Size * 8 - 1));
            c = tempCF;
            tempCount--;
        }

        ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
    }

    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dest.Address, dest.Type, dest.Size, (CX_VOID*)&result, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}



///
/// @brief Compare and exchange instruction emulation
///
/// Emulates the CMPXCHG8B and CMPXCHG16B instructions.
/// Aux is ignored.
/// If the form of the instruction which operates on registers is used (invalid encoding).
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerCmpXchg8(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 newflags, value[2] = {0};
    BOOLEAN zf;
    CX_UINT64 rax, rdx;
    EMU_OPERAND op = {0};

    UNREFERENCED_PARAMETER(Aux);

    zf = FALSE;
    newflags = Vcpu->ArchRegs.RFLAGS;
    rax = 0;
    rdx = 0;

    // Validate ModRM
    if (Instrux->ModRm.mod == 3)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // step 1: compare
    if (op.Size == 8)
    {
        // cmpxchg8b
        CX_UINT32 opHigh, opLow;

        opHigh = ((CX_UINT32*)value)[1];
        opLow = ((CX_UINT32*)value)[0];

        if (opHigh == (CX_UINT32)Vcpu->ArchRegs.RDX && opLow == (CX_UINT32)Vcpu->ArchRegs.RAX)
        {
            zf = TRUE;

            ((CX_UINT32*)value)[1] = (CX_UINT32)Vcpu->ArchRegs.RCX;
            ((CX_UINT32*)value)[0] = (CX_UINT32)Vcpu->ArchRegs.RBX;
        }
        else
        {
            zf = FALSE;

            rdx = opHigh;
            rax = opLow;
        }
    }
    else
    {
        CX_UINT64 op1, op2;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        if ((op.Address & 15) != 0)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
        }
#endif

        op1 = value[1];
        op2 = value[0];

        if (op1 == Vcpu->ArchRegs.RDX && op2 == Vcpu->ArchRegs.RAX)
        {
            zf = TRUE;

            value[1] = Vcpu->ArchRegs.RCX;
            value[0] = Vcpu->ArchRegs.RBX;
        }
        else
        {
            zf = FALSE;

            rdx = value[1];
            rax = value[0];
        }
    }

    // step 2: store new value, if any; We will store it regardless of the ZF, because the CPU also stores the value
    // regardless of the comparison result.
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, value, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // We must modify RDX:RAX also, but only if ZF is false.
    if (!zf)
    {
        Vcpu->ArchRegs.RDX = rdx;
        Vcpu->ArchRegs.RAX = rax;
    }

    // step 3: set ZF
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, zf);

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}


///
/// @brief XAdd instruction emulation
///
/// Emulates XADD instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerXadd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, result, newflags;
    CX_UINT8 c = 0, p = 0, s = 0, z = 0, o;
    EMU_OPERAND dst = {0}, src = {0};

    UNREFERENCED_PARAMETER(Aux);

    valuesrc = valuedst = 0;
    newflags = Vcpu->ArchRegs.RFLAGS;


    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dst);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dst, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE); // This is destination, but it can't be mem.
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    result = valuedst + valuesrc;

    //
    // Set the flags
    //
    _NdComputeFlags(result, dst.Size, valuesrc, valuedst, 0, 0, &c, &p, &s, &z, FALSE);
    o = (ND_GET_SIGN(dst.Size, valuedst) == ND_GET_SIGN(src.Size, valuesrc)) &&
        (ND_GET_SIGN(dst.Size, valuedst) != ND_GET_SIGN(dst.Size, result));

    ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
    ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
    ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);
    ND_SET_FLAG(newflags, ND_EFLAG_OF, o);

    // adjust flag
    {
        CX_UINT8 a1, a2;

        a1 = valuedst & 0xF;
        a2 = valuesrc & 0xF;

        if ((a1 + a2) > 0xF)
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 1);
        }
        else
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 0);
        }
    }


    // Memory operand must be modified first, in case of exceptions.
    if (ND_EMU_OP_MEM == src.Type)
    {
        // store the result in source & destination
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&result, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&result, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}


///
/// @brief XCHG instruction emulation
///
/// Emulates the XCHG instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerXchg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst;
    EMU_OPERAND dst = {0}, src = {0};

    UNREFERENCED_PARAMETER(Aux);

    valuesrc = valuedst = 0;

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dst);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dst, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE); // This is destination, but it can't be mem.
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }


    // Memory operand must be modified first, in case of exceptions.
    if (ND_EMU_OP_MEM == src.Type)
    {
        // store the result in source & destination
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuesrc, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        // store the result in source & destination
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuesrc, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }

        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief CMPXCHG instruction emulation
///
/// Emulates the CMPXCHG instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerCmpXchg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, newflags, xax, result;
    BOOLEAN zf;
    CX_UINT8 c = 0, s = 0, z = 0, p = 0, o;
    EMU_OPERAND dst = {0}, src = {0};

    UNREFERENCED_PARAMETER(Aux);

    zf = FALSE;
    newflags = Vcpu->ArchRegs.RFLAGS;
    xax = valuesrc = valuedst = 0;

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dst);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dst, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE); // This is destination, but it can't be memory.
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get al/ax/eax/rax value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, 0, ND_EMU_OP_REG_GPR, dst.Size, (CX_VOID*)&xax, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    if (dst.Size == 1)
    {
        zf = ((CX_UINT8)xax == (CX_UINT8)valuedst);
    }
    else if (dst.Size == 2)
    {
        zf = ((CX_UINT16)xax == (CX_UINT16)valuedst);
    }
    else if (dst.Size == 4)
    {
        zf = ((CX_UINT32)xax == (CX_UINT32)valuedst);
    }
    else
    {
        zf = (xax == valuedst);
    }

    // Step 2: store new value, if any
    if (zf)
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuesrc, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, NDR_RAX, ND_EMU_OP_REG_GPR, dst.Size, (CX_VOID*)&valuedst, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }

    // Step 3: Compute the other flags, as if it were a normal cmp.
    result = xax - valuedst;

    _NdComputeFlags(result, dst.Size, xax, valuedst, 0, 0, &c, &p, &s, &z, TRUE);

    // Compute OF flag.
    o = (ND_GET_SIGN(dst.Size, xax) == 0) && (ND_GET_SIGN(src.Size, valuedst) == 1) && (ND_GET_SIGN(dst.Size, result) == 1) ||
        (ND_GET_SIGN(dst.Size, xax) == 1) && (ND_GET_SIGN(src.Size, valuedst) == 0) && (ND_GET_SIGN(dst.Size, result) == 0);

    ND_SET_FLAG(newflags, ND_EFLAG_CF, c);
    ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
    ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);
    ND_SET_FLAG(newflags, ND_EFLAG_OF, o);

    // adjust flag
    {
        CX_UINT8 a1, a2;

        a1 = xax & 0xF;
        a2 = valuedst & 0xF;

        if (a1 < a2)
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 1);
        }
        else
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 0);
        }
    }

    // Step 4: save flags.
    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}


///
/// @brief INC / DEC emulation
///
/// Emulates INC & DEC instructions (with memory).
/// Aux is:
///  - 0 -> INC
///  - 1 -> DEC.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerIncDec(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, result, newflags, st;
    CX_UINT8 c = 0, p = 0, s = 0, z = 0, o;
    EMU_OPERAND op = {0};

    valuesrc = result = 0;
    newflags = Vcpu->ArchRegs.RFLAGS;

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    if (Aux == 0)
    {
        result = valuesrc + 1;
    }
    else
    {
        result = valuesrc - 1;
    }

    if (op.Size == 1)
    {
        st = (CX_UINT64)(CX_UINT8)-1;
    }
    else if (op.Size == 2)
    {
        st = (CX_UINT64)(CX_UINT16)-1;
    }
    else if (op.Size == 4)
    {
        st = (CX_UINT64)(CX_UINT32)-1;
    }
    else
    {
        st = (CX_UINT64)-1;
    }

    //
    // Set the flags
    //
    _NdComputeFlags(result, op.Size, valuesrc, Aux == 0 ? 1 : st, 0, 0, &c, &p, &s, &z, (Aux == 1));
    if (Aux == 0)
    {
        // Addition - OF will be set iff both operands have the same sign, which is different than the results sign.
        o = (ND_GET_SIGN(op.Size, valuesrc) == 0) && (0 != ND_GET_SIGN(op.Size, result));
    }
    else
    {
        // Subtraction
        o = (ND_GET_SIGN(op.Size, valuesrc) == 1) && (ND_GET_SIGN(op.Size, result) == 0);
    }

    ND_SET_FLAG(newflags, ND_EFLAG_PF, p);
    ND_SET_FLAG(newflags, ND_EFLAG_SF, s);
    ND_SET_FLAG(newflags, ND_EFLAG_ZF, z);
    ND_SET_FLAG(newflags, ND_EFLAG_OF, o);

    // adjust flag
    {
        CX_UINT8 a1, a2;

        a1 = valuesrc & 0xF;
        a2 = 1;

        if (((Aux == 1) && (a1 < a2)) ||
            ((Aux == 0) && (a1 + a2) > 0xF))
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 1);
        }
        else
        {
            ND_SET_FLAG(newflags, ND_EFLAG_AF, 0);
        }
    }

    // store the result in destination
    status = _NdEmuSetOperandValue(Vcpu, Instrux,  Context, Gpa, op.Address, op.Type, op.Size, (CX_VOID*)&result, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    Vcpu->ArchRegs.RFLAGS = newflags;

    return CX_STATUS_SUCCESS;
}


///
/// @brief Jump instruction emulation
///
/// Emulates near JMP instuction
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerJump(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    EMU_OPERAND op = {0};
    CX_UINT64 newValue;

    UNREFERENCED_PARAMETER(Aux);
    UNREFERENCED_PARAMETER(Gpa);

    newValue = 0;

    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (! NT_SUCCESS(status))
    {
        LOG("_NdEmuGetOperandEx: %x\n", status);
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }
#endif

    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, NULL, op.Address, op.Type, op.Size, &newValue, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdEmuGetOperandValue failed: 0x%08x\n", status);
        return status;
    }

    Vcpu->ArchRegs.RIP = newValue;

    return STATUS_EMU_DONT_ADVANCE_RIP;
}


///
/// BTx emulation
///
/// Emulates BTS, BTR, BTC, BT instructions.
/// Aux is:
///  - 0 -> BTS
///  - 1 -> BTR
///  - 2 -> BTC
///  - 3 -> BT
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerBt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 valuesrc, valuedst, result, bitoffs;
    CX_UINT8 c;
    EMU_OPERAND dst = {0}, src = {0};

    valuesrc = valuedst = result = bitoffs = 0;
    c = 0;

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dst);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dst, (Aux <= 2) ? TRUE : FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, (CX_VOID*)&valuesrc, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    // Important note: if the destination operand is in memory, than the real linear address has been already computed,
    // as these instruction as flagged as "BitBase" instruction by the disassembler.
    bitoffs = valuesrc & ((dst.Size << 3) - 1);

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&valuedst, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    c = (valuedst >> bitoffs) & 1;

    if (Aux == 0)
    {
        // bts, set the bit
        result = valuedst | (1ULL << bitoffs);
    }
    else if (Aux == 1)
    {
        // btr, reset the bit
        result = valuedst & ~(1ULL << bitoffs);
    }
    else if (Aux == 2)
    {
        // btc, complement bit
        result = valuedst ^ (1ULL << bitoffs);
    }
    else
    {
        // bt, do nothing
        result = valuedst;
    }

    // store the result in source & destination
    if (Aux <= 2)
    {
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dst.Address, dst.Type, dst.Size, (CX_VOID*)&result, TRUE);
        if (! NT_SUCCESS(status))
        {
            return status;
        }
    }

    ND_SET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_CF, c);

    return CX_STATUS_SUCCESS;
}



///
/// SETcc emulation
///
/// Emulates SETcc instructions.
/// Aux is the condition code to be tested (low nibble of the instruction).
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   If LOCK prefix is present and the destination operand is not in memory.
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_XXX                          On any other error.
///
static
NTSTATUS
_NdEmuHandlerSet(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )

{
    NTSTATUS status;
    CX_UINT64 result;
    EMU_OPERAND op = {0};

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // SETcc doesn't support LOCK.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    if (_NdEmuEvalCondition(Vcpu, Instrux, (CX_UINT8)Aux))
    {
        result = 1;
    }
    else
    {
        result = 0;
    }

    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, (CX_VOID*)&result, TRUE);
    if (! NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief IN / OUT instruction emulation
///
/// Emulates I/O instructions: IN, INSB, INSW, INSD, OUT, OUTSB, OUTSW, OUTSD.
/// Aux is:
///  - 0 -> IN
///  - 1 -> OUT
///
/// NOTE: This function supports the REP prefix as well.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerInOut(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
)
{
    NTSTATUS status;
    QWORD valuesrc, valuedst, result;
    EMU_OPERAND dst = { 0 }, src = { 0 };
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;
    QWORD rsi, rdi, rcx;

    valuesrc = valuedst = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // LOCK is not allowed.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // CPL must be less than or equal to the IOPL in RFLAGS.
    if ((NdVcpuRing(Vcpu) > ((Vcpu->ArchRegs.RFLAGS & RFLAGS_IOPL) >> 12)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        /// TODO: Validate the I/O Bitmap in the TSS!!

        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Get destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dst);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Get source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dst, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get destination value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, NULL, Gpa, dst.Address, dst.Type, dst.Size, (PVOID)&valuedst, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Get source value
    status = _NdEmuGetOperandValue(Vcpu, Instrux, NULL, Gpa, src.Address, src.Type, src.Size, (PVOID)&valuesrc, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    rcx = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RCX);
    rsi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RSI);
    rdi = ND_TRIM_ADDR(Instrux->AddrMode, Vcpu->ArchRegs.RDI);

    // We need to handle rep prefix as well
    for (;;)
    {
        if (Aux == 0)
        {
            // IN
            if (dst.Size == 1)
            {
                if (Context == NULL)
                {
                    BYTE res = __inbyte((WORD)valuesrc);
                    result = res;
                }
                else
                {
                    iface->ReadIoPort(Vcpu, Context, (WORD)valuesrc, 1, (CX_UINT8*)&result);
                }
            }
            else if (dst.Size == 2)
            {
                if (Context == NULL)
                {
                    WORD res = __inword((WORD)valuesrc);
                    result = res;
                }
                else
                {
                    iface->ReadIoPort(Vcpu, Context, (WORD)valuesrc, 2, (CX_UINT8*)&result);
                }
            }
            else
            {
                if (Context == NULL)
                {
                    DWORD res = __indword((WORD)valuesrc);
                    result = res;
                }
                else
                {
                    iface->ReadIoPort(Vcpu, Context, (WORD)valuesrc, 4, (CX_UINT8*)&result);
                }
            }
        }
        else
        {
            // OUT
            if (src.Size == 1)
            {
                if (Context == NULL)
                {
                    __outbyte((WORD)valuedst, (BYTE)valuesrc);
                }
                else
                {
                    iface->WriteIoPort(Vcpu, Context, (WORD)valuedst, 1, (CX_UINT8*)&valuesrc);
                }
            }
            else if (src.Size == 2)
            {
                if (Context == NULL)
                {
                    __outword((WORD)valuedst, (WORD)valuesrc);
                }
                else
                {
                    iface->WriteIoPort(Vcpu, Context, (WORD)valuedst, 2, (CX_UINT8*)&valuesrc);
                }
            }
            else
            {
                if (Context == NULL)
                {
                    __outdword((WORD)valuedst, (DWORD)valuesrc);
                }
                else
                {
                    iface->WriteIoPort(Vcpu, Context, (WORD)valuedst, 4, (CX_UINT8*)&valuesrc);
                }
            }
        }

        // store the result in source & destination
        if (Aux == 0)
        {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
            status = _NdValidateOperand(Vcpu, Instrux, &dst, TRUE);
            if (!NT_SUCCESS(status))
            {
                ERROR("[ERROR] _NdValidateOperand failed!\n");
                return status;
            }
#endif

            status = _NdEmuSetOperandValue(Vcpu, Instrux, NULL, Gpa, dst.Address, dst.Type, dst.Size, (PVOID)&result, TRUE);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        if ((0 == Aux) && (ND_INS_INS == Instrux->Instruction))
        {
            // ins, advance rdi with the size of the operand and decrement rcx
            if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
            {
                rdi += dst.Size;
                Gpa = Gpa + dst.Size;
                dst.Address += dst.Size;
                dst.Gva += dst.Size;
            }
            else
            {
                rdi -= dst.Size;
                Gpa = Gpa - dst.Size;
                dst.Address -= dst.Size;
                dst.Gva -= dst.Size;
            }
        }

        if ((1 == Aux) && (ND_INS_OUTS == Instrux->Instruction))
        {
            // outs, advance rsi with the size of the operand
            if (ND_GET_FLAG(Vcpu->ArchRegs.RFLAGS, ND_EFLAG_DF) == 0)
            {
                rsi += src.Size;
                Gpa = Gpa + src.Size;
                src.Address += src.Size;
                src.Gva += src.Size;
            }
            else
            {
                rsi -= src.Size;
                Gpa = Gpa - src.Size;
                src.Address -= src.Size;
                src.Gva -= src.Size;
            }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
            status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE);
            if (!NT_SUCCESS(status))
            {
                ERROR("[ERROR] _NdValidateOperand failed!\n");
                return status;
            }
#endif

            // fetch the next operand
            status = _NdEmuGetOperandValue(Vcpu, Instrux, NULL, Gpa, src.Address, src.Type, src.Size, (PVOID)&valuesrc, TRUE);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        if (Instrux->Rep != ND_PREFIX_G1_REPE_REPZ)
        {
            // no rep, leave
            break;
        }

        rcx--;

        if (rcx == 0)
        {
            break;
        }
    }

    if (Instrux->Rep != 0)
    {
        if (Instrux->AddrMode == ND_ADDR_16)
        {
            Vcpu->ArchRegs.CX = (WORD)rcx;
            Vcpu->ArchRegs.SI = (WORD)rsi;
            Vcpu->ArchRegs.DI = (WORD)rdi;
        }
        else
        {
            Vcpu->ArchRegs.RCX = rcx & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
            Vcpu->ArchRegs.RSI = rsi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
            Vcpu->ArchRegs.RDI = rdi & (Instrux->AddrMode == ND_ADDR_32 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF);
        }
    }

    return CX_STATUS_SUCCESS;
}

///
/// @brief MSR read / write instruction emulation
///
/// Emulates RDMSR & WRMSR instructions.
/// Aux is:
///  - 0 -> RDMSR
///  - 1 -> WRMSR
///
/// NOTE: This function can handle both MSRs that must be written/read from the VMCS and MSRs that
/// must be handled bare-metal!
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerRdWrMsr(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    CX_UINT32 msr;
    CX_UINT64  msrValue, i;
    BOOLEAN found;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

#define MSR_COUNT 7
    static const CX_UINT32 cMsrs[MSR_COUNT] =
    {
        MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_RIP, MSR_IA32_SYSENTER_RSP, MSR_IA32_DEBUGCTL,
        MSR_IA32_PERF_GLOBAL_CTRL, MSR_IA32_PAT, MSR_IA32_EFER,
    };

    static const CX_UINT32 cVmcsMsrs[MSR_COUNT] =
    {
        VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_RIP, VMCS_GUEST_IA32_SYSENTER_RSP, VMCS_GUEST_IA32_DEBUGCTL,
        VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, VMCS_GUEST_IA32_PAT, VMCS_GUEST_IA32_EFER,
    };

    UNREFERENCED_PARAMETER(Vcpu);
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);

    msr = Vcpu->ArchRegs.RCX & 0xFFFFFFFF;
    msrValue = 0;
    found = FALSE;

    if ((0 != NdVcpuRing(Vcpu)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if (Aux == 0)
    {
        // RDMSR, return the msr indicated by ecx
        for (i = 0; i < MSR_COUNT; i++)
        {
            if (cMsrs[i] == msr)
            {
                iface->VmxRead(Vcpu, cVmcsMsrs[i], &msrValue);
                found = TRUE;
                break;
            }
        }

        if (! found)
        {
            msrValue = __readmsr(msr);
        }

        Vcpu->ArchRegs.RAX = Vcpu->ArchRegs.RDX = 0;

        // put high 32 bit in edx, low 32 bit in eax
        Vcpu->ArchRegs.RDX = msrValue >> 32;
        Vcpu->ArchRegs.RAX = msrValue & 0xFFFFFFFF;
    }
    else
    {
        // WRMSR, write the value in edx:eax in MSR indicated by ecx
        msrValue = ((Vcpu->ArchRegs.RDX & 0xFFFFFFFF) << 32) | (Vcpu->ArchRegs.RAX & 0xFFFFFFFF);

        for (i = 0; i < MSR_COUNT; i++)
        {
            if (cMsrs[i] == msr)
            {
                if (0 != iface->VmxWrite(Vcpu, cVmcsMsrs[i], msrValue))
                {
                    ERROR("Write has failed!\n");
                    return CX_STATUS_UNEXPECTED_IO_ERROR;
                }

                found = TRUE;
                break;
            }
        }

        if (! found)
        {
            __writemsr(msr, msrValue);
        }
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief CPUID instruction emulation
///
///
/// Emulates CPUID instruction.
/// Aux is ignored.
///
/// NOTE: This function only supports bare-metal handling of the CPUID instruction!
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerCpuid(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    int regs[4] = {0};

    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Aux);

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // Generate #UD if the LOCK prefix is being used.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    __cpuidex(regs, (CX_UINT32)Vcpu->ArchRegs.RAX, (CX_UINT32)Vcpu->ArchRegs.RCX);

    //
    // Intel 3-198 Vol. 2A, CPUID-CPU Identification: On Intel 64 processors, CPUID
    // clears the high 32 bits of the RAX/RBX/RCX/RDX registers in all modes.
    //
    Vcpu->ArchRegs.RAX = regs[0];
    Vcpu->ArchRegs.RBX = regs[1];
    Vcpu->ArchRegs.RCX = regs[2];
    Vcpu->ArchRegs.RDX = regs[3];

    return CX_STATUS_SUCCESS;
}



///
/// @brief INVD instruction emulation
///
///
/// Emulates INVD instruction. It is emulated separatly, it doesn't come through this emulator
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerInvd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Vcpu);
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Aux);

    return CX_STATUS_OPERATION_NOT_SUPPORTED;
}



///
/// @brief WBINVD instruction emulation
///
/// Emulates WBINVD instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerWbInvd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Vcpu);
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Aux);

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // Generate #GP(0) if ring is not 0.
    if ((0 != NdVcpuRing(Vcpu)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Generate #UD if the LOCK prefix is used.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Inject #GP(0) if Vcpu is in V8086 mode.
    if (ND_MODE_V8086 == NdVcpuMode(Vcpu))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    __wbinvd();

    return CX_STATUS_SUCCESS;
}



///
/// @brief INVLPG instruction emulation
///
/// Emulates INVLPG instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerInvlpg(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    EMU_OPERAND op = {0};

    UNREFERENCED_PARAMETER(Aux);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Context);

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // Generate #GP(0) if the current CPL is not 0.
    if ((0 != NdVcpuRing(Vcpu)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Generate #UD if the operand is register or if LOCK prefix is used.
    // INVLPG has only one operand so this should not be a problem
    if (ND_OP_REG == Instrux->Operands[0].Type || Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Generate #GP(0) if we are in V8086 mode.
    if (ND_MODE_V8086 == NdVcpuMode(Vcpu))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = CpuVmxInvVpid(1, (CX_VOID*)op.Address, Vcpu->Vpid);

    return CX_STATUS_SUCCESS;
}


///
/// @brief LGDT instruction emulation
///
/// Handles LGDT instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerLgdt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 qwGdtBase;
    CX_UINT64 wGdtLimit;
    EMU_OPERAND op = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // Pre-init
    qwGdtBase = 0;
    wGdtLimit = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // Inject #UD if the LOCK prefix is being used.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Inject #GP(0) if the current privilege level is not 0.
    if ((0 != NdVcpuRing(Vcpu)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Inject #UD if the source operand is not a memory location.
    // LGDT has only one operand, so Operands[0] should be what we want
    if (ND_OP_MEM != Instrux->Operands[0].Type)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Fetch source operand, which contains a linear address to the GDT limit:base.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Read the limit of the GDT
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, sizeof(CX_UINT16), (CX_VOID*)&wGdtLimit, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Read the base of the GDT
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address + sizeof(CX_UINT16), op.Type,
                                  op.Size - sizeof(CX_UINT16), (CX_VOID*)&qwGdtBase, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Load the new GDT inside the VMCS
    if (0 != iface->VmxWrite(Vcpu, VMCS_GUEST_GDTR_LIMIT, wGdtLimit))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    if (0 != iface->VmxWrite(Vcpu, VMCS_GUEST_GDTR_BASE, qwGdtBase))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief LIDT instruction emulation
///
/// Handles LIDT instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerLidt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 qwIdtBase;
    CX_UINT64 wIdtLimit;
    EMU_OPERAND op = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // Pre-init
    qwIdtBase = 0;
    wIdtLimit = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // Inject #UD if the LOCK prefix is being used.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Inject #GP(0) if the current privilege level is not 0.
    if ((0 != NdVcpuRing(Vcpu)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Inject #UD if the source operand is not a memory location.
    if (ND_OP_MEM != Instrux->Operands[0].Type)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Fetch source operand, which contains a linear address to the IDT limit:base.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        ERROR("_NdEmuGetOperandEx failed: 0x%08x\n", status);
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif


    // Read the limit of the IDT
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, sizeof(CX_UINT16), (CX_VOID*)&wIdtLimit, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("_NdEmuGetOperandValue failed: 0x%08x\n", status);
        return status;
    }

    // Read the base of the IDT
    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address + sizeof(CX_UINT16), op.Type,
                                  op.Size - sizeof(CX_UINT16), (CX_VOID*)&qwIdtBase, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("_NdEmuGetOperandValue failed: 0x%08x\n", status);
        return status;
    }

    // Load the new GDT inside the VMCS
    if (0 != iface->VmxWrite(Vcpu, VMCS_GUEST_IDTR_LIMIT, wIdtLimit))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }
    if (0 != iface->VmxWrite(Vcpu, VMCS_GUEST_IDTR_BASE, qwIdtBase))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief SGDT instruction emulation
///
/// Handles SGDT instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerSgdt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 qwGdtBase;
    CX_UINT64 wGdtLimit;
    CX_UINT8 value[10] = {0};
    EMU_OPERAND op = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // Pre-init
    qwGdtBase = 0;
    wGdtLimit = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if ((0 != (Vcpu->ArchRegs.CR4 & CR4_UMIP)) && (NdVcpuRing(Vcpu) > 0))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if (ND_OP_MEM != Instrux->Operands[0].Type)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Fetch source operand, which contains a linear address to the GDT limit:base.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get the GDT from the VMCS
    iface->VmxRead(Vcpu, VMCS_GUEST_GDTR_LIMIT, &wGdtLimit);
    iface->VmxRead(Vcpu, VMCS_GUEST_GDTR_BASE, &qwGdtBase);

    *(CX_UINT16*)(value) = (CX_UINT16)wGdtLimit;
    *(CX_UINT64*)(value + 2) = qwGdtBase;

    // Store the GDT descriptor.
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, (CX_VOID*)value, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief SIDT instruction emulation
///
/// Handles SIDT instruction.
/// Aux is ignored.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerSidt(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;
    CX_UINT64 qwIdtBase;
    CX_UINT64 wIdtLimit;
    CX_UINT8 value[10] = {0};
    EMU_OPERAND op = {0};
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // Pre-init
    qwIdtBase = 0;
    wIdtLimit = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if ((0 != (Vcpu->ArchRegs.CR4 & CR4_UMIP)) && (NdVcpuRing(Vcpu) > 0))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if (ND_OP_MEM != Instrux->Operands[0].Type)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif


    // Fetch source operand, which contains a linear address to the IDT limit:base.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get the IDT from the VMCS
    iface->VmxRead(Vcpu, VMCS_GUEST_IDTR_LIMIT, &wIdtLimit);
    iface->VmxRead(Vcpu, VMCS_GUEST_IDTR_BASE, &qwIdtBase);

    *(CX_UINT16*)(value) = (CX_UINT16)wIdtLimit;
    *(CX_UINT64*)(value + 2) = qwIdtBase;

    // Store de IDT descriptor.
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, (CX_VOID*)value, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief CLI/STI instruction emulation
///
/// Will set or clear the IF (Interrupt enable flag) in RFLAGS.
/// Aux is:
///  - 0 -> CLI
///  - 1 -> STI
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerCliSti(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    // CPL must be less than or equal to the IOPL in RFLAGS.
    if ((NdVcpuRing(Vcpu) > ((Vcpu->ArchRegs.RFLAGS & RFLAGS_IOPL) >> 12)) && (ND_MODE_REAL != NdVcpuMode(Vcpu)))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    if (Aux == 0)
    {
        Vcpu->ArchRegs.RFLAGS &= (~RFLAGS_IF);
    }
    else
    {
        Vcpu->ArchRegs.RFLAGS |= RFLAGS_IF;
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief CF instructions manipulation emulation
///
/// Will set or clear the CF (carry flag) in RFLAGS.
/// Aux is:
///  - 0 -> CMC
///  - 1 -> CLC
///  - 2 -> STC
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerCarry(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);

    if (Aux == 0)
    {
        // CMC
        Vcpu->ArchRegs.RFLAGS ^= RFLAGS_CF;
    }
    else if (Aux == 1)
    {
        // CLC
        Vcpu->ArchRegs.RFLAGS &= (~RFLAGS_CF);
    }
    else
    {
        // STC
        Vcpu->ArchRegs.RFLAGS |= RFLAGS_CF;
    }

    return CX_STATUS_SUCCESS;
}



///
/// @brief Direction Flag instructions manipulation emulation
///
/// Will set or clear the DF (directoin flag) in RFLAGS.
/// Aux is:
///  - 0 -> CLD
///  - 1 -> STD
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerDirection(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);

    if (Aux == 0)
    {
        Vcpu->ArchRegs.RFLAGS &= (~RFLAGS_DF);
    }
    else
    {
        Vcpu->ArchRegs.RFLAGS |= RFLAGS_DF;
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief Load system segment emulation
///
/// Load system segment
/// Aux tells us what segment are we loading:
///  - 0 -> LDT
///  - 1 -> TR
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerSystemSegLoad(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
)
{
    NTSTATUS status;
    QWORD selector, base, limit, ar, descriptor[2] = { 0 }, gdtBase = 0;
    QWORD gdtLimit = 0, descSize;
    EMU_OPERAND op = { 0 };
    BYTE mode;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    // Pre-init
    selector = 0;
    base = 0;
    limit = 0;
    ar = 0;
    descriptor[0] = descriptor[1] = 0;
    mode = 0;

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    mode = NdVcpuMode(Vcpu);

    // Make sure we don't have a LOCK prefix.
    if (Instrux->HasLock)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Make sure we're in PM (we can't execute LLDT/LTR in real-mode or V8086 mode.
    if ((ND_MODE_REAL == mode) || (ND_MODE_V8086 == mode))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    // Generate #GP(0) if we're not in ring 0.
    if (0 != NdVcpuRing(Vcpu))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    if (0 != (Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
    {
        // We're in 64 bit - system descriptors are 16 bytes in size.
        descSize = 16;
    }
    else
    {
        // Not 64 bit mode - system descriptors are 8 bytes in size.
        descSize = 8;
    }

    // Fetch source operand, which contains a selector to the desired segment descriptor.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, &selector, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //LOG("Cpu: %d, Aux: %d, Operand type: %p, operand size: %p, operand value: %x, selector: %x\n",
    //    Vcpu->GuestCpuIndex, Aux, op1Type, op1Size, op1Value, selector);

    // We have the selector - get the base, limit, ar from the GDT entry.
    iface->VmxRead(Vcpu, VMCS_GUEST_GDTR_BASE, &gdtBase);
    iface->VmxRead(Vcpu, VMCS_GUEST_GDTR_LIMIT, &gdtLimit);

    // Make sure the selector is well within the limits of this GDT.
    if ((selector & ~0x7) + descSize - 1 > gdtLimit)
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, (DWORD)selector, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    if ((0 == Aux) && (0 == (selector & ~0x7)))
    {
        //
        // If bits 2-15 of the source operand are 0, LDTR is marked invalid and the LLDT instruction completes silently.
        // However, all subsequent references to descriptors in the LDT (except by the LAR, VERR, VERW or LSL instructions)
        // cause a general protection exception (#GP).
        //
        base = 0;
        limit = 0;
        ar = 0x0001c000;

        goto _load;
    }

    // Fetch the descriptor. Note that we can't use get operand value functions, as this is an implicit memory
    // access (no operand).
    status = _NdEmuLoadFromLinearAddress(Vcpu, Instrux, Context, Gpa, gdtBase + (selector & ~0x7),
        &descriptor, descSize, TRUE, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Fetch the base, limit & ar.
    base = ((descriptor[0] >> 16) & 0xFFFFFF) | ((descriptor[0] >> 32) & 0xFF000000);

    if (16 == descSize)
    {
        // 64 bit, more base!!
        base = base | ((descriptor[1] & 0xFFFFFFFF) << 32);
    }

    limit = (descriptor[0] & 0xFFFF) | ((descriptor[0] >> 32) & 0xF0000);

    // Make sure the LDT is present.
    ar = ((descriptor[0] >> 40) & 0xFFFF);

    // Make sure this is a system segment.
    if (0 != (ar & 0x10))
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, (DWORD)selector, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Make sure the segment is present.
    if (0 == (ar & 0x80))
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_SEGMENT_NOT_PRESENT, (DWORD)selector, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Make sure this is a LDT descriptor (Type field must be 2).
    if ((0 == Aux) && (2 != (ar & 0xF)))
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, (DWORD)selector, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    // Make sure this is a TSS descriptor (Type must be 1, 3, 9, 11 in 32 bit mode, or 9, 11 in 64 bit mode).
    // This is because at VMEntry Controls the TSS type must be 3 (in 16 bit mode) or 11 (in 64 bit mode) (26.2.1.3 VM-Entry Control Fields),
    // but we set the Busy flag (bit 1) anyway so the type can also be 1 or 9
    if ((1 == Aux) && ((1 != (ar & 0xF)) && (3 != (ar & 0xF)) && (9 != (ar & 0xF)) && (11 != (ar & 0xF))))
    {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, (DWORD)selector, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
#else
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
    }

    if (0 != (Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
    {
        // 64 bit, TR can only be type 9 or 11.
        if ((1 == Aux) && ((9 != (ar & 0xF)) && (11 != (ar & 0xF))))
        {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, (DWORD)selector, 0);
            return STATUS_EMU_EXCEPTION_INJECTED;
#else
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
        }
    }

    if (1 == Aux)
    {
        // We have LTR, all validations succeeded, we need to mark the TSS as being busy.
        descriptor[0] |= (1ULL << 41);
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, gdtBase + (selector & ~0x7), ND_EMU_OP_MEM, descSize, descriptor, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Set Busy bit in access rights as well.
        ar |= 0x2;

        // From intel manual: Bit 15 (G).
        // - If any bit in the limit field in the range 11:0 is 0, G must be 0.
        // - If any bit in the limit field in the range 31:20 is 1, G must be 1.
        if (0xFFF != (limit & 0xFFF))
        {
            // There is at least one 0 bit, G must be zero.
            ar &= ~0x8000;
        }

        if (0 != (limit & 0xFFF00000))
        {
            // There is at least one 1 bit in the 31:20 interval.
            ar |= 0x8000;
        }
    }

_load:
    // Store the new values inside the VMCS.
    if (0 == Aux)
    {
        BOOLEAN failed = FALSE;

        // LDT loading, store the new values inside the VMCS.
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_LDTR, selector);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_LDTR_BASE, base);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_LDTR_LIMIT, limit);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_LDTR_ACCESS_RIGHTS, ar);
        if (failed)
        {
            ERROR("a vmx_vmwrite operation has failed!\n");
            return CX_STATUS_UNEXPECTED_IO_ERROR;
        }
    }
    else if (1 == Aux)
    {
        BOOLEAN failed = FALSE;

        // TR loading, store the new values inside the VMCS.
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_TR, selector);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_TR_BASE, base);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_TR_LIMIT, limit);
        failed |= iface->VmxWrite(Vcpu, VMCS_GUEST_TR_ACCESS_RIGHTS, ar);
        if (failed)
        {
            ERROR("A vmx_vmwrite operation has failed!\n");
            return CX_STATUS_UNEXPECTED_IO_ERROR;
        }
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief Store system segment emulation
///
/// Store system segment.
/// Aux tells us what segment are we storing:
///  - 0 -> LDT
///  - 1 -> TR
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
///
static
NTSTATUS
_NdEmuHandlerSystemSegStore(
    _In_ VCPU* Vcpu,
    _In_ PINSTRUX Instrux,
    _In_opt_ PVOID Context,
    _In_opt_ QWORD Gpa,
    _In_ DWORD Aux
)
{
    NTSTATUS status;
    QWORD segDesc, opSize, opValue, zero;
    DWORD opType;
    EMU_OPERAND op = { 0 };
    BYTE mode;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    UNREFERENCED_PARAMETER(Aux);

    // Pre-init
    segDesc = 0;
    opSize = 0;
    opValue = 0;
    opType = 0;
    zero = 0;
    mode = 0;


#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    mode = NdVcpuMode(Vcpu);

    // Generate #UD if LOCK is present. These checks are done in every operating mode.
    // Generate #UD if the instruction is executed in real or v8086 mode.
    if ((Instrux->HasLock) || (ND_MODE_V8086 == mode) || (ND_MODE_REAL == mode))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }

    if ((0 != (Vcpu->ArchRegs.CR4 & CR4_UMIP)) && (NdVcpuRing(Vcpu) > 0))
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_EMU_EXCEPTION_INJECTED;
    }
#endif

    // Fetch source operand, which contains a linear address to the GDT limit:base.
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed!\n");
        return status;
    }
#endif

    // Get the GDT from the VMCS
    if (1 == Aux)
    {
        iface->VmxRead(Vcpu, VMCS_GUEST_TR, &segDesc);
    }
    else
    {
        iface->VmxRead(Vcpu, VMCS_GUEST_LDTR, &segDesc);
    }

    if (opType != ND_EMU_OP_MEM)
    {
        // Store zero first. If the destination is larger (for example, 32 bits), only the lower 16 bit will be modified; the rest will be cleared.
        status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, op.Size, (PVOID)&zero, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    // Store the limit; we always store 16 bits.
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op.Address, op.Type, 2, (PVOID)&segDesc, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return CX_STATUS_SUCCESS;
}

static
NTSTATUS
_NdEmuHandler0F0100Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
// Mem: SGDT
// Reg: VMCALL, VMLAUNCH, VMRESUME, VMXOFF
{
    NTSTATUS status;

    if (Instrux->ModRm.mod != 3)
    {
        status = _NdEmuHandlerSgdt(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        switch (Instrux->ModRm.rm)
        {
        case 1: // VMCALL
        case 2: // VMLAUNCH
        case 3: // VMRESUME
        case 4: // VMXOFF
        default:
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
    }

    return status;
}


static
NTSTATUS
_NdEmuHandler0F0101Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
// Mem: SIDT
// Reg: MONITOR, MWAIT, CLAC, STAC
{
    NTSTATUS status;

    if (Instrux->ModRm.mod != 3)
    {
        status = _NdEmuHandlerSidt(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        switch (Instrux->ModRm.rm)
        {
        case 0x00: // MONITOR
        case 0x01: // MWAIT
        case 0x02: // CLAC
        case 0x03: // STAC
        default:
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
    }

    return status;
}


static
NTSTATUS
_NdEmuHandler0F0102Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
// Mem: LGDT
// Reg: XGETBV, XSETBV, VMFUNC, XEND, XTEST
{
    NTSTATUS status;

    if (Instrux->ModRm.mod != 3)
    {
        status = _NdEmuHandlerLgdt(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        switch (Instrux->ModRm.rm)
        {
        case 0: // XGETBV
        case 1: // XSETBV
        case 4: // VMFUNC
        case 5: // XEND
        case 6: // XTEST
        default:
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
    }

    return status;
}


static
NTSTATUS
_NdEmuHandler0F0103Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
// Mem: LIDT
// Reg: none
{
    NTSTATUS status;

    if (Instrux->ModRm.mod != 3)
    {
        status = _NdEmuHandlerLidt(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}


static
NTSTATUS
_NdEmuHandler0F0107Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
// Mem: INVLPG
// Reg: SWAPGS, RDTSCP
{
    NTSTATUS status;

    if (Instrux->ModRm.mod != 3)
    {
        status = _NdEmuHandlerInvlpg(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}



///
/// @brief Emulate ARPL/ MOVSXD instruction
///
/// In long mode, 0x63 encodes the MOVSXD. On modes other than the long mode, it encodes ARPL.
///
/// NOTE: ARPL is currently not supported!
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS                   On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED       Exception injected
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED   Instruction emulation not supported
static
NTSTATUS
_NdEmuHandlerArplMovsxd(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Aux);

    if (ND_CODE_64 == Instrux->DefCode)
    {
        // MOVSXD, this can be handled by the MOV emulator.
        status = _NdEmuHandlerMov(Vcpu, Instrux, Context, Gpa, 0);
    }
    else
    {
        // ARPL, not supported.
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}


static
NTSTATUS
_NdEmuHandler0F10Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
//
// Handles the 4 instructions encoded as 0x0F 0x10; Depending on the prefix, they have different functionalty.
//
{
    UNREFERENCED_PARAMETER(Aux);

    if (Instrux->EncMode != ND_ENCM_LEGACY)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    if (ND_INS_MOVUPD == Instrux->Instruction)
    {
        // 0x66 0x0F 0x10 -> MOVUPD
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
    else if (ND_INS_MOVSS == Instrux->Instruction)
    {
        // 0xF3 0x0F 0x10 -> MOVSS
        return _NdEmuHandlerMovss(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else if (ND_INS_MOVSD == Instrux->Instruction)
    {
        // 0xF2 0x0F 0x10 -> MOVSD
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
    else if (ND_INS_MOVUPS == Instrux->Instruction)
    {
        // 0x0F 0x10 -> MOVUPS
        return _NdEmuHandlerMovapsMovups(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        // Unknown
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
}


static
NTSTATUS
_NdEmuHandler0F11Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Aux);

    if (Instrux->EncMode != ND_ENCM_LEGACY)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    if (ND_INS_MOVSS == Instrux->Instruction)
    {
        return _NdEmuHandlerMovss(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else if (ND_INS_MOVUPS == Instrux->Instruction)
    {
        return _NdEmuHandlerMovapsMovups(Vcpu, Instrux, Context, Gpa, Aux);
    }
    else
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
}


///
/// @brief Emulate UD2
///
/// This function will inject a UD2 exception on vcpu that is indicated as a parameter.
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
static
NTSTATUS
_NdEmuHandlerUd2(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    UNREFERENCED_PARAMETER(Instrux);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Aux);

    VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);

    return STATUS_EMU_EXCEPTION_INJECTED;
}


///
/// @brief Emulate MOVSS instruction
///
/// Note: supports only the 128-bit Legacy SSE version:
///  - MOVSS xmm1, xmm2
///  - MOVSS xmm1, m32
///  - MOVSS xmm2/m32, xmm1
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
static
NTSTATUS
_NdEmuHandlerMovss(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    EMU_OPERAND op1 = { 0 };
    EMU_OPERAND op2 = { 0 };
    CX_UINT64 value[2] = { 0 };

    UNREFERENCED_PARAMETER(Aux);

    // MOVSS / VMOVSS(when the source operand is an XMM register and the destination is memory)
    //  DEST[31:0] <- SRC[31:0]
    //
    // MOVSS(Legacy SSE version when the source operand is memory and the destination is an XMM register)
    //  DEST[31:0] <- SRC[31:0]
    //  DEST[127:32] <- 0
    //  DEST[MAX_VL - 1:128](Unmodified)

    // Fetch the destination
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &op1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Fetch the source
    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &op2);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &op1, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &op2, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    /// TODO: check Exceptions Type 5
#endif

    // If the source operand is memory and the destination XMM register, we have to clear the upper bits.
    if ((ND_EMU_OP_REG_XMM == op1.Type) && (ND_EMU_OP_MEM == op2.Type))
    {
        _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, ND_SIZE_128BIT, &value, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, op2.Address, op2.Type, op2.Size, &value, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // DEST[31:0] <- SRC[31:0]
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, op1.Address, op1.Type, ND_SIZE_32BIT, &value, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return status;
}


//
// @brief MOVAPS / MOVUPS emulation
//
// Note: supports only the 128-bit Legacy SSE version:
//  - MOVAPS xmm1, xmm2/m128
//  - MOVAPS xmm2/m128, xmm1
///
/// @param Vcpu,           Vcpu.
/// @param Instrux,        Decoded instruction.
/// @param Context,        Device context, if any.
/// @param Gpa,            Gpa of the address where the EPT violation was generated, if this is the case.
/// @param Aux             Auxiliary parameter. Used to select specific operation.
///
/// @return CX_STATUS_SUCCESS               On success.
/// @return STATUS_EMU_EXCEPTION_INJECTED   Exception injected
static
NTSTATUS
_NdEmuHandlerMovapsMovups(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    EMU_OPERAND dest = { 0 };
    EMU_OPERAND src = { 0 };
    CX_UINT64 value[2] = { 0 };

    UNREFERENCED_PARAMETER(Aux);

    // This shouldn't be called from outside the emulator, the caller can be trusted, no need to check the parameters

    // Moves 128 bits of packed single - precision floating - point values from the source operand(second operand) to the
    // destination operand(first operand).This instruction can be used to load an XMM register from a 128 - bit memory
    // location, to store the contents of an XMM register into a 128 - bit memory location, or to move data between two
    // XMM registers.
    // 128 - bit Legacy SSE version : Bits(MAX_VL - 1:128) of the corresponding ZMM destination register remain
    // unchanged.

    // MOVAPS: When the source or destination operand is a memory operand, the operand must be aligned on a 16 - CX_UINT8
    // boundary or a general - protection exception(#GP) will be generated.To move single - precision floating point
    // values to and from unaligned memory locations, use the MOVUPS instruction.

    // MOVAPS(128 - bit load - and register - copy - form Legacy SSE version)
    //  DEST[127:0] <- SRC[127:0]
    //  DEST[MAX_VL - 1:128](Unmodified)
    //
    // (V)MOVAPS(128 - bit store - form version)
    //  DEST[127:0] <- SRC[127:0]

    // MOVUPS(128 - bit load - and register - copy - form Legacy SSE version)
    //  DEST[127:0] <- SRC[127:0]
    //  DEST[MAX_VL - 1:128](Unmodified)
    //
    // (V)MOVUPS(128 - bit store - form version)
    //  DEST[127:0] <- SRC[127:0]

    // Note in case this is extended to support VEX/EVEX: the upper bits of the destination register are zeroed!

    status = _NdEmuGetOperandEx(Vcpu, Instrux, 0, &dest);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = _NdEmuGetOperandEx(Vcpu, Instrux, 1, &src);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#ifdef ENABLE_ALL_EXCEPTION_CHECKS
    status = _NdValidateOperand(Vcpu, Instrux, &dest, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    status = _NdValidateOperand(Vcpu, Instrux, &src, FALSE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdValidateOperand failed: 0x%08x\n", status);
        return status;
    }

    /// TODO: check SSE exceptions
    if (ND_INS_MOVAPS == Instrux->Instruction)
    {
        CX_UINT64 gla = ND_EMU_OP_MEM == src.Type ? src.Gla : ND_EMU_OP_MEM == dest.Type ? dest.Gla : 0;

        status = _NdCheckSseMemoryAlignment(Vcpu, Instrux, gla, 16);
        if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdCheckSseMemoryAlignment failed for %018p: 0x%08x\n", gla, status);
            return status;
        }
    }
#endif // ENABLE_ALL_EXCEPTION_CHECKS

    status = _NdEmuGetOperandValue(Vcpu, Instrux, Context, Gpa, src.Address, src.Type, src.Size, value, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdEmuGetOperandValue failed: 0x%08x\n", status);
        return status;
    }

    // Use the source operand size so this won't touch DEST[MAX_VL - 1:128]
    status = _NdEmuSetOperandValue(Vcpu, Instrux, Context, Gpa, dest.Address, dest.Type, src.Size, value, TRUE);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] _NdEmuSetOperandValue failed: 0x%08x\n", status);
        return status;
    }

    return CX_STATUS_SUCCESS;
}


static
NTSTATUS
_NdEmuHandler0F28Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    if (Instrux->EncMode != ND_ENCM_LEGACY)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    switch (Instrux->Instruction)
    {
    case ND_INS_MOVAPS:
        return _NdEmuHandlerMovapsMovups(Vcpu, Instrux, Context, Gpa, Aux);

    default:
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
}


static
NTSTATUS
_NdEmuHandler0F29Group(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa,
    _In_ CX_UINT32 Aux
    )
{
    if (Instrux->EncMode != ND_ENCM_LEGACY)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    switch (Instrux->Instruction)
    {
    case ND_INS_MOVAPS:
        return _NdEmuHandlerMovapsMovups(Vcpu, Instrux, Context, Gpa, Aux);

    default:
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }
}



NTSTATUS
NdEmulateInstruction(
    _In_ VCPU* Vcpu,
    _In_ INSTRUX* Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_VOID* Context,
    _In_opt_ CX_UINT64 Gpa
    )
{
    NTSTATUS status;
    PEMU_HANDLER pHandler;
    CX_UINT64 exitQual = 0, exitReason = 0;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    BOOLEAN add = TRUE;

    if (Vcpu == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (Instrux == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    //
    // Make sure we can emulate the instruction
    //
    if ((Instrux->OpLength > 2) || (Instrux->HasVex) || (Instrux->HasXop))
    {
        //ERROR("OpLen > 2 not supported!\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }


    if (Instrux->OpCodeBytes[0] == 0x0F)
    {
        pHandler = (PEMU_HANDLER) &gEmu2ByteLUT[Instrux->OpCodeBytes[1]];
    }
    else
    {
        pHandler = (PEMU_HANDLER) &gEmu1ByteLUT[Instrux->OpCodeBytes[0]];
    }

    // prefetch the handler entry.
    _mm_prefetch((const char*)pHandler, 0);

    // Check flags; flags may indicate to use reg field to select specific handler
    if (pHandler->Flags & ND_EMU_FLAG_CHECK_REG_FIELD)
    {
        pHandler = &gEmuRedirectionTable[pHandler->Flags & 0xFFFF][Instrux->ModRm.reg];
    }


    // Make sure a handler exists for this instruction
    if (pHandler->Handler == NULL)
    {
        //ERROR("No handler exists for this instruction!\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    // We do not support V8086 mode
    if ((Flags & ND_FLAG_V8086) != 0)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

#if 0
    CX_UINT32 i;
    // Update debug state - last emulated instructions
    if (CfgDebugTraceEmulatorEnabled)
    {
        // If we require only unique entries inside the trace
        if (CfgDebugTraceEmulatorUnique)
        {
            for (i = 0; i < EmuDebugGetTableSize(DBG_TABLE_TRACE); i++)
            {
                EMU_TRACE_ENTRY emuTraceDebugEntry;
                EmuDebugGetTraceEntry(Vcpu->GuestCpuIndex, i, &emuTraceDebugEntry, FALSE);
                if (emuTraceDebugEntry.EmulatedRip == Vcpu->ArchRegs.RIP)
                {
                    add = FALSE;
                    break;
                }
            }
        }

        if ((add) && (NULL == Context))
        {
            CX_UINT8 cpu = Vcpu->GuestCpuIndex;
            EMU_TRACE_ENTRY emuTraceDebugEntry = { 0 };
            EmuDebugGetTraceEntry(cpu, GET_LAST_ENTRY, &emuTraceDebugEntry, TRUE);

            emuTraceDebugEntry.EmulatedRip = Vcpu->ArchRegs.RIP;
            NdToText(Instrux, Vcpu->ArchRegs.RIP, 128, emuTraceDebugEntry.EmulatedDis);
            emuTraceDebugEntry.EmulatedBytes = *Instrux;
            emuTraceDebugEntry.IsValid = emuTraceDebugEntry.EmulatedRip != NULL ? TRUE : FALSE;

            if (emuTraceDebugEntry.IsValid) { EmuDebugInsertTraceEntry(Vcpu->GuestCpuIndex, &emuTraceDebugEntry); }
        }
    }

    if (CfgDebugTraceEmulatorEnabled)
    {
        if ((add) && (NULL == Context))
        {
            EMU_TRACE_ENTRY emuTraceDebugEntry = { 0 };
            EmuDebugGetTraceEntry(Vcpu->GuestCpuIndex, GET_LAST_ENTRY, &emuTraceDebugEntry, TRUE);

            emuTraceDebugEntry.EmulatedContextBefore = Vcpu->ArchRegs;
            emuTraceDebugEntry.IsValid = emuTraceDebugEntry.EmulatedRip != NULL ? TRUE : FALSE;

            if (emuTraceDebugEntry.IsValid) { EmuDebugInsertTraceEntry(Vcpu->GuestCpuIndex, &emuTraceDebugEntry); }
        }
    }
#endif

    iface->VmxRead(Vcpu, VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    iface->VmxRead(Vcpu, VMCS_VM_EXIT_REASON, &exitReason);

    // This was an execution attempt, we need to handle XD bit & marking the RIP PT accessed.
    if ((EXIT_REASON_EPT_VIOLATION == exitReason) && (0 != (exitQual & EPT_RAW_RIGHTS_X)))
    {
        CX_UINT64 csBase = 0, csLimit = 0;
        CX_UINT32 pfec, pfCode = 0;
        CX_UINT8 ring;

        iface->VmxRead(Vcpu, VMCS_GUEST_CS_BASE, &csBase);
        iface->VmxRead(Vcpu, VMCS_GUEST_CS_LIMIT, &csLimit);

        // Make sure the instruction is within the code segment.
        if (Vcpu->ArchRegs.RIP + Instrux->Length - 1 > csLimit)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            status = STATUS_EMU_EXCEPTION_INJECTED;
            goto dont_emulate;
        }

        ring = NdVcpuRing(Vcpu);

        pfec = ND_PF_P | ND_PF_IF | ((3 == ring) ? ND_PF_US : 0);

        // Mark the instruction page as being Accessed, only if the violation was due to an instruction fetch; Otherwise, the A bit
        // for the page containing the RIP would have already been set by the CPU.
        status = _NdEmuHandlerPageWalk(Vcpu, csBase + Vcpu->ArchRegs.RIP, Instrux->Length, ND_PW_SET_A, pfec, &pfCode, NULL);
        if (STATUS_EMU_PAGE_FAULT == status)
        {
#ifdef ENABLE_ALL_EXCEPTION_CHECKS
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_PAGE_FAULT, pfCode, csBase + Vcpu->ArchRegs.RIP);

                status = STATUS_EMU_EXCEPTION_INJECTED;
#else
                status = CX_STATUS_OPERATION_NOT_SUPPORTED;
#endif
                goto dont_emulate;
        }
        else if (!NT_SUCCESS(status))
        {
            ERROR("[ERROR] _NdEmuHandlerPageWalk failed: 0x%08x\n", status);
            goto dont_emulate;
        }
    }

    // re-execute instead of emulate whenever possible
    if (Vcpu->SafeToReExecute)
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    // Call the emulation handler
    status = pHandler->Handler(Vcpu, Instrux, Context, Gpa, (pHandler->Flags & 0xFFFF));

dont_emulate:

    if (CfgDebugTraceEmulatorEnabled)
    {
        if ((add) && (NULL == Context))
        {
            EMU_TRACE_ENTRY emuTraceDebugEntry = { 0 };
            EmuDebugGetTraceEntry(Vcpu->GuestCpuIndex, GET_LAST_ENTRY, &emuTraceDebugEntry, TRUE);

            emuTraceDebugEntry.EmulatedContextAfter = Vcpu->ArchRegs;
            emuTraceDebugEntry.IsValid = emuTraceDebugEntry.EmulatedRip != NULL ? TRUE : FALSE;

            if (emuTraceDebugEntry.IsValid) { EmuDebugInsertTraceEntry(Vcpu->GuestCpuIndex, &emuTraceDebugEntry); }
        }
    }

    return status;
}


NTSTATUS
NdEmuInit(
    _In_ CX_UINT32 CpuCount
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    if (CfgDebugTraceEmulatorEnabled)
    {
        LOG("About to initialize emulator trace debugger...\n");
        status = EmuDebugInit((CX_UINT8)CpuCount);
        if (!NT_SUCCESS(status))
        {
            // We should not game over the emulator entity
            // just because a debugger functionality fails.
            // Log it, disable debugger functionality and go ahead.
            ERROR("EmuDebugInit failed! You should see logs that tell you why above.\n");
            status = CX_STATUS_SUCCESS;
            CfgDebugTraceEmulatorEnabled = 0;
        }
    }

    return status;
}



static __forceinline CX_VOID
_NdLockSetBit64(
    _In_ PQWORD Address,
    _In_ CX_UINT64 Value,
    _In_ CX_UINT64 Mask
    )
{
    CX_UINT64 oldValue;

    for (;;)
    {
        if (Value & ND_PT_P)
        {
            // Only if the entry is present.

            oldValue = HvInterlockedCompareExchangeU64(Address, Value | Mask, Value);

            if (oldValue == Value)
            {
                // Exchange successful.
                break;
            }
            else
            {
                // Couldn't do it the first time, try again, but this time with the new comparand.
                Value = oldValue;
            }
        }
        else
        {
            break;
        }
    }
}



static __forceinline CX_VOID
_NdLockSetBit32(
    _In_ PDWORD Address,
    _In_ CX_UINT32 Value,
    _In_ CX_UINT32 Mask
    )
{
    CX_UINT32 oldValue;

    for (;;)
    {
        if (Value & ND_PT_P)
        {
            // Only if the entry is present.

            oldValue = HvInterlockedCompareExchangeU32(Address, Value | Mask, Value);

            if (oldValue == Value)
            {
                // Exchange successful.
                break;
            }
            else
            {
                // Couldn't do it the first time, try again, but this time with the new comparand.
                Value = oldValue;
            }
        }
        else
        {
            break;
        }
    }
}


///
/// @brief Page walk emulation
///
/// This function will emulate a page-walk, and it will set the Accessed & Dirty bits (where required)
/// for the provided virtual address.
///
/// @params Vcpu,                        Curent vcpu on which we perform page walk emulation
/// @params GuestLinearAddress,          Guest linear address which triggered page walk
/// @params AccessSize,                  Size of access; the access may cross the page boundary, case that must be handled.
/// @params Flags,                       Flags indicating what we want to do with this page/pages.
/// @params RequiredFlags,               Required access
/// @params FaultFlags,                  Contains on return the page fault flags
/// @params GuestPhysicalAddress         Guest physical address which triggered the page walk
///
/// @return STATUS_NO_MAPPING_STRUCTURES    Linear address could not be translated
/// @return STATUS_PAGE_NOT_PRESENT         Page is marked as not present in guest page tables
/// @return CX_STATUS_INVALID_PARAMETER_3   Access size is invalid (> 64 bytes)
///
/// TODO: Check for reserved bits set in paging structures. However, this is tricky, because if a future processor
/// will not have reserved bits in a zone, we might inject unexpected #PFs inside the guest.
///
static NTSTATUS
_NdEmuHandlerPageWalk(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 GuestLinearAddress,
    _In_ CX_UINT64 AccessSize,
    _In_ CX_UINT32 Flags,
    _In_ CX_UINT32 RequiredFlags,
    __out_opt CX_UINT32 *FaultFlags,
    __out_opt CX_UINT64 *GuestPhysicalAddress
    )
{
    NTSTATUS status;
    CX_UINT64 gpa, efer = 0;
    CX_UINT32 pageSize, pfec;
    BOOLEAN accessed, dirty, dirtyifaa, pf, userTranslation,
        execTranslation, writeTranslation, accsTranslation, suppressEx;
    BOOLEAN reqWrite, reqExecute, reqUser, smepActive, smapActive,
        acActive, implicitSmAccess, explicitSmAccess, nxActive,
        pkActive, ia32e, wpActive;
    CX_UINT8 ring, pk;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    // pre-init
    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-
    gpa = 0;
    pageSize = 0; // can be 4K, 2M, 4M, 1G
    pfec = 0; // page fault error code
    pf = FALSE;
    smepActive = smapActive = FALSE;
    userTranslation = execTranslation = writeTranslation = accsTranslation = FALSE;
    implicitSmAccess = explicitSmAccess = FALSE;
    wpActive = acActive = pkActive = ia32e = FALSE;
    ring = pk = 0;


    if (0 == AccessSize)
    {
        // LEA instruction, not an actual memory-access, but an address generation.
        return CX_STATUS_SUCCESS;
    }

    if (AccessSize > 64)
    {
        // The maximum size - ZMM registers (future AVX512 extensions)
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    // Init stuff.
    accessed = 0 != (Flags & ND_PW_SET_A);
    dirty = 0 != (Flags & ND_PW_SET_D);
    dirtyifaa = 0 != (Flags & ND_PW_SET_D_IF_ALREADY_A);
    // This flag must be used with care! It should be used only when emulating the PW just to set the A/D bits,
    // and not as part of an instruction emulation.
    suppressEx = 0 != (Flags & ND_PW_SUPPRESS_EXCEPTION_CHECKS);

    reqWrite = 0 != (RequiredFlags & ND_PF_RW);
    reqExecute = 0 != (RequiredFlags & ND_PF_IF);
    reqUser = 0 != (RequiredFlags & ND_PF_US);

    // Write Protection is enabled if CR0.WP is set.
    wpActive = 0 != (Vcpu->ArchRegs.CR0 & CR0_WP);

    // SMEP is enabled of CR4.SMEP is set.
    smepActive = 0 != (Vcpu->ArchRegs.CR4 & CR4_SMEP);

    // SMAP is enforced if and only if the CR4.SMAP is set.
    smapActive = 0 != (Vcpu->ArchRegs.CR4 & CR4_SMAP);

    // Protection keys are active if CR4.PKE is set.
    pkActive = 0 != (Vcpu->ArchRegs.CR4 & CR4_PKE);

    // SMAP is enabled for explicit accesses only if AC is 0.
    acActive = 0 != ((Vcpu->ArchRegs.RFLAGS & RFLAGS_AC));

    iface->VmxRead(Vcpu, VMCS_GUEST_IA32_EFER, &efer);

    // IA32e mode (long mode)
    ia32e = 0 != (efer & EFER_LMA);

    // NX/XD is active if bit 11 in EFER is set.
    nxActive = 0 != (efer & EFER_XD_ENABLE);


    // A page is accessible from CPL 3 if and only if all the page table entries are marked as being
    // User accessible (bit 2 set).
    userTranslation = TRUE;

    // A page is writable if the R/W bit is 1 in every paging structure that controls the translation.
    writeTranslation = TRUE;

    // A page is executable if the XD bit is 0 in every paging structure controlling the translation.
    execTranslation = TRUE;

    // Assume the translation is accessed.
    accsTranslation = TRUE;

    // Get the current privilege level.
    ring = NdVcpuRing(Vcpu);

    // Check if this memory access is a supervisory access. A memory access can be explicit or implicit.
    // Explicit accesses are supervisory if ring != 3. Some implicit memory accesses are supervisory by
    // default; these are: accesses to the global descriptor table (GDT) or local descriptor table (LDT)
    // to load a segment descriptor; accesses to the interrupt descriptor table (IDT) when delivering an
    // interrupt or exception; and accesses to the task-state segment (TSS) as part of a task switch or
    // change of CPL
    implicitSmAccess = (Flags & ND_PW_IMPLICIT_SUPER_ACCESS);

    explicitSmAccess = ((ring != 3) && (0 == (Flags & ND_PW_IMPLICIT_SUPER_ACCESS)));


    // Macros used to test for access rights - they care called for each paging mode.
#define IS_USER_FAULT   (!suppressEx && reqUser && !userTranslation && !implicitSmAccess)

#define IS_NX_FAULT     (!suppressEx && reqExecute && !execTranslation && nxActive)

#define IS_WRITE_FAULT  (!suppressEx && reqWrite && !writeTranslation && ((3 == ring) || wpActive))

#define IS_SMAP_FAULT   (!suppressEx && ((smapActive && userTranslation && !reqExecute && implicitSmAccess) ||         \
                         (smapActive && userTranslation && !reqExecute && explicitSmAccess && !acActive)))

#define IS_SMEP_FAULT   (!suppressEx && smepActive && userTranslation  && reqExecute && (3 != ring))

#define IS_PK_FAULT(pk) (!suppressEx && pkActive && ia32e && userTranslation &&                                        \
                         (((0 != (CpuGetPkru() & (1ULL << ((pk) * 2)))) ||                                             \
                           (0 != (CpuGetPkru() & (1ULL << ((pk) * 2 + 1)))) && reqWrite && ((3 == ring) || wpActive))))


    if (CfgDebugTraceEmulatorEnabled)
    {
        EMU_TLB_ENTRY emuTlbDebugEntry = { 0 };

        emuTlbDebugEntry.Cpu = HvGetCurrentCpuIndex();
        emuTlbDebugEntry.Flags = Flags;
        emuTlbDebugEntry.RequiredFlags = RequiredFlags;
        emuTlbDebugEntry.Gva = GuestLinearAddress;
        emuTlbDebugEntry.Size = (CX_UINT32)AccessSize;
        emuTlbDebugEntry.IsValid = emuTlbDebugEntry.Gva != NULL ? TRUE : FALSE;

        if (emuTlbDebugEntry.IsValid) { EmuDebugInsertTlbEntry(&emuTlbDebugEntry); }
    }

    ///LOG("Emulating PageWalk for GLA %018p, PFEC 0x%x\n", GuestLinearAddress, RequiredFlags);

    //
    // According to Intel, Vol. 3A 4-39, "Paging": bits 52-63 from every paging structure are ignored.
    // According to Intel, Vol. 3A 4-7, "Paging": CPUID.80000008H:EAX[7:0] reports the physical-address width supported by
    // the processor. (For processors that do not support CPUID function 80000008H,
    // the width is generally 36 if CPUID.01H:EDX.PAE [bit 6] = 1 and 32 otherwise.)
    // This width is referred to as MAXPHYADDR. MAXPHYADDR is at most 52. Therefore, any physical address
    // will not exceed 52 bit in width.
    //
    if (0 != (Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
    {
        PQWORD pml4, pdp, pd, pt;
        CX_UINT64 pdpAddr, pdAddr, ptAddr, pfAddr, pageAddr, pageFlags;
        CX_UINT32 pml4Index, pdpIndex, pdIndex, ptIndex;

        // 64 bit guest, LMA = 1; use CR3 to get and map PML4, PDP, PD and PT tables
        pml4 = NULL;
        pdp = NULL;
        pd = NULL;
        pt = NULL;
        pdpAddr = pdAddr = ptAddr = pfAddr = pageAddr = 0;
        pageFlags = 0;

        // Get the indexes inside the paging structures
        pml4Index = ((CX_UINT64)GuestLinearAddress >> (9 + 9 + 9 + 12)) & 0x1ff;
        pdpIndex = ((CX_UINT64)GuestLinearAddress >> (9 + 9 + 12)) & 0x1ff;
        pdIndex = ((CX_UINT64)GuestLinearAddress >> (9 + 12)) & 0x1ff;
        ptIndex = ((CX_UINT64)GuestLinearAddress >> (12)) & 0x1ff;

        // Map PML4. CR3 must be cleared, as it may contain caching or PCID in the lower 12 bits.
        status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(Vcpu->ArchRegs.CR3), 1, &pml4);
        if (!SUCCESS(status))
        {
            LOG("ERROR: MapPhysicalMemoryCache failed for CR3 %018p (can't get PML4)\n", Vcpu->ArchRegs.CR3);
            goto cleanup_64;
        }

        // get PDP address from PML4
        pdpAddr = pml4[pml4Index];
        if (0 == (pdpAddr & ND_PT_P))
        {
            pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        // Check for reserved bits set.
        if (!suppressEx && !nxActive && (0 != (pdpAddr & ND_PT_XD)))
        {
            pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                   (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        userTranslation = userTranslation && (pdpAddr & ND_PT_U);
        writeTranslation = writeTranslation && (pdpAddr & ND_PT_W);
        execTranslation = execTranslation && (0 == (pdpAddr & ND_PT_XD));
        accsTranslation = accsTranslation && (pdpAddr & ND_PT_A);

        // Map PDP
        status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(pdpAddr), 1, &pdp);
        if (!SUCCESS(status))
        {
            LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PDP)\n", pdpAddr);
            goto cleanup_64;
        }

        // Get PD address
        pdAddr = pdp[pdpIndex];
        if (0 == (pdAddr & ND_PT_P))
        {
            pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        // Check for reserved bits set.
        if (!suppressEx && !nxActive && (0 != (pdAddr & ND_PT_XD)))
        {
            pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                   (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }


        userTranslation = userTranslation && (pdAddr & ND_PT_U);
        writeTranslation = writeTranslation && (pdAddr & ND_PT_W);
        execTranslation = execTranslation && (0 == (pdAddr & ND_PT_XD));
        accsTranslation = accsTranslation && (pdAddr & ND_PT_A);

        // Check if this is a huge, 1G page
        if (0 != (pdAddr & ND_PT_PS))
        {
            pageFlags = pdAddr;

            pageAddr = (pdAddr & CpuGetMaxPhysicalAddress() & 0xffffffffc0000000) | (GuestLinearAddress & 0x3fffffff);

            pageSize = PAGE_SIZE_1G;

            goto using_1g_page;
        }

        // Map PD
        status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(pdAddr), 1, &pd);
        if (!SUCCESS(status))
        {
            LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PD)\n", pdAddr);
            goto cleanup_64;
        }

        // Get PT address
        ptAddr = pd[pdIndex];
        if (0 == (ptAddr & ND_PT_P))
        {
            pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        // Check for reserved bits set.
        if (!suppressEx && !nxActive && (0 != (ptAddr & ND_PT_XD)))
        {
            pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                   (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        userTranslation = userTranslation && (ptAddr & ND_PT_U);
        writeTranslation = writeTranslation && (ptAddr & ND_PT_W);
        execTranslation = execTranslation && (0 == (ptAddr & ND_PT_XD));
        accsTranslation = accsTranslation && (ptAddr & ND_PT_A);

        // is this a 2M page (is PD.PS = 1, bit 7)?
        if (0 != (ptAddr & ND_PT_PS))
        {
            pageFlags = ptAddr;

            pageAddr = (ptAddr & CpuGetMaxPhysicalAddress() & 0xffffffffffe00000) | (GuestLinearAddress & 0x1fffff);

            pageSize = PAGE_SIZE_2M;

            goto using_2m_page;
        }

        // Map PT
        status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(ptAddr), 1, &pt);
        if (!SUCCESS(status))
        {
            LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PT)\n", pt);
            goto cleanup_64;
        }

        // Get PAGE address
        pageAddr = pfAddr = pt[ptIndex];
        if (0 == (pageAddr & ND_PT_P))
        {
            pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_PAGE_NOT_PRESENT;

            goto cleanup_64;
        }

        // Check for reserved bits set.
        if (!suppressEx && !nxActive && (0 != (pageAddr & ND_PT_XD)))
        {
            pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                   (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = STATUS_NO_MAPPING_STRUCTURES;

            goto cleanup_64;
        }

        userTranslation = userTranslation && (pageAddr & ND_PT_U);
        writeTranslation = writeTranslation && (pageAddr & ND_PT_W);
        execTranslation = execTranslation && (0 == (pageAddr & ND_PT_XD));
        accsTranslation = accsTranslation && (pageAddr & ND_PT_A);

        pageFlags = pageAddr;

        pageAddr = (pageAddr & CpuGetMaxPhysicalAddress() & 0xfffffffffffff000) | (GuestLinearAddress & 0xfff);

        pageSize = PAGE_SIZE_4K;

        goto using_4k_page;

using_1g_page:
using_2m_page:
using_4k_page:

        gpa = pageAddr;

        //
        // Make paging validation, in order to make sure that we indeed have rights to access the page.
        //

        // SMEP - if we are in ring != 3, and we are trying to fetch code from a user-mode page, and SMEP is active, we
        // need to trigger a #PF.
        if (IS_SMEP_FAULT)
        {
            // Fetch from a user-mode page, in ring0, with SMEP active.
            pfec = ND_PF_P | ND_PF_IF; // Instruction fetch, Supervisor mode, Page was present.

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }

        // SMAP - if we are in ring != 3, and we are trying to access data from a user page, and SMAP is active and
        // the AC flag in RFLAGS is 0 or we have an implicit supervisory access, than we will generate a #PF.
        if (IS_SMAP_FAULT)
        {
            // Access in user mode page from ring0 with SMAP active
            pfec = ND_PF_P | (reqWrite ? ND_PF_RW : 0);

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }

        // If this is a user request, make sure the page is mapped for user mode, not for kernel mode only.
        if (IS_USER_FAULT)
        {
            // User code tried to access kernel page.
            pfec = ND_PF_P | ND_PF_US | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }

        // Make sure the access inside the entry is consistent with the rights required.
        if (IS_WRITE_FAULT)
        {
            // Write is required, bu the entry has RW bit == 0, and WP bit inside CR0 is 1. We will generate #PF.
            pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | ND_PF_RW | (reqExecute ? ND_PF_IF : 0);

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }

        // If this is an instruction fetch, make sure the page is not XD.
        if (IS_NX_FAULT)
        {
            // Fetch attempted from a no-execute page.
            pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | ND_PF_IF;

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }

        // Check for protection keys violations.
        if (IS_PK_FAULT((pageFlags & ND_PT_PK) >> 59ULL))
        {
            // Protection key violation.
            pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | ND_PF_PK;

            pf = TRUE;

            status = CX_STATUS_ACCESS_DENIED;

            goto cleanup_64;
        }


        //
        // Set Accessed bit inside the paging structures, or dirty flag inside the page table entry.
        //

        // Set A bit inside the PML4, PDP, PD, PT entries
        if (accessed)
        {
            if (NULL != pml4)
            {
                _NdLockSetBit64(&pml4[pml4Index], pdpAddr, ND_PT_A);
            }

            if (NULL != pdp)
            {
                _NdLockSetBit64(&pdp[pdpIndex], pdAddr, ND_PT_A);
            }

            if (NULL != pd)
            {
                _NdLockSetBit64(&pd[pdIndex], ptAddr, ND_PT_A);
            }

            if (NULL != pt)
            {
                _NdLockSetBit64(&pt[ptIndex], pfAddr, ND_PT_A);
            }
        }

        //
        // Now handle dirty bit.
        // Set D bit inside the PT/PD/PDP entry (depending on the page size)
        //
        if (dirty && ((!dirtyifaa) || accsTranslation))
        {
            switch (pageSize)
            {
            case PAGE_SIZE_4K:
                // 4K page.
                _NdLockSetBit64(&pt[ptIndex], pfAddr, ND_PT_D);
                break;
            case PAGE_SIZE_2M:
                // 2M page
                _NdLockSetBit64(&pd[pdIndex], ptAddr, ND_PT_D);
                break;
            case PAGE_SIZE_1G:
                // 1G page
                _NdLockSetBit64(&pdp[pdpIndex], pdAddr, ND_PT_D);
                break;
            default:
                ERROR("Invalid page size: %d\n", pageSize);
                status = CX_STATUS_OPERATION_NOT_SUPPORTED;
                break;
            }
        }

cleanup_64:
        if (NULL != pml4)
        {
            iface->UnmapPhysicalMemory(&pml4);
        }

        if (NULL != pdp)
        {
            iface->UnmapPhysicalMemory(&pdp);
        }

        if (NULL != pd)
        {
            iface->UnmapPhysicalMemory(&pd);
        }

        if (NULL != pt)
        {
            iface->UnmapPhysicalMemory(&pt);
        }

        if (pf)
        {
            status = STATUS_EMU_PAGE_FAULT;
        }
    }
    else if (0 != (Vcpu->ArchRegs.CR0 & CR0_PG))
    {
        // do we have PAE enabled?
        if (0 != (Vcpu->ArchRegs.CR4 & CR4_PAE)) // 32 bit PM, PAE
        {
            PQWORD pdpte, pd, pt;
            CX_UINT64 pdAddr, ptAddr, pfAddr, pageAddr;
            CX_UINT32 pdpIndex, pdIndex, ptIndex;
            PQWORD pdptePage = NULL;
            CX_UINT64 pdptePageAddr, pageFlags;

            // 32 bit paged guest, CR0.PG = 1
            pdpte = NULL;
            pd = NULL;
            pt = NULL;
            pdAddr = ptAddr = pfAddr = pageAddr = 0;
            pageFlags = 0;

            // Get the indexes
            pdpIndex = ((CX_UINT64)GuestLinearAddress >> (9 + 9 + 12)) & 0x3;
            pdIndex = ((CX_UINT64)GuestLinearAddress >> (9 + 12)) & 0x1ff;
            ptIndex = ((CX_UINT64)GuestLinearAddress >> (12)) & 0x1ff;

            pdptePageAddr = CLEAR_PHY_ADDR(Vcpu->ArchRegs.CR3);

            // Map PDP
            status = iface->MapPhysicalMemory(Vcpu, pdptePageAddr, 1, &pdptePage);
            if (!SUCCESS(status))
            {
                LOG("ERROR: MapPhysicalMemoryCache failed for CR3 %018p (can't get PDPTE)\n", Vcpu->ArchRegs.CR3);
                goto cleanup_32_pae;
            }

            // NOTE: we are assured that this can NOT span across multiple pages (CR3 is 0x20 aligned for 32-bit PAE paging)
            pdpte = (PQWORD)(((CX_UINT8*)pdptePage) + (Vcpu->ArchRegs.CR3 & 0xFE0));

            // get PD address
            pdAddr = pdpte[pdpIndex];    // 2 bits wide !!!
            if (0 == (pdAddr & ND_PT_P))
            {
                pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_NO_MAPPING_STRUCTURES;

                goto cleanup_32_pae;
            }

            // Map the PD.
            status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(pdAddr), 1, &pd);
            if (!SUCCESS(status))
            {
                LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PD)\n", pd);
                goto cleanup_32_pae;
            }

            // get PT address
            ptAddr = pd[pdIndex];
            if (0 == (ptAddr & ND_PT_P))
            {
                pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_NO_MAPPING_STRUCTURES;

                goto cleanup_32_pae;
            }

            // Check for reserved bits set.
            if (!suppressEx && !nxActive && (0 != (ptAddr & ND_PT_XD)))
            {
                pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                       (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_NO_MAPPING_STRUCTURES;

                goto cleanup_32_pae;
            }

            userTranslation = userTranslation && (ptAddr & ND_PT_U);
            writeTranslation = writeTranslation && (ptAddr & ND_PT_W);
            execTranslation = execTranslation && (0 == (ptAddr & ND_PT_XD));
            accsTranslation = accsTranslation && (ptAddr & ND_PT_A);

            // is this a 2M page (is PD.PS = 1, bit 7)?
            if (0 != (ptAddr & ND_PT_PS))
            {
                pageFlags = ptAddr;

                pageAddr = (ptAddr & CpuGetMaxPhysicalAddress() & 0xffffffffffe00000) | (GuestLinearAddress & 0x001fffff);

                pageSize = CX_PAGE_SIZE_2M;

                goto using_2m_page_pae;
            }

            // Map PT
            status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(ptAddr), 1, &pt);
            if (!SUCCESS(status))
            {
                LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PT)\n", pt);
                goto cleanup_32_pae;
            }

            // get PAGE address
            pageAddr = pfAddr = pt[ptIndex];
            if (0 == (pageAddr & ND_PT_P))
            {
                pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_PAGE_NOT_PRESENT;

                goto cleanup_32_pae;
            }

            // Check for reserved bits set.
            if (!suppressEx && !nxActive && (0 != (pageAddr & ND_PT_XD)))
            {
                pfec = ND_PF_P | ND_PF_RSVD | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) |
                       (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_NO_MAPPING_STRUCTURES;

                goto cleanup_32_pae;
            }

            userTranslation = userTranslation && (pageAddr & ND_PT_U);
            writeTranslation = writeTranslation && (pageAddr & ND_PT_W);
            execTranslation = execTranslation && (0 == (pageAddr & ND_PT_XD));
            accsTranslation = accsTranslation && (pageAddr & ND_PT_A);

            pageFlags = pageAddr;

            pageAddr = (pageAddr & CpuGetMaxPhysicalAddress() & 0xfffffffffffff000) | (GuestLinearAddress & 0xfff);

            pageSize = CX_PAGE_SIZE_4K;

            goto using_4k_page_pae;

using_2m_page_pae:
using_4k_page_pae:
            gpa = pageAddr;

            // SMEP - if we are in ring != 3, and we are trying to fetch code from a user-mode page, and SMEP is active, we
            // need to trigger a #PF.
            if (IS_SMEP_FAULT)
            {
                // Fetch from a user-mode page, in ring0, with SMEP active.
                pfec = ND_PF_P | ND_PF_IF; // Instruction fetch, Supervisor mode, Page was present.

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32_pae;
            }

            // SMAP - if we are in ring != 3, and we are trying to access data from a user page, and SMAP is active and
            // the AC flag in RFLAGS is 0 or we have an implicit supervisory access, than we will generate a #PF.
            if (IS_SMAP_FAULT)
            {
                // Access in user mode page from ring0 with SMAP active
                pfec = ND_PF_P | (reqWrite ? ND_PF_RW : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32_pae;
            }

            // If this is a user request, make sure the page is mapped for user mode, not for kernel mode.
            if (IS_USER_FAULT)
            {
                // User code tried to access kernel page.
                pfec = ND_PF_P | ND_PF_US | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32_pae;
            }

            // Make sure the access inside the entry is consistent with the rights required.
            if (IS_WRITE_FAULT)
            {
                // Write is required, bu the entry has RW bit == 0, and WP bit inside CR0 is 1. We will generate #PF.
                pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | ND_PF_RW | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32_pae;
            }

            // If this is an instruction fetch, make sure the page is not XD.
            if (IS_NX_FAULT)
            {
                // Fetch attempted from a no-execute page.
                pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | ND_PF_IF;

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32_pae;
            }


            //
            // Set Accessed bit inside the paging structures, or dirty flag inside the page table entry.
            //

            // Set A bit inside the PD, PT entries (PDPTE entries DO NOT have A or D bits).
            if (accessed)
            {
                if (NULL != pd)
                {
                    _NdLockSetBit64(&pd[pdIndex], ptAddr, ND_PT_A);
                }

                if (NULL != pt)
                {
                    _NdLockSetBit64(&pt[ptIndex], pfAddr, ND_PT_A);
                }
            }


            //
            // Now handle dirty bit.
            // Set D bit inside the PD/PT entry (depending on the page size)
            //
            if (dirty && ((!dirtyifaa) || accsTranslation))
            {
                switch (pageSize)
                {
                case CX_PAGE_SIZE_4K:
                    _NdLockSetBit64(&pt[ptIndex], pfAddr, ND_PT_D);
                    break;
                case CX_PAGE_SIZE_2M:
                    _NdLockSetBit64(&pd[pdIndex], ptAddr, ND_PT_D);
                    break;
                default:
                    ERROR("Invalid page size: %d\n", pageSize);
                    status = CX_STATUS_OPERATION_NOT_SUPPORTED;
                    break;
                }
            }

cleanup_32_pae:
            if (NULL != pdptePage)
            {
                iface->UnmapPhysicalMemory(&pdptePage);
            }

            if (NULL != pd)
            {
                iface->UnmapPhysicalMemory(&pd);
            }

            if (NULL != pt)
            {
                iface->UnmapPhysicalMemory(&pt);
            }

            if (pf)
            {
                status = STATUS_EMU_PAGE_FAULT;
            }
        }
        else // 32 bit PM, non-PAE
        {
            PDWORD pd, pt;
            CX_UINT32 ptAddr, pfAddr, pageAddr;
            CX_UINT32 pdIndex, ptIndex, pageFlags;

            // 32 bit paged guest, CR0.PG = 1
            pd = NULL;
            pt = NULL;
            ptAddr = pfAddr = pageAddr = 0;
            pageFlags = 0;

            // Get the indexes
            pdIndex = ((CX_UINT32)(CX_UINT64)GuestLinearAddress >> (10 + 12)) & 0x3ff;
            ptIndex = ((CX_UINT32)(CX_UINT64)GuestLinearAddress >> (12)) & 0x3ff;

            // Map PD
            status = iface->MapPhysicalMemory(Vcpu, Vcpu->ArchRegs.CR3 & 0xFFFFF000, 1, &pd);
            if (!SUCCESS(status))
            {
                LOG("ERROR: MapPhysicalMemoryCache failed for CR3 %018p (can't get PD)\n", Vcpu->ArchRegs.CR3);
                goto cleanup_32;
            }

            // Get PT address
            ptAddr = pd[pdIndex];
            if (0 == (ptAddr & ND_PT_P))
            {
                pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_NO_MAPPING_STRUCTURES;

                goto cleanup_32;
            }

            userTranslation = userTranslation && (ptAddr & ND_PT_U);
            writeTranslation = writeTranslation && (ptAddr & ND_PT_W);
            accsTranslation = accsTranslation && (ptAddr & ND_PT_A);

            // is this a 4M page (is PD.PS = 1, bit 7)?
            if (0 != (ptAddr & ND_PT_PS))
            {
                pageFlags = (CX_UINT32)ptAddr;

                // This is a special mode: bits 21:11 of the PDE entry represent the bits 42:32 of the physical address
                pageAddr = ((ptAddr & 0xffc00000) | ((ptAddr & 0x3fe000) << 19)) | (GuestLinearAddress & 0x003fffff);

                pageSize = CX_PAGE_SIZE_4M;

                goto using_4m_page;
            }

            // Map PT
            status = iface->MapPhysicalMemory(Vcpu, CLEAR_PHY_ADDR(ptAddr), 1, &pt);
            if (!SUCCESS(status))
            {
                LOG("ERROR: MapPhysicalMemoryCache failed for %018p (can't get PT)\n", pt);
                goto cleanup_32;
            }

            // get PAGE address
            pageAddr = pfAddr = pt[ptIndex];
            if (0 == (pageAddr & ND_PT_P))
            {
                pfec = (reqUser ? ND_PF_US : 0) | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = STATUS_PAGE_NOT_PRESENT;

                goto cleanup_32;
            }

            userTranslation = userTranslation && (pageAddr & ND_PT_U);
            writeTranslation = writeTranslation && (pageAddr & ND_PT_W);
            accsTranslation = accsTranslation && (pageAddr & ND_PT_A);

            pageFlags = (CX_UINT32)pageAddr;

            pageAddr = (pageAddr & CpuGetMaxPhysicalAddress() & 0xfffffffffffff000) | (GuestLinearAddress & 0xfff);

            pageSize = CX_PAGE_SIZE_4K;

            goto using_4k_page_normal;

using_4m_page:
using_4k_page_normal:

            gpa = pageAddr;

            // SMEP - if we are in ring != 3, and we are trying to fetch code from a user-mode page, and SMEP is active, we
            // need to trigger a #PF.
            if (IS_SMEP_FAULT)
            {
                // Fetch from a user-mode page, in ring0, with SMEP active.
                pfec = ND_PF_P | ND_PF_IF; // Instruction fetch, Supervisor mode, Page was present.

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32;
            }

            // SMAP - if we are in ring != 3, and we are trying to access data from a user page, and SMAP is active and
            // the AC flag in RFLAGS is 0 or we have an implicit supervisory access, than we will generate a #PF.
            if (IS_SMAP_FAULT)
            {
                // Access in user mode page from ring0 with SMAP active
                pfec = ND_PF_P | (reqWrite ? ND_PF_RW : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32;
            }

            // If this is a user request, make sure the page is mapped for user mode, not for kernel mode.
            if (IS_USER_FAULT)
            {
                // User code tried to access kernel page.
                pfec = ND_PF_P | ND_PF_US | (reqWrite ? ND_PF_RW : 0) | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32;
            }

            // Make sure the access inside the entry is consistent with the rights required.
            if (IS_WRITE_FAULT)
            {
                // Write is required, bu the entry has RW bit == 0, and WP bit inside CR0 is 1. We will generate #PF.
                pfec = ND_PF_P | (reqUser ? ND_PF_US : 0) | ND_PF_RW | (reqExecute ? ND_PF_IF : 0);

                pf = TRUE;

                status = CX_STATUS_ACCESS_DENIED;

                goto cleanup_32;
            }


            //
            // Set Accessed bit inside the paging structures, or dirty flag inside the page table entry.
            //

            // Set A bit inside the PD, PT entries (PDPTE entries DO NOT have A or D bits).
            if (accessed)
            {
                if (NULL != pd)
                {
                    _NdLockSetBit32(&pd[pdIndex], ptAddr, ND_PT_A);
                }

                if (NULL != pt)
                {
                    _NdLockSetBit32(&pt[ptIndex], pfAddr, ND_PT_A);
                }
            }


            //
            // Now handle dirty bit.
            // Set D bit inside the PD/PT entry (depending on the page size)
            //
            if (dirty && ((!dirtyifaa) || accsTranslation))
            {
                switch (pageSize)
                {
                case CX_PAGE_SIZE_4K:
                    _NdLockSetBit32(&pt[ptIndex], pfAddr, ND_PT_D);
                    break;
                case CX_PAGE_SIZE_4M:
                    _NdLockSetBit32(&pd[pdIndex], ptAddr, ND_PT_D);
                    break;
                default:
                    ERROR("Invalid page size: %d\n", pageSize);
                    status = CX_STATUS_OPERATION_NOT_SUPPORTED;
                    break;
                }
            }

cleanup_32:
            if (NULL != pd)
            {
                iface->UnmapPhysicalMemory(&pd);
            }

            if (NULL != pt)
            {
                iface->UnmapPhysicalMemory(&pt);
            }

            if (pf)
            {
                status = STATUS_EMU_PAGE_FAULT;
            }
        } // non-PAE
    }
    else if (0 != (Vcpu->ArchRegs.CR0 & CR0_PE))
    {
        // 32 bit non-paged guest, CR0.PG = 0, CR0.PE = 1
        // ==> simply use the linear address as a physical address
        gpa = GuestLinearAddress;

        status = CX_STATUS_SUCCESS;
    }
    else
    {
        // 16 bit real mode guest
        // ==> simply use the linear address as a physical address
        gpa = GuestLinearAddress;

        status = CX_STATUS_SUCCESS;
    }

    // Store the Page Fault error code in the out var.
    if (NULL != FaultFlags)
    {
        *FaultFlags = pfec;
    }

    if (NULL != GuestPhysicalAddress)
    {
        *GuestPhysicalAddress = gpa;
    }

    return status;
}



NTSTATUS
NdEmulatePageWalk(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Gla,
    _In_ CX_UINT64 Qualification
    )
{
    NTSTATUS status;
    CX_UINT64 gla = 0, exitQualification = 0;

    if (NULL == Vcpu)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    exitQualification = Qualification;
    gla = Gla;

    // Make sure the Guest Linear Address field is valid; If it is, we'll speed up the emulation by using it instead of
    // the standard instruction decoder.
    if (0 != (exitQualification & VMCS_VM_EXIT_QUALIFICATION_IS_VALID_GLA))
    {
        //
        // Get the Guest Linear Address field. According to Intel:
        // Alternatively, translation of the linear address may reference a paging-structure entry whose
        // access caused the EPT violation
        //
        if ((Vcpu->ArchRegs.RIP == Vcpu->LastPageWalkRip) &&
            (gla == Vcpu->LastPageWalkGla))
        {
            status = _NdEmuHandlerPageWalk(Vcpu,
                                          gla & PAGE_MASK, 1,
                                          ND_PW_SET_A |
                                          ND_PW_SET_D |
                                          ND_PW_SET_D_IF_ALREADY_A |
                                          ND_PW_SUPPRESS_EXCEPTION_CHECKS,
                                          ND_PF_P,
                                          NULL,
                                          NULL);
            if (!NT_SUCCESS(status) && (STATUS_EMU_PAGE_FAULT != status))
            {
                ERROR("[ERROR] _NdEmuHandlerPageWalk failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = _NdEmuHandlerPageWalk(Vcpu,
                                          gla & PAGE_MASK,
                                          1,
                                          ND_PW_SET_A | ND_PW_SUPPRESS_EXCEPTION_CHECKS,
                                          ND_PF_P,
                                          NULL,
                                          NULL);
            if (!NT_SUCCESS(status) && (STATUS_EMU_PAGE_FAULT != status))
            {
                ERROR("[ERROR] _NdEmuHandlerPageWalk failed: 0x%08x\n", status);
            }
        }

        Vcpu->LastPageWalkRip = Vcpu->ArchRegs.RIP;
        Vcpu->LastPageWalkGla = gla;
    }
    else
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}
