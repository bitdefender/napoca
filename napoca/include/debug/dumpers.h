/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __DACIA_DUMPERS_H__
#define __DACIA_DUMPERS_H__

#include "coredefs.h"
#include "base/cx_sal.h"
#include "base/cx_types.h"
#include "wrappers/cx_wintypes.h"

#include "debug/interpreter.h"

typedef struct _PCPU PCPU;
typedef struct _GUEST GUEST;
typedef struct _ARCH_REGS ARCH_REGS;
typedef struct _MTRR_STATE MTRR_STATE;
typedef struct _HV_TRAP_FRAME HV_TRAP_FRAME;

typedef enum _TRACING_CONFIG
{
    TRACING_CONFIG_DISABLE              = 0,
    TRACING_CONFIG_LIST_EACH_INTRUCTION = 1,    // (default) list each instruction
    TRACING_CONFIG_BREAK                = 2,    // list and break after each instruction
    TRACING_CONFIG_SILENT               = 3,    // silent (vmexits only)
}TRACING_CONFIG;

typedef enum _DUMP_OPTION_FLAGS
{
    DBG_MEMDUMP_NO_OPTIONS          = 0,
    DBG_MEMDUMP_DISABLE_ADDR        = 1,
    DBG_MEMDUMP_DISABLE_CHARS       = 2,
    DBG_MEMDUMP_DISABLE_ALIGN       = 4,
    DBG_MEMDUMP_DISABLE_HEXSPACE    = 8,
    DBG_MEMDUMP_DISABLE_NEWLINES    = 16,
    DBG_MEMDUMP_WIDE                = 32,  // to use 32 instead of 16 chars / line

    // dump stuff as WORD/DWORD/QWORD
    DBG_MEMDUMP_WORDS               = 64,
    DBG_MEMDUMP_DWORDS              = 128,
    DBG_MEMDUMP_QWORDS              = 256,
    DBG_MEMDUMP_DISABLE_HEX         = 512,

    DBG_MEMDUMP_APICID              = 1024,  // to append the cpu id before dumped lines (useful when multiple cpu's are dumping at the same time)
    DBG_MEMDUMP_FROM_NMI_HANDLER    = 2048,

    DBG_MEMDUMP_MINIMAL             = (DBG_MEMDUMP_DISABLE_ADDR | DBG_MEMDUMP_DISABLE_CHARS | DBG_MEMDUMP_DISABLE_ALIGN | DBG_MEMDUMP_DISABLE_HEXSPACE | DBG_MEMDUMP_DISABLE_NEWLINES),
}DUMP_OPTION_FLAGS;

typedef enum _DISASM_OPTION_FLAGS
{
    DBG_DISASM_16                   = 16,
    DBG_DISASM_32                   = 32,
    DBG_DISASM_64                   = 64,
}DISASM_OPTION_FLAGS;

//////////////////////////////////////////////////
//                                              //
//                  Prototypes                  //
//                                              //
//////////////////////////////////////////////////

CX_STATUS
DumpersMemDump(
    _In_ CX_VOID    *Address,
    _In_ CX_UINT64  NumberOfBytes
);

CX_STATUS
DumpersMemDumpEx(
    _In_opt_ DUMP_OPTION_FLAGS  FormatOptions,
    _In_    CX_BOOL             IsGuestMem,
    _In_    CX_BOOL             IsVirtualAddress,
    _In_    CX_UINT32           GuestIndex,
    _In_    CX_UINT32           VcpuIndex,
    _In_    CX_SIZE_T           Address,
    _In_    CX_SIZE_T           NumberOfBytes,

    _In_opt_ DBG_PARAM_TARGETRANGE *Target  // In some cases, the memory is mapped, checked and ready to be dumped.
                                            // One of these cases is when the debugger interpreter does this.
                                            // Therefore, the interpreter prepares the DBG_PARAM_TARGETRANGE structure
                                            // that can be passed to this function.
                                            // In the other cases, the user must set to CX_NULL this parameter.
);

CX_STATUS
DumpersMemDisasm(
    _In_ CX_BOOL            IsGuestMem,
    _In_ CX_BOOL            IsVirtualAddress,
    _In_ CX_UINT32          GuestIndex,
    _In_ CX_UINT32          VcpuIndex,
    _In_ CX_SIZE_T          Address,
    _In_ CX_SIZE_T          NumberOfBytes,
    _In_ DISASM_OPTION_FLAGS Options,

    _In_opt_ DBG_PARAM_TARGETRANGE *Target  // In some cases, the memory is mapped, checked and ready to be disassembled.
                                            // One of these cases is when the debugger interpreter does this.
                                            // Therefore, the interpreter prepares the DBG_PARAM_TARGETRANGE structure
                                            // that can be passed to this function.
                                            // In the other cases, the user must set to CX_NULL this parameter.
);

#define DBG_CUSTOMTYPE_FLAGS                0xFFFF000000000000ULL   // reserved for flags
#define DBG_CUSTOMTYPE_FLAG_KV              0x8000000000000000ULL   // used for KV now
#define DBG_CUSTOMTYPE_FLAG_KVX             0x4000000000000000ULL   // used for KVX now

#define DumpersGenerateAndSendStackWalkDump(Cpu,Trap,Flags)                 DumpersGenerateAndSendStackWalkDumpEx((Cpu), (Trap), (Flags), CX_FALSE, __FILE__, __LINE__)
#define DumpersGenerateAndSendStackWalkDumpFromNmiHandler(Cpu,Trap,Flags)   DumpersGenerateAndSendStackWalkDumpEx((Cpu), (Trap), (Flags), CX_TRUE, __FILE__, __LINE__)
CX_STATUS
DumpersGenerateAndSendStackWalkDumpEx(
    _In_ PCPU            *Cpu,
    _In_ HV_TRAP_FRAME  *TrapFrame,
    _In_ CX_UINT64      Flags,
    _In_ CX_BOOL        IsFromNmiHandler,
    _In_ const CHAR     *File,
    _In_ CX_UINT64      Line
);

CX_STATUS
DumpersDumpHeapsInfo(
    CX_VOID
);

CX_VOID
DumpersLogInstruction(
    _In_ VCPU       *Vcpu,
    _In_ CX_UINT16  Cs,
    _In_ CX_UINT64  Rip
);

CX_STATUS
DumpersDumpHeapByTags(
    CX_VOID
);

CX_STATUS
DumpersDumpArchRegs(
    _In_ ARCH_REGS *ArchRegs
);

CX_STATUS
DumpersDumpHostFpuState(
    CX_VOID
);

CX_STATUS
DumpersDumpGuestFpuState(
    _In_ VCPU *Vcpu
);

CX_STATUS
DumpersDumpEptPageTablesWalk(
    _In_ VCPU      *Vcpu,
    _In_ CX_UINT64  Gpa
);

CX_VOID
DumpersDumpMTRRSate(
    _In_ MTRR_STATE *MtrrState
);

CX_VOID
DumpersDumpGlobalStats(
    _In_ CX_BOOL IncludePerVcpuStats
);

CX_VOID
DumpersDumpControlRegisters(
    _In_ CHAR *Message
);

CX_VOID
DumpersResetPeriodicTimers(
    CX_VOID
);

CX_VOID
DumpersDumpPeriodicStats(
    _In_        CX_BOOL     IncludePerVcpuStats,
    _In_opt_    CX_UINT64   DumpPeriodMicroseconds,
    _In_opt_    CX_UINT64   ResetPeriodMicroseconds
);

CX_BOOL
DumpersTryToDumpEmergencyLogs(
    CX_VOID
);

CX_STATUS
DumpersDumpMemoryLog(
    CX_VOID
);

CX_VOID
DumpersConfigureInstructionTracing(
    _In_ VCPU           *Vcpu,
    _In_ TRACING_CONFIG TracingOption
);

//////////////////////////////////////////////////
//                                              //
// Functions that prepare a string for dumping  //
//                                              //
//////////////////////////////////////////////////
CHAR*
ConvertMsrToString(
    _In_ CX_UINT64 Msr
);

CHAR*
ConvertVmxExitReasonToString(
    _In_ CX_UINT64 ExitReason
);

CHAR*
ConvertVmxInstructionErrorToString(
    _In_ CX_UINT64 ErrorNo
);

//
// MORSE beeper
//
CX_VOID
DumpersMorse64(
    _In_ CHAR *Message
);

CX_STATUS
DumpCurrentVmcs(
    DWORD DisplayedApicId
);

#endif //__DACIA_DUMPERS_H__
