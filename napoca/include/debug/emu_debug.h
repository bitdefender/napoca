/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __EMU_DEBUG_H__
#define __EMU_DEBUG_H__

#include "common/external_interface/disasm_types.h"
#include "napoca.h"
#include "bddisasm.h"

//
// This entity retain information about instruction trace, tlbs, etc.
//

typedef enum _DBG_TABLE
{
    DBG_TABLE_TLB,
    DBG_TABLE_TRACE,
}DBG_TABLE;

#define EMULATED_INSTRUCTION_DEISASSEMBLY_BUFFER_SIZE   128
typedef struct _EMU_TRACE_ENTRY
{
    CX_BOOL     IsValid;
    CX_UINT64   EmulatedRip;                                                    // holds emulated instructions RIP
    char        EmulatedDis[EMULATED_INSTRUCTION_DEISASSEMBLY_BUFFER_SIZE];     // holds emulated instructions disassembly
    INSTRUX     EmulatedBytes;                                                  // the actual instrux of the emulated instruction
    CX_UINT64   EmulatedTargetGva;                                              // the address accessed because of the emulation
    CX_UINT64   EmulatedTargetValueLoad;
    CX_UINT64   EmulatedTargetValueStore;
    CX_UINT8    EmulatedTargetSize;
    ARCH_REGS   EmulatedContextBefore;
    ARCH_REGS   EmulatedContextAfter;
}EMU_TRACE_ENTRY;

typedef struct _EMU_TLB_ENTRY
{
    CX_BOOL         IsValid;
    CX_UINT64       Gva;
    CX_UINT32       Cpu;
    CX_UINT32       Flags;
    CX_UINT32       RequiredFlags;
    CX_UINT32       Size;
} EMU_TLB_ENTRY;

STATUS              EmuDebugInit(_In_ CX_UINT8 CpuCount);

// We keep information about the last N instructions/tlbs/etc. emulated.
// To find max N, call this function.
// The function return 0 if this debug entity
// fails to initialize (or it is not initialized)
CX_UINT32           EmuDebugGetTableSize(_In_ DBG_TABLE DebugTable);

STATUS              EmuDebugInsertTlbEntry(_In_ EMU_TLB_ENTRY* NewTlbDebugEntry);
STATUS              EmuDebugInsertTraceEntry(_In_ CX_UINT8 CpuIndex, _In_ EMU_TRACE_ENTRY* NewDebugEntry);

// If BackInTimeNEntries is 0 then informations about last saved entry is returned
// If BackInTimeNEntries is 1, information about last - 1 saved entry is returned, and so on..
// The maximum value of BackInTimeNEntries can be EmuDebugGetTableSize - 1
#define GET_LAST_ENTRY  0
STATUS              EmuDebugGetTlbEntry(_In_ CX_UINT32 BackInTimeNEntries, _Outptr_ EMU_TLB_ENTRY* TlbDebugEntry, _In_ CX_BOOL RemoveEntryFromHistory);
STATUS              EmuDebugGetTraceEntry(_In_ CX_UINT8 CpuIndex, _In_ CX_UINT32 BackInTimeNEntries, _Outptr_ EMU_TRACE_ENTRY* TraceDebugEntry, _In_ CX_BOOL RemoveEntryFromHistory);

#endif //__EMU_DEBUG_H__
