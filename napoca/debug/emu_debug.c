/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "debug/emu_debug.h"
#include "kernel/spinlock.h"
#include "memory/heap.h"

#define EMU_DEBUG_TABLE_TRACE_ENTRIES                   64
typedef struct _EMU_TRACE_TABLE
{
    CX_UINT32           Head;
    EMU_TRACE_ENTRY     Entries[EMU_DEBUG_TABLE_TRACE_ENTRIES];
} EMU_TRACE_TABLE;

#define EMU_DEBUG_TABLE_TLB_ENTRIES                     256
typedef struct _EMU_TLB_TABLE
{
    CX_UINT32       Head;
    EMU_TLB_ENTRY   Entries[EMU_DEBUG_TABLE_TLB_ENTRIES];
} EMU_TLB_TABLE;

typedef struct _EMU_DEBUG_GLOBAL_DATA
{
    SPINLOCK            Lock;
    CX_UINT8            NumberOfCpus;
    EMU_TLB_TABLE*      EmuTlbDebugTable;
    EMU_TRACE_TABLE*    EmuTraceDebugTable;
}EMU_DEBUG_GLOBAL_DATA;
static EMU_DEBUG_GLOBAL_DATA* EmuDebugGLobalData = CX_NULL;

/* Static functions */
static __forceinline CX_BOOL    _IsEmuDebugComponentInited(CX_VOID);
static __forceinline CX_UINT32  _GetEntryIndexFromBackInTimeNumber(_In_ CX_UINT32 BackInTimeNEntries, _In_opt_ CX_UINT8 CpuIndex, _In_ DBG_TABLE CacheMem);

STATUS
EmuDebugInit(
    _In_ CX_UINT8 CpuCount
)
{

    CX_STATUS status = HpAllocWithTag(&EmuDebugGLobalData, sizeof(EmuDebugGLobalData[0]), TAG_EMU);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTag", status);
        goto cleanup;
    }
    memzero(EmuDebugGLobalData, sizeof(EmuDebugGLobalData[0]));

    // Trace instructions are per CPU. So each cpu has a table
    EmuDebugGLobalData->NumberOfCpus = CpuCount;
    status = HpAllocWithTag(&EmuDebugGLobalData->EmuTraceDebugTable, sizeof(EmuDebugGLobalData->EmuTraceDebugTable[0]) * CpuCount, TAG_EMU);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTag", status);
        goto cleanup;
    }
    memzero(EmuDebugGLobalData->EmuTraceDebugTable, sizeof(EmuDebugGLobalData->EmuTraceDebugTable[0]) * CpuCount);

    status = HpAllocWithTag(&EmuDebugGLobalData->EmuTlbDebugTable, sizeof(EmuDebugGLobalData->EmuTlbDebugTable[0]), TAG_EMU);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTag", status);
        goto cleanup;
    }
    memzero(EmuDebugGLobalData->EmuTlbDebugTable, sizeof(EmuDebugGLobalData->EmuTlbDebugTable[0]));

    HvInitSpinLock(&EmuDebugGLobalData->Lock, "EMUTLB", CX_NULL);

cleanup:
    if (!CX_SUCCESS(status))
    {
        if (EmuDebugGLobalData)
        {
            if (EmuDebugGLobalData->EmuTlbDebugTable)       { HpFreeAndNullWithTag(&EmuDebugGLobalData->EmuTlbDebugTable, TAG_EMU); }
            if (EmuDebugGLobalData->EmuTraceDebugTable)     { HpFreeAndNullWithTag(&EmuDebugGLobalData->EmuTraceDebugTable, TAG_EMU); }

            HpFreeAndNullWithTag(&EmuDebugGLobalData, TAG_EMU);
        }
    }
    return status;
}

CX_UINT32
EmuDebugGetTableSize(
    _In_ DBG_TABLE DebugTable
)
{
    if (!_IsEmuDebugComponentInited()) { return 0; }

    switch (DebugTable)
    {
    case DBG_TABLE_TLB:     return EMU_DEBUG_TABLE_TLB_ENTRIES;
    case DBG_TABLE_TRACE:   return EMU_DEBUG_TABLE_TRACE_ENTRIES;
    default:                return 0;
    }
}

STATUS
EmuDebugInsertTlbEntry(
    _In_ EMU_TLB_ENTRY* NewTlbDebugEntry
)
{
    if (!_IsEmuDebugComponentInited()) { return CX_STATUS_NOT_INITIALIZED; }

    if (!NewTlbDebugEntry) { return CX_STATUS_INVALID_PARAMETER; }

    HvAcquireSpinLock(&EmuDebugGLobalData->Lock);

    CX_UINT32 nextEntryIndex = EmuDebugGLobalData->EmuTlbDebugTable->Head + 1;
    if (nextEntryIndex >= EMU_DEBUG_TABLE_TLB_ENTRIES) { nextEntryIndex = 0; }

    EmuDebugGLobalData->EmuTlbDebugTable->Entries[nextEntryIndex] = *NewTlbDebugEntry;
    EmuDebugGLobalData->EmuTlbDebugTable->Head = nextEntryIndex;

    HvReleaseSpinLock(&EmuDebugGLobalData->Lock);

    return CX_STATUS_SUCCESS;
}

STATUS
EmuDebugInsertTraceEntry(
    _In_ CX_UINT8           CpuIndex,
    _In_ EMU_TRACE_ENTRY*   NewTraceDebugEntry
)
{
    if (!_IsEmuDebugComponentInited()) { return CX_STATUS_NOT_INITIALIZED; }

    if (CpuIndex >= EmuDebugGLobalData->NumberOfCpus) { return CX_STATUS_INVALID_PARAMETER_1; }

    if (!NewTraceDebugEntry) { return CX_STATUS_INVALID_PARAMETER_2; }

    HvAcquireSpinLock(&EmuDebugGLobalData->Lock);

    CX_UINT32 nextEntryIndex = EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Head + 1;
    if (nextEntryIndex >= EMU_DEBUG_TABLE_TRACE_ENTRIES) { nextEntryIndex = 0; }

    EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Entries[nextEntryIndex] = *NewTraceDebugEntry;
    EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Head = nextEntryIndex;

    HvReleaseSpinLock(&EmuDebugGLobalData->Lock);

    return CX_STATUS_SUCCESS;
}

STATUS
EmuDebugGetTlbEntry(
    _In_        CX_UINT32       BackInTimeNEntries,
    _Outptr_    EMU_TLB_ENTRY*  TlbDebugEntry,
    _In_        CX_BOOL         RemoveEntryFromHistory
)
{
    if (!_IsEmuDebugComponentInited()) { return CX_STATUS_NOT_INITIALIZED; }

    if (BackInTimeNEntries >= EmuDebugGetTableSize(DBG_TABLE_TLB)) { return CX_STATUS_INVALID_PARAMETER_1; }

    if (!TlbDebugEntry) { return CX_STATUS_INVALID_PARAMETER_2; }

    if (RemoveEntryFromHistory) { return CX_STATUS_OPERATION_NOT_IMPLEMENTED; }

    HvAcquireSpinLock(&EmuDebugGLobalData->Lock);

    CX_UINT32 tableIndex = _GetEntryIndexFromBackInTimeNumber(BackInTimeNEntries, CX_NULL, DBG_TABLE_TLB);
    *TlbDebugEntry = EmuDebugGLobalData->EmuTlbDebugTable->Entries[tableIndex];

    HvReleaseSpinLock(&EmuDebugGLobalData->Lock);

    return CX_STATUS_SUCCESS;
}

STATUS
EmuDebugGetTraceEntry(
    _In_        CX_UINT8            CpuIndex,
    _In_        CX_UINT32           BackInTimeNEntries,
    _Outptr_    EMU_TRACE_ENTRY*    TraceDebugEntry,
    _In_        CX_BOOL             RemoveEntryFromHistory
)
{
    if (!_IsEmuDebugComponentInited()) { return CX_STATUS_NOT_INITIALIZED; }

    if (CpuIndex >= EmuDebugGLobalData->NumberOfCpus) { return CX_STATUS_INVALID_PARAMETER_1; }

    if (BackInTimeNEntries >= EmuDebugGetTableSize(DBG_TABLE_TRACE)) { return CX_STATUS_INVALID_PARAMETER_2; }

    if (!TraceDebugEntry) { return CX_STATUS_INVALID_PARAMETER_3; }

    if (RemoveEntryFromHistory && BackInTimeNEntries != GET_LAST_ENTRY) { return CX_STATUS_OPERATION_NOT_IMPLEMENTED; }

    HvAcquireSpinLock(&EmuDebugGLobalData->Lock);

    CX_UINT32 tableIndex = _GetEntryIndexFromBackInTimeNumber(BackInTimeNEntries, CpuIndex, DBG_TABLE_TRACE);
    *TraceDebugEntry = EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Entries[tableIndex];

    if (RemoveEntryFromHistory)
    {
        CX_INT32 integerTableIndex = (CX_INT32)tableIndex;
        if (--integerTableIndex < 0) { integerTableIndex += EMU_DEBUG_TABLE_TRACE_ENTRIES; }
        EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Head = (CX_UINT32)integerTableIndex;
    }

    HvReleaseSpinLock(&EmuDebugGLobalData->Lock);

    return CX_STATUS_SUCCESS;
}


/* Static functions */
static
__forceinline
CX_BOOL
_IsEmuDebugComponentInited(
    CX_VOID
)
{
    return EmuDebugGLobalData != CX_NULL;
}

static
__forceinline
CX_UINT32
_GetEntryIndexFromBackInTimeNumber(
    _In_        CX_UINT32   BackInTimeNEntries,
    _In_opt_    CX_UINT8    CpuIndex,
    _In_        DBG_TABLE   DebugTable
)
{
    CX_INT32 headIndex, tableSize;

    switch (DebugTable)
    {
    case DBG_TABLE_TLB:
        headIndex = EmuDebugGLobalData->EmuTlbDebugTable->Head;
        tableSize = EMU_DEBUG_TABLE_TLB_ENTRIES;
        break;

    case DBG_TABLE_TRACE:
        headIndex = EmuDebugGLobalData->EmuTraceDebugTable[CpuIndex].Head;
        tableSize = EMU_DEBUG_TABLE_TRACE_ENTRIES;
        break;

    default:
        // SHould not reach this because it's a static
        // function, we know how to call it...
        return CX_NULL;
    }

    CX_INT32 desiredEntryIndex = headIndex - BackInTimeNEntries;
    if (desiredEntryIndex < 0) { desiredEntryIndex += tableSize; }

    return (CX_UINT32)desiredEntryIndex;
}