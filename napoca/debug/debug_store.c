/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "debug/debug_store.h"
#include "common/kernel/vmxdefs.h"
#include "memory/heap.h"
#include "kernel/pcpu.h"

static CX_BOOL IsComponentInited = CX_FALSE;

#define BTS_MAX_RECORDS_COUNT       1024
#define BTS_MAX_RECORDS_SIZE        (BTS_MAX_RECORDS_COUNT * sizeof(BTS_BRANCH_RECORD))

#pragma pack(push)
#pragma pack(1)
typedef struct _BTS_BRANCH_RECORD
{
    CX_UINT64       BranchFrom;
    CX_UINT64       BranchTo;
    union
    {
        CX_UINT64   _Reserved1      :4;
        CX_UINT64   BranchPredicted :1;  // Bit 4 indicates if the branch was predicted or not.
        CX_UINT64   _Reserved2      :59;
        CX_UINT64   _Reserved3;
    };
} BTS_BRANCH_RECORD;
#pragma pack(pop)

/* Static functions */
static __forceinline CX_BOOL _IsDsAvailable(CX_VOID);
static __forceinline CX_BOOL _IsDsBtsAvailable(CX_VOID);

CX_STATUS
DbgDsInit(
    _In_ PCPU* Pcpu
    )
//
// Initializes the Debug Store & Branch Trace Storage for the current CPU.
//
{
    CX_STATUS status;

    if (!CFG_ENABLE_DEBUG_STORE) return CX_STATUS_NOT_SUPPORTED;

    if (HvGetCurrentCpu() != Pcpu) return CX_STATUS_INVALID_PARAMETER_1;

    if ((!_IsDsAvailable()) || (!_IsDsBtsAvailable())) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    // Alloc space for BTS area
    status = HpAllocWithTagCore(&Pcpu->DebugStore.BtsBufferBase, BTS_MAX_RECORDS_SIZE, ':stB');
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        return status;
    }

    // Initialize DS variables.
    Pcpu->DebugStore.BtsIndex = (CX_UINT64)Pcpu->DebugStore.BtsBufferBase;
    Pcpu->DebugStore.BtsAbsolutMaximum = Pcpu->DebugStore.BtsIndex + BTS_MAX_RECORDS_SIZE;

    // We don't want interrupts, so set a threshold outside the buffer.
    Pcpu->DebugStore.BtsInterruptThreshold = Pcpu->DebugStore.BtsAbsolutMaximum + sizeof(BTS_BRANCH_RECORD);

    // Load the newly initialzed DS area inside IA32_DS_AREA msr.
    __writemsr(0x600, (CX_UINT64)&Pcpu->DebugStore);

    // Done!
    IsComponentInited = CX_TRUE;
    return CX_STATUS_SUCCESS;
}

CX_STATUS
DbgDsUninit(
    _In_ PCPU* Pcpu
    )
{
    UNREFERENCED_PARAMETER(Pcpu);

    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

CX_STATUS
DbgDsStartBranchRecording(
    _In_ PCPU* Pcpu
    )
{
    if (!IsComponentInited) return CX_STATUS_NOT_INITIALIZED;

    if (HvGetCurrentCpu() != Pcpu) return CX_STATUS_INVALID_PARAMETER_1;

    // MSR_DEBUGCTLA is at address 0x1D9.
    // We want:
    // - LBR        (bit  0) == 1 - Use LBR to generate BTMs
    // - TR         (bit  6) == 1 - Record branches
    // - BTS        (bit  7) == 1 - Record branches in BTS
    // - BTINT      (bit  8) == 0 - No interrupts, circular buffer
    // - BTS_OFF_OS (bit  9) == 0 - Intercept branches when CPL == 0
    // - BTS_OFF_USR(bit 10) == 1 - Do not intercept branches when CPL != 0
    __writemsr(0x1D9, 0x4C1);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
DbgDsStopBranchRecording(
    _In_ PCPU* Pcpu
    )
{
    if (!IsComponentInited) return CX_STATUS_NOT_INITIALIZED;

    if (HvGetCurrentCpu() != Pcpu) return CX_STATUS_INVALID_PARAMETER_1;

    // MSR_DEBUGCTLA is at address 0x1D9.
    // We want:
    // - TR         (bit  6) == 0 - Do not Record branches
    // - BTS        (bit  7) == 0 - Record branches in BTS
    // - BTINT      (bit  8) == 0 - No interrupts, circular buffer
    // - BTS_OFF_OS (bit  9) == 0 - Intercept branches when CPL == 0
    // - BTS_OFF_USR(bit 10) == 1 - Do not intercept branches when CPL != 0
    __writemsr(0x1D9, 0x400);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
DbDsDumpBranches(
    _In_ PCPU* Pcpu
    )

{
    BTS_BRANCH_RECORD *branches;
    CX_UINT32 i, index, count;

    if (!IsComponentInited) return CX_STATUS_NOT_INITIALIZED;

    branches = (BTS_BRANCH_RECORD*)Pcpu->DebugStore.BtsBufferBase;

    count = (CX_UINT32)((Pcpu->DebugStore.BtsAbsolutMaximum - (CX_UINT64)Pcpu->DebugStore.BtsBufferBase) / sizeof(BTS_BRANCH_RECORD));

    index = (((Pcpu->DebugStore.BtsIndex - (CX_UINT64)Pcpu->DebugStore.BtsBufferBase) / sizeof(BTS_BRANCH_RECORD)) - 1) % count;

    LOG("Branch history for CPU %d (newest to oldest branches)\n", HvGetCurrentApicId());

    for (i = 0; i < count; i++)
    {
        LOG("%018p -> %018p (P:%d)\n", branches[index].BranchFrom, branches[index].BranchTo, branches[index].BranchPredicted);

        index = (index - 1) % count;
    }

    LOG("LBR stack:\n");

    for (i = 0; i < 16; i++)
    {
        LOG("%018p -> %018p\n", __readmsr(0x680 + i), __readmsr(0x6C0 + i));
    }

    return CX_STATUS_SUCCESS;
}

/* Static functions */
static
__forceinline
CX_BOOL
_IsDsAvailable(
    CX_VOID
)
{
    CX_UINT32 regs[4] = {0};

    __cpuid((int*)regs, 1);

    // CPUID function 1, EDX bit 21 tells us if DS is supported.
    return (regs[3] >> 21) & 1;
}

static
__forceinline
CX_BOOL
_IsDsBtsAvailable(
    CX_VOID
)
{
    CX_UINT64 miscEnableMsr;

    // IA32_MISC_ENABLE MSR, bit 11, must be 0 in order to support BTS.
    miscEnableMsr = __readmsr(MSR_IA32_MISC_ENABLE);

    return !((miscEnableMsr >> 11) & 1);
}
