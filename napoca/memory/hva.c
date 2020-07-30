/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup hva
/// @ingroup memory
/// @{

// Hypervisor Virtual Address management
#include "napoca.h"
#include "memory/hva.h"
#include "memory/mdl.h"
#include "kernel/queue_ipc.h"

#define HVA_LOGN(...)                       LOGN(__VA_ARGS__)
#define HVA_LOG(...)                        LOG(__VA_ARGS__)
#define HVA_WARNING(...)                    WARNING(__VA_ARGS__)
#define HVA_ERROR(...)                      ERROR(__VA_ARGS__)
#define HVA_LOG_FUNC_FAIL(fn, status)       LOG_FUNC_FAIL(fn, status)


static
CX_STATUS
_HvaGetTableInfoCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           TranslatedVa,
    _In_ CX_UINT8                   TableDepth,
    _In_opt_ MEM_ALIGNED_PA         TablePa,                // TAS will either know where exactly the table is located
    _In_opt_ HVA_PTE                *UpperLevelEntryVa,     // or the upper-level table entry that links to it
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *TableInfo
);

static
CX_STATUS
_HvaAlterTableEntryCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ HVA_PTE                    *TableEntry,            // where should the changes go
    _In_ CX_UINT8                   TableDepth,             // at what depth the paging structure is (the TableEntry that needs changes)
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these properties
    _In_ CX_BOOL                    IsFirstPageInRange,     // used for ContinuousPa and/or chaining deduction
    _In_ CX_BOOL                    IsLastPageInRange,      // used for chaining deduction
    _In_ MEM_ALIGNED_PA             PhysicalPage            // where should the mapping point to (ignore unless SetProperties.PageFrame)
);

static
CX_STATUS
_HvaInitializeTableCb(
    _In_ TAS_DESCRIPTOR     *Mapping,
    _In_ CX_UINT8           TableDepth,                     // 0 for the top-level structure, 1 for the next level etc
    _Out_ MEM_ALIGNED_VA    Va,                             // a valid RW mapping of the physical page
    _Out_ MEM_ALIGNED_PA    Pa                              // the PA of the allocated page
);

TAS_DESCRIPTOR gHva = {
    .PagingDepth                = HVA_PAGING_DEPTH,
    .RootPa                     = 0,
    .GetTableInfo               = _HvaGetTableInfoCb,
    .AlterTableEntry            = _HvaAlterTableEntryCb,
    .IterateTables              = HvaIterateTables,
    .AllocPagingStructure       = CX_NULL,
    .InitPagingStructure        = _HvaInitializeTableCb,
    .AllocatedPageTablesCount   = 0
    };

const HVA_PAT gStandardCompatibilityPat =
{
    HVA_CACHING_WB,
    HVA_CACHING_WT,
    HVA_CACHING_UC_, // UC-
    HVA_CACHING_UC,
    HVA_CACHING_WB,
    HVA_CACHING_WT,
    HVA_CACHING_UC_, // UC-
    HVA_CACHING_UC
};


static
CX_STATUS
_HvaGetTableInfoCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           TranslatedVa,
    _In_ CX_UINT8                   TableDepth,
    _In_opt_ MEM_ALIGNED_PA         TablePa,                // TAS will either know where exactly the table is located
    _In_ HVA_PTE                    *UpperLevelEntryVa,     // or the upper-level table entry that links to it
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *TableInfo
)
// a MAP_GET_TABLE_INFO_CB implementation for CPU PAE paging with simple offsetting of the VA/PA mapped paging structures
{
    TAS_PAGING_STRUCTURE_INFO info = { 0 };

    // these properties are always valid, the other ones must be ignored when not at a leaf node

    CX_UINT64 vaShiftAmount = HVA_PAGE_OFFSET_BITS + (HVA_TABLE_INDEX_BITS * (Mapping->PagingDepth - TableDepth - 1));
    info.Index = (((CX_UINT64)TranslatedVa) >> vaShiftAmount) & HVA_TABLE_ENTRY_MASK;
    info.HasSuccessor = info.Index < HVA_TABLE_ENTRY_MASK; // allows for optimized traversal of a VA interval (when advancing, there's no need to refresh upper-level info when we can increment this index)
    info.ValidPropertiesMask.Read = 1;
    info.ValidPropertiesMask.Write = 1;
    info.ValidPropertiesMask.PagingStructures = 1;

    info.TablePa = UpperLevelEntryVa? (CX_PAGE_SIZE_4K * UpperLevelEntryVa->PageFrame) : TablePa;

    CX_STATUS status = Mapping->GetTableVa(info.TablePa, (MEM_UNALIGNED_VA *)&info.TableVa);
    if (info.TablePa && CX_SUCCESS(status))
    {
        // directly available fields
        info.TableEntryVa = &(((HVA_PTE_RAW*)(info.TableVa))[info.Index]);
        info.NextLevelTablePa = CX_PAGE_SIZE_4K * ((HVA_PTE_RAW*)(info.TableEntryVa))->PageFrame;

        // deduce hardware-specific info (caching, access rights, HV bits)
        CX_BOOL isLeaf = (TableDepth + 1 == Mapping->PagingDepth);
        HVA_PTE_RAW pte = *((HVA_PTE_RAW*)info.TableEntryVa);

        info.Properties.Read = pte.Present;
        info.Properties.Write = !!(pte.Present && pte.Write);
        info.Properties.Execute = !!(pte.Present && ((CpuIsXdUsed() && !pte.ExecuteDisable) || !CpuIsXdUsed()));

        info.Properties.Accessed = pte.Accessed;
        info.Properties.Dirty = pte.Dirty;

        info.Properties.Chained = pte.HvChained;
        info.Properties.ChainLimit = pte.HvChainLimit;
        info.Properties.InUse = pte.HvInUse;

        info.Properties.PagingStructures = 1;
        info.Properties.PageFrame = !!pte.PageFrame;
        info.Properties.ContinuousPa = !!(IsFirstPageInRange || (PreviousPa + CX_PAGE_SIZE_4K == info.NextLevelTablePa));

        HVA_PTE_CACHING_BITS caching = HvaPteToPatIndex(&pte); // => caching is a 3-bit value (0..4)
        info.Properties.Caching = caching.Raw;

        info.Properties.CompleteChain = !!((IsFirstPageInRange && pte.HvChained && pte.HvChainLimit) ||
            (IsLastPageInRange && !pte.HvChained && pte.HvChainLimit) ||
            (!IsFirstPageInRange && !IsLastPageInRange && pte.HvChained));

        if (isLeaf)
        {
            info.ValidPropertiesMask.Raw = CX_UINT64_MAX_VALUE;
            info.EntryMappingSizeExponent = 12;
        }
        info.IsLeafTableEntry = !!isLeaf;
    }

    *TableInfo = info;
    return CX_STATUS_SUCCESS;
}


CX_STATUS
HvaIterateTables(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_PA             TablePa,
    __out_opt MEM_ALIGNED_VA        *TableVa,
    _In_ CX_UINT8                   TableDepth,
    _Inout_ MEM_TABLE_OFFSET        *TableByteIndex,
    __out_opt MEM_ALIGNED_PA        *SizeIncrement,
    __out_opt MEM_ALIGNED_PA        *NextLevelTablePa,
    __out_opt CX_BOOL               *NextLevelTableValid,
    __out_opt CX_BOOL               *IsLeaf
)
//
// Given a Table PA, decode where the next entry is and what table is linked by the current entry
// to allow TasIterateStructures to walk (both left->right and top->down) the paging structures
//
{
    if (!TablePa)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }
    if (TableDepth + 1 > Mapping->PagingDepth)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }
    if (!TableByteIndex || *TableByteIndex % sizeof(HVA_PTE))
    {
        return CX_STATUS_INVALID_PARAMETER_4;
    }
    if (*TableByteIndex > HVA_TABLE_ENTRY_MASK * sizeof(HVA_PTE))
    {
        return CX_STATUS_NO_MORE_ENTRIES;
    }

    HVA_PTE *va;
    CX_STATUS status = Mapping->GetTableVa(TablePa, (MEM_UNALIGNED_VA *)&va);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Mapping->GetTableVa", status);
        return status;
    }

    if (TableVa)
    {
        *TableVa = (MEM_UNALIGNED_VA)va;
    }

    HVA_PTE* pte = (HVA_PTE*)(((CX_UINT8*)va) + *TableByteIndex);

    // Note/todo: modify the condition of the next if statement when/if the HVA mappings are changed to make use of larger (than 4KiB) page sizes!
    if (IsLeaf) *IsLeaf = TableDepth == Mapping->PagingDepth;

    if (NextLevelTablePa)
    {
        *NextLevelTablePa = CX_PAGE_SIZE_4K * pte->PageFrame;
        if (NextLevelTableValid)
        {
            *NextLevelTableValid = !!pte->Present;
        }
    }

    if (SizeIncrement)
    {
        // last-level entries cover 2^HVA_PAGE_OFFSET_BITS and each level above adds a 2^HVA_TABLE_INDEX_BITS factor
        *SizeIncrement = 1ull << (QWORD)(HVA_TABLE_INDEX_BITS * (Mapping->PagingDepth - (1 + TableDepth)) + HVA_PAGE_OFFSET_BITS);
    }

    *TableByteIndex += sizeof(HVA_PTE);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_HvaInitializeTableCb(
    _In_ TAS_DESCRIPTOR     *Mapping,
    _In_ CX_UINT8           TableDepth,                     // 0 for the top-level structure, 1 for the next level etc
    _Out_ MEM_ALIGNED_VA    Va,                             // a valid RW mapping of the physical page
    _Out_ MEM_ALIGNED_PA    Pa                              // the PA of the allocated page
)
// Initialize a newly allocated page table such that no properties are present
{
    UNREFERENCED_PARAMETER(Pa);

    if (TableDepth + 1 == Mapping->PagingDepth && CpuIsXdUsed())
    {
        HVA_PTE *pte = (HVA_PTE*)Va;
        for (CX_UINT16 i = 0; i < (1 << HVA_TABLE_INDEX_BITS); i++)
        {
            pte[i] = (HVA_PTE) { .ExecuteDisable = 1 };
        }
    }
    else
    {
        memzero((CX_VOID*)Va, CX_PAGE_SIZE_4K);
    }
    return CX_STATUS_SUCCESS;
}


static volatile CX_UINT64 _HvaL1tfUnusedPageFrameBitsMask = 0;

CX_UINT64
HvaGetPlatformL1tfMitigationPageFrameBitsMask(
    CX_VOID
)
{
    return _HvaL1tfUnusedPageFrameBitsMask;
}

CX_STATUS
HvaActivateL1tfMitigations(
    CX_VOID
)
{
    // Mitigate starting at the very first bit not reported as part of the physical address width
    CX_UINT8 physicalAddressBitsUsed = CpuGetPhysicalAddressWidth();

    // how many bits can we set above the max physical address?
    CX_UINT8 unusedPageFrameBits = (HVA_PTE_PHYSICAL_ADDRESS_WIDTH - physicalAddressBitsUsed);

    // fill-in a 111... binary mask of unusedPageFrameBits bits
    // if HVA_PTE_PHYSICAL_ADDRESS_WIDTH == physicalAddressBitsUsed the mask will be zero
    CX_UINT64 mask = (1ull << (CX_UINT64)unusedPageFrameBits) - 1;

    // finally, move the bits left by physicalAddressBitsUsed positions (taking into consideration this is a *page frame* mask)
    _HvaL1tfUnusedPageFrameBitsMask = mask << (CX_UINT64)(physicalAddressBitsUsed - HVA_PAGE_OFFSET_BITS);

    return CX_STATUS_SUCCESS;
}



static
__forceinline
HVA_PTE_RAW
_HvaL1tfMitigate(
    _In_ HVA_PTE_RAW Pte
)
//
// https://software.intel.com/security-software-guidance/insights/deep-dive-intel-analysis-l1-terminal-fault
// example: The CPU reports MAXPHYADDR as 36. To mitigate an L1TF exploit on this vulnerable entry, an OS can set bits 35 to 51 inclusive in the entry
// to ensure that it does not refer to any lines in the L1D. This assumes that the system does not use any memory at an address with bit 35 set.
//
{
    if (Pte.Present)
    {
        // clear any excess bits that could have been set as L1TF mitigation
        Pte.PageFrame &= ~_HvaL1tfUnusedPageFrameBitsMask;
    }
    else if (Pte.PageFrame)
    {
        // set the MSB to 1 when the pageframe exists but the mapping isn't present (a HVA hook)
        // HVA_WARNING("L1TF mitigation enforced for (H)PA=%llX (PF=%llX => new PF=%llX : new PTE=%llX)\n",
        //     CX_PAGE_SIZE_4K * Pte.PageFrame, Pte.PageFrame, Pte.PageFrame | _HvaL1tfUnusedPageFrameBitsMask, Pte.Raw);
        Pte.PageFrame |= _HvaL1tfUnusedPageFrameBitsMask;
    }
    return Pte;
}



static
CX_STATUS
_HvaAlterTableEntryCb(
    _In_ TAS_DESCRIPTOR         *Mapping,
    _In_ HVA_PTE                *TableEntry,            // where should the changes go
    _In_ CX_UINT8               TableDepth,             // at what depth the paging structure is (the TableEntry that needs changes)
    _In_ TAS_PROPERTIES         SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES         ClearProperties,        // clear these properties
    _In_ CX_BOOL                IsFirstPageInRange,     // used for ContinuousPa and/or chaining deduction
    _In_ CX_BOOL                IsLastPageInRange,      // used for chaining deduction
    _In_ MEM_ALIGNED_PA         PhysicalPage            // where should the mapping point to (ignore unless SetProperties.PageFrame)
)
// a MAP_ALTER_TABLE_ENTRY_CB implementation
{
    // default table entry clear and/or set code
    HVA_PTE_RAW origPte = *TableEntry; // no validations, the caller should call with 'must have' paging structures or SetProperties.PagingStructures
    HVA_PTE_RAW newPte = origPte;
    if (SetProperties.DefaultTableBits)
    {
        // set the most relaxed settings such that the leaf entries can enforce per-page constraints
        newPte.Present = 1;
        newPte.Write = 1;
    }

    if (SetProperties.PageFrame || ClearProperties.PageFrame)
        newPte.PageFrame = ClearProperties.PageFrame ? 0 : CX_PAGE_FRAME_NUMBER_4K(PhysicalPage);

    // some bits are managed by leaf entries only
    if (TableDepth + 1 == Mapping->PagingDepth)
    {
        newPte.Present = (SetProperties.Read || SetProperties.Write || SetProperties.Execute || (!ClearProperties.Read && origPte.Present));

        if (SetProperties.Write || ClearProperties.Write)
            newPte.Write = SetProperties.Write;

        if (SetProperties.Execute || ClearProperties.Execute)
            newPte.ExecuteDisable = (CpuIsXdUsed() && ClearProperties.Execute);

        if (SetProperties.InUse || ClearProperties.InUse)
            newPte.HvInUse = SetProperties.InUse; // consider SetProperties.X = !ClearProperties.X, otherwise, if both 1, it's a caller's issue

                                                  // make CompleteChain have precedence over the lower-level bits (which need different values for different pages)
        if (SetProperties.CompleteChain)
        {
            newPte.HvChained = !IsLastPageInRange;
            newPte.HvChainLimit = (IsLastPageInRange || IsFirstPageInRange);
        }
        else
        {
            if (SetProperties.Chained || ClearProperties.Chained)
                newPte.HvChained = SetProperties.Chained;

            if (SetProperties.ChainLimit || ClearProperties.ChainLimit)
                newPte.HvChainLimit = SetProperties.ChainLimit;
        }

        HVA_PAT_INDEX setCaching;
        HVA_PAT_INDEX clearCaching;
        setCaching.Raw = (CX_UINT8)SetProperties.Caching;
        clearCaching.Raw = (CX_UINT8)ClearProperties.Caching;

        if (setCaching.Raw || clearCaching.Raw)
        {
            if (setCaching.PAT || clearCaching.PAT) newPte.Pat = setCaching.PAT;
            if (setCaching.PWT || clearCaching.PWT) newPte.WriteThrough = setCaching.PWT;
            if (setCaching.PCD || clearCaching.PCD) newPte.CacheDisable = setCaching.PCD;
        }
        // any synchronization over a range of VAs HAS to be performed at higher level by the code owning the resource
        // trying to synchronize at low-level would only hide the synchronization issues fro the upper level code that knows
        // what the resource is and how it should be used
        *TableEntry = _HvaL1tfMitigate(newPte);
    }
    else
    {
        // not a leaf entry -- only accept PageFrame changes (which may also define the P&W bits)
        // only allow setting the page frame when not already populated
        if (SetProperties.PageFrame)
        {
            if (origPte.PageFrame || (origPte.Raw != CxInterlockedCompareExchange64(&(TableEntry->Raw), newPte.Raw, origPte.Raw)))
            {
                // the entry already has some page frame set, don't overwrite as the operation is only allowed at leaf-level nodes
                return CX_STATUS_ALREADY_INITIALIZED_HINT;
            }
        }
        if (ClearProperties.PageFrame)
        {
            // can't do that, support for freeing up the paging structures is not provided
            return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
        }
    }
    return CX_STATUS_SUCCESS;
}



//
// TLB invalidation support
//

// uncomment for tracing all full TLB invalidations performed
#define INVDLOG(...) //LOG(__VA_ARGS__)
static
__forceinline
NTSTATUS
_HvaInvalidate(
    _In_ PVOID Va,
    _In_ QWORD PageCount,
    _In_ BOOLEAN IncludeGlobalPages,
    _In_ BOOLEAN FullTlb
)
//
// Used by IPI callbacks to invalidate certain page ranges or the complete TLB.
//
{

    QWORD i;

    // we do per-page invalidation for under MAX_PAGES_FOR_INVLPG page ranges, after which we do global invalidation
    if ((!FullTlb) && PageCount && (PageCount <= HVA_GLOBAL_INVLD_PAGE_COUNT_THRESHOLD))
    {
        for (i = 0; i < PageCount; i++)
        {
            // NOTE: INVLPG invalidates also global pages, so we do NOT need to handle them separately
            __invlpg((PVOID)(((QWORD)(Va)) + i * PAGE_SIZE));
        }
    }
    else
    {
        if (!IncludeGlobalPages)
        {
            // 4.10.4.1 Vol 3 - 057 US: MOV to CR3 does NOT invalidate any global pages
            INVDLOG("FULL INVLD\n");
            __writecr3(__readcr3());
        }
        else
        {
            QWORD tmp;

            // do complete TLB invalidation for current PCPU, including global pages
            tmp = __readcr4();
            if (0 != (tmp & CR4_PGE))
            {
                INVDLOG("FULL INVLD\n");
                __writecr4(tmp & (~CR4_PGE));   // CR4.PGE = 0
                __writecr4(tmp);                // CR4.PGE = 1
            }
            else
            {
                // we are NOT using global pages, simply invalidate using CR3
                INVDLOG("FULL INVLD\n");
                __writecr3(__readcr3());
            }
        }
    }

    return CX_STATUS_SUCCESS;
}


typedef struct
{
    PVOID Va;
    struct
    {
        QWORD IncludeGlobalPages : 1;
        QWORD FullTlb : 1;
        QWORD PageCount : 64 - 2;
    };
}HVA_INV_IPC_PARAMS;


static
NTSTATUS
HvaInvalidateVaIpcCallback(
    _In_ struct _IPC_MESSAGE *Message
)
//
// Used as an IPC callbacks to invalidate certain page ranges or the complete TLB.
//
{
    if (!Message)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    static_assert(sizeof(HVA_INV_IPC_PARAMS) <= sizeof(Message->OperationParam.Callback.Data), "invalid size");

    HVA_INV_IPC_PARAMS *Params = (HVA_INV_IPC_PARAMS*)Message->OperationParam.Callback.Data;
    return _HvaInvalidate(Params->Va, Params->PageCount, (BOOLEAN)Params->IncludeGlobalPages, (BOOLEAN)Params->FullTlb);
}

static
NTSTATUS
HvaInvalidateAllRoutine(
    VOID
)
{
    return _HvaInvalidate(NULL, 0, TRUE, TRUE);
}


NTSTATUS
HvaTlbInvaldQueueConsumerRoutine(
    _In_ CPU_IPC_QUEUE *CpuQueue
)
//
// Custom processing of the messages found in the dedicated TLB invalidation IPC queue
//
{
    IPC_QUEUE_COLLAPSE_CONDITION collapseCondition = IPC_QUEUE_COLLAPSE_CONDITION_ON_DROPPED_MESSAGES;

    if (CpuQueue->CustomState.TotalTlbEntries >= HVA_GLOBAL_INVLD_PAGE_COUNT_THRESHOLD)
    {
        INVDLOG("FULL VA INVLD due to %lld pages - %lldMB\n", CpuQueue->CustomState.TotalTlbEntries, (CpuQueue->CustomState.TotalTlbEntries * PAGE_SIZE) / ONE_MEGABYTE);
        collapseCondition |= IPC_QUEUE_COLLAPSE_CONDITION_FORCED;
    }
    else if (CpuQueue->TotalDroppedMessages)
    {
        INVDLOG("FULL VA INVLD due to dropped messages (accounted %lld pages - %lldMB)\n", CpuQueue->CustomState.TotalTlbEntries, (CpuQueue->CustomState.TotalTlbEntries * PAGE_SIZE) / ONE_MEGABYTE);
    }

    CxInterlockedExchange64(&CpuQueue->CustomState.TotalTlbEntries, 0);
    return IpcQueueCollapseMessages(CpuQueue, HvaInvalidateAllRoutine, collapseCondition, 0);
}


static
__forceinline
NTSTATUS
_HvaSendInvalidateMessage(
    _In_ IPC_CPU_DESTINATION Destination,
    _In_ PVOID Address,
    _In_ DWORD PageCount,
    _In_ BOOLEAN IncludeGlobalPages,
    _In_ BOOLEAN FullTlb
)
{
    IPC_MESSAGE msg = { 0 };

    msg.MessageType = IPC_MESSAGE_TYPE_CALLBACK;
    msg.OperationParam.Callback.CallbackFunction = HvaInvalidateVaIpcCallback;

    static_assert(sizeof(HVA_INV_IPC_PARAMS) <= sizeof(msg.OperationParam.Callback.Data), "invalid size");

    HVA_INV_IPC_PARAMS *Params = (HVA_INV_IPC_PARAMS*)msg.OperationParam.Callback.Data;
    Params->Va = Address;
    Params->PageCount = PageCount;
    Params->FullTlb = FullTlb;
    Params->IncludeGlobalPages = IncludeGlobalPages;

    // report the page count value to each destination cpu, by adding it to the CustomData field
    //
    // worst synchronization issue: (performance penalty) when the value is added, consumed by destination
    // and only then are the messages actually inserted into the queue, resulting in a global invalidation (worst case)
    // which is then followed by PageCount useless __invlpg operations performed when that cpu next processes the queue (worst case)
    for (DWORD i = 0; i < gHypervisorGlobalData.CpuData.CpuCount; i++)
    {
        PCPU* cpu = gHypervisorGlobalData.CpuData.Cpu[i];
        if (cpu && IpcIsCpuSelectedByDestination(cpu, Destination) && !cpu->Ipc.Queue[IPC_PRIORITY_TLB_INVLD].TotalDroppedMessages)
        {
            CxInterlockedAdd64(&cpu->Ipc.Queue[IPC_PRIORITY_TLB_INVLD].CustomState.TotalTlbEntries, PageCount);
        }
    }

    NTSTATUS status = IpcSendCpuMessage(&msg, Destination, IPC_PRIORITY_TLB_INVLD, FALSE, IPC_WAIT_COMPLETION_NONE, TRUE);
    if ((CX_STATUS_OUT_OF_RESOURCES == status) || (CX_STATUS_ABANDONED == status))
        status = CX_STATUS_SUCCESS;

    return status;
}



NTSTATUS
HvaInvalidateTlbRange(
    _In_ CX_VOID *Address,                  // VA base address of 4K page we want to invalidate TLB cache for
    _In_ HVA_PAGE_COUNT PageCount,          // number of 4K pages the range contains
    _In_ CX_BOOL Broadcast,                 // TRUE if we want to invalidate on all CPU cores, FALSE to invalidate on current CPU only
    _In_ CX_BOOL InclGlobalPages            // TRUE if we want to invalidate also global TLB entries, FALSE by default
)
//
// Invalidates a given TLB range, either on the current CPU or on all CPU cores (broadcast). Can also enforce invalidation
// of global pages (usually not needed).
//
// NOTE: the function can choose to invalidate the complete TLB if the range contains over a certain number of pages.
//
{
    if (HvDoWeHaveIpcQueues())
    {
        return _HvaSendInvalidateMessage(
            Broadcast ? IPC_CPU_DESTINATION_ALL_INCLUDING_SELF : IPC_CPU_DESTINATION_SELF,
            Address,
            PageCount,
            InclGlobalPages,
            FALSE);
    }
    else
    {
        // otherwise only invalidate on current CPU
        for (MEM_PAGE_COUNT page = 0; page < PageCount; page++)
        {
            __invlpg((VOID*)(CX_PAGE_BASE_4K((CX_UINT64)Address) + page*CX_PAGE_SIZE_4K));
        }
    }

    return CX_STATUS_SUCCESS;
}



NTSTATUS
HvaInvalidateTlbComplete(
    _In_ CX_BOOL Broadcast,                 // TRUE if we want to invalidate on all CPU cores, FALSE to invalidate on current CPU only
    _In_ CX_BOOL InclGlobalPages            // TRUE if we want to invalidate also global TLB entries, FALSE by default
)
//
// Invalidates the complete TLB cache, either on the current CPU or on all CPU cores (broadcast). Can also enforce invalidation
// of global pages (usually not needed).
//
{
    NTSTATUS status;
    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-

    return _HvaSendInvalidateMessage(
        Broadcast ? IPC_CPU_DESTINATION_ALL_INCLUDING_SELF : IPC_CPU_DESTINATION_SELF,
        0,
        0,
        InclGlobalPages,
        TRUE);
}


//
// Debugging API
//


CX_VOID
HvaDumpProperties(
    _In_ TAS_PROPERTIES Properties
)
{
    HVA_PTE_CACHING_BITS patIndex;
    patIndex.Raw = (CX_UINT8)Properties.Caching;
    HVA_CACHING_TYPE caching = HvaGetCachingType(patIndex);

    HVA_LOGN("%s%s%s|%s|%s%s%s%s%s",
        (Properties.Read ? "R" : ""),
        (Properties.Write ? "W" : ""),
        (Properties.Execute ? "X" : ""),

        caching == HVA_CACHING_UC ? "UC" : caching == HVA_CACHING_WB ? "WB" : "??",

        (Properties.CompleteChain ? "COMPLETE" : ""),
        (Properties.Chained ? "CHAINED" : ""),
        (Properties.ChainLimit ? "BOUNDARY" : ""),
        (Properties.InUse ? "USED" : ""),
        (Properties.ContinuousPa ? "CONTINUOUS" : ""));
}


CX_VOID
HvaDumpPte(
    _In_ HVA_PTE Pte
)
{
    HVA_CACHING_TYPE caching = HvaPteBitsToCachingType(&Pte);

    HVA_LOGN("PA=0x%llX/ACCESS=(%s%s%s)/CACHING=%s",
        CX_PAGE_SIZE_4K * Pte.PageFrame,

        (Pte.Present ? "R" : ""),
        (Pte.Write ? "W" : ""),
        (Pte.ExecuteDisable ? "" : "X"),

        caching == HVA_CACHING_UC ? "UC" : caching == HVA_CACHING_WB ? "WB" : "??"
    );
}


CX_VOID
HvaDumpPteRaw(
    _In_ HVA_PTE E
)
{
    HVA_LOGN("P:%lld RW:%lld US:%lld PWT:%lld PCD:%lld A:%lld D:%lld PAT:%lld G:%lld CS:%lld C:%lld",
        E.Present,
        E.Write,
        E.Supervisor,
        E.WriteThrough,
        E.CacheDisable,
        E.Accessed,
        E.Dirty,
        E.Pat,
        E.Global,
        E.HvChainLimit,
        E.HvChained,
        E.HvInUse);
}

CX_STATUS
HvaDumpTranslationInfo(
    _In_ CX_VOID *Va
)
{
    TAS_PAGING_STRUCTURE_INFO path[4];
    TAS_PROPERTIES props, valid;
    CX_STATUS status = TasGetPagingPathInfo(&gHva, (MEM_UNALIGNED_VA)Va, FALSE, FALSE, FALSE, 0, path, &props, &valid);
    if (!SUCCESS(status))
    {
        HVA_LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
        goto cleanup;
    }
    HVA_LOG("Translation info for VA=%p given Root=%p\n", Va, &gHva.RootPa);
    for (CX_UINT8 i = 0; i < 4; i++)
    {
        HVA_PTE_RAW pte;
        pte.Raw = (path[i].TableEntryVa ? *(QWORD*)path[i].TableEntryVa : 0);

        HVA_LOGN("lvl%d tableIndex=%d, tableEntry=%16llX -- ", i, path[i].Index, pte);
        HvaDumpPte(pte);
        HVA_LOGN(" (");
        HvaDumpPteRaw(pte);
        HVA_LOGN(" )\n");
    }
cleanup:

    return status;
}



CX_VOID
HvaDumpRangeInfo(
    _In_ CX_VOID *Va,
    _In_ HVA_PAGE_COUNT PageCount
)
{
    MEM_PAGE_COUNT pages;
    TAS_PROPERTIES props;
    CX_STATUS qstatus = TasQueryRangeProperties(&gHva, (MEM_UNALIGNED_VA)Va, 0, &props, NULL, &pages);
    if (!SUCCESS(qstatus))
    {
        HVA_LOG_FUNC_FAIL("TasQueryRangeProperties", qstatus);
    }
    else
    {
        HVA_LOGN("%p: %d pages with props %llX, chained:%d pages\n", Va, PageCount, props.Raw, pages);
    }
}


static CX_BOOL gHvaOffsettingActive = CX_FALSE;

CX_STATUS
HvaGetHvaPagingStructureVaCallback(
    _In_ MEM_UNALIGNED_PA Pa,
    _Out_ MEM_UNALIGNED_VA *Va
)
{
    if (!Pa) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Va) return CX_STATUS_INVALID_PARAMETER_2;
    if (Pa > NAPOCA_PAGING_STRUCTURES_SIZE) return CX_STATUS_UNSUPPORTED_DATA_VALUE;

    *Va = (gHvaOffsettingActive ? NAPOCA_PAGING_STRUCTURES + Pa : Pa);

    return CX_STATUS_SUCCESS;
}


CX_STATUS
HvaActivateHvaPagingStructuresOffsetting(
    CX_VOID
)
{
    CX_STATUS status = MmMap(&gHvMm, (PVOID)(NAPOCA_PAGING_STRUCTURES + gTempMem->Pa), gTempMem->Pa, NULL, NULL, 0, NULL, gTempMem->Length, TAG_LD_MODULE, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmMap", status);
        return status;
    }
    gHvaOffsettingActive = CX_TRUE;

    return CX_STATUS_SUCCESS;
}
/// @}
