/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file ept.c
///  @brief Implements management routines for the Intel's Extended Page Tables virtualization feature. The implementation is a wrapper over the generic TAS (Translated Address Space) component available through the tas.c and tas.h files in the napoca/memory subfolder.
///

/// @defgroup ept
/// @ingroup memory
/// @{


#include "napoca.h"
#include "memory/ept.h"
#include "memory/memmgr.h"
#include "guests/guests.h"
#include "kernel/queue_ipc.h"
#include "boot/phase1.h"

#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201) // nonstandard extension used: nameless structure/union

typedef union
{
    struct
    {
        CX_UINT64 Read              : CX_BITFIELD(0, 0);   ///< Present; must be 1 to map a 4-KByte page
        CX_UINT64 Write             : CX_BITFIELD(1, 1);   ///< Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
        CX_UINT64 Execute           : CX_BITFIELD(2, 2);   ///< User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry
        CX_UINT64 MemoryType        : CX_BITFIELD(5, 3);   ///< 0 = UC; 1 = WC; 4 = WT; 5 = WP; and 6 = WB.Other values are reserved and cause EPT misconfigurations
        CX_UINT64 IgnorePat         : CX_BITFIELD(6, 6);   ///< Ignore PAT memory type for this 4-KByte page
        CX_UINT64 LargePage         : CX_BITFIELD(7, 7);   ///< Ignored for PTEs, specifies large pages for upper-level tables (except for the root table)
        CX_UINT64 Accessed          : CX_BITFIELD(8, 8);   ///< Indicates whether software has accessed the 4-KByte page referenced by this entry(see Section 28.2.5).Ignored if bit 6 of EPTP is 0
        CX_UINT64 Dirty             : CX_BITFIELD(9, 9);   ///< Indicates whether software has written to the 4-KByte page referenced by this entry(see Section 28.2.5).Ignored if bit 6 of EPTP is 0
        CX_UINT64 HvChained         : CX_BITFIELD(10, 10); ///< When 1 it means this entry is part of a larger mapping spanning at least over the next page too
        CX_UINT64 HvInUse           : CX_BITFIELD(11, 11); ///< Specifies whether this entry has actively been configured (= 1) or it's merely filled-in with initialization default bits (= 0)
        CX_UINT64 PageFrame         : CX_BITFIELD(51, 12); ///< HPA page index for the destination physical memory backing up the translated GPA
        CX_UINT64 HvChainLimit      : CX_BITFIELD(52, 52); ///< If 1 the next guest physical page is not part of a multi-page continuous region
        CX_UINT64 Ignored           : CX_BITFIELD(60, 53);
        CX_UINT64 Spp               : CX_BITFIELD(61, 61); ///< When 1, sub-page protection is used/active for this entry
        CX_UINT64 HvDeviceMem       : CX_BITFIELD(62, 62); ///< Marks hooked memory device pages (1 = hooked, 0 = not hooked)
        CX_UINT64 BypassVe          : CX_BITFIELD(63, 63); ///< EPT violations caused by accesses to this page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is 0, this bit is ignored
    };
    CX_UINT64                       Raw;
    CX_UINT16                       PteCacheAndRights;
}EPT_PTE_RAW;
typedef volatile EPT_PTE_RAW EPT_PTE;
static_assert(sizeof(EPT_PTE) == sizeof(CX_UINT64), "the PTE entries are QWORDs");


///
/// @brief        Fill-in and return the rights and caching of a new raw EPT PTE entry based on the given EPT_PROPERTIES
/// @param[in]    Props                            input Read/Write/Execute/Spp properties
/// @returns      resulting raw EPT PTE-like value
///
CX_UINT64
EptPropsToPteCachingAndRightsBits(
    _In_ EPT_PROPERTIES Props
)
{
    EPT_PTE_RAW pte = { 0 };
    pte.Read        = Props.Read;
    pte.Write       = Props.Write;
    pte.Execute     = Props.Execute;
    pte.MemoryType  = Props.Caching;
    pte.IgnorePat   = 0;
    pte.BypassVe    = Props.BypassVe;
    pte.Spp         = Props.Spp;
    return pte.Raw;
}



static
__forceinline
EPT_CACHING
_EptPteToCaching(
    _In_ EPT_PTE_RAW Pte
)
{
    EPT_CACHING caching = { 0 };
    caching.IgnorePat   = (CX_UINT16) Pte.IgnorePat;
    caching.MemoryType  = (CX_UINT16) Pte.MemoryType;
    return caching;
}



static
__forceinline
EPT_PTE_RAW
_EptCachingToPte(
    _In_ EPT_CACHING Caching
)
{
    EPT_PTE_RAW pte;
    pte.MemoryType  = Caching.MemoryType;
    pte.IgnorePat   = Caching.IgnorePat;
    return pte;
}


static
__forceinline
CX_BOOL
_EptIsValidCaching(
    _In_ EPT_CACHING Caching
)
{
    // just like the HVA_CACHING_TYPE definitions: 0 = UC; 1 = WC; 4 = WT; 5 = WP; and 6 = WB. Other values are reserved and cause EPT misconfigurations
    return (
        Caching.MemoryType == HVA_CACHING_UC ||
        Caching.MemoryType == HVA_CACHING_WC ||
        Caching.MemoryType == HVA_CACHING_WT ||
        Caching.MemoryType == HVA_CACHING_WP ||
        Caching.MemoryType == HVA_CACHING_WB);
}


static
__forceinline
CX_STATUS
_EptGetPredefinedStatus(
    _In_ CX_STATUS TasStatus,
    _In_ TAS_PROPERTIES Properties
)
{
    // EPT-related predefined status values are expected by some of our callers -- convert the TAS generic status values to those ones
    if (STATUS_ACCESS_REQUIREMENTS_NOT_MET == TasStatus) return STATUS_NO_MAPPING_STRUCTURES;
    if (!CX_SUCCESS(TasStatus)) return TasStatus;
    if (!Properties.PagingStructures) return STATUS_NO_MAPPING_STRUCTURES;
    if (!Properties.InUse || !Properties.PageFrame) return STATUS_EMPTY_MAPPING;

    return CX_STATUS_SUCCESS;
}

//
// TAS callbacks
//

static
CX_STATUS
_EptGetTableInfoCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           TranslatedVa,
    _In_ CX_UINT8                   TableDepth,
    _In_opt_ MEM_ALIGNED_PA         TablePa,                // TAS will either know where exactly the table is located
    _In_ EPT_PTE                    *UpperLevelEntryVa,     // or the upper-level table entry that links to it
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *TableInfo
)
{
    TAS_PAGING_STRUCTURE_INFO info = { 0 };

    // these properties are always valid, the other ones must be ignored when not at a leaf node

    CX_UINT64 vaShiftAmount = HVA_PAGE_OFFSET_BITS + (HVA_TABLE_INDEX_BITS * (Mapping->PagingDepth - TableDepth - 1));
    info.Index = (((CX_UINT64)TranslatedVa) >> vaShiftAmount) & HVA_TABLE_ENTRY_MASK;
    info.HasSuccessor = info.Index < HVA_TABLE_ENTRY_MASK; // allows for optimized traversal of a VA interval (when advancing, there's no need to refresh upper-level info when we can increment this index)

    info.ValidPropertiesMask.Read = 1;
    info.ValidPropertiesMask.Write = 1;
    info.ValidPropertiesMask.Execute = 1;
    info.ValidPropertiesMask.PagingStructures = 1;

    info.TablePa = UpperLevelEntryVa ? (CX_PAGE_SIZE_4K * UpperLevelEntryVa->PageFrame) : TablePa;

    CX_STATUS status = Mapping->GetTableVa(info.TablePa, (MEM_UNALIGNED_VA*)&info.TableVa);
    if (info.TablePa && CX_SUCCESS(status))
    {
        // directly available fields
        info.TableEntryVa = &(((EPT_PTE_RAW*)(info.TableVa))[info.Index]);
        info.NextLevelTablePa = CX_PAGE_SIZE_4K * ((EPT_PTE_RAW*)(info.TableEntryVa))->PageFrame;

        // deduce hardware-specific info (caching, access rights, HV bits)
        EPT_PTE_RAW pte = *((EPT_PTE_RAW*)info.TableEntryVa);
        CX_BOOL isPte = (TableDepth + 1 == Mapping->PagingDepth);
        CX_BOOL isLeaf = (isPte || (TableDepth && pte.LargePage));

        info.Properties.Read = !!pte.Read;
        info.Properties.Write = !!pte.Write;
        info.Properties.Execute = !!pte.Execute;
        info.Properties.BypassVe = !!pte.BypassVe;
        info.Properties.Spp = isPte && pte.Spp; // this field is the only field not available unless the entry is a true PT entry
        info.Properties.Special = !!pte.HvDeviceMem;

        info.Properties.Accessed = pte.Accessed;
        info.Properties.Dirty = pte.Dirty;

        info.Properties.Chained = pte.HvChained;
        info.Properties.ChainLimit = pte.HvChainLimit;
        info.Properties.InUse = pte.HvInUse;

        info.Properties.PagingStructures = 1;
        info.Properties.PageFrame = 1;
        info.Properties.ContinuousPa = !!(IsFirstPageInRange || (PreviousPa + CX_PAGE_SIZE_4K == info.NextLevelTablePa));
        info.Properties.Caching = _EptPteToCaching(pte).Raw;

        info.Properties.CompleteChain = !!((IsFirstPageInRange && pte.HvChained && pte.HvChainLimit) ||
            (IsLastPageInRange && !pte.HvChained && pte.HvChainLimit) ||
            (!IsFirstPageInRange && !IsLastPageInRange && pte.HvChained));

        if (isLeaf)
        {
            info.ValidPropertiesMask.Raw = CX_UINT64_MAX_VALUE;
            info.EntryMappingSizeExponent = (CX_UINT32)vaShiftAmount;
        }
        info.IsLeafTableEntry = !!isLeaf;
    }

    *TableInfo = info;
    return CX_STATUS_SUCCESS;
}

static
__forceinline
EPT_PTE_RAW
_EptL1tfMitigate(
    _In_ EPT_PTE_RAW Pte
)
//
// https://software.intel.com/security-software-guidance/insights/deep-dive-intel-analysis-l1-terminal-fault
// example: The CPU reports MAXPHYADDR as 36. To mitigate an L1TF exploit on this vulnerable entry, an OS can set bits 35 to 51 inclusive in the entry
// to ensure that it does not refer to any lines in the L1D. This assumes that the system does not use any memory at an address with bit 35 set.
//
{
//  CX_UINT64 mask = HvaGetPlatformL1tfMitigationPageFrameBitsMask();
//  if (Pte.Read) // we don't care about write, a successful exploit only reads forbidden memory (i.e. it does not write or execute)
//  {
//      // clear any excess bits that could have been set as L1TF mitigation
//      Pte.PageFrame &= mask;
//  }
//  else if (Pte.PageFrame)
//  {
//      // set the MSB to 1 when the pageframe exists but the mapping isn't present (a HVA hook)
//      // HVA_WARNING("L1TF mitigation enforced for (H)PA=%llX (PF=%llX => new PF=%llX : new PTE=%llX)\n",
//      //     CX_PAGE_SIZE_4K * Pte.PageFrame, Pte.PageFrame, Pte.PageFrame | _HvaL1tfUnusedPageFrameBitsMask, Pte.Raw);
//      Pte.PageFrame |= mask;
//  }
    return Pte;
}


static
CX_STATUS
_EptAlterTableEntryCb(
    _In_ TAS_DESCRIPTOR         *Mapping,               ///< memory space associated with the table entry
    _In_ EPT_PTE                *TableEntry,            ///< where should the changes go
    _In_ CX_UINT8               TableDepth,             ///< at what depth the paging structure is (the TableEntry that needs changes)
    _In_ TAS_PROPERTIES         SetProperties,          ///< mark these properties when walking the VAs
    _In_ TAS_PROPERTIES         ClearProperties,        ///< clear these properties
    _In_ CX_BOOL                IsFirstPageInRange,     ///< used for ContinuousPa and/or chaining deduction
    _In_ CX_BOOL                IsLastPageInRange,      ///< used for chaining deduction
    _In_ MEM_ALIGNED_PA         PhysicalPage            ///< where should the mapping point to (ignore unless SetProperties.PageFrame)
)
/// Callback function called by TAS as a MAP_ALTER_TABLE_ENTRY_CB routine for all table entry modifications needed
{
    // default table entry clear and/or set code
    EPT_PTE_RAW origPte = *TableEntry; // no validations, the caller should call with 'must have' paging structures or SetProperties.PagingStructures
    EPT_PTE_RAW newPte = origPte;

    struct _EPT_DESCRIPTOR_INTERNAL *eptInternal = (struct _EPT_DESCRIPTOR_INTERNAL *)Mapping;
    CX_UINT64 vaShiftAmount = HVA_PAGE_OFFSET_BITS + (HVA_TABLE_INDEX_BITS * (Mapping->PagingDepth - TableDepth - 1));

    if (SetProperties.DefaultTableBits)
    {
        // set the most relaxed settings such that the leaf entries can enforce per-page constraints, for large pages they will be customized afterwards
        newPte.Read = 1;
        newPte.Write = 1;
        newPte.Execute = 1;
        if (TableDepth == 1 && eptInternal->Use1GbPages) newPte.LargePage = 1;
    }

    if (PhysicalPage > gCpuMaxPhysicalAddress)
    {
        WARNING("EPT destination HPA will be truncated: %llX -> %llX\n", PhysicalPage, PhysicalPage & gCpuMaxPhysicalAddress);
        PhysicalPage &= gCpuMaxPhysicalAddress;
    }

    if (SetProperties.PageFrame || ClearProperties.PageFrame)
        newPte.PageFrame = ClearProperties.PageFrame ? 0 : CX_PAGE_FRAME_NUMBER_4K(newPte.LargePage ? CX_ROUND_DOWN(PhysicalPage, (1ull << vaShiftAmount)) : PhysicalPage);

    // some bits are managed by leaf entries only
    CX_BOOL isPte = (TableDepth + 1 == Mapping->PagingDepth);
    if (isPte || (TableDepth && newPte.LargePage))
    {
        newPte.BypassVe = 1; // by default, don't let the \#VE handler intercept all the EPT violations

        // if (gVirtFeatures.EptVpidFeatures.Parsed.EptExecuteOnly == 0) => the platform does not support execute-only in ept tables
        if (SetProperties.Read || ClearProperties.Read)
            newPte.Read = SetProperties.Read;

        if (SetProperties.Write || ClearProperties.Write)
            newPte.Write = SetProperties.Write;

        if (SetProperties.Execute || ClearProperties.Execute)
            newPte.Execute = SetProperties.Execute;

        if (SetProperties.InUse || ClearProperties.InUse)
            newPte.HvInUse = SetProperties.InUse;

        if (SetProperties.BypassVe || ClearProperties.BypassVe)
            newPte.BypassVe = SetProperties.BypassVe;

        if (isPte && (SetProperties.Spp || ClearProperties.Spp)) // only applied for true PT entry leafs, missing from higher-level table entries even if they map large pages
            newPte.Spp = SetProperties.Spp;

        if (SetProperties.Special || ClearProperties.Special)
            newPte.HvDeviceMem = SetProperties.Special;

        // decide whether the change to this page frame requires an invalidation
        CX_BOOL lostRights = ((origPte.Raw | newPte.Raw) & 7) > (newPte.Raw & 7);
        CX_BOOL lostCaching = origPte.MemoryType > newPte.MemoryType; // 0 = UC ... 6 = WB
        CX_BOOL usageChanges = ( ((origPte.Spp != newPte.Spp) || (origPte.BypassVe != newPte.BypassVe)));
        eptInternal->InvalidationNeeded |= (lostRights || lostCaching || usageChanges);

        // TODO: paranoid mode - until more testing is done and we're sure the need for invalidations is properly detected
        if (ClearProperties.Raw || SetProperties.BypassVe || SetProperties.Spp || origPte.PageFrame && SetProperties.PageFrame)
        {
            eptInternal->InvalidationNeeded = 1;
        }

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

        if (SetProperties.Caching || ClearProperties.Caching)
        {
            EPT_CACHING tmp = { 0 };
            tmp.Raw = (CX_UINT16)SetProperties.Caching;
            tmp.Raw &= (CX_UINT16)(~ClearProperties.Caching);
            newPte.MemoryType = tmp.MemoryType;
            newPte.IgnorePat = tmp.IgnorePat;
        }

        // any synchronization over a range of VAs HAS to be performed at higher level by the code owning the resource
        // trying to synchronize at low-level would only hide the synchronization issues fro the upper level code that knows
        // what the resource is and how it should be used
        *TableEntry = _EptL1tfMitigate(newPte);
    }
    else
    {
        // not a leaf entry -- only accept PageFrame changes as the other bits are managed internally
        // and only allow setting the page frame when not already populated
        if (SetProperties.PageFrame)
        {
            newPte.BypassVe = 0;
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



static
CX_STATUS
_EptIterateTables(
    _In_ TAS_DESCRIPTOR         *Mapping,
    _In_ MEM_ALIGNED_PA         TablePa,
    __out_opt MEM_ALIGNED_VA    *TableVa,
    _In_ CX_UINT8               TableDepth,
    _Inout_ MEM_TABLE_OFFSET    *TableByteIndex,
    __out_opt MEM_ALIGNED_PA    *SizeIncrement,
    __out_opt MEM_ALIGNED_PA    *NextLevelTablePa,
    __out_opt CX_BOOL           *NextLevelTableValid,
    __out_opt CX_BOOL           *IsLeaf
)
///
/// Given a Table PA, decode where the next entry is and what table is linked by the current entry
/// to allow TasIterateStructures to walk (both left->right and top->down) the paging structures
///
{
    if (!TablePa)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }
    if (TableDepth + 1 > Mapping->PagingDepth)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }
    if (!TableByteIndex || *TableByteIndex % sizeof(EPT_PTE))
    {
        return CX_STATUS_INVALID_PARAMETER_4;
    }
    if (*TableByteIndex > HVA_TABLE_ENTRY_MASK * sizeof(EPT_PTE))
    {
        return CX_STATUS_NO_MORE_ENTRIES;
    }

    EPT_PTE *va;
    CX_STATUS status = Mapping->GetTableVa(TablePa, (MEM_UNALIGNED_VA*)&va);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Mapping->GetTableVa", status);
        return status;
    }

    if (TableVa)
    {
        *TableVa = (MEM_UNALIGNED_VA)va;
    }

    EPT_PTE *pte = (EPT_PTE*)(((CX_UINT8*)va) + *TableByteIndex);

    if (IsLeaf) *IsLeaf = (TableDepth == Mapping->PagingDepth || pte->LargePage);

    if (NextLevelTablePa)
    {
        *NextLevelTablePa = CX_PAGE_SIZE_4K * pte->PageFrame;
        if (NextLevelTableValid)
        {
            *NextLevelTableValid = (pte->Read || pte->Write || pte->Execute || pte->PageFrame || pte->HvInUse);
        }
    }

    if (SizeIncrement)
    {
        // last-level entries cover 2^HVA_PAGE_OFFSET_BITS and each level above adds a 2^HVA_TABLE_INDEX_BITS factor
        *SizeIncrement = 1ull << (QWORD)(HVA_TABLE_INDEX_BITS * (Mapping->PagingDepth - (1 + TableDepth)) + HVA_PAGE_OFFSET_BITS);
    }

    *TableByteIndex += sizeof(EPT_PTE);
    return CX_STATUS_SUCCESS;
}



static
CX_STATUS
_EptInitializeTableCb(
    _In_ TAS_DESCRIPTOR*    Mapping,                        ///< target TAS memory space descriptor
    _In_ CX_UINT8           TableDepth,                     ///< 0 for the top-level structure, 1 for the next level etc
    _Out_ MEM_ALIGNED_VA    Va,                             ///< a valid RW mapping of the physical page
    _Out_ MEM_ALIGNED_PA    Pa                              ///< the PA of the allocated page
)
/// Initialize a newly allocated page table such that no properties are present
{
    CX_UNREFERENCED_PARAMETER(Mapping, Pa, TableDepth);
    struct _EPT_DESCRIPTOR_INTERNAL *eptInternal = (struct _EPT_DESCRIPTOR_INTERNAL *)Mapping;
    EPT_PTE_RAW init = { .BypassVe = 1 };
    if (eptInternal->Use1GbPages && TableDepth == 1) init.LargePage = 1;

    {
        EPT_PTE_RAW *pte = (EPT_PTE_RAW *)Va;
        for (CX_UINT16 i = 0; i < (1 << HVA_TABLE_INDEX_BITS); i++)
        {
            pte[i] = init;
        }
    }
    return CX_STATUS_SUCCESS;
}



#define EPT_PAGING_DEPTH 4



///
/// @brief        Initialize a newly allocated or uninitialized EPT descriptor, making it ready for all the other EPT operations
/// @remark       This function has to be the very first EPT API called on any new memory space.
/// @param[out]   Ept                              Pointer to the descriptor to be initialized
/// @param[in]    InvalidationRoutine              Address of a function to be notified when changes needing TLB invalidations have occurred
/// @param[in]    InvalidationRoutineContext       Address of custom data sent to the InvalidationRoutine every time it is called
/// @param[in]    UseLimitedLargePages             If true, try to minimize the paging structures memory usage assuming the largest supported page size is enough for all purposes (finer-grained paging structures won't be available when set)
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The EPT descriptor cannot is NULL
///
CX_STATUS
EptInitDescriptor(
    _Out_ EPT_DESCRIPTOR                *Ept,
    _In_opt_ EPT_NOTIFY_INVALIDATION_CB *InvalidationRoutine,
    _In_opt_ CX_VOID                    *InvalidationRoutineContext,
    _In_ CX_BOOL                        UseLimitedLargePages
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;

    static const TAS_DESCRIPTOR _EptTemplateDescriptor = {
        .PagingDepth                = EPT_PAGING_DEPTH,
        .RootPa                     = 0,
        .GetTableInfo               = _EptGetTableInfoCb,
        .GetTableVa                 = HvaGetHvaPagingStructureVaCallback,
        .AlterTableEntry            = _EptAlterTableEntryCb,
        .IterateTables              = _EptIterateTables,
        .AllocPagingStructure       = FinalAllocPagingStructureCallback,
        .FreePagingStructure        = FinalFreePagingStructureCallback,
        .InitPagingStructure        = _EptInitializeTableCb,
        .AllocatedPageTablesCount   = 0
    };

    if (UseLimitedLargePages) LOG("New EPT domain will use 1GB pages!\n");

    Ept->Use1GbPages = UseLimitedLargePages;
    Ept->Tas = _EptTemplateDescriptor;
    Ept->InvalidationRoutine = InvalidationRoutine;
    Ept->InvalidationRoutineContext = InvalidationRoutineContext;
    HvInitRwSpinLock(&Ept->DestroyLock, "EptDestroyLock", CX_NULL);

    // force autovivification of a path through the page tables as the root PA is needed to be available ASAP
    TAS_PAGING_STRUCTURE_INFO path[EPT_PAGING_DEPTH];
    CX_STATUS status = TasGetPagingPathInfo(&Ept->Tas, 0, CX_TRUE, CX_TRUE, CX_TRUE, 0, path, CX_NULL, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
    }
    return status;
}



///
/// @brief        Returns the physical address of the topmost remapping table/structure (the PML4 table address)
/// @param[in]    Ept                              EPT domain descriptor
/// @param[out]   Hpa                              Pointer to where the host physical address of the top-level table should be saved
/// @returns      CX_STATUS_SUCCESS                - The table address was successfully retrieved
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The input descriptor pointer is NULL
///
CX_STATUS
EptGetRootPa(
    _In_ EPT_DESCRIPTOR         *Ept,
    __out_opt MEM_ALIGNED_PA    *Hpa
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    if (Hpa) *Hpa = Ept->Tas.RootPa;
    return CX_STATUS_SUCCESS;
}



NTSTATUS
EptInvalidateGpaOnCurrentVcpu(
    _In_opt_ QWORD              Gpa
)
{
    if (NULL == HvGetCurrentVcpu())
    {
        return CX_STATUS_SUCCESS;
    }
    NTSTATUS status = CpuVmxInvEpt(INVEPT_TYPE_ALL_CONTEXT, 0, 0);
    //NTSTATUS status = CpuVmxInvEpt(Gpa ? INVEPT_TYPE_SINGLE_CONTEXT : INVEPT_TYPE_ALL_CONTEXT, (PVOID)Gpa);
    if (!SUCCESS(status))
    {
        ERROR("CpuVmxInvEpt failed (%s) for %d:%p\n", NtStatusToString(status), Gpa ? INVEPT_TYPE_SINGLE_CONTEXT : INVEPT_TYPE_ALL_CONTEXT, (PVOID)Gpa);
    }
    return status;
}



static
NTSTATUS
EptInvalidateGpaIpcCallback(
    _In_ struct _IPC_MESSAGE *Message
)
{
    if (!Message)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }
    QWORD gpa = ((QWORD *)Message->OperationParam.Callback.Data)[0];
    return EptInvalidateGpaOnCurrentVcpu(gpa);
}



///
/// @brief        Broadcast a message that will perform EPT TLB invalidation all CPUs that might have stale TLB cached data for a given Guest
/// @param[in]    Guest                            The guest whose cached TLB data should be affected
/// @param[in]    Context                          EPT invalidation type/context data
/// @param[in]    WaitForCompletion                TRUE for blocking (wait until finished) invalidation, FALSE for asynchronious broadcast without waiting
/// @returns      CX_STATUS_SUCCESS                - if no invalidation is needed or the invalidation message was sent (and processed, when WaitForCompletion is TURE) successfully
///
NTSTATUS
EptInvalidateTlbs(
    _In_ GUEST*             Guest,
    _In_ QWORD              Context,
    _In_ BOOLEAN            WaitForCompletion
)
{
    UNREFERENCED_PARAMETER(WaitForCompletion);
    if (!Guest)
    {
        return CX_STATUS_SUCCESS;
    }

    IPC_MESSAGE msg = { 0 };

    static_assert(sizeof(QWORD) <= sizeof(msg.OperationParam.Callback.Data), "invalid size");

    msg.MessageType = IPC_MESSAGE_TYPE_CALLBACK;
    msg.OperationParam.Callback.CallbackFunction = EptInvalidateGpaIpcCallback;
    //msg.Trace = 1;
    ((QWORD *)msg.OperationParam.Callback.Data)[0] = Context;

    NTSTATUS status;
    if (WaitForCompletion)
    {
        status = IpcSendCpuMessage(
            &msg,
            IPC_CPU_DESTINATION_ALL_INCLUDING_SELF,
            IPC_PRIORITY_EPT_INVLD,
            TRUE,                                   // do interrupt cpus when possible
            IPC_WAIT_COMPLETION_BEST_EFFORT,        // wait for confirmation if possible to interrupt
            TRUE);                                  // drop message if too many already (at least an
                                                    // ept broadcast was just sent with interruption so we know the invalidation will be processed
    }
    else
    {
        status = IpcSendCpuMessage(
            &msg,
            IPC_CPU_DESTINATION_ALL_INCLUDING_SELF,
            IPC_PRIORITY_EPT_INVLD,
            FALSE,                                  // don't interrupt
            IPC_WAIT_COMPLETION_NONE,               // don't wait
            TRUE);                                  // allow dropping the message when there are already too many collected in queue(s)
    }

    if (CX_STATUS_ABANDONED == status)
    {
        // this is an expected outcome of the call, there's nothing wrong
        status = CX_STATUS_SUCCESS;
    }
    return status;
}



static
NTSTATUS
EptInvalidateAllRoutine(
    VOID
)
{
    return EptInvalidateGpaOnCurrentVcpu(EPT_INVD_ANY_CONTEXT);
}



NTSTATUS
EptInvaldQueueConsumerRoutine(
    _In_ CPU_IPC_QUEUE *CpuQueue
)
///
/// Custom processing of the messages found in the dedicated TLB invalidation IPC queue
///
{
    return IpcQueueCollapseMessages(CpuQueue, EptInvalidateAllRoutine, IPC_QUEUE_COLLAPSE_CONDITION_ON_DROPPED_MESSAGES, 0);
}



static
CX_VOID
_EptAutoflush(
    _In_ EPT_DESCRIPTOR *Ept,
    _In_ CX_BOOL LockAlreadyAcquired
)
///
/// Check & notify if invalidations are needed for this EPT memory space
///
{
    if (Ept->InvalidationNeeded && Ept->InvalidationRoutine)
    {
        Ept->InvalidationNeeded = 0; // safe, an invalidation 100% follows so we're surely not hiding it by resetting the value

        if (!LockAlreadyAcquired) HvAcquireRwSpinLockShared(&Ept->DestroyLock);
        CX_STATUS status = Ept->InvalidationRoutine(Ept, Ept->InvalidationRoutineContext);
        if (!LockAlreadyAcquired) HvReleaseRwSpinLockShared(&Ept->DestroyLock);

        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("Ept->InvalidationRoutine", status);
        }
    }
}



///
/// @brief        Create mappings such that the given domain translates the EptMemoryMap-described guest addresses to their target host physical addresses. Any host physical addresses used internally by the Hypervisor are skipped and the corresponding translations won't be available through in the EPT memory view.
/// @param[in]    Ept                              Descriptor of the memory space where the translations/mappings should be applied to
/// @param[in]    EptMemoryMap                     Memory map entries describing the new translations to be reflected throught the EPT mappings
/// @returns      CX_STATUS_INVALID_DATA_VALUE     - The caching information for some entry in the given memory map is invalid for EPT
/// @returns      CX_STATUS_SUCCESS                - All map entries were applied to the EPT
///
CX_STATUS
EptCopyTranslationsFromMemoryMap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MMAP*                  EptMemoryMap
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    if (!EptMemoryMap) return CX_STATUS_INVALID_PARAMETER_2;
    if (!EptMemoryMap->Entry || !EptMemoryMap->Count || EptMemoryMap->Count > EptMemoryMap->MaxCount)
    {
        return STATUS_INVALID_MMAP;
    }

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);

    // try to map all corresponding entries from the memory map
    CX_STATUS status = CX_STATUS_SUCCESS;
    MEM_SIZE_IN_BYTES pageSize = (Ept->Use1GbPages ? CX_PAGE_SIZE_1G : CX_PAGE_SIZE_4K);
    struct
    {
        MEM_ALIGNED_PA Base;
        CX_UINT64      PageCount;
        TAS_PROPERTIES Set;
        TAS_PROPERTIES Clear;
        EPT_CACHING    Caching;
    } previous = { 0 }, current = { 0 };


    for (DWORD i = 0; i < EptMemoryMap->Count; i++)
    {
        MEM_MAP_ENTRY* entry = &(EptMemoryMap->Entry[i]);
        if (!LdIsHvMemTypeAvailableToGuests(entry->Type)) continue; // map all types that are valid and NOT restricted to be HV-only

        EPT_PTE_RAW pteCaching;
        pteCaching.Raw = entry->CacheAndRights;
        current.Caching = _EptPteToCaching(pteCaching);
        current.Caching.IgnorePat = 0;
        if (!_EptIsValidCaching(current.Caching))
        {
            ERROR("Got an invalid caching value in the EPT MAP entry[%d]\n", i);
            status = CX_STATUS_INVALID_DATA_VALUE;
            goto cleanup;
        }

        if (Ept->Use1GbPages) current.Caching = EPT_CACHING_WB;

        current.Set             = (TAS_PROPERTIES) { .PagingStructures = 1, .CompleteChain = 1, .InUse = 1, .PageFrame = 1 };
        current.Set.Read        = pteCaching.Read;
        current.Set.Write       = pteCaching.Write;
        current.Set.Execute     = pteCaching.Execute;
        current.Set.Caching     = current.Caching.Raw;

        current.Clear           = (TAS_PROPERTIES) { 0 };
        current.Clear.Read      = !pteCaching.Read;
        current.Clear.Write     = !pteCaching.Write;
        current.Clear.Execute   = !pteCaching.Execute;
        current.Clear.Caching   = (~current.Caching.Raw);

        current.Base            = (Ept->Use1GbPages ? CX_PAGE_BASE_1G(entry->StartAddress) : CX_PAGE_BASE_4K(entry->StartAddress));
        current.PageCount       = (Ept->Use1GbPages ? CX_PAGE_COUNT_1G(entry->StartAddress, entry->Length) : CX_PAGE_COUNT_4K(entry->StartAddress, entry->Length));

        // first, try to merge it into the current page (or at least the overlapping part, if any)
        if (previous.PageCount == 1 && current.Base == previous.Base)
        {
            previous.Set.Raw     |= current.Set.Raw;
            previous.Clear.Raw   &= current.Clear.Raw;
            previous.Caching.Raw = CX_MIN(current.Caching.Raw, previous.Caching.Raw); // 0 is the most restrictive while 6 is the most relaxed caching policy

            // the previous range already contains the overlapped page, remove it from the current interval
            current.Base += pageSize;
            current.PageCount--;
        }

        // second, if current region didn't fit completely (couldn't be simply merged to the previous region/page), map the previous region and continue the processing with what's left of the current one
        if (current.PageCount)
        {
            // flush the previous region (map it)
            if (previous.PageCount)
            {
                TAS_PROPERTIES lack = gTasMapLackProps;
                TAS_PROPERTIES have = gTasMapHaveProps;

                if (Ept->Use1GbPages)
                {
                    previous.Set.Read = 1; previous.Set.Write = 1; previous.Set.Execute = 1;
                    previous.Clear.Read = 0; previous.Clear.Write = 0; previous.Clear.Execute = 0;
                    lack.Raw = 0;
                    have.Raw = 0;
                }

                status = TasMapRangeEx(&Ept->Tas, previous.Base, pageSize * previous.PageCount, previous.Set, previous.Clear, have, lack, previous.Base, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("TasMapRangeEx", status);
                    goto cleanup;
                }
            }

            // and now use the leftovers for the next iteration
            previous = current;
        }
    }

    // flush the remaining entry
    if (previous.PageCount)
    {
        TAS_PROPERTIES lack = gTasMapLackProps;
        TAS_PROPERTIES have = gTasMapHaveProps;

        if (Ept->Use1GbPages)
        {
            previous.Set.Read = 1; previous.Set.Write = 1; previous.Set.Execute = 1;
            previous.Clear.Read = 0; previous.Clear.Write = 0; previous.Clear.Execute = 0;
            lack.Raw = 0;
            have.Raw = 0;
        }

        status = TasMapRangeEx(&Ept->Tas, previous.Base, pageSize * previous.PageCount, previous.Set, previous.Clear, have, lack, previous.Base, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("TasMapRangeEx", status);
            goto cleanup;
        }
    }
    _EptAutoflush(Ept, CX_TRUE);

cleanup:

    HvReleaseRwSpinLockShared(&Ept->DestroyLock);
    return status;
}



static
__forceinline
CX_STATUS
_EptAlterMappingsEx(
    _In_ EPT_DESCRIPTOR*        Ept,                ///< target memory space that needs updated properties
    _In_ MEM_UNALIGNED_PA       Gpa,                ///< address of the first byte that needs changes (additional bytes at lower addresses will suffer changes in the same manner if needed due to page alignment constraints)
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,      ///< specifies how many bytes need their properties being updated, by default (when 0) a single memory page is changed (additional bytes up to the end of the page will be updated too, if needed)
    _In_ EPT_PROPERTIES         SetProperties,      ///< properties that need to be logically true after the mappings are altered
    _In_ EPT_PROPERTIES         ClearProperties,    ///< properties that have to be logically false when the operation is finished
    _In_ MEM_UNALIGNED_PA       NewHpa,             ///< ignored unless SetProperties.PageFrame is 1
    __out_opt EPT_PROPERTIES*   OriginalProperties, ///< properties that were originally true for the region as a whole
    __out_opt MEM_UNALIGNED_PA* OriginalHpa         ///< the beginning host physical address
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    if (!NumberOfBytes) NumberOfBytes = 1;

    CX_STATUS status;

    HvAcquireRwSpinLockShared(&Ept->DestroyLock); // we'll keep the lock until both TasQueryRangeProperties and TasWalkPagesEx finish

    // if the original HPA is being queried, we need to perform a separate call to get its value
    if (OriginalHpa)
    {
        TAS_PROPERTIES props;
        MEM_UNALIGNED_PA pa;

        status = TasQueryRangeProperties(&Ept->Tas, (MEM_UNALIGNED_VA)Gpa, NumberOfBytes, &props, &pa, CX_NULL);
        status = _EptGetPredefinedStatus(status, props);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("TasQueryRangeProperties", status);
            goto cleanup;
        }
        *OriginalHpa = pa;
    }

    TAS_PROPERTIES props;
    status = TasWalkPagesEx(&Ept->Tas, CX_PAGE_BASE_4K(Gpa), (MEM_PAGE_COUNT)CX_PAGE_COUNT_4K(Gpa, NumberOfBytes), SetProperties, ClearProperties, gTasQueryHaveProps, gTasQueryLackProps, CX_NULL, CX_NULL, NewHpa, CX_NULL, CX_NULL, &props);
    if (CX_SUCCESS(status))
    {
        if (OriginalProperties) *OriginalProperties = props;
        _EptAutoflush(Ept, CX_TRUE);
    }

cleanup:

    HvReleaseRwSpinLockShared(&Ept->DestroyLock);
    return status;
}



///
/// @brief        Low-level API allowing any changes (such as rights, caching, destination address) to existing (or new) EPT memory addresses
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              The address of the first byte to be affected. Other bytes at lower addresses may be affected if this address is not aligned to the page size used.
/// @param[in]    NumberOfBytes                    How many bytes should be affected (a full page is considered if this parameter is 0). Additional bytes may be affected due to page alignment.
/// @param[in]    SetProperties                    Properties that need to be TRUE (or with given value) after the processing ends
/// @param[in]    ClearProperties                  Properties that need to be FALSE (or 0 for caching or other such info) after the processing ends
/// @param[in]    NewHpa                           Value for the new destination host physical address of the very first byte, ignored unless SetProperties contains the PageFrame field set
/// @param[out]   OriginalProperties               Will be filled-in with properties that are true for all the addresses in the [Gpa, Gpa + NumberOfBytes) range
/// @param[out]   OriginalHpa                      The host physical address that corresponds to the Gpa value
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptAlterMappingsEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         SetProperties,
    _In_ EPT_PROPERTIES         ClearProperties,
    _In_ MEM_UNALIGNED_PA       NewHpa,
    __out_opt EPT_PROPERTIES    *OriginalProperties,
    __out_opt MEM_UNALIGNED_PA  *OriginalHpa
)
{
    return _EptAlterMappingsEx(Ept, Gpa, NumberOfBytes, SetProperties, ClearProperties, NewHpa, OriginalProperties, OriginalHpa);
}



///
/// @brief        Change the access rights, caching, \#VE control and SPP for a EPT-translated memory region
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              The address of the first byte to be affected. Other bytes at lower addresses may be affected if this address is not aligned to the page size used.
/// @param[in]    NumberOfBytes                    How many bytes should be affected (a full page is considered if this parameter is 0). Additional bytes may be affected due to page alignment.
/// @param[in]    SetProperties                    Rights or other properties to be granted (will be available after the processing ends)
/// @param[in]    ClearProperties                  Properties to clear on the given address space
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptAlterMappings(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         SetProperties,
    _In_ EPT_PROPERTIES         ClearProperties
)
{
    return _EptAlterMappingsEx(Ept, Gpa, NumberOfBytes, SetProperties, ClearProperties, 0, CX_NULL, CX_NULL);
}



///
/// @brief        Change the access rights and the caching type for a EPT-translated memory region
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              The address of the first byte to be affected. Other bytes at lower addresses may be affected if this address is not aligned to the page size used.
/// @param[in]    NumberOfBytes                    How many bytes should be affected (a full page is considered if this parameter is 0). Additional bytes may be affected due to page alignment.
/// @param[in]    Rights                           Rights that will be available after the processing ends
/// @param[in]    Caching                          Caching type for the given address space
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptSetCacheAndRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights,
    _In_ EPT_CACHING            Caching
)
{
    TAS_PROPERTIES set = Rights;

    // the rights to be cleared can't be deduced easily, we need to take into account only the relevant 'rights' fields
    TAS_PROPERTIES clear = { 0 };
    clear.Read      = !Rights.Read;
    clear.Write     = !Rights.Write;
    clear.Execute   = !Rights.Execute;

    set.Caching     = Caching.Raw;
    clear.Caching   = (~Caching.Raw); // clear any bit that's to be set to 0 in the given caching value

    return _EptAlterMappingsEx(Ept, Gpa, NumberOfBytes, set, clear, 0, CX_NULL, CX_NULL);
}



///
/// @brief        Change the access rights and the caching type for a EPT-translated memory region
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              The address of the first byte to be affected. Other bytes at lower addresses may be affected if this address is not aligned to the page size used.
/// @param[in]    NumberOfBytes                    How many bytes should be affected (a full page is considered if this parameter is 0). Additional bytes may be affected due to page alignment.
/// @param[in]    Rights                           Final rights that will be available after the processing ends
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptSetRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights
)
{
    TAS_PROPERTIES set = Rights;

    // the rights to be cleared can't be deduced easily, we need to take into account only the relevant 'rights' fields
    TAS_PROPERTIES clear = { 0 };
    clear.Read      = !Rights.Read;
    clear.Write     = !Rights.Write;
    clear.Execute   = !Rights.Execute;

    return _EptAlterMappingsEx(Ept, Gpa, NumberOfBytes, set, clear, 0, CX_NULL, CX_NULL);
}



///
/// @brief        Change the caching type of a memory region translated through ETP
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              The address of the first byte to be affected. Other bytes at lower addresses may be affected if this address is not aligned to the page size used.
/// @param[in]    NumberOfBytes                    How many bytes should be affected (a full page is considered if this parameter is 0). Additional bytes may be affected due to page alignment.
/// @param[in]    Caching                          New caching type
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptSetCaching(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_CACHING           Caching
)
{
    TAS_PROPERTIES setCaching = { 0 }, clearCaching = { 0 };
    setCaching.Caching      = Caching.Raw;
    clearCaching.Caching    = ~Caching.Raw; // clear any bit that's to be set to 0 in the given caching value

    return _EptAlterMappingsEx(Ept, Gpa, NumberOfBytes, setCaching, clearCaching, 0, CX_NULL, CX_NULL);
}



///
/// @brief        Change the destination host physical address associated with a given input guest physical address
/// @param[in]    Ept                              Descriptor of the EPT memory space to modify
/// @param[in]    Gpa                              Guest physical address whose host physical address needs changing
/// @param[in]    Hpa                              New host physical address
/// @returns      CX_STATUS_SUCCESS                - All changes were succesfully applied
///
CX_STATUS
EptSetHpa(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa
)
{
    return _EptAlterMappingsEx(Ept, Gpa, 0, (TAS_PROPERTIES) { .PageFrame = 1 }, (TAS_PROPERTIES) { 0 }, Hpa, CX_NULL, CX_NULL);
}



///
/// @brief        Query the properties (rights, caching, \#VE and SPP policies) of a given address range translated by the EPT identified via the Ept descriptor sent
/// @param[in]    Ept                              Ept descriptor identifying the memory space
/// @param[in]    Gpa                              First byte whose properties are queried
/// @param[in]    NumberOfBytes                    The number of bytes whose properties are being queried
/// @param[out]   Properties                       Infered properties that are TRUE for the whole input range
/// @param[out]   Hpa                              The host physical address of the first byte at the given Gpa
/// @returns      CX_STATUS_SUCCESS                - The required information was succesfully queried and the output argument values are valid
///
CX_STATUS
EptQueryProperties(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    __out_opt EPT_PROPERTIES   *Properties,
    __out_opt MEM_UNALIGNED_PA  *Hpa
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    if (!NumberOfBytes) NumberOfBytes = 1;

    TAS_PROPERTIES props;
    MEM_UNALIGNED_PA hpa;

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasQueryRangeProperties(&Ept->Tas, Gpa, NumberOfBytes, &props, &hpa, CX_NULL);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    status = _EptGetPredefinedStatus(status, props);
    if (!CX_SUCCESS(status))
    {
        ///LOG_FUNC_FAIL("TasQueryRangeProperties", status);
        return status;
    }

    if (Properties) *Properties = props;
    if (Hpa) *Hpa = Ept->Use1GbPages? CX_PAGE_BASE_1G(hpa) + CX_PAGE_OFFSET_1G(Gpa) : CX_PAGE_BASE_4K(hpa) + CX_PAGE_OFFSET_4K(Gpa);

    return CX_STATUS_SUCCESS;
}



///
/// @brief        Query the access rights available through the EPT translations of the given memory interval
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The address of the first byte in queried address interval
/// @param[in]    NumberOfBytes                    The number of bytes in the interval
/// @param[out]   Rights                           Inferred access rights that are true/valid for the whole address range
/// @returns      CX_STATUS_SUCCESS                - The required information was succesfully queried and the output argument values are valid
///
CX_STATUS
EptGetRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    __out_opt EPT_RIGHTS       *Rights
)
{
    return EptQueryProperties(Ept, Gpa, NumberOfBytes, Rights, CX_NULL);
}



///
/// @brief        Retrieve the host physical address associated with a given input guest physical address through an EPT-translated memory space
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The guest physica address
/// @param[out]   Hpa                              Resulted host physical address
/// @returns      CX_STATUS_SUCCESS                - The input address has a valid translation and output argument is ready for use
///
CX_STATUS
EptGetHpa(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    __out_opt MEM_UNALIGNED_PA  *Hpa
)
{
    return EptQueryProperties(Ept, Gpa, 0, CX_NULL, Hpa);
}



///
/// @brief        Chack if a given guest physical address region is known (has associated valid and properly initialized mapping information inside the translation tables)
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The starting address of the queried interval
/// @param[in]    NumberOfBytes                    The number of bytes in the address range
/// @returns      TRUE                             - the input addresses are known and have valid translation information filled-in or FALSE otherwise
/// @returns      FALSE                            - the input addresses are not known and do not have valid translation information filled-in
///
CX_BOOL
EptIsMemMapped(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    EPT_PROPERTIES props;
    CX_STATUS status = EptQueryProperties(Ept, Gpa, NumberOfBytes, &props, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        return CX_FALSE;
    }
    return CX_TRUE;
}



///
/// @brief        Chack if a given guest physical addresses are readable by the guest
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The starting address of the queried interval
/// @param[in]    NumberOfBytes                    The number of bytes in the address range
/// @returns      TRUE                             - the input addresses are valid and the guest can perform read accesses to any addresses inside the interval without encountering an EPT VIOLATION
/// @returns      FALSE                            - the input addresses are either not mapped or the guest is lacking read access to some address in the interval
///
CX_BOOL
EptIsMemReadable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    EPT_PROPERTIES props;
    CX_STATUS status = EptQueryProperties(Ept, Gpa, NumberOfBytes, &props, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        return CX_FALSE;
    }

    return !!props.Read;
}



///
/// @brief        Chack if a given guest physical addresses can be written by the guest
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The starting address of the queried interval
/// @param[in]    NumberOfBytes                    The number of bytes in the address interval
/// @returns      TRUE                             - the input addresses are valid and the guest can perform write accesses to any addresses inside the interval without encountering an EPT VIOLATION
/// @returns      FALSE                            - the input addresses are either not mapped or the guest is lacking write access to some address in the interval
///
CX_BOOL
EptIsMemWriteable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    EPT_PROPERTIES props;
    CX_STATUS status = EptQueryProperties(Ept, Gpa, NumberOfBytes, &props, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        return CX_FALSE;
    }

    return !!props.Write;
}



///
/// @brief        Chack if a given guest physical addreses can be executed by the guest
/// @param[in]    Ept                              Address of the EPT descriptor identifying the memory space
/// @param[in]    Gpa                              The starting address of the queried interval
/// @param[in]    NumberOfBytes                    The number of bytes in the address interval
/// @returns      TRUE                             - the input addresses are valid and the guest can execute instructions from any addresses inside the interval without encountering an EPT VIOLATION
/// @returns      FALSE                            - the input addresses are either not mapped or the guest is lacking execute access to some address in the interval
///
CX_BOOL
EptIsMemExecutable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    EPT_PROPERTIES props;
    CX_STATUS status = EptQueryProperties(Ept, Gpa, NumberOfBytes, &props, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        return CX_FALSE;
    }

    return !!props.Execute;
}



///
/// @brief        Free all the data structures used for encoding translation information for the given EPT memory space
/// @param[in, out] Ept                              Descriptor identifying the memory space to be teared-down
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The EPT descriptor is NULL
///
NTSTATUS
EptDestroy(
    _Inout_ EPT_DESCRIPTOR  *Ept
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;

    HvAcquireRwSpinLockExclusive(&Ept->DestroyLock);
    CX_STATUS status = TasFreePagingStructures(&Ept->Tas);
    HvReleaseRwSpinLockExclusive(&Ept->DestroyLock);

    return status;
}



///
/// @brief        Calculate the total memory space in bytes occupied by the EPT translation data structures
/// @param[in]    Ept                              Descriptor identifying the memory space to be evaluated
/// @returns      Total number of bytes used by the various page tables currently allocated
///
CX_UINT64
EptGetStructuresSize(
    _In_ EPT_DESCRIPTOR     *Ept
)
{
    if (!Ept) return (CX_UINT64)-1;
    return CX_PAGE_SIZE_4K * Ept->Tas.AllocatedPageTablesCount;
}



static
__forceinline
CX_STATUS
_EptMapEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_ MEM_SIZE_IN_BYTES      NumberOfBytes,
    _In_ EPT_PROPERTIES         Set,
    _In_ EPT_PROPERTIES         Clear,
    _In_ EPT_PROPERTIES         MustHave,
    _In_ EPT_PROPERTIES         MustLack
)
{
    if (!NumberOfBytes) NumberOfBytes = 1;

    // enforce some of the bits that we can't expect the caller to always configure properly...
    Set.PagingStructures = 1;
    Set.CompleteChain = 1;
    Set.InUse = 1;
    Set.PageFrame = 1;

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasMapRangeEx(&Ept->Tas, Gpa, NumberOfBytes, Set, Clear, MustHave, MustLack, Hpa, CX_NULL);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasMapRangeEx", status);
    }

    _EptAutoflush(Ept, CX_FALSE);
    return status;
}



///
/// @brief        Low-level function to create or update/overwrite existing mappings with full control over every setting (rights, caching, SPP, VE)
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens.
/// @param[in]    Hpa                              Starting host physical address that is to be mapped to the guest. Additional bytes below this address might also be mapped. Gpa and Hpa need to have the same page offsets. If the range covers more than one page, the mapped host physical pages will be continuous
/// @param[in]    NumberOfBytes                    Number of bytes that are to be mapped. If 0, a single memory page will be affected. More than NumberOfBytes will be mapped if needed for page alignment constraints.
/// @param[in]    Set                              EPT properties that need to be true on the newly updated mappings (access rights granted, caching type bits etc...)
/// @param[in]    Clear                            EPT properties that need to be false after the mappings are updated,
/// @param[in]    MustHave                         EPT properties that need to already be true for all bytes in the described guest physical memory space
/// @param[in]    MustLack                         EPT properties that have to already be false for all bytes
/// @returns      CX_STATUS_SUCCESS                - The Memory range met the MustHave and MustLack requirements and the [Gpa, Gpa + NumberOfBytes) interval is translated to [Hpa, Hpa + NumberOfBytes) with the access rights, caching and other properties described by the Set and Clear property values
///
CX_STATUS
EptMapEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         Set,
    _In_ EPT_PROPERTIES         Clear,
    _In_ EPT_PROPERTIES         MustHave,
    _In_ EPT_PROPERTIES         MustLack
)
{
    return _EptMapEx(Ept, Gpa, Hpa, NumberOfBytes, Set, Clear, MustHave, MustLack);
}



///
/// @brief        Remove existing mappings (created by EptMapEx) from an EPT domain, making the guest physical addresses untranslatable to any host physical addresses
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens
/// @param[in]    NumberOfBytes                    Number of bytes that are to be unmapped. If 0, a single memory page will be affected. More than NumberOfBytes can be unmapped if needed due to page alignment considerations
/// @returns      CX_STATUS_SUCCESS                - The Memory interval [Gpa, Gpa + NumberOfBytes) has no longer any host physical memory associated and any guest access to this address interval will result in an EPT VIOLATION exit
///
CX_STATUS
EptUnmapEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasUnmapRange(&Ept->Tas, Gpa, NumberOfBytes);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    _EptAutoflush(Ept, CX_FALSE);
    return status;
}



///
/// @brief        Create new EPT mappings with given access rights and caching type
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens.
/// @param[in]    Hpa                              Starting host physical address that is to be mapped to the guest. Additional bytes below this address might also be mapped. Gpa and Hpa need to have the same page offsets. If the range covers more than one page, the mapped host physical pages will be continuous
/// @param[in]    NumberOfBytes                    Number of bytes that are to be mapped. If 0, a single memory page will be affected. More than NumberOfBytes will be mapped if needed for page alignment constraints.
/// @param[in]    Rights                           Access rights to be granted on this memory region
/// @param[in]    Caching                          EPT caching type for memory accesses to this address interval
/// @returns      CX_STATUS_SUCCESS                - The Memory range met the MustHave and MustLack requirements and the [Gpa, Gpa + NumberOfBytes) interval is translated to [Hpa, Hpa + NumberOfBytes) with the access rights, caching and other properties described by the Set and Clear property values
///
CX_STATUS
EptMap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights,
    _In_ EPT_CACHING            Caching
)
{
    TAS_PROPERTIES set = gTasMapSetProps;
    set.Read        = Rights.Read;
    set.Write       = Rights.Write;
    set.Execute     = Rights.Execute;
    set.Caching     = Caching.Raw;

    TAS_PROPERTIES clear = gTasMapClearProps;
    clear.Read      = !Rights.Read;
    clear.Write     = !Rights.Write;
    clear.Execute   = !Rights.Execute;
    clear.Caching   = (~Caching.Raw);

    if (!NumberOfBytes) NumberOfBytes = 1;
    return _EptMapEx(Ept, Gpa, Hpa, NumberOfBytes, set, clear, gTasMapHaveProps, gTasMapLackProps);
}



///
/// @brief        Remove existing mappings (created by EptMap) from an EPT domain, making the guest physical addresses untranslatable to any host physical addresses
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens
/// @param[in]    NumberOfBytes                    Number of bytes that are to be unmapped. If 0, a single memory page will be affected. More than NumberOfBytes can be unmapped if needed due to page alignment considerations
/// @returns      CX_STATUS_SUCCESS                - The Memory interval [Gpa, Gpa + NumberOfBytes) has no longer any host physical memory associated and any guest access to this address interval will result in an EPT VIOLATION exit
///
CX_STATUS
EptUnmap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    return EptUnmapEx(Ept, Gpa, NumberOfBytes);
}



///
/// @brief        Create new EPT mappings with RWX access rights for a guest physical address interval pointing to conventional RAM (meaning Write-Back caching type)
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens.
/// @param[in]    Hpa                              Starting host physical address that is to be mapped to the guest. Additional bytes below this address might also be mapped. Gpa and Hpa need to have the same page offsets. If the range covers more than one page, the mapped host physical pages will be continuous
/// @param[in]    NumberOfBytes                    Number of bytes that are to be mapped. If 0, a single memory page will be affected. More than NumberOfBytes will be mapped if needed for page alignment constraints.
/// @returns      CX_STATUS_SUCCESS                - The Memory range met the MustHave and MustLack requirements and the [Gpa, Gpa + NumberOfBytes) interval is translated to [Hpa, Hpa + NumberOfBytes) with the access rights, caching and other properties described by the Set and Clear property values
///
CX_STATUS
EptMapMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    return EptMap(Ept, Gpa, Hpa, NumberOfBytes, EPT_RIGHTS_RWX, EPT_CACHING_WB);
}



///
/// @brief        Remove existing mappings (created by EptMapMem) from an EPT domain, making the guest physical addresses untranslatable to any host physical addresses
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens
/// @param[in]    NumberOfBytes                    Number of bytes that are to be unmapped. If 0, a single memory page will be affected. More than NumberOfBytes can be unmapped if needed due to page alignment considerations
/// @returns      CX_STATUS_SUCCESS                - The Memory interval [Gpa, Gpa + NumberOfBytes) has no longer any host physical memory associated and any guest access to this address interval will result in an EPT VIOLATION exit
///
CX_STATUS
EptUnmapMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    return EptUnmapEx(Ept, Gpa, NumberOfBytes);
}



///
/// @brief        Create new EPT mappings with RW access rights for a guest physical address interval pointing to memory-mapped device resources (uncacheable memory)
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens.
/// @param[in]    Hpa                              Starting host physical address that is to be mapped to the guest. Additional bytes below this address might also be mapped. Gpa and Hpa need to have the same page offsets. If the range covers more than one page, the mapped host physical pages will be continuous
/// @param[in]    NumberOfBytes                    Number of bytes that are to be mapped. If 0, a single memory page will be affected. More than NumberOfBytes will be mapped if needed for page alignment constraints.
/// @returns      CX_STATUS_SUCCESS                - The Memory range met the MustHave and MustLack requirements and the [Gpa, Gpa + NumberOfBytes) interval is translated to [Hpa, Hpa + NumberOfBytes) with the access rights, caching and other properties described by the Set and Clear property values
///
CX_STATUS
EptMapDevMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    return EptMap(Ept, Gpa, Hpa, NumberOfBytes, EPT_RIGHTS_RW, EPT_CACHING_UC);
}



///
/// @brief        Remove existing mappings (created by EptMapDevMem) from an EPT domain, making the guest physical addresses untranslatable to any host physical addresses
/// @param[in]    Ept                              Pointer to the descriptor identifying the EPT to operate upon
/// @param[in]    Gpa                              Starting guest physical address of the transtions to modify. Additional bytes below this address might also be affected due to page alignmens
/// @param[in]    NumberOfBytes                    Number of bytes that are to be unmapped. If 0, a single memory page will be affected. More than NumberOfBytes can be unmapped if needed due to page alignment considerations
/// @returns      CX_STATUS_SUCCESS                - The Memory interval [Gpa, Gpa + NumberOfBytes) has no longer any host physical memory associated and any guest access to this address interval will result in an EPT VIOLATION exit
///
CX_STATUS
EptUnmapDevMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
)
{
    return EptUnmapEx(Ept, Gpa, NumberOfBytes);
}


typedef struct
{
    MTRR_STATE *Mtrr;
    BOOLEAN CachingChanged;
}EPT_MTRR_UPDATE;


static
CX_STATUS
_EptUpdateCachingBasedOnMtrrs(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ CX_UINT8                   Depth,                  // at what depth is the table or entry located
    _In_opt_ MEM_ALIGNED_VA         TranslatedVa,           // first VA translated through this table OR entry
    _In_ MEM_ALIGNED_PA             Pa,                     // Table PA,
    _In_opt_ MEM_TABLE_OFFSET       Offset,                 // Entry offset (inside the table) when asking for entries
    _In_opt_ MEM_ALIGNED_PA         DestinationPa,          // entries-only: where does the entry (page-frame) point to
    _In_opt_ MEM_SIZE_IN_BYTES      CoveredSize,            // entries-only: how much memory is translated by this entry
    _In_opt_ CX_VOID                *Context                // data sent to the TasIterateStructures function, if any
)
{
    CX_UNREFERENCED_PARAMETER(CoveredSize, Depth, TranslatedVa);
    EPT_MTRR_UPDATE *ctx = (EPT_MTRR_UPDATE *)Context;

    // get to the EPT PTE and extract the caching type
    EPT_PTE *pt;
    CX_STATUS status = Mapping->GetTableVa(Pa, (MEM_UNALIGNED_VA*)&pt);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Mapping->GetTableVa", status);
        return status;
    }
    EPT_PTE *pte = (EPT_PTE *)((CX_UINT8 *)pt + Offset);
    EPT_CACHING origCaching = _EptPteToCaching(*pte);
    EPT_CACHING newCaching = origCaching;

    // get the most restrictive caching affecting the DestinationPa as described by the MTRRs
    if (origCaching.MemoryType != HVA_CACHING_UC)
    {
        EPT_PTE_RAW mtrrPteBits = { 0 };
        EPT_CACHING mtrrCaching;
        for (DWORD mtrrIndex = 0; mtrrIndex < ctx->Mtrr->Map.Count; mtrrIndex++)
        {
            MEM_MAP_ENTRY *mapEntry = &ctx->Mtrr->Map.Entry[mtrrIndex];
            if ((DestinationPa >= mapEntry->StartAddress) && (DestinationPa < mapEntry->StartAddress + mapEntry->Length))
            {
                mtrrPteBits.PteCacheAndRights = mapEntry->CacheAndRights;
                mtrrCaching = _EptPteToCaching(mtrrPteBits);

                newCaching.MemoryType = CX_MIN(newCaching.MemoryType, mtrrCaching.MemoryType);
            }
        }
    }
    if (newCaching.Raw < origCaching.Raw)
    {
        pte->MemoryType = newCaching.MemoryType;
        ctx->CachingChanged = CX_TRUE;
    }
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Reflect MTRR caching settings to the caching values assigned through the EPT data structures to a guest memory domain
/// @param[in, out] Ept                            Ept descriptor targeted for the caching settings update
/// @param[in]    Mtrr                             MTRR values to inspect for copying any caching value differences
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The EPT descriptor pointer is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - The MTRR state pointer us NULL
/// @returns      CX_STATUS_SUCCESS                - The caching settings for all addresses translated through the given EPT are up-to-date with respect to the MTRR values
///
NTSTATUS
EptUpdateCachingFromMtrrs(
    _Inout_ EPT_DESCRIPTOR      *Ept,
    _In_ MTRR_STATE             *Mtrr
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Mtrr) return CX_STATUS_INVALID_PARAMETER_2;

    EPT_MTRR_UPDATE ctx;
    ctx.Mtrr = Mtrr;
    ctx.CachingChanged = CX_FALSE;

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasIterateStructures(&Ept->Tas, 0, Ept->Tas.RootPa, 0, Ept->Tas.PagingDepth,
        TAS_ITERATION_MODE_LEAFS_ONLY, TAS_ITERATION_TARGET_ENTRIES, _EptUpdateCachingBasedOnMtrrs, &ctx);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasIterateStructures", status);
        goto cleanup;
    }
    _EptAutoflush(Ept, CX_FALSE);
cleanup:
    return status;
}



static
CX_STATUS
_EptCloneCb(
    _In_ TAS_DESCRIPTOR                 *Source,
    _In_opt_ MEM_ALIGNED_VA             StartVa,
    _In_ MEM_ALIGNED_PA                 StartPa,
    _In_ MEM_SIZE_IN_BYTES              Size,
    _In_ TAS_PROPERTIES                 Properties,             // only R/W/X are guaranteed to be valid
    _In_opt_ EPT_DESCRIPTOR             *Destination
)
{
    UNREFERENCED_PARAMETER(Source);

    // these next two bits should already be set (as long as our decoder callback is well-behaved), but it's harmless to enforce them anyway
    Properties.PageFrame = 1;
    Properties.PagingStructures = 1;
    Properties.InUse = 1;
    CX_STATUS status = TasMapRangeEx(&Destination->Tas, StartVa, Size, Properties, gTasMapClearProps, gTasMapHaveProps, gTasMapLackProps, StartPa, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasMapRange", status);
    }
    return status;
}



///
/// @brief        This function will clone the translations defined by SourceEpt into the DestinationEpt memory domain.
/// @param[out]   DestinationEpt                   Destination EPT to create the source translations to. Any existing DestinationEpt translations also defined by SourceEpt will be overwritten with the SourceEpt data
/// @param[in]    SourceEpt                        Ept descriptor describing the translations that need to be copied to the DestinationEpt
/// @returns      CX_STATUS_SUCCESS                - Any guest physical address that has a valid mapping via SourceEpt points to the same physical address in the DestinationEpt and has the same settings (access rights, caching etc...)
///
CX_STATUS
EptCopyTranslations(
    _Inout_ EPT_DESCRIPTOR      *DestinationEpt,
    _In_ EPT_DESCRIPTOR         *SourceEpt
)
{
    TAS_PROPERTIES breakOnChangesMask = { .Read = 1, .Write = 1, .Execute = 1, .BypassVe = 1, .Spp = 1, .Caching = TAS_CACHING_MASK, .ContinuousPa = 1 };

    HvAcquireRwSpinLockShared(&SourceEpt->DestroyLock);
    HvAcquireRwSpinLockShared(&DestinationEpt->DestroyLock);
    CX_STATUS status = TasIterateMappings(&SourceEpt->Tas, breakOnChangesMask, _EptCloneCb, DestinationEpt);
    HvReleaseRwSpinLockShared(&DestinationEpt->DestroyLock);
    HvReleaseRwSpinLockShared(&SourceEpt->DestroyLock);

    if (!CX_SUCCESS(status))
    {
        CX_STATUS tempStatus = EptDestroy(DestinationEpt);
        if (!CX_SUCCESS(tempStatus))
        {
            ERROR("EptDestroy failed: 0x%08x\n", tempStatus);
        }
    }

    return status;
}



/**
* @brief Extended-Page-Table Pointer (EPTP)
*
* The extended-page-table pointer (EPTP) contains the address of the base of EPT PML4 table, as well as other EPT
* configuration information.
*
* @see Vol3C[28.2.2(EPT Translation Mechanism]
* @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP)] (reference)
*/
typedef union
{
    struct
    {
        UINT64 MemoryType                   : 3;
        UINT64 PageWalkLength               : 3;
        UINT64 EnableAccessAndDirtyFlags    : 1;
        UINT64 Reserved1                    : 5;
        UINT64 PageFrameNumber              : 36;
        UINT64 Reserved2 : 16;
    };
    UINT64 Raw;
} EPT_POINTER;

#define EPT_PAGE_WALK_LENGTH_4                                       0x00000003
#define EPT_POINTER_PAGE_FRAME_NUMBER(_)                             (((_) >> 12) & 0xFFFFFFFFF)


CX_STATUS
EptGetRawEptpValue(
    _In_ EPT_DESCRIPTOR         *Ept,
    __out_opt CX_UINT64         *RawEptpValue
)
{
    CX_UINT64 rootPa;
    CX_STATUS status = EptGetRootPa(Ept, &rootPa);
    if (!SUCCESS(status)) return status;

    EPT_POINTER eptp        = { 0 };
    eptp.PageFrameNumber    = EPT_POINTER_PAGE_FRAME_NUMBER(rootPa);
    eptp.MemoryType         = (EPT_RAW_CACHING_WB >> 3);
    eptp.PageWalkLength     = EPT_PAGE_WALK_LENGTH_4;

    if (RawEptpValue) *RawEptpValue = eptp.Raw;

    return CX_STATUS_SUCCESS;
}


///
/// @brief        Print a full listing of all guest memory address translations (address values, caching type, rights) defined through the given EPT descriptor
/// @param[in]    Ept                              EPT descriptor for the memory domain to print
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The EPT descriptor sent is NULL
/// @returns      CX_STATUS_SUCCESS                - All EPT translations were decoded and printed
///
CX_STATUS
EptDumpMappings(
    _In_ EPT_DESCRIPTOR *Ept
)
{
    if (!Ept) return CX_STATUS_INVALID_PARAMETER_1;
    TAS_PROPERTIES breakOn = { .Read = 1, .Write = 1, .Execute = 1, /*.Caching = TAS_CACHING_MASK,*/ .BypassVe = 1, .Spp = 1, .Special = 1 };

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasDumpMappings(&Ept->Tas, breakOn);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    return status;
}



///
/// @brief        Decode and dump the information encoded inside an EPT page table structure
/// @param[in]    Pte                              An EPT page table structure entry
/// @param[in]    IsLeaf                           TRUE when this is an actual PTE (Page-Table Entry) and not a higher-level entry, FALSE otherwise
///
CX_VOID
EptDumpPte(
    _In_ EPT_PTE_RAW        Pte,
    _In_ CX_BOOL            IsLeaf
)
{
    LOGN(
        "PA=0x%llX/ACCESS=(%s%s%s%s%s%s)/CACHING=%s",
        CX_PAGE_SIZE_4K * Pte.PageFrame,

        (Pte.Read ? "R" : ""),
        (Pte.Write ? "W" : ""),
        (Pte.Execute ? "X" : ""),
        (IsLeaf && Pte.Spp ? ".SPP" : ""),
        (IsLeaf && !Pte.BypassVe ? ".#VE" : ""),
        (IsLeaf && Pte.HvDeviceMem ? ".DEV" : ""),

        (Pte.MemoryType == HVA_CACHING_UC ? "UC" : Pte.MemoryType == HVA_CACHING_WB ? "WB" : "??")
    );
}



///
/// @brief        Decode and dump a brief listing of the memory characteristics entailed by a given EPT structure entry
/// @param[in]    E                                An EPT page table structure entry
/// @param[in]    IsLeaf                           TRUE when this is an actual PTE as opposed to a higher-level entry, FALSE otherwise
///
CX_VOID
EptDumpPteRaw(
    _In_ EPT_PTE_RAW        E,
    _In_ CX_BOOL            IsLeaf
)
{
    CX_UNREFERENCED_PARAMETER(IsLeaf);
    LOGN("R:%lld W:%lld X:%lld A:%lld D:%lld !VE:%lld SPP:%lld DEV:%lld I:%lld MT:%lld U:%lld",
        E.Read,
        E.Write,
        E.Execute,
        E.Accessed,
        E.Dirty,
        E.BypassVe,
        E.Spp,
        E.HvDeviceMem,
        E.IgnorePat,
        E.MemoryType,
        E.HvInUse
    );
}



///
/// @brief        Given a guest physical address, display all relevant EPT data structures (including their properties) that control any guest memory accesses to the specified address.
/// @param[in]    Ept                              EPT memory descriptor identifying the guest memory domain
/// @param[in]    Gpa                              Guest physical address of interest
/// @returns      CX_STATUS_SUCCESS                - The data structures exist and have been successfully decoded and printed
///
CX_STATUS
EptDumpTranslationInfo(
    _In_ EPT_DESCRIPTOR     *Ept,
    _In_ MEM_UNALIGNED_PA   Gpa
)
{
    TAS_PAGING_STRUCTURE_INFO path[4];
    TAS_PROPERTIES props, valid;

    HvAcquireRwSpinLockShared(&Ept->DestroyLock);
    CX_STATUS status = TasGetPagingPathInfo(&Ept->Tas, (MEM_UNALIGNED_VA)Gpa, FALSE, FALSE, FALSE, 0, path, &props, &valid);
    HvReleaseRwSpinLockShared(&Ept->DestroyLock);

    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
        goto cleanup;
    }
    LOG("Translation info for GPA=%llX given Root=%llX\n", Gpa, Ept->Tas.RootPa);
    for (CX_UINT8 i = 0; i < Ept->Tas.PagingDepth; i++)
    {
        EPT_PTE_RAW pte;
        pte.Raw = (path[i].TableEntryVa ? *(QWORD *)path[i].TableEntryVa : 0);

        LOGN("lvl%d tableIndex=%4d, tableEntry=%16llX -- ", i, path[i].Index, pte);
        EptDumpPte(pte, i == 3);
        LOGN(" (");
        EptDumpPteRaw(pte, i == 3);
        LOGN(" )\n");
    }
cleanup:

    return status;
}
/// @}