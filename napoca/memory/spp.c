/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup spp Sub-page protection support
/// ingroup memory
/// @{
#include "napoca.h"
#include "memory/spp.h"
#include "guests/guests.h"
#include "memory/ept.h"
#include "memory/hva.h"
#include "boot/phase1.h"

#define SPP_PAGING_DEPTH                4

#define SPP_PAGE_OFFSET_BITS            12ull
#define SPP_TABLE_INDEX_BITS            9
#define SPP_TABLE_ENTRY_MASK            511

#pragma pack(push, 1)
typedef union _SPP_NON_LEAF_TABLE_ENTRY_SHADOW
{
    struct
    {
        QWORD                   Valid           : 1;

        QWORD                   __reserved1_11  : 11;

        // bits 63:N are reserved, where N is the processor's physical-address width
        QWORD                   PageFrame       : 52;
    };

    QWORD                       Raw;
} SPP_NON_LEAF_TABLE_ENTRY_SHADOW;
typedef volatile SPP_NON_LEAF_TABLE_ENTRY_SHADOW SPP_NON_LEAF_TABLE_ENTRY;
static_assert(sizeof(SPP_NON_LEAF_TABLE_ENTRY_SHADOW) == 8,
    "Intel Instruction Set Extensions and Future Features April 2019 - 3.5.2 Operation of SPPT-based Write-Permission");

typedef union _SPP_LEAF_TABLE_ENTRY_SHADOW
{
    QWORD                       Raw;
} SPP_LEAF_TABLE_ENTRY_SHADOW;
typedef volatile SPP_LEAF_TABLE_ENTRY_SHADOW SPP_LEAF_TABLE_ENTRY;
static_assert(sizeof(SPP_LEAF_TABLE_ENTRY_SHADOW) == 8,
    "Intel Instruction Set Extensions and Future Features April 2019 - 3.5.2 Operation of SPPT-based Write-Permission");

#pragma pack(pop)

static
CX_STATUS
_SppGetTableInfoCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           TranslatedVa,
    _In_ CX_UINT8                   TableDepth,
    _In_opt_ MEM_ALIGNED_PA         TablePa,                // TAS will either know where exactly the table is located
    _In_ HVA_PTE                    *UpperLevelEntryVa,     // or the upper-level table entry that links to it
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *TableInfo
);

static
CX_STATUS
_SppAlterTableEntryCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ SPP_NON_LEAF_TABLE_ENTRY   *TableEntry,            // where should the changes go
    _In_ CX_UINT8                   TableDepth,             // at what depth the paging structure is (the TableEntry that needs changes)
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these properties
    _In_ CX_BOOL                    IsFirstPageInRange,     // used for ContinuousPa and/or chaining deduction
    _In_ CX_BOOL                    IsLastPageInRange,      // used for chaining deduction
    _In_ MEM_ALIGNED_PA             PhysicalPage            // where should the mapping point to (ignore unless SetProperties.PageFrame)
);

static
CX_STATUS
_SppInitializeTableCb(
    _In_ TAS_DESCRIPTOR     *Mapping,
    _In_ CX_UINT8           TableDepth,                     // 0 for the top-level structure, 1 for the next level etc
    _Out_ MEM_ALIGNED_VA    Va,                             // a valid RW mapping of the physical page
    _Out_ MEM_ALIGNED_PA    Pa                              // the PA of the allocated page
);


static
CX_STATUS
_SppGetTableInfoCb(
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
{
    UNREFERENCED_PARAMETER((IsLastPageInRange, PreviousPa, IsFirstPageInRange));

    TAS_PAGING_STRUCTURE_INFO info = { 0 };

    CX_UINT64 vaShiftAmount = SPP_PAGE_OFFSET_BITS + (SPP_TABLE_INDEX_BITS * (Mapping->PagingDepth - TableDepth - 1));
    info.Index = (((CX_UINT64)TranslatedVa) >> vaShiftAmount) & SPP_TABLE_ENTRY_MASK;

    info.ValidPropertiesMask.Read = 1;


    info.TablePa = UpperLevelEntryVa? (CX_PAGE_SIZE_4K * UpperLevelEntryVa->PageFrame) : TablePa;
    CX_STATUS status = Mapping->GetTableVa(info.TablePa, (MEM_UNALIGNED_VA *)&info.TableVa);
    if (info.TablePa && CX_SUCCESS(status))
    {
        info.TableEntryVa = &(((SPP_NON_LEAF_TABLE_ENTRY_SHADOW*)(info.TableVa))[info.Index]);
        info.NextLevelTablePa = CX_PAGE_SIZE_4K * ((SPP_NON_LEAF_TABLE_ENTRY*)(info.TableEntryVa))->PageFrame;

        SPP_NON_LEAF_TABLE_ENTRY pte = *((SPP_NON_LEAF_TABLE_ENTRY*)info.TableEntryVa);

        info.Properties.Read = pte.Valid;
        info.Properties.PageFrame = !!pte.PageFrame;

        CX_BOOL isLeaf = (TableDepth + 1 == Mapping->PagingDepth);
        info.IsLeafTableEntry = !!isLeaf;
    }

    *TableInfo = info;

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_SppAlterTableEntryCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ SPP_NON_LEAF_TABLE_ENTRY   *TableEntry,            // where should the changes go
    _In_ CX_UINT8               TableDepth,             // at what depth the paging structure is (the TableEntry that needs changes)
    _In_ TAS_PROPERTIES         SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES         ClearProperties,        // clear these properties
    _In_ CX_BOOL                IsFirstPageInRange,     // used for ContinuousPa and/or chaining deduction
    _In_ CX_BOOL                IsLastPageInRange,      // used for chaining deduction
    _In_ MEM_ALIGNED_PA         PhysicalPage            // where should the mapping point to (ignore unless SetProperties.PageFrame)
    )
{
    UNREFERENCED_PARAMETER((IsFirstPageInRange, IsLastPageInRange));

    BOOLEAN isLeaf = (TableDepth + 1 == Mapping->PagingDepth);
    if (isLeaf)
    {
        CRITICAL("SPP at leaf, we do no support modifying SPP table leaf values through the TAS interface!\n");
        return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    const SPP_NON_LEAF_TABLE_ENTRY origPte = *TableEntry;
    SPP_NON_LEAF_TABLE_ENTRY newPte = origPte;

    // R/W/X doesn't make sense for SPP
    if (SetProperties.DefaultTableBits)
        newPte.Valid = 1;

    if (SetProperties.PageFrame || ClearProperties.PageFrame)
        newPte.PageFrame = ClearProperties.PageFrame ? 0 : CX_PAGE_FRAME_NUMBER_4K(PhysicalPage);

    // not a leaf entry -- only accept PageFrame changes (which may also define the P&W bits)
    // only allow setting the page frame when not already populated
    if (SetProperties.PageFrame)
    {
        if (origPte.PageFrame || (origPte.Raw != HvInterlockedCompareExchangeU64(&(TableEntry->Raw), newPte.Raw, origPte.Raw)))
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

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_SppInitializeTableCb(
    _In_ TAS_DESCRIPTOR     *Mapping,
    _In_ CX_UINT8           TableDepth,                     // 0 for the top-level structure, 1 for the next level etc
    _Out_ MEM_ALIGNED_VA    Va,                             // a valid RW mapping of the physical page
    _Out_ MEM_ALIGNED_PA    Pa                              // the PA of the allocated page
)
{
    UNREFERENCED_PARAMETER((Mapping, TableDepth, Pa));

    memzero((CX_VOID*)Va, CX_PAGE_SIZE_4K);
    return CX_STATUS_SUCCESS;
}

NTSTATUS
_GetSppLeafForGpa(
    _In_        MEM_ALIGNED_PA          GuestPhysicalAddress,
    _In_        BOOLEAN                 Autovivify,
    _Outptr_    SPP_LEAF_TABLE_ENTRY    **Pte
    )
{
    static TAS_DESCRIPTOR _sppTasDesc = {
        .PagingDepth            = SPP_PAGING_DEPTH,
        .RootPa                 = 0,
        .GetTableVa             = HvaGetHvaPagingStructureVaCallback,
        .GetTableInfo           = _SppGetTableInfoCb,
        .AlterTableEntry        = _SppAlterTableEntryCb,
        .AllocPagingStructure   = FinalAllocPagingStructureCallback,
        .InitPagingStructure    = _SppInitializeTableCb,
        .FreePagingStructure    = FinalFreePagingStructureCallback
    };

    TAS_PAGING_STRUCTURE_INFO pagingPath[SPP_PAGING_DEPTH];

    NTSTATUS status = TasGetPagingPathInfo(
        &_sppTasDesc,
        GuestPhysicalAddress,
        Autovivify,
        TRUE,
        TRUE,
        NULL,
        pagingPath,
        NULL,
        NULL
    );
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasGetPagingPathInfo", status);
        goto cleanup;
    }

    if (Autovivify)
    {
        GUEST* guest = HvGetCurrentGuest();
        if (guest->SpptRootVa == NULL)
        {
            guest->SpptRootVa = pagingPath[0].TableVa;
            guest->SpptRootPa = pagingPath[0].TablePa;

            HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1 << guest->VcpuCount) - 1);
        }
    }

    if (!pagingPath[SPP_PAGING_DEPTH - 1].IsLeafTableEntry)
    {
        status = STATUS_PAGE_NOT_PRESENT;
        goto cleanup;
    }

    *Pte = (SPP_LEAF_TABLE_ENTRY*)(pagingPath[SPP_PAGING_DEPTH - 1].TableEntryVa);
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

NTSTATUS
SppSetPageProtection(
    _In_    MEM_ALIGNED_PA      GuestPhysicalAddress,
    _In_    QWORD               SppValue            // raw value to be stored "as is" in a SPP leaf-table entry
    )
{
    NTSTATUS status;
    GUEST* guest = HvGetCurrentGuest();

    SPP_LEAF_TABLE_ENTRY* pte = NULL;
    status = _GetSppLeafForGpa(GuestPhysicalAddress, TRUE, &pte);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_GetSppLeafForGpa", status);
        goto cleanup;
    }

    // we need to invalidate only if we change any subpage protection rights
    if (pte->Raw == SppValue)
    {
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }

    pte->Raw = SppValue;
    EPT_DESCRIPTOR *ept;
    status = GstGetEptDescriptorEx(guest, GuestPredefinedMemoryDomainIdPhysicalMemory, &ept);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetEptDescriptor", status);
        goto cleanup;
    }

    // If SppValue is 0       => epte->SPP = 0 (SppValue == 0 means SPP doesn't affect rights)
    // for any other SppValue => epte->SPP = 1
    EPT_PROPERTIES set = { 0 }, clear = { 0 };
    set.Spp = !!SppValue;
    clear.Spp = !SppValue;

    status = EptAlterMappings(ept, GuestPhysicalAddress, 0, set, clear);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptAlterMappings", status);
        goto cleanup;
    }
    EptInvalidateTlbs(guest, EPT_INVD_ANY_CONTEXT, FALSE);
cleanup:
    return status;
}

NTSTATUS
SppGetPageProtection(
    _In_    MEM_ALIGNED_PA      GuestPhysicalAddress,
    _Out_   QWORD               *SppValue
    )
{
    SPP_LEAF_TABLE_ENTRY* pte = NULL;

    NTSTATUS status = _GetSppLeafForGpa(GuestPhysicalAddress, FALSE, &pte);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_GetSppLeafForGpa", status);
        goto cleanup;
    }

    *SppValue = pte->Raw;

    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}
/// @}