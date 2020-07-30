/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup tas Translated address space
/// @ingroup memory
/// @{
#include "napoca.h"
#include "memory/tas.h"
#include "memory/mdl.h"


#define TAS_LOGN(...)                       LOGN(__VA_ARGS__)                   ///< naked log macro (without any built-in additional text)
#define TAS_LOG(...)                        LOG(__VA_ARGS__)                    ///< macro for logging TAS messages
#define TAS_WARNING(...)                    WARNING("[WARNING] " __VA_ARGS__)   ///< macro for emitting standardized warnings from the TAS code
#define TAS_ERROR(...)                      ERROR("[ERROR] " __VA_ARGS__)       ///< provide standardized TAS error messages
#define TAS_LOG_FUNC_FAIL(fn, status)       LOG_FUNC_FAIL(fn, status)           ///< macro for signaling CX_STATUS errors


#define VA_MAX_THEORETICAL_PAGING_DEPTH             10                          ///< harcoded value that allows avoiding a coupling / dependency with the heap (or other dynamic allocator)

static
__forceinline
CX_BOOL
_TasIsLeaf(
    _In_ TAS_DESCRIPTOR *Mapping,
    _In_ CX_UINT8 Depth
)
{
    return (Depth + 1 == Mapping->PagingDepth);
}

static
__forceinline
CX_STATUS
_TasAllocAndLinkPageTable(
    _In_ TAS_DESCRIPTOR *Mapping,
    _In_ CX_VOID *RootEntry,
    _In_ CX_INT8 TableDepth,
    _In_ CX_BOOL IsFirstPageInRange,
    _In_ CX_BOOL IsLastPageInRange
)
// allocate a new page table and link it to the given page table entry, without altering other root entry bits except for the PageFrame
{
    CX_VOID *tableVa;
    MEM_ALIGNED_PA tablePa;

    CX_STATUS status = Mapping->AllocPagingStructure(Mapping, 1 + TableDepth, (MEM_ALIGNED_VA *)&tableVa, &tablePa);
    if (!CX_SUCCESS(status))
    {
        TAS_LOG_FUNC_FAIL("Mapping->AllocPage", status);
        goto cleanup;
    }

    if (Mapping->InitPagingStructure)
    {
        status = Mapping->InitPagingStructure(Mapping, 1 + TableDepth, (MEM_ALIGNED_VA)tableVa, tablePa);
        if (!CX_SUCCESS(status))
        {
            TAS_LOG_FUNC_FAIL("Mapping->AllocPage", status);
            goto cleanup;
        }
    }

    if (-1 == TableDepth)
    {
        // this is the descriptor-defined root PA (known and managed by the Tas* code)
        if (0 != CxInterlockedCompareExchange64((volatile CX_UINT64*)RootEntry, tablePa, 0))
        {
            status = CX_STATUS_ALREADY_INITIALIZED_HINT;
            goto cleanup;
        }
    }
    else
    {
        TAS_PROPERTIES setProps = { 0 };
        TAS_PROPERTIES clearProps = { 0 };
        setProps.PageFrame = 1;
        setProps.DefaultTableBits = 1;

        status = Mapping->AlterTableEntry(Mapping, RootEntry, TableDepth, setProps, clearProps, IsFirstPageInRange, IsLastPageInRange, tablePa);
        if (!CX_SUCCESS(status))
        {
            TAS_LOG_FUNC_FAIL("Mapping->AlterTableEntry", status);
            goto cleanup;
        }
    }
    status = CX_STATUS_SUCCESS;
cleanup:
    if (CX_STATUS_ALREADY_INITIALIZED_HINT == status)
    {
        Mapping->FreePagingStructure(Mapping, (MEM_ALIGNED_VA)tableVa, tablePa);
    }
    else
    {
        CxInterlockedIncrement64(&Mapping->AllocatedPageTablesCount);
    }

    return status;
}



///
/// @brief        Recursive walk of the paging structures and table entries.
/// @param[in]    Mapping                          TAS descriptor of the memory domain to process
/// @param[in]    StartingVa                       virtual address of the first byte that is translated through the starting node / paging structure defined by TablePa found at TableDept
/// @param[in]    TablePa                          start iterating the structures at this particular paging structures node, this parameter has to be consistent with the StartingVa
/// @param[in]    TableDepth                       at what depth is this table (the starting node) found
/// @param[in]    MaxDepth                         impose a limit on the maximum depth of the nodes allowed to be visited
/// @param[in]    IterationMode                    defines node ordering and whether or not all nodes need to be reported to the provided callback function
/// @param[in]    Target                           specifies if the actual tables or their contained entries are to be reported
/// @param[in]    Callback                         this routine will receive the tables and/or entries iterated
/// @param[in]    Context                          additional callback-defined data to send to the callback routine
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Mapping is NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_8    - No callback function was provided (the argument is NULL)
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - The registered IterateTables descriptor callback is NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasIterateStructures(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_opt_ MEM_ALIGNED_VA         StartingVa,
    _In_ MEM_UNALIGNED_PA           TablePa,
    _In_ CX_UINT8                   TableDepth,
    _In_ CX_UINT8                   MaxDepth,
    _In_ TAS_ITERATION_MODE         IterationMode,
    _In_ TAS_ITERATION_TARGET       Target,
    _In_ TAS_ITERATE_STRUCTURES_CB  Callback,
    _In_ CX_VOID                    *Context
)
{
    if (!Mapping) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Mapping->IterateTables) return CX_STATUS_OPERATION_NOT_SUPPORTED;
    if (!Callback) return CX_STATUS_INVALID_PARAMETER_8;

    if (TableDepth >= MaxDepth) return CX_STATUS_SUCCESS;

    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_BOOL processAtReturn = CX_FALSE;
    MEM_ALIGNED_VA currentVa = StartingVa;

    // process current table before visiting recursively the child tables
    if (Target == TAS_ITERATION_TARGET_TABLES)
    {
        // when we're at the max depth or processing top-down it's safe to process here, at the beginning of the function
        if (IterationMode == TAS_ITERATION_MODE_TOP_DOWN || TableDepth + 1 == MaxDepth)
        {
            status = Callback(Mapping, TableDepth, StartingVa, TablePa, 0, 0, 0, Context);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("TasIterateStructures::Callback", status);
                return status;
            }
        }
        else
        {
            // the table still needs to be processed but we're only allowed to do it after its child tables
            processAtReturn = CX_TRUE;
        }
    }

    // iterate the entries if they're targeted or if the next level tables are needed (and not beyond MaxDepth)
    if (Target == TAS_ITERATION_TARGET_ENTRIES || TableDepth + 1 < MaxDepth)
    {
        MEM_TABLE_OFFSET currentTableOffset, nextTableOffset = 0;
        do
        {
            MEM_ALIGNED_VA sizeIncrement;
            CX_BOOL nextTableIsValid;
            MEM_UNALIGNED_PA nextTablePa;
            MEM_UNALIGNED_VA tableVa;
            currentTableOffset = nextTableOffset;

            // get the current child and next sibling of the current entry
            CX_BOOL isLeaf;
            status = Mapping->IterateTables(Mapping, TablePa, &tableVa, TableDepth, &nextTableOffset, &sizeIncrement, &nextTablePa, &nextTableIsValid, &isLeaf);
            if (CX_SUCCESS(status) && nextTableIsValid)
            {
                // process the entry if all entries are targeted or TAS_ITERATION_MODE_LEAFS_ONLY and we're at last level
                if (Target == TAS_ITERATION_TARGET_ENTRIES && (IterationMode != TAS_ITERATION_MODE_LEAFS_ONLY || TableDepth + 1 == MaxDepth || isLeaf))
                {
                    status = Callback(Mapping, TableDepth, currentVa, TablePa, (MEM_TABLE_OFFSET)currentTableOffset, nextTablePa, sizeIncrement, Context);
                    if (!CX_SUCCESS(status))
                    {
                        LOG_FUNC_FAIL("TasIterateStructures::Callback", status);
                        goto cleanup;
                    }
                }

                // process the child table
                if (!isLeaf)
                {
                    status = TasIterateStructures(Mapping, currentVa, nextTablePa, TableDepth + 1, MaxDepth, IterationMode, Target, Callback, Context);
                    if (!CX_SUCCESS(status) && (status != CX_STATUS_NO_MORE_ENTRIES))
                    {
                        LOG_FUNC_FAIL("TasIterateStructures", status);
                        goto cleanup;
                    }
                }
            }

            // take into account the size translated through this entry
            currentVa += sizeIncrement;
        } while (CX_SUCCESS(status));
    }

    // `no more entries` is the expected status at this point
    if (status != CX_STATUS_NO_MORE_ENTRIES) goto cleanup;
    status = CX_STATUS_SUCCESS;

    // finally, process the originally-sent table if needed
    if (processAtReturn)
    {
        status = Callback(Mapping, TableDepth, StartingVa, TablePa, 0, 0, 0, Context);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("TasIterateStructures::Callback", status);
        }
    }
cleanup:
    return status;
}


static
CX_STATUS
_TasFreeTableCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ CX_UINT8                   Depth,                  // at what depth is the table or entry located
    _In_opt_ MEM_ALIGNED_VA         TranslatedVa,           // first VA translated through this table OR entry
    _In_ MEM_ALIGNED_PA             Pa,                     // table PA,
    _In_opt_ MEM_TABLE_OFFSET       Offset,                 // entry offset (inside the table) when asking for entries
    _In_opt_ MEM_ALIGNED_PA         DestinationPa,          // entries-only: where does the entry (page-frame) point to
    _In_opt_ MEM_SIZE_IN_BYTES      CoveredSize,            // entries-only: how much memory is translated by this entry
    _In_opt_ CX_VOID                *Context                // data sent to the TasIterateStructures function, if any
)
//
// Callback used for freeing the paging structures backing up a mapping through the TasFreePagingStructures function
// IMPORTANT: Don't call directly, this is only a helper function for TasFreePagingStructures
//
{
    UNREFERENCED_PARAMETER((Depth, TranslatedVa, Context, Offset, DestinationPa, CoveredSize));

    if (!Mapping) return CX_STATUS_INVALID_PARAMETER_1;

    MEM_ALIGNED_VA va;
    CX_STATUS status = Mapping->GetTableVa(Pa, &va);
    if (!CX_SUCCESS(status))
    {
        return status;
    }

    status = Mapping->FreePagingStructure(Mapping, va, Pa);
    if (CX_SUCCESS(status))
    {
        CxInterlockedDecrement64(&Mapping->AllocatedPageTablesCount);
    }
    return status;
}



///
/// @brief        Free all the memory resources used by the page table structures defining the mappings and properties of a TAS
/// @param[in]    Mapping                          Target TAS to tear down
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - The given TAS descriptor does not provide the necessary callbacks (.IterateTables and .FreePagingStructure) to make this operation possible
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasFreePagingStructures(
    _In_ TAS_DESCRIPTOR             *Mapping
)
{
    if (!Mapping->IterateTables || !Mapping->FreePagingStructure)
    {
        TAS_WARNING("(!Mapping->IterateTables=%p || !Mapping->FreePagingStructure=%p)\n", Mapping->IterateTables, Mapping->FreePagingStructure);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return TasIterateStructures(Mapping, 0, Mapping->RootPa, 0, Mapping->PagingDepth, TAS_ITERATION_MODE_BOTTOM_UP, TAS_ITERATION_TARGET_TABLES, _TasFreeTableCb, CX_NULL);
}


typedef struct
{
    TAS_ITERATE_MAPPINGS_CB         OrigCallback;
    CX_VOID                         *OrigContext;
    MEM_ALIGNED_VA                  StartVa;
    MEM_ALIGNED_PA                  StartPa;
    MEM_SIZE_IN_BYTES               Size;
    CX_BOOL                         Initialized;
    TAS_PROPERTIES                  BreakOnChangesMask;
    TAS_PROPERTIES                  Properties;
    TAS_PROPERTIES                  ValidProperties;
}TAS_INTERATE_MAPPINGS_CONTEXT;


static
CX_STATUS
_TasIterateMappingsCb(
    _In_ TAS_DESCRIPTOR             *Mapping,               // target TAS descriptor
    _In_ CX_UINT8                   Depth,                  // at what depth is the table or entry located
    _In_opt_ MEM_ALIGNED_VA         TranslatedVa,           // first VA translated through this table OR entry
    _In_ MEM_ALIGNED_PA             Pa,                     // Table PA,
    _In_opt_ MEM_TABLE_OFFSET       Offset,                 // Entry offset (inside the table) when asking for entries
    _In_opt_ MEM_ALIGNED_PA         DestinationPa,          // entries-only: where does the entry (page-frame) point to
    _In_opt_ MEM_SIZE_IN_BYTES      CoveredSize,            // entries-only: how much memory is translated by this entry
    _In_opt_ CX_VOID                *Context                // data sent to the TasIterateStructures function, if any
)
//
// Coalesce page-by-page translations into address intervals and call the function sent to TasIterateMappings on each interval
// IMPORTANT: Don't call directly, this is only a helper function for TasIterateMappings
//
{
    UNREFERENCED_PARAMETER(Offset);
    TAS_INTERATE_MAPPINGS_CONTEXT *ctx = (TAS_INTERATE_MAPPINGS_CONTEXT*)Context;

    TAS_PAGING_STRUCTURE_INFO info;
    CX_STATUS status = Mapping->GetTableInfo(Mapping, TranslatedVa, Depth, Pa, CX_NULL, FALSE, FALSE, 0, &info);
    if (!SUCCESS(status))
    {
        return status;
    }

    TAS_PROPERTIES commonValidProps;
    commonValidProps.Raw = ctx->ValidProperties.Raw & info.ValidPropertiesMask.Raw;
    commonValidProps.ContinuousPa = 0; // this property is deduced and maintained "by hand" to simplify logic (FirstPageInRange/LastPageInRange deduction)
    CX_BOOL doBreak = !ctx->Initialized;

    // break if the VA is non-contiguous
    doBreak |= (ctx->StartVa + ctx->Size) != TranslatedVa;

    // break if the PA should be continuous but it's not
    doBreak |= ctx->BreakOnChangesMask.ContinuousPa && ((ctx->StartPa + ctx->Size) != DestinationPa);

    // break if any valid bits in BreakOnChangesMask have changed from the previous / last page
    doBreak |= (info.Properties.Raw & ctx->BreakOnChangesMask.Raw & commonValidProps.Raw) != (ctx->Properties.Raw & ctx->BreakOnChangesMask.Raw & commonValidProps.Raw);

    if (doBreak)
    {
        if (ctx->Initialized)
        {
            // flush the old translated range
            status = ctx->OrigCallback(Mapping, ctx->StartVa, ctx->StartPa, ctx->Size, ctx->Properties, ctx->OrigContext);
            if (!SUCCESS(status))
            {
                TAS_LOG_FUNC_FAIL("ctx->OrigCallback", status);
                goto cleanup;
            }
        }

        // start another range here
        ctx->StartVa = TranslatedVa;
        ctx->StartPa = DestinationPa;
        ctx->Properties = info.Properties;
        ctx->ValidProperties = info.ValidPropertiesMask;
        ctx->Size = CoveredSize;
        ctx->Initialized = CX_TRUE;
    }
    else
    {
        ctx->Size += CoveredSize;
        ctx->Properties = TasCombineProperties(info.Properties, info.ValidPropertiesMask, ctx->Properties, ctx->ValidProperties, &ctx->ValidProperties);
    }
cleanup:
    return status;
}



///
/// @brief        Parse all the paging structures and call the provided Callback on each distinct memory interval mapped.inside the given Mapping
/// @param[in]    Mapping                          TAS descriptor of the memory domain whose defined address translations and properties need to be investigated
/// @param[in]    BreakOnChangesMask               defines the properties that MUST be constant throughout each and every reported whole interval, and, any change of any of these properties from an address to the next one marks the start of a new memory interval
/// @param[in]    Callback                         the address intervals and their properties are reported to this callback function
/// @param[in]    Context                          custom context data to send to the callback routine
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - the input Mapping argument must be non-null
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - a non-null callback function is necessary
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasIterateMappings(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ TAS_PROPERTIES             BreakOnChangesMask,
    _In_ TAS_ITERATE_MAPPINGS_CB    Callback,
    _In_ CX_VOID                    *Context
)
{
    if (!Mapping)
    {
        TAS_LOG_FUNC_FAIL("TasIterateMappings", CX_STATUS_INVALID_PARAMETER_1);
        return CX_STATUS_INVALID_PARAMETER_1;
    }


    if (!Callback)
    {
        TAS_LOG_FUNC_FAIL("TasIterateMappings", CX_STATUS_INVALID_PARAMETER_3);
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    TAS_INTERATE_MAPPINGS_CONTEXT ctx = { 0 };
    ctx.OrigCallback = Callback;
    ctx.OrigContext = Context;
    ctx.BreakOnChangesMask = BreakOnChangesMask;
    CX_STATUS status = TasIterateStructures(Mapping, 0, Mapping->RootPa, 0, Mapping->PagingDepth, TAS_ITERATION_MODE_LEAFS_ONLY, TAS_ITERATION_TARGET_ENTRIES, _TasIterateMappingsCb, &ctx);
    if (!SUCCESS(status))
    {
        TAS_LOG_FUNC_FAIL("TasIterateStructures", status);
        return status;
    }
    // flush the very last cached interval, if there is one
    if (ctx.Initialized && ctx.Size)
    {
        status = ctx.OrigCallback(Mapping, ctx.StartVa, ctx.StartPa, ctx.Size, ctx.Properties, ctx.OrigContext);
        if (!SUCCESS(status))
        {
            TAS_LOG_FUNC_FAIL("ctx.OrigCallback", status);
        }
    }
    return status;
}

static
__forceinline
CX_STATUS
_TasGetPagingPathInfo(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_ CX_BOOL                    AutoVivifyMissingTables,
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _In_ CX_BOOL                    ContinuousVaReuse,      // a continuous traversal allows reusing precalculated Path data from the previous VA call
    _Inout_ TAS_PAGING_STRUCTURE_INFO *Path,
    __inout_opt TAS_PROPERTIES      *PathProperties,
    __inout_opt TAS_PROPERTIES      *ValidPathPropertiesMask
)
// Fill in the necessary info about all the paging structures through which an address is translated, and, optionally, autovivify any missing such structures
{
    CX_STATUS status;
    CX_UINT8 pagingDepth = Mapping->PagingDepth;

    // by default, consider the root identity mapped -- so, provide an initial table value based on this assumption
    CX_VOID *upperEntry = (CX_VOID *)&Mapping->RootPa; // this is where the very first link will be made if the root table is to be vivified
    TAS_PROPERTIES properties = { 0 };
    TAS_PROPERTIES validPropertiesMask = { 0 };
    for (CX_UINT8 depth = 0; depth < pagingDepth; depth++)
    {
        CX_BOOL canReusePrecomputedData = ContinuousVaReuse && ((depth + 1) < pagingDepth) && Path[depth + 1].TableVa && Path[depth + 1].HasSuccessor;
        if (!canReusePrecomputedData)
        {
            // allow two tries for getting the info, first 'as is' and a second one after populating the page table (if needed&allowed)
            for (CX_UINT8 twice = 0; twice < 2; twice++)
            {
                // ask for the level=depth table info
                status = Mapping->GetTableInfo(Mapping, Va, depth, 0, upperEntry, IsFirstPageInRange, IsLastPageInRange, PreviousPa, &(Path[depth]));
                if (!CX_SUCCESS(status))
                {
                    TAS_LOG_FUNC_FAIL("Mapping->GetTableInfo", status);
                    goto cleanup;
                }


                // get to the next table unless there is a need (and possibility) for autovivification
                if (Path[depth].TableVa || !AutoVivifyMissingTables) break;

                // ((CX_INT8)depth) - 1: when we allocate a paging structure for depth N, its address must be linked by an entry at depth N-1
                status = _TasAllocAndLinkPageTable(Mapping, upperEntry, ((CX_INT8)depth) - 1, IsFirstPageInRange, IsLastPageInRange);
                if (!CX_SUCCESS(status))
                {
                    TAS_LOG_FUNC_FAIL("_TasAllocAndLinkPageTable", status);
                    goto cleanup; // yes, it's an error, we've been asked to fill-in any missing tables and it failed
                }
            }
        }

        // account for any newly defined/valid bits
        properties = TasCombineProperties(Path[depth].Properties, Path[depth].ValidPropertiesMask, properties, validPropertiesMask, &validPropertiesMask);

        if (Path[depth].IsLeafTableEntry)
        {
            break; // stop if it's some kind of a large page
        }

        // advance, the upper entry is found in the current table and the actual new table is defined by this new entry
        upperEntry = Path[depth].TableEntryVa;
    }
    if (PathProperties) *PathProperties = properties;
    if (ValidPathPropertiesMask) *ValidPathPropertiesMask = validPropertiesMask;
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



///
/// @brief        Inquire information about the paging data structures actively used on a given TAS if an input VA would be translated to its associated PA
/// @param[in]    Mapping                          TAS descriptor of the memory domain
/// @param[in]    Va                               input address considered for the translation mechanism in question
/// @param[in]    AutoVivifyMissingTables          if 1, missing paging structures are to be allocated and populated automatically while performing the query
/// @param[in]    IsFirstPageInRange               information useful only when chaining and continuous PA deduction is needed
/// @param[in]    IsLastPageInRange                information useful only when chaining and continuous PA deduction is needed
/// @param[in]    PreviousPa                       information useful only when chaining and continuous PA deduction is needed
/// @param[out]   Path                             array of TAS_PAGING_STRUCTURE_INFO to fill in with the information gathered from each level of paging structures
/// @param[out]   PathProperties                   combined properties deduced from the properties given at each level
/// @param[out]   ValidPathPropertiesMask          defines the properties that have valid/defined value, any field set to 0 is considered an undefined property value and should not be used
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasGetPagingPathInfo(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_ CX_BOOL                    AutoVivifyMissingTables,
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *Path,
    _Out_opt_ TAS_PROPERTIES        *PathProperties,
    _Out_opt_ TAS_PROPERTIES        *ValidPathPropertiesMask
)
{
    return _TasGetPagingPathInfo(Mapping, Va, AutoVivifyMissingTables, IsFirstPageInRange, IsLastPageInRange, PreviousPa, CX_FALSE, Path, PathProperties, ValidPathPropertiesMask);
}


static
__forceinline
CX_STATUS
_TasWalkPagesEx(
    _In_ TAS_DESCRIPTOR             *Mapping,               // mapping descriptor
    _In_ MEM_ALIGNED_VA             Va,                     // starting address of a VA range
    _In_opt_ MEM_PAGE_COUNT         PageCount,              // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these
    _In_ TAS_PROPERTIES             MustHaveProperties,     // stop unless these properties are met for each and every VA page, BEFORE setting/clearing bits
    _In_ TAS_PROPERTIES             MustLackProperties,     // stop if some of these are present for any of the covered VA pages, BEFORE setting/clearing bits
    _In_opt_ TAS_WALK_MDL_CB        MdlCallback,            // optional, if sent will be called for processing the physical pages backing-up the VA range
    _In_opt_ CX_VOID                *MdlCallbackData,       // additional data to send to the callback function
    _In_ MEM_ALIGNED_PA             PaStart,                // used when SetProperties.PageFrame + SetProperties.ContinuousPa
    _In_ MDL                        *Mdl,                   // used when SetProperties.PageFrame + !SetProperties.ContinuousPa
    _Out_opt_ MEM_PAGE_COUNT        *TotalPagesWalked,      // if non-null will be filled-in with how many have been processed up to this point
    _Out_opt_ TAS_PROPERTIES        *Properties             // the inferred properties of the VA space walked, BEFORE setting/clearing bits
)
//
// When possible, avoid using this function directly and opt for a simpler wrapper instead...
//
{
    CX_STATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    if (CX_PAGE_OFFSET_4K((CX_UINT64)Va))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    if ((SetProperties.Raw & ClearProperties.Raw) || (MustHaveProperties.Raw & MustLackProperties.Raw))
    {
        return CX_STATUS_INCONSISTENT_DATA_VALUE;
    }

    TAS_PAGING_STRUCTURE_INFO pagingPath[VA_MAX_THEORETICAL_PAGING_DEPTH];
    MEM_ALIGNED_PA          mappedPa = 0;
    MEM_ALIGNED_PA          nextPaToMap = 0;
    MEM_ALIGNED_PA          prevPa = 0;
    MEM_PAGE_COUNT          pageIndex = 0;

    MDL_ITERATE_CONTEXT     mdlContext = { 0 };
    CX_UINT32               mdlEntryIndex = 0;
    CX_UINT32               mdlPageIndex = 0;

    CX_BOOL                 isWalkingByChain = (!Mdl && !PageCount);
    CX_BOOL                 isAtFirstPage = CX_TRUE;
    CX_BOOL                 isAtLastPage = CX_FALSE;
    CX_BOOL                 isAtFirstMdl = CX_TRUE;
    CX_BOOL                 fullVaHasPaMappings = CX_FALSE;
    TAS_PROPERTIES          properties = { 0 }, validPropertiesMask = { 0 };
    TAS_PROPERTIES          mustLackIntermediateProperties = MustLackProperties;

    mustLackIntermediateProperties.ContinuousPa = 0;    // don't consider an issue any two consecutive pages being continuously mapped
    mustLackIntermediateProperties.CompleteChain = 0;   // a chain does not have to be broken at every point if it 'MustLack' the CompleteChain properties
    if (SetProperties.ContinuousPa || Mdl)
    {
        nextPaToMap = (SetProperties.ContinuousPa ? PaStart : CX_PAGE_BASE_4K(Mdl->Entry[mdlEntryIndex].BaseAddress));
    }

    if (MdlCallback || SetProperties.Raw || ClearProperties.Raw)
    {
        // the paging structures must be already filled-in if the already present physical addresses are needed
        // or when changes have to be made without allowing autotivification of the upper-level page tables
        MustHaveProperties.PagingStructures = 1;
    }

    do
    {
        // decode current translation and locate the PTe
        MEM_SIZE_IN_BYTES pageSize;
        TAS_PROPERTIES pathProperties, validPathProperties;
        status = _TasGetPagingPathInfo(Mapping, Va, !!SetProperties.PagingStructures, isAtFirstPage, isAtLastPage, prevPa, !isAtFirstPage, pagingPath, &pathProperties, &validPathProperties);
        if (!CX_SUCCESS(status))
        {
            TAS_LOG_FUNC_FAIL("_TasGetPagingPathInfo", status);
            goto cleanup;
        }

        // is this the very last page that need to be processed?
        if (isWalkingByChain)
        {
            if (!pathProperties.PagingStructures)
            {
                status = CX_STATUS_DATA_NOT_FOUND;
                goto cleanup;
            }
            if (!pathProperties.Chained)
            {
                isAtLastPage = CX_TRUE;
                pathProperties.CompleteChain = pathProperties.ChainLimit;
                MustHaveProperties.Chained = 0; // the last page in a chain can't be expected to be linked any further
            }
        }
        else
        {
            if (!Mdl)
                isAtLastPage = pageIndex + 1 >= PageCount;
            else
                isAtLastPage = (mdlEntryIndex + 1 == Mdl->EntryCount && mdlPageIndex + 1 == Mdl->Entry[mdlEntryIndex].PageCount);

            if (isAtLastPage) pathProperties.CompleteChain = pathProperties.ChainLimit;
        }

        // check properties constraints
        properties = TasCombineProperties(pathProperties, validPathProperties, properties, validPropertiesMask, &validPropertiesMask);
        if (
                // missing properties that must be globally present
                ((properties.Raw & MustHaveProperties.Raw) != MustHaveProperties.Raw) ||
                // present properties that should be missing for each address
                (properties.Raw & mustLackIntermediateProperties.Raw) ||
                // properties that, in the end, should not be globally present
                (isAtLastPage && (properties.Raw & MustLackProperties.Raw))
           )
        {
            /// very useful logs but we can't afford to keep active as intro will spam us when scanning for the highest mapped EPT address   (maybe add a setting into the TAS descriptor telling how rigorous the code is?)
//             TAS_LOG("TasCombineProperties(0x%llX): properties=%llX(", Va, properties.Raw);
//             TasDumpProperties(properties);
//             TAS_LOGN("), mustHave=%llX(", MustHaveProperties.Raw);
//             TasDumpProperties(MustHaveProperties);
//             TAS_LOGN("), mustLack = %llX(", MustLackProperties.Raw);
//             TasDumpProperties(MustLackProperties);
//             TAS_LOGN("), mustLackInt = %llX(", mustLackIntermediateProperties.Raw);
//             TasDumpProperties(mustLackIntermediateProperties);
//             TAS_LOGN(")\n");

            return STATUS_ACCESS_REQUIREMENTS_NOT_MET;
        }

        // find the leaf entry where the final mapping resides
        TAS_PAGING_STRUCTURE_INFO *leafInfo = CX_NULL;
        CX_UINT8 leafDepth = 0;
        for (CX_UINT8 i = 0; i < Mapping->PagingDepth; i++)
        {
            if (pagingPath[i].IsLeafTableEntry)
            {
                leafInfo = &pagingPath[i];
                leafDepth = i;
                break;
            }
        }
        if (leafInfo)
        {
            mappedPa = leafInfo->NextLevelTablePa; // the leaf points to the mapped page
            pageSize = 1ull << leafInfo->EntryMappingSizeExponent;
        }
        else
        {
            pageSize = CX_PAGE_SIZE_4K; // the walk will advance only by the minimum page-size known to TAS
            if (MustHaveProperties.PagingStructures)
            {
                // there's some inconsistency in the behavior, either STATUS_ACCESS_REQUIREMENTS_NOT_MET should have been returned
                // or the leaf table entry should exist (one of _VaGetPagingPathInfo or _VaCombineProperties has somehow failed)
                status = CX_STATUS_INVALID_INTERNAL_STATE;
                goto cleanup;
            }
        }

        // we need to know if the callback mdl is VA continuous or not
        if (isAtFirstPage)
        {
            fullVaHasPaMappings = !!properties.PageFrame;
        }
        else if (!properties.PageFrame)
        {
            fullVaHasPaMappings = CX_FALSE;
        }

        // fill-in and pass the backing physical pages to the callback function if asked to
        if (MdlCallback && fullVaHasPaMappings)
        {
            status = MdlIterate(mappedPa, pageSize, &mdlContext);
            if (status == CX_STATUS_DATA_BUFFER_TOO_SMALL)
            {
                // this is guaranteed not the last call as the current PA didn't fit and will need a new mdl for it
                status = MdlCallback(mdlContext.Mdl, isAtFirstMdl, CX_FALSE, MdlCallbackData);
                if (!CX_SUCCESS(status))
                {
                    TAS_LOG_FUNC_FAIL("MdlCallback", status);
                    goto cleanup;
                }
                isAtFirstMdl = CX_FALSE;
            }
            else if (!CX_SUCCESS(status))
            {
                TAS_LOG_FUNC_FAIL("MdlIterate", status);
                goto cleanup;
            }
        }

        //
        // alter the PTE bits -- don't take any locks as the resource mapped through this VA range must be synchronized externally if used
        // concurrently: if some "thread" is writing while another is removing the write access, it is a problem with that resource's management
        // and not a problem the VA mapper can solve (even if the operation would be atomic, it is still an issue for the two threads)
        //
        if (SetProperties.Raw || ClearProperties.Raw)
        {
            status = Mapping->AlterTableEntry(Mapping, leafInfo->TableEntryVa, leafDepth, SetProperties, ClearProperties, isAtFirstPage, isAtLastPage, nextPaToMap);
            if (!CX_SUCCESS(status))
            {
                TAS_LOG_FUNC_FAIL("Mapping->AlterTableEntry", status);
                goto cleanup;
            }
        }

        // advance VA & PA
        isAtFirstPage = CX_FALSE;
        CX_UINT32 coveredPages = (CX_UINT32)(CX_PAGE_COUNT_4K(0, pageSize)); // no truncation unless pageSize would be at least 16T...
        pageIndex += coveredPages; // the interface assumes we're receiving a number of 4K pages as argument of the function, count all the logical pages even if the physical page is larger
        prevPa = mappedPa;
        Va = (MEM_ALIGNED_VA)(CX_SIZE_T)((CX_UINT64)Va + pageSize);
        if (!isWalkingByChain)
        {
            nextPaToMap += pageSize;
            if (Mdl)
            {
                CX_BOOL mdlDepleted = CX_FALSE;
                for (CX_UINT32 mdlPageCount = 0; mdlPageCount < coveredPages; mdlPageCount++)
                {
                    // advance the mdl address and check if the above += did overflow the current entry
                    mdlPageIndex++;

                    if (mdlPageIndex >= Mdl->Entry[mdlEntryIndex].PageCount)
                    {
                        mdlPageIndex = 0;
                        mdlEntryIndex++;

                        if (mdlEntryIndex < Mdl->EntryCount)
                        {
                            nextPaToMap = CX_PAGE_BASE_4K(Mdl->Entry[mdlEntryIndex].BaseAddress);

                            // when the VA page covers multiple 4K pages (if we're past the mdlPageCount=0 value), make sure the physical pages are continuous as they're all part of a single (continuos) VA page
                            if (mdlPageCount && (prevPa + CX_PAGE_SIZE_4K * (mdlPageCount + 1) != nextPaToMap))
                            {
                                // the MDL isn't describing a continuous 4K-paged interval while the page tables are using a (continuous) page larger than 4K
                                status = CX_STATUS_ALIGNMENT_INCONSISTENCY;
                                TAS_ERROR("Can't map a set of discontinuous 4K MDL pages over a large page of size 0x%llX\n", pageSize);
                                goto cleanup;
                            }
                        }
                        else
                        {
                            // done, last page of the last entry has just been processed
                            mdlDepleted = CX_TRUE; // mark the need of a break out of the outer loop too
                            break;
                        }
                    }
                }
                if (mdlDepleted) break;
            }
        }

        // stop at max allowed pages
        if (PageCount && pageIndex >= PageCount) break;
    } while (!isAtLastPage);

    status = CX_STATUS_SUCCESS;

cleanup:

    // final flush for freeing any remaining cached PA pages
    if (CX_SUCCESS(status) && MdlCallback)
    {
        status = MdlCallback(
            mdlContext.Mdl && mdlContext.Mdl->TotalPageCount ? mdlContext.Mdl : CX_NULL,
            isAtFirstMdl,
            CX_TRUE,
            MdlCallbackData
        );

        if (!CX_SUCCESS(status))
        {
            TAS_LOG_FUNC_FAIL("MdlCallback", status);
            goto cleanup;
        }
    }
    if (TotalPagesWalked) *TotalPagesWalked = pageIndex;

    if (Properties) *Properties = properties;

    return status;
}


///
/// @brief        Low-level and complex routine, see the more specialized API when available for the type of operation needed! This function offers page table traversal for the purpose of gathering information and/or performing changes to the paging structures, capable of providing most of the TAS functionality but too complex to call in most scenarios when simpler and higher-level API already covers most of this function's use-cases
/// @param[in]    Mapping                          address of the TAS descriptor for the memory domain to operate upon
/// @param[in]    Va                               virtual address where the walk (data structures traversal) should start
/// @param[in]    PageCount                        three use-cases for limiting the amount of memory being processed: a) with a Mdl, PageCount decides if the walk should touch at most PageCount entries (0 makes this additional limitation to be ignored); b) exactly PageCount entries will be processed when no Mdl is given and PageCount is non-zero; c) if no Mdl is given and PageCount is zero, use pre-existing chaining information to limit the operation on a single set of chained-together memory pages
/// @param[in]    SetProperties                    perform the needed changes such that these properties get to be true when the walk finishes
/// @param[in]    ClearProperties                  clear these logic properties
/// @param[in]    MustHaveProperties               stop unless these properties are met (before any changes being applied) for each and every address
/// @param[in]    MustLackProperties               stop if some of these properties are present (before making any changes) for any of the covered virtual addresses
/// @param[in]    MdlCallback                      optional, if sent, this function will be called for custom processing of the physical pages backing-up the VA range
/// @param[in]    MdlCallbackData                  optional and callback-defined data that is to be forwarded to the MdlCallback function each time it is called
/// @param[in]    PaStart                          if SetProperties.PageFrame and SetProperties.ContinuousPa are both true, the virtual address space subject to the operation will be (re)directed to link to (map to) continuous physical addresses starting with/at PaStart
/// @param[in]    Mdl                              when SetProperties.PageFrame is true and SetProperties.ContinuousPa is false, this MDL will provide backing physical memory to be mapped at the input iterated virtual addresses
/// @param[out]   TotalPagesWalked                 optional, returns the number of pages (no matter their actual sizes) that were processed
/// @param[out]   Properties                       the inferred original properties of the VA space walked (before any changes have been performed)
/// @returns      CX_STATUS_ALIGNMENT_INCONSISTENCY - the input virtual address does not have the correct alignment needed for this operation to succeed
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasWalkPagesEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             Va,
    _In_opt_ MEM_PAGE_COUNT         PageCount,
    _In_ TAS_PROPERTIES             SetProperties,
    _In_ TAS_PROPERTIES             ClearProperties,
    _In_ TAS_PROPERTIES             MustHaveProperties,
    _In_ TAS_PROPERTIES             MustLackProperties,
    _In_opt_ TAS_WALK_MDL_CB        MdlCallback,
    _In_opt_ CX_VOID                *MdlCallbackData,
    _In_ MEM_ALIGNED_PA             PaStart,
    _In_ MDL                        *Mdl,
    _Out_opt_ MEM_PAGE_COUNT        *TotalPagesWalked,
    _Out_opt_ TAS_PROPERTIES        *Properties
)
{
    if (CX_PAGE_OFFSET_4K(Va) || CX_PAGE_OFFSET_4K(PaStart))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }
    return _TasWalkPagesEx(Mapping, Va, PageCount, SetProperties, ClearProperties, MustHaveProperties, MustLackProperties, MdlCallback, MdlCallbackData, PaStart, Mdl, TotalPagesWalked, Properties);
}



///
/// @brief        Create mappings for the physical pages described by a MDL inside the virtual address space, starting at the given virtual address (Va)
/// @param[in]    Mapping                          address of the TAS descriptor for the memory domain to operate upon
/// @param[in]    Va                               starting virtual address for the address interval to map to the MDL physical pages
/// @param[in]    SetProperties                    perform the needed changes such that these properties get to be true when the operation ends
/// @param[in]    ClearProperties                  clear these logic properties
/// @param[in]    MustHaveProperties               stop unless these properties are met (before any changes being applied) for each and every address
/// @param[in]    MustLackProperties               stop if some of these properties are present (before making any changes) for any of the covered virtual addresses
/// @param[in]    Mdl                              backing physical memory for the affected virtual address range
/// @param[out]   NumberOfPagesMapped              optional, returns the number of pages that were mapped
/// @returns      CX_STATUS_ALIGNMENT_INCONSISTENCY - the input virtual address has to be page-aligned (to an implementation-specific page size value, and, at least 4KiB in size)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasMapMdlEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             Va,
    _In_ TAS_PROPERTIES             SetProperties,
    _In_ TAS_PROPERTIES             ClearProperties,
    _In_ TAS_PROPERTIES             MustHaveProperties,
    _In_ TAS_PROPERTIES             MustLackProperties,
    _In_ MDL                        *Mdl,
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfPagesMapped
)
{
    if (CX_PAGE_OFFSET_4K(Va))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }
    return _TasWalkPagesEx(Mapping, Va, 0, SetProperties, ClearProperties, MustHaveProperties, MustLackProperties, CX_NULL, CX_NULL, 0, Mdl, NumberOfPagesMapped, CX_NULL);
}



///
/// @brief        Map a continuous virtual-address interval to a continuous physical-address interval or simply change or query properties of pre-existing mappings at the given input Va
/// @param[in]    Mapping                          pointer to the TAS descriptor of the memory domain to add the new mappings to
/// @param[in]    Va                               starting input virtual address (additional bytes at lower addresses might be affected due to page-alignment constraints)
/// @param[in]    Size                             the number of bytes in the VA/PA intervals, or, it can be 0 to make use of pre-existing chaining information at the given Va
/// @param[in]    SetProperties                    make these properties logically true
/// @param[in]    ClearProperties                  clear these
/// @param[in]    MustHaveProperties               stop unless these properties are met for each and every VA page, before setting/clearing bits
/// @param[in]    MustLackProperties               stop if some of these are present for any of the covered VA pages, before setting/clearing bits
/// @param[in]    PaStart                          the start of the new destination addresses for translations of the input address interval; this argument is ignored and no mapping changes are performed unless SetProperties.PageFrame and SetProperties.ContinuousPa are both true
/// @param[out]   NumberOfPagesMapped              returns the number of pages in the address range
/// @returns      CX_STATUS_ALIGNMENT_INCONSISTENCY - input Va has inconsistent page offset relatiev to the value of  PaStart
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasMapRangeEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,
    _In_ TAS_PROPERTIES             SetProperties,
    _In_ TAS_PROPERTIES             ClearProperties,
    _In_ TAS_PROPERTIES             MustHaveProperties,
    _In_ TAS_PROPERTIES             MustLackProperties,
    _In_ MEM_UNALIGNED_PA           PaStart,
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfPagesMapped
)
{
    if (CX_PAGE_OFFSET_4K(Va) != CX_PAGE_OFFSET_4K(PaStart))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }
    SetProperties.ContinuousPa = 1;
    return _TasWalkPagesEx(Mapping, CX_PAGE_BASE_4K(Va), Size ? (MEM_PAGE_COUNT)CX_PAGE_COUNT_4K(Va, Size) : 0, SetProperties, ClearProperties, MustHaveProperties, MustLackProperties, CX_NULL, CX_NULL, CX_PAGE_BASE_4K(PaStart), CX_NULL, NumberOfPagesMapped, CX_NULL);
}



///
/// @brief        Apply changes to the properties of the mappings defined for a given virtual address range
/// @param[in]    Mapping                          destination TAS whose translation properties are subject of the changes
/// @param[in]    Va                               starting address of the affected interval (additional memory at lower addresses may be altered if needed for page-alignment limitations)
/// @param[in]    Size                             the number of bytes in the interval (additional bytes may be affected up to a page boundary) or 0 to deduce the size based on pre-existing chaining information at the destination Va
/// @param[in]    SetProperties                    perform the needed changes to enforce these properties
/// @param[in]    ClearProperties                  make these properties logically false
/// @param[in]    MustHaveProperties               stop unless these properties are met for each and every VA page before any current changes
/// @param[in]    MustLackProperties               stop if some of these are present for any of the covered VA pages before any current changes
/// @param[out]   NumberOfAlteredPages             if called with Size = 0, returns the number of pages found in the chain
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasAlterRangeEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,
    _In_ TAS_PROPERTIES             SetProperties,
    _In_ TAS_PROPERTIES             ClearProperties,
    _In_ TAS_PROPERTIES             MustHaveProperties,
    _In_ TAS_PROPERTIES             MustLackProperties,
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfAlteredPages
)
{
    return _TasWalkPagesEx(Mapping, CX_PAGE_BASE_4K(Va), Size ? (MEM_PAGE_COUNT)CX_PAGE_COUNT_4K(Va, Size) : 0, SetProperties, ClearProperties, MustHaveProperties, MustLackProperties, CX_NULL, CX_NULL, 0, CX_NULL, NumberOfAlteredPages, CX_NULL);
}



typedef struct
{
    MEM_ALIGNED_PA  FirstPa;
    CX_BOOL         Valid;
}GET_FIRST_PA_CB_CONTEXT;

static
CX_STATUS
_GetFirstPaCb(
    _In_ MDL *Mdl,                                          // (partial) mdl describing the backing PA pages for a VA mapping
    _In_ CX_BOOL First,                                     // only set when this is the last mdl for the given operation
    _In_ CX_BOOL Last,                                      // only set when this is the last mdl for the given operation
    _In_ CX_VOID *CallbackContext                           // user data for the callback
)
{
    UNREFERENCED_PARAMETER(Last);
    GET_FIRST_PA_CB_CONTEXT *ctx = (GET_FIRST_PA_CB_CONTEXT*) CallbackContext;
    if (!CallbackContext) return CX_STATUS_INVALID_PARAMETER_1;

    if (First && MdlIsPopulated(Mdl))
    {
        ctx->FirstPa = CX_PAGE_BASE_4K(Mdl->Entry[0].BaseAddress);
        ctx->Valid = CX_TRUE;
    }
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Query the properties of a range of virtual addresses
/// @param[in]    Mapping                          TAS descriptor of the memory domain to inspect
/// @param[in]    Va                               starting address of the range
/// @param[in]    Size                             range size (in bytes) or zero to auto-determine a fully-chained memory range
/// @param[out]   Properties                       the inferred overall properties met the addresses in the input address interval
/// @param[out]   PaStart                          will be filled-in with the physical address corresponding to Va and is only defined when the resulting Properties.PageFrame is true
/// @param[out]   TotalPages                       the total number of pages (of unknown / implementation defined sizes) that compose the address range
/// @returns      CX_STATUS_INVALID_DATA_VALUE     - An invalid or undefined physical address was encountered inside the page-table structures
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasQueryRangeProperties(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,
    _Out_opt_ TAS_PROPERTIES        *Properties,
    _Out_opt_ MEM_ALIGNED_PA        *PaStart,
    _Out_opt_ MEM_PAGE_COUNT        *TotalPages
)
{
    GET_FIRST_PA_CB_CONTEXT ctx = { 0 };
    TAS_PROPERTIES properties = { 0 };

    CX_STATUS status = _TasWalkPagesEx(
        Mapping,
        CX_PAGE_BASE_4K(Va),
        Size ? (MEM_PAGE_COUNT)CX_PAGE_COUNT_4K(Va, Size) : 0,
        gTasQuerySetProps,
        gTasQueryClearProps,
        gTasQueryHaveProps,
        gTasQueryLackProps,
        _GetFirstPaCb,
        (CX_VOID*)&ctx,
        CX_NULL,
        CX_NULL,
        TotalPages,
        &properties);

    if (!CX_SUCCESS(status))
    {
        ///TAS_LOG_FUNC_FAIL("_TasWalkPagesEx", status);
        goto cleanup;
    }

    if (PaStart)
    {
        if (!ctx.Valid)
        {
            if (Properties)
            {
                properties.PageFrame = 0; // make sure it's 0, no matter what
            }
            else
            {
                // no other way to signal the PA is invalid
                status = CX_STATUS_INVALID_DATA_VALUE;
                goto cleanup;
            }
        }
        *PaStart = ctx.FirstPa;
    }
    if (Properties) *Properties = properties;
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



///
/// @brief        Debug routine for decoding and printing (with no newline characters) out the content of a #TAS_PROPERTIES value
/// @param[in]    Properties                       properties value to decode and print
///
CX_VOID
TasDumpProperties(
    _In_ TAS_PROPERTIES Properties
)
{
    TAS_LOGN("%s%s%s|%lld|%s%s%s%s%s%s%s%s%s%s%s",
        (Properties.Read ? "R" : ""),
        (Properties.Write ? "W" : ""),
        (Properties.Execute ? "X" : ""),

        Properties.Caching,

        (Properties.PageFrame ? ".FRAME" : ""),
        (Properties.CompleteChain ? ".COMPLETE" : ""),
        (Properties.Chained ? ".CHAINED" : ""),
        (Properties.ChainLimit ? ".BOUNDARY" : ""),
        (Properties.InUse ? ".USED" : ""),
        (Properties.ContinuousPa ? ".CONTINUOUS" : ""),
        (Properties.Accessed? ".A" : ""),
        (Properties.Dirty? ".D" : ""),
        (Properties.Spp? ".SPP" : ""),
        (Properties.BypassVe? "" : ".#VE"),
        (Properties.Special? ".*" : "")
        );
}


static
NTSTATUS
_TasDumpMappingsCb(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_opt_ MEM_ALIGNED_VA         StartVa,
    _In_ MEM_ALIGNED_PA             StartPa,
    _In_ MEM_SIZE_IN_BYTES          Size,
    _In_ TAS_PROPERTIES             Properties,             // only R/W/X are guaranteed to be valid
    _In_opt_ CX_VOID                *Context
)
{
    UNREFERENCED_PARAMETER(Mapping);
    TAS_PROPERTIES *breakOnChangesMask = (TAS_PROPERTIES *)Context;

    if (breakOnChangesMask->ContinuousPa)
    {
        TAS_LOG("[%018p->%018p) -> [%018p->%018p) %4d%cB ", StartVa, StartVa + Size, StartPa, StartPa + Size,
            Size < CX_MEGA ? Size / CX_KILO : Size < CX_GIGA ? Size / CX_MEGA : Size / CX_GIGA,
            Size < CX_MEGA ? 'K' : Size < CX_GIGA ? 'M' : 'G'
        );
    }
    else
    {
        TAS_LOG("[%018p->%018p) %4d%cB ", StartVa, StartVa + Size,
            Size < CX_MEGA ? Size / CX_KILO : Size < CX_GIGA ? Size / CX_MEGA : Size / CX_GIGA,
            Size < CX_MEGA ? 'K' : Size < CX_GIGA ? 'M' : 'G'
        );
    }
    TasDumpProperties(Properties);
    TAS_LOGN("\n");
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Debug routine that uses #TasIterateMappings with a callback that prints a detailed report of the memory mapped through a given TAS descriptor
/// @param[in]    Mapping                          TAS descriptor whose mappings are to be dumped
/// @param[in]    BreakOnChangesMask               properties that must be constant throughout whole intervals (properties that, on changes, trigger a new entry to be printed)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
TasDumpMappings(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ TAS_PROPERTIES             BreakOnChangesMask      // properties that MUST be constant throughout a whole interval
)
{
    return TasIterateMappings(Mapping, BreakOnChangesMask, _TasDumpMappingsCb, &BreakOnChangesMask);
}

//
// Default properties to set/clear/check for/against when setting address translation
//
const TAS_PROPERTIES gTasMapSetProps = {
    .Read               = 1, // Read access right
    .Write              = 1, // Write access right; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
    .Execute            = 1, // although it has a hardware bit associated, it isn't always available and it's negated
    .InUse              = 1, // the old "reserved" flag, this VA is NOT free but known/reserved or already used
    .PageFrame          = 1, // has or do set or query the page-frame numbers
    .CompleteChain      = 1, // applies to a VA range: signals a complete start ... chained ... end chain
    .PagingStructures   = 1, // a VA range with all the paging structures populated, even if the VA itself might not be present/defined
};
const TAS_PROPERTIES gTasMapClearProps = { 0 };
const TAS_PROPERTIES gTasMapHaveProps = { 0 };
const TAS_PROPERTIES gTasMapLackProps = {
    .InUse              = 1, // the old "reserved" flag, this VA is NOT free but known/reserved or already used
};


//
// Default properties to set/clear/check for/against when reserving addresses
//
const TAS_PROPERTIES gTasReserveSetProps = {
    .CompleteChain      = 1, // applies to a VA range: signals a complete start ... chained ... end chain
    .PagingStructures   = 1, // a VA range with all the paging structures populated, even if the VA itself might not be present/defined
};
const TAS_PROPERTIES gTasReserveClearProps = {
    .Read               = 1, // Read access right
    .Write              = 1, // Write access right; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
    .Execute            = 1, // although it has a hardware bit associated, it isn't always available and it's negated
    .Accessed           = 1, // Accessed; indicates whether software has accessed the page referenced by this entry
    .Dirty              = 1, // Dirty; indicates whether software has written to the page referenced by this entry
    .Global             = 1, // Determines whether the translation is global
};
const TAS_PROPERTIES gTasReserveHaveProps = { 0 };
const TAS_PROPERTIES gTasReserveLackProps = {
    .Read               = 1, // Read access right
    .Write              = 1, // Write access right; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
    .Execute            = 1, // although it has a hardware bit associated, it isn't always available and it's negated
    .ChainLimit         = 1, // marks the first and/or last page (boundaries) in a chained allocation
    .Chained            = 1, // this page is linked to the next one
    .InUse              = 1, // the old "reserved" flag, this VA is NOT free but known/reserved or already used
    .PageFrame          = 1, // has or do set or query the page-frame numbers
    .CompleteChain      = 1, // applies to a VA range: signals a complete start ... chained ... end chain
};


//
// Default properties to set/clear/check for/against when unmapping some existing translations
//
const TAS_PROPERTIES gTasUnmapSetProps = { 0 };
const TAS_PROPERTIES gTasUnmapClearProps = {
    .Read               = 1, // Read access right
    .Write              = 1, // Write access right; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
    .Execute            = 1, // although it has a hardware bit associated, it isn't always available and it's negated
    .Accessed           = 1, // Accessed; indicates whether software has accessed the page referenced by this entry
    .Dirty              = 1, // Dirty; indicates whether software has written to the page referenced by this entry
    .Global             = 1, // Determines whether the translation is global
    .ChainLimit         = 1, // marks the first and/or last page (boundaries) in a chained allocation
    .Chained            = 1, // this page is linked to the next one
    .InUse              = 1, // the old "reserved" flag, this VA is NOT free but known/reserved or already used
    .PageFrame          = 1, // has or do set or query the page-frame numbers
    .CompleteChain      = 1, // applies to a VA range: signals a complete start ... chained ... end chain
    .ContinuousPa       = 1, // a VA range that is continuous in the physical address space
    .PagingStructures   = 1, // a VA range with all the paging structures populated, even if the VA itself might not be present/defined
    .DefaultTableBits   = 1, // fill-in with default implementation-defined bits for upper-level table entries
    ._UnusedBits        = 1, // yet to be defined bits
};
const TAS_PROPERTIES gTasUnmapHaveProps = {
    .InUse              = 1, // the old "reserved" flag, this VA is NOT free but known/reserved or already used
    .CompleteChain      = 1, // applies to a VA range: signals a complete start ... chained ... end chain
    .PagingStructures   = 1, // a VA range with all the paging structures populated, even if the VA itself might not be present/defined
};
const TAS_PROPERTIES gTasUnmapLackProps = { 0 };


//
// Default properties to set/clear/check for/against when querying some translations info
//
const TAS_PROPERTIES gTasQuerySetProps = { 0 };
const TAS_PROPERTIES gTasQueryClearProps = { 0 };
const TAS_PROPERTIES gTasQueryHaveProps = { 0 };
const TAS_PROPERTIES gTasQueryLackProps = { 0 };

/// @}
