/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file tas.h
///  @brief A generic (and low-level) API for managing some TAS (Translated Address Space) through the use of some kind of paging data structures, based on application-specific behavior defined by means of implementation-defined callback functions
///

/// @ingroup tas
/// @{


#ifndef _TAS_H_
#define _TAS_H_

#include "base/cx_sal.h"
#include "wrappers/cx_winsal.h"
#include "cx_native.h"
#include "memory/mdl.h"

typedef CX_UINT64   MEM_ALIGNED_VA;     ///< a Virtual Address (meaning an input address value that gets translated through the paging structures to some different kind of output address type, not necessarily a CPU virtual memory address value) that has to start at the first byte of a page
typedef CX_UINT64   MEM_UNALIGNED_VA;   ///< a translatable address value that has no need to meet any alignment requirements
typedef CX_UINT64   MEM_ALIGNED_PA;     ///< a Physical Address (meaning the result of translating a #MEM_ALIGNED_VA through the paging structures, not necessarily an actual physical system memory address) that has to correspond to the fist byte of a memory page
typedef CX_UINT64   MEM_UNALIGNED_PA;   ///< the output address value resulting from the translation of an input virtual address with no alignment constraints imposed
typedef CX_UINT32   MEM_PAGE_COUNT;     ///< defines a number of memory pages, a particular page size isn't implied and the underlying implementation is left with full control over the page size(s) used in a particular application/implementation
typedef CX_UINT16   MEM_TABLE_OFFSET;   ///< byte-level offset value for identifying data found inside some page table structure
typedef CX_UINT64   MEM_SIZE_IN_BYTES;  ///< size in bytes of a logical resource located in a translated address space, actual managed size might be greater due to page-granularity/boundary constraints and is inferred automatically and transparently by the called functions

typedef struct _TAS_DESCRIPTOR              TAS_DESCRIPTOR;
typedef struct _TAS_PAGING_STRUCTURE_INFO   TAS_PAGING_STRUCTURE_INFO;
typedef union  _TAS_PROPERTIES              TAS_PROPERTIES;



///
/// @brief        Callback function type for retrieving the location in the HV VA space of a paging structure given its host physical address
/// @param[in]    Pa                               input host physical address of some location inside a page table structure
/// @param[out]   Va                               the host virtual address where the content referred by PA can be accessed (both read and write access rights are needed)
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_GET_TABLE_VA_CB)(
    _In_ MEM_UNALIGNED_PA           Pa,
    _Out_ MEM_UNALIGNED_VA          *Va
    );



///
/// @brief        Callback function type for retrieving detailed info about a paging structure processed by TAS
/// @param[in]    Mapping                          identifier of the TAS the address and table data structure(s) belong to
/// @param[in]    TranslatedVa                     an input address value that is translated through the data structure in question
/// @param[in]    TableDepth                       at what level/depth is this table at (the root is at 0)
/// @param[in]    TablePa                          TAS will either know where exactly the table is located and send a non-zero value for this parameter
/// @param[in]    UpperLevelEntryVa                if the address of the subject table structure is unknown, the host virtual address of the upper-level table entry that links to it is sent
/// @param[in]    IsFirstPageInRange               can be used to allow ContinuousPa and/or chaining deduction
/// @param[in]    IsLastPageInRange                can be used for chaining deduction
/// @param[in]    PreviousPa                       can be used for ContinuousPa deduction
/// @param[out]   TableInfo                        output data structure that need to be filled with the information required by TAS
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_GET_TABLE_INFO_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           TranslatedVa,
    _In_ CX_UINT8                   TableDepth,
    _In_opt_ MEM_ALIGNED_PA         TablePa,
    _In_opt_ volatile CX_VOID       *UpperLevelEntryVa,
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *TableInfo
    );



///
/// @brief        Callback function type for applying changes to the implementation-specific data-format/type of the page table entries.
/// @param[in]    Mapping                          TAS descriptor identifying the address space the change needs to be applied to
/// @param[in]    TableEntry                       table entry where the changes should be saved to
/// @param[in]    TableDepth                       at what depth the paging structure resides (the TableEntry that needs changes)
/// @param[in]    SetProperties                    make any needed changes such that these properties get to be true
/// @param[in]    ClearProperties                  clear these properties
/// @param[in]    IsFirstPageInRange               used for ContinuousPa and/or chaining deduction
/// @param[in]    IsLastPageInRange                used for chaining deduction
/// @param[in]    PhysicalPage                     where should the entry (or final mapping) point (ignore unless SetProperties.PageFrame)
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_ALTER_TABLE_ENTRY_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ volatile CX_VOID           *TableEntry,
    _In_ CX_UINT8                   TableDepth,
    _In_ TAS_PROPERTIES             SetProperties,
    _In_ TAS_PROPERTIES             ClearProperties,
    _In_ CX_BOOL                    IsFirstPageInRange,
    _In_ CX_BOOL                    IsLastPageInRange,
    _In_ MEM_ALIGNED_PA             PhysicalPage
    );




///
/// @brief        Type for a callback function that given be a table at some level and a byte-level index inside the table it will return the next level table and advance the index to the next table entry (both at the same time)
/// @param[in]    Mapping                          address of the target TAS descriptor
/// @param[in]    TablePa                          host physical address of the very first byte in the page table
/// @param[out]   TableVa                          optional (optimization-only) parameter to fill-in the host virtual address corresponding to the TablePa argument
/// @param[in]    TableDepth                       at what depth/level is the table situated
/// @param[in, out] TableByteIndex                 input: offset of the current entry inside the table; ouput: offset to the next table entry
/// @param[out]   SizeIncrement                    how many bytes are covered/mapped by an entry (how much memory is mapped through a table entry)
/// @param[out]   NextLevelTablePa                 the address of the child table (or actually mapped memory) this entry points to
/// @param[out]   NextLevelTableValid              the address of the next (same level and consecutive) table entry
/// @param[out]   IsLeaf                           set to 1 if the table / table entry links physical pages and not yet another paging structure (or set to 0 otherwise)
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_ITERATE_TABLES_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_PA             TablePa,
    _Out_opt_ MEM_ALIGNED_VA        *TableVa,
    _In_ CX_UINT8                   TableDepth,
    _Inout_ MEM_TABLE_OFFSET        *TableByteIndex,
    _Out_opt_ MEM_ALIGNED_PA        *SizeIncrement,
    _Out_opt_ MEM_ALIGNED_PA        *NextLevelTablePa,
    _Out_opt_ CX_BOOL               *NextLevelTableValid,
    _Out_opt_ CX_BOOL               *IsLeaf
    );



///
/// @brief        Callback function type for allowing various custom processing of the backing physical memory associated with some translated address range
/// @param[in]    Mdl                              (potentially partial/incomplete) MDL describing the backing PA pages (or a chunk of them) for a VA mapping
/// @param[in]    First                            only set if this is the first MDL (chunk) for the given operation
/// @param[in]    Last                             only set when this is the last MDL for the given operation
/// @param[in]    CallbackContext                  user-defined data passed to the callback
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_WALK_MDL_CB)(
    _In_ MDL *Mdl,
    _In_ CX_BOOL First,
    _In_ CX_BOOL Last,
    _In_ CX_VOID *CallbackContext
    );



///
/// @brief        Callback function type called when a new paging structure is needed
/// @param[in]    Mapping                          TAS descriptor of the memory space needing more resources
/// @param[in]    TableDepth                       at what page table depth will the new structure go (0 for the top-level structure, 1 for the next level etc...)
/// @param[out]   Va                               return a valid host RW VA mapping of the physical memory allocated
/// @param[out]   Pa                               set it to the host PA of the newly allocated structure
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_ALLOC_PHYSICAL_PAGE_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ CX_UINT8                   TableDepth,
    _Out_ MEM_ALIGNED_VA            *Va,
    _Out_ MEM_ALIGNED_PA            *Pa
    );



///
/// @brief        Optional callback function used to perform custom initialization of a newly allocated table
/// @param[in]    Mapping                          Identifies the TAS the paging structure belongs to
/// @param[in]    TableDepth                       at what depth (0 for the top-level structure, 1 for the next level etc...) is the structure located
/// @param[out]   Va                               a valid RW mapping of the physical page inside the host virtual address space
/// @param[out]   Pa                               the host PA of the allocated page that needs initialization
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_INIT_PHYSICAL_PAGE_CB)(
    _In_ TAS_DESCRIPTOR     *Mapping,
    _In_ CX_UINT8           TableDepth,
    _Out_ MEM_ALIGNED_VA    Va,
    _Out_ MEM_ALIGNED_PA    Pa
    );



///
/// @brief        Free callback routine type called when another thread is faster/first to populate the missing paging structure (and so, the allocated page is no longer needed and can be freed)
/// @param[in]    Mapping                          Target TAS the paging structure belongs to
/// @param[in]    Va                               a valid host RW mapping for the physical page for accessing its content
/// @param[in]    Pa                               the host PA of the data that must be freed from memory
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_FREE_PHYSICAL_PAGE_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             Va,
    _In_ MEM_ALIGNED_PA             Pa
);



///
/// @brief        Callback function type used for inspecting the paging data structures through the call of the TasIterateStructures function
/// @param[in]    Mapping                          TAS that's being iterated
/// @param[in]    Depth                            at what depth is the table or entry located
/// @param[in]    TranslatedVa                     first VA translated through this table or table entry
/// @param[in]    Pa                               table host PA
/// @param[in]    Offset                           byte-offset inside the table when the table entries are being iterated
/// @param[in]    DestinationPa                    entries-only: where does the entry (page-frame) point to
/// @param[in]    CoveredSize                      entries-only: how much memory is translated by this entry
/// @param[in]    Contex                           forwarded data sent originally to the TasIterateStructures function, if any
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_ITERATE_STRUCTURES_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ CX_UINT8                   Depth,
    _In_opt_ MEM_ALIGNED_VA         TranslatedVa,
    _In_ MEM_ALIGNED_PA             Pa,
    _In_opt_ MEM_TABLE_OFFSET       Offset,
    _In_opt_ MEM_ALIGNED_PA         DestinationPa,
    _In_opt_ MEM_SIZE_IN_BYTES      CoveredSize,
    _In_opt_ CX_VOID                *Contex
    );



///
/// @brief        Callback function type used for inspecting the mappings defined by a TAS when the TasIterateMappings function is called
/// @param[in]    Mapping                          address space being inspected
/// @param[in]    StartVa                          starting address of a new individual address interval
/// @param[in]    StartPa                          the starting physical address the virtual addresses are translated to
/// @param[in]    Size                             size of the address range
/// @param[in]    Properties                       properties of the current address interval (only R/W/X are guaranteed to be valid, depending on the underlying application-specific implementation)
/// @param[in]    Context                          custom data passed to the callback function
/// @returns      CX_STATUS_SUCCESS                on success
typedef
CX_STATUS
(*TAS_ITERATE_MAPPINGS_CB)(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             StartVa,
    _In_ MEM_ALIGNED_PA             StartPa,
    _In_ MEM_SIZE_IN_BYTES          Size,
    _In_ TAS_PROPERTIES             Properties,
    _In_opt_ CX_VOID                *Context
    );


#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

/// @brief Define a *logical view* of what properties some table, translated address or memory range might have
typedef union _TAS_PROPERTIES
{
    struct
    {
        CX_UINT64 Read              : CX_BITFIELD(0, 0);   ///< Read access right
        CX_UINT64 Write             : CX_BITFIELD(1, 1);   ///< Write access right; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
        CX_UINT64 Execute           : CX_BITFIELD(2, 2);   ///< although it has a hardware bit associated, it isn't always available and it's negated
        CX_UINT64 Accessed          : CX_BITFIELD(3, 3);   ///< Accessed; indicates whether software has accessed the page referenced by this entry
        CX_UINT64 Dirty             : CX_BITFIELD(4, 4);   ///< Dirty; indicates whether software has written to the page referenced by this entry
        CX_UINT64 Global            : CX_BITFIELD(5, 5);   ///< Determines whether the translation is global
        CX_UINT64 ChainLimit        : CX_BITFIELD(6, 6);   ///< marks the first and/or last page (boundaries) in a chained allocation
        CX_UINT64 Chained           : CX_BITFIELD(7, 7);   ///< this page is linked to the next one
        CX_UINT64 InUse             : CX_BITFIELD(8, 8);   ///< the old "reserved" flag, this VA is NOT free but known/reserved or already used
        CX_UINT64 PageFrame         : CX_BITFIELD(9, 9);   ///< has or do set or query the page-frame numbers
        CX_UINT64 CompleteChain     : CX_BITFIELD(10, 10); ///< applies to a VA range: signals a complete start ... chained ... end chain
        CX_UINT64 ContinuousPa      : CX_BITFIELD(11, 11); ///< a VA range that is continuous in the physical address space
        CX_UINT64 PagingStructures  : CX_BITFIELD(12, 12); ///< a VA range with all the paging structures populated, even if the VA itself might not be present/defined
        CX_UINT64 DefaultTableBits  : CX_BITFIELD(13, 13); ///< fill-in with default implementation-defined bits for upper-level table entries
        CX_UINT64 Caching           : CX_BITFIELD(17, 14); ///< caching type, implementation specific and might not be supported
#define TAS_TOTAL_CACHING_VALUES     (1 << 4)              ///< total values that can be encoded in the .Caching field
#define TAS_CACHING_MASK             (TAS_TOTAL_CACHING_VALUES - 1) ///< total values that can be encoded in the .Caching field
        CX_UINT64 BypassVe          : CX_BITFIELD(18, 18); ///< no predefined TAS semantics, ignored (can be used for custom data), named only because it's handy in the EPT use-case
        CX_UINT64 Spp               : CX_BITFIELD(19, 19); ///< no predefined TAS semantics, ignored (can be used for custom data), named only because it's handy in the EPT use-case
        CX_UINT64 Special           : CX_BITFIELD(20, 20); ///< no predefined TAS semantics, ignored (can be used for custom data), named only because it's handy in the EPT use-case
        CX_UINT64 _UnusedBits       : CX_BITFIELD(63, 21); ///< bits available for future properties
    };
    CX_UINT64 Raw;
}TAS_PROPERTIES;


static_assert(sizeof(TAS_PROPERTIES) == sizeof(CX_UINT64), "don't ask for more than 64 bits without a good reason...");

/// @brief Data structure defining the properties implied by passing through a paging structure when translating an input address
typedef struct _TAS_PAGING_STRUCTURE_INFO
{
    struct
    {
        CX_UINT32               Index : 23;                ///< the entry index of the selected entry inside this table
        CX_UINT32               HasSuccessor : 1;          ///< 1 if the selected entry is not at the very end of the table (is not the highest index value)
        CX_UINT32               IsLeafTableEntry : 1;      ///< 1 if the entry is populated but there are no child paging structures below (the entry points to the actual mapped memory)
        CX_UINT32               EntryMappingSizeExponent : 7; ///< (ignored unless it's a leaf entry) the entry maps a total of 2 to the power of EntryMappingSizeExponent bytes
    };
    CX_VOID                     *TableVa;               ///< HVA with RW access to the table content
    MEM_ALIGNED_PA              TablePa;                ///< HPA where the table resides
    CX_VOID                     *TableEntryVa;          ///< the actual table entry in question
    MEM_ALIGNED_PA              NextLevelTablePa;       ///< address of the next-level table or backing phyiscal memory (a PAGE_SIZE * .PageFrame, most likely)
    TAS_PROPERTIES              Properties;             ///< access, various implementation-specific custom properties and caching rights granted by the entry
    TAS_PROPERTIES              ValidPropertiesMask;    ///< only the ValidPropertiesMask bits set are to be considered semantically meaningful for the Properties value
}TAS_PAGING_STRUCTURE_INFO;



CX_STATUS
TasGetPagingPathInfo(
    _In_ TAS_DESCRIPTOR *Mapping,
    _In_ MEM_UNALIGNED_VA Va,
    _In_ CX_BOOL AutoVivifyMissingTables,
    _In_ CX_BOOL IsFirstPageInRange,
    _In_ CX_BOOL IsLastPageInRange,
    _In_ MEM_ALIGNED_PA PreviousPa,
    _Out_ TAS_PAGING_STRUCTURE_INFO *Path,
    _Out_opt_ TAS_PROPERTIES *PathProperties,
    _Out_opt_ TAS_PROPERTIES *ValidPathPropertiesMask
);

/// @brief Encapsulates the state and behavior of a translated address space,
typedef struct _TAS_DESCRIPTOR
{
    CX_UINT8                    PagingDepth;                ///< maximum depth of paging data structures
    CX_UINT64                   RootPa;                     ///< if 0, the root table host physical address is automatically filled in this field when it is allocated, otherwise this value is kept constant by the TAS code
    TAS_GET_TABLE_VA_CB         GetTableVa;                 ///< given the PA of some data found inside some paging structure, return its VA
    TAS_GET_TABLE_INFO_CB       GetTableInfo;               ///< callback used for decoding the path through the paging structures walked for translating a given VA
    TAS_ALTER_TABLE_ENTRY_CB    AlterTableEntry;            ///< callback for managing the implementation-defined bits from the page tables
    TAS_ITERATE_TABLES_CB       IterateTables;              ///< optional callback for allowing waking the tables (to free / tear them down, for example)
    TAS_ALLOC_PHYSICAL_PAGE_CB  AllocPagingStructure;       ///< allocation routine for a paging structure
    TAS_INIT_PHYSICAL_PAGE_CB   InitPagingStructure;        ///< initialization routine that allows reuse of an AllocPage implementation
    TAS_FREE_PHYSICAL_PAGE_CB   FreePagingStructure;        ///< deallocation routine for the page tables
    volatile CX_UINT64          AllocatedPageTablesCount;   ///< total pages allocated for page tables
}TAS_DESCRIPTOR;



/// @brief Defines a page tables or page table entries walk strategy
typedef enum
{
    TAS_ITERATION_MODE_TOP_DOWN,        ///< process a table before its childrens (before visiting the child tables recursively)
    TAS_ITERATION_MODE_BOTTOM_UP,       ///< process a table after all its children are visited (after returning from the recursive calls)
    TAS_ITERATION_MODE_LEAFS_ONLY,      ///< only process the leaf nodes, "left-to-right"
}TAS_ITERATION_MODE;


/// @brief Defines the subject of a page tables/entries walk
typedef enum
{
    TAS_ITERATION_TARGET_TABLES,        ///< send the complete (unprocessed) tables to the callback function
    TAS_ITERATION_TARGET_ENTRIES,       ///< iterate the tables too and only call the callback function on the actual entries
}TAS_ITERATION_TARGET;


#pragma warning(pop)

extern const TAS_PROPERTIES gTasMapSetProps;        ///< template for common properties that needs to be set when adding/defining new mappings in a TAS
extern const TAS_PROPERTIES gTasMapClearProps;      ///< template for common properties that needs to be cleared when adding/defining new mappings in a TAS
extern const TAS_PROPERTIES gTasMapHaveProps;       ///< template for common properties that should to be logically true when adding/defining new mappings in a TAS
extern const TAS_PROPERTIES gTasMapLackProps;       ///< template for common properties that shouldn't be true when adding/defining new mappings in a TAS
extern const TAS_PROPERTIES gTasReserveSetProps;    ///< template for common properties that needs to be set when (only) initializing a virtual memory region without backing mappings
extern const TAS_PROPERTIES gTasReserveClearProps;  ///< template for common properties that needs to be cleared when (only) initializing a virtual memory region without backing mappings
extern const TAS_PROPERTIES gTasReserveHaveProps;   ///< template for common properties that should to be logically true when (only) initializing a virtual memory region without backing mappings
extern const TAS_PROPERTIES gTasReserveLackProps;   ///< template for common properties that shouldn't be true when (only) initializing a virtual memory region without backing mappings
extern const TAS_PROPERTIES gTasUnmapSetProps;      ///< template for common properties that needs to be set when removing/undefining preexisting mappings in a TAS
extern const TAS_PROPERTIES gTasUnmapClearProps;    ///< template for common properties that needs to be cleared when removing/undefining preexisting mappings in a TAS
extern const TAS_PROPERTIES gTasUnmapHaveProps;     ///< template for common properties that should to be logically true when removing/undefining preexisting mappings in a TAS
extern const TAS_PROPERTIES gTasUnmapLackProps;     ///< template for common properties that shouldn't be true when removing/undefining preexisting mappings in a TAS
extern const TAS_PROPERTIES gTasQuerySetProps;      ///< template for common properties that needs to be set when querying for properties a range of addresses translated through TAS
extern const TAS_PROPERTIES gTasQueryClearProps;    ///< template for common properties that needs to be cleared when querying for properties a range of addresses translated through TAS
extern const TAS_PROPERTIES gTasQueryHaveProps;     ///< template for common properties that should to be logically true when querying for properties a range of addresses translated through TAS
extern const TAS_PROPERTIES gTasQueryLackProps;     ///< template for common properties that shouldn't be true when querying for properties a range of addresses translated through TAS



///
/// @brief        Allow combining a set of properties of a page table structure with the properties of the next one (or those of a translation to the ones of another)
/// @param[in]    Properties                       some properties for a single translation or table
/// @param[in]    ValidPropertiesMask              which of the properties are valid
/// @param[in]    PreviousProperties               0 or properties already present before
/// @param[in]    PreviousValidPropertiesMask      what properties are valid in the PreviousProperties value
/// @param[out]   ResultingValidPropertiesMask     marks the properties that have valid values in both inputs
/// @returns      the properties that are true for the two sets of page-table properties as a whole, (when they're both true or one is true and the other undefined/ignored)
///
__forceinline
TAS_PROPERTIES
TasCombineProperties(
    _In_ TAS_PROPERTIES Properties,
    _In_ TAS_PROPERTIES ValidPropertiesMask,
    _In_opt_ TAS_PROPERTIES PreviousProperties,
    _In_ TAS_PROPERTIES PreviousValidPropertiesMask,
    _Out_opt_ TAS_PROPERTIES *ResultingValidPropertiesMask
)
{
    // account for any newly defined/valid bits
    if (ResultingValidPropertiesMask) ResultingValidPropertiesMask->Raw = ValidPropertiesMask.Raw | PreviousValidPropertiesMask.Raw;
    // properties that do not apply for this table are kept as they were
    CX_UINT64 old = (~ValidPropertiesMask.Raw & PreviousProperties.Raw);

    // while any properties that were not defined before are initialized to what this table dictates
    CX_UINT64 new = (ValidPropertiesMask.Raw & ~PreviousValidPropertiesMask.Raw & Properties.Raw);

    // and the remaining properties (both already defined and with a valid new setting) are ANDed together
    CX_UINT64 combo = (ValidPropertiesMask.Raw & PreviousValidPropertiesMask.Raw & PreviousProperties.Raw & Properties.Raw);

    Properties.Raw = old | new | combo;

    return Properties;
}


CX_STATUS
TasWalkPagesEx(
    _In_ TAS_DESCRIPTOR             *Mapping,               // mapping descriptor
    _In_ MEM_ALIGNED_VA             Va,                     // starting address of a VA range
    _In_opt_ MEM_PAGE_COUNT         PageCount,              // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these
    _In_ TAS_PROPERTIES             MustHaveProperties,     // stop unless these properties are met for each and every VA page, BEFORE setting/clearing bits
    _In_ TAS_PROPERTIES             MustLackProperties,     // stop if some of these are present for any of the covered VA pages, BEFORE setting/clearing bits
    _In_opt_ TAS_WALK_MDL_CB  MdlCallback,            // optional, if sent will be called for processing the physical pages backing-up the VA range
    _In_opt_ CX_VOID                *MdlCallbackData,       // additional data to send to the callback function
    _In_ MEM_ALIGNED_PA             PaStart,                // used when SetProperties.PageFrame + SetProperties.ContinuousPa
    _In_ MDL                        *Mdl,                   // used when SetProperties.PageFrame + !SetProperties.ContinuousPa
    _Out_opt_ MEM_PAGE_COUNT        *TotalPagesWalked,      // if non-null will be filled-in with how many have been processed up to this point
    _Out_opt_ TAS_PROPERTIES        *Properties             // the inferred properties of the VA space walked, BEFORE setting/clearing bits
);


CX_STATUS
TasMapMdlEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             Va,
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these
    _In_ TAS_PROPERTIES             MustHaveProperties,     // stop unless these properties are met for each and every VA page, BEFORE setting/clearing bits
    _In_ TAS_PROPERTIES             MustLackProperties,     // stop if some of these are present for any of the covered VA pages, BEFORE setting/clearing bits
    _In_ MDL                        *Mdl,                   // used when SetProperties.PageFrame + !SetProperties.ContinuousPa
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfPagesMapped    // returns the number of pages that were mapped
);



///
/// @brief        Create new mappings at a given VA for the physical pages described by a MDL
/// @param[in]    Mapping                          TAS domain to modify
/// @param[in]    Va                               starting VA address where the physical pages should be mapped to
/// @param[in]    SetProperties                    make these properties true for the affected addresses
/// @param[in]    Mdl                              MDL containing the physical addresses to map
/// @returns      CX_STATUS_ALIGNMENT_INCONSISTENCY - the Va parameter isn't properly aligned to allow for the exact VA to PA mappings to be defined
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
TasMapMdl(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_VA             Va,
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ MDL                        *Mdl
)
{
    if (CX_PAGE_OFFSET_4K(Va))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }
    return TasMapMdlEx(Mapping, Va, SetProperties, gTasMapClearProps, gTasMapHaveProps, gTasMapLackProps, Mdl, CX_NULL);
}


CX_STATUS
TasMapRangeEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,                   // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these
    _In_ TAS_PROPERTIES             MustHaveProperties,     // stop unless these properties are met for each and every VA page, BEFORE setting/clearing bits
    _In_ TAS_PROPERTIES             MustLackProperties,     // stop if some of these are present for any of the covered VA pages, BEFORE setting/clearing bits
    _In_ MEM_UNALIGNED_PA           PaStart,                // used when SetProperties.PageFrame + SetProperties.ContinuousPa
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfPagesMapped    // returns the number of pages that were mapped
);



///
/// @brief        Create/add mappings for a range of VAs pointing to a continuous interval of PAs
/// @param[in]    Mapping                          Destination TAS that needs to be adjusted
/// @param[in]    Va                               Byte-granularity address of the first address to map (additional addresses might be affected if needed for page-granularity constraints)
/// @param[in]    Size                             number of bytes to map, or, if 0, try to set new mappings for all the VAs (already) chained together starting at VA
/// @param[in]    SetProperties                    optional, make these properties true -- if this is {0}, the TAS-provided defaults will be used
/// @param[in]    PaStart                          first destination PA value, only used when SetProperties.PageFrame and SetProperties.ContinuousPa are set, otherwise the existing backing physical memory is left unchanged and only other properties of the mappings are affected
/// @returns      CX_STATUS_ALIGNMENT_INCONSISTENCY - the given VA and PA values do not have the same page alignment properties (they differ by the page offset values)
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
TasMapRange(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,                   // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
    _In_opt_ TAS_PROPERTIES         SetProperties,          // mark these properties when walking the VAs
    _In_ MEM_UNALIGNED_PA           PaStart                 // used when SetProperties.PageFrame + SetProperties.ContinuousPa
)
{
    if (CX_PAGE_OFFSET_4K(Va) != CX_PAGE_OFFSET_4K(PaStart))
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }
    return TasMapRangeEx(Mapping, Va, Size, SetProperties.Raw ? SetProperties : gTasMapSetProps, gTasMapClearProps, gTasMapHaveProps, gTasMapLackProps, PaStart, CX_NULL);
}


CX_STATUS
TasAlterRangeEx(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,                   // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
    _In_ TAS_PROPERTIES             SetProperties,          // mark these properties when walking the VAs
    _In_ TAS_PROPERTIES             ClearProperties,        // clear these
    _In_ TAS_PROPERTIES             MustHaveProperties,     // stop unless these properties are met for each and every VA page, BEFORE setting/clearing bits
    _In_ TAS_PROPERTIES             MustLackProperties,     // stop if some of these are present for any of the covered VA pages, BEFORE setting/clearing bits
    _Out_opt_ MEM_PAGE_COUNT        *NumberOfAlteredPages   // if called with Size=0, returns the number of pages found in the chain
);



///
/// @brief        Create any needed paging structures and setup an address interval as being prepared for mapping it to some physical addresses (that are not yet available, most likely) in such a way that the addresses can be differentiated from other unused/not-yet-defined VAs
/// @param[in]    Mapping                          target TAS
/// @param[in]    Va                               address of the first byte that needs to be marked as reserved (other additional bytes might be affected too, if needed for page-alignment constraints)
/// @param[in]    Size                             number of bytes to reserve (additional bytes up to the end of a page may be affected, too)
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - Size is not allowed to be 0, as a memory reservation assumes there isn't any previously chained memory prepared at the input Va
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
TasReserveRange(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_ MEM_SIZE_IN_BYTES          Size
)
{
    if (!Size) return CX_STATUS_INVALID_PARAMETER_3;
    return TasAlterRangeEx(Mapping, Va, Size, gTasReserveSetProps, gTasReserveClearProps, gTasReserveHaveProps, gTasReserveLackProps, CX_NULL);
}



///
/// @brief        Remove the existing VA to PA mappings for a given address interval, making the input addresses free ("missing") in the affected memory space
/// @param[in]    Mapping                          TAS domain to operate upon
/// @param[in]    Va                               Address of the first byte to unmap (additional bytes at lower addresses may be affected by this operation if needed due to page-alignment constraints)
/// @param[in]    Size                             if 0, walk and modify all the addresses chained together starting from Va
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
TasUnmapRange(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size                    // if 0, walk 'till the end of the Mdl or if the Mdl is zero too, walk the whole chain
)
{
    return TasAlterRangeEx(Mapping, Va, Size, gTasUnmapSetProps, gTasUnmapClearProps, gTasUnmapHaveProps, gTasUnmapLackProps, CX_NULL);
}

CX_STATUS
TasQueryRangeProperties(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_UNALIGNED_VA           Va,
    _In_opt_ MEM_SIZE_IN_BYTES      Size,
    _Out_opt_ TAS_PROPERTIES        *Properties,            // the inferred properties of the address
    _Out_opt_ MEM_ALIGNED_PA        *PaStart,               // valid iff Properties.PageFrame
    _Out_opt_ MEM_PAGE_COUNT        *TotalPages
);

CX_STATUS
TasFreePagingStructures(
    _In_ TAS_DESCRIPTOR             *Mapping
);

CX_STATUS
TasIterateStructures(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_opt_ MEM_ALIGNED_VA         StartingVa,
    _In_ MEM_UNALIGNED_PA           TablePa,                // starting table address
    _In_ CX_UINT8                   TableDepth,             // at what depth is this table found
    _In_ CX_UINT8                   MaxDepth,               // at what depth should it stop
    _In_ TAS_ITERATION_MODE         IterationMode,
    _In_ TAS_ITERATION_TARGET       Target,
    _In_ TAS_ITERATE_STRUCTURES_CB  Callback,               // this routine will process the tables and/or entries iterated
    _In_ CX_VOID                    *Context                // additional data to send to the callback routine
);

CX_STATUS
TasIterateMappings(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ TAS_PROPERTIES             BreakOnChangesMask,     // properties that MUST be constant throughout a whole interval
    _In_ TAS_ITERATE_MAPPINGS_CB    Callback,               // this routine will process the address ranges mapped through the Mapping
    _In_ CX_VOID                    *Context                // additional data to send to the callback routine
);

CX_VOID
TasDumpProperties(
    _In_ TAS_PROPERTIES Properties
);

CX_STATUS
TasDumpMappings(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ TAS_PROPERTIES             BreakOnChangesMask      // properties that MUST be constant throughout a whole interval
);

#endif // _TAS_H_
/// @}
