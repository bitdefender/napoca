/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup mdl
/// @{
#ifndef _MDL_H_
#define _MDL_H_

#include "base/cx_sal.h"
#include "wrappers/cx_winsal.h"
#include "cx_native.h"

#define MDL_MAX_PAGES_PER_ENTRY     2047
#define MDL_PAGE_BASE(Addr)         CX_PAGE_BASE_4K(Addr)
#pragma warning(push)
#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
/// @brief Represents one or more physically continuous pages
typedef union _MDL_ENTRY {
    CX_UINT64       BaseAddress;        ///< physical address of the first page from the entry (MDL_PAGE_BASE MUST BE APPLIED before using it as a pointer); lower 12 bits are used as PageCount and other special flags
    struct {
        CX_UINT64   PageCount:11;       ///< each MDL entry can hold up to 2047 pages (1-2047), PageCount = 0 means invalid MDL
        CX_UINT64   BigPages:1;         ///< 1, if the pages are 2M pages (0 by default, for 4K pages); BigPages support NOT implemented yet
        CX_UINT64   _Padding:52;
    };
} MDL_ENTRY;


#define MDL_FLAG_STATIC             0x00000001  ///< this MDL is statically allocated, does NOT support reallocate and free

#pragma pack(push)
#pragma pack(4)
/// @brief Represents a collection of one or more possibly not continuous physical pages (grouped into continuous entries)
typedef struct _MDL {
    CX_UINT32       Flags;              ///< Can store various flags (only MDL_FLAG_STATIC is supported for now)
    CX_UINT32       Size;               ///< Size in bytes of the MDL struct, including entries
    CX_UINT32       AllocCount;         ///< Number of total allocated MDL_ENTRY structures we can have
    CX_UINT32       EntryCount;         ///< Number of effectively used MDL_ENTRY structures (always <= AllocCount)
    CX_INT32        PpAllocHint;        ///< Index of dynamic PP allocator that allocated the physical pages, or -1 if the pages from this MDL where NOT allocated by a dynamic PP allocator
    CX_UINT32       TotalPageCount;     ///< Total number of pages, sum of all PageCount from all MDL_ENTRY structs
    CX_VOID*        MappedVa;           ///< This is an optional field, can be used to store a VA to which this MDL is mapped
    MDL_ENTRY       Entry[];            ///< Array of MDL_ENTRY structs that effectively describe the physical pages
} MDL;
#pragma pack(pop)
#pragma warning(pop)

#define SINGLE_ENTRY_MDL_SIZE       (sizeof(MDL) + sizeof(MDL_ENTRY))
#define N_ENTRY_MDL_SIZE(n)         (sizeof(MDL) + (n) * sizeof(MDL_ENTRY))

/// @brief Custom context for MDL iteration callback
typedef struct _MM_ITERATE_MDL_CONTEXT
{
    CX_UINT64   Address;                                ///< Always contains the address of the current continuous memory chunk
    CX_UINT32   PageIndex;                              ///< Last page added (or tried, at least) in chunk which is at Address + CX_PAGE_SIZE_4K * this index
    CX_UINT32   PageCount;                              ///< How many pages does the current chunk contain
    CX_BOOL     ChunkInProgress;                        ///< FALSE when not even a single page from the current chunk has been processed
    CX_BOOL     Started;                                ///< Indicates that a walk is in progress
    CX_UINT8    StaticMdlZone[N_ENTRY_MDL_SIZE(4)];     ///< MDL buffer
    MDL         *Mdl;                                   ///< MDL itself
}MDL_ITERATE_CONTEXT;


/// @brief Indicates if an MDL is valid
/// @param Mdl              MDL to validate
/// @param AcceptEmpty      TRUE if an empty MDL is treated as valid
/// @return                 TRUE if Mdl is valid; FALSE otherwise
CX_BOOL
MdlIsValid(
    _In_ const MDL*     Mdl,
    _In_ CX_BOOL        AcceptEmpty
);

/// @brief Indicates if an MDL is populated with pages
/// @param Mdl      MDL to validate
/// @return         TRUE if there is at least one MDL entry filled with pages information; FALSE otherwise
CX_BOOL
MdlIsPopulated(
    _In_ const MDL*     Mdl
    );

/// @brief Indicates if an MDL is valid (not null and with consistent fields) but not necessarily populated
/// @param Mdl          MDL to validate
/// @return             TRUE if Mdl is usable; FALSE otherwise
CX_BOOL
MdlIsUsable(
    _In_ const MDL*     Mdl
    );


/// @brief Preinitializes a memory buffer as a static MDL.
/// @param StaticMdl                pointer to the memory zone to format as an MDL
/// @param TotalBytesInclHeader     number of bytes available at StaticMdl to be used for MDL entries
/// @return CX_STATUS_INVALID_PARAMETER_1       Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2       TotalBytesInclHeader too small; at least one entry must be available
/// @return CX_STATUS_SUCCESS                   On success
CX_STATUS
MdlInit(
    _In_ MDL* StaticMdl,
    _In_ CX_UINT32 TotalBytesInclHeader
    );


/// @brief Dumps all entries from the MDL, with their base address, page count etc.
///
/// @param Message                        optional message
/// @param Mdl                            MDL we want to dump entries of
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return STATUS_INVALID_MDL              Invalid number of total pages in mdl
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlDump(
    _In_opt_ CX_INT8* Message,
    _In_ MDL* Mdl
    );


/// @brief Adds some physical pages to an mdl (the mdl can be already partially populated)
/// @param Mdl                  Mdl that will be populated
/// @param PhysicalAddress      Starting physical address; will be auto-aligned if needed
/// @param NumberOfBytes        Number of bytes to be described (aligned by rounding-up to CX_PAGE_SIZE_4K if needed)
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL or invalid
/// @return STATUS_INVALID_PHYSICAL_ADDRESS PhysicalAddress is invalid; there are unexpected bits set in the high part of the address
/// @return STATUS_STATIC_MDL_TOO_SMALL     Mdl is too small and cannot be reallocated (static MDLs)
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlAddRange(
    _In_ MDL* Mdl,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT64 NumberOfBytes
);

/// @brief Allocates a new dynamic MDL structure from heap with given size (number of entries).
/// @param Mdl                           newly allocated dynamic MDL
/// @param NumberOfEntries               number of MDL entries to hold
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   NumberOfEntries is 0
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlAlloc(
    _Out_ MDL** Mdl,
    _In_ CX_UINT32 NumberOfEntries
    );


/// @brief Reallocates a dynamic MDL structure.
/// @param Mdl                        dynamic MDL to reallocate
/// @param NewNumberOfEntries         new number of entries (must be bigger than current number of entries)
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   NewNumberOfEntries is invalid (smaller that the current number of entries)
/// @return STATUS_CANT_FREE_A_STATIC_MDL   Mdl is a static MDL that cannot be freed
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlRealloc(
    _Inout_ MDL** Mdl,
    _In_ CX_UINT32 NewNumberOfEntries
    );

/// @brief Reset an already initialized mdl for RE-use
/// @param Mdl MDL to reset
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlReset(
    _Inout_ MDL *Mdl
    );

/// @brief Frees a dynamic MDL and sets to CX_NULL the corresponding pointer.
/// @param Mdl      dynamic MDL to free
/// @return CX_STATUS_INVALID_PARAMETER_1   Mdl is NULL
/// @return STATUS_CANT_FREE_A_STATIC_MDL   Mdl is a static MDL that cannot be freed
/// @return CX_STATUS_SUCCESS               On success
CX_STATUS
MdlFree(
    _Inout_ MDL* *Mdl
    );


/// @brief Iterates a range of memory and populates the MDL for it
///
/// This function will iterate a range of memory and fill in a fixed size MDL. If the MDL is not big enough to accommodate
/// the entire range this function will return an error code and update the iteration context in order to
/// allow next calls to this function with the updated context
///
/// @param PhysicalAddress      Start address
/// @param NumberOfBytes        Number of bytes; final address will be PhysicalAddress + NumberOfBytes rounded up to the first multiple of page size
/// @param Context              zero-down the structure at first call; the Mdl subfield is meant to be used!
/// @return CX_STATUS_DATA_BUFFER_TOO_SMALL         you need to flush the MDL, the next call will continue from where it left, ignoring PhysicalAddress and NumberOfBytes
/// @return CX_STATUS_SUCCESS                       recorded and ready for new addresses, repeating the call with the same parameters(or for 0 bytes) will free the resources and terminate
/// @return CX_STATUS_NO_MORE_ENTRIES               terminated and the Context has been reinitialized
CX_STATUS
MdlIterate(
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT64 NumberOfBytes,
    _Inout_ MDL_ITERATE_CONTEXT *Context
    );

#endif // _MDL_H_
/// @}
