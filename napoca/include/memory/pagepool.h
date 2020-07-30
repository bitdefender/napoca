/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup pagepool
#ifndef _PAGEPOOL_H_
#define _PAGEPOOL_H_

#include "core.h"
#include "memory/mdl.h"

/// @brief Options controlling the behaviour of page-pool allocator
typedef struct
{
    BYTE Continuos : 1;                     ///< Allocation must be continuous
    BYTE AcceptIncompleteAllocation : 1;    ///< Allocation may be incomplete. This considers that it is acceptable to allocate less pages than required
}PP_OPTIONS;

/// @brief Page-pool allocator selection mechamism
typedef enum
{
    PP_ALLOCATOR_BY_TYPE,   ///< Select allocator by type.
    PP_ALLOCATOR_BY_INDEX   ///< Select allocator by index.
}PP_ALLOCATOR_TYPE;

/// @brief Page-pool allocator selector
typedef union
{
    struct
    {
        PP_ALLOCATOR_TYPE Type;     ///< Indicates selection type. This field indicates which one of the next fields are valid.
        union
        {
            BYTE ByIndex;           ///< Select by index
            enum
            {
                PP_ALLOCATOR_DEFAULT = 0,                           ///< Select the default page-pool allocator
                PP_ALLOCATOR_ROUNDROBIN = PP_ALLOCATOR_DEFAULT,     ///< Do round-robin selection if multiple page-pool allocators are available
                PP_ALLOCATOR_MAXFREE,                               ///< Select the allocator that has more free pages than other allocators
                PP_ALLOCATOR_INIT                                   ///< Select the allocator unsed during INIT phases.
            }ByType;                ///< Select by type
        }Value;                     ///< Selection value
    };
    QWORD Raw;                      ///< Raw access to selection value
}PP_ALLOCATOR;


//
// PP allocator prototypes (support for both no-MDL and MDL-dependent functions)
//

/// @brief Perform pre-initialization steps by preparing global resources
///
/// @param PagePoolBase         Virtual address that maps the page-pool
/// @param PagePoolAllocator    Page-pool allocator
/// @return CX_STATUS_SUCCESS   On success
void
PpPreinitAllocator(
    _In_ VOID* PagePoolBase,
    __out_opt VOID** PagePoolAllocator
    );


/// @brief Initialize the page-pool allocator
///
/// Initializes all page-pool allocators (according to MaxParallel). Each page-pool allocator will get its own range of physical
/// pages, and each allocator will have its own lock.
///
/// @param PagePoolLength           Total length in bytes of the page-pool
/// @param MaxParallel              Maximum number of paralel allocations that are supported
/// @param PerAllocatorPageCount    Number of pages allocated for each page-pool allocator
/// @return CX_STATUS_SUCCESS       On success
NTSTATUS
PpInitAllocator(
    _In_ QWORD PagePoolLength,
    _In_ DWORD MaxParallel,
    _Out_ QWORD* PerAllocatorPageCount
    );

/// @brief
///
/// Allocates a given number of 4K physical pages from the page pool and constructs an MDL to describe all those physical pages.
/// If the MDL is dynamic, its size is automatically increased if needed, otherwise the function can give a warning value and
/// return an incomplete allocation (in that case, check out Mdl->TotalPageCount to get the number of pages allocated).
///
/// @param Mdl              Descriptor of list of physical pages that need to be allocated
/// @param NumberOfPages    Total number of pages described by Mdl
/// @param Options          Allocator options.
/// @param Allocator        Allocator to be used to get the pages
/// @param HvVa             Virtual address where pages are mapped
///
/// @return CX_STATUS_INVALID_PARAMETER_1           Mdl is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2           NumberOfPages is invalid (0)
/// @return CX_STATUS_INVALID_PARAMETER_4           Allocator is invalid
/// @return STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW    An incomplete allocation was done because the MDL couldn't be increased to hold
///                                                 all necessary entries (either the MDL was static, or the reallocation of the dynamic MDL failed)
/// @return STATUS_PP_INCONSISTENCY                 On severe internal error (system shall halt, bitmaps are corrupt)
/// @return CX_STATUS_NOT_INITIALIZED               If VA allocators are not properly initialized
/// @return STATUS_OPTION_OR_FLAG_NOT_SUPPORTED     If Options contains a not supported flag
/// @return CX_STATUS_INSUFFICIENT_RESOURCES        If there are not enough free pages found
/// @return CX_STATUS_DATA_BUFFER_TOO_SMALL
/// @return CX_STATUS_SUCCESS
NTSTATUS
PpAlloc(
    _In_ MDL* Mdl,
    _In_ DWORD NumberOfPages,
    _In_ PP_OPTIONS Options,
    _In_ PP_ALLOCATOR Allocator,
    __out_opt VOID** HvVa
    );

/// @brief

///
/// Frees back to the page pool a set of 4K physical pages previously allocated with PpAlloc.
///
/// @param Mdl          MDL that describes the physical pages we want to free

///
/// @return STATUS_ADDRESS_NOT_FOUND_IN_PFN If there is an inconsistency (the MDL contains pages that are not from the HVVA range,
///                                         and thus an PA-to-VA lookup can't be done using PFN, ex. the MDL was altered after alloc or wrongly handcrafted)
/// @return STATUS_INVALID_MDL              If the MDL contains inconsistency (ex. was altered after alloc)
/// @return STATUS_INVALID_MDL_HINT         If the MDL contains an invalid PP allocator hint (ex. was altered after alloc)
/// @return CX_STATUS_INVALID_PARAMETER_1   If MDL is NULL
/// @return CX_STATUS_SUCCESS               On success
NTSTATUS
PpFree(
    _In_ MDL* Mdl
    );

/// @brief Print page-pool allocation details for debugging purposes
void
PpDumpAllocStats(
    void
    );

#endif // _PAGEPOOL_H

/// @}
