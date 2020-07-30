/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup mmap
/// @{
#ifndef _MMAP_
#define _MMAP_

#include "kernel/kerneldefs.h"
#include "boot/boot.h"

typedef struct _MEM_MAP_ENTRY MEM_MAP_ENTRY;

/// @brief Represents a memory map
typedef struct _MMAP {
    DWORD               MaxCount;               ///< Maximum number of entries available
    DWORD               Count;                  ///< Used number of entries
    BOOLEAN             Allocated;              ///< TRUE for dynamically allocated MMAPs
    MEM_MAP_ENTRY*      Entry;                  ///< Entries describing memory ranges
} MMAP;

#define MMAP_CANT_OVERLAP                   1   ///< reject with error if the NewEntry overlaps any of the old entries
#define MMAP_SPLIT_AND_KEEP_LESS_CACHED     2   ///< split old and new entires on overlap, keep always the entry with lower caching
#define MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT 3   ///< split old entries on overlap, remove all overlapping old entries but do NOT add new entry (simply delete)
#define MMAP_SPLIT_AND_KEEP_NEW             4   ///< split old and new entries on overlap, keep always the new entry


/// @brief Pre-initializes an empty MMAP (zero entries) with an already present buffer to store the MMAP entries (static MMAP).
/// @param Map              MMAP to preinitialize
/// @param Buffer           pointer to storage buffer for the MMAP entry
/// @param BufferLength     length of storage buffer in bytes
void
MmapPreinitEmpty(
    _In_ MMAP* Map,
    _In_ VOID* Buffer,
    _In_ DWORD BufferLength
    );

/// @brief Allocates entries for and initializes a dynamic MMAP.
/// @param Map              Dynamic MMAP to initialize
/// @param MaxCount         Number of entries to allocate space for
/// @return CX_STATUS_INVALID_PARAMETER_1   Map is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   MaxCount is 0
/// @return CX_STATUS_SUCESS                On success
NTSTATUS
MmapAllocMapEntries(
    _Inout_ MMAP* Map,
    _In_ DWORD MaxCount
    );

/// @brief Frees the buffer used to store the entries of a dynamic MMAP.
/// @param Map          Dynamic MMAP to free
/// @return CX_STATUS_INVALID_PARAMETER_1   Map is NULL
/// @return CX_STATUS_SUCESS                On success
NTSTATUS
MmapFreeMapEntries(
    _Inout_ MMAP* Map
    );

/// @brief Apply a new entry
///
/// Applies a new entry (memory zone with given base and length) to an existing MMAP. In the simplest case, an apply
/// equals with adding the new entry to the MMAP, but there are various ways a new entry can be applied on an existing
/// MMAP, according to Mode:
/// - MMAP_CANT_OVERLAP - reject with error if the NewEntry overlaps with any of the old entries
/// - MMAP_SPLIT_AND_KEEP_LESS_CACHED - split old and new entries on overlap, keep always the entry with lower caching
/// - MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT - split old entries on overlap, remove all overlapping old entries but
///   do NOT add new entry (simply delete)
/// - MMAP_SPLIT_AND_KEEP_NEW - split old and new entries on overlap, keep always the new entry
///
/// @param Map          Destination MMAP
/// @param NewEntry     Entry to be applied
/// @param Mode         Behavior that will be used when applying the entry
/// @return CX_STATUS_DATA_BUFFER_TOO_SMALL     if the MMAP does NOT contain enough space for new entries
/// @return STATUS_OVERLAP_VIOLATION            if MMAP_CANT_OVERLAP is used and an overlap is detected
/// @return CX_STATUS_INVALID_PARAMETER_1       Map is NULL or invalid
/// @return CX_STATUS_INVALID_PARAMETER_2       NewEntry is NULL or invalid
/// @return CX_STATUS_INVALID_PARAMETER_3       Mode is invalid
/// @return CX_STATUS_SUCESS                On success
NTSTATUS
MmapApplyNewEntry(
    _In_ MMAP* Map,
    _In_ MEM_MAP_ENTRY* NewEntry,
    _In_ DWORD Mode
    );

/// @brief Allocates entries in the destination MMAP then copy all entries from source MMAP to destination MMAP
/// @param Dest             destination MMAP
/// @param Source           source MMAP
/// @param IncreaseCount    the number of new entries to allocate for Dest beside the ones used to hold entries from Source
/// @return CX_STATUS_INVALID_PARAMETER_1   Dest is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2   Source is NULL
/// @return CX_STATUS_SUCESS                On success
NTSTATUS
MmapCopyMap(
    _Inout_ MMAP* Dest,
    _In_ MMAP* Source,
    _In_ DWORD IncreaseCount
    );

/// @brief Applies (combines) all entries from a source MMAP to a detination MMAP.
/// @param Dest                  MMAP to apply the entries from Source on
/// @param Source                MMAP containg all the entries to be applied on Dest
/// @param Mode                  MMAP_xxx - how to handle conflicts
/// @return CX_STATUS_INVALID_PARAMETER_1       Dest is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2       Source is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3       Mode is invalid
/// @return CX_STATUS_SUCESS                On success
NTSTATUS
MmapApplyFullMap(
    _Inout_ MMAP* Dest,
    _In_ MMAP* Source,
    _In_ DWORD Mode
    );


/// @brief Dumps the structure of a MMAP, for debugging.
/// @param Map                       MMAP to dump
/// @param MemType                   a memory type (entry.Type) for which we calculate statistics
/// @param Message                   optional message to print
void
MmapDump(
    _In_ MMAP* Map,
    _In_ BYTE MemType,
    _In_opt_ CHAR* Message
    );

/// @brief Check if an address is present in the memory MMAP
/// @param Map              Memory map to check
/// @param Address          Address to check for in the map
/// @param MemType          The type of memory that is associated with the given Address. Use BOOT_MEM_TYPE_INVALID to just check for its presence
/// @return TRUE if Address is in the map; FALSE otherwise
BOOLEAN
MmapIsAddressInMap(
    _In_ MMAP* Map,
    _In_ QWORD Address,
    _In_ LD_HV_MEM_TYPE MemType
);

#endif // _MMAP_
/// @}
