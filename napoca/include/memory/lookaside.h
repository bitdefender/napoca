/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup lookaside
/// @{
#ifndef _LOOKASIDE_H_
#define _LOOKASIDE_H_

#include "wrappers/cx_winlists.h"

/// @brief Lookaside list data
typedef struct _LOOKASIDE_LIST {
    BOOLEAN             Initialized;        ///< TRUE, if the lookaside list has been correctly initialized
    STACK_HEAD          Tos;                ///< contains pointer to the last item inserted intro the lookaside (Top-Of-Stack)
    volatile DWORD      ItemCount;          ///< current number of items in the lookaside list
    DWORD               ItemSize;           ///< size of one item
    DWORD               ItemTag;            ///< TAG used for heap allocations
    DWORD               MaxItemCount;       ///< maximum number of items to hold
    STACK_ENTRY*        Buffer;             ///< Raw buffer to lookaside list entries
    volatile INT64      TotalAllocCount;    ///< number of total LokAlloc calls, for statistics
    volatile INT64      TotalFreeCount;     ///< number of total LokFree calls, for statistics
    volatile INT64      TotalHitCount;      ///< number of LokAlloc calls handled from the lookaside list
} LOOKASIDE_LIST;


/// @brief Perform basic preinitialization steps
/// @param Lookaside    Pointer to caller allocated lookaside list structure
void
LokPreinit(
    _In_ LOOKASIDE_LIST* Lookaside
    );

/// @brief Performs initialization for the lookaside list.
///
/// Setup the lookaside list for usage. It also allocates a given number of elements in the lookaside list if requested.
///
/// @param Lookaside            Pointer to caller allocated lookaside list structure
/// @param ItemSize             Size in bytes of an item
/// @param ItemTag              Tag to identify these allocations
/// @param MaxItemCount         Maximum number of items that the lookaside may hold
/// @param PreallocItemCount    Number of items to allocate in advance
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_ALREADY_INITIALIZED_HINT          Already initialized
/// @return CX_STATUS_INVALID_PARAMETER_2               ItemSize is less the 16 bytes
/// @return CX_STATUS_INVALID_PARAMETER_4               MaxItemCount is less the 16 items
/// @return CX_STATUS_INVALID_PARAMETER_5               PreallocItemCount is greater than MaxItemCount
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokInit(
    _In_ LOOKASIDE_LIST* Lookaside,
    _In_ DWORD ItemSize,
    _In_ DWORD ItemTag,
    _In_ DWORD MaxItemCount,
    _In_ DWORD PreallocItemCount
    );


/// @brief Uninitializes the lookaside list
/// @param Lookaside                                    Pointer to caller allocated lookaside list structure
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_NOT_INITIALIZED_HINT              Not initialized
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokUninit(
    _In_ LOOKASIDE_LIST* Lookaside
    );

/// @brief Flushes the lookaside list
/// @param Lookaside                                    Pointer to caller allocated lookaside list structure
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_NOT_INITIALIZED_HINT              Not initialized
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokFlush(
    _In_ LOOKASIDE_LIST* Lookaside
    );

/// @brief Allocates a new item from the lookaside list
///
/// This function will allocate a new element from the lookaside list if there are free items in the list or
/// it will allocate the item using heap allocator if the lookaside list is full.
///
/// @param Lookaside        Pointer to caller allocated lookaside list structure
/// @param Item             Address of the allocated item
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2               Item is NULL
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokAlloc(
    _In_ LOOKASIDE_LIST* Lookaside,
    _Out_ VOID** Item
    );

/// @brief Free an element from the lookaside list
/// @param Lookaside            Pointer to caller allocated lookaside list structure
/// @param Item                 Address of the item to free
/// @param SkipLookaside        If TRUE it will free the item and its backing memory.
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_INVALID_PARAMETER_2               Item is NULL
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokFree(
    _In_ LOOKASIDE_LIST* Lookaside,
    _Inout_ VOID** Item,
    _In_ BOOLEAN SkipLookaside
    );

/// @brief Print statistics about lookaside list usage
/// @param Lookaside        Pointer to caller allocated lookaside list structure
/// @param Message          Optional message to display before statistics
/// @return CX_STATUS_INVALID_PARAMETER_1               Lookaside is NULL
/// @return CX_STATUS_SUCCESS                           On success
NTSTATUS
LokDumpStats(
    _In_ LOOKASIDE_LIST* Lookaside,
    _In_opt_ CHAR* Message
    );

#endif // _LOOKASIDE_H_
/// @}
