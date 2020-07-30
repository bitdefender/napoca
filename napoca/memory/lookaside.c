/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup lookaside Lookaside support
/// @ingroup memory
/// @{
#include "napoca.h"
#include "kernel/kernel.h"
#include "memory/memmgr.h"
#include "memory/lookaside.h"


void
LokPreinit(
    _In_ LOOKASIDE_LIST* Lookaside
    )

{
    assert(Lookaside != NULL);

    Lookaside->Initialized = FALSE;
}



NTSTATUS
LokInit(
    _In_ LOOKASIDE_LIST* Lookaside,
    _In_ DWORD ItemSize,
    _In_ DWORD ItemTag,
    _In_ DWORD MaxItemCount,
    _In_ DWORD PreallocItemCount
    )
{
    NTSTATUS status;

    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (Lookaside->Initialized) return CX_STATUS_ALREADY_INITIALIZED_HINT;
    if (ItemSize < 16)  return CX_STATUS_INVALID_PARAMETER_2;
    if (MaxItemCount < 16) return CX_STATUS_INVALID_PARAMETER_4;
    if (PreallocItemCount > MaxItemCount) return CX_STATUS_INVALID_PARAMETER_5;

    // initialize lookaside structure
    Lookaside->Tos.Next = NULL;
    Lookaside->ItemCount = 0;
    Lookaside->ItemSize = ItemSize;
    Lookaside->ItemTag = ItemTag;
    Lookaside->MaxItemCount = MaxItemCount;
    Lookaside->TotalAllocCount = 0;
    Lookaside->TotalFreeCount = 0;
    Lookaside->TotalHitCount = 0;
    Lookaside->Buffer = NULL;

    status = HpAllocWithTagCore(&Lookaside->Buffer, ItemSize * PreallocItemCount, ItemTag);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        goto cleanup;
    }

    STACK_ENTRY* item = Lookaside->Buffer;
    for (DWORD i = 0; i < PreallocItemCount; i++)
    {
        // add item to lookaside list
        InterlockedPushStackEntry(&Lookaside->Tos, item);
        Lookaside->ItemCount++;

        item = (STACK_ENTRY*)((BYTE*)item + ItemSize);
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;
    Lookaside->Initialized = TRUE;

cleanup:

    if (!SUCCESS(status))
    {
        while ((item = InterlockedPopStackEntry(&Lookaside->Tos)) != NULL)
        {
            Lookaside->ItemCount--;
        }

        HpFreeAndNullWithTag(&Lookaside->Buffer, ItemTag);
    }

    return status;
}



NTSTATUS
LokUninit(
    _In_ LOOKASIDE_LIST* Lookaside
    )
{
    NTSTATUS status;

    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Lookaside->Initialized) return CX_STATUS_NOT_INITIALIZED_HINT;

    // first of all, flush all items from the lookaside list
    status = LokFlush(Lookaside);
    if (!SUCCESS(status)) goto cleanup;

    // free this item
    status = HpFreeAndNullWithTag(&Lookaside->Buffer, Lookaside->ItemTag);
    if (!SUCCESS(status))
    {
        LOG("ERROR: HpFreeAndNullWithTag failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;
    Lookaside->Initialized = FALSE;

cleanup:

    return status;
}



NTSTATUS
LokFlush(
    _In_ LOOKASIDE_LIST* Lookaside
    )
{
    NTSTATUS status;
    STACK_ENTRY* item;

    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Lookaside->Initialized) return CX_STATUS_NOT_INITIALIZED;

    while ((item = InterlockedPopStackEntry(&Lookaside->Tos)) != NULL)
    {
        Lookaside->ItemCount--;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;
    return status;
}



NTSTATUS
LokAlloc(
    _In_ LOOKASIDE_LIST* Lookaside,
    _Out_ VOID** Item
    )
{
    NTSTATUS status;
    STACK_ENTRY* item;

    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Item) return CX_STATUS_INVALID_PARAMETER_2;

    *Item = NULL;

    Lookaside->TotalAllocCount++;

    // do we have a new item in the lookaside list?
    item = InterlockedPopStackEntry(&Lookaside->Tos);
    if (item)
    {
        Lookaside->TotalHitCount++;
        Lookaside->ItemCount--;
    }
    else
    {
        // if not found in lookaside list, try to explicitly allocate
        status = HpAllocWithTagCore(&item, Lookaside->ItemSize, Lookaside->ItemTag);
        if (!SUCCESS(status))
        {
            LOG("ERROR: HpAllocWithTagCore failed, status=%s\n", NtStatusToString(status));
            goto cleanup;
        }
    }

    // integrity check
    assert(item != NULL);

    *Item = item;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



NTSTATUS
LokFree(
    _In_ LOOKASIDE_LIST* Lookaside,
    _Inout_ VOID** Item,
    _In_ BOOLEAN SkipLookaside
    )
{
    NTSTATUS status;
    STACK_ENTRY* item;

    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Item) return CX_STATUS_INVALID_PARAMETER_2;

    Lookaside->TotalFreeCount++;

    item = (STACK_ENTRY*)*Item;
    *Item = NULL;

    // shall we do a free-to-lookaside?
    if ((!SkipLookaside) &&
        (Lookaside->ItemCount < Lookaside->MaxItemCount))
    {
        InterlockedPushStackEntry(&Lookaside->Tos, item);
        Lookaside->ItemCount++;
    }
    // or we shall do a real free?
    else
    {
        // free this item
        status = HpFreeAndNullWithTag(&item, Lookaside->ItemTag);
        if (!SUCCESS(status))
        {
            LOG("ERROR: HpFreeAndNullWithTag failed, status=%s\n", NtStatusToString(status));
            goto cleanup;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



NTSTATUS
LokDumpStats(
    _In_ LOOKASIDE_LIST* Lookaside,
    _In_opt_ CHAR* Message
    )
{
    if (!Lookaside) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Lookaside->Initialized) return CX_STATUS_NOT_INITIALIZED;

    if (Message)
    {
        LOG("dump lookaside list statistics%s\n", Message);
    }

    LOG("ItemCount %d   x ItemSize %d bytes = TotalSize %d bytes\n",
        Lookaside->ItemCount, Lookaside->ItemSize, Lookaside->ItemCount * Lookaside->ItemSize);
    LOG("TotalAllocCount %d   TotalHitCount %d   TotalFreeCount %d\n",
        (DWORD)Lookaside->TotalAllocCount, (DWORD)Lookaside->TotalHitCount, (DWORD)Lookaside->TotalFreeCount);

    return CX_STATUS_SUCCESS;
}
/// @}