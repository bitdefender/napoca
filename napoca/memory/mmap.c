/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup mmap Memory maps support
/// @ingroup memory
/// @{
#include "napoca.h"
#include "kernel/kernel.h"



void
MmapPreinitEmpty(
    _In_ MMAP* Map,
    _In_ VOID* Buffer,
    _In_ DWORD BufferLength
    )
{
    assert(BufferLength > 0);
    assert(NULL != Buffer);

    Map->Entry = (MEM_MAP_ENTRY*)Buffer;
    Map->Count = 0;
    Map->MaxCount = BufferLength / sizeof(MEM_MAP_ENTRY);
    Map->Allocated = FALSE;

    memzero(Map->Entry, BufferLength);
}



NTSTATUS
MmapAllocMapEntries(
    _Inout_ MMAP* Map,
    _In_ DWORD MaxCount
    )
{
    NTSTATUS status;

    if (!Map) return CX_STATUS_INVALID_PARAMETER_1;
    if (!MaxCount) return CX_STATUS_INVALID_PARAMETER_2;

    Map->MaxCount = 0;
    Map->Count = 0;
    Map->Allocated = TRUE;
    Map->Entry = NULL;

    status = HpAllocWithTagCore(&Map->Entry, sizeof(MEM_MAP_ENTRY) * MaxCount, TAG_MMP);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore / MMAP entries", status);
        goto cleanup;
    }

    memzero(Map->Entry, sizeof(MEM_MAP_ENTRY) * MaxCount);

    // everything done just fine
    Map->MaxCount = MaxCount;
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



NTSTATUS
MmapFreeMapEntries(
    _Inout_ MMAP* Map
    )
{
    NTSTATUS status;

    if (!Map) return CX_STATUS_INVALID_PARAMETER_1;
    if ((!Map->Entry) || (!Map->Allocated)) return CX_STATUS_SUCCESS;

    status = HpFreeAndNullWithTag(&Map->Entry, TAG_MMP);

    // zero down pointers and counts anyway, then return heap free status
    Map->Entry = NULL;
    Map->MaxCount = 0;
    Map->Count = 0;
    Map->Allocated = FALSE;

    return status;
}



NTSTATUS
MmapApplyNewEntry(
    _In_ MMAP* Map,                         // MMAP to apply the new entry on
    _In_ MEM_MAP_ENTRY* NewEntry,           // entry to apply on the MMAP
    _In_ DWORD Mode                         // MMAP_xxx - how to handle conflicts
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD start, end, size, dest;
    BYTE type;
    WORD cache;
    DWORD i, k;

    if ((!Map) || (!Map->Entry) || (!Map->MaxCount) || (Map->Count > Map->MaxCount)) return CX_STATUS_INVALID_PARAMETER_1;
    if ((!NewEntry) || (!NewEntry->Length)) return CX_STATUS_INVALID_PARAMETER_2;

    if ((MMAP_CANT_OVERLAP != Mode) &&
        (MMAP_SPLIT_AND_KEEP_LESS_CACHED != Mode) &&
        (MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT != Mode) &&
        (MMAP_SPLIT_AND_KEEP_NEW != Mode))
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    // start with full block as 'new entry'
    start = NewEntry->StartAddress;
    size = NewEntry->Length;
    end = start + size - 1;
    type = NewEntry->Type;
    cache = NewEntry->CacheAndRights;
    dest = NewEntry->DestAddress;

    // try to process repeatedly while we have a valid chunk left
    i = 0;
    while (size > 0)
    {
        QWORD oldStart, oldEnd, oldSize, oldDest;
        QWORD delta;
        BYTE oldType;
        WORD oldCache;

        // I. if we compared to all entries, no overlap found ==> simply apply
        if (i >= Map->Count)
        {
            i = Map->Count;

            switch (Mode)
            {
            case MMAP_CANT_OVERLAP:
            case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
            case MMAP_SPLIT_AND_KEEP_NEW:
                //
                // we must insert (or coalesce with existing entry from i-1) the new entry, then discard it
                //
                if ((i > 0) && (start == Map->Entry[i-1].StartAddress + Map->Entry[i-1].Length) &&
                    (type == Map->Entry[i-1].Type) && (cache == Map->Entry[i-1].CacheAndRights) &&
                    (dest == Map->Entry[i-1].DestAddress + Map->Entry[i-1].Length))
                {
                    //
                    // coalesce with existing entry at i-1 - simply adjust the size of the entry at i-1
                    //
                    Map->Entry[i-1].Length = Map->Entry[i-1].Length + size;

                    // discard new entry
                    size = 0;
                }
                else
                {
                    //
                    // insert new entry to pos i
                    //

                    // check we have one more free slot
                    if (Map->Count >= Map->MaxCount)
                    {
                        ERROR("Map->Count %d  >  Map->MaxCount %d, Map %018p\n", Map->Count, Map->MaxCount, Map);

                        status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                        goto cleanup;
                    }

                    // simply insert to pos i (no shifting needed), because we know this is tha LAST position
                    Map->Entry[i].StartAddress = start;
                    Map->Entry[i].Length = size;
                    Map->Entry[i].Type = type;
                    Map->Entry[i].CacheAndRights = cache;
                    Map->Entry[i].DestAddress = dest;
                    Map->Count++;

                    // discard new entry
                    size = 0;
                }
                break;

            case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                {
                    //
                    // nothing to do, because we do NOT insert
                    //

                    // discard new entry
                    size = 0;
                }
                break;
            }

            // will stop processing, because of size == 0
            continue;
        }

        // get old entry values from index i
        oldStart = Map->Entry[i].StartAddress;
        oldSize = Map->Entry[i].Length;
        oldEnd = oldStart + oldSize - 1;
        oldType = Map->Entry[i].Type;
        oldCache = Map->Entry[i].CacheAndRights;
        oldDest = Map->Entry[i].DestAddress;

        // II. compare new entry with old entry at index i to find any overlaps
        if (start < oldStart)
        {
            if (end < oldStart)
            {
                //
                // case 1 - no overlap at all, simply apply new entry
                //
                switch (Mode)
                {
                case MMAP_CANT_OVERLAP:
                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                case MMAP_SPLIT_AND_KEEP_NEW:
                    //
                    // we must insert (or coalesce with existing entry from i-1) the new entry, then discard it
                    //
                    if ((i > 0) && (start == Map->Entry[i-1].StartAddress + Map->Entry[i-1].Length) &&
                        (type == Map->Entry[i-1].Type) && (cache == Map->Entry[i-1].CacheAndRights))
                    {
                        //
                        // coalesce with existing entry at i-1 - simply adjust the size of the entry at i-1
                        //
                        Map->Entry[i-1].Length = Map->Entry[i-1].Length + size;

                        // discard new item (setting 'size = 0' will stop the while cycle)
                        size = 0;
                    }
                    else
                    {
                        //
                        // insert new entry to pos i
                        //

                        // check we have one more free slot
                        if (Map->Count >= Map->MaxCount)
                        {
                            ERROR("Map->Count %d  >  Map->MaxCount %d, Map %018p\n", Map->Count, Map->MaxCount, Map);

                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // shift RIGHT all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k] = Map->Entry[k-1];
                        }

                        // insert new entry to pos i
                        Map->Entry[i].StartAddress = start;
                        Map->Entry[i].Length = size;
                        Map->Entry[i].Type = type;
                        Map->Entry[i].CacheAndRights = cache;
                        Map->Entry[i].DestAddress = dest;
                        Map->Count++;

                        // discard new item
                        size = 0;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // nothing to do, because we do NOT insert; simply discard new item
                        //
                        size = 0;
                    }
                    break;
                }
            }
            else
            {
                //
                // skip if overlapping is NOT allowed
                //
                if (MMAP_CANT_OVERLAP == Mode)
                {
                    status = STATUS_OVERLAP_VIOLATION;
                    goto cleanup;
                }

                //
                // case 2 - we have overlap and also part of new chunk hanging before
                //
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((type == oldType) && (cache == oldCache))
                    {
                        //
                        // simply extend to left the old entry and continue with i ==> 6,7,8
                        //
                        delta = oldStart - start;
                        oldStart = oldStart - delta;
                        oldSize = oldSize + delta;
                        oldDest = oldDest - delta;
                        Map->Entry[i].StartAddress = oldStart;
                        Map->Entry[i].Length = oldSize;
                        Map->Entry[i].DestAddress = oldDest;

                        // continue with i
                        continue;
                    }
                    else
                    {
                        //
                        // we must insert (or coalesce with existing entry from i-1) the new entry, then adjust new entry and continue with i (for coalesce) or i+1 (for insert) ==> 6,7,8
                        //
                        delta = oldStart - start;

                        if ((i > 0) && (start == Map->Entry[i-1].StartAddress + Map->Entry[i-1].Length) &&
                            (type == Map->Entry[i-1].Type) && (cache == Map->Entry[i-1].CacheAndRights))
                        {
                            //
                            // coalesce with existing entry at i-1 - simply adjust the size of the entry at i-1
                            //
                            Map->Entry[i-1].Length = Map->Entry[i-1].Length + delta;

                            // adjust new entry
                            size = size - delta;
                            start = start + delta;
                            dest = dest + delta;

                            // continue with i
                            continue;
                        }
                        else
                        {
                            //
                            // insert new entry to pos i
                            //

                            // check we have one more free slot
                            if (Map->Count >= Map->MaxCount)
                            {
                                status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                                goto cleanup;
                            }

                            // shift RIGHT all entries from (i+1) to (Count-1)
                            for (k = Map->Count; k > i; k--)
                            {
                                Map->Entry[k] = Map->Entry[k-1];
                            }

                            // insert chunk to pos i and adjust new entry
                            Map->Entry[i].StartAddress = start;
                            Map->Entry[i].Length = delta;
                            Map->Entry[i].Type = type;
                            Map->Entry[i].CacheAndRights = cache;
                            Map->Entry[i].DestAddress = dest;
                            Map->Count++;

                            // adjust new entry
                            size = size - delta;
                            start = start + delta;
                            dest = dest + delta;

                            // continue with i+1
                            i++;
                            continue;
                        }
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // adjust new entry, but do NOT insert anything; continue with i ==> 6,7,8
                        //
                        delta = oldStart - start;
                        size = size - delta;
                        start = start + delta;
                        dest = dest + delta;

                        // continue with i
                        continue;
                    }
                    break;
                }
            }
        }
        else if ((start > oldStart) && (start < oldEnd))
        {
            //
            // skip if overlapping is NOT allowed
            //
            if (MMAP_CANT_OVERLAP == Mode)
            {
                ERROR("Overlapping entry: base address %p, length %p, overlapping at %p\n", NewEntry->StartAddress, NewEntry->Length, start);
                status = STATUS_OVERLAP_VIOLATION;
                goto cleanup;
            }

            if (end < oldEnd)
            {
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case3_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case3_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case3_new_is_more_powerfull:
                        //
                        // we must split the old entry into two pieces (i, i+2), and also insert the new entry between (i+1), then discard the new entry
                        //

                        // check we have two more free slots
                        if ((Map->Count+1) >= Map->MaxCount)
                        {
                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // shift RIGHT TWICE all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k+1] = Map->Entry[k-1];      // from (k-1) to (k+1), that is, shift TWO positions !
                        }

                        // create second chunk at pos i+2, based on old entry
                        Map->Entry[i+2].Type = oldType;
                        Map->Entry[i+2].CacheAndRights = oldCache;
                        delta = (start - oldStart) + size;
                        Map->Entry[i+2].StartAddress = oldStart + delta;
                        Map->Entry[i+2].Length = oldSize - delta;
                        Map->Entry[i+2].DestAddress = oldDest + delta;
                        Map->Count++;

                        // adjust old chunk at pos i
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // insert new entry to pos i+1
                        Map->Entry[i+1].Type = type;
                        Map->Entry[i+1].CacheAndRights = cache;
                        Map->Entry[i+1].StartAddress = start;
                        Map->Entry[i+1].Length = size;
                        Map->Entry[i+1].DestAddress = dest;
                        Map->Count++;

                        // discard new item
                        size = 0;
                    }
                    else
                    {
case3_old_is_just_fine:
                        //
                        // simply ignore new entry, because the old one has lower or equal caching
                        //
                        size = 0;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must split the old entry into two pieces, then discard the new entry
                        //

                        // check we have one more free slot
                        if (Map->Count >= Map->MaxCount)
                        {
                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // shift RIGHT all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k] = Map->Entry[k-1];
                        }

                        // insert second chunk to pos i+1, based on old entry
                        delta = (start - oldStart) + size;
                        Map->Entry[i+1].Type = oldType;
                        Map->Entry[i+1].CacheAndRights = oldCache;
                        delta = (start - oldStart) + size;
                        Map->Entry[i+1].StartAddress = oldStart + delta;
                        Map->Entry[i+1].Length = oldSize - delta;
                        Map->Entry[i+1].DestAddress = oldDest + delta;
                        Map->Count++;

                        // adjust old chunk at pos i
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // discard the new entry
                        size = 0;
                    }
                    break;
                }
            }
            else if (end == oldEnd)
            {
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case4_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case4_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case4_new_is_more_powerfull:
                        //
                        // we must adjust the old entry, then insert the new entry to i+1; discard the new entry after that
                        //

                        // check we have one more free slot
                        if (Map->Count >= Map->MaxCount)
                        {
                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // adjust the old entry
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // shift RIGHT all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k] = Map->Entry[k-1];
                        }

                        // insert new entry to pos i+1
                        Map->Entry[i+1].Type = type;
                        Map->Entry[i+1].CacheAndRights = cache;
                        Map->Entry[i+1].StartAddress = start;
                        Map->Entry[i+1].Length = size;
                        Map->Entry[i+1].DestAddress = dest;
                        Map->Count++;

                        // discard the new entry
                        size = 0;
                    }
                    else
                    {
case4_old_is_just_fine:
                        //
                        // simply ignore new entry, because the old one has lower or equal caching
                        //
                        size = 0;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must adjust the old entry and discard the new entry
                        //
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // discard the new entry
                        size = 0;
                    }
                    break;
                }
            }
            else
            {

                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case5_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case5_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case5_new_is_more_powerfull:
                        //
                        // we must adjust the old entry, then insert the new entry to i+1; adjust the new entry after that and continue with i+2
                        //

                        // check we have one more free slot
                        if (Map->Count >= Map->MaxCount)
                        {
                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // adjust the old entry
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // shift RIGHT all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k] = Map->Entry[k-1];
                        }

                        // insert new entry to pos i+1
                        Map->Entry[i+1].Type = type;
                        Map->Entry[i+1].CacheAndRights = cache;
                        Map->Entry[i+1].StartAddress = start;
                        delta = oldEnd - start + 1;
                        Map->Entry[i+1].Length = delta;
                        Map->Entry[i+1].DestAddress = dest;
                        Map->Count++;

                        // adjust new entry
                        size = size - delta;
                        start = start + delta;
                        dest = dest + delta;

                        // continue with i+2
                        i = i + 2;
                        continue;
                    }
                    else
                    {
case5_old_is_just_fine:
                        //
                        // adjust the new entry and continue with i+1
                        //
                        delta = oldEnd - start + 1;
                        start = start + delta;      //oldEnd + 1;
                        size = size - delta;
                        dest = dest + delta;

                        // continue with i+1
                        i++;
                        continue;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must adjust the old entry, then adjust the new entry and continue with i+1
                        //
                        oldSize = (start - oldStart);
                        Map->Entry[i].Length = oldSize;

                        // adjust new entry
                        delta = oldEnd - start + 1;
                        start = start + delta;
                        size = size - delta;
                        dest = dest + delta;

                        // continue with i+1
                        i++;
                        continue;
                    }
                    break;
                }
            }
        }
        else if (start == oldStart)
        {
            //
            // skip if overlapping is NOT allowed
            //
            if (Mode == MMAP_CANT_OVERLAP)
            {
                ERROR("Overlapping entry: base address %p, length %p, overlapping at %p\n", NewEntry->StartAddress, NewEntry->Length, start);
                status = STATUS_OVERLAP_VIOLATION;
                goto cleanup;
            }

            if (end < oldEnd)
            {
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case6_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case6_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case6_new_is_more_powerfull:
                        //
                        // we must adjust the old entry, then insert the new entry to i; discard the new entry after that
                        //

                        // check we have one more free slot
                        if (Map->Count >= Map->MaxCount)
                        {
                            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                            goto cleanup;
                        }

                        // adjust the old entry (will be shifted to i+1)
                        delta = size;
                        oldStart = oldStart + delta;
                        oldSize = oldSize - delta;
                        oldDest = oldDest + delta;
                        Map->Entry[i].StartAddress = oldStart;
                        Map->Entry[i].Length = oldSize;
                        Map->Entry[i].DestAddress = oldDest;

                        // shift RIGHT all entries from (i+1) to (Count-1)
                        for (k = Map->Count; k > i; k--)
                        {
                            Map->Entry[k] = Map->Entry[k-1];
                        }

                        // insert new entry to pos i
                        Map->Entry[i].Type = type;
                        Map->Entry[i].CacheAndRights = cache;
                        Map->Entry[i].StartAddress = start;
                        Map->Entry[i].Length = size;
                        Map->Entry[i].DestAddress = dest;
                        Map->Count++;

                        // discard new entry
                        size = 0;
                    }
                    else
                    {
case6_old_is_just_fine:
                        //
                        // simply ignore new entry, because the old one has lower or equal caching
                        //
                        size = 0;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must adjust the old entry and discard the new entry
                        //
                        delta = size;
                        oldStart = oldStart + delta;
                        oldSize = oldSize - delta;
                        oldDest = oldDest + delta;
                        Map->Entry[i].StartAddress = oldStart;
                        Map->Entry[i].Length = oldSize;
                        Map->Entry[i].DestAddress = oldDest;

                        // discard new entry
                        size = 0;
                    }
                    break;
                }
            }
            else if (end == oldEnd)
            {
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case7_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case7_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case7_new_is_more_powerfull:
                        //
                        // we must update the old entry's caching, then discard the new entry after that
                        //

                        // update old entry
                        Map->Entry[i].Type = type;
                        Map->Entry[i].CacheAndRights = cache;
                        Map->Entry[i].DestAddress = dest;

                        // discard new entry
                        size = 0;
                    }
                    else
                    {
case7_old_is_just_fine:
                        //
                        // simply ignore new entry, because the old one has lower or equal caching
                        //
                        size = 0;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must delete the old entry and discard the new entry
                        //

                        // shift LEFT all entries from (i+1) to (Count-1)
                        for (k = i; k < Map->Count-1; k++)
                        {
                            Map->Entry[k] = Map->Entry[k+1];
                        }

                        Map->Count--;

                        // discard new entry
                        size = 0;
                    }
                    break;
                }
            }
            else
            {
                switch (Mode)
                {
                case MMAP_SPLIT_AND_KEEP_NEW:
                    if ((type != oldType) || (cache != oldCache))
                    {
                        goto case8_new_is_more_powerfull;
                    }
                    else
                    {
                        goto case8_old_is_just_fine;
                    }

                case MMAP_SPLIT_AND_KEEP_LESS_CACHED:
                    if ((cache & 0x38) < (oldCache & 0x38))
                    {
case8_new_is_more_powerfull:
                        //
                        // we must update the old entry's caching, then adjust the new entry and continue with i+1
                        //

                        // update old entry
                        Map->Entry[i].Type = type;
                        Map->Entry[i].CacheAndRights = cache;
                        Map->Entry[i].DestAddress = dest;

                        // adjust new entry
                        delta = oldSize;
                        start = start + delta;
                        size = size - delta;
                        dest = dest + delta;

                        // continue with i+1
                        i++;
                        continue;
                    }
                    else
                    {
case8_old_is_just_fine:
                        //
                        // adjust the new entry and continue with i+1
                        //
                        delta = oldEnd - start + 1;
                        start = start + delta;      //oldEnd + 1;
                        size = size - delta;
                        dest = dest + delta;

                        // continue with i+1
                        i++;
                        continue;
                    }
                    break;

                case MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT:
                    {
                        //
                        // we must delete the old entry, then adjust the new entry and continue with i
                        //

                        // shift LEFT all entries from (i+1) to (Count-1)
                        for (k = i; k < Map->Count-1; k++)
                        {
                            Map->Entry[k] = Map->Entry[k+1];
                        }

                        Map->Count--;

                        //
                        // adjust the new entry and continue with i+1
                        //
                        delta = oldEnd - start + 1;
                        start = start + delta;
                        size = size - delta;
                        dest = dest + delta;

                        continue;
                    }
                    break;
                }
            }
        }
        else
        {
            // NO overlap at all, go to next old entry
            i++;
        }
    }

    // cleanup and determine final status
cleanup:
    if ((!size) && (!SUCCESS(status)))
    {
        status = CX_STATUS_SUCCESS;

        // if everything is successful, then should check if the algorithm is correct
    }

    return status;
}



NTSTATUS
MmapCopyMap(
    _Inout_ MMAP* Dest,
    _In_ MMAP* Source,
    _In_ DWORD IncreaseCount
    )
{
    NTSTATUS status;

    if (!Dest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Source) return CX_STATUS_INVALID_PARAMETER_2;

    // allocate dest map
    status = MmapAllocMapEntries(Dest, Source->MaxCount + IncreaseCount);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapAllocMapEntries", status);
        goto cleanup;
    }

    // copy all entries from source map to dest map
    Dest->Count = Source->Count;
    memcpy(Dest->Entry, Source->Entry, Source->Count * sizeof(MEM_MAP_ENTRY));

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
MmapApplyFullMap(
    _Inout_ MMAP* Dest,
    _In_ MMAP* Source,
    _In_ DWORD Mode
    )
{
    NTSTATUS status;
    DWORD i;
    MEM_MAP_ENTRY* entry;

    if (!Dest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Source) return CX_STATUS_INVALID_PARAMETER_2;

    if ((Mode != MMAP_CANT_OVERLAP) &&
        (Mode != MMAP_SPLIT_AND_KEEP_LESS_CACHED) &&
        (Mode != MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT) &&
        (Mode != MMAP_SPLIT_AND_KEEP_NEW))
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    // remove each Source entry from Dest map, in-place
    for (i = 0; i < Source->Count; i++)
    {
        entry = &(Source->Entry[i]);

        status = MmapApplyNewEntry(Dest, entry, Mode);
        if (!SUCCESS(status))
        {
            ERROR("Failed applying entry #%d: start = %p, length = %p, dest = %p\n", i, entry->StartAddress, entry->Length, entry->DestAddress);
            goto cleanup;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


void
MmapDump(
    _In_ MMAP* Map,
    _In_ BYTE MemType,
    _In_opt_ CHAR* Message
    )
{
    QWORD total;
    DWORD i;
    QWORD lastMappedByte = (QWORD)-1;   // +1 == 0, used to count the first possible gap (from 0 to X)

    if ((!Map) || (!Map->Entry) || (Map->Count > Map->MaxCount))
    {
        ERROR("Invalid Map parameter!\n");
        return;
    }

    // determine total BOOT_MEM_TYPE_RAM_AVAILABLE space
    total = 0;

    for (i = 0; i < Map->Count; i++)
    {
        if (MemType == Map->Entry[i].Type)
        {
            total = total + Map->Entry[i].Length;
        }
    }

    // DEBUG - dump out total RAM amount + map layout
    LOGN("%stotal (type %d) memory = %zd bytes  (%10.3f MB)\n",
        (NULL == Message)?"":Message, MemType, total, (double)total / (double)ONE_MEGABYTE);

    for (i = 0; i < Map->Count; i++)
    {
        if ((lastMappedByte+1) != Map->Entry[i].StartAddress)
        {
            LOGN("%018p - %018p - *GAP* - %10.3f MB\n",
                (lastMappedByte+1),
                Map->Entry[i].StartAddress,
                (Map->Entry[i].StartAddress - (lastMappedByte+1)) / (double)ONE_MEGABYTE );
        }

         LOGN("%018p - %018p (==> %018p) - type %d / cache 0x%03x - %10.3f MB\n",
             Map->Entry[i].StartAddress,
             Map->Entry[i].StartAddress + Map->Entry[i].Length - 1,
             Map->Entry[i].DestAddress,
             Map->Entry[i].Type, Map->Entry[i].CacheAndRights,
             (double)Map->Entry[i].Length / (double)ONE_MEGABYTE );

        lastMappedByte = Map->Entry[i].StartAddress + Map->Entry[i].Length - 1;
    }
}

BOOLEAN
MmapIsAddressInMap(
    _In_ MMAP* Map,
    _In_ QWORD Address,
    _In_ LD_HV_MEM_TYPE MemType
)
{
    for (DWORD entryIndex = 0; entryIndex < Map->Count; entryIndex++)
    {
        if (Address >= Map->Entry[entryIndex].StartAddress &&
            (Address < Map->Entry[entryIndex].StartAddress + Map->Entry[entryIndex].Length) &&
            (MemType == BOOT_MEM_TYPE_MAX_VALUE || Map->Entry[entryIndex].Type == MemType)
            )
        {
            return TRUE;
        }
    }

    return FALSE;
}
/// @}
