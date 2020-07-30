/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup memory Memory management
/// @defgroup vamgr Virtual address space management
/// @ingroup memory
/// @{
#include "napoca.h"
#include "kernel/kernel.h"
#include "kernel/kerneldefs.h"
#include "kernel/spinlock.h"
#include "memory/vamgr.h"
#include "memory/lookaside.h"
#include "base/aatree.h"
#include "base/ilockrr.h"
#include "memory/heapfa.h"



#define VAMAP_FREE_BIN_TABLE_COUNT      8

#pragma pack(push)
#pragma pack(4)
/// @brief Represents a chunk of virtual memory allocation; it is the chunk descriptors used for free (free-bin-table entries) and allocated (big-space-map only) chunks
typedef struct _VAMAP_CHUNK {
    union {
        AANODE      AaNode;                 ///< Arne Anderson tree node (from aatree.h); this MUST be the first field in VAMAP_CHUNK
                                            ///< so that can use we lookup tree links(by placing AANODE as the very first field of VAMAP_CHUNK) as pointers both as AANODE and VAMAP_CHUNK
                                            ///< pointers; also BaseAddr directly maps over AANODE.Key
        struct {
            struct _VAMAP_CHUNK *Left;      ///< Left node
            struct _VAMAP_CHUNK *Right;     ///< Right node
            struct _VAMAP_CHUNK *Parent;    ///< Parent node
            QWORD   BaseAddr;               ///< Allocation base address
            INT32   _Padding;
        };
    };
    INT32           FreeBinIdx;             ///< 0..7 index, or a negative value for non-free items (note: this also acts as padding because of AANODE)
    LIST_ENTRY      FreeLink;               ///< free-bin-table link
    LIST_ENTRY      BigLink;                ///< big-space-map link
    QWORD           Length;                 ///< Size in bytes
    QWORD           UsedLength;             ///< Size in bytes of used
    DWORD           Tag;                    ///< Allocation tag
} VAMAP_CHUNK;
#pragma pack(pop)

/// @brief Free Bin item for va allocator
typedef struct _VAMAP_FREE_BIN {
    QWORD           BinSize;        ///< Size in bytes - 16K, 64K, 256K, 1M, 4M, 16M, 64M, big
    INT64           ChunkCount;     ///< Number of chunks
    LIST_ENTRY      ListHead;       ///< List of chunks
} VAMAP_FREE_BIN;

/// @brief VA allocator header
typedef struct _VA_HEADER {
    SPINLOCK        Lock;                                       ///< Lock used for synchronization access to this allocator
    DWORD           Size;                                       ///< Size in bytes of this header
    INT64           PageCount;                                  ///< Number of pages managed by this allocator
    INT64           FreeCount;                                  ///< Number of free pages available to this allocator; used for PP_ALLOCATOR_MAXFREE
    QWORD           MinVa;                                      ///< Minimum virtual address managed by this allocator
    QWORD           MaxVa;                                      ///< Maximum virtual address managed by this allocator
    DWORD           FreeBinCount;                               ///< number of free bins in the free bin table
    VAMAP_FREE_BIN  FreeBin[VAMAP_FREE_BIN_TABLE_COUNT];        ///< Free bins array
    INT64           BigChunkCount;                              ///< Number of chunks in big-space-list
    LIST_ENTRY      BigListHead;                                ///< List of big-space chunks
    union {
        AATREE          AaTree;                                 ///< balanced AA tree
        VAMAP_CHUNK*    TreeRoot;                               ///< root entry for the lookup tree
    };
    LOOKASIDE_LIST  DescPool;                                   ///< chunk descriptor pool
    INT32           Index;                                      ///< Allocator index

    // fields for statistics
    volatile INT32  TotalReserveCount;                          ///< Number of pages allocated/reserved by this allocator
    volatile INT32  TotalFreeCount;                             ///< Number of pages freed/released by this allocator
    volatile INT32  TotalFreeAttempt;                           ///< Number of free attempts
    volatile INT32  TotalCoalesceCount;                         ///< Number of coalesced chunks
} VA_HEADER;

/// @brief Global data that aggregates all va allocators
typedef struct _VA_GLOBAL {
    DWORD           Pc;                                         ///< parallel count of va allocators
    DWORD           Size;                                       ///< Size in bytes of this header
    VA_HEADER       VaAllocator[NAPOCA_MAX_PARALLELIZATION];    ///< Array of possible parallel va allocators
    QWORD           MinVa;                                      ///< Minimum virtual address space managed by all allocators
    QWORD           MaxVa;                                      ///< Maximum virtual address space managed by all allocators
    BOOLEAN         Initialized;                                ///< Indicates if allocators are initialized
    ILOCK_RR        RrHint;                                     ///< ROUND-ROBIN hint, index of VA-allocator to try to use for next alloc in round-robin mode
} VA_GLOBAL;


/// @brief Virtual address allocator Bin size array
static const QWORD gDefBinSize[] = { 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024, 256 * 1024 * 1024 };

/// @brief Global virtual allocator aggregator
static VA_GLOBAL gVa;


static
NTSTATUS
_VaMgrDummyFreeAaNode(
    _In_ AATREE* Tree,
    _Inout_ AANODE* *Node
);


VOID
VaMgrPreinitAllocator(
    VOID
    )
{
    memzero(&gVa, sizeof(VA_GLOBAL));

    gVa.Initialized = FALSE;

    gVa.Size = sizeof(VA_GLOBAL);
    gVa.Pc = gHypervisorGlobalData.CpuData.MaxParallel;

    gVa.MinVa = NAPOCA_VA_ALLOCATOR_BASE;
    gVa.MaxVa = gVa.MinVa + NAPOCA_PER_VA_ALLOCATOR_LENGTH * gVa.Pc - 1;
}


BOOLEAN
VaMgrIsInitialized(
    VOID
)
{
    return gVa.Initialized;
}

NTSTATUS
VaMgrInitAllocator(
    VOID
    )
{
    NTSTATUS status;
    QWORD base;


    IrrInit(&gVa.RrHint, (INT32)gVa.Pc);

    // Fast allocator used by the lookaside list (all the allocations made with LokAlloc will be made through the fast allocator from the beginning)
    status = HpInitFastAllocator(sizeof(VAMAP_CHUNK));
    if (!SUCCESS(status))  ERROR("HpInitFastAllocator failed, for size %d status=%s\n", sizeof(VAMAP_CHUNK), NtStatusToString(status));

    base = NAPOCA_VA_ALLOCATOR_BASE;

    // STEP 1 - init per-VA-allocator stuff
    for (DWORD i = 0; i < gVa.Pc; i++)
    {
        VA_HEADER* va;

        va = &gVa.VaAllocator[i];

        HvInitSpinLock(&va->Lock, "VA_HEADER->Lock", va);

        va->Size = sizeof(VA_HEADER);
        va->MinVa = base;
        va->MaxVa = va->MinVa + NAPOCA_PER_VA_ALLOCATOR_LENGTH - 1;
        va->PageCount = NAPOCA_PER_VA_ALLOCATOR_LENGTH / PAGE_SIZE;
        va->FreeCount = va->PageCount;

        va->TotalReserveCount = 0;
        va->TotalFreeCount = 0;
        va->TotalFreeAttempt = 0;
        va->TotalCoalesceCount = 0;

        // initialize per-VA-allocator bin-table, big-space and lookaside lists
        {
            va->FreeBinCount = VAMAP_FREE_BIN_TABLE_COUNT;
            for (DWORD k = 0; k < va->FreeBinCount; k++)
            {
                va->FreeBin[k].BinSize = gDefBinSize[k];
                va->FreeBin[k].ChunkCount = 0;
                InitializeListHead(&va->FreeBin[k].ListHead);
            }

            va->BigChunkCount = 0;
            InitializeListHead(&va->BigListHead);

            va->TreeRoot = NULL;

            AaPreinit(&va->AaTree);

            status = AaInit(&va->AaTree, &_VaMgrDummyFreeAaNode);
            if (!SUCCESS(status))
            {
                ERROR("AaInit failed, status=%s\n", NtStatusToString(status));
                goto cleanup;
            }
            LokPreinit(&va->DescPool);

            //
            // Preallocate only one item from the heap for the lookaside list, and for the rest of heap allocations of sizeof(VAMAP_CHUNK) use the fast allocator.
            // By preallocating more items (from splitting a big heap allocation to smaller chunks of size VAMAP_CHUNK), there exists a chance that the lookaside
            // list is full in the moment of freeing an item from the initial preallocated buffer, resulting in trying to free that address from the heap, and likely
            // to result in a #GP or #PF.
            //
            status = LokInit(&va->DescPool, sizeof(VAMAP_CHUNK), TAG_LOOKASIDE, 2000, 1);
            if (!SUCCESS(status))
            {
                ERROR("LokInit / DescPool failed, status=%s\n", NtStatusToString(status));
                goto cleanup;
            }

            // add the complete VA space of this VA-allocator as a single free chunk to the free-bin-table and the big-space-map
            {
                VAMAP_CHUNK* chunk = NULL;

                status = LokAlloc(&va->DescPool, &chunk);
                if (!SUCCESS(status))
                {
                    ERROR("LokAlloc / DescPool failed, status=%s\n", NtStatusToString(status));
                    goto cleanup;
                }

                chunk->BaseAddr = va->MinVa;
                chunk->Length = va->MaxVa - va->MinVa + 1;
                chunk->Tag = TAG_FREE;

                // assume this is a match for the biggest bin (>=256M), so we use FreeBinCount-1
                chunk->FreeBinIdx = va->FreeBinCount-1;
                va->FreeBin[chunk->FreeBinIdx].ChunkCount = 1;
                InsertTailList(&va->FreeBin[chunk->FreeBinIdx].ListHead, &chunk->FreeLink);

                va->BigChunkCount = 1;
                InsertTailList(&va->BigListHead, &chunk->BigLink);

                status = AaInsert(&va->AaTree, &chunk->AaNode);
                if (!SUCCESS(status))
                {
                    ERROR("AaInsert failed, status=%s\n", NtStatusToString(status));
                    goto cleanup;
                }
            }
        }

        // get base for next VA allocator
        base = base + NAPOCA_PER_VA_ALLOCATOR_LENGTH;
    }

    gVa.Initialized = TRUE;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
VaMgrUninitAllocator(
    VOID
    )
{
    NTSTATUS status;

    if (!gVa.Initialized)
    {
        return CX_STATUS_SUCCESS;
    }

    // mark Initialized as FALSE, even if we fail complete uninitialization
    gVa.Initialized = FALSE;

    // uninitialize VA-allocators
    for (DWORD i = 0; i < gVa.Pc; i++)
    {
        VA_HEADER* va;

        va = &gVa.VaAllocator[i];

        // per-VA-allocator uninit: free-bin-tables, big-space-map, lookaside lists
        {
            PLIST_ENTRY entry;
            VAMAP_CHUNK* chunk;

            // note: we MUST effectively remove items only based on big-space-map, then the free-bin-lists and
            // the lookup tree must be set to empty state explicitely (to avoid multiple free attempts)

            // effectively remove chunks from big-space-map
            while (!IsListEmpty(&va->BigListHead))
            {
                entry = RemoveTailList(&va->BigListHead);
                va->BigChunkCount--;
                chunk = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

                status = LokFree(&va->DescPool, &chunk, FALSE);
                if (!SUCCESS(status))
                {
                    ERROR("LokFree / DescPool failed, status = %s\n", NtStatusToString(status));
                    goto cleanup;
                }
            }

            // mark free bins as empty (chunks will be effectively removed by walking through the big space map)
            for (DWORD k = 0; k < va->FreeBinCount; k++)
            {
                va->FreeBin[k].ChunkCount = 0;
                InitializeListHead(&va->FreeBin[k].ListHead);
            }

            // mark lookup tree as empty
            va->TreeRoot = NULL;

            va->AaTree.Root = NULL;
            va->AaTree.NodeCount = 0;
            AaUninit(&va->AaTree);

            LokUninit(&va->DescPool);
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
VaMgrGenerateDebugTagStats(
    _In_ INT8 VaIndex,
    _Inout_ HTS_VECTOR* Hts
    )
{
    NTSTATUS status;
    VA_HEADER* va;
    INT8 index;
    PLIST_ENTRY entry;
    VAMAP_CHUNK* chunk;
    INT32 k, j;
    INT32 l, r;

    if ((VaIndex < -1) || ((VaIndex >= 0) && ((DWORD)VaIndex >= gVa.Pc)))  return CX_STATUS_INVALID_PARAMETER_1;

    if (!Hts) return CX_STATUS_INVALID_PARAMETER_2;

    // initialize HTS
    Hts->TagCount = 0;
    Hts->Flags = 0;
    Hts->HeapIndex = VaIndex;

    // select first VA for stat
    index = VaIndex;
    if (-1 == VaIndex)
    {
        va = &gVa.VaAllocator[0];
        index = 0;
    }
    else
    {
        va = &gVa.VaAllocator[index];
    }

    // get stat for currently selected VA allocator
    for (;;)
    {
        entry = va->BigListHead.Flink;
        while (entry != &va->BigListHead)
        {
            chunk = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

            // lookup TAG in statistics, using binary lookup
            l = 0;
            r = Hts->TagCount-1;
            k = -1;

            while (l <= r)
            {
                j = (l + r) / 2;
                if (Hts->Tag[j].Tag == chunk->Tag)
                {
                    k = j;
                    break;
                }
                else if (SWAPTAG(Hts->Tag[j].Tag) > SWAPTAG(chunk->Tag))
                {
                    r = j - 1;
                }
                else
                {
                    l = j + 1;
                }
            }

            // if TAG not found, allocate a new one
            if (k < 0)
            {
                if (Hts->TagCount >= MAX_HTS_ENTRY_COUNT)
                {
                    Hts->Flags |= HTS_FLAG_OVERFLOW;
                    goto go_to_next_chunk;
                }

                k = Hts->TagCount;
                Hts->TagCount++;

                Hts->Tag[k].Tag = chunk->Tag;
                Hts->Tag[k].AllocCount = 0;
                Hts->Tag[k].TotalBytes = 0;

                // ensure HTS entries are sorted by TAG
                j = k;
                while (j >= 1)
                {
                    if (SWAPTAG(Hts->Tag[j].Tag) >= SWAPTAG(Hts->Tag[j-1].Tag))
                    {
                        // stop processing, the new entry is in ordered place
                        break;
                    }

                    // exchange ('bubble downward' the new entry from j to j-1)
                    {
                        HTS_ENTRY temp;

                        temp = Hts->Tag[j];
                        Hts->Tag[j] = Hts->Tag[j-1];
                        Hts->Tag[j-1] = temp;

                        // update k
                        k = j-1;
                    }

                    // check again
                    j--;
                }
            }

            // count the current chunk into the statistics
            Hts->Tag[k].AllocCount++;
            Hts->Tag[k].TotalBytes += chunk->Length;

            // go to next chunk
go_to_next_chunk:
            entry = entry->Flink;
        }

        // go to next VA allocator (if needed), otherwise stop processing
        if ((-1 != VaIndex) || ((DWORD)(++index) >= gVa.Pc))
        {
            break;
        }

        va = &gVa.VaAllocator[index];
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

    return status;
}



#define TAG_TO_CHARS(x)     (char)(x&0xff),(char)((x>>8)&0xff),(char)((x>>16)&0xff),(char)((x>>24)&0xff)
NTSTATUS
VaMgrDumpWalkByTagInfo(
    _In_ INT8 VaIndex,
    _In_ DWORD Tag
)
{
    NTSTATUS status;
    VA_HEADER* va;
    INT8 index;
    PLIST_ENTRY entry;
    VAMAP_CHUNK* chunk;

    if ((VaIndex < -1) || ((VaIndex >= 0) && ((DWORD)VaIndex >= gVa.Pc))) return CX_STATUS_INVALID_PARAMETER_1;

    // select first heap for stat
    index = VaIndex;
    if (VaIndex == -1)
    {
        va = &gVa.VaAllocator[0];
    }
    else
    {
        va = &gVa.VaAllocator[index];
    }

    LOGN("[VA %d] walking for tag '%c%c%c%c' follows\n", VaIndex, TAG_TO_CHARS(Tag));

    // walk currently selected VA allocator
    for (;;)
    {
        entry = va->BigListHead.Flink;
        while (entry != &va->BigListHead)
        {
            chunk = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

            // does this chunk have the tag we are looking for
            if (chunk->Tag != Tag)
            {
                goto go_to_next_chunk;
            }

            // now, process this chunk
            LOGN("%p - %10lld bytes\n",
                chunk->BaseAddr, chunk->Length);

            // go to next chunk
        go_to_next_chunk:
            entry = entry->Flink;
        }

        // go to next VA allocator (if needed), otherwise stop processing
        if ((-1 != VaIndex) || ((DWORD)(++index) >= gVa.Pc))
        {
            break;
        }

        va = &gVa.VaAllocator[index];
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

    return status;
}



static NTSTATUS
_VaMgrCoalesceWithNext(
    _In_ VA_HEADER* Va,
    _In_ VAMAP_CHUNK* Chunk
    )
//
// == COALESCE-WITH-NEXT(VA, C) algorithm ==
//
//     1. check that (C.FreeBinIdx >= 0) and (C.BigLink.Next != NULL) and (C.BigLink.Next.FreeBinIdx >= 0)
//     2. set C2 = C.BigLink.Next
//     3. set C.Length = C.Length + C2.Length
//     4. remove C2 frin free-bin-list
//     5. remove C2 from big-space-map
//     6. remove C2 from lookup-tree
//     7. free chunk C2 to lookaside list
//     8. set B = C.FreeBinIdx
//     9. while (B < VA.FreeBinCount-1) and (C.Length >= VA.FreeBin[B+1].BinSize) do B = B + 1
//    10. if B > C.FreeBinIdx then
//        - remove C from current free-bin-list
//        - set C.FreeBinIdx = B
//        - add C to free-bin-list according to new C.FreeBinIdx
//
//
{
    NTSTATUS status;
    PLIST_ENTRY entry;
    VAMAP_CHUNK* chunk2;
    VAMAP_CHUNK* succ;
    INT32 binIdx;

    chunk2 = NULL;
    succ = NULL;

    if (!Va) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Chunk) return CX_STATUS_INVALID_PARAMETER_2;

    // 1. check that (C.FreeBinIdx >= 0) and (C.BigLink.Next != NULL) and (C.BigLink.Next.FreeBinIdx >= 0)
    // can't coalesce because this is NOT a free chunk
    if (Chunk->FreeBinIdx < 0) return CX_STATUS_SUCCESS;

    // we can't coalesce-WITH-NEXT as this is the last chunk from big-space-map
    if (Chunk->BigLink.Flink == &Va->BigListHead) return CX_STATUS_SUCCESS;

    // 2. set C2 = C.BigLink.Next
    entry = Chunk->BigLink.Flink;
    chunk2 = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

    // can't coalesce because the NEXT chunk is NOT a free chunk
    if (chunk2->FreeBinIdx < 0) return CX_STATUS_SUCCESS;

    // do some more consistency checks (shall always hold)
    if ((0 != (Chunk->Length % Va->FreeBin[0].BinSize)) ||
        (0 != (chunk2->Length % Va->FreeBin[0].BinSize)) ||
        (Chunk->BaseAddr + Chunk->Length != chunk2->BaseAddr) ||
        (0 == Chunk->Length) ||
        (0 == chunk2->Length))
    {
        ERROR("Inconsistency: we have two successful, invalid or zero sized chunks\n");
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }

    // update statistics
    Va->TotalCoalesceCount++;

    // 3. set C.Length = C.Length + C2.Length
    Chunk->Length = Chunk->Length + chunk2->Length;
    Chunk->Tag = TAG_FREE;

    // 4. remove C2 from free-bin-list
    RemoveEntryList(&chunk2->FreeLink);
    Va->FreeBin[chunk2->FreeBinIdx].ChunkCount--;
    chunk2->FreeBinIdx = -1;

    // determine successor
    if (chunk2->BigLink.Flink != &Va->BigListHead)
    {
        succ = CONTAINING_RECORD(chunk2->BigLink.Flink, VAMAP_CHUNK, BigLink);
    }
    else
    {
        succ = NULL;
    }

    // 5. remove C2 from big-space-map
    RemoveEntryList(&chunk2->BigLink);
    Va->BigChunkCount--;

    // 6. remove C2 from lookup-tree
    // perform remove from AA tree with optional successor hint
    status = AaRemove(&Va->AaTree, &chunk2->AaNode, &succ->AaNode);
    if (!SUCCESS(status))
    {
        LOG("ERROR: AaRemove failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }
    // IMPORTANT: we do NOT need to update Va->FreeCount because it doesn't change at a coalesce

    // 7. free chunk C2 to lookaside list
    status = LokFree(&Va->DescPool, &chunk2, FALSE);
    if (!SUCCESS(status))
    {
        LOG("ERROR: LokFree / DescPool failed, status = %s\n", NtStatusToString(status));
        goto cleanup;
    }

    // 8. set B = C.FreeBinIdx
    binIdx = (INT32)Chunk->FreeBinIdx;

    // 9. while (B < VA.FreeBinCount-1) and (C.Length >= VA.FreeBin[B+1].BinSize) do B = B + 1
    while ((binIdx < (INT32)(Va->FreeBinCount-1)) && (Chunk->Length >= Va->FreeBin[binIdx+1].BinSize))
    {
        binIdx++;
    }

    // 10. if B > C.FreeBinIdx then
    //    - remove C from current free-bin-list
    //    - set C.FreeBinIdx = B
    //    - add C to free-bin-list according to new C.FreeBinIdx
    if (binIdx > Chunk->FreeBinIdx)
    {
        Va->FreeBin[Chunk->FreeBinIdx].ChunkCount--;
        RemoveEntryList(&Chunk->FreeLink);

        Chunk->FreeBinIdx = binIdx;
        Va->FreeBin[Chunk->FreeBinIdx].ChunkCount++;
        InsertTailList(&Va->FreeBin[Chunk->FreeBinIdx].ListHead, &Chunk->FreeLink);
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

__forceinline
static
NTSTATUS
_VaMgrGetAllocatorIndex(
    _In_ VAMGR_ALLOCATOR_ID Allocator,
    _Out_ DWORD *AllocatorIndex
)
{
    INT32 index = -1;
    if (Allocator.IsDefinedByIndex)
    {
        if (Allocator.Index < 0 || Allocator.Index >= (INT32)gVa.Pc)
        {
            return CX_STATUS_NOT_FOUND;
        }
        *AllocatorIndex = Allocator.Index;
        return CX_STATUS_SUCCESS;
    }

    if (Allocator.Hint < 0 || Allocator.Hint > MEM_ALLOCATOR_HINT_MAX_VALID_HINT)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (Allocator.Hint == MEM_ALLOCATOR_HINT_DEFAULT)
    {
        Allocator.Hint = gHypervisorGlobalData.BootProgress.StageTwoDone ? MEM_ALLOCATOR_HINT_ROUNDROBIN : MEM_ALLOCATOR_HINT_MAXFREE;
    }

    if (Allocator.Hint == MEM_ALLOCATOR_HINT_ROUNDROBIN)
    {
        index = IrrGetNext(&gVa.RrHint);
    }
    else // MAXFREE
    {
        INT64 maxFree = -1;

        // determine VA-allocator with maximum free page count
        for (DWORD k = 0; k < gVa.Pc; k++)
        {
            if (gVa.VaAllocator[k].FreeCount > maxFree)
            {
                maxFree = gVa.VaAllocator[k].FreeCount;
                index = k;
            }
        }
    }

    if (index < 0)
    {
        return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    *AllocatorIndex = (DWORD)index;
    return CX_STATUS_SUCCESS;
}


NTSTATUS
VaMgrAllocPages(
    _In_ VAMGR_PAGE_COUNT       NumberOfPages,
    _Out_ VAMGR_ALIGNED_VA      *Va,
    __out_opt VAMGR_PAGE_COUNT  *ActuallyReservedPages,
    _In_ VAMGR_ALLOCATOR_ID     Allocator,
    _In_ DWORD                  Tag
)
/*
== ALLOC algorithm ==
1. decide which VA-allocator A shall be used (based on round-robin, associated, most-free, explicit according to VaHint etc)
2. acquire allocator lock (A.Lock)
3. if size-to-alloc S >= A.FreeBin[A.FreeBinCount-1].BinSize then lookup chunk C from biggest sized bin
according to first-fit algorithm (that is B = A.FreeBinCount-1)
- if found a suitable chunk C jump to 7
- else jump to 10
4. lookup smallest free-bin A.FreeBin[B] to fit size S (ex. bin with B=1 fits chunks up to 64K bytes, including)
5. if A.FreeBin[B].ChunkCount >= 1 then use this bin
- else try B = B+1, if B < A.FreeBinCount then jump to 4
- else jump to 10
6. remove the first chunk descriptor C from A.FreeBin[B]
7. if C.Length >= S + A.FreeBin[0].BinSize (ex. 16K) then split chunk into two (cut down S round up to smallest bin
size - like 16K - for allocation, remaining will become C2)
- reduce size for current chunk C (S-round-up-to-smallest-bin-size)
- alloc new chunk C2 from lookaside
- C2.Length = original-length - C.Length
- insert C2 into big-space-map (right after C)
- insert C2 into free bin list (according to C2.Length)
- insert C2 into lookup tree
8. mark C as allocated (C.FreeBinIdx = -1) and remove it from the free bin list
9. if we have a valid C then allocate and create intermediate paging structures (PML4, PDP, PD, PT entries needed)
- note: this can't be completely simulated on Win32 user-mode
- note: this corresponds to VaVivifyPagingStructuresForVaPages
10. release allocator lock (A.Lock)
11. if we have a valid C then return allocation according to it
- else, if can we try another VA-allocator (according to round-robin etc) then switch to new A and jump to 2
- else, return 'insufficient resources' (we tried all VA-allocators, all bins etc)
*/
{
    NTSTATUS status;
    VA_HEADER* allocator = NULL;
    DWORD startingAllocatorIndex = (DWORD)-1;
    VAMAP_CHUNK* chunk = NULL;
    QWORD lengthToAlloc;
    DWORD k;
    BOOLEAN lockTaken = FALSE;
    BOOLEAN done = FALSE;

    if (!Va) return CX_STATUS_INVALID_PARAMETER_2;
    if (NumberOfPages < 1) return CX_STATUS_INVALID_PARAMETER_1;

    status = _VaMgrGetAllocatorIndex(Allocator, &startingAllocatorIndex);
    if (!SUCCESS(status)) return status;


    *Va = NULL;

    // we also keep in mind the first VA allocator we selected for allocation (this is needed to be sure, that
    // if we need to circularly try also other VA allocators in case of failed allocation, to be sure we don't
    // retry the same allocator twice)

    // try with each allocator if necessary
    for (DWORD i = 0; i < gVa.Pc; i++)
    {
        DWORD allocatorIndex = (startingAllocatorIndex + i) % gVa.Pc;

        if (lockTaken)
        {
            // release the previous allocator's lock before taking another one
            HvReleaseSpinLock(&allocator->Lock);
        }

        // 2. acquire allocator lock (A.Lock)
        allocator = &gVa.VaAllocator[allocatorIndex];
        HvAcquireSpinLockNoInterrupts(&allocator->Lock);
        lockTaken = TRUE;

        // 3. if size-to-alloc S >= A.FreeBin[A.FreeBinCount-1].BinSize then lookup chunk C from biggest sized bin
        //    according to first-fit algorithm (that is B = A.FreeBinCount-1)
        //    - if found a suitable chunk C jump to 7
        //    - else jump to 9
        // 4. lookup smallest free-bin A.FreeBin[B] to fit size S (ex. bin with B=1 fits chunks up to 64K bytes, including)
        // 5. if A.FreeBin[B].ChunkCount >= 1 then use this bin
        //    - else try B = B+1, if B < A.FreeBinCount then jump to 4
        //    - else jump to 9
        // 6. remove the first chunk descriptor C from A.FreeBin[B]
        lengthToAlloc = ROUND_UP((QWORD)NumberOfPages * PAGE_SIZE, allocator->FreeBin[0].BinSize);     // round-up to smallest-bin-size
        chunk = NULL;

        // do we need to use the biggest bin?   (ex. anything over the guaranteed size of the *pior-to-last* bin?), step 3
        if (lengthToAlloc >= allocator->FreeBin[allocator->FreeBinCount - 2].BinSize)
        {
            VAMAP_FREE_BIN* bin;
            PLIST_ENTRY entry;

            bin = &allocator->FreeBin[allocator->FreeBinCount - 1];

            // here, we do need to check each chunk from the last bin and select chunk according to first fit
            entry = bin->ListHead.Blink;        // note: we start at Tail (Blink) and go in reverse order to achieve LIFO semantics
                                                // this shall be better for a 'reuse the lastly used one' usage pattern (caching)
            while (entry != &bin->ListHead)
            {
                chunk = CONTAINING_RECORD(entry, VAMAP_CHUNK, FreeLink);
                if (chunk->Length >= lengthToAlloc)
                {
                    break;
                }

                chunk = NULL;   // this is important, as we need to have chunk = NULL if we exit the while due to unsuccessful search

                                // go to next possible chunk
                entry = entry->Blink;
            }
        }
        else
        {
            k = 0;
            while ((NULL == chunk) && (k < allocator->FreeBinCount))
            {
                if ((allocator->FreeBin[k].BinSize >= lengthToAlloc) && (allocator->FreeBin[k].ChunkCount > 0))   // step 5
                {
                    if (allocator->FreeBin[k].ListHead.Blink == &allocator->FreeBin[k].ListHead)
                    {
                        LOG("ERROR: va->FreeBin[k].ListHead.Blink == &va->FreeBin[k].ListHead %p,  va %p, k %d\n", &allocator->FreeBin[k].ListHead, allocator, k);
                        status = CX_STATUS_INVALID_INTERNAL_STATE;
                        goto cleanup;
                    }

                    // here we can simply use the first chunk (we know it fit's our requirement because of the bin size), step 6
                    chunk = CONTAINING_RECORD(allocator->FreeBin[k].ListHead.Blink, VAMAP_CHUNK, FreeLink);    // use Tail (Blink) for LIFO semantics
                }
                else
                {
                    k++;    // try a bigger bin
                }
            }
        }

        if (!chunk)
        {
            continue;
        }

        // 7. if C.Length >= S + A.FreeBin[0].BinSize (ex. 16K) then split chunk into two (cut down S round up to smallest bin
        //    size - like 16K - for allocation, remaining will become C2)
        //    - reduce size for current chunk C (S-round-up-to-smallest-bin-size)
        //    - alloc new chunk C2 from lookaside
        //    - C2.Length = original-length - C.Length
        //    - insert C2 into big-space-map (right after C)
        //    - insert C2 into free bin list (according to C2.Length)
        //    - insert C2 into lookup tree
        if (chunk->Length >= lengthToAlloc + allocator->FreeBin[0].BinSize)
        {
            QWORD origLength;
            VAMAP_CHUNK* chunk2;

            // alloc new chunk
            status = LokAlloc(&allocator->DescPool, &chunk2);

            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("LokAlloc", status);
                goto cleanup;
            }

            memzero(chunk2, sizeof(VAMAP_CHUNK));

            // yup, we shall split as we have space for at least a new smallest-bin-sized free entry
            origLength = chunk->Length;
            chunk->Length = lengthToAlloc;      // already rounded-up

                                                // setup chunk2
            chunk2->BaseAddr = chunk->BaseAddr + chunk->Length;
            chunk2->Length = origLength - chunk->Length;
            chunk2->FreeBinIdx = -1;
            chunk2->Tag = TAG_FREE;

            // insert C2 into big-space-map (right after C)
            InsertHeadList(&chunk->BigLink, &chunk2->BigLink);  // tricky: by using InsertHeadList with chunk as head we insert an item right after chunk

            allocator->BigChunkCount++;

            // insert C2 into free bin list (according to C2.Length)
            k = 0;
            while (((k + 1) < allocator->FreeBinCount) && (allocator->FreeBin[k + 1].BinSize <= chunk2->Length))
            {
                k++;
            }
            InsertTailList(&allocator->FreeBin[k].ListHead, &chunk2->FreeLink);
            allocator->FreeBin[k].ChunkCount++;
            chunk2->FreeBinIdx = k;

            // insert C2 into lookup tree

            status = AaInsert(&allocator->AaTree, &chunk2->AaNode);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("AaInsert", status);
                goto cleanup;
            }
        }

        // 8. mark C as allocated (C.FreeBinIdx = -1) and remove it from the free bin list
        RemoveEntryList(&chunk->FreeLink);
        allocator->FreeBin[chunk->FreeBinIdx].ChunkCount--;
        chunk->FreeBinIdx = -1;

        // update counters and statistics
        allocator->FreeCount -= (chunk->Length / PAGE_SIZE);   // how many free pages in this VA are left (chunk->Length is always multiple of PAGE_SIZE)
        allocator->TotalReserveCount++;

        chunk->Tag = Tag;

        // 9. if we have a valid C then allocate and create intermediate paging structures (PML4, PDP, PD, PT entries needed)
        //    - note: this corresponds to VaVivifyPagingStructuresForVaPages
        //    we also need to effectively mark space as RESERVED in PT table entries
        //
        // NO, this is not the responsibility of the VA allocators....
        //


        // 10. if we have a valid C then return allocation according to it
        //    - else, if can we try another VA-allocator (according to round-robin etc) then switch to new A and jump to 2
        //    - else, return 'insufficient resources' (we tried all VA-allocators, all bins etc)
        *Va = (PVOID)chunk->BaseAddr;
        chunk->UsedLength = PAGE_SIZE * NumberOfPages;
        if (ActuallyReservedPages)
        {
            *ActuallyReservedPages = (DWORD)(chunk->Length / PAGE_SIZE);
        }

        done = TRUE;
        break;
    }

    if (!done)
    {
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    if (lockTaken)
    {
        HvReleaseSpinLock(&allocator->Lock);
    }

    return status;
}



NTSTATUS
VaMgrFreePages(
    _Inout_ VAMGR_ALIGNED_VA Address,
    _In_ DWORD Tag,
    __out_opt VAMGR_PAGE_COUNT *PageCount
)
/*
== FREE algorithm ==
1. detect which VA-allocator A this chunk used, based on address ranges
2. acquire allocator lock (A.Lock)
3. determine chunk descriptor C based on lookup tree search (binary lookup)
4. add C to free bin list B according to C.Length
- set also C.FreeBinIdx = B
5. if (C.BigLink.Prev != NULL) and (C.BigLink.Prev.FreeBinIdx >= 0) then
- set temp = C.BigLink.Prev
- call COALESCE-WITH-NEXT(A, C.BigLink.Prev)
- set C = temp
6. if (C.BigLink.Next != NULL) and (C.BigLink.Next.FreeBinIdx >= 0) then
- call COALESCE-WITH-NEXT(A, C)
7. release allocator lock (A.Lock)
*/
{
    NTSTATUS status;
    VA_HEADER* allocator = NULL;
    QWORD addr;
    DWORD pageCount;
    VAMAP_CHUNK* chunk;
    VAMAP_CHUNK* pivot;
    DWORD k;
    BOOLEAN lockTaken = FALSE;

    if (!Address) return CX_STATUS_INVALID_PARAMETER_1;

    addr = (QWORD)Address;

    // minimal consistency validations
    if (PAGE_OFFSET(addr))
    {
        LOG("unaligned addr\n");
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    // 0. handle fixed VA case
    if ((addr < gVa.MinVa) || (addr > gVa.MaxVa))
    {
        // the address is not managed
        return STATUS_NOT_A_VALID_DYNAMIC_VA;
    }

    // 1. detect which VA-allocator A this chunk used, based on address ranges
    allocator = NULL;
    for (k = 0; k < gVa.Pc; k++)
    {
        if ((addr >= gVa.VaAllocator[k].MinVa) && (addr <= gVa.VaAllocator[k].MaxVa))
        {
            allocator = &gVa.VaAllocator[k];
            break;
        }
    }

    if (NULL == allocator)
    {
        status = CX_STATUS_DATA_NOT_FOUND;
        goto cleanup;
    }

    // 2. acquire allocator lock (A.Lock)
    HvAcquireSpinLockNoInterrupts(&allocator->Lock);
    lockTaken = TRUE;

    // update statistics
    allocator->TotalFreeAttempt++;

    // 3. determine chunk descriptor C based on lookup tree search (binary lookup)
    chunk = NULL;
    pivot = allocator->TreeRoot;
    while (NULL != pivot)
    {
        if (addr == pivot->BaseAddr)
        {
            // bingo, chunk found!
            chunk = pivot;
            break;
        }
        else if (addr < pivot->BaseAddr)
        {
            pivot = pivot->Left;
        }
        else // (addr > pivot->BaseAddr)
        {
            pivot = pivot->Right;
        }
    }

    if (!chunk)
    {
        // inconsistency / invalid parameter
        LOG("ERROR: chunk for addr %p NOT found in VA tree\n", addr);

        status = CX_STATUS_DATA_NOT_FOUND;
        goto cleanup;
    }

    // update statistics
    allocator->TotalFreeCount++;

    // 3bis. check integrity of chunk, according to Tag
    if (Tag != chunk->Tag)
    {
        WARNING("Inconsistent VA space tags: reserved with %.4s release with %.4s\n", &chunk->Tag, &Tag);
    }

    // 4. add C to free bin list B according to C.Length
    //    - set also C.FreeBinIdx = B
    {
        k = 0;
        while (((k + 1) < allocator->FreeBinCount) && (allocator->FreeBin[k + 1].BinSize <= chunk->Length))
        {
            k++;
        }
        InsertTailList(&allocator->FreeBin[k].ListHead, &chunk->FreeLink);
        allocator->FreeBin[k].ChunkCount++;
        chunk->FreeBinIdx = k;
    }

    // update counters and statistics
    pageCount = (DWORD)(chunk->Length / PAGE_SIZE);
    allocator->FreeCount += pageCount;   // how many free pages in this VA are left
    if (PageCount) *PageCount = (VAMGR_PAGE_COUNT)PAGE_COUNT_4K((QWORD)Address, chunk->UsedLength);
                                                    // save chunk zone
    assert(addr == chunk->BaseAddr);

    // 5. if (C.BigLink.Prev != NULL) and (C.BigLink.Prev.FreeBinIdx >= 0) then
    //    - set temp = C.BigLink.Prev
    //    - call COALESCE-WITH-NEXT(A, C.BigLink.Prev)
    //    - set C = temp
    {
        PLIST_ENTRY entry;

        entry = chunk->BigLink.Blink;
        if (entry != &allocator->BigListHead)
        {
            pivot = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

            if (pivot->FreeBinIdx >= 0)
            {
                status = _VaMgrCoalesceWithNext(allocator, pivot);
                if (!SUCCESS(status))
                {
                    ERROR("VaCoalesceWithNext / C.Prev + C failed, status = %s\n", NtStatusToString(status));
                    goto cleanup;
                }

                // we need to update chunk to point to the new C
                chunk = pivot;
            }
        }
    }

    // 6. if (C.BigLink.Next != NULL) and (C.BigLink.Next.FreeBinIdx >= 0) then
    //    - call COALESCE-WITH-NEXT(A, C)
    {
        PLIST_ENTRY entry;

        entry = chunk->BigLink.Flink;
        if (entry != &allocator->BigListHead)
        {
            pivot = CONTAINING_RECORD(entry, VAMAP_CHUNK, BigLink);

            if (pivot->FreeBinIdx >= 0)
            {
                status = _VaMgrCoalesceWithNext(allocator, chunk);
                if (!SUCCESS(status))
                {
                    ERROR("VaCoalesceWithNext / C + C.Next failed, status = %s\n", NtStatusToString(status));
                    goto cleanup;
                }
            }
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    if (lockTaken)
    {
        // 7. release allocator lock (A.Lock)
        HvReleaseSpinLock(&allocator->Lock);
    }

    return status;
}



void
VaMgrDumpVaAllocStats(
    void
)
{
    DWORD i;

    LOG("dumping %d serialized VA allocators...\n", gVa.Pc);
    for (i = 0; i < gVa.Pc; i++)
    {
        VA_HEADER* va;

        va = &(gVa.VaAllocator[i]);

        HvPrint("%03d header %018p, 4K freecount %d, 4K pagecount %d    lock %d\n", i, va, va->FreeCount, va->PageCount, va->Lock);
        HvPrint("     minva %018p  -  maxva %018p\n", va->MinVa, va->MaxVa);
        HvPrint("     DescPool.TotalAllocCount %d   TotalHitCount %d   TotalFreeCount %d\n",
            (DWORD)va->DescPool.TotalAllocCount, (DWORD)va->DescPool.TotalHitCount, (DWORD)va->DescPool.TotalFreeCount);
        HvPrint("     BigChunkCount %d\n", (DWORD)va->BigChunkCount);
        HvPrint("     TotalReserveCount %d   TotalFreeCount %d   TotalFreeAttempt %d   TotalCoalesceCount %d\n",
            va->TotalReserveCount, va->TotalFreeCount, va->TotalFreeAttempt, va->TotalCoalesceCount);
    }
}

static
NTSTATUS
_VaMgrDummyFreeAaNode(
    _In_ AATREE* Tree,
    _Inout_ AANODE* *Node
)
{
    UNREFERENCED_PARAMETER(Tree);
    UNREFERENCED_PARAMETER(Node);

    // not needed, if we properly do the cleanup based on big space map

    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


/// @brief Default allocator id defined by index
const VAMGR_ALLOCATOR_ID gVamgrDefaultAllocator =
{
    CX_FALSE,                       // CX_BOOL IsDefinedByIndex;
    MEM_ALLOCATOR_HINT_DEFAULT      //CX_UINT32 Index;
};

/// @brief Round-robin allocator id defined by index
const VAMGR_ALLOCATOR_ID gVamgrRoundRobinAllocator =
{
    CX_FALSE,                       // CX_BOOL IsDefinedByIndex;
    MEM_ALLOCATOR_HINT_ROUNDROBIN   //CX_UINT32 Index;
};

/// @brief Max-free allocator id defined by index
const VAMGR_ALLOCATOR_ID gVamgrMaxFreeAllocator =
{
    CX_FALSE,                       // CX_BOOL IsDefinedByIndex;
    MEM_ALLOCATOR_HINT_MAXFREE      //CX_UINT32 Index;
};
/// @}