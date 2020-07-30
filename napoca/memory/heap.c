/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup heap Heap allocation support
/// @ingroup memory
/// @{
#include "napoca.h"
#include "memory/heap.h"
#include "kernel/kernel.h"
#include "memory/memmgr.h"
#include "memory/pagepool.h"
#include "apic/ipi.h"
#include "memory/falloc.h"
#include "base/ilockrr.h"
#include "debug/dumpers.h"
#include "memory/heapfa.h"

#define HEAP_PRINT

static
VOID
_HpiDumpHeap(
    _In_opt_ VOID* Heap
    );

#define HEAP_BIN_COUNT              16  ///< Number of different heap allocation chunks

/// @brief Default allocation chunk size
static DWORD HEAP_DEFAULT_BIN_LIMIT[HEAP_BIN_COUNT] = {
    32, 64, 96, 128, 192, 256, 384, 512,
    768, 1024, 1536, 2048, 3072, 4096, 8192, 16384 };

#pragma pack(push)
#pragma pack(1)
/// @brief Header of an allocation
typedef struct _HP_HEAD {               // Must be multiple of 8
    DWORD           Magic1;             ///< Magic value used to detect corruptions
    DWORD           Tag;                ///< Allocation tag
    LIST_ENTRY      Link;               ///< List of allocations of the same size; used to coalesce chunks on free
    DWORD           Size;               ///< Size of allocation useful size
    QWORD           OffsetToData;       ///< Pointer to useful data buffer
    DWORD           Magic2;             ///< Magic value used to detect corruptions
} HP_HEAD;

/// @brief Header of an aligned allocation
typedef struct _HP_HEAD_PREBUF
{
    QWORD           Offset;     ///< Offset to usable data
} HP_HEAD_PREBUF;

/// @brief List item of free chunks of a predetermined size
typedef struct _HP_HEAD_FREE {
    HP_HEAD         Head;           ///< Head of chunk
    LIST_ENTRY      FreeLink;       ///< Link to next free chunk
    DWORD           BinIndex;       ///< Index
} HP_HEAD_FREE;

/// @brief Tail of an allocation
typedef struct _HP_TAIL {               // Must be multiple of 8
    DWORD           Magic1;             ///< Magic value used to detect corruptions
    DWORD           Tag;                ///< Tag of allocation
    DWORD           Size;               ///< Size of allocation
    DWORD           Magic2;             ///< Magic value used to detect corruptions
} HP_TAIL;
#pragma pack(pop)


/// @brief Heap bin descriptor
typedef struct _HEAP_BIN {
    DWORD           Limit;              ///< a value from HEAP_DEFAULT_BIN_LIMIT
    DWORD           AllocChunkCount;    ///< Number of allocated chunks from this bin
    DWORD           FreeChunkCount;     ///< Number of free chunks from this bin
    LIST_HEAD       FreeChunks;         ///< List of free chunks
} HEAP_BIN;

/// @brief Heap header that contains details for a heap allocator
typedef struct _HEAP_HEADER {
    SPINLOCK        Lock;               ///< Synchronize access to this heap allocator
    DWORD           Size;               ///< Size in bytes of this header
    QWORD           AllocBytes;         ///< Allocated bytes from this heap; includes also the bytes used for HEAD / TAIL
    QWORD           FreeBytes;          ///< Free bytes in this heap; includes also the bytes that will be used for HEAD / TAIL (so this is a gross upper limit, can NEVER be effectively allocated)
    QWORD           MinVa;              ///< Virtual address range (minimum address) managed by this heap allocator
    QWORD           MaxVa;              ///< Virtual address range (maximum address) managed by this heap allocator
    QWORD           NextFreeVaToMap;    ///< used for heap growing
    LIST_ENTRY      AllChunks;          ///< Links all chunks from this heap into one big list (all allocated + all free)
    QWORD           BiggestFreeSize;    ///< Biggest chunk from the whole heap, effective bytes (without HEAD + TAIL)
    DWORD           BinCount;           ///< Shall always be HEAP_BIN_COUNT
    HEAP_BIN        Bin[HEAP_BIN_COUNT];///< List of Bins associated with this heap allocator
} HEAP_HEADER;

/// @brief Global data for all heap allocators
typedef struct _HEAP_GLOBAL {
    DWORD           Pc;                                 ///< Parallel number of heap allocators supported
    DWORD           Size;                               ///< Size in bytes of this header
    QWORD           TotalSize;                          ///< Total heap size in bytes
    QWORD           TotalFreeSize;                      ///< Total free heap size in bytes
    QWORD           CriticalFreeLimit;                  ///< Critical free limit in bytes that will be used to deny allocation requests from non core components
    DWORD           RunoutBehavior;                     ///< How the heap acts (the algorithm to choose a new heap when the assigned one runs out)
    HEAP_HEADER     Heap[NAPOCA_MAX_PARALLELIZATION];   ///< Number of parallel heaps initialized
    ILOCK_RR        RrHint;                             ///< ROUND ROBIN hint
    BOOLEAN         Initialized;                        ///< heap is initialized and can be used for allocations
} HEAP_GLOBAL, *PHEAP_GLOBAL;

/// @brief  Global heap
static HEAP_GLOBAL gHeap = {0};

#define     HEAP_MAGIC1     0xBDBDBDBDUL    ///< Heap magic value
#define     HEAP_MAGIC2     0xBEBEBEBEUL    ///< Heap magic value


#define TAG_TO_CHARS(x)     (char)(x&0xff),(char)((x>>8)&0xff),(char)((x>>16)&0xff),(char)((x>>24)&0xff) ///< Gives back 4 characters to be used with print functions (such as HvPrint)

#define GET_HP_HEAD_PREBUF(Address)         ((HP_HEAD_PREBUF*)PTR_DELTA(Address, sizeof(HP_HEAD_PREBUF)))   ///< Returns a pointer to the HP_HEAD_PREBUFFER preceding a chunk - for aligned allocations
#define GET_HP_HEAD(Address)                (HP_HEAD*)(PTR_DELTA(Address, (GET_HP_HEAD_PREBUF(Address)->Offset + sizeof(HP_HEAD))))             ///< Returns a pointer to the HP_HEAD preceding a chunk
#define GET_HP_TAIL(Address)                (HP_TAIL*)(PTR_ADD(Address, (GET_HP_HEAD(Address))->Size - (GET_HP_HEAD_PREBUF(Address))->Offset)) ///< Returns a pointer to the HP_TAIL of chunk
#define GET_HP_CHUNK_TOTAL_SIZE(Chunk)      (((HP_HEAD*)(Chunk))->Size + sizeof(HP_HEAD) + sizeof(HP_TAIL)) ///< Returns the total size of a chunk
#define GET_HP_ADDR(HeadPtr)                (VOID*)(PTR_ADD(HeadPtr, HeadPtr->OffsetToData))    ///< Returns useful address of a chunk

void
HpPreinit(
    void
    )
{
    memzero(&gHeap, sizeof(HEAP_GLOBAL));

    gHeap.Size = sizeof(HEAP_GLOBAL);
    gHeap.Pc = gHypervisorGlobalData.CpuData.MaxParallel;

    for (DWORD i = 0; i < gHeap.Pc; i++)
    {
        HvInitSpinLock(&gHeap.Heap[i].Lock, "gHeap.Heap[i].Lock", (VOID*)(QWORD)i);

        gHeap.Heap[i].Size = sizeof(HEAP_HEADER);
        gHeap.Heap[i].AllocBytes = 0;
        gHeap.Heap[i].FreeBytes = 0;
        gHeap.Heap[i].MaxVa = QWORD_MIN;    // this is to ensure the first free zone added to the heap will override this
        gHeap.Heap[i].NextFreeVaToMap = NAPOCA_HEAP_ALLOCATOR_BASE + NAPOCA_PER_HEAP_ALLOCATOR_LENGTH * i;  // each heap allocator has plenty of VA space to avoid overlapping
        gHeap.Heap[i].MinVa = gHeap.Heap[i].NextFreeVaToMap;

        InitializeListHead(&gHeap.Heap[i].AllChunks);
        gHeap.Heap[i].BiggestFreeSize = 0;

        gHeap.Heap[i].BinCount = HEAP_BIN_COUNT;
        for (DWORD k = 0; k < gHeap.Heap[i].BinCount; k++)
        {
            gHeap.Heap[i].Bin[k].AllocChunkCount = 0;
            gHeap.Heap[i].Bin[k].FreeChunkCount = 0;
            gHeap.Heap[i].Bin[k].Limit = HEAP_DEFAULT_BIN_LIMIT[k];

            InitializeListHead(&gHeap.Heap[i].Bin[k].FreeChunks);
        }

        HEAP_PRINT("Heap Header[%u] %llx, starting at %llx\n", i, &gHeap.Heap[i], gHeap.Heap[i].MinVa);
    }

    // init ROUND-ROBIN hints
    IrrInit(&gHeap.RrHint, (INT32)gHeap.Pc);
}


/// @brief  Maps a range of memory to virtual address space of a heap allocator
/// @param Heap             Heap for which virtual address is mapped
/// @param Length           Length in bytes
/// @param LockAlreadyHeld  TRUE if heap lock is already taken; FALSE otherwise
/// @return
static NTSTATUS
_HpAddAndMapZoneToHeap(
    _In_ HEAP_HEADER* Heap,
    _In_ DWORD Length,
    _In_ BOOLEAN LockAlreadyHeld
    )
{
    NTSTATUS status;
    QWORD addrToMapTo;
    DWORD k;

    if (!Heap) return CX_STATUS_INVALID_PARAMETER_1;
    if ((!Length) || ((Length & 0xFFF)) || (Length < CX_PAGE_SIZE_4K)) return CX_STATUS_INVALID_PARAMETER_2;

    if (!LockAlreadyHeld) HvAcquireSpinLock(&Heap->Lock);

    //
    // we MUST remap this zone into the area of this heap
    //
    {
        addrToMapTo = Heap->NextFreeVaToMap;

        // check that we can fit this piece into the HEAP's VA range
        if (Heap->NextFreeVaToMap + Length >= Heap->MinVa + NAPOCA_PER_HEAP_ALLOCATOR_LENGTH)
        {
            status = CX_STATUS_INVALID_INTERNAL_STATE;
            goto cleanup;
        }

        LOG("Allocating %d bytes at %p for heap\n", Length, addrToMapTo);
        status = MmAlloc(&gHvMm, (MM_UNALIGNED_VA)addrToMapTo, 0, NULL, Length, TAG_HEAP, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAlloc", status);
            goto cleanup;
        }

        // update NextFreeVaToMap pointer
        Heap->NextFreeVaToMap = Heap->NextFreeVaToMap + Length;

        // update per-Heap min / max VA addresses
        if (Heap->MinVa > addrToMapTo) Heap->MinVa = addrToMapTo;
        if (Heap->MaxVa < (addrToMapTo + Length - 1)) Heap->MaxVa = (addrToMapTo + Length - 1);
    }

    // update total free bytes
    Heap->FreeBytes = Heap->FreeBytes + Length;

    // lookup correct bin (almost every time this is the last bin)
    k = 0;
    while ((k < Heap->BinCount) && (Heap->Bin[k].Limit < Length))
    {
        k++;
    }

    if (k == Heap->BinCount) k--;

    // add Zone to bin K and also to the full heap list
    {
        HP_HEAD_FREE* headFree;
        HP_HEAD* head;
        HP_TAIL* tail;
        DWORD effectiveLength;

        headFree = (HP_HEAD_FREE*)addrToMapTo;
        head = (HP_HEAD*)addrToMapTo;              // headFree and head overlap
        tail = (HP_TAIL*)(((BYTE*)addrToMapTo) + Length - sizeof(HP_TAIL));

        // a free chunk must be chained twice: first to the free bin list...
        InsertTailList(&Heap->Bin[k].FreeChunks, &headFree->FreeLink);
        Heap->Bin[k].FreeChunkCount++;

        // ...secondly to the all-chunks list
        InsertTailList(&Heap->AllChunks, &head->Link);

        // adjust biggest free, if needed
        effectiveLength = Length - sizeof(HP_HEAD) - sizeof(HP_TAIL);
        if (effectiveLength > Heap->BiggestFreeSize) Heap->BiggestFreeSize = effectiveLength;

        // setup head and tail
        head->Magic1 = HEAP_MAGIC1;
        head->Magic2 = HEAP_MAGIC2;
        head->Size = effectiveLength;
        head->Tag = TAG_FREE;

        tail->Magic1 = HEAP_MAGIC1;
        tail->Magic2 = HEAP_MAGIC2;
        tail->Size = effectiveLength;
        tail->Tag = TAG_FREE;
    }

    status = CX_STATUS_SUCCESS;

cleanup:

    // release the lock only if it was not already locked by caller
    if (!LockAlreadyHeld) HvReleaseSpinLock(&Heap->Lock);

    return status;
}



NTSTATUS
HpInitHeap(
    _In_ HP_RUNOUT_BEHAVIOR Behavior
    )
{
    NTSTATUS status;
    DWORD i;
    QWORD size = 0;
    QWORD pageCount = 0;

    for (i = 0; i < gHeap.Pc; i++)
    {
        pageCount = (gHypervisorGlobalData.MemInfo.PerPpaPageCount * HP_PAGE_POOL_FOR_HEAP_AMOUNT / HP_PAGE_POOL_SUM);

        size = pageCount * PAGE_SIZE;
        status = _HpAddAndMapZoneToHeap(&(gHeap.Heap[i]), (DWORD)size, FALSE);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_HpAddAndMapZoneToHeap", status);
            return status;
        }

        LOG("HEAP[%d] VA [0x%llx ----> 0x%llx] pages: %018lld bytes: %018lld\n",
            i, gHeap.Heap[i].MinVa, gHeap.Heap[i].MaxVa, pageCount, size);

        gHeap.TotalSize += size;
    }

    gHeap.RunoutBehavior = Behavior;
    gHeap.TotalFreeSize = gHeap.TotalSize;
    gHeap.CriticalFreeLimit = ((gHeap.TotalFreeSize * 5) / 100);
    gHeap.Initialized = TRUE;

    return CX_STATUS_SUCCESS;
}


/// @brief Initializes values for head and tail of a heap allocation
/// @param Address  Allocation address
/// @param Size     Size in bytes of allocation
/// @param Tag      Tag of allocation
static
__forceinline
VOID
_HpiSetHeadAndTail(
    _In_ HP_HEAD* Address,
    _In_ DWORD Size,
    _In_ DWORD Tag
    )
{
    HP_TAIL* tail = (HP_TAIL*)((PCHAR)Address + sizeof(HP_HEAD) + Size);

    Address->Magic1     = HEAP_MAGIC1;
    Address->Tag        = Tag;
    Address->Size       = Size;
    Address->Magic2     = HEAP_MAGIC2;

    tail->Magic1        = HEAP_MAGIC1;
    tail->Tag           = Tag;
    tail->Size          = Size;
    tail->Magic2        = HEAP_MAGIC2;
}


/// @brief Inserts the chunk in the appropriate Bin entry
/// @param HeapHeader   Heap where the chunk will be inserted
/// @param ChunkHeader  Chunk header to be inserted
static
VOID
_HpiInsertFreeChunk(
    _In_ HEAP_HEADER* HeapHeader,
    _Inout_ HP_HEAD_FREE* ChunkHeader
    )
{
    for (int i = HeapHeader->BinCount - 1; i >= 0; i--)
    {
        if (ChunkHeader->Head.Size >= HeapHeader->Bin[i].Limit)      // Must have the Size set!
        {
            HEAP_PRINT("[HEAP] Insert: %llx in Bin[%d], Size=%d\n", ChunkHeader, HeapHeader->Bin[i].Limit, ChunkHeader->Head.Size);

            InsertTailList(&HeapHeader->Bin[i].FreeChunks, &ChunkHeader->FreeLink);

            HeapHeader->Bin[i].FreeChunkCount = HeapHeader->Bin[i].FreeChunkCount + 1;
            ChunkHeader->BinIndex = i;

            break;
        }
    }
}


/// @brief Split a heap chunk
///
/// Splits a chunk in two, and preserves linkage information.
/// Assumes there remains enough space for the new smaller chunk.
///
/// Returns in FreeHeader a pointer to the new free chunk header created.
///
/// @param Header       Heap for which the chunk will be split
/// @param Size         Size in bytes to split
/// @param FreeHeader   Pointer to a free chunk that was split
static
VOID
_HpiSplitChunk(
    _Inout_ HP_HEAD* Header,
    _In_ DWORD Size,
    _Inout_ HP_HEAD_FREE** FreeHeader
    )
{
    HP_HEAD_FREE* freeHdr;
    HP_TAIL* freeTail;

    //
    // Setup new chunk's header
    //
    freeHdr = (HP_HEAD_FREE*)((PCHAR)Header + sizeof(HP_HEAD) + Size + sizeof(HP_TAIL));

    freeHdr->Head.Magic1    = HEAP_MAGIC1;
    freeHdr->Head.Tag       = TAG_FREE;
    freeHdr->Head.Size      = Header->Size - sizeof(HP_HEAD) - sizeof(HP_TAIL) - Size;
    freeHdr->Head.Magic2    = HEAP_MAGIC2;

    //
    // Setup new chunk's tail
    //
    freeTail = (HP_TAIL*)((PCHAR)freeHdr + sizeof(HP_HEAD) + freeHdr->Head.Size);

    freeTail->Magic1 = HEAP_MAGIC1;
    freeTail->Magic2 = HEAP_MAGIC2;
    freeTail->Size   = freeHdr->Head.Size;
    freeTail->Tag    = TAG_FREE;

    //
    // Perform linkage
    //
    InsertHeadList(&Header->Link, &freeHdr->Head.Link);

    //
    // Return the newly created chunk
    //
    *FreeHeader = freeHdr;

    HEAP_PRINT("[HEAP][ALOC] Split: OldHeader=%llx (NewSize=%d, requested=%d), NewFreeHeader=%llx (NewSize=%d)\n",
        Header,
        Header->Size - freeHdr->Head.Size - sizeof(HP_HEAD) - sizeof(HP_TAIL),
        Size,
        freeHdr,
        freeHdr->Head.Size);
}

/// @brief Updates the size of biggest free chunk available in a heap
/// @param HeapHdr      Heap for which the update will be performed
static
VOID
_HpiUpdateBiggestFree(
    _In_ HEAP_HEADER* HeapHdr
    )
{
    HP_HEAD_FREE* chunk = NULL;         // In the end, will point to the biggest free chunk, or NULL if hash table is empty.

    // Search the next biggest free chunk (we might find the old one reduced, but it doesn't matter)
    for (int i = HeapHdr->BinCount - 1; i >= 0; i--)
    {
        if (HeapHdr->Bin[i].FreeChunkCount > 0)
        {
            // It's here, in this Bin entry. Search the biggest chunk here.
            PLIST_ENTRY chunkEntry = HeapHdr->Bin[i].FreeChunks.Flink;

            while (chunkEntry != &HeapHdr->Bin[i].FreeChunks)
            {
                HP_HEAD_FREE* newChunk = CONTAINING_RECORD(chunkEntry, HP_HEAD_FREE, FreeLink);

                if ((!chunk) || (newChunk->Head.Size > chunk->Head.Size))
                {
                    chunk = newChunk;
                }

                // Advance in list
                chunkEntry = chunkEntry->Flink;
            }

            // The biggest chunk can only be found in the biggest Bin entry that is not empty.
            break;
        }
    }

    // The hash table is empty
    if (!chunk) HeapHdr->BiggestFreeSize = 0;
    else HeapHdr->BiggestFreeSize = chunk->Head.Size;
}

/// @brief Returns the heap where the needed chunk will be allocated from.
///
/// RunoutBehavior determines which will be the heap to be returned, if the assigned one has ran out.
/// When the function returns, the HeapHeader for the heap being returned is taken!
///
/// @param MinimumSizeNeeded    Minimum size in bytes that is needed
/// @return         Pointer to a heap fitting the requested size; NULL when there's no Heap fitting the requested size
static
__forceinline
HEAP_HEADER*
_HpiGetHeapUsingBehaviour(
    _In_ DWORD MinimumSizeNeeded
    )
{
    HEAP_HEADER* heapHdr = NULL;
    DWORD j;

    // during init always use the most free heap
    if ((!gHypervisorGlobalData.BootProgress.StageTwoDone) && (gHeap.RunoutBehavior == HpNextWhenRunout))
    {
        QWORD maxFree;
        DWORD maxIndex;

        maxFree = gHeap.Heap[0].FreeBytes;
        maxIndex = 0;

        for (DWORD i = 1; i < gHeap.Pc; i++)
        {
            if (gHeap.Heap[i].FreeBytes > maxFree)
            {
                maxFree = gHeap.Heap[i].FreeBytes;
                maxIndex = i;
            }
        }

        j = maxIndex;
    }
    else
    {
        j = IrrGetNext(&gHeap.RrHint);
    }

    switch (gHeap.RunoutBehavior)
    {
    case HpNextWhenRunout:                  // This is the default
        //
        // Search the first available heap.
        //
        for (DWORD i = 0; i < gHeap.Pc; i++)      // Loop for exactly N times, where N is the parallelization count (i unused inside)
        {
            heapHdr = &gHeap.Heap[j];       // Index by j, whose first value is the heap hint index for current processor
            HvAcquireSpinLock(&heapHdr->Lock);
            if (heapHdr->BiggestFreeSize >= MinimumSizeNeeded)
            {
                break;
            }

            HvReleaseSpinLock(&heapHdr->Lock);
            heapHdr = NULL;

            j = (j + 1) % gHeap.Pc;         // Get the next heap index
        }
        break;

    case HpRestrictToAssigned:
        //
        // Always try only the first heap
        //
        heapHdr = &gHeap.Heap[j];           // Try only the heap assigned for the current processor

        HvAcquireSpinLock(&heapHdr->Lock);
        if (heapHdr->BiggestFreeSize >= MinimumSizeNeeded)
        {
            break;
        }

        HvReleaseSpinLock(&heapHdr->Lock);
        heapHdr = NULL;
        break;

    case HpDbgAlwaysSingle:
        //
        // Always try only the assigned heap
        //
        heapHdr = &gHeap.Heap[0];           // Try only index 0

        HvAcquireSpinLock(&heapHdr->Lock);
        if (heapHdr->BiggestFreeSize >= MinimumSizeNeeded)
        {
            break;
        }

        HvReleaseSpinLock(&heapHdr->Lock);
        heapHdr = NULL;
        break;

    case HpFreestWhenRunout:
        ///
        /// TODO: Try the assigned heap. If it ran out, search for the freest heap.
        ///
    case HpDbgAlwaysFreest:
        ///
        /// TODO: Always search for the freest heap (a little tricky!!)
        ///
        heapHdr = NULL;
        break;
    }

    return heapHdr;
}


#define AlignAddressLower(addr,alig)        CX_ROUND_DOWN((QWORD)addr, (QWORD)alig) ///< Aligns down an address to a given alignment
#define AlignAddressUpper(addr,alig)        CX_ROUND_UP((QWORD)addr, (QWORD)alig)   ///< Aligns up an address to a given alignment

NTSTATUS
HpAllocWithTagAndInfo(
    _Out_ VOID* *Address,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_ DWORD Tag
)
{
    NTSTATUS status = HpAllocWithTagAndInfoAligned(Address, Size, Flags, Tag, 1);
    return status;
}



NTSTATUS
HpAllocWithTagAndInfoAligned(
    _Out_ VOID* *Address,
    _In_ SIZE_T Size,
    _In_ DWORD Flags,
    _In_ DWORD Tag,
    _In_ DWORD Alignment
    )
{

    HEAP_HEADER* heapHdr = NULL;
    DWORD usefulSize = 0;
    INT32 i, fitIndex = -1;
    HP_HEAD* head = NULL;
    BOOLEAN biggerThanLastBin = FALSE;
    BOOLEAN thisWasTheBiggestFreeChunk;
    SIZE_T requiredChunkSize;
    DWORD extraSize;

    if (!Address) return CX_STATUS_INVALID_PARAMETER_1;
    if (Tag == TAG_FREE) return CX_STATUS_INVALID_PARAMETER_3;
    if (!Alignment) return CX_STATUS_INVALID_PARAMETER_4;

#ifdef DEBUG
    static DWORD dumpCriticalLimitInfo = TRUE;
#endif

    static DWORD dumpInsufficientResourcesInfo = TRUE;


    // we need the total number of performed allocations as a reference for selecting
    // specific sizes to use with fast allocators
    CxInterlockedIncrement64(&gHpFastData.Stats.TotalAllocations);

#if HP_USE_FAST_ALLOCATORS
    if ((Size < HP_MAX_FAST_ALLOCATION_SIZE) && (Alignment == 1))
    {
        NTSTATUS fastAllocStatus = HpFastAlloc(Address, (DWORD)Size);
        if (SUCCESS(fastAllocStatus)) return fastAllocStatus;
    }
#endif


    extraSize = sizeof(HP_HEAD_PREBUF) + (Alignment - 1);
    requiredChunkSize = Size + extraSize;

    if (gHeap.TotalFreeSize < requiredChunkSize)
    {
        if (HvInterlockedCompareExchangeU32(&dumpInsufficientResourcesInfo, FALSE, TRUE))
        {
            ERROR("Insufficient heap resources. Deny allocs for all components! Total %d, Free: %d, Critical limit: %d, requested: %d\n",
                gHeap.TotalSize, gHeap.TotalFreeSize, gHeap.CriticalFreeLimit, requiredChunkSize);

            LOG("Heap info:\n");
            DumpersDumpHeapsInfo();

            LOG("Heap tags stats:\n");
            DumpersDumpHeapByTags();
        }

        return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    // use this param in low resources conditions if this allocation is requested by a core component
    if ( (gHeap.TotalFreeSize < gHeap.CriticalFreeLimit) || ( (SIZE_T)(gHeap.TotalFreeSize - requiredChunkSize) < gHeap.CriticalFreeLimit) )
    {
        if ( (Flags & HEAP_FLAG_ALLOC_MUST_SUCCEED) == 0)
        {
#ifdef DEBUG
            if (HvInterlockedCompareExchangeU32(&dumpCriticalLimitInfo, FALSE, TRUE))
            {
                ERROR("Critical heap size limit reached. Deny allocs for non-core components! Total %d, Free: %d, Critical limit: %d, requested: %d\n",
                    gHeap.TotalSize, gHeap.TotalFreeSize, gHeap.CriticalFreeLimit, requiredChunkSize);

                LOG("Heap info:\n");
                DumpersDumpHeapsInfo();

                LOG("Heap tags stats:\n");
                DumpersDumpHeapByTags();
            }
#endif
            return CX_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Assure the useful returned size will be multiple of 8, and at least equal to the smallest BIN limit
    //
    usefulSize = (requiredChunkSize + 7) & ~7;
    if (usefulSize < HEAP_DEFAULT_BIN_LIMIT[0])
    {
        usefulSize = HEAP_DEFAULT_BIN_LIMIT[0];
    }

    //
    // Get the heap to allocate from, using the behavior specified at Init
    //
    heapHdr = _HpiGetHeapUsingBehaviour(usefulSize);     // N.B.: If the returned value is not NULL,
                                                        // the returned heap is already locked!
    if (NULL == heapHdr)
    {
        if (HvInterlockedCompareExchangeU32(&dumpInsufficientResourcesInfo, FALSE, TRUE))
        {
            ERROR("Insufficient heap resources. Deny allocs for all components! Total %d, Free: %d, Critical limit: %d, requested: %d\n",
                gHeap.TotalSize, gHeap.TotalFreeSize, gHeap.CriticalFreeLimit, requiredChunkSize);

            LOG("Heap info:\n");
            DumpersDumpHeapsInfo();

            LOG("Heap tags stats:\n");
            DumpersDumpHeapByTags();
        }

        return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    HEAP_PRINT("[HEAP][ALOC] NewAlloc: %d (requested %d), HeapHeader: 0x%llx, HeapMinVA: %llx\n", usefulSize, requiredChunkSize, heapHdr, heapHdr->MinVa);

    //
    // Select the Bin where the chunk will be allocated from
    //
    for (i = 0; i < (int)heapHdr->BinCount; i++)
    {
        if (heapHdr->Bin[i].Limit >= usefulSize)
        {
            if (heapHdr->Bin[i].FreeChunkCount > 0)
            {
                HEAP_PRINT("[HEAP][ALOC] BinHdr = %d (%d chunks)\n", heapHdr->Bin[i].Limit, heapHdr->Bin[i].FreeChunkCount);
                break;
            }
            else if (fitIndex == -1)
            {
                HEAP_PRINT("[HEAP][ALOC] LastFitIndex=%d\n", i);
                fitIndex = i;                   // Save the position where the chunk must have fitted
                                                // In the end, if no other bins will fit the chunk, the biggest free chunk
            }                                   // is at bin[fitIndex - 1].
        }
        else if (i == ((int)heapHdr->BinCount - 1))
        {
            // We are sure that here, in the last bin, there is a chunk that fits the requested size, because:
            //  - BiggestFreeChunk was greater than the requested size
            //  - The previous bins all have smaller chunks (the requested size is greater than last bin's value
            //  - => the biggest free chunk must be here, in the last bin
            HEAP_PRINT("[HEAP][ALOC] BinHdr = %d (%d chunks)\n", heapHdr->Bin[i].Limit, heapHdr->Bin[i].FreeChunkCount);
            biggerThanLastBin = TRUE;
            break;
        }
    }


    //
    // Select the free chunk from the selected bin (in most cases, the first-fit will be taken)
    //
    if (i == (int)heapHdr->BinCount)        // We couldn't find a Bin entry because the biggest free chunk is right below
    {                                       // the best fit entry. Need to search a suitable chunk in Bin[lastFitingIndex].
                                            // Example: Bin[i]=1024 { 1030, 1050 }, MaxFree = 1050, usefulSize = 1040.
                                            // -------  The rest of the entries (>1024) have no chunks.
        PLIST_ENTRY entry;

        HEAP_PRINT("Corner case: BiggestFreeChunk is in a Bin smaller than UsefulSize\n");

        if (fitIndex == -1)
        {
            ERROR("[HEAP] LastFitIndex is -1\n");
            HvReleaseSpinLock(&heapHdr->Lock);

            return STATUS_HEAP_LAST_FIT_INDEX_NOT_SET;
        }

        entry = heapHdr->Bin[fitIndex - 1].FreeChunks.Flink;

        HEAP_PRINT("Dumping %d chunks from Bin %d\n", heapHdr->Bin[fitIndex - 1].FreeChunkCount, fitIndex - 1);

        while (entry != &heapHdr->Bin[fitIndex - 1].FreeChunks)
        {
            HP_HEAD_FREE* freeChunk = CONTAINING_RECORD(entry, HP_HEAD_FREE, FreeLink);
            HEAP_PRINT("[HEAP][ALOC] FreeChunkSize in Bin %d: %d bytes\n", fitIndex - 1, freeChunk->Head.Size);
            if (usefulSize <= freeChunk->Head.Size)
            {
                // This chunk is ok
                head = (HP_HEAD*)freeChunk;
                HEAP_PRINT("[HEAP][ALOC] (LastFit) Header @ %llx, Size=%d\n", head, head->Size);
                RemoveEntryList(entry);
                heapHdr->Bin[fitIndex - 1].FreeChunkCount = heapHdr->Bin[fitIndex - 1].FreeChunkCount - 1;
                heapHdr->FreeBytes = heapHdr->FreeBytes - GET_HP_CHUNK_TOTAL_SIZE(head);

                break;
            }

            // Advance
            entry = entry->Flink;
        }
        if (head == NULL)
        {
            HvPrint("[HEAP] Internal Error: No free chunk found\n");
        }
    }
    else if (biggerThanLastBin)             // It is set only when choosing the last bin
    {
        //
        // We need to search in the last bin
        //
        PLIST_ENTRY entry;

        HEAP_PRINT("UsefulSize > LastBinSize, searching a fitting chunk in the last bin (%d)\n", i);

        entry = heapHdr->Bin[i].FreeChunks.Flink;

        while (entry != &heapHdr->Bin[i].FreeChunks)
        {
            HP_HEAD_FREE* freeChunk = CONTAINING_RECORD(entry, HP_HEAD_FREE, FreeLink);
            if (usefulSize <= freeChunk->Head.Size)
            {
                // This chunk is ok
                head = (HP_HEAD*)freeChunk;
                HEAP_PRINT("[HEAP][ALOC] (BigChunk) Header @ %llx, Size=%d\n", head, head->Size);
                RemoveEntryList(entry);
                heapHdr->Bin[i].FreeChunkCount = heapHdr->Bin[i].FreeChunkCount - 1;
                heapHdr->FreeBytes = heapHdr->FreeBytes - GET_HP_CHUNK_TOTAL_SIZE(head);

                break;
            }

            // Advance
            entry = entry->Flink;
        }

        if (head == NULL)
        {
            HvPrint("[HEAP] Internal Error: No free chunk found\n");
        }
    }
    else
    {
        //
        // Select from best-fit bin the first free chunk
        //
        head = (HP_HEAD*)CONTAINING_RECORD(RemoveHeadList(&heapHdr->Bin[i].FreeChunks), HP_HEAD_FREE, FreeLink);
        HEAP_PRINT("[HEAP][ALOC] Header @ %llx, Size=%d\n", head, head->Size);
        heapHdr->Bin[i].FreeChunkCount = heapHdr->Bin[i].FreeChunkCount - 1;
        heapHdr->FreeBytes = heapHdr->FreeBytes - GET_HP_CHUNK_TOTAL_SIZE(head);
    }

    if (!head)
    {
        ERROR("[HEAP] No free chunk found!!!\n");
        HvReleaseSpinLock(&heapHdr->Lock);

        return STATUS_HEAP_NO_FREE_CHUNK_FOUND;
    }

    thisWasTheBiggestFreeChunk = (head->Size == heapHdr->BiggestFreeSize);

    //
    // Split: if at least smallest-bin-limit (32 bytes def) + sizeof(HP_TAIL) + sizeof(HP_HEAD) remains after
    // allocation, then we need to create a new free chunk (otherwise, we simply convert this chunk to allocated)
    //
    if (head->Size - usefulSize >= sizeof(HP_HEAD) + sizeof(HP_TAIL) + heapHdr->Bin[0].Limit)
    {
        HP_HEAD_FREE* chunkHdr = NULL;

        // We need to split the chunk (don't know yet where will the new smaller chunk go)
        _HpiSplitChunk(head, usefulSize, &chunkHdr);

        // Place the new chunk in the appropriate Bin entry
        _HpiInsertFreeChunk(heapHdr, chunkHdr);
        heapHdr->FreeBytes = heapHdr->FreeBytes + GET_HP_CHUNK_TOTAL_SIZE(chunkHdr);

        // Finally, initialize the Head and Tail for the returned chunk
        _HpiSetHeadAndTail(head, usefulSize, Tag);
        heapHdr->AllocBytes = heapHdr->AllocBytes + GET_HP_CHUNK_TOTAL_SIZE(head);
    }
    else
    {
        // Will return the entire chunk, because there's no room left for the smallest possible chunk
        // There can remain some bytes after Tail, so the next structure does not begin right after the Tail
        heapHdr->AllocBytes = heapHdr->AllocBytes + GET_HP_CHUNK_TOTAL_SIZE(head);      // Must be before SetHeadAndTail!

        _HpiSetHeadAndTail(head, usefulSize, Tag);
    }

    // Update the biggest free chunk, if this one has been the biggest
    if (thisWasTheBiggestFreeChunk)
    {
        _HpiUpdateBiggestFree(heapHdr);
    }

    HvReleaseSpinLock(&heapHdr->Lock);

    *Address = (VOID*)((PCHAR)head + sizeof(HP_HEAD) + sizeof(HP_HEAD_PREBUF));
    *Address = (VOID*) (AlignAddressUpper(*Address, Alignment));
    HP_HEAD_PREBUF* prebuf = GET_HP_HEAD_PREBUF(*Address);

    // no conversion problem because the alignment is represented on a DWORD
    head->OffsetToData = (QWORD) PTR_DELTA(*Address, head);
    prebuf->Offset = (QWORD) PTR_DELTA(*Address, PTR_ADD(head, sizeof(HP_HEAD)));

    gHeap.TotalFreeSize -= (usefulSize + sizeof(HP_HEAD) + sizeof(HP_TAIL)); // interlocked!!!!

    return CX_STATUS_SUCCESS;
}


/// @brief Checks whether the given Head needs to be coalesced with the chunks from its left and from its right.
/// @param Heap         Heap for which coalesce is attempted
/// @param Chunk        Chunk that will be coalesced if possible
/// @param FreeChunk    Pointer where the coalesced chunk will be returned
/// @return         A pointer to the final coalesced chunk (all headers/tails will be set accordingly).
VOID
HpiCoalesceChunkIfNeeded(
    _In_ HEAP_HEADER* Heap,
    _In_ HP_HEAD* Chunk,
    _In_ HP_HEAD_FREE** FreeChunk
    )
{
    HP_HEAD_FREE* leftChunk = (HP_HEAD_FREE*)Chunk;
    HP_HEAD_FREE* rightChunk = (HP_HEAD_FREE*)Chunk;
    HP_TAIL* tailChunk = NULL;
    DWORD chunkSize = 0;
    PCHAR endOfChunk = NULL;

    HEAP_PRINT("[HEAP][Free] Freeing Chunk @ %llx (Size=%u)\n", Chunk, Chunk->Size);

    //
    // Find the end of the current chunk
    //
    if (Chunk->Link.Flink == &Heap->AllChunks)    // Check against list header
    {
        // This is the last chunk. We don't know if this chunk's tail is right at the end of the buffer
        endOfChunk = (PCHAR)Heap->MaxVa + 1;
    }
    else
    {
        // Again, because the tail might not be right at the end of the chunk,
        // we must consider the address of the next chunk as a reference.
        endOfChunk = (PCHAR)(CONTAINING_RECORD(Chunk->Link.Flink, HP_HEAD, Link));
    }

    /// TODO: In case of growing heaps, need to check if coalescing doesn't produce a chunk bigger than 4GB (Size is represented on DWORD)

    //
    // Check whether the chunk must be coalesced to the left
    //
    if (Chunk->Link.Blink != &Heap->AllChunks)              // Check against list header
    {
        if (CONTAINING_RECORD(Chunk->Link.Blink, HP_HEAD, Link)->Tag == TAG_FREE)
        {
            leftChunk = (HP_HEAD_FREE*)CONTAINING_RECORD(Chunk->Link.Blink, HP_HEAD, Link);

            HEAP_PRINT("[HEAP][Free] Coalescing with the left chunk (0x%llx <- 0x%llx)\n", leftChunk, Chunk);

            // Update linkage information in AllChunks (remove the "Chunk")
            RemoveHeadList(&leftChunk->Head.Link);

            // Remove from free chunks
            RemoveEntryList(&leftChunk->FreeLink);
            Heap->Bin[leftChunk->BinIndex].FreeChunkCount = Heap->Bin[leftChunk->BinIndex].FreeChunkCount - 1;
        }
    }

    //
    // Check whether the chunk must be coalesced to the right
    //
    if (leftChunk->Head.Link.Flink != &Heap->AllChunks)     // Check against list header
    {
        if (CONTAINING_RECORD(Chunk->Link.Flink, HP_HEAD, Link)->Tag == TAG_FREE)
        {
            rightChunk = (HP_HEAD_FREE*)CONTAINING_RECORD(Chunk->Link.Flink, HP_HEAD, Link);

            HEAP_PRINT("[HEAP][Free] Coalescing with the right chunk (0x%llx -> 0x%llx)\n", Chunk, rightChunk);

            // Update linkage information (remove the "Chunk")
            RemoveHeadList(&leftChunk->Head.Link);

            // Remove from free chunks
            RemoveEntryList(&rightChunk->FreeLink);
            Heap->Bin[rightChunk->BinIndex].FreeChunkCount = Heap->Bin[rightChunk->BinIndex].FreeChunkCount - 1;
        }
    }

    //
    // Find out where the tail should be
    //
    if (rightChunk->Head.Link.Flink == &Heap->AllChunks)    // Check against list header
    {
        // This is the last chunk. We don't know if this chunk's tail is right at the end of the buffer, we must
        // set the tail to point to MaxVa+1 - sizeof(HP_TAIL)
        tailChunk = (HP_TAIL*)((PCHAR)Heap->MaxVa + 1 - sizeof(HP_TAIL));
    }
    else
    {
        // Again, because the tail might not be right at the end of the chunk,
        // we must consider the address of the next chunk as a reference.
        tailChunk = (HP_TAIL*)((PCHAR)(CONTAINING_RECORD(leftChunk->Head.Link.Flink, HP_HEAD, Link)) - sizeof(HP_TAIL));
    }

    //
    // Now, as we know where the final Head and Tail are, compute the new chunk's size, and set other fields.
    //
    leftChunk->Head.Size = (DWORD)((PCHAR)tailChunk - (PCHAR)leftChunk - sizeof(HP_HEAD));
    leftChunk->Head.Tag = TAG_FREE;
    leftChunk->Head.Magic1 = HEAP_MAGIC1;
    leftChunk->Head.Magic2 = HEAP_MAGIC2;

    tailChunk->Magic1 = HEAP_MAGIC1;
    tailChunk->Magic2 = HEAP_MAGIC2;
    tailChunk->Tag = TAG_FREE;
    tailChunk->Size = leftChunk->Head.Size;

    //
    // Stats: the difference between endOfChunk and the given Chunk
    //        must be subtracted from AllocBytes and added to FreeBytes.
    //
    chunkSize = (DWORD)(endOfChunk - (PCHAR)Chunk);
    Heap->AllocBytes = Heap->AllocBytes - chunkSize;
    Heap->FreeBytes = Heap->FreeBytes + chunkSize;

    //
    // Return the coalesced free chunk
    //
    *FreeChunk = leftChunk;

    HEAP_PRINT("[HEAP][Free] Coalesced chunk: 0x%llx, tail %llx, next %llx\n", leftChunk, tailChunk, CONTAINING_RECORD(leftChunk->Head.Link.Flink, HP_HEAD, Link));
}


/// @brief Print heap statistics
/// @param Heap     Heap for which statistics will be generated; Lock must be previously acquired!
VOID
_HpiDumpHeap(
    _In_opt_ VOID* Heap
    )
{
    DWORD i;
    HEAP_HEADER* heap = Heap;
    DWORD totalSize = 0;

    if (!heap)
    {
        heap = &gHeap.Heap[IrrGetNext(&gHeap.RrHint)];
    }

    LOG("Dumping heap %llx - %llx, MaxFreeChunk=%d\n", heap->MinVa, heap->MaxVa, heap->BiggestFreeSize);

    for (i = 0; i < heap->BinCount; i++)
    {
        PLIST_ENTRY entry = heap->Bin[i].FreeChunks.Flink;
        DWORD count = 0;

        LOG("Bin [%5d] (%3d entries): ", heap->Bin[i].Limit, heap->Bin[i].FreeChunkCount);
        while (entry != &heap->Bin[i].FreeChunks)
        {
            HP_HEAD_FREE* chunk = CONTAINING_RECORD(entry, HP_HEAD_FREE, FreeLink);
            LOGN("%d ", chunk->Head.Size);
            entry = entry->Flink;
            count++;
            totalSize += chunk->Head.Size + sizeof(HP_HEAD) + sizeof(HP_TAIL);
        }

        LOGN("\n");

        if (count != heap->Bin[i].FreeChunkCount)
        {
            ERROR("[HEAP] FreeChunkCount (%d) different from counted free chunks (%d)!\n", heap->Bin[i].FreeChunkCount, count);
            HvHalt();
            {
                CX_STATUS_UNINITIALIZED_STATUS_VALUE;
                return; /// this function isn't expecting HvHalt to return back the control
            }
        }
    }

    if (totalSize != heap->FreeBytes)
    {
        ERROR("[HEAP] Heap.FreeBytes (%d) different from measured free chunks sizes (%d)!\n", heap->FreeBytes, totalSize);
        HvHalt();
    }

    if ((int)(heap->AllocBytes) < 0)
    {
        ERROR("[HEAP] AllocBytes is negative %d\n", heap->AllocBytes);
        HvHalt();
    }

    if ((int)(heap->FreeBytes) < 0)
    {
        ERROR("[HEAP] FreeBytes is negative %d\n", heap->FreeBytes);
        HvHalt();
    }

    if (heap->AllocBytes + heap->FreeBytes != heap->MaxVa + 1 - heap->MinVa)
    {
        ERROR("[HEAP] AllocBytes (%d) + FreeBytes (%d) != TotalBytes (%d)\n", heap->AllocBytes, heap->FreeBytes, heap->MaxVa + 1 - heap->MinVa);
        HvHalt();
    }
}


/// @brief Print statistics for all heaps
VOID
HpiDumpHeaps(
    void
    )
{
    DWORD j;
    HEAP_HEADER* heap;

    j = 0;

    for (DWORD i = 0; i < gHeap.Pc; i++)    // Loop for exactly N times, where N is the parallelization count (i unused inside)
    {
        heap = &gHeap.Heap[j];

        HvAcquireSpinLock(&heap->Lock);
        _HpiDumpHeap(heap);
        HvReleaseSpinLock(&heap->Lock);

        j = (j + 1) % gHeap.Pc;         // Get the next heap index
    }
}

/// @brief Perform basic integrity checks for an allocation
/// @param Ptr      Allocation address
/// @param Tag      Allocation tag
/// @return         TRUE if integrity checks pass; FAIL otherwise
static
__forceinline
BOOLEAN
HpiCheckChunkIntegrity(
    _In_ VOID* Ptr,
    _In_ DWORD Tag
    )
{
    register HP_HEAD* head;
    register HP_TAIL* tail;

    head = GET_HP_HEAD(Ptr);
    tail = GET_HP_TAIL(Ptr);

    if (Tag != head->Tag)
    {
        ERROR("Tag 0x%08x  !=  head->Tag 0x%08x  HEAD %p TAIL %p\n", Tag, head->Tag, head, tail);
        return TRUE;
    }

    if (head->Magic1 != HEAP_MAGIC1)
    {
        ERROR("HEAP_MAGIC1 0x%08x  !=  head->Magic1 0x%08x  HEAD %p\n", HEAP_MAGIC1, head->Magic1, head);
        return TRUE;
    }

    if (head->Magic2 != HEAP_MAGIC2)
    {
        ERROR("HEAP_MAGIC2 0x%08x  !=  head->Magic2 0x%08x  HEAD %p\n", HEAP_MAGIC2, head->Magic2, head);
        return TRUE;
    }

    if (Tag != tail->Tag)
    {
        ERROR("Tag 0x%08x  !=  tail->Tag 0x%08x  HEAD %p TAIL %p\n", Tag, tail->Tag, head, tail);
        return TRUE;
    }

    if (tail->Magic1 != HEAP_MAGIC1)
    {
        ERROR("HEAP_MAGIC1 0x%08x  !=  tail->Magic1 0x%08x  HEAD %p\n", HEAP_MAGIC1, tail->Magic1, head);
        return TRUE;
    }

    if (tail->Magic2 != HEAP_MAGIC2)
    {
        ERROR("HEAP_MAGIC2 0x%08x  !=  tail->Magic2 0x%08x  HEAD %p\n", HEAP_MAGIC2, tail->Magic2, head);
        return TRUE;
    }

    if (head->Size != tail->Size)
    {
        ERROR("head->Size %d  !=  tail->Size %d  HEAD %p\n", head->Size, tail->Size, head);
        return TRUE;
    }

    return FALSE;
}


/// @brief Dump details about a heap chunk
/// @param Address              Heap allocated address
/// @param IncludeBinaryDump    Dump memory content; not supported
__forceinline
VOID
HpiDumpChunkDetails(
    _In_ VOID* Address,
    _In_ BOOLEAN IncludeBinaryDump
    )
{
    HP_HEAD* head = GET_HP_HEAD(Address);
    HP_TAIL* tail = GET_HP_TAIL(Address);

    HvPrint("[HEAP][Head] Magic1    %X\n", head->Magic1);
    HvPrint("[HEAP][Head] Tag       %c%c%c%c (0x%X)\n", TAG_TO_CHARS(head->Tag), head->Tag);
    HvPrint("[HEAP][Head] Flink     0x%llx\n", head->Link.Flink);
    HvPrint("[HEAP][Head] Blink     0x%llx\n", head->Link.Blink);
    HvPrint("[HEAP][Head] Size      %d\n", head->Size);
    HvPrint("[HEAP][Head] Magic2    %X\n", head->Magic2);

    HvPrint("[HEAP][Tail] Magic1    %X\n", tail->Magic1);
    HvPrint("[HEAP][Tail] Tag       %c%c%c%c (0x%X)\n", TAG_TO_CHARS(tail->Tag), tail->Tag);
    HvPrint("[HEAP][Tail] Size      %d\n", tail->Size);
    HvPrint("[HEAP][Tail] Magic2    %X\n", tail->Magic2);

    if (IncludeBinaryDump)
    {
        /// TODO Memory dump
    }
}



NTSTATUS
HpFreeWithTagAndInfo(
    _Out_ VOID** Address,
    _In_ DWORD Tag
    )
{
    HEAP_HEADER* heapHdr;
    int i;
    HP_HEAD* chunkHdr;
    HP_HEAD_FREE* freeChunk = NULL;
    DWORD chunkSize = 0;

    // Some parameter validation
    if ((!Address) || (!*Address)) return CX_STATUS_INVALID_PARAMETER_1;

#if HP_USE_FAST_ALLOCATORS
    NTSTATUS status = HpFastFree(Address);
    if (SUCCESS(status)) return status;
#endif

    chunkHdr = GET_HP_HEAD(*Address);

    //
    // Save chunk size for later use
    //
    chunkSize = chunkHdr->Size;

    //
    // Detect correct Heap based on VA
    //
    for (i = 0; i < (int)gHeap.Pc; i++)
    {
        if  (((QWORD)*Address < gHeap.Heap[i].MaxVa) && ((QWORD)*Address >= gHeap.Heap[i].MinVa))
        {
            HEAP_PRINT("[HEAP][Free] Free from heap %d: %llx - %llx\n", i, gHeap.Heap[i].MinVa, gHeap.Heap[i].MaxVa);
            break;
        }
    }

    if (i == (int)gHeap.Pc) return CX_STATUS_INVALID_PARAMETER_1;

    heapHdr = &gHeap.Heap[i];

    HvAcquireSpinLock(&gHeap.Heap[i].Lock);


    //
    // Check for possible heap corruption
    //
    if (HpiCheckChunkIntegrity(*Address, Tag))
    {
        HEAP_PRINT("[HEAP][FREE] CORRUPTION: @ 0x%llx, FreeTag=%c%c%c%c\n", (SIZE_T)(*Address) - sizeof(HP_HEAD), TAG_TO_CHARS(Tag));
        HpiDumpChunkDetails(*Address, FALSE);

#ifndef HEAP_PRINT
        HvPrint("[HEAP][FREE] CORRUPTION: @ 0x%llx, FreeTag=%c%c%c%c\n", (SIZE_T)(*Address) - sizeof(HP_HEAD), TAG_TO_CHARS(Tag));
#else
        CLN_UNLOAD(CX_STATUS_INVALID_INTERNAL_STATE);
#endif
    }

    //
    // Check and perform any coalesce needed (both prev and next), returns the coalesced chunk in freeChunk
    //
    HpiCoalesceChunkIfNeeded(&gHeap.Heap[i], chunkHdr, &freeChunk);

    //
    // Add the new free chunk to the Bin hash table
    //
    _HpiInsertFreeChunk(&gHeap.Heap[i], freeChunk);

    //
    // Update if needed the biggest-free-chunk-size case
    //
    if (freeChunk->Head.Size > gHeap.Heap[i].BiggestFreeSize) gHeap.Heap[i].BiggestFreeSize = freeChunk->Head.Size;           // There can be no other.

    HvReleaseSpinLock(&gHeap.Heap[i].Lock);

    *Address = NULL;

    gHeap.TotalFreeSize += (chunkSize + sizeof(HP_HEAD) + sizeof(HP_TAIL));

    return CX_STATUS_SUCCESS;
}

NTSTATUS
HpReallocWithTagAndInfo(
    _Inout_ VOID* *Address,
    _In_ DWORD NewSize,
    _In_ DWORD Tag
    )
{
    NTSTATUS status = HpReallocWithTagAndInfoAligned(Address, NewSize, Tag, 1);
    return status;
}



NTSTATUS
HpReallocWithTagAndInfoAligned(
    _Inout_ VOID* *Address,
    _In_ DWORD NewSize,
    _In_ DWORD Tag,
    _In_ DWORD Alignment
    )
{
    NTSTATUS status;
    BYTE* oldBuffer = (*Address);
    VOID* newBuffer = NULL;
    HP_HEAD* oldHeader = GET_HP_HEAD(oldBuffer);

    // allocate a new chunk with needed size
    status = HpAllocWithTagAndInfoAligned(&newBuffer, NewSize, 0, Tag, Alignment);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagAndInfoAligned", status);
        goto cleanup;
    }

    // copy content
    memzero(newBuffer, NewSize);
    memcpy(newBuffer, oldBuffer, (oldHeader->Size < NewSize)?oldHeader->Size:NewSize);

    // free old chunk
    status = HpFreeWithTagAndInfo(&oldBuffer, oldHeader->Tag);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpFreeWithTagAndInfo", status);
        goto cleanup;
    }

    *Address = newBuffer;

cleanup:
    return status;
}


void
HpDumpHeapAllocStats(
    void
    )
{
    HvPrint("Dumping %d serialized HEAP allocators...\n", gHeap.Pc);
    for (DWORD i = 0; i < gHeap.Pc; i++)
    {
        HEAP_HEADER* heap;

        heap = &(gHeap.Heap[i]);

        HvPrint("%03d heap %018p, A/F: %zd/%zd (%d%%), biggest free %zd\n",
            i, heap, heap->AllocBytes, heap->FreeBytes, heap->FreeBytes * 100 / (heap->FreeBytes + heap->AllocBytes),heap->BiggestFreeSize);
        HvPrint("   minva %018p  -  maxva %018p\n", heap->MinVa, heap->MaxVa);
    }
}



NTSTATUS
HpGenerateHeapTagStats(
    _In_ INT8 HeapIndex,
    _Inout_ HTS_VECTOR* Hts
    )
{
    NTSTATUS status;
    HEAP_HEADER* heap;
    INT8 index;
    PLIST_ENTRY entry;
    HP_HEAD* head;
    INT32 k, j;
    INT32 l, r;

    if ((HeapIndex < -1) || ((HeapIndex >= 0) && ((DWORD)HeapIndex >= gHeap.Pc))) return CX_STATUS_INVALID_PARAMETER_1;

    if (!Hts) return CX_STATUS_INVALID_PARAMETER_2;

    // initialize HTS
    Hts->TagCount = 0;
    Hts->Flags = 0;
    Hts->HeapIndex = HeapIndex;

    // select first heap for stat
    index = HeapIndex;
    if (HeapIndex == -1)
    {
        heap = &gHeap.Heap[0];
        index = 0;
    }
    else
    {
        heap = &gHeap.Heap[index];
    }

    // get stat for currently selected heap
    for (;;)
    {
        entry = heap->AllChunks.Flink;
        while (entry != &heap->AllChunks)
        {
            head = CONTAINING_RECORD(entry, HP_HEAD, Link);

            // lookup TAG in statistics, using binary lookup
            l = 0;
            r = Hts->TagCount-1;
            k = -1;

            while (l <= r)
            {
                j = (l + r) / 2;
                if (Hts->Tag[j].Tag == head->Tag)
                {
                    k = j;
                    break;
                }
                else if (SWAPTAG(Hts->Tag[j].Tag) > SWAPTAG(head->Tag))
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

                Hts->Tag[k].Tag = head->Tag;
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
            Hts->Tag[k].TotalBytes += head->Size;

            // go to next chunk
go_to_next_chunk:
            entry = entry->Flink;
        }

        // go to next heap (if needed), otherwise stop processing
        if ((-1 != HeapIndex) || ((DWORD)(++index) >= gHeap.Pc))
        {
            break;
        }

        heap = &gHeap.Heap[index];
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

    return status;
}



NTSTATUS
HpWalkHeapByTag(
    _In_ INT8 HeapIndex,
    _In_ DWORD Tag
    )
{
    NTSTATUS status;
    HEAP_HEADER* heap;
    INT8 index;
    PLIST_ENTRY entry;
    HP_HEAD* head;

    if ((HeapIndex < -1) || ((HeapIndex >= 0) && ((DWORD)HeapIndex > gHeap.Pc))) return CX_STATUS_INVALID_PARAMETER_1;

    // select first heap for stat
    index = HeapIndex;
    if (HeapIndex == -1)
    {
        heap = &gHeap.Heap[0];
    }
    else
    {
        heap = &gHeap.Heap[index];
    }

    LOGN("[HEAP %d] walking for tag '%c%c%c%c' follows\n", HeapIndex, TAG_TO_CHARS(Tag));

    // walk currently selected heap
    for (;;)
    {
        entry = heap->AllChunks.Flink;
        while (entry != &heap->AllChunks)
        {
            head = CONTAINING_RECORD(entry, HP_HEAD, Link);

            // does this chunk have the tag we are looking for
            if (head->Tag != Tag)
            {
                goto go_to_next_chunk;
            }

            // now, process this chunk
            LOGN("%p - %7d bytes, alloc\n",
                GET_HP_ADDR(head), head->Size);

            // go to next chunk
go_to_next_chunk:
            entry = entry->Flink;
        }

        // go to next heap (if needed), otherwise stop processing
        if ((-1 != HeapIndex) || ((DWORD)(++index) >= gHeap.Pc))
        {
            break;
        }

        heap = &gHeap.Heap[index];
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

    return status;
}



NTSTATUS
HpQuerySize(
    _Out_ SIZE_T *TotalSize,
    _Out_ SIZE_T *FreeSize
    )
{
    if (!TotalSize) return CX_STATUS_INVALID_PARAMETER_1;
    if (!FreeSize) return CX_STATUS_INVALID_PARAMETER_2;

    *TotalSize = gHeap.TotalSize;
    *FreeSize  = gHeap.TotalFreeSize;

    return CX_STATUS_SUCCESS;
}

BOOLEAN
HpInitialized(
    void
    )
{
    return gHeap.Initialized;
}

NTSTATUS
HpGetAllocationSize(
    _In_ VOID* Address,
    _Out_ DWORD* Size
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    HP_HEAD* addrHeader = NULL;
    DWORD i;

    if (!Address) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Size) return CX_STATUS_INVALID_PARAMETER_2;


    //
    // Detect correct Heap based on VA
    //
    for (i = 0; i < (int)gHeap.Pc; i++)
    {
        if  (((QWORD)((SIZE_T)Address) < gHeap.Heap[i].MaxVa) && ((QWORD)((SIZE_T)Address) >= gHeap.Heap[i].MinVa)) break;
    }

    if (i == (int)gHeap.Pc) return CX_STATUS_INVALID_PARAMETER_1;

    HvAcquireSpinLock(&gHeap.Heap[i].Lock);

    addrHeader = GET_HP_HEAD(Address);

    if (addrHeader == NULL)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }

    if (addrHeader->Magic1 != HEAP_MAGIC1)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }

    if (addrHeader->Magic2 != HEAP_MAGIC2)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }

    *Size = addrHeader->Size;

cleanup:
    HvReleaseSpinLock(&gHeap.Heap[i].Lock);
    return status;
}

BOOLEAN
HpIsValidHeapAddress(
    _In_ VOID* Address
    )
{
    for (DWORD i = 0; i < gHeap.Pc; i++)
    {
        if (((QWORD)((SIZE_T)Address) < gHeap.Heap[i].MaxVa) && ((QWORD)((SIZE_T)Address) >= gHeap.Heap[i].MinVa)) return TRUE;
    }

    return FALSE;
}
/// @}
