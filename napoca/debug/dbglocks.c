/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "core.h"
#include "debug/dbglocks.h"

#ifndef DBG_LOCKS_ENABLED

#pragma warning (disable: 4206) // nonstandard extension used: translation unit is empty

#else

//
// DEBUG builds
//
#include "core.h"
#include "kernel/kerneldefs.h"
#include "io/io.h"
#include "kernel/spinlock.h"
#include "kernel/time.h"

static volatile CX_UINT32 gLocksCount; // ordinal of each initialized spinlock

typedef struct _DL_TRACK_DATA
{
    char    *File;
    CX_UINT32   Line;
    CX_UINT64   Tsc;
}DL_TRACK_DATA;

// per cpu stack entries
typedef struct _DL_CPULOCK
{
    DBG_LOCK_HEADER *LockHeader;
    DL_TRACK_DATA Waiting;
    DL_TRACK_DATA Owning;
    CX_BOOL Acquired;
}DL_CPULOCK_SHADOW;
typedef volatile DL_CPULOCK_SHADOW DL_CPULOCK;

// global lock statistics
typedef struct _DL_GLOBAL_LOCK_DATA_SHADOW
{
    DBG_LOCK_HEADER *LockHeader;
    volatile CX_UINT32 InternalLock;
    CX_UINT64 TotalWaitingTsc;
    CX_UINT64 TotalOwningTsc;
    CX_UINT64 AcquiredCount;
    CX_UINT32 AcquiredCurrentCount;
    char *LastOwnerFile;
    CX_UINT32 LastOwnerLine;
    CX_UINT32 LastOwnerCpuId;
}DL_GLOBAL_LOCK_DATA_SHADOW;
typedef volatile DL_GLOBAL_LOCK_DATA_SHADOW DL_GLOBAL_LOCK_DATA;

#define DL_MAX_CPUS         8
#define DL_MAX_LOCKSTACK    128
#define DL_MAX_LOCK_INDEX   4096

static volatile int         DlEnabled = 1;
static DL_CPULOCK           DlStacks[DL_MAX_CPUS][DL_MAX_LOCKSTACK];    // locks either acquired by or blocking the current CPU
static CX_UINT32            DlIndexes[DL_MAX_CPUS];                     // current top-of-stack (depth) of each CPU
static DL_GLOBAL_LOCK_DATA  DlGlobalData[DL_MAX_LOCK_INDEX];            // global statistics of each lock
static volatile CX_UINT32   DlLogLock = 0;                              // a locally-managed lock for self-consistent logging

#ifdef DBG_LOCKS_ORDERING_ENABLED
// DlOrdering[a][b] means we've seen b being taken after a (direct arc, not a lengthy path)
static volatile CX_UINT8        DlOrdering[DL_MAX_LOCK_INDEX][DL_MAX_LOCK_INDEX]; // M[a,b] > 0: at some point a and b were acquired in this order
#endif

CX_STATUS
DlGetLockInfo(
    _In_ DBG_LOCK_HEADER *LockHeader,
    __out_opt char **LastOwnerFile,
    __out_opt CX_UINT32 *LastOwnerLine,
    __out_opt CX_UINT32 *LastOwnerCpuId,
    __out_opt CX_UINT64 *TotalWaitingTsc,
    __out_opt CX_UINT64 *TotalOwningTsc
)
{
    if (!LockHeader)
        return CX_STATUS_INVALID_PARAMETER_1;
    if (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX)
        return CX_STATUS_DATA_NOT_FOUND;
    DL_GLOBAL_LOCK_DATA_SHADOW snapshot = DlGlobalData[LockHeader->LockIndex];

    if (LastOwnerFile)      *LastOwnerFile      = snapshot.LastOwnerFile;
    if (LastOwnerLine)      *LastOwnerLine      = snapshot.LastOwnerLine;
    if (LastOwnerCpuId)     *LastOwnerCpuId     = snapshot.LastOwnerCpuId;
    if (TotalWaitingTsc)    *TotalWaitingTsc    = snapshot.TotalWaitingTsc;
    if (TotalOwningTsc)     *TotalOwningTsc     = snapshot.TotalOwningTsc;

    return CX_STATUS_SUCCESS;
}

static
__forceinline
CX_UINT32
_DlCpuIndex(void)
{
    int regs[4] = { 0 };
    __cpuid(regs, 1);
    return (((CX_UINT32)regs[1] >> 24));
}

CX_UINT32
DlGetCpuIndex(void)
{
    return _DlCpuIndex();
}

#define DL_CPU_ID _DlCpuIndex

#define DL_DISABLE_INT unsigned __int64 flags = __readeflags(); _disable();
#define DL_RESTORE_INT if (RFLAGS_IF & flags) { _enable(); }

#ifdef DL_BLOCKING
static volatile CX_UINT32  DlLock;
#define DL_LOCK {while(0 != HvInterlockedCompareExchangeU32(&DlLock, 1, 0));}
#define DL_UNLOCK {DlLock=0;}
#else
#define DL_LOCK
#define DL_UNLOCK
#endif

#define DL_LOG_ACQUIRE while(0 != HvInterlockedCompareExchangeU32(&DlLogLock, 1, 0))
#define DL_LOG_RELEASE DlLogLock = 0
#define DL_STR(X) ((X)? (X) : "N/A")

#define DL_LOG(x, ...) HvPrintNoLock(x, __VA_ARGS__)
#define DL_LOG_LOCKHEADER(LockHeader)                                                                   \
    DL_LOG("Spinlock%s <%s>[%d] %s:%d", LockHeader && (LockHeader->Flags & DL_FLAG_SHARED) ? "*" : "",  \
        LockHeader ? DL_STR(LockHeader->LockName) : "N/A",                                              \
        LockHeader ? LockHeader->LockIndex : 0,                                                         \
        LockHeader ? DL_STR(LockHeader->InitFilename) : "N/A",                                          \
        LockHeader ? LockHeader->InitLineNumber : 0)

#define DL_LOG_LOCK(MsgType, LockHeader, x, ...)    \
    DL_LOG(MsgType " "),                            \
    DL_LOG_LOCKHEADER(LockHeader),                  \
    DL_LOG(" => "),                                 \
    DL_LOG(x, __VA_ARGS__)

#define DL_WARN_LOCK(LockHeader, x, ...)  DL_LOG_LOCK("WARNING", LockHeader, x, __VA_ARGS__)
#define DL_WARN_LOCK_SYNCH(LockHeader, x, ...)  \
    DL_LOG_ACQUIRE;                             \
    DL_WARN_LOCK(LockHeader, x, __VA_ARGS__);   \
    DL_LOG_RELEASE

#define DL_ERR_LOCK(LockHeader, x, ...)  DL_LOG_LOCK("ERROR", LockHeader, x, __VA_ARGS__)
#define DL_ERR_LOCK_SYNCH(LockHeader, x, ...)   \
    DL_LOG_ACQUIRE;                             \
    DL_ERR_LOCK(LockHeader, x, __VA_ARGS__);    \
    DL_LOG_RELEASE

#define DL_MAGIC 0xD1A1CA1EE1CE5821ull

void
DlInitSpinlock(
    _In_ char *Name,
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ CX_BOOL Shared
    )
{
    CX_UINT32 lockIndex;
    CX_BOOL alreadyLinked = CX_FALSE;

    if (CX_NULL == LockHeader) return;

    // check for double init
    if ((LockHeader->Magic == DL_MAGIC) && (LockHeader->InitFilename != CX_NULL))
    {
        if ((LockHeader->InitFilename == File) && (LockHeader->InitLineNumber == Line))
        {
            if (DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount)
            {
                DL_WARN_LOCK_SYNCH(LockHeader, "already initialized (from same file&line) while being owned by %s:%d[%d]\n",
                    DL_STR(DlGlobalData[LockHeader->LockIndex].LastOwnerFile), DlGlobalData[LockHeader->LockIndex].LastOwnerLine, DlGlobalData[LockHeader->LockIndex].LastOwnerCpuId);
                DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount = 0; // try to adapt to the hard release...
            }
            else
            {
                DL_WARN_LOCK_SYNCH(LockHeader, "initializing already initialized unowned lock (from same file&line)\n");
            }
        }
        else
        {
            if (DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount)
            {
                DL_ERR_LOCK_SYNCH(LockHeader, "initializing already initialized lock (from another file/line) at %s:%d while being owned by %s:%d[%d]\n",
                    DL_STR(File), Line,
                    DL_STR(DlGlobalData[LockHeader->LockIndex].LastOwnerFile), DlGlobalData[LockHeader->LockIndex].LastOwnerLine, DlGlobalData[LockHeader->LockIndex].LastOwnerCpuId);
                DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount = 0; // try to adapt to the hard release...
            }
            else
            {
                DL_WARN_LOCK_SYNCH(LockHeader, "initializing already initialized unowned lock (from another file/line) at %s:%d\n", DL_STR(File), Line);
            }
        }
        alreadyLinked = CX_TRUE;
    }
    else
    {
        // allocate a new ID and setup the fields
        LockHeader->LockIndex = HvInterlockedIncrementU32(&gLocksCount); // index == 0 (not initialized) is NOT valid/assigned to any LockIndex!
    }

    LockHeader->LockName = Name;
    LockHeader->InitFilename = File;
    LockHeader->InitLineNumber = Line;
    LockHeader->Flags = Shared ? DL_FLAG_SHARED : 0;
    LockHeader->Magic = DL_MAGIC;

    lockIndex = LockHeader->LockIndex;
    if ((lockIndex < DL_MAX_LOCK_INDEX) && (!alreadyLinked))
    {
        // create DlGlobalData:lock mapping
        if (0 != HvInterlockedCompareExchangeU64((CX_UINT64 *)&(DlGlobalData[lockIndex].LockHeader), (CX_SIZE_T)LockHeader, 0))
        {
            DL_LOG_ACQUIRE;
            DL_WARN_LOCK_SYNCH(LockHeader, "already initialized, old data: ");
            DL_LOG_LOCKHEADER(DlGlobalData[lockIndex].LockHeader);
            DL_LOG_RELEASE;
        }
    }
}

void
DlUninitSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    )
{
    DL_DISABLE_INT;
    DL_LOCK;

    if ( (!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX) ) // trackable lock
    {
        goto cleanup;
    }
    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        DL_ERR_LOCK_SYNCH(LockHeader, "uninit for an uninitialized lock from %s:%d\n", File, Line);
        goto cleanup;
    }

    LockHeader->Magic = 0;
    DlGlobalData[LockHeader->LockIndex].AcquiredCount = 0;

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
}

CX_BOOL
DlProbeSpinlockAcquireWouldHang(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    )
//
// mark a lock as being waited by some blocked code
//
{
    CX_UINT32 cpu = DL_CPU_ID();
    CX_UINT32 tos;
    CX_UINT32 i;
    CX_BOOL result = CX_FALSE;
    DL_DISABLE_INT;
    DL_LOCK;

    if ((DlEnabled < 1)
        || ((cpu >= DL_MAX_CPUS) || (DlIndexes[cpu] >= DL_MAX_LOCKSTACK))   // valid cpu and stack space for lock
        || ((!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX))) // trackable lock
    {
        goto cleanup;
    }
    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        DL_ERR_LOCK_SYNCH(LockHeader, "probing an uninitialized lock from %s:%d\n", File, Line);
        goto cleanup;
    }

    // check the current stack for another owned instance of same lock
    tos = DlIndexes[cpu];
    for (i = 0; i < tos; i++)
    {
        if ((DlStacks[cpu][i].LockHeader) && (DlStacks[cpu][i].LockHeader->LockIndex == LockHeader->LockIndex))
        {
            // yes, would likely deadlock on wait
            result = CX_TRUE;
            goto cleanup;
        }
    }
    result = CX_FALSE;

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
    return result;
}

void
DlWaitSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ CX_BOOL TryOnly
    )
//
// mark a lock as being waited by some blocked code
//
{
    CX_UINT32 cpu = DL_CPU_ID();
    CX_UINT32 tos;
    CX_UINT32 i;
    DL_DISABLE_INT;
    DL_LOCK;

    if ((DlEnabled < 1)
        || ((cpu >= DL_MAX_CPUS) || (DlIndexes[cpu] >= DL_MAX_LOCKSTACK))   // valid cpu and stack space for lock
        || ((!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX))) // trackable lock
    {
        goto cleanup;
    }
    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        if (!(LockHeader->Flags & DL_FLAG_SILENT_NOT_INITIALIZED))
        {
            DL_WARN_LOCK_SYNCH(LockHeader, "uninitialized lock(%p) being waited on at %s:%d (index=%d, flags=%llX)\n", LockHeader, File, Line, LockHeader->LockIndex, LockHeader->Flags);
        }
        LockHeader->Flags |= DL_FLAG_SILENT_NOT_INITIALIZED;
        goto cleanup;
    }

    // check the current stack for another owned instance of same lock
    tos = DlIndexes[cpu];

    if (!(LockHeader->Flags & DL_FLAG_SILENT_REENTRANCE))
    {
        for (i = 0; i < tos; i++)
        {
            if ((DlStacks[cpu][i].LockHeader) && (DlStacks[cpu][i].LockHeader->LockIndex == LockHeader->LockIndex))
            {
                // differentiate between a mere try and a committed wait for the lock
                DL_ERR_LOCK_SYNCH(LockHeader, "%s a lock already owned by this CPU at %s:%d, last owner:%s:%d[%d]\n",
                    TryOnly ? "Trying to acquire" : "DEADLOCK! Waiting for",
                    DL_STR(File), Line,
                    DL_STR(DlGlobalData[LockHeader->LockIndex].LastOwnerFile), DlGlobalData[LockHeader->LockIndex].LastOwnerLine, DlGlobalData[LockHeader->LockIndex].LastOwnerCpuId);
            }
        }
    }

    // push lock on the current stack
    DlStacks[cpu][tos].Acquired = CX_FALSE;
    DlStacks[cpu][tos].Waiting.File = File;
    DlStacks[cpu][tos].Waiting.Line = Line;
    DlStacks[cpu][tos].Waiting.Tsc = __rdtsc();
    DlStacks[cpu][tos].LockHeader = LockHeader;

    // commit the entry
    DlIndexes[cpu]++;

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlAcquireSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    )
//
// mark lock as being owned by some blocked code
//
{
    CX_UINT32 cpu = DL_CPU_ID();
    CX_UINT32 tos;
    CX_UINT64 deltaTsc, newTsc, oldTsc;
    CX_UINT32 lockIndex;
    DL_DISABLE_INT;
    DL_LOCK;

    if ((DlEnabled < 1)
        || ((cpu >= DL_MAX_CPUS))                   // valid cpu
        || ((!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX))) // valid/trackable lock
    {
        goto cleanup;
    }

    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        if (!(LockHeader->Flags & DL_FLAG_SILENT_NOT_INITIALIZED))
        {
            DL_WARN_LOCK_SYNCH(LockHeader, "acquired but not initialized\n");
        }
        LockHeader->Flags |= DL_FLAG_SILENT_NOT_INITIALIZED;
        goto cleanup;
    }

    if (DlIndexes[cpu] == 0)
    {
        DL_WARN_LOCK_SYNCH(LockHeader, "acquired without being marked as waited!\n");
        goto cleanup;
    }

    // track the latest waited lock as owned
    tos = DlIndexes[cpu] - 1;
    if (DlStacks[cpu][tos].Acquired)
    {
        DL_WARN_LOCK_SYNCH(LockHeader, "acquired without being marked as waited!\n");
        goto cleanup;
    }
    if (DlStacks[cpu][tos].LockHeader != LockHeader)
    {
        DL_LOG_ACQUIRE;
        DL_WARN_LOCK(LockHeader, "acquired while "), DL_LOG_LOCKHEADER(DlStacks[cpu][tos].LockHeader), DL_LOG(" is waited\n");
        DL_LOG_RELEASE;
        goto cleanup;
    }

    DlStacks[cpu][tos].Owning.File = File;
    DlStacks[cpu][tos].Owning.Line = Line;
    DlStacks[cpu][tos].Owning.Tsc = __rdtsc();
    DlStacks[cpu][tos].Acquired = CX_TRUE;

    // track lock ordering info
    lockIndex = LockHeader->LockIndex;

#ifdef DBG_LOCKS_ORDERING_ENABLED
    if (tos > 0)
    {
        CX_UINT32 prevIndex;
        CX_UINT32 j;
        for (j = 0; j < tos; j++)
        {
            prevIndex = DlStacks[cpu][j].LockHeader->LockIndex;
            if ((prevIndex < DL_MAX_LOCK_INDEX) && (lockIndex < DL_MAX_LOCK_INDEX))
            {
                CX_UINT32 old, new;
                do
                {
                    old = DlOrdering[prevIndex][lockIndex];
                    new = old == 0 ? (tos - j) : (old < (tos - j) ? old : (tos - j)); // keep min except when old is 0
                    new = new > 255 ? 255 : new;
                } while (old != (CX_UINT32)HvInterlockedCompareExchangeU8(&(DlOrdering[prevIndex][lockIndex]), (CX_UINT8)new, (CX_UINT8)old));
                if (lockIndex != prevIndex && DlOrdering[lockIndex][prevIndex])
                {
                    DL_LOG_ACQUIRE;
                    DL_WARN_LOCK(LockHeader, "order inconsistency, now acquired after ");
                    DL_LOG_LOCKHEADER(DlGlobalData[prevIndex].LockHeader);
                    DL_LOG("\n");
                    DL_LOG_RELEASE;
                }
            }
        }
    }
#endif

    // track global stats - critical region
    while (0 != HvInterlockedCompareExchangeU32(&DlGlobalData[lockIndex].InternalLock, 1, 0));
    DlGlobalData[lockIndex].LastOwnerFile = File;
    DlGlobalData[lockIndex].LastOwnerLine = Line;
    DlGlobalData[lockIndex].LastOwnerCpuId = cpu;
    DlGlobalData[lockIndex].InternalLock = 0;

    // track global stats - lock-free region
    deltaTsc = DlStacks[cpu][tos].Owning.Tsc - DlStacks[cpu][tos].Waiting.Tsc;
    do
    {
        oldTsc = DlGlobalData[lockIndex].TotalWaitingTsc;
        newTsc = oldTsc + deltaTsc;
    } while (oldTsc != HvInterlockedCompareExchangeU64(&DlGlobalData[lockIndex].TotalWaitingTsc, newTsc, oldTsc));

    HvInterlockedIncrementU64(&(DlGlobalData[lockIndex].AcquiredCount));
    HvInterlockedIncrementU32(&(DlGlobalData[lockIndex].AcquiredCurrentCount));

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlReleaseSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    )
//
// remove lock from stack
//
{
    CX_UINT32 cpu = DL_CPU_ID();
    CX_UINT32 tos;
    CX_UINT32 i, j;
    CX_BOOL acquired = CX_TRUE, found = CX_FALSE;
    CX_UINT32 lockIndex;
    CX_UINT64 deltaTsc, oldTsc, newTsc, currentTsc = __rdtsc();
    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Line);

    DL_DISABLE_INT;
    DL_LOCK;

    if ((DlEnabled < 1) ||
        ((cpu >= DL_MAX_CPUS) || (DlIndexes[cpu] == 0)) ||                  // valid cpu
        ((!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX)))    // valid lock
    {
        goto cleanup;
    }

    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        if (!(LockHeader->Flags & DL_FLAG_SILENT_NOT_INITIALIZED))
        {
            DL_WARN_LOCK_SYNCH(LockHeader, "released but not initialized\n");
        }
        LockHeader->Flags |= DL_FLAG_SILENT_NOT_INITIALIZED;
        goto cleanup;
    }

    if (!DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount) acquired = CX_FALSE;

    for (i = 0; i < DlIndexes[cpu]; i++)
    {
        tos = (DlIndexes[cpu] - 1) - i;
        if (DlStacks[cpu][tos].LockHeader == LockHeader)
        {
            // global statistics for this spinlock
            lockIndex = DlStacks[cpu][tos].LockHeader->LockIndex;
            if (lockIndex < DL_MAX_LOCK_INDEX)
            {
                deltaTsc = currentTsc - DlStacks[cpu][tos].Owning.Tsc;
                do
                {
                    oldTsc = DlGlobalData[lockIndex].TotalOwningTsc;
                    newTsc = oldTsc + deltaTsc;
                } while (oldTsc != HvInterlockedCompareExchangeU64(&DlGlobalData[lockIndex].TotalOwningTsc, newTsc, oldTsc));
            }

            // release the entry
            if (0 != i)
            {
                if (!(LockHeader->Flags & DL_FLAG_SILENT_NOT_ON_TOP))
                {
                    DL_LOG_ACQUIRE;
                    DL_WARN_LOCK(LockHeader, "not on top-of-stack when released[%d vs %d] at %s:%d\n", tos, DlIndexes[cpu] - 1, DL_STR(File), Line);
                    DL_LOG_RELEASE;
                }
                // move the newest entries to the left
                for (j = tos + 1; j < DlIndexes[cpu]; j++)
                {
                    DlStacks[cpu][j - 1] = DlStacks[cpu][j];
                    if (!(LockHeader->Flags & DL_FLAG_SILENT_NOT_ON_TOP))
                    {
                        DL_LOG_ACQUIRE;
                        DL_WARN_LOCK(DlStacks[cpu][j].LockHeader, " -- found above (at +%d), owned from %s:%d\n", tos + 2 - j,
                            DlGlobalData[DlStacks[cpu][j].LockHeader->LockIndex].LastOwnerFile,
                            DlGlobalData[DlStacks[cpu][j].LockHeader->LockIndex].LastOwnerLine);
                        DL_LOG_RELEASE;
                    }
                }
            }
            // mark the entry as free and we're done
            DlIndexes[cpu]--;
            found = CX_TRUE;
            break;
        }
    }

    if (!found)
    {
        if (!acquired)
        {
            DL_WARN_LOCK_SYNCH(LockHeader, "double released at %s:%d\n", DL_STR(File), Line);
        }
        else
        {
            DL_ERR_LOCK_SYNCH(LockHeader, "released a lock owned by another CPU at %s:%d, real owner was %s:%d[%d]\n", DL_STR(File), Line,
                DL_STR(DlGlobalData[LockHeader->LockIndex].LastOwnerFile), DlGlobalData[LockHeader->LockIndex].LastOwnerLine, DlGlobalData[LockHeader->LockIndex].LastOwnerCpuId);
        }
    }

    // only report the 'free' if it was actually owned
    if (acquired) HvInterlockedDecrementU32(&(DlGlobalData[LockHeader->LockIndex].AcquiredCurrentCount));

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlCheckTimeout(
    _In_ CX_UINT64 *SpinStartTsc,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ char* File,
    _In_ CX_UINT32 Line
)
{
    CX_UINT32 cpu = DL_CPU_ID();
    CX_UINT32 tos;
    DL_DISABLE_INT;
    DL_LOCK;

    if ((DlEnabled < 1)
        || ((cpu >= DL_MAX_CPUS) || (DlIndexes[cpu] >= DL_MAX_LOCKSTACK))   // valid cpu and stack space for lock
        || ((!LockHeader) || (LockHeader->LockIndex >= DL_MAX_LOCK_INDEX))) // trackable lock
    {
        goto cleanup;
    }
    if ((LockHeader->LockIndex == 0) || (LockHeader->Magic != DL_MAGIC))
    {
        DL_WARN_LOCK_SYNCH(LockHeader, "uninitialized lock being waited on at %s:%d\n", File, Line);
        goto cleanup;
    }

    // check the current stack for another owned instance of same lock
    tos = DlIndexes[cpu] - 1;

    if (DlStacks[cpu][tos].LockHeader == LockHeader)
    {
        if (__rdtsc() > (*SpinStartTsc) + SPINLOCK_SPIN_TIMEOUT)
        {
            DL_WARN_LOCK_SYNCH(LockHeader, "Timeout while waiting for spinlock on cpu %d at %s:%d! Already locked by %d from %s:%d\n",
                cpu, File, Line, DlGlobalData[LockHeader->LockIndex].LastOwnerCpuId, DlGlobalData[LockHeader->LockIndex].LastOwnerFile, DlGlobalData[LockHeader->LockIndex].LastOwnerLine);
            *SpinStartTsc = __rdtsc();
        }
    }
    else
    {
        DL_WARN_LOCK_SYNCH(LockHeader, "Inconsistent TOS for spinlock from %s:%d\n", File, Line);
        DL_WARN_LOCK_SYNCH(DlStacks[cpu][tos].LockHeader, "Top of stack!\n", File, Line);
    }

cleanup:;
    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlPrintLockStats(
    _In_ DBG_LOCK_HEADER *LockHeader
    )
{
    DL_LOG_LOCK("INFO", LockHeader, "Logging stats");
}

void
DlReinitLockStats(
    void
    )
{
    CX_UINT32 i;
    DL_DISABLE_INT;
    DL_LOCK;

    DlEnabled = 0;
    for (i = 0; i < gLocksCount; i++)
    {
        DlGlobalData[i].AcquiredCount = 0;
    }
    DlEnabled++;

    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlResetLockStats(
    void
    )
{
    CX_UINT32 i;
    DL_DISABLE_INT;
    DL_LOCK;

    DlEnabled = 0;
    memzero((void*)DlStacks, sizeof(DlStacks));
    memzero(DlIndexes, sizeof(DlIndexes));
    for (i = 0; i < gLocksCount; i++)
    {
        DlGlobalData[i].AcquiredCount = 0;
        DlGlobalData[i].TotalOwningTsc = 0;
        DlGlobalData[i].TotalWaitingTsc = 0;
    }

#ifdef DBG_LOCKS_ORDERING_ENABLED
    memzero((void*)DlOrdering, sizeof(DlOrdering));
#endif
    DlEnabled++;

    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlDumpStack(
    _In_ CX_UINT32 CpuIndex,
    _In_ CX_BOOL LockHeader
    )
{
    CX_UINT32 i;
    DL_DISABLE_INT;
    DL_LOCK;
    if (CpuIndex >= DL_MAX_CPUS) goto cleanup;

    DlEnabled--;
    if (LockHeader) LOGN("%-4s   %-4s %-5s %-8s %-8s %36s:%-4s|%-4s %31s %36s:%-4s\n",
        "Cpu", "Id", "Type", "WaitedMs", "OwnedMs", "Owner", "Line", "Cpu", "Name", "Init", "Line");

    for (i = 0; i < DlIndexes[CpuIndex]; i++)
    {
        // skip corrupted locks
        DBG_LOCK_HEADER *lockHdr = DlStacks[CpuIndex][i].LockHeader;

        if (lockHdr->Magic != DL_MAGIC) continue;

        lockHdr->InitFilename;
        LOGN(
            "%4d %c %4d %-5s %8lld %8lld %36s:%4d|%4d %31s %36s:%4d\n",
            CpuIndex,
            (lockHdr->Flags & DL_FLAG_SHARED) ? '*' : ' ',
            lockHdr->LockIndex,
            (DlStacks[CpuIndex][i].Acquired ? "OWN" : "WAIT"),
            TSC2MS(DlStacks[CpuIndex][i].Acquired? DlStacks[CpuIndex][i].Owning.Tsc - DlStacks[CpuIndex][i].Waiting.Tsc : __rdtsc() - DlStacks[CpuIndex][i].Waiting.Tsc),
            TSC2MS(DlStacks[CpuIndex][i].Acquired? (__rdtsc() - DlStacks[CpuIndex][i].Owning.Tsc) : 0),
            DlStacks[CpuIndex][i].Waiting.File,
            DlStacks[CpuIndex][i].Waiting.Line,
            DL_STR(lockHdr->LockName),
            DL_STR(lockHdr->InitFilename),
            lockHdr->InitLineNumber
        );
    }
    DlEnabled++;

cleanup:

    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlDumpAllStacks(
    void
    )
{
    CX_UINT32 i;
    CX_BOOL first = CX_TRUE;
    DL_DISABLE_INT;
    DL_LOCK;

    for (i = 0; i < DL_MAX_CPUS; i++)
    {
        if (DlIndexes[i])
        {
            DlDumpStack(i, first);
            first = CX_FALSE;
        }
    }

    DL_UNLOCK;
    DL_RESTORE_INT;
}

void
DlDumpGlobalStats(
    void
    )
{
    CX_UINT32 i;
    CX_UINT32 trackedCnt = CX_MIN(DL_MAX_LOCK_INDEX, gLocksCount);
    DL_DISABLE_INT;
    DL_LOCK;

    DlEnabled--;
    LOGN("Total system locks: %d, tracked locks: %d\n", gLocksCount, trackedCnt);
    LOGN("  %-4s %31s %36s:%-4s %-9s %-8s %-8s %8s %-5s %36s:%-4s|%-4s\n",
            "Id", "Name", "Init", "Line", "#Acquired", "WaitedMs", "OwnedMs", "#/s", "State", "LastOwner", "Line", "Cpu");
    for (i = 0; i <= trackedCnt; i++)
    {
        if (!DlGlobalData[i].LockHeader || (!DlGlobalData[i].AcquiredCount) || (DlGlobalData[i].LockHeader->Magic != DL_MAGIC))
        {
            continue;
        }
        else
        {
            LOGN("%03d  %c %4d %31s %36s:%4d %9lld %8lld %8lld %8lld %5s %36s:%4d|%4d\n", i,
                (DlGlobalData[i].LockHeader->Flags & DL_FLAG_SHARED) ? '*' : ' ',
                i,
                DL_STR(DlGlobalData[i].LockHeader->LockName),
                DL_STR(DlGlobalData[i].LockHeader->InitFilename),
                DlGlobalData[i].LockHeader->InitLineNumber,
                DlGlobalData[i].AcquiredCount,
                TSC2MS(DlGlobalData[i].TotalWaitingTsc),
                TSC2MS(DlGlobalData[i].TotalOwningTsc),
                (DlGlobalData[i].TotalOwningTsc ?
                    ((gTscSpeed * DlGlobalData[i].AcquiredCount) / DlGlobalData[i].TotalOwningTsc) : 0
                ),
                (DlGlobalData[i].AcquiredCurrentCount ? "OWNED" : "FREE"),
                DL_STR(DlGlobalData[i].LastOwnerFile),
                DlGlobalData[i].LastOwnerLine,
                DlGlobalData[i].LastOwnerCpuId
                );
        }
    }
    DlEnabled++;

    DL_UNLOCK;
    DL_RESTORE_INT;
}

#ifdef DBG_LOCKS_ORDERING_ENABLED
void DlDumpOrderingInfo(
    void
    )
{
    CX_UINT32 i, j;
    DL_DISABLE_INT;
    DL_LOCK;

    DlEnabled--;
    for (i = 0; i < DL_MAX_LOCK_INDEX; i++)
    {
        CX_BOOL first = CX_TRUE;
        for (j = 0; j < DL_MAX_LOCK_INDEX; j++)
        {
            if (DlOrdering[i][j] != 0)
            {
                    if (first)
                    {

                    LOGN("||        %c %4d %36s:%4d\n",
                        (DlGlobalData[i].LockHeader->Flags & DL_FLAG_SHARED) ? '*' : ' ',
                        i,
                        DlGlobalData[i].LockHeader->InitFilename ? DlGlobalData[i].LockHeader->InitFilename : "N/A",
                        DlGlobalData[i].LockHeader->InitLineNumber
                        );
                    first = CX_FALSE;
                }

                // display child locks
                LOGN(" ==> [%02d] %c %4d %36s:%4d\n",
                    DlOrdering[i][j],
                    (DlGlobalData[j].LockHeader->Flags & DL_FLAG_SHARED) ? '*' : ' ',
                    j,
                    DlGlobalData[j].LockHeader->InitFilename ? DlGlobalData[j].LockHeader->InitFilename : "N/A",
                    DlGlobalData[j].LockHeader->InitLineNumber
                    );
            }
        }
    }
    DlEnabled++;

    DL_UNLOCK;
    DL_RESTORE_INT;
}
#endif

void
DlDumpAllStats(
    void
    )
{
    DlDumpAllStacks();
    DlDumpGlobalStats();
    DlDumpOrderingInfo();
}


#endif // DBG_LOCKS_ENABLED