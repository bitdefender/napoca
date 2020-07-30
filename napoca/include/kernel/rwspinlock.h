/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// RWSPINLOCK - Shared-Read, Exclusive-Write Spinlock

#ifndef _RWSPINLOCK_H_
#define _RWSPINLOCK_H_

#include "core.h"
#include "boot/boot.h"
#include "kernel/spinlock.h"

#ifdef DBG_LOCKS_ENABLED
#define DW_SPINLOCK_HEADER(PtrRwSpinlock)   ((PtrRwSpinlock)->DebugHeader)
#else
#define DW_SPINLOCK_HEADER(PtrRwSpinlock)
#endif


#define RW_SPINLOCK_MAX_READ_ACQUIRES   0xFFFF
#define RW_SPINLOCK_MAX_READ_WAITERS    0xFFFF
#define RW_SPINLOCK_MAX_WRITE_WAITERS   0xFFFF
#define RW_SPINLOCK_EXCLUSIVE           1           // The value of WriteAcquire word

#define MAX_WAITER_CPU_COUNT            BOOT_MAX_CPU_COUNT

typedef struct _RW_SPINLOCK
{
    union
    {
        volatile QWORD      Lock;               ///< The actual lock
        struct
        {
            volatile WORD   WriteAcquire;       ///< WA: Can be 0 or RW_SPINLOCK_EXCLUSIVE
            volatile WORD   WriteWaiters;       ///< WW: Number of exclusive waiters
            volatile WORD   ReadAcquire;        ///< RA: Number of shared readers that actually acquired the lock
            volatile WORD   ReadWaiters;        ///< RW: Number of shared waiters
        };
    };
#ifdef DBG_LOCKS_ENABLED
    DBG_LOCK_HEADER DebugHeader;
#endif
} RW_SPINLOCK;

#define HvInitRwSpinLock(RwSpinlock, LockName, Context) HvInitRwSpinLock2(RwSpinlock, LockName, __FILE__, __LINE__)
#define HvAcquireRwSpinLockExclusive(RwSpinlock)        HvAcquireRwSpinLockExclusive2(RwSpinlock, __FILE__, __LINE__)
#define HvAcquireRwSpinLockShared(RwSpinlock)           HvAcquireRwSpinLockShared2(RwSpinlock, __FILE__, __LINE__)
#define HvReleaseRwSpinLockExclusive(RwSpinlock)        HvReleaseRwSpinLockExclusive2(RwSpinlock, __FILE__, __LINE__)
#define HvReleaseRwSpinLockShared(RwSpinlock)           HvReleaseRwSpinLockShared2(RwSpinlock, __FILE__, __LINE__)

/**
 * @brief Get the state of a RwSpinlock
 *
 * @param[in]       Spinlock        Spinlock to check
 *
 * @return The state of the Spinlock
 */
__forceinline
SPINLOCK_STATE
HvGetRwSpinlockState(_In_ RW_SPINLOCK *Spinlock)
{
    if (!Spinlock)
        return SPINLOCK_STATE_INVALID;

    SPINLOCK_STATE state = 0;
    RW_SPINLOCK snapshot = *Spinlock;
    if (snapshot.ReadAcquire) state |= (SPINLOCK_STATE_ACQUIRED | SPINLOCK_STATE_ACQUIRED_SHARED);
    if (snapshot.WriteAcquire) state |= (SPINLOCK_STATE_ACQUIRED | SPINLOCK_STATE_ACQUIRED_EXCLUSIVE);

#ifdef DBG_LOCKS_ENABLED
    DWORD lastOwnerCpuId;
    NTSTATUS status = DlGetLockInfo(&snapshot.DebugHeader, NULL, NULL, &lastOwnerCpuId, NULL, NULL);
    if (!SUCCESS(status))
    {
        return state;
    }

    state |= ((DlGetCpuIndex() == lastOwnerCpuId) ? SPINLOCK_STATE_LAST_OWNER_SELF : SPINLOCK_STATE_LAST_OWNER_OTHER);
#endif

    return state;
}


void
HvInitRwSpinLock2(
    _Out_ RW_SPINLOCK *RwSpinlock,
    _In_ PCHAR Name,
    _In_ PCHAR File,
    _In_ DWORD Line
    );

void
HvUninitRwSpinLock(
    _Inout_ RW_SPINLOCK *RwSpinlock
    );

NTSTATUS
HvAcquireRwSpinLockExclusive2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    );

NTSTATUS
HvAcquireRwSpinLockShared2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    );

NTSTATUS
HvReleaseRwSpinLockExclusive2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    );

NTSTATUS
HvReleaseRwSpinLockShared2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    );

#endif
