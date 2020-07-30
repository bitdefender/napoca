/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once

// Recursive (Re-entrant) Spinlock

#include "spinlock.h"

typedef struct _RECSPINLOCK
{
    SPINLOCK            Lock;               ///< Internal Spinlock

    QWORD               OwnerId;            ///< Current owner to allow recursive re-acquires

    volatile DWORD      EntryCount;         ///< Current number of acquires
    DWORD               MaxEntryCountHint;  ///< Maximum number of concurrent acquires
} RECSPINLOCK, *PRECSPINLOCK;

void
RecSpinlockInit2(
    _Out_       RECSPINLOCK     *Spinlock,
    _In_        DWORD           MaxEntryCount,
    _In_        PCHAR           Name,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    );

void
RecSpinlockAcquire2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        BOOLEAN         Interruptible,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    );

BOOLEAN
RecSpinlockTryAcquire2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        BOOLEAN         Interruptible,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    );

void
RecSpinlockRelease2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    );

#define HvInitRecSpinLock(Spinlock, MaxEntryHint, Name)     RecSpinlockInit2(Spinlock, MaxEntryHint, Name, __FILE__, __LINE__)
#define HvAcquireRecSpinLock(Spinlock)                      RecSpinlockAcquire2(Spinlock, TRUE, __FILE__, __LINE__)
#define HvAcquireRecSpinLockNoInterrupts(Spinlock)          RecSpinlockAcquire2(Spinlock, FALSE, __FILE__, __LINE__)
#define HvTryToAcquireRecSpinLock(Spinlock)                 RecSpinlockTryAcquire2(Spinlock, TRUE, __FILE__, __LINE__)
#define HvTryToAcquireRecSpinLockNoInterrupts(Spinlock)     RecSpinlockTryAcquire2(Spinlock, FALSE, __FILE__, __LINE__)
#define HvReleaseRecSpinLock(Spinlock)                      RecSpinlockRelease2(Spinlock, __FILE__, __LINE__)

