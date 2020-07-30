/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "common/kernel/cpu_state.h"
#include "kernel/recspinlock.h"

#define     VALID_OWNER_MASK                (1ULL << 63)
#define     INVALID_OWNER_VALUE             0

#define     GetCurrentCpuOwnerId()          (HvGetInitialLocalApicIdFromCpuid() | VALID_OWNER_MASK)

__forceinline
static
void
_RecSpinlockUpdateInitialLock(
    _Inout_     RECSPINLOCK     *Spinlock
    )
{
    assert(Spinlock != NULL);

    Spinlock->OwnerId = GetCurrentCpuOwnerId();
    Spinlock->EntryCount = 1;
}

__forceinline
static
void
_RecSpinlockUpdateTakenLock(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    )
{
    assert(Spinlock != NULL);

    if (++Spinlock->EntryCount > Spinlock->MaxEntryCountHint)
    {
        HvPrintNoLock("[CRITICAL] Spinlock with max hint count %u taken already %u times. Attempt from [%s]:%u!\n",
            Spinlock->MaxEntryCountHint, Spinlock->EntryCount, File, Line);
        DlPrintLockStats(&SPINLOCK_HEADER(&Spinlock->Lock));
    }
}

/**
 * @brief Initialize a Recursive Spinlock
 *
 * @param[out]      Spinlock            Spinlock to initialize
 * @param[in]       MaxEntryCountHint   Maximum number of recursive acquires
 * @param[in]       Name                String that identifies the lock
 * @param[in]       File                File where the lock was created (debugging)
 * @param[in]       Line                Line where the lock was created (debugging)
 */
void
RecSpinlockInit2(
    _Out_       RECSPINLOCK     *Spinlock,
    _In_        DWORD           MaxEntryCountHint,
    _In_        PCHAR           Name,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    )
{
    assert(Spinlock != NULL);

    memzero(Spinlock, sizeof(RECSPINLOCK));

    HvInitSpinLock2(&Spinlock->Lock, Name, File, Line);

    Spinlock->MaxEntryCountHint = MaxEntryCountHint;
}

/**
 * @brief Acquire a Recursive Spinlock
 *
 * If the Spinlock is not readily available this routine blocks (spins) until the lock becomes available.
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       Interruptible   Specifies whether the Spinlock is interruptible
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 */
void
RecSpinlockAcquire2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        BOOLEAN         Interruptible,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    )
{
    assert(Spinlock != NULL);

    if (!RecSpinlockTryAcquire2(Spinlock, Interruptible, File, Line))
    {
        if (Interruptible)
        {
            HvAcquireSpinLock2(&Spinlock->Lock, File, Line);
        }
        else
        {
            HvAcquireSpinLockNoInterrupts2(&Spinlock->Lock, File, Line);
        }

        _RecSpinlockUpdateInitialLock(Spinlock);
    }
}

/**
 * @brief Try to Acquire a Recursive Spinlock
 *
 * If the Spinlock is not readily available this routine returns immediately
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       Interruptible   Specifies whether the wait is interruptible
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 *
 * @return TRUE                     The lock has been acquired
 * @return FALSE                    The lock could not be acquired
 */
BOOLEAN
RecSpinlockTryAcquire2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        BOOLEAN         Interruptible,
    _In_        PCHAR           File,
    _In_        DWORD           Line
)
{
    assert(Spinlock != NULL);

    if (Interruptible ? HvTryToAcquireSpinLock2(&Spinlock->Lock, File, Line) : HvTryToAcquireSpinLockNoInterrupts2(&Spinlock->Lock, File, Line))
    {
        // took the spin lock
        _RecSpinlockUpdateInitialLock(Spinlock);
    }
    else if (Spinlock->OwnerId == GetCurrentCpuOwnerId())
    {
        // we were already the owner
        _RecSpinlockUpdateTakenLock(Spinlock, File, Line);
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Release a Recursive Spinlock
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 */
void
RecSpinlockRelease2(
    _Inout_     RECSPINLOCK     *Spinlock,
    _In_        PCHAR           File,
    _In_        DWORD           Line
    )
{
    assert(Spinlock != NULL);

    if (--Spinlock->EntryCount == 0)
    {
        Spinlock->OwnerId = INVALID_OWNER_VALUE;

        HvReleaseSpinLock2(&Spinlock->Lock, File, Line);
    }
}
