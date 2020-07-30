/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// RWSPINLOCK - Shared-Read, Exclusive-Write Spinlock

#include "napoca.h"
#include "kernel/rwspinlock.h"
#include "kernel/kernel.h"

/**
 * @brief Initialize a RwSpinlock
 *
 * @param[out]      RwSpinlock      Spinlock to initialize
 * @param[in]       Name            String that identifies the lock
 * @param[in]       File            File where the lock was created (debugging)
 * @param[in]       Line            Line where the lock was created (debugging)
 */
void
HvInitRwSpinLock2(
    _Out_ RW_SPINLOCK *RwSpinlock,
    _In_ PCHAR Name,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    assert(NULL != RwSpinlock);
    RwSpinlock->Lock = 0;
    DlInitSpinlock(Name, File, Line, &DW_SPINLOCK_HEADER(RwSpinlock), TRUE);
}


/**
 * @brief Uninitialize a RwSpinlock
 *
 * @param[in,out]   RwSpinlock      Spinlock to uninitialize
 */
void
HvUninitRwSpinLock(
    _Inout_ RW_SPINLOCK *RwSpinlock
    )
{
    UNREFERENCED_PARAMETER(RwSpinlock);

    assert(NULL != RwSpinlock);
}


/**
 * @brief Acquire a RwSpinlock Exclusively (usually to write the guarded data)
 *
 * If the Spinlock is not readily available this routine blocks (spins) until the lock becomes available.
 *
 * @warning While this routine remains spinning only IPI interrupts are allowed and interrupts are enabled even if interrupts where disabled when this routine was called.
 *
 * @param[in,out]   RwSpinlock      Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 *
 * @return CX_STATUS_SUCCESS
 * @return STATUS_TOO_MANY_WAITERS  There are more than 64K exclusive-waiters on the lock (unlikely)
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
HvAcquireRwSpinLockExclusive2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File, Line));

    RW_SPINLOCK oldLock = {0};
    RW_SPINLOCK newLock = {0};
    WORD oldWaiters, newWaiters;
    QWORD startTsc;
    BOOLEAN tprChanged;
    BYTE oldTpr;
    BOOLEAN oldInterrupts;

    _mm_prefetch((const char*)RwSpinlock, _MM_HINT_T0);

    startTsc = __rdtsc();

    tprChanged = FALSE;
    oldTpr = 0;
    oldInterrupts = FALSE;

    if (NULL == RwSpinlock) return CX_STATUS_INVALID_PARAMETER_1;

    // Atomically increment number of Write Waiters, with the condition not to exceed the maximum allowed (WW++)
    for (;;)
    {
        oldWaiters = RwSpinlock->WriteWaiters;
        newWaiters = oldWaiters + 1;

        if ((newWaiters == RW_SPINLOCK_MAX_WRITE_WAITERS) || (newWaiters < oldWaiters))     // checks also for overflow condition
        {
            return STATUS_TOO_MANY_WAITERS;
        }
        else
        {
            if (HvInterlockedCompareExchangeU16(&RwSpinlock->WriteWaiters,
                                              newWaiters,
                                              oldWaiters) == oldWaiters)
            {
                break;
            }
        }

        CpuYield();
    }

    // Set exclusive lock, when there are no Readers or other Write Acquires (RA=0, WA=0)
    DlWaitSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock), DL_WAIT_BLOCKING);
    for (;;)
    {
        oldLock.Lock = RwSpinlock->Lock;

        if ((oldLock.WriteAcquire == 0) && (oldLock.ReadAcquire == 0))
        {
            newLock.Lock = oldLock.Lock;
            newLock.WriteWaiters = oldLock.WriteWaiters - 1;
            newLock.WriteAcquire = RW_SPINLOCK_EXCLUSIVE;                   // WA = 1

            if (HvInterlockedCompareExchangeU64(&RwSpinlock->Lock,
                                              newLock.Lock,
                                              oldLock.Lock) == oldLock.Lock)
            {
                DlAcquireSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock));

                return CX_STATUS_SUCCESS;
            }
        }

        CpuYield();

        DlCheckTimeout(&startTsc, &DW_SPINLOCK_HEADER(RwSpinlock), __FILE__, __LINE__);
    }
}


/**
 * @brief Acquire a RwSpinlock Shared (usually to read the guarded data)
 *
 * If the Spinlock is not readily available this routine blocks (spins) until the lock becomes available.
 *
 * @warning While this routine remains spinning only IPI interrupts are allowed and interrupts are enabled even if interrupts where disabled when this routine was called.
 *
 * @param[in,out]   RwSpinlock      Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 *
 * @return CX_STATUS_SUCCESS
 * @return STATUS_TOO_MANY_WAITERS  There are more than 64K exclusive-waiters on the lock (unlikely)
 * @return STATUS_TOO_MANY_ACQUIRES There are more than 64K shared-acquires on the lock (unlikely)
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
HvAcquireRwSpinLockShared2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File, Line));

    RW_SPINLOCK oldLock = {0};
    RW_SPINLOCK newLock = {0};
    WORD readWaiters, newWaiters;
    QWORD startTsc;
    BOOLEAN tprChanged;
    BYTE oldTpr;
    BOOLEAN oldInterrupts;

    _mm_prefetch((const char*)RwSpinlock, _MM_HINT_T0);

    startTsc = __rdtsc();

    tprChanged = FALSE;
    oldTpr = 0;
    oldInterrupts = FALSE;

    if (NULL == RwSpinlock) return CX_STATUS_INVALID_PARAMETER_1;

    // Atomically increment number of Read Waiters, with the condition not to exceed the maximum allowed (RW++)
    for (;;)
    {
        readWaiters = RwSpinlock->ReadWaiters;
        newWaiters = readWaiters + 1;

        if ((newWaiters == RW_SPINLOCK_MAX_READ_WAITERS) || (newWaiters < readWaiters))     // checks also for overflow condition
        {
            return STATUS_TOO_MANY_WAITERS;
        }
        else
        {
            if (HvInterlockedCompareExchangeU16(&RwSpinlock->ReadWaiters,
                                              newWaiters,
                                              readWaiters) == readWaiters)
            {
                break;
            }
        }
        CpuYield();
    }

    // Increment the number of Readers, when there are no Writers or Write Waiters (WA=0, WW=0)
    DlWaitSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock), DL_WAIT_BLOCKING);
    for (;;)
    {
        oldLock.Lock = RwSpinlock->Lock;

        if ((oldLock.WriteAcquire == 0) && (oldLock.WriteWaiters == 0))
        {
            newLock.Lock = oldLock.Lock;
            newLock.ReadWaiters = oldLock.ReadWaiters - 1;
            newLock.ReadAcquire = newLock.ReadAcquire + 1;
            if (newLock.ReadAcquire == RW_SPINLOCK_MAX_READ_ACQUIRES)
            {
                HvPrintNoLock("ERROR! TOO MANY ACQUIRES\n");
                DlAcquireSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock)); // finalize the lock stack entry
                DlReleaseSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock)); // and free it asap
                return STATUS_TOO_MANY_ACQUIRES;
            }

            if (HvInterlockedCompareExchangeU64(&RwSpinlock->Lock,
                                              newLock.Lock,
                                              oldLock.Lock) == oldLock.Lock)
            {
                DlAcquireSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock));

                return CX_STATUS_SUCCESS;
            }
        }

        CpuYield();

        DlCheckTimeout(&startTsc, &DW_SPINLOCK_HEADER(RwSpinlock), __FILE__, __LINE__);
    }
}


/**
 * @brief Release a RwSpinlock previously acquired Exclusively
 *
 * @param[in,out]   RwSpinlock      Spinlock to release
 * @param[in]       File            File where the lock was released (debugging)
 * @param[in]       Line            Line where the lock was released (debugging)
 *
 * @return CX_STATUS_SUCCESS
 * @return STATUS_NOT_ACQUIRED      The given lock was NOT exclusively owned (no proper release could be performed)
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
HvReleaseRwSpinLockExclusive2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File, Line));

    if (NULL == RwSpinlock) return CX_STATUS_INVALID_PARAMETER_1;

    _mm_prefetch((const char*)RwSpinlock, _MM_HINT_T0);

    if (RW_SPINLOCK_EXCLUSIVE != RwSpinlock->WriteAcquire)
    {
        return STATUS_NOT_ACQUIRED;
    }

    DlReleaseSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock));
    if (RW_SPINLOCK_EXCLUSIVE == HvInterlockedCompareExchangeU16(&RwSpinlock->WriteAcquire,       // WA = 0
                                                               0,
                                                               RW_SPINLOCK_EXCLUSIVE))
    {
        return CX_STATUS_SUCCESS;
    }
    else return STATUS_NOT_ACQUIRED;
}


/**
 * @brief Release a RwSpinlock previously acquired Shared
 *
 * @param[in,out]   RwSpinlock      Spinlock to release
 * @param[in]       File            File where the lock was released (debugging)
 * @param[in]       Line            Line where the lock was released (debugging)
 *
 * @return CX_STATUS_SUCCESS
 * @return STATUS_NOT_ACQUIRED      The given lock was NOT owned shared (no proper release could be performed)
 * @return STATUS_TOO_MANY_RELEASES The release was performed too many times (more than the number of shared acquires)

 * @return OTHER                    Other potential internal error
 */
NTSTATUS
HvReleaseRwSpinLockShared2(
    _Inout_ RW_SPINLOCK *RwSpinlock,
    _In_opt_ PCHAR File,
    _In_opt_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File, Line));

    WORD oldAcquires;
    WORD newAcquires;

    DlReleaseSpinlock(File, Line, &DW_SPINLOCK_HEADER(RwSpinlock));

    if (NULL == RwSpinlock) return CX_STATUS_INVALID_PARAMETER_1;

    _mm_prefetch((const char*)RwSpinlock, _MM_HINT_T0);

    if ((0 == RwSpinlock->ReadAcquire) || (0 != RwSpinlock->WriteAcquire))
    {
        return STATUS_NOT_ACQUIRED;
    }

    // Atomically decrement number of Read Acquires, with the condition not to decrease below 0 (RA--)
    for (;;)
    {
        oldAcquires = RwSpinlock->ReadAcquire;
        newAcquires = oldAcquires - 1;

        if ((oldAcquires == 0) || (newAcquires > oldAcquires))  // include also underflow case
        {
            return STATUS_TOO_MANY_RELEASES;
        }
        else
        {
            if (HvInterlockedCompareExchangeU16(&RwSpinlock->ReadAcquire,
                                              newAcquires,
                                              oldAcquires) == oldAcquires)
            {
                return CX_STATUS_SUCCESS;
            }
        }

        CpuYield();
    }
}
