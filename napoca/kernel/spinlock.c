/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// SPINLOCK - Implements simple Spinlock functionality

#include "napoca.h"
#include "kernel/spinlock.h"
#include <kernel\kernel.h>

extern volatile BOOLEAN gInDebugger;

/**
 * @brief Initialize a Spinlock
 *
 * @param[out]      Spinlock        Spinlock to initialize
 * @param[in]       Name            String that identifies the lock
 * @param[in]       File            File where the lock was created (debugging)
 * @param[in]       Line            Line where the lock was created (debugging)
 */
VOID
HvInitSpinLock2(
    _Out_ SPINLOCK *Spinlock,                // Spinlock to initialize
    _In_ PCHAR Name,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    assert(NULL != Spinlock);
    SPINLOCK_DATA(Spinlock).Raw = 0;
    DlInitSpinlock(Name, File, Line, &SPINLOCK_HEADER(Spinlock), FALSE);
}


/**
 * @brief Uninitialize a Spinlock
 *
 * @param[out]      Spinlock        Spinlock to uninitialize
 */
VOID
HvUninitSpinLock(
    _In_ SPINLOCK *Spinlock
    )
{
    UNREFERENCED_PARAMETER(Spinlock);

    assert(NULL != Spinlock);
    DlUninitSpinlock(__FILE__, __LINE__, &SPINLOCK_HEADER(Spinlock));
}


/**
 * @brief Acquire a Spinlock
 *
 * If the Spinlock is not readily available this routine blocks (spins) until the lock becomes available.
 *
 * @warning While this routine remains spinning only IPI interrupts are allowed and interrupts are enabled even if interrupts where disabled when this routine was called.
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 */
VOID
HvAcquireSpinLock2(
    _Inout_ SPINLOCK *Spinlock,
    _In_opt_ PCHAR File,
    _In_ DWORD Line
    )
{
    QWORD startTsc;

    startTsc = __rdtsc();

    assert(NULL != Spinlock);

    _mm_prefetch((const char*)Spinlock, _MM_HINT_T0);
    IPC_INTERRUPTIBILITY_STATE origInt;

    // first of all, try to acquire it; only if the try fails we shall start spinning
    if (!HvTryToAcquireSpinLock2(Spinlock, File, Line))
    {
        DlWaitSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock), DL_WAIT_BLOCKING);

        // block any unimportant processing while spinning
        origInt = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_ALLOW_HIGHEST_PRIORITY);

        SPINLOCK_BITS newValue = { 0 };
        newValue.Acquired = TRUE;
        SPINLOCK_BITS oldValue;

        // spin until we can acquire the lock
        do
        {
            // the effective spinning is done without interlocked op (just plain memread & pause)
            do
            {
                CpuYield();

                DlCheckTimeout(&startTsc, &DW_SPINLOCK_HEADER(Spinlock), File, Line);

                oldValue = SPINLOCK_DATA(Spinlock);
            } while (oldValue.Acquired);

        } while (oldValue.Raw != HvInterlockedCompareExchangeU32(&SPINLOCK_DATA(Spinlock).Raw, newValue.Raw, oldValue.Raw));

        DlAcquireSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock));

        // restore interrupts and irql
        IpcSetInterruptibilityState(origInt);
    }
}


/**
 * @brief Acquire a non-interruptible Spinlock
 *
 * If the Spinlock is not readily available this routine blocks (spins) until the lock becomes available.
 *
 * @warning After the Spinlock is taken only the highest priority async. messages are allowed
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 */
VOID
HvAcquireSpinLockNoInterrupts2(
    _Inout_ SPINLOCK *Spinlock,
    _In_opt_ PCHAR File,
    _In_ DWORD Line
    )
{
    QWORD startTsc;

    startTsc = __rdtsc();

    assert(NULL != Spinlock);

    _mm_prefetch((const char*)Spinlock, _MM_HINT_T0);

    // first of all, try to acquire it; only if the try fails we shall start spinning
    if (!HvTryToAcquireSpinLockNoInterrupts2(Spinlock, File, Line))
    {
        DlWaitSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock), DL_WAIT_BLOCKING);

        IPC_INTERRUPTIBILITY_STATE origInt = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

        SPINLOCK_BITS oldValue;
        SPINLOCK_BITS newValue = { 0 };
        newValue.Interruptibility = origInt;
        newValue.Acquired = TRUE;

        // spin until we can acquire lock
        do
        {
            IpcSetInterruptibilityState(origInt);
            // the effective spinning is done without interlocked op (just plain memread & pause)
            do
            {
                oldValue = SPINLOCK_DATA(Spinlock);
                CpuYield();
                DlCheckTimeout(&startTsc, &DW_SPINLOCK_HEADER(Spinlock), __FILE__, __LINE__);
            } while (oldValue.Acquired);

            IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
        } while (oldValue.Raw != HvInterlockedCompareExchangeU32(&SPINLOCK_DATA(Spinlock).Raw, newValue.Raw, oldValue.Raw));

        // NOTE: interrupts remain disabled once we got the lock (we have NoInterrupts semantics)

        DlAcquireSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock));
    }
}
