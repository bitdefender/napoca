/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// SPINLOCK - Implements simple Spinlock functionality

#ifndef _SPINLOCK_H_
#define _SPINLOCK_H_

#include "core.h"
#include "kernel/queue_ipc_common.h"
#include "kernel/hvintrin.h"
#include "debug/dbglocks.h"

typedef union SPINLOCK_BITS
{
    IPC_INTERRUPTIBILITY_STATE Interruptibility;    ///< Saves the interruptibility state when aquiring
    struct
    {
        DWORD Reserved : 31;
        DWORD Acquired : 1;                         ///< Spinlock acquired
    };
    DWORD Raw;
}SPINLOCK_BITS;

#ifdef DEBUG
#include "debug/debugger.h"
#endif

#ifdef DBG_LOCKS_ENABLED
//
// Debug build with CFG_DEBUG_TRACE_SPINLOCKS set: use a detailed data structure for each Spinlock
//

// track originator data for each Spinlock (associated with the code that called the InitSpinLock function)

typedef struct _SPINLOCK
{
    volatile SPINLOCK_BITS Lock;
    DBG_LOCK_HEADER DebugHeader;
}SPINLOCK;

// define a macro for accessing the actual lock data for hiding implementation details
#define SPINLOCK_DATA(PtrSpinlock)      ((PtrSpinlock)->Lock)
#define SPINLOCK_HEADER(PtrSpinlock)    ((PtrSpinlock)->DebugHeader)

#else

// clean/naked Spinlock data type
typedef volatile SPINLOCK_BITS SPINLOCK, *PSPINLOCK;

// Spinlock data accessor macro (for hiding implementation details)
#define SPINLOCK_DATA(PtrSpinlock)      (*(PtrSpinlock))
#define SPINLOCK_HEADER(PtrSpinlock)

#endif // DBG_LOCKS_ENABLED

// wrappers to automatically set the debugging parameters
#define HvInitSpinLock(Spinlock, Name, Context) HvInitSpinLock2(Spinlock, Name, __FILE__, __LINE__)
#define HvAcquireSpinLock(Spinlock)             HvAcquireSpinLock2(Spinlock, __FILE__, __LINE__)
#define HvAcquireSpinLockNoInterrupts(Spinlock) HvAcquireSpinLockNoInterrupts2(Spinlock, __FILE__, __LINE__)
#define HvTryToAcquireSpinLock(Spinlock)        HvTryToAcquireSpinLock2(Spinlock, __FILE__, __LINE__)
#define HvTryToAcquireSpinLockNoInterrupts(Spinlock) HvTryToAcquireSpinLockNoInterrupts2(Spinlock, __FILE__, __LINE__)
#define HvReleaseSpinLock(Spinlock)             HvReleaseSpinLock2(Spinlock, __FILE__, __LINE__)
// special 'unlock' for allowing a CPU to forcefully gain access to a lock during cleanup or unload (the old owner might be long gone at this point)
#define HvUnloadReleaseSpinlock(Spinlock)       SPINLOCK_DATA(Spinlock).Raw = 0
#define HvProbeSpinlockAcquireWouldHang(Spinlock) DlProbeSpinlockAcquireWouldHang(__FILE__, __LINE__, &SPINLOCK_HEADER(Spinlock))

typedef enum
{
    SPINLOCK_STATE_NEVER_USED           = BIT(0),       ///< Unused. (informative only, might not be available without the Spinlock debugger)
    SPINLOCK_STATE_ACQUIRED             = BIT(1),       ///< Acquired
    SPINLOCK_STATE_ACQUIRED_EXCLUSIVE   = BIT(2),       ///< Acquired exclusively, only defined for RW locks, reserved otherwise
    SPINLOCK_STATE_ACQUIRED_SHARED      = BIT(3),       ///< Acquired shared, only defined for RW locks, reserved otherwise
    SPINLOCK_STATE_LAST_OWNER_SELF      = BIT(4),       ///< Released, previously owned. (Informative only, might not be available without the Spinlock debugger)
    SPINLOCK_STATE_LAST_OWNER_OTHER     = BIT(5),       ///< Released, previously owned by someone else. (Informative only, might not be available without the Spinlock debugger)

    SPINLOCK_STATE_INVALID              = BIT(31),
}SPINLOCK_STATE;

DWORD
DlGetCpuIndex(
    void
);


/**
 * @brief Get the state of a Spinlock
 *
 * @param[in]       Spinlock        Spinlock to check
 *
 * @return The state of the Spinlock
 */
__forceinline
SPINLOCK_STATE
HvGetSpinlockState(
    _In_ SPINLOCK *Spinlock
    )
{
    if (!Spinlock) return SPINLOCK_STATE_INVALID;

    SPINLOCK_STATE state = 0;
    SPINLOCK snapshot = *Spinlock;
    if (SPINLOCK_DATA(&snapshot).Acquired) state |= SPINLOCK_STATE_ACQUIRED;

#ifdef DBG_LOCKS_ENABLED
    DWORD lastOwnerCpuId;
    NTSTATUS status = DlGetLockInfo(&snapshot.DebugHeader, NULL, NULL, &lastOwnerCpuId, NULL, NULL);
    if (!SUCCESS(status)) return state;

    state |= ((DlGetCpuIndex() == lastOwnerCpuId) ? SPINLOCK_STATE_LAST_OWNER_SELF : SPINLOCK_STATE_LAST_OWNER_OTHER);
#endif

    return state;
}


VOID
HvInitSpinLock2(
    _Out_ SPINLOCK *Spinlock,
    _In_ PCHAR Name,
    _In_ PCHAR File,
    _In_ DWORD Line
    );

VOID
HvUninitSpinLock(
    _In_ SPINLOCK *Spinlock
    );


VOID
HvAcquireSpinLock2(
    _Inout_ SPINLOCK *Spinlock,
    _In_opt_ PCHAR File,
    _In_ DWORD Line
    );

VOID
HvAcquireSpinLockNoInterrupts2(
    _Inout_ SPINLOCK *Spinlock,
    _In_opt_ PCHAR File,
    _In_ DWORD Line
    );



/**
 * @brief Try to Acquire a Recursive Spinlock
 *
 * If the Spinlock is not readily available this routine returns immediately
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 *
 * @return TRUE                     The lock has been acquired
 * @return FALSE                    The lock could not be acquired
 */
__forceinline
BOOLEAN
HvTryToAcquireSpinLock2(
    _Inout_ SPINLOCK *Spinlock,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File,Line));

    assert(NULL != Spinlock);

    PROCESS_IPCS();
    SPINLOCK_BITS newVal = { 0 };
    newVal.Acquired = TRUE;
    SPINLOCK_BITS oldVal = SPINLOCK_DATA(Spinlock);

    // check variable without interlocked op and then try to acquire it using interlocked op (to avoid race condition)
    if (!oldVal.Acquired &&
            (oldVal.Raw == HvInterlockedCompareExchangeU32(&SPINLOCK_DATA(Spinlock).Raw, newVal.Raw, oldVal.Raw))
       )
    {
        DlWaitSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock), DL_WAIT_TRY);
        DlAcquireSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock));
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief Try to Acquire a non-interruptible Spinlock
 *
 * If the Spinlock is not readily available this routine returns immediately
 *
 * @warning After the Spinlock is taken only the highest priority async. messages are allowed
 *
 * @param[in,out]   Spinlock        Spinlock to acquire
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 *
 * @return TRUE                     The lock has been acquired
 * @return FALSE                    The lock could not be acquired
 */
__forceinline
BOOLEAN
HvTryToAcquireSpinLockNoInterrupts2(
    _Inout_ SPINLOCK *Spinlock,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File,Line));

    PROCESS_IPCS();

    assert(NULL != Spinlock);

    _mm_prefetch((const char*)Spinlock, _MM_HINT_T0);

    SPINLOCK_BITS oldLockValue = SPINLOCK_DATA(Spinlock);

    // first of all, check variable without interlocked op
    if (oldLockValue.Acquired) return FALSE;

    // new state: acquired + capture old interruptibility info + block all interrupts
    SPINLOCK_BITS newLockValue = { 0 };
    newLockValue.Interruptibility = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
    newLockValue.Acquired = TRUE;

    if (oldLockValue.Raw == HvInterlockedCompareExchangeU32(&SPINLOCK_DATA(Spinlock).Raw, newLockValue.Raw, oldLockValue.Raw))
    {
        DlWaitSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock), DL_WAIT_TRY);
        DlAcquireSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock));
        return TRUE;
    }

    // if not successfully acquired, must restore old interrupts
    IpcSetInterruptibilityState(newLockValue.Interruptibility);

    return FALSE;
}

/**
 * @brief Release a Spinlock
 *
 * If the lock was acquired with NoInterrupts semantics will restore interrupts into their original state from the moment when the lock was acquired.
 *
 * @param[in,out]   Spinlock        Spinlock to release
 * @param[in]       File            File where the lock was acquired (debugging)
 * @param[in]       Line            Line where the lock was acquired (debugging)
 */
__forceinline
VOID
HvReleaseSpinLock2(
    _Inout_ SPINLOCK *Spinlock,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    UNREFERENCED_PARAMETER((File, Line));

    assert(NULL != Spinlock);

    _mm_prefetch((const char*)Spinlock, _MM_HINT_T0);

    // release lock
    SPINLOCK_BITS oldValue = SPINLOCK_DATA(Spinlock);
    SPINLOCK_BITS newValue = {0};
    newValue.Acquired = FALSE;
    CxInterlockedExchange32(&SPINLOCK_DATA(Spinlock).Raw, newValue.Raw);

    DlReleaseSpinlock(File, Line, &SPINLOCK_HEADER(Spinlock));

    // restore any changes performed to interruptibility state at acquire
    IpcSetInterruptibilityState(oldValue.Interruptibility);
}

/**
 * @brief Check if a Spinlock is acquired
 *
 * @param[in]      Spinlock         Spinlock to check
 *
 * @return TRUE                     The lock is acquired
 * @return FALSE                    The lock is not acquired
 */
__forceinline
BOOLEAN
HvCheckIfSpinLockIsAcquired(
    _In_ SPINLOCK *Spinlock
    )
{
    assert(NULL != Spinlock);
    return !!SPINLOCK_DATA(Spinlock).Acquired;
}

#endif