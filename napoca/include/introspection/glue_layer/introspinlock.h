/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introspinlock.h
*   @brief INTROSPINLOCK -  NAPOCA hypervisor glue layer, spinlock synchronization facilities.
*
*/

#ifndef _INTROSPINLOCK_H_
#define _INTROSPINLOCK_H_

#include "glueiface.h"

///
/// @brief  Initializes and allocates a spin lock
///
/// @param[out] SpinLock    Pointer to an opaque void* value that will represent the spin lock
/// @param[in]  Name        NULL-terminated string that contains the name of the spinlock
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Name is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if HpAllocWithTagCore returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if HpAllocWithTagCore returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised by HpAllocWithTagCore
///
NTSTATUS
GuestIntNapSpinLockInit(
    _Outptr_ PVOID* SpinLock,
    _In_z_ PCHAR Name
);

///
/// @brief  Uninits and releases the memory for a spin lock
///
/// @param[in, out] SpinLock    Pointer to an opaque void* value that will represent the spin lock
///                             This was previously initialized by a UPPER_IFACE.SpinLockInit call.
///                             On success, SpinLock will be set to NULL
///
/// @returns    CX_STATUS_SUCCESS                   - if the un-init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if HpFreeWithTagCore returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if HpFreeWithTagCore returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised by HpFreeWithTagCore
///
///
NTSTATUS
GuestIntNapSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) PVOID* SpinLock
);

///
/// @brief  Exclusively acquires a spin lock
///
/// Wrapper on HvAcquireSpinLock. Will acquire the spinlock. This function blocks
/// until the spinlock is acquired.
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         UPPER_IFACE.SpinLockInit call
///
/// @returns    CX_STATUS_SUCCESS                   - if the lock was acquired was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
///
NTSTATUS
GuestIntNapSpinLockAcquire(
    _In_ PVOID SpinLock
);

///
/// @brief  Release a spin lock previously acquired with UPPER_IFACE.SpinLockAcquire
///
/// @param[in]  SpinLock    The lock that must be released
///
/// @returns    CX_STATUS_SUCCESS                   - if the lock was acquired was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
///
NTSTATUS
GuestIntNapSpinLockRelease(
    _In_ PVOID SpinLock
);

///
/// @brief  Initializes and allocates a rw-spin lock (Read-Write)
///
/// @param[out] SpinLock    Pointer to an opaque void* value that will represent the spin lock
/// @param[in]  Name        NULL-terminated string that contains the name of the spinlock
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Name is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if HpAllocWithTagCore returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if HpAllocWithTagCore returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised by HpAllocWithTagCore
///
NTSTATUS
GuestIntNapRwSpinLockInit(
    _Outptr_ PVOID* SpinLock,
    _In_z_ PCHAR Name
);

///
/// @brief  Uninits and releases the memory for a rw-spin lock
///
/// @param[in, out] SpinLock    Pointer to an opaque void* value that will represent the spin lock
///                             This was previously initialized by a UPPER_IFACE.RwSpinLockInit call.
///                             On success, SpinLock will be set to NULL
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if HpFreeAndNullWithTag returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if HpFreeAndNullWithTag returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised by HpFreeAndNullWithTag
///
NTSTATUS
GuestIntNapRwSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) PVOID* SpinLock
);

///
/// @brief  Acquires a spin rw-lock in shared mode (for reading)
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         UPPER_IFACE.RwSpinLockInit call
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL

/// @returns    STATUS_TOO_MANY_WAITERS             - in the very unlikely situation when there are more than 64K shared-waiters on the lock
/// @returns    STATUS_TOO_MANY_ACQUIRES            - in the very unlikely situation when there are more than 64K shared-acquires on the lock
///
NTSTATUS
GuestIntNapRwSpinLockAcquireShared(
    _In_ PVOID SpinLock
);

///
/// @brief  Acquires a spin rw-lock in exclusive mode (for writing)
///
/// NOTE: until this routine remains spinning only IPI interrupts are allowed and interrupts are enabled even if interrupts
/// where disabled when this routine was called.
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         UPPER_IFACE.RwSpinLockInit call
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    STATUS_TOO_MANY_WAITERS             - in the very unlikely situation when there are more than 64K exclusive-waiters on the lock
///
NTSTATUS
GuestIntNapRwSpinLockAcquireExclusive(
    _In_ PVOID SpinLock
);

///
/// @brief  Release a spin rw-lock previously acquired in shared mode with UPPER_IFACE.RwSpinLockAcquireShared
///
/// @param[in]  SpinLock    The lock that must be released
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    STATUS_NOT_ACQUIRED                 - if the given lock was NOT acquired in shared mode(so no proper release could be performed)
/// @returns    STATUS_TOO_MANY_RELEASES            - if the release was performed too many times (more than the number of shared acquires)
///
NTSTATUS
GuestIntNapRwSpinLockReleaseShared(
    _In_ PVOID SpinLock
);

///
/// @brief  Release a spin rw-lock previously acquired in exclusive mode with UPPER_IFACE.RwSpinLockAcquireExclusive
///
/// @param[in]  SpinLock    The lock that must be released
///
/// @returns    CX_STATUS_SUCCESS                   - if the init was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Spinlock is NULL
/// @returns    STATUS_NOT_ACQUIRED                 - if the given lock was NOT exclusively owned (so no proper release could be performed)
///
NTSTATUS
GuestIntNapRwSpinLockReleaseExclusive(
    _In_ PVOID SpinLock
);

#endif // _INTROSPINLOCK_H_

///@}