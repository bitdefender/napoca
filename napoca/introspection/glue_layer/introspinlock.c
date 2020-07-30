/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introspinlock.c
*   @brief INTROSPINLOCK -  NAPOCA hypervisor glue layer, spinlock synchronization facilities.
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introspinlock.h"
#include "guests/intro.h"
#include "kernel/kernel.h"


NTSTATUS
GuestIntNapSpinLockInit(
    _Outptr_ PVOID* SpinLock,
    _In_z_ PCHAR Name
)
{
    NTSTATUS status;

    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Name == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // Pre-init the spin-lock.
    *SpinLock = NULL;

    // Alloc the spin-lock.
    status = HpAllocWithTagCore(SpinLock, sizeof(SPINLOCK), TAG_ILCK);
    if (!NT_SUCCESS(status)) return HV_STATUS_TO_INTRO_STATUS(status);

    HvInitSpinLock((SPINLOCK*)*SpinLock, Name, NULL);

    return CX_STATUS_SUCCESS;
}


NTSTATUS
GuestIntNapSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) PVOID* SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvUninitSpinLock(*SpinLock);

    NTSTATUS status = HpFreeAndNullWithTag(SpinLock, TAG_ILCK);

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapSpinLockAcquire(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvAcquireSpinLock((SPINLOCK*)SpinLock);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapSpinLockRelease(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvReleaseSpinLock(SpinLock);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRwSpinLockInit(
    _Outptr_ PVOID* SpinLock,
    _In_z_ PCHAR Name
)
{
    NTSTATUS status;

    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Name == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // Pre-init it with NULL.
    *SpinLock = NULL;

    // Alloc the spin-lock.
    status = HpAllocWithTagCore(SpinLock, sizeof(RW_SPINLOCK), TAG_ILCK);
    if (!NT_SUCCESS(status)) return HV_STATUS_TO_INTRO_STATUS(status);

    HvInitRwSpinLock(*SpinLock, Name, NULL);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRwSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) PVOID* SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvUninitRwSpinLock(*SpinLock);

    NTSTATUS status = HpFreeAndNullWithTag(SpinLock, TAG_ILCK);

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapRwSpinLockAcquireShared(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    NTSTATUS status =  HvAcquireRwSpinLockShared((RW_SPINLOCK*)SpinLock);

    return status;
}



NTSTATUS
GuestIntNapRwSpinLockAcquireExclusive(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    NTSTATUS status = HvAcquireRwSpinLockExclusive((RW_SPINLOCK*)SpinLock);

    return status;
}



NTSTATUS
GuestIntNapRwSpinLockReleaseShared(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    NTSTATUS status = HvReleaseRwSpinLockShared((RW_SPINLOCK*)SpinLock);

    return status;
}



NTSTATUS
GuestIntNapRwSpinLockReleaseExclusive(
    _In_ PVOID SpinLock
)
{
    if (SpinLock == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    NTSTATUS status = HvReleaseRwSpinLockExclusive((RW_SPINLOCK*)SpinLock);

    return status;
}


///@}