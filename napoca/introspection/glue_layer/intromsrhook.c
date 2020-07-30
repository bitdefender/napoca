/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file intromsrhook.c
*   @brief INTROMSRHOOK -  NAPOCA hypervisor glue layer, MSR hook support
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/intromsrhook.h"
#include "guests/intro.h"
#include "guests/guests.h"


NTSTATUS
GuestIntNapRegisterMsrHandler(
    _In_ PVOID Guest,                       // Guest handle.
    _In_ PFUNC_IntMSRViolationCallback Callback // Callback that will be called whenever a MSR violation takes place.
)
{
    GUEST *guest;

    if (Guest == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (Callback == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    guest = Guest;

    if (guest->Intro.RawIntroMsrCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroMsrCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterMsrHandler(
    _In_ PVOID Guest                        // Guest handle.
)
{
    GUEST *guest;

    if (Guest == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    guest = Guest;

    if (guest->Intro.RawIntroMsrCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroMsrCallback = NULL;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapEnableMsrExit(
    _In_ PVOID Guest,                       // Guest handle.
    _In_ DWORD Msr,                         // The MSR we want to intercept.
    _Out_ BOOLEAN* OldValue                 // TRUE if the MSR was already intercepted, FALSE otherwise.
)
{
    if (Guest == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    GUEST *guest = Guest;

    if (OldValue == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    // Acquire global spinlock
    HvAcquireSpinLock(&guest->MsrHookLockGlb);

    // Update MSR bitmap
    if ((Msr >= 0xC0000000) && (Msr <= 0xC0001FFF))
    {
        Msr = Msr - 0xC0000000;

        *OldValue = (guest->MsrBitmap[384 + (Msr >> 6)] & BIT_AT(Msr & 0x3f)) != 0;

        guest->MsrBitmap[384 + (Msr >> 6)] |= BIT_AT(Msr & 0x3f);           // msr / 64, msr % 64
    }
    else
    {
        *OldValue = (guest->MsrBitmap[256 + (Msr >> 6)] & BIT_AT(Msr & 0x3f)) != 0;

        guest->MsrBitmap[256 + (Msr >> 6)] |= BIT_AT(Msr & 0x3f);           // msr / 64, msr % 64
    }

    // Release global spinlock
    HvReleaseSpinLock(&guest->MsrHookLockGlb);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapDisableMsrExit(
    _In_ PVOID Guest,                       // Guest handle.
    _In_ DWORD Msr,                         // The MSR we want to disable interceptions on.
    _Out_ BOOLEAN* OldValue                 // TRUE if interceptions were active on this MSR, FALSE otherwise.
)
{
    if (Guest == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (OldValue == NULL)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    GUEST *guest = Guest;

    // Acquire global spinlock
    HvAcquireSpinLock(&guest->MsrHookLockGlb);

    // Update MSR bitmap
    if ((Msr >= 0xC0000000) && (Msr <= 0xC0001FFF))
    {
        Msr = Msr - 0xC0000000;

        *OldValue = (guest->MsrBitmap[384 + (Msr >> 6)] & BIT_AT(Msr & 0x3f)) != 0;

        guest->MsrBitmap[384 + (Msr >> 6)] &= ~BIT_AT(Msr & 0x3f);          // msr / 64, msr % 64
    }
    else
    {
        *OldValue = (guest->MsrBitmap[256 + (Msr >> 6)] & BIT_AT(Msr & 0x3f)) != 0;

        guest->MsrBitmap[256 + (Msr >> 6)] &= ~BIT_AT(Msr & 0x3f);          // msr / 64, msr % 64
    }

    // Release global spinlock
    HvReleaseSpinLock(&guest->MsrHookLockGlb);

    return CX_STATUS_SUCCESS;
}

///@}