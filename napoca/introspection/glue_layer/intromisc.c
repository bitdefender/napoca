/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file intromisc.c
 *  @brief INTROMISC - NAPOCA hypervisor glue layer, other events callback handlers registration functions
 *
 *  The implementation
 */

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/intromisc.h"
#include "guests/intro.h"
#include "guests/guests.h"


NTSTATUS
GuestIntNapRegisterBreakpointHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntBreakpointCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroBreakpointCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroBreakpointCallback = Callback;

    guest->Intro.IntroEnableBreakpointExit = TRUE;

    HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterBreakpointHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroBreakpointCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    guest->Intro.IntroEnableBreakpointExit = FALSE;

    HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroBreakpointCallback = NULL;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRegisterEventInjectionHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntEventInjectionCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroEventInjectionCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroEventInjectionCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterEventInjectionHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroEventInjectionCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroEventInjectionCallback = NULL;

    return CX_STATUS_SUCCESS;
}

///@}