/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introtimer.c
*   @brief INTROTIMER -  NAPOCA hypervisor glue layer, generic timing facilities.
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introtimer.h"
#include "guests/intro.h"
#include "guests/guests.h"


NTSTATUS
GuestIntNapRegisterVmxTimerHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroTimerCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroTimerCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroTimerCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterVmxTimerHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroTimerCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroTimerCallback = NULL;

    return CX_STATUS_SUCCESS;
}


///@}