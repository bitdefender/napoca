/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introhvcall.c
*   @brief INTROHVCALL -  NAPOCA hypervisor glue layer, generic VM/HV call functions.
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introhvcall.h"
#include "guests/intro.h"
#include "guests/guests.h"

NTSTATUS
GuestIntNapRegisterIntroCallHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroCallCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroCallCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroCallCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterIntroCallHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (guest->Intro.RawIntroCallCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroCallCallback = NULL;

    return CX_STATUS_SUCCESS;
}

///@}