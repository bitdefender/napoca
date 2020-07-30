/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introreghook.c
*   @brief INTROREGHOOK -  NAPOCA hypervisor glue layer, registers hook functions
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introreghook.h"
#include "guests/intro.h"
#include "guests/guests.h"


NTSTATUS
GuestIntNapEnableCrWriteExit(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (Cr == 0) return CX_STATUS_SUCCESS;
    else if (Cr == 3)
    {
        guest->Intro.IntroEnableCr3LoadExit = TRUE;

        HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

        return CX_STATUS_SUCCESS;
    }
    else if (Cr == 4) return CX_STATUS_SUCCESS;

    return CX_STATUS_INVALID_PARAMETER_2;
}



NTSTATUS
GuestIntNapDisableCrWriteExit(
    _In_ PVOID GuestHandle,
    _In_ DWORD Cr
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Cr == 0) return CX_STATUS_SUCCESS;
    else if (Cr == 3)
    {
        guest->Intro.IntroEnableCr3LoadExit = FALSE;

        HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

        return CX_STATUS_SUCCESS;
    }
    else if (Cr == 4) return CX_STATUS_SUCCESS;

    return CX_STATUS_INVALID_PARAMETER_2;
}



NTSTATUS
GuestIntNapRegisterCrWriteHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntCrWriteCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroCrCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroCrCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterCrWriteHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroCrCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroCrCallback = NULL;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRegisterDescriptorTableHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntIntroDescriptorTableCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroDescriptorTableCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroDescriptorTableCallback = Callback;

    guest->Intro.IntroEnableDescLoadExit = TRUE;

    HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterDescriptorTableHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroDescriptorTableCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    guest->Intro.IntroEnableDescLoadExit = FALSE;

    HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << guest->VcpuCount) - 1);

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroDescriptorTableCallback = NULL;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRegisterXcrWriteHandler(
    _In_ PVOID GuestHandle,
    _In_ PFUNC_IntXcrWriteCallback Callback
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroXcrCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroXcrCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterXcrWriteHandler(
    _In_ PVOID GuestHandle
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = GuestHandle;

    if (guest->Intro.RawIntroXcrCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroXcrCallback = NULL;

    return CX_STATUS_SUCCESS;
}


///@}