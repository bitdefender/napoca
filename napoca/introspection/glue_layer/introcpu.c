/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup introcallhv Introspection support for introspection -> hypervisor calls, the callbacks passed by the GLUE interface and the UPPER interface
/// @ingroup introspection
///@{

/** @file introcpu.c
*   @brief INTROCPU -  NAPOCA hypervisor glue layer, CPU utilities
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introcpu.h"
#include "guests/intro.h"
#include "guests/guests.h"

NTSTATUS
GuestIntNapPauseVcpus(
    _In_ PVOID Guest                       // Guest handle.
)
{
    // Validate
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = Guest;

    NTSTATUS status = GstPause(guest, GST_UPDATE_REASON_PAUSE_GUEST);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("GstPause", status);

    return HV_STATUS_TO_INTRO_STATUS(status);
}


NTSTATUS
GuestIntNapResumeVcpus(
    _In_ PVOID Guest                       // Guest handle.
)
{
    // Validate
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = Guest;

    NTSTATUS status = GstUnpause(guest, GST_UPDATE_REASON_PAUSE_GUEST);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("GstUnpause", status);

    return HV_STATUS_TO_INTRO_STATUS(status);
}


NTSTATUS
GuestIntNapSetIntroEmulatorContext(
    _In_ PVOID Guest,
    _In_ DWORD CpuNumber,
    _In_ QWORD VirtualAddress,
    _In_ DWORD BufferSize,
    _In_reads_bytes_(BufferSize) PBYTE Buffer
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = Guest;

    if (Buffer == NULL) return CX_STATUS_INVALID_PARAMETER_5;

    if (BufferSize == 0) return CX_STATUS_INVALID_PARAMETER_4;

    if (CpuNumber == IG_CURRENT_VCPU) CpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;

    if (CpuNumber >= guest->VcpuCount) return CX_STATUS_INVALID_PARAMETER_2;

    memcpy(guest->Vcpu[CpuNumber]->IntroEmu.Buffer, Buffer, MIN(BufferSize, sizeof(guest->Vcpu[CpuNumber]->IntroEmu.Buffer)));

    guest->Vcpu[CpuNumber]->IntroEmu.BufferSize = BufferSize;
    guest->Vcpu[CpuNumber]->IntroEmu.BufferGla = VirtualAddress;

    guest->Vcpu[CpuNumber]->IntroEmu.BufferValid = TRUE;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
GuestIntNapToggleRepOptimization(
    _In_ PVOID Guest,
    _In_ BOOLEAN Enable
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST* guest = Guest;

    guest->Intro.IntroDisableRepOptimization = !Enable;

    return CX_STATUS_SUCCESS;
}

///@}