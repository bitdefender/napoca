/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup hibernate
///@{

/** @file hibernate_clients.c
 *  @brief HIBERNATE_CLIENTS - All the supported clients which store and restore some specific data during of the power transition of the Guest into S4(Hibernate) state.
 *
 */

#include "napoca.h"
#include "guests/guests.h"
#include "kernel/kernel.h"
#include "guests/pci.h"
#include "memory/hibernate_clients.h"

NTSTATUS
HvHibGuestEnlightGetData(
    _Out_ BYTE *DataBuffer,
    _In_ DWORD DataBufferSize
)
{
    GUEST_ENLIGHT_SAVE_DATA *saveData = (GUEST_ENLIGHT_SAVE_DATA*)DataBuffer;
    GUEST *guest = gHypervisorGlobalData.Guest[0];

    if (sizeof(GUEST_ENLIGHT_SAVE_DATA) > DataBufferSize) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    if (!DataBuffer) return CX_STATUS_INVALID_PARAMETER_1;

    saveData->GuestOsId.Raw = GstEnGetMsrValue(guest->Vcpu[0], HV_X64_MSR_GUEST_OS_ID);

    saveData->HypercallPageGpa = GstEnGetMsrValue(guest->Vcpu[0], HV_X64_MSR_HYPERCALL);

    saveData->HypercallPageActive = guest->HypercallPageActive;

    saveData->TscPage = GstEnGetMsrValue(guest->Vcpu[0], HV_X64_MSR_REFERENCE_TSC);

    saveData->GuestVcpuCount = guest->VcpuCount;

    LOG("Save:\n");
    LOG("\tGuestOsId %p, HypercallPageGpa %p GuestVcpuCount %p\n",
        saveData->GuestOsId.Raw, saveData->HypercallPageGpa, saveData->GuestVcpuCount);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvHibGuestEnlightPutData(
    _In_ BYTE  *DataBuffer,
    _In_ DWORD DataBufferSize
)
{
    NTSTATUS status;
    GUEST_ENLIGHT_SAVE_DATA *saveData = (GUEST_ENLIGHT_SAVE_DATA*)DataBuffer;
    GUEST *guest = gHypervisorGlobalData.Guest[0];

    if (sizeof(GUEST_ENLIGHT_SAVE_DATA) > DataBufferSize) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    if (!DataBuffer) return CX_STATUS_INVALID_PARAMETER_1;

    LOG("Restore:\n");
    LOG("\tGuestOsId %p, HypercallPageGpa %p GuestVcpuCount %p\n",
        saveData->GuestOsId.Raw, saveData->HypercallPageGpa, saveData->GuestVcpuCount);

    if (guest->VcpuCount != saveData->GuestVcpuCount)
    {
        CRITICAL("Inconsistent vcpu count: Before %d after %d\n", saveData->GuestVcpuCount, guest->VcpuCount);
        return CX_STATUS_INVALID_INTERNAL_STATE;
    }

    status = GstEnHandleMsrWrite(guest->Vcpu[0], HV_X64_MSR_GUEST_OS_ID, saveData->GuestOsId.Raw);
    if (!SUCCESS(status)) ERROR("Failed to restore guest os id with value %p and status 0x%x\n", saveData->GuestOsId.Raw, status);

    status = GstEnHandleMsrWrite(guest->Vcpu[0], HV_X64_MSR_HYPERCALL, saveData->HypercallPageGpa);
    if (!SUCCESS(status))
    {
        ERROR("Failed to restore hypercall page with value %p and status 0x%x\n", saveData->HypercallPageGpa, status);
        guest->HypercallPageActive = FALSE;
    }
    else guest->HypercallPageActive = saveData->HypercallPageActive;

    // not windows 7 => rewrite TSC page
    // on some legacy W7 systems the system BSODs with 0xE3 on resume from hibernate
    if (!(saveData->GuestOsId.Ms.MajorVersion == 6 && saveData->GuestOsId.Ms.MinorVersion == 1))
    {
        status = GstEnHandleMsrWrite(guest->Vcpu[0], HV_X64_MSR_REFERENCE_TSC, saveData->TscPage);
        if (!SUCCESS(status)) ERROR("Failed to restore tsc page with value %p and status 0x%x\n", saveData->TscPage, status);
    }

    return status;
}

NTSTATUS
HvHibGuestBarReconfGetData(
    _Out_ BYTE *DataBuffer,
    _In_ DWORD DataBufferSize
)
{
    NTSTATUS status;
    GUEST_BAR_RECONF_SAVE_DATA *saveData = (GUEST_BAR_RECONF_SAVE_DATA*)DataBuffer;

    if (sizeof(GUEST_BAR_RECONF_SAVE_DATA) > DataBufferSize) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    if (!DataBuffer) return CX_STATUS_INVALID_PARAMETER_1;

    LOG("Save PCI BAR reconfigurations!\n");

    status = PciStoreBarReconfigurationDataOnHibernate(&saveData->BarReconfigurations);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("PciStoreBarReconfigurationDataOnHibernate", status);

    return status;
}

NTSTATUS
HvHibGuestBarReconfPutData(
    _In_ BYTE  *DataBuffer,
    _In_ DWORD DataBufferSize
)
{
    NTSTATUS status;
    GUEST_BAR_RECONF_SAVE_DATA *saveData = (GUEST_BAR_RECONF_SAVE_DATA*)DataBuffer;

    if (sizeof(GUEST_BAR_RECONF_SAVE_DATA) > DataBufferSize) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    if (!DataBuffer) return CX_STATUS_INVALID_PARAMETER_1;

    LOG("Restore PCI BAR Reconfigurations:\n");

    status = PciRestoreBarReconfigurationDataOnHibernate(&saveData->BarReconfigurations);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("PciRestoreBarReconfigurationDataOnHibernate", status);

    return status;
}

///@}