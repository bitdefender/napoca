/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introept.c
*   @brief INTROEPTHOOK -  NAPOCA hypervisor glue layer, EPT hook support and SPP hook support
*
*/

#include "napoca.h"
#include "introstatus.h"
#include "introspection/glue_layer/introept.h"
#include "guests/guests.h"
#include "memory/ept.h"
#include "memory/cachemap.h"
#include "memory/spp.h"
#include "memory/memmgr.h"
#include "guests/intro.h"

///
/// @brief Verifies if the memory described by the GPA is valid for the introspection engine.
///
/// The address should not be the address of GuestEnlightment pages, Memory Mapped IO for devices and not
/// WriteBack cacheable.
///
/// @param[in] Guest        The Guest identifier
/// @param[in] Address      The GPA which should be checked for introspection.
///
/// @returns    CX_TRUE         - if the memory is valid for introspection
/// @returns    CX_FALSE        - if the memory is not valid for introspection
///
static
BOOLEAN
_GuestIntNapIsMemValidForHvi(
    _In_ GUEST* Guest,
    _In_ QWORD Address
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    BYTE type = IG_MEM_UNKNOWN;

    if (GstEnIsHyperPageAddress(Address) || MmapIsAddressInMap(&Guest->MmioMap, Address, BOOT_MEM_TYPE_MAX_VALUE))
    {
        return CX_FALSE;
    }

    status = ChmGetPhysicalPageTypeFromMtrrs(Guest, PAGE_BASE_PA(Address), &type);
    if (!SUCCESS(status)) CRITICAL("GuestIntNapGetPhysicalPageTypeFromMtrrs for address %p failed with status: %s\n",
        Address, NtStatusToString(status));

    if (type != IG_MEM_WB) return CX_FALSE;

    return CX_TRUE;
}


NTSTATUS
GuestIntNapGetEPTPageProtection(
    _In_ PVOID GuestHandle,                 // Guest handle.
    _In_ DWORD EptIndex,
    _In_ QWORD Address,                     // GPA whose EPT page protection attributes will be retrieved.
    _Out_ BYTE* Read,                       // 1 or 0 upon exit, if readable or not readable.
    _Out_ BYTE* Write,                      // 1 or 0 upon exit, if writable or not writable.
    _Out_ BYTE* Execute                     // 1 or 0 upon exit, if executable or not executable.
)
{
    GUEST *guest = GuestHandle;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Read) return CX_STATUS_INVALID_PARAMETER_4;
    if (!Write) return CX_STATUS_INVALID_PARAMETER_5;
    if (!Execute) return CX_STATUS_INVALID_PARAMETER_6;
    if (!_GuestIntNapIsMemValidForHvi(guest, Address)) return CX_STATUS_NOT_SUPPORTED;

    EPT_DESCRIPTOR *ept;
    NTSTATUS status = GstGetEptDescriptorEx(guest, (GUEST_MEMORY_DOMAIN_INDEX)EptIndex, &ept);
    if (!CX_SUCCESS(status)) return CX_STATUS_INVALID_PARAMETER_2;

    EPT_RIGHTS rights;
    status = EptGetRights(ept, CX_PAGE_BASE_4K(Address), 0, &rights);
    if (!NT_SUCCESS(status)) return HV_STATUS_TO_INTRO_STATUS(status);

    // give back the rights
    *Read       = !!rights.Read;
    *Write      = !!rights.Write;
    *Execute    = !!rights.Execute;

    return CX_STATUS_SUCCESS;
}

NTSTATUS
GuestIntNapSetEPTPageProtection(
    _In_ PVOID GuestHandle,                 // Guest handle.
    _In_ DWORD EptIndex,                    // The index of the EPT in which modifications will happen (from the Guests EPT list)
    _In_ QWORD Address,                     // GPA whose EPT attributes are to be modified.
    _In_ BYTE Read,                         // New Read rights.
    _In_ BYTE Write,                        // New Write rights.
    _In_ BYTE Execute                       // New Execute rights.
)
{
    GUEST *guest = GuestHandle;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!_GuestIntNapIsMemValidForHvi(guest, Address)) return CX_STATUS_NOT_SUPPORTED;

    EPT_RIGHTS rights = { 0 };
    rights.Read     = !!Read;
    rights.Write    = !!Write;
    rights.Execute  = !!Execute;

    EPT_DESCRIPTOR *ept;
    NTSTATUS status = GstGetEptDescriptorEx(guest, (GUEST_MEMORY_DOMAIN_INDEX)EptIndex, &ept);
    if (!NT_SUCCESS(status)) return CX_STATUS_INVALID_PARAMETER_2;

    status = EptSetRights(ept, CX_PAGE_BASE_4K(Address), 0, rights);
    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapGetEPTPageConvertible(
    _In_ PVOID GuestHandle,                 // Guest handle.
    _In_ DWORD EptIndex,
    _In_ QWORD Address,                     // GPA whose EPT page convertible attribute is retrieved
    _Out_ BOOLEAN* Convertible
)
{
    GUEST *guest = GuestHandle;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Convertible) return CX_STATUS_INVALID_PARAMETER_4;
    if (!_GuestIntNapIsMemValidForHvi(guest, Address)) return CX_STATUS_NOT_SUPPORTED;

    EPT_DESCRIPTOR *ept;
    NTSTATUS status = GstGetEptDescriptorEx(guest, (GUEST_MEMORY_DOMAIN_INDEX)EptIndex, &ept);
    if (!CX_SUCCESS(status)) return CX_STATUS_INVALID_PARAMETER_2;

    EPT_RIGHTS rights;
    status = EptGetRights(ept, CX_PAGE_BASE_4K(Address), 0, &rights);
    *Convertible = !rights.BypassVe;

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapSetEPTPageConvertible(
    _In_ PVOID GuestHandle,                 // Guest handle.
    _In_ DWORD EptIndex,
    _In_ QWORD Address,                     // GPA whose EPT attributes are to be modified.
    _In_ BOOLEAN Convertible
)
{
    GUEST *guest = GuestHandle;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!_GuestIntNapIsMemValidForHvi(guest, Address)) return CX_STATUS_NOT_SUPPORTED;

    EPT_DESCRIPTOR *ept;
    CX_STATUS status = GstGetEptDescriptorEx(guest, (GUEST_MEMORY_DOMAIN_INDEX)EptIndex, &ept);
    if (!NT_SUCCESS(status)) return CX_STATUS_INVALID_PARAMETER_2;

    EPT_PROPERTIES set = { 0 }, clear = { 0 };
    set.BypassVe    = !Convertible;
    clear.BypassVe  = Convertible;

    status = EptAlterMappings(ept, CX_PAGE_BASE_4K(Address), 0, set, clear);

    CX_STATUS invStatus = EptInvalidateTlbs(guest, EPT_INVD_ANY_CONTEXT, TRUE);
    if (!NT_SUCCESS(invStatus))
    {
        LOG_FUNC_FAIL("EptInvalidateTlbs", invStatus);
        // don't fail the API
    }

    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapCreateEPT(
    _In_ PVOID Guest,
    _Out_ DWORD* EptIndex
)
{
    GUEST *guest = Guest;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!EptIndex) return CX_STATUS_INVALID_PARAMETER_2;

    // ask for a new domain preinitialized with the main physical-memory mappings of the guest
    GUEST_MEMORY_DOMAIN_INDEX newDomainIndex;
    GUEST_MEMORY_DOMAIN_INDEX sourceDomainIndex = GuestPredefinedMemoryDomainIdPhysicalMemory;
    CX_STATUS status = GstCreateMemoryDomain(Guest, NULL, GUEST_MEMORY_DOMAIN_VMFUNC_ALLOW, NULL, &sourceDomainIndex, NULL, &newDomainIndex);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstCreateMemoryDomain", status);
        goto cleanup;
    }

    LOG("Created EPT domain[%d] for intro\n", newDomainIndex);
    *EptIndex = newDomainIndex;

cleanup:
    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapDestroyEPT(
    _In_ PVOID Guest,
    _In_ DWORD EptIndex
)
{
    GUEST *guest = Guest;

    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (EptIndex < GuestPredefinedMemoryDomainIdValues) return CX_STATUS_INVALID_PARAMETER_2;
    if (EptIndex >= GstGetMemoryDomainsCount(guest)) return CX_STATUS_INVALID_PARAMETER_2;

    NTSTATUS status = GstDestroyMemoryDomain(guest, (GUEST_MEMORY_DOMAIN_INDEX)EptIndex);
    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapSwitchEPT(
    _In_ PVOID Guest,
    _In_ DWORD NewEptIndex
)
{
    GUEST *guest = Guest;
    if (!guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (NewEptIndex >= GstGetMemoryDomainsCount(guest)) return CX_STATUS_INVALID_PARAMETER_2;

    NTSTATUS status = VcpuActivateDomain(HvGetCurrentVcpu(), (GUEST_MEMORY_DOMAIN_INDEX)NewEptIndex);
    return HV_STATUS_TO_INTRO_STATUS(status);
}



NTSTATUS
GuestIntNapSetVEInfoPage(
    _In_ PVOID Guest,
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoGpa
)
{
    NTSTATUS status;
    QWORD veInfoPageHpa;

    LOG("%s(%p %x %p)\n", __FUNCTION__, Guest, CpuNumber, VeInfoGpa);

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = Guest;

    if (CpuNumber >= guest->VcpuCount) return CX_STATUS_INVALID_PARAMETER_2;

    if (0 != VeInfoGpa)
    {
        VEINFOPAGE* hva = NULL;

        status = ChmGpaToHpa(guest, VeInfoGpa, &veInfoPageHpa);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("ChmGpaToHpa", status);
            return HV_STATUS_TO_INTRO_STATUS(status);
        }

        status = MmMapMem(&gHvMm, veInfoPageHpa, PAGE_SIZE, TAG_IVE, (VOID**)&hva);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmMapMem", status);
            return HV_STATUS_TO_INTRO_STATUS(status);
        }

        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHpa = veInfoPageHpa;
        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHva = hva;
        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageGpa = VeInfoGpa;
    }
    else
    {
        if (guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHva)
        {
            status = MmUnmapMem(&gHvMm, TRUE, TAG_IVE, (VOID**)&guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHva);
            if (!NT_SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmUnmapMem", status);
                return HV_STATUS_TO_INTRO_STATUS(status);
            }
        }
        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHpa = 0;
        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageGpa = 0;
        guest->Vcpu[CpuNumber]->VirtualizationException.InfoPageHva = 0;
    }

    HvInterlockedOrU64(&guest->Intro.IntroVcpuMask, (1ULL << CpuNumber));

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapRegisterEptHandler(
    _In_ PVOID Guest,
    _In_ PFUNC_IntEPTViolationCallback Callback
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = Guest;

    if (Callback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (guest->Intro.RawIntroEptCallback != NULL) return CX_STATUS_ALREADY_INITIALIZED;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroEptCallback = Callback;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapUnregisterEptHandler(
    _In_ PVOID Guest
)
{
    GUEST *guest;

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    guest = Guest;

    if (guest->Intro.RawIntroEptCallback == NULL) return CX_STATUS_NOT_INITIALIZED_HINT;

    ValidateIntroCallbacksLock(&guest->Intro.IntroCallbacksLock);
    guest->Intro.RawIntroEptCallback = NULL;

    return CX_STATUS_SUCCESS;
}

//
// SPP hooks
//

NTSTATUS
GuestIntNapGetSPPPageProtection(
    _In_ PVOID Guest,
    _In_ QWORD Address,
    _Out_ QWORD* SppValue
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if ((CX_PAGE_OFFSET_4K(Address)) != 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (SppValue == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    NTSTATUS status = SppGetPageProtection((MEM_ALIGNED_PA)Address, SppValue);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

NTSTATUS
GuestIntNapSetSPPPageProtection(
    _In_ PVOID GuestHandle,
    _In_ QWORD Address,
    _In_ QWORD SppValue
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if ((CX_PAGE_OFFSET_4K(Address)) != 0) return CX_STATUS_INVALID_PARAMETER_2;

    NTSTATUS status = SppSetPageProtection((MEM_ALIGNED_PA)Address, SppValue);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

///@}