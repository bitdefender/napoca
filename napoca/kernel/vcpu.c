/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file vcpu.c
*   @brief VCPU - VCPU functions for Guest Memory Domain management
*
*/

#include "napoca.h"
#include "kernel/vcpu.h"
#include "guests/guests.h"
#include "kernel/vmx.h"
#include "kernel/newcore.h"


///
/// @brief        Updates the EPT on the CPU by writing the EPT from the EPT_DESCRIPTOR to the VMCS (updating eptp index in case of VmFunc feature) and
///               executes a cache invalidation for the new eptp.
///
/// @param[in]    Ept                              The EPT_DESCRIPTOR address of the new EPT.
/// @param[in]    EptIndex                         The index of the guest memory domain, in case of VMFUNC feature is available it is used as eptp index.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      ERROR_STATUS                     - in case the INVEPT failed
///
static
CX_STATUS
_VcpuSetEptp(
    _In_ EPT_DESCRIPTOR             *Ept,
    _In_ GUEST_MEMORY_DOMAIN_INDEX  EptIndex
)
{
    CX_UINT64 eptp;
    CX_STATUS status = EptGetRawEptpValue(Ept, &eptp);
    if (!CX_SUCCESS(status)) return status;

    __vmx_vmwrite(VMCS_EPTP, eptp);
    if (VmxIsVmfuncAvailable())
    {
        __vmx_vmwrite(VMCS_EPTP_INDEX, EptIndex);
    }
    return CpuVmxInvEpt(INVEPT_TYPE_SINGLE_CONTEXT, eptp, 0);
}



CX_STATUS
VcpuPreinit(
    _Inout_ VCPU                        *Vcpu,
    _In_ GUEST                          *Guest,
    _In_ CX_UINT32                      VcpuIndex
)
{
    memzero(&Vcpu->ArchRegs, sizeof(ARCH_REGS));

    Vcpu->GuestExitRoutine = (CX_VOID *)HvVmxHandleVmExitCommon;

    // allocate guarded VMCS structure
    CX_STATUS status = MmAllocMemEx(&gHvMm, NAPOCA_GUEST_VMCS_LENGTH, TAG_VMCS, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &Vcpu->Vmcs, &Vcpu->VmcsPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMemEx", status);
        goto cleanup;
    }
    MmRegisterVaInfo(Vcpu->Vmcs, NAPOCA_GUEST_VMCS_LENGTH, "VMCS#%d.%d", Guest->Index, VcpuIndex);

    // allocate a guarded IntroEmu.SingleStep.Buffer
    Vcpu->IntroEmu.SingleStep.BufferSize = 2 * CX_PAGE_SIZE_4K;

    status = MmAllocMemEx(&gHvMm, Vcpu->IntroEmu.SingleStep.BufferSize, TAG_SINGLESTEP, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &Vcpu->IntroEmu.SingleStep.Buffer, &Vcpu->IntroEmu.SingleStep.BufferPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMemEx", status);
        goto cleanup;
    }
    MmRegisterVaInfo(Vcpu->IntroEmu.SingleStep.Buffer, Vcpu->IntroEmu.SingleStep.BufferSize, "IntroEmu.SingleStep.Buffer#%d.%d", Guest->Index, VcpuIndex);

    memzero(Vcpu->IntroEmu.SingleStep.Buffer, Vcpu->IntroEmu.SingleStep.BufferSize);

    // set a pointer back to the GUEST struct and GUEST / VCPU indexes
    Vcpu->Guest = Guest;
    Vcpu->GuestIndex = (CX_UINT8)(Guest->Index);
    Vcpu->GuestCpuIndex = (CX_UINT8)(VcpuIndex);

    // setup statistics / counters
    Vcpu->ExitCount = 0;
    Vcpu->VcpuPauseCount = 0;
    Vcpu->FirstApInitExitState = BEFORE_FIRST_INIT_EXIT;
    Vcpu->CurrentExitReason = EXIT_REASON_INVALID;

    HvInitSpinLock(&Vcpu->MemoryDomain.Lock, "ActiveDomainLock", CX_NULL);

cleanup:
    return status;
}



CX_STATUS
VcpuActivateDomainEx(
    _In_ VCPU                       *Vcpu,
    _In_ GUEST_MEMORY_DOMAIN    *Domain
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Domain) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Domain->Initialized) return CX_STATUS_DATA_NOT_INITIALIZED;

    EPT_DESCRIPTOR *ept;
    CX_STATUS status = GstGetMemoryDomainEptDescriptor(Domain, &ept);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetMemoryDomainEptDescriptor", status);
        return status;
    }

    HvAcquireSpinLock(&Vcpu->MemoryDomain.Lock);

    if (Vcpu->MemoryDomain.HistoryIndex >= MAX_VCPU_DOMAIN_HISTORY)
    {
        ERROR("No more stack entries left for domain history tracking!\n");
        status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    Vcpu->MemoryDomain.History[Vcpu->MemoryDomain.HistoryIndex] = Vcpu->MemoryDomain.ActiveDomain;
    Vcpu->MemoryDomain.HistoryIndex++;
    Vcpu->MemoryDomain.ActiveDomain = Domain;

    status = _VcpuSetEptp(ept, Vcpu->MemoryDomain.ActiveDomain->Index);

cleanup:
    HvReleaseSpinLock(&Vcpu->MemoryDomain.Lock);
    return status;
}



CX_STATUS
VcpuActivateDomain(
    _In_ VCPU                       *Vcpu,
    _In_ GUEST_MEMORY_DOMAIN_INDEX  DomainIndex
)
{
    GUEST_MEMORY_DOMAIN *domain;
    CX_STATUS status = GstGetMemoryDomain(Vcpu->Guest, DomainIndex, &domain);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetMemoryDomain", status);
        return status;
    }

    return VcpuActivateDomainEx(Vcpu, domain);
}



CX_STATUS
VcpuDeactivateDomainEx(
    _In_ VCPU                       *Vcpu,
    _In_opt_ GUEST_MEMORY_DOMAIN    *ActiveDomain,
    _In_ CX_BOOL                    ForceDeactivation
)
{
    CX_STATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; // VC complains at 'return status' and can't even be silenced with pragma suppress..
    CX_BOOL inconsistencyDetected = CX_FALSE;

    HvAcquireSpinLock(&Vcpu->MemoryDomain.Lock);
    if (!Vcpu->MemoryDomain.HistoryIndex || !Vcpu->MemoryDomain.History[Vcpu->MemoryDomain.HistoryIndex - 1])
    {
        status = CX_STATUS_NO_MORE_ENTRIES; // no actual history to revert to
        goto release_and_cleanup;
    }

    if (ActiveDomain && (ActiveDomain != Vcpu->MemoryDomain.ActiveDomain))
    {
        VCPUERROR(Vcpu, "An unexpected memory domain (index=%d) is currently active when trying to revert back to the previous one (index=%d)\n", ActiveDomain->Index, Vcpu->MemoryDomain.ActiveDomain->Index);
        inconsistencyDetected = CX_TRUE;

        if (!ForceDeactivation) goto release_and_cleanup;
    }

    Vcpu->MemoryDomain.HistoryIndex--;
    Vcpu->MemoryDomain.ActiveDomain = Vcpu->MemoryDomain.History[Vcpu->MemoryDomain.HistoryIndex];

    EPT_DESCRIPTOR *ept;
    status = GstGetMemoryDomainEptDescriptor(Vcpu->MemoryDomain.ActiveDomain, &ept);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetMemoryDomainEptDescriptor", status);
        goto release_and_cleanup;
    }

    status = _VcpuSetEptp(ept, Vcpu->MemoryDomain.ActiveDomain->Index);

release_and_cleanup:
    HvReleaseSpinLock(&Vcpu->MemoryDomain.Lock);

    if (inconsistencyDetected) status = CX_STATUS_DATA_ALTERED_FROM_OUSIDE;
    return status;
}



CX_STATUS
VcpuDeactivateDomain(
    _In_ VCPU                           *Vcpu,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *DomainIndex // optional, used only for a sanity check
)
{
    GUEST_MEMORY_DOMAIN *domain = CX_NULL;
    if (DomainIndex)
    {
        CX_STATUS status = GstGetMemoryDomain(Vcpu->Guest, *DomainIndex, &domain);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstGetMemoryDomain", status);
            return status;
        }
    }
    return VcpuDeactivateDomainEx(Vcpu, domain, CX_FALSE);
}



CX_STATUS
VcpuGetActiveMemoryDomainIndex(
    _In_  VCPU                           *Vcpu,
    _Out_ GUEST_MEMORY_DOMAIN_INDEX *DomainIndex
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Vcpu->MemoryDomain.ActiveDomain) return CX_STATUS_COMPONENT_NOT_READY;
    if (!DomainIndex) return CX_STATUS_INVALID_PARAMETER_2;
    *DomainIndex = Vcpu->MemoryDomain.ActiveDomain->Index;
    return CX_STATUS_SUCCESS;
}



CX_STATUS
VcpuGetActiveEptDescriptor(
    _In_ VCPU                           *Vcpu,
    _Out_opt_ EPT_DESCRIPTOR             **Ept
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Vcpu->MemoryDomain.ActiveDomain) return CX_STATUS_COMPONENT_NOT_READY;
    GUEST_MEMORY_DOMAIN_INDEX index = Vcpu->MemoryDomain.ActiveDomain->Index;
    return GstGetEptDescriptorEx(Vcpu->Guest, index, Ept);
}



CX_STATUS
VcpuRefreshActiveMemoryDomain(
    _In_ VCPU *Vcpu
)
{
    CX_UINT64 actualRootPa;
    __vmx_vmread(VMCS_EPTP, &actualRootPa);
    actualRootPa = CX_PAGE_BASE_4K(actualRootPa);

    EPT_DESCRIPTOR *ept;
    CX_STATUS status = VcpuGetActiveEptDescriptor(Vcpu, &ept);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("VcpuGetActiveEptDescriptor", status);
        goto cleanup;
    }

    CX_UINT64 expectedRootPa;
    status = EptGetRootPa(ept, &expectedRootPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptGetRootPa", status);
        goto cleanup;
    }

    if (actualRootPa != expectedRootPa)
    {
        // this condition happens all the time when #VE is active, don't log and preferably, don't fail after receiving this error
        // this code MIGHT be useful at some point, if/when the currently active EPTP would be important throughout the exit handling
        status = CX_STATUS_INVALID_INTERNAL_STATE;
    }

cleanup:
    return status;
}
