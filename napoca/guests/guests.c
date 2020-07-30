/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// GUESTS - GUEST definitions
#include "kernel/kernel.h"
#include "kernel/mtrr.h"
#include "guests/guests.h"
#include "memory/cachemap.h"
#include "introspection/intro_cb_wrappers.h"
#include "memory/hibernate_clients.h"
#include "guests/msrcallbacks.h"



///
/// @brief        Get an estimation of the memory resources used for defining all the memory domains (the actual mappings and their properties) of a guest
/// @param[in]    Guest                            Input #GUEST structure
/// @returns      the total number of bytes used as page table structures
///
CX_UINT64
GstGetDomainsMemoryConsumption(
    _In_ GUEST *Guest
)
{
    if (!Guest) return 0;
    CX_UINT64 totalMem = 0;
    GUEST_MEMORY_DOMAIN_INDEX domainsCount = GstGetMemoryDomainsCount(Guest);
    for (GUEST_MEMORY_DOMAIN_INDEX i = 0; i < domainsCount; i++)
    {
        EPT_DESCRIPTOR *ept;
        CX_STATUS status = GstGetEptDescriptorEx(Guest, i, &ept);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstGetEptDescriptor", status);
            // continue...
        }
        else
        {
            totalMem += EptGetStructuresSize(ept);
        }
    }
    return totalMem;
}


/// @brief Allocate and initialize the VCPU structure
///
/// @param[in]  Guest           The guest structure
/// @param[in]  VcpuIndex       Index of the VCPU to be initialized
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, VCPU allocated an initialized
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - VcpuIndex can not be greater then the VCPU count
/// @returns    OTHER                               - Internal error
static
CX_STATUS
_GstAllocAndPreinitVcpu(
    _In_ GUEST* Guest,
    _In_ CX_UINT32 VcpuIndex
    )
{
    VCPU* vcpu;
    CX_STATUS status;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (VcpuIndex >= Guest->VcpuCount) return CX_STATUS_INVALID_PARAMETER_2;

    status = HpAllocWithTagCore(&vcpu, sizeof(VCPU), TAG_VCPU);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore / VCPU", status);
        goto cleanup;
    }

    memzero(vcpu, sizeof(VCPU));

    Guest->Vcpu[VcpuIndex] = vcpu;

    status = VcpuPreinit(vcpu, Guest, VcpuIndex);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("VcpuPreinit", status);
        goto cleanup;
    }

cleanup:
    return status;
}


CX_STATUS
GstAllocAndPreinitGuest(
    _Out_ GUEST** Guest,
    _In_ CX_UINT32 VcpuCount
    )
{
    CX_STATUS status;
    GUEST* guest;
    CX_INT32 index;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if ((0 == VcpuCount) || (VcpuCount > gBootInfo->CpuCount))
    {
        if (VcpuCount)
        {
            HvPrint("Guest requires %d CPUs, but only %d available on the machine; please check buildconfig.h!",
                    VcpuCount, gBootInfo->CpuCount);
        }
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    //
    // currently only one guest supported
    index = 0;

    // allocate and map a GUEST structure (to 3T+ addresses)
    status = MmAllocMemEx(&gHvMm, sizeof(GUEST), TAG_GST, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &guest, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMemEx", status);
        goto cleanup;
    }
    MmRegisterVaInfo(guest, sizeof(GUEST), "Guest[%d]", index);

    // do some very basic pre-initializations on the guest
    memzero(guest, sizeof(GUEST));

    HvInitSpinLock(&guest->GlobalUpdate.InternalConsistencyLock, "GlobalUpdate.InternalConsistencyLock", guest);
    HvInitSpinLock(&guest->GlobalUpdate.Locks.Ept, "Locks.Ept", guest);
    HvInitSpinLock(&guest->GlobalUpdate.Locks.Reexec, "Locks.Reexec", guest);

    guest->Index = (CX_UINT16)index;

    gHypervisorGlobalData.Guest[index] = guest;
    HvInterlockedIncrementI32(&gHypervisorGlobalData.GuestCount);

    // allocate and pre-initialize all VCPUs
    guest->VcpuCount = VcpuCount;
    for (CX_UINT32 i = 0; i < guest->VcpuCount; i++)
    {
        status = _GstAllocAndPreinitVcpu(guest, i);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_GstAllocAndPreinitVcpu", status);
            goto cleanup;
        }
    }

    guest->Vcpu[0]->IsBsp = CX_TRUE;

    // initialize per-guest EMHV interface
    status = EmhvInitGenericPerGuestIface(guest);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EmhvInitGenericPerGuestIface", status);
        goto cleanup;
    }

    // allocate and pre-initialize MSR (4 x 1K + 2x 4K guard) bitmaps
    MM_SIZE_IN_BYTES msrBitmapSize = CX_PAGE_SIZE_4K;
    status = MmAllocMemEx(&gHvMm, msrBitmapSize, TAG_MSRBITMAP, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &guest->MsrBitmap, &guest->MsrBitmapPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMemEx", status);
        goto cleanup;
    }
    MmRegisterVaInfo(guest->MsrBitmap, msrBitmapSize, "Guest[%d]->MsrBitmap", index);

    memzero(guest->MsrBitmap, msrBitmapSize);

    //  allocate and pre-initialize IO (2 x 4K + 2 x 4K guard) bitmaps
    MM_SIZE_IN_BYTES ioBitmapSize = 2 * CX_PAGE_SIZE_4K;

    status = MmAllocMemEx(&gHvMm, ioBitmapSize, TAG_IOBITMAP, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &guest->IoBitmap, &guest->IoBitmapPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMemEx", status);
        goto cleanup;
    }
    MmRegisterVaInfo(guest->IoBitmap, ioBitmapSize, "Guest[%d]->IoBitmap", index);

    memzero(guest->IoBitmap, ioBitmapSize);

    // pre-initialize memory maps, MTRR and EPT related stuffs
    guest->Mtrr = CX_NULL;
    guest->MtrrUpdateBitmaskActual = 0;

    guest->PhysMap.MaxCount = 0;
    guest->PhysMap.Count = 0;
    guest->PhysMap.Entry = CX_NULL;

    //
    // Prepare memory domains for the guest (start with the two predefined ones)
    //

    if (VmxIsVmfuncAvailable())
    {
        status = MmAllocMemEx(&gHvMm, CX_PAGE_SIZE_4K, TAG_EPTP, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, &guest->EptpPage, &guest->EptpPagePa);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            return status;
        }
        MmRegisterVaInfo(guest->EptpPage, CX_PAGE_SIZE_4K, "EPTP");
        memzero(guest->EptpPage, CX_PAGE_SIZE_4K);
    }

    // create the (empty for now) predefined memory domains
    GUEST_MEMORY_DOMAIN_INDEX domainIndexes[] = { GuestPredefinedMemoryDomainIdPhysicalMemory, GuestPredefinedMemoryDomainIdSingleStepMemory };
    for (CX_UINT32 i = 0; i < ARRAYSIZE(domainIndexes); i++)
    {
        GUEST_MEMORY_DOMAIN_VMFUNC vmFuncPolicy = (domainIndexes[i] == GuestPredefinedMemoryDomainIdPhysicalMemory ? GUEST_MEMORY_DOMAIN_VMFUNC_ALLOW : GUEST_MEMORY_DOMAIN_VMFUNC_DENY);
        status = GstCreateMemoryDomain(guest, &domainIndexes[i], vmFuncPolicy, CX_NULL, CX_NULL, CX_NULL, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstCreateMemoryDomain", status);
            goto cleanup;
        }
    }

    // pre-initialize IO / MSR / EPT hooking support
    status = HkPreinitGuestHookTables(guest);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HkPreinitGuestHookTables", status);
        goto cleanup;
    }


    HvInitRecSpinLock(&guest->PauseVcpusLock, 16, "GUEST->PauseVcpusLock");

    HvInitRwSpinLock(&guest->Intro.IntroCallbacksLock, "IntroCallbacksLock", CX_NULL);
    DlEnableSpinlockOptions(&DW_SPINLOCK_HEADER(&guest->Intro.IntroCallbacksLock), DL_FLAG_SILENT_NOT_ON_TOP);

    guest->Intro.IntroEptCallback               = IntEPTViolationCallbackWrapper;
    guest->Intro.IntroMsrCallback               = IntMSRViolationCallbackWrapper;
    guest->Intro.IntroCallCallback              = IntIntroCallCallbackWrapper;
    guest->Intro.IntroTimerCallback             = IntIntroTimerCallbackWrapper;
    guest->Intro.IntroDescriptorTableCallback   = IntIntroDescriptorTableCallbackWrapper;
    guest->Intro.IntroCrCallback                = IntCrWriteCallbackWrapper;
    guest->Intro.IntroXcrCallback               = IntXcrWriteCallbackWrapper;
    guest->Intro.IntroBreakpointCallback        = IntBreakpointCallbackWrapper;
    guest->Intro.IntroEventInjectionCallback    = IntEventInjectionCallbackWrapper;


    // Microsoft Hypervisor Interface preinitialize for Guest
    {
        if (BOOT_UEFI) guest->UseOsSigScan = CX_TRUE;

        guest->MicrosoftHvInterfaceFlags =
            CfgFeaturesVirtualizationEnlightEnabled?MSFT_HV_FLAG_EXPOSING_INTERFACE:MSFT_HV_FLAG_DO_NOT_TRY_TO_EXPOSE_INTERFACE;

        // intended initialization for the hibernate comeback scenario, when hooking is not needed but guest doesn't suggest new
        // TSC page.
        guest->TscWorkaroundInit = CX_INTERLOCKED_ONCE_SUCCESSFUL;
    }

    guest->SipiCount = 1; // BSP will NOT receive a SIPI
    guest->SipiMask = 1;

    // everything done just fine
    *Guest = guest;
    if (!CX_SUCCESS(status)) status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

CX_STATUS
GstActivateGuest(
    _In_ GUEST* Guest,
    _In_ CX_BOOL MarkVcpusSchedulable
    )
{
    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (!BOOT_OPT_MULTIPROCESSOR)
    {
        CX_STATUS status = GstAssignVCpusToPCpus(Guest, MarkVcpusSchedulable);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstAssignVCpusToPCpus", status);
            return status;
        }
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
GstAssignVCpusToPCpus(
    _In_ GUEST* Guest,
    _In_ CX_BOOL MarkVcpusSchedulable
    )
{
    PCPU* cpu;
    VCPU* vcpu;

    // try to register all VCPUs into the scheduling list
    // first VCPU will be scheduled on physical BSP
    for (CX_UINT32 i = 0; i < Guest->VcpuCount; i++)
    {
        cpu = gHypervisorGlobalData.CpuData.Cpu[i];
        vcpu = Guest->Vcpu[i];

        if (!gHypervisorGlobalData.BootFlags.IsWakeup) cpu->Vcpu = vcpu;

        vcpu->AttachedPcpu = cpu;           // this will never be set to null

        vcpu->LapicId = cpu->Id;

        vcpu->VirtualTsc = vcpu->LinearTsc  = 0;

        vcpu->Schedulable = MarkVcpusSchedulable;

        LOG("[G%d] VCPU[%d] -> PCPU[%d] (ApicId=0x%x). VCPU initial TSC = %zu\n",
            Guest->Index, i, i, gHypervisorGlobalData.CpuData.Cpu[i]->Id, 0);
    }

    return CX_STATUS_SUCCESS;
}

STATUS
GstInitRipCache(
    _Out_ RIP_CACHE* Cache,
    _In_ CX_UINT32 MaxEntries
    )
{
    if ((MaxEntries == 0) || (MaxEntries > RIP_CACHE_MAX_ENTRIES)) return CX_STATUS_INVALID_PARAMETER_2;

    memzero(Cache, sizeof(RIP_CACHE));

    Cache->MaxEntries = MaxEntries;
    Cache->CurrentIndex = MaxEntries - 1;

    return CX_STATUS_SUCCESS;
}

STATUS
GstSearchRipInCache(
    _Inout_ RIP_CACHE* Cache,
    _In_ CX_UINT64 Rip,
    _Out_ CX_BOOL* FoundRip,
    _In_ CX_BOOL AddIfNotFound
)
{
    CX_BOOL bFound = CX_FALSE;

    for (CX_UINT32 i = 0; i < Cache->ValidEntries; ++i)
    {
        CX_UINT32 curIndex = (i + Cache->CurrentIndex) % (Cache->ValidEntries + 1);

        if (Cache->Entries[curIndex].Rip == Rip)
        {
            Cache->CurrentIndex = curIndex;

            bFound = CX_TRUE;
            break;
        }
    }

    if (!bFound && AddIfNotFound)
    {
        Cache->CurrentIndex = (Cache->CurrentIndex + 1) % Cache->MaxEntries;

        Cache->Entries[Cache->CurrentIndex].Rip = Rip;
        Cache->ValidEntries = CX_MIN(Cache->ValidEntries + 1, Cache->MaxEntries);
    }

    *FoundRip = bFound;

    return CX_STATUS_SUCCESS;
}


CX_STATUS
GstInitPhysMap(
    _In_ GUEST* Guest
)
{
    CX_STATUS status;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    // init from global physmap
    status = MmapCopyMap(&Guest->PhysMap,
        &gHypervisorGlobalData.MemInfo.PhysMap,
        gHypervisorGlobalData.MemInfo.HyperMap.MaxCount + gHypervisorGlobalData.MemInfo.GuestAreaMap.MaxCount + 100 // just a guess to be big enough
    );
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapCopyMap", status);
        goto cleanup;
    }

    // remove HV mem space
    status = MmapApplyFullMap(&Guest->PhysMap, &gHypervisorGlobalData.MemInfo.HyperMap, MMAP_SPLIT_AND_KEEP_NEW);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap / -HyperMap", status);
        goto cleanup;
    }

    // remove non-primary guest mem space
    status = MmapApplyFullMap(&Guest->PhysMap, &gHypervisorGlobalData.MemInfo.GuestAreaMap, MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap / -GuestAreaMap", status);
        MmapDump(&Guest->PhysMap, 0, "Guest->PhysMap ");
        MmapDump(&gHypervisorGlobalData.MemInfo.GuestAreaMap, 0, "gHypervisorGlobalData.GuestAreaMap ");
        goto cleanup;
    }

    // update DEST addresses - use 1:1 mapping for PG
    for (DWORD i = 0; i < Guest->PhysMap.Count; i++)
    {
        Guest->PhysMap.Entry[i].DestAddress = Guest->PhysMap.Entry[i].StartAddress;
    }

    if (CfgFeaturesHibernatePersistance)
    {
        status = HvHibInitialize(Guest);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HvHibInitialize", status);
            goto cleanup;
        }

        if (CfgFeaturesVirtualizationEnlightEnabled)
        {
            status = HvHibRegisterClient(Guest, HvHibGuestEnlightGetData, HvHibGuestEnlightPutData, sizeof(GUEST_ENLIGHT_SAVE_DATA));
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HvHibRegisterClient", status);
                goto cleanup;
            }
        }

        status = HvHibRegisterClient(Guest, HvHibGuestBarReconfGetData, HvHibGuestBarReconfPutData, sizeof(GUEST_BAR_RECONF_SAVE_DATA));
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HvHibRegisterClient", status);
            goto cleanup;
        }
    }

cleanup:

    return status;
}



CX_STATUS
GstInitMtrrs(
    _In_ GUEST* Guest
)
{
    CX_STATUS status;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    for (CX_UINT64 i = 0; i < Guest->VcpuCount; i++)
    {
        status = HpAllocWithTagCore(&(Guest->Vcpu[i]->Mtrr), sizeof(MTRR_STATE), TAG_MTRR);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTagCore / MTRR_STATE", status);
            goto cleanup;
        }

        // copy from host
        memcpy(Guest->Vcpu[i]->Mtrr, &gHypervisorGlobalData.MemInfo.MtrrState, sizeof(MTRR_STATE));

        // do NOT generate MTRR map for all VCPUs
        Guest->Vcpu[i]->Mtrr->Map.MaxCount = 0;
        Guest->Vcpu[i]->Mtrr->Map.Count = 0;
        Guest->Vcpu[i]->Mtrr->Map.Entry = CX_NULL;
    }

    // set the guest MTRR state to the state of the "virtual BSP" MTRR state to be Guest->Vcpu[0]
    Guest->Mtrr = Guest->Vcpu[0]->Mtrr;

    // generate MTRR based map  (this will also be called at each update of the MTRR registers)
    status = MtrrGenerateMapFromState(Guest->Mtrr);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MtrrGenerateMapFromState", status);
        goto cleanup;
    }

    if (CfgDebugTraceMemoryMaps) MmapDump(&Guest->Mtrr->Map, BOOT_MEM_TYPE_AVAILABLE, "Mtrr->Map ");

cleanup:
    return status;
}


CX_STATUS
GstSetupVcpus(
    _In_ GUEST* Guest
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    VCPU* vcpu;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    for (CX_UINT32 i = 0; i < Guest->VcpuCount; i++)
    {
        vcpu = Guest->Vcpu[i];

        // add all CPU specific resources under VCPU[0]
        if (i == 0)    /// only set up for VCPU 0
        {
            if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
            {
                status = HkSetMsrHook(Guest, MSR_IA32_PERF_GLOBAL_CTRL, MSR_IA32_PERF_GLOBAL_CTRL, 0, VirtPerfCntReadCallback, VirtPerfCntWriteCallback, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERF_GLOBAL_CTRL", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PERF_GLOBAL_STATUS_RESET, MSR_IA32_PERF_GLOBAL_STATUS_RESET, 0, VirtPerfCntReadCallback, VirtPerfCntWriteCallback, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERF_GLOBAL_STATUS_RESET", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PERFEVTSEL0, MSR_IA32_PERFEVTSEL0, 0, VirtPerfCntReadCallback, VirtPerfCntWriteCallback, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERFEVTSEL0", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PERF_GLOBAL_CTRL, MSR_IA32_PERF_GLOBAL_CTRL, 0, VirtPerfCntReadCallback, VirtPerfCntWriteCallback, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERF_GLOBAL_CTRL", status);
                    goto cleanup;
                }
            }

            // create resources for MTRR MSRs
            status = HkSetMsrHook(Guest, MSR_IA32_MTRRCAP, MSR_IA32_MTRRCAP, 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRRCAP", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MTRR_DEF_TYPE, MSR_IA32_MTRR_DEF_TYPE, 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRR_DEF_TYPE", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MTRR_PHYSBASE0, (CX_UINT32)(MSR_IA32_MTRR_PHYSBASE0 + (2 * vcpu->Mtrr->VarCount) - 1), 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRR_PHYSBASE0 - MSR_IA32_MTRR_PHYSBASE0++", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MTRR_FIX64K_00000, MSR_IA32_MTRR_FIX64K_00000, 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRR_FIX64K_00000", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000, 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRR_FIX16K_80000 - MSR_IA32_MTRR_FIX16K_A0000", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MTRR_FIX4K_C0000, MSR_IA32_MTRR_FIX4K_F8000, 0, VirtMtrrReadCallback, VirtMtrrWriteCallback, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MTRR_FIX4K_C0000 - MSR_IA32_MTRR_FIX4K_F8000", status);
                goto cleanup;
            }

            // always intercept this msr - do not allow guest to write to physical TSC
            {
                status = HkSetMsrHook(Guest, MSR_IA32_TSC, MSR_IA32_TSC, 0, VirtMsrReadTscCallback, VirtMsrWriteTscCallback, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_TSC", status);
                    goto cleanup;
                }
            }

            // hook SYSENTER / LSTAR, potentially unnecessary
            status = HkSetMsrHook(Guest, MSR_IA32_LSTAR, MSR_IA32_LSTAR, 0, CX_NULL, VirtMsrWriteLstar, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_LSTAR", status);
                goto cleanup;
            }
            status = HkSetMsrHook(Guest, MSR_IA32_SYSENTER_RIP, MSR_IA32_SYSENTER_RIP, 0, CX_NULL, VirtMsrWriteSysEnter, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_SYSENTER_RIP", status);
                goto cleanup;
            }

            status = HkSetMsrHook(Guest, MSR_IA32_MISC_ENABLE, MSR_IA32_MISC_ENABLE, 0, CX_NULL, VirtMsrWriteMiscEnable, CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_MISC_ENABLE", status);
                goto cleanup;
            }

            // power and performance
            if (CfgDebugInterceptHwp)
            {
                status = HkSetMsrHook(Guest, MSR_IA32_PERF_STATUS, MSR_IA32_PERF_CTL, 0, VirtReadPowerAndPerf, VirtWritePowerAndPerf, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERF_STATUS - MSR_IA32_PERF_CTL", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PERF_ENERGY_BIAS, MSR_IA32_PERF_ENERGY_BIAS, 0, VirtReadPowerAndPerf, VirtWritePowerAndPerf, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PERF_ENERGY_BIAS", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PM_ENABLE, MSR_IA32_HWP_STATUS, 0, VirtReadPowerAndPerf, VirtWritePowerAndPerf, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PM_ENABLE - MSR_IA32_HWP_STATUS", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_THERM_STATUS, MSR_IA32_THERM_STATUS, 0, VirtReadPowerAndPerf, VirtWritePowerAndPerf, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_THERM_STATUS", status);
                    goto cleanup;
                }

                status = HkSetMsrHook(Guest, MSR_IA32_PPERF, MSR_IA32_PPERF, 0, VirtReadPowerAndPerf, VirtWritePowerAndPerf, CX_NULL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HkSetMsrHook / MSR_IA32_PPERF", status);
                    goto cleanup;
                }
            }
        }

        // Initialize the FPU state zone for this VCPU
        status = MmAllocMem(&gHvMm, HvGetCurrentCpu()->FpuSaveSize, TAG_EXT, (MM_ALIGNED_VA*)&vcpu->ExtState);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMem / CPU_EXT_STATE", status);
            return status;
        }

        memset(vcpu->ExtState, 0, HvGetCurrentCpu()->FpuSaveSize);
        CpuSaveFloatingState(vcpu->ExtState); // save a valid state taken from host

        vcpu->LapicId = gHypervisorGlobalData.CpuData.Cpu[i]->Id;

        vcpu->UsedExitReasonEntries = 0;
        vcpu->LastExitReasonIndex = (CX_UINT32)-1;
    }

cleanup:

    return status;
}

CX_STATUS
GstGetVcpuMode(
    _In_ VCPU* Vcpu,
    _Out_ CX_UINT8* OperatingMode
    )
{
    CX_UINT64 csAccess;
    CX_UINT8 csL, csD, bOperatingMode;

    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &csAccess);
    csL = (csAccess >> 13) & 1; // cs.L bit
    csD = (csAccess >> 14) & 1; // cs.D bit

    if ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA) != 0)
    {
        if (csL == 1)
        {
            // If L bit of the code segment descriptor is 1, we have a 64-bit code segment
            bOperatingMode = ND_CODE_64;
        }
        else
        {
            // If L bit is 0, we have compatibility mode segment; check D bit to get default operand size
            if (csD == 0)
            {
                // D bit 0 => 16 bit compatibility mode
                bOperatingMode = ND_CODE_16;
            }
            else
            {
                // D bit 1 => 32 bit compatibility mode
                bOperatingMode = ND_CODE_32;
            }
        }
    }
    else if ((Vcpu->ArchRegs.CR0 & CR0_PE) != 0)
    {
        if (csD == 0) bOperatingMode = ND_CODE_16;
        else bOperatingMode = ND_CODE_32;
    }
    else
    {
        if (csD == 0) bOperatingMode = ND_CODE_16;
        else bOperatingMode = ND_CODE_32;
    }

    if (OperatingMode) *OperatingMode = bOperatingMode;

    return CX_STATUS_SUCCESS;
}

static
__forceinline
CX_STATUS
_GstUpdAcquireLock(
    _In_ GST_UPDATE_REASON UpdateReason,
    _In_ GST_UPDATE_REASON WriteReason,
    _In_ volatile CX_UINT32 *Counter,
    _In_ SPINLOCK *Lock,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    if ((UpdateReason & WriteReason) && (CxInterlockedIncrement32(Counter) == 1))
    {
        HvAcquireSpinLock2(Lock, File, Line);
        HvInterlockedOrU32(Counter, 0x80000000);
    }
    else if (UpdateReason & WriteReason)
    {
        CX_UINT32 bk = *Counter;
        if (!(bk & 0x80000000))
        {
            ERROR("%s:%d trying to acquire lock while the counter=%X has already been increased without the lock being acquired!\n", File, Line, bk);
            return CX_STATUS_SYNCHRONIZATION_INCONSISTENCY;
        }
    }
    return CX_STATUS_SUCCESS;
}


static
__forceinline
CX_STATUS
_GstUpdReleaseLock(
    _In_ GST_UPDATE_REASON UpdateReason,
    _In_ GST_UPDATE_REASON WriteReason,
    _In_ volatile CX_UINT32 *Counter,
    _In_ SPINLOCK *Lock,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    if ((UpdateReason & WriteReason) && (0x80000000 == CxInterlockedDecrement32(Counter)))
    {
        HvInterlockedAndU32(Counter, 0x7fffffff);
        HvReleaseSpinLock2(Lock, File, Line);
    }
    return CX_STATUS_SUCCESS;
}


CX_STATUS
GstBeginUpdateEx2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_MODE UpdateMode,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
//
// Acquire exclusive lock and/or pause the guest for applying atomic changes
//
{
    VCPU* vcpu = HvGetCurrentVcpu();
    if (!Guest || !vcpu || !vcpu->ExitCount) return CX_STATUS_SUCCESS;

    if (Guest != vcpu->Guest)
    {
        ERROR("GstBeginUpdateEx is not supported for a remote/different guest\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    CX_STATUS status = CX_STATUS_SUCCESS;

    status = _GstUpdAcquireLock(Reason, _GST_UPDATE_REASON_EPT_LOCK, &vcpu->SynchronizedUpdate.Ept, &Guest->GlobalUpdate.Locks.Ept, File, Line);
    if (!CX_SUCCESS(status))
    {
        ERROR("%s:%d _GstUpdAcquireLock: %s\n", File, Line, NtStatusToString(status));
        return status;
    }

    status = _GstUpdAcquireLock(Reason, _GST_UPDATE_REASON_REEXEC_LOCK, &vcpu->SynchronizedUpdate.Reexec, &Guest->GlobalUpdate.Locks.Reexec, File, Line);
    if (!CX_SUCCESS(status))
    {
        ERROR("%s:%d _GstUpdAcquireLock: %s\n", File, Line, NtStatusToString(status));
        return status;
    }
    GstUpdateRememberReasons(Guest, Reason);

    if (!(UpdateMode & GST_UPDATE_MODE_PAUSED)) return CX_STATUS_SUCCESS;


    // check if current vcpu is just getting in a transaction
    if (CxInterlockedIncrement32(&vcpu->CalledGstPauseCount) == 1)
    {
        HvAcquireSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
        if (CxInterlockedIncrement64(&Guest->GlobalUpdate.PausedCount) == 1)
        {
            PerfAccountTransition(&Guest->PausingStats[VCPU_PAUSING_STATE_RUNNING], Guest->LastPauseTransitionTsc, &Guest->LastPauseTransitionTsc);

            // if this vcpu is the first one to take part in the transaction we need to get all cpus out of the guest
            status = HvPauseVcpus(Guest, VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_VCPU(vcpu), CX_TRUE);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("HvPauseVcpus", status);
            }
        }
        HvReleaseSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
    }

    return status;
}


static
__forceinline
CX_STATUS
_GstUpdateFlushAtResume(
    _In_ GUEST* Guest,
    _In_ CX_BOOL IsGuestPaused
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    if (Guest->GlobalUpdate.Reasons & _GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST)
    {
        // don't wait for invalidation when the guest is paused as all cpus will process their queues before resuming guest execution
        status = EptInvalidateTlbs(Guest, EPT_INVD_ANY_CONTEXT, IsGuestPaused? CX_FALSE : CX_TRUE);
    }

    Guest->GlobalUpdate.Reasons = 0;
    return status;
}


CX_STATUS
GstEndUpdateEx2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_MODE UpdateMode,                    // correlate with the UpdateMode of the paired GstBeginUpdateEx call
    _In_ GST_UPDATE_REASON Reason,
    _In_opt_ CX_BOOL IgnoreVcpuPauseNestingWhenResuming, // ignored when UpdateMode doesn't contain GST_UPDATE_MODE_PAUSED
    _In_ char *File,
    _In_ CX_UINT32 Line
)
//
// Release exclusive lock and/or resume guest execution after applying some atomic changes
//
{
    VCPU* vcpu = HvGetCurrentVcpu();
    if (!Guest || !vcpu || !vcpu->ExitCount) return CX_STATUS_SUCCESS;

    if (Guest != vcpu->Guest)
    {
        ERROR("GstEndUpdateEx is not supported for a remote/different guest\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    GstUpdateRememberReasons(Guest, Reason);

    // apply pending changes kept for when execution is resumed, there are two cases:
    // 1) guest is paused => before unpausing, the last vcpu (whoever that is, maybe ourselves when actually unpausing the guest) will apply any such changes
    // 2) guest is NOT paused => current cpu will apply before resuming guest execution
    // note: if 2) looks true but someone is just pausing the guest, the operations might be applied twice
    if ( (Reason & GST_UPDATE_REASON_RESUME_EXECUTION) && (Guest->GlobalUpdate.Reasons & _GST_UPDATE_REASON_POSTPONED_OPERATIONS_MASK) )
    {
        HvAcquireSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
        if (
                !Guest->GlobalUpdate.PausedCount &&
                ((Reason & GST_UPDATE_REASON_RESUME_EXECUTION) && (Guest->GlobalUpdate.Reasons & _GST_UPDATE_REASON_POSTPONED_OPERATIONS_MASK))
           )
        {
            // 2) guest is NOT paused => current cpu will apply before resuming guest execution
            CX_STATUS flushStatus = _GstUpdateFlushAtResume(Guest, CX_FALSE);
            if (!CX_SUCCESS(flushStatus)) LOG_FUNC_FAIL("_GstUpdateFlushAtResume", flushStatus);
        }
        // otherwise the last to unpause will perform the flush
        HvReleaseSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
    }

    CX_STATUS status;
    status = _GstUpdReleaseLock(Reason, GST_UPDATE_REASON_REEXEC_CHANGES, &vcpu->SynchronizedUpdate.Reexec, &Guest->GlobalUpdate.Locks.Reexec, File, Line);
    if (!CX_SUCCESS(status))
    {
        ERROR("%s:%d _GstUpdReleaseLock: %s\n", File, Line, NtStatusToString(status));
        return status;
    }
    status = _GstUpdReleaseLock(Reason, GST_UPDATE_REASON_EPT_READ | GST_UPDATE_REASON_EPT_CHANGES, &vcpu->SynchronizedUpdate.Ept, &Guest->GlobalUpdate.Locks.Ept, File, Line);
    if (!CX_SUCCESS(status))
    {
        ERROR("%s:%d _GstUpdReleaseLock: %s\n", File, Line, NtStatusToString(status));
        return status;
    }

    if (!(UpdateMode & GST_UPDATE_MODE_PAUSED) || (IgnoreVcpuPauseNestingWhenResuming && !vcpu->CalledGstPauseCount)) return CX_STATUS_SUCCESS;

    if (IgnoreVcpuPauseNestingWhenResuming || !CxInterlockedDecrement32(&vcpu->CalledGstPauseCount))
    {
        HvAcquireSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
        if (!CxInterlockedDecrement64(&Guest->GlobalUpdate.PausedCount))
        {
            // 1) guest is paused => before unpausing, the last vcpu (us/we) will apply any such changes
            if (Guest->GlobalUpdate.Reasons & _GST_UPDATE_REASON_POSTPONED_OPERATIONS_MASK)
            {
                CX_STATUS flushStatus = _GstUpdateFlushAtResume(Guest, CX_TRUE);
                if (!CX_SUCCESS(flushStatus))
                {
                    LOG_FUNC_FAIL("_GstUpdateFlushAtResume", flushStatus);
                }
            }

            // this vcpu was the last to exit the active transaction
            status = HvResumeVcpus(Guest, VCPU_AFFINITY_ALL_INCLUDING_SELF_BY_VCPU(vcpu));
            if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("HvResumeVcpus", status);

            PerfAccountTransition(&Guest->PausingStats[VCPU_PAUSING_STATE_PAUSED], Guest->LastPauseTransitionTsc, &Guest->LastPauseTransitionTsc);
        }

        vcpu->CalledGstPauseCount = 0;
        HvReleaseSpinLock(&Guest->GlobalUpdate.InternalConsistencyLock);
    }

    return CX_STATUS_SUCCESS;
}


static
CX_STATUS
_GstPostponeDomainInvalidation(
    _In_ EPT_DESCRIPTOR                 *EptDescriptor,
    _In_ CX_VOID                        *Guest
)
{
    UNREFERENCED_PARAMETER(EptDescriptor);
    GstUpdateRememberReasons(Guest, _GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST);
    return CX_STATUS_SUCCESS;
}


///
/// @brief        Checks if 1GiB pages can and should be used for a given EPT
/// @param[in]    IsSingleStepEpt true if this is the guest memory domain (the EPT) used for single-step instruction execution
/// @returns      TRUE in case the feature is available and should be activated, FALSE otherwise
///
static
__forceinline
CX_BOOL
_GstDomainShouldUse1GPages(
    _In_ GUEST_MEMORY_DOMAIN_INDEX          DomainIndex
)
{
    return (CfgFeaturesVirtualizationSingleStepUsingLargePages && VmxIsEpt1GPagesFeatureAvailable() && DomainIndex == GuestPredefinedMemoryDomainIdSingleStepMemory && !(HvGetCurrentCpu()->HasRepGranularityBug));
}


///
/// @brief        Create a new memory domain (a custom memory view) for a given #GUEST
/// @param[in]    Guest                            Guest that should own the new domain
/// @param[in]    WantedDomainIndex                NULL or else, if the domain is one of the predefined ones, a pointer to a domain index value
/// @param[in]    VmFuncPolicy                     true if this domain is an allowed VMFUNC memory target
/// @param[in]    InitFromThisMemoryMap            Optional, the new domain should map all the memory described in this #MMAP structure
/// @param[in]    CopyThisDomain                   Optional, the new domain should copy the memory mappings (access rights included) of an already existing memory domain, overwriting if needed any of the mappings detemined by the WantedDomainIndex parameter
/// @param[out]   Domain                           Optional output pointer to receive the address of the newly created domain
/// @param[out]   ResultedDomainIndex              Optional output argument to return the internal domain index of the new domain
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - The Guest pointer is NULL
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - Safely updating the guest's memory domains has failed due to some unforseen synchronization issue or memory corruption
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - The WantedDomainIndex doesn't select one of the predefined domains
/// @returns      CX_STATUS_OUT_OF_RESOURCES       - There is no room for a new domain
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
GstCreateMemoryDomain(
    _In_ GUEST                          *Guest,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *WantedDomainIndex,
    _In_ GUEST_MEMORY_DOMAIN_VMFUNC     VmFuncPolicy,
    _In_opt_ MMAP                       *InitFromThisMemoryMap,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *CopyThisDomain,
    __out_opt GUEST_MEMORY_DOMAIN       **Domain,
    __out_opt GUEST_MEMORY_DOMAIN_INDEX *ResultedDomainIndex
)
{
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;
    CX_BOOL newAllocatedIndex = CX_FALSE;
    GUEST_MEMORY_DOMAIN_INDEX domainIndex = MAX_TOTAL_DOMAINS_COUNT; // invalid value
    if (WantedDomainIndex)
    {
        // allow the operation only for the static, predefined domains, dynamic domains should be managed here and not by external code
        if (*WantedDomainIndex >= GuestPredefinedMemoryDomainIdValues) return CX_STATUS_OPERATION_NOT_SUPPORTED;
        domainIndex = *WantedDomainIndex;
    }
    else
    {
        // take one of the dynamic domains still available
        CX_UINT8 tryIndex;
        do
        {
            tryIndex = Guest->DynamicDomainsCount;
            if (tryIndex >= MAX_DYNAMIC_DOMAINS_COUNT) return CX_STATUS_OUT_OF_RESOURCES;
        } while (tryIndex != CxInterlockedCompareExchange8(&Guest->DynamicDomainsCount, tryIndex + 1, tryIndex));
        newAllocatedIndex = GuestPredefinedMemoryDomainIdValues + tryIndex;
        domainIndex = GuestPredefinedMemoryDomainIdValues + tryIndex;
    }

    // the domainIndex value has been validated both on the static and dynamic cases, it can't be invalid at this point
    if (domainIndex >= MAX_TOTAL_DOMAINS_COUNT) return CX_STATUS_INVALID_INTERNAL_STATE;

    GUEST_MEMORY_DOMAIN *domain = &Guest->MemoryDomains[domainIndex];
    EPT_DESCRIPTOR newEpt = { 0 };

    CX_BOOL singleStepUse1GPages = _GstDomainShouldUse1GPages(domainIndex);
    CX_STATUS status = EptInitDescriptor(&newEpt, _GstPostponeDomainInvalidation, Guest, singleStepUse1GPages);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptInitDescriptor", status);
        goto cleanup;
    }
    if (singleStepUse1GPages) Guest->SingleStepUsing1GEpt = CX_TRUE;

    if (InitFromThisMemoryMap)
    {
        status = EptCopyTranslationsFromMemoryMap(&newEpt, InitFromThisMemoryMap);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("EptCopyTranslationsFromMemoryMap", status);
            goto cleanup;
        }
    }

    if (CopyThisDomain)
    {
        EPT_DESCRIPTOR *srcEpt;
        status = GstGetEptDescriptorEx(Guest, *CopyThisDomain, &srcEpt);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstGetEptDescriptorEx", status);
            goto cleanup;
        }
        status = EptCopyTranslations(&newEpt, srcEpt);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("EptCopyTranslations", status);
            goto cleanup;
        }
    }

    if (VmFuncPolicy == GUEST_MEMORY_DOMAIN_VMFUNC_ALLOW && VmxIsVmfuncAvailable())
    {
        domain->AllowVmfunc = CX_TRUE;
        MEM_ALIGNED_PA rootPa;
        status = EptGetRootPa(&newEpt, &rootPa);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("EptGetRootPa", status);
            goto cleanup;
        }
        Guest->EptpPage[domainIndex] = rootPa | 0x1E;
    }

cleanup:
    if (CX_SUCCESS(status))
    {
        domain->Ept = newEpt;
        domain->Index = domainIndex;
        domain->Initialized = CX_TRUE;

        if (Domain) *Domain = domain;
        if (ResultedDomainIndex) *ResultedDomainIndex = domainIndex;
        LOG("Memory domain with rootPa=%p at index = %d was created!\n", domain->Ept.Tas.RootPa, domain->Index);
    }
    else if (newAllocatedIndex)
    {
        // try to reverse the change if no one took a new index since
        if (newAllocatedIndex - 1 != CxInterlockedCompareExchange8(&Guest->DynamicDomainsCount, newAllocatedIndex, newAllocatedIndex - 1))
        {
            WARNING("GstCreateMemoryDomain has failed and left an empty & unusable guest memory domain entry!\n");
        }
        EptDestroy(&newEpt);
    }

    return status;
}



///
/// @brief        Tear-down the mapping structures (page tables) and unregister the given memory domain from a guest
/// @param[in]    Guest                            The #GUEST owning the memory domain
/// @param[in]    DomainIndex                      The domain, given by it's index
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Guest can not be NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
GstDestroyMemoryDomain(
    _In_ GUEST                          *Guest,
    _In_ GUEST_MEMORY_DOMAIN_INDEX      DomainIndex
)
{
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST_MEMORY_DOMAIN *domain;
    CX_STATUS status = GstGetMemoryDomain(Guest, DomainIndex, &domain);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetMemoryDomain", status);
        goto cleanup;
    }

    domain->Initialized = CX_FALSE; // TODO(?): if this operation would be executed frequently, an actual lock would be needed here
    status = EptDestroy(&domain->Ept);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptDestroy", status);
        goto cleanup;
    }

    if (VmxIsVmfuncAvailable()) Guest->EptpPage[domain->Index] = 0;

    memzero(domain, sizeof(*domain));

    // try to decrease the number of registered domains IFF the freed index was the very last allocated (dynamic) domain
    if (DomainIndex >= GuestPredefinedMemoryDomainIdValues)
    {
        GUEST_MEMORY_DOMAIN_INDEX dynamicIndex = DomainIndex - GuestPredefinedMemoryDomainIdValues;
        // the current expected dynamic domain count should be 1 greater than the dynamic index => if we set it to the index value we're reducing it by one
        if (dynamicIndex + 1 != CxInterlockedCompareExchange8(&Guest->DynamicDomainsCount, dynamicIndex, dynamicIndex + 1))
        {
            WARNING("GstDestroyMemoryDomain has failed to reclaim a dynamic memory domain index of a freed domain!\n");
        }
    }

cleanup:
    return status;
}



///
/// @brief        Print detailed info about the guest physical memory available to a #GUEST as seen through each of its memory domains
/// @param[in]    Guest                            Input #GUEST structure to process
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Guest cannot be NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS
GstDumpMemoryDomains(
    _In_ GUEST *Guest
)
{
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;

    for (GUEST_MEMORY_DOMAIN_INDEX i = 0; i < GstGetMemoryDomainsCount(Guest); i++)
    {
        EPT_DESCRIPTOR *ept = GstGetEptDescriptor(Guest, i);
        if (!ept) continue;
        MEM_ALIGNED_PA rootPa;
        CX_STATUS status = EptGetRootPa(ept, &rootPa);
        if (!CX_SUCCESS(status)) continue;

        LOG("Mappings for the guest memory domain[%d] with rootPa=%p:\n", i, rootPa);
        EptDumpMappings(ept);
    }

    return CX_STATUS_SUCCESS;
}
