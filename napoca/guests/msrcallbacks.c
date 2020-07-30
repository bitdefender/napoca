/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup hooks
/// @{

#include "kernel/kernel.h"
#include "guests/msrcallbacks.h"
#include "guests/guests.h"
#include "debug/dumpers.h"
#include "kernel/mtrr.h"
#include "memory/ept.h"

CX_STATUS
VirtMtrrReadCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64 *Value,
    _In_opt_ CX_VOID* Context
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    MTRR_STATE* mtrrState;

    UNREFERENCED_PARAMETER(Context);

    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;

    mtrrState = HvGetCurrentVcpu()->Mtrr;

    if (Msr == MSR_IA32_MTRRCAP) *Value = mtrrState->MtrrCapMsr;
    else if (Msr == MSR_IA32_MTRR_DEF_TYPE) *Value = mtrrState->MtrrDefMsr;
    else if (MtrrIsFixed(Msr))
    {
        status = MtrrGetFixedRangeValue(mtrrState, Msr, Value);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("MtrrGetFixedRangeValue", status);
    }
    else if (MtrrIsVariable(mtrrState, Msr))
    {
        status = MtrrGetVarRangeValue(mtrrState, Msr, Value);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("MtrrGetVarRangeValue", status);
    }
    else
    {
        LOG("Unknown MSR for MTRR: 0x%x, %s\n", Msr, ConvertMsrToString(Msr));
        status = STATUS_NO_HOOK_MATCHED;
    }

    return status;
}

CX_STATUS
VirtMtrrWriteCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    )
//
{
    CX_STATUS status;
    MTRR_STATE* vcpuMtrrState;
    GUEST* Guest;

    UNREFERENCED_PARAMETER(Context);

    status = CX_STATUS_SUCCESS;
    Guest = HvGetCurrentVcpu()->Guest;

    vcpuMtrrState = HvGetCurrentVcpu()->Mtrr;

    if (MtrrIsVariable(vcpuMtrrState, Msr))
    {
        CX_UINT32 index;
        MTRR_VAR_ENTRY* varEntry;
        CX_UINT64 oldValue;

        // check if new value != old value
        status = MtrrGetVarRangeValue(vcpuMtrrState, Msr, &oldValue);
        if (CX_SUCCESS(status) && (oldValue != Value))
        {
            //LOG("[CPU %d] Will update MSR: 0x%x, %s from: %p to: %p\n", HvGetCurrentApicId(), Msr, ConvertMsrToString(Msr), oldValue, Value);
            varEntry = MtrrGetVarRangeEntryAndIndex(vcpuMtrrState, Msr, &index);
            if (varEntry)
            {
                // is this a mask
                if ((Msr - MSR_IA32_MTRR_PHYSBASE0 - (2ULL * index)) != 0) varEntry->MaskMsr = Value;
                else varEntry->BaseMsr = Value;
            }
            else
            {
                status = CX_STATUS_INVALID_INTERNAL_STATE;
            }
        }
    }
    else if (MtrrIsFixed(Msr))
    {
        CX_UINT32 index, i;
        MTRR_FIX_ENTRY* fixEntry;
        CX_UINT64 oldValue;

        // check if new value != old value
        status = MtrrGetFixedRangeValue(vcpuMtrrState, Msr, &oldValue);
        if (CX_SUCCESS(status) && (oldValue != Value))
        {
            //LOG("[CPU %d] Will update MSR: 0x%x, %s from: %p to: %p\n", HvGetCurrentApicId(), Msr, ConvertMsrToString(Msr), oldValue, Value);
            // we need to update all 8 entries associated with this MTRR
            fixEntry = MtrrGetFixedRangeEntryAndIndex(vcpuMtrrState, Msr, &index);
            if (fixEntry)
            {
                for (i = 0; i < 8; i++)
                {
                    //LOG("[CPU %d] Will update MSR: 0x%x[0x%x], %s from: %p to: %p\n",
                    //    HvGetCurrentApicId(), Msr, i, ConvertMsrToString(Msr), (CX_UINT64)vcpuMtrrState->Fixed[index + i].Type, (CX_UINT64)((Value >> (i * 8)) & 0xFF));

                    vcpuMtrrState->Fixed[index + i].Type = (CX_UINT8)((Value >> (i * 8)) & 0xFF);
                }
            }
            else
            {
                status = CX_STATUS_INVALID_INTERNAL_STATE;
            }
        }
    }
    else if (Msr == MSR_IA32_MTRR_DEF_TYPE)
    {
        if (vcpuMtrrState->MtrrDefMsr != Value)
        {
            if ((0 == vcpuMtrrState->Enabled) && (0 != (Value & 0x800)))
            {
                // do this strictly when we switch the Enabled bit from 0 to 1
                HvInterlockedBitTestAndSetU64(&Guest->MtrrUpdateBitmaskActual, HvGetCurrentVcpu()->GuestCpuIndex);
            }

            //LOG("[CPU %d] Will update MSR: 0x%x, %s from: %p to: %p\n", HvGetCurrentApicId(), Msr, ConvertMsrToString(Msr), vcpuMtrrState->MtrrDefMsr, Value);
            vcpuMtrrState->MtrrDefMsr = Value;
        }
    }
    else if (Msr == MSR_IA32_MTRRCAP)
    {
        if (vcpuMtrrState->MtrrCapMsr != Value) vcpuMtrrState->MtrrCapMsr = Value;
    }
    else
    {
        LOG("Unknown MSR for MTRR: 0x%x, %s\n", Msr, ConvertMsrToString(Msr));
        status = STATUS_NO_HOOK_MATCHED;
    }

    // we expect every cpu to go through the update
    CX_UINT64 mtrrUpdateBitmaskRequired = FIELD_MASK(Guest->VcpuCount - 1);
    // Update EPT map based on MTRR updates
    // we assume that the guest operating system conforms to what
    // Intel SDM indicates at 11.11.8 MTRR Considerations in MP Systems
    if (
        CX_SUCCESS(status)
        && (Guest->MtrrUpdateBitmaskActual == mtrrUpdateBitmaskRequired)     // do we have a complete set of updates, from all CPUs?
        && (Guest->Mtrr->Enabled)                                                   // and MTRRs are enabled
        )
    {
        CX_UINT64 oldMaxPhysicalAddress;
        CX_UINT32 vcpuIndex;

        // in the event of a race condition, we ensure that only 1 CPU can proceed with the EPT map update
        if (mtrrUpdateBitmaskRequired != HvInterlockedCompareExchangeU64(&Guest->MtrrUpdateBitmaskActual, 0, mtrrUpdateBitmaskRequired)) goto cleanup;

        // make sure that the we have the entire physical range covered (based on BSP's MTRR state)
        status = MtrrUpdateMaxPhysicalAddressInState(Guest->Mtrr, &oldMaxPhysicalAddress);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MtrrUpdateMaxPhysicalAddressInState", status);
            goto cleanup;
        }

        // regenerate map from the guest's BSP MTRR state
        status = MtrrGenerateMapFromState(Guest->Mtrr);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MtrrGenerateMapFromState", status);
            goto cleanup;
        }

        // copy the MTRR state from the guest's BSP to all other VCPUs of the GUEST
        for (vcpuIndex = 1; vcpuIndex < Guest->VcpuCount; vcpuIndex++)
        {
            memcpy(Guest->Vcpu[vcpuIndex]->Mtrr, Guest->Mtrr, sizeof(MTRR_STATE));

            // do NOT generate MTRR map for all VCPUs for now
            Guest->Vcpu[vcpuIndex]->Mtrr->Map.MaxCount = 0;
            Guest->Vcpu[vcpuIndex]->Mtrr->Map.Count = 0;
            Guest->Vcpu[vcpuIndex]->Mtrr->Map.Entry = CX_NULL;
        }

        VCPULOG(HvGetCurrentVcpu(), "Update EPT tree to reflect MTTRs changes!\n");

        if (CfgDebugTraceMemoryMaps)
        {
            for (vcpuIndex = 0; vcpuIndex < Guest->VcpuCount; vcpuIndex++)
            {
                LOGN("\nVCPU[%d]:\n", Guest->Vcpu[vcpuIndex]->LapicId);
                if (vcpuIndex != 0) MmapDump(&Guest->Vcpu[vcpuIndex]->Mtrr->Map, BOOT_MEM_TYPE_AVAILABLE, CX_NULL);

                DumpersDumpMTRRSate(Guest->Vcpu[vcpuIndex]->Mtrr);
            }
        }

        GUEST_MEMORY_DOMAIN_INDEX totalDomains = GstGetMemoryDomainsCount(Guest);
        for (GUEST_MEMORY_DOMAIN_INDEX index = 0; index < totalDomains; index++)
        {
            EPT_DESCRIPTOR *ept;
            status = GstGetEptDescriptorEx(Guest, index, &ept);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("GstGetEptDescriptor", status);
                goto cleanup;
            }

            status = EptUpdateCachingFromMtrrs(ept, Guest->Mtrr);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("EptUpdateCacheWithMtrrsFast", status);
                goto cleanup;
            }
        }

        // invalidate EPT
        LOG("Blocking EPT invalidation!\n");
        EptInvalidateTlbs(Guest, CX_NULL, CX_TRUE); // blocking invalidation broadcast

        Guest->MtrrUpdateBitmaskActual = 0x0;

        VCPULOG(HvGetCurrentVcpu(), "EPT tree reflects MTTRs changes!\n");

        if (Guest->UseOsSigScan)
        {
            Guest->UseOsSigScan = CX_FALSE;
            VCPULOG(HvGetCurrentVcpu(), "Disabled OS signature scanning\n");
        }
    }

cleanup:

    return status;
}

CX_STATUS
VirtMsrReadTscCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64 *Value,
    _In_opt_ CX_VOID* Context
    )
{
    UNREFERENCED_PARAMETER(Msr);
    UNREFERENCED_PARAMETER(Context);

    *Value = HvGetCurrentVcpu()->VirtualTsc;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtMsrWriteTscCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    )
{
    UNREFERENCED_PARAMETER(Msr);
    UNREFERENCED_PARAMETER(Context);

    VCPU* vcpu = HvGetCurrentVcpu();
    CX_UINT64 tscOffset = 0;

    if ((BOOT_UEFI) &&
        (!(vcpu->Guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_EXPOSING_INTERFACE)) &&
        (vcpu->Guest->OsScanVerdict == OS_SCAN_WIN7) &&
        (!(vcpu->Guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_DO_NOT_TRY_TO_EXPOSE_INTERFACE)))
    {
        VCPULOG(vcpu, "Enable GuestEnlightments/exposing HV interface to WinGuest!\n");
        vcpu->Guest->MicrosoftHvInterfaceFlags |= MSFT_HV_FLAG_EXPOSING_INTERFACE;
    }

    vcpu->VirtualTsc = Value;

    tscOffset = vcpu->VirtualTsc - vcpu->LastExitTsc;

    vmx_vmwrite(VMCS_TSC_OFFSET, tscOffset);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtMsrWriteMiscEnable(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
    )
{
    UNREFERENCED_PARAMETER((Msr, Context, Value));

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_ProcessIdtAndUpdateOsSigScan(
        _Inout_     VCPU        *Vcpu
    )
{
    if (Vcpu->Guest->UseOsSigScan)
    {
        Vcpu->Guest->UseOsSigScan = CX_FALSE;
        VCPULOG(Vcpu, "Disabled OS signature scanning\n");
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtMsrWriteLstar(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER((Context, Msr));

    if (Value != 0)
    {
        CX_STATUS status = _ProcessIdtAndUpdateOsSigScan(HvGetCurrentVcpu());
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("_ProcessIdtAndUpdateOsSigScan", status);
    }

    return STATUS_NO_HOOK_MATCHED;
}

CX_STATUS
VirtMsrWriteSysEnter(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER((Context, Msr));

    if (Value != 0)
    {
        CX_STATUS status = _ProcessIdtAndUpdateOsSigScan(HvGetCurrentVcpu());
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("_ProcessIdtAndUpdateOsSigScan", status);
    }

    return STATUS_NO_HOOK_MATCHED;
}

CX_STATUS
VirtPerfCntWriteCallback(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER(Context);

    LOG("[CPU %d] For MSR: 0x%x, %s - ignore write (intended write value: 0x%016llX)\n", HvGetCurrentApicId(), Msr, ConvertMsrToString(Msr), Value);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtPerfCntReadCallback(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64* Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER(Context);

    *Value = 0;

    LOG("[CPU %d] For MSR: 0x%x, %s - ignore read (giving back: 0x%016llX)\n", HvGetCurrentApicId(), Msr, ConvertMsrToString(Msr), *Value);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtWritePowerAndPerf(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER(Context);

    if (CfgDebugTraceHwp)
    {
        VCPULOG(HvGetCurrentVcpu(), "Allow bare-metal writing of MSR 0x%x (%s) with value 0x%016llX\n", Msr, ConvertMsrToString(Msr), Value);
    }

    __writemsr((unsigned long)Msr, Value);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
VirtReadPowerAndPerf(
    _In_ CX_UINT64 Msr,
    _Out_ CX_UINT64* Value,
    _In_opt_ CX_VOID* Context
)
{
    UNREFERENCED_PARAMETER(Context);

    *Value = __readmsr((unsigned long)Msr);
    if (CfgDebugTraceHwp)
    {
        VCPULOG(HvGetCurrentVcpu(), "Allow bare-metal read of MSR 0x%x (%s) with value 0x%016llX\n",
            Msr, ConvertMsrToString(Msr), *Value);
    }

    return CX_STATUS_SUCCESS;
}

/// @}
