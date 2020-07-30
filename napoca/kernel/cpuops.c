/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpuops.c
*   @brief CPUOPS - macro wrappers and prototypes for intrinsics and plain assembler CPU operations
*
*/

#include "napoca.h"
#include "kernel/kernel.h"

CX_UINT16
CpuGetBootIndexForLocalApicId(
    _In_ CX_UINT32 LapicId
    )
{
    CX_UINT16 cpuIndex;
    CX_UINT16 i;
    cpuIndex = 0xFFFF;

    // locate local APIC ID in gBootInfo to get AP index
    for (i = 0; i < gBootInfo->CpuCount; i++)
    {
        if (LapicId == gBootInfo->CpuMap[i].Id)
        {
            cpuIndex = i;
            break;
        }
    }

    if (0xFFFF == cpuIndex)
    {
        // it should not happen, but it would be critical
        HvPrint("[CPU %d] CRITICAL: local APIC id of AP not found in gBootInfo[], halt\n", LapicId);
        HvHalt();

        return 0; // this function isn't expecting DbgEnterDebugger to return back the control

    }

    return cpuIndex;
}

// turn of compiler optimizations
#pragma optimize("", off)

// Neither this function, nor the function it calls does IPC processing, so no need to block IPCs
void
CpuSaveFloatingArea(
    _In_ VCPU* Vcpu
    )
{
    PCPU *cpu = HvGetCurrentCpu();

    if (Vcpu->RestoreExtState)
    {
        // The state was already saved, do not contaminate it
        return;
    }

    // disable emulation for floating point operations
    __writecr0(__readcr0() & ~CR0_EM);

    if (cpu->UseXsave)
    {
        // save the guest's XCR0
        Vcpu->ArchRegs.XCR0 = __xgetbv(0);

        // set XCR0 to the host value, to force saving a complete FX state
        __xsetbv(0, cpu->Xcr0AvailMask);
    }

    CpuSaveFloatingState(Vcpu->ExtState);
    Vcpu->RestoreExtState = CX_TRUE;           // mark that we need to restore the fx state when we re-enter the guest

    FpuSseInit();

    _mm_setcsr(cpu->HostMxcsr);
}

// turn back on compiler optimizations
#pragma optimize("", on)

// turn of compiler optimizations
#pragma optimize("", off)
void
CpuRestoreFloatingArea(
    _In_ VCPU* Vcpu
    )
{
    if (Vcpu->RestoreExtState)
    {
        CpuRestoreFloatingState(Vcpu->ExtState);

        if (HvGetCurrentCpu()->UseXsave)
        {
            // restore the guest's XCR0
            __xsetbv(0, Vcpu->ArchRegs.XCR0 | 1ULL);
        }

        Vcpu->RestoreExtState = CX_FALSE;

        // also, from now on, do not allow any execution of floating point instructions,
        // and request exception to be generated on such attempt
        __writecr0(__readcr0() | CR0_EM);
    }
}
// turn back on compiler optimizations
#pragma optimize("", on)


///
/// @brief        Invalidate cached mappings of address translation based on VPID, routine implemented in assembly.
///
/// @param[in]    Type                             The type of the invalidation
/// @param[in]    LinearAddress                    The linear address of which translation is invalidated
/// @param[in]    Vpid                             The actual VPID for which the invalidation happens
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      ERROR_STATUS                     - in case the INVVPID failed
///
CX_STATUS
CpuVmxInvVpid_(
    _In_ CX_UINT64 Type,
    _In_ CX_VOID *LinearAddress,
    _In_ CX_UINT64 Vpid
    );

CX_STATUS
CpuVmxInvVpid(
    _In_ CX_UINT64 Type,
    _In_ CX_VOID *LinearAddress,
    _In_ CX_UINT64 Vpid
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    VCPU* vcpu = HvGetCurrentVcpu();
    static CX_UINT64 invalidationCount = 0;

    if (!vcpu) return CX_STATUS_INVALID_INTERNAL_STATE;

    if ((VmxIsInvVpidSupported()) && (vcpu->VmcsConfig.ProcExecCtrl2 & VMCSFLAG_PROCEXEC2_ENABLE_VPID) != 0)
    {
        switch (Type)
        {
        case 0:
            status = VmxIsInvVpidAddressInvalidationSupported() ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        case 1:
            status = VmxIsInvVpidSingleContextInvalidationSupported() ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        case 2:
            status = VmxIsInvVpidAllContextInvalidationSupported() ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        case 3:
            status = VmxIsInvVpidAllContextRetGlobalsInvalidationSupported() ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        default:
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        if (CX_SUCCESS(status))
        {
            status = CpuVmxInvVpid_(Type, LinearAddress, Vpid);
            if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("CpuVmxInvVpid_", status);
        }
        else
        {
            ERROR("INVVPID instruction not supported! Type: %p, LinearAddress: %p, Vpid: %p, EptVpidMsr: %p, ProcExecCtrl2: 0x%x\n",
                Type, LinearAddress, Vpid, gVirtFeatures.EptVpidFeatures.Raw, vcpu->VmcsConfig.ProcExecCtrl2);
        }
    }
    else
    {
        invalidationCount++;

        if ((invalidationCount % 1000000) == 0)
        {
            ERROR("INVVPID instruction support: %d VPID support activated in VMCS: %d! Perform FULL cache invalidation! Total invalidations: %p\n",
                (CX_UINT32)VmxIsInvVpidSupported(),
                (CX_UINT32)((vcpu->VmcsConfig.ProcExecCtrl2) & VMCSFLAG_PROCEXEC2_ENABLE_VPID),
                invalidationCount
                );
        }

        // invalidate cache by re-writing CR3
        __writecr3(__readcr3());
    }

    return status;
}

///
/// @brief        Invalidate cached EPT mappings(TLB) with INVEPT instruction, routine implemented in assembly.
///
/// @param[in]    Type                             The type of the invalidation (single context or all context)
/// @param[in]    InvEptDesc                       An INVEPT_DESCRIPTOR structure containing the Ept for which the Gpa is invalidated.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      ERROR_STATUS                     - in case the INVEPT failed
///
CX_STATUS
CpuVmxInvEptAsm(
    _In_ CX_UINT64 Type,
    _In_ INVEPT_DESCRIPTOR *InvEptDesc
);

CX_STATUS
CpuVmxInvEpt(
    _In_ INVEPT_TYPE Type,
    _In_ CX_UINT64 Eptp,
    _In_ CX_UINT64 Address
)
{
    INVEPT_DESCRIPTOR desc;

    desc.Eptp = Eptp;
    desc.Gpa = Address;

    assert(desc.Gpa == 0);

    CX_STATUS status = CpuVmxInvEptAsm(Type, &desc);

#ifdef DEBUG
    if (!CX_SUCCESS(status))
    {
        ERROR("Failed to invalidate ept! Type: 0x%02x eptp %p address %p\n", Type, Eptp, Address);
    }
#endif
    return status;
}



CX_UINT32
CpuComputeExtendedStateSize(
    _In_ CX_UINT64 FeatureMask
    )
{
    int regs[4] = { 0 };
    CX_UINT32 size = 512 + 64;
    CX_UINT32 bitPos = 0;

    // Get the supported features bit mask.
    __cpuidex(regs, 0xD, 0x0);

    // Clear out mandatory bits - XCR0_X87 and XCR0_SSE. Also, clear out any invalid/unsupported bit.
    FeatureMask &= ~(XCR0_X87 | XCR0_SSE) & (((CX_UINT64)regs[3] << 32) | (CX_UINT64)regs[0]);

    while (0 != HvBitScanForwardU64(&bitPos, FeatureMask))
    {
        __cpuidex(regs, 0xD, (int)bitPos);

        if ((CX_UINT32)regs[0] + (CX_UINT32)regs[1] > size) size = (CX_UINT32)regs[0] + (CX_UINT32)regs[1];

        HvBitTestAndResetU64(&FeatureMask, bitPos);
    }

    return size;
}

/// @brief Contains the masks applied on CPUID leafs for the guest for hiding different features
static
CPUID_STATE gCpuIdReserved =
{
    11,  // TotalLeafCount
    {   //InEax InEbx, OutEax, OutEbx, OutEcx, OutEdx

        // standard
        { 1,    CPUID_ECX_ANY, CPUID_01_EAX_FLAG_RESERVED, CPUID_RESERVE_NONE, CPUID_01_ECX_RESERVED, CPUID_01_EDX_RESERVED },
        { 3,    CPUID_ECX_ANY, CPUID_03_EAX_RESERVED, CPUID_03_EBX_RESERVED, CPUID_03_ECX_RESERVED, CPUID_03_EDX_RESERVED },
        { 4,    CPUID_ECX_ANY, CPUID_04_EAX_RESERVED, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE, CPUID_04_EDX_RESERVED },
        { 6,    CPUID_ECX_ANY, CPUID_06_EAX_RESERVED, CPUID_06_EBX_RESERVED, CPUID_06_ECX_RESERVED, CPUID_RESERVE_NONE },
        { 7,    CPUID_ECX_ANY, CPUID_07_00_EAX_RESERVED, CPUID_07_00_EBX_RESERVED, CPUID_07_00_ECX_RESERVED, CPUID_07_00_EDX_RESERVED },
        { 8,    CPUID_ECX_ANY, CPUID_08_EAX_RESEVED, CPUID_08_EBX_RESEVED, CPUID_08_ECX_RESEVED, CPUID_08_EDX_RESEVED },
        { 9,    CPUID_ECX_ANY, CPUID_09_EAX_RESEVED, CPUID_09_EBX_RESEVED, CPUID_09_ECX_RESEVED, CPUID_09_EDX_RESEVED },
        { 0xA,  CPUID_ECX_ANY, CPUID_0A_EAX_RESEVED, CPUID_0A_EBX_RESEVED, CPUID_0A_ECX_RESEVED, CPUID_0A_EDX_RESEVED },
        { 0xD,  1,             CPUID_0D_01_EAX_RESERVED, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE },

        // extended
        { 0x80000001, CPUID_ECX_ANY, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE, CPUID_80000001_ECX_RESERVED, CPUID_80000001_EDX_RESERVED },
        { 0x80000007, CPUID_ECX_ANY, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE, CPUID_RESERVE_NONE, CPUID_80000007_EDX_RESERVED },
    }
};

///
/// @brief        Searches a certain CPUID instruction leaf in the reserved leaves array, based on EAX and ECX values.
///
/// @param[in]    InEax                            The value of the EAX, the primary leaf number
/// @param[in]    InEcx                            The value of the ECX, the secondary leaf number (CPUID_ECX_ANY in case it doesn't matter)
///
/// @returns      CPUID_LEAF*                      - The found CPUID leaf amongst the reserved ones, if it was found
/// @returns      CX_NULL                          - if not found
///
static
CPUID_LEAF*
_FindCpuidLeaf(
    _In_ CX_UINT32      InEax,
    _In_ CX_UINT32      InEcx
    )
{
    for (CX_UINT32 cpuidIdx = 0; cpuidIdx < gCpuIdReserved.TotalLeafCount; cpuidIdx++)
    {
        // eax filtering
        if (InEax == gCpuIdReserved.Leaf[cpuidIdx].EaxIn)
        {
            if ((gCpuIdReserved.Leaf[cpuidIdx].EcxIn == CPUID_ECX_ANY) || (gCpuIdReserved.Leaf[cpuidIdx].EcxIn == InEcx))
            {
                return &gCpuIdReserved.Leaf[cpuidIdx];
            }
        }
    }

    return CX_NULL;
}


///
/// @brief        Applies a reserved CPUID leafs mask on the values of the registers returned by the actual CPUID instruction
///
/// @param[in]    CpuidLeaf                        The reserved CPUID leaf, containing all the reserved bits for all 4 registers
/// @param[in, out]   Eax                          The address in memory where the value returned for EAX from the CPUID is stored
/// @param[in, out]   Ebx                          The address in memory where the value returned for EBX from the CPUID is stored
/// @param[in, out]   Ecx                          The address in memory where the value returned for ECX from the CPUID is stored
/// @param[in, out]   Edx                          The address in memory where the value returned for EDX from the CPUID is stored
///
__forceinline
static
void
_CpuidApplyMaskOnRegisters(
    _In_        const CPUID_LEAF*   CpuidLeaf,
    _Inout_     CX_UINT32*              Eax,
    _Inout_     CX_UINT32*              Ebx,
    _Inout_     CX_UINT32*              Ecx,
    _Inout_     CX_UINT32*              Edx
    )
{
    *Eax &= (~CpuidLeaf->EaxOut);
    *Ebx &= (~CpuidLeaf->EbxOut);
    *Ecx &= (~CpuidLeaf->EcxOut);
    *Edx &= (~CpuidLeaf->EdxOut);
}

void
CpuidChangePrimaryGuestExposedFeatures(
    _In_ CX_UINT32      InEax,
    _In_ CX_UINT32      InEcx,
    _In_ CX_UINT8       RegisterIndex,
    _In_ CX_UINT32      FlagsToChange,
    _In_ CX_BOOL    Expose
    )
{
    CPUID_LEAF* cpuidLeaf = _FindCpuidLeaf(InEax, InEcx);

    if (RegisterIndex >= ARRAYSIZE(cpuidLeaf->Registers))
    {
        WARNING("Received CpuidChangePrimaryGuestExposedFeatures for invalid register index %u\n", RegisterIndex);
        return;
    }

    if (Expose) cpuidLeaf->Registers[RegisterIndex] &= ~FlagsToChange;
    else cpuidLeaf->Registers[RegisterIndex] |= FlagsToChange;
}

void
CpuidApplyForPrimaryGuestQuery(
    _In_        CX_UINT32       InEax,
    _In_        CX_UINT32       InEcx,
    _Inout_     CX_UINT32*      Eax,
    _Inout_     CX_UINT32*      Ebx,
    _Inout_     CX_UINT32*      Ecx,
    _Inout_     CX_UINT32*      Edx
    )
{
    CX_UINT32 finalEax =
        (
            (InEax > gHypervisorGlobalData.CpuData.MaxExtendedCpuidInputValue) ||
            ((InEax > gHypervisorGlobalData.CpuData.MaxBasicCpuidInputValue) && (InEax < CPUID_START_OF_EXTENDED_RANGE)))
        ? gHypervisorGlobalData.CpuData.MaxBasicCpuidInputValue
        : InEax;

    CPUID_LEAF* cpuidLeaf = _FindCpuidLeaf(
        finalEax,
        InEcx);
    if (cpuidLeaf != CX_NULL) _CpuidApplyMaskOnRegisters(cpuidLeaf, Eax, Ebx, Ecx, Edx);
}

void
CpuidCollectMaxLeafValues(
    _Out_       CX_UINT32*      MaxBasic,
    _Out_       CX_UINT32*      MaxExtended
    )
{
    int cpuidInfo[4];

    __cpuid(cpuidInfo, CPUID_BASIC_CPUID_INFORMATION);
    *MaxBasic = cpuidInfo[0];

    __cpuid(cpuidInfo, CPUID_EXTENDED_CPUID_INFORMATION);
    *MaxExtended = cpuidInfo[0];
}

///
/// @brief        Verifies support of the NXE(execute-disable) feature by CPUID and activates it in the IA32_EFER_MSR if available.
///
/// @returns      TRUE if NXE is supported and was successfully activated, FALSE otherwise
///
CX_BOOL
LdActivateNxe(
    void
);

static volatile CX_UINT8 _NxActive = 1; ///< Stores the state of the NXE feature

CX_STATUS
CpuActivateNxe(
    CX_VOID
)
{
    CX_BOOL activated = LdActivateNxe();
    CxInterlockedAnd8(&_NxActive, !!activated);
    return activated ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
}

CX_BOOL
CpuIsXdUsed(
    CX_VOID
)
{
    return gBootInfo? (0 != gBootInfo->CpuMap[0].ExtendedIntelFeatures.Edx.NX) : (_NxActive != 0);
}

CX_UINT8 gCpuPhysicalAddressWidth = 0;                     ///< Max physical address width reported by the CPU
CX_UINT8 gCpuVirtualAddressWidth = 0;                      ///< Max virtual address width reported by the CPU
CX_UINT64 gCpuMaxPhysicalAddress = 0xFFFFFFFFFFFFFFFFULL;      ///< mask to be used to store the PHYSICAL ADDRESS MASK of the host CPUs, pre-inited to max CX_UINT64

CX_VOID
CpuInitAddressWidthData(
    CX_VOID
)
{
    CPUID_REGS cpuidRegs = { 0 };
    __cpuid((int*)&cpuidRegs, 0x80000008);
    gCpuPhysicalAddressWidth = cpuidRegs.Eax & 0xff;
    gCpuVirtualAddressWidth = (cpuidRegs.Eax >> 8) & 0xff;
    gCpuMaxPhysicalAddress = FIELD_MASK(gCpuPhysicalAddressWidth - 1);
}

#pragma optimize("", off)
void
CpuSaveFloatingState(
    _In_ CX_VOID *SaveArea
)
{
    if (HvGetCurrentCpu()->UseXsaveopt) _xsaveopt64(SaveArea, (CX_UINT64)-1LL);
    else if (HvGetCurrentCpu()->UseXsave) _xsave64(SaveArea, (CX_UINT64)-1LL);
    else _fxsave64(SaveArea);
}
#pragma optimize("", on)

#pragma optimize("", off)
void
CpuRestoreFloatingState(
    _In_ CX_VOID *SaveArea
)
{
    if (HvGetCurrentCpu()->UseXsave) _xrstor64(SaveArea, (CX_UINT64)-1LL);
    else _fxrstor64(SaveArea);
}
#pragma optimize("", on)

static CX_BOOL gIsIa32PatSupported = 0; ///< Stores the state of the PAT support

CX_VOID
CpuInitIa32Pat(
    CX_VOID
)
{
    static CX_ONCE_INIT0 patSupportKnown = 0;

    if (CxInterlockedBeginOnce(&patSupportKnown))
    {
        if (!gBootInfo)
        {
            CPUID_REGS cpuidRegs;
            __cpuid((int *)&cpuidRegs, 1);
            gIsIa32PatSupported = !!(cpuidRegs.Edx & CPUID_01_EDX_FLAG_PAT);
        }
        else gIsIa32PatSupported = !!gBootInfo->CpuMap[0].IntelFeatures.Edx.PAT;

        CxInterlockedEndOnce(&patSupportKnown);
    }
}


CX_STATUS
CpuGetIa32Pat(
    _Out_ CX_UINT64 *Pat
)
{
    if (gIsIa32PatSupported)
    {
        HVA_PAT pat;
        pat.Raw = __readmsr(MSR_IA32_PAT);
        *Pat = pat.Raw;
        return CX_STATUS_SUCCESS;
    }
    return CX_STATUS_DATA_NOT_FOUND;
}


CX_STATUS
CpuCpuidPrimaryGuest(
    _In_ const VCPU* Vcpu,
    _In_ CX_UINT32 InEax,
    _In_ CX_UINT32 InEcx,
    _Out_ CX_UINT32 *Eax,
    _Out_ CX_UINT32 *Ebx,
    _Out_ CX_UINT32 *Ecx,
    _Out_ CX_UINT32 *Edx)
{
    int a[4];

    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Eax == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;
    if (Ebx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;
    if (Ecx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_6;
    if (Edx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_7;

    // bare metal cpuid
    __cpuidex(a, InEax, InEcx);
    *Eax = (CX_UINT32)a[0];
    *Ebx = (CX_UINT32)a[1];
    *Ecx = (CX_UINT32)a[2];
    *Edx = (CX_UINT32)a[3];

    // disable features that we do not want to be available to this guest
    if (InEax == 0x01)
    {
        // From Intel SDM, CPUID Leaf 1, ECX.27:
        // "A value of 1 indicates that the OS has set CR4.OSXSAVE[bit 18]  to enable the XSAVE feature set."
        // We must make sure that we don't return the host state for this bit, otherwise we may cause all kind of funky
        // effects inside the guest: we need to make sure that the guests' CR4 has OSXSAVE bit set before setting it.
        // Otherwise, the guest will think that OSXSAVE feature has been activated inside CR4 and it will start
        // to execute all kind of AVX instructions that will trigger faults.
        CX_UINT32 flagsToRemove = (Vcpu->ArchRegs.CR4 & CR4_OSXSAVE) ? 0 : CPUID_01_ECX_FLAG_OSXSAVE;

        *Ecx &= ~(flagsToRemove);

        if (CfgFeaturesVirtualizationEnlightEnabled) *Ecx |= CPUID_01_ECX_FLAG_HYPERVISOR_PRESENT;

        if (CfgFeaturesHidePhysicalX2Apic) *Ecx &= (~CPUID_01_ECX_FLAG_X2APIC);

    }
    else if ((CfgFeaturesNmiPerformanceCounterTicksPerSecond) && (InEax == 0xA))
    {
        *Eax = *Eax & (~0xFFFF);
    }
    else if (InEax == 7 && InEcx == 0)
    {
        // remove Intel PT if CPU does not support it in non-root mode
        if (!gVirtFeatures.VmxMisc.IntelPTInVMX)
        {
            *Ebx &= (~CPUID_07_00_EBX_FLAG_INTEL_PROC_TRACE);
        }
    }

    // mask all that we do not know and what we do not support
    CpuidApplyForPrimaryGuestQuery(
        InEax,
        InEcx,
        Eax,
        Ebx,
        Ecx,
        Edx);

    return CX_STATUS_SUCCESS;
}


CX_STATUS
CpuIsXsetbvCallValid(
    _In_ const VCPU* Vcpu,
    _In_ CX_UINT32 Index,
    _In_ CX_UINT64 NewXcrValue
    )
{
    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    // #GP(0)
    // If the current privilege level is not 0 => solved by VT-x (we have exit only if CPL is 0)
    // If an invalid XCR is specified in ECX.
    if (Index != 0)
    {
        LOG("Index is not zero %u\n", Index);
        return STATUS_INJECT_GP;
    }

    // If the value in EDX:EAX sets bits that are reserved in the XCR specified by ECX.
    if ((NewXcrValue & Vcpu->Pcpu->Xcr0AvailMask) != (NewXcrValue))
    {
        LOG("NewCrValue is %p, while Xcr0AvailMask is %p\n", NewXcrValue, Vcpu->Pcpu->Xcr0AvailMask);
        return STATUS_INJECT_GP;
    }

    // If an attempt is made to clear bit 0 of XCR0.
    if (!(NewXcrValue & XCR0_X87))
    {
        LOG("Guest is attempting to clear bit 0 of XCR0, value is %p\n", NewXcrValue);
        return STATUS_INJECT_GP;
    }

    // If an attempt is made to set XCR0[2:1] to 10b
    if ((NewXcrValue & (XCR0_SSE | XCR0_YMM_HI128)) == XCR0_YMM_HI128)
    {
        LOG("NewCRValue will set XCR0[2:1] to 10b, value is %p\n", NewXcrValue);
        return STATUS_INJECT_GP;
    }

    // #UD
    // If CPUID.01H:ECX.XSAVE[bit 26] = 0.
    CX_UINT32 eax, ebx, ecx, edx;

    CX_STATUS status = CpuCpuidPrimaryGuest(Vcpu, 1, 0, &eax, &ebx, &ecx, &edx);
    if ((!CX_SUCCESS(status)) || (!(ecx & CPUID_01_ECX_FLAG_XSAVE)))
    {
        LOG("XSAVE is not set in CPUID, ecx value is 0x%X\n", ecx);
        return STATUS_INJECT_GP;
    }

    // If CR4.OSXSAVE[bit 18] = 0.
    if (!(Vcpu->ArchRegs.CR4 & CR4_OSXSAVE)) return STATUS_INJECT_UD;

    // If the LOCK prefix is used. => solved by VT-x (automatically causes #UD before VM exit for XSETBV)

    return CX_STATUS_SUCCESS;
}

CX_BOOL
CpuIsKnownMsr(
    _In_ CX_UINT32 Msr
)
{
    return (
        ((Msr > 0x00000000) && (Msr < 0x00001FFF))      // low part
        || ((Msr > 0xC0000000 && Msr < 0xC0001FFF))     // high part
        );
}
