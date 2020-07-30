/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpu_features.c
*   @brief CPU_FEATURES - Identify CPU features
*/
#include "cx_native.h"
#include "common/boot/cpu_features.h"
#include "common/boot/loader_interface.h"
#include "common/kernel/cpudefs.h"
#include "common/kernel/vmxdefs.h"

#include "external_interface/kernel_interface.h"

// the next file is included only for checking for consistency between the externally provided header and the expected documented interface
#include "common/external_interface/kernel_interface.h"

/// @brief Bit 11 from MSR_IA32_APIC_BASE signal if APIC is enabled
#define APIC_ENABLED        1 << 11

CX_VOID
CpuPrintCpuidFeatures(
    _In_ CPU_ENTRY *CpuEntry
    )
{
    if (CpuEntry->ProcessorType.Intel)
    {
        FEAT_PRINTN("Intel: VMX  x64  EPT  VPid x2Ap x2En DMT  iTSC XCR0 X16b AVX  P1Gb APICv ApRV #VE  TscD VMFUNC\n   ");
    }
    else if (CpuEntry->ProcessorType.AMD)
    {
        FEAT_PRINTN("AMD:   SVM  x64  NPag ASId x2Ap x2En DMT  iTSC XCR0 X16b AVX  P1Gb\n   ");
    }
    else
    {
        FEAT_PRINT("ERROR: Processor unidentified!\n");
        return;
    }

    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.VMX);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.x64);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.EPT);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.VPID);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.x2APIC);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.x2APICEn);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.DMT);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.InvariantTSC);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.XCR0);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.CMPXCHG16B);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.AVX);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.Page_1GB);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.APICv);
    FEAT_PRINTN("%6d", CpuEntry->MiscIntelFeatures.ApicRegVirt);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.EptVe);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.TscDeadline);
    FEAT_PRINTN("%5d", CpuEntry->MiscIntelFeatures.VMFUNC);
}

CX_VOID
CpuPrintLocalApic(
    _In_ CPU_ENTRY *CpuEntry
    )
{
    FEAT_PRINT("[CPU] Local APIC: Id=%d, Base=0x%llx\n", CpuEntry->Id, CpuEntry->LocalApicBase);
}

CX_VOID
CpuPrintMiscFeatures(
    _In_ CPU_ENTRY *CpuEntry
    )
{
    CpuPrintLocalApic(CpuEntry);

    FEAT_PRINT("[CPU] Family (hex): Stepping %X, Model %X, Family %X, ExtModel %X, ExtFamily %X\n",
        CpuEntry->FamilyFields.Stepping,
        CpuEntry->FamilyFields.Model,
        CpuEntry->FamilyFields.Family,
        CpuEntry->FamilyFields.ExtendedModel,
        CpuEntry->FamilyFields.ExtendedFamily
        );

    FEAT_PRINT("[CPU] Addressability: Physical %d bits, Virtual %d bits\n",
        CpuEntry->Addressability.PhysicalAddressWidth,
        CpuEntry->Addressability.VirtualAddressWidth
        );

    {
        char brandIdentificationString[50] = { 0 };
        int regs[4] = { 0 }, tempI = 0, cpuidParameter = 0x80000002;

        __cpuid(regs, 0x80000000);
        if (regs[0] >= 0x80000004)
        {
            regs[0] = regs[1] = regs[2] = regs[3] = 0;

            for (tempI = 0; tempI < 3; tempI++)
            {
                __cpuid(regs, cpuidParameter + tempI);
                memcpy(brandIdentificationString + 4 * sizeof(CX_UINT32) * tempI, regs, 4 * sizeof(CX_UINT32));
            }
            brandIdentificationString[tempI * 4 * sizeof(CX_UINT32)] = '\0';
            FEAT_PRINT("Processor brand string: %s.\n", brandIdentificationString);
        }
    }

    CpuPrintCpuidFeatures(CpuEntry);

    FEAT_PRINTN("\n");
}

CX_BOOL
InitCpuEntry(
    _Out_ CPU_ENTRY *CpuEntry
    )
{
    CPUID_REGS cpuidRegs = {0};
    CX_UINT64 msr = 0;

    msr = 1;

    if (!CpuEntry) return CX_FALSE;

    //
    // Preinit. Fields in order, size in bytes.
    //
    CpuEntry->LocalApicBase = 0;            // 8
    CpuEntry->__padding = 0;                // 8
    CpuEntry->Features.Ecx = 0;             // 4
    CpuEntry->Features.Edx = 0;             // 4
    CpuEntry->ExtendedFeatures.Ecx = 0;     // 4
    CpuEntry->ExtendedFeatures.Edx = 0;     // 4
    CpuEntry->MiscFeatures2 = 0;            // 4
    CpuEntry->Family = 0;                   // 4
    ((CX_UINT32*)(CpuEntry->Name))[0] = 0;      // 4
    ((CX_UINT32*)(CpuEntry->Name))[1] = 0;      // 4
    ((CX_UINT32*)(CpuEntry->Name))[2] = 0;      // 4
    CpuEntry->Name[12] = 0;                 // 1
    CpuEntry->Name[13] = 0;                 // 1
    CpuEntry->ProcessorTypeIdentified = 0;  // 2
    CpuEntry->Addressability.PhysicalAddressWidth = 0;  // 1
    CpuEntry->Addressability.VirtualAddressWidth = 0;   // 1
    CpuEntry->Reserved = 0;                 // 2


    //
    // Check Identification String (Function 0H)
    //
    __cpuid((int*)&cpuidRegs, 0);

    // Initialize processor Name
    ((CX_UINT32*)(CpuEntry->Name))[0] = cpuidRegs.Ebx;
    ((CX_UINT32*)(CpuEntry->Name))[1] = cpuidRegs.Edx;
    ((CX_UINT32*)(CpuEntry->Name))[2] = cpuidRegs.Ecx;
    CpuEntry->Name[12] = 0;
    CpuEntry->Name[13] = 0;     // Not used, but initialize to 0

    //FEAT_PRINT("%s\n", CpuEntry->Name);

    //
    // Initialize processor type field (Intel / AMD)
    //
    if ((cpuidRegs.Ebx == 'uneG') && (cpuidRegs.Edx == 'Ieni') && (cpuidRegs.Ecx == 'letn'))
    {
        // EBX  EDX  ECX
        // Genu ineI ntel
        CpuEntry->ProcessorType.Intel = CX_TRUE;
    }
    else if ((cpuidRegs.Ebx == 'htuA') && (cpuidRegs.Edx == 'itne') && (cpuidRegs.Ecx == 'DMAc'))
    {
        // EBX  EDX ECX
        // Auth enti cAMD
        CpuEntry->ProcessorType.AMD = CX_TRUE;
    }
    else
    {
        return CX_FALSE;
    }

    //
    // Get the local APIC base
    //
    msr = __readmsr(MSR_IA32_APIC_BASE);

    CpuEntry->LocalApicBase = msr & 0xFFFFFF000;    // bits 12-35

    if (!(msr & APIC_ENABLED))
    {
        return CX_FALSE;       // Intel documentation says the local APIC is enabled after reset.
    }

    CpuEntry->Topology.IsBsp = (msr & 0x100) >> 8;

    //
    // Check Family, Features and Local APIC
    //
    __cpuid((int*)&cpuidRegs, 1);

    CpuEntry->Family = cpuidRegs.Eax;               // Family

    CpuEntry->Features.Ecx = cpuidRegs.Ecx;         // Basic features, ECX
    CpuEntry->Features.Edx = cpuidRegs.Edx;         // Basic features, EDX

    CpuEntry->Id = (CX_UINT32)(cpuidRegs.Ebx >> 24);    // Local APIC ID


    //
    // Check some CPUID features
    //
    if (CpuEntry->ProcessorType.Intel)
    {
        if (CpuEntry->IntelFeatures.Ecx.x2APIC)
        {
            // The Local APIC ID is in MSR 802H, replace the one read with CPUID, if x2APIC is enabled.
            // Otherwise, local APIC ID will remain the one stored before.

            // Read IA32_APIC_BASE
            msr = __readmsr(MSR_IA32_APIC_BASE);

            // Check whether x2APIC is enabled or not
            if (msr & (1 << 10))        // If it's already enabled, we will leave it that way
            {
                // Read Local APIC Id (MSR 0x802)
                msr = __readmsr(0x802);
                CpuEntry->Id = (CX_UINT32)msr;
                CpuEntry->MiscIntelFeatures.x2APICEn = 1;
            }
        }
    }

    //
    // Check for CMPXCHG16B, XCR0, AVX (the same for Intel / AMD)
    //
    CpuEntry->MiscIntelFeatures.CMPXCHG16B  = CpuEntry->IntelFeatures.Ecx.CMPXCHG16B;
    CpuEntry->MiscIntelFeatures.XCR0        = CpuEntry->IntelFeatures.Ecx.XSAVE;
    CpuEntry->MiscIntelFeatures.AVX         = CpuEntry->IntelFeatures.Ecx.AVX;


    //
    // Check the maximum extension Id this processor supports
    //
    __cpuid((int*)&cpuidRegs, 0x80000000);
    if (cpuidRegs.Eax < 0x80000008)
    {
        //FEAT_PRINT("ERROR: CPU Features: [-] Extended CPUID information (sub-functions <= 0x80000007)\n");
        return CX_FALSE;
    }

    //
    // Check for Invariant TSC (the same for Intel & AMD)
    //
    __cpuid((int*)&cpuidRegs, 0x80000007);
    if (cpuidRegs.Edx & (1 << 8))
    {
        CpuEntry->MiscIntelFeatures.InvariantTSC = 1;       // same as setting MiscAmdFeatures.InvariantTSC
    }

    //
    // Read address space width supported by processor
    //
    __cpuid((int*)&cpuidRegs, 0x80000008);
    CpuEntry->Addressability.PhysicalAddressWidth = cpuidRegs.Eax & 0xff;
    CpuEntry->Addressability.VirtualAddressWidth  = (cpuidRegs.Eax >> 8) & 0xff;

    //
    // Check Extended Features
    //
    __cpuid((int*)&cpuidRegs, 0x80000001);

    CpuEntry->ExtendedFeatures.Ecx = cpuidRegs.Ecx;
    CpuEntry->ExtendedFeatures.Edx = cpuidRegs.Edx;


    //
    // Initialize MiscFeatures (the one that actually represent our concern)
    //

    // Bit 0: Virtualization (VMX / SVM); Intel: CPUID.01:ECX[5], AMD: CPUID:80000001H:ECX[2]
    if (CpuEntry->ProcessorType.Intel)
    {
        CpuEntry->MiscIntelFeatures.VMX = CpuEntry->IntelFeatures.Ecx.VMX;
    }
    else if (CpuEntry->ProcessorType.AMD)
    {
        CpuEntry->MiscAmdFeatures.SVM = CpuEntry->ExtendedAmdFeatures.Ecx.SVM;
    }

    // Bit 1: x64 support; Intel: CPUID.80000001H:EDX[29], AMD: CPUID.80000001H:EDX[29]; same sub-function, register and bit index
    CpuEntry->MiscIntelFeatures.x64 = CpuEntry->ExtendedIntelFeatures.Edx.Intel64;   // same as CpuEntry->ExtendedAmdFeatures.Edx.AMD64LM

    // Bit 10: 1-GB Pages (same for Intel & AMD: CPUID.80000001H:EDX[26])
    CpuEntry->MiscIntelFeatures.Page_1GB = CpuEntry->ExtendedIntelFeatures.Edx.PAGE_1GB;

    // Bit 2 & 3 & 5: EPT + VPID + DMT (Intel), NP + ASID + DMT
    if (CpuEntry->ProcessorType.AMD)
    {
        __cpuid((int*)&cpuidRegs, 0x80000000);
        if (cpuidRegs.Eax < 0x8000000A)
        {
            //FEAT_PRINT("ERROR: CPU Features: [-] AMD CPUID SVM Revision and Feature Information\n");
            return CX_FALSE;
        }

        __cpuid((int*)&cpuidRegs, 0x8000000A);
        if (cpuidRegs.Edx & 1)
        {
            // EDX[0] NP: nested paging.
            CpuEntry->MiscAmdFeatures.NP = 1;
        }

        if (cpuidRegs.Ebx > 0)
        {
            // EBX[31:0] NASID: Number of address space identifiers (ASID).
            CpuEntry->MiscAmdFeatures.ASID = 1;
            // NASID might need to be stored for future use
        }

        //
        // DMT for AMD. If SmmLock bit is NOT set in HWCR MSR (bit 0), we can have a SMM hypervisor.
        //
        if (CpuEntry->MiscAmdFeatures.SVM)
        {
            msr = __readmsr(0xc0010015);    // HWCR
            if ((msr & 1) == 0)             // The bit must be cleared!
            {
                CpuEntry->MiscAmdFeatures.DMT = 1;
            }
        }
    }
    else if (CpuEntry->ProcessorType.Intel)
    {
        // Read VMX MSRs only if VMX is available on this Intel processor, otherwise a GP fault will be produced
        if (CpuEntry->MiscIntelFeatures.VMX)
        {
            // IA32_VMX_BASIC
            msr = __readmsr(0x480);

            // Dual Monitor Treatment
            if (msr & (1ULL << 49))
            {
                CpuEntry->MiscIntelFeatures.DMT = 1;
            }

            // IA32_VMX_PROCBASED_CTLS
            msr = __readmsr(0x482);
            if ( msr & (1ULL << 63))
            {
                // IA32_VMX_PROCBASED_CTLS2
                msr = __readmsr(0x48B);
                if (msr & (1ULL << 33))
                {
                    // EPT
                    CpuEntry->MiscIntelFeatures.EPT = CX_TRUE;
                }

                if (msr & (1ULL << 37))
                {
                    // VPID
                    CpuEntry->MiscIntelFeatures.VPID = 1;
                }

                if (CpuEntry->MiscIntelFeatures.EPT || CpuEntry->MiscIntelFeatures.VPID)
                {
                    // IA32_VMX_EPT_VPID_CAP
                    msr = __readmsr(0x48C);
                }
            }
        }
    }


    // Bit 4: x2APIC; Intel: CPUID.01:ECX[21], AMD: ?
    if (CpuEntry->ProcessorType.Intel)
    {
        CpuEntry->MiscIntelFeatures.x2APIC = CpuEntry->IntelFeatures.Ecx.x2APIC;

        CpuEntry->MiscIntelFeatures.TscDeadline = CpuEntry->IntelFeatures.Ecx.TSC_Deadline;
    }

    return CX_TRUE;
}

CX_BOOL
InitCpuVirtualizationFeatures(
    _Inout_ CPU_ENTRY *CpuEntry,
    _Out_ VIRTUALIZATION_FEATURES *VirtFeat
)
{
    if (!CpuEntry || !VirtFeat) return CX_FALSE;

    if (CpuEntry->ProcessorType.Intel)
    {
        if (CpuEntry->MiscIntelFeatures.VMX)
        {
            CX_BOOL suppProcBased2Ctl = CX_FALSE;

            VirtFeat->MsrFeatureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);

            VirtFeat->VmxBasic.Raw = __readmsr(MSR_IA32_VMX_BASIC);       // conform Intel Vol 3B, Appendix G.1, "Basic VMX Information"

            // do we have IA32_VMX_TRUE_xxx_CTLS support?
            if (VirtFeat->VmxBasic.Raw & (1ull << 55))
            {
                VirtFeat->VmxPinBased.Raw = __readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
                VirtFeat->VmxProcBased.Raw = __readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
                VirtFeat->VmxExit.VmxExitRaw = __readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
                VirtFeat->VmxEntry.VmxEntryRaw = __readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
            }
            else
            {
                VirtFeat->VmxPinBased.Raw = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
                VirtFeat->VmxProcBased.Raw = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
                VirtFeat->VmxExit.VmxExitRaw = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
                VirtFeat->VmxEntry.VmxEntryRaw = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);
            }

            // do we have support for secondary processor based VM execution controls?
            if ((VirtFeat->VmxProcBased.Raw >> 32) & VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2)
            {
                suppProcBased2Ctl = CX_TRUE;
            }

            if (suppProcBased2Ctl)
            {
                VirtFeat->VmxProcBased2.Raw = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

                if (VirtFeat->VmxProcBased2.Parsed.One.VirtualInterruptDelivery)
                {
                    CpuEntry->MiscIntelFeatures.APICv = 1;
                }

                if (VirtFeat->VmxProcBased2.Parsed.One.ApicRegisterVirtualization)
                {
                    CpuEntry->MiscIntelFeatures.ApicRegVirt = 1;
                }

                if (VirtFeat->VmxProcBased2.Parsed.One.EnableVMFunctions)
                {
                    CpuEntry->MiscIntelFeatures.VMFUNC = 1;
                }

                if (VirtFeat->VmxProcBased2.Parsed.One.EptViolationCauseException)
                {
                    CpuEntry->MiscIntelFeatures.EptVe = 1;
                }
            }

            VirtFeat->VmxMisc.VmxMiscRaw = __readmsr(MSR_IA32_VMX_MISC);

            //If ( CPUID.01H:ECX.[bit 5], IA32_VMX_PROCBASED_CTLS[bit 63], and either
            //    IA32_VMX_PROCBASED_CTLS2[bit 33] or IA32_VMX_PROCBASED_CTLS2[bit 37]
            //)
            if (    (CpuEntry->IntelFeatures.Ecx.VMX) && (VirtFeat->VmxProcBased.Parsed.One.ActivateSecondaryCtls) &&
                    (VirtFeat->VmxProcBased2.Parsed.One.EnableEpt || VirtFeat->VmxProcBased2.Parsed.One.EnableVpid)
                )
            {
                VirtFeat->EptVpidFeatures.Raw = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
            }
            else
            {
                VirtFeat->EptVpidFeatures.Raw = 0;
            }
        }
        else
        {
            return CX_FALSE;
        }
    }
    else if (!CpuEntry->MiscAmdFeatures.SVM)
    {
        return CX_FALSE;
    }

    return CX_TRUE;
}

CX_UINT32
CpuGetOriginalApicId(
    void
    )
{
    CPUID_REGS cpuidRegs = {0};

    __cpuid((int*)&cpuidRegs, 1);

    return (CX_UINT32)(cpuidRegs.Ebx >> 24);
}

CX_STATUS
CpuCheckFeatures(
    _In_ CPU_ENTRY *CpuEntry,
    _In_ VIRTUALIZATION_FEATURES *VirtFeat
    )
{
    // we MUST be running either on Intel or on AMD
    if (CpuEntry->ProcessorTypeIdentified == 0) return CX_STATUS_NOT_SUPPORTED;

    // check that we do have all needed features (we can do the same checks for both Intel and AMD, because the bits overlap)
    // we need at least: EM64T/x64, VMX/SVM, EPT/NP, VPID/ASID, CMPXCHG16B, InvariantTSC
    if ((CpuEntry->MiscIntelFeatures.x64        == 0) ||
        (CpuEntry->MiscIntelFeatures.VMX        == 0) ||
        (CpuEntry->MiscIntelFeatures.EPT        == 0) ||
        (CpuEntry->MiscIntelFeatures.VPID       == 0) ||
        (CpuEntry->MiscIntelFeatures.CMPXCHG16B == 0) ||
        (CpuEntry->MiscIntelFeatures.InvariantTSC == 0))
    {
        CX_UINT32 feat = 0, missing = 0;

        feat = CpuEntry->MiscFeatures2;

        CpuEntry->MiscFeatures2 = 0;
        CpuEntry->MiscIntelFeatures.x64 = 1;
        CpuEntry->MiscIntelFeatures.VMX = 1;
        CpuEntry->MiscIntelFeatures.EPT = 1;
        CpuEntry->MiscIntelFeatures.VPID = 1;
        CpuEntry->MiscIntelFeatures.CMPXCHG16B = 1;
        CpuEntry->MiscIntelFeatures.InvariantTSC = 1;

        missing = CpuEntry->MiscFeatures2 & ~(feat);

        FEAT_PRINT("\nFATAL: The following critical CPU features are NOT present:\n");

        CpuEntry->MiscFeatures2 = missing;

        CpuPrintCpuidFeatures(CpuEntry);
        FEAT_PRINT("\n\n");

        CpuEntry->MiscFeatures2 = feat;

        return CX_STATUS_NOT_SUPPORTED;
    }

    //
    // check for required VMX / SVM capabilities
    //
    if (CpuEntry->ProcessorType.Intel)
    {
        CX_BOOL suppProcBased2Ctl, suppUnrestrictedGuest;

        suppProcBased2Ctl = suppUnrestrictedGuest = CX_FALSE;

        // do we have support for secondary processor based VM execution controls?
        if ((VirtFeat->VmxProcBased.Raw >> 32) & VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2)
        {
            suppProcBased2Ctl = CX_TRUE;
        }

        // do we have support for unrestricted guests?
        if ((VirtFeat->VmxProcBased2.Raw >> 32) & VMCSFLAG_PROCEXEC2_UNRESTRICTED_GUEST)
        {
            suppUnrestrictedGuest = CX_TRUE;
        }

        // check we have everything we need
        if ((!suppProcBased2Ctl)
            || (!suppUnrestrictedGuest)
            )
        {
            FEAT_PRINT("\nFATAL: INTEL VMX capability checks NOT passed (suppProcBased2Ctl=%d, suppUnrestrictedGuest=%d) :-(\n",
                (CX_UINT32)suppProcBased2Ctl, (CX_UINT32)suppUnrestrictedGuest);

            return CX_STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        FEAT_PRINT("\nFATAL: AMD SVM capability checks NOT implemented\n");
        return CX_STATUS_NOT_SUPPORTED;
    }

    return CX_STATUS_SUCCESS;
}

CX_BOOL
InitCpuSmxFeatures(
    _In_ CPU_ENTRY *CpuEntry,
    _Inout_ SMX_CAPABILITIES *SmxCapabilities
    )
{
    CX_BOOL res = CX_TRUE;

    // check if this is Intel CPU
    if (CpuEntry->ProcessorType.Intel)
    {
        // check if cpuid reports support for SMX
        if (!CpuEntry->IntelFeatures.Ecx.SMX)
        {
            FEAT_PRINT("This CPU does not support SMX!\n");
            SmxCapabilities->SmxCapabilities0Raw = 0;
        }
        else
        {
            CX_SIZE_T originalCr4 = 0;
            CPU_IRQL irql = CpuRaiseIrqlToDpcLevel();

            // enable SMX in CR4 so we can execute getsec instrux
            originalCr4 = __readcr4();
            __writecr4(originalCr4 | CR4_SMXE);

            if (__readcr4() & CR4_SMXE)
            {
                SmxCapabilities->SmxCapabilities0Raw = CpuGetSecCapabilities(0);
            }

            // restore CR4
            __writecr4(originalCr4);
            CpuLowerIrql(irql);
        }
    }
    else
    {
        return res;
    }

    return res;
}

CX_BOOL
CpuHasSmep(
    CX_VOID
    )
{
    int regs[4] = {0};

    // Function ID 0x7, SubFunction ID 0x0 (EAX = 7, ECX = 0).
    __cpuidex(regs, 0x7, 0x0);

    // Bit 7 inside EBX tells us if SMEP is supported.
    return (regs[1] & (1 << 7)) != 0;
}

CX_BOOL
CpuHasSmap(
    CX_VOID
    )
{
    int regs[4] = {0};

    // Function ID 0x7, SubFunction ID 0x0 (EAX = 7, ECX = 0).
    __cpuidex(regs, 0x7, 0x0);

    // Bit 20 inside EBX tells us if SMAP is supported.
    return (regs[1] & (1 << 20)) != 0;
}
