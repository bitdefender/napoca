/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file guestenlight.c
*   @brief The enlightment interface exposed by our Hypervisor
*/

/// \addtogroup gst_enlight
/// @{

#include "napoca.h"
#include "kernel/guestenlight.h"
#include "kernel/kernel.h"
#include "memory/cachemap.h"
#include "kernel/interrupt.h"
#include "kernel/intelhwp.h"

/** @name Partition privileges
*   @brief Partition privileges
*
*   The hypervisor defines facilities that the partition is allowed to access.
*   This enables the parent to control which synthetic MSRs and hypercalls a child partition can access.
*   The property is defined with the MSFT_HV_IDENTIFICATION_PARTITION_PRIVILEGES and MSFT_HV_IDENTIFICATION_PARTITION_FLAGS structures.
*
*/
///@{
typedef union _MSFT_HV_IDENTIFICATION_PARTITION_PRIVILEGES
{
    CX_UINT32  Raw;
    struct {
        CX_UINT32           AccessVpRunTimeMsr              : 1;    ///< The partition has access to the synthetic MSR HV_X64_MSR_VP_RUNTIME.
                                                                    ///< If this flag is cleared, accesses to this MSR results in
                                                                    ///< a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessPartitionReferenceCounter : 1;    ///< The partition has access to the partition-wide reference count MSR,
                                                                    ///< HV_X64_MSR_TIME_REF_COUNT. If this flag is cleared,
                                                                    ///< accesses to this MSR results in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessSynicMsrs                 : 1;    ///< The partition has access to the synthetic MSRs associated with the
                                                                    ///< Synic (HV_X64_MSR_SCONTROL through HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15).
                                                                    ///< If this flag is cleared, accesses to these MSRs results in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessSyntheticTimerMsrs        : 1;    ///< The partition has access to the synthetic MSRs associated with the Synic (HV_X64_MSR_STIMER0_CONFIG through HV_X64_MSR_STIMER3_COUNT).
                                                                    ///< If this flag is cleared, accesses to these MSRs results in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AcessApicMsrs                   : 1;    ///< The partition has access to the synthetic MSRs associated with the APIC (HV_X64_MSR_EOI,
                                                                    ///< HV_X64_MSR_ICR and HV_X64_MSR_TPR). If this flag is cleared, accesses to these MSRs results
                                                                    ///< in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessHypercallMsrs             : 1;    ///< The partition has access to the synthetic MSRs related to the hypercall
                                                                    ///< interface (HV_X64_MSR_GUEST_OS_ID and HV_X64_MSR_HYPERCALL).
                                                                    ///< If this flag is cleared, accesses to these MSRs result in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AcessVpIndex                    : 1;    ///< The partition has access to the synthetic MSR that returns the virtual processor index. If this flag is cleared,
                                                                    ///< accesses to this MSR results in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessResetMsr                  : 1;    ///< This partition has access to the synthetic MSR that resets the system. If this flag is cleared,
                                                                    ///< accesses to this MSR results in a \c \#GP fault if the MSR intercept is not installed.

        CX_UINT32           AccessStatsMsr                  : 1;    ///< This partition has access to the synthetic MSRs that allows the guest to map and unmap its own statistics pages.
        CX_UINT32           AccessPartitionReferenceTsc     : 1;    ///< The partition has access to the reference TSC.
        CX_UINT32           AccessGuestIdleMsr              : 1;    ///< The partition has access to the synthetic MSR that allows the guest to enter the guest idle state.
        CX_UINT32           AcessFrequencyMsrs              : 1;    ///< The partition has access to the synthetic MSRs that supply the TSC and APIC frequencies, if supported.
        CX_UINT32           Reserved                        : 20;
    };
}MSFT_HV_IDENTIFICATION_PARTITION_PRIVILEGES;

typedef union _MSFT_HV_IDENTIFICATION_PARTITION_FLAGS
{
    CX_UINT32  Raw;
    struct {
        CX_UINT32           CreatePartitions                : 1;    ///< The partition can invoke the hypercall HvCreatePartition. The partition also can make any other
                                                                    ///< hypercall that is restricted to operating on children.

        CX_UINT32           AccessPartitionId               : 1;    ///< The partition can invoke the hypercall HvGetPartitionId to obtain its own partition ID.
        CX_UINT32           AccessMemoryPool                : 1;    ///< The partition can invoke the hypercalls HvDepositMemory, HvWithdrawMemory and HvGetMemoryBalance.
        CX_UINT32           AdjustMessageBuffers            : 1;
        CX_UINT32           PostMessages                    : 1;    ///< The partition can invoke the hypercall HvPostMessage.
        CX_UINT32           SignalEvents                    : 1;    ///< The partition can invoke the hypercall HvSignalEvent.
        CX_UINT32           CreatePort                      : 1;    ///< The partition can invoke the hypercall HvCreatePort.
        CX_UINT32           ConnectPort                     : 1;    ///< The partition can invoke the hypercall HvConnectPort.
        CX_UINT32           AccessStats                     : 1;    ///< The partition can invoke the hypercalls HvMapStatsPage and HvUnmapStatsPage.
        CX_UINT32           Reserved2                       : 2;
        CX_UINT32           Debugging                       : 1;    ///< The partition can invoke the hypercalls HvPostDebugData, HvRetrieveDebugData and HvResetDebugSession.

        CX_UINT32           CpuManagement                   : 1;    ///< The partition can invoke the hypercalls HvGetLogicalProcessorRunTime and HvCallParkedVirtualProcessors.
                                                                    ///< This partition also has access to the power management MSRs.

        CX_UINT32           ConfigureProfiler               : 1;
        CX_UINT32           Reserved3                       : 18;
    };
}MSFT_HV_IDENTIFICATION_PARTITION_FLAGS;
///@}

/**
*   @brief Indicates which behaviors the hypervisor recommends the OS implement for optimal performance.
*/
typedef union _MSFT_HV_IMPLEMENTATION_RECOMMENDATIONS
{
    CX_UINT32 Raw;
    struct {
        CX_UINT32        RecommendHypercallForMovToCr3          : 1;    ///< Recommend using hypercall for address space switches rather than MOV to CR3 instruction
        CX_UINT32        RecommendHypercallForInvlpg            : 1;    ///< Recommend using hypercall for local TLB flushes rather than INVLPG or MOV to CR3 instructions
        CX_UINT32        RecommendHypercallForBroadcastingInvlpg : 1;   ///< Recommend using hypercall for remote TLB flushes rather than inter-processor interrupts
        CX_UINT32        RecommendUsingMsrsForApicRegisterAccess : 1;   ///< Recommend using MSRs for accessing APIC registers EOI, ICR and TPR rather than their memory-mapped counterparts.
        CX_UINT32        RecommendUsingMsrForSystemReset        : 1;    ///< Recommend using the hypervisor-provided MSR to initiate a system RESET.
        CX_UINT32        RecommendRelaxedTiming                 : 1;    ///< Recommend using relaxed timing for this partition. If used, the VM should disable any watchdog timeouts that rely on the timely delivery of external interrupts.
        CX_UINT32        RecommendUsingDMAremapping             : 1;    ///< Recommend using DMA remapping.
        CX_UINT32        RecommendUsingInterruptRemapping       : 1;    ///< Recommend using interrupt remapping.
        CX_UINT32        RecommendUsingX2ApicMsrs               : 1;    ///< Recommend using x2APIC MSRs.
        CX_UINT32        RecommendReprecatingAutoEOI            : 1;    ///< Recommend deprecating AutoEOI.
        CX_UINT32        Reserved                               : 22;
    };
}MSFT_HV_IMPLEMENTATION_RECOMMENDATIONS;

/** @name Hypercall handlers from assembly code
*   @brief Addresses for the code to be written in the hypercall page prepared for the guest OS
*/
///@{
extern CX_UINT64 GuestHypercallStubx64;
extern CX_UINT64 GuestHypercallStubEndx64;
extern CX_UINT64 GuestHypercallStubx86;
extern CX_UINT64 GuestHypercallStubEndx86;
///@}

/// @}

typedef struct _BYTE_LOCATION
{
    CX_UINT8 Pos;
    CX_UINT8 Val;
}BYTE_LOCATION;

typedef struct _WINHVR_SIGNATURE
{
    const CX_UINT8 Count;
    const BYTE_LOCATION* const Bytes;

} WINHVR_SIGNATURE;

static const BYTE_LOCATION SigUpTo19H2[] = {
    { 0, 0x48}, { 1, 0x8B}, { 2, 0x44}, { 3, 0x24},                 // 48 8B 44 24 [20]            mov     rax,[rsp + 48h + var_28]
    { 5, 0x48}, { 6, 0xC1}, { 7, 0xE8}, { 8, 0x2C},                 // 48 C1 E8 2C                 shr     rax, 2Ch
    { 9, 0x24}, {10, 0x01},                                         // 24 01                       and     al, 1
    {11, 0x88}, {12, 0x05},                                         // 88 05 [4A 41 FF FF]         mov     cs : WinHvpCpuManagement, al
    {17, 0x75},                                                     // 75 [24]                     jnz     short loc_1C001A5D4
    {19, 0xC6}, {20, 0x05},                                         // C6 05 [42 41 FF FF 01]      mov     cs : WinHvpRunningLoopback, 1
    {26, 0xE8},                                                     // E8 [7C FE FF FF]            call    WinHvpAllocNumaMaps
    {31, 0x8B}, {32, 0xD8},                                         // 8B D8                       mov     ebx, eax
    {33, 0x85}, {34, 0xC0},                                         // 85 C0                       test    eax, eax
    {35, 0x0F}, {36, 0x88},                                         // 0F 88 [6A 01 00 00]         js      loc_1C001A730
    {41, 0xE8},                                                     // E8 [C5 FA FF FF]            call    WinHvpInitializeHypercallSupport
    {46, 0x8B}, {47, 0xD8},                                         // 8B D8                       mov     ebx, eax
    {48, 0x85}, {49, 0xC0},                                         // 85 C0                       test    eax, eax
    {50, 0xE9},                                                     // E9 [4F 01 00 00]            jmp     loc_1C001A723
};

static const BYTE_LOCATION Sig20H1AndUp[] = {
     { 0, 0x48}, { 1, 0x8B}, { 2, 0x44}, { 3, 0x24},                // 48 8B 44 24 [30]            mov     rax, qword ptr[rsp + 58h + var_28]
     { 5, 0xBE}, { 6, 0x01}, { 7, 0x00}, { 8, 0x00}, { 9, 0x00},    // BE 01 00 00 00              mov     esi, 1
     {10, 0x48}, {11, 0xC1}, {12, 0xE8}, {13, 0x2C},                // 48 C1 E8 2C                 shr     rax, 2Ch
     {14, 0x40}, {15, 0x22}, {16, 0xC6},                            // 40 22 C6                    and     al, sil
     {17, 0x88}, {18, 0x05},                                        // 88 05 [63 63 FF FF]         mov     cs : WinHvpCpuManagement, al
     {23, 0x75},                                                    // 75 [24]                     jnz     short loc_1C001D483
     {25, 0x40}, {26, 0x88}, {27, 0x35},                            // 40 88 35 [5B 63 FF FF]      mov     cs : WinHvpRunningLoopback, sil
     {32, 0xE8},                                                    // E8 [D9 FD FF FF]            call    WinHvpAllocNumaMaps
     {37, 0x8B}, {38, 0xD8},                                        // 8B D8                       mov     ebx, eax
     {39, 0x85}, {40, 0xC0},                                        // 85 C0                       test    eax, eax
     {41, 0x0F}, {42, 0x88},                                        // 0F 88 [80 01 00 00]         js      loc_1C001D5F5
     {47, 0xE8},                                                    // E8 [9A FC FF FF]            call    WinHvpInitializeHypercallSupport
     {52, 0x8B}, {53, 0xD8},                                        // 8B D8                       mov     ebx, eax
     {54, 0x85}, {55, 0xC0},                                        // 85 C0                       test    eax, eax
     {56, 0xE9},                                                    // E9 [65 01 00 00]            jmp     loc_1C001D5E8
};

static const WINHVR_SIGNATURE gWinhvrSignatures[] = {
    {
        ARRAYSIZE(SigUpTo19H2),
        SigUpTo19H2
    },
    {
        ARRAYSIZE(Sig20H1AndUp),
        Sig20H1AndUp
    },
};

static const CX_UINT8 gWinhvrSignatureCount = ARRAYSIZE(gWinhvrSignatures);

static
CX_STATUS
ScanForWinhvrSysOnCurrentStack(
    _Out_ CX_BOOL* DriverFound
)
{
#define IS_KERNEL_POINTER_WIN(is64, p)  ((is64) ? (((p) & 0xFFFF800000000000) == 0xFFFF800000000000) : (((p) & 0x80000000) == 0x80000000))

    // winhvr!WinHvpInitialize -> nt!HviGetHypervisorFeatures -> cpuid
    // try to check if a call is from WinHvR.sys by signing the code immediately after the call to nt!HviGetHypervisorFeatures in winhvr!WinHvpInitialize

    CX_STATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    CX_UINT32 mappedCodeSize = 0;
    VCPU *vcpu = HvGetCurrentVcpu();
    CX_UINT64 addressOfReturnAddressGva = vcpu->ArchRegs.RSP + 0x8 + 0x20; // push rdi; sub rsp, 20h
    CX_UINT64 *addressOfReturnAddress = CX_NULL;
    CX_UINT64 returnAddressGva; // should point to code in WinHvpInitialize
    CX_VOID *returnAddress = CX_NULL;
    CX_UINT8 *codeAddress = CX_NULL;
    CX_UINT32 const sizeOfCallNop = 5;

    if (!DriverFound) return CX_STATUS_INVALID_PARAMETER;

    *DriverFound = CX_FALSE;

    status = ChmMapGvaRange(vcpu, addressOfReturnAddressGva, sizeof(CX_UINT64), CHM_FLAG_AUTO_ALIGN, &addressOfReturnAddress, 0, TAG_GENL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmMapGvaRange", status);
        goto cleanup;
    }

    returnAddressGva = *addressOfReturnAddress;

    if (!IS_KERNEL_POINTER_WIN(CX_TRUE, returnAddressGva))
    {
        goto cleanup;
    }

    for (CX_UINT32 i = 0; i < gWinhvrSignatureCount; i++)
        mappedCodeSize = CX_MAX(mappedCodeSize, gWinhvrSignatures[i].Bytes[gWinhvrSignatures[i].Count - 1].Pos);

    mappedCodeSize += 1 + sizeOfCallNop;

    status = ChmMapGvaRange(vcpu, returnAddressGva, mappedCodeSize, CHM_FLAG_AUTO_ALIGN, &returnAddress, 0, TAG_GENL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmMapGvaRange", status);
        goto cleanup;
    }

    codeAddress = returnAddress;

    if ((*(CX_UINT64*)returnAddress & 0x000000FFFFFFFFFF) == 0x0000441F0F) // 0F 1F 44 00 00     nop dword ptr [rax+rax+00h]
        codeAddress += sizeOfCallNop;

    CX_BOOL matched = CX_FALSE;

    for (CX_UINT32 i = 0; i < gWinhvrSignatureCount && !matched; i++)
    {
        matched = CX_TRUE;

        for (CX_UINT32 j = 0; j < gWinhvrSignatures[i].Count && matched; j++)
            matched = codeAddress[gWinhvrSignatures[i].Bytes[j].Pos] == gWinhvrSignatures[i].Bytes[j].Val;
    }

    *DriverFound = matched;

cleanup:
    if (returnAddress) ChmUnmapGvaRange(&returnAddress, TAG_GENL);

    if (addressOfReturnAddress) ChmUnmapGvaRange(&addressOfReturnAddress, TAG_GENL);

    return CX_STATUS_SUCCESS;
}

/// \addtogroup gst_enlight
/// @{

CX_STATUS
GstEnHandleCpuid(
    _In_  VCPU      *Vcpu,
    _In_  CX_UINT32 InEax,
    _In_  CX_UINT32 InEcx,
    _Out_ CX_UINT32 *Eax,
    _Out_ CX_UINT32 *Ebx,
    _Out_ CX_UINT32 *Ecx,
    _Out_ CX_UINT32 *Edx
)
{
    CX_STATUS status;

    UNREFERENCED_PARAMETER(InEcx);

    switch (InEax)
    {
    case RAX_MSFT_HV_LEAF_0:
    {
        *Eax = RAX_MSFT_HV_LEAF_MAX; // report max supported microsoft hypervisor identification cpuid leaf;

        // vendor id signature in the ebx, ecx, edx; they are used only for reporting and diagnostic purposes
        // according to MSFT HV TLFS documentation
        // "Napocahv    "
        *Ebx = 0x6e617067;
        *Ecx = 0x63616876;
        *Edx = 0x20202020;

        break;
    }
    case RAX_MSFT_HV_LEAF_1:
    {
        *Eax = 0x31237648; // 'Hv#1'  the hypervisor interface identification signature

        break;
    }
    case RAX_MSFT_HV_LEAF_2:    // Hypervisor system identity, no fields are necessary for minimal implementation
    {
        *Eax = 0;
        *Ebx = 0;
        *Ecx = 0;
        *Edx = 0;

        break;
    }
    case RAX_MSFT_HV_LEAF_3:
    {
        MSFT_HV_IDENTIFICATION_PARTITION_PRIVILEGES privilleges = { 0 };
        MSFT_HV_IDENTIFICATION_PARTITION_FLAGS      flags = { 0 };

        privilleges.Raw = 0;
        privilleges.AccessHypercallMsrs = 1;    // The partition has access to the synthetic MSRs
                                                // related to the hypercall interface (HV_X64_MSR_GUEST_OS_ID and HV_X64_MSR_HYPERCALL).

        privilleges.AcessVpIndex = 1;           // The partition has access to the synthetic MSR
                                                // that returns the virtual processor index.

        privilleges.AccessSynicMsrs = 0;        // Accesses to the synthetic MSRs associated with the Synic
                                                // (HV_X64_MSR_SCONTROL through HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15)
                                                // are not allowed => results in a #GP fault

        privilleges.AccessResetMsr = 1;         // This partition has access to the synthetic MSR that resets the system.

        privilleges.AccessPartitionReferenceCounter =           // The partition has (or not) access to the partition-wide
            CfgFeaturesVirtualizationEnlightRefCounter ? 1 : 0; // reference count MSR, HV_X64_MSR_TIME_REF_COUNT.

        privilleges.AccessPartitionReferenceTsc =               // The partition has (or not) access to the reference TSC.
            CfgFeaturesVirtualizationEnlightTscPage ? 1 : 0;    // Used to virtualize the TSC.

        flags.Raw = 0;

        MSFT_HV_X64_MSR_GUEST_OS_ID guestId;
        guestId.Raw = GstEnGetMsrValue(Vcpu, HV_X64_MSR_GUEST_OS_ID);
        if (CfgFeaturesVirtualizationEnlightCpuManagement == 1 ||
            (CfgFeaturesVirtualizationEnlightCpuManagement == 2 && guestId.Ms.MajorVersion == 10))
        {
            CX_UINT8 opMode;

            GstGetVcpuMode(Vcpu, &opMode);
            if (IS_KERNEL_POINTER_WIN((opMode == ND_CODE_64), HvGetCurrentVcpu()->ArchRegs.RIP))
            {
                flags.CpuManagement = 1;

                if (CfgHacksWinhvrReducedEnlightenment)
                {
                    // WinHvR.sys hack
                    // this driver crashes if it gets partial guest enlightment support therefore we enlight it less so that it gives up loading
                    CX_BOOL driverFound;

                    status = ScanForWinhvrSysOnCurrentStack(&driverFound);
                    if (CX_SUCCESS(status) && driverFound)
                    {
                        LOG("Lying to WinHvR.sys\n");
                        flags.CpuManagement = 0;
                    }
                }
            }
            else
            {
                flags.CpuManagement = 0;
            }
        }

        *Eax = privilleges.Raw;
        *Ebx = flags.Raw;
        *Ecx = 0;       // power management related information, may be zero
        *Edx = 0;       // miscellaneous features, may be zero

        break;

    }

    case RAX_MSFT_HV_LEAF_4:
    {
        MSFT_HV_IMPLEMENTATION_RECOMMENDATIONS implementation = { 0 };

        implementation.Raw = 0;
        implementation.RecommendRelaxedTiming = 1; // Recommend VM to disable watchdog timeouts that rely on the delivery of external interrups

        implementation.RecommendUsingMsrForSystemReset = 1;

        *Eax = implementation.Raw;
        *Ebx = 0;       // recommended number of attempts to retry a spinlock failure
                        // 0 - to disable
                        // 0xffffffff indicates never to retry
        *Ecx = 0;
        *Edx = 0;

        break;
    }

    case RAX_MSFT_HV_LEAF_5:
    {
        // in this leaf any value of 0 means the hypervisor does not expose the corresponding information

        /// we might need to set -1 instead of 0 in eax, documentation is not clear
        *Eax = (CX_UINT32)(-1);       // maximum number of virtual processors supported
        *Ebx = 0;       // maximum number of logical processors supported
        *Ecx = 0;       // maximum number of physical interrupt vectors available for interrupt remapping
        *Edx = 0;       // reserved

        break;
    }
    case RAX_MSFT_HV_LEAF_6:
    {
        *Eax = BIT(1) | // Support for MSR bitmaps is detected and in use.
            BIT(3);     // Support for second level address translation is detected and in use.

        *Ebx = 0;
        *Ecx = 0;
        *Edx = 0;

        break;
    }
    case RAX_MSFT_HV_LEAF_7:
    {
        *Eax = 0;
        *Ebx = 1;       // ProcessorPowerManagement
        *Ecx = 0;
        *Edx = 0;
        break;
    }
    default:
    {
        ERROR("Got unsupported Cpuid leaf 0x%x \n", InEax);
        status = CX_STATUS_OPERATION_NOT_IMPLEMENTED;
        DbgBreak();
        goto cleanup;
    }
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

CX_STATUS
GstEnHandleMsrRead(
    _In_ VCPU        *Vcpu,
    _In_ CX_UINT32   Msr,
    _Out_ CX_UINT64  *Value
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    if (!Value) return CX_STATUS_INVALID_PARAMETER_3;

    if ((Vcpu->Guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_EXPOSING_INTERFACE) == 0)
    {
        return STATUS_INJECT_GP;
    }

    switch (Msr)
    {
    case HV_X64_MSR_GUEST_OS_ID:
    {
        *Value = GstEnGetMsrValue(Vcpu, Msr);
        break;
    }
    case HV_X64_MSR_HYPERCALL:
    {
        *Value = GstEnGetMsrValue(Vcpu, Msr);
        break;
    }
    case HV_X64_MSR_VP_INDEX:
    {
        *Value = Vcpu->GuestCpuIndex;
        break;
    }
    case HV_X64_MSR_RESET:
    {
        *Value = 0;
        break;
    }
    case HV_X64_MSR_UNDOCUMENTED:
    {
        *Value = GstEnGetMsrValue(Vcpu, Msr);
        break;
    }
    case HV_X64_MSR_TIME_REF_COUNT:
    {
        *Value = Vcpu->PartitionReferenceTime;
        break;
    }
    case HV_X64_MSR_REFERENCE_TSC:
    {
        *Value = GstEnGetMsrValue(Vcpu, Msr);
        break;
    }
    case HV_X64_MSR_TSC_FREQUENCY:
    {
        status = STATUS_INJECT_GP;
        VCPULOG(Vcpu, "Requested TSC freq %p!\n", *Value);
        break;
    }
    case HV_X64_MSR_APIC_FREQUENCY:
    {
        status = STATUS_INJECT_GP;
        VCPULOG(Vcpu, "Requested APIC freq %p!\n", *Value);
        break;
    }
    case HV_X64_MSR_APIC_ASSIST_PAGE:
    case HV_X64_MSR_EOI:
    case HV_X64_MSR_ICR:
    case HV_X64_MSR_TPR:

    case HV_X64_MSR_SCONTROL:
    case HV_X64_MSR_SVERSION:
    case HV_X64_MSR_SIEFP:
    case HV_X64_MSR_SIMP:
    case HV_X64_MSR_EOM:
    case HV_X64_MSR_SINT0:
    case HV_X64_MSR_SINT1:
    case HV_X64_MSR_SINT2:
    case HV_X64_MSR_SINT3:
    case HV_X64_MSR_SINT4:
    case HV_X64_MSR_SINT5:
    case HV_X64_MSR_SINT6:
    case HV_X64_MSR_SINT7:
    case HV_X64_MSR_SINT8:
    case HV_X64_MSR_SINT9:
    case HV_X64_MSR_SINT10:
    case HV_X64_MSR_SINT11:
    case HV_X64_MSR_SINT12:
    case HV_X64_MSR_SINT13:
    case HV_X64_MSR_SINT14:
    case HV_X64_MSR_SINT15:
    {
        LOG("got synthetic rd msr 0x%x! \n", Msr);
        status = STATUS_INJECT_GP;
        break;
    }
    case HV_X64_MSR_POWER_STATE_TRIGGER_C1:
    case HV_X64_MSR_POWER_STATE_TRIGGER_C2:
    case HV_X64_MSR_POWER_STATE_TRIGGER_C3:
    {
        *Value = 0;
        break;
    }
    default:
    {
        CRITICAL("got synthetic rd msr 0x%x\n", Msr);
        status = STATUS_INJECT_GP;
        break;
    }
    }

    return status;
}

CX_STATUS
GstEnHandleMsrWrite(
    _In_ VCPU        *Vcpu,
    _In_ CX_UINT32   Msr,
    _In_ CX_UINT64   Value
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_UINT8 *hvaOfGuestHypercallPage = CX_NULL;

    if ((Vcpu->Guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_EXPOSING_INTERFACE) == 0)
    {
        return STATUS_INJECT_GP;
    }

    // save the value to our per vcpu cache
    GstEnSetMsrValue(Vcpu, Msr, Value);

    switch (Msr)
    {
    case HV_X64_MSR_GUEST_OS_ID:
    {
        //this is a guest global value so we need to make sure all vcpus have the same value
        for (CX_UINT32 i = 0; i < Vcpu->Guest->VcpuCount; i++)
        {
            GstEnSetMsrValue(Vcpu->Guest->Vcpu[i], Msr, Value);

            if (0 == Value)
            {
                GstEnSetMsrValue(Vcpu->Guest->Vcpu[i],
                                 HV_X64_MSR_HYPERCALL,
                                 (GstEnGetMsrValue(Vcpu->Guest->Vcpu[i], HV_X64_MSR_HYPERCALL) & ((CX_UINT64)~1))
                );

                Vcpu->Guest->HypercallPageActive = FALSE;
            }
        }

        MSFT_HV_X64_MSR_GUEST_OS_ID guestId;
        guestId.Raw = Value;
        LOG("Enlighted guest ID: Raw: 0x%016llX (%u.%u.%u.%u)\n", Value,
            guestId.Ms.MajorVersion, guestId.Ms.MinorVersion, guestId.Ms.ServiceVersion, guestId.Ms.BuildNumber);

        // In order to allow the Windows to throttle the physical CPU's on it's own,
        // we needed to expose the CpuManagement privilege (we never intended to implement a throttling on our own).
        // The documentation states that "Some implementations may restrict this partition privilege to the root partition"
        // and based on their behavior we managed to conclude the following:
        //  Windows 10: Activating by default (~before the GuestOS ID's registration) will always crash the system,
        //      exposing the CpuManagement privilege after the GuestOS ID's registration seems to work
        //      (mostly, still seems to use APERF/MPERF and on some CPUs the throttling is limited,
        //      causing the CPU to lose a few hundred Mhz from it's top range, probably somehow connected to the TURBO_RATIO_LIMIT MSR)
        //  Windows 7: The OS seems to use the legacy APERF/MPERF,
        //      disregarding the CpuManagement privilege and throttles the CPU on it's free will
        //  Windows 8: Exposing the privilege at any point seems to be impossible without crashing the system
        //      (or implementing a massive amount of additional undocumented features from the MSHI).
        //      As the last resort we forcefully activated HWP with maximum performance, if it is supported by the CPU.
        // If windows is not win 10 or win 7 (which uses APERF/MPERF) and CfgFeaturesActivateHwp is set to 2 (enable HWP on any OS != 10 || 7), enable HWP
        if (CfgFeaturesActivateHwp == 2 && (!(guestId.Ms.MajorVersion == 10 || (guestId.Ms.MajorVersion == 6 && guestId.Ms.MinorVersion == 1))))
        {
            HvActivatePerformanceMode();
        }
        break;
    }
    case HV_X64_MSR_HYPERCALL:
    {
        //this is a guest global value so we need to make sure all vcpus have the same value
        for (CX_UINT32 i = 0; i < Vcpu->Guest->VcpuCount; i++)
        {
            GstEnSetMsrValue(Vcpu->Guest->Vcpu[i], Msr, Value);
        }

        if (0 == GstEnGetMsrValue(Vcpu, HV_X64_MSR_GUEST_OS_ID))
        {
            LOG("trying to write value %p to HV_X64_MSR_HYPERCALL but no Guest ID set \n", Value);
            // documentation says this should "fail" but says nothing about a #GP as it does in other cases
            status = STATUS_INJECT_GP;
        }
        else
        {
            if (Value & 0x1ULL)
            {
                CX_UINT64 length = 0;
                CX_UINT8 operationMode;

                VCPULOG(Vcpu, "Activating the Hypercall page at guest GPA %p \n", (Value & PAGE_MASK));

                // check if this is a valid GPA for this guest, otherwise inject a #GP
                if (!EptIsMemMapped(GstGetEptOfPhysicalMemory(Vcpu->Guest), CX_PAGE_BASE_4K(Value), 0))
                {
                    ERROR("EptIsMemMapped returned CX_FALSE\n");
                    status = STATUS_INJECT_GP;
                    break;
                }
                // remove write and add read and execute right
                status = EptSetRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), CX_PAGE_BASE_4K(Value), 0, EPT_RIGHTS_RX);
                if (!CX_SUCCESS(status))
                {
                    status = STATUS_INJECT_GP;
                    break;
                }

                status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, Value & PAGE_MASK, 1, 0, &hvaOfGuestHypercallPage, CX_NULL, TAG_GENL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("ChmMapContinuousGuestGpaPagesToHost", status);
                    break;
                }

                // copy the x86/x64 code stub
                GstGetVcpuMode(Vcpu, &operationMode);
                Vcpu->Guest->HypercallPage = hvaOfGuestHypercallPage;

                CX_VOID *codeStart, *codeEnd;
                if (operationMode == ND_CODE_64)
                {
                    codeStart = &GuestHypercallStubx64;
                    codeEnd = &GuestHypercallStubEndx64;
                }
                else
                {
                    codeStart = &GuestHypercallStubx86;
                    codeEnd = &GuestHypercallStubEndx86;
                }

                length = (CX_UINT64)codeEnd - (CX_UINT64)codeStart;

                if ((length > CX_PAGE_SIZE_4K) || (0 == length))
                {
                    status = CX_STATUS_INVALID_INTERNAL_STATE;
                    break;
                }

                memcpy(Vcpu->Guest->HypercallPage, codeStart, length);

                Vcpu->Guest->HypercallPageActive = TRUE;
            }
            else
            {
                Vcpu->Guest->HypercallPageActive = FALSE;

                INFO("Disabling Hypercall page \n");
            }
        }
        break;
    }
    case HV_X64_MSR_VP_INDEX:
    {
        status = STATUS_INJECT_GP;
        break;
    }
    case HV_X64_MSR_RESET:
    {
        if (Value & 0x1)
        {
            VCPULOG(Vcpu, "System reset requested via msr 0x%x access with value %p. writing to 0x%x value 0x%x.\n",
                    Msr, Value, gHypervisorGlobalData.AcpiData.Fadt->ResetRegister.Address, gHypervisorGlobalData.AcpiData.Fadt->ResetValue);

            PwrReboot(CX_FALSE, CX_FALSE);
        }
        break;
    }
    case HV_X64_MSR_UNDOCUMENTED:
    {
        break;
    }
    case HV_X64_MSR_REFERENCE_TSC:
    {
        //this is a guest global value so we need to make sure all vcpus have the same value
        for (CX_UINT32 i = 0; i < Vcpu->Guest->VcpuCount; i++)
        {
            GstEnSetMsrValue(Vcpu->Guest->Vcpu[i], Msr, Value);
        }

        if (0 == GstEnGetMsrValue(Vcpu, HV_X64_MSR_GUEST_OS_ID))
        {
            VCPULOG(Vcpu, "trying to write value %p to HV_X64_MSR_REFERENCE_TSC but no Guest ID set \n", Value);
            // documentation says this should "fail" but says nothing about a #GP as it does in other cases
        }
        else
        {
            if (Value & 0x1ULL)
            {
                CX_UINT8 *hva = CX_NULL;

                VCPULOG(Vcpu, "Activating REFERENCE_TSC page at guest GPA %p \n", Value & PAGE_MASK);

                // check if this is a valid GPA for this guest, otherwise inject a #GP
                if (!EptIsMemMapped(GstGetEptOfPhysicalMemory(Vcpu->Guest), CX_PAGE_BASE_4K(Value), 0))
                {
                    ERROR("EptIsMemMapped returned CX_FALSE\n");
                    status = STATUS_INJECT_GP;
                    break;
                }

                // As you can see, (if we use this workaround) we practically do not offer any rights to the physical page
                // where the REFERENCE TSC page is, so we put a hook that will take the next
                // guest access to this page. Why?
                // On Win10 RS4 Hibernate results in a Bugcheck 0x00A (DRIVER_IRQL_NOT_LESS_OR_EQUAL),
                // and for the rest of the operating systems it seems to work ok. After investigation,
                // it seems that the OS pulls off the Reading rights from the TSC page in its own Mapping structures,
                // then once more it tries to read the TSC page, which results in a Bugcheck.
                // Found out that if we overwrite the PWT bit (bit 3) in the PTE
                // for the address of the TSC page in the guests mapping structures,
                // then at hibernate the guest doesn't change its mapping rights for the TSC page and the Hibernate works.
                status = EptSetRights(
                    GstGetEptOfPhysicalMemory(Vcpu->Guest),
                    CX_PAGE_BASE_4K(Value),
                    0,
                    CfgFeaturesVirtualizationEnlightTscPageWorkaround ? EPT_RIGHTS_NONE : EPT_RIGHTS_R);
                if (!CX_SUCCESS(status))
                {
                    status = STATUS_INJECT_GP;
                    break;
                }

                status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, Value & PAGE_MASK, 1, 0, &hva, CX_NULL, TAG_GENL);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("ChmMapContinuousGuestGpaPagesToHost", status);
                    break;
                }

                memzero((CX_UINT8 *)hva, CX_PAGE_SIZE_4K);

                Vcpu->ReferenceTscPage = (HV_REFERENCE_TSC_PAGE *)hva;

                Vcpu->ReferenceTscPage->TscSequence = 1;
                Vcpu->ReferenceTscPage->TscScale = ((10000LL << 32) / (gTscSpeed / 1000)) << 32;
                Vcpu->ReferenceTscPage->TscOffset = 0;

                VCPULOG(Vcpu, "TSC page: Seq 0x%x, Scale 0x%llx, Offset 0x%llx\n",
                        Vcpu->ReferenceTscPage->TscSequence,
                        Vcpu->ReferenceTscPage->TscScale,
                        Vcpu->ReferenceTscPage->TscOffset);

                CX_UINT64 hpa = 0;
                status = MmQueryPa(&gHvMm, Vcpu->ReferenceTscPage, &hpa);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("MmQueryPa", status);
                    break;
                }

                VCPULOG(Vcpu, "TSC HPA: 0x%llx, HVA: 0x%llx\n", hpa, hva);

                //this is a guest global value so we need to make sure all vcpus have the same value
                for (CX_UINT32 i = 0; i < Vcpu->Guest->VcpuCount; i++)
                {
                    Vcpu->Guest->Vcpu[i]->ReferenceTscPage = (HV_REFERENCE_TSC_PAGE *)hva;
                }

                // init the single-use-hook mechanism
                if (CfgFeaturesVirtualizationEnlightTscPageWorkaround) CxInterlockedExchange8(&Vcpu->Guest->TscWorkaroundInit, CX_INTERLOCKED_ONCE_NOT_STARTED);
            }
            else
            {
                INFO("Disabling REFERENCE TSC page \n");
            }
        }
        break;
    }
    case HV_X64_MSR_APIC_ASSIST_PAGE:
    case HV_X64_MSR_EOI:
    case HV_X64_MSR_ICR:
    case HV_X64_MSR_TPR:

    case HV_X64_MSR_SCONTROL:
    case HV_X64_MSR_SVERSION:
    case HV_X64_MSR_SIEFP:
    case HV_X64_MSR_SIMP:
    case HV_X64_MSR_EOM:
    case HV_X64_MSR_SINT0:
    case HV_X64_MSR_SINT1:
    case HV_X64_MSR_SINT2:
    case HV_X64_MSR_SINT3:
    case HV_X64_MSR_SINT4:
    case HV_X64_MSR_SINT5:
    case HV_X64_MSR_SINT6:
    case HV_X64_MSR_SINT7:
    case HV_X64_MSR_SINT8:
    case HV_X64_MSR_SINT9:
    case HV_X64_MSR_SINT10:
    case HV_X64_MSR_SINT11:
    case HV_X64_MSR_SINT12:
    case HV_X64_MSR_SINT13:
    case HV_X64_MSR_SINT14:
    case HV_X64_MSR_SINT15:
    {
        LOG("got synthetic wr msr 0x%x with value %p \n", Msr, Value);
        status = STATUS_INJECT_GP;
        break;
    }
    default:
    {
        CRITICAL("got synthetic wr msr 0x%x with value %p \n", Msr, Value);
        status = STATUS_INJECT_GP;
        break;
    }
    }

    return status;
}

CX_STATUS
GstEnUpdatePartitionRefCount(
    _In_     GUEST       *Guest,
    _Out_    CX_UINT64   *RefValue
)
{
    UNREFERENCED_PARAMETER(Guest);

    VCPU* vcpu = HvGetCurrentVcpu();
    *RefValue = HvTscTicksIntervalTo100Ns(vcpu->LastExitTsc, vcpu->AttachedPcpu->StartTsc);

    return CX_STATUS_SUCCESS;
}

CX_BOOL
GstEnIsHyperPageAddress(
    _In_ CX_UINT64 Address
)
{
    VCPU *vcpu = HvGetCurrentVcpu();

    static const CX_UINT64 pages[] = {
        HV_X64_MSR_REFERENCE_TSC,
        HV_X64_MSR_HYPERCALL,
    };

    for (CX_UINT8 pageIdx = 0; pageIdx < ARRAYSIZE(pages); pageIdx++)
    {

        CX_UINT64 page = GstEnGetMsrValue(vcpu, pages[pageIdx]);
        if ((PAGE_BASE_PA(page)) && (PAGE_BASE_PA(page) == PAGE_BASE_PA(Address)))
        {
            return CX_TRUE;
        }
    }

    return CX_FALSE;
}

/// @}