/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file hypercall.c
*   @brief The hypercall handler
*
* Based on: Hypervisor Top Level Functional Specification -  July, 2018: Released Version 5.0c
*
*/

/// \addtogroup hc
/// @{

#include "napoca.h"
#include "kernel/hypercall.h"
#include "memory/cachemap.h"

/**
*   @brief Define that allows you to format the log of a hypercall.
*/
#define HCALL_LOG LOG

/// @}

/// \defgroup hc_codes Hypercall Codes
/// \ingroup hc
/// @{

/** @name Hypercall codes
*   @brief Define codes for hypercalls.
*
* These can be likened to SYSCALL numbers.
* Each guest operating system request to the hypervisor is encoded in a code below.
*
*/
///@{
#define HvSwitchVirtualAddressSpace          0x0001
#define HvFlushVirtualAddressSpace           0x0002
#define HvFlushVirtualAddressList            0x0003
#define HvGetLogicalProcessorRunTime         0x0004
// Reserved 0x0005 - 0x0007
#define HvNotifyLongSpinWait                 0x0008
#define HvCallParkedVirtualProcessors        0x0009 // in the documentation says 0x00090 (probably a typo)
#define HvCallSendSyntheticClusterIpi        0x000b
#define HvCallModifyVtlProtectionMask        0x000c
#define HvCallEnablePartitionVtl             0x000d
#define HvCallDisablePartitionVtl            0x000e
#define HvCallEnableVpVtl                    0x000f
#define HvCallDisableVpVtl                   0x0010
#define HvCallVtlCall                        0x0011
#define HvCallVtlReturn                      0x0012
#define HvCallFlushVirtualAddressSpaceEx     0x0013
#define HvCallFlushVirtualAddressListEx      0x0014
#define HvCallSendSyntheticClusterIpiEx      0x0015
// Reserved 0x0016 - 0x003F
#define HvCreatePartition                    0x0040
#define HvInitializePartition                0x0041
#define HvFinalizePartition                  0x0042
#define HvDeletePartition                    0x0043
#define HvGetPartitionProperty               0x0044
#define HvSetPartitionProperty               0x0045
#define HvGetPartitionId                     0x0046
#define HvGetNextChildPartition              0x0047
#define HvDepositMemory                      0x0048
#define HvWithdrawMemory                     0x0049
#define HvGetMemoryBalance                   0x004A
#define HvMapGpaPages                        0x004B
#define HvUnmapGpaPages                      0x004C
#define HvInstallIntercept                   0x004D
#define HvCreateVp                           0x004E
#define HvDeleteVp                           0x004F
#define HvGetVpRegisters                     0x0050
#define HvSetVpRegisters                     0x0051
#define HvTranslateVirtualAddress            0x0052
#define HvReadGpa                            0x0053
#define HvWriteGpa                           0x0054
// Deprecated 0x0055
#define HvClearVirtualInterrupt              0x0056
// Deprecated 0x0057
#define HvDeletePort                         0x0058
#define HvConnectPort                        0x0059
#define HvGetPortProperty                    0x005A
#define HvDisconnectPort                     0x005B
#define HvPostMessage                        0x005C
#define HvSignalEvent                        0x005D
#define HvSavePartitionState                 0x005E
#define HvRestorePartitionState              0x005F
#define HvInitializeEventLogBufferGroup      0x0060
#define HvFinalizeEventLogBufferGroup        0x0061
#define HvCreateEventLogBuffer               0x0062
#define HvDeleteEventLogBuffer               0x0063
#define HvMapEventLogBuffer                  0x0064
#define HvUnmapEventLogBuffer                0x0065
#define HvSetEventLogGroupSources            0x0066
#define HvReleaseEventLogBuffer              0x0067
#define HvFlushEventLogBuffer                0x0068
#define HvPostDebugData                      0x0069
#define HvRetrieveDebugData                  0x006A
#define HvResetDebugSession                  0x006B
#define HvMapStatsPage                       0x006C
#define HvUnmapStatsPage                     0x006D
#define HvCallMapSparseGpaPages              0x006E
#define HvCallSetSystemProperty              0x006F
#define HvCallSetPortProperty                0x0070
// Reserved 0x0071 - 0x0075
#define HvCallAddLogicalProcessor            0x0076
#define HvCallRemoveLogicalProcessor         0x0077
#define HvCallQueryNumaDistance              0x0078
#define HvCallSetLogicalProcessorProperty    0x0079
#define HvCallGetLogicalProcessorProperty    0x007A
#define HvCallGetSystemProperty              0x007B
#define HvCallMapDeviceInterrupt             0x007C
#define HvCallUnmapDeviceInterrupt           0x007D
#define HvCallRetargetDeviceInterrupt        0x007E
// Reserved 0x007F
#define HvCallMapDevicePages                 0x0080
#define HvCallUnmapDevicePages               0x0081
#define HvCallAttachDevice                   0x0082
#define HvCallDetachDevice                   0x0083
#define HvCallNotifyStandbyTransition        0x0084
#define HvCallPrepareForSleep                0x0085
#define HvCallPrepareForHibernate            0x0086
#define HvCallNotifyPartitionEvent           0x0087
#define HvCallGetLogicalProcessorRegisters   0x0088
#define HvCallSetLogicalProcessorRegisters   0x0089
#define HvCallQueryAssociatedLpsforMca       0x008A
#define HvCallNotifyRingEmpty                0x008B
#define HvCallInjectSyntheticMachineCheck    0x008C
#define HvCallScrubPartition                 0x008D
#define HvCallCollectLivedump                0x008E
#define HvCallDisableHypervisor              0x008F
#define HvCallModifySparseGpaPages           0x0090
#define HvCallRegisterInterceptResult        0x0091
#define HvCallUnregisterInterceptResult      0x0092
#define HvCallAssertVirtualInterrupt         0x0094
#define HvCallCreatePort                     0x0095
#define HvCallConnectPort                    0x0096
#define HvCallGetSpaPageList                 0x0097
// Reserved 0x0098
#define HvCallStartVirtualProcessor          0x0099
#define HvCallGetVpIndexFromApicId           0x009A
// Reserved 0x009A - 0x00AE
#define HvCallFlushGuestPhysicalAddressSpace 0x00AF
#define HvCallFlushGuestPhysicalAddressList  0x00B0

//
// Extended hypercall list
//
#define HvExtCallQueryCapabilities           0x8001
#define HvExtCallGetBootZeroedMemory         0x8002
///@}

/// @}

/// \addtogroup hc
/// @{

// Virtual address spaces are identified by a caller-defined 64-bit ID value.
typedef CX_UINT64 HC_HV_ADDRESS_SPACE_ID;

typedef CX_UINT32 HC_HV_FLUSH_FLAGS;

#pragma pack(push, 1)
/**
* @brief    The structure that represents the input to a hypercall which
*           invalidates portions of the virtual TLB that belong to a specified address space.
*/
typedef struct _HC_FLUSH_VIRTUAL_ADDRESS_LIST
{
    HC_HV_ADDRESS_SPACE_ID AddressSpace;    ///< Specifies an address space ID (a CR3 value).
    HC_HV_FLUSH_FLAGS Flags;                ///< Specifies a set of flag bits that modify the operation of the flush.
    CX_UINT32 _Padding;
    CX_UINT64 ProcessorMask;                ///< Specifies a processor mask indicating which processors
                                            ///< should be affected by the flush operation.

    CX_VOID* GvaRangeList[];                ///< A list of GVA ranges. Each range has a base GVA.
                                            ///< Because flushes are performed with page granularity,
                                            ///< the bottom 12 bits of the GVA can be used to define a range length. These bits encode the number of additional pages (beyond the initial page) within the range. This allows each entry to encode a range of 1 to 4096 pages.
}HC_FLUSH_VIRTUAL_ADDRESS_LIST;

/**
* @brief    Hypercall input value.
*           Note that it is 64 bits long. In the case of 64-bit guest operating systems
*           the input is placed in the RCX register and in the case of the 32-bit ones
*           the input will be in the EDX:EAX registers
*/
typedef union _HYPERCALL_INPUT_VALUE
{
    CX_UINT64 RawQword;
    struct
    {
        CX_UINT16 CallCode;                 ///< Specifies which hypercall is requested

        CX_UINT16 IsFastCall         : 1;   ///< Specifies whether the hypercall uses the register-based calling convention.
                                            ///< 0: Use the memory-based calling convention
                                            ///< 1: Use the register-based calling convention

        // In documentation this field is 9 bits long.
        // However, if we add all the bits we get to only 63.
        // Probably this field is of size 10 and it's a typo in the documentation
        CX_UINT16 VariableHeaderSize : 10;  ///< The size of a variable header, in QWORDS
        CX_UINT16 _ReservedZero1     : 5;   ///< Must be zero
        CX_UINT16 RepCount           : 12;  ///< Total number of reps (for rep call, must be zero otherwise)
        CX_UINT16 _ReservedZero2     : 4;   ///< Must be zero
        CX_UINT16 RepIndex           : 12;  ///< Starting index (for rep call, must be zero otherwise)
        CX_UINT16 _ReservedZero3     : 4;   ///< Must be zero
    };
} HYPERCALL_INPUT_VALUE;

/**
* @brief    Hypercall result value.
*           Note that it is 64 bits long. In the case of 64-bit guest operating systems
*           the result is placed in the RCX register and in the case of the 32-bit ones
*           the result will be in the EDX:EAX registers
*/
typedef union _HYPERCALL_RESULT_VALUE
{
    CX_UINT64 RawQword;
    struct
    {
        CX_UINT32 LowDword;
        CX_UINT32 HighDword;
    };
    struct
    {
        CX_UINT16 Result;               ///< HV_STATUS code indicating success or failure
        CX_UINT16 _Reserved1;           ///< Callers should ignore the value in these bits
        CX_UINT32 RepsCompleted : 12;   ///< Number of reps successfully completed
        CX_UINT32 _Reserved2    : 20;   ///< Callers should ignore the value in these bits
    };
}HYPERCALL_RESULT_VALUE;
#pragma pack(pop)

//
// Additional internal functions
//

///
/// @brief Check if the guest OS that did the hypercall is in long mode or not.
///
/// @param[in] Vcpu     The vcpu on which the hypercall-specific vmcall exit was performed
///
/// @returns    TRUE    - if guest OS is running in 64 bits mode.
/// @returns    FALSE   - if guest OS NOT is running in 64 bits mode.
///
static
BOOLEAN
_HcIsCaller64bit(
    _In_ VCPU* Vcpu
)
{
    BYTE operationMode;

    GstGetVcpuMode(Vcpu, &operationMode);

    return operationMode == ND_CODE_64;
}

VOID
HcHyperCallHandler(
    VOID
)
{
    CX_STATUS status;
    HYPERCALL_INPUT_VALUE hcInputVal;
    HC_HV_STATUS hcStatus;
    VCPU *vcpu = HvGetCurrentVcpu();
    CX_BOOL is64BitCaller = _HcIsCaller64bit(vcpu);
    CX_UINT64 inGpa, outGpa;

    inGpa = outGpa = 0;

    // Whether or not the hypercall is fast,
    // its code will be in the RCX or EDX : EAX
    // Input and output parameters GPAs: (if the hypercall is not of fast type)
    //    x64    |    x86    |    Content
    //    RCX    |  EBX:ECX  | Input Parameters GPA
    //    R8     |  EDI:ESI  | Output Parameters GPA
    if (is64BitCaller)
    {
        hcInputVal.RawQword = vcpu->ArchRegs.RCX;

        if (!hcInputVal.IsFastCall)
        {
            inGpa = vcpu->ArchRegs.RDX;
            outGpa = vcpu->ArchRegs.R8;
        }
    }
    else
    {
        hcInputVal.RawQword = (vcpu->ArchRegs.RDX << 32) | vcpu->ArchRegs.EAX;

        if (!hcInputVal.IsFastCall)
        {
            inGpa = (vcpu->ArchRegs.RBX << 32) | vcpu->ArchRegs.ECX;
            outGpa = (vcpu->ArchRegs.RDI << 32) | vcpu->ArchRegs.ESI;
        }
    }

    HCALL_LOG("[HC %s - %p] CallCode: 0x%04X, IsFastCall: %s, RepCount: %u, RepIndex: %u, inGpa: 0x%016llX, outGpa: 0x%016llX\n",
        is64BitCaller ? "x64" : "x86", vcpu->ArchRegs.RIP, hcInputVal.CallCode, hcInputVal.IsFastCall ? "YES": "NO",
        hcInputVal.RepCount, hcInputVal.RepIndex, inGpa, outGpa);

    switch (hcInputVal.CallCode) {
    case HvFlushVirtualAddressSpace:
    {
        HC_FLUSH_VIRTUAL_ADDRESS_LIST *hcFvas;

        if (hcInputVal.IsFastCall)
        {
            hcStatus = HC_HV_STATUS_INVALID_PARAMETER;
            break;
        }

        status = ChmMapContinuousGuestGpaPagesToHost(gHypervisorGlobalData.Guest[0], inGpa, 1, 0, &hcFvas, NULL, TAG_HCAL);
        if (!NT_SUCCESS(status))
        {
            ERROR("ChmMapContinuousGuestGpaPagesToHost failed on %p with %s\n", inGpa, NtStatusToString(status));
            hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
            break;
        }
        else
        {
            HCALL_LOG("--- 0x%016llX: AddressSpace: 0x%016llX, Flags: 0x%08X, ProcessorMask: 0x%016llX, GvaRange[0]: 0x%016llX\n",
                hcFvas, hcFvas->AddressSpace, hcFvas->Flags, hcFvas->ProcessorMask, hcFvas->GvaRangeList[0]);
        }

        CpuVmxInvVpid(2, 0, vcpu->Vpid);

        status = ChmUnmapContinuousGuestGpaPagesFromHost(&hcFvas, TAG_HCAL);
        if (!NT_SUCCESS(status))
        {
            ERROR("ChmUnmapContinuousGuestGpaPagesFromHost failed on %p with %s\n", hcFvas, NtStatusToString(status));
            hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
            break;
        }

        hcStatus = HC_HV_STATUS_SUCCESS;
        break;
    }
    case HvFlushVirtualAddressList:
    {
        HC_FLUSH_VIRTUAL_ADDRESS_LIST *hcFval;

        if (hcInputVal.IsFastCall)
        {
            hcStatus = HC_HV_STATUS_INVALID_PARAMETER;
            break;
        }

        status = ChmMapContinuousGuestGpaPagesToHost(gHypervisorGlobalData.Guest[0], inGpa, 1, 0, &hcFval, NULL, TAG_HCAL);
        if (!NT_SUCCESS(status))
        {
            ERROR("ChmMapContinuousGuestGpaPagesToHost failed on %p with %s\n", inGpa, NtStatusToString(status));
            hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
            break;
        }
        else
        {
            HCALL_LOG("--- 0x%016llX: AddressSpace: 0x%016llX, Flags: 0x%08X, ProcessorMask: 0x%016llX, GvaRange[0]: 0x%016llX\n",
                hcFval, hcFval->AddressSpace, hcFval->Flags, hcFval->ProcessorMask, hcFval->GvaRangeList[0]);
        }

        CpuVmxInvVpid(2, 0, vcpu->Vpid);

        status = ChmUnmapContinuousGuestGpaPagesFromHost(&hcFval, TAG_HCAL);
        if (!NT_SUCCESS(status))
        {
            ERROR("ChmUnmapContinuousGuestGpaPagesFromHost failed on %p with %s\n", hcFval, NtStatusToString(status));
            hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
            break;
        }

        hcStatus = HC_HV_STATUS_SUCCESS;
        break;
    }

    case HvExtCallQueryCapabilities:
        hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
        WARNING("HvExtCallQueryCapabilities called\n");
        break;
    default:
        ERROR("Unexpected hypercall: 0x%04X\n", hcInputVal.CallCode);
        hcStatus = HC_HV_STATUS_INVALID_HYPERCALL_CODE;
        break;
    }

    HYPERCALL_RESULT_VALUE resultVal = { 0 };
    resultVal.Result = hcStatus;
    if (resultVal.Result == HC_HV_STATUS_SUCCESS)
    {
        // For rep hypercalls, the reps complete field is the total number of reps complete.
        // We solve each hypercall in one call, we do not use the hypercall rep mechanism
        resultVal.RepsCompleted = hcInputVal.RepCount;
    }

    // The hypercall result value is passed back in registers.
    // The register mapping depends on whether the caller is running in 32-bit (x86) or 64-bit (x64) mode.
    // The register mapping for hypercall outputs is as follows:
    //    x64    |    x86    |    Content
    //    RAX    |  EDX:EAX  | Hypercall Result Value
    if (is64BitCaller)
    {
        vcpu->ArchRegs.RAX = resultVal.RawQword;
        HCALL_LOG("--- Results: 0x%016llX\n", vcpu->ArchRegs.RAX);
    }
    else
    {
        vcpu->ArchRegs.EAX = resultVal.LowDword;
        vcpu->ArchRegs.EDX = resultVal.HighDword;
    }

    return;
}

/// @}
