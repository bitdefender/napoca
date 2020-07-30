/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file guestenlight.h
*   @brief The enlightment interface exposed by our Hypervisor
*/

/// \defgroup gst_enlight Guest Enlightenments - Support to expose the enlightenment interface
/// @{

#ifndef __GUEST_ENLIGHT_H__
#define __GUEST_ENLIGHT_H__

#include "base/cx_sal.h"
#include "base/cx_defs.h"
#include "base/cx_types.h"

typedef struct _VCPU VCPU;
typedef struct _GUEST GUEST;

/**
*   @brief The layout of the MSR that the guest writes to identify itself to the hypervisor.
*
*   The guest OS running within the partition must identify itself
*   to the hypervisor by writing its signature and version to an MSR (HV_X64_MSR_GUEST_OS_ID).
*   This MSR is partition-wide and is shared among all virtual processors
*   (virtual processors are described in chapter 7, Virtual Processor Management).
*   The following is the recommended encoding for this MSR. Some fields may not apply for some guest OSs.
*
*/
typedef union _MSFT_HV_X64_MSR_GUEST_OS_ID
{
    CX_UINT64 Raw;
    union
    {
        struct
        {
            CX_UINT64 BuildNumber       : 16;   ///< Indicates the build number of the OS
            CX_UINT64 ServiceVersion    : 8;    ///< Indicates the service version (for example, "service pack" number).
            CX_UINT64 MinorVersion      : 8;    ///< Indicates the minor version of the OS.
            CX_UINT64 MajorVersion      : 8;    ///< Indicates the major version of the OS.
            CX_UINT64 OsId              : 8;    ///< Indicates the OS variant. Encoding is unique to the vendor.

            CX_UINT64 VendorId          : 15;   ///< Indicates the guest OS vendor. A value of 0 is reserved.
                                                ///< A value of 1 indicates Microsoft.

            CX_UINT64 OsType            : 1;    ///< Indicates the OS types. A value of 0 indicates a proprietary,
                                                ///< closed source OS. A value of 1 indicates an open source OS.
        }Ms;
        struct
        {
            CX_UINT64 BuildNumber       : 16;   ///< Bits 15:0 should specify any additional identification.
            CX_UINT64 Version           : 32;   ///< Bits 47:16 should specify the upstream kernel version information.

            CX_UINT64 OsId              : 8;    ///< Bits 55:48 may specify any additional vendor information

            CX_UINT64 OsType            : 8;    ///< Bits 62-57 should specify the OS type (e.g., Linux, FreeBSD, etc.).
                                                ///< Linux is 0x100.

            CX_UINT64 OpenSource        : 1;    ///< Bit 63 should be set to 1 to indicate an Open Source OS.
        }OpenSourceSO;
    };
}MSFT_HV_X64_MSR_GUEST_OS_ID;

/** @name CPUID leafs
*   @brief CPUID leafs used to discover Hypervisor features.
*
*   CPUID.01h.ECX:31 if set, virtualization present
*   If the "hypervisor present bit" is set, additional CPUID leafs can be queried
*   for more information about the conformant hypervisor and its capabilities.
*   Two such leaves are guaranteed to be available: 0x40000000 and 0x40000001.
*   Subsequently-numbered leaves may also be available.
*   When the leaf at 0x40000000 is queried, the hypervisor will return information
*   that provides the maximum hypervisor CPUID leaf number (RAX_MSFT_HV_LEAF_MAX) and a vendor ID signature.
*
*/
///@{
#define RAX_MSFT_HV_LEAF_0              0x40000000
#define RAX_MSFT_HV_LEAF_1              0x40000001
#define RAX_MSFT_HV_LEAF_2              0x40000002
#define RAX_MSFT_HV_LEAF_3              0x40000003
#define RAX_MSFT_HV_LEAF_4              0x40000004
#define RAX_MSFT_HV_LEAF_5              0x40000005
#define RAX_MSFT_HV_LEAF_6              0x40000006
#define RAX_MSFT_HV_LEAF_7              0x40000007
#define RAX_MSFT_HV_LEAF_MIN            RAX_MSFT_HV_LEAF_0
#define RAX_MSFT_HV_LEAF_MAX            RAX_MSFT_HV_LEAF_7
#define RAX_MSFT_HV_READ_OSID           0x4f000000
///@}

/** @name Synthetic MSRs
*   @brief Used to query or set some enlightment interface specific variables
*/
///@{
#define HV_X64_MSR_GUEST_OS_ID          0x40000000
#define HV_X64_MSR_HYPERCALL            0x40000001
#define HV_X64_MSR_VP_INDEX             0x40000002
#define HV_X64_MSR_UNDOCUMENTED         0x40000004
#define HV_X64_MSR_TIME_REF_COUNT       0x40000020
#define HV_X64_MSR_REFERENCE_TSC        0x40000021
#define HV_X64_MSR_TSC_FREQUENCY        0x40000022
#define HV_X64_MSR_APIC_FREQUENCY       0x40000023
#define HV_X64_MSR_POWER_STATE_TRIGGER_C1 0x400000C1
#define HV_X64_MSR_POWER_STATE_TRIGGER_C2 0x400000C2
#define HV_X64_MSR_POWER_STATE_TRIGGER_C3 0x400000C3
///@}

/** @name SynIC MSRs
*   @brief can be used to interrupt virtualization
*/
///@{
#define HV_X64_MSR_SCONTROL             0x40000080
#define HV_X64_MSR_SVERSION             0x40000081
#define HV_X64_MSR_SIEFP                0x40000082
#define HV_X64_MSR_SIMP                 0x40000083
#define HV_X64_MSR_EOM                  0x40000084
#define HV_X64_MSR_SINT0                0x40000090
#define HV_X64_MSR_SINT1                0x40000091
#define HV_X64_MSR_SINT2                0x40000092
#define HV_X64_MSR_SINT3                0x40000093
#define HV_X64_MSR_SINT4                0x40000094
#define HV_X64_MSR_SINT5                0x40000095
#define HV_X64_MSR_SINT6                0x40000096
#define HV_X64_MSR_SINT7                0x40000097
#define HV_X64_MSR_SINT8                0x40000098
#define HV_X64_MSR_SINT9                0x40000099
#define HV_X64_MSR_SINT10               0x4000009A
#define HV_X64_MSR_SINT11               0x4000009B
#define HV_X64_MSR_SINT12               0x4000009C
#define HV_X64_MSR_SINT13               0x4000009D
#define HV_X64_MSR_SINT14               0x4000009E
#define HV_X64_MSR_SINT15               0x4000009F
///@}

/** @name Local APIC MSR Accesses
*/
///@{
#define HV_X64_MSR_EOI                  0x40000070
#define HV_X64_MSR_ICR                  0x40000071
#define HV_X64_MSR_TPR                  0x40000072
#define HV_X64_MSR_APIC_ASSIST_PAGE     0x40000073
///@}

/**
*   @brief Reset MSR.
*
*   Guest OS can signal machine reboot writing to this MSR.
*
*/
#define HV_X64_MSR_RESET                0x40000003

#define HV_X64_MSR_MAX                  0x400001FF
#define HV_X64_MSR_INDEX_MASK           0x000001FF
#define HV_X64_MSR_MAX_COUNT            ((HV_X64_MSR_MAX & HV_X64_MSR_INDEX_MASK) + 1)

/**
 *  @brief Used to query whether an MSR is synthetic, ie it is used by the enlightment entity.
 */
#define IS_MSFT_HV_SYNTHETIC_MSR(Msr)  ((Msr >= HV_X64_MSR_GUEST_OS_ID) && (Msr <= HV_X64_MSR_MAX))

/** @name Getter and Setter for the synthetic MSRs internally recorded by our HV
*/
///@{
#define GstEnGetMsrValue(Vcpu, Msr)             (((VCPU*)(Vcpu))->MsftMsr[(Msr) & HV_X64_MSR_INDEX_MASK])
#define GstEnSetMsrValue(Vcpu, Msr, Value)      ((((VCPU*)(Vcpu))->MsftMsr[(Msr) & HV_X64_MSR_INDEX_MASK]) = (Value))
///@}

/** @name Flags for exposing or hiding the interface
 *  @brief  Flags used internally by the hypervisor to signal
 *          whether or not it expose the elightment interface.
 */
///@{
#define MSFT_HV_FLAG_EXPOSING_INTERFACE             0x00000001
#define MSFT_HV_FLAG_DO_NOT_TRY_TO_EXPOSE_INTERFACE 0x00000010
///@}

/**
*   @brief Layout of the value written on the TSC reference page.
*
*   The hypervisor provides a partition-wide virtual reference TSC page
*   which is overlaid on the partition's GPA space. It is used to virtualize the TSC.
*   This structure represents the layout of the value that will be written on the
*   TSC reference page starting with the first byte of it.
*
*/
#pragma pack (push, 1)
typedef struct _HV_REFERENCE_TSC_PAGE
{
    volatile CX_UINT32  TscSequence;
    CX_UINT32           Reserved1;
    volatile CX_UINT64  TscScale;
    volatile CX_INT64   TscOffset;
    CX_UINT64           Reserved2[509];
} HV_REFERENCE_TSC_PAGE;
#pragma pack(pop)

///
/// @brief Function dealing with CPUIDs whose inputs are synthetic leafs
///
/// Through the synthetic CPUIDs the guest OS finds out whether or not
/// the enlightment interface is expose by our HV. If so, guest can also find more information
/// about the features implemented by Hypervisor through synthetic CPUIDs.
///
/// @param[in]  Vcpu                    VCPU on which CPUID exit arrive.
/// @param[in]  InEax                   EAX register used when CPUID was called.
/// @param[in]  InEcx                   ECX register used when CPUID was called.
/// @param[out] Eax                     the EAX register that we want the guest OS to see after executing the CPUID instruction
/// @param[out] Ebx                     the EBX register that we want the guest OS to see after executing the CPUID instruction
/// @param[out] Ecx                     the ECX register that we want the guest OS to see after executing the CPUID instruction
/// @param[out] Edx                     the EDX register that we want the guest OS to see after executing the CPUID instruction
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_OPERATION_NOT_IMPLEMENTED - if CPUID synthetic input is not exposed by our HV.
///
CX_STATUS
GstEnHandleCpuid(
    _In_  VCPU      *Vcpu,
    _In_  CX_UINT32 InEax,
    _In_  CX_UINT32 InEcx,
    _Out_ CX_UINT32 *Eax,
    _Out_ CX_UINT32 *Ebx,
    _Out_ CX_UINT32 *Ecx,
    _Out_ CX_UINT32 *Edx
);

///
/// @brief Function dealing with synthetic MSR read.
///
/// To access some information from the hypervisor, the guest OS can read MSRs
/// specific to the enlightment interface. Within each MSR is encoded a
/// specific information (example: hypercall page, guest OS ID, etc)
///
/// @param[in]  Vcpu                    VCPU on which rdmsr exit arrive.
/// @param[in]  Msr                     the MSR to be read.
/// @param[out] Value                   the value that we want the guest OS to see after executing the rdmsr instruction
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if VCPU is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Value is NULL.
/// @returns    STATUS_INJECT_GP                    - if the Hypervisor does not expose the enlightenment interface
///                                                 or the MSR that the guest is trying to read is not exposed by hv.
///
CX_STATUS
GstEnHandleMsrRead(
    _In_ VCPU        *Vcpu,
    _In_ CX_UINT32   Msr,
    _Out_ CX_UINT64 *Value
);

///
/// @brief Function dealing with synthetic MSR write.
///
/// To set some infos or features implemented by the hypervisor, the guest OS can write MSRs
/// specific to the enlightment interface. Within each MSR is encoded a
/// specific information (example: hypercall page, guest OS ID, etc)
///
/// @param[in]  Vcpu                    VCPU on which wrmsr exit arrive.
/// @param[in]  Msr                     the MSR to be write.
/// @param[in]  Value                   the value that the guest OS want to be written
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    STATUS_INJECT_GP                    - if the Hypervisor does not expose the enlightenment interface
///                                                 or the MSR that the guest is trying to write is not exposed by hv,
///                                                 or the guest OS commits an inconsistency with the enlightment interface.
///
/// @return     OTHERS                              - other statuses returned by the APIs used by the function.
///
CX_STATUS
GstEnHandleMsrWrite(
    _In_ VCPU        *Vcpu,
    _In_ CX_UINT32   Msr,
    _In_ CX_UINT64   Value
);

///
/// @brief Update the partition reference time.
///
/// When the TSC page is exposed, the guest OS uses information from that page to calculate the TSC.
/// If the TSC page is not exposed then the guest OS reads the HV_X64_MSR_TIME_REF_COUNT MSR
/// (if this is exposed) to find the partition reference time. This function updates at each exit
/// the value that will be returned if the guest OS reads HV_X64_MSR_TIME_REF_COUNT.
///
/// @param[in]  Guest                   GUEST on which exit occurs.
/// @param[out] RefValue                returned partition reference time.
///
/// @returns    CX_STATUS_SUCCESS                   - everything went with success.
///
CX_STATUS
GstEnUpdatePartitionRefCount(
    _In_     GUEST        *Guest,
    _Out_    CX_UINT64   *RefValue
);

///
/// @brief Check if a memory page is used within enlightment mechanism.
///
/// A physical guest memory page can be used in the enlightment mechanism (hypercall page, tsc page, etc.).
/// Any of these pages should not be manipulated by introspection for example so
/// as not to endanger the enlightment interface.
///
/// @param[in]  Address                 GUEST physical address.
///
/// @returns    TRUE                    - if memory page is used in enlightment mechanism.
/// @returns    FALSE                   - if memory page is NOT used in enlightment mechanism.
///
CX_BOOL
GstEnIsHyperPageAddress(
    _In_ CX_UINT64 Address
);

/// @}

#endif __GUEST_ENLIGHT_H__ //__GUEST_ENLIGHT_H__
