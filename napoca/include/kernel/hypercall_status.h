/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file hypercall_status.h
*   @brief Hypercall Status Code
*
*   Based on: Hypervisor Top Level Functional Specification -  July, 2018: Released Version 5.0c
*
*/
#ifndef _HYPERCALL_STATUS_H_
#define _HYPERCALL_STATUS_H_

#include "kerneldefs.h"

/// \defgroup hc_status Hypercall Status Code
/// \ingroup hc
/// @{

/** @name Hypercall Status Code
*
*/
///@{
typedef CX_UINT16 HC_HV_STATUS;

#define HC_HV_STATUS_SUCCESS                                              0x0000 ///< The operation succeeded.
// Reserved 0x0001
#define HC_HV_STATUS_INVALID_HYPERCALL_CODE                               0x0002 ///< The hypervisor does not support the operation because the specified hypercall code is not supported.
#define HC_HV_STATUS_INVALID_HYPERCALL_INPUT                              0x0003 ///< The rep count was incorrect (for example, a non-zero rep count was passed to a non-rep call or a zero rep count was passed to a rep call) or a reserved bit in the specified hypercall input value was non-zero.
#define HC_HV_STATUS_INVALID_ALIGNMENT                                    0x0004 ///< The specified input and/or output GPA pointers were not aligned to 8 bytes or the specified input and/or output parameters lists spanned a page boundary.
#define HC_HV_STATUS_INVALID_PARAMETER                                    0x0005 ///< One or more input parameters were invalid.
#define HC_HV_STATUS_ACCESS_DENIED                                        0x0006 ///< The caller did not possess sufficient access rights to perform the requested operation.
#define HC_HV_STATUS_INVALID_PARTITION_STATE                              0x0007 ///< The specified partition's state was not appropriate for the requested operation.
#define HC_HV_STATUS_OPERATION_DENIED                                     0x0008 ///< The operation could not be performed. (The actual cause depends on the operation.)
#define HC_HV_STATUS_UNKNOWN_PROPERTY                                     0x0009 ///< The specified partition property ID is not a recognized property.
#define HC_HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE                          0x000A ///< The specified value of a partition property is out of range or violates an invariant.
#define HC_HV_STATUS_INSUFFICIENT_MEMORY                                  0x000B ///< Insufficient memory exists for the call to succeed.
#define HC_HV_STATUS_PARTITION_TOO_DEEP                                   0x000C ///< The maximum partition depth has been exceeded for the partition hierarchy.
#define HC_HV_STATUS_INVALID_PARTITION_ID                                 0x000D ///< The specified partition ID is invalid.
#define HC_HV_STATUS_INVALID_VP_INDEX                                     0x000E ///< The specified VP index is invalid.
// Reserved 0x000F
// Reserved 0x0010
#define HC_HV_STATUS_INVALID_PORT_ID                                      0x0011 ///< The specified port ID is not unique or does not exist.
#define HC_HV_STATUS_INVALID_CONNECTION_ID                                0x0012 ///< The specified connection ID is not unique or does not exist.
#define HC_HV_STATUS_INSUFFICIENT_BUFFERS                                 0x0033 ///< The target port does not have sufficient buffers for the caller to post a message.
#define HC_HV_STATUS_NOT_ACKNOWLEDGED                                     0x0014 ///< An external interrupt has not previously been asserted and acknowledged by the virtual processor prior to clearing it.
#define HC_HV_STATUS_INVALID_VP_STATE                                     0x0015 ///< A virtual processor is not in the correct state for the performance of the indicated operation.
#define HC_HV_STATUS_ACKNOWLEDGED                                         0x0016 ///< An external interrupt cannot be asserted because a previously-asserted external interrupt was acknowledged by the virtual processor and has not yet been cleared.
#define HC_HV_STATUS_INVALID_SAVE_RESTORE_STATE                           0x0017 ///< The initial call to HvSavePartitionState or HvRestorePartitionState specifying HV_SAVE_RESTORE_STATE_START was not made at the beginning of the save/restore process.
#define HC_HV_STATUS_INVALID_SYNIC_STATE                                  0x0018 ///< The operation could not be performed because a required feature of the SynIC was disabled.
#define HC_HV_STATUS_OBJECT_IN_USE                                        0x0019 ///< The operation could not be performed because the object or value was either already in use or being used for a purpose that would not permit it.
#define HC_HV_STATUS_INVALID_PROXIMITY_DOMAIN_INFO                        0x001A ///< The Flags field included an invalid mask value in the proximity domain information. The Id field contained an invalid ACPI node ID in the proximity domain information.
#define HC_HV_STATUS_NO_DATA                                              0x001B ///< An attempt to retrieve data failed because none was available.
#define HC_HV_STATUS_INACTIVE                                             0x001C ///< The physical connection being used for debugging has not recorded any receive activity since the last operation.
#define HC_HV_STATUS_NO_RESOURCES                                         0x001D ///< A resource is unavailable for allocation. This may indicate that there is a resource shortage or that an implementation limitation may have been reached.
#define HC_HV_STATUS_FEATURE_UNAVAILABLE                                  0x001E ///< A hypervisor feature is not available to the caller.
#define HC_HV_STATUS_PARTIAL_PACKET                                       0x001F ///< The debug packet returned is only a partial packet due to an I/O error.
#define HC_HV_STATUS_PROCESSOR_FEATURE_SSE3_NOT_SUPPORTED                 0x0020 ///< The supplied restore state requires an unsupported processor feature (SSE3).
#define HC_HV_STATUS_PROCESSOR_FEATURE_LAHFSAHF_NOT_SUPPORTED             0x0021 ///< The supplied restore state requires an unsupported processor feature (LAHFSAHF ).
#define HC_HV_STATUS_PROCESSOR_FEATURE_SSSE3_NOT_SUPPORTED                0x0022 ///< The supplied restore state requires an unsupported processor feature (SSSE3).
#define HC_HV_STATUS_PROCESSOR_FEATURE_SSE4_1_NOT_SUPPORTED               0x0023 ///< The supplied restore state requires an unsupported processor feature (SSE4.1).
#define HC_HV_STATUS_PROCESSOR_FEATURE_SSE4_2_NOT_SUPPORTED               0x0024 ///< The supplied restore state requires an unsupported processor feature SSE4.2 is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_SSE4A_NOT_SUPPORTED                0x0025 ///< The supplied restore state requires an unsupported processor feature SSE4a is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_XOP_NOT_SUPPORTED                  0x0026 ///< The supplied restore state requires an unsupported processor feature XOP is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_POPCNT_NOT_SUPPORTED               0x0027 ///< The supplied restore state requires an unsupported processor feature POPCNT is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_CMPXCHG16B_NOT_SUPPORTED           0x0028 ///< The supplied restore state requires an unsupported processor feature CMPXCHG16B is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_ALTMOVCR8_NOT_SUPPORTED            0x0029 ///< The supplied restore state requires an unsupported processor feature ALTMOVCR8 is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_LZCNT_NOT_SUPPORTED                0x002A ///< The supplied restore state requires an unsupported processor feature LZCNT is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_MISALIGNED_SSE_NOT_SUPPORTED       0x002B ///< The supplied restore state requires an unsupported processor feature MISALIGNED SSE3 is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_MMX_EXT_NOT_SUPPORTED              0x002C ///< The supplied restore state requires an unsupported processor feature MMX EXT is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_3DNOW_NOT_SUPPORTED                0x002D ///< The supplied restore state requires an unsupported processor feature 3DNow is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_EXTENDED_3DNOW_NOT_SUPPORTED       0x002E ///< The supplied restore state requires an unsupported processor feature Extended 3DNow is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_PAGE_1GB_NOT_SUPPORTED             0x002F ///< The supplied restore state requires an unsupported processor feature PAHGE 1GB is not supported.
#define HC_HV_STATUS_PROCESSOR_CACHE_LINE_FLUSH_SIZE_INCOMPATIBLE         0x0030 ///< The processor's cache line flush size is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVE_NOT_SUPPORTED                0x0031 ///< The supplied restore state requires an unsupported processor feature XSAVE is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVEOPT_NOT_SUPPORTED             0x0032 ///< The supplied restore state requires an unsupported processor feature XSAVEOPT is not supported.
#define HC_HV_STATUS_INSUFFICIENT_BUFFER                                  0x0033 ///< The specified buffer was too small to contain all of the requested data.
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVE_AVX_NOT_SUPPORTED            0x0034 ///< The supplied restore state requires an unsupported processor feature AVX is not supported.
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVE_FEATURE_NOT_SUPPORTED        0x0035 ///< The supplied restore state requires an unsupported XSAVE processor feature.
#define HC_HV_STATUS_PROCESSOR_XSAVE_SAVE_AREA_INCOMPATIBLE               0x0036 ///< The processor's XSAVE area is not supported.
#define HC_HV_STATUS_INCOMPATIBLE_PROCESSOR                               0x0037 ///< The processor architecture is not supported.
#define HC_HV_STATUS_INSUFFICIENT_DEVICE_DOMAINS                          0x0038 ///< The maximum number of domains supported by the platform I/O remapping hardware is currently in use.
#define HC_HV_STATUS_PROCESSOR_FEATURE_AES_NOT_SUPPORTED                  0x0039 ///< The supplied restore state requires an unsupported processor feature (AES).
#define HC_HV_STATUS_PROCESSOR_FEATURE_PCLMULQDQ_NOT_SUPPORTED            0x003A ///< The supplied restore state requires an unsupported processor feature (PCLMULQDQ).
#define HC_HV_STATUS_PROCESSOR_FEATURE_INCOMPATIBLE_                      0x003B ///< XSAVE_FEATURES The supplied restore state enables incompatible XSAVE features.  (Enabling AVX without XSAVE/enabling XSAVEOPT without XSAVE)
#define HC_HV_STATUS_CPUID_FEATURE_VALIDATION_ERROR                       0x003C ///< Generic logical processor CPUID feature set validation error.
#define HC_HV_STATUS_CPUID_XSAVE_FEATURE_VALIDATION_ERROR                 0x003D ///< CPUID XSAVE feature validation error.
#define HC_HV_STATUS_PROCESSOR_STARTUP_TIMEOUT                            0x003E ///< Processor startup timed out.
#define HC_HV_STATUS_SMX_ENABLED                                          0x003F ///< SMX enabled by the BIOS.
#define HC_HV_STATUS_PROCESSOR_FEATURE_PCID_NOT_SUPPORTED                 0x0040 ///< The supplied restore state requires an unsupported processor processor feature (PCID).
#define HC_HV_STATUS_INVALID_LP_INDEX                                     0x0041 ///< The hypervisor could not perform the operation because the specified LP index is invalid.
#define HC_HV_STATUS_FEATURE_FMA4_NOT_SUPPORTED                           0x0042 ///< The supplied restore state requires an unsupported processor feature (FMA4).
#define HC_HV_STATUS_FEATURE_F16C_NOT_SUPPORTED                           0x0043 ///< The supplied restore state requires an unsupported processor feature (F16C).
#define HC_HV_STATUS_PROCESSOR_FEATURE_RDRAND_NOT_SUPPORTED               0x0044 ///< The supplied restore state requires an unsupported processor feature (RDRAND).
#define HC_HV_STATUS_PROCESSOR_FEATURE_RDWRFSGS_NOT_SUPPORTED             0x0045 ///< The supplied restore state requires an unsupported processor feature (Read/Write FS/GS).
#define HC_HV_STATUS_PROCESSOR_FEATURE_SMEP_NOT_SUPPORTED                 0x0046 ///< The supplied restore state requires an unsupported processor feature (SMEP).
#define HC_HV_STATUS_PROCESSOR_FEATURE_ENHANCED_FAST_STRING_NOT_SUPPORTED 0x0047 ///< The supplied restore state requires an unsupported processor feature (Enhanced Fast String).
#define HC_HV_STATUS_PROCESSOR_FEATURE_MOVBE_NOT_SUPPORTED                0x0048 ///< The supplied restore state requires an unsupported processor feature (MovBe Instruction).
#define HC_HV_STATUS_PROCESSOR_FEATURE_BMI1_NOT_SUPPORTED                 0x0049 ///< The supplied restore state requires an unsupported processor feature (Bmi1).
#define HC_HV_STATUS_PROCESSOR_FEATURE_BMI2_NOT_SUPPORTED                 0x004A ///< The supplied restore state requires an unsupported processor feature (Bmi2).
#define HC_HV_STATUS_PROCESSOR_FEATURE_HLE_NOT_SUPPORTED                  0x004B ///< The supplied restore state requires an unsupported processor feature (Hle).
#define HC_HV_STATUS_PROCESSOR_FEATURE_RTM_NOT_SUPPORTED                  0x004C ///< The supplied restore state requires an unsupported processor feature (Rtm).
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVE_FMA_NOT_SUPPORTED            0x004D ///< The supplied restore state requires an unsupported processor feature (Fma).
#define HC_HV_STATUS_PROCESSOR_FEATURE_XSAVE_AVX2_NOT_SUPPORTED           0x004E ///< The supplied restore state requires an unsupported processor feature (Avx2)
#define HC_HV_STATUS_PROCESSOR_FEATURE_NPIEP1_NOT_SUPPORTED               0x004F ///< The supplied restore state requires an unsupported processor feature (NPIEP1).
#define HC_HV_STATUS_INVALID_REGISTER_VALUE                               0x0050 ///< The supplied register value is invalid.
#define HC_HV_STATUS_PROCESSOR_FEATURE_RDSEED_NOT_SUPPORTED               0x0052 ///< The supplied restore state requires an unsupported processor feature (RdSeed).
#define HC_HV_STATUS_PROCESSOR_FEATURE_ADX_NOT_SUPPORTED                  0x0053 ///< The supplied restore state requires an unsupported processor feature (Adx).
#define HC_HV_STATUS_PROCESSOR_FEATURE_SMAP_NOT_SUPPORTED                 0x0054 ///< The supplied restore state requires an unsupported processor feature (SMAP).
#define HC_HV_STATUS_NX_NOT_DETECTED                                      0x0055 ///< NX not detected on the machine.
#define HC_HV_STATUS_PROCESSOR_FEATURE_INTEL_PREFETCH_NOT_SUPPORTED       0x0056 ///< The supplied restore state requires an unsupported processor feature (Intel Prefetch)
#define HC_HV_STATUS_INVALID_DEVICE_ID                                    0x0057 ///< The supplied device ID is invalid.
#define HC_HV_STATUS_INVALID_DEVICE_STATE                                 0x0058 ///< The operation is not allowed in the current device state.
#define HC_HV_STATUS_PENDING_PAGE_REQUESTS                                0x0059 ///< The device had pending page requests which were discarded.
#define HC_HV_STATUS_PAGE_REQUEST_INVALID                                 0x0060 ///< The supplied page request specifies a memory access that the guest does not have permissions to perform.
#define HC_HV_STATUS_OPERATION_FAILED                                     0x0071 ///< The requested operation failed.
#define HC_HV_STATUS_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE                  0x0072 ///< The requested operation is not allowed due to one or more virtual processors having nested virtualization active.
///@}

/// @}

#endif // _HYPERCALL_STATUS_H_