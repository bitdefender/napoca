/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introcpu.h
*   @brief INTROCPU -  NAPOCA hypervisor glue layer, CPU utilities
*
*/

#ifndef _INTROCPU_H_
#define _INTROCPU_H_

#include "glueiface.h"

///
/// @brief  Pauses all the VCPUs assigned to a guest
///
/// Will pause all the vcpus of a given guest.
///
/// NOTE: On exit, all processors are guaranteed to be paused.
///
/// @param[in]  Guest        Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the pause was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if GstPause returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if GstPause returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised GstPause
///
/// @remarks    Failures of this API are considered fatal errors by the introspection engine
///
NTSTATUS
GuestIntNapPauseVcpus(
    _In_ PVOID Guest
);

///
/// @brief  Resumes all the VCPUs assigned to a guest that were previously paused with a
/// GLUE_IFACE.PauseVcpus call
///
/// Will resume all the vcpus of a given guest.
/// NOTE: On exit, all processors are guaranteed to be paused.
///
/// @param[in]  Guest         Integrator-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - if the resume was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if GstPause returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if GstPause returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised GstPause
///
/// @remarks    Failures of this API are considered fatal errors by the introspection engine
///
NTSTATUS
GuestIntNapResumeVcpus(
    _In_ PVOID Guest
);

///
/// @brief  Sets the memory contents with which an instruction will be emulated by the hypervisor
///
/// When this function is called, the emulation of the instruction that caused the current VMEXIT
/// should use Buffer contents instead of the real memory contents when emulating accesses in the
/// range [VirtualAddress, VirtualAddress + BufferSize)
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  CpuNumber       The VCPU number. Can be IG_CURRENT_VCPU
/// @param[in]  VirtualAddress  The virtual address for which the Buffer contents will be used. It is important
///                             that the hypervisor uses this address, and not the one reported by the VMEXIT
///                             as they can be different
/// @param[in]  BufferSize      The size of the buffer, in bytes
/// @param[in]  Buffer          The emulator context buffer
///
/// @returns    CX_STATUS_SUCCESS                   - if the resume was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if CpuNumber is greater than the VcpuCount of the Guest
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if BufferSize is 0
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - if Buffer is NULL
/// @returns    INT_STATUS_NO_MAPPING_STRUCTURES    - if GstPause returns STATUS_NO_MAPPING_STRUCTURES
/// @returns    INT_STATUS_PAGE_NOT_PRESENT         - if GstPause returns STATUS_PAGE_NOT_PRESENT
/// @returns    OTHER                               - other potential internal STATUS error value raised GstPause
///
/// @remarks    This function does not check if the buffer for emulation has already been set.
///
NTSTATUS
GuestIntNapSetIntroEmulatorContext(
    _In_ PVOID Guest,
    _In_ DWORD CpuNumber,
    _In_ QWORD VirtualAddress,
    _In_ DWORD BufferSize,
    _In_reads_bytes_(BufferSize) PBYTE Buffer
);


///
/// @brief  Enables or disables the REP optimization
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  Enable          True if the optimizations will be enabled, False if not
///
/// @returns    CX_STATUS_SUCCESS                   - if the resume was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL
///
NTSTATUS
GuestIntNapToggleRepOptimization(
    _In_ PVOID Guest,
    _In_ BOOLEAN Enable
);
#endif // _INTROCPU_H_

///@}