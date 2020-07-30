/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _NEWCORE_H_
#define _NEWCORE_H_

/// \addtogroup core
/// @{

#include "kernel/kerneldefs.h"
#include "kernel/vcpu.h"

/// @brief The main routine before VMENTRY/VMLAUNCH
///
/// This is called by both the BSP and AP processors, being effectively the core of PHASE 3. Constantly tries to
/// get a VCPU to be executed on the current PCPU. If no schedulable VCPU is found, the physical CPU is halted (HLT).
/// This routine is called also after each VMX VmExit (after the exit reason is handled) to switch back to VM guest.
///
/// @returns Never
void
HvPcpuRootMainCycle(
    void
    );

/// @brief The assembly part of the common exit handler
void
HvVmxHandleVmExitAsm(
    void
    );


/// @brief Common part of (almost) all exit handlers
///
/// This is called from the ASM part of the VMX VmExit handler (HvVmxHandleVmExitAsm) on a successful VmExit (on failure,
/// HvVmxLaunchOrResumeFailed is called instead).
///
/// @param[in]  Vcpu            The VCPU structure on which the exit occurred
void
HvVmxHandleVmExitCommon(
    _In_ VCPU* Vcpu
    );

/// @brief The assembly part of switching back/back to the guest
void
HvVmxSwitchFromHostToVmGuest(
    void
    );

/// @brief The assembly part of switching back to the guest, and expecting to get the control back where the function call was issues
void
HvVmxSwitchFromHostToVmGuestWithContinuation(
    void
    );

/// @brief Called if the VMLAUNCH or the VMRESUM failed
///
/// IMPORTANT: take care, because the full register set is NOT saved to ArchRegs, only part of it (take a look to kernel_vmx.nasm)
///
/// @param[in] Vcpu            The VCPU structure on which the failure occurred
/// @param[in] ErrorNumber     Should contain the failure's reason
///
/// @returns Should not!
void
HvVmxLaunchOrResumeFailed(
    _In_ VCPU* Vcpu,
    _In_ QWORD ErrorNumber
    );

/// @}

#endif // _NEWCORE_H_

