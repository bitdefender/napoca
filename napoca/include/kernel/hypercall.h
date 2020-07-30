/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file hypercall.h
*   @brief The hypercall handler
*
* The hypervisor provides a calling mechanism for guests.
* Such calls are referred to as hypercalls. Each hypercall defines a set of input and/or output parameters.
* These parameters are specified in terms of a memory-based data structure
* or directly as values through the VCPU registers (in the case of fast type hypercalls).
* You can make an analogy between syscall and hypercall.
* The syscall is a User-Mode <-> Kernel-Mode communication mechanism
* and the hypercall is a GuestOs <-> Hypervisor communication mechanism
*
*/

/// \defgroup hc Hypercall support
/// \ingroup gst_enlight
/// @{

#ifndef _HYPERCALL_H_
#define _HYPERCALL_H_

#include "kernel/kernel.h"
#include "kernel/hypercall_status.h"

/**
*   @brief Hypercall magic
*
*   A simple overview of the hypercall mechanism:
*   The hypervisor prepares a memory page with executable code,
*   the page where the guest jumps and executes to make a hypercall.
*   Within that page a vmcall will be made, to pass from the guest to the hypervisor
*   (somewhat equivalent to SYSENTER in the case of syscalls).
*   So, for our hypervisor to differentiate between hypercalls
*   and other events that come within the vmcall exit, this magic value will be used.
*   Please keep this definition synchronized
*   with HC_VMCALL_MAGIC from the kernel_vmx.nasm file.
*
*/
#define HC_VMCALL_MAGIC 0xBDBDBD66

///
/// @brief Manages the hypercalls that reach our hypervisor.
///
/// If a vmcall exit appears in the hypervisor and that vmcall has the
/// magic value HC_VMCALL_MAGIC set in the EBP register then it is considered
/// a HYPERCALL because it reached us on the page we prepared for the GUEST OS.
/// This function will handle the hypercall request.
///
CX_VOID
HcHyperCallHandler(
    CX_VOID
);

/// @}

#endif // !_HYPERCALL_H_