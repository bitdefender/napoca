/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _VECOMMON_H_
#define _VECOMMON_H_

//
// This file is common between the #VE driver and the hypervisor. Exposes hypercall numbers.
//

// On success, 0 will be returned in EAX/RAX.
#define VE_STATUS_SUCCESS           0x00000000

// On any kind of error, (DWORD)-1 will be returned in EAX/RAX.
#define VE_STATUS_ERROR             0xFFFFFFFF

// Physical address mask. Note that maximum 52 bits of physical address will ever be used.
#define VE_PHYSMASK                 0x000FFFFFFFFFF000

// Should be redefined to something more... appropriate?
#define VE_VMCALL_MAGIC             0x99669966

// Get #VE capabilities hypercall
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_GET_CAP
// Output: RAX = #VE capabilities; bit 0 - #VE support, bit 1 - VMFUNC support.
#define VE_HCALL_GET_CAP            1

// Capabilities returned in EAX/RAX.
#define VE_CAPABILITY_VE            1 // Indicates #VE support from the CPU & HV.
#define VE_CAPABILITY_VMFUNC        2 // Indicates VMFUNC support from the CPU & HV.
#define VE_CAPABILITY_READY         4 // Indicates that the HV made appropriate initializations in order to accept #VE.


// Set #VE information page
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_SET_VE_INFO
// Input: RDX = GPA of the #VE information page for the given CPU.
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_SET_VE_INFO        2


// Set GPA access rights
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_SET_GPA_AR
// Input: RBX = EPT index where the access will be modified
// Input: RDX = GPA & new access rights: bits 12:63 - GPA, bits 0:11 - access rights, caching, etc. Bit 11
//        will be set if the entry needs to be marked as being convertible, ie, #VE to be delivered instead if
//        EPT violations.
// Output: RAX = error code: 0 = success, not 0 = error
// Note: this will be used only during initialization phase.
#define VE_HCALL_SET_GPA_AR         3

#define VE_ACCESS_NONE              0x000
#define VE_ACCESS_READ              0x001
#define VE_ACCESS_WRITE             0x002
#define VE_ACCESS_EXECUTE           0x004
#define VE_NOT_CONVERTIBLE          0x8000000000000000

// Get GPA access rights
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_GET_GPA_AR
// Input: RBX = EPT index where to be used for access retrieval
// Input: RDX = GPA for which the access will be retrieved; bit 0:11 are ignored
// Output: RAX = error code: 0 = success, not 0 = error
// Output: RDX = access rights of the indicated GPA, in bits 0:2 (in case of success; otherwise, undefined)
#define VE_HCALL_GET_GPA_AR         4

// Create a new EPT from the master EPT
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_CREATE_EPT
// Output: RAX = error code: 0 = success, not 0 = error
// Output: RCX = new EPT index (in case of success; otherwise, undefined)
#define VE_HCALL_CREATE_EPT         5

// Destroy an EPT
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_DESTROY_EPT
// Input: RBX = the EPT index
// Output: RAX = error code: 0 = success, not 0 = error
// Note: it is the responsibility of the caller to maintain an the EPT list in order to properly destroy EPTs.
// The EPT index cannot be 0 (the master EPT), 1 (the protected view EPT) or greater than 511.
#define VE_HCALL_DESTROY_EPT        6

// Enable or disable VM exits for certain control register accesses
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_CONTROL_CR_EXIT
// Input: RDX = 0 if exits should be disabled, 1 if exits should be enabled
// Input: RBX = control register number
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_CONTROL_CR_EXIT    7

// Enable or disable VM exits for certain MSR accesses
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_CONTROL_MSR_EXIT
// Input: RDX = 0 if exits should be disabled, 1 if exits should be enabled
// Input: RBX = MSR id
// Output: RAX = error code: 0 = success, not 0 = error
// Output: RDX = 0 if exits were not enabled for the MSR before, 1 if exits were enabled before us
#define VE_HCALL_CONTROL_MSR_EXIT   8

// Enable or disable delivery of #VE events for certain events
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_ENABLE_EVENT_VE
// Input: RDX = bit 0: 0 if exits should be disabled, 1 if exits should be enabled
//              bits 1:7 - event type: 0 - CR writes, 1 - MSR writes, 2 - DTR loads,
//                                     3 - CR reads, 4 - MSR reads, 5 - DTR stores
// Input: RBX = CR number of MSR id
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_ENABLE_EVENT_VE    9

// Invalidate EPT translations in all TLBs.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_INVALIDATE_EPT
// Input: RBX = 0 for local invalidation (current VCPU), 1 for global invalidation (all VCPUs)
// Input: RDX = The EPT for which the invalidation will be made. 0xFFFFFFFF for all context invalidation.
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_INVALIDATE_EPT     10

// Pause all the VCPUs, except for the current one.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_PAUSE_VCPUS
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_PAUSE_VCPUS        11

// Resume all the VCPUs, except for the current one.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_RESUME_VCPUS
// Output: RAX = error code: 0 = success, not 0 = error
#define VE_HCALL_RESUME_VCPUS       12

// Enables SIDT interceptions on the current VCPU and will return a predefined value.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_HIDE_IDT
// Input: RDX = Original IDT address
// Input: RBX = Cloned IDT address
// NOTE: This hypercall uses the default, maximum limit for the IDT.
#define VE_HCALL_HIDE_IDT           15

// Disabled SIDT interceptions on the current VCPU.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_UNHIDE_IDT
#define VE_HCALL_UNHIDE_IDT         16

// Sends a string to the HV to be logged.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_LOG
// Input: RDX = NULL terminated logging string
#define VE_HCALL_LOG                17

// Loads a new IDT.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_LOAD_IDT
// Input: RDX = IDT base
// Input: RBX = IDT limit
#define VE_HCALL_LOAD_IDT           18

// Sets the dispatcher address - this address will be treated specially, as it will be cached.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_SET_DISPATCH
// Input: RDX = Dispatcher address - more precisely, the address with the SIDT
#define VE_HCALL_SET_DISPATCH       19

// Informs the HV that the #VE driver has done initializations. No more hypercalls are accepted from the unprotected
// view.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_INIT_DONE
#define VE_HCALL_INIT_DONE          30

// Initiates #VE unitialization.
// Input: RAX = VE_VMCALL_MAGIC
// Input: RCX = VE_HCALL_UNINIT
#define VE_HCALL_UNINIT             31




// Other definitions go here
/// ...

// Guest-mapped EPT related.

// Maximum addressable are 1 TB of physical memory.
#define VE_MAX_GPA                  (2ULL * 512ULL * 512ULL * 512ULL * 4096ULL)

// Size of the guest-mapped EPT page tables (note: only PTs will be mapped in a contiguous space; PML4, PDP, PD will
// not be mapped inside the guest). Each EPT takes up to 4G of physical address space (note that only a small fraction
// will actually be used).
#define VE_GUEST_MAPPED_EPT_SIZE    (0x100000000)

// The Master & the single step EPT will be mapped inside the guest PA space inside a synthetic GPA range, below
// the maximum addressable range of 1TB.
#define VE_MASTER_EPT_GPA_BASE      (VE_MAX_GPA - (VE_GUEST_MAPPED_EPT_SIZE * 1))
#define VE_SINGLE_STEP_EPT_GPA_BASE (VE_MAX_GPA - (VE_GUEST_MAPPED_EPT_SIZE * 2))

#define VE_EPT_PML4_OFFSET          (0x00000000)
#define VE_EPT_PML4_COUNT           (1)
#define VE_EPT_PDP_OFFSET           (0x00001000)
#define VE_EPT_PDP_COUNT            (2)
#define VE_EPT_PD_OFFSET            (0x00003000)
#define VE_EPT_PD_COUNT             (2 * 512)
#define VE_EPT_PT_OFFSET            (0x00410000)
#define VE_EPT_PT_COUNT             (2 * 512 * 512)

typedef enum _EPT_TYPE
{
    VE_EPT_MASTER = 0,
    VE_EPT_PROTECTED,
    VE_EPT_SINGLE_STEP,
    VE_EPT_ANY = 0xFFFFFFFF,
} EPT_TYPE;

#endif // _VECOMMON_H_