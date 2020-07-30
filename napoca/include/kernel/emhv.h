/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// EMHV - emulator to hypervisor interface

#ifndef _EMHV_H_
#define _EMHV_H_

#include "core.h"

//
// emulator -> hv interface
//
typedef struct _GUEST GUEST;
typedef struct _VCPU VCPU;

typedef enum
{
    emhvSaveUnknwnState = 0,
    emhvSaveFpuState
}EMHV_SAVE_STATE;


typedef NTSTATUS (*PFUNC_EmhvTranslateVirtualAddress)(_In_ VCPU* Vcpu, _In_ CX_UINT64 GuestVirtualAddress, _Inout_ CX_UINT64 *GuestPhysicalAddress);
typedef NTSTATUS (*PFUNC_EmhvGetMemType)(_In_ VCPU* Vcpu, _In_ CX_UINT64 PhysicalPageAddress, _In_ CX_UINT32 PageCount, _Out_ CX_UINT32 *Flags);
typedef NTSTATUS (*PFUNC_EmhvMapPhysicalMemory)(_In_ VCPU* Vcpu, _In_ CX_UINT64 PageAddress, _In_ CX_UINT32 PageCount, _Inout_ CX_VOID **HostVa);
typedef NTSTATUS (*PFUNC_EmhvMapVirtualMemory)(_In_ VCPU* Vcpu, _In_ CX_UINT64 PageAddress, _In_ CX_UINT32 PageCount, _Inout_ CX_VOID **HostVa);
typedef NTSTATUS (*PFUNC_EmhvUnmapVirtualMemory)(_Inout_ CX_VOID **HostVa);
typedef NTSTATUS (*PFUNC_EmhvUnmapPhysicalMemory)(_Inout_ CX_VOID **HostVa);

typedef NTSTATUS (*PFUNC_EmhvReadDevMem)(_In_ VCPU* Vcpu, _In_opt_ CX_VOID* Context, _In_ CX_UINT64 PhysicalAddress, _In_ CX_UINT8 Length, _Out_ CX_UINT8* Value);
typedef NTSTATUS (*PFUNC_EmhvWriteDevMem)(_In_ VCPU* Vcpu, _In_opt_ CX_VOID* Context, _In_ CX_UINT64 PhysicalAddress, _In_ CX_UINT8 Length, _In_ CX_UINT8* Value);

typedef NTSTATUS (*PFUNC_EmhvReadIoPort)(_In_ VCPU* Vcpu, _In_opt_ CX_VOID* Context, _In_ CX_UINT16 IoPort, _In_ CX_UINT8 Length, _Out_ CX_UINT8* Value);
typedef NTSTATUS (*PFUNC_EmhvWriteIoPort)(_In_ VCPU* Vcpu, _In_opt_ CX_VOID* Context, _In_ CX_UINT16 IoPort, _In_ CX_UINT8 Length, _In_ CX_UINT8* Value);

typedef NTSTATUS (*PFUNC_EmhvReadMsr)(_In_ VCPU* Vcpu,_In_opt_ CX_VOID* Context, _In_ CX_UINT32 Msr, _Out_ CX_UINT64 *Value);
typedef NTSTATUS (*PFUNC_EmhvWriteMsr)(_In_ VCPU* Vcpu, _In_opt_ CX_VOID* Context, _In_ CX_UINT32 Msr, _In_ CX_UINT64 Value);

typedef NTSTATUS (*PFUNC_EmHvVmxRead)(_In_ VCPU* Vcpu, _In_ CX_UINT64 Id, _Out_ CX_UINT64* Value);
typedef NTSTATUS (*PFUNC_EmHvVmxWrite)(_In_ VCPU* Vcpu, _In_ CX_UINT64 Id, _In_ CX_UINT64 Value);

typedef NTSTATUS(*PFUNC_EmHvSaveCpuState)(_In_ VCPU* Vcpu, _In_ EMHV_SAVE_STATE cpuSaveState);

// The interface
typedef struct _EMHV_INTERFACE {
    BOOLEAN     Initialized;
    // memory handling (to directly map CODE and DATA)

    PFUNC_EmhvTranslateVirtualAddress   TranslateVirtualAddress;
    PFUNC_EmhvGetMemType                GetMemType;
    PFUNC_EmhvMapPhysicalMemory         MapPhysicalMemory;
    PFUNC_EmhvMapVirtualMemory          MapVirtualMemory;
    PFUNC_EmhvUnmapVirtualMemory        UnmapVirtualMemory;
    PFUNC_EmhvUnmapPhysicalMemory       UnmapPhysicalMemory;
    // dev-mem handling (to handle MMIO for devices)
    PFUNC_EmhvReadDevMem                ReadDevMem;
    PFUNC_EmhvWriteDevMem               WriteDevMem;
    // PORT I/O handling
    PFUNC_EmhvReadIoPort                ReadIoPort;
    PFUNC_EmhvWriteIoPort               WriteIoPort;
    // MSR handling
    PFUNC_EmhvReadMsr                   ReadMsr;
    PFUNC_EmhvWriteMsr                  WriteMsr;

    // vmcs / vmcb access
    PFUNC_EmHvVmxRead                   VmxRead;
    PFUNC_EmHvVmxWrite                  VmxWrite;

    // misc
    PFUNC_EmHvSaveCpuState              SaveCpuState;
} EMHV_INTERFACE;

//
// Flags that may be passed to the EmhvDecodeAndEmulateInGuestContext
//
#define EMHV_FLAG_REEXECUTE         0x80000000      // Will re-execute the instruction, without attempting emulation.


///
/// @brief Starts a single-step operation on given VCPU
///
/// This function will perform necesary steps in order to perform a singlestep operation. It will map in dedicated
/// single step ept the pages that are required to successfully perform a patched re-execution of an instruction.
/// The patched memory content, if available, is provided in general by the introspection engine and contains
/// the original memory content before introspection updated it for various reasons. The guest will see the original
/// memory content when the processor will re-execute the instruction.
///
/// In case of singlestep using 1G pages this function will pause all vcpus associated to the current guest and will
/// not remap any pages in EPT but it will restore in-place the patched memory using the patch buffer, if available.
///
/// @param Vcpu                         The VCPU that will have it's current instruction re-executed.
/// @param Gpa                          The GPA where the access was made and resulted in a EPT violation.
/// @param Gla                          The GLA of the access.
/// @param RequiredAccess               The access rights required in order to re-execute the instruction.
///
/// @return CX_STATUS_SUCCESS           The necessary steps for instruction re-execution were successfull.
/// @return STATUS_XXX                  If an error occurs.
///
NTSTATUS
EmhvStartHandlingEptViolation(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Gla,
    _In_ CX_UINT16 RequiredAccess
    );

///
/// @brief Ends a single-step operation on given VCPU
///
/// This function will undo any steps performed by the start of single-step function. It will undo any mapping done in dedicated
/// single step ept.
///
/// In case of singlestep using 1G pages this function will un-pause all vcpus associated to the current guest and will
/// will restore in-place the patched memory using the content when single-step begun.
///
/// @param Vcpu                         The VCPU that for whcich instruction re-execution was started
///
/// \ret CX_STATUS_SUCCESS All processors have been resumed.
/// \ret STATUS_XXX If an error occurs.
///
NTSTATUS
EmhvEndHandlingEptViolation(
    _In_ VCPU* Vcpu
    );

///
/// @brief Initialization function for emulator interface
///
/// Initializez the hypervisor emulator interface for the given guest, by filling in pointers to various
/// functions used by the software emulator: memory mapping/unmapping, memory translation,
/// and callbacks for device memory, I/O ports and MSRs.
///
/// @param Guest                         Pointer to the guest whos EMHV interface will be initialized.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   If the pointer to the guest is NULL.
/// @return CX_STATUS_SUCCESS               If the initialization of the interface was succesfull.
///
NTSTATUS
EmhvInitGenericPerGuestIface(
    _In_ GUEST* Guest
    );


///
/// @brief Decode/disasamble the instruction at current vpu rip address
///
/// This function will map the memory pointed by current vcpu rip and it will decode the instruction contained there, by
/// using the current operating mode of the Vcpu (real mode, protected mode, long mode), and the current CS
/// segment attributes.
///
/// @param Vcpu          Current Vcpu for the instruction that shall be decoded.
/// @param Instrux       Will contain upon exit the decoded instruction.
/// @param Flags         Flags for the decoder.
/// @param Gpa           GPA of the faulting address, if any.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   If a NULL Vcpu has been passed as parameter
/// @return CX_STATUS_INVALID_PARAMETER_2   If a NULL Instrux has been passed as parameter
/// @return STATUS_PAGE_NOT_PRESENT         If the page(s) containg the instruction is not marked as present in guest page-tables.
///
/// @return STATUS_NO_EMHV_INITIALIZED      If the EMHV interface has not been initialized.
/// @return CX_STATUS_SUCCESS               If the memory pointed by Vcpu->ArchRegs.RIP has been succesfully mapped,
///                                          and the instruction has been succesfully decoded.
///
NTSTATUS
EmhvDecodeInGuestContext(
    _In_ VCPU* Vcpu,
    _Out_ INSTRUX* Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_UINT64 Gpa  // IMPORTANT: we assume that this GPA, if different from 0x0 and 0xFFFFFFFF`FFFFFFFF is the GPA of a memory OPERAND
    );

///
/// @brief Retrieve the instruction lenght
///
/// This function will decode the instruction pointed by current rip, and returns its length via InstructionLen argument.
///
/// @param Vcpu             The Vcpu containig the context of the instruction to be decoded.
/// @param InstructionLen   WIll contain upon exit the lenth of the instruction.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   NULL pointer provided for vcpu
/// @return CX_STATUS_INVALID_PARAMETER_2   NULL pointer provided for storage of instruction length
///
NTSTATUS
EmhvDecodeInstructionLenInGuestContext(
    _In_ VCPU* Vcpu,
    _Out_ CX_UINT8 *InstructionLen
    );


///
/// @brief Decode and eulate in guest context
///
/// This function will try to emulate the instruction pointed by Vcpu->ArchRegs.RIP using the software emulator. If the
/// sotware emulator fails, it will try to re-execute the instruction using the fallback mechanism, only
/// if the instruction caused an false EPT violation (generally due to introspection hooks).
///
///
///
/// @param Vcpu             Vcpu containing the context of the instruction to be emulated.
/// @param Instrux          An already decoded instruction if available
/// @param Flags            Flags for emulator.
/// @param Gpa              This is accessed GPA, if different from 0x0 and 0xFFFFFFFF`FFFFFFFF is the GPA of a memory OPERAND
/// @param Context          Device-specific context pointer.
///
/// @return                 CX_STATUS_SUCCESS The instruction has been succesfully emulated and the context has been fully updated, or a single-step as been successfully started.
///
NTSTATUS
EmhvDecodeAndEmulateInGuestContext(
    _In_ VCPU* Vcpu,
    _In_opt_ PINSTRUX Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_UINT64 Gpa,
    _In_opt_ CX_VOID* Context
    );

#endif // _EMHV_H_
