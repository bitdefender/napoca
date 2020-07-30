/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file handler.c Hypervisor VMEXIT handlers

#include "kernel/kernel.h"
#include "guests/guests.h"
#include "common/kernel/cpu_state.h"
#include "boot/vmstate.h"
#include "guests/intro.h"
#include "memory/cachemap.h"
#include "communication/comm_guest.h"
#include "kernel/emhv.h"
#include "kernel/newcore.h"
/// \defgroup exit_handlers VM exit handlers
/// @{
#include "kernel/simplechecksum.h"
#include "debug/dumpers.h"
#include "guests/pci_tools.h"
#include "kernel/guestenlight.h"
#include "communication/guestcommands.h"
#include "guests/msrcallbacks.h"
#include "kernel/hypercall.h"

// internal code pointers used by the BIOS hook handling code
extern BYTE __RealModeHookStubEnd;
extern BYTE __RealModeHookPost;
extern BYTE __RealModeHookPre;

/// @brief Function prototype for every exit handler
///
/// @param[in]  Vcpu            The VCPU structure on which the exit occurred
typedef
NTSTATUS
(*PFUNC_VmxExitHandler)(
    _In_ VCPU* Vcpu
    );

static NTSTATUS _VmxExitHandlerDefault(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerExceptionNmi(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerExternalInterrupt(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerTripleFault(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInit(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerSipi(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerSmi(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerOtherSmi(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInterruptWindow(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerNmiWindow(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerTaskSwitch(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerCpuid(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerGetSec(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerHlt(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvd(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvlpg(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRdpmc(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRdtsc(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRsm(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerCrAccess(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerDrAccess(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerIo(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMsrRead(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMsrWrite(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvalidGuestState(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMsrLoading(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMwait(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMonitorTrapFlag(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMonitor(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerPause(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerMachineCheck(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerTprBelowThreshold(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerApicAccess(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVirtualizedEoi(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerGdtIdtrAccess(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerLdtrTrAccess(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerEptViolation(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerEptMisconfiguration(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvEpt(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRdtscp(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerPreemptionTimerExpired(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvVpid(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerWbinvd(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerXsetbv(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerApicWrite(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRdRand(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerInvPcid(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerVmFunc(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerEncls(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerRdSeed(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerPmlFull(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerXSaveS(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerXRestoreS(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerSPP(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerUmwait(_In_ VCPU* Vcpu);
static NTSTATUS _VmxExitHandlerTpause(_In_ VCPU* Vcpu);

static
PFUNC_VmxExitHandler
gExitHandlers[] =
{
    _VmxExitHandlerExceptionNmi,                 // EXIT_REASON_EXCEPTION_NMI                       0
    _VmxExitHandlerExternalInterrupt,            // EXIT_REASON_EXTERNAL_INTERRUPT                  1
    _VmxExitHandlerTripleFault,                  // EXIT_REASON_TRIPLE_FAULT                        2
    _VmxExitHandlerInit,                         // EXIT_REASON_INIT                                3
    _VmxExitHandlerSipi,                         // EXIT_REASON_SIPI                                4
    _VmxExitHandlerSmi,                          // EXIT_REASON_SMI                                 5
    _VmxExitHandlerOtherSmi,                     // EXIT_REASON_OTHER_SMI                           6
    _VmxExitHandlerInterruptWindow,              // EXIT_REASON_INTERRUPT_WINDOW                    7
    _VmxExitHandlerNmiWindow,                    // EXIT_REASON_NMI_WINDOW                          8
    _VmxExitHandlerTaskSwitch,                   // EXIT_REASON_TASK_SWITCH                         9
    _VmxExitHandlerCpuid,                        // EXIT_REASON_CPUID                               10
    _VmxExitHandlerGetSec,                       // EXIT_REASON_GETSEC                              11
    _VmxExitHandlerHlt,                          // EXIT_REASON_HLT                                 12
    _VmxExitHandlerInvd,                         // EXIT_REASON_INVD                                13
    _VmxExitHandlerInvlpg,                       // EXIT_REASON_INVLPG                              14
    _VmxExitHandlerRdpmc,                        // EXIT_REASON_RDPMC                               15
    _VmxExitHandlerRdtsc,                        // EXIT_REASON_RDTSC                               16
    _VmxExitHandlerRsm,                          // EXIT_REASON_RSM                                 17
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMCALL                              18
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMCLEAR                             19
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMLAUNCH                            20
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMPTRLD                             21
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMPTRST                             22
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMREAD                              23
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMRESUME                            24
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMWRITE                             25
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMOFF                               26
    _VmxExitHandlerVmx,                          // EXIT_REASON_VMON                                27
    _VmxExitHandlerCrAccess,                     // EXIT_REASON_CR_ACCESS                           28
    _VmxExitHandlerDrAccess,                     // EXIT_REASON_DR_ACCESS                           29
    _VmxExitHandlerIo,                           // EXIT_REASON_IO_INSTRUCTION                      30
    _VmxExitHandlerMsrRead,                      // EXIT_REASON_MSR_READ                            31
    _VmxExitHandlerMsrWrite,                     // EXIT_REASON_MSR_WRITE                           32
    _VmxExitHandlerInvalidGuestState,            // EXIT_REASON_INVALID_GUEST_STATE                 33
    _VmxExitHandlerMsrLoading,                   // EXIT_REASON_MSR_LOADING                         34
    _VmxExitHandlerDefault,                      //                                                 35
    _VmxExitHandlerMwait,                        // EXIT_REASON_MWAIT_INSTRUCTION                   36
    _VmxExitHandlerMonitorTrapFlag,              // EXIT_REASON_MONITOR_TRAP_FLAG                   37
    _VmxExitHandlerDefault,                      //                                                 38
    _VmxExitHandlerMonitor,                      // EXIT_REASON_MONITOR                             39
    _VmxExitHandlerPause,                        // EXIT_REASON_PAUSE                               40
    _VmxExitHandlerMachineCheck,                 // EXIT_REASON_MACHINE_CHECK                       41
    _VmxExitHandlerDefault,                      //                                                 42
    _VmxExitHandlerTprBelowThreshold,            // EXIT_REASON_TPR_BELOW_THRESHOLD                 43
    _VmxExitHandlerApicAccess,                   // EXIT_REASON_APIC_ACCESS                         44
    _VmxExitHandlerVirtualizedEoi,               // EXIT_REASON_VIRTUALIZED_EOI                     45
    _VmxExitHandlerGdtIdtrAccess,                // EXIT_REASON_GDTR_IDTR_ACCESS                    46
    _VmxExitHandlerLdtrTrAccess,                 // EXIT_REASON_LDTR_TR_ACCESS                      47
    _VmxExitHandlerEptViolation,                 // EXIT_REASON_EPT_VIOLATION                       48
    _VmxExitHandlerEptMisconfiguration,          // EXIT_REASON_EPT_MISCONFIGURATION                49
    _VmxExitHandlerInvEpt,                       // EXIT_REASON_INVEPT                              50
    _VmxExitHandlerRdtscp,                       // EXIT_REASON_RDTSCP                              51
    _VmxExitHandlerPreemptionTimerExpired,       // EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED        52
    _VmxExitHandlerInvVpid,                      // EXIT_REASON_INVVPID                             53
    _VmxExitHandlerWbinvd,                       // EXIT_REASON_WBINVD                              54
    _VmxExitHandlerXsetbv,                       // EXIT_REASON_XSETBV                              55
    _VmxExitHandlerApicWrite,                    // EXIT_REASON_APIC_WRITE                          56
    _VmxExitHandlerRdRand,                       // EXIT_REASON_RDRAND                              57
    _VmxExitHandlerInvPcid,                      // EXIT_REASON_INVPCID                             58
    _VmxExitHandlerVmFunc,                       // EXIT_REASON_VMFUNC                              59
    _VmxExitHandlerEncls,                        // EXIT_REASON_ENCLS                               60
    _VmxExitHandlerRdSeed,                       // EXIT_REASON_RDSEED                              61
    _VmxExitHandlerPmlFull,                      // EXIT_REASON_PML_FULL                            62
    _VmxExitHandlerXSaveS,                       // EXIT_REASON_XSAVES                              63
    _VmxExitHandlerXRestoreS,                    // EXIT_REASON_XRSTORS                             64
    _VmxExitHandlerDefault,                      //                                                 65
    _VmxExitHandlerSPP,                          // EXIT_REASON_SPP                                 66
    _VmxExitHandlerUmwait,                       // EXIT_REASON_UMWAIT                              67
    _VmxExitHandlerTpause                        // EXIT_REASON_TPAUSE                              68
};

/// @brief Calls the exit handler with the given reason
///
/// @param[in]  ExitReason      The exit reason for which we want the handler to be called
/// @param[in]  Vcpu            The VCPU on which we want the handler to be called
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the handler was executed successfully
/// @returns    OTHER                               - Other internal error returned by the callback
NTSTATUS
HndCallExitHandler(
    _In_ CX_UINT64 ExitReason,
    _In_ VCPU* Vcpu
)
{
    return gExitHandlers[ExitReason](Vcpu);
}



/// @brief Calculate the instruction size and advance the RIP accordingly
///
/// @param[in]  Vcpu            VCPU on which the RIP will be advanced
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the RIP is adjusted
/// @returns    OTHER                               - Other internal error from #EmhvDecodeInstructionLenInGuestContext
static
__forceinline
NTSTATUS
_SkipCurrentInstruction(
    _In_ VCPU* Vcpu
)
{
    NTSTATUS status;
    BYTE iLen = 0;

    status = EmhvDecodeInstructionLenInGuestContext(Vcpu, &iLen);
    if (!NT_SUCCESS(status))
    {
        if ((status == STATUS_PAGE_NOT_PRESENT) || (status == STATUS_NO_MAPPING_STRUCTURES) || (status == STATUS_EMPTY_MAPPING))
        {
            // The page containing the instruction was swapped out. We can safely retry the instruction, as a #PF
            // will be triggered and the page will be swapped back in.
            status = CX_STATUS_SUCCESS;
        }
        else ERROR("EmhvDecodeInGuestContext failed with status 0x%08x at RIP %018p!\n", status, Vcpu->ArchRegs.RIP);
    }
    else Vcpu->ArchRegs.RIP += iLen;

    return status;
}


/// @brief Specific VMX exit handler for VMCALL
///
/// @param[in]  Vcpu            VCPU on which the exit occurred
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the VMCALL was handled
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_VmCallHandler(
    _In_ VCPU* Vcpu
)
{
    NTSTATUS status;

    //
    // BIOS Interrupt Hooks - only in real mode
    //
    if ((Vcpu->ArchRegs.CR0 & CR0_PE) == 0)
    {
        QWORD csBase = 0, ssBase = 0;
        BIOS_INT_HOOK *hook = NULL;
        WORD flags = 0;
        BOOLEAN isPost = FALSE;

        vmx_vmread(VMCS_GUEST_CS_BASE, &csBase);

        status = HkGetBiosHook(Vcpu->Guest, csBase + (0xFFFF & (Vcpu->ArchRegs.RIP)), &hook, &isPost);
        if (SUCCESS(status))
        {
            status = hook->Handler(hook, Vcpu, isPost);
            if (SUCCESS(status))
            {
                BYTE *rmStack;
                vmx_vmread(VMCS_GUEST_SS_BASE, &ssBase);
                rmStack = Vcpu->Guest->RealModeMemory + ssBase + (Vcpu->ArchRegs.ESP & 0xFFFF);

                if (!isPost)
                {
                    // 1) pre-hook with status 'let the BIOS handle it'
                    if ((status == STATUS_EXECUTE_ORIGINAL_HANDLER) || (status == STATUS_SET_POST_HOOK))
                    {
                        // 2) pre-hook with status 'forward to BIOS and set post hook'
                        if (status == STATUS_SET_POST_HOOK)
                        {

                            // add an artificial INTerrupt return stack frame to trap the IRET executed by BIOS
                            Vcpu->ArchRegs.ESP -= 3 * sizeof(WORD);
                            rmStack -= 3 * sizeof(WORD);
                            memcpy(rmStack, rmStack + 3 * sizeof(WORD), 3 * sizeof(WORD));

                            // patch the CS:IP pair on the stack to point to the 'post' VMCALL instruction
                            ((WORD*)rmStack)[0] = (WORD)((Vcpu->ArchRegs.RIP + (&__RealModeHookPost - &__RealModeHookPre)) & 0xFFFF);
                            ((WORD*)rmStack)[1] = (WORD)(csBase / 16);
                        }

                        // set cs / cs_base / IP to the original interrupt handler address
                        vmx_vmwrite(VMCS_GUEST_CS, hook->OldSegment);
                        vmx_vmwrite(VMCS_GUEST_CS_BASE, hook->OldSegment * 16);
                        Vcpu->ArchRegs.RIP = (Vcpu->ArchRegs.RIP & (~0xFFFF)) | hook->OldOffset;

                        // let BIOS execute its handler and perform IRET with original values found on stack
                        return STATUS_EMU_DONT_ADVANCE_RIP;
                    }
                    // 3) pre-hook with status 'handled'
                    else
                    {

                        // update CF in the FLAGS register on stack
                        flags = ((WORD*)rmStack)[2];
                        flags = (flags & ~(RFLAGS_CF | RFLAGS_ZF)) | (Vcpu->ArchRegs.EFLAGS & (RFLAGS_CF | RFLAGS_ZF));
                        ((WORD*)rmStack)[2] = flags;

                        // bypass the post hook (its code is equal to the pre hook code)
                        Vcpu->ArchRegs.RIP += &__RealModeHookPost - &__RealModeHookPre;

                        // let our IRET instruction return to the original INT caller
                        return CX_STATUS_SUCCESS;
                    }
                }
                else
                {
                    // 4) our post-hook handler has been executed (and our fake return stack frame freed)
                    flags = ((WORD*)rmStack)[2];
                    flags = (flags & ~(RFLAGS_CF | RFLAGS_ZF)) | (Vcpu->ArchRegs.EFLAGS & (RFLAGS_CF | RFLAGS_ZF));
                    ((WORD*)rmStack)[2] = flags;

                    // let our IRET instruction return to the original INT caller
                    return CX_STATUS_SUCCESS;
                }
            }
            else
            {
                VCPUERROR(Vcpu, "BIOS interrupt %x handling failed, status=%s\n", hook->InterruptNumber, NtStatusToString(status));
                return status;
            }
        }
        else if (status != CX_STATUS_DATA_NOT_FOUND)
        {
            LOG_FUNC_FAIL("HkGetBiosHook", status);
            return status;
        }
    }

    QWORD guestAddress;
    QWORD hostAddress;
    QWORD accessRights, dpl;

    // The SS always contains the actual CPL; CS may not contain the real CPL (for example, conforming segments).
    vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &accessRights);
    dpl = (accessRights >> 5) & 3; // ss.DPL bits

    status = ChmGvaToGpaAndHpa(Vcpu, Vcpu->ArchRegs.RIP, &guestAddress, &hostAddress);
    if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("ChmGvaToGpaAndHpa", status);
    else
    {
        if (
            (CX_PAGE_BASE_4K(GstEnGetMsrValue(Vcpu, HV_X64_MSR_HYPERCALL)) == CX_PAGE_BASE_4K(guestAddress))
            && (dpl == 0)
            && (Vcpu->ArchRegs.EBP == HC_VMCALL_MAGIC)
            && (Vcpu->Guest->HypercallPageActive)
            )
        {
            //
            // Microsoft Hypervisor Interface handler
            //
            HcHyperCallHandler();
            return CX_STATUS_SUCCESS;
        }
    }

    //
    // Our handlers
    //
    if (Vcpu->ArchRegs.EBX == VMCALL_GUEST_MAGIC)
    {
       Vcpu->ArchRegs.RAX = (QWORD)VxhVmCallGuestMessage(
            Vcpu,
            dpl == 0,
            (COMMAND_CODE)Vcpu->ArchRegs.RAX,
            Vcpu->ArchRegs.RCX, Vcpu->ArchRegs.RDX, Vcpu->ArchRegs.RSI, Vcpu->ArchRegs.RDI,
            &Vcpu->ArchRegs.RCX, &Vcpu->ArchRegs.RDX, &Vcpu->ArchRegs.RSI, &Vcpu->ArchRegs.RDI);

#if CFG_ENABLE_DEBUG_HVCOMM
        INFO("VMCALL[%d.%d] out: %p/%p/%p/%p; status: 0x%08X.\n",
            Vcpu->GuestIndex, Vcpu->GuestCpuIndex,
            Vcpu->ArchRegs.RCX, Vcpu->ArchRegs.RDX, Vcpu->ArchRegs.RSI, Vcpu->ArchRegs.RDI,
            Vcpu->ArchRegs.RAX);
#endif

        return CX_STATUS_SUCCESS;
    }

    //
    // Introspection handler
    //
    BOOLEAN bIsLongMode = ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA) != 0);

    if ((Vcpu->ArchRegs.EAX == 34) &&
        ((!bIsLongMode && (Vcpu->ArchRegs.EBX == 24)) || (bIsLongMode && (Vcpu->ArchRegs.EDI == 24))))
    {
        IPC_INTERRUPTIBILITY_STATE oldInts = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_ALLOW_CURRENT);

        status = Vcpu->Guest->Intro.IntroCallCallback(Vcpu->Guest, Vcpu->ArchRegs.RIP, Vcpu->GuestCpuIndex);
        if (!SUCCESS(status))
        {
            LOG("Intro callback returned 0x%x\n", status);
        }

        IpcSetInterruptibilityState(oldInts);

        return CX_STATUS_SUCCESS;
    }

    VCPULOG(Vcpu, "Unknown VMCALL: %d 0x%p 0x%p 0x%p\n", HvGetCurrentApicId(), Vcpu->ArchRegs.RBX, Vcpu->ArchRegs.RAX, Vcpu->ArchRegs.RDI);

    return STATUS_INJECT_GP;
}


/// @brief Reloads the VMCS field for PAE32
///
/// @param[in]  Vcpu            VCPU on which the reload should take place
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_VmxReloadVmcsFieldsForPae32(
    _In_ VCPU* Vcpu
)
{
    QWORD ia32Efer;
    QWORD* table ;

    NTSTATUS status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(Vcpu->ArchRegs.CR3), 1, 0, &table, NULL, TAG_GVAT);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmMapContinuousGuestGpaPagesToHost", status);
        return status;
    }

    vmx_vmread(VMCS_GUEST_IA32_EFER, &ia32Efer);

    if ((Vcpu->ArchRegs.CR4 & CR4_PAE) && !(ia32Efer & EFER_IA32E_ACTIVE))
    {
        // NOTE: we are assured that this can NOT span across multiple pages (CR3 is 0x20 aligned for 32-bit PAE paging)
        table = (PQWORD)((PBYTE)table + (Vcpu->ArchRegs.CR3 & 0xFE0));
    }

    // read entries and copy to VMCS
    // conform Intel Vol 3, 26.3.2.4, "Loading Page-Directory-Pointer-Table Entries"
    vmx_vmwrite(VMCS_GUEST_PDPTE0, table[0]);
    vmx_vmwrite(VMCS_GUEST_PDPTE1, table[1]);
    vmx_vmwrite(VMCS_GUEST_PDPTE2, table[2]);
    vmx_vmwrite(VMCS_GUEST_PDPTE3, table[3]);

    // unmap page from HV space
    ChmUnmapContinuousGuestGpaPagesFromHost(&table, TAG_GVAT);

    return status;
}


static NTSTATUS _VmxExitHandlerDefault(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerExceptionNmi(_In_ VCPU* Vcpu)
{
    QWORD rip, temp;
    WORD cs;
    QWORD intrInfo;
    BYTE vector;
    BOOLEAN hasError;
    BYTE type;
    DWORD errorCode;

    // get information about the exception
    vmx_vmread(VMCS_VM_EXIT_INTERRUPTION_INFORMATION, &intrInfo);

    vector = (BYTE)(intrInfo & 0xff); // bits 7-0
    hasError = ((intrInfo & 0x800) != 0); // bit 11
    type = (BYTE)((intrInfo & 0x700) >> 8); // bits 10-8

    if (hasError)
    {
        vmx_vmread(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE, &temp);
        errorCode = (DWORD)temp;
    }
    else errorCode = 0xFFFFFFFF;

    vmx_vmread(VMCS_GUEST_RIP, &rip);
    vmx_vmread(VMCS_GUEST_CS, &temp);
    cs = (WORD)temp;
    if ((CfgDebugTraceGuestExceptions) && (vector != 1)) // skip debug exceptions
    {
        VCPULOG(Vcpu, "EXCEPTION[%d] at cs=%p, rip=%p\n", vector, cs, rip);
        DumpersLogInstruction(Vcpu, cs, rip);

        QWORD exitQual;
        VMCS_VECTORED_EVENT_INFO tmp;
        QWORD t;

        DUMP_BEGIN;
        vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);

        VCPULOG(Vcpu, "[CPU %d] VECTORED event, qualification = %018p, info = %018p\n", HvGetCurrentCpuIndex(), exitQual, intrInfo);
        VCPULOG(Vcpu, "EXCEPTION[%d] type[%d] at cs=%p, rip=%p\n", vector, type, cs, rip);

        vmx_vmread(VMCS_VM_EXIT_INTERRUPTION_INFORMATION, (QWORD*)&tmp);
        vmx_vmread(VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE, &t);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.ErrorCode", t);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.Raw", tmp.Raw);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.ErrorCodeValid", tmp.ErrorCodeValid);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.Type", tmp.Type);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.Valid", tmp.Valid);
        VCPULOG(Vcpu, "%-16s: %p\n", "info.Vector", tmp.Vector);

        DumpersLogInstruction(Vcpu, cs, rip);
        DUMP_END;
    }


    // NMI
    if (type == 0x02)
    {
        IntNmiHandler();

        // The debugger can send an NMI to a processor
        // for it to print it's stack.
        // This handler take care of this request (if the request exists).
        DbgNmiHandler(NULL);
    }
    // EXCEPTION 0x01 - DEBUG exception
    else if ((type == 0x03) && (vector == 0x01))
    {
        if (Vcpu->DebugContext.SingleStep != 0) DbgHandleInstructionTracing(Vcpu, cs, rip);
        else
        {
            HvPrint("[CPU %d] DEBUG EXCEPTION, CS = 0x%04x, RIP = %018p, info = %018p, will re-inject\n",
                HvGetCurrentCpuIndex(), cs, rip, intrInfo);
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_DEBUG, 0, 0);
        }
    }
    // EXCEPTION 0x03 - BP exception
    else if (vector == 0x03)
    {
        BOOLEAN introHandlerFound = FALSE;
        NTSTATUS introStatus;

        introStatus = Vcpu->Guest->Intro.IntroBreakpointCallback(Vcpu->Guest, 0, Vcpu->GuestCpuIndex);
        if (NT_SUCCESS(introStatus)) introHandlerFound = TRUE;

        if (!introHandlerFound)
        {
            NTSTATUS localStatus;
            BOOLEAN mustInjectBp = FALSE;
            INSTRUX instrux;

            HvAcquireRwSpinLockShared(&HvGetCurrentGuest()->Intro.IntroCallbacksLock);

            if (!HvGetCurrentGuest()->Intro.IntrospectionEnabled)
            {
                localStatus = EmhvDecodeInGuestContext(Vcpu, &instrux, 0, 0);
                if (SUCCESS(localStatus))
                {
                    mustInjectBp = (instrux.Instruction == ND_INS_INT3 || (instrux.Instruction == ND_INS_INT && instrux.Immediate1 == 3));
                }
                else
                {
                    VCPUERROR(Vcpu, "Failed decoding instrux at rip: %p! Skip #BP injection in guest!\n", Vcpu->PseudoRegs.CsRip);
                }
            }
            else mustInjectBp = TRUE;

            if (mustInjectBp)
            {
                VCPULOG(Vcpu, "BP/INT3 EXCEPTION, injected!\n");

                // set RFLAGS.RF = 1
                Vcpu->ArchRegs.RFLAGS |= RFLAGS_RF;

                // re-inject
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_BREAKPOINT, 0, 0);
            }
            else VCPUWARNING(Vcpu, "Skip injecting #BP! No BP instrux at given rip!\n");

            HvReleaseRwSpinLockShared(&HvGetCurrentGuest()->Intro.IntroCallbacksLock);

        }
    }
    // EXCEPTION 0x06 - UD exception
    else if (vector == 0x06)
    {
        VCPULOG(Vcpu, "UD exception, CS = 0x%04x, RIP = %018p\n", cs, rip);

        VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
    }
    else
    {
        QWORD exitQual = 0;

        vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);

        VCPULOG(Vcpu, "VECTORED event, qualification = %018p, info = %018p\n", exitQual, intrInfo);
    }

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerExternalInterrupt(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerTripleFault(_In_ VCPU* Vcpu)
{
    DUMP_BEGIN;
    VCPULOG(Vcpu, "*** TRIPLE FAULT IN GUESTxxxxxxxx ***\n");
    DumpCurrentVmcs(Vcpu->GuestCpuIndex);
    DumpersDumpArchRegs(&(Vcpu->ArchRegs));
    LOG("Dumping stack from SS:RSP %018p\n", ROUND_DOWN(Vcpu->PseudoRegs.SsRsp, PAGE_SIZE_4K));
    DumpersMemDumpEx(DBG_MEMDUMP_NO_OPTIONS, TRUE, TRUE, Vcpu->GuestIndex, Vcpu->GuestCpuIndex, ROUND_DOWN(Vcpu->PseudoRegs.SsRsp, PAGE_SIZE_4K), PAGE_SIZE_4K, NULL);
    LOG("Dumping instructions from CS:RIP %018p\n", ROUND_DOWN(Vcpu->PseudoRegs.CsRip, PAGE_SIZE_4K));
    DumpersMemDumpEx(DBG_MEMDUMP_NO_OPTIONS, TRUE, TRUE, Vcpu->GuestIndex, Vcpu->GuestCpuIndex, ROUND_DOWN(Vcpu->PseudoRegs.CsRip, PAGE_SIZE_4K), PAGE_SIZE_4K, NULL);
    DUMP_END;

    // if there was a task switch - successful or not - on any vcpu then we reboot the system without any regrets
    PwrReboot(FALSE, !Vcpu->Guest->TaskSwitchVcpuMask);

    return CX_STATUS_SUCCESS;
}


/// @brief Checks if we need to restore the VCPU state (to HLT)
///
/// @param[in]  Vcpu            The VCPU which should or should be not set back to HLT
///
/// @returns TRUE if it would be set back, FALSE otherwise
static
__forceinline
BOOLEAN
_DoWeNeedToRestoreVcpuState(_In_ const VCPU* Vcpu)
{
    return (CfgFeaturesVirtualizationMonitorGuestActivityStateChanges) &&
        (Vcpu->GuestActivityMonitor.IsInactive) &&
        (Vcpu->GuestActivityMonitor.GuestHaltedCsRip == Vcpu->PseudoRegs.CsRip);
}

/// @brief Set back the given VCPU's state to HLT if needed
///
/// @param[in]  Vcpu            The VCPU which will or will not be set back to HLT
static
__forceinline
void
_RestoreVcpuActivityStateIfNecessary(_Inout_ VCPU* Vcpu)
{
    if (!_DoWeNeedToRestoreVcpuState(Vcpu))
    {
        Vcpu->GuestActivityMonitor.IsInactive = FALSE;
        return;
    }

    vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, VMCS_ACTIVITY_STATE_HLT);
}

static NTSTATUS _VmxExitHandlerInit(_In_ VCPU* Vcpu)
{
    if (!GstIsSafeToInterrupt(HvGetCurrentGuest())) vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, VMCS_ACTIVITY_STATE_WAIT_FOR_SIPI);
    else _RestoreVcpuActivityStateIfNecessary(Vcpu);

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerSipi(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD exitQual;

    QWORD actState = 0;
    WORD cs = 0, ip = 0;

    VMCS_CONFIGURE_SETTINGS options = {
       .InitVmcs = CX_FALSE,
       .ActivateGuestDomain = CX_FALSE,
       .GuestOptions = VMCS_GUEST_REAL_MODE,
       .ControlsOptions = VMCS_CONTROLS_NO_UPDATE,
       .HostOptions = VMCS_HOST_NO_UPDATE,
       .ClearVmcsFromCpu = CX_FALSE,
       .SetNewVmcs = CX_FALSE
    };

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, &actState);

    if (VMCS_ACTIVITY_STATE_WAIT_FOR_SIPI == actState)
    {
        // "For a start-up IPI (SIPI), the exit qualification contains the SIPI vector
        // information in bits 7:0. Bits 63:8 of the exit qualification are cleared to 0."
        cs = (((WORD)exitQual) & 0x00ff) << 8;
        ip = 0;

        HvInterlockedOrU64(&Vcpu->Guest->SipiMask, (1ull << Vcpu->GuestCpuIndex));

        if (GstIsSafeToInterrupt(Vcpu->Guest))
        {
            VCPULOG(Vcpu, "Safe to interrupt VCPUs! Mask %p (%d / %d)\n",
                Vcpu->Guest->SipiMask, __popcnt64(Vcpu->Guest->SipiMask), Vcpu->Guest->VcpuCount);
        }

        LOG("[CPU %d] received SIPI (qualification %018p), will execute from CS:IP 0x%04x:0x%04x (= 0x%08x)\n",
            HvGetCurrentApicId(), exitQual, cs, ip, ((DWORD)cs << 4) + ip);

        LOG("Vcpu %d.%d is waking up (SIPI), cs=0x%p IP=0x%p\n", Vcpu->GuestIndex, Vcpu->GuestCpuIndex, (DWORD)cs, (QWORD)ip);

        options.GuestConfig.RealModeState.Cs = cs;
        options.GuestConfig.RealModeState.Ip = ip & 0xFFFF;
        options.GuestConfig.RealModeState.Ss = 0x0;
        options.GuestConfig.RealModeState.Sp = 0x7C00;
        options.GuestConfig.RealModeState.ActivityState = VMCS_GUEST_ACTIVITY_STATE_ACTIVE;

        status = VmstateConfigureVmcs(
            Vcpu,
            &options
        );
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
            return status;
        }

        HvInterlockedIncrementU32(&Vcpu->Guest->SipiCount);
    }
    else
    {
        LOG("[CPU %d] ERROR, received SIPI (exit qualification %018p) but NOT in wait-for-SIPI state !!!!\n",
            HvGetCurrentApicId(), exitQual);
    }

    return status;
}


static NTSTATUS _VmxExitHandlerSmi(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerOtherSmi(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerInterruptWindow(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);

    HvControlInterruptWindowExiting(FALSE);

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerNmiWindow(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);

    VmstateControlNMIWindowExiting(FALSE);

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerTaskSwitch(_In_ VCPU* Vcpu)
{
    WORD switchType; // 0 = CALL, 1 = IRET, 2 = JMP, 3 = IDT task gate
    WORD newTaskSelector;
    QWORD exitQual;

    HvInterlockedOrU64(&Vcpu->Guest->TaskSwitchVcpuMask, (1ULL << Vcpu->GuestCpuIndex));

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);

    switchType = (exitQual >> 30) & 3; // bits 31:30 of ExitQual
    newTaskSelector = exitQual & 0xFFFF;
    newTaskSelector &= (0xFFFF - 7); // mask any non-offset bits from selector

    VCPULOG(Vcpu, "PERFORMING A TASK SWITCH (type=%d, newTaskSelector=%x)!\n", switchType, newTaskSelector);

    static CX_ONCE_INIT0 once;

    if (CxInterlockedBeginOnce(&once)) PwrReboot(FALSE, FALSE);

    return CX_STATUS_SUCCESS;

}


static NTSTATUS _VmxExitHandlerCpuid(_In_ VCPU* Vcpu)
{
    NTSTATUS status;
    DWORD inEax;
    DWORD inEcx;
    DWORD *eax;
    DWORD *ebx;
    DWORD *ecx;
    DWORD *edx;

    static BYTE toggleHypervInterface = 0;

    // do these checks only on BSP and EFI systems only once
    if ((Vcpu->IsBsp && BOOT_UEFI) && (toggleHypervInterface == 0))
    {
        OdDetectGuestOs(Vcpu->Guest, Vcpu);

        if (Vcpu->Guest->OsScanVerdict == OS_SCAN_WIN7)
        {
            // On Windows 7 EFI we have to activate the guest enlightenment interface later
            // because here Hyper-V is loaded from a driver and only after it tells Windows to make
            // the necessary initializations. This workaround helps us avoid the 0x50 bug-check.
            Vcpu->Guest->MicrosoftHvInterfaceFlags &= (~MSFT_HV_FLAG_EXPOSING_INTERFACE);

            toggleHypervInterface = 1;
        }
    }

    inEax = Vcpu->ArchRegs.EAX;
    inEcx = Vcpu->ArchRegs.ECX;

    Vcpu->ArchRegs.RAX = Vcpu->ArchRegs.RBX = Vcpu->ArchRegs.RCX = Vcpu->ArchRegs.RDX = 0;

    eax = &Vcpu->ArchRegs.EAX;
    ebx = &Vcpu->ArchRegs.EBX;
    ecx = &Vcpu->ArchRegs.ECX;
    edx = &Vcpu->ArchRegs.EDX;

    // Handle the OSID request
    if (inEax == RAX_MSFT_HV_READ_OSID)
    {
        // Read the OSID value
        QWORD value;
        value = GstEnGetMsrValue(Vcpu, HV_X64_MSR_GUEST_OS_ID);

        // Put OSID in EAX:EBX
        *eax = ((DWORD *)(&value))[1];
        *ebx = ((DWORD *)(&value))[0];
        *ecx = 0;
        *edx = 0;
        status = CX_STATUS_SUCCESS;
        goto end;
    }
    if ((inEax >= RAX_MSFT_HV_LEAF_MIN) && (inEax <= RAX_MSFT_HV_LEAF_MAX))
    {
        if (Vcpu->Guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_EXPOSING_INTERFACE)
        {
            status = GstEnHandleCpuid(Vcpu, inEax, inEcx, eax, ebx, ecx, edx);
            goto end;
        }
    }

    status = CpuCpuidPrimaryGuest(Vcpu, inEax, inEcx, eax, ebx, ecx, edx);

end:
    if (SUCCESS(status)) status = STATUS_UPDATE_RIP;

    return status;
}



static NTSTATUS _VmxExitHandlerGetSec(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    /*
    An execution of GETSEC in VMX non-root operation causes a VM exit if CR4.SMXE[Bit 14] = 1
    regardless of the value of CPL or RAX. An execution of GETSEC causes an invalid-opcode exception
    (#UD) if CR4.SMXE[Bit 14] = 0.
    */

    if (CR4_SMXE & Vcpu->ArchRegs.CR4)
    {
        if (Vcpu->ArchRegs.RBX != 0 && Vcpu->ArchRegs.RAX != 0) // special case for WINGUEST
        {
            // if both are not 0 then inject UD - don't let others to call GETSEC
            WARNING("Guest executes GETSEC. Will inject #UD!");
            status = STATUS_INJECT_UD;
        }
        else
        {
            if (gBootInfo->CpuMap[HvGetCurrentCpuIndex()].IntelFeatures.Ecx.SMX != 0)
            {
                QWORD originalCr4;

                // enable SMX in CR4 so we can execute GETSEC instrux
                originalCr4 = __readcr4();
                __writecr4(originalCr4 | CR4_SMXE);

                if ((__readcr4() & CR4_SMXE) == 0) //check if SMXE flag is set
                {
                    CRITICAL("SMXE bit isn't set in host CR4\n");
                }

                Vcpu->ArchRegs.RAX = CpuGetsec(Vcpu->ArchRegs.RBX, Vcpu->ArchRegs.RAX);
                status = STATUS_UPDATE_RIP;

                // restore CR4
                __writecr4(originalCr4);
            }
            else
            {
                WARNING("Guest executes GETSEC. SMX not available. Will inject #UD!");
                status = STATUS_INJECT_UD;
            }
        }
    }
    else
    {
        // inject an UD if SMXE bit not set in CR4
        WARNING("Guest executes GETSEC. Will inject #UD!");
        status = STATUS_INJECT_UD;
    }

    return status;
}

static NTSTATUS _VmxExitHandlerHlt(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerInvd(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);

    __wbinvd();

    return STATUS_UPDATE_RIP;
}


static NTSTATUS _VmxExitHandlerInvlpg(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerRdpmc(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerRdtsc(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    if (CfgFeaturesVirtualizationTscExit)
    {
        Vcpu->ArchRegs.RAX = Vcpu->VirtualTsc & 0xFFFFFFFF;
        Vcpu->ArchRegs.RDX = Vcpu->VirtualTsc >> 32;

        // advance RIP to the next instruction
        status = STATUS_UPDATE_RIP;
    }
    else
    {
        LOG("[CPU %d] ERROR, unhandled VM-exit, Vcpu %018p, exit-reason = 0x%08x (%s)\n", HvGetCurrentApicId(), Vcpu,
            Vcpu->CurrentExitReason, ConvertVmxExitReasonToString(Vcpu->CurrentExitReason));

        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return status;
}


static NTSTATUS _VmxExitHandlerRsm(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerVmx(_In_ VCPU* Vcpu)
{
    NTSTATUS  status;
    QWORD exitReason = 0;

    vmx_vmread(VMCS_VM_EXIT_REASON, &exitReason);
    if (exitReason == EXIT_REASON_VMCALL)
    {
        status = _VmCallHandler(Vcpu);
        if (status != STATUS_INJECT_GP && status != STATUS_INJECT_UD && status != STATUS_EMU_DONT_ADVANCE_RIP) status = STATUS_UPDATE_RIP;
    }
    else
    {
        LOG("[Vcpu %d] Attempted to execute VMX instruction. Will inject #UD.\n", Vcpu->GuestCpuIndex);

        return STATUS_INJECT_UD;
    }

    return status;
}


static NTSTATUS _VmxExitHandlerCrAccess(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    INTRO_ACTION action = introGuestAllowed;
    BYTE opType = 0;
    BYTE crReg = 0;
    BYTE gpReg = 0;
    QWORD exitQual = 0;

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);

    opType = (BYTE)((exitQual & 0x30) >> 4);
    crReg = (BYTE)(exitQual & 0x0F);
    gpReg = (BYTE)((exitQual & 0xF00) >> 8);

    // MOV to CR from GP
    if (opType == 0)
    {
        // MOV CR0, ...
        if (crReg == 0)
        {
            QWORD cr0 = 0;

            cr0 = Vcpu->ArchRegs.CR0;

            // Call introspection callback for CR0 load, if set.
            NTSTATUS introStatus = CX_STATUS_SUCCESS;

            introStatus = Vcpu->Guest->Intro.IntroCrCallback(Vcpu->Guest, 0, Vcpu->GuestCpuIndex, cr0, ((PQWORD)(&Vcpu->ArchRegs))[gpReg], &action);
            if (NT_SUCCESS(introStatus) && introGuestNotAllowed == action)
            {
                status = CX_STATUS_SUCCESS;
                goto update_rip;
            }
            // else ignore

            // update ***SHADOW*** CR0 value, both in Vcpu/ARCH and VMCS
            Vcpu->ReadShadowCR0 = ((PQWORD)(&Vcpu->ArchRegs))[gpReg];
            vmx_vmwrite(VMCS_GUEST_CR0_READ_SHADOW, Vcpu->ReadShadowCR0);


            // handle PAGED --> NON-PAGED transitions, when guest sets CR0.PG = 0
            if (((Vcpu->ReadShadowCR0 & CR0_PG) == 0) &&
                ((cr0 & CR0_PG) != 0))
            {
                if ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA) != 0)
                {
                    QWORD efer = 0;

                    // update VM ENTRY control
                    Vcpu->VmcsConfig.VmEntryCtrl = Vcpu->VmcsConfig.VmEntryCtrl & (~(DWORD)(VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA));

                    // Intel 26.3.1
                    // If the "IA-32e mode guest" VM-entry control is 0, bit 17 in the CR4 field (corresponding to CR4.PCIDE) must be 0.
                    Vcpu->ArchRegs.CR4 &= ~((QWORD)CR4_PCIDE);

                    vmx_vmwrite(VMCS_VM_ENTRY_CONTROL, Vcpu->VmcsConfig.VmEntryCtrl);

                        // update EFER MSR
                    vmx_vmread(VMCS_GUEST_IA32_EFER, &efer);
                    efer = efer & ~EFER_LMA;
                    vmx_vmwrite(VMCS_GUEST_IA32_EFER, efer);
                }
            }

            // handle NON-PAGED --> PAGED transition, when guest sets CR0.PG = 1
            if (((Vcpu->ReadShadowCR0 & CR0_PG) != 0) &&
                ((cr0 & CR0_PG) == 0))
            {
                QWORD efer = 0;
                vmx_vmread(VMCS_GUEST_IA32_EFER, &efer);

                if (((efer & EFER_LME) != 0) && ((efer & EFER_LMA) == 0))
                {
                    Vcpu->VmcsConfig.VmEntryCtrl = Vcpu->VmcsConfig.VmEntryCtrl | VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA;
                    vmx_vmwrite(VMCS_VM_ENTRY_CONTROL, Vcpu->VmcsConfig.VmEntryCtrl);

                    // update EFER MSR
                    efer = efer | EFER_LMA;
                    vmx_vmwrite(VMCS_GUEST_IA32_EFER, efer);
                }
                else
                {
                    if ((Vcpu->ReadShadowCR4 & CR4_PAE) != 0)
                    {
                        status = _VmxReloadVmcsFieldsForPae32(Vcpu); // set CR0.PG = 1 in 32 bit
                        if (!SUCCESS(status))
                        {
                            LOG_FUNC_FAIL("_VmxReloadVmcsFieldsForPae32", status);
                            return status;
                        }
                    }
                }
            }

            // update ***REAL*** CR0 value, both in ARCH and VMCS
            Vcpu->ArchRegs.CR0 = Vcpu->ReadShadowCR0 | CR0_NE;
            {
                QWORD vpid = 0;

                vmx_vmread(VMCS_VPID, &vpid);

                status = CpuVmxInvVpid(1, NULL, vpid); // TYPE 1: Single-context invalidation
                if (!SUCCESS(status))
                {
                    HvPrint("[AP %d] INVVPID type 1 failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
                    return CX_STATUS_INVALID_INTERNAL_STATE; //HvHalt();
                }
            }


        }
        // MOV CR4, ...
        else if (crReg == 4)
        {
            QWORD cr4 = 0;

            vmx_vmread(VMCS_GUEST_CR4, &cr4);

            NTSTATUS introStatus = CX_STATUS_SUCCESS;

            // Call introspection callback for CR4 load, if set.
            introStatus = Vcpu->Guest->Intro.IntroCrCallback(Vcpu->Guest, 4, Vcpu->GuestCpuIndex, cr4, ((PQWORD)(&Vcpu->ArchRegs))[gpReg], &action);
            if (NT_SUCCESS(introStatus) && introGuestNotAllowed == action)
            {
                status = CX_STATUS_SUCCESS;
                goto update_rip;
            }

            // update ***SHADOW*** CR4 value, both in Vcpu/ARCH and VMCS
            Vcpu->ReadShadowCR4 = ((PQWORD)(&Vcpu->ArchRegs))[gpReg];
            vmx_vmwrite(VMCS_GUEST_CR4_READ_SHADOW, Vcpu->ReadShadowCR4);

            // handle NON-PAE --> PAE transition, when guest sets CR4.PAE = 1
            if (((Vcpu->ReadShadowCR4 & CR4_PAE) != 0) &&
                ((cr4 & CR4_PAE) == 0))
            {
                QWORD efer = 0;
                QWORD cr0 = 0;

                vmx_vmread(VMCS_GUEST_IA32_EFER, &efer);

                if (((efer & EFER_IA32E_ENABLE) != 0) && ((efer & EFER_IA32E_ACTIVE) == 0))
                {
                    HvPrint("[CPU %d] guest tries to do 64 bit PM, NON-PAE --> PAE transition by setting CR4.PAE = 1\n", HvGetCurrentApicId());
                }
                else
                {
                    cr0 = Vcpu->ArchRegs.CR0;

                    if ((cr0 & CR0_PG) != 0)
                    {
                        // 32 bit mode PAE, with PG = 1
                        VCPULOG(Vcpu, "[CPU %d] guest tries to do 32 bit NON-PAE --> PAE transition, CR0.PG is 1, by setting CR4.PAE = 1\n", HvGetCurrentApicId());
                        return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
                    }
                }
            }

            // update ***REAL*** CR4 value, both in ARCH and VMCS
            Vcpu->ArchRegs.CR4 = Vcpu->ReadShadowCR4 | CR4_VMXE;
            {
                QWORD vpid = 0;

                vmx_vmread(VMCS_VPID, &vpid);

                status = CpuVmxInvVpid(1, NULL, vpid); // TYPE 1: Single-context invalidation
                if (!SUCCESS(status))
                {
                    HvPrint("[AP %d] INVVPID type 1 failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
                    return CX_STATUS_INVALID_INTERNAL_STATE;
                }
            }
        }
        // MOV CR3, ...
        else if (crReg == 3)
        {
            QWORD cr3 = 0;
            QWORD newCr3 = 0;
            BOOLEAN needsInvalidation = FALSE;

            cr3 = Vcpu->ArchRegs.CR3;
            newCr3 = ((PQWORD)(&Vcpu->ArchRegs))[gpReg];

            needsInvalidation = ((((newCr3 & BIT(63)) == 0) && (Vcpu->ArchRegs.CR4 & CR4_PCIDE)) || ((Vcpu->ArchRegs.CR4 & CR4_PCIDE) == 0)) ;

            newCr3 = (newCr3 & (~BIT(63)));

            // Call introspection callback for CR3 load, if set.
            NTSTATUS introStatus = CX_STATUS_SUCCESS;
            introStatus = Vcpu->Guest->Intro.IntroCrCallback(Vcpu->Guest, 3, Vcpu->GuestCpuIndex, cr3, newCr3, &action);
            if (NT_SUCCESS(introStatus) && introGuestNotAllowed == action)
            {
                status = CX_STATUS_SUCCESS;
                goto update_rip;
            }

            // update ***REAL*** CR3 value, both in ARCH and VMCS
            Vcpu->ArchRegs.CR3 = ((PQWORD)(&Vcpu->ArchRegs))[gpReg];

            Vcpu->ArchRegs.CR3 = newCr3;

            // CRITICAL: if we are in 32 bit mode with PAE active, we MUST reload the VMCS fields
            if (((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA) == 0) &&
                ((Vcpu->ReadShadowCR4 & CR4_PAE) != 0))
            {
                status = _VmxReloadVmcsFieldsForPae32(Vcpu); // reload CR3
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("_VmxReloadVmcsFieldsForPae32", status);
                    return status;
                }
            }

            if (needsInvalidation)
            {
                QWORD vpid = 0;

                vmx_vmread(VMCS_VPID, &vpid);

                status = CpuVmxInvVpid(3, NULL, vpid); // TYPE 3: Single-context invalidation, retaining global translations
                if (!SUCCESS(status))
                {
                    HvPrint("[AP %d] INVVPID type 3 failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
                    return CX_STATUS_INVALID_INTERNAL_STATE;
                }
            }
        }
        else if (crReg  == 8)
        {
            BYTE newCr8 = ((PQWORD)(&Vcpu->ArchRegs))[gpReg] & 0xF;

            __writecr8(newCr8);
        }
        else
        {
            LOG("UNHANDLED CASE #2\n");

            return CX_STATUS_INVALID_INTERNAL_STATE;
        }
    }
    // MOV to GP from CR
    else if (opType == 1)
    {
        // MOV ..., CR3
        if (crReg == 3) ((PQWORD)(&Vcpu->ArchRegs))[gpReg] = Vcpu->ArchRegs.CR3;
        else
        {
            HvPrint("UNHANDLED CASE #3\n");

            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
    }
    // CLTS
    else if (opType == 2)
    {
        QWORD cr0 = 0;

        cr0 = Vcpu->ArchRegs.CR0;

        // clear CR0.TS, in all places (read shadow, real value and also Arch)
        Vcpu->ReadShadowCR0 = Vcpu->ReadShadowCR0 & ~((QWORD)CR0_TS);

        cr0 = (cr0 & ~((QWORD)CR0_TS)) | CR0_NE;

        Vcpu->ArchRegs.CR0 = cr0;
    }
    // LMSW
    else if (opType == 3)
    {
        QWORD cr0 = 0;
        QWORD src = 0;

        cr0 = Vcpu->ArchRegs.CR0;

        src = (exitQual & 0xffff0000) >> 16; // bits 31:16, LMSW source data conform Intel Vol 3B, Table 24-3 "Exit Qualification for Control-Register Accesses"
        Vcpu->ReadShadowCR0 = (Vcpu->ReadShadowCR0 & 0xfffffffffffffff0ULL) | (src & 0xf); // patch CR0, lower 4 bits only (0,1,2,3), conform Intel Vol 2A, LMSW instrux reference

        vmx_vmwrite(VMCS_GUEST_CR0_READ_SHADOW, Vcpu->ReadShadowCR0);
        cr0 = (cr0 & 0xfffffffffffffff0ULL) | (src & 0xf) | CR0_NE;

        Vcpu->ArchRegs.CR0 = cr0;
    }
    else
    {
        HvPrint("[CPU %d] MOV TO/FROM CR  opType %d  crReg %d  gpReg %d\n",
            HvGetCurrentApicId(), opType, crReg, gpReg);

        HvPrint("UNHANDLED CASE #4\n");
    }

update_rip:
    if (SUCCESS(status)) status = STATUS_UPDATE_RIP;

    return status;
}


static NTSTATUS _VmxExitHandlerDrAccess(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerIo(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    GUEST* guest = NULL;
    GUEST_IO_HOOK hook;
    WORD ioPort = 0;
    QWORD exitQual = 0;

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    ioPort = (WORD)((exitQual & 0xFFFF0000) >> 16);

    guest = Vcpu->Guest;

    // Call the hypervisor specific I/O hook handler
    status = HkCallIoHook(Vcpu, ioPort, exitQual, &hook);
    if ((!SUCCESS(status)) &&
        (status != STATUS_NO_HOOK_MATCHED) &&
        (status != STATUS_NEEDS_EMULATION) &&
        (status != STATUS_EXECUTE_ON_BARE_METAL))
    {
        LOG("[CPU %d] HkCallIoHook failed, status = %s\n", HvGetCurrentApicId(), NtStatusToString(status));
        return status;
    }

    if (SUCCESS(status)) return STATUS_UPDATE_RIP;

    // For REP or STRING IN/OUT instrux we need emulation, then fall back to default handler or bare-metal because of NULL hook
    if ((exitQual & 0x30) != 0)
    {
        // this is the case when we get STATUS_NO_HOOK_MATCHED from HkCallIoHook and have NO resource
        status = STATUS_NEEDS_EMULATION;
    }

    if (status  == STATUS_NO_HOOK_MATCHED)
    {
        // NOTE: we do NOT have introspection callback for I/O ops here

        // Directly call the default hook handlers, if present (note, that this is NOT done for REP or STRING IN/OUT ops, which are emulated)
        if ((exitQual & 0x08) == 0)
        {
            // OUT
            if (guest->WriteIoPort != NULL)
            {
                status = guest->WriteIoPort(ioPort, (exitQual & 0x7) + 1, (PBYTE)&Vcpu->ArchRegs.EAX, NULL);
                if (status == STATUS_EXECUTE_ON_BARE_METAL) goto execute_on_bare_metal;

                if (!SUCCESS(status)) LOG("Callback failed on WriteIoPort with status %s\n", NtStatusToString(status));
                goto jump_over_instrux;
            }
            else
            {
                status = STATUS_EXECUTE_ON_BARE_METAL;
                goto execute_on_bare_metal;
            }
        }
        else
        {
            // IN
            if (guest->ReadIoPort != NULL)
            {
                status = guest->ReadIoPort(ioPort, (exitQual & 0x7) + 1, (PBYTE)&Vcpu->ArchRegs.EAX, NULL);
                if (status == STATUS_EXECUTE_ON_BARE_METAL) goto execute_on_bare_metal;

                if (!SUCCESS(status)) LOG("Callback failed on ReadIoPort with status %s\n", NtStatusToString(status));
                goto jump_over_instrux;
            }
            else
            {
                status = STATUS_EXECUTE_ON_BARE_METAL;
                goto execute_on_bare_metal;
            }
        }
    }

    // If needed, try to run the emulator
    if (status == STATUS_NEEDS_EMULATION) status = EmhvDecodeAndEmulateInGuestContext(Vcpu, NULL, 0, 0, &hook);

    // If not matched, then we perform bare-metal op
    if (status == STATUS_EXECUTE_ON_BARE_METAL)
        execute_on_bare_metal:
    {
        BYTE opWidth = (exitQual & 0x7);

        // perform op bare-metal IN / OUT
        if ((exitQual & 0x08) == 0)
        {
            // OUT
            switch (opWidth)
            {
            case 0x00:
                __outbyte(ioPort, Vcpu->ArchRegs.AL);
                break;
            case 0x01:
                __outword(ioPort, Vcpu->ArchRegs.AX);
                break;
            case 0x03:
                __outdword(ioPort, Vcpu->ArchRegs.EAX);
                break;
            }
        }
        else
        {
            // IN
            switch (opWidth)
            {
            case 0x00:
                Vcpu->ArchRegs.AL = __inbyte(ioPort);
                break;
            case 0x01:
                Vcpu->ArchRegs.AX = __inword(ioPort);
                break;
            case 0x03:
                Vcpu->ArchRegs.EAX = __indword(ioPort);
                break;
            }
        }

        status = CX_STATUS_SUCCESS;

        // jump over instrux
    jump_over_instrux:
        status = STATUS_UPDATE_RIP;
    }

    return status;
}


static NTSTATUS _VmxExitHandlerMsrRead(_In_ VCPU* Vcpu)
{
    NTSTATUS status;
    GUEST* guest = Vcpu->Guest;
    GUEST_MSR_HOOK hook;
    BOOLEAN callbacksLockTaken = FALSE;
    DWORD msr = Vcpu->ArchRegs.ECX;
    QWORD tempValue;

    if (msr == MSR_DBG_ENABLE_SERIAL_IO)
    {
        CfgDebugOutputSerialEnabled = 1;
        IoInitForTrace(FALSE, TRUE);
        IoEnableSerialOutput(TRUE);
        IoEnableSerial(TRUE);

        DbgEnterDebugger();

        tempValue = 0xDB60DB60DB60DB60;

        status = CX_STATUS_SUCCESS;
        goto jump_over_instrux;
    }
    if (msr == MSR_DBG_REQUEST_FEEDBACK_MODULE)
    {
        LD_NAPOCA_MODULE *module = NULL;

        status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_FEEDBACK, &module);

        tempValue = SUCCESS(status) ? module->Pa : 0;

        status = CX_STATUS_SUCCESS;
        goto jump_over_instrux;
    }


    // Special treatment for SYNTHETIC MSRs (HYPER-V)
    if (IS_MSFT_HV_SYNTHETIC_MSR(msr))
    {
        status = GstEnHandleMsrRead(Vcpu, msr, &tempValue);
        goto jump_over_instrux;
    }

    // Call the hypervisor specific MSR hook handler
    status = HkCallMsrHook(Vcpu, msr, FALSE, &tempValue, &hook);
    if ((!SUCCESS(status)) &&
        (status != STATUS_NO_HOOK_MATCHED) &&
        (status != STATUS_NEEDS_EMULATION) &&
        (status != STATUS_EXECUTE_ON_BARE_METAL))
    {
        LOG("[CPU %d] HkCallMsrHook failed, status = %s\n", HvGetCurrentApicId(), NtStatusToString(status));
        return status;
    }

    if (SUCCESS(status)) goto jump_over_instrux;

    // If not matched (STATUS_NO_HOOK_MATCHED), call the introspection specific MSR hook handler
    if (status == STATUS_NO_HOOK_MATCHED)
    {
        NTSTATUS statusIntro = CX_STATUS_SUCCESS;
        HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
        callbacksLockTaken = TRUE;
        PFUNC_IntMSRViolationCallback pIntroMsrCallback = guest->Intro.RawIntroMsrCallback;

        if (pIntroMsrCallback != NULL)
        {
            INTRO_ACTION action = 0;

            statusIntro = pIntroMsrCallback(Vcpu->Guest, msr, IG_MSR_HOOK_READ, &action, tempValue, &tempValue, Vcpu->GuestCpuIndex);
            if (SUCCESS(statusIntro) && action == introGuestAllowed)
            {
                status = CX_STATUS_SUCCESS;
                goto jump_over_instrux;
            }
            else if (statusIntro == CX_STATUS_NOT_FOUND)
            {
                // Simply go on, will handle this below; we want the original HV status to be used, not our introcore status.
            }
            else if (statusIntro == INT_STATUS_FATAL_ERROR)
            {
                HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
                callbacksLockTaken = FALSE;
                LOG("Introspection callback returned 0x%x! Disable introspection for this guest!\n");
                statusIntro = NapIntDisable((PVOID)guest, IG_DISABLE_IGNORE_SAFENESS);
                if (!SUCCESS(statusIntro)) LOG_FUNC_FAIL("NapIntDisable", statusIntro);
            }
            else
            {
                LOG("[CPU %d] pIntroMsrCallback failed, status = %s\n", HvGetCurrentApicId(), NtStatusToString(status));
            }
        }
    }

    // If needed, try to run the emulator
    if (status == STATUS_NEEDS_EMULATION) status = EmhvDecodeAndEmulateInGuestContext(Vcpu, NULL, 0, 0, &hook);

    // If not matched, try to handle special, built-in cases
    if (status == STATUS_NO_HOOK_MATCHED)
    {
        // assume at the beginning that will match
        status = CX_STATUS_SUCCESS;

        switch (msr)
        {
        case MSR_IA32_DEBUGCTL:
            vmx_vmread(VMCS_GUEST_IA32_DEBUGCTL, &tempValue);
            break;
        case MSR_IA32_SYSENTER_CS:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_CS, &tempValue);
            break;
        case MSR_IA32_SYSENTER_RSP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RSP, &tempValue);
            break;
        case MSR_IA32_SYSENTER_RIP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RIP, &tempValue);
            break;
        case MSR_IA32_PERF_GLOBAL_CTRL:
            vmx_vmread(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, &tempValue);
            break;
        case MSR_IA32_PAT:
            vmx_vmread(VMCS_GUEST_IA32_PAT, &tempValue);
            break;
        case MSR_IA32_EFER:
            vmx_vmread(VMCS_GUEST_IA32_EFER, &tempValue);
            break;
        case MSR_IA32_FS_BASE:
            vmx_vmread(VMCS_GUEST_FS_BASE, &tempValue);
            break;
        case MSR_IA32_GS_BASE:
            vmx_vmread(VMCS_GUEST_GS_BASE, &tempValue);
            break;
        default:
            // 6. if none of the special MSRs matched, we will need to call the default handler, or execute it at bare-metal level
            if (guest->ReadMsr != NULL)
            {
                status = guest->ReadMsr(msr, &tempValue, NULL);
                goto jump_over_instrux;
            }
            else
            {
                status = STATUS_EXECUTE_ON_BARE_METAL;
            }
        }

        if (SUCCESS(status))
        {
            goto jump_over_instrux;
        }
    }

    // If not matched, then it is a non-standard MSR (out of the typical low / high ranges), so we perform bare-metal op
    if (status == STATUS_EXECUTE_ON_BARE_METAL)
    {
        // if we get here then we need to inject a #GP in guest if it is trying to access an unknown MSR
        if (CpuIsKnownMsr(msr))
        {
            tempValue = __readmsr(msr);
            status = CX_STATUS_SUCCESS;
        }
        else status = STATUS_INJECT_GP;

    jump_over_instrux:
        if (SUCCESS(status)) status = STATUS_UPDATE_RIP;
    }

    if (callbacksLockTaken) HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    if (CX_SUCCESS(status))
    {
        // give back in EDX:EAX the value of the MSR
        DWORD edx = (tempValue >> 32) & 0xffffffff;
        DWORD eax = tempValue & 0xffffffff;
        Vcpu->ArchRegs.RDX = edx;       // RDX and RAX, conform Intel Vol 2B, RDMSR, states "On processors that support the Intel 64
        Vcpu->ArchRegs.RAX = eax;       // architecture, the high-order 32 bits of each of RAX and RDX are cleared."
    }

    return status;
}


static NTSTATUS _VmxExitHandlerMsrWrite(_In_ VCPU* Vcpu)
{
    NTSTATUS status;
    GUEST* guest = Vcpu->Guest;
    GUEST_MSR_HOOK hook;
    BOOLEAN callbacksLockTaken = FALSE;

    DWORD msr = Vcpu->ArchRegs.ECX;
    QWORD value = (((QWORD)Vcpu->ArchRegs.EDX) << 32) | (Vcpu->ArchRegs.EAX);

    //
    // On UEFI boot we are looking for a behavior in order to determine if the guest is Windows 7 or Windows 8
    // This is important because we are exposing a Microsoft Hypervisor Interface
    // in order to enable Relaxed Timing (get rid of Clock Watchdog and DPC watchdog violation bug-checks).
    // In Windows 7 Hyper-V is loaded as a boot service and is not started before the OS (confirmed by Microsoft Hyper-V developers).
    // If we expose the MS HV interface too soon on Windows 7 UEFI we get a nice 0x50 bug-check because
    // such a scenario, Microsoft HV before OS on Windows 7 UEFI, was never intended by Microsoft.
    // We will use a MSR access pattern in order to distinguish Windows 7 from Windows 8(or newer)
    // When the LSTAR is first written we will begin exposing Microsoft HV interface
    // if the next MSR used after LSTAR is not a synthetic msr we will assume we are dealing with Windows 7
    // and for Windows 7 we will stop exposing the Microsoft Hypervisor interface until MSR_IA32_TSC is first written
    // note: we ignore IA32_EFER MSR accesses because they are irrelevant
    //
    if (IS_MSFT_HV_SYNTHETIC_MSR(msr))
    {
        status = GstEnHandleMsrWrite(Vcpu, msr, value);
        goto jump_over_instrux;
    }

    // Call the hypervisor specific MSR hook handler
    status = HkCallMsrHook(Vcpu, msr, TRUE, &value, &hook);
    if ((!SUCCESS(status)) &&
        (status != STATUS_NO_HOOK_MATCHED) &&
        (status != STATUS_NEEDS_EMULATION) &&
        (status != STATUS_EXECUTE_ON_BARE_METAL))
    {
        LOG("[CPU %d] HkCallMsrHook failed on %u(0x%016llX), status = %s\n", HvGetCurrentApicId(), msr, value, NtStatusToString(status));
        return status;
    }

    HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
    callbacksLockTaken = TRUE;
    PFUNC_IntMSRViolationCallback pIntroMsrCallback = guest->Intro.RawIntroMsrCallback;

    // We know that the violation wasn't generated by a hook on a virtual device, so we can re-execute it if needed.
    Vcpu->SafeToReExecute = TRUE;

    if (pIntroMsrCallback != NULL)
    {
        QWORD newValue = 0, oldValue = 0;
        INTRO_ACTION action = 0;

        newValue = value;

        switch (msr)
        {
        case MSR_IA32_DEBUGCTL:
            vmx_vmread(VMCS_GUEST_IA32_DEBUGCTL, &oldValue);
            break;
        case MSR_IA32_SYSENTER_CS:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_CS, &oldValue);
            break;
        case MSR_IA32_SYSENTER_RSP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RSP, &oldValue);
            break;
        case MSR_IA32_SYSENTER_RIP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RIP, &oldValue);
            break;
        case MSR_IA32_PERF_GLOBAL_CTRL:
            vmx_vmread(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, &oldValue);
            break;
        case MSR_IA32_PAT:
            vmx_vmread(VMCS_GUEST_IA32_PAT, &oldValue);
            break;
        case MSR_IA32_EFER:
            vmx_vmread(VMCS_GUEST_IA32_EFER, &oldValue);
            break;
        case MSR_IA32_FS_BASE:
            vmx_vmread(VMCS_GUEST_FS_BASE, &oldValue);
            break;
        case MSR_IA32_GS_BASE:
            vmx_vmread(VMCS_GUEST_GS_BASE, &oldValue);
            break;
        default:
            // NOTE: This is safe, since we are executing as a result of a WRMSR; therefore, any MSR not auto-saved
            // inside the VMCS will can be read directly (because we don't use MSR load/save area!!!)
            if (!CpuIsKnownMsr(msr))
            {
                status = STATUS_INJECT_GP;
                goto jump_over_instrux;
            }

            oldValue = __readmsr(msr);

            break;
        }

        NTSTATUS statusIntro = pIntroMsrCallback(Vcpu->Guest, msr, IG_MSR_HOOK_WRITE, &action, oldValue, &newValue, Vcpu->GuestCpuIndex);
        if (SUCCESS(status))
        {
            // If the HV callback on this MSR returned CX_STATUS_SUCCESS, we need to jump over the instruction,
            // regardless of the value returned by the introspection callback.
            goto jump_over_instrux;
        }
        else if (SUCCESS(statusIntro))
        {
            if (action == introGuestNotAllowed)
            {
                // Skip the instruction if DENIED by introspection engine. Here we will actually modify the
                // value returned, since we want to block the WRMSR.
                status = CX_STATUS_SUCCESS;
                goto jump_over_instrux;
            }
            else
            {
                // Nothing to do here. We will propagate the status returned by the HV, not the intro one.
            }
        }
        else if (statusIntro == CX_STATUS_NOT_FOUND)
        {
            // Simply go on, will handle this below; we want the original HV status to be used, not our introcore status.
        }
        else if (statusIntro == INT_STATUS_FATAL_ERROR)
        {
            HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
            callbacksLockTaken = FALSE;

            LOG("Introspection callback returned 0x%x! Disable introspection for this guest!\n", statusIntro);
            statusIntro = NapIntDisable((PVOID)guest, IG_DISABLE_IGNORE_SAFENESS);
            if (!SUCCESS(statusIntro))
            {
                LOG_FUNC_FAIL("NapIntDisable", statusIntro);
            }
        }
        else
        {
            LOG("[CPU %d] pIntroMsrCallback failed, status = %s\n", HvGetCurrentApicId(), NtStatusToString(statusIntro));
        }
    }
    else if (SUCCESS(status)) goto jump_over_instrux;

    // 4. if needed, try to run the emulator
    if (status == STATUS_NEEDS_EMULATION)
    {
        status = EmhvDecodeAndEmulateInGuestContext(Vcpu, NULL, 0, 0, &hook);        // no Flags, no GPA, we DO have RESOURCE (Context) pointer but might be NULL
        if (!SUCCESS(status))
        {
            LOG("ERROR: EmhvDecodeAndEmulateInGuestContext failed guest %p  PCPU %p  vcpu %p  msr 0x%08x  value 0x%016llx, status=%s\n",
                guest, HvGetCurrentCpu(), Vcpu, msr, value, NtStatusToString(status));
        }
    }

    // 5. if not matched, try to handle special, built-in cases
    if (status == STATUS_NO_HOOK_MATCHED)
    {
        // assume at the beginning that will match
        status = CX_STATUS_SUCCESS;

        switch (msr)
        {
        case MSR_IA32_DEBUGCTL:
            vmx_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, value);
            break;
        case MSR_IA32_SYSENTER_CS:
            vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, value);
            break;
        case MSR_IA32_SYSENTER_RSP:
            vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_RSP, value);
            break;
        case MSR_IA32_SYSENTER_RIP:
            vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_RIP, value);
            break;
        case MSR_IA32_PERF_GLOBAL_CTRL:
            vmx_vmwrite(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, value);
            break;
        case MSR_IA32_PAT:
            vmx_vmwrite(VMCS_GUEST_IA32_PAT, value);
            break;
        case MSR_IA32_EFER:
            vmx_vmwrite(VMCS_GUEST_IA32_EFER, value);
            break;
        case MSR_IA32_FS_BASE:
            vmx_vmwrite(VMCS_GUEST_FS_BASE, value);
            break;
        case MSR_IA32_GS_BASE:
            vmx_vmwrite(VMCS_GUEST_GS_BASE, value);
            break;
        default:
            // 6. if none of the special MSRs matched, we will need to call the default handler, or execute it at bare-metal level
            if (guest->WriteMsr != NULL)
            {
                status = guest->WriteMsr(msr, value, NULL);
                if (!SUCCESS(status))
                {
                    LOG("ERROR: guest->WriteMsr default handler failed guest %p  PCPU %p  vcpu %p  msr 0x%08x  value 0x%016llx, status=%s\n",
                        guest, HvGetCurrentCpu(), Vcpu, msr, value, NtStatusToString(status));
                }
                goto jump_over_instrux;
            }
            else status = STATUS_EXECUTE_ON_BARE_METAL;
        }

        if (SUCCESS(status)) goto jump_over_instrux;
    }

    // 7. if not matched, then it is a non-standard MSR (out of the typical low / high ranges), so we perform bare-metal op
    if (status == STATUS_EXECUTE_ON_BARE_METAL)
    {
        if (CpuIsKnownMsr(msr))
        {
            __writemsr(msr, value);

            status = CX_STATUS_SUCCESS;
        }
        else status = STATUS_INJECT_GP;

    jump_over_instrux:

        if (SUCCESS(status)) status = STATUS_UPDATE_RIP; // jump over WRMSR
    }

    if (callbacksLockTaken) HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}


static NTSTATUS _VmxExitHandlerInvalidGuestState(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerMsrLoading(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

static NTSTATUS _VmxExitHandlerMwait(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerMonitorTrapFlag(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    status = EmhvEndHandlingEptViolation(Vcpu);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] EmhvEndHandlingEptViolation failed: 0x%08x\n", status);
        DbgBreak();
    }
    if (status != CX_STATUS_SUCCESS) VCPULOG(Vcpu, "Handling MTF exit with status 0x%x!", status);

    return status;
}


static NTSTATUS _VmxExitHandlerMonitor(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerPause(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerMachineCheck(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerTprBelowThreshold(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerApicAccess(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerVirtualizedEoi(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerGdtIdtrAccess(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD instructionInformation = 0;
    DWORD flags = 0;
    INTRO_ACTION action = introReasonAllowed;

    vmx_vmread(VMCS_VM_EXIT_INSTRUCTION_INFORMATION, &instructionInformation);

    // Invoke introcore, if required.
    flags = 0;

    // Get the entity accessed - TR, LDT, GDT, IDT.
    switch ((instructionInformation >> 28) & 3)
    {
    case 0:
        // SGDT
        flags = IG_DESC_ACCESS_GDTR | IG_DESC_ACCESS_READ;
        break;
    case 1:
        // SIDT
        flags = IG_DESC_ACCESS_IDTR | IG_DESC_ACCESS_READ;
        break;
    case 2:
        // LGDT
        flags = IG_DESC_ACCESS_GDTR | IG_DESC_ACCESS_WRITE;
        break;
    case 3:
        // LIDT
        flags = IG_DESC_ACCESS_IDTR | IG_DESC_ACCESS_WRITE;
        break;
    }

    NTSTATUS introStatus = CX_STATUS_SUCCESS;

    introStatus = Vcpu->Guest->Intro.IntroDescriptorTableCallback(Vcpu->Guest, flags, Vcpu->GuestCpuIndex, &action);
    if ((NT_SUCCESS(introStatus)) && (introGuestNotAllowed == action)) goto _block_emulation;
    else if (!SUCCESS(introStatus)) LOG("Introspection callback returned 0x%x\n", introStatus);

    status = EmhvDecodeAndEmulateInGuestContext(Vcpu, NULL, 0, 0, NULL);
    if (!NT_SUCCESS(status)) ERROR("EMU : Failed emulating instruction at %018p\n", Vcpu->ArchRegs.RIP);

    goto _done_emulation;

_block_emulation:
    if (SUCCESS(status)) status = STATUS_UPDATE_RIP;

_done_emulation:

    return status;
}


static NTSTATUS _VmxExitHandlerLdtrTrAccess(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    status = EmhvDecodeAndEmulateInGuestContext(Vcpu, NULL, 0, 0, NULL);
    if (!NT_SUCCESS(status)) ERROR("EMU : Failed emulating instruction at %018p\n", Vcpu->ArchRegs.RIP);

    return status;

}


/// @brief Handler for the TSC page hook (workaround)
///
/// This function takes the Guest physical address of the hooked TSC page, clears the hook and sets the PWT bit in the last
/// page entry of the Guests' virtual translation to that address. This ensures the hibernate happens on Win 10 RS4.
/// This is issue only happens on Win 10 RS4, if TSC paging enlightenment is activated.
///
/// @param[in]  Vcpu            VCPU on which the workaround will be executed
/// @param[in]  GuestAddress    GPA where the workaround will be applied
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, workaround done
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_VmxHandleTscPageHook(
    _In_    VCPU*           Vcpu,
    _In_    QWORD           GuestAddress
)
{
    NTSTATUS status;
    QWORD gla;
    QWORD temp_hpa; // needed for function call
    VOID* pte;

    // first read of the TSC page. Hack Guest mapping, make sure to have PWT set in it's PTE (or the last level
    // paging structure entry). This is needed only for Hibernate on Win10 RS4.
    VCPULOG(Vcpu, "First access to TSC page!\n");

    status = EptSetCacheAndRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), PAGE_BASE_PA(GuestAddress), 0, EPT_RIGHTS_R, EPT_CACHING_WB);
    if (!_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptSetCacheAndRights", status);
        return status; // failed to set the access rights and the cache rights for the TSC page, keep hook alive.
    }

    // get to the guests mapping structures, and change them
    vmx_vmread(VMCS_GUEST_LINEAR, &gla);
    VCPULOG(Vcpu, "TSC page Guest Linear Address: 0x%llx\n", gla);

    status = ChmGvaToGpaAndHpaEx(Vcpu, gla, NULL, &temp_hpa, &pte);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmGvaToGpaAndHpaEx", status);
        // put back hook --> never should be the case.
        EptSetRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), PAGE_BASE_PA(GuestAddress), 0, EPT_RIGHTS_NONE);
        return status;
    }

    BYTE entry = 0;
    entry = *(BYTE*)pte;
    VCPULOG(Vcpu, "TSC page Last Page Table HVA for the entry: %p, HPA of the TSC page: 0x%llx\n", pte, temp_hpa);

    entry |= BIT(3); // Mark PWT
    *(BYTE*)pte = entry;

    // free the VM reservation
    PVOID tmp = (PVOID)PAGE_BASE_VA(pte);
    MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &tmp);

    return CX_STATUS_SUCCESS;
}

static NTSTATUS _VmxExitHandlerEptViolation(_In_ VCPU* Vcpu)
{
    NTSTATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    GUEST* guest = NULL;
    BOOLEAN matched = FALSE, introMatched = FALSE;
    GUEST_EPT_HOOK hook;
    BOOLEAN hvMem = FALSE;
    QWORD exitQual = 0;
    QWORD guestAddress = 0;
    QWORD hpa;
    BOOLEAN callbacksLockTaken = FALSE;
    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    vmx_vmread(VMCS_GUEST_PHYSICAL, &guestAddress);

    guest = Vcpu->Guest;

    // check if this is a known guest address
    status = ChmGpaToHpa(guest, PAGE_BASE_PA(guestAddress), &hpa);
    if ((status == STATUS_NO_MAPPING_STRUCTURES) || (status == STATUS_EMPTY_MAPPING))
    {
        if (CfgDebugTracePci) VCPULOG(Vcpu, "Need to scan for BAR reconfigurations!\n");

        // Scan the PCI space for BAR reconfigurations and map new Guest memory zones.
        status = PciScanAllPciDeviceBarReconfigurations();
        if (!SUCCESS(status)) VCPUCRITICAL(Vcpu, "PciScanAllPciDeviceBarReconfigurations failed with status: %s!\n", NtStatusToString(status));

        // check once more the address to see if it was mapped.
        status = ChmGpaToHpa(guest, PAGE_BASE_PA(guestAddress), &hpa);
        if ((status == STATUS_NO_MAPPING_STRUCTURES) || (status == STATUS_EMPTY_MAPPING))
        {
            VCPUWARNING(Vcpu, "Attempted access to unknown physical address %p! WE MAP IT!:)\n", guestAddress);
            status = EptMapDevMem(GstGetEptOfPhysicalMemory(guest), CX_PAGE_BASE_4K(guestAddress), CX_PAGE_BASE_4K(guestAddress), 0);
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("EptMapDevMem", status);
        }
        return status;
    }
    else if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("ChmGpaToHpa", status);
    if (CfgFeaturesVirtualizationEnlightTscPage && CfgFeaturesVirtualizationEnlightTscPageWorkaround)
    {
        //
        // To see why we do this here please read the comment from the guestenlight.c file,
        // the GstEnHandleMsrWrite function, which deals with activating the TSC page
        // (case HV_X64_MSR_REFERENCE_TSC from the switch statement).
        //

        // Check if the violation comes from TSC page access, do this check only until it first happens.
        // status is checked for assuring the fact that we are dealing with a known guest address.
        if (NT_SUCCESS(status) && CxInterlockedBeginOnce(&guest->TscWorkaroundInit))
        {
            QWORD tsc = 0;
            status = MmQueryPa(&gHvMm, (PVOID)Vcpu->ReferenceTscPage, &tsc);
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("MmQueryPa", status);
            if (hpa == tsc)
            {
                status = _VmxHandleTscPageHook(Vcpu, guestAddress);
                if (NT_SUCCESS(status))
                {
                    CxInterlockedEndOnce(&guest->TscWorkaroundInit);
                    return CX_STATUS_SUCCESS;
                }
                else
                {
                    LOG_FUNC_FAIL("_VmxHandleTscPageHook", status);
                    CxInterlockedAbortOnce(&guest->TscWorkaroundInit);
                }
            }
            else CxInterlockedAbortOnce(&guest->TscWorkaroundInit);
        }
    }

    if (CfgFeaturesHibernatePersistance && HvHibIsHibernateMemoryAddress(guest, guestAddress))
    {
        return HvHibHandleHibernateMemory(guest, Vcpu, guestAddress, exitQual);
    }

    // check if this is a paging structure violation
    if ((exitQual & 0x100) == 0 && (exitQual & 0x80) != 0)
    {
        Vcpu->PagingStructureViolation = TRUE;
        Vcpu->SafeToReExecute = TRUE;

        // We don't want to go through all the decoding & searching of a matching hook code, we can simply skip
        // to emulation of faults due to A/D bits.
        goto emulate_now;
    }
    else Vcpu->PagingStructureViolation = FALSE;

    // in case of access to hyper-pages we will inject GP in guest
    // EPT rights must be configured correctly when guest set the page address
    // when handling synthetic MSRs
    if ((guest->MicrosoftHvInterfaceFlags & MSFT_HV_FLAG_EXPOSING_INTERFACE) && GstEnIsHyperPageAddress(guestAddress))
    {
        return STATUS_INJECT_GP;
    }

    // 1. call the hypervisor specific EPT hook handler
    status = HkCallEptHook(Vcpu, (QWORD)guestAddress, &hook);
    if ((!SUCCESS(status)) &&
        (status != STATUS_NO_HOOK_MATCHED) &&
        (status != STATUS_NEEDS_EMULATION))
    {
        LOG("[CPU %d] HkCallEptHook failed, status = %s\n", HvGetCurrentApicId(), NtStatusToString(status));
        return status;
    }


    // 2. if not matched (STATUS_NO_HOOK_MATCHED), call the introspection specific EPT hook handler
    if (status == STATUS_NO_HOOK_MATCHED)
    {
        //
        // We store the callback pointer in a separate var; we don't want it modified AFTER the if,
        // but before actually calling the callback.
        //
        HvAcquireRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
        callbacksLockTaken = TRUE;
        PFUNC_IntEPTViolationCallback pIntroEptCallback = guest->Intro.RawIntroEptCallback;
        QWORD gla = 0;

        vmx_vmread(VMCS_GUEST_LINEAR, &gla);

        // We know that the violation wasn't generated by a hook on a virtual device, so we can re-execute it if needed.
        Vcpu->SafeToReExecute = TRUE;

        if ((pIntroEptCallback != NULL) && (!Vcpu->PagingStructureViolation))
        {
            INTRO_ACTION action = introGuestAllowed;
            INTRO_ACTION tempAction = introGuestAllowed;
            BYTE type = 0;

            GstLock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);

            if (exitQual & EPT_RAW_RIGHTS_X) type |= IG_EPT_HOOK_EXECUTE;
            if (exitQual & EPT_RAW_RIGHTS_R) type |= IG_EPT_HOOK_READ;
            if (exitQual & EPT_RAW_RIGHTS_W) type |= IG_EPT_HOOK_WRITE;

            tempAction = introGuestAllowed;

            // Make sure the interrupts are enabled while we do our stuff; we don't want to hog the CPU in case we're doing something costly...
            IPC_INTERRUPTIBILITY_STATE intState = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_ALLOW_CURRENT);

            // Must use the same EPT violation callback as the old HV, to maintain consistency.
            status = pIntroEptCallback(Vcpu->Guest,             // The guest
                (QWORD)guestAddress,     // The faulted GPA
                0,                       // Access size. If 0, intro will deduce it.
                gla,                     // Guest linear address.
                Vcpu->GuestCpuIndex,     // CPU number.
                &tempAction,             // Desired action for this attempt.
                type                     // Access type.
            );

            IpcSetInterruptibilityState(intState);

            // Always keep the largest value. The actions are ordered: the higher the priority, the largest the
            // ID.
            action = MAX(action, tempAction);

            GstUnlock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);

            if (SUCCESS(status))
            {
                matched = TRUE;
                introMatched = TRUE;

                // IntroEmu.BufferValid can be used only when the introspection returns IntroGuestAllowedPatched.
                if ((introGuestAllowedPatched != action) && (Vcpu->IntroEmu.BufferValid))
                {
                    // The action was overridden by another callback; simply invalidate the emu buffer.
                    Vcpu->IntroEmu.BufferValid = FALSE;
                    Vcpu->IntroEmu.BufferSize = 0;
                    Vcpu->IntroEmu.BufferGla = 0;
                }

                // IntroEmu.BufferValid is false but IntroGuestAllowedPatched is not set. This is not good.
                if ((introGuestAllowedPatched == action) && (!Vcpu->IntroEmu.BufferValid))
                {
                    ERROR("[ERROR] Introspection returned action %d, and IntroEmu.BufferValid is NOT set!\n", action);
                }

                // Set the appropriate status, according to the requested action.
                if (action == introGuestAllowed)
                {
                    // Allow the action. The instruction will be either re-executed, either emulated.
                    status = STATUS_NEEDS_EMULATION;
                }
                else if (action == introGuestIgnore)
                {
                    // Ignore the violation. Emulate or re-execute the instruction.
                    status = STATUS_NEEDS_EMULATION;
                }
                else if (action == introGuestAllowedVirtual)
                {
                    // Simply re-enter the guest at the current RIP and continue execution. This is used
                    // when HIPE modifies the RIP in order to make it point to some other instruction. This
                    // may also happen if intro fully emulated the instruction.
                    status = CX_STATUS_SUCCESS;
                    goto leave;
                }
                else if (action == introGuestRetry)
                {
                    // Simply re-enter the guest at the same RIP and continue execution. This is used by
                    // HIPE when some important pages (the page containing RIP, the written page) are
                    // swapped out by another Vcpu before we get to access them.
                    status = CX_STATUS_SUCCESS;
                    goto leave;
                }
                else if (action == introGuestAllowedPatched)
                {
                    // Intro has called IntroSetEmulatorContext in order to patch the access. Emulation is needed
                    // for this.
                    status = STATUS_NEEDS_EMULATION;
                }
                else if (action == introGuestNotAllowed)
                {
                    // Block this attempt. No modification will be made to the memory or CPU state, except
                    // for advancing the RIP to the next instruction.
                    status = CX_STATUS_ACCESS_DENIED;
                }
                else ERROR("Unknown action returned: %d\n", action);
            }
            else if (status == CX_STATUS_NOT_FOUND)
            {
                // NOTE: we can't execute on bare metal for EPT callbacks, so we try to emulate
                status = STATUS_NEEDS_EMULATION;
            }
            else if (status == INT_STATUS_FATAL_ERROR)
            {
                HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);
                callbacksLockTaken = FALSE;
                LOG("Introspection callback returned 0x%x! Disable introspection for this guest!\n", status);
                status = NapIntDisable((PVOID)guest, IG_DISABLE_IGNORE_SAFENESS);
                if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntDisable", status);

                status = STATUS_NEEDS_EMULATION;
            }
            else
            {
                // Any Introspection case of failure is treated by emulating the faulting instruction.
                status = STATUS_NEEDS_EMULATION;
            }
        }
        else status = STATUS_NEEDS_EMULATION;
    }
    else matched = TRUE;

    // 3. if needed, try to run the emulator, otherwise, simply skip the instruction
    if (status == STATUS_NEEDS_EMULATION)
    {
    perform_emulation:
        matched = TRUE;

        // detect if this is an access to our hypervisor reserved memory

        for (DWORD i = 0; i < gHypervisorGlobalData.MemInfo.HyperMap.Count; i++)
        {
            if ((gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].StartAddress <= (QWORD)((SIZE_T)guestAddress)) &&
                ((gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].StartAddress + gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].Length) > (QWORD)((SIZE_T)guestAddress))
                )
            {
                VCPULOG(Vcpu, "Guest tries to access our memory! Ignore and advance the RIP! Start: %p End: %p, address: %p\n",
                    gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].StartAddress, (gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].StartAddress + gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].Length), guestAddress);

                hvMem = TRUE;
                break;
            }
        }

        if (hvMem) status = _SkipCurrentInstruction(Vcpu);
        else
        {
        emulate_now:
            status = EmhvDecodeAndEmulateInGuestContext(Vcpu, // In the context of the current VCPU
                NULL,                                         // Let the emulator decode the instruction
                introMatched ? ND_FLAG_INTROSPECTION : 0,     // Due to introspection?
                (QWORD)guestAddress,                          // Faulted GPA
                &hook
            );
        }

        goto leave;
    }
    else if (status == CX_STATUS_ACCESS_DENIED)
    {
        matched = TRUE;

        // Skip the faulting instruction.
        status = _SkipCurrentInstruction(Vcpu);

        // If we were emulating an EPT violation, stop it now.
        if (Vcpu->EmulatingEptViolation)
        {
            status = EmhvEndHandlingEptViolation(Vcpu);
            if (!NT_SUCCESS(status)) ERROR("EmhvEndHandlingEptViolation failed: 0x%08x\n", status);
        }

        goto leave;
    }

    // 5. if not matched, then we assume that the VMEXIT was performed due to granularity issues, and thus, we
    // do need to perform emulation of the instrux in the GUEST environment
    if (!matched)
    {
        LOG("[CPU %d] EPT violation on GPA %018p matching NO hook handlers at all; assume 4K granularity limit and perform emulation\n", HvGetCurrentApicId(), guestAddress);

        goto perform_emulation;
    }

leave:
    if (callbacksLockTaken) HvReleaseRwSpinLockShared(&guest->Intro.IntroCallbacksLock);

    return status;
}


static NTSTATUS _VmxExitHandlerEptMisconfiguration(_In_ VCPU* Vcpu)
{
    QWORD exitQual = 0;
    QWORD guestAddress = 0;

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    vmx_vmread(VMCS_GUEST_PHYSICAL, &guestAddress);

    CRITICAL("EPT misconfiguration on %p with %p\n", guestAddress, exitQual);
    LOG("Total domains: %d\n", GstGetMemoryDomainsCount(Vcpu->Guest));
    for (CX_UINT8 i = 0; i < GstGetMemoryDomainsCount(Vcpu->Guest); i++)
    {
        LOG("EptpPage[%d]=%llX\n", i, Vcpu->Guest->EptpPage[i]);
    }
    DumpersDumpEptPageTablesWalk(Vcpu, guestAddress);
    EPT_DESCRIPTOR *ept = CX_NULL;
    VcpuGetActiveEptDescriptor(Vcpu, &ept);
    EptDumpMappings(ept);
    DumpCurrentVmcs(Vcpu->GuestCpuIndex);
    PwrReboot(CX_TRUE, CX_TRUE);

    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerInvEpt(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerRdtscp(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerPreemptionTimerExpired(_In_ VCPU* Vcpu)
{
    vmx_vmwrite(VMCS_VMX_PREEMPTION_TIMER, Vcpu->VmxTimerQuantum);

    if (IoGetPerCpuPhase() >= IO_CPU_ROOT_CYCLE) PROCESS_IPCS();

    //
    // Invoke the introspection timer callback.
    //
    if (CfgFeaturesIntrospectionCallTimer
        && Vcpu->IsBsp
        && (HvTscTicksIntervalToMicroseconds(HvGetTscTickCount(), Vcpu->IntroTimer) >= ONE_SECOND_IN_MICROSECONDS)
        )
    {
        NTSTATUS introStatus = CX_STATUS_SUCCESS;
        introStatus = Vcpu->Guest->Intro.IntroTimerCallback(Vcpu->Guest);
        if (!SUCCESS(introStatus))
        {
            if (introStatus != CX_STATUS_COMPONENT_NOT_INITIALIZED) LOG("Introspection callback returned 0x%x\n", introStatus);
        }

        Vcpu->IntroTimer = __rdtsc();
    }

    _RestoreVcpuActivityStateIfNecessary(Vcpu);

    return CX_STATUS_SUCCESS;
}


static NTSTATUS _VmxExitHandlerInvVpid(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerWbinvd(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerXsetbv(_In_ VCPU* Vcpu)
{
    NTSTATUS status;
    QWORD newXcrValue;

    newXcrValue = ((QWORD)Vcpu->ArchRegs.EDX << 32) | Vcpu->ArchRegs.EAX;

    LOG("[CPU %d] XSETBV, ECX = 0x%08x, EDX:EAX = 0x%08x%08x\n", HvGetCurrentApicId(), Vcpu->ArchRegs.ECX, Vcpu->ArchRegs.EDX, Vcpu->ArchRegs.EAX);

    status = CpuIsXsetbvCallValid(Vcpu, Vcpu->ArchRegs.ECX, newXcrValue);
    if (!NT_SUCCESS(status)) return status;

    Vcpu->ArchRegs.XCR0 = newXcrValue;

    // Invoke the intro handler.
    {
        INTRO_ACTION action = introGuestAllowed;

        NTSTATUS introStatus = Vcpu->Guest->Intro.IntroXcrCallback(Vcpu->Guest, Vcpu->GuestCpuIndex, &action);
        if (!NT_SUCCESS(introStatus))
        {
            if (introStatus != CX_STATUS_NOT_FOUND &&
                introStatus != CX_STATUS_COMPONENT_NOT_INITIALIZED)
            {
                ERROR("IntroXcrCallback failed: 0x%08x\n", introStatus);
            }

            // We don't want to crash the HV just because the Intro handler failed.
            status = CX_STATUS_SUCCESS;
        }
        else if (introGuestNotAllowed == action) goto _block_xsetbv;
    }
    // Allow the XCR0 to be set as the guest wants, but only until us (the host) have to utilize the FPU...

_block_xsetbv:
    // jump over XSETBV
    if (SUCCESS(status)) status = STATUS_UPDATE_RIP;

    return status;
}


static NTSTATUS _VmxExitHandlerApicWrite(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerRdRand(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerInvPcid(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerVmFunc(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerEncls(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerRdSeed(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerPmlFull(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerXSaveS(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerXRestoreS(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerSPP(_In_ VCPU* Vcpu)
{
    QWORD exitQual;
    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);

    VCPULOG(Vcpu, "Exit qualification %018p. Is SPP miss %u. NMI unblocking due to IRET %u\n",
        exitQual,
        ((exitQual & (1 << 11)) != 0),
        ((exitQual & (1 << 12)) != 0)
            );

    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerUmwait(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}


static NTSTATUS _VmxExitHandlerTpause(_In_ VCPU* Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
}

/// @}
