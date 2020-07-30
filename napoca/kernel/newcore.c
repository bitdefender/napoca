/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file newcore.c Hypervisor core functionality

/// \addgroup core Core (the main VM entry and VM exit point)
/// @{

#include "kernel/kerneldefs.h"
#include "kernel/kernel.h"
#include "kernel/newcore.h"
#include "debug/dumpers.h"
#include "debug/debugger.h"
#include "apic/lapic.h"
#include "guests/intro.h"
#include "boot/vmstate.h"
#include "communication/comm_guest.h"
#include "memory/cachemap.h"

NTSTATUS
HndCallExitHandler(
    _In_ CX_UINT64 ExitReason,
    _In_ VCPU* Vcpu
);

void
HvPcpuRootMainCycle(
    void
    )
{
    NTSTATUS status;
    PCPU* cpu;
    VCPU* vcpu;

    cpu = HvGetCurrentCpu();
    vcpu = HvGetCurrentVcpu();

    // don't schedule anything if we're trying to re-execute an instruction, using the fall back mechanism.
    if (vcpu->EmulatingEptViolation == FALSE) // if not re-execute instrux
    {
        QWORD startVcpuSearchTsc = __rdtsc();

        // just a sanity check to be sure that there we are scheduling the right thing
        if (cpu->Vcpu == vcpu)
        {
            // make this VMCS is active
            __vmx_vmptrld(&vcpu->VmcsPa);

            while (!vcpu->Schedulable)
            {
                // => sleep
                if (HvInterlockedAndI32((volatile int*)&vcpu->Guest->PowerState, UINT32_MAX) == GstPowerTransitionOccurring)
                {
                    IpcSetInterruptibilityValues(
                        TRUE, IPC_INTERRUPTS_ENABLED,
                        TRUE, TRUE,
                        TRUE, IPC_PRIORITY_IPI);

                    // we need to halt with queue processing enabled to be able to receive IPIs (including the IPI which requests are VMXOFF before power transition
                    for (;;) CpuYield();
                }

                // check for possible timeouts
                QWORD totalVcpuSearchTsc = 0;
                QWORD nowTsc = HvGetTscTickCount();

                // update total wait time
                totalVcpuSearchTsc += (nowTsc - startVcpuSearchTsc);

                // check if current wait time if over the timeout
                if (HvTscTicksIntervalToMicroseconds(nowTsc, startVcpuSearchTsc) >= 5 * 3 * ONE_SECOND_IN_MICROSECONDS) // more than 5 seconds
                {
                    CRITICAL("PCPU[%d] Id: %d is trying to get a VCPU to run for %d ms!\n",
                        HvGetCurrentCpuIndex(),
                        cpu->Id,
                        HvTscTicksDeltaToMilliseconds(totalVcpuSearchTsc)
                    );
                    for (DWORD pcpuIndex = 0; pcpuIndex < gHypervisorGlobalData.CpuData.CpuCount; pcpuIndex++)
                    {
                        VCPU* pVcpu = gHypervisorGlobalData.CpuData.Cpu[pcpuIndex]->Vcpu;
                        if (!pcpuIndex)
                        {
                            LOG("Guest->GlobalUpdate.PausedCount=%p\n", pVcpu->Guest->GlobalUpdate.PausedCount);
                        }
                        VCPULOG(pVcpu, "vcpu->CalledGstPauseCount=%d\n", pVcpu->CalledGstPauseCount);
                    }


                    for (DWORD vcpuIdx = 0; vcpuIdx < HvGetCurrentGuest()->VcpuCount; vcpuIdx++)
                    {
                        VCPU* localVcpu = HvGetCurrentGuest()->Vcpu[vcpuIdx];
                        VCPULOG(localVcpu, "Schedulable 0x%x state 0x%x pause count %d EmulatingEptViolation %d Guest power state %d\n",
                            localVcpu->Schedulable, localVcpu->State, localVcpu->VcpuPauseCount, localVcpu->EmulatingEptViolation, localVcpu->Guest->PowerState);
                    }

                    startVcpuSearchTsc = HvGetTscTickCount();
                }

                // give the debugger a chance
                if (CfgDebugOutputSerialEnabled) DbgScheduleDebugger();

                CpuYield();
            }

            // we need to update VMCS fields as requested by intro engine here because
            // on vcpu might pause other vcpu and request to activate BP exception exits on them
            // and then resume all paused VCPUs;
            // paused VCPUs are held in the above loop so any VMCS updates must be done here on resume
            VmstateUpdateVmcsForIntrospection(vcpu, FALSE, FALSE);
        }
        else ERROR("[PCPU %d] Different VCPUs: %p->%p\n", cpu->Id, cpu->Vcpu,vcpu);
    }

    // Do not inject any event while we re-execute an instruction using the magical mechanism
    if (vcpu->EmulatingEptViolation == FALSE)
    {
        QWORD interruptInj = 0;

        vmx_vmread(VMCS_VM_ENTRY_EVENT_INJECTION, &interruptInj);

        if ((interruptInj & 0x80000000) == 0)
        {
            BOOLEAN eventInjected;

            eventInjected = VirtExcReinjectPendingExceptions();

            if (eventInjected == FALSE)
            {
                status = VirtExcHandlePendingExceptions(vcpu);
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("VirtExcHandlePendingExceptions", status);
                    goto try_unload;
                }
            }
        }
        else LOG("Event injected in VMCS prematurely! (%p)\n", interruptInj);

        IpcSetInterruptibilityValues(FALSE, 0, FALSE, 0, TRUE, IPC_PRIORITY_LOWEST);
    }

    // If introcore requested a trap injection during this exit, notify it about the event that was actually injected
    if (vcpu->IntroRequestedTrapInjection)
    {
        QWORD interruptInj = 0;
        QWORD errCode = 0;

        vmx_vmread(VMCS_VM_ENTRY_EVENT_INJECTION, &interruptInj);
        vmx_vmread(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE, &errCode);

        HvGetCurrentGuest()->Intro.IntroEventInjectionCallback(HvGetCurrentGuest(), (interruptInj & 0xFF),
            errCode, vcpu->ArchRegs.CR2, vcpu->GuestCpuIndex);
    }

    if (!vcpu->EmulatingEptViolation) IpcSetInterruptibilityValues(FALSE, 0, FALSE, 0, TRUE, IPC_PRIORITY_LOWEST);

    // Restore guest DR6
    __writedr(6, vcpu->ArchRegs.DR6);

    // Load GUEST x86 / x64 ARCH registers implicitly handled by VMCS
    vmx_vmwrite(VMCS_GUEST_RFLAGS, vcpu->ArchRegs.RFLAGS);

    vmx_vmwrite(VMCS_GUEST_RIP, vcpu->ArchRegs.RIP);

    vmx_vmwrite(VMCS_GUEST_RSP, vcpu->ArchRegs.RSP);

    vmx_vmwrite(VMCS_GUEST_DR7, vcpu->ArchRegs.DR7);

    vmx_vmwrite(VMCS_GUEST_CR0, vcpu->ArchRegs.CR0);

    vmx_vmwrite(VMCS_GUEST_CR3, vcpu->ArchRegs.CR3);

    vmx_vmwrite(VMCS_GUEST_CR4, vcpu->ArchRegs.CR4);

    // last point where we check for ack of messages sent from another core to this core
    // any message that arrives after this point will be postponed
    PROCESS_IPCS();

    // the TPR is modified in multiple places, make sure we don't alter it for now
    if (vcpu->CurrentExitReason != EXIT_REASON_INVALID)
    {
        QWORD cr8 = __readcr8();
        if (vcpu->PlatformCr8AtExit != cr8)
        {
            if (vcpu->FirstApInitExitState != AT_FIRST_INIT_EXIT)
            {
                VCPULOG(vcpu, "Platform CR8 was left with modifications after handling a VM-Exit! Original %p current %p!\n",
                    vcpu->PlatformCr8AtExit, cr8);
            }
            __writecr8(vcpu->PlatformCr8AtExit);
        }
    }

    if (vcpu->FirstApInitExitState == AT_FIRST_INIT_EXIT) IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_ALLOW_ALL);

    // EXPERIMENTAL: save host DR7
    cpu->Dr7 = __readdr(7);

    HvVmxSwitchFromHostToVmGuest();

    status = CX_STATUS_NOT_SUPPORTED;
try_unload:
    CLN_UNLOAD(status);

    // Never returns
}


/// @brief Decode and calculate the current instruction length on the given VCPU
///
/// @param[in]  Vcpu            The VCPU structure on which the instruction will be analyzed
///
/// @returns The length of the current instruction, or 0 if something went wrong
static
__forceinline
BYTE
_GetInstructionLength(
    _In_ VCPU* Vcpu
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD iLen = 0;

    status = EmhvDecodeInstructionLenInGuestContext(Vcpu, (PBYTE)&iLen);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("EmhvDecodeInstructionLenInGuestContext", status);
        iLen = 0;
    }

    return (BYTE)iLen;
}


/// @brief Advances the RIP of the given VCPU
///
/// IMPORTANT: This function must be used only for instructions where the VMCS_VM_EXIT_INSTRUCTION_LENGTH is set
///
/// @param[in]  Vcpu            The VCPU structure on which the RIP will be updated
static
__forceinline
void
_UpdateRip(
    _In_ VCPU* Vcpu
)
{
    QWORD iLen = 0;

    // Try to get the length from the VMCS
    vmx_vmread(VMCS_VM_EXIT_INSTRUCTION_LENGTH, &iLen);

    if (iLen == 0) iLen = _GetInstructionLength(Vcpu);

    Vcpu->ArchRegs.RIP += iLen;
    Vcpu->PseudoRegs.CsRip += iLen;

    // we emulated an instruction => we need to clear the blocking by conditions
    QWORD intrState;

    vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intrState);

    intrState &= ~(VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS | VMCSFLAG_IRRSTATE_BLOCKING_BY_STI);

    vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intrState);
}


void
HvVmxHandleVmExitCommon(
    _In_ VCPU* Vcpu
    )
{
    NTSTATUS status;

    Vcpu->PlatformCr8AtExit = __readcr8();

    HvGetCurrentCpu()->NmiWatchDog.StartingRootModeTsc = HvGetTscTickCount();

    // Save the guest DR6
    Vcpu->ArchRegs.DR6 = __readdr(6);

    // Restore GUEST x86 / x64 ARCH registers implicitly handled by VMCS
    vmx_vmread(VMCS_GUEST_RFLAGS, &Vcpu->ArchRegs.RFLAGS);

    vmx_vmread(VMCS_GUEST_RSP, &Vcpu->ArchRegs.RSP);

    vmx_vmread(VMCS_GUEST_RIP, &Vcpu->ArchRegs.RIP);

    vmx_vmread(VMCS_GUEST_DR7, &Vcpu->ArchRegs.DR7);

    vmx_vmread(VMCS_GUEST_CR0, &Vcpu->ArchRegs.CR0);

    vmx_vmread(VMCS_GUEST_CR3, &Vcpu->ArchRegs.CR3);

    vmx_vmread(VMCS_GUEST_CR4, &Vcpu->ArchRegs.CR4);

    // Restore DR7
    __writedr(7, HvGetCurrentCpu()->Dr7);

    // EXPERIMENTAL DR state for host - reset DR6 (status register)
    // TODO: we would also need to save & restore DR0-3 if the guest would touch them
    __writedr(6, 0);

    vmx_vmread(VMCS_VM_EXIT_REASON, &Vcpu->CurrentExitReason);
    if (Vcpu->CurrentExitReason & EXIT_REASON_VM_ENTRY)
    {
        // failed entry... call resume / launch failure handler
        HvVmxLaunchOrResumeFailed(Vcpu, 0x1'00000000 | (Vcpu->CurrentExitReason & 0xFFFFFFFF));
    }

    // enable NMI watchdog
    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
    {
        LapicEnablePerfNMI();
    }

    PROCESS_IPCS();

    QWORD guestRIP, guestCsBase, guestSsBase, guestRSP, idtrLimit, gdtrLimit;

    vmx_vmread(VMCS_GUEST_RIP, &guestRIP);
    vmx_vmread(VMCS_GUEST_RSP, &guestRSP);
    vmx_vmread(VMCS_GUEST_CS_BASE, &guestCsBase);
    vmx_vmread(VMCS_GUEST_SS_BASE, &guestSsBase);
    vmx_vmread(VMCS_GUEST_IDTR_BASE, &Vcpu->ArchRegs.IdtrBase);
    vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &idtrLimit);
    vmx_vmread(VMCS_GUEST_GDTR_BASE, &Vcpu->ArchRegs.GdtrBase);
    vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &gdtrLimit);


    Vcpu->ArchRegs.IdtrLimit = (WORD)idtrLimit;
    Vcpu->ArchRegs.GdtrLimit = (WORD)gdtrLimit;
    Vcpu->PseudoRegs.CsRip = guestCsBase + guestRIP;
    Vcpu->PseudoRegs.SsRsp = guestSsBase + guestRSP;

    Vcpu->CurrentExitReason &= 0xFFFF;

    // reinsert only after all VCPUs are interruptible
    // in order to avoid timeouts in INIT/SIPI/SIPI sequence
    if (GstIsSafeToInterrupt(HvGetCurrentGuest()))
    {
        //
        // check if any message in ring-buffer should be reinserted
        //
        CommTryReinsertMessages(gHypervisorGlobalData.Comm.SharedMem);

        //
        // check if pending alerts need to be sent
        //
        if (Vcpu->Guest->Intro.IntrospectionEnabled) CommIntroCheckPendingAlerts(Vcpu, FALSE);
    }

    if (!Vcpu->IsBsp)
    {
        // before_first_init -> at_first_init transition
        if ((Vcpu->FirstApInitExitState == BEFORE_FIRST_INIT_EXIT) && (Vcpu->CurrentExitReason == EXIT_REASON_INIT))
        {
            Vcpu->FirstApInitExitState = AT_FIRST_INIT_EXIT;
            IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
            // SHORTCUTTING the first exit (normally the real processor starting by the OS, which is time-critical) to less time in HOST
            HndCallExitHandler(EXIT_REASON_INIT, Vcpu);
            HvPcpuRootMainCycle();
        }
        // else, check for at_first_init -> after_first_init transition
        else if (Vcpu->FirstApInitExitState == AT_FIRST_INIT_EXIT)
        {
            Vcpu->FirstApInitExitState = AFTER_FIRST_INIT_EXIT;

            // and log the time it took to handle the previous exit (which was the time-critical one)
            // important: at a delay of around 500us, the guest BSP starts to abandon its APs!
            // issue a warning if the exit took more than 1/2 of that!
            QWORD exitDurationUs = HvTscTicksDeltaToMicroseconds(Vcpu->PrevInHostTscDuration);
            if (exitDurationUs > 250)
            {
                VCPUWARNING(Vcpu, "FIRST INIT exit took %lldus (and then %lldus were spent in guest), current exit: %s\n",
                    HvTscTicksDeltaToMicroseconds(Vcpu->PrevInHostTscDuration),
                    HvTscTicksDeltaToMicroseconds(Vcpu->PrevInGuestTscDuration),
                    ConvertVmxExitReasonToString(Vcpu->CurrentExitReason));
            }
            else
            {
                VCPULOG(Vcpu, "FIRST INIT stats: host = %lldus guest = %lldus, current exit: %s\n",
                    HvTscTicksDeltaToMicroseconds(Vcpu->PrevInHostTscDuration),
                    HvTscTicksDeltaToMicroseconds(Vcpu->PrevInGuestTscDuration),
                    ConvertVmxExitReasonToString(Vcpu->CurrentExitReason));
            }
        }
    }

    if (Vcpu->ExitCount && Vcpu->PrevExitReason < EXIT_REASON_MAX)
    {
        GUEST* guest = Vcpu->Guest;
        PerfAccountEvent(&guest->ExitStats[Vcpu->PrevExitReason], Vcpu->PrevInHostTscDuration);
        PerfAccountEvent(&guest->GuestStats, Vcpu->PrevInGuestTscDuration);
        PerfAccountEvent(&guest->HostStats, Vcpu->PrevInHostTscDuration);

        PerfAccountEvent(&Vcpu->ExitStats[Vcpu->PrevExitReason], Vcpu->PrevInHostTscDuration);
        PerfAccountEvent(&Vcpu->GuestStats, Vcpu->PrevInGuestTscDuration);
        PerfAccountEvent(&Vcpu->HostStats, Vcpu->PrevInHostTscDuration);
        PerfAccountEvent(&guest->Cr8Stats[Vcpu->PrevCr8], Vcpu->PrevInHostTscDuration);
        Vcpu->PrevCr8 = (Vcpu->ArchRegs.CR8 & 0xF);
    }

    if (CfgDebugTracePeriodicStatsEnabled && Vcpu->FirstApInitExitState != AT_FIRST_INIT_EXIT)
    {
        DumpersDumpPeriodicStats(FALSE, 10 * ONE_SECOND_IN_MICROSECONDS, 60 * ONE_SECOND_IN_MICROSECONDS);
    }

    // Reset the exception injection information.
    VirtExcResetPendingExceptions(Vcpu);
    Vcpu->IntroRequestedTrapInjection = FALSE;

    // Reset the PagingStructureviolation control. We will determine in the EPT violation handler if the violation
    // is on a paging structure or not.
    Vcpu->PagingStructureViolation = FALSE;

    // Reset the intro emulation buffer. It will be reinitialized if needed.
    if (!Vcpu->EmulatingEptViolation)
    {
        Vcpu->IntroEmu.BufferValid = FALSE;
        Vcpu->IntroEmu.BufferSize = 0;
        Vcpu->IntroEmu.BufferGla = 0;
    }

    //
    // Increment counters
    //
    HvInterlockedIncrementI64(&Vcpu->ExitCount);
    Vcpu->PrevExitReason = Vcpu->CurrentExitReason;

    // other stats
    Vcpu->LastExitReasonIndex++;
    Vcpu->LastExitReasons[Vcpu->LastExitReasonIndex % LAST_EXIT_REASONS_COUNT].Reason = (DWORD)Vcpu->CurrentExitReason;
    Vcpu->LastExitReasons[Vcpu->LastExitReasonIndex % LAST_EXIT_REASONS_COUNT].Rip = Vcpu->PseudoRegs.CsRip;
    Vcpu->LastExitReasons[Vcpu->LastExitReasonIndex % LAST_EXIT_REASONS_COUNT].DiffTsc = 0;
    if (Vcpu->UsedExitReasonEntries < LAST_EXIT_REASONS_COUNT)
    {
        Vcpu->UsedExitReasonEntries++;
    }

    //
    // Check/account for automatic #VE memory domain transition occurred during the last guest execution session
    //
    VcpuRefreshActiveMemoryDomain(Vcpu);

    //
    // Update Partition Reference Counter on every exit - better rollover detection
    // Cache the value of the counter
    //      - use it all over the places during one the VMX exit
    //      - avoid locking on accessing the guest->PartitionReferenceTime
    //
    GstEnUpdatePartitionRefCount(Vcpu->Guest, &Vcpu->PartitionReferenceTime);


    //
    // Pre-handling debugging features
    //
    DbgPreHandlerDebugActions(Vcpu);

    // make sure we have serial ports active
    if (CfgDebugOutputSerialEnabled) DbgScheduleDebugger();

    //
    // Adjust the TSC for this VCPU
    //
    {
        QWORD tscOffset = 0;

        vmx_vmread(VMCS_TSC_OFFSET, &tscOffset);

        Vcpu->LinearTsc += Vcpu->LastExitTsc - Vcpu->LastEntryTsc;
        Vcpu->VirtualTsc = Vcpu->LastExitTsc + tscOffset;
    }
    //
    // Init other per-vcpu specific fields
    //
    Vcpu->SafeToReExecute = FALSE;

    if ((Vcpu->EmulatingEptViolation) &&
        (Vcpu->CurrentExitReason != EXIT_REASON_EPT_VIOLATION) &&
        (Vcpu->CurrentExitReason != EXIT_REASON_MONITOR_TRAP_FLAG)
        )
    {
        // If it's anything except for exception and EPT violation, we'll stop handling the instruction re-execution.
        // The idea is that even if we'd re-generate a new exit, we could re-handle it. However, in case of EPT
        // violation, we may be stuck in an infinite loop on accesses crossing the page boundary. Therefore, if
        // another EPT violation is generated while re-executing the instruction, we will handle it normally. If it's
        // needed, we will nest the instruction re-execution, in order to handle this access too.

        status = EmhvEndHandlingEptViolation(Vcpu);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("EmhvEndHandlingEptViolation", status);
            DbgBreak();
        }
    }

    //
    // If resuming from hibernate check if windows has finished restoring hypervisor data
    //
    if (Vcpu->IsBsp && CfgFeaturesHibernatePersistance) HvHibCheckCompleteRestorationOfSavedData(Vcpu);

    //
    // I - handle VM exit
    //
    if (Vcpu->CurrentExitReason <= EXIT_REASON_MAX)
    {
        status = HndCallExitHandler(Vcpu->CurrentExitReason, Vcpu);
        if (status == STATUS_INJECT_GP)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
            status = CX_STATUS_SUCCESS;
        }
        else if (status == STATUS_INJECT_UD)
        {
            VirtExcInjectException(NULL, Vcpu, EXCEPTION_INVALID_OPCODE, 0, 0);
            status = CX_STATUS_SUCCESS;
        }

        if (!SUCCESS(status)) CRITICAL("Handler for exit reason 0x%x failed with status 0x%X\n", Vcpu->CurrentExitReason, status);
        else if (status == STATUS_UPDATE_RIP) _UpdateRip(Vcpu);
    }
    else LOG("Invalid exit reason %d!\n", Vcpu->CurrentExitReason);

    //
    // II - handle single stepping / debugging
    //
    if (Vcpu->DebugContext.SingleStep != 0)
    {
        DWORD intrState = 0, activityState = 0;
        QWORD pendingDbgExcept = 0, temp = 0;

        vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &temp);
        intrState = (DWORD)temp;
        vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, &temp);
        activityState = (DWORD)temp;
        vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pendingDbgExcept);

        if (activityState == VMCS_ACTIVITY_STATE_HLT) DbgBreak();

        // NOTE: we can either set BS in pendingDbgExcept and emulate the instrux (jump over STI),
        // or clear the interruptibility state imposed by STI
        if (((intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_STI) != 0) ||
            ((intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS) != 0))
        {
            intrState = intrState & ~(DWORD)(VMCSFLAG_IRRSTATE_BLOCKING_BY_STI | VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS);
            vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intrState);
        }

        // set TF for single stepping
        Vcpu->ArchRegs.RFLAGS |= RFLAGS_TF;

        // save last CS/RIP values (for tracing)
        for (DWORD i = MAX_CSRIP_TRACE - 1; i >= 1; i--)
        {
            Vcpu->DebugContext.LastCs[i] = Vcpu->DebugContext.LastCs[i - 1];
            Vcpu->DebugContext.LastCsBase[i] = Vcpu->DebugContext.LastCsBase[i - 1];
            Vcpu->DebugContext.LastRip[i] = Vcpu->DebugContext.LastRip[i - 1];
        }

        vmx_vmread(VMCS_GUEST_CS, &temp);
        Vcpu->DebugContext.LastCs[0] = (WORD)temp;
        vmx_vmread(VMCS_GUEST_CS_BASE, &temp);
        Vcpu->DebugContext.LastCsBase[0] = temp;
        vmx_vmread(VMCS_GUEST_RIP, &temp);
        Vcpu->DebugContext.LastRip[0] = temp;
    }

    // if there was a guest update in progress on demand of this VCPU, the exit was handled
    // so we're safe to end by unpausing the guest (relative to current VCPU / finished update)
    status = GstEndUpdateEx(Vcpu->Guest, GST_UPDATE_MODE_PAUSED, GST_UPDATE_REASON_RESUME_EXECUTION, TRUE);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("GstEndUpdateEx", status);

    // invalidate cached VA translations for this VCPU
    status = ChmInvalidateVACache(Vcpu);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("ChmInvalidateVACache", status);

    // ANY CODE AFTER THIS POINT WILL BYPASS THE CACHEMAP!
    DbgPostHandlerDebugActions(Vcpu);

    // make sure we have TF active for most of the time it is possible
    if (Vcpu->DebugContext.SingleStep > 0) Vcpu->ArchRegs.RFLAGS |= RFLAGS_TF;

    if (gNeedToUnload)
    {
        VCPULOG(Vcpu, "*** STATUS_HV_UNLOAD_REQUESTED_INTERNALLY, GIVING IT A TRY,\n*** CLEANUP IS NOT PROPERLY SUPPORTED AFTER HV INITIALIZATION\n");
        CLN_UNLOAD(STATUS_HV_UNLOAD_REQUESTED_INTERNALLY);
    }

    // disable NMI watchdog
    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond) LapicDisablePerfNMI();

    //
    // effectively cycle on the physical CPU until we have a schedulable VCPU to switch to (usually switch back to the
    // VCPU that generated the VM exit we have just handled)
    //
    HvPcpuRootMainCycle();

    // Never returns
}

void
HvVmxLaunchOrResumeFailed(
    _In_ VCPU* Vcpu,
    _In_ QWORD ErrorNumber
    )
{
    NTSTATUS status;

    LOG("Failed launch on VCPU %d\n", Vcpu->LapicId);

    if ((ErrorNumber & 0xffffffff00000000ULL) == 0)
    {
        //
        // launch / resume failed BEFORE validating HOST state
        //

        VCPUERROR(Vcpu, "launch / resume failed (BEFORE HOST), VMX-instrux-error = 0x%08x (%s) \n",
            (DWORD)ErrorNumber, ConvertVmxInstructionErrorToString(ErrorNumber & 0x7FFFFFFF));

        DumpCurrentVmcs(Vcpu->GuestCpuIndex);
        DumpersDumpArchRegs(&Vcpu->ArchRegs);
        DumpersMemDisasm(TRUE, TRUE, Vcpu->GuestIndex, Vcpu->GuestCpuIndex, Vcpu->ArchRegs.RIP, 0x20, DBG_MEMDUMP_NO_OPTIONS, NULL);

        status = CX_STATUS_NOT_SUPPORTED;
    }
    else
    {
        //
        // launch / resume failed AFTER validating HOST state
        //

        DUMP_BEGIN;
        LOG("[PCPU ID %d  VCPU %d.%d] ERROR, VCPU %018p launch / resume failed (AFTER HOST), VMX-exit-reason-error = 0x%08x (%s)\n",
            HvGetCurrentApicId(), Vcpu->GuestIndex, Vcpu->GuestCpuIndex, Vcpu, (DWORD)ErrorNumber, ConvertVmxExitReasonToString((DWORD)(ErrorNumber & 0x7FFFFFFF)));

        EptDumpTranslationInfo(GstGetEptOfPhysicalMemory(Vcpu->Guest), 2 * CX_MEGA);
        DumpCurrentVmcs(Vcpu->GuestCpuIndex);
        DumpersDumpArchRegs(&Vcpu->ArchRegs);
        DumpersMemDisasm(TRUE, TRUE, Vcpu->GuestIndex, Vcpu->GuestCpuIndex, Vcpu->ArchRegs.RIP, 0x20, DBG_MEMDUMP_NO_OPTIONS, NULL);
        // 0x21 - VM-entry failure due to invalid guest state. A VM entry failed one of the checks identified in Section 26.3.1.
        DUMP_END;

        status = CX_STATUS_SUCCESS;
    }

    CLN_UNLOAD(status);
}

/// @}
