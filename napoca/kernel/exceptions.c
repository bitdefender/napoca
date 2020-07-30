/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file exceptions.c
*   @brief EXCEPTIONS - exception, IDT and interrupt handling
*
*/
#include "napoca.h"
#include "kernel/kernel.h"
#include "boot/boot.h"
#include "common/kernel/cpu_state.h"
#include "boot/vmstate.h"
#include "kernel/interrupt.h"
#include "kernel/newcore.h"
#include "debug/dumpers.h"

///
/// @brief        Function which prints all the useful information from different exceptions, mostly the content of the trap-frame.
///
/// @param[in]    String                           Additional message string to be printed
/// @param[in]    ExceptionCode                    The exception code, to identify the type of the exception
/// @param[in]    TrapFrame                        The Hypervisors TrapFrame
///
static
void
_HvPrintExceptionInfo(
    _In_ CX_INT8 *String,
    _In_ CX_UINT32 ExceptionCode,
    _In_ HV_TRAP_FRAME *TrapFrame
    )
{
    CX_UINT64 efer, cr3, cr4, cr8;

    efer = __readmsr(MSR_IA32_EFER);
    cr3 = __readcr3();
    cr4 = __readcr4();
    cr8 = __readcr8();

    if (EXCEPTION_MACHINE_CHECK == ExceptionCode)
    {
        HvPrintNoLock("[PCPU ID %d] Delivering exception: %d (%s)\n",
            HvGetCurrentApicId(), ExceptionCode, String );
        HvPrintNoLock(
            " *** [PCPU ID %d] EXCEPTION_CODE = %u (%s) *** \nTrapFrame at %018p\n"
            "     -> RAX = 0x%016llx RBX = 0x%016llx\n"
            "     -> RCX = 0x%016llx RDX = 0x%016llx\n"
            "     -> RSI = 0x%016llx RDI = 0x%016llx\n"
            "     -> R8  = 0x%016llx R9  = 0x%016llx\n"
            "     -> R10 = 0x%016llx R11 = 0x%016llx\n"
            "     -> R12 = 0x%016llx R13 = 0x%016llx\n"
            "     -> R14 = 0x%016llx R15 = 0x%016llx\n"
            "     -> RBP = 0x%016llx RSP = 0x%016llx\n"
            "     -> RIP = 0x%016llx\n"
            "     -> ErrorCode = 0x%016llx (isExternal=%d IsIdt=%d IsGdt=%d IsLdt=%d, selector=0x%X)\n"
            "     -> EFLAGS = 0x%08x\n"
            "     -> CS = 0x%04hx SS = 0x%04hx DS = 0x%04hx ES = 0x%04hx FS = 0x%04hx GS = 0x%04hx\n"
            "     -> CR2 = 0x%016llx CR3=0x%016llx\n"
            "     -> CR4 = 0x%016llx EFER = 0x%016llx\n\n",
            HvGetCurrentApicId(),
            ExceptionCode, gExceptionDetails[ExceptionCode].Name,
            TrapFrame,
            TrapFrame->Rax, TrapFrame->Rbx, TrapFrame->Rcx, TrapFrame->Rdx,
            TrapFrame->Rsi, TrapFrame->Rdi, TrapFrame->R8, TrapFrame->R9,
            TrapFrame->R10, TrapFrame->R11, TrapFrame->R12, TrapFrame->R13,
            TrapFrame->R14, TrapFrame->R15, TrapFrame->Rbp, TrapFrame->Rsp,
            TrapFrame->Rip, TrapFrame->ErrorCode,
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->ExternalEvent,
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt,
            (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt) && (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->LdtNotGdt),
            (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt) && (1 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->LdtNotGdt),
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->SelectorIndex,
            TrapFrame->EFlags,
            TrapFrame->SegCs, TrapFrame->SegSs, TrapFrame->SegDs, TrapFrame->SegEs, TrapFrame->SegFs, TrapFrame->SegGs,
            TrapFrame->Cr2, cr3, cr4, efer
            );
    }
    else
    {
        EXCEPTION_LOG("[PCPU ID %d] Delivering exception: %d (%s)\n",
            HvGetCurrentApicId(), ExceptionCode, String );
        EXCEPTION_LOG(
            " *** [PCPU ID %d] EXCEPTION_CODE = %u (%s) *** \nTrapFrame at %018p\n"
            "     -> RAX = 0x%016llx RBX = 0x%016llx\n"
            "     -> RCX = 0x%016llx RDX = 0x%016llx\n"
            "     -> RSI = 0x%016llx RDI = 0x%016llx\n"
            "     -> R8  = 0x%016llx R9  = 0x%016llx\n"
            "     -> R10 = 0x%016llx R11 = 0x%016llx\n"
            "     -> R12 = 0x%016llx R13 = 0x%016llx\n"
            "     -> R14 = 0x%016llx R15 = 0x%016llx\n"
            "     -> RBP = 0x%016llx RSP = 0x%016llx\n"
            "     -> RIP = 0x%016llx\n"
            "     -> ErrorCode = 0x%016llx (isExternal=%d IsIdt=%d IsGdt=%d IsLdt=%d, selector=0x%X)\n"
            "     -> EFLAGS = 0x%08x\n"
            "     -> CS = 0x%04hx SS = 0x%04hx DS = 0x%04hx ES = 0x%04hx FS = 0x%04hx GS = 0x%04hx\n"
            "     -> CR2 = 0x%016llx CR3=0x%016llx\n"
            "     -> CR4 = 0x%016llx EFER = 0x%016llx\n\n",
            HvGetCurrentApicId(),
            ExceptionCode, gExceptionDetails[ExceptionCode].Name,
            TrapFrame,
            TrapFrame->Rax, TrapFrame->Rbx, TrapFrame->Rcx, TrapFrame->Rdx,
            TrapFrame->Rsi, TrapFrame->Rdi, TrapFrame->R8, TrapFrame->R9,
            TrapFrame->R10, TrapFrame->R11, TrapFrame->R12, TrapFrame->R13,
            TrapFrame->R14, TrapFrame->R15, TrapFrame->Rbp, TrapFrame->Rsp,
            TrapFrame->Rip, TrapFrame->ErrorCode,
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->ExternalEvent,
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt,
            (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt) && (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->LdtNotGdt),
            (0 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->IdtNotGdtOrLdt) && (1 == ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->LdtNotGdt),
            ((EXCEPTION_ERROR_CODE*)(&(TrapFrame->ErrorCode)))->SelectorIndex,
            TrapFrame->EFlags,
            TrapFrame->SegCs, TrapFrame->SegSs, TrapFrame->SegDs, TrapFrame->SegEs, TrapFrame->SegFs, TrapFrame->SegGs,
            TrapFrame->Cr2, cr3, cr4, efer
            );
    }


    if (EXCEPTION_MACHINE_CHECK == ExceptionCode)
    {
        HvPrintNoLock("****[CPU %d] MC ***", HvGetCurrentApicId());

        CX_UINT8 nrOfBanks;
        CX_UINT8 i;
        CX_UINT64 t1;
        CX_BOOL found;
        CX_UINT64 ia32McgStatus = __readmsr(MSR_IA32_MCG_STATUS);
        CX_UINT32 k;

        k = 0;
        found = CX_FALSE;

        // clear the mc in progress flag
        __writemsr(MSR_IA32_MCG_STATUS, ia32McgStatus & (~(1ULL << 2)));

        HvPrintNoLock("[CPU %d] -> Machine Check Exception, IA32_MCG_STATUS = 0x%llx\n", HvGetCurrentApicId(), ia32McgStatus);

        // 15.3.2 -> the number of reporting banks is indicated by bits [7:0] of IA32_MCG_CAP MSR
        //        -> the first error reporting register (IA32_MC0_CTL) always starts at address 0x400
        nrOfBanks = (CX_UINT8) (__readmsr(MSR_IA32_MCG_CAP) & 0xFF);

        for (i = 0; i < nrOfBanks; i++)
        {
            // read each bank
            CX_UINT32 bankOffset = i * 4;
            CX_UINT64 ia32McStatus = __readmsr(MSR_IA32_MC0_CTL + bankOffset + IA32_MCG_STATUS_OFFSET);


            if (IA32_MCG_STATUS_VALID & ia32McStatus)
            {
                HvPrintNoLock("[CPU %d] -> msrBank = 0x%x IA32_MC%d_STATUS = 0x%016llx ->> valid\n",
                    HvGetCurrentApicId(), MSR_IA32_MC0_CTL + bankOffset, i, ia32McStatus);

                found = CX_TRUE;

                if (IA32_MCG_STATUS_ADDR & ia32McStatus)
                {
                    HvPrintNoLock("[CPU %d] ->> IA32_MC%d_ADDR = 0x%016llx\n",
                        HvGetCurrentApicId(), i,  __readmsr(MSR_IA32_MC0_CTL + bankOffset + IA32_MCG_ADDRESS_OFFSET));
                }

                if (IA32_MCG_STATUS_MISC & ia32McStatus)
                {
                    HvPrintNoLock("[CPU %d] ->> IA32_MC%d_MISC = 0x%016llx\n",
                        HvGetCurrentApicId(), i, __readmsr(MSR_IA32_MC0_CTL + bankOffset + IA32_MCG_MISC_OFFSET));
                }
            }
        }

        if (!found)
        {
            HvPrintNoLock("[CPU %u] -> No valid MC info found in MC MSRs...\n", HvGetCurrentApicId());
        }

        HvInterlockedBitTestAndSetU64(&gHypervisorGlobalData.Debug.McRecvdAffinity, HvGetCurrentCpuIndex());

        t1 = __rdtsc();
        while (gHypervisorGlobalData.Debug.McRecvdAffinity != gHypervisorGlobalData.Debug.AffinifyMask)
        {
            if (__rdtsc() > (t1 + 2 * gTscSpeed))
            {
                HvPrintNoLock("[CPU %d] -> Still waiting for all cpus to recv MC (McRevcdAffinity = 0x%llx), AffinityMask = 0x%llx)\n",
                    HvGetCurrentApicId(), gHypervisorGlobalData.Debug.McRecvdAffinity, gHypervisorGlobalData.Debug.AffinifyMask);
                t1 = __rdtsc();
                k++;

                if (k == 5)
                {
                    // waited 10 seconds, abort and bugcheck
                    DbgEnterDebugger();
                    {
                        return; // this function isn't expecting DbgEnterDebugger to return back the control
                    }
                }
            }
            CpuYield();
        }

        HvPrintNoLock("[CPU %d] -> All CPUs received the MC...\n", HvGetCurrentApicId());

    }
}


///
/// @brief        On fatal exceptions, this function aborts the current code execution and calls the unload mechanism in order to cleanup the
///               platform and try booting without the Hypervisor.
///
static
void
_HvAbortExecutionFromException(
    void
    )
{
    LOG("*** TRYING TO UNLOAD AFTER HV EXCEPTION ***\n");
    CLN_UNLOAD(CX_STATUS_ABORTED_ON_CRITICAL_FAULT);
};


///
/// @brief        Prepares the unload of the Hypervisor after completing the exception. In case of nested faults, the unload is impossible
///               so instead the Reboot is called.
///
/// @param[in]    ExceptionCode                    The exception code of the current exception (exception type)
/// @param[out]   TrapFrame                        The TrapFrame of the Hypervisor which will be modified to resume
///                                                 after the exception with the unloading process.
///
static
void
_HvPrepareToUnloadFromExceptionHandler(
    _In_ CX_UINT32 ExceptionCode,
    _Inout_ HV_TRAP_FRAME *TrapFrame
    )
//
// Switch to the cleanup routine's RIP (_HvAbortExecutionFromException)
// if we need to forcefully unload the HV
//
{
    UNREFERENCED_PARAMETER(ExceptionCode);

    // check if we're at the very first _HvPrepareToUnloadFromExceptionHandler call on this CPU
    PCPU *cpu = HvGetCurrentCpu();
    if ((cpu != CX_NULL) && CxInterlockedIncrement32(&cpu->CpuIsDead) == 1)
    {
        // yes, this is the first try
        if (CfgFeaturesUnloadOnErrorsEnabled)
        {
            TrapFrame->Rip = (CX_UINT64)&_HvAbortExecutionFromException;

            // maybe we should ALWAYS change stack
            TrapFrame->SegSs = CpuGetSS();
            TrapFrame->Rsp = CpuGetRSP();                           // start with current RSP
            TrapFrame->Rsp = CX_ROUND_DOWN(TrapFrame->Rsp, 16) - 8; // align to 16 and make it odd
        }
        else
        {
            CLN_UNLOAD(CX_STATUS_UNINITIALIZED_STATUS_VALUE);
        }
    }
    else
    {
        // this is a nested fault, trying to unload is hopeless (it would probably just fault again)
        PwrReboot(CX_FALSE, CX_FALSE);
    }

    return;
};



///
/// @brief        Generic exception handler, called from the assembly handlers
///
/// @param[in]    ExceptionCode                    The code of the exception
/// @param[in]    TrapFrame                        The HV_TRAP_FRAME of the current machine state
/// @param[in]    ExceptionExtraInfo               Extra information regarding the exception if available
///
/// @remark       Exposed only to except.nasm
///
void
HvDispatchException(
    _In_ CX_UINT32 ExceptionCode,
    _In_ HV_TRAP_FRAME *TrapFrame,
    _In_ CX_UINT64 ExceptionExtraInfo
    )

{
    IPC_INTERRUPTIBILITY_STATE origInt = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    if ((ExceptionCode == EXCEPTION_INVALID_OPCODE) ||
        (ExceptionCode == EXCEPTION_DEVICE_NOT_AVAIL))
    {
        VCPU* vcpu = HvGetCurrentVcpu();

        if (vcpu == CX_NULL)
        {
            LOG("[ERROR] FATAL: HvGetCurrentVcpu returned CX_NULL!\n");
            goto fatal_exception;
        }

        // CR0_EM is only manipulated in CpuSaveFloatingArea alongside vcpu->RestoreExtState
        // so if CR0_EM is somehow set, vcpu->RestoreExtState should definitely be CX_FALSE,
        // but still, leave the sanity checks
        if (__readcr0() & CR0_EM)
        {
            if (vcpu->RestoreExtState)
            {
                LOG("[CPU %d] ERROR: Extended state already saved!\n",
                    HvGetInitialLocalApicIdFromCpuid());
                goto fatal_exception;
            }

            CpuSaveFloatingArea(vcpu);

            LOG("You shoudn't be seeing this..... w00t! VCPU %d TSC %p\n", vcpu->GuestCpuIndex, vcpu->LastExitTsc);

            goto handled_exception;
        }
        else
        {
            LOG("[CPU %d] %s exception, RIP = %018p\n",
                HvGetCurrentApicId(),
                gExceptionDetails[ExceptionCode].Name,
                TrapFrame->Rip);
            goto fatal_exception;
        }
    }
    else if (EXCEPTION_NMI == ExceptionCode)
    {
        //
        // we received a NMI while in HV
        //
        //
        // NOTE : we cannot use HvTrace & friends because we might have received the NMI
        //        while we were in the middle of printing something, so we had the HvSerialSpinlock acquired
        //
        if (1 == ExceptionExtraInfo)
        {
            HvPrintNoLock("[%u] -> FATAL : Nested NMI\n", HvGetCurrentApicId());
            goto fatal_exception;
        }

        IntNmiHandler();

        // The debugger can send a NMI to a processor
        // for it to print it's stack.
        // This handler take care of this request (if the request exists).
        DbgNmiHandler(TrapFrame);

        goto handled_exception;
    }
    else if (EXCEPTION_MACHINE_CHECK == ExceptionCode)
    {
        CX_UINT64 ia32McgStatus = __readmsr(MSR_IA32_MCG_STATUS);

        // Check if the RIPV-Restart IP valid flag is set; In that case, we can safely resume execution.
        if (ia32McgStatus & 1)
        {
            _HvPrintExceptionInfo("WARNING", ExceptionCode, TrapFrame);
            goto handled_exception;
        }
        else goto fatal_exception;
    }
    else if (EXCEPTION_SIMD_FLOATING_POINT == ExceptionCode)
    {
        if (HvGetCurrentCpu())
        {
            CRITICAL("[PCPU %d] Current Host MXCSR: 0x%08x\n", HvGetCurrentCpu()->Id, _mm_getcsr());
        }

        goto fatal_exception;
    }
    else goto fatal_exception;

handled_exception:
    IpcSetInterruptibilityState(origInt);
    return;

fatal_exception:
    VgaBugcheck();

    VgaSetColor(0x0700);

    _HvPrintExceptionInfo("FATAL", ExceptionCode, TrapFrame);

    DumpersGenerateAndSendStackWalkDump(HvGetCurrentCpu(), TrapFrame, 0);

    _HvPrepareToUnloadFromExceptionHandler(ExceptionCode, TrapFrame);

    return;
}

///
/// @brief        Sets up the interrupt gate inside for and exception handler
///
/// @param[in]    Gate                             The address inside the IDT of the gate
/// @param[in]    Handler                          The address of the handler routine for the exception
/// @param[in]    IstIndex                         The index of the special interrupt stack for this interrupt if there is one
///
static
void
_HvSetIntHandler(
    _In_ INTERRUPT_GATE *Gate,
    _In_ CX_VOID *Handler,
    _In_ CX_UINT8 IstIndex
    )
{
    Gate->Offset_15_0 = ((CX_UINT64)Handler) & 0x000000000000ffffULL;
    Gate->Offset_31_16 = (((CX_UINT64)Handler) & 0x00000000ffff0000ULL) >> 16;
    Gate->Offset_63_32 = (((CX_UINT64)Handler) & 0xffffffff00000000ULL) >> 32;

    Gate->Selector = CODE64_SELECTOR;
    Gate->Reserved2 = 0;
    Gate->Fields = (CX_UINT16) 0x8E00; // P, DPL = 0, Type = 14 (0xE) - Interrupt Gate
    Gate->Fields |= IstIndex;     // set the IST Index if needed
}



CX_STATUS
HvInitGdtTssIdt(
    _In_ PCPU *Cpu
    )
{
    if (!Cpu)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    //
    // 1. prepare GDT descriptors
    //

    GDT *gdt;
    CX_UINT32 gdtSize;

    gdt = (GDT*)Cpu->MemoryResources.IdtGdtTss->Gdt;
    gdtSize = sizeof(GDT);

    memzero(gdt, gdtSize);

    gdt->Null = 0x0000000000000000ULL;
    gdt->Code64 = 0x002f9A000000ffffULL;            // L = 1, D = 0
    gdt->Data64 = 0x00cf92000000ffffULL;
    gdt->Gs64.Raw[0] = 0x00cf92000000ffffULL;
    gdt->Code32Compat = 0x004f9A000000ffffULL;      // L = 0, D = 1

    //
    // 2. prepare TSS segment
    //
    TSS64 *tss;
    CX_UINT32 tssSize;
    SYSTEM_DESCRIPTOR *tssDesc;

    tss = (TSS64*)Cpu->MemoryResources.IdtGdtTss->Tss;
    tssSize = sizeof(TSS64);

    memzero(tss, tssSize);

    tss->IoMapBaseAddr = 0x68;
    tss->RSP0 = 0;      // we do NOT support inter-privilege interrupts since we run only at CPL 0,
                        // so we mark inter-level RSPs as CX_NULL
    tss->RSP1 = 0;
    tss->RSP2 = 0;
    tss->Reserved1 = 0;
    tss->Reserved2 = 0;
    tss->Reserved3 = 0;
    tss->Reserved4 = 0;

    // we set up pristine stacks for the NMI, Double-Fault and Machine Check interrupts

    tss->IST1 = (CX_UINT64)Cpu->MemoryResources.DfStack + NAPOCA_CPU_DBF_STACK_SIZE - 8;
    tss->IST2 = (CX_UINT64)Cpu->MemoryResources.NmiStack + NAPOCA_CPU_NMI_STACK_SIZE - 8;
    tss->IST3 = (CX_UINT64)Cpu->MemoryResources.McStack + NAPOCA_CPU_MC_STACK_SIZE - 8;

    // set the TSS descriptor
    tssDesc = &(gdt->Tss64);

    tssDesc->MustBeZero = 0;
    tssDesc->Limit_15_0 = (CX_UINT16)(sizeof(TSS64) - 1);
    tssDesc->Base_15_0 = (CX_UINT16)(((CX_UINT64)tss) & 0xFFFF);
    tssDesc->Base_23_16 = (CX_UINT8)((((CX_UINT64)tss) >> 16) & 0xFF);
    tssDesc->Base_31_24 = (CX_UINT8)((((CX_UINT64)tss) >> 24) & 0xFF);
    tssDesc->Base_63_32 = (CX_UINT32)((((CX_UINT64)tss) >> 32) & 0xFFFFFFFF);
    tssDesc->Fields = 0x89;     // G = 0, DPL = 0, P = 1, Busy = 0, Type = TSS

    //
    // 3. prepare IDT table
    //
    INTERRUPT_GATE *idt;
    CX_UINT32 idtSize;

    idt = (INTERRUPT_GATE*)Cpu->MemoryResources.IdtGdtTss->Idt;
    idtSize = (256 * sizeof(INTERRUPT_GATE));

    memzero(idt, idtSize);

    HvInitExceptionHandlers(idt, CX_TRUE);

    // everything was done just fine
    return CX_STATUS_SUCCESS;
}



CX_STATUS
HvInitExceptionHandlers(
    _In_ INTERRUPT_GATE *Idt,
    _In_ CX_BOOL AreFinalStacksAvailable
)
{
    // set handlers (EXCEPTION_DIVIDE_ERROR, EXCEPTION_DEBUG, ...)
    _HvSetIntHandler(&Idt[0],  (CX_VOID *)HvHndDivideError, 0);
    _HvSetIntHandler(&Idt[1],  (CX_VOID *)HvHndDebug, 0);
    _HvSetIntHandler(&Idt[2],  (CX_VOID *)HvHndNMI, AreFinalStacksAvailable && NAPOCA_USE_DISTINCT_NMI_STACK ? IST_NMI : 0);
    _HvSetIntHandler(&Idt[3],  (CX_VOID *)HvHndBreakpoint, 0);
    _HvSetIntHandler(&Idt[4],  (CX_VOID *)HvHndOverflow, 0);
    _HvSetIntHandler(&Idt[5],  (CX_VOID *)HvHndBOUND, 0);
    _HvSetIntHandler(&Idt[6],  (CX_VOID *)HvHndInvalidOpcode, 0);
    _HvSetIntHandler(&Idt[7],  (CX_VOID *)HvHndDeviceNotAvailable, 0);
    _HvSetIntHandler(&Idt[8],  (CX_VOID *)HvHndDoubleFault, AreFinalStacksAvailable ? IST_DF : 0);
    _HvSetIntHandler(&Idt[9],  (CX_VOID *)HvHndCoprocessorSegmentOverrun, 0);
    _HvSetIntHandler(&Idt[10], (CX_VOID *)HvHndInvalidTSS, 0);
    _HvSetIntHandler(&Idt[11], (CX_VOID *)HvHndSegmentNotPresent, 0);
    _HvSetIntHandler(&Idt[12], (CX_VOID *)HvHndStackFault, 0);
    _HvSetIntHandler(&Idt[13], (CX_VOID *)HvHndGeneralProtection, 0);
    _HvSetIntHandler(&Idt[14], (CX_VOID *)HvHndPageFault, 0);
    _HvSetIntHandler(&Idt[16], (CX_VOID *)HvHndFPUError, 0);
    _HvSetIntHandler(&Idt[17], (CX_VOID *)HvHndAlignmentCheck, 0);
    _HvSetIntHandler(&Idt[18], (CX_VOID *)HvHndMachineCheck, AreFinalStacksAvailable ? IST_MC : 0);
    _HvSetIntHandler(&Idt[19], (CX_VOID *)HvHndSIMDFloatingPoint, 0);

    return CX_STATUS_SUCCESS;
}


CX_STATUS
HvLoadGdtTssIdtGs(
    _In_ CX_VOID *Gdt,
    _In_ CX_VOID *Tss,
    _In_ CX_VOID *Idt,
    _In_ CX_UINT64 GsBase
    )
{
    LGDT lgdt = {0};
    LIDT lidt = {0};

    if (!Gdt) return CX_STATUS_INVALID_PARAMETER_1;

    if (!Tss) return CX_STATUS_INVALID_PARAMETER_2;

    if (!Idt) return CX_STATUS_INVALID_PARAMETER_3;

    // prepare values for LIDT, LGDT instructions
    lgdt.GdtAddress = (CX_UINT64)Gdt;
    lgdt.Size = sizeof(GDT) - 1;
    lidt.IdtAddress = (CX_UINT64)Idt;
    lidt.Size = (256 * sizeof(INTERRUPT_GATE)) - 1;     // 256 x 16 bytes = 4K, check out "6.14.1 64-Bit Mode IDT" from Intel Vol 3A

    // set GDTR, IDTR, TR
    _lgdt(&lgdt);
    __lidt(&lidt);

    CpuSetTR(TSS64_SELECTOR);

    // force reload hidden part of CS, FS, GS descriptors inside the CPU (SS, DS, ES are NOT used on x64 mode)
    CpuSetCS(CODE64_SELECTOR);
    CpuSetSS(DATA64_SELECTOR);
    CpuSetDS(DATA64_SELECTOR);
    CpuSetES(DATA64_SELECTOR);
    CpuSetFS(NULL_SELECTOR);
    CpuSetGS(GS64_SELECTOR);        // take care, this does NOT load the upper 32 bits (must be written by MSR below)

    // setup GS
    CpuBindStructureToGs((PCPU*)GsBase);

    return CX_STATUS_SUCCESS;
}

CX_VOID
HvSetupSseExceptions(
    CX_VOID
)
{
    CX_UINT32 mxcsr = 0;

    // CRITICAL: set also default host MXCSR
    mxcsr = _mm_getcsr();

    LOG("[PCPU %d] Host mxcsr 0x%08x\n", HvGetInitialLocalApicIdFromCpuid(), mxcsr);


    // All SIMD floating-point exceptions are masked (bits 7 through 12 of the MXCSR register is set to 1).
    mxcsr |= 0x1F80;
    _mm_setcsr(mxcsr);

    LOG("[PCPU %d] Changed host mxcsr 0x%08x\n", HvGetInitialLocalApicIdFromCpuid(), mxcsr);
}