/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"
#include "debug/dumpers.h"
#include "memory/heap.h"
#include "debug/stackdump.h"
#include "common/debug/memlog.h"

typedef struct _DUMPERS_GLOBAL_DATA
{
    volatile CX_UINT32 ConcurrentDumps;
    volatile CX_UINT64 PeriodicDumpsTsc;
    volatile CX_UINT64 PeriodicResetTsc;
}DUMPERS_GLOBAL_DATA;
static DUMPERS_GLOBAL_DATA DumpersGlobalData;

/* Static functions */
static CX_STATUS                _EptDumpPageTableEntry(_In_ CX_VOID *Ptr);
static CX_STATUS                _DumpFpuState(_In_ EXTENDED_REGS *FpuState);
static CX_VOID                  _DbgDumpGuestStats(_In_ GUEST *Guest, _In_ CX_BOOL IncludePerVcpuStats);
static CX_VOID                  _DbgResetGuestStats(_In_ GUEST *Guest);
static CX_VOID                  _DbgResetGlobalStats(CX_VOID);
static CX_VOID                  _Usleep64(_In_ CX_UINT32 MicroSecs);
static CX_VOID                  _Beep64(_In_ CX_UINT32 Hertz);
static CX_STATUS                _DbgMemMap(_In_ CX_BOOL IsGuestMem, _In_ CX_BOOL IsVirtualAddress, _In_ CX_UINT32 GuestIndex, _In_ CX_UINT32 VcpuIndex, _In_ CX_SIZE_T Address, _In_ CX_SIZE_T NumberOfBytes, _Out_ CX_VOID ** Hva, _Out_ CX_VOID ** RefHandle);
static CX_STATUS                _DbgMemGetInfo(_In_ CX_VOID *RefHandle, __out_opt DBG_PARAM_MEMTARGET** Target, __out_opt DBG_PARAM_MEMRANGE** Range);
static CX_STATUS                _DbgDisassemble(_In_opt_ char* Message, _In_ DBG_PARAM_TARGETRANGE* Target, _In_ CX_UINT64 Options);
static CX_STATUS                _DbgMemUnmap(_In_ CX_VOID ** Hva, _In_ CX_VOID ** RefHandle);
static CX_STATUS                _DbgDumpMemory(_In_opt_ char* Message, _In_ CX_VOID *Pointer, _In_ CX_SIZE_T Length, _In_ CX_SIZE_T DisplayedAddress, _In_ DUMP_OPTION_FLAGS Options);
static CX_UINT8                 _DbgReadByteDwordAligned(_In_ CX_VOID *Address);
static __forceinline CX_BOOL    _DbgAreOutputOptionsAvailable(CX_VOID);

CX_STATUS
DumpersDumpHeapsInfo(
    CX_VOID
)
{
    HpiDumpHeaps();

    HpDumpHeapAllocStats();

    return CX_STATUS_SUCCESS;
}

CX_STATUS
DumpersMemDump(
    _In_ CX_VOID    *Address,
    _In_ CX_UINT64  NumberOfBytes
)
{
    return DumpersMemDumpEx(
        DBG_MEMDUMP_NO_OPTIONS,
        CX_FALSE,
        CX_TRUE,
        HvGetCurrentVcpu()->GuestIndex,
        HvGetCurrentVcpu()->LapicId,
        (CX_SIZE_T)Address,
        NumberOfBytes,
        CX_NULL
    );
}

CX_VOID
DumpersLogInstruction (
    _In_ VCPU       *Vcpu,
    _In_ CX_UINT16  Cs,
    _In_ CX_UINT64  Rip
)
{
    INSTRUX instr = {0};
    CX_STATUS status;
    char buffer[ND_MIN_BUF_SIZE] = {0};
    CX_UINT32 opIdx = 0;

    status = EmhvDecodeInGuestContext(Vcpu, &instr, 0, 0);
    if (CX_SUCCESS(status))
    {
        CX_UINT64 cr0;

        cr0 = Vcpu->ArchRegs.CR0;

        if (0 == (cr0 & 1))
        {
            status = NdToText(&instr, Vcpu->PseudoRegs.CsIp, ND_MIN_BUF_SIZE, buffer);
        }
        else
        {
            status = NdToText(&instr, Rip, ND_MIN_BUF_SIZE, buffer);
        }
        if (CX_SUCCESS(status))
        {
            if (0 == (cr0 & 1))
            {
                CX_UINT32 i;
                LOGN("--->[CPU %02d/CR0=%p/CR3=%p/RF=%p/SP=%p] 0x%04x:0x%04x[0x%05x]",Vcpu->GuestCpuIndex, Vcpu->ArchRegs.CR0, Vcpu->ArchRegs.CR3, Vcpu->ArchRegs.RFLAGS, Vcpu->ArchRegs.RSP, Cs, Rip, Vcpu->PseudoRegs.CsIp);
                for (i = 0; i < instr.Length; i++)
                {
                    LOGN("%02X ", instr.InstructionBytes[i]);
                }
                for (; i < 8; i++)
                {
                    LOGN("   ");
                }
                LOGN("\t%s\n", buffer);
            }
            else
            {
                LOGN("--->[CPU %02d/CR0=%p/CR3=%p/RF=%p/SP=%p] [%p]\t%s\n",Vcpu->GuestCpuIndex, Vcpu->ArchRegs.CR0, Vcpu->ArchRegs.CR3, Vcpu->ArchRegs.RFLAGS, Vcpu->ArchRegs.RSP, Rip, buffer);
            }

            for (opIdx = 0; opIdx < instr.OperandsCount; opIdx++)
            {
                if ((ND_OP_REG == instr.Operands[opIdx].Type) && (1 == instr.Operands[opIdx].Access.Write) && (ND_REG_GPR == instr.Operands[opIdx].Info.Register.Type))
                {
                    switch (instr.Operands[opIdx].Info.Register.Reg)
                    {
                    case NDR_RAX:
                        LOGN("   *RAX = %p\n", Vcpu->ArchRegs.RAX);
                        break;
                    case NDR_RCX:
                        LOGN("   *RCX = %p\n", Vcpu->ArchRegs.RCX);
                        break;
                    case NDR_RDX:
                        LOGN("   *RDX = %p\n", Vcpu->ArchRegs.RDX);
                        break;
                    case NDR_RBX:
                        LOGN("   *RBX = %p\n", Vcpu->ArchRegs.RBX);
                        break;
                    case NDR_RSP:
                        LOGN("   *RSP = %p\n", Vcpu->ArchRegs.RSP);
                        break;
                    case NDR_RBP:
                        LOGN("   *RBP = %p\n", Vcpu->ArchRegs.RBP);
                        break;
                    case NDR_RSI:
                        LOGN("   *RSI = %p\n", Vcpu->ArchRegs.RSI);
                        break;
                    case NDR_RDI:
                        LOGN("   *RDI = %p\n", Vcpu->ArchRegs.RDI);
                        break;
                    case NDR_R8:
                        LOGN("   *R8 = %p\n", Vcpu->ArchRegs.R8);
                        break;
                    case NDR_R9:
                        LOGN("   *R9 = %p\n", Vcpu->ArchRegs.R9);
                        break;
                    case NDR_R10:
                        LOGN("   *R10 = %p\n", Vcpu->ArchRegs.R10);
                        break;
                    case NDR_R11:
                        LOGN("   *R11 = %p\n", Vcpu->ArchRegs.R11);
                        break;
                    case NDR_R12:
                        LOGN("   *R12 = %p\n", Vcpu->ArchRegs.R12);
                        break;
                    case NDR_R13:
                        LOGN("   *R13 = %p\n", Vcpu->ArchRegs.R13);
                        break;
                    case NDR_R14:
                        LOGN("   *R14 = %p\n", Vcpu->ArchRegs.R14);
                        break;
                    case NDR_R15:
                        LOGN("   *R15 = %p\n", Vcpu->ArchRegs.R15);
                        break;
                    }
                }
            }
        }
    }
    return;
}

CX_STATUS
DumpersDumpHeapByTags(
    CX_VOID
)
{
    CX_STATUS status;
    HTS_VECTOR hts = {0};
    CX_INT32 k;
    CHAR tagText[5] = {0};

    // get statistics
    status = HpGenerateHeapTagStats(-1, &hts);
    if (!CX_SUCCESS(status))
    {
        HvPrint("ERROR: HpGenerateHeapTagStats failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // dump statistics
    HvPrint("dumping HEAP TAG statistics for %d tags   flags 0x%08x\n", hts.TagCount, hts.Flags);
    for (k = 0; k < hts.TagCount; k++)
    {
        // inverse (NT DDK) ordered decoding!
        tagText[3] = (CHAR)((hts.Tag[k].Tag & 0xFF000000) >> 24);
        tagText[2] = (CHAR)((hts.Tag[k].Tag & 0x00FF0000) >> 16);
        tagText[1] = (CHAR)((hts.Tag[k].Tag & 0x0000FF00) >> 8);
        tagText[0] = (CHAR)(hts.Tag[k].Tag & 0x000000FF);
        tagText[4] = 0;

        HvPrint("[%4s] %6d allocs  %10lld bytes   %10lld average / alloc\n",
                tagText, hts.Tag[k].AllocCount, hts.Tag[k].TotalBytes,
                hts.Tag[k].TotalBytes / CX_MAX(hts.Tag[k].AllocCount, 1));
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

CX_STATUS
DumpersGenerateAndSendStackWalkDumpEx(
    _In_ PCPU            *Cpu,
    _In_ HV_TRAP_FRAME  *TrapFrame,
    _In_ CX_UINT64      Flags,
    _In_ CX_BOOL        IsFromNmiHandler,
    _In_ const CHAR     *File,
    _In_ CX_UINT64      Line
)
{
    CX_UINT64 rsp, rip, rdi, tos;
    CX_UINT32 payloadLen, blobLen;
    DVTC_BLOB_STACKWALK head = {0};
    CX_UINT32 cpuBootIndex = 0;

    if (!_DbgAreOutputOptionsAvailable()) return STATUS_OPTION_OR_FLAG_NOT_SUPPORTED;

    typedef CX_STATUS (*PFUNC_Print)(CHAR *, ...);
    PFUNC_Print PrintFunction = IsFromNmiHandler ? HvPrintNoLock : HvPrint;

    if (TrapFrame == CX_NULL)
    {
        rsp = CpuGetRSP();
        rip = CpuGetRIP();
        rdi = CpuGetRDI();
    }
    else
    {
        rsp = TrapFrame->Rsp;
        rip = TrapFrame->Rip;
        rdi = TrapFrame->Rdi;
    }

    //
    // at very early boot, HvGetCurrentCpu() will return CX_NULL (gs still contains a DUMMY_CPU)
    //
    if (Cpu == CX_NULL)
    {
        tos = rsp;

        for (CX_UINT32 currentPage = 0; currentPage < 4 && (MmIsMemReadable(&gHvMm, (CX_VOID *)tos, 1)); currentPage++)
        {
            if (!IsFromNmiHandler) LOG(">> TOS: 0x%08X\n", tos);

            if (CX_PAGE_OFFSET_4K(tos) != 0)
            {
                tos = CX_ROUND_UP(tos, CX_PAGE_SIZE_4K);
            }
            else
            {
                tos += CX_PAGE_SIZE_4K;
            }
        }
    }
    else
    {
        tos = Cpu->TopOfStack;
        cpuBootIndex = Cpu->BootInfoIndex;
    }

    // 1. determine payload
    payloadLen = (CX_UINT32)(tos - rsp);
    payloadLen = CX_MIN(payloadLen, 8 * CX_PAGE_SIZE_4K);
    blobLen = DVTC_BLOB_NEEDED_SIZE_HEXENCODED(DVTC_BLOB_STACKWALK, payloadLen);

    // 2. headers
    head.Header.BlobSize = blobLen;
    head.Header.Type = DVTC_BLOB_TYPE_STACKWALK;
    head.CpuBootIndex = cpuBootIndex;
    head.Rsp = rsp;
    head.Rip = rip;
    head.Rdi = rdi;
    head.Flags = DVTC_FLAG_STACKWALK_BASIC_INFO;
    if (Flags & DBG_CUSTOMTYPE_FLAG_KV) head.Flags |= DVTC_FLAG_STACKWALK_PARAM_INFO;
    if (Flags & DBG_CUSTOMTYPE_FLAG_KVX) head.Flags |= DVTC_FLAG_STACKWALK_LOCAL_INFO;

    head.RawStackLength = payloadLen;

    // 3. Dump the stack (serial, vga)
    if (!IsFromNmiHandler) DUMP_BEGIN;
    {
        if (!IsFromNmiHandler) LOG("Stack blob from [%s:%u]!\n", File, Line);

        PrintFunction(DVTC_BLOB_PREFIX);
        PrintFunction(DVTC_BLOB_MAGIC_HEXENCODED);

        for (CX_UINT32 i = 0; i < sizeof(DVTC_BLOB_STACKWALK); i++)
        {
            PrintFunction("%02X", ((CX_UINT8 *)&head)[i]);
        }

        for (CX_UINT32 i = 0; i < payloadLen; i++)
        {
            PrintFunction("%02X", ((CX_UINT8 *)rsp)[i]);
        }

        PrintFunction(DVTC_BLOB_SUFFIX);
    }
    if (!IsFromNmiHandler) DUMP_END;

    return CX_STATUS_SUCCESS;
}

CX_VOID
DumpersDumpMTRRSate(
    _In_ MTRR_STATE *MtrrState
)
{
    CX_UINT32 i;
    CX_UINT64 rangeBaseAddress, rangeSize, physicalAddressMask;

    physicalAddressMask = CpuGetMaxPhysicalAddress();

    HvPrint("\tMtrrCapMsr: %p, VarCount: %d, FixedSupport: %d, WcCacheSupport: %d, SmmrSupport: %d\n",
            MtrrState->MtrrCapMsr, MtrrState->VarCount, MtrrState->FixedSupport, MtrrState->WcCacheSupport, MtrrState->SmmrSupport);
    HvPrint("\tMtrrDefMsr: %p, DefType: %d, FixedEnabled: %d, Enabled: %d\n",
            MtrrState->MtrrDefMsr, MtrrState->DefType, MtrrState->FixedEnabled, MtrrState->Enabled);

    for (i = 0; i < MAX_FIXED_MTRR;i++)
    {
        HvPrint("\tFixed[%d]: ", i);
        HvPrint("MinAddr: %p, MaxAddr: %p, Type: %p\n", MtrrState->Fixed[i].MinAddr, MtrrState->Fixed[i].MaxAddr, MtrrState->Fixed[i].Type);
    }

    for (i = 0; i < MtrrState->VarCount;i++)
    {
        rangeBaseAddress = (MtrrState->Var[i].BaseMsr & (physicalAddressMask) ) & (VAR_MTRR_BASE_MASK);
        rangeSize = ((~((MtrrState->Var[i].MaskMsr & (physicalAddressMask) ) & VAR_MTRR_MASK_MASK)) & physicalAddressMask ) + 1;
        HvPrint("\tVar[%d]: Range: %p -> %p, Size: %p, BaseMsr: %p (Type: %d, PhysBase: %p), MaskMsr: %p (Valid: %d, PhysMask: %p)\n",
                i, rangeBaseAddress, rangeBaseAddress + rangeSize - 1, rangeSize,
                MtrrState->Var[i].BaseMsr, MtrrState->Var[i].Type, MtrrState->Var[i].PhysBase,
                MtrrState->Var[i].MaskMsr, MtrrState->Var[i].Valid, MtrrState->Var[i].PhysMask);
    }

    HvPrint("\tMaxAddr: %p\n", MtrrState->MaxAddr);

    return;
}

CHAR*
ConvertMsrToString(
    _In_ CX_UINT64 Msr
)
//
// Returns a textual name for the given IA x86 MSR register.
//
// IMPORTANT: some parts of this routine are NOT multi-thread safe (if the MSR is an unknown MSR or an indexed one).
//
// \ret Pointer to the MSR's name as a static or global text.
//
{
    static char unknown[100] = {0};

    switch (Msr)
    {
    case MSR_IA32_FEATURE_CONTROL:
        return "MSR_IA32_FEATURE_CONTROL";
    case MSR_IA32_DEBUGCTL:
        return "MSR_IA32_DEBUGCTL";
    case MSR_IA32_SYSENTER_CS:
        return "MSR_IA32_SYSENTER_CS";
    case MSR_IA32_SYSENTER_RSP:
        return "MSR_IA32_SYSENTER_RSP";
    case MSR_IA32_SYSENTER_RIP:
        return "MSR_IA32_SYSENTER_RIP";
    case MSR_IA32_PERF_GLOBAL_CTRL:
        return "MSR_IA32_PERF_GLOBAL_CTRL";
    case MSR_IA32_PAT:
        return "MSR_IA32_PAT";
    case MSR_IA32_EFER:
        return "MSR_IA32_EFER";
    case MSR_IA32_STAR:
        return "MSR_IA32_STAR";
    case MSR_IA32_LSTAR:
        return "MSR_IA32_LSTAR";
    case MSR_IA32_CSTAR:
        return "MSR_IA32_CSTAR";
    case MSR_IA32_FMASK:
        return "MSR_IA32_FMASK";
    case MSR_IA32_MTRRCAP:
        return "MSR_IA32_MTRRCAP";
    case MSR_IA32_MTRR_PHYSBASE0:
        return "MSR_IA32_MTRR_PHYSBASE0";
    case MSR_IA32_MTRR_PHYSMASK0:
        return "MSR_IA32_MTRR_PHYSMASK0";
    case MSR_IA32_MTRR_DEF_TYPE:
        return "MSR_IA32_MTRR_DEF_TYPE";
    case MSR_IA32_MTRR_FIX64K_00000:
        return "MSR_IA32_MTRR_FIX64K_00000";
    case MSR_IA32_MTRR_FIX16K_80000:
        return "MSR_IA32_MTRR_FIX16K_80000";
    case MSR_IA32_MTRR_FIX16K_A0000:
        return "MSR_IA32_MTRR_FIX16K_A0000";
    case MSR_IA32_MTRR_FIX4K_C0000:
        return "MSR_IA32_MTRR_FIX4K_C0000";
    case MSR_IA32_MTRR_FIX4K_C8000:
        return "MSR_IA32_MTRR_FIX4K_C8000";
    case MSR_IA32_MTRR_FIX4K_D0000:
        return "MSR_IA32_MTRR_FIX4K_D0000";
    case MSR_IA32_MTRR_FIX4K_D8000:
        return "MSR_IA32_MTRR_FIX4K_D8000";
    case MSR_IA32_MTRR_FIX4K_E0000:
        return "MSR_IA32_MTRR_FIX4K_E0000";
    case MSR_IA32_MTRR_FIX4K_E8000:
        return "MSR_IA32_MTRR_FIX4K_E8000";
    case MSR_IA32_MTRR_FIX4K_F0000:
        return "MSR_IA32_MTRR_FIX4K_F0000";
    case MSR_IA32_MTRR_FIX4K_F8000:
        return "MSR_IA32_MTRR_FIX4K_F8000";
    case MSR_IA32_FS_BASE:
        return "MSR_IA32_FS_BASE";
    case MSR_IA32_GS_BASE:
        return "MSR_IA32_GS_BASE";
    case MSR_IA32_KERNEL_GS_BASE:
        return "MSR_IA32_KERNEL_GS_BASE";
    case MSR_IA32_TSC:
        return "MSR_IA32_TSC";
    case MSR_IA32_PLATFORM_ID:
        return "MSR_IA32_PLATFORM_ID";
    case MSR_IA32_APIC_BASE:
        return "MSR_IA32_APIC_BASE";
    case MSR_IA32_BIOS_SIGN_ID:
        return "MSR_IA32_BIOS_SIGN_ID";
    case MSR_IA32_PMC0:
        return "MSR_IA32_PMC0";
    case MSR_IA32_PMC1:
        return "MSR_IA32_PMC1";
    case MSR_IA32_PMC2:
        return "MSR_IA32_PMC2";
    case MSR_IA32_PMC3:
        return "MSR_IA32_PMC3";
    case MSR_IA32_PMC4:
        return "MSR_IA32_PMC4";
    case MSR_IA32_PMC5:
        return "MSR_IA32_PMC5";
    case MSR_IA32_PMC6:
        return "MSR_IA32_PMC6";
    case MSR_IA32_PMC7:
        return "MSR_IA32_PMC7";
    case MSR_IA32_MPERF:
        return "MSR_IA32_MPERF";
    case MSR_IA32_APERF:
        return "MSR_IA32_APERF";
    case MSR_IA32_MCG_CAP:
        return "MSR_IA32_MCG_CAP";
    case MSR_IA32_MCG_STATUS:
        return "MSR_IA32_MCG_STATUS";
    case MSR_IA32_PERFEVTSEL0:
        return "MSR_IA32_PERFEVTSEL0";
    case MSR_IA32_PERFEVTSEL1:
        return "MSR_IA32_PERFEVTSEL1";
    case MSR_IA32_PERFEVTSEL2:
        return "MSR_IA32_PERFEVTSEL2";
    case MSR_IA32_PERFEVTSEL3:
        return "MSR_IA32_PERFEVTSEL3";
    case MSR_IA32_PERF_STATUS:
        return "MSR_IA32_PERF_STATUS";
    case MSR_IA32_PERF_CTL:
        return "MSR_IA32_PERF_CTL";
    case MSR_IA32_CLOCK_MODULATION:
        return "MSR_IA32_CLOCK_MODULATION";
    case MSR_IA32_THERM_INTERRUPT:
        return "MSR_IA32_THERM_INTERRUPT";
    case MSR_IA32_THERM_STATUS:
        return "MSR_IA32_THERM_STATUS";
    case MSR_IA32_THERM2_CTL:
        return "MSR_IA32_THERM2_CTL";
    case MSR_IA32_MISC_ENABLE:
        return "MSR_IA32_MISC_ENABLE";
    case MSR_IA32_PERF_ENERGY_BIAS:
        return "MSR_IA32_PERF_ENERGY_BIAS";
    case MSR_IA32_FIXED_CTR_CTRL:
        return "MSR_IA32_FIXED_CTR_CTRL";
    case MSR_IA32_TSC_AUX:
        return "MSR_IA32_TSC_AUX";
    case MSR_IA32_PM_ENABLE:
        return "MSR_IA32_PM_ENABLE";
    case MSR_IA32_HWP_CAPABILITIES:
        return "MSR_IA32_HWP_CAPABILITIES";
    case MSR_IA32_HWP_REQUEST_PKG:
        return "MSR_IA32_HWP_REQUEST_PKG";
    case MSR_IA32_HWP_INTERRUPT:
        return "MSR_IA32_HWP_INTERRUPT";
    case MSR_IA32_HWP_REQUEST:
        return "MSR_IA32_HWP_REQUEST";
    case MSR_IA32_HWP_PECI_REQUEST_INFO:
        return "MSR_IA32_HWP_PECI_REQUEST_INFO";
    case MSR_IA32_HWP_STATUS:
        return "MSR_IA32_HWP_STATUS";
    case MSR_IA32_PPERF:
        return "MSR_IA32_PPERF";

    default:
        // MTRR specific
        if ((Msr >= 0x00000200) && (Msr <= 0x00000249))
        {
            if (0 == (Msr & 0x1))
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_PHYSBASE%lld", (Msr - 0x200) >> 1);
            }
            else
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_PHYSMASK%lld", (Msr - 0x200) >> 1);
            }
            return unknown;
        }
        // MC specific, #1
        else if ((Msr >= 0x00000280) && (Msr <= 0x00000295))
        {
            snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_MC%lld_CTL2", (Msr - 0x280));
            return unknown;
        }
        // MC specific, #2
        else if ((Msr >= 0x00000400) && (Msr <= 0x00000457))
        {
            if (0 == (Msr & 0x3))
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_MC%lld_CTL", (Msr - 0x400) >> 2);
            }
            else if (1 == (Msr & 0x3))
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_MC%lld_STATUS", (Msr - 0x400) >> 2);
            }
            else if (2 == (Msr & 0x3))
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_MC%lld_ADDR", (Msr - 0x400) >> 2);
            }
            else
            {
                snprintf(unknown, sizeof(unknown)-1, "MSR_IA32_MC%lld_MISC", (Msr - 0x400) >> 2);
            }
            return unknown;
        }
    }

    // handle unknown status messages
    snprintf(unknown, sizeof(unknown)-1, "(unknown MSR 0x%08llx)", Msr);

    return unknown;
}

CHAR*
ConvertVmxExitReasonToString(
    _In_ CX_UINT64 ExitReason
)
//
// Returns a textual name for the given Intel VMX exit reason.
//
// \ret Pointer to the exit reason's name as a static text.
//
{
    switch (ExitReason)
    {
    case EXIT_REASON_EXCEPTION_NMI:
        return "EXIT_REASON_EXCEPTION_NMI";
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        return "EXIT_REASON_EXTERNAL_INTERRUPT";
    case EXIT_REASON_TRIPLE_FAULT:
        return "EXIT_REASON_TRIPLE_FAULT";
    case EXIT_REASON_INIT:
        return "EXIT_REASON_INIT";
    case EXIT_REASON_SIPI:
        return "EXIT_REASON_SIPI";
    case EXIT_REASON_SMI:
        return "EXIT_REASON_SMI";
    case EXIT_REASON_OTHER_SMI:
        return "EXIT_REASON_OTHER_SMI";
    case EXIT_REASON_NMI_WINDOW:
        return "EXIT_REASON_NMI_WINDOW";
    case EXIT_REASON_INTERRUPT_WINDOW:
        return "EXIT_REASON_INTERRUPT_WINDOW";
    case EXIT_REASON_TASK_SWITCH:
        return "EXIT_REASON_TASK_SWITCH";
    case EXIT_REASON_CPUID:
        return "EXIT_REASON_CPUID";
    case EXIT_REASON_GETSEC:
        return "EXIT_REASON_GETSEC";
    case EXIT_REASON_HLT:
        return "EXIT_REASON_HLT";
    case EXIT_REASON_INVLPG:
        return "EXIT_REASON_INVLPG";
    case EXIT_REASON_RDPMC:
        return "EXIT_REASON_RDPMC";
    case EXIT_REASON_RDTSC:
        return "EXIT_REASON_RDTSC";
    case EXIT_REASON_RSM:
        return "EXIT_REASON_RSM";
    case EXIT_REASON_VMCALL:
        return "EXIT_REASON_VMCALL";
    case EXIT_REASON_VMCLEAR:
        return "EXIT_REASON_VMCLEAR";
    case EXIT_REASON_VMLAUNCH:
        return "EXIT_REASON_VMLAUNCH";
    case EXIT_REASON_VMPTRLD:
        return "EXIT_REASON_VMPTRLD";
    case EXIT_REASON_VMPTRST:
        return "EXIT_REASON_VMPTRST";
    case EXIT_REASON_VMREAD:
        return "EXIT_REASON_VMREAD";
    case EXIT_REASON_VMRESUME:
        return "EXIT_REASON_VMRESUME";
    case EXIT_REASON_VMWRITE:
        return "EXIT_REASON_VMWRITE";
    case EXIT_REASON_VMOFF:
        return "EXIT_REASON_VMOFF";
    case EXIT_REASON_VMON:
        return "EXIT_REASON_VMON";
    case EXIT_REASON_CR_ACCESS:
        return "EXIT_REASON_CR_ACCESS";
    case EXIT_REASON_DR_ACCESS:
        return "EXIT_REASON_DR_ACCESS";
    case EXIT_REASON_IO_INSTRUCTION:
        return "EXIT_REASON_IO_INSTRUCTION";
    case EXIT_REASON_MSR_READ:
        return "EXIT_REASON_MSR_READ";
    case EXIT_REASON_MSR_WRITE:
        return "EXIT_REASON_MSR_WRITE";
    case EXIT_REASON_INVALID_GUEST_STATE:
        return "EXIT_REASON_INVALID_GUEST_STATE";
    case EXIT_REASON_MSR_LOADING:
        return "EXIT_REASON_MSR_LOADING";
    case EXIT_REASON_MWAIT_INSTRUCTION:
        return "EXIT_REASON_MWAIT_INSTRUCTION";
    case EXIT_REASON_MONITOR_TRAP_FLAG:
        return "EXIT_REASON_MONITOR_TRAP_FLAG";
    case EXIT_REASON_MONITOR:
        return "EXIT_REASON_MONITOR";
    case EXIT_REASON_PAUSE:
        return "EXIT_REASON_PAUSE";
    case EXIT_REASON_MACHINE_CHECK:
        return "EXIT_REASON_MACHINE_CHECK";
    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        return "EXIT_REASON_TPR_BELOW_THRESHOLD";
    case EXIT_REASON_APIC_ACCESS:
        return "EXIT_REASON_APIC_ACCESS";
    case EXIT_REASON_EPT_VIOLATION:
        return "EXIT_REASON_EPT_VIOLATION";
    case EXIT_REASON_GDTR_IDTR_ACCESS:
        return "EXIT_REASON_GDTR_IDTR_ACCESS";
    case EXIT_REASON_LDTR_TR_ACCESS:
        return "EXIT_REASON_LDTR_TR_ACCESS";
    case EXIT_REASON_EPT_MISCONFIGURATION:
        return "EXIT_REASON_EPT_MISCONFIGURATION";
    case EXIT_REASON_INVEPT:
        return "EXIT_REASON_INVEPT";
    case EXIT_REASON_RDTSCP:
        return "EXIT_REASON_RDTSCP";
    case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        return "EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED";
    case EXIT_REASON_INVVPID:
        return "EXIR_REASON_INVVPID";
    case EXIT_REASON_WBINVD:
        return "EXIT_REASON_WBINVD";
    case EXIT_REASON_XSETBV:
        return "EXIT_REASON_XSETBV";
    case EXIT_REASON_RDRAND:
        return "EXIT_REASON_RDRAND";
    case EXIT_REASON_INVPCID:
        return "EXIT_REASON_INVPCID";
    case EXIT_REASON_VMFUNC:
        return "EXIT_REASON_VMFUNC";
    case EXIT_REASON_VIRTUALIZED_EOI:
        return "EXIT_REASON_VIRTUALIZED_EOI";
    case EXIT_REASON_APIC_WRITE:
        return "EXIT_REASON_APIC_WRITE";
    default:
        return "Unknown exit reason";
    }
}

CHAR*
ConvertVmxInstructionErrorToString(
    _In_ CX_UINT64 ErrorNo
)
//
// Returns a textual description for the given Intel VMX instruction error code.
//
// \ret Pointer to the error described as a static text.
//
{
    switch (ErrorNo)
    {
    case VM_INSTRUCTION_ERROR_VMCALL_IN_ROOT:
        return "VM_INSTRUCTION_ERROR_VMCALL_IN_ROOT";
    case VM_INSTRUCTION_ERROR_VMCLEAR_INV_PA:
        return "VM_INSTRUCTION_ERROR_VMCLEAR_INV_PA";
    case VM_INSTRUCTION_ERROR_VMCLEAR_WITH_VMXON_PTR:
        return "VM_INSTRUCTION_ERROR_VMCLEAR_WITH_VMXON_PTR";
    case VM_INSTRUCTION_ERROR_VMLAUNCH_NON_CLEAR_VMCS:
        return "VM_INSTRUCTION_ERROR_VMLAUNCH_NON_CLEAR_VMCS";
    case VM_INSTRUCTION_ERROR_VMRESUME_NON_LAUNCHED_VMCS:
        return "VM_INSTRUCTION_ERROR_VMRESUME_NON_LAUNCHED_VMCS";
    case VM_INSTRUCTION_ERROR_VMRESUME_AFTER_VMXOFF:
        return "VM_INSTRUCTION_ERROR_VMRESUME_AFTER_VMXOFF";
    case VM_INSTRUCTION_ERROR_VMENTRY_INV_CTRL_FIELDS:
        return "VM_INSTRUCTION_ERROR_VMENTRY_INV_CTRL_FIELDS";
    case VM_INSTRUCTION_ERROR_VMENTRY_INV_HOST_FIELDS:
        return "VM_INSTRUCTION_ERROR_VMENTRY_INV_HOST_FIELDS";
    case VM_INSTRUCTION_ERROR_VMPTRLD_INV_PA:
        return "VM_INSTRUCTION_ERROR_VMPTRLD_INV_PA";
    case VM_INSTRUCTION_ERROR_VMPTRLD_WITH_VMXON_PTR:
        return "VM_INSTRUCTION_ERROR_VMPTRLD_WITH_VMXON_PTR";
    case VM_INSTRUCTION_ERROR_VMPTRLD_INV_VMCS_REV_ID:
        return "VM_INSTRUCTION_ERROR_VMPTRLD_INV_VMCS_REV_ID";
    case VM_INSTRUCTION_ERROR_UNSUPPORTED_VMCS_COMP:
        return "VM_INSTRUCTION_ERROR_UNSUPPORTED_VMCS_COMP";
    case VM_INSTRUCTION_ERROR_VMWRITE_TO_READONLY_VMCS_COMP:
        return "VM_INSTRUCTION_ERROR_VMWRITE_TO_READONLY_VMCS_COMP";
    case VM_INSTRUCTION_ERROR_VMXON_IN_ROOT:
        return "VM_INSTRUCTION_ERROR_VMXON_IN_ROOT";
    case VM_INSTRUCTION_ERROR_VMENTRY_INV_EXECUTIVE_VMCS_PTR:
        return "VM_INSTRUCTION_ERROR_VMENTRY_INV_EXECUTIVE_VMCS_PTR";
    case VM_INSTRUCTION_ERROR_VMENTRY_NON_LAUNCHED_EXECUTIVE_VMCS:
        return "VM_INSTRUCTION_ERROR_VMENTRY_NON_LAUNCHED_EXECUTIVE_VMCS";
    case VM_INSTRUCTION_ERROR_VMENTRY_EXEC_VMCS_PTR_NOT_VMXON_PTR:
        return "VM_INSTRUCTION_ERROR_VMENTRY_EXEC_VMCS_PTR_NOT_VMXON_PTR";
    case VM_INSTRUCTION_ERROR_VMCALL_NON_CLEAR_VMCS:
        return "VM_INSTRUCTION_ERROR_VMCALL_NON_CLEAR_VMCS";
    case VM_INSTRUCTION_ERROR_VMCALL_INV_EXIT_CTRL_FIELDS:
        return "VM_INSTRUCTION_ERROR_VMCALL_INV_EXIT_CTRL_FIELDS";
    case VM_INSTRUCTION_ERROR_VMCALL_INV_MSEG_ID:
        return "VM_INSTRUCTION_ERROR_VMCALL_INV_MSEG_ID";
    case VM_INSTRUCTION_ERROR_VMXOFF_UNDER_DUAL_MODE:
        return "VM_INSTRUCTION_ERROR_VMXOFF_UNDER_DUAL_MODE";
    case VM_INSTRUCTION_ERROR_VMCALL_INV_SMM_FEATURES:
        return "VM_INSTRUCTION_ERROR_VMCALL_INV_SMM_FEATURES";
    case VM_INSTRUCTION_ERROR_VMENTRY_INV_EXEC_CTRL_FIELDS:
        return "VM_INSTRUCTION_ERROR_VMENTRY_INV_EXEC_CTRL_FIELDS";
    case VM_INSTRUCTION_ERROR_VMENTRY_BLOCKED_BY_MOV_SS:
        return "VM_INSTRUCTION_ERROR_VMENTRY_BLOCKED_BY_MOV_SS";
    case VM_INSTRUCTION_ERROR_INV_OP_TO_INVEPT_INVVPID:
        return "VM_INSTRUCTION_ERROR_INV_OP_TO_INVEPT_INVVPID";
    default:
        return "Unknown error.";
    }
}

//
// MORSE beeper
//
CX_VOID
DumpersMorse64(
    _In_ CHAR *Message
)
{
    if (!Message) return;

    while (0 != *Message)
    {
        if (('.' == *Message) || ('*' == *Message))
        {
            _Beep64(900);
            _Usleep64(20000);
            _Beep64(0);
            _Usleep64(60000);
        }
        else if (('-' == *Message) || ('_' == *Message))
        {
            _Beep64(500);
            _Usleep64(60000);
            _Beep64(0);
            _Usleep64(60000);
        }
        else
        {
            // assume space
            _Usleep64(100000);
        }

        Message++;
    }
}

CX_VOID
DumpersDumpControlRegisters(
    _In_ CHAR *Message
)
{
    register CX_UINT64 rsp;
    register CX_UINT64 rip;
    CX_UINT64 temp[2];

    rip = CpuGetRIP();
    rsp = CpuGetRSP();

    HvPrint("dumping CR registers %s\n", Message);
    HvPrint("CR0 = 0x%016zx\n", __readcr0());
    HvPrint("CR3 = 0x%016zx\n", __readcr3());
    HvPrint("CR4 = 0x%016zx\n", __readcr4());
    HvPrint("CR8 = 0x%016zx\n", __readcr8());
    HvPrint("EFER = 0x%016zx\n", __readmsr(0xC0000080));    // IA32_EFER
    HvPrint("RSP = 0x%016zx\n", rsp);
    HvPrint("RIP = 0x%016zx\n", rip);
    _sgdt(&temp);
    HvPrint("GDTR = %018p\n", temp[0]);
    __sidt(&temp);
    HvPrint("IDTR = %018p\n", temp[0]);
}

CX_VOID
DumpersDumpGlobalStats(
    _In_ CX_BOOL IncludePerVcpuStats
)
{
    for (CX_UINT32 i = 0; i < (CX_UINT32)gHypervisorGlobalData.GuestCount; i++)
    {
        _DbgDumpGuestStats(gHypervisorGlobalData.Guest[i], IncludePerVcpuStats);
    }
}

CX_VOID DumpFastAllocatorStats(CX_VOID);

CX_VOID
DumpersDumpPeriodicStats(
    _In_        CX_BOOL     IncludePerVcpuStats,
    _In_opt_    CX_UINT64   DumpPeriodMicroseconds,
    _In_opt_    CX_UINT64   ResetPeriodMicroseconds
)
{
    if (1 == CxInterlockedIncrement32(&DumpersGlobalData.ConcurrentDumps)) // only one cpu will "see" the timout/s
    {
        if (HvTimeout(DumpersGlobalData.PeriodicDumpsTsc))
        {
            if (CfgDebugTracePeriodicStatsPerformance) DumpersDumpGlobalStats(IncludePerVcpuStats);
            DumpersGlobalData.PeriodicDumpsTsc = HvApproximateTimeGuardFast((CX_UINT32)(DumpPeriodMicroseconds ? DumpPeriodMicroseconds : 10 * ONE_SECOND_IN_MICROSECONDS));
            if (CfgDebugTracePeriodicStatsFastAllocators)
            {
                static volatile CX_UINT16 counter = 0; // once in
                static volatile CX_UINT16 divisor = 3; // this many dumps add the fast heap stats to the dump

                counter++;
                if (counter % divisor)
                    DumpFastAllocatorStats();
            }
        }
        if (HvTimeout(DumpersGlobalData.PeriodicResetTsc))
        {
            if (CfgDebugTracePeriodicStatsPerformance) _DbgResetGlobalStats();
            DumpersGlobalData.PeriodicResetTsc = HvApproximateTimeGuardFast((CX_UINT32)(ResetPeriodMicroseconds ? ResetPeriodMicroseconds : 60 * ONE_SECOND_IN_MICROSECONDS));
        }

    }
    CxInterlockedDecrement32(&DumpersGlobalData.ConcurrentDumps);
}

CX_STATUS
DumpersDumpEptPageTablesWalk(
    _In_ VCPU      *Vcpu,
    _In_ CX_UINT64  Gpa
)
{
    EPT_DESCRIPTOR *ept;

    CX_STATUS status = VcpuGetActiveEptDescriptor(Vcpu, &ept);
    if (!CX_SUCCESS(status)) { return status; }

    return EptDumpTranslationInfo(ept, Gpa);
}

CX_STATUS
DumpersDumpGuestFpuState(
    _In_ VCPU *Vcpu
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    return _DumpFpuState((EXTENDED_REGS*)Vcpu->ExtState);
}

CX_STATUS
DumpersDumpHostFpuState(
    CX_VOID
)
{
    EXTENDED_REGS *values = CX_NULL;
    CX_STATUS status = HpAllocWithTagCore(&values, 4096+64, TAG_FPU_DUMP);
    CX_SIZE_T adr = CX_ROUND_UP((CX_SIZE_T)values, 64);

    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        return status;
    }

    CpustateCaptureGuestXState((CX_VOID *)adr);
    status = _DumpFpuState((EXTENDED_REGS*)adr);
    HpFreeAndNullWithTag(&values, TAG_FPU_DUMP);
    return status;
}

CX_STATUS
DumpersMemDisasm(
    _In_ CX_BOOL            IsGuestMem,
    _In_ CX_BOOL            IsVirtualAddress,
    _In_ CX_UINT32          GuestIndex,
    _In_ CX_UINT32          VcpuIndex,
    _In_ CX_SIZE_T          Address,
    _In_ CX_SIZE_T          NumberOfBytes,
    _In_ DISASM_OPTION_FLAGS Options,

    _In_opt_ DBG_PARAM_TARGETRANGE *Target  // In some cases, the memory is mapped, checked and ready to be disassembled.
                                              // One of these cases is when the debugger interpreter does this.
                                              // Therefore, the interpreter prepares the DBG_PARAM_TARGETRANGE structure
                                              // that can be passed to this function.
                                              // In the other cases, the user must set to CX_NULL this parameter.
)
{
    CX_STATUS status;
    CX_VOID *hva = CX_NULL;
    CX_VOID *ref;
    DBG_PARAM_MEMTARGET *target;
    DBG_PARAM_MEMRANGE *range;
    DBG_PARAM_TARGETRANGE targetRange;

    if (Target)
    {
        targetRange = *Target;
        goto _dissasemble;
    }

    status = _DbgMemMap(IsGuestMem, IsVirtualAddress, GuestIndex, VcpuIndex, Address, NumberOfBytes, &hva, &ref);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    status = _DbgMemGetInfo(ref, &target, &range);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    targetRange.Address = (CX_SIZE_T)hva;
    targetRange.Size = NumberOfBytes;
    targetRange.OriginRange = *range;
    targetRange.OriginTarget = *target;

_dissasemble:
    status = _DbgDisassemble(CX_NULL, &targetRange, Options);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    if (hva && Target == CX_NULL) _DbgMemUnmap(&hva, &ref);
    return status;
}

CX_STATUS
DumpersMemDumpEx(
    _In_opt_ DUMP_OPTION_FLAGS  FormatOptions,
    _In_    CX_BOOL             IsGuestMem,
    _In_    CX_BOOL             IsVirtualAddress,
    _In_    CX_UINT32           GuestIndex,
    _In_    CX_UINT32           VcpuIndex,
    _In_    CX_SIZE_T           Address,
    _In_    CX_SIZE_T           NumberOfBytes,

    _In_opt_ DBG_PARAM_TARGETRANGE *Target  // In some cases, the memory is mapped, checked and ready to be dumped.
                                              // One of these cases is when the debugger interpreter does this.
                                              // Therefore, the interpreter prepares the DBG_PARAM_TARGETRANGE structure
                                              // that can be passed to this function.
                                              // In the other cases, the user must set to CX_NULL this parameter.
)
{
    CX_STATUS status;
    CX_VOID *hva = CX_NULL;
    CX_VOID *ref;
    DBG_PARAM_MEMTARGET *target;
    DBG_PARAM_MEMRANGE *range;
    DBG_PARAM_TARGETRANGE targetRange;

    if(Target)
    {
        targetRange = *Target;
        goto _dump;
    }

    status = _DbgMemMap(IsGuestMem, IsVirtualAddress, GuestIndex, VcpuIndex, Address, NumberOfBytes, &hva, &ref);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    status = _DbgMemGetInfo(ref, &target, &range);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    targetRange.Address = (CX_SIZE_T)hva;
    targetRange.Size = NumberOfBytes;
    targetRange.OriginRange = *range;
    targetRange.OriginTarget = *target;

_dump:
    status = _DbgDumpMemory(CX_NULL, (CX_VOID *)targetRange.Address, targetRange.Size, targetRange.OriginRange.Address, FormatOptions);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    if (hva && Target == CX_NULL) _DbgMemUnmap(&hva, &ref);
    return status;
}

CX_BOOL
DumpersTryToDumpEmergencyLogs(
    CX_VOID
)
{
#define CFG_CRASH_ENABLE_LOG                            BIT(0)
#define CFG_CRASH_REBOOT_ON_FAILURE                     BIT(1)

#define CfgIsTraceOnCrashEnabled()                      ((CfgDebugTraceCrashLog & CFG_CRASH_ENABLE_LOG) != 0)
#define CfgIsRebootPreferredOnCrashDumpFailure()        ((CfgDebugTraceCrashLog & CFG_CRASH_REBOOT_ON_FAILURE) != 0)

    static CX_ONCE_INIT0 __dbgEmergencyLogger = CX_INTERLOCKED_ONCE_NOT_STARTED;

    if (CfgIsTraceOnCrashEnabled())
    {
        DumpersGenerateAndSendStackWalkDump(HvGetCurrentCpu(), CX_NULL, 0);

        if (CxInterlockedBeginOnce(&__dbgEmergencyLogger))
        {
            if (0 == gSerialInited)
            {
                UartSerialInit(0);

                LOG("\n\n\n****CRASH****\nInitializing the output to display the HV log\n\n\n");
                DumpersDumpMemoryLog();
            }

            DumpersDumpMemoryLog();

            CxInterlockedEndOnce(&__dbgEmergencyLogger);
        }

        return (CfgIsRebootPreferredOnCrashDumpFailure());
    }

    return CfgIsRebootPreferredOnCrashDumpFailure();
}

CX_STATUS
DumpersDumpMemoryLog(
    CX_VOID
)
{
    extern HV_FEEDBACK_HEADER *gFeedback;

    if (((gSerialInited && gSerialEnabled)) && (gFeedback && gFeedback->Logger.Initialized))
    {
        IoEnableSerialOutput(CX_TRUE);

        LOG("dumping last log\n");

        if (gFeedback->Logger.BufferRollover) IoSerialWrite(gFeedback->Logger.Buffer + gFeedback->Logger.BufferWritePos, gFeedback->Logger.BufferSize - gFeedback->Logger.BufferWritePos);

        IoSerialWrite(gFeedback->Logger.Buffer, gFeedback->Logger.BufferWritePos);

        LOG("DONE dumping last log\n");
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
DumpersDumpArchRegs(
    _In_ ARCH_REGS *ArchRegs
)
{
    if (!ArchRegs)
    {
        HvPrint("ArchRegs == CX_NULL\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }
    HvPrint("ArchRegs\n");
    HvPrint("--> %-18s  <%018p>\n", "RAX", ArchRegs->RAX);
    HvPrint("--> %-18s  <%018p>\n", "RCX", ArchRegs->RCX);
    HvPrint("--> %-18s  <%018p>\n", "RDX", ArchRegs->RDX);
    HvPrint("--> %-18s  <%018p>\n", "RBX", ArchRegs->RBX);
    HvPrint("--> %-18s  <%018p>\n", "RSP", ArchRegs->RSP);
    HvPrint("--> %-18s  <%018p>\n", "RBP", ArchRegs->RBP);
    HvPrint("--> %-18s  <%018p>\n", "RSI", ArchRegs->RSI);
    HvPrint("--> %-18s  <%018p>\n", "RDI", ArchRegs->RDI);
    HvPrint("--> %-18s  <%018p>\n", "R8", ArchRegs->R8);
    HvPrint("--> %-18s  <%018p>\n", "R9", ArchRegs->R9);
    HvPrint("--> %-18s  <%018p>\n", "R10", ArchRegs->R10);
    HvPrint("--> %-18s  <%018p>\n", "R11", ArchRegs->R11);
    HvPrint("--> %-18s  <%018p>\n", "R12", ArchRegs->R12);
    HvPrint("--> %-18s  <%018p>\n", "R13", ArchRegs->R13);
    HvPrint("--> %-18s  <%018p>\n", "R14", ArchRegs->R14);
    HvPrint("--> %-18s  <%018p>\n", "R15", ArchRegs->R15);
    HvPrint("--> %-18s  <%018p>\n", "DR6", ArchRegs->DR6);
    HvPrint("--> %-18s  <%018p>\n", "DR7", ArchRegs->DR7);
    HvPrint("--> %-18s  <%018p>\n", "RFLAGS", ArchRegs->RFLAGS);
    HvPrint("--> %-18s  <%018p>\n", "RIP", ArchRegs->RIP);
    HvPrint("--> %-18s  <%018p>\n", "CR0", ArchRegs->CR0);
    HvPrint("--> %-18s  <%018p>\n", "CR2", ArchRegs->CR2);
    HvPrint("--> %-18s  <%018p>\n", "CR3", ArchRegs->CR3);
    HvPrint("--> %-18s  <%018p>\n", "CR4", ArchRegs->CR4);
    HvPrint("--> %-18s  <%018p>\n", "CR8", ArchRegs->CR8);
    HvPrint("--> %-18s  <%018p>\n", "XCR0", ArchRegs->XCR0);
    HvPrint("--> %-18s  <%018p>\n", "IDTR base", ArchRegs->IdtrBase);
    HvPrint("--> %-18s  <%018p>\n", "IDTR limit", ArchRegs->IdtrLimit);
    HvPrint("--> %-18s  <%018p>\n", "GDTR base", ArchRegs->GdtrBase);
    HvPrint("--> %-18s  <%018p>\n", "GDTR limit", ArchRegs->GdtrLimit);
    HvPrint("--> %-18s  <%018p>\n", "_Reserved6", ArchRegs->_Reserved6);
    HvPrint("--> %-18s  <%018p>\n", "_Reserved7", ArchRegs->_Reserved7);

    return CX_STATUS_SUCCESS;
}

CX_VOID
DumpersResetPeriodicTimers(
    CX_VOID
)
{
    DumpersGlobalData.PeriodicDumpsTsc = 0;
    DumpersGlobalData.PeriodicResetTsc = 0;
    DumpersGlobalData.ConcurrentDumps = 0;
}

extern CX_BOOL gShowSingleStepTrace;
CX_VOID
DumpersConfigureInstructionTracing(
    _In_ VCPU           *Vcpu,
    _In_ TRACING_CONFIG TracingOption
)
{
    CX_UINT64 excBitmap = 0;
    CX_UINT64 currentVmcsPA = 0;
    CX_BOOL targetVcpuNotCurrentVcpu = (Vcpu != HvGetCurrentVcpu() ? CX_TRUE : CX_FALSE);

    if (targetVcpuNotCurrentVcpu)
    {
        // Save current VMCS
        __vmx_vmptrst(&currentVmcsPA);

        // Load wanted VMCS
        __vmx_vmptrld(&Vcpu->VmcsPa);
    }

    /// 0 => disable, 1 => (default) list each instruction, 2 => list and break after each instruction, 3 => silent (vmexits only)
    vmx_vmread(VMCS_EXCEPTION_BITMAP, &excBitmap);

    if (TracingOption != TRACING_CONFIG_DISABLE)
    {
        CX_UINT64 activityState = 0;

        vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, &activityState);
        if (activityState != VMCS_ACTIVITY_STATE_ACTIVE)
        {
            LOG("Sorry guest is not in active state, cannot start tracing, try again later! :(\n");
            return;
        }

        excBitmap |= 2; // intercept #DB - Debug Exceptions
        if (0 != vmx_vmwrite(VMCS_EXCEPTION_BITMAP, excBitmap))
        {
            ERROR("vmx_vmwrite has failed!\n");
        }

        Vcpu->ArchRegs.RFLAGS |= RFLAGS_TF;
        Vcpu->DebugContext.SingleStep = (CX_UINT8)TracingOption;
        gShowSingleStepTrace = (TracingOption != TRACING_CONFIG_SILENT);
    }
    else
    {
        excBitmap &= ~0x2ULL; // stop intercepting #DB - Debug Exceptions
        if (0 != vmx_vmwrite(VMCS_EXCEPTION_BITMAP, excBitmap))
        {
            ERROR("vmx_vmwrite has failed!\n");
        }

        Vcpu->DebugContext.StopTracingAfterExit = CX_TRUE;
    }

    // Restore VMCS
    if (targetVcpuNotCurrentVcpu) __vmx_vmptrld(&currentVmcsPA);

    return;
}

/* Static functions */
static
CX_STATUS
_EptDumpPageTableEntry(
    _In_ CX_VOID *Ptr
)
{
    if (!Ptr) return CX_STATUS_INVALID_PARAMETER_1;
    HvPrint("_EptDumpPageTableEntry [%p]\n", *(CX_UINT64*)Ptr);
    HvPrint("%-48s  0x%X\n", "Ignored[63:52]", BITRANGE_VAL(QWORD_AT(Ptr, 0), 52, (63-52+1)));
    HvPrint("%-48s  0x%X\n", "Target Address", BITRANGE_VAL(QWORD_AT(Ptr, 0), 12, (51-12+1)));
    HvPrint("%-48s  0x%X\n", "Ignored[11:8]", BITRANGE_VAL(QWORD_AT(Ptr, 0), 8, (11-8+1)));
    HvPrint("%-48s  0x%X\n", "MemType", BITRANGE_VAL(QWORD_AT(Ptr, 0), 3, 3));
    HvPrint("%-48s  0x%X\n", "Execute", BITRANGE_VAL(QWORD_AT(Ptr, 0), 2, 1));
    HvPrint("%-48s  0x%X\n", "Write", BITRANGE_VAL(QWORD_AT(Ptr, 0), 1, 1));
    HvPrint("%-48s  0x%X\n", "Read", BITRANGE_VAL(QWORD_AT(Ptr, 0), 0, 1));
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_DumpFpuState(
    _In_ EXTENDED_REGS *FpuState
)

{
    CX_UINT32 i;

    if (!FpuState) return CX_STATUS_INVALID_PARAMETER_1;
    HvPrint("FpuState\n");
    HvPrint("--> %-18s  <%04X>\n", "FCW", FpuState->FCW);
    HvPrint("--> %-18s  <%04X>\n", "FSW", FpuState->FSW);
    HvPrint("--> %-18s  <%02X>\n", "FTW", FpuState->FTW);
    HvPrint("--> %-18s  <%02X>\n", "_Reserved1", FpuState->_Reserved1);
    HvPrint("--> %-18s  <%04X>\n", "FOP", FpuState->FOP);
    HvPrint("--> %-18s  <%018p>\n", "FPUIP", FpuState->FPUIP);
    HvPrint("--> %-18s  <%018p>\n", "FPUDP", FpuState->FPUDP);
    HvPrint("--> %-18s  <%08X>\n", "MXCSR", FpuState->MXCSR);
    HvPrint("--> %-18s  <%08X>\n", "MXCSR_MASK", FpuState->MXCSR_MASK);
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM0", i, FpuState->MM0[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM1", i, FpuState->MM1[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM2", i, FpuState->MM2[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM3", i, FpuState->MM3[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM4", i, FpuState->MM4[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM5", i, FpuState->MM5[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM6", i, FpuState->MM6[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "MM7", i, FpuState->MM7[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM0", i, FpuState->XMM0[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM1", i, FpuState->XMM1[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM2", i, FpuState->XMM2[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM3", i, FpuState->XMM3[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM4", i, FpuState->XMM4[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM5", i, FpuState->XMM5[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM6", i, FpuState->XMM6[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM7", i, FpuState->XMM7[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM8", i, FpuState->XMM8[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM9", i, FpuState->XMM9[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM10", i, FpuState->XMM10[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM11", i, FpuState->XMM11[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM12", i, FpuState->XMM12[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM13", i, FpuState->XMM13[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM14", i, FpuState->XMM14[i]);
    }
    for (i = 0; i < 2; i++)
    {
        HvPrint("--> %-18s[%d]  <%018p>\n", "XMM15", i, FpuState->XMM15[i]);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_VOID
_DbgDumpGuestStats(
    _In_ GUEST *Guest,
    _In_ CX_BOOL IncludePerVcpuStats
)
{
    DUMP_BEGIN;
    PerfDumpHeader("Global statistics");
    PerfDumpSeparator();
    PerfDumpStats(&Guest->GuestStats, "Guest CPU chunks");
    PerfDumpStats(&Guest->HostStats, "Host CPU chunks");
    PerfDumpStats(&Guest->PausingStats[VCPU_PAUSING_STATE_RUNNING], "Guest running");
    PerfDumpStats(&Guest->PausingStats[VCPU_PAUSING_STATE_PAUSED], "Guest paused");
    PerfDumpSeparator();
    char*cr8Text[16] = { "TPR=0", "TPR=1", "TPR=2", "TPR=3", "TPR=4", "TPR=5", "TPR=6", "TPR=7", "TPR=8", "TPR=9", "TPR=A", "TPR=B", "TPR=C", "TPR=D", "TPR=E", "TPR=F" };
    for (CX_UINT32 cr8 = 0; cr8 < 16; cr8++)
    {
        PerfDumpStats(&Guest->Cr8Stats[cr8], cr8Text[cr8]);
    }
    PerfDumpSeparator();
    for (CX_UINT32 reason = 0; reason < EXIT_REASON_MAX; reason++)
    {
        PerfDumpStats(&Guest->ExitStats[reason], ConvertVmxExitReasonToString(reason));
    }

    if (IncludePerVcpuStats)
    {
        PerfDumpSeparator();

        CX_UINT32 i;
        CX_BOOL dataExists;
        PerfDumpTableHeader(Guest->VcpuCount, "VCPU");
        PerfDumpTableSeparator(Guest->VcpuCount);

        for (dataExists = CX_FALSE, i = 0; i < Guest->VcpuCount; i++) if (Guest->Vcpu[i]->GuestStats.TotalEvents) { dataExists = CX_TRUE; break; }
        for (i = 0; dataExists && i < Guest->VcpuCount; i++)
        {
            VCPU *vcpu = Guest->Vcpu[i];
            CX_BOOL isLast = i + 1 >= Guest->VcpuCount;
            PerfDumpColumnStats(i, &vcpu->GuestStats, "Guest", isLast);
        }

        for (dataExists = CX_FALSE, i = 0; i < Guest->VcpuCount; i++) if (Guest->Vcpu[i]->HostStats.TotalEvents) { dataExists = CX_TRUE; break; }
        for (i = 0; dataExists && i < Guest->VcpuCount; i++)
        {
            VCPU *vcpu = Guest->Vcpu[i];
            CX_BOOL isLast = i + 1 >= Guest->VcpuCount;
            PerfDumpColumnStats(i, &vcpu->HostStats, "Host", isLast);
        }

        for (dataExists = CX_FALSE, i = 0; i < Guest->VcpuCount; i++) if (Guest->Vcpu[i]->PausingStats[VCPU_PAUSING_STATE_RUNNING].TotalEvents) { dataExists = CX_TRUE; break; }
        for (i = 0; dataExists && i < Guest->VcpuCount; i++)
        {
            VCPU *vcpu = Guest->Vcpu[i];
            CX_BOOL isLast = i + 1 >= Guest->VcpuCount;
            PerfDumpColumnStats(i, &vcpu->PausingStats[VCPU_PAUSING_STATE_RUNNING], "running", isLast);
        }

        for (dataExists = CX_FALSE, i = 0; i < Guest->VcpuCount; i++) if (Guest->Vcpu[i]->PausingStats[VCPU_PAUSING_STATE_PAUSED].TotalEvents) { dataExists = CX_TRUE; break; }
        for (i = 0; dataExists && i < Guest->VcpuCount; i++)
        {
            VCPU *vcpu = Guest->Vcpu[i];
            CX_BOOL isLast = i + 1 >= Guest->VcpuCount;
            PerfDumpColumnStats(i, &vcpu->PausingStats[VCPU_PAUSING_STATE_PAUSED], "paused", isLast);
        }

        for (CX_UINT32 reason = 0; reason < EXIT_REASON_MAX; reason++)
        {
            for (dataExists = CX_FALSE, i = 0; i < Guest->VcpuCount; i++) if (Guest->Vcpu[i]->ExitStats[reason].TotalEvents) { dataExists = CX_TRUE; break; }
            for (i = 0; dataExists && i < Guest->VcpuCount; i++)
            {
                VCPU *vcpu = Guest->Vcpu[i];
                CX_BOOL isLast = i + 1 >= Guest->VcpuCount;
                PerfDumpColumnStats(i, &vcpu->ExitStats[reason], ConvertVmxExitReasonToString(reason), isLast);
            }
        }
    }

    if (Guest->GuestStats.TotalTsc + Guest->HostStats.TotalTsc) LOGN("CPU overhead %.2f%%\n",
        ((float)(Guest->HostStats.TotalTsc * 100) / (Guest->GuestStats.TotalTsc + Guest->HostStats.TotalTsc)));

    LOGN("\n");
    DUMP_END;
}

static
CX_VOID
_DbgResetGuestStats(
    _In_ GUEST *Guest
)
{
    PerfReset(Guest->ExitStats, EXIT_REASON_MAX);
    PerfReset(Guest->PausingStats, VCPU_PAUSING_STATE_TOTAL_VALUES);
    PerfReset(Guest->Cr8Stats, 16);
    PerfReset(&Guest->GuestStats, 1);
    PerfReset(&Guest->HostStats, 1);
}

static
CX_VOID
_DbgResetGlobalStats(
)
{
    for (CX_UINT32 i = 0; i < (CX_UINT32)gHypervisorGlobalData.GuestCount; i++)
    {
        _DbgResetGuestStats(gHypervisorGlobalData.Guest[i]);
    }
}

static
CX_VOID
_Usleep64(
    _In_ CX_UINT32 MicroSecs
)
{
    while (MicroSecs > 0)
    {
        __outbyte(0x80, 0);     // approx 1 us, using DMA controller
                                ///__outbyte(0xBDBF, 0);
                                ///__outbyte(0xBDBF, 0);
        MicroSecs--;
    }
}

static
CX_VOID
_Beep64(
    _In_ CX_UINT32 Hertz
)
{
    CX_UINT16 div;
    CX_UINT8 cl;

    if (0 == Hertz)
    {
        cl = 0;
    }
    else
    {
        div = (CX_UINT16)(1193181 / Hertz);

        // reprogramm PIT
        __outbyte(0x43, 0x46);      // ctr 2, squarewave, load, binary
        __outbyte(0x42, (CX_UINT8)(div & 0x00FF));          // LSB of counter
        __outbyte(0x42, (CX_UINT8)((div & 0xFF00) >> 8));   // MSB of counter

        cl = 3;
    }

    // keyboard controller
    __inbyte(0x61);                 // dummy read of System Control Port B
    __outbyte(0x61, cl);            // enable timer 2 output to speaker
}

static
CX_STATUS
_DbgMemMap(
    _In_ CX_BOOL IsGuestMem,
    _In_ CX_BOOL IsVirtualAddress,
    _In_ CX_UINT32 GuestIndex,
    _In_ CX_UINT32 VcpuIndex,
    _In_ CX_SIZE_T Address,
    _In_ CX_SIZE_T NumberOfBytes,
    _Out_ CX_VOID **Hva,
    _Out_ CX_VOID **RefHandle    // you need to forward this pointer to _DbgMemUnmap
)
//
// Map to HV VA some physical host/guest or virtual guest memory
// DON'T ABUSE this function (debug only), it assumes we have heap support set up and uses uncacheable memory
//
{
    CX_STATUS status;
    DBG_PARAM_MEMTARGET *target;
    DBG_PARAM_MEMRANGE *range;
    CX_VOID *ptr;
    CX_UINT8 *buffer;

    ptr = CX_NULL;
    buffer = CX_NULL;

    status = HpAllocWithTagCore(&buffer, sizeof(DBG_PARAM_MEMTARGET)+sizeof(DBG_PARAM_MEMRANGE),TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    target = (DBG_PARAM_MEMTARGET*) buffer;
    range = (DBG_PARAM_MEMRANGE*) (((CX_UINT8 *)buffer) + sizeof(DBG_PARAM_MEMTARGET));
    target->IsHostNotGuest = !IsGuestMem;
    target->IsPhysicalNotVirtual = !IsVirtualAddress;
    if (IsGuestMem)
    {
        target->VcpuTarget.GuestIndex = GuestIndex;
        target->VcpuTarget.VcpuIndex = VcpuIndex;
        target->VcpuTarget.Vcpu = gHypervisorGlobalData.Guest[GuestIndex]->Vcpu[VcpuIndex];
    }
    else
    {
        target->VcpuTarget.VcpuIndex = VcpuIndex;
        target->VcpuTarget.Vcpu = gHypervisorGlobalData.Guest[0]->Vcpu[VcpuIndex];
    }
    range->Address = Address;
    range->Size = NumberOfBytes;

    status = InterpreterMapAlienSpace(target, range, &ptr);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    if (!CX_SUCCESS(status))
    {
        if (buffer) HpFreeAndNullWithTag(&buffer, TAG_DBG);
    }
    if (RefHandle) *RefHandle = buffer;
    if (Hva) *Hva = ptr;
    return status;
}

static
CX_STATUS
_DbgMemGetInfo(
    _In_ CX_VOID *RefHandle,                      // obtained with DbgMapMemory
    __out_opt DBG_PARAM_MEMTARGET **Target,       // automatically freed when DbgUnmapMemory is called
    __out_opt DBG_PARAM_MEMRANGE **Range          // automatically freed when DbgUnmapMemory is called
)
//
// The returned structures are automatically freed when _DbgMemUnmap is called
//
{
    if (!RefHandle) return CX_STATUS_INVALID_PARAMETER_1;
    if (Target) *Target = (DBG_PARAM_MEMTARGET *)(RefHandle);
    if (Range) *Range = (DBG_PARAM_MEMRANGE *)(((CX_UINT8 *)(RefHandle)) + sizeof(DBG_PARAM_MEMTARGET));

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_DbgDisassemble(
    _In_opt_ char *Message,
    _In_ DBG_PARAM_TARGETRANGE *Target,
    _In_ CX_UINT64 Options
)
//
// Validate and disassemble a given memory range
//
{
    CX_STATUS status;
    INSTRUX instruxStructure = {0};
    CX_BOOL failed;
    CX_UINT8 codeType, dataType;
    CX_SIZE_T rip, off;
    CX_UINT32 i;
    char dis[ND_MIN_BUF_SIZE] = {0};

    DUMP_BEGIN;
    // check the target variable
    if (!MmIsMemReadable(&gHvMm, Target, sizeof(DBG_PARAM_TARGETRANGE)))
    {
        LOG("Invalid DBG_PARAM_TARGETRANGE specified\n");
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto cleanup;
    }

    // (double)check the read access to the memory range
    if (!MmIsMemReadable(&gHvMm, (CX_VOID *)Target->Address, Target->Size))
    {
        LOGN("Disassembly failed, bad memory in specified range (0x%X bytes from address %p)\n", Target->Size, Target->Address);
        status = CX_STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    if (Message) LOGN("%s\n", Message);

    codeType = dataType = ND_CODE_64;

    // process options
    if (Options == DBG_DISASM_16)
    {
        codeType = dataType = ND_CODE_16;
    }
    else if (Options == DBG_DISASM_32)
    {
        codeType = dataType = ND_CODE_32;
    }
    else if (Options == DBG_DISASM_64)
    {
        codeType = dataType = ND_CODE_64;
    }
    else
    {
        // get default options if none were given
        if (0 == Options)
        {
            //case 1: this memory is coming from a guest
            if (!Target->OriginTarget.IsHostNotGuest)
            {
                CX_UINT32 guest = (CX_UINT32)Target->OriginTarget.VcpuTarget.GuestIndex;
                CX_UINT32 vcpu = (CX_UINT32)Target->OriginTarget.VcpuTarget.VcpuIndex;
                if (0 != (gHypervisorGlobalData.Guest[guest]->Vcpu[vcpu]->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
                {
                    codeType = dataType = ND_CODE_64;
                }
                else if (gHypervisorGlobalData.Guest[guest]->Vcpu[vcpu]->ReadShadowCR0 & CR0_PE)
                {
                    codeType = dataType = ND_CODE_32;
                }
                else
                {
                    codeType = dataType = ND_CODE_16;
                }
            }
            // HOST code => 64 bits
            else
            {
                codeType = dataType = ND_CODE_64;
            }
        }
    }
    rip = 0;
    off = Target->Address & 0xFFF;
    if (Target->OriginRange.UnspecifiedSize != 0) Target->Size = 1;

    while (rip < Target->Size)
    {
        failed = CX_FALSE;
        if (
            (!Target->OriginTarget.IsHostNotGuest) &&
            (Target->OriginTarget.VcpuTarget.Vcpu) &&
            (Target->OriginTarget.VcpuTarget.Vcpu->PseudoRegs.CsRip == Target->OriginRange.Address + rip)
            )
        {
            // highlight/mark the next instruction that would be executed
            HvPrint("0x%016llx:*", Target->OriginRange.Address + rip);
        }
        else
        {
            HvPrint("0x%016llx: ", Target->OriginRange.Address + rip);
        }

        status = NdDecode(&instruxStructure, (CX_VOID *)((CX_UINT64)Target->Address + rip), codeType, dataType);
        if (!CX_SUCCESS(status))
        {
            failed = CX_TRUE;
            instruxStructure.Length = 1;
        }

        // Print instruction bytes
        for (i = 0; i < instruxStructure.Length; i++)
        {
            HvPrint("%02X ", instruxStructure.InstructionBytes[i]);
        }

        // Print spaces, for nice alignment
        for (; i < 16; i++)
        {
            HvPrint("   ");
        }

        // Convert to text
        if (!failed)
        {
            NdToText(&instruxStructure, Target->OriginRange.Address + rip, sizeof(dis), dis);
            HvPrint("%s\n", dis);
        }
        else
        {
            HvPrint("DB 0x%02x\n", instruxStructure.InstructionBytes[0]);
        }

        rip += instruxStructure.Length;
    }
    status = CX_STATUS_SUCCESS;
cleanup:
    DUMP_END;
    return status;
}

static
CX_STATUS
_DbgMemUnmap(
    _In_ CX_VOID **Hva,            // address in HV to where the memory was mapped
    _In_ CX_VOID **RefHandle       // obtained with _DbgMemMap
)
{
    CX_STATUS status;
    DBG_PARAM_MEMTARGET *target;
    DBG_PARAM_MEMRANGE *range;

    if (!RefHandle) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Hva) return CX_STATUS_INVALID_PARAMETER_2;

    status = _DbgMemGetInfo(RefHandle, &target, &range);
    if (!CX_SUCCESS(status))
    {
        goto cleanup;
    }

    status = InterpreterUnmapAlienSpace(target, Hva);
    HpFreeAndNullWithTag(Hva, TAG_DBG);

    *Hva = CX_NULL;
    *RefHandle = CX_NULL;

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

static
CX_STATUS
_DbgDumpMemory(
    _In_opt_ char *Message,
    _In_ CX_VOID *Pointer,
    _In_ CX_SIZE_T Length,
    _In_ CX_SIZE_T DisplayedAddress,
    _In_ DUMP_OPTION_FLAGS Options
)
//
// Validate and dump a memory range based on DBG_MEMDUMP_* options
//
{
    CX_UINT64 i, j;
    CX_UINT8 *ptr;
    CX_SIZE_T pos;

    CX_UINT8 addressCharacters = 16 + 2;        // 0x + characters to the left of values
    CX_UINT8 separatorCharacters = 3;           // ' - '
    CX_UINT8 charactersPerElement = 2;             // number of characters used for a byte

                                               // configuration
    CX_BOOL printAddress    = (0 == (Options & DBG_MEMDUMP_DISABLE_ADDR));
    CX_BOOL printChars      = (0 == (Options & DBG_MEMDUMP_DISABLE_CHARS));
    CX_BOOL alignAddress    = (0 == (Options & DBG_MEMDUMP_DISABLE_ALIGN));     // align address with XX/? padding
    CX_BOOL shortHex        = (0 != (Options & DBG_MEMDUMP_DISABLE_HEXSPACE));  // no spacing between 0xXX values
    CX_BOOL useNewLines     = (0 == (Options & DBG_MEMDUMP_DISABLE_NEWLINES));  // single line dump
    CX_UINT8 bytesPerLine       = (0 == (Options & DBG_MEMDUMP_WIDE)) ? 16: 32;     // hex characters per line
    CX_BOOL prefixApicId    = (0 != (Options & DBG_MEMDUMP_APICID));
    CX_BOOL fromNmiHandler  = (0 != (Options & DBG_MEMDUMP_FROM_NMI_HANDLER));
    CX_UINT8 bytesPerElement    = 1;
    char *hexFormat         = "%02X ";

    CX_STATUS status;
    CX_UINT32 bufferSize;
    CX_UINT32 separatorPos;
    char *buffer = CX_NULL;

    if (0 != (Options & DBG_MEMDUMP_WORDS))
    {
        bytesPerElement = 2;
        charactersPerElement = 4;
    }
    else if (0 != (Options & DBG_MEMDUMP_DWORDS))
    {
        bytesPerElement = 4;
        charactersPerElement = 8;
    }
    else if (0 != (Options & DBG_MEMDUMP_QWORDS))
    {
        bytesPerElement = 8;
        charactersPerElement = 16;
    }

    if (!printAddress) addressCharacters = 0;

    if (shortHex)
    {
        switch (bytesPerElement)
        {
        case 1: hexFormat = "%02X"; break;
        case 2: hexFormat = "%04X"; break;
        case 4: hexFormat = "%08X"; break;
        case 8: hexFormat = "%016llX"; break;
        }
    }
    else
    {
        switch (bytesPerElement)
        {
        case 1: hexFormat = "%02X "; break;
        case 2: hexFormat = "%04X "; break;
        case 4: hexFormat = "%08X "; break;
        case 8: hexFormat = "%016llX "; break;
        }
        charactersPerElement++;
    }
    bufferSize = addressCharacters + separatorCharacters + charactersPerElement * bytesPerLine + separatorCharacters + bytesPerLine + 1;


    UNREFERENCED_PARAMETER(Options);
    UNREFERENCED_PARAMETER(DisplayedAddress);

    // (double-)check the read access to the memory range
    if (!MmIsMemReadable(&gHvMm, Pointer, Length))
    {
        if (fromNmiHandler)
        {
            NMILOGN("Dump failed, bad memory in specified range (0x%X bytes from address %p)\n", Length, Pointer);
        }
        else
        {
            LOGN("Dump failed, bad memory in specified range (0x%X bytes from address %p)\n", Length, Pointer);
        }

        goto cleanup;
    }

    // prepare a buffer for output
    buffer = CX_NULL;
    status = HpAllocWithTagCore((CX_VOID **)&buffer, bufferSize, TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        if (fromNmiHandler)
        {
            NMILOG("[ERROR]: HpAllocWithTagCore failed, status = 0x%x \n", status);
        }
        else
        {
            LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        }

        goto cleanup;
    }

    if (Message)
    {
        if (prefixApicId)
        {
            if (fromNmiHandler)
            {
                NMILOGN("%d: %s\n", CpuGetOriginalApicId(), Message);
            }
            else
            {
                LOGN("%d: %s\n", CpuGetOriginalApicId(), Message);
            }

        }
        else
        {
            if (fromNmiHandler)
            {
                NMILOGN("%s\n", Message);
            }
            else
            {
                LOGN("%s\n", Message);
            }

        }
    }


    // find out where the ' - ' separator should be
    separatorPos = 0;
    if (printAddress) separatorPos += addressCharacters + separatorCharacters;
    separatorPos += (bytesPerLine * charactersPerElement) / bytesPerElement;


    // prepare for iterating bytes
    ptr = Pointer;
    pos = (CX_SIZE_T)Pointer;
    if (alignAddress) pos -= DisplayedAddress - CX_ROUND_DOWN((CX_SIZE_T)DisplayedAddress, bytesPerLine);

    // generate the output
    j = 0;
    for (i = 0; pos < ((CX_SIZE_T)Pointer + Length);)
    {
        CX_UINT8 current;
        CX_UINT64 currentHex = 0;
        CX_UINT64 currentChar = 0;

        if (printAddress)
        {
            currentHex += addressCharacters + separatorCharacters;
            currentChar += addressCharacters + separatorCharacters;
        }
        currentHex += charactersPerElement * (j / bytesPerElement);
        currentChar += separatorCharacters + ((bytesPerLine * charactersPerElement) / bytesPerElement) + j;

        // prepare the current address
        if ((j == 0) && (printAddress))
        {
            snprintf(buffer, CX_MIN(22, addressCharacters + separatorCharacters + 1), "%018zx : ", DisplayedAddress + (pos - (CX_SIZE_T)Pointer));
        }

        // consume the current byte
        if (printChars)
        {
            if (pos < (CX_SIZE_T)Pointer)
            {
                snprintf(buffer + currentChar, CX_MIN(2, bufferSize - currentChar), "?");
            }
            else
            {
                current = _DbgReadByteDwordAligned((CX_VOID *)pos);
                if (!((current>=32) && (current < 128)))
                {
                    current = '.';
                }
                snprintf(buffer + currentChar, CX_MIN(2, bufferSize - currentChar), "%c", current);
            }
        }
        if ((pos < (CX_SIZE_T)Pointer) || (pos + bytesPerElement > ((CX_SIZE_T)Pointer + Length)))
        {
            if (0 == (pos % bytesPerElement))
            {
                switch (bytesPerElement)
                {
                case 1: snprintf(buffer + currentHex, CX_MIN(4, bufferSize - currentHex), (shortHex? "XX":"XX ")); break;
                case 2: snprintf(buffer + currentHex, CX_MIN(8, bufferSize - currentHex), (shortHex? "XXXX":"XXXX ")); break;
                case 4: snprintf(buffer + currentHex, CX_MIN(12, bufferSize - currentHex), (shortHex? "XXXXXXXX":"XXXXXXXX ")); break;
                case 8: snprintf(buffer + currentHex, CX_MIN(20, bufferSize - currentHex), (shortHex? "XXXXXXXXXXXXXXXX":"XXXXXXXXXXXXXXXX ")); break;
                }
            }

        }
        else
        {
            if (0 == (pos % bytesPerElement))
            {
                switch (bytesPerElement)
                {
                case 1: snprintf(buffer + currentHex, CX_MIN(4, bufferSize - currentHex), hexFormat, *(CX_UINT8*)pos); break;
                case 2: snprintf(buffer + currentHex, CX_MIN(8, bufferSize - currentHex), hexFormat, *(CX_UINT16*)pos); break;
                case 4: snprintf(buffer + currentHex, CX_MIN(12, bufferSize - currentHex), hexFormat, *(CX_UINT32*)pos); break;
                case 8: snprintf(buffer + currentHex, CX_MIN(20, bufferSize - currentHex), hexFormat, *(CX_UINT64*)pos); break;
                }
            }
        }

        if (j == bytesPerLine - 1)
        {
            // overwrite the zero after hex bytes and set the separator (without zero terminator)
            if (printChars) memcpy(buffer + separatorPos, " - ", separatorCharacters);
            if (useNewLines)
            {
                if (prefixApicId)
                {
                    if (fromNmiHandler)
                    {
                        NMILOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                    }
                    else
                    {
                        LOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                    }

                }
                else
                {
                    if (fromNmiHandler)
                    {
                        NMILOGN("%s\n", buffer);
                    }
                    else
                    {
                        LOGN("%s\n", buffer);
                    }

                }
            }
            else
            {
                if (prefixApicId)
                {
                    if (fromNmiHandler)
                    {
                        NMILOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                    }
                    else
                    {
                        LOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                    }

                }
                else
                {
                    if (fromNmiHandler)
                    {
                        NMILOGN("%s", buffer);
                    }
                    else
                    {
                        LOGN("%s", buffer);
                    }

                }
            }

            i += bytesPerLine;
            j = 0;
            pos++;
        }
        else
        {
            j++;
            pos++;
        }
    }


    // final buffer flush
    if ((!printChars) && (!alignAddress))
    {
        if (useNewLines)
        {
            if (prefixApicId)
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                }
                else
                {
                    LOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                }

            }
            else
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%s\n", buffer);
                }
                else
                {
                    LOGN("%s\n", buffer);
                }

            }
        }
        else
        {
            if (prefixApicId)
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                }
                else
                {
                    LOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                }

            }
            else
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%s", buffer);
                }
                else
                {
                    LOGN("%s", buffer);
                }

            }
        }
    }
    else if (j != 0)
    {
        for (i = j; i < bytesPerLine; i++, pos++)
        {

            CX_UINT64 currentHex = 0;
            CX_UINT64 currentChar = 0;



            if (printAddress)
            {
                currentHex += addressCharacters + separatorCharacters;
                currentChar += addressCharacters + separatorCharacters;
            }
            currentHex += charactersPerElement * (i / bytesPerElement);
            currentChar += separatorCharacters +((bytesPerLine * charactersPerElement) / bytesPerElement) + i;

            if (0 == (pos % bytesPerElement))
            {
                switch (bytesPerElement)
                {
                case 1: snprintf(buffer + currentHex, CX_MIN(4, bufferSize - currentHex), (shortHex? "XX":"XX ")); break;
                case 2: snprintf(buffer + currentHex, CX_MIN(8, bufferSize - currentHex), (shortHex? "XXXX":"XXXX ")); break;
                case 4: snprintf(buffer + currentHex, CX_MIN(12, bufferSize - currentHex), (shortHex? "XXXXXXXX":"XXXXXXXX ")); break;
                case 8: snprintf(buffer + currentHex, CX_MIN(20, bufferSize - currentHex), (shortHex? "XXXXXXXXXXXXXXXX":"XXXXXXXXXXXXXXXX ")); break;
                }
            }

            if (printChars) snprintf(buffer + currentChar, CX_MIN(2, bufferSize - currentChar), "?");
        }
        // overwrite the zero after hex bytes and set the separator (without zero terminator)
        if (printChars) memcpy(buffer + separatorPos, " - ", separatorCharacters);
        // set the zero terminator -- already present from the last %c
        if (useNewLines)
        {
            if (prefixApicId)
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                }
                else
                {
                    LOGN("%d: %s\n", CpuGetOriginalApicId(), buffer);
                }

            }
            else
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%s\n", buffer);
                }
                else
                {
                    LOGN("%s\n", buffer);
                }

            }
        }
        else
        {
            if (prefixApicId)
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                }
                else
                {
                    LOGN("%d: %s", CpuGetOriginalApicId(), buffer);
                }

            }
            else
            {
                if (fromNmiHandler)
                {
                    NMILOGN("%s", buffer);
                }
                else
                {
                    LOGN("%s", buffer);
                }

            }
        }

        i += bytesPerLine;
        j = 0;
    }

cleanup:
    if (buffer) HpFreeAndNullWithTag(&buffer, TAG_DBG);
    return 0;
}

static
CX_UINT8
_DbgReadByteDwordAligned(
    _In_ CX_VOID *Address
)
//
// memory dumper helper for supporting dev. memory by reading DWORDS and returning bytes
//
{
    CX_UINT32 *aligned;

    // round down the address to be CX_UINT32 aligned
    aligned = (CX_UINT32*)(CX_SIZE_T)((((CX_SIZE_T)Address)>>2)<<2);

    // get a CX_UINT32 and shift it to the right to eliminate 0 to 3 bytes
    return 0xFF & ((*aligned) >> (8*(((CX_SIZE_T)Address) & 3)));
}

static
__forceinline
CX_BOOL
_DbgAreOutputOptionsAvailable(
    CX_VOID
)
{
    return !!CfgDebugOutputSerialEnabled;
}

CX_STATUS
DumpCurrentVmcs(
    _In_ DWORD DisplayedApicId
)
{
    NTSTATUS status;
    QWORD vmcsPtr;
    DWORD apicId;
    QWORD temp;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    vmcsPtr = 0;
    temp = 0;

    apicId = DisplayedApicId;

    DUMP_BEGIN;

    // do we have a currently loaded VMCS?
    __vmx_vmptrst(&vmcsPtr);

    HvPrint("[CPU %d] VMCSPTR = %018p\n", apicId, vmcsPtr);

    if (0xffffffffffffffffULL == vmcsPtr) goto cleanup;

#define VMX_DUMP_WORD(x)                                                                \
    {                                                                                   \
        if (0 == vmx_vmread((x), &temp))                                              \
        {                                                                               \
            temp = temp & 0x0000ffff;                                                   \
            HvPrint("[CPU %d] %-35s = 0x%04x\n", apicId, #x, (DWORD)temp);              \
        }                                                                               \
        else                                                                            \
        {                                                                               \
            HvPrint("[CPU %d] %-35s ==> READ FAILED\n", apicId, #x);                    \
        }                                                                               \
    }

#define VMX_DUMP_DWORD(x)                                                               \
    {                                                                                   \
        if (0 == vmx_vmread((x), &temp))                                              \
        {                                                                               \
            HvPrint("[CPU %d] %-35s = 0x%08x\n", apicId, #x, (DWORD)temp);              \
        }                                                                               \
        else                                                                            \
        {                                                                               \
            HvPrint("[CPU %d] %-35s ==> READ FAILED\n", apicId, #x);                    \
        }                                                                               \
    }

#define VMX_DUMP_QWORD(x)                                                               \
    {                                                                                   \
        if (0 == vmx_vmread((x), &temp))                                              \
        {                                                                               \
            HvPrint("[CPU %d] %-35s = 0x%016zx\n", apicId, #x, temp);                   \
        }                                                                               \
        else                                                                            \
        {                                                                               \
            HvPrint("[CPU %d] %-35s ==> READ FAILED\n", apicId, #x);                    \
        }                                                                               \
    }

    //
    // VMX VMCS offsets, conform Intel Vol 3B, Appendix H
    //
    VMX_DUMP_WORD(VMCS_VPID);
    VMX_DUMP_QWORD(VMCS_EPTP);

    VMX_DUMP_DWORD(VMCS_PIN_BASED_EXEC_CONTROL);
    VMX_DUMP_DWORD(VMCS_PROC_BASED_EXEC_CONTROL);
    VMX_DUMP_DWORD(VMCS_PROC_BASED_EXEC_CONTROL_2);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_CONTROL);
    VMX_DUMP_DWORD(VMCS_VM_ENTRY_CONTROL);
    VMX_DUMP_DWORD(VMCS_EXCEPTION_BITMAP);
    VMX_DUMP_DWORD(VMCS_VMX_PREEMPTION_TIMER);

    VMX_DUMP_DWORD(VMCS_CR3_TARGET_COUNT);
    VMX_DUMP_QWORD(VMCS_CR3_TARGET_VALUE_0);
    VMX_DUMP_QWORD(VMCS_CR3_TARGET_VALUE_1);
    VMX_DUMP_QWORD(VMCS_CR3_TARGET_VALUE_2);
    VMX_DUMP_QWORD(VMCS_CR3_TARGET_VALUE_3);

    VMX_DUMP_QWORD(VMCS_IO_BITMAP_A);
    VMX_DUMP_QWORD(VMCS_IO_BITMAP_B);
    VMX_DUMP_QWORD(VMCS_MSR_BITMAP);

    VMX_DUMP_DWORD(VMCS_VM_EXIT_MSR_STORE_COUNT);
    VMX_DUMP_QWORD(VMCS_VM_EXIT_MSR_STORE_ADDRESS);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_MSR_LOAD_COUNT);
    VMX_DUMP_QWORD(VMCS_VM_EXIT_MSR_LOAD_ADDRESS);
    VMX_DUMP_DWORD(VMCS_VM_ENTRY_MSR_LOAD_COUNT);
    VMX_DUMP_QWORD(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS);

    VMX_DUMP_DWORD(VMCS_VM_ENTRY_EVENT_INJECTION);
    VMX_DUMP_DWORD(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE);
    VMX_DUMP_DWORD(VMCS_VM_ENTRY_INSTRUCTION_LENGTH);

    VMX_DUMP_DWORD(VMCS_ERROR);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_REASON);
    VMX_DUMP_QWORD(VMCS_VM_EXIT_QUALIFICATION);
    VMX_DUMP_QWORD(VMCS_GUEST_PHYSICAL);
    VMX_DUMP_QWORD(VMCS_GUEST_LINEAR);

    VMX_DUMP_DWORD(VMCS_VM_EXIT_INTERRUPTION_INFORMATION);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE);
    VMX_DUMP_DWORD(VMCS_IDT_VECTORING_INFORMATTION);
    VMX_DUMP_DWORD(VMCS_IDT_VECTORING_ERROR_CODE);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_INSTRUCTION_LENGTH);
    VMX_DUMP_DWORD(VMCS_VM_EXIT_INSTRUCTION_INFORMATION);

    VMX_DUMP_QWORD(VMCS_VIRTUAL_APIC_ADDR);
    VMX_DUMP_QWORD(VMCS_APIC_ACCESS_ADDR);
    VMX_DUMP_DWORD(VMCS_TPR_THRESHOLD);

    //
    // guest related
    //
    VMX_DUMP_QWORD(VMCS_GUEST_CR0);
    VMX_DUMP_QWORD(VMCS_GUEST_CR3);
    VMX_DUMP_QWORD(VMCS_GUEST_CR4);
    VMX_DUMP_QWORD(VMCS_GUEST_DR7);
    VMX_DUMP_QWORD(VMCS_GUEST_RSP);
    VMX_DUMP_QWORD(VMCS_GUEST_RIP);
    VMX_DUMP_QWORD(VMCS_GUEST_RFLAGS);

    VMX_DUMP_WORD(VMCS_GUEST_CS);
    VMX_DUMP_QWORD(VMCS_GUEST_CS_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_CS_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_CS_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_SS);
    VMX_DUMP_QWORD(VMCS_GUEST_SS_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_SS_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_SS_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_DS);
    VMX_DUMP_QWORD(VMCS_GUEST_DS_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_DS_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_DS_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_ES);
    VMX_DUMP_QWORD(VMCS_GUEST_ES_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_ES_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_ES_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_FS);
    VMX_DUMP_QWORD(VMCS_GUEST_FS_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_FS_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_FS_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_GS);
    VMX_DUMP_QWORD(VMCS_GUEST_GS_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_GS_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_GS_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_TR);
    VMX_DUMP_QWORD(VMCS_GUEST_TR_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_TR_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_TR_ACCESS_RIGHTS);

    VMX_DUMP_WORD(VMCS_GUEST_LDTR);
    VMX_DUMP_QWORD(VMCS_GUEST_LDTR_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_LDTR_LIMIT);
    VMX_DUMP_DWORD(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    VMX_DUMP_QWORD(VMCS_GUEST_GDTR_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_GDTR_LIMIT);

    VMX_DUMP_QWORD(VMCS_GUEST_IDTR_BASE);
    VMX_DUMP_DWORD(VMCS_GUEST_IDTR_LIMIT);

    VMX_DUMP_QWORD(VMCS_GUEST_IA32_DEBUGCTL);
    VMX_DUMP_DWORD(VMCS_GUEST_IA32_SYSENTER_CS);
    VMX_DUMP_QWORD(VMCS_GUEST_IA32_SYSENTER_RSP);
    VMX_DUMP_QWORD(VMCS_GUEST_IA32_SYSENTER_RIP);
    VMX_DUMP_QWORD(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
    VMX_DUMP_QWORD(VMCS_GUEST_IA32_PAT);
    VMX_DUMP_QWORD(VMCS_GUEST_IA32_EFER);
    VMX_DUMP_DWORD(VMCS_GUEST_SMBASE);
    VMX_DUMP_QWORD(VMCS_GUEST_PDPTE0);
    VMX_DUMP_QWORD(VMCS_GUEST_PDPTE1);
    VMX_DUMP_QWORD(VMCS_GUEST_PDPTE2);
    VMX_DUMP_QWORD(VMCS_GUEST_PDPTE3);

    VMX_DUMP_QWORD(VMCS_GUEST_LINK_POINTER);
    VMX_DUMP_QWORD(VMCS_GUEST_ACTIVITY_STATE);
    VMX_DUMP_QWORD(VMCS_GUEST_INTERRUPTIBILITY_STATE);
    VMX_DUMP_QWORD(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);

    VMX_DUMP_QWORD(VMCS_GUEST_CR0_MASK);
    VMX_DUMP_QWORD(VMCS_GUEST_CR0_READ_SHADOW);
    VMX_DUMP_QWORD(VMCS_GUEST_CR4_MASK);
    VMX_DUMP_QWORD(VMCS_GUEST_CR4_READ_SHADOW);

    //
    // host related
    //
    VMX_DUMP_QWORD(VMCS_HOST_CR0);
    VMX_DUMP_QWORD(VMCS_HOST_CR3);
    VMX_DUMP_QWORD(VMCS_HOST_CR4);
    VMX_DUMP_QWORD(VMCS_HOST_RSP);
    VMX_DUMP_QWORD(VMCS_HOST_RIP);

    VMX_DUMP_DWORD(VMCS_HOST_CS);
    VMX_DUMP_DWORD(VMCS_HOST_SS);
    VMX_DUMP_DWORD(VMCS_HOST_DS);
    VMX_DUMP_DWORD(VMCS_HOST_ES);
    VMX_DUMP_DWORD(VMCS_HOST_FS);
    VMX_DUMP_QWORD(VMCS_HOST_FS_BASE);
    VMX_DUMP_DWORD(VMCS_HOST_GS);
    VMX_DUMP_QWORD(VMCS_HOST_GS_BASE);
    VMX_DUMP_DWORD(VMCS_HOST_TR);
    VMX_DUMP_QWORD(VMCS_HOST_TR_BASE);
    VMX_DUMP_QWORD(VMCS_HOST_GDTR_BASE);
    VMX_DUMP_QWORD(VMCS_HOST_IDTR_BASE);

    VMX_DUMP_DWORD(VMCS_HOST_IA32_SYSENTER_CS);
    VMX_DUMP_QWORD(VMCS_HOST_IA32_SYSENTER_RSP);
    VMX_DUMP_QWORD(VMCS_HOST_IA32_SYSENTER_RIP);
    VMX_DUMP_QWORD(VMCS_HOST_IA32_PERF_GLOBAL_CTRL);
    VMX_DUMP_QWORD(VMCS_HOST_IA32_PAT);
    VMX_DUMP_QWORD(VMCS_HOST_IA32_EFER);

    /// ...

    // everything was done just fine
    status = CX_STATUS_SUCCESS;

cleanup:
    DUMP_END;
    return status;
}