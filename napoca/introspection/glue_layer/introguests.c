/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introcallhv
///@{

/** @file introguests.c
*   @brief INTROGUESTS -  NAPOCA hypervisor glue layer, generic guest and glue related functions
*
*   The implementation.
*/

#include "kernel/kernel.h"
#include "introspection/glue_layer/introguests.h"
#include "guests/intro.h"
#include "communication/comm_guest.h"
#include "kernel/queue_ipc.h"

/// @brief Holds Intro Guest Query information and other context for IPC Callback Context
typedef struct _QUERY_GUEST_INFO_CTX
{
    PVOID GuestHandle;
    DWORD InfoClass;
    PVOID InfoParam;
    PVOID Buffer;
    DWORD BufferLength;

    NTSTATUS ProcessingStatus;
}QUERY_GUEST_INFO_CTX;

///
/// @brief      Static function for the IPC callback sent to CPUs, in order to Query Guest information for the introspection engine.
///
/// Based on the InfoClass value, the functions should get or set different guest attributes on the targeted CPUs, as follows.
/// See IG_QUERY_INFO_CLASS for possible classes of information.
/// Information may be: register status, MSR value, IDT/GDT tables, number of CPUs. The content of the buffer will depend on the
/// info class queried, and it will be:
/// - PINTRO_ARCH_REGS for register status.
/// - PIG_QUERY_MSR    for MSR value.
/// - PQWORD           for IDT base.
/// - PQWORD           for GDT base.
/// - PQWORD           for CPU count.
///
/// @param[in, out]  Context    QUERY_GUEST_INFO_CTX type context information about the query.
/// @param[in]  Reserved        Currently not used additional parameter, conforming PNAPOCA_IPI_HANDLER.
///
/// @returns    CX_STATUS_SUCCESS                 - if the query was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_*     - if parameters from the passed context are invalid.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED - if an unimplemented info class is requested or an un-supported operation
///                                                 takes place (VCPU is not paused and is not safe to execute the requested operation).
/// @returns    CX_STATUS_DATA_OUT_OF_RANGE       - if buffer is bigger than the Extended State area.
/// @returns    CX_STATUS_DATA_BUFFER_TOO_SMALL   - if buffer is too small for the requested information
/// @returns    OTHER                             - other potential internal STATUS error value raised during IPC sending to other CPUs.
static
NTSTATUS
_GuestIntNapQueryGuestInfoHandler(
    _Inout_   QUERY_GUEST_INFO_CTX* Context,
    _In_ PVOID Reserved
);

/// @brief current index of the latest intro alert received (used it to sort the alerts in UM)
static volatile QWORD gIntroAlertCount;

NTSTATUS
GuestIntNapQueryGuestInfo(
    _In_ PVOID GuestHandle,
    _In_ DWORD InfoClass,
    _In_opt_ PVOID InfoParam,
    _When_(InfoClass == IG_QUERY_INFO_CLASS_SET_REGISTERS, _In_reads_bytes_(BufferLength))
    _When_(InfoClass != IG_QUERY_INFO_CLASS_SET_REGISTERS, _Out_writes_bytes_(BufferLength))
    PVOID Buffer,
    _In_ DWORD BufferLength
)
{
    NTSTATUS status;
    GUEST* guest;


    VCPU* targetVcpu = NULL;
    DWORD targetVcpuIndex = 0;

    status = CX_STATUS_SUCCESS;

    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    guest = (GUEST*)GuestHandle;

    if (Buffer == NULL) return CX_STATUS_INVALID_PARAMETER_4;

    switch (InfoClass)
    {
    case IG_QUERY_INFO_CLASS_REGISTER_STATE:
    case IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS:
    case IG_QUERY_INFO_CLASS_READ_MSR:
    case IG_QUERY_INFO_CLASS_IDT:
    case IG_QUERY_INFO_CLASS_GDT:
        targetVcpuIndex = (DWORD)(SIZE_T)InfoParam;
        break;
    case IG_QUERY_INFO_CLASS_CPU_COUNT:
        targetVcpuIndex = HvGetCurrentVcpu()->GuestCpuIndex;
        break;
    case IG_QUERY_INFO_CLASS_SET_REGISTERS:
        targetVcpuIndex = (DWORD)(SIZE_T)InfoParam;
        break;
    case IG_QUERY_INFO_CLASS_TSC_SPEED:
        targetVcpuIndex = HvGetCurrentVcpu()->GuestCpuIndex;
        break;
    case IG_QUERY_INFO_CLASS_CURRENT_TID:
        targetVcpuIndex = HvGetCurrentVcpu()->GuestCpuIndex;
        break;

    case IG_QUERY_INFO_CLASS_CS_TYPE:
    case IG_QUERY_INFO_CLASS_CS_RING:
        targetVcpuIndex = (DWORD)(SIZE_T)InfoParam;
        break;
    case IG_QUERY_INFO_CLASS_SEG_REGISTERS:
        targetVcpuIndex = HvGetCurrentVcpu()->GuestCpuIndex;
        break;
    case IG_QUERY_INFO_CLASS_XSAVE_SIZE:
    case IG_QUERY_INFO_CLASS_XSAVE_AREA:
        targetVcpuIndex = (DWORD)(SIZE_T)InfoParam;
        break;
    case IG_QUERY_INFO_CLASS_EPTP_INDEX:
    case IG_QUERY_INFO_CLASS_MAX_GPFN:
    case IG_QUERY_INFO_CLASS_VE_SUPPORT:
    case IG_QUERY_INFO_CLASS_VMFUNC_SUPPORT:
    case IG_QUERY_INFO_CLASS_SPP_SUPPORT:
    case IG_QUERY_INFO_CLASS_DTR_SUPPORT:
        targetVcpuIndex = HvGetCurrentVcpu()->GuestCpuIndex;
        break;
    case IG_QUERY_INFO_CLASS_SET_XSAVE_AREA:
    case IG_QUERY_INFO_CLASS_GET_XCR0:
        targetVcpuIndex = (DWORD)(SIZE_T)InfoParam;
        break;
    default:
        ERROR("Unknown Info Class %u\n", InfoClass);
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        break;
    }

    if (targetVcpuIndex == IG_CURRENT_VCPU)
    {
        targetVcpu = HvGetCurrentVcpu();
    }
    else if (targetVcpuIndex >= guest->VcpuCount)
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }
    else
    {
        targetVcpu = guest->Vcpu[targetVcpuIndex];
    }

    QUERY_GUEST_INFO_CTX ctx;
    ctx.GuestHandle = GuestHandle;
    ctx.InfoClass = InfoClass;
    ctx.InfoParam = (PVOID)(SSIZE_T)IG_CURRENT_VCPU;
    ctx.Buffer = Buffer;
    ctx.BufferLength = BufferLength;
    ctx.ProcessingStatus = CX_STATUS_SUCCESS;

    IPC_MESSAGE msg = { 0 };
    msg.MessageType = IPC_MESSAGE_TYPE_IPI_HANDLER;
    msg.OperationParam.IpiHandler.CallbackFunction = _GuestIntNapQueryGuestInfoHandler;
    msg.OperationParam.IpiHandler.CallbackContext = &ctx;

    IPC_CPU_DESTINATION dest;
    dest.DestinationMode = IPC_DESTINATION_CPU_POINTER;
    dest.Id.CpuPointer = targetVcpu->AttachedPcpu;

    status = IpcSendCpuMessage(
        &msg,
        dest,
        IPC_PRIORITY_IPI,
        TRUE,                               // do interrupt cpus when possible
        IPC_WAIT_COMPLETION_FORCED,         // wait for confirmation if possible to interrupt
        FALSE);                             // do not drop message

    if (SUCCESS(status)) status = ctx.ProcessingStatus;

    return HV_STATUS_TO_INTRO_STATUS(status);
}

static
NTSTATUS
_GuestIntNapQueryGuestInfoHandler(
    _Inout_   QUERY_GUEST_INFO_CTX* Context,
    _In_ PVOID Reserved
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    GUEST* guest;
    UNREFERENCED_PARAMETER(Reserved);

    PVOID guestHandle = Context->GuestHandle;
    DWORD infoClass = Context->InfoClass;
    PVOID infoParam = Context->InfoParam;
    PVOID buffer = Context->Buffer;
    DWORD bufferLength = Context->BufferLength;

    guest = (GUEST*)guestHandle;

    switch (infoClass)
    {
    case IG_QUERY_INFO_CLASS_REGISTER_STATE:
    case IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS:
    {
        DWORD cpuNum = (DWORD)(SIZE_T)infoParam;

        if (cpuNum == IG_CURRENT_VCPU)
        {
            cpuNum = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNum >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        if (bufferLength < sizeof(IG_ARCH_REGS))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        {
            VCPU* vcpu = guest->Vcpu[cpuNum];
            PIG_ARCH_REGS introArch;

            introArch = (PIG_ARCH_REGS)buffer;

            introArch->Rax = vcpu->ArchRegs.RAX;
            introArch->Rcx = vcpu->ArchRegs.RCX;
            introArch->Rdx = vcpu->ArchRegs.RDX;
            introArch->Rbx = vcpu->ArchRegs.RBX;
            introArch->Rsp = vcpu->ArchRegs.RSP;
            introArch->Rbp = vcpu->ArchRegs.RBP;
            introArch->Rsi = vcpu->ArchRegs.RSI;
            introArch->Rdi = vcpu->ArchRegs.RDI;
            introArch->R8 = vcpu->ArchRegs.R8;
            introArch->R9 = vcpu->ArchRegs.R9;
            introArch->R10 = vcpu->ArchRegs.R10;
            introArch->R11 = vcpu->ArchRegs.R11;
            introArch->R12 = vcpu->ArchRegs.R12;
            introArch->R13 = vcpu->ArchRegs.R13;
            introArch->R14 = vcpu->ArchRegs.R14;
            introArch->R15 = vcpu->ArchRegs.R15;

            introArch->Flags = vcpu->ArchRegs.RFLAGS;
            introArch->Rip = vcpu->ArchRegs.RIP;

            introArch->Cr0 = vcpu->ArchRegs.CR0;
            introArch->Cr3 = vcpu->ArchRegs.CR3;
            introArch->Cr4 = vcpu->ArchRegs.CR4;
            introArch->Cr8 = vcpu->ArchRegs.CR8;
            introArch->Dr7 = vcpu->ArchRegs.DR7;

            if (infoClass == IG_QUERY_INFO_CLASS_REGISTER_STATE)
            {
                introArch->IdtBase = vcpu->ArchRegs.IdtrBase;
                introArch->IdtLimit = vcpu->ArchRegs.IdtrLimit;

                introArch->GdtBase = vcpu->ArchRegs.GdtrBase;
                introArch->GdtLimit = vcpu->ArchRegs.GdtrLimit;
            }
        }
    }
    break;

    case IG_QUERY_INFO_CLASS_READ_MSR:
    {
        DWORD cpu = (DWORD)(SIZE_T)infoParam;
        PIG_QUERY_MSR msrStruct;
        VCPU* vcpu;

        if (cpu == IG_CURRENT_VCPU)
        {
            cpu = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpu >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        // If we're trying to set the context for another VCPU, make sure that it is paused, or use the current one
        if ((HvGetCurrentVcpu()->GuestCpuIndex != cpu) && HvGetCurrentVcpu()->Guest->Vcpu[cpu]->Schedulable)
        {
            vcpu = HvGetCurrentVcpu();
        }
        else
        {
            vcpu = HvGetCurrentVcpu()->Guest->Vcpu[cpu];
        }

        if (bufferLength < sizeof(IG_QUERY_MSR))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        msrStruct = (PIG_QUERY_MSR)buffer;
        msrStruct->Value = 0;

        switch (msrStruct->MsrId)
        {
        case IG_IA32_GS_BASE:
            vmx_vmread(VMCS_GUEST_GS_BASE, &msrStruct->Value);
            break;
        case IG_IA32_FS_BASE:
            vmx_vmread(VMCS_GUEST_FS_BASE, &msrStruct->Value);
            break;
        case IG_IA32_EFER:
            vmx_vmread(VMCS_GUEST_IA32_EFER, &msrStruct->Value);
            break;
        case IG_IA32_SYSENTER_CS:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_CS, &msrStruct->Value);
            break;
        case IG_IA32_SYSENTER_ESP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RSP, &msrStruct->Value);
            break;
        case IG_IA32_SYSENTER_EIP:
            vmx_vmread(VMCS_GUEST_IA32_SYSENTER_RIP, &msrStruct->Value);
            break;
        case IG_IA32_STAR:
            msrStruct->Value = __readmsr(MSR_IA32_STAR);
            break;
        case IG_IA32_LSTAR:
            msrStruct->Value = __readmsr(MSR_IA32_LSTAR);
            break;
        case IG_IA32_DEBUGCTL:
            vmx_vmread(VMCS_GUEST_IA32_DEBUGCTL, &msrStruct->Value);
            break;
        case IG_IA32_PAT:
            vmx_vmread(VMCS_GUEST_IA32_PAT, &msrStruct->Value);
            break;
        case MSR_IA32_KERNEL_GS_BASE:
            // safe to read msr, is not used by the hypervisor
            msrStruct->Value = __readmsr(MSR_IA32_KERNEL_GS_BASE);
            break;
        default:
            ERROR("Unknown MSR for guest : msr id = 0x%08x\n", msrStruct->MsrId);
            status = CX_STATUS_OPERATION_NOT_IMPLEMENTED;
            break;
        }

        if (!SUCCESS(status))
        {
            break;
        }
    }
    break;

    case IG_QUERY_INFO_CLASS_IDT:
    {
        QWORD* pIdtBase = (QWORD*)buffer;
        DWORD cpuNum = (DWORD)(SIZE_T)infoParam;
        VCPU* vcpu;

        if (bufferLength < sizeof(vcpu->ArchRegs.IdtrBase))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        if (cpuNum == IG_CURRENT_VCPU)
        {
            cpuNum = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNum >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        vcpu = guest->Vcpu[cpuNum];

        *pIdtBase = vcpu->ArchRegs.IdtrBase;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_GDT:
    {
        QWORD* pGdtBase = (QWORD*)buffer;
        DWORD cpuNum = (DWORD)(SIZE_T)infoParam;
        VCPU* vcpu;

        if (bufferLength < sizeof(vcpu->ArchRegs.GdtrBase))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        if (cpuNum == IG_CURRENT_VCPU)
        {
            cpuNum = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNum >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        vcpu = guest->Vcpu[cpuNum];

        *pGdtBase = vcpu->ArchRegs.GdtrBase;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_CPU_COUNT:
    {
        if (bufferLength < sizeof(guest->VcpuCount))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        DWORD* pCpuCount = (DWORD*)buffer;

        *pCpuCount = guest->VcpuCount;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_SET_REGISTERS:
    {
        //
        // NOTE: This will work only for the registers of the current VCPU!!
        // It is absurd to try to modify the registers of another VCPU (which
        // may be in God knows what state...)
        //

        PIG_ARCH_REGS pIntroRegs;
        ARCH_REGS *pRegs;
        DWORD cpu;

        if (bufferLength < sizeof(IG_ARCH_REGS))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        pIntroRegs = (PIG_ARCH_REGS)buffer;

        cpu = (DWORD)(SIZE_T)infoParam;

        if (cpu == IG_CURRENT_VCPU)
        {
            cpu = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpu >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        pRegs = (ARCH_REGS*)&guest->Vcpu[cpu]->ArchRegs;

        // If we're trying to set the context for another VCPU, make sure that it is paused.
        if ((HvGetCurrentVcpu()->GuestCpuIndex != cpu) && HvGetCurrentVcpu()->Guest->Vcpu[cpu]->Schedulable)
        {
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        pRegs->RAX = pIntroRegs->Rax;
        pRegs->RCX = pIntroRegs->Rcx;
        pRegs->RDX = pIntroRegs->Rdx;
        pRegs->RBX = pIntroRegs->Rbx;
        pRegs->RSP = pIntroRegs->Rsp;
        pRegs->RBP = pIntroRegs->Rbp;
        pRegs->RSI = pIntroRegs->Rsi;
        pRegs->RDI = pIntroRegs->Rdi;
        pRegs->R8 = pIntroRegs->R8;
        pRegs->R9 = pIntroRegs->R9;
        pRegs->R10 = pIntroRegs->R10;
        pRegs->R11 = pIntroRegs->R11;
        pRegs->R12 = pIntroRegs->R12;
        pRegs->R13 = pIntroRegs->R13;
        pRegs->R14 = pIntroRegs->R14;
        pRegs->R15 = pIntroRegs->R15;
        pRegs->RIP = pIntroRegs->Rip;
        pRegs->RFLAGS = pIntroRegs->Flags;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_TSC_SPEED:
    {
        if (bufferLength < sizeof(gTscSpeed))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        QWORD* pTscpSpeed = (QWORD*)buffer;

        *pTscpSpeed = gTscSpeed;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_CURRENT_TID:
    {
        if (bufferLength < sizeof(HvGetCurrentCpu()->BootInfoIndex))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        DWORD* pTid = (DWORD*)buffer;

        *pTid = HvGetCurrentCpuIndex();

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_CS_TYPE:
    {
        QWORD csAccess = 0, csL, csD, cpuNumber;
        DWORD* pCsType = (DWORD*)buffer;

        if (bufferLength < sizeof(DWORD))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        cpuNumber = (DWORD)(SIZE_T)infoParam;

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &csAccess);

        csL = (csAccess >> 13) & 1; // cs.L bit
        csD = (csAccess >> 14) & 1; // cs.D bit

        if (0 != (guest->Vcpu[cpuNumber]->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
        {
            if (csL == 1)
            {
                // If L bit of the code segment descriptor is 1, we have a 64-bit code segment
                *pCsType = IG_CS_TYPE_64B;
            }
            else
            {
                // If L bit is 0, we have compatibility mode segment; check D bit to get default operand size
                if (csD == 0)
                {
                    // D bit 0 => 16 bit compatibility mode
                    *pCsType = IG_CS_TYPE_16B;
                }
                else
                {
                    // D bit 1 => 32 bit compatibility mode
                    *pCsType = IG_CS_TYPE_32B;
                }
            }
        }
        else if (0 != (guest->Vcpu[cpuNumber]->ArchRegs.CR0 & CR0_PE))
        {
            if (csD == 0)
            {
                *pCsType = IG_CS_TYPE_16B;
            }
            else
            {
                *pCsType = IG_CS_TYPE_32B;
            }
        }
        else
        {
            if (csD == 0)
            {
                *pCsType = IG_CS_TYPE_16B;
            }
            else
            {
                *pCsType = IG_CS_TYPE_32B;
            }
        }

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_CS_RING:
    {
        QWORD ssAccess = 0, ssDpl, cpuNumber;
        DWORD* pSsRing = (DWORD*)buffer;

        if (bufferLength < sizeof(DWORD))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        cpuNumber = (DWORD)(SIZE_T)infoParam;

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        // The SS always contains the actual CPL; CS may not contain the real CPL (for example, conforming
        // segments).
        vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &ssAccess);

        ssDpl = (ssAccess >> 5) & 3; // ss.DPL bits

        // Although we will store the exact same value as IG_CS_RING_*, we want to be compatible
        // with any other modification that may be made to the glue.
        switch (ssDpl)
        {
        case 0:
            *pSsRing = IG_CS_RING_0;
            break;
        case 1:
            *pSsRing = IG_CS_RING_1;
            break;
        case 2:
            *pSsRing = IG_CS_RING_2;
            break;
        case 3:
            *pSsRing = IG_CS_RING_3;
            break;
        default:
            break;
        }

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_SEG_REGISTERS:
    {
        PIG_SEG_REGS pSeg = (PIG_SEG_REGS)buffer;
        QWORD segBase = 0, segLimit = 0, segAr = 0, segSel = 0;

        if (bufferLength < sizeof(IG_SEG_REGS))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        vmx_vmread(VMCS_GUEST_CS_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_CS_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_CS, &segSel);

        pSeg->CsBase = segBase;
        pSeg->CsLimit = segLimit;
        pSeg->CsAr = segAr;
        pSeg->CsSelector = segSel;

        vmx_vmread(VMCS_GUEST_DS_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_DS_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_DS_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_DS, &segSel);

        pSeg->DsBase = segBase;
        pSeg->DsLimit = segLimit;
        pSeg->DsAr = segAr;
        pSeg->DsSelector = segSel;

        vmx_vmread(VMCS_GUEST_ES_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_ES_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_ES_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_ES, &segSel);

        pSeg->EsBase = segBase;
        pSeg->EsLimit = segLimit;
        pSeg->EsAr = segAr;
        pSeg->EsSelector = segSel;

        vmx_vmread(VMCS_GUEST_SS_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_SS_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_SS, &segSel);

        pSeg->SsBase = segBase;
        pSeg->SsLimit = segLimit;
        pSeg->SsAr = segAr;
        pSeg->SsSelector = segSel;

        vmx_vmread(VMCS_GUEST_FS_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_FS_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_FS_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_FS, &segSel);

        pSeg->FsBase = segBase;
        pSeg->FsLimit = segLimit;
        pSeg->FsAr = segAr;
        pSeg->FsSelector = segSel;

        vmx_vmread(VMCS_GUEST_GS_BASE, &segBase);
        vmx_vmread(VMCS_GUEST_GS_LIMIT, &segLimit);
        vmx_vmread(VMCS_GUEST_GS_ACCESS_RIGHTS, &segAr);
        vmx_vmread(VMCS_GUEST_GS, &segSel);

        pSeg->GsBase = segBase;
        pSeg->GsLimit = segLimit;
        pSeg->GsAr = segAr;
        pSeg->GsSelector = segSel;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_XSAVE_SIZE:
    {
        PDWORD pXsaveStateSize = (PDWORD)buffer;
        DWORD cpuNumber;

        if (bufferLength < sizeof(DWORD))
        {
            status = CX_STATUS_INVALID_PARAMETER_5;
            break;
        }

        cpuNumber = (DWORD)(SIZE_T)infoParam;

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        *pXsaveStateSize = CpuComputeExtendedStateSize(guest->Vcpu[cpuNumber]->ArchRegs.XCR0);

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_XSAVE_AREA:
    {
        DWORD cpuNumber;
        DWORD size;

        cpuNumber = (DWORD)(SIZE_T)infoParam;

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        size = CpuComputeExtendedStateSize(guest->Vcpu[cpuNumber]->ArchRegs.XCR0);
        if (bufferLength < size)
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        memcpy(buffer, HvGetCurrentVcpu()->Guest->Vcpu[cpuNumber]->ExtState, size);

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_SET_XSAVE_AREA:
    {
        DWORD cpuNumber = (DWORD)(SIZE_T)infoParam;
        DWORD xsaveSize;

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        xsaveSize = CpuComputeExtendedStateSize(guest->Vcpu[cpuNumber]->ArchRegs.XCR0);
        if (bufferLength > xsaveSize)
        {
            status = CX_STATUS_DATA_OUT_OF_RANGE;
            break;
        }

        memcpy(HvGetCurrentVcpu()->Guest->Vcpu[cpuNumber]->ExtState, buffer, bufferLength);

        status = CX_STATUS_SUCCESS;
        break;
    }
    case IG_QUERY_INFO_CLASS_EPTP_INDEX:
    {
        PDWORD pEptpIndex = (PDWORD)buffer;

        if (bufferLength < sizeof(DWORD))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }
        GUEST_MEMORY_DOMAIN_INDEX currentDomainIndex;
        status = VcpuGetActiveMemoryDomainIndex(HvGetCurrentVcpu(), &currentDomainIndex);
        if (CX_SUCCESS(status))
        {
            *pEptpIndex = currentDomainIndex;
        }
    }
    break;

    case IG_QUERY_INFO_CLASS_MAX_GPFN:
    {
        QWORD* pMaxGpfn = (PQWORD)buffer;

        if (bufferLength < sizeof(QWORD))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        *pMaxGpfn = HvGetCurrentVcpu()->Guest->MaxPhysicalAddress >> 12;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_VE_SUPPORT:
    {
        BOOLEAN* pSupport = (BOOLEAN*)buffer;

        if (bufferLength < sizeof(BOOLEAN))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        *pSupport = VmxIsVeAvailable();

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_VMFUNC_SUPPORT:
    {
        BOOLEAN* pSupport = (BOOLEAN*)buffer;

        if (bufferLength < sizeof(BOOLEAN))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        *pSupport = VmxIsVmfuncAvailable();

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_SPP_SUPPORT:
    {
        BOOLEAN* pSupport = (BOOLEAN*)buffer;

        if (bufferLength < sizeof(BOOLEAN))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        *pSupport = VmxIsSppAvailable();

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_DTR_SUPPORT:
    {
        BOOLEAN* pSupport = (BOOLEAN*)buffer;

        if (bufferLength < sizeof(BOOLEAN))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        *pSupport = TRUE;

        status = CX_STATUS_SUCCESS;
    }
    break;

    case IG_QUERY_INFO_CLASS_GET_XCR0:
    {
        DWORD cpuNumber = (DWORD)(SIZE_T)infoParam;
        QWORD* value = (QWORD*)buffer;

        if (bufferLength < sizeof(QWORD))
        {
            status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
            break;
        }

        if (cpuNumber == IG_CURRENT_VCPU)
        {
            cpuNumber = HvGetCurrentVcpu()->GuestCpuIndex;
        }
        else if (cpuNumber >= guest->VcpuCount)
        {
            status = CX_STATUS_INVALID_PARAMETER_3;
            break;
        }

        *value = guest->Vcpu[cpuNumber]->ArchRegs.XCR0;

        status = CX_STATUS_SUCCESS;
        break;
    }

    default:
        ERROR("Unknown Info Class %u\n", infoClass);
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        break;
    }

    Context->ProcessingStatus = status;

    return status;
}

NTSTATUS
GuestIntNapIntroEventNotify(
    _In_ PVOID GuestHandle,
    _In_ DWORD EventClass,
    _In_opt_ PVOID Parameters,
    _In_ size_t EventSize
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    if (!GstIsSafeToInterrupt(GuestHandle)) return CX_STATUS_SUCCESS;

    // validate
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = GuestHandle;

    if (Parameters == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (guest->AlertsCache.Buffer == NULL)
    {
        status = HpAllocWithTag(&guest->AlertsCache.Buffer, sizeof(INTROSPECTION_ALERT) * MAX_INTROSPECTION_ALERTS, TAG_EVENT);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTag", status);
            return HV_STATUS_TO_INTRO_STATUS(status);
        }
        memzero(guest->AlertsCache.Buffer, sizeof(INTROSPECTION_ALERT) * MAX_INTROSPECTION_ALERTS);

        guest->AlertsCache.Size = MAX_INTROSPECTION_ALERTS;
        guest->AlertsCache.Count = 0;

        HvInitSpinLock(&guest->AlertsCache.Spinlock, "AlertsCache.Spinlock", NULL);
    }

    if (0 == guest->AlertsCache.Count)
    {
        guest->AlertsCache.Tsc = __rdtsc();
    }

    HvAcquireSpinLock(&guest->AlertsCache.Spinlock);

    memcpy(&guest->AlertsCache.Buffer[guest->AlertsCache.Count].Event, Parameters, EventSize);
    guest->AlertsCache.Buffer[guest->AlertsCache.Count].Type = EventClass;
    guest->AlertsCache.Buffer[guest->AlertsCache.Count].IndexInQueue = (QWORD)_InterlockedIncrement64((long long*)&gIntroAlertCount);
    guest->AlertsCache.Count++;

    // make sure we do not overflow the buffer
    if (guest->AlertsCache.Count >= guest->AlertsCache.Size)
    {
        PCMD_SEND_INTROSPECTION_ALERT cmd = NULL;

        status = CommPrepareMessage(cmdSendIntrospectionAlert, COMM_FLG_IS_NON_CORE_MESSAGE, TargetWinguestUm, (DWORD)sizeof(CMD_SEND_INTROSPECTION_ALERT) + (guest->AlertsCache.Count - 1) * sizeof(INTROSPECTION_ALERT), (PCOMM_MESSAGE*)&cmd);
        if (!NT_SUCCESS(status))
        {
            if (CX_STATUS_ACCESS_DENIED == status) status = CX_STATUS_SUCCESS;
            else LOG_FUNC_FAIL("CommPrepareMessage", status);

            goto invalidate_cache;
        }

        memcpy(cmd->Alerts, guest->AlertsCache.Buffer, sizeof(INTROSPECTION_ALERT) * guest->AlertsCache.Count);
        cmd->Count = guest->AlertsCache.Count;

        status = CommPostMessage((PCOMM_MESSAGE)cmd);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("CommPostMessage", status);

            // and free the message
            CommDestroyMessage((PCOMM_MESSAGE)cmd);
        }

    invalidate_cache:
        guest->AlertsCache.Count = 0;
    }

    HvReleaseSpinLock(&guest->AlertsCache.Spinlock);
    return HV_STATUS_TO_INTRO_STATUS(status);
}


void
GuestIntNapBugCheck(
    void
)
{
#ifdef DEBUG
    VCPUERROR(HvGetCurrentVcpu(), "This is a debug build! Introspection bugcheck came, we will try to enter debugger!\n");

    DbgBreakIgnoreCleanupIKnowWhatImDoing();
#else
    VCPUERROR(HvGetCurrentVcpu(), "This is release build! Introspection bugcheck came, we will take as if introspection engine requested a disable operation!\n");

    HvGetCurrentGuest()->Intro.IntroRequestedToBeDisabled = TRUE;

#endif
    return;
}



void
GuestIntNapEnterDebugger(
    void
)
{
#ifdef DEBUG
    VCPUERROR(HvGetCurrentVcpu(), "Intro requested to enter debugger!\n");

    DbgBreakIgnoreCleanupIKnowWhatImDoing();
#else
    VCPUERROR(HvGetCurrentVcpu(), "This is release build! Ignore request to enter debugger!\n");

    HvGetCurrentGuest()->Intro.IntroRequestedToBeDisabled = TRUE;
#endif
}



NTSTATUS
GuestIntNapNotifyIntrospectionActivated(
    _In_ PVOID Guest
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    LOG("Introspection was activated.\n");
    ((GUEST*)Guest)->Intro.IntrospectionActivated = TRUE;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapNotifyIntrospectionDeactivated(
    _In_ PVOID Guest
)
{
    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = Guest;

    ((GUEST*)Guest)->Intro.IntrospectionActivated = FALSE;

    guest->Intro.IntroRequestedToBeDisabled = TRUE;

    LOG("Introspection notified that it de-activated itself or needs to be deactivated!\n");

    return CX_STATUS_SUCCESS;
}



NTSTATUS
GuestIntNapNotifyIntrospectionErrorState(
    _In_     PVOID                Guest,
    _In_     INTRO_ERROR_STATE    Error,
    _In_opt_ PINTRO_ERROR_CONTEXT Context
)
{
    NTSTATUS status;
    PCMD_REPORT_INTROSPECTION_ERROR cmd;

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    GUEST *guest = Guest;

    switch (Error)
    {
    case intErrGuestNotIdentified:
        WARNING("The guest operating system was not identified.\n");
        break;

    case intErrGuestNotSupported:
        WARNING("The guest operating system version is not supported.\n");
        break;

    case intErrGuestKernelNotFound:
        WARNING("The kernel image was not found.\n");
        break;

    case intErrGuestApiNotFound:
        WARNING("A critical guest API was not found.\n");
        break;

    case intErrGuestExportNotFound:
        WARNING("A guest export was not found.\n");
        break;

    case intErrGuestStructureNotFound:
        WARNING("A critical guest kernel object was not found.\n");
        break;

    case intErrUpdateFileNotSupported:
        WARNING("The CAMI update file is not supported!\n");
        break;

    case intErrProcNotProtectedNoMemory:
        WARNING("A process could not be protected due to insufficient memory.\n");
        break;

    case intErrProcNotProtectedInternalError:
        WARNING("A process could not be protected due to an internal error.\n");
        break;

    default:
        ERROR("Unexpected INTRO_ERROR_STATE error value/state: 0x%08x\n", Error);
    }

    // save/cache error state
    guest->Intro.IntroReportedErrorStates |= BIT(Error);

    // report error to user mode

    status = CommPrepareMessage(cmdReportIntrospectionError, COMM_FLG_IS_NON_CORE_MESSAGE, TargetWinguestUm, (DWORD)sizeof(CMD_REPORT_INTROSPECTION_ERROR), (PCOMM_MESSAGE*)&cmd);
    if (!NT_SUCCESS(status))
    {
        if (CX_STATUS_ACCESS_DENIED == status) status = CX_STATUS_SUCCESS;
        else LOG_FUNC_FAIL("CommPrepareMessage", status);

        goto cleanup;
    }

    cmd->Error.Type = Error;

    if (Context) cmd->Error.Context = *Context;

    status = CommPostMessage((PCOMM_MESSAGE)cmd);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("CommPostMessage", status);

        CommDestroyMessage((PCOMM_MESSAGE)cmd);
        goto cleanup;
    }

cleanup:
    return CX_STATUS_SUCCESS;
}

NTSTATUS
GuestIntNapNotifyGuestDetectedOs(
    _In_ PVOID GuestHandle,
    _In_ GUEST_INFO* GuestInfo
)
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (GuestInfo == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    LOG("Guest startup time: %llu\n", GuestInfo->StartupTime);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
GuestIntNapReleaseBuffer(
    _In_ PVOID GuestHandle,
    _In_ PVOID Buffer,
    _In_ DWORD Size
)
//
// Introspection notifies us that the buffer can be freed.
// Should be used only to free the current buffer for intro_live_update.bin.
// As we don't want to free in order to not lose the content of the module, we just bypass this.
//
{
    if (GuestHandle == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Buffer == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (Size == 0) return CX_STATUS_INVALID_PARAMETER_3;

    return CX_STATUS_SUCCESS;
}

NTSTATUS
GuestIntNapInjectTrap(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ BYTE TrapNumber,
    _In_ DWORD ErrorCode,
    _In_opt_ QWORD Cr2
)
{
    // In current implementation, HVI will only inject a trap on the current VCPU,
    // so this argument will always be either the actual current VCPU number or IG_CURRENT_VCPU.
    if ((CpuNumber != IG_CURRENT_VCPU) && (CpuNumber != HvGetCurrentCpuIndex())) return CX_STATUS_OPERATION_NOT_IMPLEMENTED;

    VCPU* vcpu = HvGetCurrentVcpu();
    vcpu->IntroRequestedTrapInjection = TRUE;

    NTSTATUS status = VirtExcInjectException(GuestHandle, vcpu, TrapNumber, ErrorCode, Cr2);

    return HV_STATUS_TO_INTRO_STATUS(status);
}

///@}