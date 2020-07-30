/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file virt_exceptions.c
 *  @brief Support for injecting exceptions into the guest
 */

 /// \addtogroup virt_exceptions
 /// @{

#include "guests/virt_exceptions.h"
#include "napoca.h"
#include "kernel/kernel.h"
#include "boot/boot.h"
#include "common/kernel/cpu_state.h"
#include "boot/vmstate.h"
#include "kernel/interrupt.h"
#include "kernel/newcore.h"

/** @name Exception bitmap
 *  @brief Methods to handle VcpuException bitmap from #VCPU structure
 */
///@{
/// @brief Converts the exception number to the corresponding bit so that we can keep the exceptions in a bitmap
#define VCPU_GET_EXCEPTION_MASK(Exception)                              ((DWORD)(BIT(Exception)))

///
/// @brief Function that marks an exception as it should be injected
///
/// @param[in]  Vcpu            VCPU that should receive the exception when it reaches the guest
/// @param[in]  ExceptionNumber The number of the exception to be injected
/// @param[in]  Info            Additional information by exception (eg page fault address)
///
static __forceinline VOID VCPU_MARK_EXCEPTION(_In_ VCPU* Vcpu, _In_ EXCEPTION ExceptionNumber, _In_opt_ EXCEPTION_INFO Info)
{
    HvInterlockedOrU32(&(Vcpu->VcpuException.ExceptionInjectionMask), VCPU_GET_EXCEPTION_MASK(ExceptionNumber));
    Vcpu->VcpuException.ExceptionInfo[ExceptionNumber] = Info;
}

///
/// @brief Check if an exception is marked as it needs to be injected
///
/// @param[in]  Vcpu            VCPU being checked
/// @param[in]  ExceptionNumber The number of the exception being checked
///
/// @returns    TRUE            - if the exception with number ExceptionNumber must be injected
/// @returns    FALSE           - otherwise
///
static __forceinline BOOLEAN VCPU_IS_EXCEPTION_MARKED(_In_ VCPU* Vcpu, _In_ EXCEPTION ExceptionNumber)
{
    return QueryFlagInterlocked(Vcpu->VcpuException.ExceptionInjectionMask, VCPU_GET_EXCEPTION_MASK(ExceptionNumber));
}

///
/// @brief Function that removes an exception from the injection
///
/// @param[in]  Vcpu            VCPU from which the injection will be removed
/// @param[in]  ExceptionNumber The number of the exception to be removed
///
static __forceinline VOID VCPU_UNMARK_EXCEPTION(_In_ VCPU* Vcpu, _In_ EXCEPTION ExceptionNumber)
{
    HvInterlockedAndU32(&(Vcpu->VcpuException.ExceptionInjectionMask), ~(VCPU_GET_EXCEPTION_MASK(ExceptionNumber)));
}

///
/// @brief Check if any exceptions need to be injected on a VCPU
///
/// @param[in]  Vcpu            VCPU to be checked
///
/// @returns    TRUE            - if any exceptions need to be injected into this VCPU
/// @returns    FALSE           - otherwise
///
static __forceinline BOOLEAN VCPU_HAS_EXCEPTIONS(_In_ VCPU* Vcpu)
{
    return QueryFlagInterlocked((Vcpu)->VcpuException.ExceptionInjectionMask, DWORD_MAX);
}
///@}

/// @brief Format of the VM-Entry Interruption-Information Field
typedef union _VM_ENTRY_INT_INFO
{
    struct
    {
        DWORD           Vector              : 8;    ///< Vector of interrupt or exception
        DWORD           InterruptionType    : 3;    ///< Interruption type (see Intel Manual Volume 3 Cap 24.8.4)
        DWORD           DeliverErrorCode    : 1;    ///< Deliver error code (0 = do not deliver; 1 = deliver)
        DWORD           Reserved            : 19;
        DWORD           Valid               : 1;    ///< 1 if structure is valid
    };

    DWORD               Raw;
} VM_ENTRY_INT_INFO;

/// @brief Information about exceptions
const EXCEPTION_DETAILS gExceptionDetails[] =
{
    [EXCEPTION_DIVIDE_ERROR] =              { .IsAvailable = TRUE,  .Name = "Divide Error",                     .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_DEBUG] =                     { .IsAvailable = TRUE,  .Name = "Debug Exception",                  .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_NMI] =                       { .IsAvailable = TRUE,  .Name = "NMI Interrupt",                    .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_BREAKPOINT] =                { .IsAvailable = TRUE,  .Name = "Breakpoint",                       .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_OVERFLOW] =                  { .IsAvailable = TRUE,  .Name = "Overflow",                         .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_BOUND] =                     { .IsAvailable = TRUE,  .Name = "Bound Range Exceeded",             .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_INVALID_OPCODE] =            { .IsAvailable = TRUE,  .Name = "Invalid Opcode",                   .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_DEVICE_NOT_AVAIL] =          { .IsAvailable = TRUE,  .Name = "Device Not Available",             .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_DOUBLE_FAULT] =              { .IsAvailable = TRUE,  .Name = "Double Fault",                     .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_INVALID_TSS] =               { .IsAvailable = TRUE,  .Name = "Invalid TSS",                      .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_SEGMENT_NOT_PRESENT] =       { .IsAvailable = TRUE,  .Name = "Segment Not Present",              .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_STACK_FAULT] =               { .IsAvailable = TRUE,  .Name = "Stack-Segment Fault",              .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_GENERAL_PROTECTION] =        { .IsAvailable = TRUE,  .Name = "General Protection",               .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_PAGE_FAULT] =                { .IsAvailable = TRUE,  .Name = "Page Fault",                       .HasErrorCode = TRUE,   .HasSpecificInfo = TRUE },
    [EXCEPTION_FPU_ERROR] =                 { .IsAvailable = TRUE,  .Name = "Math Fault",                       .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_ALIGNMENT_CHECK] =           { .IsAvailable = TRUE,  .Name = "Alignment Check",                  .HasErrorCode = TRUE,   .HasSpecificInfo = FALSE },
    [EXCEPTION_MACHINE_CHECK] =             { .IsAvailable = TRUE,  .Name = "Machine Check",                    .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_SIMD_FLOATING_POINT] =       { .IsAvailable = TRUE,  .Name = "SIMD Floating-Point Exception",    .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
    [EXCEPTION_VIRTUALIZATION_EXCEPTION] =  { .IsAvailable = TRUE,  .Name = "Virtualization Exception",         .HasErrorCode = FALSE,  .HasSpecificInfo = FALSE },
};
#define MAX_KNOWN_EXCEPTION                 (ARRAYSIZE(gExceptionDetails) - 1)

///
/// @brief Check if an exception needs to be reinjected
///
/// @param[in]  Event           Event structure
///
/// @returns    TRUE            - if the exception needs to be reinjected
/// @returns    FALSE           - otherwise
///
static BOOLEAN _HvEventNeedsReinjection(_In_ VM_ENTRY_INT_INFO Event);

///
/// @brief Prepare the specific structure from vmcs for the exception to be injected
///
/// @param[in]  Vcpu            VCPU that should receive the exception when it reaches the guest
/// @param[in]  ExceptionNumber The number of the exception to be injected
/// @param[in]  ExceptionInfo   Additional information by exception (eg page fault address)
///
/// @returns    STATUS_LAPIC_ENABLED_NMI_WINDOW_EXIT    - if enable NMI-window exiting needed
/// @returns    STATUS_SUCCESS                          - if success
///
static NTSTATUS _InjectException(_In_ VCPU* Vcpu, _In_ BYTE ExceptionNumber, _In_ EXCEPTION_INFO ExceptionInfo);

///
/// @brief The exception is prepared to be injected into the GUEST.
///
/// Wrapper over #VCPU_MARK_EXCEPTION. This function also handles additional
/// information for the exception (now only the page fault address)
///
/// @param[in] Vcpu        VCPU on which we will mark the exception to be injected
/// @param[in] TrapNumber  Exception number
/// @param[in] ErrorCode   Exception error code (if the exception has an error code)
/// @param[in] Cr2         Page fault address (if TrapNumber is page fault)
///
static void _MarkExceptionForInjection(_In_ VCPU* Vcpu, _In_ BYTE TrapNumber, _In_opt_ DWORD ErrorCode, _In_opt_ QWORD Cr2);

NTSTATUS
VirtExcInjectException(
    _In_ PVOID      GuestHandle,
    _In_ VCPU*      Vcpu,
    _In_ EXCEPTION  ExceptionNumber,
    _In_ DWORD      ErrorCode,
    _In_opt_ QWORD  Cr2
)
{
    UNREFERENCED_PARAMETER(GuestHandle);

    if (Vcpu == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (ExceptionNumber > MAX_KNOWN_EXCEPTION || !gExceptionDetails[ExceptionNumber].IsAvailable) return CX_STATUS_INVALID_PARAMETER_3;

    _MarkExceptionForInjection(Vcpu, ExceptionNumber, ErrorCode, Cr2);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
VirtExcResetPendingException(
    _In_ VCPU*      Vcpu,
    _In_ EXCEPTION  ExceptionNumber
)
{
    if (Vcpu == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (ExceptionNumber > MAX_KNOWN_EXCEPTION || !gExceptionDetails[ExceptionNumber].IsAvailable) return CX_STATUS_INVALID_PARAMETER_2;

    VCPU_UNMARK_EXCEPTION(Vcpu, ExceptionNumber);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
VirtExcHandlePendingExceptions(
    _In_ VCPU* Vcpu
)
{
    // The order is the following, based on Intel System Programming Manual:
    // Chapter 6.9: Priority Among Simultaneous Exceptions and Interrupts
    //   INIT / SIPI
    //   Breakpoint
    //   NMI
    //   Hardware interrupts (PIC, LAPIC)
    //   Low priority exceptions (GP etc)

    //
    //  1. Hardware resets / MC
    //  2. Trap on TSS
    //  3. External hardware interventions (flush, stopclk, SMI, INIT)
    //  4. Traps on the previous instruction (breakpoints, debug trap exceptions)
    //  5. NMI
    //  6. Maskable hardware interrupts
    //  7. Code breakpoint fault
    //  8. Faults from fetching next instruction (code-segment limit violation, code page fault)
    //  9. Faults from decoding next instruction (instruction length > 15, invalid opcode, coprocessor not available)
    // 10. Fault on executing an instruction (overflow, bound error, invalid TSS, segment not present, stack fault, GP, data page fault,
    //     alignment check, x87 FPU FP exception, SIMD FP exception)
    //

    //
    // 0. Synthetic PF exception. Must be injected before anything else, otherwise we won't have the chance to do it
    // again. The problem is that this mechanism has to be synced with the one in Xen, and in Xen, we can't call
    // an Intro API to tell us when we can inject the #PF. Instead, we rely on Introcore to do the check beforehand,
    // and, when calling the injection API, we are certain that we can inject the #PF, but we must to it before
    // serving any other events, otherwise this request will be lost.
    //

    if (Vcpu == CX_NULL || Vcpu != HvGetCurrentVcpu())
    {
        return CX_STATUS_INVALID_PARAMETER;
    }

    if (!VCPU_HAS_EXCEPTIONS(Vcpu))
    {
        return CX_STATUS_SUCCESS;
    }

    if (VCPU_IS_EXCEPTION_MARKED(Vcpu, EXCEPTION_PAGE_FAULT))
    {
        VCPULOG(Vcpu, "[CPU %d] Injecting a PF exception in guest on VCPU %d, RIP %018p, CR2 %018p, CR3 %018p, PFEC %x\n",
            HvGetCurrentApicId(),
            Vcpu->GuestCpuIndex,
            Vcpu->ArchRegs.RIP,
            Vcpu->VcpuException.ExceptionInfo[EXCEPTION_PAGE_FAULT].SpecificInfo.PageFaultSpecific.VirtualAddress,
            Vcpu->ArchRegs.CR3,
            Vcpu->VcpuException.ExceptionInfo[EXCEPTION_PAGE_FAULT].ExceptionErrorCode
        );

        // Effectively inject
        _InjectException(Vcpu, EXCEPTION_PAGE_FAULT, Vcpu->VcpuException.ExceptionInfo[EXCEPTION_PAGE_FAULT]);

        // Reset injection mask
        VCPU_UNMARK_EXCEPTION(Vcpu, EXCEPTION_PAGE_FAULT);

        return CX_STATUS_SUCCESS;
    }

    //
    // 4. Debug Exception
    //
    if (VCPU_IS_EXCEPTION_MARKED(Vcpu, EXCEPTION_BREAKPOINT))
    {
        VCPULOG(Vcpu, "[CPU %d] Injecting a #BP exception in guest RIP=%p.\n",
            HvGetCurrentApicId(),
            HvGetCurrentVcpu()->ArchRegs.RIP
        );

        // Effectively inject
        _InjectException(Vcpu, EXCEPTION_BREAKPOINT, Vcpu->VcpuException.ExceptionInfo[EXCEPTION_BREAKPOINT]);

        // Reset injection mask
        VCPU_UNMARK_EXCEPTION(Vcpu, EXCEPTION_BREAKPOINT);

        return CX_STATUS_SUCCESS;
    }

    //
    // 5. NMI Injection
    //
    if (VCPU_IS_EXCEPTION_MARKED(Vcpu, EXCEPTION_NMI))
    {
        // Try to inject the NMI if not blocked
        NTSTATUS localStatus = _InjectException(Vcpu, EXCEPTION_NMI, Vcpu->VcpuException.ExceptionInfo[EXCEPTION_NMI]);

        if (localStatus == STATUS_LAPIC_ENABLED_NMI_WINDOW_EXIT)
        {
            VmstateControlNMIWindowExiting(TRUE);
        }
        else if (localStatus == STATUS_LAPIC_ENABLED_INTR_WINDOW_EXIT)
        {
            HvControlInterruptWindowExiting(TRUE);
        }

        return localStatus;
    }

    const EXCEPTION exceptionOrder[] =
    {
        EXCEPTION_GENERAL_PROTECTION,
        EXCEPTION_INVALID_OPCODE,
        EXCEPTION_DEVICE_NOT_AVAIL,
        EXCEPTION_OVERFLOW,
        EXCEPTION_BOUND,
        EXCEPTION_INVALID_TSS,
        EXCEPTION_SEGMENT_NOT_PRESENT,
        EXCEPTION_STACK_FAULT,
        //EXCEPTION_PAGE_FAULT, -> injected first.
        EXCEPTION_ALIGNMENT_CHECK,
        EXCEPTION_FPU_ERROR,
        EXCEPTION_SIMD_FLOATING_POINT,

        EXCEPTION_END
    };

    BYTE index = 0;
    while (exceptionOrder[index] != EXCEPTION_END)
    {
        if (VCPU_IS_EXCEPTION_MARKED(Vcpu, exceptionOrder[index]))
        {
            VCPULOG(Vcpu, "[CPU %d] Injecting exception [%d] in guest.\n", HvGetCurrentApicId(), exceptionOrder[index]);

            // Effectively inject the exception exceptionOrder[index]
            _InjectException(Vcpu, exceptionOrder[index], Vcpu->VcpuException.ExceptionInfo[exceptionOrder[index]]);

            // Reset injection mask
            VCPU_UNMARK_EXCEPTION(Vcpu, exceptionOrder[index]);

            return CX_STATUS_SUCCESS;
        }

        ++index;
    }

    return CX_STATUS_SUCCESS;
}

BOOLEAN
VirtExcReinjectPendingExceptions(
    void
)
{
    size_t  temp = 0;
    QWORD   intrState = 0;
    QWORD   exitReason = 0;
    BOOLEAN eventReinjected = 0;
    QWORD   idtVectoringErrorCode = 0;
    VM_ENTRY_INT_INFO idtVectoringInformation = { 0 };

    // Read the VM EXIT IDT Vectoring Information
    vmx_vmread(VMCS_IDT_VECTORING_INFORMATTION, &temp);
    idtVectoringInformation.Raw = (DWORD)temp;

    // Check if event re-injection is needed, ie, the idtVectoringInformation field is valid.
    if (idtVectoringInformation.Valid)
    {
        // the exit reason is used only for debugging purposes.
        vmx_vmread(VMCS_VM_EXIT_REASON, &exitReason);

        // If the exit reason is not task switch, we will proceed on forwarding the event inside the event injection info.
        // The idea is that a task switch can interrupt an event delivery if and only if it is caused by the event
        // itself; this happens on x86 systems for NMI, #DF and #MC handlers, which have different tasks attached;
        // any of these events will also cause a task switch to occur; if we'd try to reinject the event, we would
        // cause an infinite loop of inject - task switch - inject.
        if ((exitReason != EXIT_REASON_TASK_SWITCH) && (_HvEventNeedsReinjection(idtVectoringInformation)))
        {
            // Write the event injection information
            vmx_vmwrite(VMCS_VM_ENTRY_EVENT_INJECTION, idtVectoringInformation.Raw);

            if (idtVectoringInformation.DeliverErrorCode)
            {
                //
                // If exception delivery caused a VM-exit, and the exception pushes an error code on the stack,
                // the error code is saved in IdtVectoringErrorCode. We need to put it back in VmEntryExceptionErrorCode.
                //

                // Write the error code (even if there isn't an error code, we can safely write this field).
                vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE, &idtVectoringErrorCode);
                vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE, idtVectoringErrorCode);
            }

            //
            // If NMI delivery caused the VM-exit (during NMI delivery), the BlockingByNMI bit is already set
            // in InterruptibilityState, so it will block further NMI delivery. It needs to be reset, so the
            // NMI can be reinjected.
            //
            if (idtVectoringInformation.InterruptionType == VM_EVENT_INTR_NMI) // NMI being re-injected
            {
                vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intrState);

                intrState &= ~VMCSFLAG_IRRSTATE_BLOCKING_BY_NMI;

                vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intrState);
            }

            eventReinjected = TRUE;
        }
    }

    return eventReinjected;
}

NTSTATUS
VirtExcResetPendingExceptions(
    VCPU* Vcpu
)
{
    if (Vcpu == NULL) return CX_STATUS_INVALID_PARAMETER;

    // Avoid to reset NMI.
    // Even if we failed to inject it into an exit handle cycle,
    // it will be injected into the next exit, compared to the exceptions below that will be deleted
    HvInterlockedAndU32(&(Vcpu->VcpuException.ExceptionInjectionMask),
        ~
        (VCPU_GET_EXCEPTION_MASK(EXCEPTION_DIVIDE_ERROR)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_DEBUG)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_BREAKPOINT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_OVERFLOW)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_BOUND)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_INVALID_OPCODE)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_DEVICE_NOT_AVAIL)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_DOUBLE_FAULT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_COPROC)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_INVALID_TSS)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_SEGMENT_NOT_PRESENT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_STACK_FAULT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_GENERAL_PROTECTION)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_PAGE_FAULT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_FPU_ERROR)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_ALIGNMENT_CHECK)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_MACHINE_CHECK)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_SIMD_FLOATING_POINT)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_VIRTUALIZATION_EXCEPTION)
            | VCPU_GET_EXCEPTION_MASK(EXCEPTION_SX))
    );

    return CX_STATUS_SUCCESS;
}

/******************************** Static functions *******************************************/

static
void
_MarkExceptionForInjection(
    _In_ VCPU*      Vcpu,
    _In_ BYTE       ExceptionNumber,
    _In_opt_ DWORD  ErrorCode,
    _In_opt_ QWORD  Cr2
)
{
    EXCEPTION_INFO exceptionInfo = { 0 };

    exceptionInfo.ExceptionErrorCode = ErrorCode;
    switch (ExceptionNumber)
    {
    case EXCEPTION_PAGE_FAULT:
        exceptionInfo.SpecificInfo.PageFaultSpecific.VirtualAddress = Cr2;
        break;

    default:
        break;
    }

    VCPU_MARK_EXCEPTION(Vcpu, ExceptionNumber, exceptionInfo);

    return;
}

static
NTSTATUS
_InjectException(
    _In_ VCPU*           Vcpu,
    _In_ BYTE            ExceptionNumber,
    _In_ EXCEPTION_INFO  ExceptionInfo
)
{
    VM_ENTRY_INT_INFO entryInterruptionInformation = { 0 };

    // Populate interruption information fields
    entryInterruptionInformation.Valid = 1;
    entryInterruptionInformation.Vector = ExceptionNumber;

    // If ProtectedMode bit is set in CR0 (bit0) and the vector is at most 31,
    // the event should be injected as a HardwareException
    if ((Vcpu->ArchRegs.CR0 & CR0_PE) == 0)
    {
        entryInterruptionInformation.InterruptionType = VM_EVENT_INTR_EXTERNAL_INT;
        entryInterruptionInformation.DeliverErrorCode = 0;

        goto inject;
    }

    if (ExceptionNumber == EXCEPTION_BREAKPOINT)
    {
        // Software exception
        entryInterruptionInformation.InterruptionType = VM_EVENT_INTR_SOFT_EXCEPTION;

        // If VM entry successfully injects (with no nested exception) an event with interruption type software
        // interrupt, privileged software exception, or software exception, the current guest RIP is incremented by the
        // VM-entry instruction length before being pushed on the stack.
        // RIP + 1 must be placed on the stack, because Windows subtracts 1 from the RIP on the stack (because #BP has trap behavior).
        __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LENGTH, 0 + 1);

        goto inject;
    }
    else if (ExceptionNumber == EXCEPTION_NMI)
    {
        QWORD intrState = 0;

        // Can we inject NMI right now?
        vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intrState);
        if (
            (!(intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_STI))       // conform Intel Vol 3B, Table 21-3 "Format of Interruptibility State"
            && (!(intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS))
            && (!(intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_NMI))
            )
        {
            if (CfgFeaturesVirtualizationVe && CfgFeaturesVirtualizationVmFunc)
            {
                if ((Vcpu->VirtualizationException.InfoPageHva) && (Vcpu->VirtualizationException.InfoPageHva->Reserved == VEINFOPAGE_RESERVED_MAGIC))
                {
                    return STATUS_LAPIC_ENABLED_INTR_WINDOW_EXIT;
                }
            }

            VCPU_UNMARK_EXCEPTION(Vcpu, EXCEPTION_NMI);

            // Type 2, no error code, conform Intel Vol 3B, 23.5, "Event Injection"
            entryInterruptionInformation.InterruptionType = VM_EVENT_INTR_NMI;

            goto inject;
        }
        else
        {
            return STATUS_LAPIC_ENABLED_NMI_WINDOW_EXIT;
        }
    }
    else
    {
        entryInterruptionInformation.InterruptionType = VM_EVENT_INTR_HARD_EXCEPTION;
    }

    if (gExceptionDetails[ExceptionNumber].HasErrorCode)
    {
        entryInterruptionInformation.DeliverErrorCode = 1;
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE, ExceptionInfo.ExceptionErrorCode);
    }

    if (gExceptionDetails[ExceptionNumber].HasSpecificInfo)
    {
        switch (ExceptionNumber)
        {
        case EXCEPTION_PAGE_FAULT:
            Vcpu->ArchRegs.CR2 = Vcpu->VcpuException.ExceptionInfo[EXCEPTION_PAGE_FAULT].SpecificInfo.PageFaultSpecific.VirtualAddress;

        default:
            break;
        }
    }

inject:
    __vmx_vmwrite(VMCS_VM_ENTRY_EVENT_INJECTION, entryInterruptionInformation.Raw);

    return CX_STATUS_SUCCESS;
}

static
BOOLEAN
_HvEventNeedsReinjection(
    _In_ VM_ENTRY_INT_INFO Event
)
//
// Some events, such as software interrupts, software exceptions (int3, into) don't need
// reinjection. Other events, such as the hardware interrupts or hardware exceptions do
// need reinjection.
//
{
    BOOLEAN reinject;

    switch (Event.InterruptionType)
    {
    case VM_EVENT_INTR_EXTERNAL_INT:
    case VM_EVENT_INTR_NMI:
        reinject = TRUE;
        break;
    case VM_EVENT_INTR_HARD_EXCEPTION:
        // int3 and into are considered software interrupts, so no reinjection is needed.
        reinject = (Event.Vector != EXCEPTION_BREAKPOINT) && (Event.Vector != EXCEPTION_OVERFLOW);
        break;
    default:
        reinject = FALSE;
        break;
    }

    return reinject;
}

/// @}