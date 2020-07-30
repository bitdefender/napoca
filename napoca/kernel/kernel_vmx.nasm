;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

;
; KERNEL_VMX.nasm - implements VMX ROOT / NON-ROOT (HOST / GUEST) switching
;
%include "loader_interface.nasm"
%ifdef __YASM_MAJOR__
    %include "cpu_state_defs.nasm"
    %include "vcpu64.nasm"
    %include "pcpu.nasm"
%else
    %include "kernel\cpu_state_defs.nasm"
    %include "kernel\vcpu64.nasm"
    %include "kernel\pcpu.nasm"
%endif

VMCS_GUEST_ACTIVITY_STATE               equ 0x00004826
VMCS_VM_EXIT_REASON                     equ 0x00004402
VMCS_GUEST_INTERRUPTIBILITY_STATE       equ 0x00004824
VMCS_GUEST_RIP                          equ 0x0000681E
VMCS_GUEST_CS_BASE                      equ 0x00006808

VMCSFLAG_IRRSTATE_BLOCKING_BY_STI       equ 0x00000001
VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS    equ 0x00000002

EXIT_REASON_HLT                         equ 12
VMCS_ACTIVITY_STATE_HLT                 equ 1

HC_VMCALL_MAGIC equ 0xBDBDBD66

VMCS_ERROR    equ 0x00004400
VMCS_HOST_RIP equ 0x00006C16
VMCS_HOST_RSP equ 0x00006C14
;
; import from 64 bit 1T VA C part
;

;;
;; NTSTATUS HvVmLaunchOrResumeFailed(__in VCPU* Vcpu)
;; - MUST return SUCCESS value to continue scheduling with another VCPU (on !SUCCESS will stop the current PCPU main cycle)
;;
extern HvVmxLaunchOrResumeFailed
extern CfgFeaturesVirtualizationMonitorGuestActivityStateChanges
extern CpuSaveFloatingArea
extern CpuRestoreFloatingArea

;
; export functions
;
global GuestHypercallStubx64, GuestHypercallStubEndx64
global GuestHypercallStubx86, GuestHypercallStubEndx86

[BITS 64]
;;
;; ----- NEWCORE STUFF ------------------------------------------------------------
;;

global HvVmxSwitchFromHostToVmGuest
global HvVmxSwitchFromHostToVmGuestWithContinuation
global HvVmxHandleVmExitAsm


;;
;; HvVmxSwitchFromHostToVmGuest
;;
HvVmxSwitchFromHostToVmGuest:
    ;; ...load generic state
    ;; ...save entry TSC
    ;; ...do launch / resume

    ;
    ; ...TODO/FIXME TRACING...
    ;

    ;
    ; IMPORTANT: GS:[...] points to PCPU structure
    ;

    mov     rcx, [GS:PCPU.Vcpu]             ; RCX = Vcpu pointer

    push        rcx
    X64CALL     CpuRestoreFloatingArea, rcx
    pop         rcx

    ;
    ; load GUEST x86/x64 ARCH registers NOT implicitly handled by VMCS
    ; CR2, CR8, RAX, RDX, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15, RFLAGS (and later also RAX, RDX and RCX)
    ;
    mov     rax, [rcx + VCPU.ArchRegs + ARCHREGS.CR2]
    mov     cr2, rax                        ; CR2 = CR2 of guest
    mov     rax, [rcx + VCPU.ArchRegs + ARCHREGS.CR8]
    mov     rbx, [rcx + VCPU.ArchRegs + ARCHREGS.RBX]
    mov     rbp, [rcx + VCPU.ArchRegs + ARCHREGS.RBP]
    mov     rsi, [rcx + VCPU.ArchRegs + ARCHREGS.RSI]
    mov     rdi, [rcx + VCPU.ArchRegs + ARCHREGS.RDI]
    mov     r8, [rcx + VCPU.ArchRegs + ARCHREGS.R8]
    mov     r9, [rcx + VCPU.ArchRegs + ARCHREGS.R9]
    mov     r10, [rcx + VCPU.ArchRegs + ARCHREGS.R10]
    mov     r11, [rcx + VCPU.ArchRegs + ARCHREGS.R11]
    mov     r12, [rcx + VCPU.ArchRegs + ARCHREGS.R12]
    mov     r13, [rcx + VCPU.ArchRegs + ARCHREGS.R13]
    mov     r14, [rcx + VCPU.ArchRegs + ARCHREGS.R14]
    mov     r15, [rcx + VCPU.ArchRegs + ARCHREGS.R15]

    ;
    ; save Vcpu->LastEntryTsc
    ;
    mfence
    lfence
    rdtsc                                       ; Read time stamp counter to EDX:EAX
    lfence

    shl     rdx, 32                             ; Move low part of RDX to its high part
    or      rdx, rax                            ; RDX = full 64 bit TSC

    mov     [rcx + VCPU.LastEntryTsc], rdx      ; Save the result in Vcpu->LastEntryTsc

    sub     rdx, [rcx + VCPU.LastExitTsc]       ; LastEntry (= now) - LastExit => how much time was spent in root-mode
    mov     [rcx + VCPU.PrevInHostTscDuration], rdx

    ;; do not update TSC OFFSETTING here unless you want to hide the time spent in hv from guest
    ;;sub     rdx, [rcx + VCPU.LastExitTsc]       ; RDX = TimeInHv
    ;;push    rdx
    ;;mov     rdx, 0x2010
    ;;vmread  rax, rdx
    ;;pop     rdx
    ;;; rax = oldTscOffset, rdx = TimeInHv
    ;;sub     rax,    rdx

    ;;mov     rdx, 0x2010
    ;;vmwrite rdx, rax

    ;
    ; continue load GUEST ARCH state
    ;
    cmp     WORD [rcx + VCPU.State], VCPU_STATE_ACTIVE;
    jne     __do_launch_newcore

__do_resume_newcore:
    mov     rax, [rcx + VCPU.ArchRegs + ARCHREGS.RAX]   ; RAX = RAX of guest
    mov     rdx, [rcx + VCPU.ArchRegs + ARCHREGS.RDX]   ; RDX = RDX of guest
    mov     rcx, [rcx + VCPU.ArchRegs + ARCHREGS.RCX]   ; RCX = RCX of guest
    vmresume

    ; ...resume failed :-(
    mov     rcx, [GS:PCPU.Vcpu]                         ; RCX = VCPU pointer (from [GS:0x030])
    mov     WORD [rcx + VCPU.State], VCPU_STATE_ERROR
    jmp     __launch_resume_failed_newcore

__do_launch_newcore:
    mov     rax, [rcx + VCPU.ArchRegs + ARCHREGS.RAX]   ; RAX = RAX of guest
    mov     rdx, [rcx + VCPU.ArchRegs + ARCHREGS.RDX]   ; RDX = RDX of guest
    mov     WORD [rcx + VCPU.State], VCPU_STATE_ACTIVE;
    mov     rcx, [rcx + VCPU.ArchRegs + ARCHREGS.RCX]   ; RCX = RCX of guest
    vmlaunch

    ; ...launch failed :-(
    mov     rcx, [GS:PCPU.Vcpu]                         ; RCX = VCPU pointer (from [GS:0x030])
    mov     WORD [rcx + VCPU.State], VCPU_STATE_ERROR

    ;
    ; common handler for failure of launch / resume attempts
    ;
__launch_resume_failed_newcore:
    ; do we have an error number (CF = 0, ZF = 1) or we do NOT have an error number (CF = 1, ZF = 0)?  conform Intel Vol 2B, 5.2, "Conventions"
    mov     edx, 0xffffffff                 ; assume we do NOT have a valid error number
    jc      __no_error_value_newcore
    mov     rax, VMCS_ERROR
    vmread  rdx, rax                        ; RDX = error number, conform Intel Vol 2B, 5.4 "VM Instruction Error Numbers"
__no_error_value_newcore:
    and     rdx, 0x00000000ffffffff         ; ensure upper half is zero for RDX (0 means launch / reasume failed *before* HOST state validation)
    ; sub     rsp, 0x20                       ; home register stuff + alignment of stack to paragraph
    ; call    HvVmxLaunchOrResumeFailed       ; RCX = VCPU, RDX = ErrorNumber
    ; add     rsp, 0x20

    push        rcx
    X64CALL     CpuSaveFloatingArea, rcx
    pop         rcx

    X64CALL  HvVmxLaunchOrResumeFailed, rcx, rdx

    mov     rcx, [GS:PCPU.Vcpu]             ; set back RCX = VCPU
    ;;; shall NEVER get here

   ; rax, rdx, rcx are the only registers ok to overwrite
HvVmxHandleHltAsm:
    mov     edx, VMCS_GUEST_INTERRUPTIBILITY_STATE
    vmread  rax, rdx

    ; we are emulating an instruction
    ; => we need to update RIP
    ; => we need to update activity state (HLT)
    ; => we need to clear interruptibility state
    and     eax, ~(VMCSFLAG_IRRSTATE_BLOCKING_BY_STI | VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS)

    vmwrite rdx, rax

    mov     edx, VMCS_GUEST_RIP
    vmread  rax, rdx

    inc     rax

    vmwrite rdx, rax

    mov     edx, VMCS_GUEST_CS_BASE
    vmread  rdx, rdx

    add     rax, rdx

    mov     [rcx + VCPU.IsInactive], BYTE 1
    mov     [rcx + VCPU.GuestHaltedCsRip], rax
    inc     QWORD [rcx + VCPU.TimesHalted]

    mov     edx, VMCS_GUEST_ACTIVITY_STATE
    mov     eax, VMCS_ACTIVITY_STATE_HLT
    vmwrite rdx, rax

    jmp     __do_resume_newcore

;;
;; HvVmxSwitchFromHostToVmGuestWithContinuation
;;
HvVmxSwitchFromHostToVmGuestWithContinuation:
    pushf
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    mov     rdx, VMCS_HOST_RIP
    call    .getrip
.getrip:
    pop rax
    add rax, .exit - .getrip
    vmwrite rdx, rax

    mov     rdx, VMCS_HOST_RSP
    mov     rax, rsp
    vmwrite rdx, rax

    call    HvVmxSwitchFromHostToVmGuest

.exit:
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    r11
    pop    r10
    pop    r9
    pop    r8
    pop    rdi
    pop    rsi
    pop    rbp
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    popf

    ret
;;
;; HvVmxHandleVmExitAsm
;;
HvVmxHandleVmExitAsm:
    ;; ...save exit TSC
    ;; ...check exit reason
    ;; ...save generic state
    ;; ...call C part

    ;
    ; IMPORTANT: GS:[...] points to PCPU structure
    ;

    ; save RCX to temporary location
    mov     [GS:PCPU.TempRCX], rcx          ; PCPU.TempRCX <== guest RCX

    ; get VCPU pointer and update VCPU state
    mov     rcx, [GS:PCPU.Vcpu]             ; RCX = VCPU pointer

    ;
    ; save Vcpu->LastExitTsc
    ;
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RAX], rax
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RDX], rdx

    mov     rax, [GS:PCPU.TempRCX]
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RCX], rax

    mov     rax, QWORD CfgFeaturesVirtualizationMonitorGuestActivityStateChanges
    cmp     [rax], BYTE 1
    jne     .no_bypass

    mov     edx, VMCS_VM_EXIT_REASON
    vmread  rax, rdx
    cmp     eax, EXIT_REASON_HLT
    je      HvVmxHandleHltAsm

.no_bypass:
    mfence
    lfence
    rdtsc                                   ; time stamp counter is now read into EDX:EAX
    lfence

    shl     rdx, 32                         ; mov edx to high part of rdx
    or      rdx, rax                        ; EDX = full 64 bit TSC
    mov     [rcx + VCPU.LastExitTsc], rdx   ; Vcpu->LastExitTsc = TSC

    sub     rdx, [rcx + VCPU.LastEntryTsc]  ; LastExit (= now) - LastEntry = for how much time the guest ran before this exit
    mov     [rcx + VCPU.PrevInGuestTscDuration], rdx
    ;
    ; save GUEST x86/x64 ARCH registers NOT implicitly handled by VMCS
    ; RAX, CR2, RCX, RDX, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15, RFLAGS
    ;
    ;;;mov     [rcx + VCPU.ArchRegs + ARCHREGS.RAX], rax
    mov     rax, cr2
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.CR2], rax       ; CR2 of guest
    mov     rax, cr8
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.CR8], rax       ; CR8 of guest
    ;;;mov     [rcx + VCPU.ArchRegs + ARCHREGS.RDX], rdx
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RBX], rbx       ; RBX of guest
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RBP], rbp       ; RBP of guest
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RSI], rsi       ; ...
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.RDI], rdi
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R8], r8
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R9], r9
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R10], r10
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R11], r11
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R12], r12
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R13], r13
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R14], r14
    mov     [rcx + VCPU.ArchRegs + ARCHREGS.R15], r15

    push        rcx
    X64CALL     CpuSaveFloatingArea, rcx
    pop         rcx

    X64ABSCALL  QWORD [rcx + VCPU.GuestExitRoutine], rcx

    ;;; shall NEVER get here
    ; trigger a fault to see this rip if somehow we do get to this point
    xor rax, rax
    inc byte [rax]
    dec rax
    inc byte [rax]
    hlt


GuestHypercallStubx64:
    push rbp
    mov rbp, HC_VMCALL_MAGIC
    vmcall
    pop rbp
    ret
GuestHypercallStubEndx64:

[bits 32]
GuestHypercallStubx86:
    push ebp
    mov ebp, HC_VMCALL_MAGIC
    vmcall
    pop ebp
    ret
GuestHypercallStubEndx86: