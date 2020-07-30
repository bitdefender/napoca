;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%include "asmlib/struct.nasm"
%include "asmlib/system.nasm"
%include "asmlib/loader_interface.nasm"

[bits 64]
section .text


;;
;; public symbols
;;
EXTERN CpustateCaptureGuestState
EXTERN CpustateRestoreGuestState
EXTERN CpustateSetRIP
EXTERN CpustateSetRSP
EXTERN CpustateGetTrFromSecondaryGdt

global InterlockedCompareExchange32
global UefiGetRSP
global UartLock

global UefiToHypervisorTrampoline64
global UefiToHypervisorTrampoline64End

global UefiHandlersTable
global AsmHandlersTable
global AsmHandlersTableEnd

global AsmSendBufferToHv
global AsmHvBreak

global AsmException



UartLock dd 0


;;
;; data types
;;
struct EXTENDED_STATE
    RAW             (Unknown, 4096+63)
endstruct

%define CPU_STATE_BOOL BYTE
struct CPU_STATE
    CPU_STATE_BOOL  (IsStructureInitialized)
    QWORD           (Rax)
    QWORD           (Rbx)
    QWORD           (Rcx)
    QWORD           (Rdx)
    QWORD           (Rbp)
    QWORD           (Rsi)
    QWORD           (Rdi)
    QWORD           (R8)
    QWORD           (R9)
    QWORD           (R10)
    QWORD           (R11)
    QWORD           (R12)
    QWORD           (R13)
    QWORD           (R14)
    QWORD           (R15)
    CPU_STATE_BOOL  (UsingFakedTr)
    WORD            (Es)
    WORD            (Cs)
    WORD            (Ss)
    WORD            (Ds)
    WORD            (Fs)
    WORD            (Gs)
    WORD            (Ldtr)
    WORD            (Tr)
    QWORD           (LinkPointer)
    QWORD           (Ia32Debugctl)
    QWORD           (Ia32Pat)
    QWORD           (Ia32Efer)
    QWORD           (Ia32PerfGlobalCtrl)
    QWORD           (Pdpte0)
    QWORD           (Pdpte1)
    QWORD           (Pdpte2)
    QWORD           (Pdpte3)
    DWORD           (EsLimit)
    DWORD           (CsLimit)
    DWORD           (SsLimit)
    DWORD           (DsLimit)
    DWORD           (FsLimit)
    DWORD           (GsLimit)
    DWORD           (LdtrLimit)
    DWORD           (TrLimit)
    DWORD           (GdtrLimit)
    DWORD           (IdtrLimit)
    DWORD           (EsAccessRights)
    DWORD           (CsAccessRights)
    DWORD           (SsAccessRights)
    DWORD           (DsAccessRights)
    DWORD           (FsAccessRights)
    DWORD           (GsAccessRights)
    DWORD           (LdtrAccessRights)
    DWORD           (TrAccessRights)
    DWORD           (InterruptibilityState)
    DWORD           (ActivityState)
    DWORD           (SmBase)
    DWORD           (Ia32SysenterCs)
    DWORD           (VmxPreemptionTimerValue)
    QWORD           (Cr0)
    QWORD           (Cr2)
    QWORD           (Cr3)
    QWORD           (Cr4)
    QWORD           (Cr8)
    QWORD           (EsBase)
    QWORD           (CsBase)
    QWORD           (SsBase)
    QWORD           (DsBase)
    QWORD           (FsBase)
    QWORD           (GsBase)
    QWORD           (LdtrBase)
    QWORD           (TrBase)
    QWORD           (GdtrBase)
    QWORD           (IdtrBase)
    QWORD           (Dr7)
    QWORD           (Rsp)
    QWORD           (Rip)
    QWORD           (Rflags)
    QWORD           (PendingDebugExceptions)
    QWORD           (Ia32SysenterEsp)
    QWORD           (Ia32SysenterEip)
    QWORD           (Ia32KernelGsBase)

    QWORD           (Star)
    QWORD           (CStar)
    QWORD           (LStar)

    EXTENDED_STATE  (Extensions)
    DWORD           (LapicId)
endstruct

struct TRAMPOLINE_DATA
    QWORD           (ApicId)
    QWORD           (Cr3)
    QWORD           (StackTop)
    QWORD           (BootContextPa)
    QWORD           (HvEntryPointVa)
    QWORD           (CpuBootStateVa)
endstruct





;;
;; utility functions
;;
UefiGetRSP:
    mov     rax,            rsp
    add     rax,            (0x20 + 8)
    ret


InterlockedCompareExchange32:
    mov     eax, edx
    lock    cmpxchg [rcx], r8d  ; if eax == [rcx] r8 -> [rcx] else [rcx] -> eax
    ret



;;
;; Hv trampoline code
;;
UefiToHypervisorTrampoline64:
    ; rcx = TRAMPOLINE_DATA
    pushf
    cli
    push    rcx
    push    rdx
    push    r10
    push    r11
    push    r9


    mov     rdx,    rcx
    with rdx as TRAMPOLINE_DATA


    ;
    ; capture and prepare the extended cpu state needed by the HV
    ;
    mov     rcx,    [rdx.CpuBootStateVa]
    sub     rsp,    0x20
    call    CpustateCaptureGuestState ; rsp will need +20
    add     rsp,    0x20

    with rcx as CPU_STATE
    mov     [rcx.Rsp], rsp
    lea     rax,    [rel .virtualized]
    mov     [rcx.Rip], rax
    mov     eax,    [rdx.ApicId]
    mov     [rcx.LapicId], eax
    mov     BYTE[rcx.IsStructureInitialized], 1

    endwith rcx

    ;
    ; enter the HV
    ;
    mov     r11,    rsp
    mov     r10,    cr3

    mov     r9,     [rdx.HvEntryPointVa]
    mov     rcx,    [rdx.BootContextPa]

    ; switch to loader's (+HV) stack and VA space
    mov     rax,    [rdx.Cr3]
    mov     rsp,    [rdx.StackTop] ; no stack before changing cr3
    mov     cr3,    rax

    ; save old cr3 and rsp on the new (hv) stack
    push    r10
    push    r11

    X64ABSCALL_INIT64 r9

    ; exit point in case of cleanup/unload
.error:
    ; revert to old VA space and stack
    pop     r11
    pop     r10
    mov     cr3,    r10
    mov     rsp,    r11

    ; restore the extended state with .unloaded as rip
    push    rdx
    mov     rcx,    [rdx.CpuBootStateVa]
    lea     rdx,    [rel .unloaded]
    mov     [rcx + CPU_STATE.Rip], rdx
    pop     rdx

    sub     rsp,    0x20
    call    CpustateRestoreGuestState
    ; unreachable code...
    add     rsp,    0x20

    ; continuation after cpu state restauration

.unloaded:
    mov     rax,    1
    jmp     .done


    ; exit point when virtualized
.virtualized:
    xor     rax,    rax

    endwith rdx ; undefine rdx.* symbols

.done:

    pop     r9
    pop     r11
    pop     r10
    pop     rdx
    pop     rcx
    popf
    ret



UefiToHypervisorTrampoline64End:

;;
;; Debugging
;;

AsmSendBufferToHv:
    ; rcx = buffer, rdx = length
    pusha64

    mov     rax,    0xEF1EF1EF1EF1EF1E
    xor     rbx,    rbx
    cpuid

    popa64
    ret


AsmHvBreak:
    ; void
    pusha64

    mov     rax,    0xEF1EF1EF1EF1EF1E
    xor     rbx,    rbx
    inc     rbx
    cpuid

    popa64
    ret


AsmException:
    xor     rax,    rax
    div     rax
    ret






;;
;; Security version information (for preloader)
;;
[section VERSION]

    dd      1




