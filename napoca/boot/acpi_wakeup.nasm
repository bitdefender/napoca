;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

%include "system.nasm"
%include "loader_interface.nasm"


global gWakeupStart
global gWakeupEnd
global gWakeupData
global gWakeupPatchedInstruction
global GuestPscStub, GuestPscStubEnd

%define RVA(X)      X - gWakeupStart
%define SEL(X)      WakeupGdtTable %+ . %+ X - WakeupGdtTable


_struc WAKEUP_DATA
        QWORD       (FinalRsp)
        QWORD       (FinalPml4Pa)
        DWORD       (FinalCr4)
        DWORD       (FinalCr0)
        QWORD       (FinalEfer)
        QWORD       (EntryPoint64)
        DWORD       (ZoneSize)
        BYTE        (EntryFlags)
_endstruc

gWakeupStart:
[bits 16]

    cli
gWakeupPatchedInstruction:                  ; patched base of dynamically allocated wakeup region
    mov     edx,    0xFFFFFFFF              ; the C code must set the correct value before dropping the trampoline to lower memory

    ; init segment registers and find out the actual segment offset at where we were loaded
    mov     ebp,    edx
    ror     ebp,    4                       ; get [31:28] = offset, [28:0] = reserved, [15:0] = segment
    mov     ax,     bp                      ; ax = segment
    shr     ebp,    (32-4)                  ; bx = offset
    mov     ds,     ax
    mov     es,     ax
    mov     ss,     ax
    mov     fs,     ax
    mov     gs,     ax

    ;;
    ;; prepare stack
    ;;
    lea     esp,    [ebp + RVA(WakeupStackTop)]

    ;;
    ;; load PM descriptor table
    ;;
    lea     eax,    [edx + RVA(WakeupGdtTable)] ; linear address
    push    eax
    push    word    (WakeupGdtTable.end - WakeupGdtTable) - 1
    lgdt    [esp]                           ; esp as sp is not supported by the 16 bits addressing model
    add     sp,     6

    ;;
    ;; activate PM
    ;;
    mov     eax,    cr0
    or      eax,    1                       ; CR0.PE
    mov     cr0,    eax

    ;;
    ;; switch to 32 bits
    ;;
    mov     ax,     SEL(data32)
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax

    push    word SEL(code32)
    lea     eax,    [edx + RVA(.to32)]
    mov     [edx + RVA(.patch) + 2], eax    ; patch the 0xFFFFFFF to the correct value
    jmp     .patch                          ; clear cache to reflect change (not necessary)

.patch:
    jmp     dword SEL(code32) : 0xFFFFFFFF

.to32:
[bits 32]
    mov     ax,     SEL(data32)
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax

    ; fix stack and ebx = 'imagebase' address
    mov     ebp,    edx
    lea     esp,    [ebp + RVA(WakeupStackTop)]

    ;;
    ;; activate Ia32e compatibility mode (cr3/4/0)
    ;;
    lea     ebx,    [ebp + RVA(gWakeupData)]

    mov     eax,    [ebx + WAKEUP_DATA.FinalCr4]
    mov     cr4,    eax

    mov     eax,    [ebx + WAKEUP_DATA.FinalPml4Pa]
    mov     cr3,    eax

    mov     eax,    [ebx + WAKEUP_DATA.FinalEfer]
    mov     edx,    [ebx + WAKEUP_DATA.FinalEfer + 4]
    mov     ecx,    0xC0000080
    wrmsr

    mov     eax,    [ebx + WAKEUP_DATA.FinalCr0]
    mov     cr0,    eax


    ;;
    ;; switch to 64 bits
    ;;
    mov     ax,     SEL(data64)
    mov     ds,     ax
    mov     es,     ax
    mov     ss,     ax
    mov     fs,     ax
    mov     gs,     ax

    lea     eax,    [ebp + RVA(.to64)]
    push    dword SEL(code64)
    push    eax
    retf

.to64:
[bits 64]

    ;;
    ;; call C with final cr3 and rsp
    ;;
    mov     ebx,    ebx                     ; zero-down high part of rbx
    mov     rsp,    [rbx + WAKEUP_DATA.FinalRsp]

    mov     rax,    [rbx + WAKEUP_DATA.FinalPml4Pa]
    mov     cr3,    rax
    movzx   rcx,    byte [rbx + WAKEUP_DATA.EntryFlags]
    mov     rax,    [rbx + WAKEUP_DATA.EntryPoint64]
    X64ABSCALL rax

;;
;; Stack and PM descriptor table
;;
align 16
WakeupStack:    times(4) dq 0
WakeupStackTop:

WakeupGdtTable:
    .start:
    .null                   dq  0
    .code64                 dq  FLAT_DESCRIPTOR_CODE64
    .data64                 dq  FLAT_DESCRIPTOR_DATA64
    .code16                 dq  FLAT_DESCRIPTOR_CODE16
    .data16                 dq  FLAT_DESCRIPTOR_DATA16
    .code32                 dq  FLAT_DESCRIPTOR_CODE32
    .data32                 dq  FLAT_DESCRIPTOR_DATA32
    .end:

;;
;; C-interfacing gWakeupData data structure
;;
gWakeupData: times sizeof(WAKEUP_DATA) db 0
;_istruc gWakeupData, WAKEUP_DATA
;_endstruc

[bits 16]
;; no stack usage
;; only used before entering sleep
GuestPscStub:
    vmcall
    jmp GuestPscStub
GuestPscStubEnd:

gWakeupEnd:







;;
;; Unload at wakeup support
;;
global WakeupRunOriginalVector
global WakeupRunOriginalVectorEnd


WakeupRunOriginalVector:
; rcx  = original vector real-mode segment
; rdx  = original vector real-mode offset
; must be called in long mode at some <1MB address with identity mapping

%define RVA(X) (X - WakeupRunOriginalVector)
%define SEL(X) (. %+ X - .gdtTableStart)

        [bits 64]
        cli

        ; find the runtime base of our code
        call    .findRip
    .findRip:
        pop     rbp
        sub     rbp,    .findRip - WakeupRunOriginalVector

        ; setup a small stack for transitions (below 1MB)
        lea     rsp,    [rbp + RVA(.stackTop)]

        ; backup the segment and offset to keep the values ready for when we're in real mode
        mov     si,     cx
        mov     di,     dx

        ; prepare a new gdt with transition descriptors
        lea     rbx,    [rbp + RVA(.gdtBase)]       ; ptr to gdt base field
        lea     rax,    [rbp + RVA(.gdtTableStart)]
        mov     [rbx],  rax                         ; set the gdt base to its runtime value
        lgdt    [rbp + RVA(.gdt)]

        ; long mode to compatibility mode transition
        mov     rax,    SEL(code32)                 ; segment
        push    rax
        lea     rax,    [rbp + RVA(.to32)]
        push    rax                                 ; offset
        o64 retf

    .to32:
        [bits 32]
        ; compatibility mode to 32 bits protected mode without paging transition

        DISABLE_PAGING
        DISABLE_LME
        DISABLE_PAE

        ; load a real-mode compatible idt
        lidt    [ebp + RVA(.idt)]

        ; 32 bits to 16 bits protected mode
        mov     eax,    SEL(code16)
        push    eax
        lea     eax,    [ebp + RVA(.to16)]
        push    eax
        retf

    .to16:
        [bits 16]
        ; protected mode to real mode
        mov     ax,     SEL(data16)
        mov     ds,     ax
        mov     es,     ax
        mov     ss,     ax
        mov     fs,     ax
        mov     gs,     ax

        lea     ebx,    [ebp + RVA(.toRm)]
        mov     ax,     bx
        shr     ebx,    4                           ; / 16
        and     ax,     0xF                         ; % 16
        push    bx                                  ; real-mode segment
        push    ax                                  ; real-mode offset

        mov     eax,    cr0
        and     eax,    0xFFFFFFFF - (0x80000000 + 1)
        mov     cr0,    eax
        retf

    .toRm:
        ; call the old handler
        push    si
        push    di
        retf


    .idt:
        .idtLimit       dw  (4*256) - 1
        .idtBase        dq  0
    .gdt:
        .gdtLimit       dw  (.gdtTableEnd - .gdtTableStart) - 1
        .gdtBase        dq  0
    .gdtTableStart:
        .zero           dq 0
        .code32         dq FLAT_DESCRIPTOR_CODE32
        .code16         dq FLAT_DESCRIPTOR_CODE16
        .data16         dq FLAT_DESCRIPTOR_DATA16
     .gdtTableEnd:

     ; a very small stack for transitions
     .stackBase:        dq 0, 0, 0
     .stackTop:
WakeupRunOriginalVectorEnd: