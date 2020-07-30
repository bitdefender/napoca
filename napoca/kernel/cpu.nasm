;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

;
; APIC, CPU, FPU, SMP and VMX specific ASM routines
;

%include "loader_interface.nasm"
[bits 64]

; CX_VOID FpuSseInit();
global FpuSseInit
FpuSseInit:
    fninit
    ret

; CX_VOID CpuSetCS(_In_ CX_UINT16 Selector);
global CpuSetCS
CpuSetCS:
    xor     rax, rax
    mov     ax, cx
    push    rax
    call    .pushRip
.pushRip:
    add     qword [rsp], .done - .pushRip
    o64 retf
.done:
    ret

; CX_VOID CpuSetDS(_In_ CX_UINT16 Selector);
global CpuSetDS
CpuSetDS:
  mov ds,cx
  ret

; CX_VOID CpuSetES(_In_ CX_UINT16 Selector);
global CpuSetES
CpuSetES:
  mov es,cx
  ret

; CX_VOID CpuSetFS(_In_ CX_UINT16 Selector);
global CpuSetFS
CpuSetFS:
    mov fs, cx
    ret

; CX_VOID CpuSetGS(_In_ CX_UINT16 Selector);
global CpuSetGS
CpuSetGS:
    mov gs, cx
    ret

; CX_VOID CpuSetSS(_In_ CX_UINT16 Selector);
global CpuSetSS
CpuSetSS:
  mov ss,cx
  ret

; CX_VOID CpuSetTR(_In_ CX_UINT16 Selector);
global CpuSetTR
CpuSetTR:
    ltr     cx
    ret

; CX_UINT64 __stdcall CpuSetRSP(_In_ CX_UINT64 Rsp)
global CpuSetRSP
CpuSetRSP:
    mov     rax, rsp        ; return the old RSP address
    mov     rsp, rcx        ; set RSP
    jmp     qword [rax]     ; return execution

; CX_UINT16 CpuGetCS(CX_VOID);
global CpuGetCS
CpuGetCS:
    mov     ax, cs
    ret

; CX_UINT16 CpuGetDS(CX_VOID);
global CpuGetDS
CpuGetDS:
    mov ax, ds
    ret

; CX_UINT16 CpuGetES(CX_VOID);
global CpuGetES
CpuGetES:
    mov ax, es
    ret

; CX_UINT16 CpuGetFS(CX_VOID);
global CpuGetFS
CpuGetFS:
    mov ax, fs
    ret

; CX_UINT16 CpuGetGS(CX_VOID);
global CpuGetGS
CpuGetGS:
    mov ax, gs
    ret

; CX_UINT16 CpuGetSS(CX_VOID);
global CpuGetSS
CpuGetSS:
    mov ax, ss
    ret

; CX_UINT16 CpuGetTR(CX_VOID);
global CpuGetTR
CpuGetTR:
    str     ax
    ret

; CX_UINT64 CpuGetRIP(CX_VOID);
global CpuGetRIP
CpuGetRIP:
    mov     rax, [rsp]
    ret

; CX_UINT64 CpuGetRDI(CX_VOID);
global CpuGetRDI
CpuGetRDI:
    mov     rax, rdi
    ret

; CX_UINT64 __stdcall CpuGetRSP(CX_VOID);
global CpuGetRSP
CpuGetRSP:
    mov     rax, rsp
    add     rax, 8
    ret

; CX_STATUS CpuVmxInvVpid_(_In_ CX_UINT64 Type, _In_ CX_VOID *LinearAddress, _In_ CX_UINT64 Vpid );
global CpuVmxInvVpid_
CpuVmxInvVpid_:
    sub     rsp, 10h
    mov     [rsp], r8               ; 63..0 - Vpid
    mov     [rsp+8], rdx            ; 127..64 - LinearAddress
    mov     rdx, rsp                ; RDX = pointer to INVVPID descriptor (m128)
    invvpid rcx, [rdx] ; RCX = Type
    jbe     .fail
.success:
    xor     eax, eax
    add     rsp, 10h
    ret
.fail:
    mov     eax, 0C0000000h
    add     rsp, 10h
    ret

; CX_STATUS CpuVmxInvEptAsm(_In_ CX_UINT64 Type, _In_ INVEPT_DESCRIPTOR *InvEptDesc);
global CpuVmxInvEptAsm
CpuVmxInvEptAsm:
    invept rcx, [rdx]
    jbe     CpuVmxInvEptAsm__fail
CpuVmxInvEptAsm__success:
    xor     eax, eax
    jmp CpuVmxInvEptAsm__done

CpuVmxInvEptAsm__fail:
    mov     eax, 0C0000000h

CpuVmxInvEptAsm__done:
    ret

global CpuGetSecCapabilities
CpuGetSecCapabilities:
    push    rbx

    mov     rbx, rcx    ; RBX capabilities index
    xor     rax, rax    ; RAX param for getsec - 0 = capabilities
    getsec

    pop     rbx
    ret

global CpuGetsec
CpuGetsec:
    push    rbx

    mov     rbx, rcx    ; RBX capabilities index
    mov     rax, rdx    ; RAX param for getsec
    getsec

    pop     rbx
    ret

; CX_UINT32 __stdcall CpuGetPkru(CX_VOID);
global CpuGetPkru
CpuGetPkru:
    xor     ecx, ecx
    rdpkru
    retn

align 0x10, db 0xCC
; rax   CpuDiv128(           RCX,                        RDX,                         R8,                  R9)
; CX_UINT64 CpuDiv128(_In_ CX_UINT64 LowPartDividend, _In_ CX_UINT64 HighPartDividend, _In_ CX_UINT64 Divisor, _Out_ CX_UINT64 *Quotient)
global CpuDiv128
CpuDiv128:
    mov rax, rcx
    div r8                  ; rax <- rdx:rax / r8, rdx <- rdx:rax % r8

    mov [r9], rdx           ; save quotient

    ret

; CX_VOID CpuLockStore(_In_ CX_VOID *Destination, _In_ CX_VOID *Src, _In_ CX_UINT8 Size)
global CpuLockStore
CpuLockStore:

    cmp        r8b, 1
    jz         __access_byte
    cmp        r8b, 2
    jz         __access_word
    cmp        r8b, 4
    jz         __access_dword
    cmp        r8b, 8
    jz         __access_qword
    cmp        r8b, 16
    jz         __access_oword
    jmp        __access_default

__access_byte:
    mov        al, byte [rdx]
    lock        xchg byte [rcx], al
    jmp        __leave

__access_word:
    mov        ax, word [rdx]
    lock        xchg word [rcx], ax
    jmp        __leave

__access_dword:
    mov        eax, dword [rdx]
    lock xchg dword [rcx], eax
    jmp        __leave

__access_qword:
    mov         rax, qword [rdx]
    lock        xchg qword [rcx], rax
    jmp        __leave

__access_oword:
    test    rcx, 0Fh
    jnz        __access_oword_sse

    push    rax
    push    rdx
    push    rcx
    push    rbx
    push    rsi
    push    rdi

    mov        rsi, rcx
    mov        rdi, rdx

    ;
    ; We are guaranteed that no one will overwrite the current value in memory!!
    ;
    mov        rax, qword [rsi]
    mov        rdx, qword [rsi + 8]
    mov        rbx, qword [rdi]
    mov        rcx, qword [rdi + 8]

    lock       cmpxchg16b [rsi]

    pop        rdi
    pop        rsi
    pop        rbx
    pop        rcx
    pop        rdx
    pop        rax

    jmp        __leave

__access_oword_sse:
    ; Save xmm0, just in case...
    sub         rsp, 16
    movdqu      [rsp], xmm0
    movdqu      xmm0, [rdx]
    movdqu      [rcx], xmm0
    movdqu      xmm0, [rsp]
    add         rsp, 16

    jmp         __leave

__access_default:
    push        rsi
    push        rdi
    mov         rdi, rcx
    mov         rsi, rdx
    xor         rcx, rcx
    mov         cl, r8b
    rep         movsb
    pop         rdi
    pop         rsi

__leave:
    ret

global HardReset
HardReset:
    ; disable interrupts so we can change the IDT to an invalid one
    ; if we wouldn't disable interrupts => an interrupt could come after we set the IDT to 0
    ; and a triple fault in VMX root mode is bad :) - hang
    cli

    xor     rax, rax

    sub     rsp, sizeof(TABLE_DESCRIPTOR64)
    mov     [rsp + TABLE_DESCRIPTOR64.Limit], ax
    mov     [rsp + TABLE_DESCRIPTOR64.Base], rax
    lidt    [rsp]

    add     rsp, sizeof(TABLE_DESCRIPTOR64)

    ; exit VMX operation only after IDT is 0
    ; if we would do this with a valid IDT and we wouldn't be in root mode we would receive an
    ; #UD exception => we wouldn't reset due to a triple fault
    vmxoff

    ; actually cause the triple fault, if we get here we surely exited VMX mode and we have an
    ; IDT mapped at 0
    mov     cr3, rax

    ; Ensure that the machine resets. If the triple fault didn't produce (most likely paging is not active)
    ; reset the machine via 8042 keyboard controller
    mov     dx,     0x64
.again:
    in      al,     dx
    test    al,     2
    jnz     .again
    mov     al,     0xfe
    out     dx,     al
    cli
    hlt
