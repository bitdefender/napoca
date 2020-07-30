;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

[BITS 64]
%include "seh.nasm"


section .text


;
; HvVmcall(
;   SIZE_T MessageType, 
;   SIZE_T Param1, 
;   SIZE_T Param2, 
;   SIZE_T Param3, 
;   SIZE_T Param4, 
;   SIZE_T *OutParam1, 
;   SIZE_T *OutParam2, 
;   SIZE_T *OutParam3, 
;   SIZE_T *OutParam4)
;
SEH_INSTANTIATE_DEFAULT_HANDLER

global HvVmcall

HvVmcall:
SEH
    PUSHREGS    RBP, RBX, RDI, RSI
    ENDPROLOG

    .argdelta   equ 4*8 + 8 + 0x20     ; 4x8 bytes from 4xpushreg + 8 bytes return address + 0x20 for the "shadow store"

    mov rax, rcx    ; first arg
    mov rcx, rdx    ; second arg
    mov rdx, r8     ; third
    mov rsi, r9     ; 4th arg
    mov rdi, [rsp + .argdelta] ; 5th arg

    xor     rbx, rbx
    mov     ebx, 06C437648H
    vmcall

    mov     rbx, [rsp + .argdelta + 8]
    test    rbx, rbx
    jz      .skip_paramout1
    mov     [rbx],  rcx
.skip_paramout1:
    mov     rbx, [rsp + .argdelta + 8*2]
    test    rbx, rbx
    jz      .skip_paramout2
    mov     [rbx],  rdx
.skip_paramout2:
    mov     rbx, [rsp + .argdelta + 8*3]
    test    rbx, rbx
    jz      .skip_paramout3
    mov     [rbx],  rsi
.skip_paramout3:
    mov     rbx, [rsp + .argdelta + 8*4]
    test    rbx, rbx
    jz      .skip_paramout4
    mov     [rbx],  rdi
.skip_paramout4:

    POPREGS RBP, RBX, RDI, RSI
    ret
ENDSEH


global CpuGetSecCapabilities
CpuGetSecCapabilities:
    push    rbx

    mov     rbx, rcx    ; RBX capabilities index
    xor     rax, rax    ; RAX param for getsec - 0 = capabilities
    getsec

    pop     rbx
    ret