;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

[BITS 32]
;
;

section .text

global _HvVmcall
_HvVmcall:
    push ebp
    mov  ebp, esp

    push    esi
    push    ebx
    push    edi
    push    ebx

    mov eax, [ebp+8]
    mov ecx, [ebp+12]
    mov edx, [ebp+16]
    mov esi, [ebp+20]
    mov edi, [ebp+24]

    xor     ebx, ebx
    mov     ebx, 06C437648H
    vmcall

    mov ebx, dword [ebp+28]
    cmp ebx, 0
    jz skip_paramout1
    mov [ebx], ecx
skip_paramout1:
    mov ebx, dword [ebp+32]
    cmp ebx, 0
    jz skip_paramout2
    mov [ebx], edx
skip_paramout2:
    mov ebx, dword [ebp+36]
    cmp ebx, 0
    jz skip_paramout3
    mov [ebx], esi
skip_paramout3:
    mov ebx, dword [ebp+40]
    cmp ebx, 0
    jz skip_paramout4
    mov [ebx], edi
skip_paramout4:

    pop     ebx
    pop     edi
    pop     ebx
    pop     esi

    mov esp,ebp
    pop ebp
    ret


global _CpuGetSecCapabilities
_CpuGetSecCapabilities:
    push    ebx

    mov     ebx, [esp + 08h]    ; RBX capabilities index
    xor     eax, eax            ; RAX param for getsec - 0 = capabilities
    getsec

    pop     ebx
    ret
