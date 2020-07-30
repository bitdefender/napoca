;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

[section .BOOT code align=16]
section .BOOT
;
; PXE entry point, this MUST be generated at exactly RVA = 0x400 inside the resulted binary PE file
;


;
; RAUL / BOGDAN: decomentati definitia pt a putea boota linux (e hack pana se fixeaza in hv modul de generat EPT maps
;
;%define ABOVE_128MB_LINUX


; define the module offset for the loader (where will its code be generated as offset inside the PXE binary file)
%define ORIGIN_IN_FILE 0x400

; enforce a min address for the reserved memory
%define PXE32_RESERVE_MEM_ABOVE 128*MEGA

; include the loader code here (the pxe loader is outside of this project as it's used by multiple projects)
%include "pxe32.nasm"                      ; use one more ..\ then necessary, yasm command line gets a .\boot\file.nasm and yasm treats '.' as a real folder


section .text
global LdReturnToLoader

global LdTestRead

[bits 64]
LdReturnToLoader:
    RESTORE_CONTEXT
    hlt

LdTestRead:
        ret

global LdReadAlienQword
LdReadAlienQword:
    ; rcx = ptr
    ; rdx = cr3
    pushf
    cli

    push    r8
    mov     r8, cr3
    mov     cr3, rdx
    mov     rax, [rcx]
    mov     cr3, r8
    pop     r8
    popf
    ret




; sample warm reboot entry point code
LdRebootFromPxeEntry:
%define RMOFS(X) (X-LdRebootFromPxeEntry)

    [bits 16]
    mov     ax,     cs
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ax,     0xb800
    mov     gs,     ax
    mov     [gs:0], DWORD 'aAbB'
    cli
    hlt

    ; dummy stack over BDA 0x40:0x50 (8 words available) which contain screen cursor position info
    xor     ax,     ax
    mov     ss,     ax
    mov     esp,    0x458


    ; load a gdt and switch to 32 bits
    call    LdRebootFromPxeEntryGdt.getGdt

LdRebootFromPxeEntryGdt:
    .limit          dw  (.tableEnd - .tableStart) - 1
    .base           dd  0                           ; .tableStart

    .tableStart:
    .dscZero        dq 0
    .dscCode32      dq FLAT_DESCRIPTOR_CODE32
    .dscData32      dq FLAT_DESCRIPTOR_DATA32
    .dscCode64      dq FLAT_DESCRIPTOR_CODE64
    .dscData64      dq FLAT_DESCRIPTOR_DATA64
    .dscCode16      dq FLAT_DESCRIPTOR_CODE16
    .dscData16      dq FLAT_DESCRIPTOR_DATA16
    .dscBase32      dq FLAT_DESCRIPTOR_DATA32       ; patched to runtime image base
    .tableEnd:

.getGdt:
    ; get the linear base address (LdRebootFromPxeEntry) to ebp
    xor     eax,    eax
    pop     ax
    xor     ebp,    ebp
    mov     bp,     cs
    shl     ebp,    4
    lea     ebp,    [ebp + eax - RMOFS(LdRebootFromPxeEntryGdt)]

    ; set the .base value inside the gdt structure
    lea     eax,    [ebp + RMOFS(LdRebootFromPxeEntryGdt)]
    mov     [RMOFS(LdRebootFromPxeEntryGdt.base)], eax


    ; load the actual gdt table
    lgdt    [RMOFS(LdRebootFromPxeEntryGdt)]

    ; activate protection
    mov     eax,    cr0
    or      eax,    1
    mov     cr0,    eax

    ; switch to a 32-bit cs
    lea     eax,    [ebp + RMOFS(.code32)]
    mov     [RMOFS(.toPatch) + 2], eax

.toPatch:
    jmp     DWORD SEL_CODE32: 0

    [bits 32]
.code32:
    mov     [0xb8000], DWORD 'xxyy'
    cli
    hlt
LdRebootFromPxeEntryEnd:


; returns TRUE if NXE is supported and was successfully activated
global LdActivateNxe
LdActivateNxe:
    [bits 64]
    push    rdx
    push    rcx

    ENABLE_XD ; eax is non-zero if successful

    pop     rcx
    pop     rdx
    ret


;;
;; Security version information section (for EFI loader)
;;
[section VERSION]

    dd      1