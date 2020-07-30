;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
; Module Name:
;
;   ZeroMem.Asm
;
; Abstract:
;
;   ZeroMem function
;
; Notes:
;
;------------------------------------------------------------------------------

    .code

;------------------------------------------------------------------------------
;  VOID *
;  CxMemZero (
;    IN VOID   *Buffer,
;    IN UINTN  Count
;    );
;------------------------------------------------------------------------------
CxMemZeroBasic64  PROC    USES    rdi
    push    rcx
    xor     rax, rax
    mov     rdi, rcx
    mov     rcx, rdx
    shr     rcx, 3
    and     rdx, 7
    rep     stosq
    mov     ecx, edx
    rep     stosb
    pop     rax
    ret
CxMemZeroBasic64  ENDP

CxMemZeroMmx64  PROC    USES    rdi
    mov     rdi, rcx
    mov     rcx, rdx
    mov     r8, rdi
    and     edx, 7
    shr     rcx, 3
    jz      @ZeroBytes
    DB      0fh, 0efh, 0c0h             ; pxor mm0, mm0
@@:
    DB      0fh, 0e7h, 7                ; movntq [rdi], mm0
    add     rdi, 8
    loop    @B
    DB      0fh, 0aeh, 0f0h             ; mfence
@ZeroBytes:
    xor     eax, eax
    mov     ecx, edx
    rep     stosb
    mov     rax, r8
    ret
CxMemZeroMmx64  ENDP

CxMemZeroSse264  PROC    USES    rdi
    mov     rdi, rcx
    xor     rcx, rcx
    xor     eax, eax
    sub     rcx, rdi
    and     rcx, 15
    mov     r8, rdi
    jz      @F
    cmp     rcx, rdx
    cmova   rcx, rdx
    sub     rdx, rcx
    rep     stosb
@@:
    mov     rcx, rdx
    and     edx, 15
    shr     rcx, 4
    jz      @ZeroBytes
    pxor    xmm0, xmm0
@@:
    movntdq [rdi], xmm0                 ; rdi should be 16-byte aligned
    add     rdi, 16
    loop    @B
    mfence
@ZeroBytes:
    mov     ecx, edx
    rep     stosb
    mov     rax, r8
    ret
CxMemZeroSse264  ENDP

END
