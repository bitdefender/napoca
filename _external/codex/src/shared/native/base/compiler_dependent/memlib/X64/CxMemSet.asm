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
;   SetMem.Asm
;
; Abstract:
;
;   SetMem function
;
; Notes:
;
;------------------------------------------------------------------------------

    .code

;------------------------------------------------------------------------------
;  VOID *
;  CxMemSetXX (
;    IN VOID   *Buffer,
;    IN UINTN  Count,
;    IN UINTXX  Value
;    )
;------------------------------------------------------------------------------

CxMemSet8Basic64   PROC    USES    rdi
    mov     rax, r8    ; rax = Value
    mov     rdi, rcx   ; rdi = Buffer
    xchg    rcx, rdx   ; rcx = Count, rdx = Buffer
    rep     stosb
    mov     rax, rdx   ; rax = Buffer
    ret
CxMemSet8Basic64   ENDP

CxMemSet16Basic64 PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    xchg    rcx, rdx
    rep     stosw
    mov     rax, rdx
    ret
CxMemSet16Basic64 ENDP

CxMemSet32Basic64 PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    xchg    rcx, rdx
    rep     stosd
    mov     rax, rdx
    ret
CxMemSet32Basic64 ENDP


CxMemSet64Basic64 PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    xchg    rcx, rdx
    rep     stosq
    mov     rax, rdx
    ret
CxMemSet64Basic64 ENDP


CxMemSet8Mmx64   PROC    USES    rdi
    mov     rax, r8
    mov     ah, al
    DB      48h, 0fh, 6eh, 0c0h         ; movd mm0, rax
    mov     r8, rcx
    mov     rdi, r8                     ; rdi <- Buffer
    mov     rcx, rdx
    and     edx, 7
    shr     rcx, 3
    jz      @SetBytes
    DB      0fh, 70h, 0C0h, 00h         ; pshufw mm0, mm0, 0h
@@:
    DB      0fh, 0e7h, 07h              ; movntq [rdi], mm0
    add     rdi, 8
    loop    @B
    mfence
@SetBytes:
    mov     ecx, edx
    rep     stosb
    mov     rax, r8
    ret
CxMemSet8Mmx64   ENDP

CxMemSet16Mmx64 PROC    USES    rdi
    mov     rax, r8
    DB      48h, 0fh, 6eh, 0c0h         ; movd mm0, rax
    mov     r8, rcx
    mov     rdi, r8
    mov     rcx, rdx
    and     edx, 3
    shr     rcx, 2
    jz      @SetWords
    DB      0fh, 70h, 0C0h, 00h         ; pshufw mm0, mm0, 0h
@@:
    DB      0fh, 0e7h, 07h              ; movntq [rdi], mm0
    add     rdi, 8
    loop    @B
    mfence
@SetWords:
    mov     ecx, edx
    rep     stosw
    mov     rax, r8
    ret
CxMemSet16Mmx64 ENDP

CxMemSet32Mmx64 PROC
    DB      49h, 0fh, 6eh, 0c0h         ; movd mm0, r8 (Value)
    mov     rax, rcx                    ; rax <- Buffer
    xchg    rcx, rdx                    ; rcx <- Count  rdx <- Buffer
    shr     rcx, 1                      ; rcx <- # of qwords to set
    jz      @SetDwords
    DB      0fh, 70h, 0C0h, 44h         ; pshufw mm0, mm0, 44h
@@:
    DB      0fh, 0e7h, 02h              ; movntq [rdx], mm0
    lea     rdx, [rdx + 8]              ; use "lea" to avoid flag changes
    loop    @B
    mfence
@SetDwords:
    jnc     @F
    DB      0fh, 7eh, 02h               ; movd [rdx], mm0
@@:
    ret
CxMemSet32Mmx64 ENDP


CxMemSet64Mmx64 PROC
    DB      49h, 0fh, 6eh, 0c0h         ; movd mm0, r8 (Value)
    mov     rax, rcx                    ; rax <- Buffer
    xchg    rcx, rdx                    ; rcx <- Count
@@:
    DB      0fh, 0e7h, 02h              ; movntq  [rdx], mm0
    add     rdx, 8
    loop    @B
    mfence
    ret
CxMemSet64Mmx64 ENDP


CxMemSet8Sse264   PROC    USES    rdi
    mov     rdi, rcx                    ; rdi <- Buffer
    mov     al, r8b                     ; al <- Value
    mov     r9, rdi                     ; r9 <- Buffer as return value
    xor     rcx, rcx
    sub     rcx, rdi
    and     rcx, 15                     ; rcx + rdi aligns on 16-byte boundary
    jz      @F
    cmp     rcx, rdx
    cmova   rcx, rdx
    sub     rdx, rcx
    rep     stosb
@@:
    mov     rcx, rdx
    and     rdx, 15
    shr     rcx, 4
    jz      @SetBytes
    mov     ah, al                      ; ax <- Value repeats twice
    movdqa  [rsp + 10h], xmm0           ; save xmm0
    movd    xmm0, eax                   ; xmm0[0..16] <- Value repeats twice
    pshuflw xmm0, xmm0, 0               ; xmm0[0..63] <- Value repeats 8 times
    movlhps xmm0, xmm0                  ; xmm0 <- Value repeats 16 times
@@:
    movntdq [rdi], xmm0                 ; rdi should be 16-byte aligned
    add     rdi, 16
    loop    @B
    mfence
    movdqa  xmm0, [rsp + 10h]           ; restore xmm0
@SetBytes:
    mov     ecx, edx                    ; high 32 bits of rcx are always zero
    rep     stosb
    mov     rax, r9                     ; rax <- Return value
    ret
CxMemSet8Sse264   ENDP

CxMemSet16Sse264 PROC    USES    rdi
    mov     rdi, rcx
    mov     r9, rdi
    xor     rcx, rcx
    sub     rcx, rdi
    and     rcx, 15
    mov     rax, r8
    jz      @F
    shr     rcx, 1
    cmp     rcx, rdx
    cmova   rcx, rdx
    sub     rdx, rcx
    rep     stosw
@@:
    mov     rcx, rdx
    and     edx, 7
    shr     rcx, 3
    jz      @SetWords
    movd    xmm0, eax
    pshuflw xmm0, xmm0, 0
    movlhps xmm0, xmm0
@@:
    movntdq [rdi], xmm0
    add     rdi, 16
    loop    @B
    mfence
@SetWords:
    mov     ecx, edx
    rep     stosw
    mov     rax, r9
    ret
CxMemSet16Sse264 ENDP

CxMemSet32Sse264 PROC    USES    rdi
    mov     rdi, rcx
    mov     r9, rdi
    xor     rcx, rcx
    sub     rcx, rdi
    and     rcx, 15
    mov     rax, r8
    jz      @F
    shr     rcx, 2
    cmp     rcx, rdx
    cmova   rcx, rdx
    sub     rdx, rcx
    rep     stosd
@@:
    mov     rcx, rdx
    and     edx, 3
    shr     rcx, 2
    jz      @SetDwords
    movd    xmm0, eax
    pshufd  xmm0, xmm0, 0
@@:
    movntdq [rdi], xmm0
    add     rdi, 16
    loop    @B
    mfence
@SetDwords:
    mov     ecx, edx
    rep     stosd
    mov     rax, r9
    ret
CxMemSet32Sse264 ENDP


CxMemSet64Sse264 PROC
    mov     rax, rcx                    ; rax <- Buffer
    xchg    rcx, rdx                    ; rcx <- Count & rdx <- Buffer
    test    dl, 8
    movd    xmm0, r8
    jz      @F
    mov     [rdx], r8
    add     rdx, 8
    dec     rcx
@@:
    shr     rcx, 1
    jz      @SetQwords
    movlhps xmm0, xmm0
@@:
    movntdq [rdx], xmm0
    lea     rdx, [rdx + 16]
    loop    @B
    mfence
@SetQwords:
    jnc     @F
    mov     [rdx], r8
@@:
    ret
CxMemSet64Sse264 ENDP

END
