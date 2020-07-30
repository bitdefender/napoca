;------------------------------------------------------------------------------
;
; Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
;
;------------------------------------------------------------------------------

    .code

;------------------------------------------------------------------------------
; CONST VOID *
; EFIAPI
; CxMemScanXX (
;   IN      CONST VOID                *Buffer,
;   IN      UINTN                     Length,
;   IN      UINTXX                    Value
;   );
;------------------------------------------------------------------------------
CxMemScan8Basic64 PROC    USES    rdi
    mov     rdi, rcx
    mov     rcx, rdx
    mov     rax, r8
    repne   scasb
    lea     rax, [rdi - 1]
    cmovnz  rax, rcx                    ; set rax to 0 if not found
    ret
CxMemScan8Basic64 ENDP

CxMemScan16Basic64    PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    mov     rcx, rdx
    repne   scasw
    lea     rax, [rdi - 2]
    cmovnz  rax, rcx
    ret
CxMemScan16Basic64    ENDP


CxMemScan32Basic64    PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    mov     rcx, rdx
    repne   scasd
    lea     rax, [rdi - 4]
    cmovnz  rax, rcx
    ret
CxMemScan32Basic64    ENDP


CxMemScan64Basic64    PROC    USES    rdi
    mov     rdi, rcx
    mov     rax, r8
    mov     rcx, rdx
    repne   scasq
    lea     rax, [rdi - 8]
    cmovnz  rax, rcx
    ret
CxMemScan64Basic64    ENDP


END
