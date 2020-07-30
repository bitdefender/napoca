;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

global __security_check_cookie

extern __report_cookie_corruption
extern __security_cookie

[BITS 64]
align 0x10, db 0
__security_check_cookie:
    ; store rax
    cmp             rcx, [rel __security_cookie] ; yasm: [__security_cookie wrt rip]

    je              .end

    jmp             __report_cookie_corruption

    ; we should NOT return, we should UNLOAD
    ; this generates the 2 byte codification of the INT3 interrupt
    int             3

.end:
    ret
