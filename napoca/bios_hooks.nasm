;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

;
; Guest interrupt handlers/hooks, originally part of _init32.nasm
;

;
; Exported symbols
;

global __RealModeHookPre
global __RealModeHookPost
global __RealModeHookStubEnd


align 0x100
__RealModeHookPre:
vmcall
__RealModeHookPost:
vmcall
iret
__RealModeHookStubEnd:

