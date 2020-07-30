;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

%define EXCEPT_HAS_PCPU
%define EX_FPU_RESERVED_SIZE    2048
%define EX_FPU_REG_SIZE         128
%define EX_SAVE_XCR0            1
%define EX_PRESERVE_FPU_STATE   2
%define EX_ZERO_FPU_SAVE_AREA   1

%ifdef __YASM_MAJOR__
	%include "pcpu.nasm"
	%include "..\..\asmlib\except.nasm"
%else
	%include "kernel\pcpu.nasm"
	%include "except.nasm"
%endif
