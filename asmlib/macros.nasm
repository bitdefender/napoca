;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _MACROS_YASM_
%define _MACROS_YASM_

%ifdef DOC_FILE
    macros.nasm - This file contains universal definitions which are generic enough to be useful for other projects too
%endif

%macro EMPTY_STATEMENT 0-*
%endmacro

%idefine                    sizeof(X) X %+ _size
%idefine                    nl 10

%idefine BIT(a)             (1<<a)
%idefine BIT(a,b)           BIT(a)|BIT(b)
%idefine BIT(a,b,c)         BIT(a)|BIT(b)|BIT(c)
%idefine BIT(a,b,c,d)       BIT(a)|BIT(b)|BIT(c)|BIT(d)


%imacro mpush    1-*
        %rep    %0
                push        %1
                %rotate     1
        %endrep
%endmacro

%imacro mpop     1-*
        %rep    %0
                %rotate     -1
                pop         %1
        %endrep
%endmacro

; some dummy decorators
%idefine __in
%idefine __ptr
%idefine __out
%idefine __in_opt
%idefine __out_opt
%idefine _PVOID
%idefine _POINTER
%idefine _BYTE
%idefine _PBYTE
%idefine _WORD
%idefine _PWORD
%idefine _DWORD
%idefine _PDWORD
%idefine _QWORD
%idefine _PQWORD
%idefine CX_UINT8
%idefine CX_UINT16
%idefine CX_UINT32
%idefine CX_UINT64
%idefine RETURNS            EMPTY_STATEMENT
%idefine PROC

%macro define 2
    %xdefine %1 %2
%endmacro

%define PARAM(N)            ebp + 8 + N*4
%define PARAM16(N)          bp + 4 + N*2

; handy parameter naming, procedure calling and stack parameter releasing
%imacro PROC32 1-*
    [bits 32]
    %1:
    %push procedure
    %define %$procName %1

    ; define an empty macro to allow ret PARAMS_SIZE to perform by default a simple ret
    %define PARAMS_SIZE
%endmacro

%imacro PARAMS32 1-*
    %ifctx procedure
    %else
        ; create a preprocesor context to separate local names between functions
        %push procedure
    %endif

    ; we'll sum the occupied stack space and number of parameters
    %assign %$index 0
    %assign %$params_size 0

    ; make sure a ret PARAMS_SIZE will actually free the parameters -> bound PARAMS_SIZE to %$params_size
    %define PARAMS_SIZE %$params_size

    ; take each parameter and define %$parameter for clean access
    %rep %0
        ; define %$name as ebp + current index - %$ makes the symbol visible only in current context (until the %pop at endproc)
        define %$ %+ %1, PARAM(%$index)
        %assign %$index %$index + 1
        ; get to the next param
        %rotate 1
        %assign %$params_size %$params_size + 4
    %endrep
%endmacro

%macro ENDPROC 0-*
    ; cleanup the temporary context
    %$procName %+ End:
    %pop
%endmacro

; push the parameters on stack in correct order and call a STDCALL function
%imacro STDCALL 1-*

    ; reverse-iterate all parameters except for the function name
    %rep %0 - 1
        %rotate -1              ; skip the name
        push DWORD %1
    %endrep

    ; get back the the proc. name
    %rotate -1
    call    %1
%endmacro



    ; handy parameter naming, procedure calling and stack parameter releasing
%imacro PROC16 1-*
    %1:
    [bits 16]
    %push procedure16
    %define %$procName %1

    ; define an empty macro to allow ret PARAMS_SIZE to perform by default a simple ret
    %define PARAMS_SIZE
%endmacro

%imacro PARAMS16 1-*
    %ifctx procedure16
    %else
    ; create a preprocesor context to separate local names between functions
        %push procedure16
    %endif

    ; we'll sum the occupied stack space and number of parameters
    %assign %$index 0
    %assign %$params_size 0

    ; make sure a ret PARAMS_SIZE will actually free the parameters -> bound PARAMS_SIZE to %$params_size
    %define PARAMS_SIZE %$params_size

    ; take each parameter and define %$parameter for clean access
    %rep %0
    ; define %$name as bp + current index - %$ makes the symbol visible only in current context (until the %pop at endproc)
        define %$ %+ %1, PARAM16(%$index)
        %assign %$index %$index + 1
    ; get to the next param
        %rotate 1
        %assign %$params_size %$params_size + 2
    %endrep
%endmacro

%macro ENDPROC16 0-*
    ; cleanup the temporary context
    %$procName %+ End:
    %pop
%endmacro

        ; push the parameters on stack in correct order and call a STDCALL function
%imacro RMCALL 1-*

        ; reverse-iterate all parameters except for the function name
    %rep %0 - 1
        %rotate -1              ; skip the name
        push WORD %1
    %endrep

        ; get back the the proc. name
    %rotate -1
    call    %1
%endmacro


%endif ; _MACROS_YASM_