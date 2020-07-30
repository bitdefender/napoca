;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%include "struct.nasm"


startenum 0
    enum UNW_FLAG.EHANDLER
    enum UNW_FLAG.UHANDLER
    enum UNW_FLAG.CHAININFO
stopenum

startenum 0
    enum UWOP_PUSH_NONVOL
    enum UWOP_ALLOC_LARGE
    enum UWOP_ALLOC_SMALL
    enum UWOP_SET_FPREG
    enum UWOP_SAVE_NONVOL
    enum UWOP_SAVE_NONVOL_FAR
    enum UWOP_SAVE_XMM128
    enum UWOP_SAVE_XMM128_FAR
    enum UWOP_PUSH_MACHFRAME
stopenum

startenum 0
    enum OPINFO.RAX
    enum OPINFO.RCX
    enum OPINFO.RDX
    enum OPINFO.RBX
    enum OPINFO.RSP
    enum OPINFO.RBP
    enum OPINFO.RSI
    enum OPINFO.RDI
    enum OPINFO.R8
    enum OPINFO.R9
    enum OPINFO.R10
    enum OPINFO.R11
    enum OPINFO.R12
    enum OPINFO.R13
    enum OPINFO.R14
    enum OPINFO.R15
stopenum

startenum 0
    enum ExceptionContinueExecution
    enum ExceptionContinueSearch
    enum ExceptionNestedException
    enum ExceptionCollidedUnwin
stopenum

_struc RUNTIME_FUNCTION
    DWORD (FunctionStartRva)
    DWORD (FunctionEndRva)
    DWORD (FunctionUnwindInfoRva)
_endstruc

_struc UNWIND_INFO
    BYTE (VersionAndFlags)
    BYTE (SizeOfProlog)
    BYTE (CountOfUnwindCodes)
    BYTE (FrameRegisterAndOffset)
    VOID (UnwindCodesArray)
_endstruc

_struc UNWIND_HANDLER
    DWORD (HandlerRva)
    VOID  (CustomHandlerData)
_endstruc

_struct UNWIND_CODE
    BYTE (OffsetInProlog)
    BYTE (UnwindOperationCodeAndInfo)
_endstruc

%macro _PUSHREG_HELPER_ 1
    %ifdef __YASM_MAJOR__
            [pushreg %1]
        %else
            %%currentRip:
            [section .xdata rdata use64 align=8]
            _istruc %%unwind_code, UNWIND_CODE
                _at OffsetInProlog,             db %%currentRip - %$$begin  ; %%current refers the orig section (allowing delta calculation)
                _at UnwindOperationCodeAndInfo, db ((OPINFO.%1 * 16) + UWOP_PUSH_NONVOL)
            _endstruc
            __SECT__
        %endif
%endmacro

%macro PUSHREGS 1-*
    %rep %0
        push %1
        %rotate 1
    %endrep

    %rep %0
        %rotate -1
        _PUSHREG_HELPER_ %1

        %assign %$total_codes %$total_codes + 1
    %endrep
%endmacro

%macro POPREGS 1-*
    %rep %0
        %rotate -1
        pop %1
    %endrep
%endmacro

%macro SEH 0-1  ; the opt argument is a label to the handler routine
    %push SEH

    %assign %$total_codes 0
    %if %0
        %xdefine %$HANDLER %1
    %endif

    %$begin:
    [section .pdata rdata use64 align=4]
        ; can't use "_istruc %%runtime_function, RUNTIME_FUNCTION" as any .pdata symbol/label breaks the link...
        dd      %$begin wrt ..imagebase
        dd      %$end wrt ..imagebase
        dd      %%unwind_info wrt ..imagebase

    [section .xdata rdata use64 align=8]
        _istruc %%unwind_info, UNWIND_INFO
            _at VersionAndFlags,        db (UNW_FLAG.EHANDLER << 3 | 1)
            _at SizeOfProlog,           db %$$prolog_end - %$$begin
            _at CountOfUnwindCodes,     db %$$final_total_codes_value
            _at FrameRegisterAndOffset, db %$$frame_and_offset_value
        _iend
        ; the structure is left "open" for adding unwind codes
    __SECT__
%endmacro

%macro PROLOG 0
    ; nothing to do, added only for ensuring proper code structure
%endmacro

%macro ENDPROLOG 0
    %define %$HAS_PROLOG
    %ifdef __YASM_MAJOR__
        [endprolog]
    %else
        %$prolog_end:
        ; the 'Unwind codes array' needs to have an even number of entries (aka. alignment), not necessary reflected by the 'Count of unwind codes'
        %if %$total_codes % 2
            [section .xdata rdata use64 align=8]
                %%unwind_code_align: times sizeof(UNWIND_CODE) db 0
        %endif

        [section .xdata rdata use64 align=8]
            ; fill-in the 'Exception Handler' structure right affter the codes array
            _istruc %%unwind_handler, UNWIND_HANDLER
                %ifdef %$HANDLER
                    _at HandlerRva, dd %$HANDLER wrt ..imagebase
                %else
                    %ifndef SEH_INITIALIZED
                        %error "SEH_INSTANTIATE_DEFAULT_HANDLER macro was not called before needing the default exception handler"
                    %endif
                    _at HandlerRva, dd seh_pass_exception wrt ..imagebase
                %endif
            _iend
        __SECT__
    %endif
%endmacro

%macro ENDSEH 0
    %ifndef %$HAS_PROLOG
        %$prolog_end: ; hide the misterious error due to missing label and instead show a useful message
        %error "PROLOG and ENDPROLOG are mandatory (can't finalize the UNWIND_INFO structure otherwise)"
    %endif
    %$end:
    ; switch to a new segment and capture the value of the macro as a label to an absolute pos inside that segment
    [absolute %$total_codes]
        %$final_total_codes_value:

    %ifdef %$HAS_FRAME
        ; switch to a new segment and calculate&capture the value of FrameRegisterAndOffset as a label
        [absolute ((%$FRAME_POINTER_OFFSET * 16) + %+ OPINFO.%$FRAME_POINTER_REGISTER )]
    %else
        ; let the ignored value be linked to whatever $ value happens
    %endif
        [absolute 0]
            %$frame_and_offset_value:

    __SECT__
   %pop
%endmacro

%macro SEH_INSTANTIATE_DEFAULT_HANDLER 0
    %define SEH_INITIALIZED
    seh_pass_exception:
        mov rax, ExceptionContinueSearch    ; leave it unhandled (unwind and continue searching for a handler)
        ret 0                               ; STDCALL function with 4 register arguments
%endmacro