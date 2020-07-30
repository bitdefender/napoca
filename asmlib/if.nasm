;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _IF_YASM_
%define _IF_YASM_

%ifdef DOC_FILE
    if.nasm - macro definitions for the if/ifnot/if equal macros.

    Example:
     ifnot zero(eax)
        ifnot zero(ebx)
            mov     BYTE [ebp], 1
        endif
    endif

    if equal(eax, 0)
        ifnot zero(ecx)
            dec ebp
        endif
    else
        inc ebp
    endif

%endif


%idefine equal(a, b)             z, cmp, a, b
%idefine different(a, b)         nz, cmp, a, b

%idefine above(x, y)             a, cmp, x, y
%idefine below(x, y)             b, cmp, x, y

%idefine greater(a, b)           g, cmp, a, b
%idefine less(a, b)              l, cmp, a, b

%idefine zero(v)                 z, cmp, v, 0

%idefine if(cond)                if cond
%idefine fi endif



%imacro if 1-4                  ; if flag or if condition involving equal / above / zero
    %push   if                  ; remember we're inside an if 'statement'
    %if     %0 == 4
        %2      %3, %4          ; emit an instruction to test the given condition
    %endif
    j%-1    %$skip              ; skip the if body if condition NOT met
%endmacro

%imacro ifnot 1-4               ; ifnot flag or ifnot condition involving equal / above / zero
    %push   if                  ; remember we're inside somekind of an if 'statement'
    %if     %0 == 4
        %2      %3, %4          ; emit an instruction to test the given condition
    %endif
    j%1     %$skip              ; skip the if body if condition is actually met
%endmacro

%imacro else 0
    %ifnctx if                  ; stop with error unless inside an if
        %error "else without matching if!"
    %endif

    jmp     %$end
    %$skip:                     ; emit the label needed for skipping the body
    %push   else                ; remember we're inside the else part of the statement
%endmacro

%imacro endif 0
    %ifctx else
        %pop                    ; the required skip label was already generated, just get out of the else
        %$end:
        %pop                    ; and out of the if
    %else
        %ifctx if
            %$skip:             ; emit the label and exit the if
            %pop
        %else
            %error "endif without matching if!"
        %endif
    %endif
%endmacro


%imacro do 0
    %push do                    ; remember we're inside a do-while statement
    %$start:                    ; label to repeating block
%endmacro

%imacro while 1+
    %ifctx do                   ; when inside a do-while
        %$continue:             ; a continue inside a do-while would land here
            if %1               ; test the while condition
                jmp %$$start     ; repeat the block
            endif
            %$break:            ; label for breaking outside of the do-while block
            %pop                ; here's where the repeating do-while block ends
    %else
        %push while             ; otherwise just consider we're inside a while-endwhile block
        %$continue:             ; label for continuing the loop (test & repeat here)
            ifnot %1
                jmp %$break     ; exit the repeating block when condition doesn't hold
            endif
    %endif
%endmacro

%imacro endwhile 0
    %ifnctx while
        %error "endwhile without matching while!"
    %else
        jmp %$continue          ; re-test condition and repeat if necessary
        %$break:                ; set the exit label here
    %endif
%endmacro

%imacro continue 0
    jmp %$continue              ; will err unless inside a statement with a %$continue label defined
%endmacro

%imacro break 0
    jmp %$stop                  ; will err unless inside a statement with a %$continue label defined
%endmacro

%endif
