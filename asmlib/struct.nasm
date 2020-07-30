;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _STRUCT_YASM_
%define _STRUCT_YASM_

%ifdef DOC_FILE
    struct.nasm - macro definitions for C-like syntax constructs such as struct, enum, sizeof, etc
%endif

%idefine sizeof(X) X %+ _size

; define one or more dynamically generated symbol name(s) with associated value(s)
%macro xdefine 2-*
    %rep %0/2                                               ; for each pair
        %xdefine %1 %2                                      ; actual definition
        %rotate 2                                           ; advance to next pair
    %endrep
%endmacro


; define a dynamically generated symbol as the result of a concatenation of two symbols to avoid early evaluation
%macro xconcat 3
    %xdefine %1 %2 %+ %3
%endmacro


%define _struct _struc
%define struct _struc
%define _endstruct _endstruc
%define endstruct _endstruc

%ifdef DOC_METHOD
    Structure definition start
%endif
%macro _struc 1
    %push struct                                            ; local context for temporary definitions that are discarded at _endstruc
    %assign %$pos 0                                         ; local variable to count the occupied bytes
    %xdefine %$name %1                                      ; remember the first param (the name of the defined structure type)
    %assign %$padding_cnt 0                                 ; a suffix for managing padding fields

    ; define standard member types available while inside structure definition
    %idefine byte(x)    members x, 1
    %idefine word(x)    members x, 2
    %idefine dword(x)   members x, 4
    %idefine qword(x)   members x, 8
    %idefine void(x)    members x, 0

    %idefine word_align     raw_align 2
    %idefine dword_align    raw_align 4
    %idefine qword_align    raw_align 8
    %idefine raw_align(x)   raw_align x
    %idefine align(x)       raw_align x

    %idefine byte(x,n)  members x, 1*n
    %idefine word(x,n)  members x, 2*n
    %idefine dword(x,n) members x, 4*n
    %idefine qword(x,n) members x, 8*n
%endmacro

%ifdef DOC_METHOD
    Structure definition end
%endif
%macro _endstruc 0
    xdefine %$name %+ _size, %$pos                          ; ..._size is defined as total occupied bytes (for compatibility with standart 'struct' macro)
    xdefine %$name %+ _members, {%$members}                 ; ..._members will remember how each member is defined (useful for structure instantiation)
    xdefine %$name(X), {substruct X, %$name}, {%$name(X,Y)}, {members X, Y}
                                                            ; STRUCT_NAME(name) will instantiate the substruct macro
                                                            ; STRUCT_NAME(name,count) will generate space for an array of n elements
    %pop                                                    ; free all temporary definitions that were used to keep track of members
    %undef byte
    %undef word
    %undef dword
    %undef qword
    %undef word_align
    %undef dword_align
    %undef qword_align
    %undef raw_align
    %undef align
    %undef void
%endmacro

%imacro raw_align 1                                         ; align current structure's pos to a given alignment value by adding a padding field
    %assign %$value %1

    %if %1 == 0
        %assign %$value 1
    %endif

    %if (%$pos % %$value) != 0
        %assign %$value %$value - (%$pos % %1)
        members align %+ %$padding_cnt, %$value
        %assign %$padding_cnt %$padding_cnt + 1
    %endif

    ;%error %$members
%endmacro

%ifdef DOC_METHOD
 Definine structure members: list of pairs (name, sizeof)
%endif
%macro members 2+
    %rep %0/2                                               ; for each pair
        xdefine %$name %+ . %+ %1, %$pos                    ; define name.member as pos
        %assign %$pos %$pos + %2                            ; advance pos
        %ifndef %$members
            %define %$members %1, %2                        ; consider the first pair (member, sizeof) as all members for now
        %else
            %xdefine %$tmp %$members                        ; use an intermediary variable to capture the current list of pairs
            %define %$members %$tmp, %1, %2                 ; append the new pair to the existing list
        %endif
        %rotate 2                                           ; get to the next pair
    %endrep
%endmacro


; RAW(name, bytes) will generate a member 'name' of size = 'bytes'
%idefine RAW(x,y) members x, y                              ; use the members macro to define a member named 'x' of 'y' bytes

; helper macro for 'substruct': generate sub-names and add to the current members list of pairs (name, size) each sub-member with its size
%macro generatemembers 3-*
    %xdefine %$substructure %1
    %rotate 1
    %rep (%0 - 1)/2
        members %$substructure %+ . %+ %1, %2
        %rotate 2
    %endrep
%endmacro

%ifdef DOC_METHOD
    sub-structure inside a structure: generates a .whole_structure definition for where it starts and then member names for each sub-member
    substruct substruct_name, struct_type
%endif
%macro substruct 2
    members %1, 0                                           ; generate a dummy member of size 0 for substruct_name
    generatemembers %1, %2 %+ _members                      ; generate sub-fields (named like substruct_name.field1, substruct_name.field2, ...)
%endmacro

%ifdef DOC_METHOD
    structure instantiation helper: label-like definitions for members
%endif
%macro GENLABELS 3-*
    %xdefine %$base %1                                      ; remember the base (similar to a global label for which sub-labels would be defined
    %assign %$index 0                                       ; how many bytes were emitted
    %rotate 1                                               ; skip the base part

    %rep (%0 - 1)/2                                         ; for each field's pair of (name, size)
        xdefine %$structstart %+ . %+ %1, (%$structstart + %$index)
                                                            ; define a global symbol base.subname equal to the address of this field (not just an offset inside structure)
        %assign %$index %$index + %2                        ; get to the next pair
        %rotate 2
    %endrep
%endmacro

%ifdef DOC_METHOD
    structure instantiasion
    _istruc variable_name, structure_type_name
%endif
%macro _istruc 2
    %push istruct                                           ; create a context for some local variables
    %define %$structname %2                                 ; remember the structure type
    %xdefine %$structstart %1                               ; remember the address (the '$' symbol) where the structure is being emitted
    %1:                                                     ; generate the actual label which will capture the current value of '$'
    GENLABELS %1, %{$structname}_members                    ; define each name.fieldname symbols as label + offset
%endmacro

; add optional padding until a given member position and then emit bytes for it
%imacro _at 2
    xdefine %$temp, %$structname %+ . %+ %1                 ; make
    times %$temp - ($-%$structstart) db 0
    %2
    %undef %$temp
%endmacro

%ifdef DOC_METHOD
    end of a structure instantiasion, this will set to 0 any remaining uninitialized field and free preproc definitions
%endif
%macro _iend 0
    times %{$structname}_size-($-%$structstart) db 0
    %pop                                                    ; destroy all temporary definitions
%endmacro

%ifdef DOC_METHOD
    generate symbols based on a counter optionally given as parameter or considered 0 in the beginning
%endif
%imacro startenum 0-2
    %push ENUM
    %if %0 >= 1
        %assign %$counter %1
    %else
        %assign %$counter 0
    %endif
    %if %0 >= 2
        %xdefine %$basename %2
    %endif
%endmacro

%imacro stopenum 0
    %ifnctx ENUM
        %error endenum without matchin enum
    %else
        %pop
    %endif
%endmacro

%imacro enum 1
    %ifnctx ENUM
        %error endenum without matchin enum
    %else
        %xdefine %1 %$counter
        %assign %$counter %$counter + 1
    %endif
%endmacro

%imacro enumpos 1
    %assign %$counter %1
%endmacro

%imacro enumbit 1-*
    %ifnctx ENUM
        %error endenum without matchin enum
    %else
        %rep %0
            %ifdef %$basename
                xdefine %$basename %+ . %+ %1, (1 << %$counter)
            %else
                %xdefine %1 (1 << %$counter)
            %endif
            %assign %$counter %$counter + 1
            %rotate 1
        %endrep
    %endif
%endmacro


%define as ,

%macro _with 3-*
    %define %$name %{1}.
    %define %$type %2
    %define %$delta %3
    %rotate 3

    %rep (%0-2)/2
        %define asijgfyojdlaskjasd (%$delta + %$type %+ . %+ %1)
        xconcat %$name %+ %1, asijgfyoj, dlaskjasd
        %rotate 2
    %endrep
%endmacro

%macro with 2-3 ; with rax, STR, delta
    %push with
    %if %0 == 2
        _with %1, %2, %1, %2 %+ _members
    %else
        _with %1, %2, %3, %2 %+ _members
    %endif
%endmacro

%macro unconcat 2
%undef %1%2
%endmacro

%macro _endwith 0-*
%rep %0/2
    unconcat %$name, %1
    %rotate 2
%endrep
%endmacro

%macro endwith 0-1
    %ifnctx with
        %error endwith without matching with!
    %else
        _endwith %$type %+ _members
        %pop
    %endif
%endmacro


%endif ; _STRUCT_YASM_


%ifdef DOC_FILE
Syntax example/use case of the defined macros
    _struc A
        word    (x)
        dword   (y)
    _endstruc

    _struc B
        word    (x)
        dword   (y)
        A       (a)
    _endstruc

    _struc C
        word    (x)
        dword   (y)
        B       (b)
    _endstruc

    _istruc structura, C
        _at x,      dw 1
        _at b.x,    dw 2
    _iend


    mov eax, [ebx + C.b.a.x]

    with eax as C
    mov [eax.b.x], ax   ; => mov [eax + field_offset], ax
    endwith eax

    with name as C, rbx + rdi
    mov [name.b.x], ax  ; => mov [rbx+rdi + field_offset], ax
    endwith name

    mov ecx, [structura.b.x]
    mov ecx, [structura.b.a.y]

%endif








