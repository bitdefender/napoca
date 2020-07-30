;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _SYSTEM_YASM_
%define _SYSTEM_YASM_

%include "macros.nasm"
%include "if.nasm"
%include "struct.nasm"

%ifdef DOC_FILE
    system.nasm - Contains generic definitions of data types, data structures and macros for defining and interacting with hardware defined structures.
%endif

;
; generic constants
;
KILO                        equ 1024
MEGA                        equ KILO * KILO
GIGA                        equ KILO * MEGA
TERA                        equ KILO * GIGA

PAGE_SIZE                   equ 4096
PAGE_MASK                   equ (0xFFFFFFFF - 4095)
%idefine                    NULL 0


;
; system definitions
;
FLAT_DESCRIPTOR_CODE64      equ 0x002F9A000000FFFF                  ; Code: Execute/Read
FLAT_DESCRIPTOR_DATA64      equ 0x00CF92000000FFFF                  ; Data: Read/Write
FLAT_DESCRIPTOR_CODE32      equ 0x00CF9A000000FFFF                  ; Code: Execute/Read
FLAT_DESCRIPTOR_DATA32      equ 0x00CF92000000FFFF                  ; Data: Read/Write
FLAT_DESCRIPTOR_CODE16      equ 0x00009B000000FFFF                  ; Code: Execute/Read, accessed
FLAT_DESCRIPTOR_DATA16      equ 0x000093000000FFFF                  ; Data: Read/Write, accessed

RFLAGS_CF                   equ 1
RFLAGS_PF                   equ (1<<2)
RFLAGS_ZF                   equ (1<<6)
RFLAGS_SF                   equ (1<<7)
RFLAGS_TF                   equ (1<<8)
RFLAGS_IF                   equ (1<<9)
RFLAGS_DF                   equ (1<<10)
RFLAGS_OF                   equ (1<<11)
RFLAGS_IOPL                 equ (3<<12)
RFLAGS_NT                   equ (1<<14)
RFLAGS_RF                   equ (1<<16)
RFLAGS_VM                   equ (1<<17)
RFLAGS_ID                   equ (1<<21)

IA32_EFER                   equ 0xC0000080
IA32_EFER_LME               equ 0x100
IA32_EFER_NXE               equ 0x800
IA32_MISC_ENABLE            equ 0x1A0

; paging access and rights for VA to PA translations
VA_PRESENT                  equ bit(0)
VA_WRITE_ACCESS             equ bit(1)
VA_USER_ACCESS              equ bit(2)
VA_WRITETHROUGH             equ bit(3)
VA_CACHE_DISABLE            equ bit(4)
VA_ACCESSED                 equ bit(5)
VA_DIRTY                    equ bit(6)
VA_PAGE_SIZE                equ bit(7)
VA_GLOBAL                   equ bit(8)
VA_MASK                     equ 0x1FF

; CPUID bits
CPUID_LEAF_1_XSAVE_ENABLED  equ 26

; MEM-MAP
MEM_TYPE_AVAILABLE          equ 1                                       ; RAM usable by the operating system
MEM_TYPE_RESERVED           equ 2                                       ; reserved by the system
MEM_TYPE_ACPI_RECLAIM       equ 3                                       ; available RAM usable by the OS after it reads the ACPI tables
MEM_TYPE_ACPI_NVS           equ 4                                       ; reserved, required to be saved and restored across an NVS sleep
MEM_TYPE_UNUSABLE           equ 5                                       ; range must not be used by OSPM
MEM_TYPE_DISABLED           equ 6                                       ; memory that is not enabled

MEM_ATTR_NON_VOLATILE       equ 1                                       ; permananent memory, avoid use as RAM
MEM_ATTR_SLOW_ACCESS        equ 2                                       ; may incur considerable latencies
MEM_ATTR_ERROR_LOG          equ 3                                       ; memory used for logging hardware errors

_struc MEM_MAP_ENTRY_RAW
    QWORD                   (BaseAddress)
    QWORD                   (Length)
    DWORD                   (Type)                                      ; MEM_TYPE..
    DWORD                   (Attributes)                                ; MEM_ATTR..
_endstruc

_struc MEM_MAP_ENTRY
    ;;;DWORD                   (StructureSize)                             ; how much space do the other fields occupy
    QWORD                   (BaseAddress)
    QWORD                   (Length)
    DWORD                   (Type)                                      ; MEM_TYPE..
    DWORD                   (Attributes)                                ; MEM_ATTR..
_endstruc

; registers saved on stack by PUSHA
_struc PUSHA16
    WORD                    (Di)
    WORD                    (Si)
    WORD                    (Bp)
    WORD                    (Sp)
    WORD                    (Bx)
    WORD                    (Dx)
    WORD                    (Cx)
    WORD                    (Ax)
_endstruc

_struc PUSHA32
    DWORD                   (Edi)
    DWORD                   (Esi)
    DWORD                   (Ebp)
    DWORD                   (Esp)
    DWORD                   (Ebx)
    DWORD                   (Edx)
    DWORD                   (Ecx)
    DWORD                   (Eax)
_endstruc

_struc PUSHA64
    QWORD                   (r15)
    QWORD                   (r14)
    QWORD                   (r13)
    QWORD                   (r12)
    QWORD                   (r11)
    QWORD                   (r10)
    QWORD                   (r9)
    QWORD                   (r8)
    QWORD                   (rsi)
    QWORD                   (rdi)
    QWORD                   (rdx)
    QWORD                   (rcx)
    QWORD                   (rbx)
    QWORD                   (rax)
_endstruc

startenum 0, CR0
    enumbit PE, MP, EM, TS, ET, NE
    enumpos 16
    enumbit WP
    enumpos 18
    enumbit AM
    enumpos 29
    enumbit NW, CD, PG
stopenum

startenum 0, XCR0
    enumbit X87, SSE, AVX, BNDREG, BNDCSR, OPMASK, ZMM_HI256, HI16_ZMM
    enumpos 9
    enumbit PKRU
    enumpos 11
    enumbit CET_USER_STATE, CET_SUPERVISOR_STATE
    enumbit XAAD
stopenum

startenum 0, CR4
    enumbit VME, PVI, TSD, DE, PSE, PAE, MCE, PGE, PCE, OSFXSR, OSXMMEXCPT
    enumpos 13
    enumbit VMXE, SMXE
    enumpos 16
    enumbit FSGSBASE, PCIDE, OSXSAVE
    enumpos 20
    enumbit SMAP, PKE
stopenum

startenum 0, IA32_MISC_ENABLE
    enumbit FAST_STRINGS
    enumpos 3
    enumbit AUTO_THERMAL_CONTROL
    enumpos 7
    enumbit PERF_MON
    enumpos 16
    enumbit ENHANCED_SPEEDSTEP
    enumpos 18
    enumbit MONITOR
    enumpos 22
    enumbit LIMIT_CPUID
    enumpos 34
    enumbit XD_DISABLE
stopenum

%ifdef DOC_METHOD
    Pushes all x64 general purpose registers onto the stack
%endif
%macro pusha64 0
    mpush   rax,rbx,rcx,rdx,rdi,rsi,r8,r9,r10,r11,r12,r13,r14,r15
%endmacro

%ifdef DOC_METHOD
    Pops all x64 general purpose registers from the stack
%endif
%macro popa64 0
    mpop    rax,rbx,rcx,rdx,rdi,rsi,r8,r9,r10,r11,r12,r13,r14,r15
%endmacro

%ifdef DOC_METHOD
    CONFIGURE_IA32_MISC(set_mask, clear_mask) CONFIGURE_IA32_MISC Activate, Deactivate
%endif
%macro CONFIGURE_IA32_MISC 2
    mov ecx, IA32_MISC_ENABLE
    rdmsr

    %if (%1 & 0xFFFFFFFF)
        or eax, ((%1) & 0xFFFFFFFF)
    %endif
    %if (%1 >> 32)
        or edx, ((%1) >> 32)
    %endif

    %if (%2 & 0xFFFFFFFF)
        and eax, 0xFFFFFFFF - ((%2) & 0xFFFFFFFF)
    %endif
    %if (%2 >> 32)
        and edx, 0xFFFFFFFF - ((%2) >> 32)
    %endif

    wrmsr
%endmacro

%ifdef DOC_METHOD
    Enables IA32_EFER_NXE bit
    Eax is 0 on error
    Note: alters EAX, ECX, EDX and EFLAGS
%endif
%macro ENABLE_XD 0
    mov     eax, 0x80000001
    cpuid
    test    edx, 0x00100000
    if nz
        mov     ecx, IA32_EFER
        rdmsr
        or      eax, IA32_EFER_NXE
        wrmsr
        mov     al, 1
    else
        xor     eax, eax
    endif
%endmacro

%ifdef DOC_METHOD
    Set CR0.PG bit
%endif
%macro ENABLE_PAGING 0 ;
    mov     eax, cr0
    or      eax, CR0.PG
    mov     cr0, eax
%endmacro

%ifdef DOC_METHOD
    Clear CR0.PG bit
%endif
%macro DISABLE_PAGING 0
    mov     eax, cr0
    and     eax, 0xFFFFFFFF - CR0.PG
    mov     cr0, eax
%endmacro

%ifdef DOC_METHOD
    Set CR4.PAE bit
%endif
%macro ENABLE_PAE 0
    mov     eax, cr4
    or      eax, CR4.PAE
    mov     cr4, eax
%endmacro

%ifdef DOC_METHOD
    Clear CR4.PAE bit
%endif
%macro DISABLE_PAE 0
    mov     eax, cr4
    and     eax, 0xFFFFFFFF - CR4.PAE
    mov     cr4, eax
%endmacro

%ifdef DOC_METHOD
    Set IA32_EFER_LME bit
%endif
%macro ENABLE_LME 0 ;
    mov     ecx,    IA32_EFER           ; Read EFER MSR
    rdmsr
    or      eax,    IA32_EFER_LME       ; Set the LME bit in EFER
    wrmsr
%endmacro

%ifdef DOC_METHOD
    Clear IA32_EFER_LME bit
%endif
%macro DISABLE_LME 0 ;
    mov     ecx,    IA32_EFER           ; Read EFER MSR
    rdmsr
    and     eax,    ~IA32_EFER_LME      ; clear the LME bit
    wrmsr
%endmacro


%endif ; _SYSTEM_YASM_
