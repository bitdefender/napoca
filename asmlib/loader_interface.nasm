;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _LOADER_INTERFACE_YASM_
%define _LOADER_INTERFACE_YASM_
%include "struct.nasm"

%ifdef DOC_FILE
    loader_interface.nasm - contains definitions for data structures, data definitions and generic macros
    used during the boot process of the HV.
%endif

%ifndef _SYSTEM_YASM_
KILO equ 1024
MEGA equ 1024 * KILO

_struc MEM_MAP_ENTRY
    QWORD                   (BaseAddress)
    QWORD                   (Length)
    DWORD                   (Type)                                      ; MEM_TYPE..
    DWORD                   (Attributes)                                ; MEM_ATTR..
_endstruc

%endif

; memory usage/layout
PXE_BASE                    equ 2*MEGA
STACK_SIZE                  equ 16*KILO                 ; MEGA
TEMP_BUFFER_SIZE            equ 64*MEGA                 ; memory reserved for boot time when loaded by standard PXE
MEMORY_MAP_MAX_ENTRIES      equ 2048


; napoca boot definitions

; see the "BOOT_MODE" C-enum
startenum 0
    enum BOOT_MODE_UNKNOWN
    enum BOOT_MODE_LEGACY
    enum BOOT_MODE_LEGACY_PXE
    enum BOOT_MODE_UEFI
    enum BOOT_MODE_UEFI_PXE
stopenum

; cpuid definitions
CPUID_ECX_VMX               equ 1 << 5
CPUID_ECX_HYPERVISOR        equ 1 << 31

;;; always keep synchronized the definitions found here, in loader_interface.h and the array of names (ModuleInformation in loader_interface.c)
startenum 0
    enum LD_MODID_INVALID                                               ; this is not a valid module entry
    enum LD_MODID_BOOT_CONTEXT                                          ; specifies where the data sent to Init64 is located
    enum LD_MODID_NAPOCA_IMAGE                                          ; describes the area occupied by the kernel
    enum LD_MODID_NAPOCA_STACK                                          ; describes the area occupied by the kernel stack, optional if the stack is part of another persistent module
    enum LD_MODID_MEMORY_MAP                                            ; E820-like memory map sent by a loader
    enum LD_MODID_HVMEMORY_MAP                                          ; hypervisor memory prepared/allocated by the loader
    enum LD_MODID_COMMAND_LINE                                          ; string sent by some loader
    enum LD_MODID_FREE_MEMORY                                           ; mem. free for any use by the HV -- will alloc. any necessary mem for uninitialized modules from here
    enum LD_MODID_INTRO_EXCEPTIONS                                      ; exceptions module for introspection
    enum LD_MODID_INTRO_CORE                                            ; introspection engine
    enum LD_MODID_INTRO_LIVE_UPDATE,                                    ; intro_live_update.bin module for introspection

    ; necessary if the loader doesn't prepare memory for all uninitialized memory modules, must cover all the memory requirements
    ; for allocating all missing modules
    enum LD_MODID_ORIG_MBR                                              ; mbr belonging to primary os, prepared by our loader
    enum LD_MODID_LOADER_CUSTOM
    ; modules that are automatically allocated (LD_MODID_FREE_MEMORY) unless prepared/sent by our loader
    enum LD_MODID_BOOT_STATE                                            ; captured state of the hardware resources before loading the HV (gBootState)
    enum LD_MODID_NVS                                                   ; memory buffer for reading and writing data persistent over hibernate

    ; HV-internal modules, a loader shouldn't set these modules
    enum LD_MODID_FEEDBACK                                              ; logs
    enum LD_MODID_MBR_SETTINGS,                                         ; loader module containing settings for the MBR/PXE boot loader
    enum MAX_MODULES
stopenum




LD_MODFLAG_EARLYBOOT        equ 1                                       ; this module should be available only at napoca entry point, won't be mapped and kept in mem after changing the boot VA space
LD_MODFLAG_PHASE1           equ 2                                       ; module memory (PA + VA) should be available throughout all phase1
LD_MODFLAG_PHASE2           equ 4                                       ; module memory (PA + VA) should be available throughout all phase2
LD_MODFLAG_PERMANENT        equ 8                                       ; module memory (PA + VA) should be ALWAYS available, even after the guests are up&running

MAX_MODULE_ID               equ MAX_MODULES - 1                         ; highest index module allocated
MODULE_ENTRIES              equ MAX_MODULE_ID + 1                       ; total number of array entries


; modules that are automatically allocated (LD_MODID_FREE_MEMORY) unless prepared/sent by our loader
;LD_MODID_BOOT_STATE            equ 6                                       ; captured state of the hardware resources before loading the HV (gBootState)
                                                                        ; MIGHT NEED replacing static sub-structures with pointers and defining more module types



_struc BOOT_MODULE
    QWORD                   (Va)                                        ; where is this region mapped in VA space
    QWORD                   (Pa)                                        ; where's the PA range
    DWORD                   (Size)                                      ; size in bytes
    DWORD                   (Flags)                                     ; generic information about the module
_endstruc

_struc MEM_BUFFER
    QWORD                   (Va)
    QWORD                   (Pa)
    QWORD                   (Length)                                    ; total size
    QWORD                   (NextFreeAddress)                           ; VA of where the next free block starts
_endstruc

_struc TABLE_DESCRIPTOR64
    WORD                    (Limit)
    QWORD                   (Base)
_endstruc

; global structure shared with later code
_struc BOOT_CONTEXT
    DWORD                   (BootMode)                                  ; the good old boot mode
    DWORD                   (GuestArch)                                 ; x86 or x64 guest
    QWORD                   (Modules)                                   ; NAPOCA_MODULE *Modules (below 4GB)
    QWORD                   (ModulesPa)                                 ; base PA of modules array
    DWORD                   (NumberOfModules)
    DWORD                   (NumberOfLoaderCpus)                        ; how many ACTIVE cpu's were there at load time
    QWORD                   (OriginalStackTop)                          ; OPTIONAL, default 0
    QWORD                   (Cr3)                                       ; base PA of page tables root
    QWORD                   (Cr4)
    QWORD                   (Cr0)
    QWORD                   (Cr8)

    TABLE_DESCRIPTOR64      (Gdt)
    TABLE_DESCRIPTOR64      (Idt)

    QWORD                   (Rax)
    QWORD                   (Rbx)
    QWORD                   (Rcx)
    QWORD                   (Rdx)
    QWORD                   (Rsi)
    QWORD                   (Rdi)
    QWORD                   (Rbp)
    QWORD                   (Rsp)
    QWORD                   (R8)
    QWORD                   (R9)
    QWORD                   (R10)
    QWORD                   (R11)
    QWORD                   (R12)
    QWORD                   (R13)
    QWORD                   (R14)
    QWORD                   (R15)
    QWORD                   (RFlags)
    raw_align               (16)                                        ; make sure the structure is 16-bytes aligned as it is being allocated from the stack
    RAW                     (CAlign, 32)                                ; additional data to actually align the structure (C is unable to align without wasting mem)
_endstruc


startenum 0, MAP_TYPE
    enum MEMORY_MAP_TYPE_E820
    enum LD_MEMORY_MAP_TYPE_EFI
stopenum

; CUSTOM data structure sent by our loader(s)
_struc CUSTOM_BOOT_INFO
    DWORD                   (Signature)
    MEM_BUFFER              (TempMem)                                   ; range of (protected) memory useful during napoca initialization
    DWORD                   (NumberOfModules)
    QWORD                   (Modules)                                   ; BOOT_MODULE *Modules (below 4GB)
_endstruc


_struc MEMORY_MAP
    DWORD                   (MapType)
    DWORD                   (NumberOfEntries)
    RAW                     (Entries, sizeof(MEM_MAP_ENTRY) * MEMORY_MAP_MAX_ENTRIES)
_endstruc


_struc MULTIBOOT_DEVICE
    BYTE                    (Part3)
    BYTE                    (Part2)
    BYTE                    (Part1)
    BYTE                    (Drive)
_endstruc

_struc LD_LEGACY_CUSTOM
    DWORD                   (BootMode)
    MULTIBOOT_DEVICE        (BiosOsDrive)
_endstruc

_struc LD_CONFIGURATION_OPTIONS
    BYTE                    (RecoveryEnabled)
    BYTE                    (GrubBoot)
_endstruc

; context manipulation macros
%macro RESTORE_CONTEXT 0
    ; this macro assumes RCX to point to the boot context structure containing the right context
    ; to be restored on current CPU and RDX
        push    QWORD       [rcx + BOOT_CONTEXT.RFlags]
        popf
        cli
        mov     rbx,        [rcx + BOOT_CONTEXT.Rbx]
        mov     rdx,        [rcx + BOOT_CONTEXT.Rdx]
        mov     rsi,        [rcx + BOOT_CONTEXT.Rsi]
        mov     rdi,        [rcx + BOOT_CONTEXT.Rdi]
        mov     rbp,        [rcx + BOOT_CONTEXT.Rbp]
        mov     r8,         [rcx + BOOT_CONTEXT.R8]
        mov     r9,         [rcx + BOOT_CONTEXT.R9]
        mov     r10,        [rcx + BOOT_CONTEXT.R10]
        mov     r11,        [rcx + BOOT_CONTEXT.R11]
        mov     r12,        [rcx + BOOT_CONTEXT.R12]
        mov     r13,        [rcx + BOOT_CONTEXT.R13]
        mov     r14,        [rcx + BOOT_CONTEXT.R14]
        mov     r15,        [rcx + BOOT_CONTEXT.R15]
        mov     rax,        [rcx + BOOT_CONTEXT.Cr3]
        mov     cr3,        rax
        mov     rax,        [rcx + BOOT_CONTEXT.Cr4]
        mov     cr4,        rax
        mov     rax,        [rcx + BOOT_CONTEXT.Cr0]
        mov     cr0,        rax
        mov     rax,        [rcx + BOOT_CONTEXT.Cr8]
        mov     cr8,        rax
        lidt    [rcx + BOOT_CONTEXT.Idt]
        lgdt    [rcx + BOOT_CONTEXT.Gdt]

        mov     rax,        [rcx + BOOT_CONTEXT.Rax]

        ; get the stack pointer back to the return address
        mov     rsp,        [rcx + BOOT_CONTEXT.Rsp]
        sub     rsp,        8   ; assume we have the return address as the next thing on stack

        ret 0x20 + sizeof(BOOT_CONTEXT)
%endmacro

%macro CAPTURE_CONTEXT 0
    ; this macro assumes RCX to point to the boot context structure where the current
    ; CPU context should be saved
    ; MUST BE CALLED RIGHT BEFORE THE ACTUAL CALL TO INIT64

        ; local alloc a new BOOT_CONTEXT structure
        sub     rsp,    sizeof(BOOT_CONTEXT)

        ; save registers used for initializing (copy) a new BOOT_CONTEXT structure
        push    rdi
        push    rsi
        pushf

        lea     rdi,    [rsp + 3*8]
        mov     rsi,    rcx
        mov     rcx,    sizeof(BOOT_CONTEXT)
        push    rdi                                         ; ptr to the new BOOT_CONTEXT instance
        cld
        rep movsb

        ; restore the registers
        pop     rcx                                         ; ptr to the new BOOT_CONTEXT instance
        popf
        pop     rsi
        pop     rdi


        mov     [rcx + BOOT_CONTEXT.Rax],   rax
        mov     [rcx + BOOT_CONTEXT.Rbx],   rbx
        mov     [rcx + BOOT_CONTEXT.Rcx],   rcx
        mov     [rcx + BOOT_CONTEXT.Rdx],   rdx
        mov     [rcx + BOOT_CONTEXT.Rsi],   rsi
        mov     [rcx + BOOT_CONTEXT.Rdi],   rdi
        mov     [rcx + BOOT_CONTEXT.Rbp],   rbp
        mov     [rcx + BOOT_CONTEXT.R8],    r8
        mov     [rcx + BOOT_CONTEXT.R9],    r9
        mov     [rcx + BOOT_CONTEXT.R10],   r10
        mov     [rcx + BOOT_CONTEXT.R11],   r11
        mov     [rcx + BOOT_CONTEXT.R12],   r12
        mov     [rcx + BOOT_CONTEXT.R13],   r13
        mov     [rcx + BOOT_CONTEXT.R14],   r14
        mov     [rcx + BOOT_CONTEXT.R15],   r15

        mov     rax,    cr3
        mov     [rcx + BOOT_CONTEXT.Cr3],   rax
        mov     rax,    cr4
        mov     [rcx + BOOT_CONTEXT.Cr4],   rax
        mov     rax,    cr0
        mov     [rcx + BOOT_CONTEXT.Cr0],   rax
        mov     rax,    cr8
        mov     [rcx + BOOT_CONTEXT.Cr8],   rax

        mov     rax,    [rcx + BOOT_CONTEXT.Rax]
        sgdt    [rcx + BOOT_CONTEXT.Gdt]
        sidt    [rcx + BOOT_CONTEXT.Idt]

        ; the captured rsp will send us right at the end of the newly creaded home registers space
        pushf
        pop     QWORD [rcx + BOOT_CONTEXT.RFlags]
        sub     rsp,    0x20                                ; leave room for home registers (RESTORE_CONTEXT frees it)
        mov     [rcx + BOOT_CONTEXT.Rsp],   rsp
%endmacro

%macro  MOV_UNLESS_IDENTIC 2
        %ifnidni %1, %2
                mov     %1,     %2
        %endif
%endmacro



%imacro _X64CALL 1-*
; usage: X64CALL FunctionName, param, ...
; prepares params in rcx/rdx/r8/r9 and stack(right to left), calls FunctionName with rsp 16-byte aligned and then restores the old stack

        %push xcall

        %assign %$stackQNeeded (0x20 + 2*8)/8               ; leave room for rax and the alignment delta
        %if     %0 > 5
                %assign %$stackQNeeded %$stackQNeeded + (%0-5)
        %endif

        %assign %$rotations 0
        ;%error needed %$stackQNeeded -4 QWORDs for %0 -5 on-stack params

        ;
        ; first, prepare a rsp that allows us to get to call the function with an aligned stack
        ;

        push    rax                                         ; save rax
        mov     rax,    rsp
        and     rax,    15
        %if (%$stackQNeeded % 2) == 0
                add     rax,    8
        %endif
        sub     rsp,    rax
        push    rax                                         ; save the alignment delta
        lea     rax,    [rsp + rax + 8]                     ; get to the saved rax value
        mov     rax,    [rax]                               ; restore rax

        ; remember the function address (or its name)
        %xdefine %$function %1
        %rotate 1
        %assign %$rotations %$rotations + 1

        ; prepare params
        %if     %0>1
                MOV_UNLESS_IDENTIC  rcx,    %1
                %rotate             1
                %assign %$rotations %$rotations + 1
        %endif
        %if     %0>2
                MOV_UNLESS_IDENTIC  rdx,    %1
                %rotate             1
                %assign %$rotations %$rotations + 1
        %endif
        %if     %0>3
                MOV_UNLESS_IDENTIC  r8,     %1
                %rotate             1
                %assign %$rotations %$rotations + 1
        %endif
        %if     %0>4
                MOV_UNLESS_IDENTIC  r9,     %1
                %rotate             1
                %assign %$rotations %$rotations + 1
        %endif

        ; get the LAST parameter in %1
        %rotate -(%$rotations + 1)
        %assign %$rotations %$rotations + 1
        %if     %0 > 5
                %rep    %0 - 5
                        push        %1
                        %rotate     -1
                %endrep
        %endif

        sub     rsp,    0x20
        %ifdef _X64CALL_CAPTURE_CONTEXT
                CAPTURE_CONTEXT
        %endif
        %ifdef _X64CALL_USE_ABSOLUTE_CALLS
                call    %%getRip
                %%getRip:
                add     QWORD [rsp], %%ret - %%getRip
                push    QWORD %$function
                ret
               %%ret:
        %else
                call    %$function
        %endif

        add     rsp,    [rsp + %$stackQNeeded*8 - 16]       ; skip the alignment first
        add     rsp,    %$stackQNeeded*8                    ; home registers + the rax left on stack

        %pop ; remove 'xcall' from the preproc context stack
%endmacro

%imacro X64CALL 1+
    %ifdef _X64CALL_USE_ABSOLUTE_CALLS
            %undef _X64CALL_USE_ABSOLUTE_CALLS
    %endif
    _X64CALL %1
%endmacro

%imacro X64ABSCALL 1+
    %ifndef _X64CALL_USE_ABSOLUTE_CALLS
            %define _X64CALL_USE_ABSOLUTE_CALLS 1
    %endif
    _X64CALL %1
%endmacro

%macro X64CALL_INIT64 1+                                    ; rcx MUST contain the BOOT_CONTEXT structure when used
    ; capture context before the call
    %define _X64CALL_CAPTURE_CONTEXT 1
    X64CALL %1
    %undef _X64CALL_CAPTURE_CONTEXT
%endmacro

%macro X64ABSCALL_INIT64 1+                                 ; rcx MUST contain the BOOT_CONTEXT structure when used
    ; capture context before the call
    %define _X64CALL_CAPTURE_CONTEXT 1
    X64ABSCALL %1
    %undef _X64CALL_CAPTURE_CONTEXT
%endmacro

%endif ; _LOADERDEFS_YASM_

