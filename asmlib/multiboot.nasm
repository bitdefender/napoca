;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%ifndef _MULTIBOOT_YASM_
%define _MULTIBOOT_YASM_
%include "struct.nasm"
%include "macros.nasm"

%ifdef DOC_FILE
    multiboot.nasm - contains the definition for the MULTIBOOT_INFO structure and related data types.
    Used during system boot.
%endif

_struc MULTIBOOT_HEADER
    dword                   (magic)
    dword                   (flags)
    dword                   (checksum)
    dword                   (header_addr)
    dword                   (load_addr)
    dword                   (load_end_addr)
    dword                   (bss_end_addr)
    dword                   (entry_addr)
    dword                   (mode_type)
    dword                   (width)
    dword                   (height)
    dword                   (depth)
_endstruc


MULTIBOOT_HEADER_SIZE       equ 48                                  ; check out '3.1.1 The layout of Multiboot header'
MULTIBOOT_HEADER_MAGIC      equ 0x1BADB002
MULTIBOOT_HEADER_FLAGS      equ MB_HEADERFLAG_PAGE_ALIGNED | MB_HEADERFLAG_MEM_MAP | MB_HEADERFLAG_FIXED_BASE
MULTIBOOT_LOADER_MAGIC      equ 0x2BADB002
MB_HEADERFLAG_PAGE_ALIGNED  equ bit(0)
MB_HEADERFLAG_MEM_MAP       equ bit(1)
MB_HEADERFLAG_FIXED_BASE    equ bit(16)


_struc MULTIBOOT_INFO
    DWORD                   (flags)             ; 0       | flags             |    (required)
                                                ;         +-------------------+
    DWORD                   (mem_lower)         ; 4       | mem_lower         |    (present if flags[0] is set)
    DWORD                   (mem_upper)         ; 8       | mem_upper         |    (present if flags[0] is set)
                                                ;         +-------------------+
    DWORD                   (boot_device)       ; 12      | boot_device       |    (present if flags[1] is set)
                                                ;         +-------------------+
    DWORD                   (cmdline)           ; 16      | cmdline           |    (present if flags[2] is set)
                                                ;         +-------------------+
    DWORD                   (mods_count)        ; 20      | mods_count        |    (present if flags[3] is set)
    DWORD                   (mods_addr)         ; 24      | mods_addr         |    (present if flags[3] is set)
                                                ;         +-------------------+
    RAW                     (syms, 44-28)       ; 28 - 40 | syms              |    (present if flags[4] or
                                                ;         |                   |                flags[5] is set)
                                                ;         +-------------------+
    DWORD                   (mmap_length)       ; 44      | mmap_length       |    (present if flags[6] is set)
    DWORD                   (mmap_addr)         ; 48      | mmap_addr         |    (present if flags[6] is set)
                                                ;         +-------------------+
    DWORD                   (drives_length)     ; 52      | drives_length     |    (present if flags[7] is set)
    DWORD                   (drives_addr)       ; 56      | drives_addr       |    (present if flags[7] is set)
                                                ;         +-------------------+
    DWORD                   (config_table)      ; 60      | config_table      |    (present if flags[8] is set)
                                                ;         +-------------------+
    DWORD                   (boot_loader_name)  ; 64      | boot_loader_name  |    (present if flags[9] is set)
                                                ;         +-------------------+
    DWORD                   (apm_table)         ; 68      | apm_table         |    (present if flags[10] is set)
                                                ;         +-------------------+
    DWORD                   (vbe_control_info)  ; 72      | vbe_control_info  |    (present if flags[11] is set)
    DWORD                   (vbe_mode_info)     ; 76      | vbe_mode_info     |
    DWORD                   (vbe_mode)          ; 80      | vbe_mode          |
    DWORD                   (vbe_interface_seg) ; 82      | vbe_interface_seg |
    DWORD                   (vbe_interface_off) ; 84      | vbe_interface_off |
    DWORD                   (vbe_interface_len) ; 86      | vbe_interface_len |
                                                ;         +-------------------+
_endstruc

_struc MULTIBOOT_MODULE
    DWORD                   (mod_start)
    DWORD                   (mod_end)
    DWORD                   (string)
    DWORD                   (reserved)
_endstruc

_struc MULTIBOOT_MODULES_ADDRESS
    DWORD                   (ImageBase)
    DWORD                   (Length)
_endstruc

_struc MULTIBOOT_MODULE_STRING_ID
    DWORD                   (Address)
    DWORD                   (Length)
_endstruc

_struc MULTIBOOT_NAMEPTR_TO_ID
    DWORD                   (Name)
    DWORD                   (ModId)
_endstruc
%endif ; _MULTIBOOT_YASM_