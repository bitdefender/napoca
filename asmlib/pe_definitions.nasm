;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;



%ifndef _PE_DEFINITIONS_YASM_
%define _PE_DEFINITIONS_YASM_

%ifdef DOC_FILE
    pe_definitions.nasm - PE32+ (64 bits) file header data structures and data types definitions
%endif

%include "struct.nasm"

IMAGE_DOS_SIGNATURE                     equ 0x5A4D      ; MZ
IMAGE_OS2_SIGNATURE                     equ 0x454E      ; NE
IMAGE_OS2_SIGNATURE_LE                  equ 0x454C      ; LE
IMAGE_VXD_SIGNATURE                     equ 0x454C      ; LE
IMAGE_NT_SIGNATURE                      equ 0x00004550  ; PE00


IMAGE_NUMBEROF_DIRECTORY_ENTRIES        equ 16
IMAGE_SIZEOF_SHORT_NAME                 equ  8

IMAGE_DIRECTORY_ENTRY_EXPORT            equ 0   ; Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT            equ 1   ; Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE          equ 2   ; Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION         equ 3   ; Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY          equ 4   ; Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC         equ 5   ; Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG             equ 6   ; Debug Directory
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      equ 7   ; Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR         equ 8   ; RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS               equ 9   ; TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       equ 10  ; Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      equ 11  ; Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT               equ 12  ; Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      equ 13  ; Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    equ 14  ; COM Runtime descriptor

IMAGE_FILE_MACHINE_UNKNOWN              equ 0
IMAGE_FILE_MACHINE_I386                 equ 0x014c  ; Intel 386.
IMAGE_FILE_MACHINE_R3000                equ 0x0162  ; MIPS little-endian, 0x160 big-endian
IMAGE_FILE_MACHINE_R4000                equ 0x0166  ; MIPS little-endian
IMAGE_FILE_MACHINE_R10000               equ 0x0168  ; MIPS little-endian
IMAGE_FILE_MACHINE_WCEMIPSV2            equ 0x0169  ; MIPS little-endian WCE v2
IMAGE_FILE_MACHINE_ALPHA                equ 0x0184  ; Alpha_AXP
IMAGE_FILE_MACHINE_SH3                  equ 0x01a2  ; SH3 little-endian
IMAGE_FILE_MACHINE_SH3DSP               equ 0x01a3
IMAGE_FILE_MACHINE_SH3E                 equ 0x01a4  ; SH3E little-endian
IMAGE_FILE_MACHINE_SH4                  equ 0x01a6  ; SH4 little-endian
IMAGE_FILE_MACHINE_SH5                  equ 0x01a8  ; SH5
IMAGE_FILE_MACHINE_ARM                  equ 0x01c0  ; ARM Little-Endian
IMAGE_FILE_MACHINE_THUMB                equ 0x01c2
IMAGE_FILE_MACHINE_AM33                 equ 0x01d3
IMAGE_FILE_MACHINE_POWERPC              equ 0x01F0  ; IBM PowerPC Little-Endian
IMAGE_FILE_MACHINE_POWERPCFP            equ 0x01f1
IMAGE_FILE_MACHINE_IA64                 equ 0x0200  ; Intel 64
IMAGE_FILE_MACHINE_MIPS16               equ 0x0266  ; MIPS
IMAGE_FILE_MACHINE_ALPHA64              equ 0x0284  ; ALPHA64
IMAGE_FILE_MACHINE_MIPSFPU              equ 0x0366  ; MIPS
IMAGE_FILE_MACHINE_MIPSFPU16            equ 0x0466  ; MIPS
IMAGE_FILE_MACHINE_AXP64                equ IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE              equ 0x0520  ; Infineon
IMAGE_FILE_MACHINE_CEF                  equ 0x0CEF
IMAGE_FILE_MACHINE_EBC                  equ 0x0EBC  ; EFI Byte Code
IMAGE_FILE_MACHINE_AMD64                equ 0x8664  ; AMD64 (K8)
IMAGE_FILE_MACHINE_M32R                 equ 0x9041  ; M32R little-endian
IMAGE_FILE_MACHINE_CEE                  equ 0xC0EE

_struc   IMAGE_DOS_HEADER
    WORD    (e_magic)
    WORD    (e_cblp)
    WORD    (e_cp)
    WORD    (e_crlc)
    WORD    (e_cparhdr)
    WORD    (e_minalloc)
    WORD    (e_maxalloc)
    WORD    (e_ss)
    WORD    (e_sp)
    WORD    (e_csum)
    WORD    (e_ip)
    WORD    (e_cs)
    WORD    (e_lfarlc)
    WORD    (e_ovno)
    WORD    (e_res, 4)
    WORD    (e_oemid)
    WORD    (e_oeminfo)
    WORD    (e_res2, 10)
    DWORD   (e_lfanew)
_endstruc


_struc   IMAGE_FILE_HEADER
    WORD    (Machine)
    WORD    (NumberOfSections)
    DWORD   (TimeDateStamp)
    DWORD   (PointerToSymbolTable)
    DWORD   (NumberOfSymbols)
    WORD    (SizeOfOptionalHeader)
    WORD    (Characteristics)
_endstruc


_struc   IMAGE_DATA_DIRECTORY
    DWORD   (VirtualAddress)
    DWORD   (Size)
_endstruc


_struc   IMAGE_OPTIONAL_HEADER
    WORD    (Magic)
    BYTE    (MajorLinkerVersion)
    BYTE    (MinorLinkerVersion)
    DWORD   (SizeOfCode)
    DWORD   (SizeOfInitializedData)
    DWORD   (SizeOfUninitializedData)
    DWORD   (AddressOfEntryPoint)
    DWORD   (BaseOfCode)
    DWORD   (BaseOfData)
    DWORD   (ImageBase)
    DWORD   (SectionAlignment)
    DWORD   (FileAlignment)
    WORD    (MajorOperatingSystemVersion)
    WORD    (MinorOperatingSystemVersion)
    WORD    (MajorImageVersion)
    WORD    (MinorImageVersion)
    WORD    (MajorSubsystemVersion)
    WORD    (MinorSubsystemVersion)
    DWORD   (Win32VersionValue)
    DWORD   (SizeOfImage)
    DWORD   (SizeOfHeaders)
    DWORD   (CheckSum)
    WORD    (Subsystem)
    WORD    (DllCharacteristics)
    DWORD   (SizeOfStackReserve)
    DWORD   (SizeOfStackCommit)
    DWORD   (SizeOfHeapReserve)
    DWORD   (SizeOfHeapCommit)
    DWORD   (LoaderFlags)
    DWORD   (NumberOfRvaAndSizes)
    IMAGE_DATA_DIRECTORY (DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
_endstruc


_struc IMAGE_OPTIONAL_HEADER64
    WORD        (Magic)
    BYTE        (MajorLinkerVersion)
    BYTE        (MinorLinkerVersion)
    DWORD       (SizeOfCode)
    DWORD       (SizeOfInitializedData)
    DWORD       (SizeOfUninitializedData)
    DWORD       (AddressOfEntryPoint)
    DWORD       (BaseOfCode)
    QWORD       (ImageBase)
    DWORD       (SectionAlignment)
    DWORD       (FileAlignment)
    WORD        (MajorOperatingSystemVersion)
    WORD        (MinorOperatingSystemVersion)
    WORD        (MajorImageVersion)
    WORD        (MinorImageVersion)
    WORD        (MajorSubsystemVersion)
    WORD        (MinorSubsystemVersion)
    DWORD       (Win32VersionValue)
    DWORD       (SizeOfImage)
    DWORD       (SizeOfHeaders)
    DWORD       (CheckSum)
    WORD        (Subsystem)
    WORD        (DllCharacteristics)
    QWORD       (SizeOfStackReserve)
    QWORD       (SizeOfStackCommit)
    QWORD       (SizeOfHeapReserve)
    QWORD       (SizeOfHeapCommit)
    DWORD       (LoaderFlags)
    DWORD       (NumberOfRvaAndSizes)
    IMAGE_DATA_DIRECTORY (DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
_endstruc


_struc   IMAGE_NT_HEADERS
    DWORD                   (Signature)
    IMAGE_FILE_HEADER       (FileHeader)
    IMAGE_OPTIONAL_HEADER   (OptionalHeader)
_endstruc


_struc   IMAGE_NT_HEADERS64
    DWORD                   (Signature)
    IMAGE_FILE_HEADER       (FileHeader)
    IMAGE_OPTIONAL_HEADER64 (OptionalHeader)
_endstruc

_struc   IMAGE_SECTION_HEADER
    BYTE    (Name, IMAGE_SIZEOF_SHORT_NAME)
    DWORD   (VirtualSize)
    DWORD   (VirtualAddress)
    DWORD   (SizeOfRawData)
    DWORD   (PointerToRawData)
    DWORD   (PointerToRelocations)
    DWORD   (PointerToLinenumbers)
    WORD    (NumberOfRelocations)
    WORD    (NumberOfLinenumbers)
    DWORD   (Characteristics)
_endstruc

_struc   IMAGE_EXPORT_DIRECTORY
    DWORD   (Characteristics)
    DWORD   (TimeDateStamp)
    WORD    (MajorVersion)
    WORD    (MinorVersion)
    DWORD   (Name)
    DWORD   (Base)
    DWORD   (NumberOfFunctions)
    DWORD   (NumberOfNames)
    DWORD   (AddressOfFunctions)
    DWORD   (AddressOfNames)
    DWORD   (AddressOfNameOrdinals)
_endstruc


%endif ; _PE_DEFINITIONS_
