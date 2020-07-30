;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%include "..\asmlib\system.nasm"
%include "..\asmlib\loader_interface.nasm"
%include "..\asmlib\multiboot.nasm"
%include "..\asmlib\pe_definitions.nasm"
%include "..\asmlib\if.nasm"

%define PXE32_CONFIRM_ERRORS 0
%define ENABLE_VGA_OUTPUT 0

%ifdef DOC_FILE
    pxe32.nasm - First code executed when in legacy/pxe boot mode. The boot loader loads
    this file as well as other modules into memory. This code retrieves the loaded modules and
    moves them in a new memory location. The napoca module will then be executed in IA32e mode
    with all the gathered information given as parameter

    The code executes the following steps:
    - Retrieve RIP for relative address computations
    - Set custom GDT table
    - Retrieve the multiboot structure
    - Parse the PXE file and get the RVA addreess for relative address computations
    - Iterate memory map and finds a suitable memory location for the modules loaded
    - Relocates boot modules
    - Creates 4 level paging structures
    - Switches to IA32e mode
    - Calls the C method Init64.c

    After a return from Init64.c, the code switches back to IA32 mode and tries to load the OS. If this fails the systm in placed in a halt state.
%endif

%ifndef PXE32_RESERVE_MEM_ABOVE
    %define PXE32_RESERVE_MEM_ABOVE 32*MEGA
%endif

;
; Define a label for the first address where something is emitted
;
bootStart:

%ifdef DOC_FILE
    http://www.gnu.org/software/grub/manual/multiboot/multiboot.html
    definitions specific to our PXE entry code
%endif

; if ORIGIN_IN_FILE is 0 => the actual PE is an overlay, otherwise we're part of the PE
%ifndef ORIGIN_IN_FILE
    %define ORIGIN_IN_FILE 0
%endif

; uncomment to detect nested PXE + MBR load
; %define CHECK_FOR_NAPOCA_PRESENT

; easy handling of labels for location-aware coding
%define REL(base, label)    (base + (label - bootStart))            ; what value would 'label' have if first byte of our code (bootStart) were at address 0
%define RVA(label)          REL(ORIGIN_IN_FILE, label)              ; offset relative to the ORIGIN_IN_FILE; links a label from this module to its actual position in the PE file
%define PXEADR(label)       (PXE_BASE + RVA(label))                 ; absolute address for a label considering the address where PXE loads the PE file
%define ADDR64(label)       (FINAL_BASE + RVA(label))               ; value of 'label' in Napoca VA space

%define BOOT_SIZE                                                   (bootEnd - bootStart)
%define BOOT_SIZE_ALIGNED                                           (((BOOT_SIZE + PAGE_SIZE - 1) >> 12) << 12)

%define SECTOR_SIZE_BITS                                            9
%define SECTOR_SIZE                                                 (1 << SECTOR_SIZE_BITS)
%define ROUND_UP(constBase, constAlign)                             ((constAlign) * (((constBase) + (constAlign) - 1) / (constAlign)))


;
; MACRO DEFINITIONS
;

%define        getValidModulePtr(ModId)        STDCALL getModulePtrEx, ModId, 1
%define        getModulePtr(ModId)                STDCALL getModulePtrEx, ModId, 0

%define        getValidModuleAddress(ModId)    GET_VALID_MODULE_FIELD    ModId, Pa
%define        getValidModuleSize(ModId)        GET_VALID_MODULE_FIELD    ModId, Size

%define        getModuleAddressPtr(ModId)        GET_MODULE_FIELD_PTR    ModId, Pa
%define        getModuleSizePtr(ModId)            GET_MODULE_FIELD_PTR    ModId, Size

%macro        GET_VALID_MODULE_FIELD 2
    getValidModulePtr(%1)
    ifnot zero(eax)
            mov        eax,    [eax + BOOT_MODULE.%2]
    endif
%endmacro

%macro        GET_MODULE_FIELD_PTR 2
    getModulePtr(%1)
    ifnot zero(eax)
            lea        eax,    [eax + BOOT_MODULE.%2]
    endif
%endmacro


%imacro print 1-*
    %rep %0/2
        _print %1
        hex %2
        %rotate 2
    %endrep
    %if ((%0 % 2) != 0)
        _print %1
    %endif
%endmacro

%imacro println 1-*
    %rep %0/2
        _print %1
        hex %2
        %rotate 2
    %endrep
    %if ((%0 % 2) == 0)
        _print nl
    %else
        _print %1, nl
    %endif
%endmacro

%imacro confirm 1+
    println %1
%if PXE32_CONFIRM_ERRORS != 0
    push eax
    stdcall readKey, 1, 1  ; both fresh keystroke and blocking to actually wait
    pop eax
%endif
%endmacro

%macro ERROR_MSG 0
    confirm "Failed at ", DWORD __LINE__
%endmacro


%imacro __CHECKED_CALL 2+
        stdcall %2
        test    eax,    eax
        if z
                ERROR_MSG
                jmp      .cleanup
        endif
%endmacro
%imacro CALL_OR_DIE 1+
    __CHECKED_CALL 1, %1
%endmacro
%imacro CALL_OR_FAIL 1+
    __CHECKED_CALL 0, %1
%endmacro

%imacro FAIL_SILENT_IF 1+
        if      %1
                jmp      .cleanup
        endif
%endmacro

%imacro FAIL_IF 1+
        if      %1
                ERROR_MSG
                jmp      .cleanup
        endif
%endmacro

%imacro DIE_IF 1+
        if      %1
                ERROR_MSG
                jmp      .cleanup
        endif
%endmacro

%macro _print 1+
%if ENABLE_VGA_OUTPUT
        %push print         ; create a new context for the %$push label (not to interfere with outside local .labels)
        call    %$push
        db  %1, 0
        %$push:
        call    printString
        %pop
%endif
%endmacro

%macro hex 1-2+
%if ENABLE_VGA_OUTPUT
    push DWORD %1
    call printHexFmt
    %if %0 == 2
        _print %2
    %endif
%endif
%endmacro

%define rmcall RM_CALL ebp, 0x600,
%macro RM_CALL 3-*  ; RM_CALL BaseAddress, destination <64K buffer address, procName, param*
    %push RMCALL
    %xdefine %$Base %1  ; we HAVE to obtain a relative address for RmProc (ie [Base + RVA(proc_label)])
    %xdefine %$Destination %2
    %xdefine %$RmProc %3
    %xdefine %$RmProcEnd %3 %+ End
    ;%error %1 %2 %3 %3 %+ End

    push    eax
    %rotate -1      ; rotate 1 to the right to get the last param as %1
    %rep %0 - 3
        push WORD %1
        %rotate -1
    %endrep
    lea     eax,    [%$Base + RVA(%$RmProc)]
    stdcall callToRealMode, %$Destination, eax, %$RmProcEnd - %$RmProc, 2*(%0 - 2)

    ; free RM proc params from the 32-bit stack
    add     esp, 2*(%0 - 3)
    pop     eax
    %pop
%endmacro

%ifdef DOC_METHOD
    GetStructureIndex _In CX_CHAR* StructureName, _In CX_UINT32 ModuleId
    Multiplies ModuleId by sizeof(StructureName), where sizeof(StructureName) must be 2,4,8,16 or 24
    The result is returned in EAX.
    If the structure size is not supporten, an error is thrown.
%endif
%macro  GetStructureIndex 2
    %ifnidni    %2, eax
        mov eax,    %2
    %endif

    %if     1   == sizeof(%1)

    %elif 2 == sizeof(%1)
        shl eax,    1
    %elif 4 == sizeof(%1)
        shl eax,    2
    %elif 8 == sizeof(%1)
        shl eax,    3
    %elif 16 == sizeof(%1)
        shl eax,    4
    %elif 24 == sizeof(%1)
        shl    eax,    3                ; * 8
        lea eax,    [eax * 2 + eax]    ; * 3
    %else
        %error structure size not supported
    %endif
%endmacro

%define getStructureIndex(a, b) GetStructureIndex a, b

%ifdef DOC_METHOD
    movm CX_VOID *Mem1, CX_VOID *Mem2
    Moves Mem2 in Mem1.
%endif
%macro movm 2
    push    %2
    pop        %1
%endmacro


;
; DATA STRUCTURES
;

; PXE entry initial context
_struc PXE_CONTEXT
    PUSHA32                 (PushaStruc)                                ; all boot-time register values, except for esp
_endstruc

; Multiboot header structure for PXE loaders.
; "The Multiboot header must be contained completely within the first 8192 bytes of the OS image, and must be longword (32-bit) aligned."

_istruc multibootHeader, MULTIBOOT_HEADER
    _at magic,          dd MULTIBOOT_HEADER_MAGIC
    _at flags,          dd MB_HEADERFLAG_PAGE_ALIGNED | MB_HEADERFLAG_MEM_MAP | MB_HEADERFLAG_FIXED_BASE
    _at checksum,       dd 0 - (MULTIBOOT_HEADER_MAGIC + (MB_HEADERFLAG_PAGE_ALIGNED | MB_HEADERFLAG_MEM_MAP | MB_HEADERFLAG_FIXED_BASE))
    _at header_addr,    dd PXE_BASE + RVA(multibootHeader)
    _at load_addr,      dd PXE_BASE
    _at load_end_addr,  dd 0
    _at bss_end_addr,   dd 0
    _at entry_addr,     dd PXEADR(entryPoint)
    _at mode_type,      dd 0
    _at width,          dd 0
    _at height,         dd 0
    _at depth,          dd 0
_iend


    multibootInformationStructure dd 0
    db "MULTIBOOT_START_STRING", 0
; get MULTIBOOT_NAMES_COUNT and MULTIBOOT_NAMEPTR_TO_ID MultibootModuleNameToModId[MULTIBOOT_NAMES_COUNT] from multibootdefs.nasm
%include "..\autogen\multibootdefs.nasm"

ldModules:
    times MAX_MODULES * sizeof(BOOT_MODULE) db 0

fpuTestWord:
    dw      0xBDBD

; Boot-time descriptors
    bootIdt:
        .limit          dw  0x3FF
        .base           dd  0

; Boot-time Gdt table, flat memory descriptor mode
    bootGdt:
        .limit          dw  (.tableEnd - .tableStart) - 1
        .base           dd  0                           ; .tableStart

        .tableStart:
        .dscZero        dq 0
        .dscCode32      dq FLAT_DESCRIPTOR_CODE32
        .dscData32      dq FLAT_DESCRIPTOR_DATA32
        .dscCode64      dq FLAT_DESCRIPTOR_CODE64
        .dscData64      dq FLAT_DESCRIPTOR_DATA64
        .dscCode16      dq FLAT_DESCRIPTOR_CODE16
        .dscData16      dq FLAT_DESCRIPTOR_DATA16
        .dscBase32      dq FLAT_DESCRIPTOR_DATA32       ; patched to runtime image base
        .tableEnd:
    bootGdtEnd:
    SEL_NULL            equ 0*8
    SEL_CODE32          equ 1*8
    SEL_DATA32          equ 2*8
    SEL_CODE64          equ 3*8
    SEL_DATA64          equ 4*8
    SEL_CODE16          equ 5*8
    SEL_DATA16          equ 6*8
    SEL_BASE32          equ 7*8

    ;
    ; Static data necessary for boot-time
    ;
    _istruc bootContext, BOOT_CONTEXT
    _iend

    _istruc tempMem, MEM_BUFFER
    _iend

    tempMap:            dd  0                           ; pointer to the actual memory map
    tempMapIndex        dd  0                           ; next entry index / number of entries

    peBase              dd  0
    peVaBase            dq  0
    peRvaEntryPoint     dq  0
    peImageLength       dd  0

    stackBase           dd  0
    stackLength         dd  0

    _istruc pxeContext, PXE_CONTEXT
    _iend
    tempStack:          times 4*128 db 0                ; space for a small temporary stack
    tempStackTop:

    tempMemLength       dd  0
    biosOsDrive         dd  0
    isGuestMbrAt7c00    db  0
    pxeBase                dd    0
    _istruc legacyCustomModule, LD_LEGACY_CUSTOM
    _iend
;
; ENTRY POINT AND PRE-INITIALIZATIONS CODE
;


[bits 32]
entryPoint:
    ; check if we have a consistent loader state

    DIE_IF different(eax, MULTIBOOT_LOADER_MAGIC)

    ; setup an early stack in a free low memory area
    mov     esp,    0x7c00
    call    .getEip
.getEip:
    pop     ebp                     ; Get the physical address in memory of the .getEip label
    sub     ebp, RVA(.getEip)       ; Compute the physical address of the image base

    mov     [0x7c00-4], DWORD 0     ; Clear the obtained rip address

    ; Place the stack at the end of the pxeContext in order to save all general purpose registers
    lea     esp, [ebp + RVA(pxeContext.PushaStruc) + sizeof(PUSHA32)]

    pusha                           ; Save general purpose registers in pxeContext structure

    ; Move esp at the end of the designated temporary-stack area
    lea     esp,    [ebp + RVA(tempStackTop)]

    ; Patch GDT descriptor to point at image base
    mov     eax,    ebp
    shr     eax,    24
    mov     [ebp + RVA(bootGdt.dscBase32+7)], al                ; base[32:24]

    mov     eax,    ebp
    shr     eax,    16
    and     eax,    0xFF
    mov     [ebp + RVA(bootGdt.dscBase32+4)], al                ; base[23:16]

    mov     eax,    ebp
    and     eax,    0xFFFF
    mov     [ebp + RVA(bootGdt.dscBase32+2)], ax                ; base[15:0]

    ; Reset IDT to the real mode IVT (ipxe problem with the new driver)
    lidt    [ebp + RVA(bootIdt)]

    ; Prepare and activate our custom GDT
    lea     eax,    [ebp + RVA(bootGdt.tableStart)]
    mov     [ebp + RVA(bootGdt.base)], eax
    lgdt    [ebp + RVA(bootGdt)]

    ; make FS point directly to our base (offset = 0)
    mov     ax,     SEL_BASE32
    mov     fs,     ax

    ; Set the napoca module base
    getModuleAddressPtr(LD_MODID_NAPOCA_IMAGE)
    mov        [eax],    ebp                     ; ldModules[LD_MODID_NAPOCA_IMAGE].Va = ImageBase
    mov        [ebp + RVA(pxeBase)],    ebp

    ; all other segments are flat
    mov     ax,     SEL_DATA32
    mov     ds,     ax
    mov     es,     ax
    mov     gs,     ax
    mov     ss,     ax

    ; Reload CS segment selector and GDT
    push    DWORD   SEL_CODE32
    lea     eax,    [ebp + RVA(.csReloaded)]
    push    eax

    retf

.csReloaded:



;
; CAPTURE THE INITIAL CONTEXT
;

    rmcall  initTextMode16, 3
    println "Basic initializations done, running from ", ebp

    ; get the multiboot info structure
    mov     [ebp + RVA(bootContext.BootMode)], DWORD BOOT_MODE_LEGACY_PXE
    mov     ebx,    [ebp + RVA(pxeContext.PushaStruc.Ebx)]          ; ebx was pointing to the Multiboot Information Structure
    mov     [ebp + RVA(multibootInformationStructure)], ebx
    mov     eax,    [ebx + MULTIBOOT_INFO.boot_device]
    mov     [ebp + RVA(biosOsDrive)], eax

;
; PARSE THE PE FILE
;
    println "parsing the PE file"

%if ORIGIN_IN_FILE == 0
    ; get right after the pxe code
    mov     edi,    BOOT_SIZE_ALIGNED
%else
    xor     edi,    edi
%endif

    ; Save in peBase the offset between image base and the MZ-PE Header
    mov     [ebp + RVA(peBase)], edi

    ; Compute in edi the absolute address of the MZ-PE Header
    add     edi,    ebp

    DIE_IF different([edi], WORD IMAGE_DOS_SIGNATURE)

    mov     esi,    [edi + IMAGE_DOS_HEADER.e_lfanew]
    add     esi,    edi                                                     ; esi = IMAGE_NT_HEADERS
    DIE_IF different([esi], DWORD IMAGE_NT_SIGNATURE)
    DIE_IF different([esi + IMAGE_NT_HEADERS.FileHeader.Machine], WORD IMAGE_FILE_MACHINE_AMD64)

    ; Get the runtime virtual addresses of the image base and entry point
    mov     edx,    [esi + IMAGE_NT_HEADERS64.OptionalHeader.ImageBase + 4]
    mov     eax,    [esi + IMAGE_NT_HEADERS64.OptionalHeader.ImageBase]
    println "VA BASE HIGH = ", edx, " VA BASE LOW = ", eax
    mov     [ebp + RVA(peVaBase) + 4], edx
    mov     [ebp + RVA(peVaBase)], eax

    mov     eax,    [esi + IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage]
    add     eax,    PAGE_SIZE - 1
    and     eax,    (0xFFFFFFFF - (PAGE_SIZE - 1))

    mov     [ebp + RVA(peImageLength)], eax

    ; save the napoca module length
    push    eax
    getModuleSizePtr(LD_MODID_NAPOCA_IMAGE)
    pop     DWORD [eax]

    mov     eax,    [esi + IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint]
    mov     [ebp + RVA(peRvaEntryPoint)], eax

;
; RETRIEVE MULTIBOOT MODULES
;
    ;STDCALL dumpMultibootModules, [ebp + RVA(multibootInformationStructure)]
    CALL_OR_DIE retrieveLoaderModules, [ebp + RVA(multibootInformationStructure)]
    ;STDCALL dumpModules

    ; setup the guest mbr sector to 7c00 in case we need to abort execution
    getValidModulePtr(LD_MODID_ORIG_MBR)
    ifnot zero(eax)
            push    eax
            CALL_OR_DIE mbrUpdatePartitionTable
            pop     eax
            stdcall copyMem, 0x7c00, DWORD[eax + BOOT_MODULE.Pa], DWORD[eax + BOOT_MODULE.Size]
            mov     BYTE [ebp + RVA(isGuestMbrAt7c00)], 1
    endif

%ifdef CHECK_FOR_NAPOCA_PRESENT
    ; get cpuid virtualization info, this must be done after patching the code below
    ; to load the second sector from the disk in case of legacy boot flow
    mov     eax,    1
    cpuid
    test    ecx,    CPUID_ECX_VMX
    ABORT_IF z
    test    ecx,    CPUID_ECX_HYPERVISOR
    ABORT_IF z
%endif


;
; MBR RECOVERY HANDLING
;
    getValidModuleAddress(LD_MODID_MBR_SETTINGS)
    ifnot zero(eax)
        println "settings[", eax, "] = (WORD)", [eax]
        ifnot zero(BYTE [eax + LD_CONFIGURATION_OPTIONS.RecoveryEnabled])
                println "running the recovery code..."
                CALL_OR_DIE mbrRecovery
                ; triple-fault to reboot the system if successful (otherwise will DIE / goto .cleanup to load the OS directly)
                rmcall  cpuReset16
        endif
    endif


;
; MEMORY MANAGMENT INITIALIZATION
;
    ; get a free memory block for our temp buffer (of TEMP_BUFFER_SIZE + napoca size)
    getValidModuleSize(LD_MODID_NAPOCA_IMAGE)
    DIE_IF zero(eax)
    lea        eax,    [eax + TEMP_BUFFER_SIZE]
    mov     [ebp + RVA(tempMemLength)], eax

    lea     eax,    [ebp + RVA(selectMemoryBlock)]
    CALL_OR_DIE iterateMemMap, eax
    DIE_IF equal([ebp + RVA(tempMem.NextFreeAddress)], DWORD 0)

    println "memory map: selected region at ", [ebp + RVA(tempMem.NextFreeAddress)], " size: ", [ebp + RVA(tempMem.Length)]

;
; MOVE TO A SAFE ADDRESS SPACE
;
    println "relocating modules..."
    CALL_OR_DIE relocateModules
    ; eax is the new absolute image base address of napoca

    ; switch the EBP value to the new image base absolute address (used for relative SIB addressing)
    mov     ebp,    eax

    ; correct the peBase to account for the final address of this code
    ; the current value of peBase contains the offset of the MZ-PE header
    ; (there may be cases in which the multiboot structure is situated before the MZ-PE headers
    ; and the MZ-PE offset in this case is not 0). By adding the offset of the module to this value
    ; the peBase contains the absolute value of the MZ-PE headers of the newly relocated NAPOCA module

    add     [ebp + RVA(peBase)], ebp

    println "switching to the new address"
    ; Switch the EIP to the newly relocated code
    lea     eax,    [ebp + RVA(.relocated)]
    push    eax
    ret

.relocated:
    ; set the updated pxeBase
    mov     [ebp + RVA(pxeBase)], ebp

    ; prepare fs base to point to the new copy
    mov     eax,    ebp
    shr     eax,    24
    mov     [ebp + RVA(bootGdt.dscBase32+7)], al                ; base[32:24]

    mov     eax,    ebp
    shr     eax,    16
    and     eax,    0xFF
    mov     [ebp + RVA(bootGdt.dscBase32+4)], al                ; base[23:16]

    mov     eax,    ebp
    and     eax,    0xFFFF
    mov     [ebp + RVA(bootGdt.dscBase32+2)], ax                ; base[15:0]

    ; reload our GDT
    lea     eax,    [ebp + RVA(bootGdt.tableStart)]
    mov     [ebp + RVA(bootGdt.base)], eax
    lgdt    [ebp + RVA(bootGdt)]

    ; make FS point directly to our base (offset = 0)
    mov     ax,     SEL_BASE32
    mov     fs,     ax

    ; fix the napoca boot module address(es), relative to the newly relocated code
    getModulePtr(LD_MODID_NAPOCA_IMAGE)
    mov        [eax + BOOT_MODULE.Pa], ebp
    movm    DWORD [eax + BOOT_MODULE.Va], DWORD [ebp + RVA(peVaBase)]
    movm    DWORD [eax + BOOT_MODULE.Va + 4], DWORD [ebp + RVA(peVaBase) + 4]


;
; SWITCH TO FINAL STACK
;
    ; prepare the final stack
    CALL_OR_DIE allocPhysicalPages, STACK_SIZE / PAGE_SIZE

    mov     [ebp + RVA(stackBase)], eax
    mov     [ebp + RVA(stackLength)], DWORD STACK_SIZE

    lea     esp,    [eax + STACK_SIZE]                          ; setup the stack, still using physical addresses
    println "prepare final loader stack: ToS PA=", esp






;
; ALLOC AND/OR MAP DATA STRUCTURES FOR NAPOCA
;
    ; map all the temp memory region, eax contains the beginning of temp mem
    ;mapPages: __in_opt _PVOID Root, __in _DWORD VaLow, __in _DWORD VaHigh, __in _DWORD PaLow, __in _DWORD PaHigh, __in _DWORD NumberOfPages
    println "temp map"
    mov     eax,    [ebp + RVA(tempMem.Va)]
    mov     ecx,    [ebp + RVA(tempMem.Length)]
    add     ecx,    STACK_SIZE                                  ; account for already allocated mem
    shr     ecx,    12
    CALL_OR_DIE mapPages, NULL, eax, 0, eax, 0, ecx

    mov     [ebp + RVA(bootContext.Cr3)],     eax
    println "cr3 = ", eax

    ; map the PE image to its imagebase
    println "map the PE image, exe PA base=", [ebp +RVA(peBase)], " VA.h=", [ebp + RVA(peVaBase) + 4], " VA.l=", [ebp + RVA(peVaBase)]

    mov     ecx,    [ebp + RVA(peImageLength)]
    shr     ecx,    12                                          ; ImageLength / PAGE_SIZE
    mov     ebx,    [ebp + RVA(peVaBase)]
    mov     edx,    [ebp + RVA(peVaBase) + 4]
    CALL_OR_DIE mapPages, eax, ebx, edx, [ebp + RVA(peBase)], 0, ecx

    ; identity map the current code region
    println "self-map"
    mov     ecx,    1 + BOOT_SIZE_ALIGNED / PAGE_SIZE
    CALL_OR_DIE mapPages, eax, ebp, 0, ebp, 0, ecx

    ; identity the map video memory
    println "video map"
    CALL_OR_DIE mapPages, eax, 0xb8000, 0, 0xb8000, 0, 4

    ; fill-in some of the bootContext fields
    lea     eax,    [ebp + RVA(ldModules)]
    mov     [ebp + RVA(bootContext.Modules)], eax
    mov     [ebp + RVA(bootContext.ModulesPa)], eax
    mov     [ebp + RVA(bootContext.NumberOfModules)], DWORD MAX_MODULES
    mov     [ebp + RVA(bootContext.NumberOfLoaderCpus)], DWORD 1
    mov     DWORD [ebp + RVA(bootContext.OriginalStackTop)], esp
    mov     DWORD [ebp + RVA(bootContext.OriginalStackTop) + 4], 0


    ; alloc space for a memory map
    mov     eax,    (sizeof(MEMORY_MAP) + PAGE_SIZE - 1) / PAGE_SIZE
    println "Memory map: pages = ", eax
    CALL_OR_DIE allocPhysicalPages, eax

    mov     [ebp + RVA(tempMap)], eax
    println "will grab mem map to ", eax

    ; get the current memory map
    println "prepare memory map"
    lea     eax,    [ebp + RVA(createMemoryMap)]
    CALL_OR_DIE iterateMemMap, eax

    println "memory map ready, preparing loader modules"

    ; fill in the number of map entries
    mov     eax,    [ebp + RVA(tempMap)]
    mov     ebx,    [ebp + RVA(tempMapIndex)]
    mov     [eax + MEMORY_MAP.NumberOfEntries], ebx
    mov     [eax + MEMORY_MAP.MapType], DWORD MEMORY_MAP_TYPE_E820





;
; REGISTER THE NAPOCA DYNAMICALLY GENERATED BOOT MODULES
;
    ; memory map
    ;_in _DWORD Id, _in _DWORD Va, _in _DWORD Pa, _in _DWORD Size
    CALL_OR_DIE registerModule, LD_MODID_MEMORY_MAP, eax, eax, sizeof(MEMORY_MAP), LD_MODFLAG_PHASE1

    ; temp mem buffer for napoca -- WE DON'T SETUP EVERYTHING SO WE SIMPLY SEND RAW MEMORY
    lea     eax,    [ebp + RVA(tempMem)]
    CALL_OR_DIE registerModule, LD_MODID_FREE_MEMORY, eax, eax, sizeof(MEM_BUFFER), LD_MODFLAG_EARLYBOOT

    ; kernel stack
    mov     eax,    [ebp + RVA(stackBase)]
    mov     ecx,    [ebp + RVA(stackLength)]
    CALL_OR_DIE registerModule, LD_MODID_NAPOCA_STACK, eax, eax, ecx, LD_MODFLAG_PHASE2

    ; register LD_LEGACY_CUSTOM if GrubBoot
    getValidModulePtr(LD_MODID_MBR_SETTINGS)
    ifnot zero(eax)
            ; fill-in the drive id
            mov     eax,    [ebp + RVA(multibootInformationStructure)]
            mov     eax,    [eax + MULTIBOOT_INFO.boot_device]
            mov     [ebp + RVA(legacyCustomModule.BiosOsDrive)], eax
            mov     [ebp + RVA(legacyCustomModule.BootMode)], DWORD BOOT_MODE_LEGACY
            mov     [ebp + RVA(bootContext.BootMode)], DWORD BOOT_MODE_LEGACY
            ; flush data
            lea     eax,    [ebp + RVA(legacyCustomModule)]
            stdcall registerModule, LD_MODID_LOADER_CUSTOM, eax, eax, sizeof(LD_LEGACY_CUSTOM), LD_MODFLAG_PERMANENT
    endif


    println "remaining free memory: ", [ebp + RVA(tempMem.Length)]

    println "preparing to run the EP at RVA=", [ebp + RVA(peRvaEntryPoint)], "ImageBase.h=", [ebp + RVA(peVaBase) + 4], "ImageBase.l=", [ebp + RVA(peVaBase)],



;
; TRANSITION TO 64 BITS FOR CALLING INIT64
;
    ;;; rmcall  initTextMode16, 3

    ;
    ; switch to 64 bits
    ;

    ; deactivate XD_DISABLE and LIMIT_CPUID in IA32_MISC
    CONFIGURE_IA32_MISC 0, IA32_MISC_ENABLE.XD_DISABLE | IA32_MISC_ENABLE.LIMIT_CPUID

    ENABLE_PAE
    ENABLE_LME
    ENABLE_XD


    call    activateFpuSupport

    mov     eax,    [ebp + RVA(bootContext.Cr3)]
    mov     cr3,    eax

    ENABLE_PAGING

    ;
    ; Prepare new 64bit-ready selectors
    ;
    mov     ax,     SEL_DATA64          ; Setup data segment selectors
    mov     fs,     ax
    mov     gs,     ax
    mov     ds,     ax
    mov     ss,     ax
    mov     es,     ax

    ;
    ; Set the CS and RIP at the same time to enter long mode
    ;

    push    DWORD SEL_CODE64
    call    .pushEip                ; place return EIP onto the stack (4 bytes)
.pushEip:
    add     DWORD [esp], .entry64 - .pushEip
    retf                            ; pops cs:rip (8 bytes) and continues execution in true long mode

[bits 64]
.entry64:
    ; ESP -> RSP
    xor     rax,    rax
    mov     eax,    esp
    mov     rsp,    rax

    ; EBP -> RBP
    xor     rax,    rax
    mov     eax,    ebp
    mov     rbp,    rax

    ; run the entry point
    mov     rax,    cr3
    mov     rdx,    0xFFFFFFFF
    and     rax,    rdx
    mov     cr3,    rax

    ; aling stack to 16
    and     esp,    0xFFFFFFF0

    ; Set parameters for Init64 code
    lea     rcx,    [rbp + RVA(bootContext)]
    sub     rsp,    0x20

    ; execute the Init64 entry point
    xor     rax,    rax
    mov     eax,    [rbp + RVA(peRvaEntryPoint)]
    add     rax,    [rbp + RVA(peVaBase)]
    X64ABSCALL_INIT64 rax
    ; this is where a RETURN from HV would land


;
; HANDLE UNLOAD/CLEANUP
;


    ; capture the returned value (useless, but that's how it's done)
    mov     esi,    eax
    rol     rax,    32
    mov     edi,    eax


.ret64:
    cli
    add     rsp,    0x20


    ;
    ; Get back to 32 bits
    ;
    xor     rax,    rax
    mov     ax,     SEL_CODE32
    push    rax
    call    .findRip
.findRip:
    pop     rax
    add     rax,    .to32 - .findRip
    push    rax
    o64 retf
.to32:
    [bits 32]
    mov     ax,     SEL_BASE32
    mov     fs,     ax
    mov     ax,     SEL_DATA32
    mov     ds,     ax
    mov     es,     ax
    mov     ss,     ax
    mov     gs,     ax

    DISABLE_PAGING

    mov     ecx,    IA32_EFER           ; Read EFER MSR
    rdmsr
    and     eax,    ~IA32_EFER_LME      ; Clear the LME bit in EFER
    and     eax,    ~IA32_EFER_NXE      ; Clear the NXE bit in EFER
    wrmsr

    DISABLE_PAE

    println "HV returned result.hi=", edi, ".low=", esi

.cleanup:
    stdcall loadOs
    println "SYSTEM HALTED."
    cli
    hlt

%ifdef DOC_METHOD
    Patch the partition table in the original OS MBR buffer with the up-to-date table found in the actual MBR
%endif
PROC32 mbrUpdatePartitionTable
    push    ebp
    mov     ebp,    esp
    pusha

    stdcall getPxeBase
    mov     edx,    eax

    getValidModulePtr(LD_MODID_ORIG_MBR)
    FAIL_IF zero(eax)
    mov        esi,    eax

    ; read the current (grub) MBR to get a fresh copy of the partition table data
    ; transferSector16 __in _PVOID Buffer, __in _BYTE Operation, __in _BYTE Drive, __in _BYTE NumberOfSectors, __in _BYTE C, __in _BYTE H, __in _BYTE S
    mov     edi,    0x7c00
    movzx   bx,     BYTE [edx + RVA(biosOsDrive)]
    RM_CALL edx, 0x600, transferSector16, di, 2, bx, 1, 0, 0, 1
    FAIL_IF c
    FAIL_IF different ([edi + 0x200 - 2], WORD 0xAA55)

    ; overwrite the partition table with the new/up-to-date one
    mov     eax,    [esi + BOOT_MODULE.Pa]
    add     eax,    446     ; start of partition table in LD_MODID_ORIG_MBR buffer
    add     edi,    446     ; start of partition table in the INT13h read buffer
    stdcall copyMem, eax, edi, 16*4

    mov     eax,    1
    jmp     .done

.cleanup:
    xor     eax,    eax

.done:
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC


;
; HELPER FUNCTIONS
;
%ifdef DOC_METHOD
    If LD_MODID_ORIG_MBR exists, copies it over the old one and saves it on the disk.
    If LD_MODID_ORIG_MBR doesn't exists, error.
%endif
PROC32 mbrRecovery
    push    ebp
    mov     ebp,    esp

    pusha
    stdcall getPxeBase
    mov     edx,    eax

    getValidModulePtr(LD_MODID_ORIG_MBR)
    FAIL_IF zero(eax)
    mov        esi,    eax

    ; copy the original OS loader sectors to lower memory
    mov     ecx,    [esi + BOOT_MODULE.Size]
    stdcall copyMem, 0x7c00, [esi + BOOT_MODULE.Pa], ecx
    FAIL_IF different ([0x7c00 + 0x200 - 2], WORD 0xAA55)

    ; now transfer the copied content to disk
    movzx   bx,     BYTE [edx + RVA(biosOsDrive)]
    add     ecx,    SECTOR_SIZE - 1
    shr     ecx,    SECTOR_SIZE_BITS    ; sector count after rounding-up to sector boundary
    confirm "Restoring original OS loader sectors"
    ; transferSector16 __in _PVOID Buffer, __in _BYTE Operation, __in _BYTE Drive, __in _BYTE NumberOfSectors, __in _BYTE C, __in _BYTE H, __in _BYTE S
    RM_CALL edx, 0x600, transferSector16, 0x7c00, 3, bx, cx, 0, 0, 1
    FAIL_IF c

    ; execute the boot sector
    RM_CALL edx, 0x600, executeBootSector16, bx
    mov     eax,    1
    jmp     .success

.cleanup:
    xor     eax,    eax

.success:
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC

PROC16 cpuReset16
    xor     ax,     ax
    int     19h
    cli
    hlt
ENDPROC

%ifdef DOC_METHOD
    Returns the absolute address of the beginning of the current code in EAX
%endif
PROC32 getPxeBase
RETURNS _PVOID BaseAddress
    call    .next
.next:
    pop     eax
    sub     eax,    RVA(.next)
    ret     PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Loads the operating system from the disk
%endif
PROC32 loadOs
RETURNS VOID
    push    ebp
    mov     ebp,    esp

    confirm "Loading the OS without virtualization!"

    stdcall getPxeBase
    mov     edx,    eax
    if equal (BYTE [edx + RVA(isGuestMbrAt7c00)], 1)
            ; switch to 16 bits and execute the original loader (the mbr is already present at 0x7c00)
            confirm "Executing the already prepared boot sector"

        .executeMbr:
            RM_CALL edx, 0x600, executeBootSector16, WORD [edx + RVA(biosOsDrive)]
            println "The OS MBR sector returned, there's nothing else we can do"
            jmp     .cleanup
    else

            ; we don't (at least for now) support deducing the correct OS boot drive when on PXE
            println "PXE - starting the OS without the HV is not supported!"
            confirm "Press any key to try to load the OS from the first drive..."

            RM_CALL edx, 0x600, transferSector16, 0x7c00, 2, 0x80, 1, 0, 0, 1
            FAIL_IF c
            ifnot equal (WORD [0x7c00 + 0x200 - 2], 0xAA55)
                println "INVALID MASTER BOOT RECORD"
                hlt
            else
                RM_CALL edx, 0x600, executeBootSector16, 0x80
            endif
    endif
    jmp     .done

.cleanup:
    xor     eax,    eax
.done:
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Transfer the execution to address 0x7c00 in 16 bit mode in order to execute the OS bootloader
%endif
PROC16 executeBootSector16
PARAMS16 BootDrive
RETURNS VOID
    push    bp
    mov     bp,     sp
    mov     dl,     [%$BootDrive]

    ; boot code entry: cs = 0, ip=0x7c00, dl = BootDrive
    jmp     00: 0x7c00
ENDPROC

%ifdef DOC_METHOD
    Reads a key from the keyboard. 32 bit wrapper for the readKey16 procedure
%endif
PROC32 readKey
PARAMS32 __in _BYTE Blocking, __in _BYTE Fresh
RETURNS AH = keyboard scan code, AL = ASCII character or zero if special function key
RETURNS eax = 0 if blocking and no keystroke ready
    push    ebp
    mov     ebp,    esp

    stdcall getPxeBase
    RM_CALL eax, 0x600, readKey16, WORD [%$Blocking], WORD [%$Fresh]
    movzx   eax,    ax
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC

%ifdef DOC_METHOD
    Reads a key from the keyboard using BIOS interrupts in real mode.
%endif
PROC16 readKey16
PARAMS16 __in _BYTE Blocking, __in _BYTE Fresh
RETURNS AH = keyboard scan code, AL = ASCII character or zero if special function key
RETURNS eax = 0 if blocking and no keystroke ready
    push    bp
    mov     bp,     sp
    if equal(WORD [%$Fresh], 1)
        ; flush keyboard buffer
        .again:
            mov     ax,     0x0100
            int     16h     ; AX = 0 if no scan code is available
            ifnot zero(ax)
                    xor     ax,     ax
                    int     16h
                    jmp     .again
            endif
    endif

    ; check if a keystroke is available
    if equal(WORD [%$Blocking], 0)
            mov     ax,     0x0100
            int     16h
            if nz
                    xor     ax,     ax
                    jmp     .cleanup
            endif
    endif

    ; (blocking) read a code
    xor     ax,     ax
    int     16h
.cleanup:
    pop     bp
    ret     PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Reads/writes a sector to/from disk
%endif
PROC16 transferSector16
PARAMS16    __in _PVOID Buffer, __in _BYTE Operation, __in _BYTE Drive, __in _BYTE NumberOfSectors, __in _BYTE C, __in _BYTE H, __in _BYTE S
RETURNS CF=1 on error
    push    bp
    mov     bp,     sp

    pusha
    mov     ah,     [%$Operation]
    mov     al,     [%$NumberOfSectors] ; 0201

    mov     bx,     [%$Buffer]          ; 7c00

    mov     ch,     [%$C]
    mov     cl,     [%$S]               ; 0001

    mov     dh,     [%$H]
    mov     dl,     [%$Drive]           ; 0080
    mov     di,     8

.repeat:
    ; try to read
    pusha
    int     13h
    popa
    if c
            ifnot zero(di)
                    ; try to reset the drive
                    pusha
                    xor     ax,     ax
                    int     13h
                    popa

                    dec     di
                    jmp     .repeat
            else
                    stc
                    jmp     .cleanup
            endif
    endif
.cleanup:
    popa

    pop     bp
    ret     PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Map a continuous range of VA to a continuous range of PA; with a NULL Root it will try to create a new one
%endif
PROC32      mapPages
PARAMS32    __in_opt _PVOID Root, __in _DWORD VaLow, __in _DWORD VaHigh, __in _DWORD PaLow, __in _DWORD PaHigh, __in _DWORD NumberOfPages
RETURNS     Root PA address on success or NULL otherwise
    push    ebp
    mov     ebp,    esp
    pusha
    mov     ecx,    [%$NumberOfPages]
    mov     eax,    [%$Root]

.nextPage:
    CALL_OR_FAIL mapPage, eax, [%$VaLow], [%$VaHigh], [%$PaLow], [%$PaHigh]

    ; advance pointers
    add     DWORD [%$VaLow], PAGE_SIZE
    adc     DWORD [%$VaHigh], 0

    add     DWORD [%$PaLow], PAGE_SIZE
    adc     DWORD [%$PaHigh], 0
    loop    .nextPage

.cleanup:
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC mapPages

%ifdef DOC_METHOD
    Create the longmode table structures for mapping a given VA to its PA
%endif
PROC32      mapPage
PARAMS32    __in_opt _PVOID Root, __in _DWORD VaLow, __in _DWORD VaHigh, __in _DWORD PaLow, __in _DWORD PaHigh
RETURNS     root PA address or NULL on failure
    push    ebp
    mov     ebp,    esp
    pusha
    mov     ebx,    [%$VaLow]
    mov     edx,    [%$VaHigh]

    ; make sure we have a valid root table
    mov     eax,    [%$Root]
    test    eax,    eax
    jnz     .exists

    ; allocate a new physical page
    CALL_OR_FAIL allocPhysicalPages, 1

    ; zero it down
    stdcall fillMem, eax, PAGE_SIZE, 0

.exists:
    mov     edi,    eax                                         ; remember the value to use as rezult

    ; get the index inside the lvl4 table
    rol     edx,    (32-7)                                      ; get the edx[15:7] to [8:0]
    mov     ecx,    edx
    and     ecx,    0x1FF                                       ; table index (bits 47:39 of Va)

    ; get the corresponding lvl3 table
    CALL_OR_FAIL mapGetNextTable, eax, ecx

    ; get the index inside the lvl3 table
    rol     edx,    9
    mov     ecx,    ebx
    and     ecx,    (0x1FF - 11b)                               ; bits 38:32 of Va as bits 8:2 of index
    rol     ebx,    2
    mov     esi,    ebx
    and     esi,    11b
    or      ecx,    esi                                         ; bits 31:30 of Va as bits 1:0 of index

    ; get the lvl2 table
    CALL_OR_FAIL mapGetNextTable, eax, ecx

    ; get the index into the lvl2 table
    rol     ebx,    9
    mov     ecx,    ebx
    and     ecx,    0x1FF                                       ; bits 29:21 of address gives us the right index

    ; get the lvl1 table address for this entry
    CALL_OR_FAIL mapGetNextTable, eax, ecx

    ; get the lvl1 entry
    rol     ebx,    9
    mov     ecx,    ebx
    and     ecx,    0x1FF                                       ; bits 20:12 of address gives us the right index

    ; map the actual target physical page to its VA
    ; STDCALL VOID mapLinkEntryToPa (__in PVOID TableBase, __in WORD EntryIndex, __IN DWORD PaLow, __IN DWORD PaHigh, _IN BYTE FlagsAndAccess)
    stdcall mapLinkEntryToPa, eax, ecx, [%$PaLow], [%$PaHigh], 3; VA_PRESENT|VA_WRITE_ACCESS|VA_USER_ACCESS
    mov     eax,    edi
    jmp     .success
.cleanup:
    xor     eax,    eax
.success:
    mov     [esp + PUSHA32.Eax], eax                            ; make eax survive the popa
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC     mapPage


PROC32      mapGetNextTable
PARAMS32    __in _PVOID TableBase, __in _WORD EntryIndex
RETURNS     NULL on failure or the address of the next-level table
    push    ebp
    mov     ebp,    esp
    pusha

    mov     edi,    [%$TableBase]
    mov     ecx,    [%$EntryIndex]
    shl     ecx,    3                                           ; 8*index = table offset
    lea     edi,    [edi + ecx]                                 ; edi = address of the actual QWORD from table

    mov     eax,    [edi]
    mov     edx,    [edi + 4]                                   ; EDX:EAX = entry value
    test    eax,    eax
    jnz     .success
    test    edx,    edx
    jnz     .success

    CALL_OR_FAIL allocPhysicalPages, 1

    ; preinit the table
    stdcall fillMem, eax, PAGE_SIZE, 0

    ; link it to its root table
    ; __in _PVOID TableBase, __in _WORD EntryIndex, __IN _DWORD PaLow, __IN _DWORD PaHigh, __IN _BYTE FlagsAndAccess
    stdcall mapLinkEntryToPa, [%$TableBase], [%$EntryIndex], eax, 0, 3; VA_PRESENT|VA_WRITE_ACCESS|VA_USER_ACCESS
    jmp     .success

.cleanup:
    xor     eax,    eax
.success:
    ; clear non-address bits from entry value
    and     eax,    PAGE_MASK
    ; make eax persistent
    mov     [esp + PUSHA32.Eax],    eax
    popa
    pop ebp
    ret PARAMS_SIZE
ENDPROC

%ifdef DOC_METHOD
    Create links between different paging structures
%endif
PROC32      mapLinkEntryToPa
PARAMS32    __in _PVOID TableBase, __in _WORD EntryIndex, __IN _DWORD PaLow, __IN _DWORD PaHigh, __IN _BYTE FlagsAndAccess
RETURNS     VOID
    push    ebp
    mov     ebp,    esp
    pusha

    ; get PA
    mov     eax,    [%$PaLow]
    and     eax,    PAGE_MASK

    ; get FLAGS
    mov     ebx,    [%$FlagsAndAccess]
    and     ebx,    VA_MASK

    ; combine them
    or      eax,    ebx

    ; get to the correct entry
    mov     edi,    [%$TableBase]
    mov     ecx,    [%$EntryIndex]

    ; make the link (low part of address)
    mov     [edi + 8*ecx], eax
    mov     eax,    [%$PaHigh]

    ; now _at the high part
    and     eax,    0xFFFFF                                     ; keep 20 bits only from the high part (for a max of 52 bits PA)
    mov     [edi + 8*ecx + 4], eax

    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC     mapLinkEntryToPa

%ifdef DOC_METHOD
    Fill a block of memory with a given byte value
%endif
PROC32      fillMem
PARAMS32    __in _PVOID AbsAddress, __in _DWORD Size, __in _BYTE Value
RETURNS     VOID
    push    ebp
    mov     ebp,    esp
    pusha
    pushf

    mov     edi,    [%$AbsAddress]
    mov     ecx,    [%$Size]
    mov     eax,    [%$Value]
    cld
    rep     stosb

    popf
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC

%ifdef DOC_METHOD
    Copy a memory block (no overlapping source and destination support!)
%endif
PROC32      copyMem
PARAMS32    __in _PVOID Destination, __in _DWORD Source, __in _DWORD Size
RETURNS     VOID
    push    ebp
    mov     ebp,    esp

    pushf
    push    ecx
    push    esi
    push    edi

    mov     esi,    [%$Source]
    mov     edi,    [%$Destination]
    mov     ecx,    [%$Size]
    cld
    test    ecx,    3           ; ecx % 4
    if z
            shr     ecx,    2   ; ecx / 4
            rep     movsd
    else
            rep     movsb
    endif

    pop     edi
    pop     esi
    pop     ecx
    popf

    pop     ebp
    ret     PARAMS_SIZE
ENDPROC

%ifdef DOC_METHOD
    Allocate memory at page granularity
%endif
PROC32      allocPhysicalPages
PARAMS32    __in _DWORD NumberOfPages
RETURNS     PA of the first allocated byte
    push    ebp
    mov     ebp,    esp
    pusha
    mov     ecx,    [PARAM(0)]                                  ; number of pages
    mov     eax,    [fs: RVA(tempMem.NextFreeAddress)]

    ; align the address
    add     eax,    PAGE_SIZE - 1
    and     eax,    PAGE_MASK

    ; check if enough mem.
    shl     ecx,    12                                          ; number of pages * PAGE_SIZE
    cmp     ecx,    [fs: RVA(tempMem.Length)]
    jae     .outOfMem

    sub     [fs: RVA(tempMem.Length)], ecx                      ; allocated

    ; find out where's the end of the block
    add     ecx,    eax
    mov     [fs: RVA(tempMem.NextFreeAddress)], ecx                         ; remember the new address of first free block
    jmp     .done

.outOfMem:
    xor     eax,    eax
.done:
    mov     [esp + PUSHA32.Eax], eax                            ; _at the return value on the PUSHA32 structure on top-of-stack
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC


PROC32      printHex
PARAMS32    __in _DWORD Value
RETURNS     VOID
    push    ebp
    mov     ebp,    esp
    pusha
    pushf
    call    .getAdr
    db      '0123456789ABCDEF'
.getAdr:
    pop     ebx                 ; ebx = translation table
    xor     dx,     dx          ; dx = stop skipping zeroes
    mov     eax,    [%$Value]
    mov     ecx,    8
.next:
    rol     eax,    4
    push    eax
    and     al,     0xF

    if zero(dx)                 ; dx = 0 while no useful digit has been found
        ifnot zero(al)          ; al = current digit
            inc     dx
            jmp     .print
        endif
    else
        .print:
            xlatb
            stdcall printChar,  eax
    endif

    pop     eax
    cmp     ecx,    3
    adc     dx,     0           ; jb is jc, cx = 2 => last digit => cf=1 => stop skipping zeroes => print a zero :p
    loop    .next

    popf
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC


PROC32      printHexFmt
PARAMS32    __in _DWORD Value
    push    ebp
    mov     ebp,    esp
    print   "0x"
    stdcall printHex, [%$Value]
    print   " "
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC



PROC32      printString
PARAMS32    __in _PBYTE String
RETURNS     VOID
    push    ebp
    mov     ebp,    esp
    pusha
    pushf
    mov     esi,    [%$String]

.next:
    lodsb
    ifnot zero(al)
        movzx   eax,    al
        stdcall printChar, eax
        jmp     .next
    endif

    popf
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC



PROC32      printChar
PARAMS32    __in _BYTE Char
RETURNS     VOID
    push    ebp
    mov     ebp,    esp
    pusha
    pushf

    call    .next
.screenPos      dd  0
.screenSize     dd  80*50*2
.screenColor    dd  7
.next:
    pop     esi

    ; make sure we're not outside of screen mem
    mov     eax,    [esi]
    cmp     eax,    [esi + 4]
    jb      .keepAdr
.scroll:
    stdcall scrollLine
    mov     eax,    [esi + 4]
    sub     eax,    80*2        ; eax right at the beginning of the last line
.keepAdr:

    ; process '\n'
    cmp     BYTE [%$Char], nl
    jne     .keepLine
    push    eax
    mov     bx,     80*2
    xor     dx,     dx
    div     bx                  ; dx = position in line
    xor     ecx,    ecx
    mov     cx,     80*2
    sub     cx,     dx          ; cx = remaining bytes to end-of-line
    shr     cx,     1
    pop     edi                 ; edi <- position
    mov     ah,     [esi + 8]   ; get the color
    mov     al,     0
    cld
    add     edi,    0xb8000
    rep     stosw               ; fill with blanks remaining chars
    sub     edi,    0xb8000
    mov     [esi],  edi         ; save the new position
    jmp     .done

.keepLine:
    mov     edi,    eax
    inc     eax
    inc     eax
    mov     [esi],  eax         ; save the updated position

    mov     al,     [%$Char]
    mov     ah,     [esi + 8]   ; get the color
    mov     [0xb8000 + edi],    ax

.done:
    popf
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC




PROC32      scrollLine
RETURNS     void
    stdcall copyMem, 0xb8000, 0xb8000 + 2*80, 2*80*(50-1)
    ret     PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Switches to Real Mode and calls the given address.
    !!! don't call directly, USE the RM_CALL macro !!!
%endif
PROC32      callToRealMode
PARAMS32    __in _DWORD RealModeBuf, __in _DWORD RmProcAddr, __in _DWORD RmProcSize, __in _DWORD RmParamsSize
RETURNS     VOID
    push    ebp
    mov     ebp,    esp

    pusha
    pushf
    push    ds
    push    es
    push    fs
    push    gs
    push    ss

    ; prepare a stack for the RM code and save current esp on its stack + leave space for cr0
    mov     [0x7c00 - 4], esp

    ; copy its parameters to its own stack
    mov     ecx,        [%$RmParamsSize]
    lea     esi,        [ebp + 8 + PARAMS_SIZE] ; skip ebp + retaddr + local params
    mov     ebx,        0x7c00 - 8          ; -8 is where cr0 is supposed to go
    sub     ebx,        ecx                 ; ebx = top of stack for rm proc (right after params)
    stdcall copyMem, ebx, esi, ecx
;println "copy ", ebx, " <- ", esi, " : ", ecx, " = ", DWORD[ebx]

    ; copy the real-mode procedure code to the desired address
    mov     edi,        [%$RealModeBuf]
    mov     ecx,        [%$RmProcSize]
;println "copy ", edi, " <- ", DWORD [%$RmProcAddr], " : ", ecx
    stdcall copyMem, edi, [%$RmProcAddr], ecx
    lea     edi,        [edi + ecx]         ; edi: remember where the target code ended

    ; copy our trampoline right after it
    stdcall getPxeBase
    lea        esi,        [eax + RVA(.startOfLowMemCode)]

;println "copy ", edi, " <- ", esi, " : ", .endOfLowMemCode - .startOfLowMemCode
    stdcall copyMem, edi, esi, .endOfLowMemCode - .startOfLowMemCode

    ; set the new stack and execute startOfLowMemCode from the new address space
    mov     esp,        ebx
    push    WORD [%$RealModeBuf]             ; save the RM proc address on the new stack

    jmp     edi

%define RMA(x) (x - .startOfLowMemCode)

.startOfLowMemCode:

    call    .getEip
.getEip:
    ; set ebp to the runtime image base of the .startOfLowMemCode block (ebp = bp)
    pop     ebp
    sub     ebp,    .getEip - .startOfLowMemCode

    lea     eax,    [ebp + RMA(.backTo16Bits)]
    mov     [ebp + RMA(.patchMe) + 1], eax
    jmp     .patchMe

    ; get back to 16 bits
.patchMe:
    jmp     SEL_CODE16: 0xFFFFFFFF  ; runtime patched to backTo16Bits (bytes: 0xEA ADDR ADDR ADDR ADDR SEG SEG)

.backTo16Bits:
    [bits 16]

    mov     ax,     SEL_DATA16
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax

    ; deactivate protection
    mov     eax,    cr0
    mov     [0x7c00 - 8], eax       ; save original cr0
    and     eax,    0xFFFFFFFF - (bit(31) + bit(0))
    mov     cr0,    eax

    lea     ax,    [bp + RMA(.backToRmCode)]
    mov     [bp + RMA(.patchme2) + 1], ax
    jmp     .patchme2

    ; prepare real mode registers
.patchme2:
    jmp     00: 0xFFFF              ; runtime patched to backToRmCode (bytes: 0xEA ADDR ADDR SEG SEG)
.backToRmCode:
    xor     ax,     ax
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax


    ;;;
    ;;; execute the actual real-mode task (rm-address is right on top of the stack)
    ;;;
    pop     ax
    call    ax
    pushf
    pop     dx
    ; TODO: make sure ax and dx are preserved (never overwritten past this point)


    ; switch back to 32
    cli
    mov     ebx,    [0x7c00 - 8]
    mov     cr0,    ebx
    lea     bx,     [bp + RMA(.toBits32)]
    mov     [bp + RMA(.patchme3) + 1], bx
    jmp     .patchme3

.patchme3:
    jmp     SEL_CODE32: 0xFFFF      ; runtime patched to toBits32 (bytes: 0xEA ADDR ADDR SEG SEG)

.toBits32:
    [bits 32]
    mov     bx,     SEL_DATA32
    mov     ss,     bx

    ; at return: revert to original stack and return to caller
    mov     esp,    [0x7c00 - 4]
    pop     ss
    pop     gs
    pop     fs
    pop     es
    pop     ds

    ; restore the 32 bits context from the PM32 stack
    popf

    and     eax,    0xFFFF
    push    eax
    mov     ah,     dl
    sahf                            ; keep the CF PF AF ZF SF as set by the real-mode code (the other bits are reserved)
    pop     eax
    ; TODO: avoid any flags-altering instructions past this point!

    mov     [esp + PUSHA32.Eax], eax
    popa

    pop     ebp
    ret     PARAMS_SIZE
    .endOfLowMemCode:
ENDPROC

PROC16      initTextMode16
PARAMS16    __in _WORD ModeNumber
RETURNS     VOID
    push    bp
    mov     bp,     sp

    mov     ax,     [%$ModeNumber]
    int     10h

    mov     ax,     0x1112
    mov     bl,     0
    int     10h

    pop     bp
    ret     PARAMS_SIZE
ENDPROC

%ifdef DOC_METHOD
    Iterates the BIOS E820 memory map and calls a callback given as parameter or every entry.
    If the callback returns 0 in EAX the ieration is stopped.
%endif
PROC32      iterateMemMap
PARAMS32    __in CallbackFunction32
RETURNS     VOID
    ; we'll be using 00:0x600 as temp buffer with stack at 0x7c00, this is ok for pure PXE load (no TXT), for TXT-enabled load the mem map MUST be sent by loader!
%define LOWMEM(X) X - .startOfLowMemCode + 0x600
    push    ebp
    mov     ebp,    esp
    pusha
    pushf

    ; copy the following code to lower memory
    mov     edi,    0x600
    mov     esi,    [fs: RVA(pxeBase)]
    add     esi,    RVA(.startOfLowMemCode)
    mov     ecx,    .endOfLowMemCode - .startOfLowMemCode
    cld
    rep     movsb


    ; make ready the param values for the 16 bits code
    mov     edx,    [%$CallbackFunction32]

    ; save context
    push    ebp
    push    ds
    push    es
    push    fs
    push    gs
    push    ss

    ; prepare a stack + stack frame for the real-mode code
    mov     [0x7c00-4], esp
    mov     esp,    0x7c00-4
    mov     eax,    cr0
    push    eax
    push    edx

.startOfLowMemCode:

    ; enter 16 bits
    cli
    jmp     SEL_CODE16:LOWMEM(.bits16)
.bits16:
    [bits 16]

    ; 16 bit protected mode
    ; set 16 bit data selectors
    mov     ax,     SEL_DATA16
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax

    mov     eax,    cr0
    and     eax,    0xFFFFFFFF - (CR0.PG + CR0.PE)
    mov     cr0,    eax ; Go to 16 bit real mode

    ; protected mode is OFF now
    ; clear segment selectors
    xor     ax,     ax
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax
    jmp     00: LOWMEM(.realMode)

    ; consistent real mode state, orig esp + params on stack (at bp we'll have fn, cr0 and esp)
.realMode:
    mov     bp,     sp
    xor     ebx,    ebx                             ; continuation code
    sub     sp,     sizeof(MEM_MAP_ENTRY_RAW)       ; alloc. storage for a mem entry, a return value for selected block address and an entry counter
    mov     di,     sp                              ; es:di points to the entry buffer
    mov     edx,    0x534D4150                      ; 'SMAP'

    ; get an entry
.getNextEntry:
    sti
    mov     eax,    0xe820
    mov     ecx,    sizeof(MEM_MAP_ENTRY_RAW)
    int     15h
    jc      .error

    cmp     edx,    0x534D4150                      ; 'SMAP'
    jne     .error

    ; switch back to 32 bits to call the function
    cli

    ; save the real mode registers for continuation
    pushad

    mov     eax,    [bp + 4]                        ; caller's cr0
    mov     cr0,    eax
    mov     ebx,    [bp]                            ; callback function
    mov     esi,    [bp + 8]                        ; caller's esp

    jmp     SEL_CODE32: LOWMEM(.toBits32)
.toBits32:

    [bits 32]
    mov     ax,     SEL_DATA32
    mov     ss,     ax

    ; remember the stack position and grab the callback function
    xor     eax,    eax
    mov     ax,     sp

    ; restore the 32 bits context from the PM32 stack

    mov     esp,    esi
    pop     ss
    pop     gs
    pop     fs
    pop     es
    pop     ds
    pop     ebp

    ; save the context back on stack for later use
    push    ebp
    push    ds
    push    es
    push    fs
    push    gs
    push    ss

    push    eax                                     ; remember the RM stack position

    ; call the target function
    movzx   eax,    di
    push    eax                                     ; param
    call    ebx                                     ; fn address, fn returns -1 for error, 0 to terminate processing, 1 to continue
    ; switch back the stack to the RM one
    pop     esp                                     ; RM stack taken from PM32 stack

    ; make sure the callback retval isn't lost
    mov     [esp + PUSHA32.Eax],    eax

    ; get back to 16 bits
    jmp     SEL_CODE16: LOWMEM(.backTo16Bits)

.backTo16Bits:
    [bits 16]
    mov     ax,     SEL_DATA16
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax

    ; deactivate protection
    mov     eax,    cr0
    and     eax,    0xFFFFFFFF - (bit(31) + bit(0))
    mov     cr0,    eax

    ; restore the real mode registers to continue the map query loop, ax will contain the callback retval
    jmp     00: LOWMEM(.backToRmCode)
.backToRmCode:
    xor     ax,     ax
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax
    popad

    ; continue with the next entry if this wasn't the last one and no error occured
    cmp     ax,     -1
    je      .error

    test    ax,     ax              ; if we've got 0 from callback stop iterating
    mov     ax,     1
    jz      .done

    test    ebx,    ebx
    jnz     .getNextEntry

    jmp     .done                   ; with ax = 1

.error:
    xor     eax,    eax

.done:
    ; grab the results (to edx:esi, ecx) and orig stack pointer, then return to caller
    cli
    mov     ebx,    [bp + 4]        ; at bp: callback, cr0, esp
    mov     esp,    [bp + 8]
    mov     cr0,    ebx
    jmp     SEL_CODE32: LOWMEM(.backTo32)

.backTo32:
    [bits 32]

    ; restore the full context from the PM32 stack
    mov     bx,     SEL_DATA32
    mov     ss,     bx
    pop     ss
    pop     gs
    pop     fs
    pop     es
    pop     ds
    pop     ebp

    ; get back to main code
    push    DWORD [fs:RVA(pxeBase)]
    add     [esp], DWORD RVA(.backToHighMem)
    ret
.endOfLowMemCode:

.backToHighMem:
    popf

    ; make the result persistent
    mov     [esp + PUSHA32.Eax], eax

    ; all done
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC iterateMemMap


%ifdef DOC_METHOD
    Checks if the given address is suitable for relocating the boot modules.
%endif
PROC32      checkMemoryAddress
PARAMS32    _DWORD Address
RETURNS     FALSE if the block is not suitable (to allow the mem map iteration to continue)
    push    ebp
    mov     ebp,    esp
    push    ebx
    push    ecx
    push    esi
    push    edi
    push    edx
    mov     edx,    [%$Address]

    ; avoid real-mode memory
    cmp     edx,    MEGA
    jb      .bad

    ; check against the lowest explicitly allowed address
    cmp     edx,    PXE32_RESERVE_MEM_ABOVE
    jb      .bad

    ; ebx <- last address in supposed allocated range
    lea     ebx,    [edx - 1]
    add     ebx,    [fs: RVA(tempMemLength)]    ;TEMP_BUFFER_SIZE

    ; must not cross 4GB
    jc      .bad

    ; must not overlap with any known multiboot module (edx = start, ebx = end of considered mem region)
    mov        ecx,    MAX_MODULES
    getModulePtr(0)            ; get the first table entry

.next:
    ; skip missing modules
    if zero(eax)
            jmp        .continue
    endif

    mov        esi,    [eax + BOOT_MODULE.Pa]
    if zero(esi)
            jmp        .continue
    endif

    mov        edi,    [eax + BOOT_MODULE.Size]
    if zero(edi)
            jmp        .continue
    endif

    lea        edi,    [edi + esi - 1]        ; last valid address in module

    ; (ESI <= EBX && EDX <= EDI) <=> Memory regions overlap
    ifnot above(esi, ebx)
        ifnot above(edx, edi)
            jmp     .bad
        endif
    endif

.continue:
    add        eax,    sizeof(BOOT_MODULE)
loop    .next

.notOverlapping:
    mov     eax,    1
    jmp     .cleanup

.bad:
    xor     eax,    eax
.cleanup:
    pop        edx
    pop     edi
    pop     esi
    pop     ecx
    pop     ebx
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC checkMemoryAddress


%ifdef DOC_METHOD
    Callback function for iterateMemMap
%endif
PROC32      selectMemoryBlock
PARAMS32    _POINTER MemMapEntry
RETURNS     TRUE if the block is not suitable (to allow the mem map iteration to continue)
    push    ebp
    mov     ebp,    esp
    push    esi
    push    ebx
    push    edi
    push    edx
    push    ecx

    mov     esi,    [%$MemMapEntry]

    ; must be available
    cmp     [esi + MEM_MAP_ENTRY_RAW.Type], DWORD MEM_TYPE_AVAILABLE
    jne     .bad

    ; must be below 4GB
    cmp     [esi + MEM_MAP_ENTRY_RAW.BaseAddress+4], DWORD 0
    jnz     .bad

%ifdef ABOVE_128MB_LINUX
    ; must be above 128MB
    cmp     [esi + MEM_MAP_ENTRY_RAW.BaseAddress], DWORD 128 * MEGA
    jbe     .bad
%endif
    ; get ebx = base, edx:ecx = length
    mov     ebx,    [esi + MEM_MAP_ENTRY_RAW.BaseAddress]

    mov     ecx,    [esi + MEM_MAP_ENTRY_RAW.Length]
    mov     edx,    [esi + MEM_MAP_ENTRY_RAW.Length + 4]

.nextBlock:
    ; must be large enough (64bits)
    push    ecx
    push    edx
    sub     ecx,    [fs: RVA(tempMemLength)]    ;TEMP_BUFFER_SIZE
    sbb     edx,    0
    pop     edx
    pop     ecx
    jc      .bad

    stdcall checkMemoryAddress, ebx
    if zero(eax)
        ; advance by 1 mega
        add     ebx,    MEGA

        ; consider 1 less mega available
        sub     ecx,    MEGA
        sbb     edx,    0
        jmp     .nextBlock
    endif

.found:
    mov     [fs: RVA(tempMem.NextFreeAddress)], ebx
    mov     [fs: RVA(tempMem.Pa)], ebx
    mov     [fs: RVA(tempMem.Va)], ebx
    mov     eax,    [fs: RVA(tempMemLength)]
    mov     [fs: RVA(tempMem.Length)], eax      ;TEMP_BUFFER_SIZE
    xor     eax,    eax

    jmp     .cleanup

.bad:
    xor     eax,    eax
    inc     eax

.cleanup:
    pop     ecx
    pop     edx
    pop     edi
    pop     ebx
    pop     esi

    pop     ebp
    ret     PARAMS_SIZE
ENDPROC selectMemoryBlock



PROC32      createMemoryMap
PARAMS32    _POINTER MemMapEntry
RETURNS     1 if processed, -1 for error / abort
    push    ebp
    mov     ebp,    esp
    push    edx
    push    esi
    push    edi
    push    ecx
    pushf

    mov     esi,    [%$MemMapEntry]
%ifdef DEBUG
    print   "MEM_MAP_ENTRY_RAW: "
    hex     [esi + MEM_MAP_ENTRY_RAW.BaseAddress+4]
    hex     [esi + MEM_MAP_ENTRY_RAW.BaseAddress]
    print   " => "
    hex     [esi + MEM_MAP_ENTRY_RAW.Length]
    print   " : "
    hex     [esi + MEM_MAP_ENTRY_RAW.Type], nl
%endif


    mov     edi,    [fs: RVA(tempMap)]
    mov     ecx,    [fs: RVA(tempMapIndex)]
    mov     eax,    sizeof(MEM_MAP_ENTRY)
    mul     ecx
    lea     ecx,    [eax + MEMORY_MAP.Entries]              ; ecx = 4 + index*sizeof(MEM_MAP_ENTRY)

    ; avoid overflow
    cmp     ecx,    sizeof(MEMORY_MAP)
    jnb     .error

    ; save the entry
    add     edi,    ecx
    mov     ecx,    sizeof(MEM_MAP_ENTRY)
    cld
    mov     eax,    sizeof(MEM_MAP_ENTRY) - 4
    ;stosd
    ; set the StructureSize field to sizeof(MEM_MAP_ENTRY) - 4
    rep     movsb

    ; done, advance and return 1 to continue
    inc     DWORD [fs: RVA(tempMapIndex)]
    xor     eax,    eax
    inc     eax
    jmp     .done

.error:
    xor     eax,    eax
    dec     eax
.done:
    popf
    pop     ecx
    pop     edi
    pop     esi
    pop     edx
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC createMemoryMap

%ifdef DOC_METHOD
    Saves in the given module id boot module structure the PA, VA, Size and Flags parameters
%endif
PROC32      registerModule
PARAMS32    __in _DWORD Id, __in _DWORD Va, __in _DWORD Pa, __in _DWORD Size, __in _DWORD Flags
RETURNS     0 for error or the address of the added entry
    push    ebp
    mov     ebp,    esp

    getModulePtr([%$Id])
    FAIL_IF zero(eax)

    movm    DWORD [eax + BOOT_MODULE.Pa],        DWORD [%$Pa]
    movm    DWORD [eax + BOOT_MODULE.Va],        DWORD [%$Va]
    movm    DWORD [eax + BOOT_MODULE.Size],        DWORD [%$Size]
    movm    DWORD [eax + BOOT_MODULE.Flags],    DWORD [%$Flags]
    jmp        .done

.cleanup:
    xor        eax,    eax

.done:
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC     registerModule


%ifdef DOC_METHOD
    Relocates a single module to a new address given as parameter. Updates the BOOT_MODULE structure to reflect the changes.
%endif
PROC32        relocateModule
PARAMS32    ModulePtr
RETURNS        NULL or the new address
    push    ebp
    mov        ebp,    esp
    push    esi
    push    edx

    mov        esi,    [%$ModulePtr]

    ; alloc mem for the copy
    mov        eax,    [esi + BOOT_MODULE.Size]
    add        eax,    PAGE_SIZE - 1        ; round-up its size to page size
    shr        eax,    12
    println "alloc ", eax
    CALL_OR_FAIL allocPhysicalPages, eax
    mov        edx,    eax

    println "copy to ", edx
    ; copy to the new address
    STDCALL    copyMem, edx, [esi + BOOT_MODULE.Pa], [esi + BOOT_MODULE.Size]

    ; reflect the updated address
    mov        [esi + BOOT_MODULE.Pa], edx
    mov        [esi + BOOT_MODULE.Va], edx
    mov        eax,    edx
    println "Returning ", eax
    jmp        .done

.cleanup:
    xor        eax,    eax
.done:
    pop        edx
    pop        esi
    pop        ebp
    ret        PARAMS_SIZE
ENDPROC


%ifdef DOC_METHOD
    Iterates all modules and relocates them at a new memory location.
    If a module is not available it is skipped.
    The last module relocated is always napoca image.
%endif
PROC32      relocateModules
RETURNS        NULL or the new address of the main module
    push    ebp
    mov     ebp, esp

    xor        ecx,    ecx
    getModulePtr(0)    ; pointer to the first indexed entry
    println "modules start at ", eax
    mov        esi,    eax

.next:
    ; skip copying the napoca module to the new address at this point
    ; otherwise the new copy won't contain correct values for modules-related variables
    if equal (ecx, LD_MODID_NAPOCA_IMAGE)
        jmp        .continue
    endif

    ; skip missing modules
    if zero(DWORD [esi + BOOT_MODULE.Size])
        jmp        .continue
    endif
    if zero(DWORD [esi + BOOT_MODULE.Pa])
        jmp        .continue
    endif

    CALL_OR_FAIL relocateModule, esi
    println "relocated ", ecx, "to ", eax

.continue:
    ; advance and loop
    add        esi,    sizeof(BOOT_MODULE)
    inc        ecx
    if below(ecx, MAX_MODULES)
            jmp        .next
    endif

    ; copy the main module now that all the others have known addresses
    getValidModulePtr(LD_MODID_NAPOCA_IMAGE)
    FAIL_IF zero(eax)
    CALL_OR_FAIL relocateModule, eax

    ; let the napoca address (in eax) be returned...
    jmp        .done

.cleanup:
    xor        eax,    eax
.done:
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC



activateFpuSupport:
    %define     CR0_MP  (1 << 1)
    %define     CR0_EM  (1 << 2)
    %define     CR0_TS  (1 << 3)
    %define     CR0_NE  (1 << 5)

    %define     CR4_OSFXSR      (1 << 9)
    %define     CR4_OSXMMEXCPT  (1 << 10)
    %define     CR4_OSXSAVE     (1 << 18)

    %define     CPUID_FPU       (1 << 0)
    %define     CPUID_XSAVE     (1 << 26)

    pusha
    xor     eax,    eax
    inc     eax
    cpuid
    test    edx,    0x1         ; bit 0 in edx specifies fpu support

    jz      .notSupported

    ; test the presence of the fpu
    mov     eax,    cr0
    and     eax,    0xFFFFFFFF - (CR0_TS + CR0_EM)
    mov     cr0,    eax
    fninit
    fnstsw  [ebp + RVA(fpuTestWord)]
    cmp     word    [ebp + RVA(fpuTestWord)],   0
    jnz     .notSupported

    mov     eax,    cr0
    and     eax,    0xFFFFFFFF - CR0_NE         ; disable interrupt generation on exceptions
    or      eax,    CR0_MP                      ; should be inverse of EM, and EM is 0
    mov     cr0,    eax

    mov     eax,    cr4
    or      eax,    CR4_OSFXSR
    and     eax,    0xFFFFFFFF - CR4_OSXMMEXCPT
    mov     cr4,    eax

    ; enable xsave
    xor     eax,    eax
    inc     eax
    test    ecx,    CPUID_XSAVE
    jz      .noXsaveSupport

    mov     eax,    cr4
    or      eax,    CR4_OSXSAVE
    mov     cr4,    eax
    .noXsaveSupport:
    .notSupported:

    popa
    ret



%ifdef DOC_METHOD
    Compares two C strings given as parameter.
%endif
PROC32      strequal
PARAMS32    __in __ptr CX_UINT8 Str1, __in __ptr CX_UINT8 Str2
RETURNS     non-zero on success
    push    ebp
    mov     ebp,    esp
    pusha
    pushf

    mov        esi,    [%$Str1]
    FAIL_IF zero(esi)
    mov        edi,    [%$Str2]
    FAIL_IF zero(edi)

    cld
    .loop:
            if zero(BYTE[esi])
                if different(BYTE[edi], 0)
                        jmp        .cleanup
                endif
                jmp        .success
            endif

            cmpsb
            if ne
                jmp        .cleanup
            endif
    jmp        .loop

.success:
    xor        eax,    eax
    inc        eax
    jmp        .done
.cleanup:
    xor        eax,    eax
.done:
    popf
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop        ebp
    ret     PARAMS_SIZE
ENDPROC     getMinimum

%ifdef DOC_METHOD
    Returns in eax the module Id afferent to the given boot module name string.
    Eax = -1 if the module si not found.
%endif
PROC32      getModuleIdByMultibootName
PARAMS32    __in String
RETURNS     module Id or -1
    push    ebp
    mov     ebp,    esp
    pusha
    pushf

    stdcall getPxeBase
    mov     edx,    eax

    cld
    lea        edi,    [edx + RVA(MultibootModuleNameToModId)]
    mov        ecx,    MULTIBOOT_NAMES_COUNT
    xor        ecx,    ecx

    .loop:
            ifnot    below(ecx,    MULTIBOOT_NAMES_COUNT)
                    jmp        .cleanup
            endif

            mov        esi,    [%$String]
            mov        ebx,    [edi + MULTIBOOT_NAMEPTR_TO_ID.Name]    ; get the name rva
            lea        ebx,    [edx + ebx]                                ; fix the name rva to actual address

            ; must check for match at each word boundary (the string might contain additional garbage sent to us..)
            .retry:
                    STDCALL strequal, esi,    ebx
                    ifnot zero(eax)
                            mov        eax,    [edi + MULTIBOOT_NAMEPTR_TO_ID.ModId]
                            jmp        .done
                    endif


                .toSpaces:
                    ; advance until a \0 or ' '
                    ifnot zero(BYTE[esi])
                            ifnot equal(BYTE[esi], ' ')
                                    inc        esi
                                    jmp        .toSpaces
                            endif
                    endif

                .skipSpaces:
                    ; advance while spaces
                    if equal(BYTE[esi], ' ')
                            inc        esi
                            jmp        .skipSpaces
                    endif

                    ifnot zero(BYTE[esi])
                            jmp        .retry
                    endif

            ; no match, try the next MultibootModuleNameToModId entry
            inc        ecx
            add        edi,    sizeof(MULTIBOOT_NAMEPTR_TO_ID)
    jmp        .loop

.cleanup:

    xor        eax,    eax
    dec        eax
.done:
    popf
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop        ebp
    ret     PARAMS_SIZE
ENDPROC     getMinimum

%ifdef DOC_METHOD
    Dumps boot modules.
%endif
PROC32      dumpMultibootModules
PARAMS32    __in MultibootInfoPointer
RETURNS     non-zero on success
    push    ebp
    mov     ebp,    esp
    pusha

    ; verify we have multiboot modules -- "present if flags[3] is set"
    mov     ebx,    [%$MultibootInfoPointer]
    bt      DWORD   [ebx + MULTIBOOT_INFO.flags], 3
    FAIL_IF nc

    mov     ecx,    [ebx + MULTIBOOT_INFO.mods_count]
    FAIL_IF zero(ecx)

    stdcall getPxeBase
    mov     edx,    eax

    push    ecx
    mov     esi,    [ebx + MULTIBOOT_INFO.mods_addr]                        ; esi points to a MULTIBOOT_MODULE array element
    .loop1:
            ; lookup the module id by its multiboot name

            print "MOD [", ecx, "] <"
            STDCALL printString, [esi + MULTIBOOT_MODULE.string]
            STDCALL getModuleIdByMultibootName, [esi + MULTIBOOT_MODULE.string]
            mov edx, [esi + MULTIBOOT_MODULE.mod_start]
            mov edx, [edx]
            println "> = ", eax, "base = ", [esi + MULTIBOOT_MODULE.mod_start], " end = ", [esi + MULTIBOOT_MODULE.mod_end], " ctrl = ", edx
            add        esi,    sizeof(MULTIBOOT_MODULE)
            dec        ecx
    jnz        .loop1
    pop        ecx

.success:
    xor        eax,    eax
    dec        eax
    jmp        .done

.cleanup:
    print    "failed[", ecx, "]"
    xor        eax,    eax
.done:
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC     getMinimum


%ifdef DOC_METHOD
    Parse the MULTIBOOT_INFO structure and retrieve the PA, VA, size and flags of the loaded boot modules.
%endif
PROC32      retrieveLoaderModules
PARAMS32    __in MultibootInfoPointer
RETURNS     non-zero on success
    push    ebp
    mov     ebp,    esp
    pusha

    ; verify we have multiboot modules -- "present if flags[3] is set"
    mov     ebx,    [%$MultibootInfoPointer]
    bt      DWORD   [ebx + MULTIBOOT_INFO.flags], 3
    FAIL_IF nc

    mov     ecx,    [ebx + MULTIBOOT_INFO.mods_count]
    FAIL_IF zero(ecx)

    stdcall getPxeBase
    mov     edx,    eax

    mov     esi,    [ebx + MULTIBOOT_INFO.mods_addr]                        ; esi points to a MULTIBOOT_MODULE array element
    .loop:
            ; lookup the module id by its multiboot name

            ;print "MOD [", ecx, "] <"
            ;STDCALL printString, [esi + MULTIBOOT_MODULE.string]
            STDCALL getModuleIdByMultibootName, [esi + MULTIBOOT_MODULE.string]
            ;println "> = ", eax
            FAIL_IF equal(eax, 0xFFFFFFFF)
            FAIL_IF above(eax, MAX_MODULES)


            ; init the ldModules entry fields
            getStructureIndex(BOOT_MODULE, eax)
            lea        edi,    [edx + RVA(ldModules) + eax]
            mov        eax,    [esi + MULTIBOOT_MODULE.mod_start]
            mov        [edi + BOOT_MODULE.Va],    eax                                ; we don't care about the high-part (it's zero already)
            mov        [edi + BOOT_MODULE.Pa],    eax

            mov        ebx,    [esi + MULTIBOOT_MODULE.mod_end]
            sub        ebx,    eax                                                ; "the memory used goes from bytes 'mod_start' to 'mod_end-1' inclusive"
            mov        [edi + BOOT_MODULE.Size], ebx

            mov        [edi + BOOT_MODULE.Flags], DWORD LD_MODFLAG_PERMANENT
            add        esi,    sizeof(MULTIBOOT_MODULE)
            dec        ecx
    jnz        .loop

.success:
    xor        eax,    eax
    dec        eax
    jmp        .done

.cleanup:
    print    "failed[", ecx, "]"
    xor        eax,    eax
.done:
    mov     [esp + PUSHA32.Eax], eax
    popa
    pop     ebp
    ret     PARAMS_SIZE
ENDPROC     getMinimum

%ifdef DOC_METHOD
    NULL or the effective address of the corresponding BOOT_MODULE structure if such a module (really) exists.
%endif
PROC32        getModulePtrEx
PARAMS32    ModId, ValidateMem
RETURNS        NULL or the effective address of the corresponding BOOT_MODULE structure if such a module (really) exists
    push    ebp
    mov        ebp,    esp
    push    edx
    print "Get ", [%$ModId]

    ; Check the module id to be a valid one
    FAIL_IF above (DWORD [%$ModId], MAX_MODULES)

    ; Get the image base address and store it in edx
    stdcall getPxeBase
    mov     edx,    eax

    ; Multiply the ModId by sizeof(BOOT_MODULE) and store the result in eax
    getStructureIndex(BOOT_MODULE, [%$ModId])

    ; Get the address of the beggining of the desired module in eax
    lea        eax,    [edx + eax + RVA(ldModules)]

    ifnot zero(DWORD [%$ValidateMem])
            FAIL_SILENT_IF zero (DWORD [eax + BOOT_MODULE.Pa])
            FAIL_SILENT_IF zero (DWORD [eax + BOOT_MODULE.Size])
    endif

    jmp        .done

.cleanup:
    xor        eax,    eax
.done:
    pop        edx
    pop        ebp
    ret     PARAMS_SIZE
ENDPROC



PROC32      dumpModules
    push    ebp
    mov        ebp,    esp
    pusha

    xor        ecx,    ecx
    getModulePtr(0)    ; pointer to the first indexed entry
    mov        esi,    eax

.next:
    println    "id = ", ecx, " base = ", [esi + BOOT_MODULE.Pa], " va = ", [esi + BOOT_MODULE.Va], " size = ", [esi + BOOT_MODULE.Size], " f = ", [esi + BOOT_MODULE.Flags]

    add        esi,    sizeof(BOOT_MODULE)
    inc        ecx
    if below(ecx, MAX_MODULES)
            jmp        .next
    endif


    popa
    pop        ebp
    ret
ENDPROC

times PAGE_SIZE - (($-bootStart) % PAGE_SIZE) db 0




;
; Define a label right after the last emitted byte
;

bootEnd:


