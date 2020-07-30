;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

;
; In-guest boot loader code, this code tries to locate the disk containing the MBR responsable for loading the OS
;
;;;%define DEBUG_REALMODE_GUEST
global __GuestPxeMbrLoaderCode
global __GuestPxeMbrLoaderCodeEnd
global __GuestPxeMbrLoaderEntry

global __GuestPxeGrubInfo
[bits 16]

%define CheckIfProtectiveMbr(BufferSegment, BufferOffset, PartitionNumber) _CheckIfProtectiveMbr BufferSegment, BufferOffset, PartitionNumber
%macro _CheckIfProtectiveMbr 3
    push    ax

    mov     al, [%1:%2 + 0x1BE + 0x10 * %3 + 0x4]

    cmp     al, 0xED
    jb      %%clearCarry
    cmp     al, 0xEF
    ja      %%clearCarry

    stc

    jmp     %%finish
%%clearCarry:
    clc
%%finish:
    pop     ax
%endmacro

;
; If you need to test some custom guest code define DEBUG_REALMODE_GUEST
;
;%define DEBUG_REALMODE_GUEST




__GuestPxeMbrLoaderCode:

%ifndef DEBUG_REALMODE_GUEST
    ;
    ; HALTED/WAIT-FOR-SIPI code trap - cs/ip set to this address but SHOULDN'T be executed
    ;
    cli
    .again:
        pause
    jmp     .again

__GuestPxeMbrLoaderEntry:
    jmp     __GuestPxeGrubInfo.start

    ;
    ; MACRO definitions
    ;
    %define PXE_RELOC(label) (0x7e00 + __GuestPxeMbrLoaderEntry %+ label - __GuestPxeMbrLoaderCode)
    %define PXE_RELOC2(label) (0x7e00 + __GuestPxeGrubInfo %+ label - __GuestPxeMbrLoaderCode)
    PXE_COLOR       equ 'a'
    PXE_HEX_COLOR   equ 'z'

    %macro _LINETRACE 0
        push    dx
        mov     dl, (__LINE__ % 100)
        call    .printHexDl
        pop     dx
    %endmacro

    %macro _EMPTY_MACRO 0-*
    %endmacro

    %define LINETRACE _EMPTY_MACRO


    ;
    ; FUNCTIONS
    ;
    .hexTable:
        db "0123456789ABCDEF"

    .screenPosition dw 0

    .startedString      db "WINBOOT START, "
    STARTEDSTRING_LEN   equ $- .startedString

    .tryString          db "try boot:"
    TRYSTRING_LEN       equ $ - .tryString

    .failedString       db "NO BOOTABLE MBR!"
    FAILEDSTRING_LEN    equ $ - .failedString

    .loadedString       db "Loaded, control passed to Windows Loader!"
    LOADEDSTRING_LEN    equ $ - .loadedString

    .failedOneBoot      db "error "
    FAILEDONEBOOT_LEN   equ $ - .failedOneBoot

    __GuestPxeGrubInfo:
        .grubBoot       db  0
        .bootDrive      db  0
        .bootSector     db  1


    ;
    ; Print string
    ;
    .printString:           ; input: bx = string address, cx = string length
        push    ax
        push    di

        mov     di,     [PXE_RELOC(.screenPosition)]
        mov     ah,     PXE_COLOR

    .nextChar:
        mov     al,     [bx]
        mov     [fs:di], ax
        add     di,     2

    ; make sure not to overflow the screen mem
        cmp     di,     80*25*2
        jb      .noOverflow
        xor     di,     di

    .noOverflow:
        inc     bx
        loop    .nextChar

        mov     [PXE_RELOC(.screenPosition)], di

        pop     di
        pop     ax
        ret



    ;
    ; Hex print a byte
    ;
    .printHexDl:            ; input: dl = value to print in hex
        pusha

        xor     bx,     bx
        mov     bl,     dl
        mov     di,     [PXE_RELOC(.screenPosition)]
        mov     ah,     PXE_HEX_COLOR
        mov     cx,     2

    ; two times translate and print a nibble
    .nextNibble:

        rol     dl,     4
        mov     bl,     dl
        and     bl,     0xF

        mov     al,     [bx + PXE_RELOC(.hexTable)] ; bh is 0 from xor bx,bx
        mov     [fs:di], ax
        add     di,     2
        loop    .nextNibble

    ; leave a white space after
        mov     al,     ' '
        mov     [fs:di], ax
        add     di,     2

    ; make sure not to overflow the screen mem (weak check only safe for page boundary)
        cmp     di,     80*25*2
        jb      .noHexOverflow
        xor     di,     di

    .noHexOverflow:
        mov     [PXE_RELOC(.screenPosition)], di

        popa
        ret


    ;
    ; Extended int 13h support info
    ;
    .checkInt0x13Extensions: ; input: dx = drive => cf or ax = supported features (as defined for int 13h service 41h)
        push    bp
        mov     bp,     sp
        pusha
        mov     ax,     0x4100
        mov     bx,     0x55aa
        int     13h
        jc      .int0x13ExtensionsNotSupported

    ; cx encodes the supported extensions
        mov     [bp - 2], cx    ; set pusha.ax = cx
        clc

    .int0x13ExtensionsNotSupported:
        popa
        pop     bp
        ret


    ;
    ; Size constraints verifications (don't boot from drives lower then 48GB)
    ;
    .checkDriveSize:     ; input: dx = drive => cf for failure
        pushad
        push    ds

        xor     ax,     ax
        mov     ds,     ax
        mov     ah,     0x48
        mov     si,     0x7c00          ; use 0x7c00 as data buffer
        mov     [si],   WORD 30         ; size of buffer, should be 30
        int     13h
        jc      .driveSizeFailed

    ; get edx:eax = number of sectors
        mov     eax,    [si + 0x10]
        mov     edx,    [si + 0x14]

    ; get size in MB
        shrd    eax,    edx, 11         ; divide by 2048 -- number of bytes / 512 (sector size) / 2 / 1024 => MB
        cmp     eax,    (48 * 1024)     ; 48 GB
    ; cf contains now 1 if below...

    .driveSizeFailed:
        pop     ds
        popad
        ret


    ;
    ; Reset&read the MBR sector from a given drive
    ;
    .readMbrSector:     ; input: dx = drive => cf for failure / read sector at 0x7c00
        pusha
        push    es

        xor     ax,     ax
        mov     es,     ax              ; segment

        LINETRACE
    ; try 7 times at most to reset and read from drive
        mov     cx,     7
    .readSectorRetry:
        push    cx

        ; reset the selected drive first
        xor     ah,     ah
        pusha

        int     0x13

        popa
        LINETRACE

        mov     ax,     0x0201          ; read one sector
        xor     ch,     ch              ; track
        mov     cl,     [PXE_RELOC2(.bootSector)]    ; sector
        xor     dh,     dh              ; head 0, dl = selected drive
        .ok:
        mov     bx,     0x7C00          ; 0ffset
        pusha
        int     13h

        popa
        LINETRACE

        pop     cx
        jnc     .readSectorDone         ; exit with CF = 0

        test    cx,     cx
        stc
        jz      .readSectorDone         ; done with error (stc), no more retries

        dec     cx
        jmp     __GuestPxeGrubInfo.readSectorRetry

    .readSectorDone:
        pop     es
        popa
        LINETRACE
        ret


    ;
    ; Load and execute the MBR of a given drive
    ;
    .runMbr:            ; dl = drive, the function DOES NOT return to caller on success
        pusha

    ; inform about the operation
        mov     bx,     PXE_RELOC(.tryString)
        mov     cx,     TRYSTRING_LEN
        call    __GuestPxeGrubInfo.printString
        call    __GuestPxeGrubInfo.printHexDl

    ; read the mbr of the selected drive
        call    __GuestPxeGrubInfo.readMbrSector
        LINETRACE
        mov     dl,     0x1         ; error code to print
        jc      .runMbrFailed

    ; check the MBR signature
        cmp     [es:0x7c00 + 510], WORD 0xAA55
        mov     dl,     0x2         ; error code to print
        jne     .runMbrFailed

    ; check for protective MBR signatures
        %assign i 0x0
        %rep    4
            CheckIfProtectiveMbr(es, WORD 0x7C00, i)
            jc      .runMbrFailed
        %assign i i + 1
        %endrep

    ; run its code and send the correct boot drive (the dl register)

        popa
        xor     dh,     dh          ; dl = drive

        mov     bx,     PXE_RELOC(.loadedString)
        mov     cx,     LOADEDSTRING_LEN
        call    __GuestPxeGrubInfo.printString
        LINETRACE

    ; clear leftover color formatting on first line
        mov     cx, 80
        mov     di, 1
    .clear_formatting:
        mov     [fs:di], byte 0x07
        inc     di
        inc     di
        loop    .clear_formatting

        jmp     00:0x7c00

    ; print an error code and return on error
    .runMbrFailed:
        mov     bx,     PXE_RELOC(.failedOneBoot)
        mov     cx,     FAILEDONEBOOT_LEN
        call    .printString

        popa
        ret



    ;
    ; The actual in-guest loader code (the real entry point)
    ;
    .start:
        mov     ax,     0xb800
        mov     fs,     ax              ; fs is now the base of video memory
        xor     ax,     ax
        mov     ds,     ax
        mov     es,     ax
        mov     ss,     ax
        ;mov     sp,     0x800           ; 0x600-0x800: hardcoded PA where windows will relocate its bootloader, we can safely use it
        mov     sp,     0x7c00
        sti


    ; clear screen
        mov     ax,     3
        int     10h
        mov     bx,     PXE_RELOC(.startedString)
        mov     cx,     STARTEDSTRING_LEN
        call    .printString

        mov     al,     [PXE_RELOC2(.grubBoot)]
        cmp     al,     1
        jz      .getGrubDrive
    ; select the most likely good boot drive, based on its size
        mov     dx, 0x80
    .tryNext:
        call    __GuestPxeGrubInfo.checkDriveSize
        jnc     .useCurrent
        inc     dl                      ; switch to the second drive (0x81)
        cmp     dl,     0x90
        jb      .tryNext
        mov     dl,     0x80            ; if no suitable disk was found, fallback to 0x80
    .useCurrent:
        jmp     .callRunMbr
    .getGrubDrive:
        mov     dl,     [PXE_RELOC2(.bootDrive)]
    .callRunMbr:
        call    .runMbr                 ; try booting from selected dl drive

    ; if failed, take each boot drive id and try running its mbr, starting with 0x80
        mov     dl,     0x80

    .bootFromNextDrive:
        call    .runMbr
        inc     dl
        cmp     dl,     0x80
        jnz     .bootFromNextDrive

    ; if all drives failed signal the invalid boot configuration
        mov     bx,     PXE_RELOC(.failedString)
        mov     cx,     FAILEDSTRING_LEN
        call    .printString
        cli
        hlt

    ; triple fault if somehow we get over cli-hlt
        xor     eax,    eax
        dec     eax
        mov     cr0,    eax
        mov     cr3,    eax

%else

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; in-guest debug/test code sample (for real mode virtualization)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


%include "..\..\asmlib\heavy\io.nasm"
%include "..\..\asmlib\heavy\biosdisk.nasm"
%include "..\..\asmlib\heavy\macros.nasm"
__GuestPxeGrubInfo:
    .grubBoot       db  0
    .bootDrive      db  0
    .bootSector     db  1

bits(16)
datasection(inplace)                    ; don't store data in a different section
libsection(inplace)                     ; library code should not go to a separate section
libdatasection(inplace)                 ; initialized data belonging to library code should't go to a different section

%define ABS(X) (0x7e00 + X - __GuestPxeMbrLoaderCode)
relocator(ABS)                          ; generate reference relocations based on this calculation (the ABS macro)

; an example lib function
libfunction(ShowDriveInfo, showDriveInfo, 1)
%macro IMPLEMENT_showDriveInfo 0
    GENERIC_PROC showDriveInfo
        PARAMS DriveParams
        SAVEALL
        mov     si,     %$DriveParams
        mov     ax,     [si + DRIVE_PARAMS.NumberOfSectors]
        mov     bx,     [si + DRIVE_PARAMS.NumberOfHeads]
        mov     cx,     [si + DRIVE_PARAMS.NumberOfCylinders]
        mov     dx,     [si + DRIVE_PARAMS.DriveId]
        print   "DRIVE=",dx," cylinders=",cx, " heads=", bx, " sectors=", ax
        mov     dx,     [si + DRIVE_PARAMS.TotalSectors + 2]
        mov     ax,     [si + DRIVE_PARAMS.TotalSectors]
        mov     bx,     ((1024*1024)/512)
        div     bx
        print   ", total space in MB: ", ax, NL
    ENDPROC
%endmacro

;;;
;;; START
;;;
__GuestPxeMbrLoaderEntry:
    cli
    IoInit(IO_TEXTMODE50)
    print "Press any key to see the disk configuration info", nl
    IoReadKey(1)

    ; declare some variables
    globaldata  tempDriveInfo, sizeof(DRIVE_PARAMS)
    globaldata  buffer, 512
    globalvar   validDrives

    ; iterate all drives and list their properties
    for edx,0,0xff
        mov     cx,     dx
        or      cx,     FL_DISK_RESET_ON_GETINFO

        GetDriveInfo(cx, relocate(tempDriveInfo))
        if ax, ne, 0
            inc SIZE_T[relocate(validDrives)]
            dbg "got a valid drive: ", cx
            ShowDriveInfo(relocate(tempDriveInfo))
            ; read one sector from LBA = 0
            ReadSectors(relocate(tempDriveInfo), relocate(buffer), 0, 0, 1)
            if c
                print "Error reading first sector", nl
            else
                print "First sector read successfully, press any key to see its content", nl
                IoReadKey(1)
                IoMemDump(relocate(buffer), 512)
            endif
        endif

    endfor

    ; done, stop execution (but allow ctrl+alt+del)
.again:
    sti
    hlt
    jmp .again
%endif


__GuestPxeMbrLoaderCodeEnd:

;;;times 0x200-$+__GuestPxeMbrLoaderSector db 'S'          ; padding (0x0200 total size for guest loader sector code)




