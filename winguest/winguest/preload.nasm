;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%include "system.nasm"
;
; PrepareAndCallTheKernel(SIZE_T ptrIntermediateCodeData, SIZE_T ptrCpuData)
;
global PrepareAndCallTheKernel
global _PrepareAndCallTheKernel@8

;
; CpustateCaptureGuestState(QWORD GuestInfo)
;
;extern CpustateCaptureGuestState
;CpustateCaptureGuestState   dq 0

;
; CpustateSetRIP(QWORD ptrGuestInfo, QWORD ripValue)
;
;extern CpustateSetRIP
;CpustateSetRIP dq 0

;
; CpustateSetRSP(QWORD ptrGuestInfo, QWORD rspValue)
;
;extern CpustateSetRSP
;CpustateSetRSP dq 0

;
; CpustateRestoreGuestState(QWORD ptrGuestInfo)
;
;extern CpustateRestoreGuestState
;CpustateRestoreGuestState dq 0

ONE_KILOBYTE                    equ     (1024)
ONE_MEGABYTE                    equ     (1024 * ONE_KILOBYTE)
ONE_GIGABYTE                    equ     (1024 * ONE_MEGABYTE)
ONE_TERABYTE                    equ     (1024 * ONE_GIGABYTE)
CPU_CONTEXT_DATA_SIZE           equ     (4 * ONE_KILOBYTE)      ;; must be same as the CPU_DATA::context from C code
CPU_STACK_SIZE                  equ     (4 * ONE_KILOBYTE)      ;; must be same as the CPU_DATA::stack from C code

IA32_FS_BASE                    equ 0C0000100H
IA32_GS_BASE                    equ 0C0000101H
IA32_MTRR_DEF_TYPE              equ 2FFH
IA32_PAT_BASE                   equ 277H

DATA64_SEL                      equ 10H     ;; 64 bit data selector / stack selector
CODE64_SEL                      equ 20H     ;; 64 bit mode code selector

DATA32_SEL                      equ 08H     ;; 32 bit data selector
CODE32_SEL                      equ 18H     ;; 32 bit code selector

TR64_SEL                        equ 30H     ;; TSS (TR) selector

EFER_LME_MASK           equ 000000100H
EFER_LMA_MASK           equ 000000400H

;;define CPU_DATA64 structure used to save the context of each cpu
struc CPU_DATA64
    .cpuStackAddress                    resq    1
    .cpuTempUnloadBufferAddress         resq    1
    .cpuTempUnloadBufferAddressPA       resq    1
    .cpuGuestStateDataAddress           resq    1
    .Status              resq   1   ;; status code returned by hv on this CPU

    ;; os control registers
    .OrigCr0             resq   1
    .OrigCr3             resq   1
    .OrigCr4             resq   1

    ;; os gdtr, idtr
    .OrigGDTRLimit       resw   1
    .OrigGDTRBase        resq   1
    .OrigIDTRLimit       resw   1
    .OrigIDTRBase        resq   1

    ;; segment registers
    .OrigFSBase          resq   1
    .OrigGSBase          resq   1
    
    ;; segment selectors
    .OrigCS              resw   1
    .OrigDS              resw   1
    .OrigSS              resw   1
    .OrigES              resw   1
    .OrigFS              resw   1
    .OrigGS              resw   1
    .OrigTR              resw   1

    .EFlags              resq   1
    .PATMsr              resq   1
endstruc

;;define CPU_DATA32 structure used to save the context of each cpu
struc CPU_DATA32
    .cpuStackAddress32  resd    1

    ;; os control registers
    .OrigCr0             resq   1
    .OrigCr3             resq   1
    .OrigCr4             resq   1

    ;; os gdtr, idtr
    .OrigGDTRLimit       resw   1
    .OrigGDTRBase        resq   1
    .OrigIDTRLimit       resw   1
    .OrigIDTRBase        resq   1

    ;; segment registers
    .OrigFSBase          resq   1
    .OrigGSBase          resq   1
    
    ;; segment selectors
    .OrigCS              resw   1
    .OrigDS              resw   1
    .OrigSS              resw   1
    .OrigES              resw   1
    .OrigFS              resw   1
    .OrigGS              resw   1
    .OrigTR              resw   1

    .EFlags              resq   1
endstruc

;; the following structure must overlap the INTERMEDIATE_CODE_DATA structure defined in C code
struc INTERMEDIATE_CODE_DATA
    .intermediateCodePA             resq    1
    .intermediatePML4PA             resq    1
    .intermediatePDP32PA            resq    1
    .kernelEntryPoint               resq    1

;; GDTR stuff - 10bytes for x64 and 6bytes for x32
;; 2 x DWORD(base & baseHigh) + 1 x WORD(Align0) is enough for both
;; Align1 is used to keep the descriptor addresses 8bytes aligned for performance
        .gdtrLimit                  resw    1
        .gdtrBase                   resd    1
        .gdtrBaseHigh               resd    1

        .Align0                     resw    1
        .Align1                     resd    1

        .nullDescriptor             resq    1
        .dataDescriptor32           resq    1
        .dataDescriptor64           resq    1
        .codeDescriptor32           resq    1
        .codeDescriptor64           resq    1

        .bootType                   resq    1
        .start                      resq    1
        .loadedFrom32Bit            resq    1
        .loaderBootContext          resq    1
endstruc

[BITS 32]
; fastcall
; PrepareAndCallTheKernel(SIZE_T ptrIntermediateCodeData, SIZE_T ptrCpuData)
;
_PrepareAndCallTheKernel@8:

;; first save regs and flags
    pushad
    pushfd

;; no more interrupts from now on
    cli

;; save parameters
    mov     esi, edx    ;; esi ptr to CPU_DATA32 struct
    mov     edi, ecx    ;; edi ptr to INTERMEDIATE_CODE_DATA struct

;; switch stack and save orig value to new stack
    mov     eax, esp
    mov     esp, [esi + CPU_DATA32.cpuStackAddress32]
    push    eax

;; save partial 32bit context
    mov     ecx, IA32_FS_BASE
    rdmsr
    mov     [esi + CPU_DATA32.OrigFSBase], eax
    mov     [esi + CPU_DATA32.OrigFSBase + 4], edx

    mov     ecx, IA32_GS_BASE
    rdmsr
    mov     [esi + CPU_DATA32.OrigGSBase], eax
    mov     [esi + CPU_DATA32.OrigGSBase + 4], edx

    mov     eax, cr0
    mov     [esi + CPU_DATA32.OrigCr0], eax

    mov     eax, cr3
    mov     [esi + CPU_DATA32.OrigCr3], eax

    mov     eax, cr4
    mov     [esi + CPU_DATA32.OrigCr4], eax

    lea     eax, [esi + CPU_DATA32.OrigGDTRLimit]
    sgdt    [eax]

    lea     eax, [esi + CPU_DATA32.OrigIDTRLimit]
    sidt    [eax]

    mov     ax, cs
    mov     [esi + CPU_DATA32.OrigCS], ax

    mov     ax, ds
    mov     [esi + CPU_DATA32.OrigDS], ax

    mov     ax, ss
    mov     [esi + CPU_DATA32.OrigSS], ax

    mov     ax, es
    mov     [esi + CPU_DATA32.OrigES], ax

    mov     ax, fs
    mov     [esi + CPU_DATA32.OrigFS], ax

    mov     ax, gs
    mov     [esi + CPU_DATA32.OrigGS], ax

    str     ax
    mov     [esi + CPU_DATA32.OrigTR], ax


    ;;
    ;; mark the current task as not being busy (see "sys prog guide a"  page 257)
    ;; before we load id in the tr, or else a GP will be triggered, see ltr instrction
    ;;
    push    edi
    xor     edi, edi
    mov     di,  [esi + CPU_DATA32.OrigTR]
    mov     eax, [esi + CPU_DATA32.OrigGDTRBase]
    shr     edi, 3
    imul    edi, 8          ;; the shr and imul are not needed in this case, written only for clarity
    add     edi, eax        ;; edi now points to the tss descriptor

    mov     eax, dword [edi + 4]        ;; eax now contains the 2'nd dword of the tss descriptor
                                        ;; need to set bit 9 to 0 (to mark the task as not busy)
    and     eax, 0FFFFFDFFH
    mov     dword [edi + 4], eax    ;; and store it in the task descriptor    
    pop     edi

    ;; load our GDT
    lea     eax, [edi + INTERMEDIATE_CODE_DATA.gdtrLimit]
    lgdt    [eax]

    ;; set selectors
    mov     ax, DATA32_SEL
    mov     ds, ax
    mov     ss, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;; switch to our 32bit code segment
    push    CODE32_SEL
    call    $ + 5
    add     dword [esp], 5
    retf

    ;; save to ebx the PA for PML4 for 64bit
    ;; !!! do not modify EBX !!!
    mov     ebx, [edi + INTERMEDIATE_CODE_DATA.intermediatePML4PA]
    ;; save to ecx the PA of intermediate code
    ;; !!! do not modify ECX !!!
    mov     ecx, [edi + INTERMEDIATE_CODE_DATA.intermediateCodePA]
    ;; save addres of PDP32PA
    ;; !!! do not modify EBP !!!
    mov     ebp, [edi + INTERMEDIATE_CODE_DATA.intermediatePDP32PA]

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; TODO: (9)
;;      01) switch to 32bit identity mapping
    mov     eax, [edi + INTERMEDIATE_CODE_DATA.intermediatePDP32PA]
    mov     cr3, eax

    ;; save the current virtual address of the page
    call    $+5
    and     dword [esp], 0xFFFFF000

    ;; switch to identity virtual addresses (EIP update)
    mov     eax, ecx
    call    $ + 5
aici:
    and     dword [esp], 0xFFF
    add     dword [esp], eax
    add     dword [esp], aici1 - aici
    ret
aici1:

;;      02) disable paging
    mov     eax, cr0
    and     eax, 0x7FFFFFFF
    mov     cr0, eax

;;      03) enable PAE
    ENABLE_PAE

;;      04) load CR3 with pml4 for 64bit
    xor     eax, eax
    mov     eax, ebx
    mov     cr3, eax

;;      05) set LME in IA32_EFER
    ENABLE_LME
    
;;      05.1) deactivate XD_DISABLE and LIMIT_CPUID in IA32_MISC and, if present, enable XD feature
    CONFIGURE_IA32_MISC 0, IA32_MISC_ENABLE.XD_DISABLE | IA32_MISC_ENABLE.LIMIT_CPUID
    ENABLE_XD
    
;;      06) enable paging
    ENABLE_PAGING


;;      07) set/check LMA in IA32_EFER
    mov     ecx, IA32_EFER
    rdmsr
    bt      eax, 10         ;; bit 10 is LMA bit
    jc      long_mode_ok

    int 3       ;; triple fault here if not long mode

long_mode_ok:

;;      08) move to 64bit VA addresses
    ;; take virtual address from the stack
    mov     eax, dword [esp]

    call    $ + 5
    and     dword [esp], 0xFFF
    add     dword [esp], eax
    add     dword [esp], 0x0F
    ret

    ;; switch to 64 bit code selector
    push    CODE64_SEL
    call    $ + 5
    add     dword [esp], 5
    retf

[BITS 64]
;;      09) prepare and call: PrepareAndCallTheKernel - 64bit version

    ;; i need:
    ;; SIZE_T ptrIntermediateCodeData   - this is in EDI
    ;; SIZE_T ptrCpuData                - this is in ESI + sizeof(CPU_DATA32)

    xor     rcx, rcx
    xor     rdx, rdx
    mov     ecx, edi
    mov     edx, esi
    add     edx, 0x1000 ;; this is (and MUST be) sizeof(CPU_DATA32)

    sub     rsp, 0x20
    call    PrepareAndCallTheKernel
    add     rsp, 0x20

    ;;sub     esi, 0x1000 ;; this is (and MUST be) sizeof(CPU_DATA32)

;;      10) all the above in reversed order :D
    ;; switch back to compatiblity mode
    push    CODE32_SEL
    call    $ + 5
    add     qword [rsp], 7
    o64 retf

[BITS 32]

    ;; switch to 32bit identity mapping
    mov     eax, [edi + INTERMEDIATE_CODE_DATA.intermediateCodePA]
    call    $ + 5
    and     dword [esp], 0xFFF
    add     dword [esp], eax
    add     dword [esp], 15
    ret

    ;; disable paging
    mov     eax, cr0
    and     eax, 0x7FFFFFFF
    mov     cr0, eax

    ;; load the pdbr for 32bit paging
    mov     cr3, ebp

    ;; disable LME
    mov     ecx, IA32_EFER
    rdmsr
    and     eax, ~EFER_LME_MASK
    wrmsr

    ;; enable paging in 32bit mode
    mov     eax, cr0
    or      eax, 0x80000000
    mov     cr0, eax

    ;; 6. a branch instruction must follow the cr0 that enables paging ???
    jmp     $ + 2

    ;; revert from identity mapping virtual addresses
    pop     eax     ; restore the virtual address of the flat code from the stack (see above, 
                    ; when we switched to physical addresses)

    call    $ + 5
    and     dword [esp], 0xFFF
    add     dword [esp], eax
    add     dword [esp], 15
    ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ;; restore original CR3
    mov eax, dword [esi + CPU_DATA32.OrigCr3]
    mov cr3, eax

    ;; restore state
    lea     eax, [esi + CPU_DATA32.OrigGDTRLimit]
    lgdt    [eax]

    lea     eax, [esi + CPU_DATA32.OrigIDTRLimit]
    lidt    [eax]

    mov     ax, [esi + CPU_DATA32.OrigDS]
    mov     ds, ax

    mov     ax, [esi + CPU_DATA32.OrigSS]
    mov     ss, ax

    mov     ax, [esi + CPU_DATA32.OrigES]
    mov     es, ax

    mov     ax, [esi + CPU_DATA32.OrigFS]
    mov     fs, ax

    mov     ax, [esi + CPU_DATA32.OrigGS]
    mov     gs, ax

    ;; restore CS
    xor     eax, eax
    mov     ax, [esi + CPU_DATA32.OrigCS]
    push    eax
    call    $ + 5
    add     dword [esp], 5
    retf

    mov     ecx, IA32_FS_BASE
    mov     eax, [esi + CPU_DATA32.OrigFSBase]
    mov     edx, [esi + CPU_DATA32.OrigFSBase + 4]
    wrmsr

    mov     ecx, IA32_GS_BASE
    mov     eax, [esi + CPU_DATA32.OrigGSBase]
    mov     edx, [esi + CPU_DATA32.OrigGSBase + 4]
    wrmsr

    mov     ax, [esi + CPU_DATA32.OrigTR]
    ltr     ax

;; revert to windows stack
    ;;mov     eax, [esi + CPU_DATA32.cpuStackAddress32]
    pop     eax
    mov     esp, eax


;; restore regs and flags
    popfd
    popad
    ret


%include "..\..\asmlib\loader_interface.nasm"


[BITS 64]
;
; PrepareAndCallTheKernel(SIZE_T ptrIntermediateCodeData, SIZE_T ptrCpuData)
;
PrepareAndCallTheKernel:

;;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;;    ret
;;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

;; first of all we have to save the registers
;; that we are using localy
    push    rcx
    push    rsi
    push    rdi
    push    r10
    push    r11
    push    rbx
    push    rbp
    push    r9
    push    r8
    push    r15

;; next save parameters in some indexing registers
    mov     rsi, rdx    ;; rsi pointer to CPU_DATA64 struct
    mov     rdi, rcx    ;; rdi pointer to INTERMEDIATE_CODE_DATA struct

;;  save flags
    pushfq
    pop     rax
    mov     [rsi + CPU_DATA64.EFlags], rax

    cli

    mov     r8, [rdi + INTERMEDIATE_CODE_DATA.start]
    mov     rcx, [rsi + CPU_DATA64.cpuGuestStateDataAddress]
    mov     rdx, [rdi + INTERMEDIATE_CODE_DATA.loadedFrom32Bit] ;; use fake tr in this case
    push    rcx
    push    r8

    sub     rsp, 20h    ;;make room for callee parameters

    call    CpustateCaptureGuestState

    call start
start:
    pop rdx
    add rdx, restore_ctx - start
    ;;sub     rsp, 20h
    mov     rcx, [rsi + CPU_DATA64.cpuGuestStateDataAddress]

    call CpustateSetRIP

do_startup:
;;  save flags
;;    pushfq
;;    pop     rax
;;    mov     [rsi + CPU_DATA64.EFlags], rax

;; nobody stops us from now on :D
    cli

;; save CPU state (gdtr, idtr, cr3 etc) to CPU_DATA64 structure

    lea     rax, [rsi + CPU_DATA64.OrigGDTRLimit]
    sgdt    [rax]

    lea     rax, [rsi + CPU_DATA64.OrigIDTRLimit]
    sidt    [rax]

    mov     rax, cr4
    mov     [rsi + CPU_DATA64.OrigCr4], rax

    mov     rax, cr3
    mov     [rsi + CPU_DATA64.OrigCr3], rax

    mov     rax, cr0
    mov     [rsi + CPU_DATA64.OrigCr0], rax

    mov     rcx, IA32_FS_BASE
    rdmsr
    shl     rdx,32
    or      rax,rdx
    mov     [rsi + CPU_DATA64.OrigFSBase], rax

    mov     rcx, IA32_GS_BASE
    rdmsr
    shl     rdx,32
    or      rax,rdx
    mov     [rsi + CPU_DATA64.OrigGSBase], rax

    ;; save the PAT_MSR
    mov     rcx, IA32_PAT_BASE
    rdmsr
    shl     rdx,32
    or      rax, rdx
    mov     [rsi + CPU_DATA64.PATMsr], rax

    [bits 32]  ;bits 32 + rsi->edi => same encoding - fool the assembler to avoid 'segment register ignored in 64-bit mode' warnings
    mov     [esi + CPU_DATA64.OrigCS], cs
    mov     [esi + CPU_DATA64.OrigDS], ds
    mov     [esi + CPU_DATA64.OrigES], es
    mov     [esi + CPU_DATA64.OrigFS], fs
    mov     [esi + CPU_DATA64.OrigGS], gs
    mov     [esi + CPU_DATA64.OrigSS], ss
    [bits 64]

    cmp     byte [rdi + INTERMEDIATE_CODE_DATA.loadedFrom32Bit], 1
    je      load_from_32bit_skip_save_tr

;; save the current tr selector
    xor     rax, rax
    str     rax
    mov     [rsi + CPU_DATA64.OrigTR], ax

    mov     r10, rax

;; mark the current task as not being busy (see "sys prog guide a"  page 257)
    mov     rax, [rsi + CPU_DATA64.OrigGDTRBase]
    shr     r10, 3      
    imul    r10, 8          ;; the shr and imul are not needed in this case, written only for clarity
    add     r10, rax        ;; r10 now points to the tss descriptor

    mov     eax, dword [r10 + 4]    ;; eax now contains the 2'nd dword of the tss descriptor
                                        ;; need to set bit 9 to 0 (to mark the task as not busy)
    and     eax, 0FFFFFDFFH

    mov     dword [r10 + 4], eax    ;; and store it in the task descriptor

load_from_32bit_skip_save_tr:

;; switch to our own GDT
    lea     rax, [rdi + INTERMEDIATE_CODE_DATA.gdtrLimit]
    lgdt    [rax]

;; switch segment registers to our data / stack segment
    mov     ax,DATA64_SEL
    mov     ds, ax
    mov     ss, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

;; update flags in cr0 and cr4
    push    rbx
    mov     rax, cr0
    or      rax, 0000000000010000h  ;;CR0.WP (bit 16) = 1
    mov     rbx, 0xFFFFFFFFFFFFFFF3 ;;EM, TS = 0
    and     rax, rbx
    mov     cr0, rax

    mov     rax, cr4
    mov     rbx, 0xFFFFFFFFFFFFFB7F  ;;PGE = 0, OSXMMEXCPT = 0
    mov     cr4, rax
    pop     rbx

;; switch to our code segment
    push    CODE64_SEL
    call    $ + 5
    add     qword [rsp], 7
    o64 retf

;; switch to our PML4
    xor     rax, rax
    mov     rax, [rdi + INTERMEDIATE_CODE_DATA.intermediatePML4PA]
    mov     cr3, rax

;; switch to the stack for this cpu
    mov     rax, rsp
    mov     rsp, [rsi + CPU_DATA64.cpuStackAddress]

    push    rax     ;;first original rsp
    push    rsi     ;; now address of CPU_DATA64
    push    rdi     ;; address of INTERMEDIATE_CODE_DATA
    mov     rax, cr3
    push    rax     ;; save our cr3 because kernel entry point will change it

    cmp     qword [rdi + INTERMEDIATE_CODE_DATA.start], 1
    je      callKernel
    mov     rax, 0
    mov     rbx, 0bdbdbdbdbdbdbdbdh
    mov     rcx, [rsi + CPU_DATA64.cpuTempUnloadBufferAddress]
    mov     rdx, [rsi + CPU_DATA64.cpuTempUnloadBufferAddressPA]
    vmcall
    jmp     skip_call_kernel


callKernel:
;; prepare the call into kernel

    call    label1
label1:
    pop     rbx
    add     rbx, (back - label1)     ;;address of back (adresa de revenire)

    ;; loaderBootContext - into RCX
    ;; entry point  - into RAX
    mov     rcx, qword [rdi + INTERMEDIATE_CODE_DATA.loaderBootContext]
    mov     rax,  [rdi + INTERMEDIATE_CODE_DATA.kernelEntryPoint]
    X64ABSCALL_INIT64 rax

back:
    ;;
    ;; in RAX we have error code from HV if any
    ;; we have to preserve this until we can access per cpu data struct
    ;; and then save it there for further analisys
    ;; we put this in RBX for now
    ;;
    mov     rbx, rax

skip_call_kernel:

    pop     rax         ;; take from stack the saved cr3, which maps both hv (1T - 1T + 4MB) and windows
    mov     cr3, rax    ;; switch to our temporary mappings

    pop     rdi         ;; address of INTERMEDIATE_CODE_DATA
    pop     rsi         ;; address of CPU_DATA64

    pop     rax         ;; restore original stack
    mov     rsp, rax

;; restore original CR3
    xor     rax, rax
    mov     rax, [rsi + CPU_DATA64.OrigCr3]
    mov     cr3, rax

;; save the status returned by HV on this CPU
;; from now on we can use RBX for whatever else
    mov     [rsi + CPU_DATA64.Status], rbx

;; restore cr0
    xor     rax, rax
    mov     rax, [rsi + CPU_DATA64.OrigCr0]
    mov     cr0, rax

;; restore cr4
    xor     rax, rax
    mov     rax, [rsi + CPU_DATA64.OrigCr4]
    mov     cr4, rax

;; restore CPU state from CPU_DATA64 structure
    lea     rax, [rsi + CPU_DATA64.OrigGDTRLimit]
    lgdt    [rax]

;; restore the original DS
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigDS]
    mov     ds, ax

;; restore the original ES
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigES]
    mov     es, ax

;; restore the original FS
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigFS]
    mov     fs, ax

;; restore the original GS
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigGS]
    mov     gs, ax

;; restore the original SS
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigSS]
    mov     ss, ax

;; restore the original CS 
    xor     rax, rax
    mov     ax, [rsi + CPU_DATA64.OrigCS]
    push    rax
    call    $ + 5
    add     qword [rsp], 7
    o64 retf

    lea     rax,[rsi + CPU_DATA64.OrigIDTRLimit]
    lidt    [rax]

    mov     rcx, IA32_FS_BASE
    mov     rax, [rsi + CPU_DATA64.OrigFSBase]
    mov     rdx, rax
    shr     rdx, 32
    wrmsr
        
    mov     rcx, IA32_GS_BASE
    mov     rax, [rsi + CPU_DATA64.OrigGSBase]
    mov     rdx, rax
    shr     rdx, 32
    wrmsr
    
    cmp     byte [rdi + INTERMEDIATE_CODE_DATA.loadedFrom32Bit], 1
    je      load_from_32bit_skip_restore_tr

;; restore the tr
    xor     rax,rax
    mov     ax, [rsi + CPU_DATA64.OrigTR]
    ltr     ax


load_from_32bit_skip_restore_tr:

    dec     QWORD [rsp + 0x20]  ; set to 0 the r8 found on stack when unloaded cause of errors

restore_ctx:
    add     rsp, 20h
    pop     r8
    pop     rcx         ;; param for CpustateRestoreState

    cmp     r8, 0x1
    je      restore_guest_state

    mov     byte [rcx + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr],  0x01     ;; use fake tr in this case

restore_guest_state:
    sub     rsp, 20h
    call    CpustateRestoreGuestState
    add     rsp, 20h

restore_regs:

    ;; set interrupts, if needed
    bt      qword [rsi + CPU_DATA64.EFlags], 9
    jnc     no_sti1                ;; the IF was 0, we do not need to set it
    sti

no_sti1:
    mov     rax, r10 ;; put the hypervisor return code back into eax

;restore_regs:
    pop     r15
    pop     r8
    pop     r9
    pop     rbp
    pop     rbx
    pop     r11
    pop     r10
    pop     rdi
    pop     rsi
    pop     rcx
    ret

;; add the rest of the code here
%include "kernel\cpu_state_asm.nasm"
