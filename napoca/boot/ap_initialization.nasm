;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

;
; AP INITIALIZATION CODE, RUNS FROM A 'VV00:0000h' - LIKE ADDRESS (Intel MP Spec.)
;

%include "system.nasm"
%include "loader_interface.nasm"


;
; Imported symbols / external dependencies
;
extern InitCpuEntry
extern IniInit64
extern PwrResumeHostAp

;
; Exported symbols
;
global  gApTrampoline16     ; the base and entry point of AP initialization code/data
global  gApTrampoline16End  ; address of where it ends
global  gApStartupData      ; structure sent by the HV to APs


;
; Configuration
;

AP_MAX_CPU_COUNT    equ 64


;
; Types and macros
;
%define RVA(X) ((X) - gApTrampoline16)                  ; offset relative to trampoline start
%define SEL(X) apGdtTable. %+ X - apGdtTable.start      ; offset inside the GDT for a given descriptor label

%macro WAKEUP_HALT 0
    push    di
    xor     di, di
    ;;;cmp     [gIsWakeup], di
    jz      %%skip
    cli
    hlt
%%skip:
    pop     di
%endmacro



; AP parameters structure, initialized by HV
_struc AP_POINTERS
    DWORD       (LapicId)                               ; an AP checks this value to find out if the current entry belongs to itself
    QWORD       (StackTop)                              ; what RSP value should I use ?
    QWORD       (CpuMapEntry)                           ; what's my CPU entry ?
    QWORD       (GsBase)                                ; where should my KERNEL_GS_BASE point at ?
_endstruc

_struc AP_STARTUP_DATA
    DWORD       (BaseAddress)                           ; must be set by napoca, NOT USED, it is dynamically determined by each AP
    QWORD       (BaseAddressVa)                         ; the VA of the trampoline start, as seen by the C code (BSP)
    QWORD       (StartupCr3)                            ; intermediate cr3 below 4GB for long mode initialization
    QWORD       (BspCr3)                                ; bsp's final cr3
    DWORD       (UefiEvent)                             ; used by UEFI
    QWORD       (UefiEntry)                             ; UEFI APs will run this code
    QWORD       (BootContext)                           ; pointer to the boot context which will be used as param for init64
    QWORD       (IsWakeUp)
    RAW         (ApPointers, AP_MAX_CPU_COUNT*sizeof(AP_POINTERS)) ; storage for per cpu pointers to structures
_endstruc



;
; Actual implementation
;
[bits 16]
gApTrampoline16:
    cli
    xor     ebp,    ebp
    mov     bp,     cs
    mov     ds,     bp
    mov     es,     bp
    mov     fs,     bp
    mov     gs,     bp
    mov     ss,     bp

    shl     ebp,    4               ; ebp is the PA of gApTrampoline16


    ;;; enable A20 address line (??)

    ; fix the gdt base value based on actual runtime address
    lea     eax,    [ebp + RVA(apGdtTable)]
    mov     [RVA(apGdtStructure.base)], eax

    ; fix the next far jump
    lea     eax,    [ebp + RVA(.bits32)]
    mov     [RVA(.farjmp)+2], eax

    ; switch to 32 bits
    lgdt    [RVA(apGdtStructure)]

    mov     eax,    cr0
    or      eax,    1
    mov     cr0,    eax

.farjmp:
    jmp     DWORD SEL(code32): 0x12345678   ; the offset is patched in the above code


;
; AP DATA
;
_istruc gApStartupData, AP_STARTUP_DATA
_iend
apStacks: times 64 dq 0     ; 64 cpu stacks of one quad each, used for 64bit switching

apGdtStructure:
    .size                   dw  apGdtTable.end - apGdtTable.start
    .base                   dq  0 ; auto-patched before use

apGdtTable:
    .start:
    .null                   dq  0
    .code64                 dq  FLAT_DESCRIPTOR_CODE64
    .data64                 dq  FLAT_DESCRIPTOR_DATA64
    .code16                 dq  FLAT_DESCRIPTOR_CODE16
    .data16                 dq  FLAT_DESCRIPTOR_DATA16
    .code32                 dq  FLAT_DESCRIPTOR_CODE32
    .data32                 dq  FLAT_DESCRIPTOR_DATA32
    .end:

fpuTestWord:
    dw                      0xBDBD

gApTrampoline16.bits32:
    [bits 32]
    mov     ax,     SEL(data32)
    mov     ds,     ax
    mov     es,     ax
    mov     fs,     ax
    mov     gs,     ax
    mov     ss,     ax

    ;
    ; Activate long-mode
    ;

    ; deactivate XD_DISABLE and LIMIT_CPUID in IA32_MISC
    CONFIGURE_IA32_MISC 0, IA32_MISC_ENABLE.XD_DISABLE | IA32_MISC_ENABLE.LIMIT_CPUID

    ENABLE_PAE
    ENABLE_LME
    ENABLE_XD

    ; set PG using the intermediate cr3
    mov     eax,    [ebp + RVA(gApStartupData.StartupCr3)]
    mov     cr3,    eax

    ENABLE_PAGING

    ; Prepare new 64bit-ready selectors
    mov     ax,     SEL(data64)         ; Setup data segment selectors
    mov     fs,     ax
    mov     gs,     ax
    mov     ds,     ax
    mov     ss,     ax
    mov     es,     ax

    ; setup the 8 bytes stack: ToS = apStacks + id*8 + 8
    xor     ebx,    ebx
    mov     eax,    1
    cpuid
    mov     edx,    ebx
    shr     edx,    24
    and     edx,    63                  ; edx is the lapic id
    lea     esp,    [ebp + edx * 8 + RVA(apStacks) + 8]

    ;
    ; switch to 64 bits
    ;
    push    DWORD SEL(code64)
    call    .pushEip                    ; place return EIP onto the stack (4 bytes)
.pushEip:
    add     DWORD [esp], .entry64 - .pushEip
    retf                                ; pops cs:rip (8 bytes) and continues execution in true long mode

    [bits 64]
.entry64:

    ; ESP -> RSP
    xor     rax,    rax
    mov     eax,    esp
    mov     rsp,    rax

    ; EBP -> RBP (PA base)
    xor     rax,    rax
    mov     eax,    ebp
    mov     rbp,    rax

    ; EDX -> RDX (apicId)
    xor     rax,    rax
    mov     eax,    edx
    mov     rdx,    rax

    ; final CR3
    mov     rax,    [rbp + RVA(gApStartupData.BspCr3)]
    mov     cr3,    rax

    ; final HV VA
    mov     rbx,    [rbp + RVA(gApStartupData.BaseAddressVa)]
    lea     rax,    [rbx + RVA(.finalVA)]
    push    rax                         ; rax is relative to rbx = gApStartupData.BaseAddressVa
    ret

.finalVA:

    ; rbp points to gApTrampoline16 PA base, rbx will point to gApTrampoline16 VA base; edx is still the lapic id

    ; find the stack and CpuMap entry
    lea     rsi,    [rbp + RVA(gApStartupData.ApPointers)]
    mov     rcx,    AP_MAX_CPU_COUNT

.nextEntry:
    cmp     [rsi + AP_POINTERS.LapicId], edx
    jz      .foundPointers
    add     rsi,    sizeof(AP_POINTERS)
    loop    .nextEntry
    jmp     .error

.foundPointers:

    ; setup stack
    mov     rax,    [rsi + AP_POINTERS.StackTop]
    mov     rsp,    rax

    ;
    ; enable fpu support
    ;
    call    activateFpuSupport

    ; Setup GS Base for the current AP
    push    rdx
    mov     eax,    [rsi + AP_POINTERS.GsBase]      ; low part
    mov     edx,    [rsi + AP_POINTERS.GsBase + 4]  ; high part

    mov     rcx, 0xC0000101             ; IA32_GS_BASE
    wrmsr
    mov     rcx, 0xC0000102             ; IA32_KERNEL_GS_BASE
    wrmsr
    pop     rdx

    ; init the gBootInfo->CpuMap entry
    X64CALL InitCpuEntry, [rsi + AP_POINTERS.CpuMapEntry]
    test    al,     al
    jz      .error

.enterHv:
    mov     rcx,    [rbp + RVA(gApStartupData.BootContext)]
    xor     rdi, rdi
    cmp     [rbp + RVA(gApStartupData.IsWakeUp)], rdi
    jz      .makecall
    mov     rcx, 0                       ;; when calling PwrResumeHostAp with a NULL parameter we know we are during Sleep - Wakeup and not doing a normal boot
    X64CALL PwrResumeHostAp

.makecall:
    X64CALL IniInit64, rcx

.error:
    cli
    hlt

[bits 64]
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

    push    rax
    push    rbx
    push    rcx
    push    rdx

    xor     rax,    rax
    inc     rax
    cpuid
    test    rdx,    CPUID_FPU           ; bit 0 in edx specifies fpu support
    jz      .notSupported

    ; test the presence of the fpu
    mov     rax,    cr0
    and     eax,    0xFFFFFFFF - (CR0_TS + CR0_EM)
    mov     cr0,    rax


    fninit
    fnstsw  [ebp + RVA(fpuTestWord)]
    cmp     word    [ebp + RVA(fpuTestWord)],   0
    jnz     .notSupported

    mov     rax,    cr0
    and     eax,    0xFFFFFFFF - CR0_NE         ; disable interrupt generation on exceptions
    or      eax,    CR0_MP                      ; should be inverse of EM, and EM is 0
    mov     cr0,    rax

    mov     rax,    cr4
    or      rax,    CR4_OSFXSR
    and     eax,    0xFFFFFFFF - CR4_OSXMMEXCPT
    ;or     eax,    CR4_OSXMMEXCPT
    mov     cr4,    rax


    ; enable xsave
    xor     rax,    rax
    inc     rax
    test    ecx,    CPUID_XSAVE
    jz      .noXsaveSupport

    mov     rax,    cr4
    or      eax,    CR4_OSXSAVE
    mov     cr4,    rax
    .noXsaveSupport:

    .notSupported:


    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    ret

gApTrampoline16End:
