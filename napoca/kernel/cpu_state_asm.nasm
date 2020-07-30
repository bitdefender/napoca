;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

%ifdef __YASM_MAJOR__
    %include "cpu_state_defs.nasm"
%else
    %include "kernel\cpu_state_defs.nasm"
%endif

%ifdef EFI_BUILD
    %include "asmlib\loader_interface.nasm"
%else
    %ifdef _CPU_STATE_ASM_USE_WINGUEST_PATH_
        %include "..\..\asmlib\loader_interface.nasm"
    %else
        %include "loader_interface.nasm"
    %endif
%endif


[bits 64]
IA32_VMX_BASIC              equ 0x480
MSR_KERNELGSbase            equ 0xC0000102
IA32_FS_BASE_MSR            equ 0xC0000100
IA32_GS_BASE_MSR            equ 0xC0000101

CPUID_01_ECX_XSAVE          equ 0x04000000 ;; bit 26

global CpustateCaptureGuestFxState
global CpustateRestoreGuestFxState

global CpustateCaptureGuestXState
global CpustateRestoreGuestXState

global  CpustateCaptureGuestState

; rcx - ptr to CPUSTATE_GUEST_STATE_INFO
; rdx - new value for RIP/RSP
global CpustateSetRIP
global CpustateSetRSP
global CpustateRestoreGuestState    ; rcx = ptr to CPUSTATE_GUEST_STATE_INFO
global CpustateGetGdtLimit
global CpustateGetGdtBase
global CpustateGetCs
global CpustateGetTrFromSecondaryGdt ; used if we needed to rebuild gdt to add a valid tr
        ; rcx = guest info ptr; rdx = address of new descriptors table
global CpuStateLock

%macro SMSR64 2     ; example: SMSR64 rdi + CPUSTATE_HOST_STATE_INFO.Ia32Efer, 0x277
    mov     rcx, %2
    rdmsr
    mov     [%1], eax
    mov     [%1 + 4], edx
%endmacro

%macro LMSR64 2     ; example: LMSR64 0x277, rdi + CPUSTATE_HOST_STATE_INFO.Ia32Efer,
    mov     rcx,    %1
    mov     eax,    [%2]
    mov     edx,    [%2 + 4]
    wrmsr
%endmacro

%define SAFE_CALL_C X64CALL


; enable fpu in CR0 (save old state on stack)
%macro ENTER_STACK_ENABLE_FPU 0
    push    rax
    mov     rax, cr0
    push    rax
    and     al, (255-4)
    mov     cr0, rax
%endmacro

; restore from stack enable/disable fpu state in CR0
%macro EXIT_STACK_ENABLE_FPU 0
    pop     rax
    mov     cr0, rax
    pop     rax
%endmacro

CpustateGetGdtBase:
    sub     rsp, 12
    sgdt    [rsp]
    mov     rax, [rsp+2]
    add     rsp, 12
    ret

CpustateGetGdtLimit:
    sub     rsp, 12
    sgdt    [rsp]
    xor     rax, rax
    mov     ax, [rsp]
    add     rsp, 12
    ret

CpustateGetCs:
    xor     rax, rax
    mov     ax, cs
    ret

_getTableBaseAndLimitForSelector:
    ; rcx = pointer to a CPUSTATE_FULL_SELECTOR_DATA structure
    ; rdx = selector value

    ; get the GDT limit & base
    sgdt    [rcx]

    test    dx,     100b
    jz      .done           ; pointing to a global descriptor, [rcx] is already filled

.local:
    ;
    ; Locate global descriptor for ldt and grab base&limit for ldt from there
    ;
    push    rdx

    sldt    rdx             ; dx = ldt selector value pointing to a global descriptor
    test    dx,     dx
    jz      .noLDT

    push    r8
    SAFE_CALL_C     CpustateGetDescriptorBaseAddress
    mov     r8,     rax     ; r8 = buffer for base address
    SAFE_CALL_C     CpustateGetDescriptorLimit
    mov     [rcx],  ax      ; prev. limit overwritten
    mov     [rcx+2],r8      ; prev. base overwritten
    pop     r8

    pop     rdx

.done:
    ; [rcx] now contains the structure
    xor     rax,    rax
    inc     rax
    ret

.noLDT:
    pop     rdx
    xor     rax,    rax
    ret



CpustateGetDescriptorBaseFromAx:
    ; returns 0 on error

    push    rcx
    push    rdx

    sub     rsp,    10
    ; locate the corresponding table

    mov     rcx,    rsp
    xor     rdx,    rdx
    mov     dx,     ax
    call    _getTableBaseAndLimitForSelector

    test    rax,    rax
    jz      .badSelector

    ; decode the base value
    SAFE_CALL_C CpustateGetDescriptorBaseAddress
    jmp     .done

.badSelector:
    xor     rax,    rax

.done:
    add     rsp,    10

    pop     rdx
    pop     rcx
    ret



CpustateGetDescriptorLimitFromAx:
    ; returns 0 on error

    push    rcx
    push    rdx

    sub     rsp,    10
    ; locate the corresponding table

    mov     rcx,    rsp
    xor     rdx,    rdx
    mov     dx,     ax
    call    _getTableBaseAndLimitForSelector

    test    rax,    rax
    jz      .badSelector

    ; decode the base value
    SAFE_CALL_C CpustateGetDescriptorLimit

    jmp     .done

.badSelector:
    xor     rax,    rax

.done:
    add     rsp,    10

    pop     rdx
    pop     rcx
    ret



CpustateGetDescriptorRightsFromAx:
    push    rcx
    push    rdx

    sub     rsp,    10
    ; locate the corresponding table
    movzx   rdx,    ax

    mov     rcx,    rsp
    xor     rdx,    rdx
    mov     dx,     ax
    call    _getTableBaseAndLimitForSelector

    test    rax,    rax
    jz      .badSelector

    ; decode the base value
    SAFE_CALL_C CpustateGetDescriptorRights
    jmp     .done

.badSelector:
    mov     rax,    0xCACA

.done:
    add     rsp,    10

    pop     rdx
    pop     rcx
    ret



CpustateCaptureGuestState:
    push    rax
    push    rdx
    push    rdi
    push    rcx
    ;;; take care at [rsp + x] indexed values!!

    mov     rdi, rcx
    ;;mov     [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], BYTE 0
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], dl

    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rax],  rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rbx],  rbx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rcx],  rcx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rdx],  rdx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rbp],  rbp
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rsi],  rsi

    push    rax
    mov     rax,                                    [rsp + 16]  ; skip two values to get to the orig rdi
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rdi],  rax
    pop     rax

    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R8 ],  r8
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R9 ],  r9
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R10],  r10
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R11],  r11
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R12],  r12
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R13],  r13
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R14],  r14
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.R15],  r15

    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.IsStructureInitialized], byte 1

    [bits 32]   ; bits 32 + rdi=>edi = same encoding - fool the assembler to avoid warnings
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Es], es
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Cs], cs
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Ss], ss
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Ds], ds
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Fs], fs
    mov     [edi + CPUSTATE_GUEST_STATE_INFO.Gs], gs
    [bits 64]

    sldt    ax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Ldtr], ax

    mov     byte [rdi + CPUSTATE_GUEST_STATE_INFO.Tr], 0
    cmp     [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], byte 1
    je skip_tr1
    str     ax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Tr], ax

skip_tr1:
    xor     rax, rax
    not     rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.LinkPointer], rax  ; reserved, needs to be 0xFFFF....FF

    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Debugctl,       0x1d9
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Pat,            0x277
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Efer,           0xC0000080
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32PerfGlobalCtrl, 0x38F


    ; EPT disabled init values...
    xor     rax, rax
    not     rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Pdpte0], rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Pdpte1], rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Pdpte2], rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Pdpte3], rax


    mov     ax, es
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.EsLimit], eax


    mov ax, cs
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.CsLimit], eax

    mov ax, ss
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.SsLimit], eax

    mov ax, ds
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.DsLimit], eax

    mov ax, fs
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.FsLimit], eax

    mov ax, gs
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.GsLimit], eax

    sldt    ax
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.LdtrLimit], eax

    cmp byte [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], 1
    je skip_tr2
    str     ax
    call    CpustateGetDescriptorLimitFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrLimit], eax

skip_tr2:
    sub     rsp, 10
    sgdt    [rsp]
    movzx   eax, WORD [rsp]
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.GdtrLimit], eax

    sidt    [rsp]
    movzx   eax, WORD [rsp]
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.IdtrLimit], eax
    add     rsp, 10


    mov ax, es
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.EsAccessRights], eax

    mov ax, cs
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.CsAccessRights], eax
    mov ax, ss
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.SsAccessRights], eax
    mov ax, ds
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.DsAccessRights], eax
    mov ax, fs
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.FsAccessRights], eax
    mov ax, gs
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.GsAccessRights], eax

    sldt    ax
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.LdtrAccessRights], eax

    cmp byte [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], 1
    je skip_tr3
    str     ax
    call    CpustateGetDescriptorRightsFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrAccessRights], eax
skip_tr3:

    xor     eax, eax    ; TODO: make sure it's ok to set interruptibility 0 (no 'blocking' state)
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.InterruptibilityState], eax

    xor     eax, eax    ; prevent effects from code changes to the above block
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.ActivityState], eax    ; 0 means 'active'


    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.SmBase],  DWORD 0xA0000

    sub     rsp, 8  ; 64-bit buffer
    SMSR64  rsp, 0x174
    pop     rax ; and the 64 bits from the stack are gone now
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterCs], eax

    xor     eax, eax
    not     eax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.VmxPreemptionTimerValue], eax  ; 0xFFFFFFFF timer value

    mov     rax, cr0
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Cr0], rax
    mov     rax, cr2
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Cr2], rax
    mov     rax, cr3
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Cr3], rax
    mov     rax, cr4
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Cr4], rax
    mov     rax, cr8
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Cr8], rax

    mov ax, es
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.EsBase], rax

    mov ax, cs
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.CsBase], rax

    mov ax, ss
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.SsBase], rax

    mov ax, ds
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.DsBase], rax


    ; set FsBase and GsBase to the corresponding MSR values
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.FsBase,     IA32_FS_BASE_MSR
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.GsBase,     IA32_GS_BASE_MSR


    sldt    ax
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.LdtrBase], rax

    cmp byte [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], 1
    je skip_tr4
    str     ax
    call    CpustateGetDescriptorBaseFromAx
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrBase], rax
skip_tr4:

    sub     rsp, 10
    sgdt    [rsp]
    mov     rax, [rsp + 2]
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.GdtrBase], rax

    sidt    [rsp]
    mov     rax, [rsp + 2]
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.IdtrBase], rax
    add     rsp, 10

    mov     rax, dr7
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Dr7], rax

    lea     rax, [rsp + (4*8 + 8)]                      ; 4 * 8 (regs backup) + 8 (retaddr)
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rsp], rax  ; rsp at function call

    mov     rax, [rsp + 24]
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rip], rax  ; rip set to the return address

    pushf
    pop     rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.Rflags], rax

    xor     rax, rax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.PendingDebugExceptions], rax
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterEsp, 0x175
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterEip, 0x176
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Ia32KernelGsBase, MSR_KERNELGSbase

    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.Star,  0xC0000081
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.LStar, 0xC0000082
    SMSR64  rdi + CPUSTATE_GUEST_STATE_INFO.CStar, 0xC0000083

    ; FPU + OTHER EXTENSIONS (align the address to 16)
    mov     rcx, rdi
    add     rcx, CPUSTATE_GUEST_STATE_INFO.Extensions

    push    rax
    push    rbx
    push    rcx
    push    rdx
    mov     rax, 0x01
    cpuid
    bt      ecx, 26         ;; bit 26
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    jnc     xsave_not_supported
    call    CpustateCaptureGuestXState
    jmp     extended_context_saved

xsave_not_supported:
    call    CpustateCaptureGuestFxState

extended_context_saved:

    pop     rcx
    pop     rdi
    pop     rdx
    pop     rax
    ret


CpustateRestoreGuestState:
    mov     rdi,    rcx

    sub     rsp,    12                                              ; 10 + 2 for 'odd alignment'
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.GdtrLimit]
    mov     [rsp],  ax
    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.GdtrBase]
    mov     [rsp+2], rax
    lgdt    [rsp]

    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.IdtrLimit]
    mov     [rsp],  ax
    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.IdtrBase]
    mov     [rsp+2], rax
    lidt    [rsp]
    add     rsp,    12

    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Es]
    mov es,     ax

    xor     rax, rax
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Cs]
    push    rax
    call    .next
.next:
    add     qword [rsp], 7
    o64 retf


    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Ss]
    mov ss,     ax
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Ds]
    mov ds,     ax
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Fs]
    mov fs,     ax
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Gs]
    mov gs,     ax

    ; restore tr if it ain't a fake one (or zero..)
    test    [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], BYTE 0xFF
jnz .don_t_restore
    mov     ax,     [rdi + CPUSTATE_GUEST_STATE_INFO.Tr]
    test    ax,     ax
    jz      .don_t_restore
    ltr ax
.don_t_restore:

    LMSR64  0x1d9,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Debugctl
    LMSR64  0x277,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Pat
    LMSR64  0xC0000080,         rdi + CPUSTATE_GUEST_STATE_INFO.Ia32Efer
    LMSR64  0x38F,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32PerfGlobalCtrl
    LMSR64  0x174,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterCs
    LMSR64  IA32_FS_BASE_MSR,   rdi + CPUSTATE_GUEST_STATE_INFO.FsBase
    LMSR64  IA32_GS_BASE_MSR,   rdi + CPUSTATE_GUEST_STATE_INFO.GsBase
    LMSR64  0x175,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterEsp
    LMSR64  0x176,              rdi + CPUSTATE_GUEST_STATE_INFO.Ia32SysenterEip
    LMSR64  MSR_KERNELGSbase,   rdi + CPUSTATE_GUEST_STATE_INFO.Ia32KernelGsBase

    LMSR64  0xC0000081,   rdi + CPUSTATE_GUEST_STATE_INFO.Star
    LMSR64  0xC0000082,   rdi + CPUSTATE_GUEST_STATE_INFO.LStar
    LMSR64  0xC0000083,   rdi + CPUSTATE_GUEST_STATE_INFO.CStar

    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Cr0]
    mov     cr0,    rax
    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Cr2]
    mov     cr2,    rax
    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Cr4]
    mov     cr4,    rax
    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Cr8]
    mov     cr8,    rax


    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Dr7]
    mov     dr7,    rax

    ; FPU + OTHER EXTENSIONS
    mov     rcx, rdi
    add     rcx, CPUSTATE_GUEST_STATE_INFO.Extensions

    push    rax
    push    rbx
    push    rcx
    push    rdx
    mov     rax, 0x01
    cpuid
    bt      ecx, 26         ;; bit 26
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax

    jnc     xrestore_not_supported
    call    CpustateRestoreGuestXState
    jmp     extended_context_restored
xrestore_not_supported:
    call    CpustateRestoreGuestFxState
extended_context_restored:

    mov     rax,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rax]
    mov     rbx,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rbx]
    mov     rcx,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rcx]
    mov     rdx,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rdx]
    mov     rbp,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rbp]
    mov     rsi,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rsi]
    mov     r8,     [rdi + CPUSTATE_GUEST_STATE_INFO.R8 ]
    mov     r9,     [rdi + CPUSTATE_GUEST_STATE_INFO.R9 ]
    mov     r10,    [rdi + CPUSTATE_GUEST_STATE_INFO.R10]
    mov     r11,    [rdi + CPUSTATE_GUEST_STATE_INFO.R11]
    mov     r12,    [rdi + CPUSTATE_GUEST_STATE_INFO.R12]
    mov     r13,    [rdi + CPUSTATE_GUEST_STATE_INFO.R13]
    mov     r14,    [rdi + CPUSTATE_GUEST_STATE_INFO.R14]
    mov     r15,    [rdi + CPUSTATE_GUEST_STATE_INFO.R15]
    mov     rdi,    [rdi + CPUSTATE_GUEST_STATE_INFO.Rdi]

.end:
    ret


; rcx will contain a pointer to a linear memory area, 16-bytes aligned, of 512 bytes where
; the FX state (FPU/MMX & SSE) will be saved
;;;todo: !!! CHECK CPUID.(EAX=0D, ECX=0):EBX to find out HOW much memory the save operation uses !!!
CpustateCaptureGuestXState:
    ENTER_STACK_ENABLE_FPU

    ; set to 0xFFF... both rax and rdx (capture ALL features)


    push    rax
    push    rdx

    ; align to 64 for xsave
    add     rcx, 63
    mov     rax, (0xFFFFFFFFFFFFFFFF - 63)
    and     rcx, rax
      
    mov     rax,    cr0
    push    rax             ; push CR0
    and     al,     ~(1<<3) ; #NM If CR0.TS[bit 3] = 1.
    mov     cr0,    rax
 
    mov     rax,    cr4
    push    rax             ; push CR4
    or      rax,    1<<18   ; #UD If CR4.OSXSAVE[bit 18] = 0.
    mov     cr4,    rax


    xor     rax, rax
    dec     rax
    mov     rdx, rax
    xsave   [rcx]

skip:

    pop     rax
    mov     cr4,    rax
    pop     rax
    mov     cr0,    rax
    
    pop     rdx
    pop     rax
    EXIT_STACK_ENABLE_FPU
    ret


; rcx contains a pointer to a 512 bytes buffer containing the FX state
CpustateRestoreGuestXState:
CpustateRestoreCompleteGuestFxState:
    ENTER_STACK_ENABLE_FPU

    ; set to 0xFFF... both rax and rdx (restore ALL features)
    push    rax
    push    rdx

    ; align to 64 for xrstor
    add     rcx, 63
    mov     rax, (0xFFFFFFFFFFFFFFFF - 63)
    and     rcx, rax

    mov     rax,    cr0
    push    rax             ; push CR0
    and     al,     ~(1<<3) ; #NM If CR0.TS[bit 3] = 1.
    mov     cr0,    rax
 
    mov     rax,    cr4
    push    rax             ; push CR4
    or      rax,    1<<18   ; #UD If CR4.OSXSAVE[bit 18] = 0.
    mov     cr4,    rax

    xor     rax, rax
    dec     rax
    mov     rdx, rax
    clts
    xrstor  [rcx]

    pop     rax
    mov     cr4,    rax
    pop     rax
    mov     cr0,    rax
    pop     rdx
    pop     rax
    EXIT_STACK_ENABLE_FPU
    ret


;;%if 0   ; DISABLED CODE...
; rcx will contain a pointer to a linear memory area, 16-bytes aligned, of 512 bytes where
; the FX state (FPU/MMX & SSE) will be saved
CpustateCaptureGuestFxState:
    ENTER_STACK_ENABLE_FPU
    ; round-up rcx to align to 16
    add     rcx, 0xF
    and     cl, 0xF0
    clts
    fxsave  [rcx]
    EXIT_STACK_ENABLE_FPU
    ret


; rcx contains a pointer to a 512 bytes buffer containing the FX state
CpustateRestoreGuestFxState:
    ENTER_STACK_ENABLE_FPU
    ; round-up rcx to align to 16
    add     rcx, 0xF
    and     cl, 0xF0
    clts
    fxrstor [rcx]
    EXIT_STACK_ENABLE_FPU
    ret
;;%endif



; rcx - ptr to CPUSTATE_GUEST_STATE_INFO
; rdx - new value for RIP
CpustateSetRIP:
    mov [rcx + CPUSTATE_GUEST_STATE_INFO.Rip], rdx
    ret

; rcx - ptr to CPUSTATE_GUEST_STATE_INFO
; rdx - new value for RSP
CpustateSetRSP:
    mov [rcx + CPUSTATE_GUEST_STATE_INFO.Rsp], rdx
    ret

CpustateGetTrFromSecondaryGdt:
    ; rcx = guest state info ptr
    ; rdx = gdt descriptors address
    push    rcx
    push    rdx
    push    rdi

    mov     rdi,    rcx

    sub     rsp,    10
    mov     [rsp],  WORD 8*3 -1
    mov     [rsp+2], rdx
    mov     rcx,    rsp
    mov     rdx,    8
    SAFE_CALL_C     CpustateGetDescriptorBaseAddress
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrBase], rax
    SAFE_CALL_C     CpustateGetDescriptorLimit
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrLimit], eax
    ;SAFE_CALL_C        CpustateGetDescriptorRights
    mov     eax, 0x8b
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.TrAccessRights], eax
    mov     [rdi + CPUSTATE_GUEST_STATE_INFO.UsingFakedTr], BYTE 1
    add     rsp,    10

    pop     rdi
    pop     rdx
    pop     rcx
    ret

CpuStateLock:
        push    r8
        push    rdx
        push    rax

        xor     edx, edx
        inc     edx

    .spin:
        nop
        call    .get
    .lock:
        dd      0
    .get:
        pop     r8                  ; r8 = lock variable
        test    rcx, rcx
        jz      .clear

        xor     eax, eax
        lock    cmpxchg [r8], edx   ; if [rcx]==0 set to 1, eax = [rcx] when we get the lock
        test    eax, eax
        jnz     .spin
        jmp     .done

    .clear:
        mov     DWORD[r8], 0
    .done:
        pop     rax
        pop     rdx
        pop     r8
        ret

global PortDelayMicroseconds
PortDelayMicroseconds:      ; param = number of microseconds
    push    rax
    push    rcx

    .here:
    in      al, 0x80
    loop    .here

    pop     rcx
    pop     rax
    ret




CpustateGetDescriptorBaseAddress:
    ; rcx = __in CPUSTATE_FULL_SELECTOR_DATA *SelectorRegisterData
    ; rdx = __in WORD Selector
    ; returns QWORD

    push    rbx

    test    dx,     (0xFFFF - 7)
    jnz     .isUsed

    ; this descriptor is not used
    xor     rax,    rax
    jmp     .cleanup

.isUsed:
    ; make sure Selector doesn't overflow the corresponding table

    ; prepare (SelectorRegisterData->Length+1) into ax
    mov     ax,     [rcx + CPUSTATE_FULL_SELECTOR_DATA.Length]
    inc     ax

    ; prepare ((Selector & (0xFFFF - 7)) + 8) into bx
    xor     rbx,    rbx
    mov     bx,     dx
    and     bx,     (0xFFFF - 7)
    add     rbx,    8

    ; if (((Selector & (0xFFFF - 7)) + 8) > (SelectorRegisterData->Length+1)) return -1
    cmp     bx,     ax
    jna     .enough8
    xor     rax,    rax
    dec     rax
    jmp     .cleanup

.enough8:
    sub     rbx,    8                                           ; bx is now (Selector & (0xFFFF - 7))
    mov     rax,    [rcx + CPUSTATE_FULL_SELECTOR_DATA.Base]    ; rax is the table base
    add     rax,    rbx                                         ; rax now points to the 64 bits descriptor

    push    rax

    ; take the bits
    push    rdx                                                 ; temp usage for rdx
    xor     rbx,    rbx                                         ; rbx will cumulate the result

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((*Descriptor) >> 16) & 0xFFFFFF...
    shr     rdx,    16
    and     rdx,    0xFFFFFF
    or      rbx,    rdx                                         ; commit these bits (Base[23:0])

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((((*Descriptor) >> (QWORD) 56)) << (QWORD)24)
    shr     rdx,    56
    shl     rdx,    24
    or      rbx,    rdx                                         ; commit (Base[31:24])

    ; check the 'system' bit
    mov     rdx,    [rax]
    shr     rdx,    32+8+4
    test    rdx,    1
    pop     rdx                                                 ; end temp usage for rdx
    pop     rax
    jnz     .notSystem

    ; system descriptor, validate if enough memory is reserved for its entry
    ; prepare (SelectorRegisterData->Length+1) into ax
    push    rax
    xor     ax,     ax
    mov     ax,     [rcx + CPUSTATE_FULL_SELECTOR_DATA.Length]
    inc     ax

    ; prepare ((Selector & (0xFFFF - 7)) + 16) into bx
    push    rbx
    mov     bx,     dx
    and     bx,     (0xFFFF - 7)
    add     bx,     16

    ; if (((Selector & (0xFFFF - 7)) + 16) > (SelectorRegisterData->Length+1)) return -1
    cmp     bx,     ax
    pop     rbx
    pop     rax
    jna     .enough16
    xor     rax,    rax
    dec     rax
    jmp     .cleanup

.enough16:
    ; result |= (Descriptor[1] << (QWORD)32);
    mov     rax,    [rax + 8]                                   ; take the second qword from descriptor
    shl     rax,    32
    or      rbx,    rax

.notSystem: ; done, our result is ready (rbx)
    mov     rax,    rbx

.cleanup:
    pop     rbx
    ret





CpustateGetDescriptorLimit:
    ; rcx = __in CPUSTATE_FULL_SELECTOR_DATA *SelectorRegisterData
    ; rdx = __in WORD Selector
    ; returns QWORD

    push    rbx

    test    dx,     (0xFFFF - 7)
    jnz     .isUsed

    ; this descriptor is not used
    xor     rax,    rax
    dec     rax
    jmp     .cleanup



.isUsed:
    ; make sure Selector doesn't overflow the corresponding table

    ; prepare (SelectorRegisterData->Length+1) into ax
    mov     ax,     [rcx + CPUSTATE_FULL_SELECTOR_DATA.Length]
    inc     ax



    ; prepare ((Selector & (0xFFFF - 7)) + 8) into bx
    xor     rbx,    rbx
    mov     bx,     dx
    and     bx,     (0xFFFF - 7)
    add     rbx,    8

    ; if (((Selector & (0xFFFF - 7)) + 8) > (SelectorRegisterData->Length+1)) return -1
    cmp     bx,     ax
    jna     .enough8
    xor     rax,    rax
    dec     rax
    jmp     .cleanup

.enough8:
    sub     rbx,    8                                           ; bx is now (Selector & (0xFFFF - 7))
    mov     rax,    [rcx + CPUSTATE_FULL_SELECTOR_DATA.Base]    ; rax is the table base
    add     rax,    rbx                                         ; rax now points to the 64 bits descriptor

    ; take the bits
    ;(((*Descriptor)>>(QWORD)(3*16) & 0xF) << (QWORD)16);  // higher 4 bits from Descriptor.high[19:16]

    push    rdx                                                 ; temp usage for rdx
    xor     rbx,    rbx                                         ; rbx will cumulate the result

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((*Descriptor) >> 16) & 0xFFFFFF...
    shr     rdx,    3*16
    and     rdx,    0xF
    shl     rdx,    16
    or      rbx,    rdx                                         ; commit the higher 4 bits from Descriptor.high[19:16]

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((((*Descriptor) >> (QWORD) 56)) << (QWORD)24)
    and     rdx,    0xFFFF
    or      rbx,    rdx                                         ; commit the lower 16 bits

    pop     rdx

    ; take the result
    mov     rax,    rbx

.cleanup:
    pop     rbx
    ret




CpustateDecodeDescriptor:

    push    rbx

    ; some validations
    test    rcx,    rcx
    jnz     .rcx_ok
    xor     rax,    rax
    jmp     .cleanup

.rcx_ok:
    test    r8,     r8
    jnz     .r8_ok
    xor     rax,    rax
    jmp     .cleanup

.r8_ok:
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.AccessAndFlags],    DWORD CPUSTATE_BAD_SELECTOR_ACCESS_RIGHTS

    test    dx,     (0xFFFF - 7)
    jnz     .isUsed

    ; not used, setup some default values
    xor     rax,    rax
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.AccessAndFlags],    DWORD CPUSTATE_BAD_SELECTOR_ACCESS_RIGHTS
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Available],         BYTE 0
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Base],              rax
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.BigOperands],       BYTE 1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Code64],            BYTE 0
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Granularity],       BYTE 1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Limit],             DWORD 0xFFFFF
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Present],           BYTE 0
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.PrivilegeLevel],    BYTE 0
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.System],            BYTE 1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Type],              BYTE 3
    jmp     .cleanup


.isUsed:
    ; make sure Selector doesn't overflow the corresponding table

    ; prepare (SelectorRegisterData->Length+1) into ax
    mov     ax,     [rcx + CPUSTATE_FULL_SELECTOR_DATA.Length]
    inc     ax

    ; prepare ((Selector & (0xFFFF - 7)) + 8) into bx
    xor     rbx,    rbx
    mov     bx,     dx
    and     bx,     (0xFFFF - 7)
    add     rbx,    8

    ; if (((Selector & (0xFFFF - 7)) + 8) > (SelectorRegisterData->Length+1)) return -1
    cmp     bx,     ax
    jna     .enough8
    xor     rax,    rax
    dec     rax
    jmp     .cleanup

.enough8:
    sub     rbx,    8                                           ; bx is now (Selector & (0xFFFF - 7))
    mov     rax,    [rcx + CPUSTATE_FULL_SELECTOR_DATA.Base]    ; rax is the table base
    add     rax,    rbx                                         ; rax now points to the 64 bits descriptor

    push    rax

    ;
    ; Base address
    ;
    push    rdx                                                 ; temp usage for rdx
    xor     rbx,    rbx                                         ; rbx will cumulate the result

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((*Descriptor) >> 16) & 0xFFFFFF...
    shr     rdx,    16
    and     rdx,    0xFFFFFF
    or      rbx,    rdx                                         ; commit these bits (Base[23:0])

    mov     rdx,    [rax]                                       ; *Descriptor, make rdx = ((((*Descriptor) >> (QWORD) 56)) << (QWORD)24)
    shr     rdx,    56
    shl     rdx,    24
    or      rbx,    rdx                                         ; commit (Base[31:24])

    ; check the 'system' bit
    mov     rdx,    [rax]
    shr     rdx,    32+8+4
    test    rdx,    1
    pop     rdx                                                 ; end temp usage for rdx
    pop     rax
    jnz     .notSystem

    ; system descriptor, validate if enough memory is reserved for its entry
    ; prepare (SelectorRegisterData->Length+1) into ax
    push    rax
    xor     ax,     ax
    mov     ax,     [rcx + CPUSTATE_FULL_SELECTOR_DATA.Length]
    inc     ax

    ; prepare ((Selector & (0xFFFF - 7)) + 16) into bx
    push    rbx
    mov     bx,     dx
    and     bx,     (0xFFFF - 7)
    add     bx,     16

    ; if (((Selector & (0xFFFF - 7)) + 16) > (SelectorRegisterData->Length+1)) return -1
    cmp     bx,     ax
    pop     rbx
    pop     rax
    jna     .enough16
    xor     rax,    rax
    dec     rax
    jmp     .cleanup

.enough16:  ; validation succeeded
    ; result |= (Descriptor[1] << (QWORD)32);
    push    rax
    mov     rax,    [rax + 8]                                   ; take the second qword from descriptor
    shl     rax,    32
    or      rbx,    rax
    pop     rax
.notSystem:
    ; save the base value
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Base],              rbx

    ;
    ; Access and flags
    ;
    mov     rbx,    [rax]
    shr     rbx,    40
    and     rbx,    0xF0FF                                      ; clear the segment limit remains
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.AccessAndFlags],    ebx

    ;
    ; Limit
    ;
    mov     rbx,    [rax]
    shr     rbx,    3*16
    and     rbx,    0xF
    shl     rbx,    16                                          ; higher 4 bits from Descriptor.high[19:16]

    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Limit],             ebx ; (((*Descriptor)>>(QWORD)(3*16) & 0xF) << (QWORD)16)
    mov     ebx,    [rax]
    and     ebx,    0xFFFF
    or      [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Limit],             ebx ; result |= (*Descriptor & 0xFFFF);

    ; Type
    mov     rbx,    [rax]
    shr     rbx,    32+8
    and     bl,     0xF
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Type],              bl ; ((*Descriptor) >> (QWORD)(32 + 8)) & 0xF

    ; PrivilegeLevel
    mov     rbx,    [rax]
    shr     rbx,    32+8+5
    and     bl,     0x3
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.PrivilegeLevel],    bl ; ((*Descriptor) >> (QWORD)(32 + 8 + 5)) & 0x3

    ;
    ; Boolean flags (code is expanded to be more readable)
    ;
    mov     rbx,    [rax]
    shr     rbx,    32 + 8 + 4
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.System],            bl ; 0 != (((*Descriptor) >> (QWORD)(32 + 8 + 4)) & 1)

    mov     rbx,    [rax]
    shr     rbx,    32 + 8 + 7
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Present],           bl ; 0 != (((*Descriptor) >> (QWORD)(32 + 8 + 7)) & 1)

    mov     rbx,    [rax]
    shr     rbx,    16*3 + 4
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Available],         bl ; 0 != (((*Descriptor) >> (QWORD)(16*3 + 4)) & 1);

    mov     rbx,    [rax]
    shr     rbx,    16*3 + 5
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Code64],            bl ; 0 != (((*Descriptor) >> (QWORD)(16*3 + 5)) & 1);

    mov     rbx,    [rax]
    shr     rbx,    16*3 + 6
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.BigOperands],       bl ; 0 != (((*Descriptor) >> (QWORD)(16*3 + 6)) & 1)


    mov     rbx,    [rax]
    shr     rbx,    16*3 + 7
    and     bl,     1
    mov     [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.Granularity],       bl ; 0 != (((*Descriptor) >> (QWORD)(16*3 + 7)) & 1)

    xor     rax,    rax
    inc     rax

.cleanup:
    pop     rbx
    ret


CpustateGetDescriptorRights:
    push    rbp
    mov     rbp,    rsp

    ; reserve a buffer for a local CPUSTATE_UNPACKED_DESCRIPTOR_DATA structure
    push    r8
    sub     rsp,    CPUSTATE_UNPACKED_DESCRIPTOR_DATA_size
    mov     r8,     rsp         ; address of local buffer

    ; preserve r8 for after-call
    push    r8
    sub     rsp,    0x20
    call    CpustateDecodeDescriptor
    add     rsp,    0x20
    pop     r8

    ; check results
    test    rax,    rax
    jz      .failed

    ; just return the returned value
    mov     rax,    [r8 + CPUSTATE_UNPACKED_DESCRIPTOR_DATA.AccessAndFlags]
    jmp     .cleanup

.failed:
    mov     rax,    CPUSTATE_BAD_SELECTOR_ACCESS_RIGHTS
.cleanup:
    add     rsp, CPUSTATE_UNPACKED_DESCRIPTOR_DATA_size
    pop     r8
    pop     rbp
    ret

