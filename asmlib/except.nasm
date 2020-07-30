;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

%include "system.nasm"
%include "loader_interface.nasm"


%ifdef DOC_FILE
except.nasm - Contains the assembly ISR logic used to handle exceptions. Crates the ISR stubs used in the IDT.

The assembly interrupt handling:
- the exception index is saved on the stack
- the common interrupt handle is called
- registers are saved on the stack (general purpose, cr2, fx registers)
- the C method HvDispatchException is called with the saved regisetrs given as parameters
- register values are restored
- the ISR exits

The list of parameters for interfacing with this code (as %define macros):
EX_FPU_RESERVED_SIZE
EX_SAVE_XCR0
EX_PRESERVE_FPU_STATE             0 = no, 1 = full, 2 = partial
EX_FPU_REG_SIZE                   128 / 256 / 512 (work on XMM/YMM/ZMM registers)
EX_ZERO_FPU_SAVE_AREA

Known limitation: FPU size is hardcoded instead of being dinamically determined based on CPUID.(EAX=0D, ECX=0):EBX
%endif

%ifndef EX_FPU_REG_SIZE
    %define EX_FPU_REG_SIZE 128
%endif

; Intel Software Developer vol 1 058
; see 13.4 XSAVE area
%define XSAVE_HEADER_OFFSET                 512
%define XSAVE_HEADER_SIZE                   64
extern  HvDispatchException

%ifdef DOC_FILE
    Methods: HvHndDivideError, HvHndDebug, HvHndNMI, HvHndBreakpoint, HvHndOverflow, HvHndOverflow, HvHndBOUND, HvHndInvalidOpcode
    HvHndDeviceNotAvailable, HvHndDoubleFault, HvHndCoprocessorSegmentOverrun, HvHndInvalidTSS, HvHndSegmentNotPresent,
    HvHndStackFault, HvHndStackFault, HvHndGeneralProtection, HvHndPageFault, HvHnd15, HvHndFPUError, HvHndFPUError,
    HvHndAlignmentCheck, HvHndMachineCheck, HvHndSIMDFloatingPoint, HvHndSX
    exposed by this file are Interrupt service routines (ISRs) that will be placed in the IDT.

    Each method pushes its repsective interrupt index and calls the common exception handler.
%endif
global  HvHndDivideError                    ;;  0
global  HvHndDebug                          ;;  1
global  HvHndNMI                            ;;  2
global  HvHndBreakpoint                     ;;  3
global  HvHndOverflow                       ;;  4
global  HvHndBOUND                          ;;  5
global  HvHndInvalidOpcode                  ;;  6
global  HvHndDeviceNotAvailable             ;;  7
global  HvHndDoubleFault                    ;;  8
global  HvHndCoprocessorSegmentOverrun      ;;  9
global  HvHndInvalidTSS                     ;;  10
global  HvHndSegmentNotPresent              ;;  11
global  HvHndStackFault                     ;;  12
global  HvHndGeneralProtection              ;;  13
global  HvHndPageFault                      ;;  14
global  HvHnd15                             ;;  15
global  HvHndFPUError                       ;;  16
global  HvHndAlignmentCheck                 ;;  17
global  HvHndMachineCheck                   ;;  18
global  HvHndSIMDFloatingPoint              ;;  19
global  HvHndSX                             ;;  30 - security exception, only for AMD when redirecting INIT

global  HvHndExtIntGeneric                  ;;  Generic external interrupt handler, will be copied inside each Interrupt Descriptor

%ifdef DOC_METHOD
    params: _In_ CX_UINT8 Index, _In_ CX_BOOL HasErrorCode
    description: Generates an ISR that prepares the stack by leveling it and pushing the exception index and calls the common exception handler HvExceptionHandlerCommon
%endif
%macro INSTANTIATE_EXCEPTION_STUB 2 ; index, hasErrorCode
%if %2 == 0
    sub rsp, 8              ; leave 8 dummy bytes for an ErrorCode
%endif
    push BYTE %1            ; will actually push a whole QWORD
    call HvExceptionHandlerCommon
%endmacro

align 16
HvExceptionHandlersArrayStart:                           ; Index, hasErrorCode
    HvHndDivideError:               INSTANTIATE_EXCEPTION_STUB 0,  0    ; EXCEPTION_DIVIDE_ERROR
    HvHndDebug:                     INSTANTIATE_EXCEPTION_STUB 1,  0    ; EXCEPTION_DEBUG
    HvHndNMI:                       INSTANTIATE_EXCEPTION_STUB 2,  0    ; EXCEPTION_NMI
    HvHndBreakpoint:                INSTANTIATE_EXCEPTION_STUB 3,  0    ; EXCEPTION_BREAKPOINT
    HvHndOverflow:                  INSTANTIATE_EXCEPTION_STUB 4,  0    ; EXCEPTION_OVERFLOW
    HvHndBOUND:                     INSTANTIATE_EXCEPTION_STUB 5,  0    ; EXCEPTION_BOUND
    HvHndInvalidOpcode:             INSTANTIATE_EXCEPTION_STUB 6,  0    ; EXCEPTION_INVALID_OPCODE
    HvHndDeviceNotAvailable:        INSTANTIATE_EXCEPTION_STUB 7,  0    ; EXCEPTION_DEVICE_NOT_AVAIL
    HvHndDoubleFault:               INSTANTIATE_EXCEPTION_STUB 8,  1    ; EXCEPTION_DOUBLE_FAULT
    HvHndCoprocessorSegmentOverrun: INSTANTIATE_EXCEPTION_STUB 9,  0    ; EXCEPTION_COPROC
    HvHndInvalidTSS:                INSTANTIATE_EXCEPTION_STUB 10, 1    ; EXCEPTION_INVALID_TSS
    HvHndSegmentNotPresent:         INSTANTIATE_EXCEPTION_STUB 11, 1    ; EXCEPTION_SEGMENT_NOT_PRESENT
    HvHndStackFault:                INSTANTIATE_EXCEPTION_STUB 12, 1    ; EXCEPTION_STACK_FAULT
    HvHndGeneralProtection:         INSTANTIATE_EXCEPTION_STUB 13, 1    ; EXCEPTION_GENERAL_PROTECTION
    HvHndPageFault:                 INSTANTIATE_EXCEPTION_STUB 14, 1    ; EXCEPTION_PAGE_FAULT
    HvHnd15:                        INSTANTIATE_EXCEPTION_STUB 15, 0    ; -
    HvHndFPUError:                  INSTANTIATE_EXCEPTION_STUB 16, 0    ; EXCEPTION_FPU_ERROR
    HvHndAlignmentCheck:            INSTANTIATE_EXCEPTION_STUB 17, 1    ; EXCEPTION_ALIGNMENT_CHECK
    HvHndMachineCheck:              INSTANTIATE_EXCEPTION_STUB 18, 0    ; EXCEPTION_MACHINE_CHECK
    HvHndSIMDFloatingPoint:         INSTANTIATE_EXCEPTION_STUB 19, 0    ; EXCEPTION_SIMD_FLOATING_POINT
                                    INSTANTIATE_EXCEPTION_STUB 20, 0    ; EXCEPTION_VE
                                    INSTANTIATE_EXCEPTION_STUB 21, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 22, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 23, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 24, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 25, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 26, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 27, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 28, 0    ; -
                                    INSTANTIATE_EXCEPTION_STUB 29, 0    ; -
    HvHndSX:                        INSTANTIATE_EXCEPTION_STUB 30, 0    ; EXCEPTION_SX - security exception, only for AMD when redirecting INIT
                                    INSTANTIATE_EXCEPTION_STUB 31, 0    ; -

%ifdef DOC_METHOD
    The parameters pushed on stack by the CPU when an exception is issued
    See Chapter 6.12 Intel Manual
%endif
_struc HV_CPU_TRAP_FRAME
    QWORD   (ErrorCode)

    ; address of interrupted instruction
    QWORD   (Rip)

    WORD    (SegCs)
    WORD    (_Fill0)
    DWORD   (_Fill1)

    DWORD   (EFlags)
    DWORD   (_Fill2)

    QWORD   (Rsp)

    WORD    (SegSs)
    WORD    (_Fill3)
    DWORD   (_Fill4)
_endstruc

%ifdef DOC_METHOD
    Other registers saved by HV in addition to what CPU has already saved
%endif
_struc HV_TRAP_FRAME
    ; Allocate 4 QWORDS for the called method parameters
    QWORD   (P1Home)
    QWORD   (P2Home)
    QWORD   (P3Home)
    QWORD   (P4Home)
    QWORD   (Reserved1)

    ; address of this trap frame
    QWORD   (Self)

    ; exception code (see above)
    QWORD   (ExceptionCode)

    ; general purpose registers
    QWORD   (Rax)
    QWORD   (Rbx)
    QWORD   (Rdx)
    QWORD   (Rcx)
    QWORD   (Rsi)
    QWORD   (Rdi)
    QWORD   (R8)
    QWORD   (R9)
    QWORD   (R10)
    QWORD   (R11)
    QWORD   (R12)
    QWORD   (R13)
    QWORD   (R14)
    QWORD   (R15)

    ; segment registers
    WORD    (SegDs)
    WORD    (_Fill100)
    DWORD   (_Fill101)

    WORD    (SegEs)
    WORD    (_Fill102)
    DWORD   (_Fill103)

    WORD    (SegFs)
    WORD    (_Fill104)
    DWORD   (_Fill105)

    WORD    (SegGs)
    WORD    (_Fill106)
    DWORD   (_Fill107)

    QWORD   (Cr2)        ; only valid if exception is page fault
    QWORD   (_FillCR2)

    ; IMPORTANT: the _Index field must be always defined right before the very last field of the synthetic/logic structure data
    VOID    (_Index)     ; the *next* QWORD (_Index is VOID...) is temporary used to store the ExceptionCode value
    QWORD   (Rbp)        ;

    ; at the end of the structure (or, early on the stack) comes the actual "hardware" trap-frame saved by the CPU
    VOID    (AsmHandlerAddress) ; this field overlaps (and needs to overlap) the CpuTrapFrame.ErrorCode from below
    HV_CPU_TRAP_FRAME (CpuTrapFrame)
_endstruc

_struc FPU_REG
    RAW(Data, 512/8)    ; always allocate 512 bits / reg, no matter if they're not that wide
_endstruc

_struc VOLATILE_FPU_REGS ; as described in: https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019#register-volatility-and-preservation
    FPU_REG     (REG0)
    FPU_REG     (REG1)
    FPU_REG     (REG2)
    FPU_REG     (REG3)
    FPU_REG     (REG4)
    FPU_REG     (REG5)
_endstruc

; define movups vs vmovups mnemonic and FPU_NTH_REG(n) to expand to XMMn/YMMn/ZMMn, based on EX_FPU_REG_SIZE
%if EX_FPU_REG_SIZE == 128
    %define FPU_NTH_REG(n) XMM %+ n
    %define FPU_MOV MOVUPS
%elif EX_FPU_REG_SIZE == 256
    %define FPU_NTH_REG(n) YMM %+ n
    %define FPU_MOV VMOVUPS
%elif EX_FPU_REG_SIZE == 512
    %define FPU_NTH_REG(n) ZMM %+ n
    %define FPU_MOV VMOVUPS
%else
    %define FPU_NTH_REG(n) XMM %+ n
    %define FPU_MOV MOVUPS
%endif

%ifdef DOC_METHOD
    params: _InOut_ HV_TRAP_FRAME* hvTrapFrame
    description: Saves register values which haven't already been saved by the CPU in the hvTrapFrame structure
%endif

%macro POPULATE_HV_TRAP_FRAME 1

    mov     [%1 + HV_TRAP_FRAME.Rax],   rax

    ; Save the ExceptionCode
    mov     rax,    [%1 + HV_TRAP_FRAME._Index]
    mov     [%1 + HV_TRAP_FRAME.ExceptionCode], rax

    mov     [%1 + HV_TRAP_FRAME.Rbx],   rbx
    mov     [%1 + HV_TRAP_FRAME.Rcx],   rcx
    mov     [%1 + HV_TRAP_FRAME.Rdx],   rdx
    mov     [%1 + HV_TRAP_FRAME.Rsi],   rsi
    mov     [%1 + HV_TRAP_FRAME.Rdi],   rdi
    mov     [%1 + HV_TRAP_FRAME.R8],    r8
    mov     [%1 + HV_TRAP_FRAME.R9],    r9
    mov     [%1 + HV_TRAP_FRAME.R10],   r10
    mov     [%1 + HV_TRAP_FRAME.R11],   r11
    mov     [%1 + HV_TRAP_FRAME.R12],   r12
    mov     [%1 + HV_TRAP_FRAME.R13],   r13
    mov     [%1 + HV_TRAP_FRAME.R14],   r14
    mov     [%1 + HV_TRAP_FRAME.R15],   r15

    ; Save the segment registers
    mov     ax,     ds
    mov     [%1 + HV_TRAP_FRAME.SegDs], ax

    mov     ax,     es
    mov     [%1 + HV_TRAP_FRAME.SegEs], ax

    mov     ax, fs
    mov     [%1 + HV_TRAP_FRAME.SegFs], ax

    mov     ax,     gs                                  ;; it is ok to save the selector into the trap frame
    mov     [%1 + HV_TRAP_FRAME.SegGs], ax

    mov     rax,    cr2
    mov     [%1 + HV_TRAP_FRAME.Cr2],   rax

    ; As rbp overlaps index in the HV_TRAP_FRAME structure, we must first ensure that the index was saved as ExcepionCode and only then ebp can be saved
    mov     [%1 + HV_TRAP_FRAME.Rbp], rbp
%endmacro

%ifdef DOC_METHOD
    params: _In_ HV_TRAP_FRAME* hvTrapFrame
    description: Restore register values to the state saved in the HV_TRAP_FRAME structure
%endif
%macro RESTORE_STATE_FROM_HV_TRAP_FRAME 1

    ;; restore the segment registers
    mov     ax,     [%1 + HV_TRAP_FRAME.SegDs]
    mov     ds,     ax

    mov     ax,     [%1 + HV_TRAP_FRAME.SegEs]
    mov     es,     ax

    ;; NOTE: it is NOT ok to reload gs with the selector
    ;; reloading the gs with a selector will cause the processor to read
    ;; the segment descriptor entry in the GDT for that selector
    ;; and put in the hidden portion of the segment descriptor register only
    ;; the LSB 32 bits and zero-ing out the MSB 32 bits.

    ;; restore general purpose registers

    mov     rbp,    [%1 + HV_TRAP_FRAME.Rbp]

    mov     rax,    [%1 + HV_TRAP_FRAME.Rax]     ;; restore the rax register in the trap frame
    mov     rbx,    [%1 + HV_TRAP_FRAME.Rbx]
    mov     rcx,    [%1 + HV_TRAP_FRAME.Rcx]
    mov     rdx,    [%1 + HV_TRAP_FRAME.Rdx]
    mov     rsi,    [%1 + HV_TRAP_FRAME.Rsi]
    mov     rdi,    [%1 + HV_TRAP_FRAME.Rdi]
    mov     r8,     [%1 + HV_TRAP_FRAME.R8]
    mov     r9,     [%1 + HV_TRAP_FRAME.R9]
    mov     r10,    [%1 + HV_TRAP_FRAME.R10]
    mov     r11,    [%1 + HV_TRAP_FRAME.R11]
    mov     r12,    [%1 + HV_TRAP_FRAME.R12]
    mov     r13,    [%1 + HV_TRAP_FRAME.R13]
    mov     r14,    [%1 + HV_TRAP_FRAME.R14]
    mov     r15,    [%1 + HV_TRAP_FRAME.R15]
%endmacro

%ifdef DOC_METHOD
    Disables FPU emulation in CR0 (and saves the old state on the stack) in order to avoid #UD when using MMX/SSE/SSE2/SSE3/SSE4 instructions
%endif
%macro ENTER_STACK_ENABLE_FPU 0
    push    rax
    mov     rax,    cr0
    push    rax
    ; Clear EM bit to disable FPU emulation
    and     al,     ~CR0.EM
    mov     cr0,    rax
%endmacro

%ifdef DOC_METHOD
    params: _InOut_ VOLATILE_FPU_REGS *fpuRegs
    description: Stores Documented FPU registers into fpuRegs
    return: VOID
%endif
%macro SAVE_FP_REGS 1
    ; param: destination VOLATILE_FPU_REGS address
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG0], FPU_NTH_REG(0)
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG1], FPU_NTH_REG(1)
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG2], FPU_NTH_REG(2)
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG3], FPU_NTH_REG(3)
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG4], FPU_NTH_REG(4)
    FPU_MOV [%1 + VOLATILE_FPU_REGS.REG5], FPU_NTH_REG(5)
%endmacro

%ifdef DOC_METHOD
    description: decides the method used to store FP registers based on EX_PRESERVE_FPU_STATE value
%endif
%macro STORE_FP_STATE 0
    %if EX_PRESERVE_FPU_STATE == 1

        ; provide full isolation between base code and the interrupt handler
        %ifdef EXCEPT_HAS_PCPU
            mov         ecx,    DWORD [GS:PCPU.FpuSaveSize]
            sub         rsp,    rcx
        %else
            sub         rsp, (EX_FPU_RESERVED_SIZE + 64) ;; +64 for alignment
        %endif ; EXCEPT_HAS_PCPU
        mov         rcx,    rsp
        call        HvCaptureFpuState

    %elif EX_PRESERVE_FPU_STATE == 2
        ; only backup & restore a subset of (documented) floting-point registers
        ENTER_STACK_ENABLE_FPU
        sub             rsp,    sizeof(VOLATILE_FPU_REGS)
        mov             rcx,    rsp
        SAVE_FP_REGS    rcx
    %endif
%endmacro

%ifdef DOC_METHOD
    description: restores from stack the state of CR0 before clearing fpu emulation. Also restores RAX
%endif
%macro EXIT_STACK_ENABLE_FPU 0
    pop     rax
    mov     cr0,    rax
    pop     rax
%endmacro

%ifdef DOC_METHOD
    params: _In_ VOLATILE_FPU_REGS *fpuRegs
    description: Restores Documented FPU registers from fpuRegs
%endif
%macro RESTORE_FP_REGS 1
    ; param: source VOLATILE_FPU_REGS address
    FPU_MOV FPU_NTH_REG(0), [%1 + VOLATILE_FPU_REGS.REG0]
    FPU_MOV FPU_NTH_REG(1), [%1 + VOLATILE_FPU_REGS.REG1]
    FPU_MOV FPU_NTH_REG(2), [%1 + VOLATILE_FPU_REGS.REG2]
    FPU_MOV FPU_NTH_REG(3), [%1 + VOLATILE_FPU_REGS.REG3]
    FPU_MOV FPU_NTH_REG(4), [%1 + VOLATILE_FPU_REGS.REG4]
    FPU_MOV FPU_NTH_REG(5), [%1 + VOLATILE_FPU_REGS.REG5]
%endmacro

%ifdef DOC_METHOD
    description: decides the method used to restore FP registers based on EX_PRESERVE_FPU_STATE value. Inverse of STORE_FP_STATE macro
%endif
%macro RESTORE_FP_STATE 0
    %if EX_PRESERVE_FPU_STATE == 1
        mov         rcx,    rsp
        call        HvRestoreFpuState
        %ifdef EXCEPT_HAS_PCPU
            mov         ecx,    DWORD [GS:PCPU.FpuSaveSize]
            add         rsp,    rcx
        %else
            add         rsp,    (EX_FPU_RESERVED_SIZE + 64) ;; +64 for alignment
        %endif ; EXCEPT_HAS_PCPU
    %elif EX_PRESERVE_FPU_STATE == 2
        mov         rcx,    rsp
        RESTORE_FP_REGS rcx
        add         rsp,    sizeof(VOLATILE_FPU_REGS)
        EXIT_STACK_ENABLE_FPU
    %endif
%endmacro

%ifdef DOC_METHOD
    description: Common code fore exception handling. Saves general purpose registers, segment registers and FPU registers on stack
    and calls HvDispatchException in C with ExceptionCode as param 1 and a pointer to the saved registers as param 2
%endif
HvExceptionHandlerCommon:
    ; @ToS: | retaddr | index | HV_CPU_TRAP_FRAME | ...
    ;                    + 8          + 16

    ; HV_CPU_TRAP_FRAME_size, the index and the return address are already present on the stack, allocate additional bytes up to HV_TRAP_FRAME_size

    ; Allocate on stack the HV_TRAP_FRAME structure.
    ;                                  RSP
    ; The current stack structure is:   | retaddr | index | HV_CPU_TRAP_FRAME | ...
    ;                                   ^

    sub     rsp,    (HV_TRAP_FRAME_size - (HV_CPU_TRAP_FRAME_size + 8 * 2))

    ;                                  RSP
    ; The current stack structure is:   |  HV_TRAP_FRAME  | HV_CPU_TRAP_FRAME | ...
    ;                                   ^

    ; Capture the current state and fill-in HV_TRAP_FRAME structure
    ; Save general purpose registers
    POPULATE_HV_TRAP_FRAME rsp

    ; Mark the stack frame
    mov     rbp,    rsp

    STORE_FP_STATE

    ; Call the C handler
    xor     r8,     r8
    movzx   rcx,    byte [rbp + HV_TRAP_FRAME.ExceptionCode]   ; ExceptionCode as param 1
    mov     rdx,    rbp                                        ; HV_CPU_TRAP_FRAME* as param 2
    X64CALL HvDispatchException

    RESTORE_FP_STATE

    ; Restore the asm state
    RESTORE_STATE_FROM_HV_TRAP_FRAME rsp

    ;; discard (part of) the trap frame and return
    add     rsp,    (HV_TRAP_FRAME_size - (5 * 8))     ;; skip the trap frame except the last 5 qwords that were pushed by the processor (rip, cs, rflags, rsp, ss)

    ;                                  RSP
    ; The current stack structure is:   | HV_CPU_TRAP_FRAME | ...
    ;                                   ^

    iretq

%ifdef DOC_METHOD
    params: _InOut_ CX_VOID *Buffer
    description: Decides which FPU registers to be saved according to hardware capabilities. Buffer is a 16 bit aligned 512 byte wide buffer where the FX state will be saved
%endif
%if EX_PRESERVE_FPU_STATE == 1
HvCaptureFpuState:

; Check if XSAVE is enabled on the system
%ifdef EXCEPT_HAS_PCPU
        cmp     [GS:PCPU.UseXsave],     BYTE 0
        je      .xsave_not_supported
%else
; If PCPU structure is not available, test manualy if XSAVE is supported on the system
        ; Save registers in order to querry the XSAVE bit in CPUID[1]:RCX
        push    rax
        push    rbx
        push    rcx
        push    rdx
        mov     eax,    0x1
        cpuid
        ; Check if XSAVE is supported on the system
        bt      ecx,    CPUID_LEAF_1_XSAVE_ENABLED
        ; Restore registers
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax
        jnc     .xsave_not_supported
%endif
; EXCEPT_HAS_PCPU
        call    HvCaptureGuestXState
        jmp     .extended_context_saved

    .xsave_not_supported:
        call    HvCaptureGuestFxState

    .extended_context_saved:
        ret

%ifdef DOC_METHOD
    params: _InOut_ CX_VOID *Buffer
    description: saves FX state (FPU/MMX & SSE registers) in Buffer, a 16 byte aligned 512 bye wide linear memory area.
    return: VOID
%endif
    HvCaptureGuestXState:
        ENTER_STACK_ENABLE_FPU

        ; Save registers
        push    rax
        push    rdx
        push    rdi

        ; Align the memory buffer to 64 for xsave
        add     rcx,    63
        mov     rax,    (0xFFFFFFFFFFFFFFFF - 63)
        and     rcx,    rax

        ; Clear TS bit in CR0 to avoid #NM being thrown when using SSE instructions
        mov     rax,    cr0
        push    rax                         ; push CR0
        and     al,     ~CR0.TS             ; #NM If CR0.TS[bit 3] = 1.
        mov     cr0,    rax

        ; Unmask SSE exceptions
        mov     rax,    cr4
        push    rax                         ; push CR4
        or      rax,    CR4.OSXSAVE         ; #UD If CR4.OSXSAVE[bit 18] = 0.
        mov     cr4,    rax

        %if EX_SAVE_XCR0 == 1
            ; save xcr0
            mov     rdi,    rcx
            xor     ecx,    ecx
            xgetbv
            push    rdx
            push    rax
            mov     rcx,    rdi
        %endif

        ; zero out the fpu register memory
        push    rcx

        %if EX_ZERO_FPU_SAVE_AREA == 1
            ; zero out the fpu register memory
            lea     rdi,    [rcx + XSAVE_HEADER_OFFSET]
            xor     rax,    rax
            mov     ecx,    XSAVE_HEADER_SIZE / 8
            cld
            rep     stosq
        %endif

        %if EX_SAVE_XCR0 == 1
            ; set xcr0
            xor     ecx,    ecx     ; specify xcr0
            %ifdef EXCEPT_HAS_PCPU
                ; IMPORTANT: GS:[...] points to PCPU structure
                mov     edx,    [GS:PCPU.Xcr0AvailMaskHigh]
                mov     eax,    [GS:PCPU.Xcr0AvailMaskLow]          ; xsetbv bits
            %else
                xor     edx,    edx
                mov     eax,    XCR0.X87 | XCR0.SSE | XCR0.AVX      ; x87 FPU/MMX State must be 1
                                                                    ; SEE = XSAVE feature set enable for MXCSR and XMM registers
                                                                    ; AVX = AVX enable, and XSAVE feature set can be used to manage YMM regs
            %endif

            ; Store the EDX:EAX value in XCR0
            xsetbv
        %endif

        ; Restore rcx
        pop     rcx

        ; Set to 0xFFF... both rax and rdx (capture ALL features)
        xor     rax,    rax
        dec     rax
        mov     rdx,    rax

%ifdef EXCEPT_HAS_PCPU
        cmp     [GS:PCPU.UseXsaveopt],  BYTE 0
        je      .do_xsave
%else
        push    rax
        push    rbx
        push    rcx
        push    rdx
        mov     eax,    0xd
        mov     ecx,    0x1     ; Processor Extended State Enumeration Sub-leaf (EAX = 0DH, ECX = 1)
        cpuid
        bt      rax,    0x1     ; Bit 01: Supports XSAVEC and the compacted form of XRSTOR if set.
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax
        jnc     .do_xsave
%endif ; EXCEPT_HAS_PCPU
        xsaveopt   [rcx]
        jmp     .done_save
    .do_xsave:
        xsave   [rcx]
    .done_save:

        %if EX_SAVE_XCR0 == 1
            ; Restore xcr0 from stack
            pop     rax
            pop     rdx
            ; save rcx
            mov     rdi,    rcx
            xor     rcx,    rcx
            xsetbv
            mov     rcx,    rdi
        %endif

        ; restore cr0 and cr4
        pop     rax
        mov     cr4,    rax
        pop     rax
        mov     cr0,    rax

        pop     rdi
        pop     rdx
        pop     rax

        ; Restore CR0 state
        EXIT_STACK_ENABLE_FPU
        ret

%ifdef DOC_METHOD
    params: _InOut_ CX_VOID *Buffer
    description: saves FX state (FPU/MMX & SSE registers) in Buffer, a 16 byte aligned 512 bye wide linear memory area.
    return: VOID
%endif
HvCaptureGuestFxState:
        ENTER_STACK_ENABLE_FPU
        ; round-up rcx to align to 16
        add     rcx,    0xF
        and     cl,     0xF0
        clts
        fxsave  [rcx]
        ; Restore CR0 state
        EXIT_STACK_ENABLE_FPU
        ret

%ifdef DOC_METHOD
    params: _In_ CX_VOID *Buffer
    description: Decides which FPU registers to be restored according to hardware capabilities. Buffer is a 16 bit aligned 512 byte wide buffer where the FX state have been saved
    return: VOID
%endif
    HvRestoreFpuState:
; Check if XSAVE is enabled on the system
%ifdef EXCEPT_HAS_PCPU
        cmp     [GS:PCPU.UseXsave],     BYTE 0
        je      .xrestore_not_supported
%else
; If PCPU structure is not available, test manualy if XSAVE is supported on the system
        ; Save registers in order to querry the XSAVE bit in CPUID[1]:RCX
        push    rax
        push    rbx
        push    rcx
        push    rdx
        ; Check if XSAVE is supported on the system
        mov     eax,    1
        cpuid
        bt      ecx,    CPUID_LEAF_1_XSAVE_ENABLED
        ; Restore registers
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax
        jnc     .xrestore_not_supported
%endif ; EXCEPT_HAS_PCPU
        call    HvRestoreGuestXState
        jmp     .extended_context_restored

    .xrestore_not_supported:
        call    HvRestoreGuestFxState

    .extended_context_restored:
        ret

%ifdef DOC_METHOD
    params: _InOut_ CX_VOID *Buffer
    description: restores FX state (FPU/MMX & SSE registers) from Buffer, a 16 byte aligned 512 bye wide linear memory area where FX state have previously been saved.
    return: VOID
%endif
    HvRestoreGuestXState:
        ENTER_STACK_ENABLE_FPU

        ; set to 0xFFF... both rax and rdx (restore ALL features)
        push    rax
        push    rdx
        push    rdi

        ; Align buffer address to 64 for xrstor
        add     rcx,    63
        mov     rax,    (0xFFFFFFFFFFFFFFFF - 63)
        and     rcx,    rax

        mov     rax,    cr0
        push    rax                         ; push CR0
        and     al,     ~CR0.TS             ; #NM If CR0.TS[bit 3] = 1.
        mov     cr0,    rax

        mov     rax,    cr4
        push    rax                         ; push CR4
        or      rax,    CR4.OSXSAVE         ; #UD If CR4.OSXSAVE[bit 18] = 0.
        mov     cr4,    rax


        %if EX_SAVE_XCR0 == 1
            ; save xcr0
            mov     rdi,    rcx
            xor     rcx,    rcx
            xgetbv
            push    rdx
            push    rax
            mov     rcx,    rdi
        %endif

        %if EX_SAVE_XCR0 == 1
            ; set xcr0
            push    rcx
            xor     ecx,    ecx     ; specify xcr0

            %ifdef EXCEPT_HAS_PCPU

                ; IMPORTANT: GS:[...] points to PCPU structure
                mov     edx,    [GS:PCPU.Xcr0AvailMaskHigh]
                mov     eax,    [GS:PCPU.Xcr0AvailMaskLow]          ; xsetbv bits
            %else
                xor     edx,    edx
                mov     eax,    XCR0.X87 | XCR0.SSE | XCR0.AVX      ; x87 FPU/MMX State must be 1
                                                                    ; SEE = XSAVE feature set enable for MXCSR and XMM registers
                                                                    ; AVX = AVX enable, and XSAVE feature set can be used to manage YMM regs
            %endif ; EXCEPT_HAS_PCPU

            xsetbv
            pop     rcx
        %endif

        xor     rax,    rax
        dec     rax
        mov     rdx,    rax
        clts
        xrstor  [rcx]

        %if EX_SAVE_XCR0 == 1
            ; restore xcr0
            pop     rax
            pop     rdx
            ; save rcx
            mov     rdi,    rcx
            xor     rcx,    rcx
            xsetbv
            ; restore rcx
            mov     rcx,    rdi
        %endif

        pop     rax
        mov     cr4,    rax
        pop     rax
        mov     cr0,    rax
        pop     rdi
        pop     rdx
        pop     rax
        EXIT_STACK_ENABLE_FPU
        ret

%ifdef DOC_METHOD
    params: _InOut_ CX_VOID *Buffer
    description: Restores FX registers from Buffer. Rcx contains a pointer to a 512 bytes Buffer containing the FX state.
    return: VOID
%endif
HvRestoreGuestFxState:
        ENTER_STACK_ENABLE_FPU
        ; round-up rcx to align to 16
        add     rcx,    0xF
        and     cl,     0xF0
        clts
        fxrstor [rcx]
        EXIT_STACK_ENABLE_FPU
        ret

%endif ; EX_PRESERVE_FPU_STATE == 1

    times 16 db         0xCC        ; magic, do not remove, specifies the end of HvHndExtIntGeneric function
                                    ; amiculas: hack -> put functions between HvHndExtIntGeneric and the 0xCC magic in order to be copied together with the aforementioned function
