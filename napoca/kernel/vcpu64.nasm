;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

;;
;; MUST be keept in sync with states from VCPU.H
;;
STRUC ARCHREGS
    .RAX        resq 1
    .RCX        resq 1
    .RDX        resq 1
    .RBX        resq 1
    .RSP        resq 1
    .RBP        resq 1
    .RSI        resq 1
    .RDI        resq 1
    .R8         resq 1
    .R9         resq 1
    .R10        resq 1
    .R11        resq 1
    .R12        resq 1
    .R13        resq 1
    .R14        resq 1
    .R15        resq 1
    .DR7        resq 1
    .RFLAGS     resq 1
    .RIP        resq 1
    .CR0        resq 1
    .CR2        resq 1
    .CR3        resq 1
    .CR4        resq 1
    .CR8        resq 1                  ;; *NOT AUTOMATICALLY SAVED*
    .XCR0       resq 1                  ;; *NOT AUTOMATICALLY SAVED* 2012/08/18
    .IDTRBASE   resq 1
    .IDTRLIMIT  resw 1
    ._RESW1     resw 1
    ._RESD1     resd 1
    .GDTRBASE   resq 1
    .GDTRLIMIT  resw 1
    ._RESW2     resw 1
    ._RESD2     resd 1
    .DR6        resq 1
    ._RESERVED  resq 2
ENDSTRUC

VCPU_STATE_INVALID      EQU 0
VCPU_STATE_NOT_ACTIVE   EQU 1
VCPU_STATE_ACTIVE       EQU 2
VCPU_STATE_ERROR        EQU 3
VCPU_STATE_TOTAL_VALUES EQU 4

MAX_AUTO_STORED_MSR_COUNT       EQU 32

STRUC MSR_ENTRY
    .Msr                    resd 1
    .Flags                  resd 1
    .Value                  resq 1
ENDSTRUC

STRUC VCPU
    .State                  resw 1
    .Schedulable            resb 1
    .Pcpu                   resq 1

    .Guest                  resq 1
    .GuestExitRoutine       resq 1
    .ExitCounter            resq 1
    .Vpid                   resw 1
    .GuestIndex             resb 1
    .GuestCpuIndex          resb 1

    .LapicId                resd 1
    .LastExitTsc            resq 1
    .LastEntryTsc           resq 1
    .PrevInHostTscDuration  resq 1
    .PrevInGuestTscDuration resq 1
    .LinearTsc              resq 1
    .VirtualTsc             resq 1

    .ArchRegs               resb ARCHREGS_size

    .ExtState               resq 1
    .RestoreExtState        resb 1

    .GuestHaltedCsRip       resq 1
    .TimesHalted            resq 1
    .IsInactive             resb 1
ENDSTRUC
