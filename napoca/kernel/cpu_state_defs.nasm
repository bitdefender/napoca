;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

section .text

struc CPUSTATE_UNPACKED_DESCRIPTOR_DATA
    .Limit                  resd 1
    .Base                   resq 1
    .AccessAndFlags         resd 1
    .Type                   resb 1
    .System                 resb 1
    .PrivilegeLevel         resb 1
    .Present                resb 1
    .Available              resb 1
    .Code64                 resb 1
    .BigOperands            resb 1
    .Granularity            resb 1
endstruc

CPUSTATE_BAD_SELECTOR_ACCESS_RIGHTS equ (0xc093 | 0x10000)

struc CPUSTATE_FULL_SELECTOR_DATA
    .Length                 resw 1
    .Base                   resq 1
endstruc

struc CPUSTATE_GUEST_STATE_INFO         ; 361 kbytes in size
    .IsStructureInitialized     resb 1
    .Rax                        resq 1
    .Rbx                        resq 1
    .Rcx                        resq 1
    .Rdx                        resq 1
    .Rbp                        resq 1
    .Rsi                        resq 1
    .Rdi                        resq 1
    .R8                         resq 1
    .R9                         resq 1
    .R10                        resq 1
    .R11                        resq 1
    .R12                        resq 1
    .R13                        resq 1
    .R14                        resq 1
    .R15                        resq 1
    .UsingFakedTr               resb 1
    .Es                         resw 1
    .Cs                         resw 1
    .Ss                         resw 1
    .Ds                         resw 1
    .Fs                         resw 1
    .Gs                         resw 1
    .Ldtr                       resw 1
    .Tr                         resw 1
    .LinkPointer                resq 1
    .Ia32Debugctl               resq 1
    .Ia32Pat                    resq 1
    .Ia32Efer                   resq 1
    .Ia32PerfGlobalCtrl         resq 1
    .Pdpte0                     resq 1
    .Pdpte1                     resq 1
    .Pdpte2                     resq 1
    .Pdpte3                     resq 1
    .EsLimit                    resd 1
    .CsLimit                    resd 1
    .SsLimit                    resd 1
    .DsLimit                    resd 1
    .FsLimit                    resd 1
    .GsLimit                    resd 1
    .LdtrLimit                  resd 1
    .TrLimit                    resd 1
    .GdtrLimit                  resd 1
    .IdtrLimit                  resd 1
    .EsAccessRights             resd 1
    .CsAccessRights             resd 1
    .SsAccessRights             resd 1
    .DsAccessRights             resd 1
    .FsAccessRights             resd 1
    .GsAccessRights             resd 1
    .LdtrAccessRights           resd 1
    .TrAccessRights             resd 1
    .InterruptibilityState      resd 1
    .ActivityState              resd 1
    .SmBase                     resd 1
    .Ia32SysenterCs             resd 1
    .VmxPreemptionTimerValue    resd 1
    .Cr0                        resq 1
    .Cr2                        resq 1
    .Cr3                        resq 1
    .Cr4                        resq 1
    .Cr8                        resq 1
    .EsBase                     resq 1
    .CsBase                     resq 1
    .SsBase                     resq 1
    .DsBase                     resq 1
    .FsBase                     resq 1
    .GsBase                     resq 1
    .LdtrBase                   resq 1
    .TrBase                     resq 1
    .GdtrBase                   resq 1
    .IdtrBase                   resq 1
    .Dr7                        resq 1
    .Rsp                        resq 1
    .Rip                        resq 1
    .Rflags                     resq 1
    .PendingDebugExceptions     resq 1
    .Ia32SysenterEsp            resq 1
    .Ia32SysenterEip            resq 1
    .Ia32KernelGsBase           resq 1
    .Star                       resq 1
    .LStar                      resq 1
    .CStar                      resq 1

    ;;;.Extensions                 resb (512+15) ; +15 so we can always get a 16-byte aligned 512 buffer
    .Extensions                 resb (4096 + 63)

    .LapicId                    resd 1
endstruc
