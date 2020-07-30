;
; Copyright (c) 2020 Bitdefender
; SPDX-License-Identifier: Apache-2.0
;

STRUC PCPU
    .Self                   resq 1
    .Id                     resd 1
    .BootInfoIndex          resd 1
    .VmxActivated           resb 1
    .IsIntel                resb 1
    .Vcpu                   resq 1
    .VmxOnPa                resq 1
    .TempRCX                resq 1
    .TopOfStack             resq 1
    .UseXsave               resb 1
    .UseXsaveopt            resb 1
    .FpuSaveSize            resd 1
    .Xcr0AvailMaskLow       resd 1
    .Xcr0AvailMaskHigh      resd 1
ENDSTRUC
