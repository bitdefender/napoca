/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _NEWLOAD_H_
#define _NEWLOAD_H_

#include "uefi_internal.h"

#define HV_LOG_LENGTH (200 * 1024)
extern UINT8 *gHvLogPhysicalAddress;
extern UINT32 gHvLogSize;

EFI_STATUS
UefiAllocHibernateBuffer(
    IN UINTN Size
    );

EFI_STATUS
UefiSetupModules(
    _In_ QWORD TempMemNumberOfBytes,
    _Inout_ QWORD *Cr3,             // set to 0 the actual *Cr3 QWORD before the call if there is no pml4 root already set up
    _In_ QWORD NapocaBase,
    _In_ QWORD NapocaLength,
    _In_ QWORD NumberOfGuests
    );

#endif