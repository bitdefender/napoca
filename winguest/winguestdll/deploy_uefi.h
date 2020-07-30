/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEPLOY_UEFI_H_
#define _DEPLOY_UEFI_H_

extern "C" {
#include "common/boot/loader_interface.h"
}

#define NAPOCAHV_UEFI_GUID       L"{0e15d1e5-113a-45a3-a42b-2a998fcfb964}"

NTSTATUS
GetLoadMonitorDataUefi(
    _Out_opt_ PDWORD AllowedRetries,
    _Out_opt_ PDWORD FailCount,
    _Out_opt_ PBOOLEAN Boot,
    _Out_opt_ PBOOLEAN Crash
    );

NTSTATUS
SetLoadMonitorDataUefi(
    _In_opt_ PDWORD AllowedRetries,
    _In_opt_ PDWORD FailCount,
    _In_opt_ PBOOLEAN Boot,
    _In_opt_ PBOOLEAN Crash
    );

NTSTATUS
DeployUefiBootFiles(
    LD_INSTALL_FILE_FLAGS Flags
    );

NTSTATUS
ConfigureUefiBoot(
    _In_ BOOLEAN Install
    );

BOOLEAN
ConfigUefiSupported(
    void
    );

HRESULT
UefiCheckConfigurationIntegrity(
    void
);

#endif //_DEPLOY_UEFI_H_
