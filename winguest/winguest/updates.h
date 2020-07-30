/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _SIGNATURES_H_
#define _SIGNATURES_H_

#include "common/kernel/napoca_version.h"

NTSTATUS
UpdateModule(
    _In_ PUNICODE_STRING FilePath,
    _In_ DWORD ModuleId,
    _In_opt_ PVOID ModuleCustomData,
    _In_opt_ DWORD ModuleCustomDataSize,
    _Out_ NAPOCA_VERSION *NewVersion
    );

#endif // _SIGNATURES_H_
