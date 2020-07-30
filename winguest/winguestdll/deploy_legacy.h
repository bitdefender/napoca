/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEPLOY_LEGACY_H_
#define _DEPLOY_LEGACY_H_

extern "C" {
#include "common/boot/loader_interface.h"
}
#include "dacia_types.h"
#include "load_monitor.h"

#define LEGACY_INSTALL_FILES_FILE_ATTRIBUTES (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY)

NTSTATUS
DeployGrubBootFiles(
    _In_ LD_INSTALL_FILE_FLAGS Flags,
    _In_ BOOLEAN CreateDynamicFiles
    );

NTSTATUS
ConfigureLegacyBoot(
    _In_ BOOLEAN Install
    );

NTSTATUS
ConfigGrubSupported(
    _In_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    );

NTSTATUS
GetSystemLegacyConfiguration(
    _Out_opt_ PDWORD HardDiskIndex,
    _Out_opt_ PDWORD NrOfOurGrubMbrs,   // only GRUB MBRs patched with our signature
    _Out_opt_ PDWORD NrOfWindowsMbrs,
    _In_ BOOLEAN Install
    );

NTSTATUS
GetLoadMonitorDataMbr(
    _Out_opt_ PDWORD AllowedRetries,
    _Out_opt_ PDWORD FailCount,
    _Out_opt_ PBOOLEAN Boot,
    _Out_opt_ PBOOLEAN Crash
    );

NTSTATUS
SetLoadMonitorDataMbr(
    _In_opt_ PDWORD AllowedRetries,
    _In_opt_ PDWORD FailCount,
    _In_opt_ PBOOLEAN Boot,
    _In_opt_ PBOOLEAN Crash
    );

#endif //_DEPLOY_LEGACY_H_

