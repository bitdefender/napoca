/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEPLOY_VALIDATION_H_
#define _DEPLOY_VALIDATION_H_

extern "C" {
#include "common/boot/loader_interface.h"
}
#include "dacia_types.h"
#include "libapis_int.h"

NTSTATUS
DetectFirmwareInfo(
    void
);

BOOLEAN
IsUefiBootedOs(
    void
);

BOOLEAN
IsSecureBootEnabled(
    void
);

NTSTATUS
CheckInVm(
    _In_ BOOLEAN* InVm
);

bool
GetConnectedStandbySupport(
    void
);

void
GetPowerPlatformRole(
    POWER_PLATFORM_ROLE* PlatformRole
);

NTSTATUS
ValidateHvConfiguration(
    _Out_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    );

bool
StatusToFeaturesBitmask(
    _In_ NTSTATUS Status,
    _Inout_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    );

NTSTATUS
CheckCurrentHvConfigurationTimerCallback(
    void
    );

#endif //_DEPLOY_VALIDATION_H_
