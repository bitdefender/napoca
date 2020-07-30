/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "dacia_types.h"
#include "ver.h"
#include "version.h"
#include "boot/boot.h"

CX_VOID
PrintVersionInfo(
    CX_VOID
    )
{
    HvPrint("\n\n\n\tNAPOCA from " GLOBAL_VERSION_BUILDMACHINE
        " Build date: " NAPOCA_BUILD_DATE
        " Build time: " NAPOCA_BUILD_TIME
        " Build type: " NAPOCA_VERSION_BUILDTYPE
        " Major: %d"
        " Minor: %d"
        " Revision: %d"
        " Build  %d"
        " Change-set: %s"
        " Branch: %s"
        " Boot Mode: %d\n\n\n",

        NAPOCA_VERSION_MAJOR,
        NAPOCA_VERSION_MINOR,
        NAPOCA_VERSION_REVISION,
        NAPOCA_VERSION_BUILDNUMBER,
        GLOBAL_VERSION_CHANGESET,
        GLOBAL_VERSION_BRANCH,
        HvGetBootMode());

    return;
}
