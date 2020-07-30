/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _BOOT_H_
#define _BOOT_H_

#include "boot/multiboot.h"
#include "common/boot/loader_interface.h"
#include "common/boot/bootdefs.h"
#include "common/boot/cpu_features.h"

//
// BOOT related global vars
//

extern BOOT_INFO *gBootInfo;

/// @brief E820 map prepared by our loader, usable during initializations
extern CX_VOID *gTempE820;

/// @brief Used when some CPU has failed its initializations and is requesting full HV unload
extern volatile CX_BOOL gNeedToUnload;

extern LD_LOADER_CUSTOM *gLoaderCustom;

/// @brief Identifies various boot modes of the hypervisor (UEFI, Legacy, PXE...)
extern BOOT_MODE gBootMode;

extern LD_BOOT_CONTEXT *gBootContext;

extern LD_NAPOCA_MODULE gBootModules[LD_MAX_MODULES];

extern LD_MEM_BUFFER *gTempMem;

static
__forceinline
BOOT_MODE
HvGetBootMode(
    void
)
{
    return gBootMode;
}

static
__forceinline
void
HvSetBootMode(
    BOOT_MODE BootMode
)
{
    gBootMode = BootMode;
}

/// @brief We were booted in a Legacy Boot environment by Mbr loading
#define BOOT_MBR                        (HvGetBootMode() == bootMbr)

/// @brief We were booted in a Legacy Boot environment by boot through PXE
#define BOOT_MBR_PXE                    (HvGetBootMode() == bootMbrPxe)

/// @brief We were booted by a UEFI firmware
#define BOOT_UEFI                       (HvGetBootMode() == bootUefi)

/// @brief We were booted through PXE in a UEFI manner
#define BOOT_UEFI_PXE                   (HvGetBootMode() == bootUefiPxe)

/// @brief Loader already running in a multi-processor environment
#define BOOT_OPT_MULTIPROCESSOR             (BOOT_UEFI)

/// @brief The loader was started in a 64 bit environment
#define BOOT_OPT_64BIT_ENVIRONMENT          (BOOT_UEFI)

/// @brief Legacy BIOS environment
#define BOOT_OPT_BIOS_ENVIRONMENT           (!(BOOT_UEFI))

/// @brief If the VGA memory is accessible/usable
#define BOOT_OPT_VGA_MEM                    BOOT_OPT_BIOS_ENVIRONMENT

/// @brief The number of CPUs which were find in the system, used for waiting to all of them in different stages
#define CPU_COUNT_TO_WAIT                   (gBootInfo->CpuCount)


#endif // _BOOT_H_
