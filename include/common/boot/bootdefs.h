/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file bootdefs.h
*   @brief BOOT - generic definitions for boot phase
*/
#ifndef _BOOT_DEFS_H_
#define _BOOT_DEFS_H_

// include also CPU features stuff, but only after common definitions
#include "common/boot/cpu_features.h"
#include "common/boot/loader_interface.h"
#include "public/dacia_types.h"

/// @brief Max boot physical memory-map entry count
#define BOOT_MAX_PHY_MEM_COUNT              512

/// @brief Maximum number of supported CPUs
#define BOOT_MAX_CPU_COUNT                  64

/// @brief The maximum number of memory zones that the hypervisor can take.
///
/// HV shouldn't allocate too many entries if the memory sent by the loader isn't fragmented
///
#define BOOT_MAX_HV_ZONE_COUNT              1024

/// @brief BOOT flags
enum
{
    BIF_HV_ZONE_MAPS_ONLY_KZ = 0x00000002U ///< We have reserved HV zone in memory map
}BOOT_FLAGS;

/// @brief Boot information passed from the loader
typedef struct _BOOT_INFO {
    struct
    {
        CX_UINT16           PhyMemCount;    ///< Number of entries in E820 memory map
        CX_UINT32           CpuCount;       ///< Number of available CPUs found parsing the MADT table
        CX_UINT32           PredetCpuCount; ///< How many ACTIVE CPUs were there at load time
        CX_UINT32           Flags;          ///< Flags from #BOOT_FLAGS
    };

    MEM_MAP_ENTRY           PhyMemMap[BOOT_MAX_PHY_MEM_COUNT];  ///<  Physical memory map prepared by the loader
    CPU_ENTRY               CpuMap[BOOT_MAX_CPU_COUNT];         ///< Array of structures that describe the features of each processor

    LD_POINTER_MEMBER(HV_MEM_MAP, HvMemMap);    ///< Hypervisor memory

} BOOT_INFO;

#pragma pack(push)
#pragma pack(1)

/// @brief Information used to boot using GRUB
typedef struct
{
    CX_UINT8 GrubBoot;
    CX_UINT8 BootDrive;
    CX_UINT8 BootSector;
}GRUB_INFO;

#pragma pack(pop)

#endif // _BOOT_DEFS_H_
