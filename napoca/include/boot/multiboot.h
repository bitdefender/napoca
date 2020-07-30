/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// MULTIBOOT - definitions for MULTIBOOT structures, 0.6.96 specs

#ifndef _MULTIBOOT_H_
#define _MULTIBOOT_H_

#include "core.h"

#define MULTIBOOT_HEADER_MAGIC 0x1BADB002

#pragma pack(push)
#pragma pack(1)


typedef struct _MULTIBOOT_HEADER
{
    DWORD           Magic;
    DWORD           Flags;
    DWORD           Checksum;
    DWORD           HeaderAddr;
    DWORD           LoadAddr;
    DWORD           LoadEndAddr;
    DWORD           BssEndAddr;
    DWORD           EntryAddr;
    DWORD           ModType;
    DWORD           Width;
    DWORD           Height;
    DWORD           Depth;

} MULTIBOOT_HEADER, *PMULTIBOOT_HEADER;

// MultiBoot Information structure
typedef struct _MULTIBOOT_INFO
{
    DWORD   Flags;
    union {
        QWORD       MemQuad;
        struct {
            DWORD   MemLower;
            DWORD   MemUpper;
        };
    };
    DWORD   BootDevice;
    DWORD   CmdLine;
    DWORD   ModsCount;
    DWORD   ModsAddr;
    BYTE    Reserved[16];

    DWORD   MmapLength;
    DWORD   MmapAddr;
    DWORD   DriversLength;
    DWORD   DriversAddr;

    DWORD   ConfigTable;

    DWORD   BootLoaderName;
    DWORD   ApmTable;

    union
    {
        DWORD   VbeControlInfo;
        DWORD   LoadingFromTxtMle;              // offset 72, this field has meaning for the hypervisor only
                                                // if 1, then TxtMle has loaded the hypervisor

        DWORD   SizeOfHvAdditionalProtect;      // offset 72, this field has meaning for the TXT MLE only
                                                // size in bytes of the region to protect against DMA starting
                                                // from (hv + hv_size)
    };

    union
    {
        DWORD   VbeModeInfo;
        DWORD   MleToHvPhysicalPage;        // offset 74, this field has meaning for the hypervisor only
                                            // if LoadingFromTxtMle is 1, then this contains the physical address
                                            // of the MleToHv page
    };

    DWORD   VbeMode;
    DWORD   VbeInterfaceSeg;
    DWORD   VbeInterfaceOff;
    DWORD   VbeInterfaceLen;


} MULTIBOOT_INFO, *PMULTIBOOT_INFO;


typedef struct _MULTIBOOT_MOD_STRUCT
{
    DWORD   ModStart;
    DWORD   ModEnd;
    DWORD   String;
    DWORD   Reserved;

} MULTIBOOT_MOD_STRUCT, *PMULTIBOOT_MOD_STRUCT;

#pragma pack(pop)

#endif