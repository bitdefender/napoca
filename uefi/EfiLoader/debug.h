/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "uefi_internal.h"


void
UefiDbgDumpMemoryMap(
    void
    );

BOOLEAN
InternalListHandlesAndProtocols(
    void
    );

#define _CR0_PG     ((DWORD)1<<31) //0x8000 0000 ULL
#define _CR0_WP     ((DWORD)1<<16)
#define _CR0_PE     (1)
#define _CR4_PSE        ((DWORD)1<<4)
#define _CR4_PAE        ((DWORD)1<<5)
#define _CR4_PGE        ((DWORD)1<<7)
#define _CR4_VMXE   ((DWORD)1<<13)
#define _CR4_SMXE   ((DWORD)1<<14)
#define _CR4_PCIDE  ((DWORD)1<<17)
#define _EFER_LME   ((DWORD)1<<8)
#define _EFER_LMA   ((DWORD)1<<10)
#define _EFER_NXE   ((DWORD)1<<11)

#endif