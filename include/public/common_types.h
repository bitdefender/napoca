/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _COMMON_TYPES_H_
#define _COMMON_TYPES_H_

// used to query the version for a component (at runtime)
typedef enum _BIN_COMPONENT
{
    compWinguestSys = 1,
    compWinguestDll = 2,
    compNapoca = 3,
    compIntro = 4,
    compExceptions = 5
}BIN_COMPONENT, *PBIN_COMPONENT;

typedef enum _BOOT_MODE {
    bootUnknown = 0,
    bootMbr = 1,
    bootMbrPxe = 2,
    bootUefi = 3,
    bootUefiPxe = 4,
}BOOT_MODE, *PBOOT_MODE;

#endif // _COMMON_TYPES_H_
