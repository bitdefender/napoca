/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEVRES_
#define _DEVRES_

#include "core.h"

/// @brief Creates a memory map with the memory ranges used by the devices, reported by the _CRS method
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the map was created
/// @returns    OTHER                               - Internal error, on our side or from the ACPICA library's side
CX_STATUS
DevresLoadMemoryResourcesAcpi(
    CX_VOID
);

#endif //_DEVRES_
