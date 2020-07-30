/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file global.c
*   @brief GLOBAL - global kernel data
*
*/

#include "core.h"
#include "kernel/kernel.h"

GLOBAL_DATA gHypervisorGlobalData;                      ///< The Hypervisor global data

VIRTUALIZATION_FEATURES gVirtFeatures = { 0 };          ///< The virtualization features found on the current platform

CX_VOID *gTempE820 = CX_NULL;                           ///< E820 map prepared by our loader