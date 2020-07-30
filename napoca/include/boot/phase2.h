/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file phase2.h Guest virtual machine configuration

#ifndef _PHASE2_H_
#define _PHASE2_H_

/// \addtogroup phase2
/// @{

#include "core.h"
#include "kernel/kerneldefs.h"

/// @brief Performs the PHASE II initialization for the BSP processor
///
/// The following major steps are executed:
///   - set up the communication buffer
///   - initialize guest structures (initialize GUEST structure, memory maps, vmcs, critical hooks, ept, rip cache)
///   - initialize the emulator
///   - activate guest
///   - trigger APs execute their phase 2 and wait
///   - execute the #Phase2ApStageTwo on BSP too
NTSTATUS
Phase2BspStageTwo(
    void
    );

/// @brief Performs the PHASE II initialization for the AP processor(s)
///
/// The following major steps are executed:
///   - fully configure the VMCS (control, host state, guest state)
///   - initializes the DS & BTS for (for potential debugging purposes)
NTSTATUS
Phase2ApStageTwo(
    void
    );

/// @}

#endif // _PHASE2_H_
