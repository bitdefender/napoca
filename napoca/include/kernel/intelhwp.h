/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file intelhwp.h
*   @brief Intel Hardware-Controlled Performance States support
*/

#ifndef  INTELHWP_H
#define INTELHWP_H

#include "base/cx_types.h"

///
/// @brief Activate HARDWARE-CONTROLLED PERFORMANCE STATES
///
/// When HWP is enabled, the processor autonomously selects performance states as deemed appropriate for the
/// applied workload and with consideration of constraining hints that are programmed by the software.
/// These software - provided hints include minimum and maximum performance limits, preference towards energy efficiency or performance.
/// Also, the hypervisor asks if it has access to Performance and Energy Bias Hint and if it does then
/// suggests maximum performance to the detriment of energy saving.
///
CX_VOID
HvActivatePerformanceMode(
    CX_VOID
);

#endif // ! INTELHWP_H
