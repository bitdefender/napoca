/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once
#ifndef _NAPOCA_H_
#define _NAPOCA_H_

// unsafe sal, basic CX_UINT8/CX_UINT16 etc types, memzero/memcpy etc operations,
#include "core.h"
#include "napocadefs.h"

#include "kernel/hvintrin.h"
#include "kernel/cpuops.h"                  // complementary definitions for what's missing from hvintrin.h

// napoca logging
#include "io/io.h"

#include "kernel/pcpu_common.h"
#include "kernel/queue_ipc_common.h"
#endif