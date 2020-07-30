/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_MEM_H_
#define _CX_MEM_H_

/// Note: this file assumes defined CX_USE_SSE2 or CX_USE_MMX for optimized versions of provided functions!

#include "base/cx_env.h"

#ifdef CX_MSVC
#include "compiler_dependent/base/cx_msvc_mem.h"
#else
#include "compiler_dependent/base/cx_linux_mem.h"
#endif


#endif // _CX_MEM_H_