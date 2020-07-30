/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_INTRIN_H_
#define _CX_INTRIN_H_

#include "base/cx_env.h"

#ifdef CX_MSVC
#include "compiler_dependent/intrin/cx_msvc_intrin.h"
#else
#include "compiler_dependent/intrin/cx_linux_intrin.h"
#endif


#endif // _CX_INTRIN_H_