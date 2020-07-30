/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Provide only the elementary, compiler-independent, set of types
//
#ifndef _CX_ELEMENTARY_TYPES_H_
#define _CX_ELEMENTARY_TYPES_H_

#include "base/cx_env.h"

#ifdef CX_MSVC
#include "compiler_dependent/types/cx_msvc_types.h"
#define CX_HAVE_BASIC_TYPES
#else
#ifdef CX_CLANG
#include "compiler_dependent/types/cx_unixtypes.h"
#define CX_HAVE_BASIC_TYPES
#else
#ifdef CX_GNUC
#include "compiler_dependent/types/cx_unixtypes.h"
#define CX_HAVE_BASIC_TYPES
#endif
#endif
#endif

#ifndef CX_HAVE_BASIC_TYPES
#error "Basic compiler-dependent types are not available!"
#endif

#endif //_CX_ELEMENTARY_TYPES_H_
