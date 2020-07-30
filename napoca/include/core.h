/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CORE_H_
#define _CORE_H_

//
// Basic (UNSAFE) declarations like generic types and macros that are not dacia or napoca specific
// USAGE: these base declarations should be available to any other headers AND this file must not include napoca-specific headers
//

#include "cx_native.h"
#include "base/cx_synchronization.h"
#include "base/cx_intrin.h"

#pragma warning(disable:4200) // nonstandard extension used : zero-sized array in struct/union
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204) // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int

#include "wrappers/cx_winsal.h"
#include "wrappers/cx_wintypes.h"
#include "wrappers/cx_defs_short.h"
#include "wrappers/cx_types_short.h"
#include "wrappers/cx_winlists.h"
#include "wrappers/crt_short/assert.h"
#include "wrappers/crt_short/memory.h"
#include "wrappers/crt_short/crtdefs.h"
#include "wrappers/crt_short/varargs.h"
#include "wrappers/crt_short/string.h"

// the built-in config constants and the dynamic command-line variables have global scope and are safe to be visible everywhere
#include "autogen/napoca_buildconfig.h"
#include "autogen/napoca_cmdline.h"

#include "hvstatus.h"
#include "coredefs.h"

#pragma intrinsic (_enable, _disable)

#endif // _CORE_H_
