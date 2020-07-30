/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef CRT_INC_SETTINGS_WRAPPER_FLTUSED_C
#include CRT_INC_SETTINGS_WRAPPER_FLTUSED_C // define it to some .h file name/path if you want to provide settings
#endif


//
// Add this file to your project if you're getting a link-time error due to _fltused not being defined.
//
// Details:  snpritf is using floating point support, and C compiler produces the _fltused
// symbol by default. Simply define this symbol to satisfy the linker.
//
// IMPORTANT: Don't compile this file as part of your project UNLESS you actually get a linker error without it
// and your project isn't a library. A library shouldn't compile this file as it might clash with other libraries
// that already define it, better let the final project solve the symbol as adding it is always possible while removing
// it from a .lib file isn't.
//

#include "cx_native.h"
CX_INT32 _fltused = 0x9875;
