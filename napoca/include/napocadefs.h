/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Globally (at napoca-scope) needed symbols
//

#ifndef _NAPOCA_DEFS_H_
#define _NAPOCA_DEFS_H_

#include "cx_native.h"
#include "core.h"

// hack for some components (disasm for example) that need AMD64 being defined / visible
#define AMD64


char*
NtStatusToString(
    _In_ CX_STATUS Status);


// remove the coredefs version of SUCCESS verification macros and provide the napoca-aware/custom ones instead
#undef _SUCCESS
#undef NTSUCCESS
#undef NT_SUCCESS
#undef SUCCESS

#define _SUCCESS                        CX_SUCCESS
#define NTSUCCESS                       CX_SUCCESS
#define NT_SUCCESS                      CX_SUCCESS
#define SUCCESS                         CX_SUCCESS

#endif // _NAPOCA_DEFS_H_