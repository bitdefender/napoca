/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_CRTDEFS_H_
#define _CRT_CRTDEFS_H_
#include "cx_native.h"


//
// elementary definitions (might also be defined in runtimelib)
//
#ifndef __CRT_ELEMENTARY_DEFINITIONS
#define __CRT_ELEMENTARY_DEFINITIONS 1


#define CRT_UNREFERENCED_PARAMETER(P)           ((void)(P))
#define CRT_UNREFERENCED_LOCAL_VARIABLE(V)      ((void)(V))
#ifdef CX_DEBUG_BUILD
#define CRT_DBG_UNREFERENCED_PARAMETER(P)       ((void)(P))     // only on DEBUG builds
#define CRT_REL_UNREFERENCED_PARAMETER(P)
#else
#define CRT_DBG_UNREFERENCED_PARAMETER(P)
#define CRT_REL_UNREFERENCED_PARAMETER(P)       ((void)(P))     // only on RELEASE builds
#endif

#endif // __CRT_ELEMENTARY_DEFINITIONS


//
// for unknown reasons VC 2008 doesn't treat CX_UINT16 as implicit type (even if /Zc: is set)
//
///typedef __wchar_t CX_UINT16;          // __wchar_t generates some warnings with L"string" constants

#endif // _CRT_CRTDEFS_H_