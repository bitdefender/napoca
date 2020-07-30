/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
/// Inconsistent cx_types vs cx_sal includes detection/guard: ensure properly SAL-decorated types are available
/// when sal is actually being used
///
#ifndef _Cx_Return_type_success_
// define a temporary dummy _Cx_Return_type_success_ macro to support types without sal
#define _Cx_Return_type_success_(X)
#define CX_STATUS_TYPE_DEFINED_WITHOUT_SAL
#else
#define CX_STATUS_TYPE_DEFINED_WITH_SAL
#endif // _Cx_Return_type_success_

#ifdef CX_STATUS_TYPE_DEFINED_WITHOUT_SAL
#ifdef CX_STATUS_TYPE_DEFINED_WITH_SAL
#error "when used, cx_sal.h needs to be included BEFORE cx_types.h for proper types annotations!"
#endif // CX_STATUS_TYPE_DEFINED_WITH_SAL
#endif // CX_STATUS_TYPE_DEFINED_WITHOUT_SAL



#ifndef _CX_TYPES_H_
#define _CX_TYPES_H_
#include "base/cx_elementary_types.h"

typedef void                            CX_VOID, *PCX_VOID;

// CX_BOOLx types for interlocked operations on boolean values
typedef CX_UINT8                        CX_BOOL, *PCX_BOOL;
typedef CX_UINT8                        CX_BOOL8, *PCX_BOOL8;
typedef CX_UINT16                       CX_BOOL16, *PCX_BOOL16;
typedef CX_UINT32                       CX_BOOL32, *PCX_BOOL32;
typedef CX_UINT64                       CX_BOOL64, *PCX_BOOL64;

typedef CX_INT8                         *PCX_INT8;
typedef CX_INT16                        *PCX_INT16;
typedef CX_INT32                        *PCX_INT32;
typedef CX_INT64                        *PCX_INT64;
typedef CX_UINT8                        *PCX_UINT8;
typedef CX_UINT16                       *PCX_UINT16;
typedef CX_UINT32                       *PCX_UINT32;
typedef CX_UINT64                       *PCX_UINT64;
typedef CX_SIZE_T                       *PCX_SIZE_T;
typedef CX_SSIZE_T                      *PCX_SSIZE_T;

#define CX_BOOL_WIDTH                   8

#define CX_INT8_MIN_VALUE               (-0x80ll)
#define CX_INT8_MAX_VALUE               0x7Fll
#define CX_INT16_MIN_VALUE              (-0x8000ll)
#define CX_INT16_MAX_VALUE              0x7FFFll
#define CX_INT32_MIN_VALUE              (-0x80000000ll)
#define CX_INT32_MAX_VALUE              0x7FFFFFFFll
#define CX_INT64_MIN_VALUE              (-0x8000000000000000ll)
#define CX_INT64_MAX_VALUE              0x7FFFFFFFFFFFFFFFll

#define CX_UINT8_MIN_VALUE              0
#define CX_UINT8_MAX_VALUE              0xFFull
#define CX_UINT16_MIN_VALUE             0
#define CX_UINT16_MAX_VALUE             0xFFFFull
#define CX_UINT32_MIN_VALUE             0
#define CX_UINT32_MAX_VALUE             0xFFFFFFFFull
#define CX_UINT64_MIN_VALUE             0
#define CX_UINT64_MAX_VALUE             0xFFFFFFFFFFFFFFFFull

#ifdef CX_ARCH32
#define CX_SIZE_T_MIN_VALUE             CX_UINT32_MIN_VALUE
#define CX_SIZE_T_MAX_VALUE             CX_UINT32_MAX_VALUE
#define CX_SSIZE_T_MIN_VALUE            CX_INT32_MIN_VALUE
#define CX_SSIZE_T_MAX_VALUE            CX_INT32_MAX_VALUE
#else
#define CX_SIZE_T_MIN_VALUE             CX_UINT64_MIN_VALUE
#define CX_SIZE_T_MAX_VALUE             CX_UINT64_MAX_VALUE
#define CX_SSIZE_T_MIN_VALUE            CX_INT64_MIN_VALUE
#define CX_SSIZE_T_MAX_VALUE            CX_INT64_MAX_VALUE
#endif

#ifndef CX_STATUS_TYPE_DEFINED
/// make sure we support CX_STATUS when sal was not included by defining a temporary dummy _Cx_Return_type_success_ macro
#ifndef _Cx_Return_type_success_
#define _Cx_Return_type_success_(X)
#define CX_STATUS_TYPE_DEFINED_WITHOUT_SAL
#endif

typedef _Cx_Return_type_success_(return >= 0) CX_INT32 CX_STATUS, *PCX_STATUS;

#endif

#endif // _CX_TYPES_H_

// undo previously defined (dummy) symbols/macros
#ifdef CX_STATUS_TYPE_DEFINED_WITHOUT_SAL
#undef _Cx_Return_type_success_
#endif
