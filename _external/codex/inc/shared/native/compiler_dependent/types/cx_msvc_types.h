/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Basic numeric types that have compiler-dependent sizes
//

#ifndef _CX_VCTYPES_H_
#define _CX_VCTYPES_H_

#include "base/cx_env.h"

typedef __int8                          CX_INT8;
typedef __int16                         CX_INT16;
typedef __int32                         CX_INT32;
typedef __int64                         CX_INT64;


typedef unsigned __int8                 CX_UINT8;
typedef unsigned __int16                CX_UINT16;
typedef unsigned __int32                CX_UINT32;
typedef unsigned __int64                CX_UINT64;

#ifdef CX_ARCH32
typedef CX_UINT32                       CX_SIZE_T;
typedef CX_INT32                        CX_SSIZE_T;
#endif

#ifdef CX_ARCH64
typedef CX_UINT64                       CX_SIZE_T;
typedef CX_INT64                        CX_SSIZE_T;
#endif

typedef CX_INT64                        CX_INTMAXTYPE;  // maximal signed integer type supported by this compiler
typedef CX_UINT64                       CX_UINTMAXTYPE; // maximal unsigned integer type supported by this compiler
#define CX_INTMAXTYPE_WIDTH             64
#define CX_UINTMAXTYPE_WIDTH            64
#define CX_INTMAXTYPE_MIN_VALUE         CX_INT64_MIN_VALUE
#define CX_INTMAXTYPE_MAX_VALUE         CX_INT64_MAX_VALUE
#define CX_UINTMAXTYPE_MIN_VALUE        CX_UINT64_MIN_VALUE
#define CX_UINTMAXTYPE_MAX_VALUE        CX_UINT64_MAX_VALUE

#endif // _CX_VCTYPES_H_
