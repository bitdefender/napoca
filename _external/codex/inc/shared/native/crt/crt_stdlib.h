/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_STDLIB_H_
#define _CRT_STDLIB_H_

#include "cx_native.h"
#include "crt/crt_memory.h"

#define CRT_RAND_MAX        CX_INT32_MAX_VALUE         // maximum value returned by crt_rand()  (0..CRT_RAND_MAX)

CX_VOID crt_srand(CX_INT32 seed);
CX_INT32 crt_rand(CX_VOID);
/// ...

#endif // _CRT_STDLIB_H_
