/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Interface to buildsystem userdata, provides the required data types
//
#ifndef _UDTYPES_H_
#define _UDTYPES_H_
#include "cx_native.h"

//
// required data types (or preprocessor symbols):
// - UD_TYPE_QWORD:     highest precision integer type (your option if signed or not)
// - UD_TYPE_NUMBER:    type used for counters, lengths etc, recommended unsigned
// - UD_BOOLEAN:        any integer type, only using zero or non-zero semantics
//
#define UD_ASCII_STRING_MAX_SIZE 256
typedef char UD_FIXEDSIZE_ASCII_STRING[UD_ASCII_STRING_MAX_SIZE];
#define UD_QWORD CX_UINT64
#define UD_NUMBER CX_UINT64
#define UD_BOOLEAN CX_BOOL
#define UD_ASCII_STRING UD_FIXEDSIZE_ASCII_STRING
#define UD_SIZE_T CX_UINT64

#define PROTECTED   1
#define RUNTIME     2

// last bit set from VariableMetadataFlags marks a cfg variable as dirty
#define DIRTY       (1ULL << 63)

//#define STATIC      2

#define CFG_USED_BUILD_CONFIGURATIONS "(UNKNOWN)"
///#include "buildconfdefs.h"

#endif
