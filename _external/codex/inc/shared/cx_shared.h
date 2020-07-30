/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __CX_SHARED_H__
#define __CX_SHARED_H__

// pull correct headers for kernel mode or user mode
#ifdef KERNEL_MODE
#include "cx_km.h"
#else
#include "cx_um.h"
#include <winioctl.h>
#endif

#endif // __CX_SHARED_H__