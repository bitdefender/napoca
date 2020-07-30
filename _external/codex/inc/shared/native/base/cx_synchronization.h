/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_SYNCHRONIZATION_H_
#define _CX_SYNCHRONIZATION_H_

//
// define CX_SIGNAL_BEGIN_BUSY_WAITING() and CX_SIGNAL_BUSY_WAITING() macros, allowing external control over their content
//

#ifdef CX_BEGIN_BUSY_WAITING_HANDLER
#define CX_SIGNAL_BEGIN_BUSY_WAITING CX_BEGIN_BUSY_WAITING_HANDLER
#else
#define CX_SIGNAL_BEGIN_BUSY_WAITING()
#endif


#ifdef CX_BUSY_WAITING_HANDLER
#define CX_SIGNAL_BUSY_WAITING CX_BUSY_WAITING_HANDLER
#else
#define CX_SIGNAL_BUSY_WAITING() _mm_pause()
#endif


#include "base/cx_env.h"


//
// Microsoft VC Compiler specifics
//
#ifdef CX_MSVC
#include "compiler_dependent/synchronization/cx_msvc_synch.h"
#else
#include "compiler_dependent/synchronization/cx_linux_synch.h"
#endif

//
// TODO: add support for other compilers by following the above model
//


#endif // _CX_SYNCHRONIZATION_H_
