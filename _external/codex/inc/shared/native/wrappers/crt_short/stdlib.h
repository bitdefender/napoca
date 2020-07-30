/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_STDLIB_H
#include crt_INC_SETTINGS_STDLIB_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_STDLIB_WRAPPER_
#define _CRT_STDLIB_WRAPPER_

#include "crt/crt_stdlib.h"

#if ( !defined(CRT_SKIP_DECL_RAND_MAX) && (!defined(CRT_DEFAULT_SKIP_STDLIB_H_DECL) || defined(CRT_WANT_DECL_RAND_MAX))  )
#define RAND_MAX                        CRT_RAND_MAX
#endif

#if ( !defined(CRT_SKIP_DECL_RAND) && (!defined(CRT_DEFAULT_SKIP_STDLIB_H_DECL) || defined(CRT_WANT_DECL_RAND))  )
#define rand                            crt_rand
#endif

#if ( !defined(CRT_SKIP_DECL_SRAND) && (!defined(CRT_DEFAULT_SKIP_STDLIB_H_DECL) || defined(CRT_WANT_DECL_SRAND))  )
#define srand                           crt_srand
#endif


#endif //_CRT_STDLIB_WRAPPER_
