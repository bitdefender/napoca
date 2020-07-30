/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_MEMORY_H
#include crt_INC_SETTINGS_MEMORY_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_MEMORY_WRAPPER_
#define _CRT_MEMORY_WRAPPER_

#include "crt/crt_memory.h"

#if ( !defined(CRT_SKIP_DECL_MEMCMP) && (!defined(CRT_DEFAULT_SKIP_MEMORY_H_DECL) || defined(CRT_WANT_DECL_MEMCMP))  )
#define memcmp                          crt_memcmp
#endif

#if ( !defined(CRT_SKIP_DECL_MEMCPY) && (!defined(CRT_DEFAULT_SKIP_MEMORY_H_DECL) || defined(CRT_WANT_DECL_MEMCPY))  )
#define memcpy                          crt_memcpy
#endif

#if ( !defined(CRT_SKIP_DECL_MEMCPY_S) && (!defined(CRT_DEFAULT_SKIP_MEMORY_H_DECL) || defined(CRT_WANT_DECL_MEMCPY_S))  )
#define memcpy_s                        crt_memcpy_s
#endif

#if ( !defined(CRT_SKIP_DECL_MEMSET) && (!defined(CRT_DEFAULT_SKIP_MEMORY_H_DECL) || defined(CRT_WANT_DECL_MEMSET))  )
#define memset                          crt_memset
#endif

#if ( !defined(CRT_SKIP_DECL_MEMZERO) && (!defined(CRT_DEFAULT_SKIP_MEMORY_H_DECL) || defined(CRT_WANT_DECL_MEMZERO))  )
#define memzero                         crt_memzero
#endif


#endif //_CRT_MEMORY_WRAPPER_
