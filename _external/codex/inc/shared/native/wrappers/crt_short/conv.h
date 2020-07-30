/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_CONV_H
#include crt_INC_SETTINGS_CONV_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_CONV_WRAPPER_
#define _CRT_CONV_WRAPPER_

#include "crt/crt_conv.h"

#if ( !defined(CRT_SKIP_DECL_STRTOL) && (!defined(CRT_DEFAULT_SKIP_CONV_H_DECL) || defined(CRT_WANT_DECL_STRTOL))  )
#define strtol                          crt_strtol
#endif

#if ( !defined(CRT_SKIP_DECL_STRTOLL) && (!defined(CRT_DEFAULT_SKIP_CONV_H_DECL) || defined(CRT_WANT_DECL_STRTOLL))  )
#define strtoll                         crt_strtoll
#endif

#if ( !defined(CRT_SKIP_DECL_STRTOQ) && (!defined(CRT_DEFAULT_SKIP_CONV_H_DECL) || defined(CRT_WANT_DECL_STRTOQ))  )
#define strtoq                          crt_strtoq
#endif

#if ( !defined(CRT_SKIP_DECL_STRTOUL) && (!defined(CRT_DEFAULT_SKIP_CONV_H_DECL) || defined(CRT_WANT_DECL_STRTOUL))  )
#define strtoul                         crt_strtoul
#endif

#if ( !defined(CRT_SKIP_DECL_STRTOULL) && (!defined(CRT_DEFAULT_SKIP_CONV_H_DECL) || defined(CRT_WANT_DECL_STRTOULL))  )
#define strtoull                        crt_strtoull
#endif


#endif //_CRT_CONV_WRAPPER_
