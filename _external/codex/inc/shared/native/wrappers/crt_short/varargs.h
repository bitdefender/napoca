/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_VARARGS_H
#include crt_INC_SETTINGS_VARARGS_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_VARARGS_WRAPPER_
#define _CRT_VARARGS_WRAPPER_

#include "crt/crt_varargs.h"

#if ( !defined(CRT_SKIP_DECL__ADDRESSOF) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL__ADDRESSOF))  )
#define _ADDRESSOF                      _CRT_ADDRESSOF
#endif

#if ( !defined(CRT_SKIP_DECL__INTSIZEOF) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL__INTSIZEOF))  )
#define _INTSIZEOF                      _CRT_INTSIZEOF
#endif

#if ( !defined(CRT_SKIP_DECL_VA_ARG) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL_VA_ARG))  )
#define va_arg                          crt_va_arg
#endif

#if ( !defined(CRT_SKIP_DECL_VA_END) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL_VA_END))  )
#define va_end                          crt_va_end
#endif

#if ( !defined(CRT_SKIP_DECL_VA_LIST) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL_VA_LIST))  )
#define va_list                         crt_va_list
#endif

#if ( !defined(CRT_SKIP_DECL_VA_START) && (!defined(CRT_DEFAULT_SKIP_VARARGS_H_DECL) || defined(CRT_WANT_DECL_VA_START))  )
#define va_start                        crt_va_start
#endif


#endif //_CRT_VARARGS_WRAPPER_
