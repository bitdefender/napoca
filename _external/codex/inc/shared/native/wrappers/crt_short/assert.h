/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_ASSERT_H
#include crt_INC_SETTINGS_ASSERT_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_ASSERT_WRAPPER_
#define _CRT_ASSERT_WRAPPER_
#include "crt/crt_assert.h"


#if ( !defined(CRT_SKIP_DECL_PFUNC_CRT_ASSERT_CALLBACK) && (!defined(CRT_DEFAULT_SKIP_ASSERT_H_DECL) || defined(CRT_WANT_DECL_PFUNC_CRT_ASSERT_CALLBACK))  )
#define PFUNC_CRT_ASSERT_CALLBACK       CRT_PFUNC_CRT_ASSERT_CALLBACK
#endif

#if ( !defined(CRT_SKIP_DECL_SETONLYONCECRTASSERTCALLBACK) && (!defined(CRT_DEFAULT_SKIP_ASSERT_H_DECL) || defined(CRT_WANT_DECL_SETONLYONCECRTASSERTCALLBACK))  )
#define SetOnlyOnceCrtAssertCallback    CrtSetOnlyOnceCrtAssertCallback
#endif

#if ( !defined(CRT_SKIP_DECL_ASSERT) && (!defined(CRT_DEFAULT_SKIP_ASSERT_H_DECL) || defined(CRT_WANT_DECL_ASSERT))  )
#define assert                          crt_assert
#endif

#if ( !defined(CRT_SKIP_DECL_ASSERT2) && (!defined(CRT_DEFAULT_SKIP_ASSERT_H_DECL) || defined(CRT_WANT_DECL_ASSERT2))  )
#define assert2                         crtAssert2
#endif


#endif //_CRT_ASSERT_WRAPPER_
