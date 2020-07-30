/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_ASSERT_
#define _CRT_ASSERT_
#include "base/cx_sal.h"
typedef CX_VOID (*CRT_PFUNC_CRT_ASSERT_CALLBACK)(_In_ const CX_INT8 *File, _In_ CX_INT32 Line, _In_opt_ CX_INT8 *Message);

#ifdef CX_DEBUG_BUILD
extern CRT_PFUNC_CRT_ASSERT_CALLBACK volatile gNativeCrtAssert;
#define crt_assert(x)      __analysis_assume(x); { if (!(x) && (CX_NULL != gNativeCrtAssert)) gNativeCrtAssert(__FILE__, __LINE__, CX_NULL); }
#define crtAssert2(x,f,l) __analysis_assume(x); { if (!(x) && (CX_NULL != gNativeCrtAssert)) gNativeCrtAssert(f, l, CX_NULL); }
#else
#define crt_assert(x)
#define crtAssert2(x,f,l)
#endif

CX_INT32
CrtSetOnlyOnceCrtAssertCallback(
    _In_ CRT_PFUNC_CRT_ASSERT_CALLBACK Callback );

#endif // _CRT_ASSERT_