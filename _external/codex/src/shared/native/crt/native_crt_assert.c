/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "crt/crt_crt.h"
#include "base/cx_synchronization.h"
#include "base/cx_env.h"

//
// global CRT crt_assert callback
//
CRT_PFUNC_CRT_ASSERT_CALLBACK volatile gNativeCrtAssert = CX_NULL;

//
// CrtSetOnlyOnceCrtAssertCallback
//
CX_INT32
CrtSetOnlyOnceCrtAssertCallback(
    _In_ CRT_PFUNC_CRT_ASSERT_CALLBACK Callback 
    )
{
#ifdef CX_MSVC
#pragma warning(suppress:4152) // nonstandard extension, function/data pointer conversion in expression
    return (0 == CxInterlockedCompareExchangePointer((CX_VOID *volatile *)&gNativeCrtAssert, Callback, CX_NULL));
#else
    return (0 == CxInterlockedCompareExchangePointer((CX_VOID *volatile *)&gNativeCrtAssert, Callback, CX_NULL));
#endif
}