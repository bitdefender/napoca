/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_SAL_H_
#define _CX_SAL_H_

#include "base/cx_env.h"

#ifdef CX_MSVC
#include "compiler_dependent/cx_vc_sal.h"

#ifndef KERNEL_MODE
_Analysis_mode_(_Analysis_code_type_user_code_)
#endif // USER_MODE
_Analysis_mode_(_Analysis_local_leak_checks_)

#else
#include "compiler_dependent/cx_vc_sal.h"
#endif


#endif // _CX_SAL_H_
