/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __CX_UM_H__
#define __CX_UM_H__

// include standard user mode headers and get also standard NTSTATUS defines
#include <winapifamily.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS     // avoid redefinition of some NTSTATUS defines 
#include <windows.h>

#include <sal.h>

// define NTSTATUS only if it is not already defined
// it can be defined by including ntdef.h or bcrypt.h which in turn includes ntdef.h
#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#endif // __CX_UM_H__
