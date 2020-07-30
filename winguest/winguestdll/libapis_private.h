/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _LIBAPIS_PRIVATE_H_
#define _LIBAPIS_PRIVATE_H_

#include "winguestdll.h"

#ifndef QWORD
#define QWORD unsigned __int64
#endif

#ifdef __cplusplus
extern "C" {
#endif

WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestFastOpt(
    _In_ DWORD Opt,
    _In_opt_ COMM_COMPONENT Destination,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_opt_ QWORD *OutParam1,
    _Out_opt_ QWORD *OutParam2,
    _Out_opt_ QWORD *OutParam3,
    _Out_opt_ QWORD *OutParam4
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestFastOpt)(
    _In_ DWORD Opt,
    _In_opt_ COMM_COMPONENT Destination,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_opt_ QWORD *OutParam1,
    _Out_opt_ QWORD *OutParam2,
    _Out_opt_ QWORD *OutParam3,
    _Out_opt_ QWORD *OutParam4
    );

WINGUEST_DLL_API
NTSTATUS
WinguestDumpUefiLogs();
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestDumpUefiLogs)();

#ifdef __cplusplus
}
#endif

#endif