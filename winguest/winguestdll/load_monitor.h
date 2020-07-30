/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _LOAD_MONITOR_H_
#define _LOAD_MONITOR_H_

typedef enum _FAIL_COUNT_ACTION
{
    assumeFail = 1,         ///< Set Boot to true and increment counter
    reset,                  ///< Reset Load Monitor Data
    recoverFail,            ///< Clear Boot and Crash flags
    noAction                ///< Do not alter Load Monitor Data
} FAIL_COUNT_ACTION, *PFAIL_COUNT_ACTION;

NTSTATUS
GetLoadMonitorData(
    _Out_opt_ PDWORD    AllowedRetries,
    _Out_opt_ PDWORD    FailCount,
    _Out_opt_ PBOOLEAN  Boot,
    _Out_opt_ PBOOLEAN  Crash
    );

NTSTATUS
UpdateLoadMonitorData(
    _In_ FAIL_COUNT_ACTION CounterAction,
    _In_opt_ PDWORD AllowedRetries
    );

bool
FailCountAllowed(
    void
    );

NTSTATUS
CheckLoadMonitor(
    void
    );

#endif //_LOAD_MONITOR_H
