/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file load_monitor.cpp
*   @brief Monitor the health of the hypervisor in order to ensure system stability and that the hypervisor boots
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;


#include "load_monitor.h"
#include "reg_opts.h"
#include "winguest_status.h"
#include "deploy_legacy.h"
#include "deploy_uefi.h"
#include "dacia_types.h"
#include "helpers.h"
#include "libapis_int.h"
#include "feedback.h"
#include "deploy_validation.h"
#include "consts.h"
#include "trace.h"
#include "common/debug/memlog.h"
#include "load_monitor.tmh"

extern BOOLEAN  gHypervisorStarted;
extern BOOLEAN  gHypervisorConfigured;
extern DWORD    gHvLogOffset;

/**
 * @brief Get Load Monitor data
 *
 * @param[out] AllowedRetries       How many attempts to boot the Hypervisor before simply passing execution to the OS loader
 * @param[out] FailCount            Number of failed attempts
 * @param[out] Boot                 The hypervisor attempted booting
 * @param[out] Crash                The hypervisor may have crashed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GetLoadMonitorData(
    _Out_opt_ PDWORD    AllowedRetries,
    _Out_opt_ PDWORD    FailCount,
    _Out_opt_ PBOOLEAN  Boot,
    _Out_opt_ PBOOLEAN  Crash
    )
{
    if (!gHypervisorConfigured)
        return STATUS_NOT_PROPERLY_CONFIGURED;

    return IsUefiBootedOs()
        ? GetLoadMonitorDataUefi(AllowedRetries, FailCount, Boot, Crash)
        : GetLoadMonitorDataMbr (AllowedRetries, FailCount, Boot, Crash);
}

/**
 * @brief Update Load Monitor data
 *
 * @param[in] CounterAction         Action to be performed on the monitor data
 * @param[in] AllowedRetries        How many attempts to boot the Hypervisor before simply passing execution to the OS loader
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
UpdateLoadMonitorData(
    _In_ FAIL_COUNT_ACTION CounterAction,
    _In_opt_ PDWORD AllowedRetries
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD failCount = 0;
    BOOLEAN boot = FALSE;
    BOOLEAN crash = FALSE;

    if (!gHypervisorConfigured)
        return STATUS_NOT_PROPERLY_CONFIGURED;

    __try
    {
        status = IsUefiBootedOs()
            ? GetLoadMonitorDataUefi(NULL, &failCount, &boot, &crash)
            : GetLoadMonitorDataMbr (NULL, &failCount, &boot, &crash);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetLoadMonitorData");
            __leave;
        }

        switch(CounterAction)
        {
        case reset:
            {
                failCount = 0;
                crash = FALSE;
                boot = FALSE;
                break;
            }
        case recoverFail:
            {
                crash = FALSE;
                boot = FALSE;
                break;
            }
        case noAction:
            {
                break;
            }
        case assumeFail: // the loader is responsible for this action
        default:
            {
                status = STATUS_INVALID_PARAMETER_2;
                __leave;
            }
        }

        status = IsUefiBootedOs()
            ? SetLoadMonitorDataUefi(AllowedRetries, &failCount, &boot, &crash)
            : SetLoadMonitorDataMbr (AllowedRetries, &failCount, &boot, &crash);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "SetLoadMonitorData");
        }
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check if Fail Counter has not reached the maximum Allowed Retries value (If Hypervisor will still attempt to boot)
 *
 * @return true         Fail Counter has not reached the maximum allowed value
 * @return false        Fail Counter has reached the maximum allowed value
 */
bool
FailCountAllowed(
    void
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD allowed = 0;
    DWORD fails = 0;

    status = GetLoadMonitorData(&allowed, &fails, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetLoadMonitorData");
        return TRUE;
    }

    return (fails < allowed) || (0 == allowed);
}

/**
 * @brief Check if Hypervisor booted and update Load Monitor data accordingly
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
CheckLoadMonitor(
    void
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN boot = FALSE;

    __try
    {
        status = GetLoadMonitorData(NULL, NULL, &boot, NULL);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "GetLoadMonitorData");
        }

        if (gHypervisorStarted)
        {
            status = UpdateLoadMonitorData(reset, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "UpdateLoadMonitorData");
            }

            if (boot)
            {
                gHvLogOffset = MEMLOG_NO_OFFSET; // reset hv log for in case of resume from hibernate
            }
        }
        else
        {
            status = UpdateLoadMonitorData(recoverFail, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "UpdateLoadMonitorData");
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}
