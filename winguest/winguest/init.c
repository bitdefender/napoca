/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file init.c
*   @brief Driver initialization
*/

#include "init.h"
#include "memory.h"
#include "umlibcomm.h"
#include "comm_hv.h"
#include "updates.h"
#include "version.h"
#include "winguest_status.h"
#include "misc_utils.h"
#include "trace.h"
#include "init.tmh"

/**
 * @brief Initialize driver resources and set default values for global data
 *
 * @param[out] DriverObject                 Driver Object (unreferenced)
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
WinguestInitialize(
    _In_ struct _DRIVER_OBJECT *DriverObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DriverObject);

    __try
    {
        LogVerbose("Initializing winguest.sys\n");

        gDrv.HvSleeping = FALSE;

        status = InitUmlibComm();
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "InitUmlibComm");
            __leave;
        }

        // Clear Apic IDs cache
        for (CX_UINT32 i = 0; i < ARRAYSIZE(gSavedApicIdForCpu); ++i)
        {
            gSavedApicIdForCpu[i] = APIC_ID_CACHE_CLEAR;
        }
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            WinguestUninitialize();
        }
    }

    gDrv.Initialized = NT_SUCCESS(status);

    return status;
}

/**
 * @brief Free driver resources and set neutral values for global data
 *
 * @param[out] DriverObject                 Driver Object (unreferenced)
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
WinguestUninitialize(
    void
    )
{
    NTSTATUS status;

    status = STATUS_SUCCESS;

    LogVerbose("%s called\n", __FUNCTION__);

    UninitUmlibComm();

    HVCommUninit();

    if (gDrv.HvCommLockInitialized)
    {
        ExDeleteResourceLite(&gDrv.HvCommLock);
        gDrv.HvCommLockInitialized = FALSE;
    }

    KeDeregisterBugCheckReasonCallback(&gDrv.BugcheckCbRecord);

    if (gDrv.HvLogDrvBuffer)
    {
        ExFreePoolWithTagAndNull(&gDrv.HvLogDrvBuffer, TAG_LOG);
    }

    if (gDrv.HvLogVirtualAddr)
    {
        MmUnmapIoSpace(gDrv.HvLogVirtualAddr, gDrv.HvLogSize);
        gDrv.HvLogVirtualAddr = NULL;
    }

    FreeUnicodeString(&gDrv.DriverRegistryPath);

    return status;
}

/**
 * @brief Initialize a subset of driver resources after a connection from user mode is established
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
WinguestDelayedInitialization(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gDrv.DelayedInitializeDone == FALSE)
    {
        __try
        {
            status = InitCpuEntry(&gDrv.CpuEntry);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "InitCpuEntry");
                __leave;
            }

            status = InitCpuVirtualizationFeatures(&gDrv.CpuEntry, &gDrv.VirtualizationFeatures);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "InitCpuVirtualizationFeatures");
                __leave;
            }

            // if HV is booted then we cannot execute GETSEC
            if (HVStarted())
            {
                LogWarning("Hypervisor started. SMX features are not detected!\n");
            }
            else
            {
                status = InitCpuSmxFeatures(&gDrv.CpuEntry, &gDrv.SmxCaps);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "InitCpuSmxFeatures");
                    __leave;
                }
            }
        }
        __finally
        {
            if (NT_SUCCESS(status))
            {
                gDrv.DelayedInitializeDone = TRUE;
            }
        }
    }

    return status;
}
