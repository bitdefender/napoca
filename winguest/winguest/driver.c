/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file driver.c
*   @brief Main driver routines and entry point
*/

#include "driver.h"
#include "winguest_types.h"
#include "umlibcomm.h"
#include "wdfobject.h"
#include "comm_hv.h"
#include "memory.h"
#include "init.h"
#include "misc_utils.h"

#include "trace.h"
#include "driver.tmh"

#define WINGUEST_SYS_DEVICE_NAME        L"\\Device\\WinguestDevice"

//
// import kernel variable to detect safe mode
//
extern PULONG InitSafeBootMode;

DRV_GLOBAL_DATA gDrv;
CX_UINT8 gSavedApicIdForCpu[255];
EVT_WDF_DRIVER_UNLOAD WinguestEvtDriverUnload;
DRIVER_REINITIALIZE WinguestReinitialize;

//
// The NT Device name of the device
//
DECLARE_CONST_UNICODE_STRING(DeviceName, WINGUEST_SYS_DEVICE_NAME);

NTSTATUS
DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    );

NTSTATUS
WinguestDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    );

VOID
WinguestEvtDeviceContextCleanup(
    IN WDFDEVICE Device
    );

VOID
WinguestEvtDriverContextCleanup(
    IN WDFDEVICE Device
    );

VOID
WinguestEvtDestroyCallback(
    IN  WDFOBJECT Object
    );

BOOLEAN
WinguestIsNtdllAvailable(
    VOID
    );

EVT_WDF_DEVICE_D0_ENTRY WinguestDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT WinguestDeviceD0Exit;

#ifdef ALLOC_PRAGMA
//#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, WinguestDeviceAdd )
#endif // ALLOC_PRAGMA

/**
 * @brief Kernel Bugcheck Callback
 */
_IRQL_requires_same_ VOID BugcheckCbSaveLog(
    KBUGCHECK_CALLBACK_REASON Reason,
    KBUGCHECK_REASON_CALLBACK_RECORD * Record,
    PVOID ReasonSpecificData,
    ULONG ReasonSpecificDataLength
)
{
    UNREFERENCED_PARAMETER((Reason, Record, ReasonSpecificDataLength));

    // {BD5E15DB-BD5D-45DD-BE93-CE12F34D43C6}
    static GUID WinguestBugCheckDataGuid = { 0xbd5e15db, 0xbd5d, 0x45dd, 0xbe, 0x93, 0xce, 0x12, 0xf3, 0x4d, 0x43, 0xc6 };

    if (!gDrv.HvLogVirtualAddr)
    {
        return;
    }

    if (gDrv.HvLogDrvBuffer)
    {
        memcpy(gDrv.HvLogDrvBuffer, gDrv.HvLogVirtualAddr, gDrv.HvLogSize);
    }

    KBUGCHECK_SECONDARY_DUMP_DATA *dumpData = ReasonSpecificData;

    DWORD logSize = gDrv.HvLogSize;
    HV_FEEDBACK_HEADER *header = gDrv.HvLogVirtualAddr;

    if (!header->Logger.BufferRollover)
    {
        logSize = min(logSize, sizeof (HV_FEEDBACK_HEADER) + header->Logger.BufferWritePos + 4096);
    }

    dumpData->Guid = WinguestBugCheckDataGuid;
    dumpData->OutBuffer = gDrv.HvLogVirtualAddr;
    dumpData->OutBufferLength = logSize;
}

/**
 * @brief Driver Entry Point
 *
 * This routine is called by the Operating System to initialize the driver.
 * It creates the device object, fills in the dispatch entry points and completes the initialization.
 *
 * @param[in] DriverObject          Pointer to the object that represents this device driver.
 * @param[in] RegistryPath          Pointer to our Services key in the registry.
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    NTSTATUS  status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attrs;
    BOOLEAN driverCreated = FALSE;

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    LogInfo("Starting winguest.sys %d.%d.%d.%d (%s %s)\n",
        WINGUEST_VERSION_HIGH, WINGUEST_VERSION_LOW, WINGUEST_VERSION_REVISION, WINGUEST_VERSION_BUILD,
        __DATE__, __TIME__);

#ifdef DEBUG
    LogInfo("DEBUG build");
#endif

    __try
    {
        // Do not allow the driver to load on SafeMode
        //
        if (*InitSafeBootMode > 0)
        {
            LogInfo("SAFE MODE: Will skip loading WINGUEST!\n");
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        RtlSecureZeroMemory(&gDrv, sizeof(DRV_GLOBAL_DATA));

        gDrv.WdfDevice = NULL;
        gDrv.WdfDeviceRef = NULL;
        gDrv.WdfdeviceCount = 0;
        gDrv.DeviceObjectRefCnt = 0;

        // save DriverObject for later use
        LogInfo("Winguest driver object: %p\n", DriverObject);
        gDrv.DriverObject = DriverObject;

        status = RetrieveUndocumentedFunctions(&gDrv.WinApis);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RetrieveUndocumentedFunctions");
        }

        gDrv.OsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
        status = RtlGetVersion((PRTL_OSVERSIONINFOW)&gDrv.OsVersionInfo);
        if (!NT_SUCCESS(status))
        {
            RtlZeroMemory(&gDrv.OsVersionInfo, sizeof(RTL_OSVERSIONINFOEXW));
        }

        gDrv.DefaultMemPoolType =
            (((gDrv.OsVersionInfo.dwMajorVersion == 0x06) && (gDrv.OsVersionInfo.dwMinorVersion >= 0x02)) || (gDrv.OsVersionInfo.dwMajorVersion > 6)) // if Windows 8 or later
            ? NonPagedPoolNx
            : NonPagedPool;

        WDF_DRIVER_CONFIG_INIT(&config, WinguestDeviceAdd);
        config.EvtDriverUnload = WinguestEvtDriverUnload;

        WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
        attrs.EvtCleanupCallback = WinguestEvtDriverContextCleanup;

        // Create a framework driver object to represent our driver.
        status = WdfDriverCreate(
            DriverObject,
            RegistryPath,
            &attrs,
            &config,
            &gDrv.WdfDriver);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WdfDriverCreate");
            __leave;
        }
        driverCreated = TRUE;

        status = CreateUnicodeString(&gDrv.DriverRegistryPath, UNICODE_LEN(*RegistryPath));
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CreateUnicodeString");
            __leave;
        }

        status = RtlUnicodeStringCopy(&gDrv.DriverRegistryPath, RegistryPath);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RtlUnicodeStringCopy");
            __leave;
        }

        KeInitializeCallbackRecord(&gDrv.BugcheckCbRecord);

        if (!KeRegisterBugCheckReasonCallback(
            &gDrv.BugcheckCbRecord,
            BugcheckCbSaveLog,
            KbCallbackSecondaryDumpData,
            (PUCHAR)"winguest"
            ))
        {
            LogError("Could not register bugcheck callback!");
        }

        status = ExInitializeResourceLite(&gDrv.HvCommLock);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ExInitializeResourceLite");
            __leave;
        }
        gDrv.HvCommLockInitialized = TRUE;

        KeInitializeGuardedMutex(&gDrv.CommandLock);

        status = HVCommInit();
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "HVCommInit");
            __leave;
        }

        DWORD paramVal = 0;
        status = WinhostReadHvParameter(&gDrv.DriverRegistryPath, hvParamReserveHvLogBuffer, &paramVal, sizeof(paramVal));
        if (!NT_SUCCESS(status))
        {
            paramVal = 0;
            status = STATUS_SUCCESS;
        }
        gDrv.HvLogReserveBuffer = !!paramVal;

        //
        // On dynamic disks, WinguestIsNtdllAvailable() will prevent winguest.sys initialization at boot time
        // With current counter (ReinitMaxCallCount) set to 0x100, WinguestIsNtdllAvailable always returns FALSE
        //status = WinhostReadHvParameter(&gDrv.DriverRegistryPath, hvParamReinitRoutineCallCount, &gDrv.ReinitMaxCallCount, sizeof(gDrv.ReinitMaxCallCount));
        //if (!NT_SUCCESS(status))
        //{
        //    gDrv.ReinitMaxCallCount = 0;
        //    status = STATUS_SUCCESS;
        //}

        //if (!WinguestIsNtdllAvailable())
        //{
        //    //
        //    // Opening ntdll failed, register a reinitialization routine
        //    //

        //    IoRegisterBootDriverReinitialization(DriverObject, WinguestReinitialize, NULL);

        //    status = STATUS_SUCCESS;
        //}
        //else
        //{
            status = WinguestInitialize(DriverObject);
        //}
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            FreeUnicodeString(&gDrv.DriverRegistryPath);
            WinguestUninitialize();

            if (!driverCreated)
            {
                WPP_CLEANUP(DriverObject);
            }
        }
    }

    return status;
}

/**
 * @brief WDF Device Query Stop Callback
 */
NTSTATUS
WinguestDeviceQueryStop(
    _In_ WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);

    LogVerbose("WinguestDeviceQueryStop called\n");

    if (0 != gDrv.DeviceObjectRefCnt)
    {
        LogCritical("Not allowed to stop the device! Lock count: %d", gDrv.DeviceObjectRefCnt);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief WDF Device Query Remove Callback
 */
NTSTATUS
WinguestDeviceQueryRemove(
    _In_ WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);

    LogVerbose("WinguestDeviceQueryRemove called");

    // allow unload if we are going to sleep
    /*if (gDrv.HvSleeping)
    {
        LogInfo("Allowed to remove device because system prepares to sleep!\n");
        return STATUS_SUCCESS;
    }*/

    if (0 != gDrv.DeviceObjectRefCnt)
    {
        LogCritical("Not allowed to remove the device! Lock count: %d", gDrv.DeviceObjectRefCnt);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief WDF PowerState Callback
 */
VOID
WinguestPowerStateCallback(
    _In_ PVOID Context,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);

    switch((QWORD)Argument1)
    {
        case PO_CB_SYSTEM_STATE_LOCK:
        {
            CMD_SEND_POWER_STATE_CHANGED cmd = { 0 };
            DWORD bytesReturned = 0;

            cmd.Command.CommandCode = cmdSendPowerStateChange;
            cmd.PowerState = !!Argument2;

            if (Argument2)
            {
                gDrv.HvSleeping = FALSE;

                LogInfo("Wakeup from Sleep/Hibernate\n");

                SIZE_T WakeupPerformed = TRUE;

                status = HvVmcallSafe(OPT_GET_POWERUP_INFO,
                    0, 0, 0, 0,
                    &WakeupPerformed, NULL, NULL, NULL);
                if (NT_SUCCESS(status))
                {
                    cmd.ResumeVolatileSettingsLost = !WakeupPerformed;
                }
            }
            else
            {
                gDrv.HvSleeping = TRUE;

                LogInfo("Sleep/Hibernate/Shutdown/Reboot\n");
            }

            status = UmLibCommSendMessage(
                &cmd,
                sizeof(cmd),
                &cmd,
                sizeof(cmd),
                &bytesReturned
            );
            if (!NT_SUCCESS(status))
            {
                //LogFuncErrorStatus(status, "UmLibCommSendMessage");
            }

            break;
        }

        case PO_CB_SYSTEM_POWER_POLICY:
        {
            // If Argument1 is PO_CB_SYSTEM_POWER_POLICY, Argument2 is not used.
            LogInfo("Powered on\n"); // this is called multiple times
            break;
        }
    }
}

/**
 * @brief WDF evice Add Callback
 *
 * Called by the DriverEntry to create a control-device. This call is responsible for freeing the memory for DeviceInit.
 *
 * @param[in] Driver            Pointer to the object that represents this device driver.
 * @param[in] DeviceInit        Pointer to a driver-allocated WDFDEVICE_INIT structure.
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
WinguestDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN addingDev = FALSE;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_OBJECT_ATTRIBUTES   attributes;
    WDFDEVICE               hDevice = NULL;
    PFDO_DATA               fdoData = NULL;
    WDF_DEVICE_POWER_CAPABILITIES powerCapabilities;
    ULONG                   latencyOneMs = (10 * 1000); // 100ns -> 1ms

    UNREFERENCED_PARAMETER( Driver );

    __try
    {
        if (0 != InterlockedCompareExchange(&gDrv.WdfdeviceCount, 1, 0))
        {
            LogError("Cannot add multiple Winguest devices\n");
            status = STATUS_DEVICE_DATA_ERROR;
            __leave;
        }

        LogInfo("Adding device");
        addingDev = TRUE;

        // give a name for communication
        status = WdfDeviceInitAssignName(DeviceInit, &DeviceName);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WdfDeviceInitAssignName");
            __leave;
        }


        //
        // Initialize the pnpPowerCallbacks structure.  Callback events for PNP
        // and Power are specified here. If you don't supply any callbacks,
        // the Framework will take appropriate default actions based on whether
        // DeviceInit is initialized to be an FDO, a PDO or a filter device
        // object.
        //

        // Register PNP callbacks.
        WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);

        //
        // Register Power callbacks.
        //
        pnpPowerCallbacks.EvtDeviceD0Entry = WinguestDeviceD0Entry;
        pnpPowerCallbacks.EvtDeviceD0Exit = WinguestDeviceD0Exit;

        //
        // Register stop & remove callbacks - to control unloading of the device
        //
        pnpPowerCallbacks.EvtDeviceQueryStop = WinguestDeviceQueryStop;
        pnpPowerCallbacks.EvtDeviceQueryRemove = WinguestDeviceQueryRemove;


        WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

        //
        // Specify the size of device context
        //
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, FDO_DATA);

        // Register a cleanup callback so that we can call WPP_CLEANUP when
        // the framework driver object is deleted during driver unload.
        attributes.EvtCleanupCallback = WinguestEvtDeviceContextCleanup;
        attributes.EvtDestroyCallback = WinguestEvtDestroyCallback;
        attributes.ExecutionLevel = WdfExecutionLevelPassive;

        status = WdfDeviceCreate(&DeviceInit, &attributes, &hDevice);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "WdfDeviceCreate");
            __leave;
        }
        gDrv.WdfDevice = hDevice;

        LogVerbose("Winguest device object: %p\n", hDevice);

        //
        // Get the device context by using the accessor function specified in
        // the WDF_DECLARE_CONTEXT_TYPE_WITH_NAME macro for FDO_DATA.
        //
        fdoData = WinguestFdoGetData(hDevice);
        if (fdoData == NULL)
        {
            status = STATUS_NOT_SUPPORTED;
            LogFuncErrorStatus(status, "WinguestFdoGetData");
            __leave;
        }

        fdoData->WdfDevice = hDevice;

        //
        // Initialize power capabilities
        //

        WDF_DEVICE_POWER_CAPABILITIES_INIT(&powerCapabilities);

        powerCapabilities.DeviceD1 = WdfFalse;
        powerCapabilities.DeviceD2 = WdfFalse;
        powerCapabilities.WakeFromD0 = WdfTrue;
        powerCapabilities.WakeFromD1 = WdfFalse;
        powerCapabilities.WakeFromD2 = WdfFalse;
        powerCapabilities.WakeFromD3 = WdfTrue;
        powerCapabilities.DeviceState[PowerSystemWorking] = PowerDeviceD0;
        powerCapabilities.DeviceState[PowerSystemSleeping1] = PowerDeviceUnspecified;
        powerCapabilities.DeviceState[PowerSystemSleeping2] = PowerDeviceUnspecified;
        powerCapabilities.DeviceState[PowerSystemSleeping3] = PowerDeviceUnspecified;
        powerCapabilities.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
        powerCapabilities.DeviceState[PowerSystemShutdown] = PowerDeviceD3;
        powerCapabilities.DeviceWake = PowerDeviceMaximum;
        powerCapabilities.D1Latency = latencyOneMs * 1000 * 10;
        powerCapabilities.D2Latency = latencyOneMs * 1000 * 10;
        powerCapabilities.D3Latency = latencyOneMs * 1000 * 10;
        powerCapabilities.IdealDxStateForSx = PowerDeviceD3;

        WdfDeviceSetPowerCapabilities(hDevice, &powerCapabilities);

        // register power state notifications
        {
            OBJECT_ATTRIBUTES attr;
            UNICODE_STRING ustr = STATIC_WSTR_TO_UNICODE(L"\\Callback\\PowerState");

            try
            {
                InitializeObjectAttributes(&attr,
                    &ustr,
                    OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                    NULL,
                    NULL);

                status = ExCreateCallback(&fdoData->CallbackObject,
                                          &attr,
                                          FALSE,
                                          FALSE);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "ExCreateCallback");
                    __leave;
                }

                fdoData->CallbackObjectHandle = ExRegisterCallback(fdoData->CallbackObject,
                                            WinguestPowerStateCallback,
                                            NULL);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "ExRegisterCallback");
                    __leave;
                }

                status = STATUS_SUCCESS;
            }
            __finally
            {
                if (!NT_SUCCESS(status))
                {
                    if (NULL != fdoData->CallbackObject)
                    {
                        ObDereferenceObject(fdoData->CallbackObject);
                        fdoData->CallbackObject = NULL;
                    }
                }
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (addingDev && !NT_SUCCESS(status))
        {
            WinguestUninitialize();

            if (NULL != DeviceInit)
            {
                WdfDeviceInitFree(DeviceInit);
            }

            gDrv.WdfdeviceCount = 0;
        }
    }

    return status;
}

/**
 * @brief WDF EvtDriver Unload Callback
 */
VOID
WinguestEvtDriverUnload(
    IN WDFDRIVER Driver
    )
//
// Routine Description:
//
//    Called by the I/O subsystem just before unloading the driver.
//    You can free the resources created in the DriverEntry either
//    in this routine or in the EvtDriverContextCleanup callback.
//
// Arguments:
//
//     Driver - Handle to a framework driver object created in DriverEntry
//
// Return Value:
//
//     NTSTATUS
//
{
    UNREFERENCED_PARAMETER(Driver);

    LogVerbose("%s", __FUNCTION__);
}

/**
 * @brief WDF Evt Driver Context Cleanup Callback
 */
VOID
WinguestEvtDriverContextCleanup(
    IN WDFDEVICE Device
    )
//
// Routine Description:
//
//    Called when the driver object is deleted during driver unload.
//    You can free all the resources created in DriverEntry that are
//    not automatically freed by the framework.
//
// Arguments:
//
//     Driver - Handle to a framework driver object created in DriverEntry
//
// Return Value:
//
//     NTSTATUS
//
{
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(Device);

    LogVerbose("WinguestEvtDriverContextCleanup called");

    timeout.QuadPart = (QWORD) (DELAY_ONE_MICROSECOND * 1);
    while (0 != InterlockedCompareExchange(&gDrv.DeviceObjectRefCnt, 0, 0))
    {
        KeDelayExecutionThread(KernelMode,FALSE,&timeout);
    }

    LogInfo("Will uninitialize winguest\n");
    WinguestUninitialize();

    LogInfo("Unloaded WINGUEST.SYS");

    RtlSecureZeroMemory(&gDrv, sizeof(DRV_GLOBAL_DATA));

    WPP_CLEANUP(gDrv.DriverObject);

    return;
}

/**
 * @brief WDF Evt Device Context Cleanup Callback
 */
VOID
WinguestEvtDeviceContextCleanup(
    IN WDFDEVICE Device
    )
//
// Routine Description:
//
//    Called when the driver object is deleted during driver unload.
//    You can free all the resources created in DriverEntry that are
//    not automatically freed by the framework.
//
// Arguments:
//
//     Driver - Handle to a framework driver object created in DriverEntry
//
// Return Value:
//
//     NTSTATUS
//
{
    UNREFERENCED_PARAMETER(Device);

    LogVerbose("WinguestEvtDeviceContextCleanup called");

    UninitUmlibComm();
}

/**
 * @brief WDF Evt Destroy Callback
 */
VOID
WinguestEvtDestroyCallback(
    IN  WDFOBJECT Object
    )
{
    PFDO_DATA   fdoData;

    LogVerbose("WinguestEvtDestroyCallback called");

    if (0 != gDrv.DeviceObjectRefCnt)
    {
        LogCritical("Not allowed to destroy the device! Lock count: %d\n", gDrv.DeviceObjectRefCnt);
        return;
    }

    if (PASSIVE_LEVEL != KeGetCurrentIrql())
    {
        LogCritical("!!! WinguestEvtDestroyCallback not called at PASSIVE_LEVEL !!!");
    }

    fdoData = WinguestFdoGetData(Object);
    if (NULL != fdoData && NULL != fdoData->CallbackObjectHandle)
    {
        ExUnregisterCallback(fdoData->CallbackObjectHandle);
        fdoData->CallbackObjectHandle = NULL;
    }
    if (NULL != fdoData && NULL != fdoData->CallbackObject)
    {
        ObDereferenceObject(fdoData->CallbackObject);
        fdoData->CallbackObject = NULL;
    }

    LogVerbose("Uninitializing user-mode communication\n");
    UninitUmlibComm();

    LogVerbose("Destroy WdfDevice\n");
    gDrv.WdfDevice = NULL;
    gDrv.WdfdeviceCount = 0;
}

/**
 * @brief Exception filter
 *
 * @return EXCEPTION_EXECUTE_HANDLER
 */
int
WinguestExceptionFilter(
    _In_ struct _EXCEPTION_POINTERS *ep,
    _In_ PCHAR File,
    _In_ DWORD Line
    )
{
    DWORD i = 0;

    DBG_UNREFERENCED_PARAMETER(ep);

    LogError("\n\n*** EXCEPTION ***\n\nException Information:\nCode    = 0x%08X\nAddress = 0x%08p\nFlags   = 0x%08IX\nNumberParameters = %d\n\nException caught at:\nFile    = %s\nLine    = %d\n\n",
        ep->ExceptionRecord->ExceptionCode,
        ep->ExceptionRecord->ExceptionAddress,
        ep->ExceptionRecord->ExceptionFlags,
        ep->ExceptionRecord->NumberParameters,
        File,
        Line);
    for (i = 0; i < ep->ExceptionRecord->NumberParameters; i++)
    {
        LogError("Parameter%d = 0x%I64X\n", (i+1), ep->ExceptionRecord->ExceptionInformation[i]);
    }
#ifdef _AMD64_
    LogError("\n\n*** DEBUG INFO ***\n RAX = %I64x \n RBX = %I64x \n RCX = %I64x \n RDX = %I64x \n RSI = %I64x\n RDI = %I64x\n RBP = %I64x\n RSP = %I64x\n RIP = %I64x\n R8 = %I64x\n R9 = %I64x\n R10 = %I64x\n R11 = %I64x\n R12 = %I64x\n R13 = %I64x\n R14 = %I64x\n R15 = %I64x\n",
        ep->ContextRecord->Rax,
        ep->ContextRecord->Rbx,
        ep->ContextRecord->Rcx,
        ep->ContextRecord->Rdx,
        ep->ContextRecord->Rsi,
        ep->ContextRecord->Rdi,
        ep->ContextRecord->Rbp,
        ep->ContextRecord->Rsp,
        ep->ContextRecord->Rip,
        ep->ContextRecord->R8,
        ep->ContextRecord->R9,
        ep->ContextRecord->R10,
        ep->ContextRecord->R11,
        ep->ContextRecord->R12,
        ep->ContextRecord->R13,
        ep->ContextRecord->R14,
        ep->ContextRecord->R15
        );
#else
    LogError("\n\n*** DEBUG INFO ***\n EAX = %x \n EBX = %x \n ECX = %x \n EDX = %x \n ESI = %x\n EDI = %x\n EBP = %x\n ESP = %x\n EIP = %x\n",
        ep->ContextRecord->Eax,
        ep->ContextRecord->Ebx,
        ep->ContextRecord->Ecx,
        ep->ContextRecord->Edx,
        ep->ContextRecord->Esi,
        ep->ContextRecord->Edi,
        ep->ContextRecord->Ebp,
        ep->ContextRecord->Esp,
        ep->ContextRecord->Eip
    );
#endif

    return EXCEPTION_EXECUTE_HANDLER;
}

/**
 * @brief Lock the winguest device to block driver unloading
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
WinguestLockDevice(
    void
    )
{
    LONG lockCount = 0;

    lockCount = InterlockedIncrement(&gDrv.DeviceObjectRefCnt);
    LogInfo("winguest.sys locked! LockCount = %d", lockCount);

    if (NULL == gDrv.WdfDeviceRef && NULL != gDrv.WdfDevice)
    {
        WdfObjectReference(gDrv.WdfDevice);
        gDrv.WdfDeviceRef = gDrv.WdfDevice;

        LogInfo("winguest.sys referenced!");
    }
    else if (NULL != gDrv.WdfDeviceRef)
    {
        LogWarning("Device already locked!");
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Unlock the winguest device to allow driver unloading
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
WinguestUnlockDevice(
    void
    )
{
    LONG lockCount = InterlockedDecrement(&gDrv.DeviceObjectRefCnt);

    LogInfo("winguest.sys unlocked! LockCount = %d", lockCount);

#ifdef DEBUG
    if (lockCount < 0)
    {
        __debugbreak();
    }
#endif

    if (0 == lockCount && gDrv.WdfDeviceRef != NULL)
    {
        WdfObjectDereference(gDrv.WdfDeviceRef);
        gDrv.WdfDeviceRef = NULL;

        LogInfo("winguest.sys dereferenced!");
    }
    else if (NULL == gDrv.WdfDeviceRef)
    {
        LogWarning("Cannot unlock device object! Device reference not available!");
    }

    return STATUS_SUCCESS;
}

/**
 * @brief WDF D0 Entry callback
 */
NTSTATUS
WinguestDeviceD0Entry(
    IN WDFDEVICE  Device,
    IN WDF_POWER_DEVICE_STATE  PreviousState
)
{
    UNREFERENCED_PARAMETER((Device, PreviousState));

    NTSTATUS status = STATUS_SUCCESS;

    gDrv.HvSleeping = FALSE;

    if (HVStarted())
    {
        // notify windows of a hypervisor presence
        // we do this because after a resume from sleep windows does not use all guest enlightenments features
        // it will stop using MSR access for EOI and ICR for example
        if (gDrv.WinApis.ZwSetSystemInformation)
        {
            status = gDrv.WinApis.ZwSetSystemInformation(SystemHypervisorInformation, NULL, 0);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwSetSystemInformation");
                status = STATUS_SUCCESS;
            }
        }

         LogInfo("Interrupts enabled -> initialize communication with HV");
         status = HVCommConnectHv();
         if (!NT_SUCCESS(status))
         {
             if (status != STATUS_WG_ALREADY_INITIALIZED)
             {
                 LogFuncErrorStatus(status, "HVCommConnectHv");
             }
             else
             {
                 LogInfo("HV comm already initialized!");
                 status = STATUS_SUCCESS;
             }
         }
    }

    gDrv.HvSleeping = FALSE;

    return STATUS_SUCCESS;
}

/**
 * @brief WDF D0 Exit callback
 */
NTSTATUS
WinguestDeviceD0Exit(
    IN WDFDEVICE  Device,
    IN WDF_POWER_DEVICE_STATE  TargetState
    )
{
    UNREFERENCED_PARAMETER((Device, TargetState));

    NTSTATUS status;

    gDrv.HvSleeping = TRUE;

    LogInfo("Disconnecting winguest...\n");
    status = HVCommDisconnectHv(FALSE);
    if (!NT_SUCCESS(status))
    {
        if (STATUS_ALREADY_DISCONNECTED != status)
        {
            LogFuncErrorStatus(status, "HVCommDisconnectHv");
        }

        status = STATUS_SUCCESS;
    }

//    gDrv.HvSleeping = FALSE;

    return STATUS_SUCCESS;
}

/**
 * @brief Driver reinitialization routine
 *
 * Check if we can access \\SystemRoot\System32\ntdll.dll. If this is accessible, then proceed with initialization,
 * else register a reinitialization routine and return STATUS_SUCCESS. In the latter case main initialization of Winguest will be
 * performed from the reinitialization routine
 */
VOID
WinguestReinitialize(
    _In_ struct _DRIVER_OBJECT *DriverObject,
    _In_opt_ PVOID Context,
    _In_ ULONG Count
    )
{
    LogInfo("Count = %d\n", Count);

    if ((0 != gDrv.ReinitMaxCallCount) && (Count > gDrv.ReinitMaxCallCount))
    {
        LogError("Failed to load driver after %d retries\n", Count);
        return;
    }

    if (FALSE == WinguestIsNtdllAvailable())
    {
        //
        // opening ntdll failed, register a reinitialization routine
        //

        IoRegisterBootDriverReinitialization(DriverObject, WinguestReinitialize, Context);
    }
    else
    {
        //
        // we succeeded in opening ntdll, so we can proceed with Winguest main initialization
        //
        WinguestInitialize(DriverObject);
    }

}

/**
 * @brief Check if ntdll.dll is available
 *
 * @return TRUE                             ntdll.dll available
 * @return FALSE                            ntdll.dll not yet available
 */
BOOLEAN
WinguestIsNtdllAvailable(
    VOID
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING ntdllPath = STATIC_WSTR_TO_UNICODE(L"\\SystemRoot\\system32\\ntdll.dll");
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hNtdll = NULL;
    IO_STATUS_BLOCK ioStatus = { 0 };

    InitializeObjectAttributes(&objAttr, &ntdllPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenFile(&hNtdll, GENERIC_READ, &objAttr, &ioStatus, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        ZwClose(hNtdll);
    }

    return NT_SUCCESS(status);
}
