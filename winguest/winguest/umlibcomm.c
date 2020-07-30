/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file umlibcomm.c
*   @brief Communication with user mode
*/

#include "winguest_types.h"
#include "umlibcomm.h"
#include "driver.h"
#include "umlibcommands.h"
#include "comm_hv.h"
#include "updates.h"
#include "init.h"
#include "cxqueuetypes.h"
#include "cxqueuekernel.h"
#include "misc_utils.h"
#include "trace.h"
#include "umlibcomm.tmh"

#define UMLIBCOMM_SEND_RETRY_COUNT  10

/**
 * @brief Initialize communication with usermode component
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
InitUmlibComm(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    COMM_INIT_DATA commInitData = { 0 };

    __try
    {
        gDrv.OptCommandTimeout = 10000;        // initialize initial timeout on responses from um (10 seconds)
        gDrv.OptAlertCommandTimeout = 70000;   // alert timeout is 70 seconds

        gDrv.HvUmTimeout.QuadPart = (QWORD)(DELAY_ONE_SECOND * HV_COMM_POOLING_INTERVAL);

        KeInitializeEvent(&gDrv.CommandEvent, NotificationEvent, FALSE);

        commInitData.Version = 1;
        commInitData.Flags = 0;
        commInitData.NativeDeviceName = WINGUEST_DEVICE_NATIVE_NAME;
        commInitData.UserDeviceName = WINGUEST_DEVICE_USER_NAME;

        commInitData.CommClientConnected = UmLibCommNewClientConnected;
        commInitData.CommClientDisconnected = UmLibCommClientDisconnected;
        commInitData.CommReceiveData = UmLibCommReceiveMessage;
        commInitData.CommReceiveDataInternal = NULL;

        status = CommInitializeQueueCommunication(gDrv.WdfDriver, &commInitData);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommInitializeQueueCommunication");
            __leave;
        }

        LogInfo("Communication initialized");
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Uninitialize communication with usermode component
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
UninitUmlibComm(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    __try
    {
        status = CommUninitializeQueueCommunication();
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommUninitializeQueueCommunication");
            __leave;
        }

        LogInfo("Communication uninitialized");
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Callback that receives messages from user mode. This routine acts as a dispatcher that calls appropriate message handlers
 *
 * @param[in]  WdfFileObject            WDF File Object (unreferenced)
 * @param[in]  InputBuffer              Message Input Buffer
 * @param[in]  InputBufferLength        Size of input message (including common header)
 * @param[in]  OutputBuffer             Buffer where reply message will be stored. Must be the same as InputBuffer
 * @param[in]  OutputBufferLength       Size of reply message buffer (including common header)
 * @param[out] BytesReturned            Actual size written to OutputBuffer
 *
 * @return STATUS_SUCCESS
 * @return STATUS_NOT_SUPPORTED                     Received an invalid message
 * @return STATUS_INSUFFICIENT_RESOURCES            Insufficient resources available to process request
 * @return STATUS_HYPERVISOR_NOT_STARTED            Hypervisor is not started
 * @return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED   Driver not connected to the hypervisor
 * @return STATUS_NOT_IMPLEMENTED                   Received unknown message type
 * @return OTHER                                    Other potential internal error
 */
NTSTATUS
UmLibCommReceiveMessage(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferLength,          // this includes the size of any msg header
    _Out_opt_ PVOID OutputBuffer,
    _In_opt_ UINT32 OutputBufferLength,
    _Out_ UINT32* BytesReturned
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCOMM_MESSAGE header = (PCOMM_MESSAGE)InputBuffer;
    COMM_COMPONENT dstComponent = 0;

    UNREFERENCED_PARAMETER(WdfFileObject);

    if ((NULL == InputBuffer) || (InputBufferLength < sizeof(COMM_MESSAGE)))
    {
        LogError("Invalid input buffer, length = %d\n", InputBufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    dstComponent = (header->CommandCode & MSG_TARGET_MASK) == MSG_TARGET_ANY
        ? header->DstComponent
        : MESSAGE_TO_TARGET(header->CommandCode);

    if (MSG_TARGET_ANY == dstComponent || 0 == dstComponent)
    {
        LogCritical("Invalid message received from User-Mode 0x%08X - unsupported MSG_TARGET_ANY from UM\n", header->CommandCode);

        return STATUS_NOT_SUPPORTED;
    }

    if (TargetWinguestKm != dstComponent)
    {
        // forward the message - not for us

        __try
        {
            if (NULL != OutputBuffer && (OutputBuffer != InputBuffer || OutputBufferLength != InputBufferLength))
            {
                LogError("Messages for NAPOCA from UM cannot have different InputBuffer and OutputBuffer\n");
#ifdef DEBUG
                __debugbreak();
#endif
                status = STATUS_NOT_SUPPORTED;
                __leave;
            }

            if (InputBufferLength < sizeof(COMM_MESSAGE))
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            if (HVStarted() == FALSE)
            {
                status = STATUS_HYPERVISOR_NOT_STARTED;
                __leave;
            }

            if (gDrv.HvCommConnected == FALSE)
            {
                status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                __leave;
            }

            if (gDrv.HvSleeping
                && (header->CommandCode == OPT_REM_ALL_PROTECTED_PROCESSES
                || header->CommandCode == OPT_FLUSH_EXCEPTIONS_FROM_ALERTS
                || header->CommandCode == cmdAddExceptionFromAlert
                || header->CommandCode == cmdSetProtectedProcess
                || header->CommandCode == cmdUpdateComponent))
            {
                LogWarning("Dropping message to HV because the machine is powering down");

                header->ProcessingStatus = STATUS_POWER_STATE_INVALID;
                *BytesReturned = OutputBufferLength;

                status = STATUS_SUCCESS;
                __leave;
            }

            if (dstComponent == TargetNapoca
                && header->CommandCode == cmdFastOpt)
            {
                CMD_FAST_OPTION *fastOpt = (CMD_FAST_OPTION *)InputBuffer;

                header->ProcessingStatus = HvVmcallSafe(fastOpt->MsgId,
                    (SIZE_T)fastOpt->Param1, (SIZE_T)fastOpt->Param2, (SIZE_T)fastOpt->Param3, (SIZE_T)fastOpt->Param4,
                    (SIZE_T *)&fastOpt->OutParam1, (SIZE_T *)&fastOpt->OutParam2, (SIZE_T *)&fastOpt->OutParam2, (SIZE_T *)&fastOpt->OutParam2);

                *BytesReturned = sizeof(CMD_FAST_OPTION);
                status = STATUS_SUCCESS;
            }
            else
            {
                status = HVCommForwardMessage(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, (DWORD*)BytesReturned);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "HVCommForwardMessage");
                    __leave;
                }
            }

            if (header->CommandCode == cmdGetCpuSmxAndVirtFeat)
            {
                PCMD_GET_CPU_SMX_VIRT_FEATURES pFeat = (PCMD_GET_CPU_SMX_VIRT_FEATURES)(InputBuffer);

                status = pFeat->Command.ProcessingStatus;
                if (NT_SUCCESS(status))
                {
                    gDrv.CpuEntry = pFeat->CpuEntry;
                    gDrv.VirtualizationFeatures = pFeat->VirtFeatures;
                    gDrv.SmxCaps = pFeat->SmxCaps;
                }
            }
        }
        __finally
        {
        }

        return STATUS_SUCCESS;
    }

    switch (header->CommandCode)
    {
        case cmdTestComm:
            status = STATUS_SUCCESS;
            *BytesReturned = OutputBufferLength;
            break;

        case cmdGetHvStatus:
            status = UmCmdGetHvStatus(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned);
            break;

        case cmdUmCheckCompatWithDrv:
            status = UmCmdUmCheckCompatibilityWithDrv(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned);
            break;

        case cmdCommandThreadCount:
            status = UmCmdCommandThreadCount(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdGetCpuSmxAndVirtFeat:
            status = UmCmdGetCpuSmxAndVirtFeatures(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdGetHostCrValues:
            status = UmCmdGetCrValues(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdGetComponentVersion:
            status = UmCmdGetComponentVersion(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdGetCompatibility:
            status = UmCmdGetCompatibility(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdGetLogs:
            status = UmCmdGetLogs(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdUpdateComponent:
            status = UmCmdUpdateComponent(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

        case cmdQueryComponent:
            status = UmCmdQueryComponent(
                InputBuffer,
                InputBufferLength,
                OutputBuffer,
                OutputBufferLength,
                (DWORD*)BytesReturned
            );
            break;

            /// auto added winguestsys commands here
        default:
            status = STATUS_NOT_IMPLEMENTED;
            *BytesReturned = min(sizeof(COMM_MESSAGE), OutputBufferLength);
            LogCritical("Undefined message received 0x%08X\n", header->CommandCode);
            break;
    }

    if (OutputBuffer) ((PCOMM_MESSAGE)OutputBuffer)->ProcessingStatus = status;

    return STATUS_SUCCESS;
}


/**
 * @brief Callback that notifies that a user mode component connected
 *
 * @param[in]  WdfFileObject            WDF File Object
 * @param[in]  ProcessId                PID of connected process (unreferenced)
 *
 * @return STATUS_NOT_SUPPORTED         Another connection already active
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
UmLibCommNewClientConnected(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ ULONG ProcessId
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ProcessId);

    if (_InterlockedCompareExchange8(&gDrv.ClientConnected, TRUE, FALSE))
    {
        return STATUS_NOT_SUPPORTED;
    }

    WinguestLockDevice();

    KeAcquireGuardedMutex(&gDrv.CommandLock);
    gDrv.WdfFileObject = WdfFileObject;
    gDrv.CommandProcessId = PsGetCurrentProcessId();
    gDrv.ClientConnected = TRUE;
    KeReleaseGuardedMutex(&gDrv.CommandLock);
    LogInfo("New client connected");

    status = WinguestDelayedInitialization();

    if (NT_SUCCESS(status))
    {
        gDrv.HvUmTimeout.QuadPart = (QWORD)(DELAY_ONE_MICROSECOND * HV_COMM_POOLING_INTERVAL);

        // notify HV communication thread that a new client is connected
        KeSetEvent(&gDrv.HvEventThreadWorkUm, IO_NO_INCREMENT, FALSE);
    }

    return status;
}

/**
 * @brief Callback that notifies that a user mode component disconnected
 *
 * @param[in]  WdfFileObject            WDF File Object (unreferenced)
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
UmLibCommClientDisconnected(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject
    )
{
    LogInfo("Client disconnected");

    UNREFERENCED_PARAMETER(WdfFileObject);

    // set command thread count limit to 0
    KeAcquireGuardedMutex(&gDrv.CommandLock);
    gDrv.CommandCountLimit = 0;
    gDrv.ClientConnected = FALSE;
    gDrv.CommandProcessId = 0;
    gDrv.WdfFileObject = NULL;
    KeReleaseGuardedMutex(&gDrv.CommandLock);

    gDrv.HvUmTimeout.QuadPart = (QWORD)(DELAY_ONE_SECOND * HV_COMM_POOLING_INTERVAL);

    WinguestUnlockDevice();

    return STATUS_SUCCESS;
}

/**
 * @brief Send a message to user mode component
 *
 * @param[in]  InputBuffer              Message Input Buffer
 * @param[in]  InputBufferLength        Size of input message (including common header)
 * @param[in]  OutputBuffer             Buffer where reply message will be stored
 * @param[in]  OutputBufferLength       Size of reply message buffer (including common header)
 * @param[out] BytesReturned            Actual size written to OutputBuffer
 *
 * @return STATUS_SUCCESS
 * @return STATUS_USERMODE_DRIVER_NOT_CONNECTED     Not connected to user mode
 * @return STATUS_NOT_SUPPORTED                     No threads available to process message
 * @return OTHER                                    Other potential internal error
 */
NTSTATUS
UmLibCommSendMessage(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    QWORD timeout = 0;
    BOOLEAN messageIsAlert = FALSE;     // if true, the timeout will be of 60 seconds, instead of 10
    PCOMM_MESSAGE cmd = (PCOMM_MESSAGE)InputBuffer;

    if (InputBufferLength < sizeof(COMM_MESSAGE))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if ((cmd->CommandCode == cmdReportIntrospectionError) || (cmd->CommandCode == cmdSendIntrospectionAlert))
    {
        messageIsAlert = TRUE;          // for alert messages, use a longer timeout
    }

    //
    // try to send notify process command
    //
    for (;;)
    {
        KeAcquireGuardedMutex(&gDrv.CommandLock);

        // if we have no threads listening return
        if (0 == gDrv.CommandCountLimit)
        {
            LogError("No threads to process the message in user mode (user mode client may be disconnected?)\n");
            KeReleaseGuardedMutex(&gDrv.CommandLock);
            return STATUS_USERMODE_DRIVER_NOT_CONNECTED;
        }

        // can we proceed with command now?
        if (gDrv.CommandActiveCount < gDrv.CommandCountLimit)
        {
            DWORD i;

            gDrv.CommandActiveCount++;

            KeReleaseGuardedMutex(&gDrv.CommandLock);

            // we can send the command now

            // set timeout in milliseconds
            timeout = (messageIsAlert ? gDrv.OptAlertCommandTimeout : gDrv.OptCommandTimeout) * DELAY_ONE_MILLISECOND;

            status = STATUS_THREAD_IS_TERMINATING;

            for (i = 0; (i < UMLIBCOMM_SEND_RETRY_COUNT) && (status == STATUS_NO_MORE_ENTRIES || status == STATUS_THREAD_IS_TERMINATING); i++)
            {
                if (i > 0)
                {
                    LARGE_INTEGER localTimeout;
                    localTimeout.QuadPart = (DELAY_ONE_MILLISECOND * 50 * i);      // each time waits more, from 50 to 500ms
                    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
                    KeDelayExecutionThread(KernelMode, FALSE, &localTimeout);
                }

                // send message and wait for reply
                status = CommSendQueueData(
                    gDrv.WdfFileObject,
                    InputBuffer,
                    (UINT32)InputBufferLength,
                    OutputBuffer,
                    (UINT32)OutputBufferLength,
                    (PUINT32)BytesReturned,
                    timeout
                    );
                if (STATUS_NO_MORE_ENTRIES == status)
                {
                    LogError("CommSendQueueData failed with STATUS_NO_MORE_ENTRIES, i=%d, msgType=%d\n", i, ((PCOMM_MESSAGE)InputBuffer)->CommandCode);
                }
            }

            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "CommSendQueueData");
            }

            // decrement active count and wake up any waiting requests
            KeAcquireGuardedMutex(&gDrv.CommandLock);
            gDrv.CommandActiveCount--;
            KeSetEvent(&gDrv.CommandEvent, 0, FALSE);
            KeReleaseGuardedMutex(&gDrv.CommandLock);

            break;

        }
        // if not, we shall wait (or check for zero limit)
        else
        {
            DWORD limit = gDrv.CommandCountLimit;

            KeResetEvent(&gDrv.CommandEvent);
            KeReleaseGuardedMutex(&gDrv.CommandLock);

            if (0 == limit)
            {
                LogError("gDrv.CommandCountLimit has become 0\n");
                status = STATUS_NOT_SUPPORTED;
                break;
            }

            // wait until somebody finishes and triggers a wake-up
            status = KeWaitForSingleObject(&gDrv.CommandEvent, Executive, KernelMode, FALSE, NULL);
            if (status != STATUS_SUCCESS)
            {
                LogFuncErrorStatus(status, "KeWaitForSingleObject");
                break;
            }
        }
    } // end while

    return status;
}