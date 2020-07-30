/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file comm_hv.c
*   @brief Communication with hypervisor
*/

#include "winguest_types.h"
#include "comm_hv.h"
#include "driver.h"
#include "memory.h"
#include "umlibcomm.h"
#include "comm_hv.h"

#include "common/kernel/napoca_compatibility.h"
#include "common/kernel/napoca_version.h"
#include "trace.h"
#include "comm_hv.tmh"

NTSTATUS
HvCommReceiveMessage(
    PCOMM_MESSAGE InputBuffer
);

/**
 * @brief Perform a VMCALL operation to send the hypervisor a message and catch cpu exceptions if any
 *
 * This performs calls the hypervisor with the NAPOCA HV standard message format described at #HvVmcall
 *
 * @param[in]  MessageType      Type of message being sent
 * @param[in]  Param1           1st Input parameter
 * @param[in]  Param2           2nd Input parameter
 * @param[in]  Param3           3rd Input parameter
 * @param[in]  Param4           4th Input parameter
 * @param[out] OutParam1        1st Output parameter
 * @param[out] OutParam2        2nd Output parameter
 * @param[out] OutParam3        3rd Output parameter
 * @param[out] OutParam4        4th Output parameter
 *
 * @return STATUS_HYPERVISOR_NOT_STARTED    Napoca HV is not currently running
 * @return OTHER                            The status returned by the Hypervisor after processing the message
 */
NTSTATUS
HvVmcallSafe(
    _In_ SIZE_T MessageType,
    _In_ SIZE_T Param1,
    _In_ SIZE_T Param2,
    _In_ SIZE_T Param3,
    _In_ SIZE_T Param4,
    _Out_opt_ SIZE_T* OutParam1,
    _Out_opt_ SIZE_T* OutParam2,
    _Out_opt_ SIZE_T* OutParam3,
    _Out_opt_ SIZE_T* OutParam4
)
{
    NTSTATUS status = STATUS_HYPERVISOR_NOT_STARTED;

    __try
    {
        if (gDrv.HypervisorStarted)
        {
            status = HvVmcall(MessageType,
                Param1, Param2, Param3, Param4,
                (CX_SIZE_T*)OutParam1, (CX_SIZE_T*)OutParam2, (CX_SIZE_T*)OutParam3, (CX_SIZE_T*)OutParam4);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return status;
}

NTSTATUS
HVCommDisconnectHvInternal(
    _In_ BOOLEAN WaitForQueueToBeEmpty
    );

/**
 * @brief Check if Napoca HV is currently running
 *
 * @return TRUE             Napoca HV is running
 * @return FALSE            Napoca HV is not running
 */
BOOLEAN
HVStarted(
    void
)
{
    SIZE_T result = 0;

    __try
    {
        HvVmcall(VMCALL_GUEST_CHECK_HV,
            0, 0, 0, 0,
            (CX_SIZE_T*)&result, NULL, NULL, NULL);

        gDrv.HypervisorStarted = (VMCALL_RESPONSE_CHECK_HV == result);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        gDrv.HypervisorStarted = FALSE;
    }

    return gDrv.HypervisorStarted;
}

/**
 * @brief Initialize the Hypervisor communication
 *
 * Allocate resources and set default values
 *
 * @return STATUS_SUCCESS   Hypervisor communication initialized successfully
 */
NTSTATUS
HVCommInit(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gDrv.HvCommInitialized) return STATUS_ALREADY_INITIALIZED;

    __try
    {
        KeInitializeEvent(&gDrv.HvEventThreadFinish, SynchronizationEvent, FALSE);
        KeInitializeEvent(&gDrv.HvEventThreadWork, SynchronizationEvent, FALSE);

        KeInitializeEvent(&gDrv.HvEventThreadFinishUm, SynchronizationEvent, FALSE);
        KeInitializeEvent(&gDrv.HvEventThreadWorkUm, SynchronizationEvent, FALSE);

        gDrv.HvCommInitialized = TRUE;
        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Uninitialize the Hypervisor communication
 *
 * Free resources and set default values
 *
 * @return STATUS_SUCCESS   Hypervisor communication uninitialized successfully
 */
NTSTATUS
HVCommUninit(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!gDrv.HvCommInitialized) return STATUS_WG_NOT_INITIALIZED;

    if (gDrv.HvCommConnected)
        HVCommDisconnectHv(FALSE);

    gDrv.HvCommInitialized = FALSE;

    return status;
}

/**
 * @brief Get the Physical Address where the Hypervisor Log is stored
 *
 * Used for debugging purposes
 *
 * @param[out] Address      Physical Address where the log is stored
 * @param[out] Size         Size of the log
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GetHvLogPhysicalAddress(
    _Out_ QWORD *Address,
    _Out_ DWORD *Size
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN lockAcquired = FALSE;
    PCMD_GET_LOGS hvcmd = NULL;

    __try
    {
        if (gDrv.HvCommConnected == FALSE)
        {
            status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            __leave;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        status = CommAllocMessage(gDrv.SharedHvMem, cmdGetLogsHv, 0, TargetNapoca, TargetWinguestKm, (DWORD)sizeof(CMD_GET_LOGS), (PCOMM_MESSAGE*)&hvcmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        hvcmd->Type = logHvPhysAddr;

        status = CommSendMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)hvcmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        status = hvcmd->Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdGetLogsHv");
            __leave;
        }

        *Address = hvcmd->PhysicalAddress;
        *Size = hvcmd->PhysicalSize;
    }
    __finally
    {
        if (NULL != hvcmd)
        {
            CommFreeMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)hvcmd);
        }

        if (lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }
    }

    return status;
}

/**
 * @brief Thread that consumes messages from the Hypervisor that must be processed by the driver
 *
 * After starting, it continuously waits for messages and processes them. In order to stop the thread HvEventThreadFinish must be signaled.
 *
 * @param[in] Context       Argument received by the thread (currently unused)
 */
VOID
WinguestEvtWorkerThread(
    _In_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    NTSTATUS status;
    PVOID objects[2] = {&gDrv.HvEventThreadFinish, &gDrv.HvEventThreadWork};

    PCOMM_MESSAGE msg = NULL;
    PCOMM_MESSAGE msgShadow = NULL;
    BOOLEAN bIsReply = FALSE;
    BOOLEAN lockAcquired = FALSE;
    LARGE_INTEGER timeout = { 0 };

    timeout.QuadPart = (QWORD)(DELAY_ONE_MICROSECOND * HV_COMM_POOLING_INTERVAL);

    for (;;)
    {
        // wait for work to do, or for stop events to be signaled
        status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, &timeout, NULL);
        if (status == STATUS_WAIT_0)
        {
            // the stop event has been signaled, we need to stop
            LogVerbose("Stopping WinguestEvtWorkerThread thread because stop event is set\n");
            break;
        }
        else if ((status == STATUS_WAIT_1) || (status == STATUS_TIMEOUT))
        {
            // the timeout expired, so test the interrupt set bit
            if ((status == STATUS_TIMEOUT) &&
                (!gDrv.HvCommConnected || (0 == InterlockedBitTestAndReset((LONG *)&gDrv.SharedHvMem->GuestICR, TargetWinguestKm))))
            {
                continue;
            }
            //
            // the work event has been signaled, process the messages
            //

            __try
            {
                for (;;)
                {
                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    KeEnterCriticalRegion();
                    ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
                    lockAcquired = TRUE;

                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    status = CommGetNextMessage(gDrv.SharedHvMem, TargetWinguestKm, &msg);
                    if (!NT_SUCCESS(status))
                    {
                        if (status != CX_STATUS_DATA_NOT_FOUND) LogFuncErrorStatus(status, "CommGetNextMessage");
                        break;
                    }

                    if (NULL == msg)
                    {
                        break;
                    }

                    msgShadow = ExAllocatePoolWithTag(NonPagedPoolNx, msg->Size, TAG_MSG);
                    if (NULL == msgShadow)
                    {
                        break;
                    }
                    RtlCopyMemory(msgShadow, msg, msg->Size);

                    bIsReply = COMM_IS_REPLY(msg);

                    if (lockAcquired)
                    {
                        // release the lock so the ringbuffer can be uninitialized
                        // while some thread processes the messages
                        ExReleaseResourceLite(&gDrv.HvCommLock);
                        KeLeaveCriticalRegion();
                        lockAcquired = FALSE;
                    }

                    status = HvCommReceiveMessage(msgShadow);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "HvCommReceiveMessage");
                    }

                    // take the lock
                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    KeEnterCriticalRegion();
                    ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
                    lockAcquired = TRUE;

                    // release the lock to allow uninitialization of ringbuffer
                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    // copy the message back to ringbuffer
                    RtlCopyMemory(msg, msgShadow, msg->Size);
                    ExFreePoolWithTagAndNull(&msgShadow, TAG_MSG);

                    if (!bIsReply)
                    {
                        status = CommDoneMessage(gDrv.SharedHvMem, msg);
                        if (!NT_SUCCESS(status))
                        {
                            LogFuncErrorStatus(status, "CommDoneMessage");
                        }
                    }

                    if (lockAcquired)
                    {
                        ExReleaseResourceLite(&gDrv.HvCommLock);
                        KeLeaveCriticalRegion();
                        lockAcquired = FALSE;
                    }
                }
            }
            __finally
            {
                if (lockAcquired)
                {
                    ExReleaseResourceLite(&gDrv.HvCommLock);
                    KeLeaveCriticalRegion();
                    lockAcquired = FALSE;
                }

                if (NULL != msgShadow)
                {
                    ExFreePoolWithTagAndNull(&msgShadow, TAG_MSG);
                }
            }
        }
        else
        {
            // this is an error
            LogFuncErrorStatus(status, "KeWaitForMultipleObjects");
            //break;
        }
    }

    // since this is a system thread, it has to terminate itself
    PsTerminateSystemThread(status);
}

/**
 * @brief Thread that consumes messages from the Hypervisor that must be forwarded to User Mode
 *
 * After starting, it continuously waits for messages and processes them. In order to stop the thread HvEventThreadFinish must be signaled.
 *
 * @param[in] Context       Argument received by the thread (currently unused)
 */
VOID
WinguestEvtWorkerThreadUm(
    _In_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);

    NTSTATUS status;
    PVOID objects[2] = {&gDrv.HvEventThreadFinishUm, &gDrv.HvEventThreadWorkUm};

    PCOMM_MESSAGE msg = NULL;
    PCOMM_MESSAGE msgShadow = NULL;
    BOOLEAN lockAcquired = FALSE;
    BOOLEAN bIsReply = FALSE;
    BOOLEAN clientConnected = FALSE;

    for (;;)
    {
        // wait for work to do, or for stop events to be signaled
        status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, &gDrv.HvUmTimeout, NULL);
        if (status == STATUS_WAIT_0)
        {
            // the stop event has been signaled, we need to stop
            LogVerbose("Stopping WinguestEvtWorkerThread thread because stop event is set\n");
            break;
        }
        else if ((status == STATUS_WAIT_1) || (status == STATUS_TIMEOUT))
        {
            KeAcquireGuardedMutex(&gDrv.CommandLock);
            // in order to send HV messages to UM we must have: 1 connected client and at least one receiving thread
            clientConnected = gDrv.ClientConnected && (0 != gDrv.CommandCountLimit);
            KeReleaseGuardedMutex(&gDrv.CommandLock);

            if (!clientConnected)
            {
                continue;
            }

            if ((status == STATUS_TIMEOUT) &&
                (!gDrv.HvCommConnected || (0 == InterlockedBitTestAndReset((LONG *)&gDrv.SharedHvMem->GuestICR, TargetWinguestUm))))
            {
                continue;
            }
            //
            // the work event has been signaled, process the messages
            //

            __try
            {
                for (;;)
                {
                    KeAcquireGuardedMutex(&gDrv.CommandLock);
                    // in order to send HV messages to UM we must have: 1 connected client and at least one receiving thread
                    clientConnected = gDrv.ClientConnected && (0 != gDrv.CommandCountLimit);
                    KeReleaseGuardedMutex(&gDrv.CommandLock);

                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    KeEnterCriticalRegion();
                    ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
                    lockAcquired = TRUE;

                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    status = CommGetNextMessage(gDrv.SharedHvMem, TargetWinguestUm, &msg);
                    if (!NT_SUCCESS(status))
                    {
                        if (status != CX_STATUS_DATA_NOT_FOUND) LogFuncErrorStatus(status, "CommGetNextMessage");
                        break;
                    }

                    if (NULL == msg)
                    {
                        break;
                    }

                    // in case we don't have any client connected consume the message
                    if (!clientConnected)
                    {
                        bIsReply = COMM_IS_REPLY(msg);

                        if (!bIsReply)
                        {
                            status = CommDoneMessage(gDrv.SharedHvMem, msg);
                            if (!NT_SUCCESS(status))
                            {
                                LogFuncErrorStatus(status, "CommDoneMessage");
                            }
                        }

                        if (lockAcquired)
                        {
                            ExReleaseResourceLite(&gDrv.HvCommLock);
                            KeLeaveCriticalRegion();
                            lockAcquired = FALSE;
                        }

                        status = STATUS_SUCCESS;
                        continue; // go to next message
                    }

                    msgShadow = ExAllocatePoolWithTag(NonPagedPoolNx, msg->Size, TAG_MSG);
                    if (NULL == msgShadow)
                    {
                        break;
                    }
                    RtlCopyMemory(msgShadow, msg, msg->Size);

                    bIsReply = COMM_IS_REPLY(msg);
                    if (lockAcquired)
                    {
                        // release the lock so the ringbuffer can be uninitialized
                        // while some thread processes the messages
                        ExReleaseResourceLite(&gDrv.HvCommLock);
                        KeLeaveCriticalRegion();
                        lockAcquired = FALSE;
                    }

                    status = HvCommReceiveMessage(msgShadow);
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "HvCommReceiveMessage");
                    }

                    // take the lock
                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    KeEnterCriticalRegion();
                    ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
                    lockAcquired = TRUE;

                    // release the lock to allow uninitialization of ringbuffer
                    if (!gDrv.HvCommConnected)
                    {
                        status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                        break;
                    }

                    // copy the message back to ringbuffer
                    RtlCopyMemory(msg, msgShadow, msg->Size);
                    ExFreePoolWithTagAndNull(&msgShadow, TAG_MSG);

                    if (!bIsReply)
                    {
                        status = CommDoneMessage(gDrv.SharedHvMem, msg);
                        if (!NT_SUCCESS(status))
                        {
                            LogFuncErrorStatus(status, "CommDoneMessage");
                        }
                    }

                    if (lockAcquired)
                    {
                        ExReleaseResourceLite(&gDrv.HvCommLock);
                        KeLeaveCriticalRegion();
                        lockAcquired = FALSE;
                    }
                }
            }
            __finally
            {
                if (lockAcquired)
                {
                    ExReleaseResourceLite(&gDrv.HvCommLock);
                    KeLeaveCriticalRegion();
                    lockAcquired = FALSE;
                }

                if (NULL != msgShadow)
                {
                    ExFreePoolWithTagAndNull(&msgShadow, TAG_MSG);
                }
            }
        }
        else
        {
            // this is an error
            LogFuncErrorStatus(status, "KeWaitForMultipleObjects");
            //break;
        }
    }

    // since this is a system thread, it has to terminate itself
    PsTerminateSystemThread(status);
}

/**
 * @brief Connect to the hypervisor in order to be able to exchange messages
 *
 * @return STATUS_SUCCESS
 * @return STATUS_WG_ALREADY_INITIALIZED Connection already established
 * @return STATUS_VERSION_INCOMPATIBLE   Connection cannot be established due to the fact that the hypervisor and driver use incompatible communication interfaces
 */
NTSTATUS
HVCommConnectHv(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PHYSICAL_ADDRESS phys;
    OBJECT_ATTRIBUTES objAttr;
    BOOLEAN lockAcquired = FALSE;
    BOOLEAN connectionMade = FALSE;

    PCMD_CHECK_COMPATIBILITY checkCompat = NULL;
    NAPOCA_VERSION reqVer = {0};

    if (!HVStarted()) return STATUS_HYPERVISOR_NOT_STARTED;
    if (gDrv.HvCommConnected) return STATUS_WG_ALREADY_INITIALIZED;

    __try
    {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        if (gDrv.HvCommConnected)
        {
            status = STATUS_WG_ALREADY_INITIALIZED;
            __leave;
        }

        LogInfo("Initializing WINGUEST -> HV communication\n");

        SIZE_T hvVerHigh = 0, hvVerLow = 0, hvVerRev = 0, hvVerBuild = 0;

        status = HvVmcallSafe(VMCALL_GUEST_GET_HV_VERSION,
            0, 0, 0, 0,
            &hvVerHigh, &hvVerLow, &hvVerRev, &hvVerBuild);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "HvVmcallSafe");
            __leave;
        }

        MakeVersion(&gDrv.NapocaVer, (DWORD)hvVerHigh, (DWORD)hvVerLow, (DWORD)hvVerRev, (DWORD)hvVerBuild);

        LogInfo("Found NAPOCA %d.%d.%d.%d\n",
            gDrv.NapocaVer.High, gDrv.NapocaVer.Low, gDrv.NapocaVer.Revision, gDrv.NapocaVer.Build);

        MakeVersion(&reqVer, NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS);

        status = CheckCompatibility(&gDrv.NapocaVer, &reqVer);
        if (!NT_SUCCESS(status))
        {
            LogError("NAPOCA is not compatible with WINGUEST.SYS which requires: %d.%d.%d.%d\n",
                NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS_MJ, NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS_MN, NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS_REV, NAPOCA_VERSION_REQUIRED_BY_WINGUESTSYS_BLD
            );

            gDrv.HypervisorIncompatible = TRUE;
            status = STATUS_VERSION_INCOMPATIBLE;
            __leave;
        }

        SIZE_T shMemLow = 0, shMemHigh = 0;

        status = HvVmcallSafe(OPT_INIT_GUEST_COMMUNICATION,
            TargetWinguestKm, 0, 0, 0,
            &shMemLow, &shMemHigh, &gDrv.SharedHvMemSize, NULL);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "HvVmcallSafe");
            __leave;
        }

        gDrv.SharedHvMemGPA = shMemLow | ((QWORD)shMemHigh << 32);

        // map returned shared mem
        phys.QuadPart = gDrv.SharedHvMemGPA;
        gDrv.SharedHvMem = MmMapIoSpace(phys, gDrv.SharedHvMemSize, MmCached);
        if (NULL == gDrv.SharedHvMem)
        {
            status = STATUS_INVALID_ADDRESS;
            LogFuncErrorStatus(status, "MmMapIoSpace");
            __leave;
        }

        // at this point winguest is connected to the HV but may not be compatible

        CommUnfreezeSharedMem(gDrv.SharedHvMem);
        gDrv.SharedHvMem->DenyAlloc = 0;

        connectionMade = TRUE;
        status = STATUS_SUCCESS;

        LogInfo("WINGUEST -> HV communication initialized\n");

        LogInfo("Check compatibility with current NAPOCA...\n");
        if (gDrv.SharedHvMem->CommVersion != COMM_HV_GUEST_PROTOCOL_VER)
        {
            LogError("Mismatched ringbuffer version: client has %02X, host has %02X!",
                COMM_HV_GUEST_PROTOCOL_VER, gDrv.SharedHvMem->CommVersion);

            gDrv.HypervisorIncompatible = TRUE;
            memset(&gDrv.WinguestSysRequiredByHv, 0xFF, sizeof(gDrv.WinguestSysRequiredByHv));
            status = STATUS_VERSION_INCOMPATIBLE;
            __leave;
        }

        status = CommAllocMessage(gDrv.SharedHvMem, cmdDriverCheckCompatWithNapoca, 0,
            MESSAGE_TO_TARGET(cmdDriverCheckCompatWithNapoca), TargetWinguestKm, sizeof(CMD_CHECK_COMPATIBILITY), (PCOMM_MESSAGE*)&checkCompat);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        checkCompat->Version.High     = WINGUEST_VERSION_HIGH;
        checkCompat->Version.Low      = WINGUEST_VERSION_LOW;
        checkCompat->Version.Revision = WINGUEST_VERSION_REVISION;
        checkCompat->Version.Build    = WINGUEST_VERSION_BUILD;

        status = CommSendMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)checkCompat);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        gDrv.WinguestSysRequiredByHv = *(NAPOCA_VERSION *)&checkCompat->CompatVersion;

        if (!NT_SUCCESS(checkCompat->Command.ProcessingStatus))
        {
            LogError("WINGUEST.SYS %d.%d.%d.%d is not compatible with NAPOCA which requires %d.%d.%d.%d\n",
                WINGUEST_VERSION_HIGH, WINGUEST_VERSION_LOW, WINGUEST_VERSION_REVISION, WINGUEST_VERSION_BUILD,
                checkCompat->Version.High, checkCompat->Version.Low, checkCompat->Version.Revision, checkCompat->Version.Build
                );

            gDrv.HypervisorIncompatible = TRUE;
            status = STATUS_VERSION_INCOMPATIBLE;
            __leave;
        }

        LogInfo("NAPOCA.BIN compatible with WINGUEST.SYS %d.%d.%d.%d\n",
                WINGUEST_VERSION_HIGH, WINGUEST_VERSION_LOW, WINGUEST_VERSION_REVISION, WINGUEST_VERSION_BUILD);

        gDrv.HypervisorIncompatible = FALSE;
        gDrv.HvCommConnected = TRUE;

        // now that we are connected, request some info from the HV
        {
            SIZE_T bootMode = 0;

            status = HvVmcallSafe(OPT_GET_HV_BOOT_MODE,
                0, 0, 0, 0,
                &bootMode, NULL, NULL, NULL);
            gDrv.HvBootMode = (BOOT_MODE)bootMode;

            QWORD hvLogPhysAddr;
            DWORD hvLogSize;

            status = GetHvLogPhysicalAddress(&hvLogPhysAddr, &hvLogSize);
            if (NT_SUCCESS(status))
            {
                LogInfo("Received hv log: 0x%I64x len: 0x%x", hvLogPhysAddr, hvLogSize);

                if (gDrv.HvLogDrvBuffer && gDrv.HvLogSize != hvLogSize)
                {
                    ExFreePoolWithTagAndNull(&gDrv.HvLogDrvBuffer, TAG_LOG);
                }

                if (gDrv.HvLogVirtualAddr
                    && (gDrv.HvLogPhysicalAddr != hvLogPhysAddr || gDrv.HvLogSize != hvLogSize))
                {
                    MmUnmapIoSpace(gDrv.HvLogVirtualAddr, gDrv.HvLogSize);
                    gDrv.HvLogVirtualAddr = NULL;
                }

                gDrv.HvLogPhysicalAddr = hvLogPhysAddr;
                gDrv.HvLogSize = hvLogSize;

                if (!gDrv.HvLogVirtualAddr)
                {
                    PHYSICAL_ADDRESS logPhysAddr;

                    logPhysAddr.QuadPart = gDrv.HvLogPhysicalAddr;
                    gDrv.HvLogVirtualAddr = MmMapIoSpace(logPhysAddr, gDrv.HvLogSize, MmCached);
                    if (!gDrv.HvLogVirtualAddr)
                    {
                        LogFuncErrorStatus(STATUS_INSUFFICIENT_RESOURCES, "MmMapIoSpace");
                    }
                }

                if (gDrv.HvLogReserveBuffer && !gDrv.HvLogDrvBuffer)
                {
                    gDrv.HvLogDrvBuffer = ExAllocatePoolWithTag(gDrv.DefaultMemPoolType, gDrv.HvLogSize, TAG_LOG);
                    if (!gDrv.HvLogDrvBuffer)
                    {
                        LogFuncErrorStatus(STATUS_INSUFFICIENT_RESOURCES, "ExAllocatePoolWithTag");
                    }
                }
            }
            else
            {
                LogFuncErrorStatus(status, "GetHvLogPhysicalAddress");
            }
        }

        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = PsCreateSystemThread(
            &gDrv.HvCommWorker,
            GENERIC_ALL,
            &objAttr,
            NULL,
            NULL,
            WinguestEvtWorkerThread,
            NULL);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "PsCreateSystemThread");
            __leave;
        }

        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = PsCreateSystemThread(
            &gDrv.HvCommWorkerUm,
            GENERIC_ALL,
            &objAttr,
            NULL,
            NULL,
            WinguestEvtWorkerThreadUm,
            NULL);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "PsCreateSystemThread");
            __leave;
        }

        // set the event
        KeSetEvent(&gDrv.HvEventThreadWork, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&gDrv.HvEventThreadWorkUm, IO_NO_INCREMENT, FALSE);

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (NULL != checkCompat)
        {
            NTSTATUS status2 = STATUS_SUCCESS;

            status2 = CommFreeMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)checkCompat);
            if (!NT_SUCCESS(status2))
            {
                LogFuncErrorStatus(status2, "CommFreeMessage");
            }
        }

        if (lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }

        if (!NT_SUCCESS(status))
        {
            HVCommDisconnectHvInternal(FALSE);
        }
    }

    return status;
}

/**
 * @brief Disconnect from the hypervisor
 *
 * This version can also be used for cleanup as it does not check if the connection is active.
 * The public api is #HVCommDisconnectHv
 *
 * @param[in] WaitForQueueToBeEmpty     If TRUE, will wait for the message queue to empty, otherwise disconnect immediately
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
HVCommDisconnectHvInternal(
    _In_ BOOLEAN WaitForQueueToBeEmpty
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN lockAcquired = FALSE;

    __try
    {
        LogInfo("Uninitializing WINGUEST -> HV communication");


        gDrv.HvCommConnected = FALSE;
        gDrv.HypervisorIncompatible = FALSE;

        KeSetEvent(&gDrv.HvEventThreadFinish, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&gDrv.HvEventThreadFinishUm, IO_NO_INCREMENT, FALSE);

        if (gDrv.HvCommWorker != NULL)
        {
            status = ZwWaitForSingleObject(gDrv.HvCommWorker, FALSE, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwWaitForSingleObject");
            }

            gDrv.HvCommWorker = NULL;
        }

        if (gDrv.HvCommWorkerUm != NULL)
        {
            status = ZwWaitForSingleObject(gDrv.HvCommWorkerUm, FALSE, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwWaitForSingleObject");
            }

            gDrv.HvCommWorkerUm = NULL;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        if (gDrv.SharedHvMem)
        {
            status = CommPrepareUninitSharedMem(gDrv.SharedHvMem, WaitForQueueToBeEmpty);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "CommPrepareUninitSharedMem");
            }

            status = HvVmcallSafe(OPT_UNINIT_GUEST_COMMUNICATION,
                TargetWinguestKm, 0, 0, 0,
                NULL, NULL, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "HvVmCallSafe");
            }

            MmUnmapIoSpace(gDrv.SharedHvMem, gDrv.SharedHvMemSize);
            gDrv.SharedHvMem = NULL;
            gDrv.SharedHvMemGPA = 0;
            gDrv.SharedHvMemSize = 0;
        }

        LogInfo("HV Communication stopped.");
    }
    __finally
    {
        if (lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }
    }

    return status;
}

/**
 * @brief Disconnect from the hypervisor
 *
 * @param[in] WaitForQueueToBeEmpty     If TRUE, will wait for the message queue to empty, otherwise disconnect immediately
 *
 * @return STATUS_SUCCESS
 * @return STATUS_ALREADY_DISCONNECTED  Connection was not active
 */
NTSTATUS
HVCommDisconnectHv(
    _In_ BOOLEAN WaitForQueueToBeEmpty
)
{
    if (!gDrv.HvCommConnected)
    {
        return STATUS_ALREADY_DISCONNECTED;
    }

    return HVCommDisconnectHvInternal(WaitForQueueToBeEmpty);
}

/**
 * @brief Forward messages from User Mode to the Hypervisor
 *
 * @param[in] InputBuffer               Message buffer that will be forwarded
 * @param[in] InputBufferLength         Size of forwarded message (including common header)
 * @param[in] OutputBuffer              Buffer where reply message will be stored. Must be the same as InputBuffer
 * @param[in] OutputBufferLength        Size of reply message buffer (including common header)
 * @param[in] BytesReturned             Number of bytes written to the reply buffer
 *
 * @return STATUS_SUCCESS
 * @return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED   Connection to Hypervisor not active
 * @return STATUS_NOT_SUPPORTED                     Message not intended for the hypervisor or if the InputBuffer and OutputBuffer are not identical
 * @return OTHER                                    Other potential internal error
 */
NTSTATUS
HVCommForwardMessage(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCOMM_MESSAGE umMsg = (PCOMM_MESSAGE)InputBuffer;
    PCOMM_MESSAGE cmd = NULL;
    COMM_COMPONENT dstComponent = 0;
    BOOLEAN lockAcquired = FALSE;

    __try
    {
        if (!gDrv.HvCommConnected)
        {
            status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            __leave;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        if (!gDrv.HvCommConnected)
        {
            status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            __leave;
        }

        if (0 == MESSAGE_TO_TARGET(umMsg->CommandCode))
        {
            LogError("Invalid command code!");
#ifdef DEBUG
            __debugbreak();
#endif
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

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
            status = STATUS_INVALID_BUFFER_SIZE;
            __leave;
        }

        if ((MSG_TARGET_ANY == (MSG_TARGET_MASK & umMsg->CommandCode)))
        {
            dstComponent = ((PCOMM_MESSAGE)InputBuffer)->DstComponent;
        }
        else
        {
            dstComponent = MESSAGE_TO_TARGET(umMsg->CommandCode);
        }

        status = CommAllocMessage(gDrv.SharedHvMem, umMsg->CommandCode,
            dstComponent == TargetNapoca ? 0 : COMM_FLG_EXPECTS_REPLY,
            dstComponent, TargetWinguestKm, InputBufferLength, (PCOMM_MESSAGE*)&cmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        // copy rest of field - don't touch the COMM_MESSAGE header
        RtlCopyMemory((BYTE*)cmd + sizeof(COMM_MESSAGE), (BYTE*)InputBuffer + sizeof(COMM_MESSAGE), InputBufferLength - sizeof(COMM_MESSAGE));

        status = CommSendMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)cmd);
        if (!NT_SUCCESS(status))
        {
            CommFreeMessage(gDrv.SharedHvMem, (PCOMM_MESSAGE)cmd);
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        if (dstComponent != TargetNapoca)
        {
            while (0 == (COMM_FLG_RECEIVED_REPLY & cmd->Flags)) // wait for reply
            {
                // checking if hv communication is being teared down while waiting for this flag
                // if it is we must abort all operations as quickly as possible
                if (!gDrv.HvCommConnected)
                {
                    status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
                    __leave;
                }
            }
        }

        if (0 != OutputBufferLength && NULL != OutputBuffer)
        {
            RtlCopyMemory(OutputBuffer, (BYTE*)cmd, OutputBufferLength);
            if (NULL != BytesReturned)
            {
                *BytesReturned = OutputBufferLength;
            }
        }
    }
    __finally
    {
        if (NULL != cmd)
        {
            status = CommFreeMessage(gDrv.SharedHvMem, cmd);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "CommFreeMessage");
            }
        }

        if (lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }
    }

    return status;
}

/**
 * @brief Common handler/dispatcher for messages that must be consumed in the driver or forwarded to user mode (called on both #WinguestEvtWorkerThread, #WinguestEvtWorkerThreadUm threads)
 *
 * @param[in] InputMessage    Message to be handled
 *
 * @return STATUS_SUCCESS
 * @return STATUS_BUFFER_TOO_SMALL      Message size is smaller than the common header
 * @return STATUS_NOT_IMPLEMENTED       Message type cannot be handled here
 * @return OTHER            Other potential internal error
 */
NTSTATUS
HvCommReceiveMessage(
    PCOMM_MESSAGE InputMessage
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (TargetWinguestKm != InputMessage->DstComponent)
    {
        if (COMM_NEEDS_REPLY(InputMessage))
        {
            PCOMM_MESSAGE msg = NULL;
            DWORD returnedBytes = 0;

            __try
            {
                if (InputMessage->Size < sizeof(COMM_MESSAGE))
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                    __leave;
                }

                msg = ExAllocatePoolWithTag(NonPagedPoolNx, InputMessage->Size, TAG_MSG);
                if (NULL == msg)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    LogFuncErrorStatus(status, "ExAllocatePoolWithTag");
                    __leave;
                }

                RtlCopyMemory(msg, InputMessage, InputMessage->Size);

                status = UmLibCommSendMessage(msg, InputMessage->Size, msg, InputMessage->Size, &returnedBytes);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "UmLibCommSendMessage");
                }
                else if (returnedBytes == InputMessage->Size && InputMessage->Size >= sizeof(COMM_MESSAGE))
                {
                    RtlCopyMemory((BYTE*)InputMessage + sizeof(COMM_MESSAGE), (BYTE*)msg + sizeof(COMM_MESSAGE), InputMessage->Size - sizeof(COMM_MESSAGE));
                    InputMessage->ProcessingStatus = msg->ProcessingStatus;
                }
            }
            __finally
            {
                   if (NULL != msg)
                   {
                       ExFreePoolWithTagAndNull(&msg, TAG_MSG);
                   }
            }

            return status;
        }
        else if (!COMM_IS_REPLY(InputMessage))
        {
            status = UmLibCommSendMessage(InputMessage, InputMessage->Size, NULL, 0, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "UmLibCommSendMessage");
            }

            return status;
        }
        else
        {
            LogCritical("Unhandled message\n");
            return STATUS_NOT_IMPLEMENTED;
        }
    }
    else if (COMM_IS_REPLY(InputMessage))
    {
        InputMessage->Flags |= COMM_FLG_RECEIVED_REPLY;

        return status;
    }

    switch (InputMessage->CommandCode)
    {
    case cmdTestComm:
        {
            PCMD_TEST_COMM testComm = (PCMD_TEST_COMM)InputMessage;

            testComm->Command.ProcessingStatus = STATUS_SUCCESS;
        }
        break;

    default:
        status = STATUS_NOT_IMPLEMENTED;
        LogCritical("Message (0x%08X) not implemented for HV->WINGUEST communication!", InputMessage->CommandCode);
        break;
    }

    return status;
}
