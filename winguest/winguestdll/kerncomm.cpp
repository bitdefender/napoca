/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file kerncomm.cpp
*   @brief Communication with kernel driver
*/

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "kerncomm.h"
#include "kerncomm_int.h"

#include "cxqueuetypes.h"
#include "cxqueueuser.h"

#include "version.h"
#include "common/kernel/napoca_version.h"
#include "common/kernel/napoca_compatibility.h"

#include "libapis.h"
#include "libapis_int.h"

#include "winguest_status.h"
#include "helpers.h"
#include "trace.h"
#include "kerncomm.tmh"

#define NUMBER_OF_RECEIVING_THREADS     5

BOOLEAN gConnected;
BOOLEAN gDriverIncompatible;
static HANDLE gCommHandle = INVALID_HANDLE_VALUE;

extern BOOLEAN gHypervisorStarted;
extern BOOLEAN gHypervisorConnected;
extern KNOWN_VERSIONS gVersions;

/**
 * @brief Send a message to another compoment (via the winguest driver)
 *
 * This version can bypass connectivity checks. Useful before properly establishing the connection with the driver.
 *
 * @param[in]  CommandId                            Message type
 * @param[in]  Destination                          Component that must receive the message
 * @param[in]  InputBuffer                          Message Input Buffer
 * @param[in]  InputBufferSize                      Size of input message (including common header)
 * @param[out] OutputBuffer                         Buffer where reply message will be stored
 * @param[in]  OutputBufferSize                     Size of reply message buffer (including common header)
 * @param[out] ActualOutputBufferSize               Actual size written to OutputBuffer
 * @param[in]  BypassConnectivityChecks             If full connection should be validated before sending
 *
 * @return STATUS_SUCCESS
 * @return STATUS_USERMODE_DRIVER_NOT_CONNECTED     Not connected to driver
 * @return STATUS_HYPERVISOR_NOT_STARTED            Napoca Hypervisor not started
 * @return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED   Driver not connected to Hypervisor
 * @return OTHER                                    Other potential internal error
 */
static
NTSTATUS
KernCommSendMessageEx(
    _In_ COMMAND_CODE CommandId,
    _In_ COMM_COMPONENT Destination,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize,
    _In_ bool BypassConnectivityChecks
)
{
    NTSTATUS status = STATUS_SUCCESS;

    COMM_MESSAGE *header = (COMM_MESSAGE*)InputBuffer;

    if (!InputBuffer)
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (!BypassConnectivityChecks)
    {
        switch (Destination)
        {
        case TargetWinguestKm:
            if (!gConnected)
                return STATUS_USERMODE_DRIVER_NOT_CONNECTED;
            break;

        case TargetNapoca:
            if (!gConnected)
                return STATUS_USERMODE_DRIVER_NOT_CONNECTED;
            if (!gHypervisorStarted)
                return STATUS_HYPERVISOR_NOT_STARTED;
            if (!gHypervisorConnected)
                return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            break;

        case TargetWinguestUm:
            return STATUS_INVALID_PARAMETER_2;

        case TargetAny:
        default:
            break;
        }
    }

    header->CommandCode = CommandId;
    header->Size = InputBufferSize;
    header->DstComponent = Destination;
    header->SrcComponent = TargetWinguestUm;
    header->ProcessingStatus = STATUS_UNSUCCESSFUL;

    status = CommSendQueueDataU(
        gCommHandle,
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        ActualOutputBufferSize
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "CommSendQueueDataU");
    }

    return status;
}

/**
 * @brief Send a message to another compoment (via the winguest driver)
 *
 * @param[in]  CommandId                            Message type
 * @param[in]  Destination                          Component that must receive the message
 * @param[in]  InputBuffer                          Message Input Buffer
 * @param[in]  InputBufferSize                      Size of input message (including common header)
 * @param[out] OutputBuffer                         Buffer where reply message will be stored
 * @param[in]  OutputBufferSize                     Size of reply message buffer (including common header)
 * @param[out] ActualOutputBufferSize               Actual size written to OutputBuffer
  *
 * @return STATUS_SUCCESS
 * @return STATUS_USERMODE_DRIVER_NOT_CONNECTED     Not connected to driver
 * @return STATUS_HYPERVISOR_NOT_STARTED            Napoca Hypervisor not started
 * @return STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED   Driver not connected to Hypervisor
 * @return OTHER                                    Other potential internal error
 */
NTSTATUS
KernCommSendMessage(
    _In_ COMMAND_CODE CommandId,
    _In_ COMM_COMPONENT Destination,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize
)
{
    return KernCommSendMessageEx(
        CommandId,
        Destination,
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        ActualOutputBufferSize,
        false
    );
}

/**
 * @brief Initialize communication with kernel driver
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
KernCommInit(
    void
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    COMM_INIT_DATA_U initData = { 0 };
    CMD_COMMAND_THREAD_COUNT threadCountCmd = { 0 };
    DWORD returnedBytes = 0;
    CMD_CHECK_COMPATIBILITY checkCompat = { 0 };
    DWORD returned = 0;
    NAPOCA_VERSION reqVer = { 0 };

    __try
    {
        initData.Version = 1;
        initData.Flags = 0;
        initData.ThreadCount = NUMBER_OF_RECEIVING_THREADS;
        initData.Name = L"\\\\.\\WinguestComm";

        initData.Alloc = NULL;
        initData.Free = NULL;

        // some custom callbacks here
        initData.CommClientConnected = KernCommNewClientConnected;
        initData.CommClientDisconnected = KernCommClientDisconnected;
        initData.CommReceiveDataU = KernCommReceiveMessage;

        status = CommInitializeCommunicationU(&initData, &gCommHandle);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommInitializeCommunicationU");
            __leave;
        }

        //
        // Versioning
        //
        checkCompat.Version.High     = WINGUESTDLL_VERSION_HIGH;
        checkCompat.Version.Low      = WINGUESTDLL_VERSION_LOW;
        checkCompat.Version.Revision = WINGUESTDLL_VERSION_REVISION;
        checkCompat.Version.Build    = WINGUESTDLL_VERSION_BUILD;

        status = KernCommSendMessageEx(
            cmdUmCheckCompatWithDrv,
            TargetWinguestKm,
            &checkCompat,
            sizeof(checkCompat),
            &checkCompat,
            sizeof(checkCompat),
            &returned,
            true
        );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessageEx");
            __leave;
        }

        LogInfo("Found WINGUEST.SYS %d.%d.%d.%d\n",
            checkCompat.Version.High, checkCompat.Version.Low, checkCompat.Version.Revision, checkCompat.Version.Build);

        gVersions.WinguestSys = *(NAPOCA_VERSION *)&checkCompat.Version;
        gVersions.WinguestDllRequiredByWinguestSys = *(NAPOCA_VERSION *)&checkCompat.CompatVersion;

        if (!NT_SUCCESS(checkCompat.Command.ProcessingStatus))
        {
            LogError("WINGUEST.DLL %d.%d.%d.%d is not compatible with WINGUEST.SYS which requires %d.%d.%d.%d\n",
                WINGUESTDLL_VERSION_HIGH, WINGUESTDLL_VERSION_LOW, WINGUESTDLL_VERSION_REVISION, WINGUESTDLL_VERSION_BUILD,
                checkCompat.Version.High, checkCompat.Version.Low, checkCompat.Version.Revision, checkCompat.Version.Build
                );

            gDriverIncompatible = TRUE;
            status = STATUS_VERSION_INCOMPATIBLE;
            __leave;
        }

        MakeVersion(&reqVer, WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL);

        status = CheckCompatibility((NAPOCA_VERSION *)&checkCompat.Version, &reqVer);
        if (!NT_SUCCESS(status))
        {
            LogError("WINGUEST.SYS is not compatible with WINGUEST.DLL which requires %d.%d.%d.%d\n",
                WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL_MJ, WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL_MN, WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL_REV, WINGUESTSYS_VERSION_REQUIRED_BY_WINGUESTDLL_BLD
                );

            gDriverIncompatible = TRUE;
            status = STATUS_VERSION_INCOMPATIBLE;
            __leave;
        }

        LogInfo("WINGUEST.SYS compatible with WINGUEST.DLL %d.%d.%d.%d\n",
                WINGUESTDLL_VERSION_HIGH, WINGUESTDLL_VERSION_LOW, WINGUESTDLL_VERSION_REVISION, WINGUESTDLL_VERSION_BUILD);

        gDriverIncompatible = FALSE;

        //
        // Send number of threads
        //
        threadCountCmd.ThreadCount = NUMBER_OF_RECEIVING_THREADS;

        status = KernCommSendMessageEx(
            cmdCommandThreadCount,
            TargetWinguestKm,
            &threadCountCmd,
            sizeof(threadCountCmd),
            &threadCountCmd,
            sizeof(threadCountCmd),
            &returnedBytes,
            true
            );
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "KernCommSendMessageEx");
            __leave;
        }

        status = threadCountCmd.Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdCommandThreadCount");
            __leave;
        }

        status = InitMessageConsumers();
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "InitMessageConsumers");
            __leave;
        }

        gConnected = TRUE;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            UninitMessageConsumers();

            if (gCommHandle != INVALID_HANDLE_VALUE)
            {
                CommUninitializeCommunicationU(gCommHandle);
                gCommHandle = INVALID_HANDLE_VALUE;
            }
        }
    }

    return status;
}

/**
 * @brief Uninitialize communication with kernel driver
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
KernCommUninit(
    void
    )
{
    if (!gConnected)
        return STATUS_SUCCESS;

    gConnected = FALSE;
    gDriverIncompatible = FALSE;

    gVersions = { 0 };

    UninitMessageConsumers();

    NTSTATUS status = CommUninitializeCommunicationU(gCommHandle);
    gCommHandle = INVALID_HANDLE_VALUE;

    return status;
}

/**
 * @brief Callback that receives messages from the driver
 *
 * @param[in]  Client                               Handle that identifies the connected client
 * @param[in]  InputBuffer                          Message Input Buffer
 * @param[in]  InputBufferLength                    Size of input message (including common header)
 * @param[out] OutputBuffer                         Buffer where reply message will be stored
 * @param[in]  OutputBufferLength                   Size of reply message buffer (including common header)
 * @param[out] BytesReturned                        Actual size written to OutputBuffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
KernCommReceiveMessage(
    _In_ HANDLE Client,
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,           // this includes the size of any msg header
    _Out_opt_ PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_opt_ DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_INVALID_MESSAGE;
    PCOMM_MESSAGE command = NULL;
    PCOMM_MESSAGE commandReply = NULL;

    UNREFERENCED_PARAMETER(Client);

    if ((NULL == InputBuffer) || (InputBufferLength < sizeof(COMM_MESSAGE)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // check command
    command = (PCOMM_MESSAGE)InputBuffer;
    commandReply = (PCOMM_MESSAGE) OutputBuffer;

    switch(command->CommandCode)
    {
    case cmdTestComm:
        {
            //PCMD_TEST_COMM testComm = (PCMD_TEST_COMM)commandReply;

            *BytesReturned = OutputBufferLength;
            status = STATUS_SUCCESS;
        }
        break;
    case cmdReportIntrospectionError:
        status = IntrospectionErrorReceive(InputBuffer, InputBufferLength);
        break;
    case cmdSendIntrospectionAlert:
        status = InstrospectionAlertReceive(InputBuffer, InputBufferLength);
        break;
    case cmdSendPowerStateChange:
        status = InternalPowerStateChanged(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, BytesReturned);
        break;
    default:
        LogCritical("Undefined message received, commandCode: %d", command->CommandCode);
        break;
    }

    command->ProcessingStatus = status;

    return STATUS_SUCCESS;
}

/**
 * @brief Callback that notifies that another component connected
 *
 * @param[in] Client                   Value that uniquely identifies the component
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
KernCommNewClientConnected(
    _In_ HANDLE Client
    )
{
    LogVerbose("New client connected -> %I64X\n", (size_t)Client);

    return STATUS_SUCCESS;
}

/**
 * @brief Callback that notifies that another component disconnected
 *
 * @param[in] Client                   Value that uniquely identifies the component
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
KernCommClientDisconnected(
    _In_ HANDLE Client
    )
{
    LogVerbose("Client disconnected -> %I64X\n", (size_t)Client);

    return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
/// Specific communication
//////////////////////////////////////////////////////////////////////////

/**
 * @brief Retrieve the values of registers CR0 and CR4 from KM/HV
 *
 * @param[out] Cr0                  Value of CR0
 * @param[out] Cr4                  Value of CR4
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
GetHostCpuCrValues(
    __inout QWORD* Cr0,
    __inout QWORD* Cr4
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CMD_GET_CR_VALUES cmd = {0};
    DWORD bytesReturned = 0;

    if (NULL == Cr0)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Cr4)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    __try
    {
        // try to ask the HV. If not available or failed, ask the driver
        for (int target = gHypervisorConnected ? 0 : 1; target <= 1; target++) // possible improvement: could simply forward to driver and decide there if it can be serviced by the HV (it gets sent there anyway sometimes twice!)
        {
            status = KernCommSendMessage(
                cmdGetHostCrValues,
                target == 0 ? TargetNapoca : TargetWinguestKm,  // First try to ask the HV, then the driver
                &cmd,
                sizeof(cmd),
                &cmd,
                sizeof(cmd),
                &bytesReturned
                );
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "KernCommSendMessage");
            }

            status = cmd.Command.ProcessingStatus;
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "cmdGetHostCrValues");
            }

            if (NT_SUCCESS(status))
                break;
        }

        if (NT_SUCCESS(status))
        {
            *Cr0 = cmd.Cr0;
            *Cr4 = cmd.Cr4;
        }
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Retrieve processor information from KM/HV
 *
 * @param[out] CpuEntry                 Processor information
 * @param[out] VirtFeatures             Processor virtualization support
 * @param[out] SmxCapabilities          Processor SMX support
 *
 * @return STATUS_SUCCESS
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
GetHostCpuAndVirtFeatures(
    __inout CPU_ENTRY *CpuEntry,
    __inout VIRTUALIZATION_FEATURES *VirtFeatures,
    __inout SMX_CAPABILITIES *SmxCapabilities
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CMD_GET_CPU_SMX_VIRT_FEATURES cmd = {0};
    DWORD bytesReturned = 0;

    if (NULL == CpuEntry)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == VirtFeatures)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == SmxCapabilities)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    __try
    {
        // try to ask the HV. If not available or failed, ask the driver
        for (int target = gHypervisorConnected ? 0 : 1; target <= 1; target++) // possible improvement: simply forward to driver and decide there if it can be serviced by the HV (it gets sent there anyway sometimes twice!)
        {
            status = KernCommSendMessage(
                cmdGetCpuSmxAndVirtFeat,
                target == 0 ? TargetNapoca : TargetWinguestKm,  // First try to ask the HV, then the driver
                &cmd,
                sizeof(cmd),
                &cmd,
                sizeof(cmd),
                &bytesReturned
            );
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "KernCommSendMessage");
            }

            status = cmd.Command.ProcessingStatus;
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "cmdGetCpuSmxAndVirtFeat");
            }

            if (NT_SUCCESS(status))
                break;
        }

        if (NT_SUCCESS(status))
        {
            *CpuEntry = cmd.CpuEntry;
            *VirtFeatures = cmd.VirtFeatures;
            *SmxCapabilities = cmd.SmxCaps;
        }
    }
    __finally
    {
    }

    return status;
}
