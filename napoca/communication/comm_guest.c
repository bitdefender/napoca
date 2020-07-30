/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "communication/comm_guest.h"
#include "kernel/kernel.h"
#include "communication/guestcommands.h"
#include "common/kernel/napoca_version.h"
#include "common/kernel/napoca_compatibility.h"
#include "apic/ipi.h"
#include "kernel/vcpu.h"
#include "common/kernel/module_updates.h"
#include "version.h"
#include "common/debug/memlog.h"
#include "memory/cachemap.h"
#include "introspection\intromodule.h"


/// @brief Structure containing relevant data for the communication port associated to a component
typedef struct _HV_COMM_PORT {
    LIST_ENTRY ListEntry;           ///< Linked list connecting all the component's communication ports
    COMM_COMPONENT CommComponent;   ///< The ID of the component
    CX_BOOL GuestDataReady;         ///< TRUE if the component is connected, FALSE otherwise
}HV_COMM_PORT;

__declspec(dllexport) NAPOCA_VERSION gNapocaVersion = {NAPOCA_VERSION_MAJOR, NAPOCA_VERSION_MINOR, NAPOCA_VERSION_REVISION, NAPOCA_VERSION_BUILDNUMBER};
__declspec(dllexport) NAPOCA_VERSION gRequiredWinVersion = {WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA};

 /**
  * @brief Wrapper over #CommAllocMessage to be used when a response is not expected
  *
  * @param[in]   CommandCode         Message Type
  * @param[in]   CommandFlags        Shared Memory Message Flags
  * @param[in]   DstComponent        Destination
  * @param[in]   Size                Size of the Message
  * @param[out]  Message             Message
  *
  * @return CX_STATUS_SUCCESS
  * @return CX_STATUS_INSUFFICIENT_RESOURCES     Insufficient free storage available
  * @return CX_STATUS_ACCESS_DENIED              Shared Memory is frozen
  * @return CX_STATUS_NOT_INITIALIZED            Shared Memory not initialized
  * @return CX_STATUS_OPERATION_NOT_SUPPORTED    Shared Memory version mismatch
  * @return OTHER                                Other potential internal error
  */
NTSTATUS
CommPrepareMessage(
    _In_ COMMAND_CODE CommandCode,
    _In_ WORD CommandFlags,
    _In_ COMM_COMPONENT DstComponent,
    _In_ DWORD Size,
    _Out_ PCOMM_MESSAGE *Message
    )
{
    return CommAllocMessage(gHypervisorGlobalData.Comm.SharedMem, CommandCode, CommandFlags, DstComponent, TargetAny, Size, Message);
}

/**
 * @brief Remove a message from the queue. Wrapper over #CommFreeMessage
 *
 * @param[in]       Message         Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
CommDestroyMessage(
    _In_ PCOMM_MESSAGE Message
    )
{
    return CommFreeMessage(gHypervisorGlobalData.Comm.SharedMem, Message);
}

/**
 * @brief Mark a message as sent and notify the guest
 *
 * @param[in]       Message         Message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
CommPostMessage(
    _In_ PCOMM_MESSAGE Message
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    status = CommSendMessage(gHypervisorGlobalData.Comm.SharedMem, Message);
    if (SUCCESS(status))
    {
        status = CommGuestForwardMessage(Message);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("CommGuestForwardMessage", status);
            CommDumpMessageInfo(gHypervisorGlobalData.Comm.SharedMem, Message);
        }
    }
    else
    {
        LOG_FUNC_FAIL("CommSendMessage", status);
    }

    return status;
}

/**
 * @brief Retrieve the communication port for a given guest component
 *
 * @param[in]   CommComponent       A component that is connected
 * @param[out]  CommPort            The associated communication port
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_DATA_NOT_FOUND The component is not connected
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
CommGetCommPortByComponent(
    _In_ COMM_COMPONENT CommComponent,
    __inout_opt HV_COMM_PORT* *CommPort
    )
{
    NTSTATUS status = CX_STATUS_DATA_NOT_FOUND;
    PLIST_ENTRY listEntry = NULL;
    HV_COMM_PORT* commPort = NULL;

    status = CX_STATUS_DATA_NOT_FOUND;
    listEntry = gHypervisorGlobalData.Comm.Ports.Flink;
    while (listEntry != &gHypervisorGlobalData.Comm.Ports)
    {
        commPort = CONTAINING_RECORD(listEntry, HV_COMM_PORT, ListEntry);

        if (CommComponent == commPort->CommComponent)
        {
            if (CommPort)
            {
                *CommPort = commPort;
            }

            status = CX_STATUS_SUCCESS;
            break;
        }

        listEntry = listEntry->Flink;
    }

    return status;
}

/**
 * @brief Informs the hypervisor that an in-guest component attempts to connect and establishes the connection. Handler for #OPT_INIT_GUEST_COMMUNICATION
 *
 * @param[in]   Component           The component that connects
 * @param[out]  OutSharedMemGPA     Guest Physical Address for the shared buffer that will be used to communicate
 * @param[out]  OutSharedMemSize    Size of the shared communication buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_OPERATION_NOT_SUPPORTED    A shared communication buffer was not found
 * @return CX_STATUS_NOT_INITIALIZED            The shared communication buffer is not initialized
 * @return CX_STATUS_INVALID_INTERNAL_STATE     The component is already connected
 * @return OTHER                                Other potential internal error
 */
NTSTATUS
GuestClientConnected(
    _In_ COMM_COMPONENT Component,
    _Out_ QWORD *OutSharedMemGPA,
    _Out_ QWORD *OutSharedMemSize
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    VCPU* vcpu = HvGetCurrentVcpu();
    HV_COMM_PORT* currentPort = NULL;

    if (TargetUndefined == Component)
    {
        CRITICAL("[%d.%d] Component ID invalid\n", vcpu->Guest->Index, HvGetCurrentVcpuApicId());
        return CX_STATUS_INVALID_INTERNAL_STATE;
    }

    HvAcquireSpinLock(&gHypervisorGlobalData.Comm.Lock);

    if (NULL == gHypervisorGlobalData.Comm.SharedMem)
    {
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        goto cleanup;
    }

    if (!gHypervisorGlobalData.Comm.SharedMem->Initialized)
    {
        status = CX_STATUS_NOT_INITIALIZED;
        goto cleanup;
    }

    // check if already connected
    status = CommGetCommPortByComponent(Component, &currentPort);
    if (NT_SUCCESS(status))
    {
        CRITICAL("Component %d is already connected, but it tries to reconnect!\n", Component);
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }

    status = HpAllocWithTagCore(&currentPort, sizeof(HV_COMM_PORT), TAG_COM);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        goto cleanup;
    }
    memset(currentPort, 0, sizeof(HV_COMM_PORT));

    currentPort->CommComponent = Component;

    LOG("Guest %d is connecting, component %d...\n", vcpu->Guest->Index, currentPort->CommComponent);

    // return ShMem address to guest
    *OutSharedMemGPA = vcpu->Guest->SharedBufferGPA;
    *OutSharedMemSize = SHARED_MEM_SIZE;

    LOG("Return ShMem GPA to guest %p\n", vcpu->Guest->SharedBufferGPA);

    currentPort->GuestDataReady = TRUE;

    CpuVmxInvEpt(2, 0, 0); // 2 == global invalidate

    InsertTailList(&gHypervisorGlobalData.Comm.Ports, &currentPort->ListEntry);

cleanup:

    HvReleaseSpinLock(&gHypervisorGlobalData.Comm.Lock);

    return status;
}

/**
 * @brief Informs the hypervisor that an in-guest component attempts to disconnect and terminates the connection. Handler for #OPT_UNINIT_GUEST_COMMUNICATION
 *
 * @param[in]   Component           The component that disconnects
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_INVALID_PARAMETER_1    An invalid Component was supplied
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
GuestClientDisconnected(
    _In_ COMM_COMPONENT Component
    )
{
    VCPU* vcpu = NULL;
    NTSTATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    HV_COMM_PORT* port = NULL;

    vcpu = HvGetCurrentVcpu();

    if (TargetUndefined == Component)
    {
        CRITICAL("[%d.%d] Component ID is invalid\n", vcpu->Guest->Index, HvGetCurrentVcpuApicId());
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    HvAcquireSpinLock(&gHypervisorGlobalData.Comm.Lock);

    status = CommGetCommPortByComponent(Component, &port);
    if (!NT_SUCCESS(status))
    {
        CRITICAL("Component %d not connected yet, but it tries to disconnect\n", Component);
        LOG_FUNC_FAIL("CommGetCommPortByComponent", status);
        goto cleanup;
    }

    port->GuestDataReady = FALSE;

    RemoveEntryList(&port->ListEntry);

    HpFreeAndNullWithTag(&port, TAG_COM);

    status = CX_STATUS_SUCCESS;
    INFO("[CPU %d] Client disconnected, component %d\n", HvGetCurrentApicId(), Component);

cleanup:
    HvReleaseSpinLock(&gHypervisorGlobalData.Comm.Lock);

    return status;
}

/**
 * @brief Initialize the shared memory used to communicate with the guest
 *
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_NOT_INITIALIZED    The shared memory could not be initialized
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
CommSetupHostRingBuffer(
    void
    )
{
    NTSTATUS status = CX_STATUS_NOT_INITIALIZED;

    InitializeListHead(&gHypervisorGlobalData.Comm.Ports);
    HvInitSpinLock(&gHypervisorGlobalData.Comm.Lock, "gHypervisorGlobalData.CommPortsLock", NULL);

    status = MmAlloc(&gHvMm, NULL, 0, NULL, SHARED_MEM_SIZE, TAG_HRBF, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, MM_GLUE_NONE, &gHypervisorGlobalData.Comm.SharedMem, (MM_UNALIGNED_PA*)&gHypervisorGlobalData.Comm.SharedBufferHpa);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAlloc", status);
        status = CX_STATUS_NOT_INITIALIZED;
        goto cleanup;
    }
    LOG("Shared mem buffer HPA: [%p, %p) HVA: %p\n", gHypervisorGlobalData.Comm.SharedBufferHpa, gHypervisorGlobalData.Comm.SharedBufferHpa + SHARED_MEM_SIZE, gHypervisorGlobalData.Comm.SharedMem);

    status = CommInitSharedMem(SHARED_MEM_SIZE, gHypervisorGlobalData.Comm.SharedMem);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("CommInitSharedMem", status);
        goto cleanup;
    }

cleanup:
    return status;
}

/**
 * @brief Handler and dispatcher for VMCALLs that represent guest messages described in commands.h
 *
 * @param[in]   Vcpu                VCPU which performed the VMCALL
 * @param[in]   Privileged          If the message comes from Kernel Mode Guest code
 * @param[in]   CommandCode         message type
 * @param[in]   Param1              1st in parameter
 * @param[in]   Param2              2nd in parameter
 * @param[in]   Param3              3rd in parameter
 * @param[in]   Param4              4th in parameter
 * @param[out]  OutParam1           1st out parameter
 * @param[out]  OutParam2           2nd out parameter
 * @param[out]  OutParam3           3rd out parameter
 * @param[out]  OutParam4           4th out parameter
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_OPERATION_NOT_IMPLEMENTED  Unrecognized message type
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
VxhVmCallGuestMessage(
    _In_ VCPU* Vcpu,
    _In_ BOOLEAN Privileged,
    _In_ COMMAND_CODE CommandCode,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_ QWORD *OutParam1,
    _Out_ QWORD *OutParam2,
    _Out_ QWORD *OutParam3,
    _Out_ QWORD *OutParam4
    )
{
    UNREFERENCED_PARAMETER((OutParam3, OutParam4));

    NTSTATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    PCOMM_MESSAGE commMsg = NULL;

#if CFG_ENABLE_DEBUG_HVCOMM
    INFO("VMCALL[%d.%d]: %s{%08X}; args: %p/%p/%p/%p out: %p/%p/%p/%p\n",
            Vcpu->GuestIndex, Vcpu->GuestCpuIndex, CommCommandToString(CommandCode), CommandCode,
            Param1, Param2, Param3, Param4, *OutParam1, *OutParam2, *OutParam3, *OutParam4);
#endif

    // inject #GP in case the request does not come from RING 0 and is not unrestricted
    if (!Privileged && (CommandCode & MSG_TYPE_MASK) != MSG_TYPE_UNRESTRICTED)
    {
        VirtExcInjectException(NULL, Vcpu, EXCEPTION_GENERAL_PROTECTION, 0, 0);
        return STATUS_INJECT_GP;
    }

    if ((CommandCode & MSG_TYPE_MASK) == MSG_TYPE_UNRESTRICTED
        || (CommandCode & MSG_TYPE_MASK) == MSG_TYPE_OPT)
    {
        return MsgFastOpt(Vcpu->Guest, CommandCode,
            Param1, Param2, Param3, Param4,
            OutParam1, OutParam2, OutParam3, OutParam4);
    }
    else if ((CommandCode & MSG_TYPE_MASK) == MSG_TYPE_EXT)
    {
        // for Extended messages, the first parameter is the offset of the message in the Shared Memory Buffer
        commMsg = (PCOMM_MESSAGE)((PBYTE)gHypervisorGlobalData.Comm.SharedMem + (DWORD)Param1);

        if (TargetNapoca != commMsg->DstComponent)
        {
            // this message will be passed to destination guest
            status = CommGuestForwardMessage(commMsg);
            if (!NT_SUCCESS(status))
            {
                WARNING("Received command for %d, but it is not present (unexpected behavior)\n", commMsg->DstComponent);

                if (COMM_NEEDS_REPLY(commMsg))
                {
                    CommSendReply(commMsg);
                    CommGuestForwardMessage(commMsg);
                }
                else
                {
                    CommDestroyMessage(commMsg);
                }
            }

            return status;
        }

        if (COMM_IS_REPLY(commMsg))
        {
            if (!(commMsg->Flags & COMM_FLG_NO_AUTO_FREE))
            {
                // if it hasn't been forwarded and COMM_FLG_NO_AUTO_FREE is not set, it can be freed
                CommDestroyMessage(commMsg);
            }

            return status;
        }

        switch (CommandCode)
        {
            case cmdTestComm:
                commMsg->ProcessingStatus = CX_STATUS_SUCCESS; // (PCMD_TEST_COMM)commMsg;
                break;

            case cmdDriverCheckCompatWithNapoca:
                commMsg->ProcessingStatus = MsgDriverCheckCompatWithNapoca((PCMD_CHECK_COMPATIBILITY)commMsg);
                break;

            case cmdGetLogsHv:
                commMsg->ProcessingStatus = MsgGetLogsHv((PCMD_GET_LOGS)commMsg);
                break;

            case cmdGetCfgItemData:
                commMsg->ProcessingStatus = MsgGetCfgItemData((PCMD_GET_CFG_ITEM_DATA)commMsg);
                break;

            case cmdSetCfgItemData:
                commMsg->ProcessingStatus = MsgSetCfgItemData((PCMD_SET_CFG_ITEM_DATA)commMsg);
                break;

            case cmdUpdateModule:
                commMsg->ProcessingStatus = UpdLoadUpdate(Vcpu, &((PCMD_UPDATE_MODULE)commMsg)->Update);
                break;

            case cmdSendDbgCommand:
                commMsg->ProcessingStatus = MsgSendDbgCommand((PCMD_SEND_DBG_COMMAND)commMsg);
                break;

            case cmdIntroFlags:
                commMsg->ProcessingStatus = MsgIntroFlags((PCMD_INTRO_FLAGS)commMsg, Vcpu->Guest);
                break;

            case cmdSetProtectedProcess:
                commMsg->ProcessingStatus = MsgSetProtectedProcess((PCMD_SET_PROTECTED_PROCESS)commMsg, Vcpu->Guest);
                break;

            case cmdAddExceptionFromAlert:
                commMsg->ProcessingStatus = MsgAddExceptionFromAlert((PCMD_ADD_EXCEPTION_FROM_ALERT)commMsg, Vcpu->Guest);
                break;

            case cmdRemoveException:
                commMsg->ProcessingStatus = MsgRemoveException((PCMD_REMOVE_EXCEPTION)commMsg, Vcpu->Guest);
                break;

            case cmdIntroGuestInfo:
                commMsg->ProcessingStatus = MsgIntroGuestInfo((PCMD_GUEST_INFO)commMsg, Vcpu->Guest);
                break;

            case cmdFastOpt:
            {
                PCMD_FAST_OPTION fastOpt = (PCMD_FAST_OPTION)commMsg;

                commMsg->ProcessingStatus = MsgFastOpt(Vcpu->Guest, fastOpt->MsgId,
                    fastOpt->Param1, fastOpt->Param2, fastOpt->Param3, fastOpt->Param4,
                    &fastOpt->OutParam1, &fastOpt->OutParam2, &fastOpt->OutParam3, &fastOpt->OutParam4);
                break;
            }

            case cmdGetComponentVersion:
                commMsg->ProcessingStatus = MsgGetComponentVersion((PCMD_GET_COMPONENT_VERSION)commMsg, Vcpu->Guest);
                break;

            case cmdGetHostCrValues:
                commMsg->ProcessingStatus = MsgGetHostCrValues((PCMD_GET_CR_VALUES)commMsg);
                break;

            case cmdGetCpuSmxAndVirtFeat:
                commMsg->ProcessingStatus = MsgGetCpuSmxAndVirtFeat((PCMD_GET_CPU_SMX_VIRT_FEATURES)commMsg);
                break;

            default:
            {
                CRITICAL("[HVCOMM] Communication error: invalid command 0x%08X(%s) received in HV from G%d.VCPU%d!\n",
                    CommandCode, CommCommandToString(CommandCode), Vcpu->GuestIndex, Vcpu->GuestCpuIndex);
                CommDumpMessageInfo(NULL, (PCOMM_MESSAGE)commMsg);
                commMsg->ProcessingStatus = CX_STATUS_OPERATION_NOT_IMPLEMENTED;
            }
        }

        if (COMM_NEEDS_REPLY(commMsg))
        {
            CommSendReply(commMsg);
            CommGuestForwardMessage(commMsg);
        }

        return CX_STATUS_SUCCESS;
    }

    return status;
}

/**
 * @brief Notifies the guest that a message has been sent
 *
  * @param[in]       Msg            The message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
CommGuestForwardMessage(
    _In_ PCOMM_MESSAGE Msg
    )
{
    NTSTATUS status = CX_STATUS_DATA_NOT_FOUND;
    HV_COMM_PORT* port = NULL;

#if CFG_ENABLE_DEBUG_HVCOMM
    LOG("[HVCOMM] Msg %s{%08X}@%p[%d] from %s to %s: status %08X\n",
            CommCommandToString(Msg->CommandCode), Msg->CommandCode, Msg, Msg->Size,
            CommComponentToString(Msg->SrcComponent), CommComponentToString(Msg->DstComponent),
            Msg->Status);
#endif

    switch (Msg->DstComponent)
    {
        case TargetNapoca:
        {
            status = CommDestroyMessage(Msg);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("CommDestroyMessage", status);
            }
            status = CX_STATUS_SUCCESS;
            break;
        }

        case TargetFalxKm:
        case TargetFalxUm:
        {
            // forward to windows
            status = CommGetCommPortByComponent(TargetFalxKm, &port);
            if (!NT_SUCCESS(status))
            {
                LOG_FUNC_FAIL("CommGetCommPortByComponent", status);
                goto cleanup;
            }

            HvInterlockedBitTestAndSetU32(&gHypervisorGlobalData.Comm.SharedMem->GuestICR, Msg->DstComponent);

            status = CX_STATUS_SUCCESS;
            break;
        }

        case TargetWinguestKm:
        case TargetWinguestUm:
        {
            // forward to windows
            status = CommGetCommPortByComponent(TargetWinguestKm, &port);
            if (!NT_SUCCESS(status))
            {
                //LOG_FUNC_FAIL("CommGetCommPortByComponent", status);
            }

            HvInterlockedBitTestAndSetU32(&gHypervisorGlobalData.Comm.SharedMem->GuestICR, Msg->DstComponent);

            status = CX_STATUS_SUCCESS;
            break;
        }

        default:
        {
            CRITICAL("Got message of type %08X for unknown component %d from component %d!\n",
                Msg->CommandCode, Msg->DstComponent, Msg->SrcComponent);
            CommDumpMessageInfo(gHypervisorGlobalData.Comm.SharedMem, Msg);
            CommDumpQueue(gHypervisorGlobalData.Comm.SharedMem);

            status = CX_STATUS_DATA_NOT_FOUND;
        }
    }

cleanup:
    return status;

}

/**
 * @brief Checks to see if introspection alerts should be sent to the guest and sends them if necessary
 *
 * In order not to flood the guest with a ton of messages for introspection alerts, they are cached and are sent in batch only when the cache is full.
 * To ensure that the guest doesn't miss alerts because the cache is not filled and no new alerts are generated,
 * this routine will check if more than one second has passed since the last generated alert and send a batch with however many alerts are currently pending
 *
 * @param[in]   Vcpu                The VCPU whose alerts are checked
 * @param[in]   ForcedFlush         If true, will always send existing alerts
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
VOID
CommIntroCheckPendingAlerts(
    _In_ VCPU* Vcpu,
    _In_ BOOLEAN ForcedFlush
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD newAlertTsc = HvGetTscTickCount();
    GUEST* guest = Vcpu->Guest;
    PCMD_SEND_INTROSPECTION_ALERT cmd = NULL;

    if (NULL == guest->AlertsCache.Buffer)
    {
        return;
    }

    // If nobody is connected there is no need to try to forward
    if (!CommIsComponentConnected(TargetWinguestKm))
    {
        return;
    }

    // do not wait for this spinlock in case other core is already owning this lock
    if (!HvTryToAcquireSpinLock(&guest->AlertsCache.Spinlock))
    {
        return;
    }

    if (0 == guest->AlertsCache.Count)
    {
        goto cleanup;
    }

    // Always sends the first alerts, and from there on, only one message per second
    if ((HvTscTicksIntervalToMicroseconds(newAlertTsc, guest->AlertsCache.Tsc) < ONE_SECOND_IN_MICROSECONDS) && !ForcedFlush)
    {
        goto cleanup;
    }

    //LOG("[%d] Will send %d pending alerts from cache\n", Vcpu->LapicId, guest->AlertsCache.Count);

    status = CommPrepareMessage(cmdSendIntrospectionAlert, COMM_FLG_IS_NON_CORE_MESSAGE, TargetWinguestUm, (DWORD)sizeof(CMD_SEND_INTROSPECTION_ALERT) + (guest->AlertsCache.Count - 1) * sizeof(INTROSPECTION_ALERT), (PCOMM_MESSAGE*)&cmd);
    if (!NT_SUCCESS(status))
    {
        if (CX_STATUS_ACCESS_DENIED == status)
        {
            status = CX_STATUS_SUCCESS;
        }
        else
        {
            LOG_FUNC_FAIL("CommPrepareMessage", status);
        }

        goto cleanup;
    }

    memcpy(cmd->Alerts, guest->AlertsCache.Buffer, guest->AlertsCache.Count * sizeof(INTROSPECTION_ALERT));
    cmd->Count = guest->AlertsCache.Count;

    status = CommPostMessage((PCOMM_MESSAGE)cmd);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("CommPostMessage", status);

        CommDestroyMessage((PCOMM_MESSAGE)cmd);
    }
    else
    {
        guest->AlertsCache.Count = 0;
    }

cleanup:
    HvReleaseSpinLock(&guest->AlertsCache.Spinlock);
}

/**
 * @brief Checks if an in-guest component is currently connected
 *
 * @param[in]   CommComponent       The component to be checked
 *
 * @return TRUE                     The component is connected
 * @return FALSE                    The component is not connected
 */
__forceinline
BOOLEAN
CommIsComponentConnected(
    _In_ COMM_COMPONENT CommComponent
)
{
    HvAcquireSpinLock(&gHypervisorGlobalData.Comm.Lock);

    CX_STATUS status = CommGetCommPortByComponent(CommComponent, NULL);

    HvReleaseSpinLock(&gHypervisorGlobalData.Comm.Lock);

    return SUCCESS(status);
}
