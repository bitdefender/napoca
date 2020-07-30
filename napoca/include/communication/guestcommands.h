/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _GUESTCOMMANDS_H_
#define _GUESTCOMMANDS_H_

#include "core.h"
#include "guests/guests.h"
#include "common/communication/commands.h"

NTSTATUS
MsgFastOpt(
    _In_ GUEST* Guest,
    _In_ COMMAND_CODE CommandCode,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4,
    _Out_ QWORD* OutParam1,
    _Out_ QWORD* OutParam2,
    _Out_ QWORD* OutParam3,
    _Out_ QWORD* OutParam4
    );

NTSTATUS
MsgDriverCheckCompatWithNapoca(
    CMD_CHECK_COMPATIBILITY *Message
    );

NTSTATUS
MsgGetComponentVersion(
    CMD_GET_COMPONENT_VERSION *Message,
    GUEST* Guest
    );

NTSTATUS
MsgGetLogsHv(
    CMD_GET_LOGS *Message
    );

NTSTATUS
MsgGetHostCrValues(
    CMD_GET_CR_VALUES *Message
    );

NTSTATUS
MsgGetCpuSmxAndVirtFeat(
    CMD_GET_CPU_SMX_VIRT_FEATURES *Message
    );

NTSTATUS
MsgGetCfgItemData(
    CMD_GET_CFG_ITEM_DATA *Message
    );

NTSTATUS
MsgSetCfgItemData(
    CMD_SET_CFG_ITEM_DATA *Message
    );

NTSTATUS
MsgSendDbgCommand(
    CMD_SEND_DBG_COMMAND *Message
    );

NTSTATUS
MsgIntroFlags(
    CMD_INTRO_FLAGS *Message,
    GUEST* Guest
    );

NTSTATUS
MsgSetProtectedProcess(
    CMD_SET_PROTECTED_PROCESS *Message,
    GUEST* Guest
    );

NTSTATUS
MsgAddExceptionFromAlert(
    CMD_ADD_EXCEPTION_FROM_ALERT *Message,
    GUEST* Guest
    );

NTSTATUS
MsgRemoveException(
    CMD_REMOVE_EXCEPTION *Message,
    GUEST* Guest
    );

NTSTATUS
MsgIntroGuestInfo(
    CMD_GUEST_INFO *Message,
    GUEST* Guest
    );

#endif // ifndef _GUESTCOMMANDS_H_
