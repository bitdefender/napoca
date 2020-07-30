/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "cx_native.h"
#include "common/communication/commands.h"

/**
 * @brief Convert a message component numeric identifier to string
 *
 * @param[in] Component     Numerical representation of the component
 *
 * @return String representation of the component
*/
const
char *
CommComponentToString(
    _In_ CX_UINT8 Component
    )
{
    switch (Component)
    {
        case TargetAny:
            return "TargetAny";
        case TargetNapoca:
            return "TargetNapoca";
        case TargetWinguestKm:
            return "TargetWinguestKm";
        case TargetWinguestUm:
            return "TargetWinguestUm";
        case TargetFalxKm:
            return "TargetFalxKm";
        case TargetFalxUm:
            return "TargetFalxUm";
        default:
            return "[unknown-component]";
    }
}

/**
 * @brief Convert a message type numeric identifier to string
 *
 * @param[in] CommandCode     Numerical representation of the message type
 *
 * @return String representation of the message type
*/
const
char *
CommCommandToString(
    _In_ COMMAND_CODE CommandCode
    )
{
    switch (CommandCode)
    {
        case VMCALL_GUEST_CHECK_HV:
            return "VMCALL_GUEST_CHECK_HV";
        case VMCALL_GUEST_GET_HV_VERSION:
            return "VMCALL_GUEST_GET_HV_VERSION";
        case VMCALL_GUEST_GET_REAL_TIME:
            return "VMCALL_GUEST_GET_REAL_TIME";
        case VMCALL_GUEST_INTRO_SIM:
            return "VMCALL_GUEST_INTRO_SIM";
        case OPT_INIT_GUEST_COMMUNICATION:
            return "OPT_INIT_GUEST_COMMUNICATION";
        case OPT_UNINIT_GUEST_COMMUNICATION:
            return "OPT_UNINIT_GUEST_COMMUNICATION";
        case OPT_GET_HV_BOOT_MODE:
            return "OPT_GET_HV_BOOT_MODE";
        case OPT_GET_POWERUP_INFO:
            return "OPT_GET_POWERUP_INFO";
        case OPT_GET_MEMORY_INTRO_STATUS:
            return "OPT_GET_MEMORY_INTRO_STATUS";
        case OPT_REM_ALL_PROTECTED_PROCESSES:
            return "OPT_REM_ALL_PROTECTED_PROCESSES";
        case OPT_FLUSH_EXCEPTIONS_FROM_ALERTS:
            return "OPT_FLUSH_EXCEPTIONS_FROM_ALERTS";
        case OPT_SET_INTRO_VERBOSITY:
            return "OPT_SET_INTRO_VERBOSITY";
        case cmdIgnore:
            return "cmdIgnore";
        case cmdTestComm:
            return "cmdTestComm";
        case cmdDriverCheckCompatWithNapoca:
            return "cmdDriverCheckCompatWithNapoca";
        case cmdGetLogsHv:
            return "cmdGetLogsHv";
        case cmdGetCfgItemData:
            return "cmdGetCfgItemData";
        case cmdSetCfgItemData:
            return "cmdGetSfgItemData";
        case cmdUpdateModule:
            return "cmdUpdateModule";
        case cmdSendDbgCommand:
            return "cmdSendDbgCommand";
        case cmdIntroFlags:
            return "cmdIntroFlags";
        case cmdSetProtectedProcess:
            return "cmdSetProtectedProcess";
        case cmdSendIntrospectionAlert:
            return "cmdSendIntrospectionAlert";
        case cmdIntroGuestInfo:
            return "cmdIntroGuestInfo";
        case cmdCommandThreadCount:
            return "cmdCommandThreadCount";
        case cmdGetHvStatus:
            return "cmdGetHvStatus";
        case cmdGetLogs:
            return "cmdGetLogs";
        case cmdGetCompatibility:
            return "cmdGetCompatibility";
        case cmdQueryComponent:
            return "cmdQueryComponent";
        case cmdUpdateComponent:
            return "cmdUpdateComponent";
        case cmdSendPowerStateChange:
            return "cmdSendPowerStateChange";
        case cmdReportIntrospectionError:
            return "cmdReportIntrospectionError";
        case cmdAddExceptionFromAlert:
            return "cmdAddExceptionFromAlert";
        case cmdRemoveException:
            return "cmdRemoveException";
        case cmdConnectHv:
            return "cmdConnectHv";
        case cmdMsrAccess:
            return "cmdMsrAccess";
        case cmdAccessPhysMem:
            return "cmdAccessPhysMem";
        case cmdUmCheckCompatWithDrv:
            return "cmdUmCheckCompatWithDrv";
        case cmdFastOpt:
            return "cmdFastOpt";
        case cmdGetComponentVersion:
            return "cmdGetComponentVersion";
        case cmdGetHostCrValues:
            return "cmdGetHostCrValues";
        case cmdGetCpuSmxAndVirtFeat:
            return "cmdGetCpuSmxAndVirtFeat";
        default:
            return "[unknown-command]";
    }
}
