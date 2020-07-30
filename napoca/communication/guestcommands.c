/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// HV-guest communication: command handling
#include "napoca.h"
#include "communication/comm_guest.h"
#include "communication/guestcommands.h"
#include "kernel/kernel.h"
#include "common/kernel/napoca_version.h"
#include "common/kernel/napoca_compatibility.h"
#include "introspection/intromodule.h"
#include "boot/boot.h"
#include "common/kernel/module_updates.h"
#include "version.h"
#include "memory/cachemap.h"
#include "base/pe.h"
#include "guests/intro.h"
#include "guests/power.h"
#include "guests/pci_tools.h"
#include "introspection/intromodule.h"
#include "common/debug/memlog.h"
#include "introspection/glue_layer/introguests.h"

extern HV_FEEDBACK_HEADER *gFeedback;

/**
 * @brief Actually apply new settings after loading command line data
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
CfgApplyDynamicVariables(
    VOID
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    BOOLEAN oneCfgFailed = FALSE;

    for (DWORD cfgVariable = 0; cfgVariable < HvCommandLineVariablesInfoCount; cfgVariable++)
    {
        if (HvCommandLineVariablesInfo[cfgVariable].VariableMetadataFlags & DIRTY)
        {
            switch (cfgVariable)
            {
                case _CfgDebugOutputDebuggerOnly_:
                {
                    // Every serial and vga log is direcly controlled by CfgDebugOutputDebuggerOnly (nothing to do)
                    break;
                }

                case _CfgDebugOutputEnabled_:
                {
                    QWORD newDebugValue = !!CfgDebugOutputEnabled;

                    CfgDebugOutputSerialEnabled = newDebugValue;
                    CfgDebugOutputVgaEnabled = newDebugValue;

                    LOG("CfgDebugOutputEnabled = %d\n", CfgDebugOutputEnabled);
                    LOG("CfgDebugOutputSerialEnabled = %d\n", CfgDebugOutputSerialEnabled);
                    LOG("CfgDebugOutputVgaEnabled = %d\n", CfgDebugOutputVgaEnabled);

                    status = CX_STATUS_SUCCESS;
                    break;
                }

                case _CfgFeaturesIntrospectionVerbosity_:
                {
                    NapIntUpdateIntrospectionVerbosityLogs(gHypervisorGlobalData.Guest[0], CfgFeaturesIntrospectionVerbosity);
                    break;
                }

                case _CfgDebugTraceAcpi_:
                case _CfgDebugTraceApic_:
                case _CfgDebugTraceCrashLog_:
                case _CfgDebugTraceEmulatorEnabled_:
                case _CfgDebugTraceEmulatorUnique_:
                case _CfgDebugTraceGuestExceptions_:
                case _CfgDebugTraceHwp_:
                case _CfgDebugTraceMemoryMaps_:
                case _CfgDebugTraceMsix_:
                case _CfgDebugTracePci_:
                case _CfgDebugTracePciDeviceBus_:
                case _CfgDebugTracePciDeviceDevice_:
                case _CfgDebugTracePciDeviceEnabled_:
                case _CfgDebugTracePciDeviceFunction_:
                case _CfgDebugTracePeriodicStatsEnabled_:
                case _CfgDebugTracePeriodicStatsFastAllocators_:
                case _CfgDebugTracePeriodicStatsPerformance_:
                {
                    status = CX_STATUS_SUCCESS;
                    break;
                }

                default:
                {
                    WARNING("Dynamic variable %s changed, but no handle found!\n", HvCommandLineVariablesInfo[cfgVariable].VariableName);
                    break;
                }
            }

            // Remove the DIRTY flag after the dynamic variable was processed
            HvCommandLineVariablesInfo[cfgVariable].VariableMetadataFlags &= ~(DIRTY);

            if (!NT_SUCCESS(status) && !oneCfgFailed)
            {
                // if at least one cfg fails, return an error ntstatus
                oneCfgFailed = TRUE;
            }
        }
    }

    return (oneCfgFailed) ? CX_STATUS_OPERATION_NOT_SUPPORTED : CX_STATUS_SUCCESS;
}

/**
 * @brief Helper that fills in minimal valid data for an instrospection error simulated via #VMCALL_GUEST_INTRO_SIM
 *
 * @param[in]       Error           The type of the introspection error that is being simulated
 * @param[out]      Context         Structure that holds information regarding the introspection error
 * @param[in]       Counter         Value that allows the guest to identify a particular message in a simulation burst
 * @param[in]       Identifier      Value that allows the guest to identify that a message comes from a specific simulation event
 *
 * @return CX_STATUS_SUCCESS
 */
NTSTATUS
IntrosimFillErrorContext(
    INTRO_ERROR_STATE Error,
    INTRO_ERROR_CONTEXT *Context,
    DWORD Counter,
    DWORD Identifier
    )
{
    UNREFERENCED_PARAMETER(Error);

    Context->ProcessProtection.Process.Valid = TRUE;
    Context->ProcessProtection.Process.Pid = Identifier;
    Context->ProcessProtection.Process.Cr3 = 0x6D69736F72746E69;
    Context->ProcessProtection.Process.CreationTime = Counter;
    strcpy_s(Context->ProcessProtection.Process.ImageName, sizeof(Context->ProcessProtection.Process.ImageName), "introsim");

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Helper that fills in minimal valid data for an instrospection Event simulated via #VMCALL_GUEST_INTRO_SIM
 *
 * @param[in]       Type            The type of the introspection event that is being simulated
 * @param[in]       Flags           Flags that can fine tune the event information to aid with testing
 * @param[out]      Event           Structure that holds information regarding the introspection event
 * @param[in]       Counter         Value that allows the guest to identify a particular message in a simulation burst
 * @param[in]       Identifier      Value that allows the guest to identify that a message comes from a specific simulation event
 *
 * @return CX_STATUS_SUCCESS
 */
NTSTATUS
IntrosimFillEvent(
    INTRO_EVENT_TYPE Type,
    DWORD Flags,
    INTROSPECTION_EVENT *Event,
    DWORD Counter,
    DWORD Identifier
    )
{
    INTRO_PROCESS *process = NULL;
    INTRO_VIOLATION_HEADER *violationHeader = NULL;

    switch (Type)
    {
        case introEventEptViolation:
            process = &Event->EptViolation.Header.CurrentProcess;
            violationHeader = &Event->EptViolation.Header;
            break;

        case introEventMsrViolation:
            process = &Event->MsrViolation.Header.CurrentProcess;
            violationHeader = &Event->MsrViolation.Header;
            break;

        case introEventCrViolation:
            process = &Event->CrViolation.Header.CurrentProcess;
            violationHeader = &Event->CrViolation.Header;
            break;

        case introEventXcrViolation:
            process = &Event->XcrViolation.Header.CurrentProcess;
            violationHeader = &Event->XcrViolation.Header;
            break;

        case introEventIntegrityViolation:
            process = &Event->IntegrityViolation.Header.CurrentProcess;
            violationHeader = &Event->IntegrityViolation.Header;
            break;

        case introEventTranslationViolation:
            process = &Event->TranslationViolation.Header.CurrentProcess;
            violationHeader = &Event->TranslationViolation.Header;
            break;

        case introEventInjectionViolation:
            process = &Event->MemcopyViolation.Header.CurrentProcess;
            violationHeader = &Event->MemcopyViolation.Header;
            break;

        case introEventDtrViolation:
            process = &Event->DtrViolation.Header.CurrentProcess;
            violationHeader = &Event->DtrViolation.Header;
            break;

        case introEventMessage:
            strcpy_s(Event->IntrospectionMessage.Message, sizeof(Event->IntrospectionMessage.Message), "Introsim sends his regards.");
            break;

        case introEventProcessEvent:
            process = &Event->ProcessEvent.CurrentProcess;
            break;

        case introEventAgentEvent:
            process = &Event->AgentEvent.CurrentProcess;
            break;

        case introEventModuleEvent:
            process = &Event->ModuleEvent.CurrentProcess;
            break;

        case introEventCrashEvent:
            process = &Event->CrashEvent.CurrentProcess;
            break;

        case introEventExceptionEvent:
            process = &Event->ExceptionEvent.CurrentProcess;
            break;

        case introEventConnectionEvent:
            process = &Event->ConnectionEvent.Owner;
            break;

        case introEventProcessCreationViolation:
            process = &Event->ProcessCreationViolation.Header.CurrentProcess;
            violationHeader = &Event->ProcessCreationViolation.Header;
            break;

        case introEventModuleLoadViolation:
            process = &Event->ModuleLoadViolation.Header.CurrentProcess;
            violationHeader = &Event->ModuleLoadViolation.Header;
            break;

        case introEventEnginesDetectionViolation:
            process = &Event->ModuleLoadViolation.Header.CurrentProcess;
            violationHeader = &Event->EnginesDetectionViolation.Header;
            break;

        default:
        {
            ERROR("Unknown Type %d\n", Type);
            return CX_STATUS_INVALID_PARAMETER_1;
        }
    }

    if (process)
    {
        process->Valid = TRUE;
        process->Pid = Identifier;
        process->Cr3 = 0x6D69736F72746E69;
        process->CreationTime = Counter;
        strcpy_s(process->ImageName, sizeof(process->ImageName), "introsim");
    }

    if (violationHeader && (Flags & INTROSIM_ALERT_EXHEADER_VALID))
    {
        violationHeader->ExHeader.Valid = TRUE;

        // Use the Identifier for hashing
        violationHeader->ExHeader.ViolationFlags = Identifier;
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Common Handler/Dispatcher for Fast Opt type messages
 *
 * @param[in]       Guest               Guest that sent the message
 * @param[in]       CommandCode         Fast Opt identifier
 * @param[in]       Param1              1st input parameter
 * @param[in]       Param2              2nd input parameter
 * @param[in]       Param3              3rd input parameter
 * @param[in]       Param4              4th input parameter
 * @param[out]      OutParam1           1st output parameter
 * @param[out]      OutParam2           2nd output parameter
 * @param[out]      OutParam3           3rd output parameter
 * @param[out]      OutParam4           4th output parameter
 *
 * @return CX_STATUS_SUCCESS
 * @return CX_STATUS_INVALID_DATA_TYPE  Unknown Fast Opt Message code supplied
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
MsgFastOpt(
    _In_ GUEST* Guest,
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
    NTSTATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    switch (CommandCode)
    {
        // Unprivileged

        case VMCALL_GUEST_CHECK_HV:
        {
            *OutParam1 = VMCALL_RESPONSE_CHECK_HV;

            return CX_STATUS_SUCCESS;
        }

        case VMCALL_GUEST_GET_HV_VERSION:
        {
            *OutParam1 = NAPOCA_VERSION_MAJOR;
            *OutParam2 = NAPOCA_VERSION_MINOR;
            *OutParam3 = NAPOCA_VERSION_REVISION;
            *OutParam4 = NAPOCA_VERSION_BUILDNUMBER;

            return CX_STATUS_SUCCESS;
        }

        case VMCALL_GUEST_GET_REAL_TIME:
        {
            QWORD tsc = 0;
            DATETIME dt = { 0 };

            tsc = __rdtsc();
            HvGetWallClockDateTime(&dt, TRUE);

            // TSC value
            *OutParam1 = (DWORD)((tsc & 0xFFFFFFFF00000000) >> 32);
            *OutParam2 = (DWORD)(tsc & 0x00000000FFFFFFFF);

            // RTC value
            *OutParam3 = (DWORD)((dt.raw & 0xFFFFFFFF00000000) >> 32);
            *OutParam4 = (DWORD)(dt.raw & 0x00000000FFFFFFFF);

            LOG("Guest requested real time. TSC: %p, rtc: %p. Will return eax: 0x%x, ebx: 0x%x, ecx: 0x%x, edx: 0x%x\n",
                tsc, dt, *OutParam1, *OutParam2, *OutParam3, *OutParam4);

            LOG("Rtc: %04d/%02d/%02d %02d:%02d:%02d, day-of-week %d\n",
                dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second, dt.DayOfWeek);

            return CX_STATUS_SUCCESS;
        }

        case VMCALL_GUEST_INTRO_SIM:
        {
            INTROSIM_OPTIONS introUmOptions = { 0 };
            introUmOptions.Raw = (DWORD)Param1;

            //LOG("Received request to generate introsim %d - %d (%lld %lld %lld)\n", introUmOptions.IntrosimType, introUmOptions.IntroMessageType, Param2, Param3, Param4);

            switch (introUmOptions.IntrosimType)
            {
                case introsimError:
                {
                    INTRO_ERROR_CONTEXT errorCtx = { 0 };

                    status = IntrosimFillErrorContext((INTRO_ERROR_STATE)introUmOptions.IntroMessageType, &errorCtx, (DWORD)Param3, (DWORD)Param4);
                    if (!NT_SUCCESS(status))
                    {
                        //LOG_FUNC_FAIL("IntrosimFillErrorContext", status);
                        return status;
                    }

                    status = GuestIntNapNotifyIntrospectionErrorState(Guest, introUmOptions.IntroMessageType, &errorCtx);
                    if (!NT_SUCCESS(status))
                    {
                        //LOG_FUNC_FAIL("GuestIntNapNotifyIntrospectionErrorState", status);
                        return status;
                    }

                    break;
                }

                case introsimAlert:
                {
                    INTROSPECTION_EVENT *event = NULL;

                    status = HpAllocWithTag(&event, sizeof(*event), TAG_DBG);
                    if (!NT_SUCCESS(status))
                    {
                        goto introsimAlertCleanup;
                    }

                    memzero(event, sizeof(*event));

                    status = IntrosimFillEvent((INTRO_EVENT_TYPE)introUmOptions.IntroMessageType, (DWORD)Param2, event, (DWORD)Param3, (DWORD)Param4);
                    if (!NT_SUCCESS(status))
                    {
                        //LOG_FUNC_FAIL("IntrosimFillEvent", status);
                        goto introsimAlertCleanup;
                    }

                    status = GuestIntNapIntroEventNotify(Guest, introUmOptions.IntroMessageType, event, sizeof(*event));
                    if (!NT_SUCCESS(status))
                    {
                        //LOG_FUNC_FAIL("GuestIntNapIntroEventNotify", status);
                        goto introsimAlertCleanup;
                    }

                introsimAlertCleanup:
                    if (event)
                    {
                        HpFreeAndNullWithTag(&event, TAG_DBG);
                    }

                    break;
                }

                default:
                    //LOG("Received malformed message.\n");
                    status = CX_STATUS_INVALID_PARAMETER;
            }

            return status;
        }

        // Privileged

        case OPT_INIT_GUEST_COMMUNICATION:
        {
            QWORD outSharedGpa = 0;

            status = GuestClientConnected((COMM_COMPONENT)Param1, &outSharedGpa, OutParam3);

            *OutParam1 = outSharedGpa & 0xFFFFFFFF;
            *OutParam2 = outSharedGpa >> 32;

            return status;
        }

        case OPT_UNINIT_GUEST_COMMUNICATION:
            return GuestClientDisconnected((COMM_COMPONENT)Param1);

        case OPT_GET_HV_BOOT_MODE:
        {
            *OutParam1 = HvGetBootMode();

            return CX_STATUS_SUCCESS;
        }

        case OPT_GET_POWERUP_INFO:
        {
            *OutParam1 = gHypervisorGlobalData.BootFlags.WakeupPerformedAtLeastOnce;

            return CX_STATUS_SUCCESS;
        }

        case OPT_GET_MEMORY_INTRO_STATUS:
        {
            *OutParam1 = CfgFeaturesIntrospectionEnabled
                ? (Guest->Intro.IntrospectionEnabled && Guest->Intro.IntrospectionActivated)
                : FALSE;

            return CX_STATUS_SUCCESS;
        }

        case OPT_REM_ALL_PROTECTED_PROCESSES:
        {
            status = NapIntRemoveAllProtectedProcesses(Guest);
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("NapIntRemoveAllProtectedProcesses", status);

            return status;
        }

        case OPT_FLUSH_EXCEPTIONS_FROM_ALERTS:
        {
            status = NapIntFlushAlertExceptions(Guest);
            if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntFlushAlertExceptions", status);

            return status;
        }

        case OPT_SET_INTRO_VERBOSITY:
        {
            LOG("Will try to update introspection verbosity with %d\n", Param1);
            status = NapIntUpdateIntrospectionVerbosityLogs(Guest, Param1);
            if (SUCCESS(status))
            {
                CfgFeaturesIntrospectionVerbosity = Param1;
            }

            return status;
        }

        default:
            return CX_STATUS_INVALID_DATA_TYPE;
    }
}


/**
 * @brief Handler for #cmdDriverCheckCompatWithNapoca
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgDriverCheckCompatWithNapoca(
    CMD_CHECK_COMPATIBILITY *Message
    )
{
    NTSTATUS status;
    NAPOCA_VERSION reqVer = { 0 };

    switch (Message->Command.SrcComponent)
    {
        case TargetWinguestKm:
            {
                INFO("Found WINGUEST.SYS %d.%d.%d.%d\n",
                    Message->Version.High, Message->Version.Low, Message->Version.Revision, Message->Version.Build);

                MakeVersion(&reqVer, WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA);

                status = CheckCompatibility((NAPOCA_VERSION*)&Message->Version, &reqVer);
                if (!NT_SUCCESS(status))
                {
                    ERROR("WINGUEST.SYS is not compatible with NAPOCA which requires %d.%d.%d.%d\n",
                        WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA);
                }
                else
                {
                    INFO("WINGUEST.SYS compatible with NAPOCA %d.%d.%d.%d\n",
                        NAPOCA_VERSION_MAJOR, NAPOCA_VERSION_MINOR, NAPOCA_VERSION_REVISION, NAPOCA_VERSION_BUILDNUMBER);
                }

                Message->CompatVersion.High = WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA_MJ;
                Message->CompatVersion.Low = WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA_MN;
                Message->CompatVersion.Revision = WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA_REV;
                Message->CompatVersion.Build = WINGUESTSYS_VERSION_REQUIRED_BY_NAPOCA_BLD;

                break;
            }

        case TargetFalxKm:
            {
                INFO("Found FALX.SYS %d.%d.%d.%d\n",
                    Message->Version.High, Message->Version.Low, Message->Version.Revision, Message->Version.Build);

                MakeVersion(&reqVer, FALXSYS_VERSION_REQUIRED_BY_NAPOCA);

                status = CheckCompatibility((NAPOCA_VERSION*)&Message->Version, &reqVer);
                if (!NT_SUCCESS(status))
                {
                    ERROR("FALX.SYS is not compatible with NAPOCA.BIN which requires %d.%d.%d.%d\n",
                        FALXSYS_VERSION_REQUIRED_BY_NAPOCA);
                }
                else
                {
                    INFO("FALX.SYS compatible with NAPOCA %d.%d.%d.%d\n",
                        NAPOCA_VERSION_MAJOR, NAPOCA_VERSION_MINOR, NAPOCA_VERSION_REVISION, NAPOCA_VERSION_BUILDNUMBER);
                }

                Message->CompatVersion.High = FALXSYS_VERSION_REQUIRED_BY_NAPOCA_MJ;
                Message->CompatVersion.Low = FALXSYS_VERSION_REQUIRED_BY_NAPOCA_MN;
                Message->CompatVersion.Revision = FALXSYS_VERSION_REQUIRED_BY_NAPOCA_REV;
                Message->CompatVersion.Build = FALXSYS_VERSION_REQUIRED_BY_NAPOCA_BLD;

                break;
            }

        default:
            {
                ERROR("Unsupported component required for compatibility checks! Component id: %d\n", Message->Command.SrcComponent);
                status = CX_STATUS_OPERATION_NOT_SUPPORTED;
            }
    }

    Message->Version.High = NAPOCA_VERSION_MAJOR;
    Message->Version.Low = NAPOCA_VERSION_MINOR;
    Message->Version.Revision = NAPOCA_VERSION_REVISION;
    Message->Version.Build = NAPOCA_VERSION_BUILDNUMBER;

    return status;
}

/**
 * @brief Handler for #cmdGetComponentVersion
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */

NTSTATUS
MsgGetComponentVersion(
    CMD_GET_COMPONENT_VERSION *Message,
    GUEST* Guest
    )
{
    NTSTATUS status;

    if (Message->Component == compIntro)
    {
        INT_VERSION_INFO hviVer;

        status = HvGetLoadedHviVersion(&hviVer);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("HvGetLoadedHviVersion", status);
        else
        {
            Message->VersionHigh = hviVer.VersionInfo.Major;
            Message->VersionLow = hviVer.VersionInfo.Minor;
            Message->VersionRevision = hviVer.VersionInfo.Revision;
            Message->VersionBuild = hviVer.VersionInfo.Build;
        }
    }
    else if (Message->Component == compExceptions)
    {
        WORD major, minor;
        DWORD buildNumber;

        status = NapIntGetExceptionsVersion(Guest, &major, &minor, &buildNumber);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("NapIntGetExceptionsVersion", status);
        else
        {
            Message->VersionHigh = major;
            Message->VersionLow = minor;
            Message->VersionRevision = 0;
            Message->VersionBuild = buildNumber;
        }
    }
    else if (Message->Component == compIntroLiveUpdt)
    {
        DWORD major, minor, buildNumber;

        status = NapIntGetSupportVersion(Guest, &major, &minor, &buildNumber);
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("NapIntGetSupportVersion", status);
        else
        {
            Message->VersionHigh = major;
            Message->VersionLow = minor;
            Message->VersionRevision = 0;
            Message->VersionBuild = buildNumber;
        }
    }
    else
    {
        ERROR("Invalid component: %u\n", Message->Component);
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status))
    {
        Message->VersionHigh = 0;
        Message->VersionLow = 0;
        Message->VersionRevision = 0;
        Message->VersionBuild = 0;
    }

    return status;
}

/**
 * @brief Handler for #cmdGetLogsHv
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgGetLogsHv(
    CMD_GET_LOGS *Message
    )
{
    if (Message->Size * sizeof(Message->Buffer[0]) > Message->Command.Size - CX_FIELD_OFFSET(CMD_GET_LOGS, Buffer)) // sanity check
    {
        return CX_STATUS_CORRUPTED_DATA;
    }

    switch (Message->Type)
    {
        case logHypervisor:
        {
            if (!gFeedback || !gFeedback->Logger.Initialized)
            {
                return CX_STATUS_NOT_INITIALIZED;
            }

            return Message->Size == 0
                ? GetLogInfo(&gFeedback->Logger, &Message->Offset, &Message->Size) // size info requested
                : GetLogChunk(&gFeedback->Logger, Message->Offset, Message->Size, Message->Buffer); // log chunk requested
        }

        case logHvPhysAddr:
        {
            LD_NAPOCA_MODULE *module = NULL;

            NTSTATUS status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_FEEDBACK, &module);
            if (SUCCESS(status))
            {
                Message->PhysicalAddress = module->Pa;
                Message->PhysicalSize = module->Size;
            }

            return status;
        }

        default:
            return CX_STATUS_INVALID_DATA_TYPE;
    }
}

/**
 * @brief Handler for #cmdGetHostCrValues
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgGetHostCrValues(
    CMD_GET_CR_VALUES *Message
    )
{
    Message->Cr0 = (QWORD)__readcr0();
    Message->Cr4 = (QWORD)__readcr4();

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdGetCpuSmxAndVirtFeat
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgGetCpuSmxAndVirtFeat(
    CMD_GET_CPU_SMX_VIRT_FEATURES *Message
    )
{
    int cpuidRegs[4] = { 0 };

    Message->CpuEntry = gBootInfo->CpuMap[0];

    if (FALSE == InitCpuVirtualizationFeatures(&gBootInfo->CpuMap[0], &Message->VirtFeatures))
    {
        memzero(&Message->VirtFeatures, sizeof(Message->VirtFeatures));
    }

    __cpuid(cpuidRegs, 1);
    // no need to check VMX support, there is no SMX without VMX
    if (0 != (cpuidRegs[2] & (1UL << 6)))   // support for SMX operation
    {
        // SMX info is initialized only for BSP => we must look it up
        Message->SmxCaps.SmxCapabilities0Raw = 0;

        for (DWORD i = 0; i < gHypervisorGlobalData.CpuData.CpuCount; i++)
        {
            if (gBootInfo->CpuMap[i].Topology.IsBsp)
            {
                Message->SmxCaps.SmxCapabilities0Raw = gHypervisorGlobalData.CpuData.Cpu[i]->SmxCapabilities.SmxCapabilities0Raw;
                break;
            }
        }
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdGetCfgItemData
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgGetCfgItemData(
    CMD_GET_CFG_ITEM_DATA *Message
    )
{
    BYTE itemValue[UD_ASCII_STRING_MAX_SIZE] = { 0 };
    UD_VAR_INFO* var;

    //LOG("Get cfg item data: %s\n", Message->CfgItemData.Name);
    if (!UdGetVariableByName(
        HvCommandLineVariablesInfo,
        HvCommandLineVariablesInfoCount,
        Message->CfgItemData.Name,
        strlen_s(Message->CfgItemData.Name, sizeof(Message->CfgItemData.Name)),
        itemValue,
        UD_ASCII_STRING_MAX_SIZE,
        NULL,
        &var))
    {
        return CX_STATUS_DATA_NOT_FOUND;
    }

    switch (var->VariableType)
    {
        case UD_TYPE_NUMBER:
        case UD_TYPE_QWORD:
        {
            Message->CfgItemData.ValueLengh = (DWORD)var->VariableSizeInBytes;
            Message->CfgItemData.ValueType = CfgValueTypeNumeric;
            memcpy(&Message->CfgItemData.Value.NumericValue, &itemValue, var->VariableSizeInBytes);

            return CX_STATUS_SUCCESS;
        }

        case UD_TYPE_ASCII_STRING:
        {
            if (var->VariableSizeInBytes > sizeof(Message->CfgItemData.Value.AsciiString))
            {
                return CX_STATUS_DATA_BUFFER_TOO_SMALL;
            }

            Message->CfgItemData.ValueLengh = (DWORD)strlen_s((CHAR *)itemValue, UD_ASCII_STRING_MAX_SIZE);
            Message->CfgItemData.ValueType = CfgValueTypeAsciiString;
            strcpy_s(Message->CfgItemData.Value.AsciiString, sizeof(Message->CfgItemData.Value.AsciiString), (CHAR *)itemValue);

            return CX_STATUS_SUCCESS;
        }

        default:
            return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    }
}

/**
 * @brief Handler for #cmdSetCfgItemData
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgSetCfgItemData(
    CMD_SET_CFG_ITEM_DATA *Message
    )
{
    NTSTATUS status;
    CX_VOID *requestId;
    QWORD consumed;

    if (Message->CmdlineLength * sizeof(Message->Cmdline[0]) > Message->Command.Size - CX_FIELD_OFFSET(CMD_SET_CFG_ITEM_DATA, Cmdline)) // sanity check
    {
        return CX_STATUS_CORRUPTED_DATA;
    }

    status = IpiFreezeCpus(AFFINITY_ALL_EXCLUDING_SELF, IFR_REASON_SET_CMDLINE, &requestId);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("IpiFreezeCpus", status);
    }

    if (!UdMatchVariablesFromTextEx(
        HvCommandLineVariablesInfo,
        HvCommandLineVariablesInfoCount,
        Message->Cmdline,
        Message->CmdlineLength,
        &consumed,
        RUNTIME,
        DIRTY))
    {
        LOG("Failed to process command line. Consumed: %d, cmd length = %d\n", consumed, Message->CmdlineLength);
        LOG("Command line: %s\n", Message->Cmdline);

        status = CX_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    status = CfgApplyDynamicVariables();
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("CfgApplyDynamicVariables", status);
        goto cleanup;
    }

cleanup:
    NTSTATUS status2 = IpiResumeCpus(&requestId);
    if (!NT_SUCCESS(status2))
    {
        LOG_FUNC_FAIL("IpiResumeCpus", status2);
    }

    return status;
}

/**
 * @brief Handler for #cmdSendDbgCommand
 *
 * @param[in,out]   Message         The message buffer
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgSendDbgCommand(
    CMD_SEND_DBG_COMMAND *Message
    )
{
    INT64 consumed = 0;
    INT64 tmp = 0;

    if (TargetFalxKm != Message->Command.SrcComponent)
    {
        return CX_STATUS_ACCESS_DENIED;
    }

    if (Message->Length * sizeof(Message->Buffer[0]) > Message->Command.Size - CX_FIELD_OFFSET(CMD_SEND_DBG_COMMAND, Buffer)) // sanity check
    {
        return CX_STATUS_CORRUPTED_DATA;
    }

    LOG("Will process commands: %s\n", Message->Buffer);

    while (consumed < Message->Length)
    {
        if (!DbgMatchCommand(Message->Buffer + consumed, Message->Length - consumed, &tmp, TRUE, NULL)) break;

        consumed += tmp;
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief Handler for #cmdIntroFlags
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgIntroFlags(
    CMD_INTRO_FLAGS *Message,
    GUEST* Guest
    )
{
    NTSTATUS status;

    HvAcquireRwSpinLockShared(&Guest->Intro.IntroCallbacksLock);

    if (Message->Write)
    {
        // Flags SHOULD contain ONLY dynamic flag changes
        LOG("Will try to update introspection flags with 0x%x\n", Message->Flags);

        if (!Guest->Intro.IntrospectionEnabled)
        {
            CfgFeaturesIntrospectionOptions = Message->Flags;
            status = CX_STATUS_SUCCESS;
        }
        else status = NapIntModifyDynamicOptions(Guest, Message->Flags);
    }
    else
    {
        status = NapIntGetCurrentIntroOptions(Guest, &Message->Flags);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("NapIntGetCurrentIntroOptions", status);
            Message->Flags = 0;
        }
    }

    HvReleaseRwSpinLockShared(&Guest->Intro.IntroCallbacksLock);

    return status;
}

/**
 * @brief Handler for #cmdSetProtectedProcess
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgSetProtectedProcess(
    CMD_SET_PROTECTED_PROCESS *Message,
    GUEST* Guest
    )
{
    if (Message->PathLen * sizeof(Message->Path[0]) > Message->Command.Size - CX_FIELD_OFFSET(CMD_SET_PROTECTED_PROCESS, Path)) // sanity check
    {
        return CX_STATUS_CORRUPTED_DATA;
    }

    NTSTATUS status = NapIntAddRemoveProtectedProcess(Guest, Message->Path, Message->Mask, Message->Mask != 0, Message->Context);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("NapIntAddRemoveProtectedProcess", status);

    return status;
}

/**
 * @brief Handler for #cmdAddExceptionFromAlert
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgAddExceptionFromAlert(
    CMD_ADD_EXCEPTION_FROM_ALERT *Message,
    GUEST* Guest
    )
{
    if (Message->AlertSize * sizeof(Message->AlertData[0]) > Message->Command.Size - CX_FIELD_OFFSET(CMD_ADD_EXCEPTION_FROM_ALERT, AlertData)) // sanity check
    {
        return CX_STATUS_CORRUPTED_DATA;
    }

    NTSTATUS status = NapIntAddExceptionFromAlert(Guest, Message->AlertData, Message->AlertType, Message->IsException, Message->Context);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntAddExceptionFromAlert", status);

    return status;
}

/**
 * @brief Handler for #cmdRemoveException
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgRemoveException(
    CMD_REMOVE_EXCEPTION *Message,
    GUEST* Guest
    )
{
    NTSTATUS status = NapIntRemoveException(Guest, Message->Context);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntRemoveException", status);

    return status;
}

/**
 * @brief Handler for #cmdIntroGuestInfo
 *
 * @param[in,out]   Message         The message buffer
 * @param[in]       Guest           Guest that sent the message
 *
 * @return CX_STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
MsgIntroGuestInfo(
    CMD_GUEST_INFO *Message,
    GUEST* Guest
)
{
    NTSTATUS status = NapIntGetGuestInfo(Guest, &Message->GuestInfo);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("NapIntGetGuestInfo", status);

    return status;
}
