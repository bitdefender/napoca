/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "cmdline.h"
#include <ntstatus.h>
#include <winternl.h>
#include <stdio.h>
#include "imports.h"
#include "feedback.h"

static BOOLEAN  IsApplicationConnectedToDriver;

//
// Prototype of a command handler
//
typedef NTSTATUS(*PFUNC_CommandHandler)(_In_ DWORD Argc, _In_ WCHAR **Argv);

// Information required for a command.
// We have the name of the command, a help message and the function
// that deals with the execution of the order.
typedef struct _COMMAND
{
    WCHAR                   *CommandName;       ///< Command name
    WCHAR                   *Parameters;        ///< Brief list of the parameters (optional)
    DWORD                   MinParamCount;      ///< Minimum number of parameters
    DWORD                   MaxParamCount;      ///< Maximum number of parameters
    WCHAR                   *HelpBrief;         ///< Brief description
    WCHAR                   *HelpFull;          ///< Detailed information (optional)
    PFUNC_CommandHandler    CommandHandler;     ///< Handler for the command
}COMMAND;

/* Static functions */
static NTSTATUS     _CmdLineMatchAndExecuteCommand(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS     _CmdLineMatchAndExecuteCommands(_In_ DWORD Argc, _In_ WCHAR **Argv);

//
// Available commands below.
// If you want to add a new command, the prototype
// of the command function should be here
//
static NTSTATUS _CmdHelp(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdExit(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdInstallDriver(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdUninstallDriver(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdSetPath(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdConfigure(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdConnectToDriver(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdDisconnectFromDriver(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdAddProcessToProtection(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdRemoveProcessFromProtection(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdSetFailCounter(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdResetFailCounter(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdUpdateIntroFlags(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdQueryNapoca(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdQueryIntrospection(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdGetMissingFeatures(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdEnableFeedback(_In_ DWORD Argc, _In_ WCHAR **Argv);
static NTSTATUS _CmdFeedbackVerbosity(_In_ DWORD Argc, _In_ WCHAR **Argv);

//
// Commands list
//
static COMMAND CommandLineCommands[] =
{
    {
        L"help", L"[command/*]",
        0, 1,
        L"Print available commands and detailed descriptions for them. Try 'help help' for more information.",
        L"        [command] A command for which to see detailed instructions or '*' to detail all commands\n"
          L"        <Parameters> represented like this are mandatory\n"
          L"        [Parameters] represented like this are optional",
        _CmdHelp
    },
    {
        L"drvinstall", L"<inf-file-full-path> <hardware-id>",
        2, 2,
        L"Install the driver.",
        L"        Example: drvinstall c:\\Dacia\\winguest.inf {8a5531a8-2c02-482e-9b2e-99f8cacecc9d}\\BdWinguest",
        _CmdInstallDriver
    },
    {
        L"drvuninstall", L"<inf-file-full-path> <hardware-id>",
        2, 2,
        L"Uninstall the driver.",
        L"        Example: drvuninstall c:\\Dacia\\winguest.inf {8a5531a8-2c02-482e-9b2e-99f8cacecc9d}\\BdWinguest",
        _CmdUninstallDriver
    },
    {
        L"drvconnect", NULL,
        0, 0,
        L"Connect to the kernel mode component (driver).",
        L"        The driver is responsible with forwarding messages to the Hypervisor.\n"
          L"        This must be called before other APIs that need to comunicate with the driver/HV are called.",
        _CmdConnectToDriver
    },
    {
        L"drvdisconnect", NULL,
        0, 0,
        L"Disconnect from the kernel mode component (driver)",
        NULL,
        _CmdDisconnectFromDriver
    },
    {
        L"setpath", L"<path-id> <path>",
        2, 2,
        L"Set paths to various folders required to operate correctly.",
        L"        <path-id>:\n"
          L"            1 => path for core hypervisor binaries. The hypervisor and the HVI engine must be located here.\n"
          L"            2 => path to HVMI related updates. HVMI expceptions and live update binaries must be located here.\n"
          L"            3 => path where HVMI generated events will be persisted to disk for later examination.\n"
          L"        <path>: The specified path. Please make sure the path ends with '\\'.\n"
          L"        Example: setpath 1 C:\\Dacia\\",
        _CmdSetPath
    },
    {
        L"missingfeatures", NULL,
        0, 0,
        L"Retrieves the missing (necessary for configuration) features mask.",
        NULL,
        _CmdGetMissingFeatures
    },
    {
        L"config", L"<mode> [cmd-line]",
        1, 2,
        L"Configure/Deconfigure the hypervisor.",
        L"        <mode>: \"enable\" or \"disable\"\n"
          L"        [cmd-line]: overrides to the default command line of the hypervisor.\n"
          L"            This parameter is recommended to be left empty, however if changes are needed to the default behavior\n"
          L"            an array of chars containing the list of templates to be applied can be specified.\n"
          L"            It is intended mainly for debugging purposes and to control advanced features of the hypervisor.\n"
          L"            Invalid or inconsistent values may lead to undefined behavior of the hypervisor.\n"
          L"            Ignored when deconfiguring.\n"
          L"        Example: config enable\n"
          L"        See 'setpath' to ensure all requirements are met before configuring",
        _CmdConfigure
    },
    {
        L"queryhv", NULL,
        0, 0,
        L"Check if Napoca HV is active.",
        NULL,
        _CmdQueryNapoca
    },
    {
        L"queryintro", NULL,
        0, 0,
        L"Check if the introspection engine is active.",
        NULL,
        _CmdQueryIntrospection
    },
    {
        L"enfeedback", L"[LocalBackupDuration] [ThrottleTime]",
        0, 2,
        L"Enable feedback generation on disk and records a callback to display in the console.",
        L"        [LocalBackupDuration]: Time (in seconds) that the files will be kept on the machine before being deleted.\n"
          L"        [ThrottleTime]: Time (in seconds) that will be used for throttling introspection alerts.\n"
          L"            Setting it on 0 will disable the throttling mechanism.\n"
          L"        NOTE: in case not all paremeters are set, default values are used\n"
          L"        Example: enfeedback 240 1.\n"
          L"        See 'setpath' to set the feedback location\n"
          L"        See 'feedback' to set console output verbosity",
        _CmdEnableFeedback
    },
    {
        L"feedback", L"<mode>",
        1, 1,
        L"Allow printing the alerts received from the introspection in the application console.",
        L"        <mode>: 'silent' - do not print in console, 'noisy' - print in console\n"
          L"        See 'enfeedback' to actually enable feedback generation",
        _CmdFeedbackVerbosity
    },
    {
        L"setfailcnt", L"<maxThreshold>",
        1, 1,
        L"Configures the boot failsafe mechanism.",
        L"        <maxThreshold>: number of incomplete boots the hv will attempt before it will stop booting.\n"
          L"            0 means infinite\n"
          L"        Normally after boot, the driver connects to the hypervisor and the user mode component connects to the driver\n"
          L"        The hypervisor increments a fail counter and the user mode component resets it signaling a successful boot\n"
          L"        If this fail counter reaches the <maxThreshold> value, the hypervisor will abandon loading.\n",
        _CmdSetFailCounter
    },
    {
        L"resetfailcnt", NULL,
        0, 0,
        L"Reset the boot failsafe counter.",
        NULL,
        _CmdResetFailCounter
    },
    {
        L"protect", L"<process> <mask> <context>",
        3, 3,
        L"Add a process to be protected by the Introspection engine.",
        L"        <process>: name or full path of the process\n"
          L"        <mask>: flags that control protection policies.\n"
          L"            For a list of possible values see: Activation & protection flags\n"
          L"        <context>: Integrator-specific context that will be passed back by introcore\n"
          L"            when sending notifications related to this process",
        _CmdAddProcessToProtection
    },
    {
        L"unprotect", L"<process>",
        1, 1,
        L"Remove a protected process from the Introspection engine.",
        L"    <process>: name or the full path of the process",
        _CmdRemoveProcessFromProtection
    },
    {
        L"updateflags", L"<flags>",
        1, 1,
        L"Update the introspection flags.",
        L"        <Flags>: New flags to be applied\n"
          L"        Example: updateflags 0x293bfffff",
        _CmdUpdateIntroFlags
    },
    {
        L"exit", NULL,
        0, 0,
        L"Close the application.",
        NULL,
        _CmdExit
    },
};
#define NUMBER_OF_COMMANDS _countof(CommandLineCommands)

/**/
BOOLEAN
CmdLineInit(
    VOID
)
{
    BOOLEAN isSuccess = TRUE;
    // Here I found it useful to search if there
    // are two commands with the same name..
    for (DWORD i = 0; i < NUMBER_OF_COMMANDS - 1; ++i)
    {
        for (DWORD j = i + 1; j < NUMBER_OF_COMMANDS; ++j)
        {
            if (wcscmp(CommandLineCommands[i].CommandName, CommandLineCommands[j].CommandName) == 0)
            {
                wprintf(L"There are two commands with name = %s!\n",
                       CommandLineCommands[i].CommandName);
                isSuccess = FALSE;

                // Get out just of the first loop,
                // we can still find commands with the same name and display those
                break;
            }
        }
    }

    return isSuccess;
}

/**/
NTSTATUS
CmdLineMatchAndExecuteCommands(
    _In_    DWORD   Argc,
    _In_    WCHAR   **Argv
)
{
    // Argv[0] -> command name
    // Argv[1] -> first parameter
    // .... and so on

    if (Argc == 0)  { return STATUS_INVALID_PARAMETER_1; }
    if (!Argv)      { return STATUS_INVALID_PARAMETER_2; }

    return _CmdLineMatchAndExecuteCommands(Argc, Argv);
}

/**/
NTSTATUS
CmdLineParseUserStringAndExecuteCommands(
    _In_ WCHAR *UserString
)
{
#define MAX_USER_INPUT_ARGC 200
    if (!UserString) { return STATUS_INVALID_PARAMETER; }

    QWORD inputLength = wcsnlen_s(UserString, MAX_USER_INPUT_STRING_LENGTH);
    // If there is no null terminator within the first MAX_USER_INPUT_STRING_LENGTH bytes of the string
    // then STATUS_INVALID_PARAMETER is returned to indicate the error condition.
    if (inputLength == MAX_USER_INPUT_STRING_LENGTH) { return STATUS_INVALID_PARAMETER; }

    // Here we should parse the string and transform it into a command line
    // which is described by Argc and Argv, and then we can call
    // the _CmdLineMatchAndExecuteCommands function.
    DWORD argc = 0;
    WCHAR *argv[MAX_USER_INPUT_ARGC] = { NULL };
    DWORD index = 0;
    while (TRUE)
    {
        // Skip leading spaces
        while ((UserString[index] == L' ') && (index < inputLength)) { ++index; }

        // All the (remaining) string was just spaces
        // or we reach the end of the string.
        // Stop processing if no more chars.
        if (index >= inputLength) { break; }

        // Found argv
        argv[argc++] = &(UserString[index]);

        if (argc >= MAX_USER_INPUT_ARGC) { break; }

        // Skip current argv until we got a space or end of string
        while ((UserString[index] != L' ') && index < inputLength) { ++index; }
        UserString[index] = 0;
        ++index;
    }

    return _CmdLineMatchAndExecuteCommands(argc, argv);
}

/* Static functions */
static
NTSTATUS
_CmdLineMatchAndExecuteCommand(
    _In_ DWORD  Argc,
    _In_ WCHAR  **Argv
)
{
    WCHAR *commandName = Argv[0];
    DWORD paramCount = Argc - 1;

    if (!commandName) { return STATUS_NOT_FOUND; }

    for (DWORD i = 0; i < NUMBER_OF_COMMANDS; ++i)
    {
        if (wcscmp(commandName, CommandLineCommands[i].CommandName) == 0)
        {
            // Command matched. Execute its handler

            if (paramCount < CommandLineCommands[i].MinParamCount || paramCount > CommandLineCommands[i].MaxParamCount)
            {
                wprintf(L"Invalid number of arguments. See 'help %s' for reference!\n", commandName);
                return STATUS_INVALID_PARAMETER;
            }

            return CommandLineCommands[i].CommandHandler(paramCount, &Argv[1]);
        }
    }

    wprintf(L"Unrecognized command: %s. See 'help' for available commands!\n", commandName);
    return STATUS_NOT_FOUND;
}

static
NTSTATUS
_CmdLineMatchAndExecuteCommands(
    _In_ DWORD  Argc,
    _In_ WCHAR  **Argv
)
{
    // The application can receive a series of commands, delimited by "+".
    // Now we have to find each command, and for each command
    // we need to compute its Argc and Argv and then call the command.
#define COMMANDS_DELIMITER L"+"
#define MAX_NUMBER_OF_COMMANDS_IN__USER_STRING 100

    DWORD numberOfCommandsFound = 1;    // If we reach this point, at least one command
                                        // was sent
    DWORD argcForEveryCommand[MAX_NUMBER_OF_COMMANDS_IN__USER_STRING] = { 0 };
    WCHAR **argvForEveryCommand[MAX_NUMBER_OF_COMMANDS_IN__USER_STRING];
    argvForEveryCommand[0] = Argv;      // Initialize first command argv to point
                                        // right at the beginning of the user string

    for (DWORD wordIndex = 0; wordIndex < Argc; ++wordIndex)
    {
        // If we did not find a delimiter,
        // we must increase the argc of the current command
        if (wcscmp(COMMANDS_DELIMITER, Argv[wordIndex]) != 0)
        {
            ++argcForEveryCommand[numberOfCommandsFound - 1];
        }
        else
        {
            // If we found a delimiter but it's nothing after
            // we can ignore
            if (wordIndex + 1 == Argc) { break; }

            // If we reach here, that means we found a legit delimiter.
            // Increase number of commands found and prepare the argv
            // for the new command found to point right after the delimiter
            // (=> to point to the name of the command).
            if (++numberOfCommandsFound > MAX_NUMBER_OF_COMMANDS_IN__USER_STRING) { break; }
            argvForEveryCommand[numberOfCommandsFound - 1] = &Argv[wordIndex + 1];
        }
    }

    // Now that we have for each command its argc and argv,
    // we can call them one at a time in the order in which they were introduced.
    for (DWORD command = 0; command < numberOfCommandsFound; ++command)
    {
        NTSTATUS status = _CmdLineMatchAndExecuteCommand(argcForEveryCommand[command], argvForEveryCommand[command]);
        if (!NT_SUCCESS(status)) { return status; }
    }

    return STATUS_SUCCESS;
}

/* Available commands */
static
NTSTATUS
_CmdHelp(
    _In_    DWORD   Argc,
    _In_    WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argv);

    BOOLEAN all = Argc == 0;
    BOOLEAN verbose = Argc == 1;

    if (Argc == 1 && _wcsicmp(Argv[0], L"*") == 0) all = TRUE;

    if (all) wprintf(L"The following commands are available:\n");

    for (DWORD i = 0; i < NUMBER_OF_COMMANDS; ++i)
    {
        if (all || _wcsicmp(Argv[0], CommandLineCommands[i].CommandName) == 0)
        {
            if (verbose)
                wprintf(L" * %s %s\n      %s\n%s\n\n",
                    CommandLineCommands[i].CommandName,
                    CommandLineCommands[i].Parameters ? CommandLineCommands[i].Parameters : L"",
                    CommandLineCommands[i].HelpBrief,
                    CommandLineCommands[i].HelpFull ? CommandLineCommands[i].HelpFull : L"");

            else
                wprintf(L" * %s: %s\n",
                    CommandLineCommands[i].CommandName,
                    CommandLineCommands[i].HelpBrief);
        }
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
_CmdExit(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    // Uninit functions for components should be called here.

    if (IsApplicationConnectedToDriver)
    {
        Winguest.DisconnectFromDriver();
    }

    ImportsUninit();

    ExitProcess(0);
}

static
NTSTATUS
_CmdInstallDriver(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Installing driver\n");

    WCHAR *infPath = Argv[0];
    WCHAR *hardwareId = Argv[1];

    NTSTATUS status = Winguest.InstallDriver(infPath, hardwareId, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestInstallDriver failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdUninstallDriver(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Uninstalling driver\n");

    WCHAR *infPath = Argv[0];
    WCHAR *hardwareId = Argv[1];

    NTSTATUS status = Winguest.UninstallDriver(infPath, hardwareId, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestUninstallDriver failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdSetPath(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Setting path\n");

    WCHAR *directoryPath = Argv[1];
    CONFIG_PATH configPathId = _wtoi(Argv[0]);

    NTSTATUS status = Winguest.SetPath(configPathId, directoryPath);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestSetPath failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdConfigure(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    wprintf(L"Configuring\n");

    BOOLEAN enabled;
    if (_wcsicmp(Argv[0], L"enable") == 0)
    {
        enabled = TRUE;
    }
    else if (_wcsicmp(Argv[0], L"disable") == 0)
    {
        enabled = FALSE;
    }
    else
    {
        wprintf(L"Invalid parameters!\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    CHAR *commandLine = NULL;
    WCHAR *commandLineWide = Argc == 2 ? Argv[1] : NULL;
    if (commandLineWide)
    {
        size_t commandLineSize = wcslen(commandLineWide) + 1;
        commandLine = (CHAR *)malloc(commandLineSize);
        if (!commandLine) { return STATUS_MEMORY_NOT_ALLOCATED; }

        size_t returnValue;
        wcstombs_s(&returnValue, commandLine, commandLineSize, commandLineWide, commandLineSize - 1);
    }

    NTSTATUS status = Winguest.ConfigureHypervisor(enabled, commandLine);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestConfigureHypervisor failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    if (commandLine) { free(commandLine); }

    return status;
}

static
NTSTATUS
_CmdConnectToDriver(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    wprintf(L"Connecting to driver\n");

    NTSTATUS status = Winguest.ConnectToDriver();
    if (!NT_SUCCESS(status))
    {
        wprintf(L"Connect to driver failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }
    else
    {
        IsApplicationConnectedToDriver = TRUE;
    }

    return status;
}

static
NTSTATUS
_CmdDisconnectFromDriver(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    wprintf(L"Disconnecting from driver\n");

    NTSTATUS status = Winguest.DisconnectFromDriver();
    if (!NT_SUCCESS(status))
    {
        wprintf(L"Disconnect from driver failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }
    else
    {
        IsApplicationConnectedToDriver = FALSE;
    }

    return status;
}

static
NTSTATUS
_CmdAddProcessToProtection(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Adding protection for process\n");

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    WCHAR *processPath = Argv[0];

    DWORD protectMask = wcstoul(Argv[1], NULL, 0);
    if (protectMask == 0)
    {
        wprintf(L"Invalid protect mask!\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    QWORD context = wcstoull(Argv[2], NULL, 0);

    NTSTATUS status = Winguest.SetProtectedProcess(processPath, protectMask, context);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestSetProtectedProcess failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdRemoveProcessFromProtection(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Removing protection for process\n");

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    WCHAR *processPath = Argv[0];

    NTSTATUS status = Winguest.SetProtectedProcess(processPath, 0, 0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestSetProtectedProcess failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdSetFailCounter(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Setting fail counter\n");

    DWORD allowedCount = wcstoul(Argv[0], NULL, 0);

    NTSTATUS status = Winguest.ConfigureLoadMonitor(&allowedCount, FALSE);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestConfigureLoadMonitor failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdResetFailCounter(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    wprintf(L"Resetting fail counter\n");

    NTSTATUS status = Winguest.ConfigureLoadMonitor(NULL, TRUE);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestConfigureLoadMonitor failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdUpdateIntroFlags(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    wprintf(L"Setting introspection flags\n");

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    QWORD introFlags = wcstoull(Argv[0], NULL, 0);

    INTRO_CONTROL_MODULE_DATA icmd;
    icmd.ControlData.Options = introFlags;
    icmd.ControlFieldsToApply = FLAG_INTRO_CONTROL_OPTIONS;

    NTSTATUS status = Winguest.ControlModule(
        compIntro,
        &icmd,
        sizeof(icmd),
        0
    );
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestControlModule failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdQueryIntrospection(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    INTRO_QUERY_MODULE_DATA iqmd;
    NTSTATUS status = Winguest.QueryModule(
        compIntro,
        &iqmd,
        sizeof(iqmd),
        0
    );
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestQueryModule failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
        return status;
    }

    wprintf(L"Introspection is %s!\n", iqmd.Enabled ? L"ON" : L"OFF");
    if (iqmd.Enabled) { wprintf(L"Options = 0x%I64x\n", iqmd.Options); }

    return STATUS_SUCCESS;
}

static
NTSTATUS
_CmdQueryNapoca(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    BOOLEAN     configured;
    BOOLEAN     started;
    BOOT_MODE   bootMode;

    NTSTATUS status = Winguest.GetHvStatus(&configured, &started, &bootMode);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestGetHvStatus failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
        return status;
    }

    if (configured)
    {
        wprintf(L"Napoca is configured!\n");
        if (started)
        {
            wprintf(L"Napoca is running! Boot mode = %d\n", bootMode);
        }
        else
        {
            wprintf(L"Napoca is NOT running!\n");
        }
    }
    else
    {
        wprintf(L"Napoca is NOT configured!\n");
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
_CmdGetMissingFeatures(
    _In_ DWORD   Argc,
    _In_ WCHAR   **Argv
)
{
    UNREFERENCED_PARAMETER((Argc, Argv));

    HV_CONFIGURATION_MISSING_FEATURES missingFeatures;
    NTSTATUS status = Winguest.GetMissingFeatures(&missingFeatures);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"WinguestGetMissingFeatures failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
        return status;
    }

    for (DWORD i = 0; i < ARRAYSIZE(missingFeatures.MissingFeatures); ++i)
    {
        wprintf(L"0x%x ", missingFeatures.MissingFeatures[i]);
    }
    wprintf(L"\n");

    return STATUS_SUCCESS;
}

static
NTSTATUS
_CmdEnableFeedback(
    _In_ DWORD  Argc,
    _In_ WCHAR  **Argv
)
{
    wprintf(L"Enabling feedback\n");

    if (!IsApplicationConnectedToDriver)
    {
        wprintf(L"Aplication should be connected to driver in order to process this command!\n");
        return STATUS_UNSUCCESSFUL;
    }

    static const QWORD defaultDiskPersistenceTime = 10 * 60;
    static const QWORD defaultThrottleTime = 1;

    QWORD localBackupDuration = Argc > 0 ? wcstoull(Argv[0], NULL, 0) : defaultDiskPersistenceTime;
    QWORD throttleTime = Argc > 1 ? wcstoull(Argv[1], NULL, 0) : defaultThrottleTime;

    NTSTATUS status = FeedbackEnable(&localBackupDuration, &throttleTime);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"Feedback enable failed with status = %S (0x%x)\n", Winguest.NtStatusToString(status), status);
    }

    return status;
}

static
NTSTATUS
_CmdFeedbackVerbosity(
    _In_ DWORD  Argc,
    _In_ WCHAR  **Argv
)
{
    UNREFERENCED_PARAMETER(Argc);

    BOOLEAN noisy;

    if (_wcsicmp(Argv[0], L"silent") == 0)
    {
        noisy = FALSE;
    }
    else if (_wcsicmp(Argv[0], L"noisy") == 0)
    {
        noisy = TRUE;
    }
    else
    {
        wprintf(L"Invalid parameters!\n");
        return STATUS_INVALID_PARAMETER_1;
    }

    return FeedbackSetVerbosity(noisy);
}
