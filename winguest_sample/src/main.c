/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <winnt.h>
#include <winternl.h>

#include <stdio.h>

#include "cmdline.h"
#include "imports.h"

DWORD wmain(DWORD Argc, WCHAR **Argv, WCHAR **Envp)
{
    UNREFERENCED_PARAMETER(Envp);

    if (!CmdLineInit()) { return 1; }

    // This application uses functions from winguestdll.dll.
    // We must initialize all imports and dll's before processing orders.
    NTSTATUS status = ImportsInit();
    if (!NT_SUCCESS(status)) { return 1; }

    // The application can be used both with and without the command line.
    // If the command line is used, the application will no longer require
    // input from the user but will parse and execute the command line, then exit.
    // If a command line is not given, the application will request input from the user.
    if (Argc > 1)
    {
        // We are in the case where we received the command line directly.
        // We send the command to the interpreter but we ignore the first argument
        // which is the name of the program.
        status = CmdLineMatchAndExecuteCommands(Argc - 1, &Argv[1]);
    }

    wprintf(L"\nWelcome to the NAPOCA Hypervisor sample configuration utility\n");
    wprintf(L"Type 'help' for available commands.\n");

    while (TRUE)
    {
        WCHAR userInputString[MAX_USER_INPUT_STRING_LENGTH] = { 0 };
        wprintf(L"Command: ");

        fgetws(userInputString, MAX_USER_INPUT_STRING_LENGTH - 1, stdin);
        size_t userInputLength = wcslen(userInputString);
        userInputString[userInputLength - 1] = 0; // Cut '\n'

        status = CmdLineParseUserStringAndExecuteCommands(userInputString);
    }

    return 0;
}