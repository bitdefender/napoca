/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CMDLINE_H_
#define _CMDLINE_H_

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

// If a command line has not been received at the start of the process,
// we will have to request a string as an input from a user, a string that
// will be transformed into a command line.
// We consider that a 512 character limit is more than sufficient for that string
#define MAX_USER_INPUT_STRING_LENGTH    512

/**/ BOOLEAN    CmdLineInit(VOID);
/**/ NTSTATUS   CmdLineMatchAndExecuteCommands(_In_ DWORD Argc, _In_ WCHAR **Argv);
/**/ NTSTATUS   CmdLineParseUserStringAndExecuteCommands(_In_ WCHAR *UserString);

#endif // !_CMDLINE_H_
