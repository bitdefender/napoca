/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _TRACE_H_
#define _TRACE_H_

/*++

Module Name:

trace.h

Abstract:

Header file for the debug tracing related function definitions and macros.

Environment:

Kernel mode

--*/

//
// Define the tracing flags.
//
// WPP Tracing GUID for winguest.sys - D61C268D-91EC-4C89-A90A-38BAE0C757E7
//

#define WPP_CONTROL_GUIDS                                               \
    WPP_DEFINE_CONTROL_GUID(                                            \
        WinguestTraceGuid, (D61C268D,91EC,4C89,A90A,38BAE0C757E7),      \
        WPP_DEFINE_BIT(TRACE_GENERIC)         /* bit  0 = 0x00000001 */ \
        )

#define WPP_FLAG_LEVEL_LOGGER(flag, level)          WPP_LEVEL_LOGGER(flag)
#define WPP_FLAG_LEVEL_ENABLED(flag, level)         (WPP_LEVEL_ENABLED(flag) && WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl, flags)          WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags)         (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

#define WPP_LEVEL_FLAGS_STATUS_LOGGER(lvl, flags, status)       WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_STATUS_ENABLED(lvl, flags, status)      (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)


//
// This comment block is scanned by the trace preprocessor to define our
// Trace function.
//
// begin_wpp config
//

// basic messages

// FUNC LogVerbose{LEVEL=TRACE_LEVEL_VERBOSE, FLAGS=TRACE_GENERIC}(MSG, ...);
// FUNC LogInfo{LEVEL=TRACE_LEVEL_INFORMATION, FLAGS=TRACE_GENERIC}(MSG, ...);
// FUNC LogWarning{LEVEL=TRACE_LEVEL_WARNING, FLAGS=TRACE_GENERIC}(MSG, ...);
// FUNC LogError{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_GENERIC}(MSG, ...);
// FUNC LogCritical{LEVEL=TRACE_LEVEL_CRITICAL, FLAGS=TRACE_GENERIC}(MSG, ...);

// error handling

// for NTSTATUS / ntstatus.h
// FUNC LogFuncErrorStatus{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_GENERIC}(STATUS, MSG, ...);
// USESUFFIX (LogFuncErrorStatus, " failed with %!STATUS!", STATUS);

// for HRESULT / winerror.h
// FUNC LogFuncErrorHr{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_GENERIC}(STATUS, MSG, ...);
// USESUFFIX (LogFuncErrorHr, " failed with %!HRESULT!", STATUS);

// for GetLastError / winerror.h
// FUNC LogFuncErrorLastErr{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_GENERIC}(STATUS, MSG, ...);
// USESUFFIX (LogFuncErrorLastErr, " failed with %!WINERROR!", STATUS);

// for other error types
// FUNC LogFuncError{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_GENERIC}(STATUS, MSG, ...);
// USESUFFIX (LogFuncError, " failed with 0x%X", STATUS);

// other

// FUNC Trace{FLAG=MYDRIVER_ALL_INFO}(LEVEL, MSG, ...);
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);

//
// end_wpp
//

__forceinline
PUNICODE_STRING
SafeEmpty(
    PUNICODE_STRING String
)
{
    // routine created to account for a bug in WPP when printing empty Unicode strings.
    static UNICODE_STRING altEmpty = { sizeof(L"<EMPTY>") - sizeof(L'\0'), sizeof(L"<EMPTY>"), L"<EMPTY>" };

    return String->Length == 0
        ? &altEmpty
        : String;
}

#endif // _TRACE_H_