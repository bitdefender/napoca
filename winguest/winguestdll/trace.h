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

User mode

--*/

//
// Define the tracing flags.
//
// WPP Tracing GUID for winguestdll.dll - 27776CBB-9A75-4F13-8832-ADC9A54CAC06
// WPP Tracing GUID for Hypervisor      - 29ACED2D-F187-4F43-B94C-6BFC475AC538
//

#define WPP_CONTROL_GUIDS                                               \
    WPP_DEFINE_CONTROL_GUID(                                            \
        WinguestdllTraceGuid, (27776CBB,9A75,4F13,8832,ADC9A54CAC06),   \
        WPP_DEFINE_BIT(TRACE_GENERIC)         /* bit  0 = 0x00000001 */ \
        )                                                               \
    WPP_DEFINE_CONTROL_GUID(                                            \
        HypervisorTraceGuid, (29ACED2D,F187,4F43,B94C,6BFC475AC538),    \
        WPP_DEFINE_BIT(TRACE_HV)              /* bit  0 = 0x00000001 */ \
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

// Hypervisor
// FUNC LogHv{LEVEL=TRACE_LEVEL_INFORMATION, FLAGS=TRACE_HV}(MSG, ...);

// other

// FUNC Trace{FLAG=MYDRIVER_ALL_INFO}(LEVEL, MSG, ...);
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);

//
// end_wpp
//

#endif // _TRACE_H_
