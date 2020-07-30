/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// DEBUGGER - interactive debugger support

#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

#include "coredefs.h"
#include "base/cx_sal.h"
#include "base/cx_types.h"
#include "wrappers/cx_wintypes.h"

#include "io/vga.h"

typedef struct _HV_TRAP_FRAME HV_TRAP_FRAME;
typedef struct _VCPU VCPU;

//
// Prototypes
//

CX_STATUS
DbgInit(
    CX_VOID
);

// This function is mostly a wrapper over Interpreter.
// But since there are also debugging commands implemented by the Introspection
// that the interpreter does not recognize,
// we preferred to include in this wrapper the sequence of code
// that deals with the recognition of introspection commands.
CX_BOOL
DbgMatchCommand(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Echo,
    __out_opt   CX_BOOL     *PartialMatch
);

#define  DbgScheduleDebugger()                              DbgScheduleDebugger_(__FILE__, __LINE__)
CX_STATUS
DbgScheduleDebugger_(
    _In_ CHAR       *File,
    _In_ CX_UINT32  Line
    );

#define DbgBreak()                                          DbgEnterDebugger3(CX_FALSE, __FILE__, __LINE__, 0)
#define DbgEnterDebugger()                                  DbgEnterDebugger3(CX_FALSE, __FILE__, __LINE__, 0)
#define DbgBreakIgnoreCleanupIKnowWhatImDoing()             DbgEnterDebugger3(CX_TRUE, __FILE__, __LINE__, 0)
#define DbgBreakIgnoreCleanupIKnowWhatImDoingOp(Options)    DbgEnterDebugger3(CX_TRUE, __FILE__, __LINE__, (Options))
CX_STATUS
DbgEnterDebugger3(
    _In_ CX_BOOL    AlwaysBreakIgnoreCleanupIKnowWhatImDoing,
    _In_ CHAR       *File,
    _In_ CX_UINT32  Line,
    _In_ CX_UINT32  Options
    );

// The debugger can send an NMI to a processor
// for it to print it's stack.
// This handler take care of this request (if the request exists).
CX_VOID
DbgNmiHandler(
    _In_  HV_TRAP_FRAME   *TrapFrame
);

#define HvHalt()                                                        \
{   VgaDebug();                                                         \
    VgaSetColor(0x0e00);                                                \
    DbgEnterDebugger();                                                 \
    HvPrint("***EXPLICIT HALT*** from %s%d\n", __FILE__, __LINE__);     \
    if (!CfgFeaturesUnloadOnErrorsEnabled) __halt();                    \
}


CX_VOID
DbgPreHandlerDebugActions(
    _In_ VCPU* Vcpu
);

CX_VOID
DbgPostHandlerDebugActions(
    _In_ VCPU* Vcpu
);

CX_VOID
DbgHandleInstructionTracing(
    _In_ VCPU* Vcpu,
    _In_ WORD Cs,
    _In_ QWORD Rip
);

#endif // _DEBUGGER_H_