/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file documents the interface declarations needed for
// compiling common C files depending on kernel_interface.h
//

#ifndef FEAT_PRINT
#error "#define FEAT_PRINT(...) is not defined"
#endif

#ifndef FEAT_PRINTN
#error "#define FEAT_PRINTN(...) is not defined"
#endif

#ifndef CPU_DEBUG_BREAK
#error "#define CPU_DEBUG_BREAK() is not defined"
#endif


typedef CPU_IRQL            CPU_IRQL;

CPU_IRQL
CpuRaiseIrqlToDpcLevel(
    CX_VOID
);

CX_VOID
CpuRaiseIrql(
    CPU_IRQL Irql,
    CPU_IRQL *OldIrql
);

CX_VOID
CpuLowerIrql(
    _In_ CPU_IRQL Irql
);

CX_STATUS
CpuDelayExecution(
    _In_ CX_BOOL Alertable,
    _In_ CX_BOOL IsRelativeInterval,
    _In_ CX_UINT64 MicrosecondsInterval
);

CX_UINT32
__cdecl
CpuGetSecCapabilities(
    _In_ CX_UINT64 Selector
);

CX_UINT32
CpuGetCurrentApicId(
    CX_VOID
);
