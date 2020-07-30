/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file is providing NAPOCA custom declarations and/or definitions needed by the common/kernel/* files
//

#ifndef _KERNEL_INTERFACE_H_
#define _KERNEL_INTERFACE_H_

#include "napoca.h"
#include "kernel/kernel.h"
#include "common/communication/ringbuf.h"

#define FEAT_PRINT          LOG
#define FEAT_PRINTN         LOGN


#define CPU_IRQL_HIGH_LEVEL 0
#define CPU_DEBUG_BREAK()


typedef CX_UINT8 CPU_IRQL;

__forceinline
CPU_IRQL
CpuRaiseIrqlToDpcLevel(
    CX_VOID
)
{
    return 0;
}

__forceinline
CX_VOID
CpuRaiseIrql(
    CPU_IRQL Irql,
    CPU_IRQL *OldIrql
)
{
    CX_UNREFERENCED_PARAMETER(Irql, OldIrql);
    return;
}

__forceinline
CX_VOID
CpuLowerIrql(
    _In_ CPU_IRQL Irql
)
{
    CX_UNREFERENCED_PARAMETER(Irql);
    return;
}

__forceinline
CX_STATUS
CpuDelayExecution(
    _In_ CX_BOOL Alertable,
    _In_ CX_BOOL IsRelativeInterval,
    _In_ CX_UINT64 MicrosecondsInterval
)
{
    CX_UNREFERENCED_PARAMETER(Alertable);
    if (IsRelativeInterval)
    {
        HvSpinWait(MicrosecondsInterval);
        return CX_STATUS_SUCCESS;
    }
    return CX_STATUS_OPERATION_NOT_SUPPORTED;
}

__forceinline
CX_UINT32
CpuGetCurrentApicId(
    CX_VOID
)
{
    return __readgsdword(FIELD_OFFSET(PCPU, Id));
}


#endif // _KERNEL_INTERFACE_H_


