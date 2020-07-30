/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file is providing custom WINGUEST declarations and/or definitions needed by the common/kernel/* files
//
#ifndef _KERNEL_INTERFACE_H_
#define _KERNEL_INTERFACE_H_

#include "driver.h"

#define FEAT_PRINT(...)         (__VA_ARGS__)
#define FEAT_PRINTN(...)        (__VA_ARGS__)
#define CPU_IRQL_HIGH_LEVEL     HIGH_LEVEL

#ifdef CX_DEBUG_BUILD
#define CPU_DEBUG_BREAK() __debugbreak()
#else
#define CPU_DEBUG_BREAK()
#endif


typedef KIRQL CPU_IRQL;

#define PLOG_FUNC_FAIL

__forceinline
CPU_IRQL
CpuRaiseIrqlToDpcLevel(
    CX_VOID
)
{
    return KeRaiseIrqlToDpcLevel();
}

__forceinline
CX_VOID
CpuRaiseIrql(
    CPU_IRQL Irql,
    CPU_IRQL *OldIrql
)
{
    KeRaiseIrql(Irql, OldIrql);
}

__forceinline
CX_VOID
CpuLowerIrql(
    _In_ CPU_IRQL Irql
)
{
    KeLowerIrql(Irql);
}

__forceinline
CX_STATUS
CpuDelayExecution(
    _In_ CX_BOOL Alertable,
    _In_ CX_BOOL IsRelativeInterval,
    _In_ CX_UINT64 MicrosecondsInterval
)
{
    LARGE_INTEGER tmp;
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    tmp.QuadPart = IsRelativeInterval? 0 - (MicrosecondsInterval * 10) : (MicrosecondsInterval * 10);
    NTSTATUS status = KeDelayExecutionThread(KernelMode, Alertable, &tmp);
    if (!NT_SUCCESS(status))
    {
        return CX_STATUS_NOT_SUPPORTED;
    }
    return CX_STATUS_SUCCESS;
}

__forceinline
CX_UINT32
CpuGetCurrentApicId(
    CX_VOID
)
{
    // We don't need synchronization because each processor
    // will access a different zone from gSavedApicIdForCpu
    // depending on cpuIndex
    CX_UINT32 cpuIndex = KeGetCurrentProcessorNumber();

    // Cache miss?
    if (gSavedApicIdForCpu[cpuIndex] == APIC_ID_CACHE_CLEAR)
    {
        // Get current cpu apic id, save it in the cache & return it

        // The value returned by bits 31-24 of the EBX register (when the CPUID instruction is executed with a
        // source operand value of 1 in the EAX register) is always the Initial APIC ID
        // (determined by the platform initialization).
        // This is true even if software has changed the value in the Local APIC ID register.
        int cpuidRes[4];
        __cpuid(cpuidRes, 1);
        CX_UINT32 ebxOut = cpuidRes[1];
        CX_UINT8 currentCpuApicId = (ebxOut & 0xFF00'0000) >> 24;

        // Save to the cache
        gSavedApicIdForCpu[cpuIndex] = currentCpuApicId;

        return currentCpuApicId;
    }

    // Cache hit
    return gSavedApicIdForCpu[cpuIndex];
}

#endif // _KERNEL_INTERFACE_H_


