/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "core.h"
#include "debug/perfstats.h"

CX_STATUS
PerfAccountEvent(
    _In_ PERF_STATS *Stats,
    _In_ CX_UINT64 DeltaTsc
)
{
    PERF_STATS_PACKED_BITFIELD oldPacked, newPacked;

    // total tsc
    CxInterlockedAdd64(&Stats->TotalTsc, DeltaTsc);

    // min
    CX_UINT64 timeout = HvApproximateTimeGuardFast(PERF_TIMEOUT);
    do
    {
        oldPacked = Stats->Packed;
        newPacked = oldPacked;
        newPacked.MinTscPerEvent = DeltaTsc;
        if (HvTimeout(timeout)) { ERROR("Timeout!\n"); timeout = HvApproximateTimeGuardFast(PERF_TIMEOUT); }
    } while ((!oldPacked.MinTscPerEvent || (DeltaTsc < oldPacked.MinTscPerEvent))
             && (oldPacked.Raw != CxInterlockedCompareExchange64(&Stats->Packed.Raw, newPacked.Raw, oldPacked.Raw)));

    // max
    CX_UINT64 oldMax;
    timeout = HvApproximateTimeGuardFast(PERF_TIMEOUT);
    do
    {
        oldMax = Stats->MaxTscPerEvent;
        if (HvTimeout(timeout)) { ERROR("Timeout!\n"); timeout = HvApproximateTimeGuardFast(PERF_TIMEOUT); }
    } while ((DeltaTsc > oldMax) && (oldMax != CxInterlockedCompareExchange64(&Stats->MaxTscPerEvent, DeltaTsc, oldMax)));

    // counter
    CxInterlockedIncrement64(&Stats->TotalEvents);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PerfReset(
    _Inout_ PERF_STATS *Stats,
    _In_ CX_UINT32 NumberOfEntries
)
{
    for (CX_UINT32 i = 0; i < NumberOfEntries; i++)
    {
        PERF_STATS *s = &Stats[i];
        memzero((CX_VOID *)s, sizeof(*s));
    }

    return CX_STATUS_SUCCESS;
}