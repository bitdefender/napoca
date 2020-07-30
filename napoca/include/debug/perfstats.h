/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _PERFSTATS_H_
#define _PERFSTATS_H_

#include "core.h"
#include "kernel/time.h"
#include "io/io.h"

typedef union PERF_STATS_PACKED_BITS
{
    struct
    {
        CX_UINT64 BeginEndLock : 1;
        CX_UINT64 ReadLock : 1;
        CX_UINT64 WriteLock : 1;
        CX_UINT64 MinTscPerEvent : 64 - 3;
    };
    CX_UINT64 Raw;
}PERF_STATS_PACKED_BITFIELD;

typedef struct
{
    CX_UINT64 TotalEvents;
    CX_UINT64 TotalTsc;
    PERF_STATS_PACKED_BITFIELD Packed;
    CX_UINT64 MaxTscPerEvent;
}volatile PERF_STATS;

CX_STATUS
PerfAccountEvent(
    _In_ PERF_STATS *Stats,
    _In_ CX_UINT64 DeltaTsc
);

__forceinline
CX_STATUS
PerfAccountTransition(
    _In_ PERF_STATS *Stats,                       // current state/event structure to account stats before the actual transition
    _In_opt_ CX_UINT64 CurrentStateStartTsc,      // when did the current event/state start
    _Inout_ CX_UINT64 *NextStateStartTsc          // where should the start of the new state be remembered
)
{
    CX_UINT64 tmp = HvGetTscTickCount();
    CX_STATUS status = CX_STATUS_NOT_INITIALIZED_HINT;
    if (CurrentStateStartTsc)
    {
        status = PerfAccountEvent(Stats, tmp - CurrentStateStartTsc);
    }
    *NextStateStartTsc = tmp;
    return status;
}

#define PERF_TIMEOUT (5 * ONE_SECOND_IN_MICROSECONDS)

#define NO_COLUMN_ID 0xFFFFFFFF
__forceinline
void
PerfDumpHeaderEx(_In_ CX_UINT32 Column, _In_ char *Prefix, _In_ char *Name, _In_ char *Suffix)
{
    if (Column == NO_COLUMN_ID)
        LOGN("%s%-47s | %-10s | %-12s | %-8s | %-8s | %-8s%s", Prefix, Name? Name:"Event Name", "Count", "Total(ms)", "Avg(us)", "Min(us)", "Max(us)", Suffix);
    else
        if (0 == Column)
            LOGN("%s%-42s[%03d] | %-10s | %-12s | %-8s | %-8s | %-8s%s", Prefix, Name ? Name : "Event Name", Column, "Count", "Total(ms)", "Avg(us)", "Min(us)", "Max(us)", Suffix);
        else
            LOGN("%s[%03d] | %-10s | %-12s | %-8s | %-8s | %-8s%s", Prefix, Column, "Count", "Total(ms)", "Avg(us)", "Min(us)", "Max(us)", Suffix);
}

__forceinline
void
PerfDumpHeader(_In_ char *Name)
{
    PerfDumpHeaderEx(NO_COLUMN_ID, "", Name, "\n");
}

__forceinline
void
PerfDumpTableHeader(_In_ CX_UINT32 Columns, _In_opt_ char *Name)
{
    for (CX_UINT32 i = 0; i < Columns; i++)
    {
        PerfDumpHeaderEx(i, "", Name ? Name : "Event Name", i + 1 < Columns? " || " : "\n");
    }
}

__forceinline
void
PerfDumpSeparatorEx(_In_ CX_BOOL IsNamed, _In_ char *Prefix, _In_ char *Suffix)
{
    if (IsNamed)
        LOGN("%s----------------------------------------------- | ---------- | ------------ | -------- | -------- | --------%s", Prefix, Suffix);
    else
        LOGN("%s      | ---------- | ------------ | -------- | -------- | --------%s", Prefix, Suffix);
}

__forceinline
void
PerfDumpSeparator(void)
{
    PerfDumpSeparatorEx(CX_TRUE, "", "\n");
}

__forceinline
void
PerfDumpTableSeparator(_In_ CX_UINT32 Columns)
{
    for (CX_UINT32 i = 0; i < Columns; i++)
    {
        PerfDumpSeparatorEx(i == 0, "", i + 1 < Columns ? " || " : "\n");
    }
}

__forceinline
CX_STATUS
PerfDumpStats(PERF_STATS *Stats, char *Name)
{
    if (!Stats || !Stats->TotalEvents)
        return CX_STATUS_DATA_NOT_READY;

    LOGN("%-47s | %10lld | %12lld | %8lld | %8lld | %8lld\n",
        Name ? Name : "N/A",
        Stats->TotalEvents,
        HvTscTicksDeltaToMilliseconds(Stats->TotalTsc),
        Stats->TotalEvents ? HvTscTicksDeltaToMicroseconds(Stats->TotalTsc / Stats->TotalEvents) : 0,
        HvTscTicksDeltaToMicroseconds(Stats->Packed.MinTscPerEvent),
        HvTscTicksDeltaToMicroseconds(Stats->MaxTscPerEvent)
    );

    return CX_STATUS_SUCCESS;
}

__forceinline
CX_STATUS
PerfDumpColumnStats(CX_UINT32 ColumnNumber, PERF_STATS *Stats, char *Name, CX_BOOL IsLastColumn)
{
    if (!Stats || !Stats->TotalEvents)
    {
        if (ColumnNumber == 0)
        {
            LOGN("%-47s | %10s | %12s | %8s | %8s | %8s%s", Name ? Name : "N/A", "-", "-", "-", "-", "-", IsLastColumn ? "\n" : " || ");
        }
        else
        {
            LOGN("      | %10s | %12s | %8s | %8s | %8s%s", "-", "-", "-", "-", "-", IsLastColumn ? "\n" : " || ");
        }
        return CX_STATUS_NOT_INITIALIZED_HINT;
    }

    if (ColumnNumber == 0)
    {
        LOGN("%-47s | %10lld | %12lld | %8lld | %8lld | %8lld%s",
            Name ? Name : "N/A",
            Stats->TotalEvents,
            HvTscTicksDeltaToMilliseconds(Stats->TotalTsc),
            Stats->TotalEvents ? HvTscTicksDeltaToMicroseconds(Stats->TotalTsc / Stats->TotalEvents) : 0,
            HvTscTicksDeltaToMicroseconds(Stats->Packed.MinTscPerEvent),
            HvTscTicksDeltaToMicroseconds(Stats->MaxTscPerEvent), IsLastColumn ? "\n" : " || "
        );
    }
    else
    {
        LOGN("      | %10lld | %12lld | %8lld | %8lld | %8lld%s",
            Stats->TotalEvents,
            HvTscTicksDeltaToMilliseconds(Stats->TotalTsc),
            Stats->TotalEvents ? HvTscTicksDeltaToMicroseconds(Stats->TotalTsc / Stats->TotalEvents) : 0,
            HvTscTicksDeltaToMicroseconds(Stats->Packed.MinTscPerEvent),
            HvTscTicksDeltaToMicroseconds(Stats->MaxTscPerEvent), IsLastColumn ? "\n" : " || "
        );
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PerfReset(
    _Inout_ PERF_STATS *Stats,
    _In_ CX_UINT32 NumberOfEntries
);

#endif