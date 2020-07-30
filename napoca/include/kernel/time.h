/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup time
///@{

/** @file time.h
*   @brief TIME - tick, linear and wall time support
*   @remark IMPORTANT: time values are stored as CX_UINT64 fields, in nanosecond units
*/

#ifndef _TIME_H_
#define _TIME_H_

#include "core.h"
#include "kernel/cpuops.h"
#include "kernel/queue_ipc_common.h"
#include "kernel/hvintrin.h"

/// @brief Structure describing date and time.
typedef union _DATETIME {
    CX_UINT64 raw;
    struct
    {
        CX_UINT64 Microsec:10;       ///< [0-999]
        CX_UINT64 Millisec:10;       ///< [0-999]
        CX_UINT64 Second:6;          ///< [0-59]
        CX_UINT64 Minute:6;          ///< [0-59]
        CX_UINT64 Hour:5;            ///< [0-23]
        CX_UINT64 Day:5;             ///< [1-31]
        CX_UINT64 Month:4;           ///< [1-12]
        CX_UINT64 Year:12;           ///< [0-4095]
        CX_UINT64 DayOfWeek:3;       ///< [1-7]
        CX_UINT64 Reserved:2;        ///< MBZ
        CX_UINT64 RelativeTime:1;    ///< 1 for relative time values
    };
} DATETIME;

extern CX_UINT64 gStartupTsc;         ///< initial TSC value
extern CX_UINT64 gTscSpeed;           ///< invariant TSC speed / sec

// wall clock time constants
#define MICROSECONDS_PER_MILISECOND         1000ULL                                 ///< 1000 (1000 ms)
#define MICROSECONDS_PER_SECOND             (MICROSECONDS_PER_MILISECOND * 1000)    ///< 1000 * 1000 (1 s)
#define MICROSECONDS_PER_MINUTE             (MICROSECONDS_PER_SECOND * 60)          ///< 1000 * 1000 * 60 (1 min)
#define MICROSECONDS_PER_HOUR               (MICROSECONDS_PER_MINUTE * 60)          ///< 1000 * 1000 * 60 * 60 (1 hr)
#define MICROSECONDS_PER_DAY                (MICROSECONDS_PER_HOUR * 24)            ///< 1000 * 1000 * 60 * 60 * 24 (1 day)
#define MICROSECONDS_PER_YEAR               (MICROSECONDS_PER_DAY * 365)            ///< 1000 * 1000 * 60 * 60 * 24 * 365 (1 year)

#define ONE_MILLISECOND_IN_100NANOSECONDS   10000ULL            ///< 1000 * 10 (1000 us * 1000/100 ns)
#define ONE_MILLISECOND_IN_FEMPTOSECONDS    1000000000000ULL    ///< 1000 * 1000 * 1000 * 1000 (1000 us * 1000 ns * 1000 ps * 1000 fs)
#define ONE_MICROSECOND_IN_100NANOSECONDS   10ULL               ///< 10 (1000 ns / 100 ns)
#define ONE_100NS_IN_FEMPTOSECONDS          100000000ULL        ///< 1000 * 1000 * 100 (1000 ps * 1000 fs * 100 ns)
#define ONE_SECOND_IN_FEMPTOSECONDS         1000000000000000ULL ///< 1000 * 1000 * 1000 * 1000 * 100 (1000 ms * 1000 us * 1000 ns * 1000 ps * 1000 fs)
#define ONE_SECOND_IN_NANOSECONDS           1000000000ULL       ///< 1000 * 1000 * 1000 (1000 ms * 1000 us * 1000ns)
#define ONE_SECOND_IN_100NANOSECONDS        10000000ULL         ///< 1000 * 1000 * 10 (1000 ms * 1000 us * 1000/100 ns)
#define ONE_SECOND_IN_MICROSECONDS          1000000ULL          ///< 1000 * 1000 (1000 ms * 1000 us)
#define ONE_SECOND_IN_MICROSECONDS_SHIFT_APPROXIMATION 20ull    ///< Used for shifting time guard approximations
#define ONE_SECOND_IN_MILLISECONDS          1000ULL             ///< 1000 (1000 ms)
#define ONE_SECOND_IN_SECOND                1ULL                ///< 1 (1s)


#define ONE_MEGAHERTZ                   1000000ULL
#define ONE_GIGAHERTZ                   (1000 * ONE_MEGAHERTZ)

#define WORST_CASE_TSC_FREQ_VALUE       5000000000ull           ///< hard-coded frequency value in case when we don't know the Tsc speed of the invariant TSC

#define HvGetTscTickCount()             ((CX_UINT64)__rdtsc())                 ///< wrapper around RDTSC for getting the tick count
#define TSC2MS(x)                       (HvTscTicksDeltaToMilliseconds(x))     ///< A macro wrapper to shorten the function name


///
/// @brief        Creates a time-guard by calculating from the current TSC tick count, the future TSC tick count value which will be when
///               MicroSeconds time passed.
///
/// @param[in]    MicroSeconds                     The time in microseconds until the guard should last
///
/// @returns      The future TSC tick count, when the guard will be exceeded.
///
__forceinline
static
CX_UINT64
HvGetTimeGuard(
    _In_ CX_UINT32 MicroSeconds
)
{
    return HvGetTscTickCount() + (MicroSeconds * (gTscSpeed ? gTscSpeed : WORST_CASE_TSC_FREQ_VALUE) / ONE_SECOND_IN_MICROSECONDS);
}


///
/// @brief        Creates a time-guard FAST by calculating from the current TSC tick count, the future TSC tick count value which will be when
///               MicroSeconds time passed. It is a faster method of calculation using shift operation instead of division, to reduce
///               the calculation time to have a more precise guard start value.
///
/// @param[in]    MicroSeconds                     The time in microseconds until the guard should last
///
/// @returns      The future TSC tick count, when the guard will be exceeded.
///
/// @remark       The time interval of the guard is calculated by approximation. Recommended for very short period time-guards.
///
__forceinline
static
CX_UINT64
HvApproximateTimeGuardFast(
    _In_ CX_UINT32 MicroSeconds
)
{
    return HvGetTscTickCount() + ((MicroSeconds * (gTscSpeed ? gTscSpeed : WORST_CASE_TSC_FREQ_VALUE)) >> ONE_SECOND_IN_MICROSECONDS_SHIFT_APPROXIMATION);
}


///
/// @brief        Verifies if the given time-guard was exceeded (time ran out).
///
/// @param[in]    TimeGuard                        The time-guard which has to be verified against the current time.
///
/// @returns      TRUE if yes and FALSE otherwise
///
__forceinline
static
CX_BOOL
HvTimeout(
    _In_ CX_UINT64 TimeGuard
)
{
    return HvGetTscTickCount() > TimeGuard;
}


///
/// @brief        Calculates based on the TSC speed, how many TimeIntervals are completed in Ticks number of TSC ticks.
///
/// @param[in]    Ticks                            The number of TSC ticks
/// @param[in]    TimeInterval                     The time interval in which the conversion has to happen
///
/// @returns      The number of TimeInterval intervals.
///
__forceinline
CX_UINT64
HvTscTicksIntervalToTime(
    _In_ CX_UINT64 Ticks,
    _In_ CX_UINT64 TimeInterval
    )
{
    if (0 != gTscSpeed)
    {
        CX_UINT64 highResult;
        CX_UINT64 lowResult = HvMul128(Ticks, TimeInterval, &highResult);
        CX_UINT64 ignored;

        return CpuDiv128(lowResult, highResult, gTscSpeed, &ignored);
    }
    else
    {
        // if not yet initialized
        return 0;
    }
}


///
/// @brief        Transforms the number of ticks into milliseconds.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of milliseconds.
///
__forceinline
CX_UINT64
HvTscTicksDeltaToMilliseconds(
    _In_ CX_UINT64 Ticks
)
{
    return HvTscTicksIntervalToTime(Ticks, ONE_SECOND_IN_MILLISECONDS);
}


///
/// @brief        Transforms the number of ticks into microseconds.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of microseconds.
///
__forceinline
CX_UINT64
HvTscTicksDeltaToMicroseconds(
    _In_ CX_UINT64 Ticks
    )
{
    return HvTscTicksIntervalToTime(Ticks, ONE_SECOND_IN_MICROSECONDS);
}


///
/// @brief        Transforms the number of ticks into 100 nanosecond units.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of 100 nanosecond units.
///
__forceinline
CX_UINT64
HvTscTicksDeltaTo100Ns(
    _In_ CX_UINT64 Ticks
    )
{
    return HvTscTicksIntervalToTime(Ticks, ONE_SECOND_IN_100NANOSECONDS);
}


///
/// @brief        Transforms the number of ticks elapsed between StartTime and Endtime into milliseconds.
///
/// @param[in]    EndTime                          Tick count when the interval ended
/// @param[in]    StartTime                        Tick count when the interval started
///
/// @returns      The number of milliseconds.
///
__forceinline
CX_UINT64
HvTscTicksIntervalToMilliseconds(
    _In_ CX_UINT64 EndTime,
    _In_ CX_UINT64 StartTime
    )
{
    return HvTscTicksIntervalToTime(EndTime - StartTime, ONE_SECOND_IN_MILLISECONDS);
}


///
/// @brief        Transforms the number of ticks elapsed between StartTime and Endtime into microseconds.
///
/// @param[in]    EndTime                          Tick count when the interval ended
/// @param[in]    StartTime                        Tick count when the interval started
///
/// @returns      The number of microseconds.
///
__forceinline
CX_UINT64
HvTscTicksIntervalToMicroseconds(
    _In_ CX_UINT64 EndTime,
    _In_ CX_UINT64 StartTime
    )
{
    return HvTscTicksIntervalToTime(EndTime - StartTime, ONE_SECOND_IN_MICROSECONDS);
}


///
/// @brief        Transforms the number of ticks elapsed between StartTime and Endtime into 100 nanosecond units.
///
/// @param[in]    EndTime                          Tick count when the interval ended
/// @param[in]    StartTime                        Tick count when the interval started
///
/// @returns      The number of 100 nanosecond units.
///
__forceinline
CX_UINT64
HvTscTicksIntervalTo100Ns(
    _In_ CX_UINT64 EndTime,
    _In_ CX_UINT64 StartTime
    )
{
    return HvTscTicksIntervalToTime(EndTime - StartTime, ONE_SECOND_IN_100NANOSECONDS);
}


///
/// @brief        Calculates the elapsed time from the startup time in milliseconds based on the tick count received.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of milliseconds elapsed from the start.
///
__forceinline
CX_UINT64
HvTscTicksToLinearTimeMilliseconds(
    _In_ CX_UINT64 Ticks
    )
{
    return HvTscTicksIntervalToMilliseconds(Ticks, gStartupTsc);
}


///
/// @brief        Calculates the elapsed time from the startup time in microseconds based on the tick count received.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of microseconds elapsed from the start.
///
__forceinline
CX_UINT64
HvTscTicksToLinearTimeMicroseconds(
    _In_ CX_UINT64 Ticks
    )
{
    return HvTscTicksIntervalToMicroseconds(Ticks, gStartupTsc);
}


///
/// @brief        Calculates the elapsed time from the startup time in 100 nanosecond units based on the tick count received.
///
/// @param[in]    Ticks                            The number of ticks.
///
/// @returns      The number of 100 nanosecond units elapsed from the start.
///
__forceinline
CX_UINT64
HvTscTicksToLinearTime100Ns(
    _In_ CX_UINT64 Ticks
    )
{
    return HvTscTicksIntervalTo100Ns(Ticks, gStartupTsc);
}


///
/// @brief        Calculates the elapsed time from the startup time in milliseconds.
///
/// @returns      The number of milliseconds elapsed from the start.
///
__forceinline
CX_UINT64
HvGetLinearTimeInMilliseconds(
    void
    )
{
    return HvTscTicksToLinearTimeMilliseconds(HvGetTscTickCount());
}


///
/// @brief        Calculates the elapsed time from the startup time in microseconds.
///
/// @returns      The number of microseconds elapsed from the start.
///
__forceinline
CX_UINT64
HvGetLinearTimeInMicroseconds(
    void
    )
{
    return HvTscTicksToLinearTimeMicroseconds(HvGetTscTickCount());
}

///
/// @brief        Calculates the elapsed time from the startup time in microseconds using fast calculation method.
///
///               For a one day time interval we have about (20 bits * ~33 bits) / (16 bits) => 53 bits / 16 bits
///               an overflow would occur in 3106 days if gTscSpeed is at most 4Gz (4294967295)
///               at 4GHz, this approximation has an error of around 1/16384 s (about 61 micro-seconds)
///
/// @returns      The number of milliseconds elapsed from the start.
///
__forceinline
CX_UINT64
HvApproximateLinearTimeInMicrosecondsFast(
    void
)
{
    CX_UINT64 passedTicks = (HvGetTscTickCount() - gStartupTsc);

    return gTscSpeed? (ONE_SECOND_IN_MICROSECONDS * (passedTicks >> 16)) / (gTscSpeed >> 16) : 0;
}


///
/// @brief        Calculates the elapsed time from the startup time in 100 nanosecond units.
///
/// @returns      The number of 100 nanosecond units elapsed from the start.
///
__forceinline
CX_UINT64
HvGetLinearTimeIn100Ns(
    void
    )
{
    return HvTscTicksToLinearTime100Ns(HvGetTscTickCount());
}


///
/// @brief  Initializes the wall clock time support for the hypervisor.
///
/// @returns    CX_STATUS_SUCCESS                       - in case everything went well
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE        - in case the invariant TSCs speed is 0
///
CX_STATUS
HvInitTime(
    void
);


///
/// @brief        Reads the current date and time, either directly from CMOS or tries to calculate  based on the invariant
///               TSC (not implemented).
///
/// @param[out]   DateTime                         The current date and time
/// @param[in]    GetDirectBareMetal               If TRUE, will get time directly from hardware(CMOS), if FALSE, will calculate based on TSC (Not implemented)
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case DateTime is an invalid pointer
/// @returns      CX_STATUS_OPERATION_NOT_IMPLEMENTED - in case GetDirectBareMetal is FALSE
///
CX_STATUS
HvGetWallClockDateTime(
    _Out_ DATETIME *DateTime,
    _In_ CX_BOOL GetDirectBareMetal
    );


///
/// @brief        Prints the current date and time.
///
CX_VOID
HvPrintTimeInfo(
    void
);


///
/// @brief        Wait a certain amount of microseconds.
///
/// @param[in]    Microseconds                     The amount of microseconds the CPU has to wait
///
void
HvSpinWait(
    _In_ CX_UINT64 Microseconds
    );


#endif // _TIME_H_

///@}