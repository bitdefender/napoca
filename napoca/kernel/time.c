/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup time Time support for NapocaHv, tick, linear and wall time support
///@{

/** @file time.c
*   @brief TIME - tick, linear and wall time support
*   @remark IMPORTANT: time values are stored as CX_UINT64 fields, in nanosecond units
*/

#include "napoca.h"
#include "kernel/kernel.h"

CX_UINT64 gStartupTsc = 0;                         ///< initial TSC value
static DATETIME gStartupTime;                      ///< initial wall clock time
CX_UINT64 gTscSpeed = 0;                           ///< invariant TSC speed / sec
static SPINLOCK gTimeInitLock;                     ///< lock used for time reading and calculation


///
/// @brief Support to convert Binary-Coded-Decimal to Integer for legacy RTC / CMOS
///
#define BCD_TO_INT(x)           ((((x) & 0xF0) >> 4)*10 + ((x) & 0x0F))


///
/// @brief        Initializes the start-up date and time, startup TSC and TSC speed
///
/// @returns      CX_STATUS_SUCCESS                - always
///
static
CX_STATUS
_HvInitTimeUsingPit(
    );


///
/// @brief        It determines how many times the TSC is incremented in one second.
///
///               This function is called very early during HV initialization. It determines how many
///               times the TSC is incremented in one second. This is done by using PIT Ch2 timer
///               programmed in "interrupt on terminal count" mode.
///
/// @returns      How many times the TSC is incremented in one second.
///
static
CX_UINT64
_HvGetTscInOneSecond(
    CX_VOID
);


///
/// @brief        Reads the given register of the CMOS.
///
/// @param[in]    Reg                              Register offset
///
/// @returns      The value read from the CMOS register
///
/// @remark       When executing these readings, interrupts should be disabled.
///
static
CX_UINT8
_HvReadCmosRegister(
    _In_ CX_UINT8 Reg
    )
{
    CX_UINT8 value;

    // The operation that follows a write operation to address 0x70 must read from address 0x71;
    // otherwise intermittent malfunctions and unreliable operation of the RT / CMOS RAM can occur.
    __outbyte(0x70, Reg | 0x80); // 0x80 means disable NMI
    value = __inbyte(0x71);
    __outbyte(0x70, 0);          // re-enable NMI

    return value;
}


CX_STATUS
HvInitTime(
    void
    )
{
    CX_STATUS status;

    HvInitSpinLock(&gTimeInitLock, "gTimeInitLock", CX_NULL);

    status = _HvInitTimeUsingPit();

    if (CX_SUCCESS(status))
    {
        if (gTscSpeed == 0)
        {
            status = CX_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    return status;
}

static
CX_STATUS
_HvInitTimeUsingPit(
    )
{
    DATETIME wall0 = {0};

    HvGetWallClockDateTime(&wall0, CX_TRUE);
    gStartupTime = wall0;

    gStartupTsc = HvGetTscTickCount();

    gTscSpeed = _HvGetTscInOneSecond();

    LOG("Time init using PIT: TSC: %p - CPU Speed: (%u.%u Ghz)\n",
        gTscSpeed, (CX_UINT32) (gTscSpeed / ONE_GIGAHERTZ), (CX_UINT32) (gTscSpeed % ONE_GIGAHERTZ));

    return CX_STATUS_SUCCESS;
}



CX_STATUS
HvGetWallClockDateTime(
    _Out_ DATETIME *DateTime,
    _In_ CX_BOOL GetDirectBareMetal
    )
{
    if (!DateTime)
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    //
    // read directly the values from CMOS registers
    // check out http://www.walshcomptech.com/ohlandl/config/cmos_registers.html
    //
    // IMPORTANT: this might generate problems for us if running under the OS, because of sequential
    // register accesses (0x70 and 0x71); we might need to intercept all indexes to 0x70 and keep count of them
    //
    // ADDRESS   FUNCTION
    //  00       Seconds
    //  02       Minutes
    //  04       Hours
    //  06       Day of week
    //  07       Date of month
    //  08       Month
    //  09       Year
    //  0A       Status register A (bit 0x80 = UIP, 1 means 'update in progress')
    //  0B       Status register B (bit 0x02 = 24/12, 1 means '24 h mode', bit 0x04 = DM, 1 means binary, 0 means BCD)
    //

    // do we need to get bare-metal RTC time?
    if ((GetDirectBareMetal) ||
        (gTscSpeed == 0))
    {
        HvAcquireSpinLockNoInterrupts(&gTimeInitLock);

        // wait until UIP is off
        while (0 != (_HvReadCmosRegister(0x0A) & 0x80));

        // NOTE: we assume BCD and 24H format here
        CX_UINT64 temp = 0;

        DateTime->Microsec = 0;
        DateTime->Millisec = 0;
        temp = _HvReadCmosRegister(0x00);
        DateTime->Second = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x02);
        DateTime->Minute = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x04);
        DateTime->Hour = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x07);
        DateTime->Day = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x08);
        DateTime->Month = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x09);
        DateTime->Year = BCD_TO_INT(temp);
        temp = _HvReadCmosRegister(0x06);
        DateTime->DayOfWeek = BCD_TO_INT(temp);

        if (DateTime->Year > 80)
        {
            DateTime->Year += 1900;
        }
        else
        {
            DateTime->Year += 2000;
        }

        DateTime->RelativeTime = 0;

        HvReleaseSpinLock(&gTimeInitLock);
    }
    // or get and use invariant TSC based time - unimplemented
    else
    {
        return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    return CX_STATUS_SUCCESS;
}

CX_VOID
HvPrintTimeInfo(
    void
)
{
    CX_STATUS status;
    DATETIME dateTime;

    status = HvGetWallClockDateTime(&dateTime, CX_TRUE);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HvGetWallClockDateTime", status);
    }
    else
    {
        LOG("Time is dd/mm/yyyy hh:mm:ss: %02u/%02u/%04u %02u:%02u:%02u\n",
            dateTime.Day, dateTime.Month, dateTime.Year,
            dateTime.Hour, dateTime.Minute, dateTime.Second);
    }
}


void
HvSpinWait(
    _In_ CX_UINT64 Microseconds
    )
{
    CX_UINT64 startTime = HvGetLinearTimeInMicroseconds();
    CX_UINT64 timeup = 0;

    // if we have a start time then we can use time APIs
    // otherwise we need to use the port io delays
    if (startTime)
    {
        timeup = HvGetLinearTimeInMicroseconds() + Microseconds;
        while (HvGetLinearTimeInMicroseconds() < timeup)
        {
            CpuYield();
        }
    }
    else
    {
        timeup = Microseconds;
        while (timeup--)
        {
            __outbyte(0x80, 0);
        }
    }

    return;
}

static
CX_UINT64
_HvGetTscInOneSecond(
    CX_VOID
)
{
    CX_STATUS status;
    CX_UINT64 tsc2, tick1, tick2;
    CX_UINT8 prevVal;

    status = CX_STATUS_SUCCESS;

    HvAcquireSpinLockNoInterrupts(&gTimeInitLock);

    prevVal = __inbyte(0x61);

    //initialize PIT Ch 2 in interrupt on terminal count
    __outbyte(0x61,__inbyte(0x61) & 0xC);       // disconnect from speaker, disable gate

    // program control word, select Counter 2, Read/Write least significant byte first, then most significant byte, Mode 1, Binary Counter 16 bits
    __outbyte(0x43,0xB0);

    //1193180/100 Hz = 11931 = 2e9bh
    __outbyte(0x42,0x9B);   //LSB
    __outbyte(0x42,0x2E);   //MSB

    // enable gate, start counting
    __outbyte(0x61, (__inbyte(0x61) & 0x0F) | 1);

    tick1 = __rdtsc();

    //now wait until PIT counter reaches zero (OUT goes HIGH)
    for (;;)
    {
        // don't latch count, only status for channel 2
        __outbyte(0x43, (3 << 6) | (1 << 5) | (1 << 3));
        if (__inbyte(0x42) & 0x80)
        {
            break;
        }
    }

    tick2 = __rdtsc();

    tsc2 = (tick2 - tick1) * 100;   // we used PIT counting for 1/100 seconds

    __outbyte(0x61, prevVal);

    HvReleaseSpinLock(&gTimeInitLock);

    return tsc2;
}


///@}