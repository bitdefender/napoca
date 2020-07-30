/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file lapic.c
 *  @brief Local APIC - Implementation of platform specific functionality
 */

 /// \addtogroup lapic
 /// @{

#include "kernel/kernel.h"
#include "apic/lapic.h"
#include "kernel/newcore.h"

/// @brief Structure used internally to maintain information about LAPIC component
typedef struct _LAPIC_GLOBAL_DATA
{
    CX_BOOL             Inited;         ///< TRUE if this component is initialized
    volatile LAPIC_PAGE *LapicBaseVa;   ///< Virtual address where we mapped the LAPIC structure
    CX_UINT64           LapicBasePa;    ///< Physical address of the LAPIC structure.
}LAPIC_GLOBAL_DATA;
static LAPIC_GLOBAL_DATA gLapicGlobalData;

//////////////////////////////////////////////////////////////////////////
#define PERF_EVENT_UNHALTED_CORE_CYCLES         0x003CULL     //// UnHalted Core Cycles///
#define PERF_EVENT_UNHALTED_CORE_CYCLES_UMASK   0x0000ULL     //// UnHalted Core Cycles///

#define PERF_EVENT_UNHALTED_REF_CYCLES          0x003CULL     //// UnHalted Ref Core Cycles///
#define PERF_EVENT_UNHALTED_REF_CYCLES_UMASK    0x0001ULL     //// UnHalted Ref Core Cycles///
//////////////////////////////////////////////////////////////////////////

// only low 32bits are available for PMC values in order to allow signed and unsigned values in a PMC
// the value of a PMC is sign-extended by CPU in order to be able to use positive and negative values
// only low-order 32bits of a PMC msr may be written in order to allow sign-extension of value up
// to architectural number of bits that are implemented in a PMC
#define PERF_COUNTER_MAX_VALUE          (CX_INT32_MAX_VALUE)

#pragma warning( push )
#pragma warning(disable:4214)   // disable bit field types other than int warning
#pragma warning(disable:4201)   // disable nameless struct warning

/// @brief Layout of the IA32_APIC_BASE MSR
typedef union _IA_32_APIC_BASE
{
    struct
    {
        CX_UINT64 Reserved1         : CX_BITFIELD(7, 0);
        CX_UINT64 BspFlag           : CX_BITFIELD(8, 8);    ///< Indicates if the processor is the bootstrap processor (BSP).
        CX_UINT64 Reserved2         : CX_BITFIELD(9, 9);
        CX_UINT64 EnableX2apicMode  : CX_BITFIELD(10, 10);  ///< System software can place the local APIC in the x2APIC mode by setting this bit.
        CX_UINT64 ApicGlobalEnable  : CX_BITFIELD(11, 11);  ///< Enables or disables the local APIC.

        // Here should be max physical address instead of 63.
        // The MAXPHYADDR is 36 bits for processors that
        // do not support CPUID leaf 80000008H, or indicated by
        // CPUID.80000008H:EAX[bits 7:0] for processors that
        // support CPUID leaf 80000008H.
        CX_UINT64 ApicBase          : CX_BITFIELD(63, 12);  ///< Specifies the base (physical) address of the APIC registers.
    };

    CX_UINT64 Raw;
} IA_32_APIC_BASE;
#pragma warning( pop )

typedef union {
    struct {
        CX_UINT64 EventSelect   : 8;
        CX_UINT64 UMask         : 8;
        CX_UINT64 Usr           : 1;
        CX_UINT64 Os            : 1;
        CX_UINT64 Edge          : 1;
        CX_UINT64 Pc            : 1;
        CX_UINT64 Intr          : 1;
        CX_UINT64 AnyThread     : 1;
        CX_UINT64 En            : 1;
        CX_UINT64 Inv           : 1;
        CX_UINT64 Cmask         : 8;
    };

    CX_UINT64 Raw;
} IA32_PERFEVTSEL_REGISTER;

typedef union
{
    struct
    {
        CX_UINT64 OvfPmc0       : 1;
        CX_UINT64 OvfPmc1       : 1;
        CX_UINT64 OvfPmc2       : 1;
        CX_UINT64 OvfPmc3       : 1;
        CX_UINT64 Reserved1     : 28;
        CX_UINT64 OvfFixedctr0  : 1;
        CX_UINT64 OvfFixedctr1  : 1;
        CX_UINT64 OvfFixedctr2  : 1;
        CX_UINT64 Reserved2     : 20;
        CX_UINT64 TraceTopaPmi  : 1;
        CX_UINT64 Reserved3     : 2;
        CX_UINT64 LbrFrz        : 1;
        CX_UINT64 CtrFrz        : 1;
        CX_UINT64 Asci          : 1;
        CX_UINT64 OvfUncore     : 1;
        CX_UINT64 OvfBuf        : 1;
        CX_UINT64 CondChgd      : 1;
    };

    CX_UINT64 Raw;
} IA32_PERF_GLOBAL_STATUS_REGISTER;

typedef union {
    struct {
        CX_UINT64 ClearOvfPmcn      : 32;
        CX_UINT64 ClearOvfFixedCtrn : 3;
        CX_UINT64 Reserved1         : 20;
        CX_UINT64 ClearTraceTopaPmi : 1;
        CX_UINT64 Reserved2         : 2;
        CX_UINT64 ClearLbrFrz       : 1;
        CX_UINT64 ClearCtrFrz       : 1;
        CX_UINT64 ClearAsci         : 1;
        CX_UINT64 ClearOvfUncore    : 1;
        CX_UINT64 ClearOvfBuf       : 1;
        CX_UINT64 ClearCondChgd     : 1;
    };

    CX_UINT64 Raw;
} IA32_PERF_GLOBAL_STATUS_RESET_REGISTER;

typedef union {
    struct
    {
        CX_UINT32 EnPmcn;
        CX_UINT32 EnFixedCtrn;
    };

    CX_UINT64 Raw;
} IA32_PERF_GLOBAL_CTRL_REGISTER;

/* Static functions */
/** @name LAPIC getter & setter
 *  @brief Write/read in/from LAPIC structure
 */
///@{
static __forceinline CX_VOID    _LapicWrite(_In_ LOCAL_APIC_REGISTERS Register, _In_ CX_UINT32 Value);
static __forceinline CX_UINT32  _LapicRead(_In_ LOCAL_APIC_REGISTERS Register);
///@}
static CX_UINT64 _LapicGetPerfcounterThreshold(_In_ PCPU* Cpu, _In_ IA32_PERFEVTSEL_REGISTER perfevtsel0);

CX_STATUS
LapicInit(
    CX_VOID
)
// Create VA mappings for the lapic page
{
    gLapicGlobalData.Inited = CX_FALSE;

    // When the CPUID instruction is executed with a source operand of 1 in the EAX register, bit 9
    // of the CPUID feature flags returned in the EDX register indicates
    // the presence (set) or absence (clear) of a local APIC.
    int cpuidRes[4];
    __cpuid(cpuidRes, 1);
    CX_UINT32 edx = cpuidRes[3];
    if (!(edx & CX_BIT(9)))
    {
        ERROR("There's no local APIC!\n");
        return CX_STATUS_NOT_SUPPORTED;
    }

    // Normally LAPIC should be enabled when we get in control.
    // But to be sure, we test bit 11 of IA32_APIC_BASE MSR.
    IA_32_APIC_BASE ia32ApicBase;
    ia32ApicBase.Raw = __readmsr(MSR_IA32_APIC_BASE);
    if (!ia32ApicBase.ApicGlobalEnable)
    {
        WARNING("Local APIC is NOT enabled! We enable it\n");
        ia32ApicBase.ApicGlobalEnable = CX_TRUE;
        __writemsr(MSR_IA32_APIC_BASE, ia32ApicBase.Raw);
    }
    else if (ia32ApicBase.EnableX2apicMode)
    {
        WARNING("We received control in x2APIC mode! We are trying to switch to xAPIC mode\n");
        // If somehow the firmware gave us control in x2APIC mode,
        // we have to switch back to xAPIC because we do not have support for x2APIC mode.
        // From Intel manual: Thus the only means to transition from x2APIC mode to xAPIC mode
        // is a two-step process:

        // 1) first transition from x2APIC mode to local APIC disabled mode (EN= 0, EXTD = 0)
        ia32ApicBase.ApicGlobalEnable = ia32ApicBase.EnableX2apicMode = CX_FALSE;
        __writemsr(MSR_IA32_APIC_BASE, ia32ApicBase.Raw);

        // 2) followed by another transition from disabled mode to xAPIC mode (EN= 1, EXTD= 0).
        ia32ApicBase.ApicGlobalEnable = CX_TRUE;
        __writemsr(MSR_IA32_APIC_BASE, ia32ApicBase.Raw);
    }

    gLapicGlobalData.LapicBasePa = ia32ApicBase.ApicBase << 12;

    CX_STATUS status = MmMapDevMem(&gHvMm, gLapicGlobalData.LapicBasePa, CX_PAGE_SIZE_4K, TAG_LAPIC, (MM_UNALIGNED_VA*)&gLapicGlobalData.LapicBaseVa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmMapDevMem", status);
        return status;
    }
    MmRegisterVaInfo((CX_VOID *)gLapicGlobalData.LapicBaseVa, CX_PAGE_SIZE_4K, "LAPIC");

    gLapicGlobalData.Inited = CX_TRUE;
    return CX_STATUS_SUCCESS;
}

CX_VOID
LapicWrite(
    _In_ LOCAL_APIC_REGISTERS    Register,
    _In_ CX_UINT32               Value
)
{
    if (!gLapicGlobalData.Inited) return;

    _LapicWrite(Register, Value);

    return;
}

CX_UINT32
LapicRead(
    _In_ LOCAL_APIC_REGISTERS Register
)
{
    if (!gLapicGlobalData.Inited) return 0;

    return _LapicRead(Register);
}

CX_UINT64
LapicGetPa(
    CX_VOID
)
{
    if (!gLapicGlobalData.Inited) return CX_NULL;

    return gLapicGlobalData.LapicBasePa;
}

CX_STATUS
LapicSetupPerfNMI(
    CX_VOID
)
{
    PCPU* cpu = HvGetCurrentCpu();
    volatile LAPIC_PAGE *lapicPage = gLapicGlobalData.LapicBaseVa;

    if (!cpu || !gLapicGlobalData.Inited) return CX_STATUS_NOT_INITIALIZED;

    LOG("Setup NMI Watchdog for index CPU%d\n", cpu->BootInfoIndex);

    cpu->NmiWatchDog.OriginalLvtPmcr = lapicPage->LvtPerfMonCounters;

    // disable all counters
    IA32_PERF_GLOBAL_CTRL_REGISTER globalCtrl = { 0 };
    IA32_PERFEVTSEL_REGISTER perfevtsel0 = { 0 };
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, globalCtrl.Raw);
    __writemsr(MSR_IA32_PERFEVTSEL0, perfevtsel0.Raw);

    // reset all overflows
    IA32_PERF_GLOBAL_STATUS_RESET_REGISTER resetReg = { 0 };
    resetReg.ClearOvfPmcn = 1;
    resetReg.ClearOvfBuf = 1;
    resetReg.ClearCondChgd = 1;
    __writemsr(MSR_IA32_PERF_GLOBAL_STATUS_RESET, resetReg.Raw);

    perfevtsel0.EventSelect = PERF_EVENT_UNHALTED_REF_CYCLES;
    perfevtsel0.UMask = PERF_EVENT_UNHALTED_REF_CYCLES_UMASK;
    perfevtsel0.Intr = 1;
    perfevtsel0.En = 1;
    perfevtsel0.Os = 1;

    // the value of a PMC is sign-extended by CPU in order to be able to use positive and negative values
    // only low-order 32bits of a PMC msr may be written in order to allow sign-extension of value up
    // to architectural number of bits that are implemented in a PMC
    CX_UINT64 ticks = PERF_COUNTER_MAX_VALUE;
    __writemsr(MSR_IA32_PMC0, (0x0ULL - ticks));

    lapicPage->LvtPerfMonCounters = NAPOCA_LVT_PERF_VECTOR | (IPI_DELIVERY_NMI << 8) | LAPIC_LVT_FLAG_ENTRY_MASKED;

    // enable PMC0
    __writemsr(MSR_IA32_PERFEVTSEL0, perfevtsel0.Raw);

    // enable PMC0
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, 0x1);
    HvSpinWait(MICROSECONDS_PER_MILISECOND);
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, 0);
    __writemsr(MSR_IA32_PERFEVTSEL0, 0);

    // mask and use only low-order 32bits
    CX_UINT64 pmc = __readpmc(0) & PERF_COUNTER_MAX_VALUE;
    cpu->NmiWatchDog.PerfCounterRate = (pmc * MICROSECONDS_PER_MILISECOND);
    LOG("Selected perf counter is 0x%llx with rate %lld ticks/s!\n",
        (perfevtsel0.EventSelect|perfevtsel0.UMask), cpu->NmiWatchDog.PerfCounterRate);

    lapicPage->LvtPerfMonCounters = cpu->NmiWatchDog.OriginalLvtPmcr;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
LapicEnablePerfNMI(
    CX_VOID
)
{
    PCPU* cpu = HvGetCurrentCpu();
    volatile LAPIC_PAGE *lapicPage = gLapicGlobalData.LapicBaseVa;

    if (!cpu || !gLapicGlobalData.Inited) return CX_STATUS_NOT_INITIALIZED;

    cpu->NmiWatchDog.OriginalLvtPmcr = lapicPage->LvtPerfMonCounters;

    cpu->NmiWatchDog.StartingRootModeTsc = HvGetTscTickCount();
    cpu->NmiWatchDog.OverflowCount = 0;

    return LapicResetPerfNMI();
}

CX_STATUS
LapicResetPerfNMI(
    CX_VOID
)
{
    CX_UINT64 ticks = 0;
    PCPU* cpu = HvGetCurrentCpu();
    volatile LAPIC_PAGE* lapicPage = gLapicGlobalData.LapicBaseVa;

    if (!cpu || !gLapicGlobalData.Inited) return CX_STATUS_NOT_INITIALIZED;

    // disable all counters
    IA32_PERF_GLOBAL_CTRL_REGISTER globalCtrl = { 0 };
    IA32_PERFEVTSEL_REGISTER perfevtsel0 = { 0 };
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, globalCtrl.Raw);
    __writemsr(MSR_IA32_PERFEVTSEL0, perfevtsel0.Raw);

    // reset all overflows
    IA32_PERF_GLOBAL_STATUS_RESET_REGISTER resetReg = { 0 };
    resetReg.ClearOvfPmcn = 1;
    resetReg.ClearOvfBuf = 1;
    resetReg.ClearCondChgd = 1;
    __writemsr(MSR_IA32_PERF_GLOBAL_STATUS_RESET, resetReg.Raw);

    perfevtsel0.EventSelect = PERF_EVENT_UNHALTED_REF_CYCLES;
    perfevtsel0.UMask = PERF_EVENT_UNHALTED_REF_CYCLES_UMASK;
    perfevtsel0.Intr = 1;
    perfevtsel0.En = 1;
    perfevtsel0.Os = 1;

    ticks = _LapicGetPerfcounterThreshold(cpu, perfevtsel0);

    __writemsr(MSR_IA32_PMC0, (0x0ULL - ticks));

    lapicPage->LvtPerfMonCounters = NAPOCA_LVT_PERF_VECTOR | (IPI_DELIVERY_NMI << 8);

    // enable PMC0
    __writemsr(MSR_IA32_PERFEVTSEL0, perfevtsel0.Raw);

    // enable PMC0
    globalCtrl.Raw = 0;
    globalCtrl.EnPmcn = 1;
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, globalCtrl.Raw);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
LapicDisablePerfNMI(
    CX_VOID
)
{
    PCPU* cpu = HvGetCurrentCpu();
    volatile LAPIC_PAGE *lapicPage = gLapicGlobalData.LapicBaseVa;

    if (!cpu || !gLapicGlobalData.Inited) return CX_STATUS_NOT_INITIALIZED;

    // mask first
    lapicPage->LvtPerfMonCounters |= LAPIC_LVT_FLAG_ENTRY_MASKED;

    // disable all counters
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, 0);
    __writemsr(MSR_IA32_PERFEVTSEL0, 0);

    lapicPage->LvtPerfMonCounters = cpu->NmiWatchDog.OriginalLvtPmcr;

    return CX_STATUS_SUCCESS;
}

CX_BOOL
LapicCheckOverflowPerfNMI(
    CX_VOID
)
{
    IA32_PERF_GLOBAL_STATUS_REGISTER reg;

    reg.Raw = __readmsr(MSR_IA32_PERF_GLOBAL_STATUS);

    return reg.OvfPmc0?CX_TRUE:CX_FALSE;
}

CX_VOID
LapicPrintPlatform(
    void
    )
{
    CX_UINT8 i = 0, j = 0;
    CX_UINT32 k = 0;
    CX_UINT32 reg = 0;
    IA_32_APIC_BASE ia32ApicBaseMsr;
    CX_UINT64 basePa = 0;
    volatile LAPIC_PAGE *lapicVa = gLapicGlobalData.LapicBaseVa;

    if (!gLapicGlobalData.Inited) return;

    ia32ApicBaseMsr.Raw = __readmsr(MSR_IA32_APIC_BASE);
    basePa = ia32ApicBaseMsr.ApicBase;

    LOGN("*** PHYSICAL LAPIC ID = %u, Ver = 0x%x, MaxLvtEntry = %d, DirectedEOI = P%d/E%d, (SW: '%s'). ApicBase=0x%x\n"
        "     -> TPR = 0x%08x,  APR = 0x%08x,  PPR = 0x%08x,  RRD = 0x%08x\n"
        "     -> LDR = 0x%08x,  DFR = 0x%08x,  SVR = 0x%08x,  Err = 0x%08x\n"
        "     -> ICR_LOW  = 0x%08x ,  ICR_HIGH = 0x%08x\n"
        "     -> LVT_INT0 = 0x%08x,  LVT_INT1 = 0x%08x\n"
        "     -> LVT_CMCI = 0x%08x,  LVT_PMCR = 0x%08x\n"
        "     -> LVT_TMR  = 0x%08x,  LVT_TSR  = 0x%08x\n"
        "     -> LVT_ERR  = 0x%08x\n"
        "     -> InitialCount = 0x%08x, CurrentCount = 0x%08x, DivideConfig = 0x%08x\n",
        lapicVa->Id >> 24,
        lapicVa->Version,
        (lapicVa->Version & 0xFF0000) >> 16,
        (lapicVa->Version >> 24) & 1, (lapicVa->SpuriousInterruptVector >> 12) & 1,
        (lapicVa->SpuriousInterruptVector & LAPIC_SVR_FLAG_SW_ENABLE) != 0 ? "Enabled" : "Disabled",
        ia32ApicBaseMsr,
        lapicVa->TPR, lapicVa->ArbitrationPriority, lapicVa->ProcessorPriority, lapicVa->RemoteRead,
        lapicVa->LogicalDestination, lapicVa->DestinationFormat, lapicVa->SpuriousInterruptVector, lapicVa->ErrorStatus,
        lapicVa->IcrLow, lapicVa->IcrHigh,
        lapicVa->LvtLINT0, lapicVa->LvtLINT1,
        lapicVa->LvtCmci, lapicVa->LvtPerfMonCounters,
        lapicVa->LvtTimer, lapicVa->LvtThermalSensor,
        lapicVa->LvtError,
        lapicVa->InitialCount, lapicVa->CurrentCount, lapicVa->DivideConfiguration
    );

    // print the ISR, TMR and IRR
    LOGN("ISR : ");

    for (i = 0; i < 8; i++)
    {
        k = 1;
        reg = (CX_UINT32) lapicVa->ISR[i*4];
        for (j = 0; j < 32; j++)
        {
            if (0 != (reg & k))
            {
                LOGN("0x%02hhx ", (CX_UINT8) (i * 32 + j));
            }
            k = k << 1;
        }
    }
    LOGN("\n");

    LOGN("TMR : ");

    for (i = 0; i < 8; i++)
    {
        k = 1;
        reg = (CX_UINT32) lapicVa->TMR[i*4];
        for (j = 0; j < 32; j++)
        {
            if (reg & k)
            {
                LOGN("0x%02hhx ", (CX_UINT8) (i * 32 + j));
            }
            k = k << 1;
        }
    }

    LOGN("\n");

    LOGN("IRR : ");

    for (i = 0; i < 8; i++)
    {
        k = 1;
        reg = (CX_UINT32) lapicVa->IRR[i*4];
        for (j = 0; j < 32; j++)
        {
            if (reg & k)
            {
                LOGN("0x%02hhx ", (CX_UINT8) (i * 32 + j));
            }
            k = k << 1;
        }
    }

    LOGN("\n");

    return;
}

/* Static functions */
static
CX_UINT64
_LapicGetPerfcounterThreshold(
    _In_ PCPU *Cpu,
    _In_ IA32_PERFEVTSEL_REGISTER perfevtsel0
)
{
    CX_UINT64 ticks = CX_UINT64_MAX_VALUE;
    IA32_PERFEVTSEL_REGISTER expected;

    expected.EventSelect = PERF_EVENT_UNHALTED_REF_CYCLES;
    expected.UMask = PERF_EVENT_UNHALTED_REF_CYCLES_UMASK;

    if ((perfevtsel0.EventSelect | perfevtsel0.UMask) == (expected.EventSelect | expected.UMask))
    {
        ticks = Cpu->NmiWatchDog.PerfCounterRate / CfgFeaturesNmiPerformanceCounterTicksPerSecond;
    }
    else
    {
        CRITICAL("Unsupported perf event type\n");
    }

    if (ticks > PERF_COUNTER_MAX_VALUE)
    {
        WARNING("Overflow of supported ticks! Requested %llx supported %llx\n", ticks, PERF_COUNTER_MAX_VALUE);
        ticks = PERF_COUNTER_MAX_VALUE;
    }

    return ticks;
}

static
__forceinline
CX_VOID
_LapicWrite(
    _In_ LOCAL_APIC_REGISTERS    Register,
    _In_ CX_UINT32               Value
)
{
    *((volatile CX_UINT32*)((CX_UINT64)gLapicGlobalData.LapicBaseVa + Register)) = Value;
    return;
}

static
__forceinline
CX_UINT32
_LapicRead(
    _In_ LOCAL_APIC_REGISTERS Register
)
{
    return *((volatile CX_UINT32*)((CX_UINT64)gLapicGlobalData.LapicBaseVa + Register));
}

/// @}