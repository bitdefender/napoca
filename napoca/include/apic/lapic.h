/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file lapic.h
 *  @brief Local APIC - Implementation of platform specific functionality
 */

/// \defgroup xapic xAPIC support
/// \defgroup lapic Local APIC - Implementation of platform specific functionality
/// \ingroup xapic
/// @{

#ifndef _LAPIC_H_
#define _LAPIC_H_

#include "core.h"
#include "kernel/time.h"

#define LAPIC_LVT_FLAG_ENTRY_MASKED         (1UL << 16)
#define LAPIC_LVT_DELIVERY_MODE_EXT_INT     (7UL << 8)
#define LAPIC_SVR_FLAG_SW_ENABLE            (1UL << 8)

/// @brief LAPIC structure size
#define LAPIC_SIZE                          0x400

/**
 * @brief Local APIC registers
 *
 * Software interacts with the local APIC by reading and writing its registers.
 * The registers are encoded like offsets from the beginning of the LAPIC structure
 *
 */
typedef enum _LOCAL_APIC_REGISTERS
{
    APIC_ID_REGISTER                            = 0x20,
    APIC_VERSION_REGISTER                       = 0x30,

    APIC_TPR_REGISTER                           = 0x80,
    APIC_ARBITRATION_PRIORITY_REGISTER          = 0x90,
    APIC_PROCESSOR_PRIORITY_REGISTER            = 0xA0,
    APIC_EOI_REGISTER                           = 0xB0,
    APIC_REMOTE_READ_REGISTER                   = 0xC0,
    APIC_LOGICAL_DESTINATION_REGISTER           = 0xD0,
    APIC_DESTINATION_FORMAT_REGISTER            = 0xE0,
    APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER     = 0xF0,
    APIC_ISR_REGISTER_BITS_31_0                 = 0x100,
    APIC_ISR_REGISTER_BITS_63_32                = 0x110,
    APIC_ISR_REGISTER_BITS_95_64                = 0x120,
    APIC_ISR_REGISTER_BITS_127_96               = 0x130,
    APIC_ISR_REGISTER_BITS_159_128              = 0x140,
    APIC_ISR_REGISTER_BITS_191_160              = 0x150,
    APIC_ISR_REGISTER_BITS_223_192              = 0x160,
    APIC_ISR_REGISTER_BITS_255_224              = 0x170,
    APIC_TMR_REGISTER_BITS_31_0                 = 0x180,
    APIC_TMR_REGISTER_BITS_63_32                = 0x190,
    APIC_TMR_REGISTER_BITS_95_64                = 0x1A0,
    APIC_TMR_REGISTER_BITS_127_96               = 0x1B0,
    APIC_TMR_REGISTER_BITS_159_128              = 0x1C0,
    APIC_TMR_REGISTER_BITS_191_160              = 0x1D0,
    APIC_TMR_REGISTER_BITS_223_192              = 0x1E0,
    APIC_TMR_REGISTER_BITS_255_224              = 0x1F0,
    APIC_IRR_REGISTER_BITS_31_0                 = 0x200,
    APIC_IRR_REGISTER_BITS_63_32                = 0x210,
    APIC_IRR_REGISTER_BITS_95_64                = 0x220,
    APIC_IRR_REGISTER_BITS_127_96               = 0x230,
    APIC_IRR_REGISTER_BITS_159_128              = 0x240,
    APIC_IRR_REGISTER_BITS_191_160              = 0x250,
    APIC_IRR_REGISTER_BITS_223_192              = 0x260,
    APIC_IRR_REGISTER_BITS_255_224              = 0x270,
    APIC_ERROR_STATUS_REGISTER                  = 0x280,

    APIC_CMCI_REGISTER                          = 0x2F0,
    APIC_INTERRUPT_COMMAND_REGISTER_LOW         = 0x300,
    APIC_INTERRUPT_COMMAND_REGISTER_HIGH        = 0x310,
    APIC_LVT_TIMER_REGISTER                     = 0x320,
    APIC_LVT_THERMAL_REGISTER                   = 0x330,
    APIC_LVT_PERF_REGISTER                      = 0x340,
    APIC_LVT_LINT0_REGISTER                     = 0x350,
    APIC_LVT_LINT1_REGISTER                     = 0x360,
    APIC_LVT_ERROR_REGISTER                     = 0x370,
    APIC_INITIAL_COUNT_REGISTER                 = 0x380,
    APIC_CURRENT_COUNT_REGISTER                 = 0x390,

    APIC_DIVIDE_CONFIGURATION_REGISTER          = 0x3E0,
}LOCAL_APIC_REGISTERS;

//
// Define the bitfield for some of the local APIC registers
//
#pragma pack(push)
#pragma pack(1)
/** @name ICR
 *  @brief ICR high and low layout
 *
 *  The interrupt command register (ICR) is a 64-bit local APIC register that allows software
 *  running on the processor to specify and send interprocessor interrupts (IPIs) to other processors in the system.
 *
 */
///@{
typedef    union _ICR_HIGH
{
    struct
    {
        CX_UINT32   Reserved    : CX_BITFIELD(23, 0);
        CX_UINT32   Destination : CX_BITFIELD(31, 24);  ///< Specifies the target processor or processors.
                                                        ///< This field is only used when the destination shorthand field is set to 00B.
    };

    CX_UINT32 Value;
}ICR_HIGH;
static_assert(sizeof(ICR_HIGH) == sizeof(CX_UINT32), "Invalid size of ICR_HIGH structure!");

typedef    union _ICR_LOW
{
    struct
    {
        CX_UINT32   Vector          : CX_BITFIELD(7, 0);    ///< The vector number of the interrupt being sent.
        CX_UINT32   DeliveryMode    : CX_BITFIELD(10, 8);   ///< Specifies the type of IPI to be sent. This field is also know as the IPI message type field.
                                                            ///< One of the #IPI_DELIVERY_MODE (see ipi.h)

        CX_UINT32   DstMode         : CX_BITFIELD(11, 11);  ///< Selects either physical (0) or logical (1) destination mode (see Section 10.6.2 Intel Manual)
                                                            ///< You can fill this field using #IPI_DESTINATION_MODE from ipi.h

        CX_UINT32   DeliveryStatus  : CX_BITFIELD(12, 12);  ///< Indicates the IPI delivery status. See #IPI_DELIVERY_STATUS from ipi.h for more info.

        CX_UINT32   ___reserved3    : CX_BITFIELD(13, 13);
        CX_UINT32   Level           : CX_BITFIELD(14, 14);  ///< For the INIT level de-assert delivery mode this flag must be set to 0;
                                                            ///< for all other delivery modes it must be set to 1.
                                                            ///< You can fill this field using #IPI_LEVEL from ipi.h

        CX_UINT32   TriggerMode     : CX_BITFIELD(15, 15);  ///< Selects the trigger mode when using the INIT level de-assert delivery mode:
                                                            ///< edge (0) or level (1).It is ignored for all other delivery modes.
                                                            ///< You can fill this field using #IPI_TRIGGER_MODE from ipi.h

        CX_UINT32   ___reserved2    : CX_BITFIELD(17, 16);
        CX_UINT32   DstShorthand    : CX_BITFIELD(19, 18);  ///< One of #IPI_DESTINATION_SHORTLAND. See ipi.h
        CX_UINT32   ___reserved1    : CX_BITFIELD(31, 20);
    };
    CX_UINT32 Value;
}ICR_LOW;
static_assert(sizeof(ICR_LOW) == sizeof(CX_UINT32), "Invalid size of ICR_LOW structure!");

typedef struct _ICR
{
    ICR_HIGH    High;
    ICR_LOW     Low;
} ICR;
static_assert(sizeof(ICR) == sizeof(CX_UINT64), "Invalid size of ICR structure!");
///@}

/// @brief Spurious-interrupt vector register
typedef union _SPURIOUS_VECTOR_REGISTER
{
    struct
    {
        CX_UINT32 SpuriousVector            : CX_BITFIELD(7, 0);    ///< Determines the vector number to be delivered
                                                                    ///< to the processor when the local APIC generates a spurious vector.

        CX_UINT32 ApicSoftwareEnable        : CX_BITFIELD(8, 8);    ///< Allows software to temporarily enable (1) or disable (0) the local APIC
        CX_UINT32 FocusProcessorChecking    : CX_BITFIELD(9, 9);    ///< Determines if focus processor checking is enabled (0) or disabled (1)
                                                                    ///<when using the lowest priority delivery mode
        CX_UINT32 Reserved1                 : CX_BITFIELD(11, 10);
        CX_UINT32 EoiBroadcastSuppression   : CX_BITFIELD(12, 12);  ///< Determines whether an EOI for a level-triggered interrupt causes
                                                                    ///< EOI messages to be broadcast to the I / O APICs(0) or not (1).
        CX_UINT32 Reserved0                 : CX_BITFIELD(31, 13);
    };

    CX_UINT32 Raw;
}SPURIOUS_VECTOR_REGISTER;
static_assert(sizeof(SPURIOUS_VECTOR_REGISTER) == sizeof(CX_UINT32), "Invalid size of SPURIOUS_VECTOR_REGISTER structure!");


/// @brief LAPIC PAGE (see table 10.1 Local APIC Register Address Map, Intel SDM 10.4.1)
typedef struct _LAPIC_PAGE
{
    CX_UINT8    __reserved_000[0x10];
    CX_UINT8    __reserved_010[0x10];

    CX_UINT32   Id;                     // offset 0x020
    CX_UINT8    __reserved_024[0x0C];

    CX_UINT32   Version;                // offset 0x030
    CX_UINT8    __reserved_034[0x0C];

    CX_UINT8    __reserved_040[0x40];

    CX_UINT32   TPR;                    // offset 0x080
    CX_UINT8    __reserved_084[0x0C];

    CX_UINT32   ArbitrationPriority;    // offset 0x090
    CX_UINT8    __reserved_094[0x0C];

    CX_UINT32   ProcessorPriority;      // offset 0x0A0
    CX_UINT8    __reserved_0A4[0x0C];

    CX_UINT32   EOI;                    // offset 0x0B0
    CX_UINT8    __reserved_0B4[0x0C];

    CX_UINT32   RemoteRead;             // offset 0x0C0
    CX_UINT8    __reserved_0C4[0x0C];

    CX_UINT32   LogicalDestination;     // offset 0x0D0
    CX_UINT8    __reserved_0D4[0x0C];

    CX_UINT32   DestinationFormat;      // offset 0x0E0
    CX_UINT8    __reserved_0E4[0x0C];

    CX_UINT32   SpuriousInterruptVector;// offset 0x0F0
    CX_UINT8    __reserved_0F4[0x0C];

    CX_UINT32   ISR[32];                // offset 0x100

    CX_UINT32   TMR[32];                // offset 0x180

    CX_UINT32   IRR[32];                // offset 0x200

    CX_UINT32   ErrorStatus;            // offset 0x280
    CX_UINT8    __reserved_284[0x0C];

    CX_UINT8    __reserved_290[0x60];

    CX_UINT32   LvtCmci;                // offset 0x2F0
    CX_UINT8    __reserved_2F4[0x0C];

    CX_UINT32   IcrLow;                 // offset 0x300
    CX_UINT8    __reserved_304[0x0C];

    CX_UINT32   IcrHigh;                // offset 0x310
    CX_UINT8    __reserved_314[0x0C];

    CX_UINT32   LvtTimer;               // offset 0x320
    CX_UINT8    __reserved_324[0x0C];

    CX_UINT32   LvtThermalSensor;       // offset 0x330
    CX_UINT8    __reserved_334[0x0C];

    CX_UINT32   LvtPerfMonCounters;     // offset 0x340
    CX_UINT8    __reserved_344[0x0C];

    CX_UINT32   LvtLINT0;               // offset 0x350
    CX_UINT8    __reserved_354[0x0C];

    CX_UINT32   LvtLINT1;               // offset 0x360
    CX_UINT8    __reserved_364[0x0C];

    CX_UINT32   LvtError;               // offset 0x370
    CX_UINT8    __reserved_374[0x0C];

    CX_UINT32   InitialCount;           // offset 0x380
    CX_UINT8    __reserved_384[0x0C];

    CX_UINT32   CurrentCount;           // offset 0x390
    CX_UINT8    __reserved_394[0x0C];

    CX_UINT8    __reserved_3A0[0x40];   // offset 0x3A0

    CX_UINT32   DivideConfiguration;    // offset 0x3E0
    CX_UINT8    __reserved_3E4[0x0C];

    CX_UINT32   SelfIpi;                // offset 0x3F0
    CX_UINT8    __reserved_3F4[0x0C];   // valid only for X2APIC
} LAPIC_PAGE;
#pragma pack(pop)
static_assert(sizeof(LAPIC_PAGE) == LAPIC_SIZE, "Invalid size of LAPIC_PAGE structure!");

//
// Function prototypes
//

///
/// @brief Initialize local Apic.
///
/// This function reads MSR_IA32_APIC_BASE. It ensures that the platform has APIC and it is active.
/// Once the physical address of the APIC has been found, it is mapped to the virtual address of the hypervisor.
/// We use only the xAPIC mode and in order for GUEST to not be able to make the switch to x2APIC,
/// when it will query the support for x2APIC mode through CPUID we hide it.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_NOT_SUPPORTED             - absence of a local APIC.
/// @returns    OTHER                               - other CX_STATUS values returned by the APIs used in the function
///
CX_STATUS
LapicInit(
    CX_VOID
);

///
/// @brief Write inside LAPIC structure.
///
/// This function writes a certain value to an offset in the LAPIC memory.
/// Note that above it says 'memory' because we do not use x2APIC mode where MSRs are used.
///
/// @param[in]  Register                    Local APIC register to be written. One of #LOCAL_APIC_REGISTERS.
/// @param[in]  Value                       The value to be written.
///
CX_VOID
LapicWrite(
    _In_ LOCAL_APIC_REGISTERS    Register,
    _In_ CX_UINT32               Value
);

///
/// @brief Read from LAPIC structure.
///
/// This function read a certain register value from the LAPIC memory.
/// Note that above it says 'memory' because we do not use x2APIC mode where MSRs are used.
///
/// @param[in]  Register                    Local APIC register from where to read. One of #LOCAL_APIC_REGISTERS.
///
/// @returns    0                           - if LAPIC component is not initialized.
/// @returns    UINT32                      - the value read from the respective register
///
CX_UINT32
LapicRead(
    _In_ LOCAL_APIC_REGISTERS Register
);

///
/// @brief Return where LAPIC structure is placed in the physical memory.
///
/// @returns    Local APIC physical address.
///
CX_UINT64
LapicGetPa(
    CX_VOID
);

///
/// @brief Debug function used to print LAPIC structure form memory.
///
CX_VOID
LapicPrintPlatform(
    CX_VOID
    );


///
/// @brief Setup a performance counter based NMI watchdog.
///
/// This function will use the performance counter to generate a NMI
/// based on the PERF_EVENT_UNHALTED_REF_CYCLES counter
/// This function must be called on each CPU core.
///
/// @return CX_STATUS_NOT_INITIALIZED       If global LAPIC data structures are not initialized.
/// @return CX_STATUS_SUCCESS               On success.
CX_STATUS
LapicSetupPerfNMI(
    CX_VOID
);

///
/// @brief This function enables the NMI watchdog.
///
/// This function will program the counter to generate a NMI
/// when a conditions are met by calling #LapicResetPerfNMI.
///
/// @return CX_STATUS_NOT_INITIALIZED       If global LAPIC data structures are not initialized.
/// @return CX_STATUS_SUCCESS               On success.
CX_STATUS
LapicEnablePerfNMI(
    CX_VOID
);

///
/// @brief This function resets/programs the NMI watchdog.
///
/// This function will reset the performance counter internal data
/// and prepare it for triggering a NMI. This function will do the
/// effective programming of performance counter by writing the
/// appropriate MSRs.
///
/// @return CX_STATUS_NOT_INITIALIZED       If global LAPIC data structures are not initialized.
/// @return CX_STATUS_SUCCESS               On success.
CX_STATUS
LapicResetPerfNMI(
    CX_VOID
);

///
/// @brief This function disables the NMI watchdog.
///
/// This function will mask the LAPIC LVT entry for
/// used for performance interrupts and also mask the performance counter
/// by writing the appropriate MSRs.
///
/// @return CX_STATUS_NOT_INITIALIZED       If global LAPIC data structures are not initialized.
/// @return CX_STATUS_SUCCESS               On success.
CX_STATUS
LapicDisablePerfNMI(
    CX_VOID
);

///
/// @brief This function retrieves the NMI watchdog timeout.
///
/// @return     Timeout in seconds.
__forceinline
CX_UINT64
LapicGetPerfNMIWatchdogMicroSecondsTimeout(
    CX_VOID
)
{
    return ONE_SECOND_IN_MICROSECONDS;
}

///
/// @brief This function checks if there is an overflow on the performance counter
///
/// selected for the NMI watchdog. When a NMI arrives, this function may be used
/// to determine if the NMI was triggered by the performance counters or not.
/// Only NMIs for which this function returns TRUE must be considered for NMI watchdog handling
///
/// @return TRUE    if this there is an overflow in performance counter selected for NMI watchdog.
CX_BOOL
LapicCheckOverflowPerfNMI(
    CX_VOID
);

/// @}
#endif