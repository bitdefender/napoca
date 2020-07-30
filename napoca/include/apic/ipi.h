/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file ipi.h
 *  @brief IPI - Inter Processor Interrupts handling
 */


/// \defgroup ipi IPI - Inter Processor Interrupts handling
/// \ingroup xapic
/// @{

#ifndef _IPI_H_
#define _IPI_H_

#include "core.h"
#include "kernel/kernel.h"

/// @brief Destination Shorthand field from ICR register
typedef enum _IPI_DESTINATION_SHORTLAND
{
    IPI_DST_NO_SHORTHAND        = 0,                ///< (No Shorthand) The destination is specified in the destination field.
    IPI_DST_SELF                = CX_BIT(0),        ///< (Self) The issuing APIC is the one and only destination of the IPI. This destination
                                                    ///< shorthand allows software to interrupt the processor on which it is executing.
                                                    ///< An APIC implementation is free to deliver the self - interrupt message
                                                    ///< internally or to issue the message to the bus and "snoop" it as with any
                                                    ///< other IPI message.

    IPI_DST_ALL_INCLUDING_SELF  = CX_BIT(1),        ///< (All Including Self)
                                                    ///< The IPI is sent to all processors in the system including the processor sending
                                                    ///< the IPI.The APIC will broadcast an IPI message with the destination
                                                    ///< field set to FH for Pentium and P6 family processors and to FFH for Pentium
                                                    ///< 4 and Intel Xeon processors.

    IPI_DST_ALL_EXCLUDING_SELF  = CX_BIT(1) | CX_BIT(0),    ///< (All Excluding Self)
                                                            ///< The IPI is sent to all processors in a system with the exception of the processor
                                                            ///< sending the IPI.The APIC broadcasts a message with the physical
                                                            ///< destination mode and destination field set to FH for Pentium andP6 family
                                                            ///< processors and to FFH for Pentium 4 and Intel Xeon processors.Support
                                                            ///< for this destination shorthand in conjunction with the lowest - priority delivery
                                                            ///< mode is model specific.For Pentium 4 and Intel Xeon processors, when
                                                            ///< this shorthand is used together with lowest priority delivery mode, the IPI
                                                            ///< may be redirected back to the issuing processor.
}IPI_DESTINATION_SHORTLAND;

/// @brief Trigger Mode field from ICR register
typedef enum _IPI_TRIGGER_MODE
{
    IPI_TRIGGER_EDGE    = 0,
    IPI_TRIGGER_LEVEL   = 1,
}IPI_TRIGGER_MODE;

/// @brief Level field from ICR register
typedef enum _IPI_LEVEL
{
    IPI_LEVEL_DE_ASSERT = 0,
    IPI_LEVEL_ASSERT    = 1,
}IPI_LEVEL;

/// @brief Delivery Status field from ICR register (read only)
typedef enum _IPI_DELIVERY_STATUS
{
    IPI_STATUS_IDLE         = 0,    ///< Indicates that this local APIC has completed sending any previous IPIs.
    IPI_STATUS_SEND_PENDING = 1,    ///< Indicates that this local APIC has not completed sending the last IPI.
}IPI_DELIVERY_STATUS;

/// @brief Destination Mode field from ICR register
typedef enum _IPI_DESTINATION_MODE
{
    IPI_DST_MODE_PHYSICAL   = 0,
    IPI_DST_MODE_LOGICAL    = 1,
}IPI_DESTINATION_MODE;

/// @brief Delivery Mode field from ICR register
typedef enum _IPI_DELIVERY_MODE
{
    IPI_DELIVERY_FIXED              = 0,                                    ///< Delivers the interrupt specified in the vector field
                                                                            ///< to the target processor or processors.

    IPI_DELIVERY_LOWEST_PRIORITY    = CX_BIT(0),                            ///< Same as fixed mode, except that the interrupt is delivered to the processor
                                                                            ///< executing at the lowest priority among the set of processors specified in
                                                                            ///< the destination field.The ability for a processor to send a lowest priority
                                                                            ///< IPI is model specific and should be avoided by BIOS and operating system
                                                                            ///< software.

    IPI_DELIVERY_SMI                = CX_BIT(1),                            ///< Delivers an SMI interrupt to the target processor or processors. The vector
                                                                            ///< field must be programmed to 00H for future compatibility.

    IPI_DELIVERY_RESERVED1          = CX_BIT(1) | CX_BIT(0),
    IPI_DELIVERY_NMI                = CX_BIT(2),                            ///< Delivers an NMI interrupt to the target processor or processors.
                                                                            ///< The vector information is ignored.

    IPI_DELIVERY_INIT               = CX_BIT(2) | CX_BIT(0),                ///< Delivers an INIT request to the target processor or processors, which
                                                                            ///< causes them to perform an INIT.As a result of this IPI message, all the target
                                                                            ///< processors perform an INIT.The vector field must be programmed to
                                                                            ///< 00H for future compatibility.

    IPI_DELIVERY_STARTUP            = CX_BIT(2) | CX_BIT(1),                ///< Sends a special "start-up" IPI (called a SIPI) to the target processor or
                                                                            ///< processors.The vector typically points to a start - up routine that is part of
                                                                            ///< the BIOS boot - strap code(see Section 8.4, "Multiple - Processor(MP) Initialization").
                                                                            ///< IPIs sent with this delivery mode are not automatically retried
                                                                            ///< if the source APIC is unable to deliver it.It is up to the software to determine
                                                                            ///< if the SIPI was not successfully delivered and to reissue the SIPI if
                                                                            ///< necessary.

    IPI_DELIVERY_RESERVED2          = CX_BIT(2) | CX_BIT(1) | CX_BIT(0),
}IPI_DELIVERY_MODE;

/**
 * @brief The reason we froze the processor
 *
 * This entity has support for freezing processors.
 * For this, the reason why they are frozen must also be specified
 * because certain operations must be done for certain reasons
 * (eg see what the IpiFreezingHandler function does when the debugger requires the processors to be frozen).
 * For now, there are two reasons why we freeze them:
 * when entering the debugger and when we want to set
 * the command line. If you want to add other reasons, add it to INTERRUPT_FREEZE_REASON enum
 * and if some specific operations have to be done for the added reason
 * then they must be done in the IpiFreezingHandler function.
 *
 */
typedef enum _INTERRUPT_FREEZE_REASON
{
    IFR_REASON_DEBUGGER,    ///< Used when a CPU is in the debugger, and needs to freeze all other CPUs
    IFR_REASON_SET_CMDLINE, ///< Used when set cmdline command arrive from integrator
}INTERRUPT_FREEZE_REASON;

/** @name CPUs affinity
 *  @brief Used to identify a CPU when sending an interrupt.
 */
///@{
#define AFFINITY_ALL_EXCLUDING_SELF     ((((CX_UINT64)1<<gHypervisorGlobalData.CpuData.CpuCount) - 1) & ~((CX_UINT64)((CX_UINT64)1<<HvGetCurrentCpuIndex())))
#define AFFINITY_ALL_INCLUDING_SELF     (((CX_UINT64)1<<gHypervisorGlobalData.CpuData.CpuCount) - 1)
#define AFFINITY_CPU_INDEX(x)           ((CX_UINT64)1 << x)
///@}

///
/// @brief Runs the MP initialization protocol to wake up all AP processors
///
/// This function prepares the trampoline code for AP processors.
/// Copy it under 1MB and make sure that the mappings are correct so as not to generate \c \#PFs.
/// Finally, the function ensures that it restores the memory area
/// overwritten by the trampoline code (this can be used by the guest in the case of sleep)
///
/// @param[in]  IsS3Wakeup              TRUE if the guest returns from S3 state.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if maximum supported APs exceeded.
/// @returns    CX_STATUS_DATA_NOT_READY            - if CPUs are not initialized yet
/// @returns    OTHER                               - other CX_STATUS values returned by the APIs used in the function
///
CX_STATUS
IpiWakeupAllApProcessors(
    _In_ CX_BOOL IsS3Wakeup
);

///
/// @brief Perform a self-init, that should reset the CPU
///
CX_VOID
IpiSelfInit(
    CX_VOID
);

///
/// @brief Send an IPI to the CPUs targeted by Affinity, with the given Vector.
///
/// This function generates an interrupt at the processor(s) specified in the Affinity parameter.
///
/// @param[in]  Affinity                AFFINITY_ALL_EXCLUDING_SELF, AFFINITY_ALL_INCLUDING_SELF or AFFINITY_CPU_INDEX(index)
/// @param[in]  Vector                  entry into IDT which will be trigger
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if maximum supported APs exceeded.
/// @returns    CX_STATUS_DATA_NOT_READY            - if CPUs are not initialized yet
/// @returns    OTHER                               - other CX_STATUS values returned by the APIs used in the function
///
CX_VOID
IpiSendVector(
    _In_ CX_UINT64    Affinity,
    _In_ CX_UINT8     Vector
);

/// @name Freezing support
/// @brief Provides support for freezing processors.
///
/// Depending on the affinity parameter, one or more processors will arrive in the IpiFreezingHandler function.
/// The Reason parameter tells us if certain operations are performed on the processor / processors reached in
/// IpiFreezingHandler function (eg: debugger flush to vmcs, see comments in function for more details).
/// After the processors perform the operations specific to the reason they were frozen (if any),
/// they sit in a spin wait until the IpiResumeCpus function is called.
/// The IpiFreezeCpus(Silent) function returns an Id via the output parameter
/// to be transmitted to the IpiResumeCpus function.
/// The Silent variant does not log the freeze request on the serial output.
///
/// @param[in]  Affinity                AFFINITY_ALL_EXCLUDING_SELF, AFFINITY_ALL_INCLUDING_SELF or AFFINITY_CPU_INDEX(index)
/// @param[in]  Reason                  Value from INTERRUPT_FREEZE_REASON enum
/// @param[out] Id                      The operation Id to use in the IpiResumeCpus function to unlock the processors
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Id parameter is CX_NULL
/// @returns    CX_STATUS_NOT_INITIALIZED           - if CPUs are not initialized yet
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE    - if Cpu freeze lock is already acquired
/// @returns    OTHER                               - other CX_STATUS values returned by the APIs used in the function
///
///@{
#define IpiFreezeCpus(Affinity, Reason, Id)       IpiFreezeCpus2(Affinity, Reason, Id, __FILE__, __LINE__, CX_FALSE)
#define IpiFreezeCpusSilent(Affinity, Reason, Id) IpiFreezeCpus2(Affinity, Reason, Id, __FILE__, __LINE__, CX_TRUE)
CX_STATUS
IpiFreezeCpus2(
    _In_ CX_UINT64                Affinity,
    _In_ INTERRUPT_FREEZE_REASON  Reason,
    _Out_ CX_VOID                 **Id,
    _In_ CX_INT8                  *File,
    _In_ CX_UINT16                Line,
    _In_ CX_BOOL                  Silent
);
///@}

/// @name Unfreezing support
/// @brief The inverse function of the IpiFreezeCpus(Silent).
///
/// This function unlocks the processors that were frozen by the IpiFreezeCpus(Silent) function.
/// It needs the operation ID returned by the IpiFreezeCpus(Silent) function.
///
/// @param[in] Id                       Id returned by IpiFreezeCpus(Silent) function.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Id is CX_NULL or the address pointed by Id is null
/// @returns    CX_STATUS_INVALID_DEVICE_STATE      - if interrupts are enabled (interruptions should be stopped by the freezing function)
///
///@{
#define IpiResumeCpus(Id) IpiResumeCpus2(Id, __FILE__, __LINE__);
CX_STATUS
IpiResumeCpus2(
    _In_ CX_VOID      **Id,
    _In_ CX_INT8      *File,
    _In_ CX_UINT16    Line
);
///@}

/// @}

#endif