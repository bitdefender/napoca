/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup power
///@{

/** @file power.h
*   @brief POWER - ACPI power management support
*
*/

#ifndef _POWER_H_
#define _POWER_H_

#include "core.h"
#include "kernel/kerneldefs.h"


///
/// @brief        Pre-initialize the Power structure with 0.
///
void
PwrPreinit(
    void
    );


///
/// @brief        Used to check if Napoca managed to setup everything that is needed for power transitions using ACPI.
///
/// @returns      TRUE                             - if the hyper-visor managed successfully to set up the power interface
/// @returns      FALSE                            - otherwise
///
BOOLEAN
PwrIsSystemSupported(
    void
);


///
/// @brief        Function called in Phase1 in order to init parts of the Power data structure, information which is extracted
///               from the ACPi tables FADT and FACS.
///
/// @param[in]    Fadt                             A pointer to the ACPI FADT table.
/// @param[in]    Facs                             A pointer to the ACPI FACS table.
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well or even if we didn't manage to log the Pa for Facs table and other informations
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case one of the tables is not available
///
NTSTATUS
PwrInitDataStructsPhase1(
    _In_ ACPI_TABLE_FADT* Fadt,
    _In_ ACPI_TABLE_FACS* Facs
    );


///
/// @brief        Sets am IO Hook on the Pm1a port having #_PwrReadPm1a and #_PwrWritePm1a functions as callbacks for the hook.
///
/// @param[in]    Guest                            Napoca-specific guest identifier
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well
/// @returns      OTHER                            - other error statuses returned by #HkSetIoHook
///
NTSTATUS
PwrHookPm1a(
    _In_ GUEST *Guest
    );


///
/// @brief        Calls AcpiGetSleepTypeData in order to retrieve available sleep types and initializes #gPowerTransTypeFound and
///               #gPowerTransType variables to hold the date retrieved.
///
void
PwrInitAcpiSleepStates(
    void
    );


///
/// @brief        Function called on all AP processors during wakeup from sleep (S3).
///
/// @returns      This function should never return neither a SUCCESS nor an ERROR status, if something fails, we should unload
///               and give back control to the loader or in case if we already started the Guest, we should just HALT.
///
/// @remark       Exposed to nasm file: ap_initialization.nasm
NTSTATUS
PwrResumeHostAp(
    void
);


///
/// @brief        Tries to reboot the platform, if specified, it performs VMX_OFF on every CPU and puts all APs into halted state
///               and executes the platform reboot on the BSP. If it is an emergency reboot it first tries to dump logs through the
///               serial port if we have it initialized or tries to initializes at that moment. If that fails and the configured
///               policy is to not prefer reboots on emergency reboot crash dump failures, then it simply HALTs also the BPS.
///
/// @param[in]    PerformVmxoffBroadcast           TRUE if VMX OFF operation s requested on every CPU, FALSE if not
/// @param[in]    IsEmergency                      TRUE if it is an emergency reboot, caused by some severe crash or
///                                                internal failure, FALSE otherwise.
///
VOID
PwrReboot(
    _In_    BOOLEAN     PerformVmxoffBroadcast,
    _In_    BOOLEAN     IsEmergency
);


/// @brief Lock used on cases of power transitions when we want to broadcast VMX_OFF, locking only one CPU to broadcast
/// @remark Lock is never released. But, it is reinitialized on wakeup, which is basically the same thing.
extern SPINLOCK gVmxOffLock;

#endif // _POWER_H_

///@}