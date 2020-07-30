/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _DRVINSTALL_H_
#define _DRVINSTALL_H_

#include "winguestdll.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Install winguest driver
 *
 * @param[in] InfFile       Full path to driver information file
 * @param[in] HwId          Device hardware Id
 * @param[in] Flags         Unused
 * @param[in] Context       Unused
 *
 * @return STATUS_SUCCESS                           operation completed successfully
 * @return STATUS_WG_NOT_INITIALIZED                Winguest dll not properly initialized
 * @return STATUS_DRIVER_CONNECTION_ACTIVE          Driver connection currently active
 * @return STATUS_UNKNOWN_HW_ID                     Hardware Id not in white list
 * @return OTHER                                    other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestInstallDriver(
    _In_ WCHAR const* InfFile,
    _In_ WCHAR const* HwId,
    _In_ DWORD Flags,
    _In_opt_ VOID* Context
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestInstallDriver)(
    _In_ WCHAR const* InfFile,
    _In_ WCHAR const* HwId,
    _In_ DWORD Flags,
    _In_opt_ VOID* Context
    );

/**
 * @brief Uninstall winguest driver
 *
 * @param[in] InfFile       Full path to driver information file
 * @param[in] HwId          Device hardware Id
 * @param[in] Flags         Unused
 * @param[in] Context       Unused
 *
 * @return STATUS_SUCCESS                           operation completed successfully
 * @return STATUS_WG_NOT_INITIALIZED                Winguest dll not properly initialized
 * @return STATUS_DRIVER_CONNECTION_ACTIVE          Driver connection currently active
 * @return STATUS_UNKNOWN_HW_ID                     Hardware Id not in white list
 * @return OTHER                                    other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestUninstallDriver(
    _In_ WCHAR const* InfFile,
    _In_ WCHAR const* HwId,
    _In_ DWORD Flags,
    _In_opt_ VOID* Context
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestUninstallDriver)(
    _In_ WCHAR const* InfFile,
    _In_ WCHAR const* HwId,
    _In_ DWORD Flags,
    _In_opt_ VOID* Context
    );

/**
 * @brief Configure Windows to work better with Napoca Hypervisor
 *
 * @param[in] Configuration     BCD entry where changes are applied. Usually should be left NULL to use the default entry.
 *
 * This routine:
 * * Enables PAE
 * * Disables dynamic ticks
 * * Relaxes registry Graphics Drivers Timeout Detection and Recovery timings
 * * Relaxes registry DPC Watchdog timings
 *
 * @return STATUS_SUCCESS                           operation completed successfully
 * @return STATUS_CONFIGURATION_REQUIRES_RESTART    Changes require reboot in order to be fully active
 * @return OTHER                                    other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetDefaultBcdValues(
    _In_opt_ WCHAR const* Configuration
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestSetDefaultBcdValues)(
    _In_opt_ WCHAR const* Configuration
    );

/**
 * @brief Clean up changes done to the machine that were made after original installation.
 *
 * Best effort. Cannot revert all changes.
 * Usually called before product uninstallation. Hypervisor must be deconfigured separately before calling this routine.
 *
 * @return STATUS_SUCCESS                   operation completed successfully
 * @return OTHER                            other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestPerformCleanup(
    void
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestPerformCleanup)(
    void
    );

#ifdef __cplusplus
}
#endif

#endif //_DRVINSTALL_H_
