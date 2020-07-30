/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup hibernate
///@{

/** @file hibernate_clients.h
 *  @brief HIBERNATE_CLIENTS - All the supported clients which store and restore some specific data during of the power transition of the Guest into S4(Hibernate) state.
 *
 */

#ifndef __HIBERNATE_CLIENTS_H__
#define __HIBERNATE_CLIENTS_H__

#include "core.h"
#include "boot/boot.h"
#include "memory/hibernate.h"
#include "kernel/guestenlight.h"

///
/// @brief Data structure holding all the needed data related to guest enlightenments, which need to be persisted and restored during hibernate.
///
typedef struct _GUEST_ENLIGHT_SAVE_DATA
{
    MSFT_HV_X64_MSR_GUEST_OS_ID GuestOsId;          ///< The guest OS id
    QWORD                       HypercallPageGpa;   ///< The address of the hyper call page
    BOOLEAN                     HypercallPageActive;///< The state of the hypercall page
    QWORD                       TscPage;            ///< The address of the Tsc page
    QWORD                       GuestVcpuCount;     ///< The guests Vcpu count
}GUEST_ENLIGHT_SAVE_DATA;

///
/// @brief Data structure holding all the PCI devices BAR reconfigurations done by the guest, which need to be persisted and restored during hibernate.
///
typedef struct _GUEST_BAR_RECONF_SAVE_DATA
{
    PCI_BAR_RECONF_INFO         BarReconfigurations; ///< All PCI BAR reconfigurations done by the guest
}GUEST_BAR_RECONF_SAVE_DATA;



///
/// @brief        The get callback of the Guest enlightenment hibernate client. It assures that the GUEST_OS_ID,
///               the Hyper call page, the TSC page and the Guest VcpuCount are saved during a hibernate.
///
/// @param[out]   DataBuffer                       Preallocated buffer of size given at register time. Implementation will copy here data that is to be persisted
/// @param[in]    DataBufferSize                   Buffer size, same size given at register time
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case the DataBufferSize is smaller than #GUEST_ENLIGHT_SAVE_DATA.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the DataBuffer is not valid
///
NTSTATUS
HvHibGuestEnlightGetData(
    _Out_ BYTE *DataBuffer,
    _In_ DWORD DataBufferSize
    );

///
/// @brief        The put callback of the Guest enlightenment hibernate client. It assures that the GUEST_OS_ID,
///               the Hyper call page, the TSC page and the Guest VcpuCount are re-stored properly after resuming a hibernate.
///
/// @param[in]    DataBuffer                       Preallocated buffer containing data that is restored
/// @param[in]    DataBufferSize                   Buffer size, same size given at register time
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case the DataBufferSize is smaller than #GUEST_ENLIGHT_SAVE_DATA.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the DataBuffer is not valid
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - in case the resumed guests Vcpu count doesn't match the number of Vcpus it had before the hibernate.
/// @returns      OTHER                            - other error statuses coming from #GstEnHandleMsrWrite.
///
NTSTATUS
HvHibGuestEnlightPutData(
    _In_ BYTE  *DataBuffer,
    _In_ DWORD DataBufferSize
    );

///
/// @brief        The get callback of the Guest PCI BAR reconfiguration client. It assures that after the hibernate resume,
///               we will know all the reconfigured addresses found inside PCI BARs. These, being physical memory addresses for devices
///               which are not present anywhere else and some OSes forget to actually reconfigure them in PCI BAR registers before accessing them after
///               a hibernate. This function stores all the reconfigurations detected on the system until the start of the hibernate process.
///
/// @param[out]   DataBuffer                       Preallocated buffer of size given at register time. Implementation will copy here data that is to be persisted;
/// @param[in]    DataBufferSize                   Buffer size, same size given at register time
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case the DataBufferSize is smaller than #GUEST_BAR_RECONF_SAVE_DATA.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the DataBuffer is not valid
/// @returns      OTHER                            - other error statuses coming from #GstEnHandleMsrWrite.
///
NTSTATUS
HvHibGuestBarReconfGetData(
    _Out_ BYTE *DataBuffer,
    _In_ DWORD DataBufferSize
);

///
/// @brief        The put callback of the Guest PCI BAR reconfiguration client. It assures that after the hibernate resume,
///               we will know all the reconfigured addresses found inside PCI BARs. These, being physical memory addresses for devices
///               which are not present anywhere else and some OSes forget to actually reconfigure them in PCI BAR registers before accessing them after
///               a hibernate. This function re-stores all the known(before hibernate) PCI BAR reconfigurations inside our EPT and Device memory maps.
///
/// @param[in]    DataBuffer                       Preallocated buffer containing data that is restored
/// @param[in]    DataBufferSize                   Buffer size, same size given at register time
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case the DataBufferSize is smaller than #GUEST_BAR_RECONF_SAVE_DATA.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the address of the DataBuffer is not valid
/// @returns      OTHER                            - other error statuses coming from #GstEnHandleMsrWrite.
///
NTSTATUS
HvHibGuestBarReconfPutData(
    _In_ BYTE  *DataBuffer,
    _In_ DWORD DataBufferSize
);

#endif

///@}