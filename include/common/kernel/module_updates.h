/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _MODULE_UPDATES_H_
#define _MODULE_UPDATES_H_

#include "cx_native.h"

#define UPD_MAGIC 0x8c43765a             ///< Magic value used for validation of an update request

/// @brief Data structure sent by the guest and describing an update available for being applied for modules
#pragma pack(push, 1)
typedef struct _UPD_GUEST_INFO
{
    //in
    CX_UINT32   Magic;          ///< Valid if equal to #UPD_MAGIC
    CX_UINT32   ModId;          ///< Identifies the module being targeted by this update
    CX_UINT64   Data;           ///< GVA when part of a simple UPD_INFO or a HVA when inside a UPD_HV_INFO, contains the data of a module
    CX_UINT32   DataSize;       ///< Size of the data buffer
    CX_UINT64   CustomData;     ///< Size of the custom data, varies in function of ModId - in & out, GVA when part of a simple UPD_INFO or a HVA when inside a UPD_HV_INFO
    CX_UINT32   CustomDataSize; ///< Size of the custom data buffer

    //out
    CX_UINT32   High;           ///< Major version of the active module after the update process finished
    CX_UINT32   Low;            ///< Minor version of the active module after the update process finished
    CX_UINT32   Revision;       ///< Revision of the active module after the update process finished
    CX_UINT32   Build;          ///< Build number of the active module after the update process finished
}UPD_INFO;
#pragma pack(pop)

/// @brief Data structure filled-in by the HV and describing an update ready to be applied
typedef struct _UPD_HV_INFO
{
    UPD_INFO VaInfo;        ///< The data structure contains everything regarded the module update, coming from the guest
    CX_UINT64 DataPa;       ///< HPA of the data buffer
    CX_UINT64 CustomDataPa; ///< HPA of the custom data buffer
}UPD_HV_INFO;


// init/un-init callbacks triggering additional processing needed for each specific module that expects hot-updates

///
/// @brief        Init callback function type for module updates, it is called before anything else during the update of the module.
///
/// @param[in]    OldInfo                          UPD_HV_INFO structure describing the old module
/// @param[in]    NewInfo                          UPD_HV_INFO structure describing the new module
/// @param[in, out] UpdateInProgressContextPtr     An optional address of a pointer where you can store the address of a buffer you allocate,
///                                                which serves as extra context information during the update of the new module.
///
typedef
CX_STATUS
(FUNC_UpdOnModuleInitCallback)(
    _In_opt_ UPD_HV_INFO *OldInfo,
    _In_ UPD_HV_INFO *NewInfo,
    _Inout_opt_ CX_VOID **UpdateInProgressContextPtr
    );

/// @brief Wrapper type for a function pointer to an FUNC_UpdOnModuleInitCallback function
typedef FUNC_UpdOnModuleInitCallback *PFUNC_UpdOnModuleInitCallback;


///
/// @brief        Un-Init callback function type for module updates, it is called after the module was successfully updated with the new data,
///               un-initializes the old module data.
///
/// @param[in]    OldInfo                          UPD_HV_INFO structure describing the old module
/// @param[in]    NewInfo                          UPD_HV_INFO structure describing the new module
/// @param[in]    UpdateInProgressContext          An optional address of the current update context buffer, describes the NEW update which is now in progress
///
typedef
CX_STATUS
(FUNC_UpdOnModuleUninitCallback)(
    _In_ UPD_HV_INFO *OldInfo,
    _In_ UPD_HV_INFO *NewInfo,
    _In_opt_ CX_VOID *UpdateInProgressContext
    );

/// @brief Wrapper type for a function pointer to an FUNC_UpdOnModuleUninitCallback function
typedef FUNC_UpdOnModuleUninitCallback *PFUNC_UpdOnModuleUninitCallback;


///
/// @brief        Done callback function type for module updates, it is called after the update is committed (and the old one was un-inited and freed).
///
/// @param[in]    Info                             UPD_HV_INFO structure describing the module which was updated successfully
/// @param[in]    UpdateInProgressContext          An optional address of the current update context buffer (you need to free it yourself if you allocated one)
///
typedef
CX_STATUS
(FUNC_UpdOnModuleDoneCallback)(
    _In_ UPD_HV_INFO *Info,
    _In_opt_ CX_VOID *UpdateInProgressContext
    );

/// @brief Wrapper type for a function pointer to an FUNC_UpdOnModuleDoneCallback function
typedef FUNC_UpdOnModuleDoneCallback *PFUNC_UpdOnModuleDoneCallback;

typedef struct _VCPU VCPU; ///< Forwarding the declaration of the internal data-structure of a Virtual CPU


//
// Public functions
//


///
/// @brief        This function allows for customizations of the update process of a given module by specifying code to be executed at various steps
///
/// @param[in]    ModId                            Callback is associated to updates targeting this module
/// @param[in]    Init                             Custom initializations / validations
/// @param[in]    Uninit                           Custom un-init if needed
/// @param[in]    Done                             Custom operations to perform when the update has been completed and we committed to the new version
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_ALREADY_INITIALIZED    - if the targeted module has been already initialized with update callbacks
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if ModId is an invalid module id, higher than the maximum id value.
/// @returns      CX_STATUS_SYNCHRONIZATION_INCONSISTENCY - if somebody altered during the initialization the callbacks of this module using unsynchronized code
/// @returns      CX_STATUS_OUT_OF_RESOURCES       - if there are no more left module entries for new modules to be managed by custom update callbacks
///
CX_STATUS
UpdSetCallbacks(
    _In_ CX_UINT32 ModId,
    _In_opt_ PFUNC_UpdOnModuleInitCallback Init,
    _In_opt_ PFUNC_UpdOnModuleUninitCallback Uninit,
    _In_opt_ PFUNC_UpdOnModuleDoneCallback Done
);

///
/// @brief        Retrieve a module update, call init and un-init callbacks, free old version of the module.
///
/// @param[in]    Vcpu                             VCPU that has access to the Update buffers (CR3)
/// @param[in]    UpdateInfo                       UPD_INFO structure describing the in-guest data buffers and update info
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_CORRUPTED_DATA         - if the magic of the update request is not our UPD_MAGIC
/// @returns      CX_STATUS_COMPONENT_NOT_READY    - if we're not in a 'ready for an update' state and we can't spin/wait, we must fail the update
/// @returns      CX_STATUS_INVALID_DATA_TYPE      - if the module is not found in the update callbacks array by the id
/// @returns      CX_STATUS_DATA_ALTERED_FROM_OUSIDE - if somebody altered during the update the synchronization variable
/// @returns      CX_STATUS_XXX                    - if some function called inside this function fails (see implementation for possible exact reasons and sources)
///
/// @remark       This function should be called by the exit handler implementing the guest-communication channel used for module updates transfers.
///
CX_STATUS
UpdLoadUpdate(
    _In_ VCPU* Vcpu,
    _In_ UPD_INFO* UpdateInfo
);

#endif // _MODULE_UPDATES_H_
