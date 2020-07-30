/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "kernel/kerneldefs.h"
#include "kernel/kernel.h"
#include "kernel/vcpu.h"
#include "memory/cachemap.h"
#include "common/kernel/module_updates.h"

#define UPLOG                       LOG         ///< activate/deactivate logging for module_updates
#define UPD_MAX_MANAGED_MODULES     4           ///< how many #UPD_MODULE_MANAGEMENT_CALLBACKS entries are available

// enforce hard-coded limits for how much memory we accept to allocate and map
#define UPD_MAX_MODULE_SIZE         (16 * CX_MEGA)    ///< maximum size in bytes for any module
#define UPD_MAX_CUSTOM_DATA_SIZE    (4 * CX_MEGA)     ///< maximum size in bytes for any custom data buffer

/// @brief Internal data structure for collecting module management information
typedef struct _UPD_MODULE_MANAGEMENT_CALLBACKS
{
    LD_MODID                          ModuleId;    ///< id of the managed module
    PFUNC_UpdOnModuleInitCallback     OnInit;      ///< init for update is called before anything else
    PFUNC_UpdOnModuleUninitCallback   OnUninit;    ///< un-init for the old module is called after init new one was successful
    PFUNC_UpdOnModuleDoneCallback     OnDone;      ///< on-done is called after the update is committed (and the old one was un-inited and freed)
    UPD_HV_INFO                       HvInfo;      ///< data structure filled-in by the HV with data coming from the guest
    CX_ONCE_INIT0                     Initialized; ///< used to keep track if the module was initialized or not
}UPD_MODULE_MANAGEMENT_CALLBACKS;

extern LD_NAPOCA_MODULE gBootModules[LD_MAX_MODULES];

/// Array of managed modules, each module can have registered callbacks to be called when an update is being applied
static UPD_MODULE_MANAGEMENT_CALLBACKS gUpdCallbacks[UPD_MAX_MANAGED_MODULES] = { 0 };

///
/// @brief        Finds #gUpdCallbacks entry by given moduleId
///
/// @param[in]    ModuleId                         The id of the module which has to be found
///
/// @returns      CX_NULL                          - when not found
/// @returns      UPD_MODULE_MANAGEMENT_CALLBACKS* - pointer to the module entry
static
UPD_MODULE_MANAGEMENT_CALLBACKS*
_UpdGetArrayEntry(
    _In_ LD_MODID ModuleId
)
{
    CX_UINT32 i;
    for (i = 0; i < UPD_MAX_MANAGED_MODULES; i++)
    {
        if (gUpdCallbacks[i].ModuleId == ModuleId)
        {
            return &gUpdCallbacks[i];
        }
    }
    return CX_NULL;
}


///
/// @brief        Retrieves the content of a Guests Update buffer and writes it to a newly allocated Buffer inside the host.
///
/// @param[in]    Vcpu                             The address of the Virtual CPU
/// @param[in]    BufferGva                        The Guest Buffers Guest Virtual Address
/// @param[in]    BufferSize                       The Guest Buffers size in bytes
/// @param[out]   DataBuffer                       The location where the newly allocated Host buffers Host Virtual Address will be returned
/// @param[out]   DataBufferPa                     The location where the newly allocated Host buffers Host Physical Address will be returned
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_XXX                    - other statuses coming from ChmMapGvaRange(), HpAllocWithTagAndInfoAligned(), MmQueryPa() or ChmUnmapGvaRange().
///
static
CX_STATUS
_UpdRetrieveBuffer(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 BufferGva,
    _In_ CX_UINT32 BufferSize,
    _Out_ CX_VOID **DataBuffer,
    _Out_ CX_UINT64 *DataBufferPa
)
{
    CX_VOID *hva;
    CX_STATUS status, unmapStatus;
    CX_BOOL unmap = CX_FALSE;

    // no validations, this is not meant to be a public function

    UPLOG("mapping guest buffer\n");

    // map the guest data buffer
    status = ChmMapGvaRange(Vcpu, BufferGva, BufferSize, CHM_FLAG_AUTO_ALIGN, &hva, CX_NULL, TAG_MODULE);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmMapGvaRange", status);
        goto cleanup;
    }
    unmap = CX_TRUE;

    // allocate a HV buffer
    UPLOG("alloc hv buffer\n");

    status = HpAllocWithTagAndInfoAligned(DataBuffer, BufferSize, 0, TAG_MODULE, CX_PAGE_SIZE_4K);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagAndInfoAligned", status);
        goto cleanup;
    }

    // get the physical address of the newly allocated buffer
    status = MmQueryPa(&gHvMm, *DataBuffer, DataBufferPa);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmQueryPa", status);
        goto cleanup;
    }

    // capture the guest buffer
    UPLOG("copy buffer: dst=%p, src=%p, sz=%d, gva=%p\n", *DataBuffer, hva, BufferSize, BufferGva);
    memcpy(*DataBuffer, hva, BufferSize);

    status = CX_STATUS_SUCCESS;

cleanup:
    if (unmap)
    {
        UPLOG("unmapped guest buffer\n");
        unmapStatus = ChmUnmapGvaRange(&hva, TAG_MODULE);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("ChmUnmapGvaRange", unmapStatus);
    }
    return status;
}


///
/// @brief        Retrieve memory buffers from guest and copy their content into HV-allocated buffers to isolate the host from the guest
///
/// @param[in]    Vcpu                             The address of the Virtual CPU
/// @param[in]    GuestInfo                        Data structure sent by the guest and describing an update available for being applied for modules
/// @param[out]   HvInfo                           Data structure containing the copy of the Guest sent update with mappings in the host
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_INVALID_DATA_SIZE      - if modules data or custom data size is bigger then the maximum allowed size.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Vcpu is an invalid pointer.
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if GuestInfo is an invalid pointer.
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if HvInfo is an invalid pointer.
/// @returns      CX_STATUS_XXX                    - other statuses coming from _UpdRetrieveBuffer() or HpFreeAndNullWithTag()
///
static
CX_STATUS
_UpdRetrieveUpdate(
    _In_ VCPU* Vcpu,
    _In_ UPD_INFO *GuestInfo,
    _Out_ UPD_HV_INFO *HvInfo
)
{
    CX_STATUS status;
    CX_VOID *dataBuffer = CX_NULL;
    CX_UINT64 dataBufferPa = 0;
    CX_VOID *customDataBuffer = CX_NULL;
    CX_UINT64 customDataBufferPa = 0;
    CX_BOOL dataAllocated = CX_FALSE, customDataAllocated = CX_FALSE;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GuestInfo) return CX_STATUS_INVALID_PARAMETER_2;
    if (!HvInfo) return CX_STATUS_INVALID_PARAMETER_3;

    if (GuestInfo->DataSize > UPD_MAX_MODULE_SIZE) return CX_STATUS_INVALID_DATA_SIZE;
    if (GuestInfo->CustomDataSize > UPD_MAX_CUSTOM_DATA_SIZE) return CX_STATUS_INVALID_DATA_SIZE;

    (HvInfo->VaInfo) = *GuestInfo; // copy whole structure and then we'll proceed with overwriting the host addresses

    if (GuestInfo->Data != CX_NULL && GuestInfo->DataSize != 0)
    {
        status = _UpdRetrieveBuffer(Vcpu, GuestInfo->Data, GuestInfo->DataSize, &dataBuffer, &dataBufferPa);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_UpdRetrieveBuffer", status);
            goto cleanup;
        }
        dataAllocated = CX_TRUE;
        HvInfo->VaInfo.Data = (CX_UINT64)(CX_SIZE_T)dataBuffer;
        HvInfo->DataPa = dataBufferPa;
        UPLOG("Got DATA at %p, size=%d\n", dataBuffer, GuestInfo->DataSize);
    }
    else UPLOG("CX_NULL : GuestInfo->Data = %p, GuestInfo->DataSize=%d\n", GuestInfo->Data, GuestInfo->DataSize);

    // custom data
    if (GuestInfo->CustomData != CX_NULL && GuestInfo->CustomDataSize != 0)
    {
        UPLOG("Retrieving CustomData of size=%d\n", GuestInfo->CustomDataSize);
        status = _UpdRetrieveBuffer(Vcpu, GuestInfo->CustomData, GuestInfo->CustomDataSize, &customDataBuffer, &customDataBufferPa);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_UpdRetrieveBuffer", status);
            goto cleanup;
        }
        customDataAllocated = CX_TRUE;
        HvInfo->VaInfo.CustomData = (CX_UINT64)(CX_SIZE_T)customDataBuffer;
        UPLOG("Got CUSTOM at %p, size=%d\n", customDataBuffer, GuestInfo->CustomDataSize);
    }
    else UPLOG("CX_NULL : GuestInfo->CustomData = %p, GuestInfo->CustomDataSize=%d\n", GuestInfo->CustomData, GuestInfo->CustomDataSize);

    return CX_STATUS_SUCCESS;

cleanup:
    if (dataAllocated)
    {
        CX_STATUS clnstatus;

        UPLOG("free data buffer\n");

        clnstatus = HpFreeAndNullWithTag((CX_VOID **)&dataBuffer, TAG_MODULE);
        if (!CX_SUCCESS(clnstatus)) LOG_FUNC_FAIL("HpFreeAndNullWithTag", clnstatus);
    }

    if (customDataAllocated)
    {
        CX_STATUS clnstatus;

        clnstatus = HpFreeAndNullWithTag((CX_VOID **)&customDataBuffer, TAG_MODULE);
        if (!CX_SUCCESS(clnstatus)) LOG_FUNC_FAIL("HpFreeAndNullWithTag", clnstatus);
    }

    return status;
}

CX_STATUS
UpdLoadUpdate(
    _In_ VCPU* Vcpu,
    _In_ UPD_INFO *UpdateInfo
)
{
    CX_STATUS status;
    UPD_INFO updateRequest;
    UPD_HV_INFO hvInfo = { 0 };
    LD_NAPOCA_MODULE *module;
    CX_BOOL needUpdateBuffersFree = CX_FALSE;
    CX_VOID *initContext = CX_NULL;
    UPD_MODULE_MANAGEMENT_CALLBACKS *cb = CX_NULL;
    CX_BOOL updateHasMainModule = CX_FALSE;
    UPD_HV_INFO oldModuleInfo;
    CX_BOOL failedInDone = CX_FALSE;

    // setup a variable for globally signaling when updates are in progress, we MUST fail all update requests while one is already in progress
    // (at least for introcore, it's important to avoid 2 updates/instances trying to unload/uninit each other..)
    static volatile CX_UINT32 gUpdUpdateInInProgress = 0;

    if (HvInterlockedCompareExchangeU32(&gUpdUpdateInInProgress, 1, 0) != 0)
    {
        // we're not in a 'ready for an update' state and we can't spin/wait, we must fail the update
        return CX_STATUS_COMPONENT_NOT_READY;
    }

    // copy the guest memory before any further processing
    updateRequest = *UpdateInfo;

    if (updateRequest.Magic != UPD_MAGIC)
    {
        status = CX_STATUS_CORRUPTED_DATA;
        goto cleanup;
    }

    UPLOG("\n  Build = %d\n  Custom = %p\n  CustomSize = %d\n  Data = %p\n  DataSize = %d\n  High = %X\n  Low = %X\n  Revision = %d\n",
        updateRequest.Build,
        updateRequest.CustomData,
        updateRequest.CustomDataSize,
        updateRequest.Data,
        updateRequest.DataSize,
        updateRequest.High,
        updateRequest.Low,
        updateRequest.Revision);

    // get the actual update payload
    UPLOG("_UpdRetrieveUpdate\n");
    status = _UpdRetrieveUpdate(Vcpu, &updateRequest, &hvInfo);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_UpdRetrieveUpdate", status);
        goto cleanup;
    }
    needUpdateBuffersFree = CX_TRUE;

    cb = _UpdGetArrayEntry(hvInfo.VaInfo.ModId);
    UPLOG("The Update is targeting %s\n", LdGetModuleName(hvInfo.VaInfo.ModId));
    if (cb == CX_NULL)
    {
        status = CX_STATUS_INVALID_DATA_TYPE;
        ERROR("Failed to find module based on the module ID: %u\n", hvInfo.VaInfo.ModId);
        goto cleanup;
    }

    // retrieve old module info
    status = LdGetModule(gBootModules, LD_MAX_MODULES, hvInfo.VaInfo.ModId, &module);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }

    // call module init callback
    if (cb->OnInit != CX_NULL)
    {
        oldModuleInfo = cb->HvInfo;
        if (oldModuleInfo.DataPa == 0)
        {
            oldModuleInfo.DataPa = module->Pa;
            oldModuleInfo.VaInfo.Data = module->Va;
            oldModuleInfo.VaInfo.DataSize = module->Size;
        }

        UPLOG("calling init callback\n");
        status = cb->OnInit(&oldModuleInfo, &hvInfo, &initContext);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("OnInit", status);
            goto cleanup;
        }
    }

    updateHasMainModule = (hvInfo.VaInfo.Data != CX_NULL);
    // call uninit callback
    if (CX_NULL != cb->OnUninit)
    {
        UPLOG("uninit old module\n");
        status = cb->OnUninit(&oldModuleInfo, &hvInfo, initContext);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("OnUninit", status);
            goto cleanup;
        }
    }

    // if we did not load new module, leave the old one
    if (updateHasMainModule)
    {
        // commit the new module
        UPLOG("commit module\n");
        cb->HvInfo = hvInfo;

        status = LdSetModule(gBootModules, LD_MAX_MODULES, hvInfo.VaInfo.ModId, hvInfo.VaInfo.Data,
            hvInfo.DataPa, hvInfo.VaInfo.DataSize, module->Flags | LD_MODFLAG_DYNAMICALLY_ALLOCATED);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("LdSetModule", status);
    }
    else UPLOG("hvInfo.VaInfo.Data is CX_NULL!\n");

    // call the done callback
    if (cb->OnDone != CX_NULL)
    {
        UPLOG("calling module done callback\n");
        status = cb->OnDone(&hvInfo, initContext);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("OnDone", status);
            failedInDone = CX_TRUE;
            goto cleanup;
        }
    }

    UpdateInfo->High = hvInfo.VaInfo.High;
    UpdateInfo->Low = hvInfo.VaInfo.Low;
    UpdateInfo->Revision = hvInfo.VaInfo.Revision;
    UpdateInfo->Build = hvInfo.VaInfo.Build;

    status = CX_STATUS_SUCCESS;

cleanup:
    if (needUpdateBuffersFree)
    {
        CX_STATUS clnstatus;

        if (!CX_SUCCESS(status))
        {
            if (hvInfo.VaInfo.Data != CX_NULL)
            {
                UPLOG("free data buffer\n");

                clnstatus = HpFreeAndNullWithTag((CX_VOID **)&hvInfo.VaInfo.Data, TAG_MODULE);
                if (!CX_SUCCESS(clnstatus))
                {
                    LOG_FUNC_FAIL("HpFreeAndNullWithTag", clnstatus);
                }
                // do not touch the existing module if the failure is at the beginning of the update (on init)
                if (failedInDone) cb->HvInfo.VaInfo.Data = CX_NULL;
            }

            // patch it ... so that the patch works (needs to be != 0 in order to detect that it's not the "genesis" introspection is the one loaded)
            if (failedInDone) cb->HvInfo.DataPa = 45067;
        }
        if (hvInfo.VaInfo.CustomData != CX_NULL)
        {
            UPLOG("free custom data buffer\n");

            clnstatus = HpFreeAndNullWithTag((CX_VOID **)&hvInfo.VaInfo.CustomData, TAG_MODULE);
            if (!CX_SUCCESS(clnstatus)) LOG_FUNC_FAIL("HpFreeAndNullWithTag", clnstatus);
        }
    }
    if (HvInterlockedCompareExchangeU32(&gUpdUpdateInInProgress, 0, 1) != 1)
    {
        // something happened to the synchronization variable
        return CX_STATUS_DATA_ALTERED_FROM_OUSIDE;
    }
    return status;
}


CX_STATUS
UpdSetCallbacks(
    _In_ CX_UINT32 ModId,
    _In_opt_ PFUNC_UpdOnModuleInitCallback Init,
    _In_opt_ PFUNC_UpdOnModuleUninitCallback Uninit,
    _In_opt_ PFUNC_UpdOnModuleDoneCallback Done
)
{
    CX_UINT32 i;
    CX_BOOL tried;
    LD_MODID moduleId = (LD_MODID)ModId;              // avoid signed/unsigned mismatch

    if (ModId >= LD_MAX_MODULES) return CX_STATUS_INVALID_PARAMETER_1;

    do
    {
        tried = CX_FALSE;
        for (i = 0; i < UPD_MAX_MANAGED_MODULES; i++)
        {
            if (gUpdCallbacks[i].Initialized)
            {
                // don't accept multiple UpdSetCallbacks for same module as it might not be "thread"-safe
                if (gUpdCallbacks[i].ModuleId == moduleId) return CX_STATUS_ALREADY_INITIALIZED;
            }
            else
            {
                // try to reserve the entry
                tried = CX_TRUE;
                if (CxInterlockedBeginOnce(&gUpdCallbacks[i].Initialized))
                {
                    gUpdCallbacks[i].OnInit = Init;
                    gUpdCallbacks[i].OnUninit = Uninit;
                    gUpdCallbacks[i].OnDone = Done;
                    gUpdCallbacks[i].ModuleId = moduleId;

                    // fail if someone altered the data using unsynchronized code
                    if (!CxInterlockedEndOnce(&gUpdCallbacks[i].Initialized)) return CX_STATUS_SYNCHRONIZATION_INCONSISTENCY;

                    return CX_STATUS_SUCCESS;
                }
            }
        }
    } while (tried); // stop if we couldn't even try taking an entry (meaning they're all occupied)


    return CX_STATUS_OUT_OF_RESOURCES;
}
