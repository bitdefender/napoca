/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup introspection Introspection integration and support
///@{

/** @file intromodule.c
*   @brief INTROMODULE -  NAPOCA hypervisor introspection module related APIs
*
*/

#include "napoca.h"
#include "kernel/kerneldefs.h"
#include "common/kernel/module_updates.h"
#include "memory/memmgr.h"
#include "memory/fastmap.h"
#include "base/pe.h"
#include "introspection/intromodule.h"
#include "kernel/interrupt.h"
#include "kernel/kernel.h"
#include "guests/intro.h"
#include "common/communication/commands.h"
#include "kernel/kernel.h"
#include "introspection/introengine.h"
#include "common/kernel/napoca_compatibility.h"
#include "common/kernel/napoca_version.h"

static HV_INTRO_MODULE_INTERFACE gIntroModuleInterface;        ///< intro module management callbacks (init/uninit/preinit)
static HV_INTRO_MODULE_INTERFACE gIntroUpdatedModuleInterface; ///< the updated intro module management callbacks (init/uninit/preinit)


///
/// @brief        Handles the control of the memory introspection engine, start or stop the engine.
///
/// @param[in]    Guest                            Napoca specific guest-identifier
/// @param[in]    Enable                           TRUE to enable/start the engine, FALSE to disable/stop
/// @param[in]    ForceOperation                   If TRUE introspection will ignore Safeness and will unload even if it leaves the Guest in unstable state
/// @param[in]    Options                          Optional, the introspection options (activation and protection flags) needed only for starting the introspection
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See NapIntNotifyAboutNewGuest() or NapIntDisable() for possible return codes.
///
static
NTSTATUS
_HandleControlMemoryIntrospection(
    _In_ GUEST* Guest,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN ForceOperation,
    _In_opt_ QWORD Options
)
{
    NTSTATUS status;

    if (Enable)
    {
        status = NapIntNotifyAboutNewGuest(Guest, Options, (BYTE*)gHypervisorGlobalData.Introspection.IntroUpdatesVa, gHypervisorGlobalData.Introspection.IntroUpdatesSize);
        if (!NT_SUCCESS(status)) ERROR("Introspection not enabled! (0x%x)\n", status);
    }
    else
    {
        QWORD flags = 0;

        LOG("Requested to disable introspection on physical CPU index: %d and apic id: %d\n", HvGetCurrentCpuIndex(), HvGetCurrentCpu()->Id);
        if (ForceOperation)
        {
            LOG("Will ignore the safe option to disable intro!\n");
            flags = IG_DISABLE_IGNORE_SAFENESS;
        }

        status = NapIntDisable(Guest, (flags));
    }

    return status;
}

///
/// @brief Cleans up Introspection related buffers from every Guest and Vcpu it also frees the fast maps and
/// if requested resets the GlueIface and the IntroModuleInterface.
///
/// @param[in]  Guest                           - Napoca specific Guest identifier
/// @param[in]  CleanupInterfaces               - if a resetting of the GLUE_IFACE and #HV_INTRO_MODULE_INTERFACE is requested
///
/// @returns    CX_STATUS_SUCCESS               - Always returns success as FmFreeRange errors are masked, due to the fact
///                                             that the rest of the data will still be freed and reset.
///
static
NTSTATUS
_HvCleanupHvIntroData(
    _In_opt_ GUEST* Guest,
    _In_     BOOLEAN CleanupInterfaces
)
{
    VCPU* vcpu;
    NTSTATUS status;

    for (INT32 gstIdx = 0; gstIdx < gHypervisorGlobalData.GuestCount; gstIdx++)
    {
        if ((!Guest) || (Guest == gHypervisorGlobalData.Guest[gstIdx]))
        {
            GUEST* localGuest = gHypervisorGlobalData.Guest[gstIdx];

            status = FmFreeRange(&gHypervisorGlobalData.Introspection.FastmapVaPtr, &gHypervisorGlobalData.Introspection.FastmapPtPtr);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("FmFreeRange", status);
            }


            for (DWORD i = 0; i < localGuest->VcpuCount; i++)
            {
                vcpu = localGuest->Vcpu[i];


                vcpu->IntroEmu.BufferValid = FALSE;
                vcpu->IntroEmu.BufferSize = 0;
                vcpu->IntroEmu.BufferGla = 0;
                memset(vcpu->IntroEmu.Buffer, 0, ND_MAX_OPERAND_SIZE);

                vcpu->IntroTimer = 0;

                if (vcpu->Guest->AlertsCache.Buffer != NULL)
                {
                    memzero(vcpu->Guest->AlertsCache.Buffer, vcpu->Guest->AlertsCache.Size * sizeof(INTROSPECTION_ALERT));
                    vcpu->Guest->AlertsCache.Count = 0;
                }

                vcpu->Guest->Intro.IntroReportedErrorStates = 0;
                vcpu->Guest->Intro.IntroRequestedToBeDisabled = FALSE;

                vcpu->Guest->AlertsCache.Tsc = 0;    // TSC of the first alert - used to cache more alerts
                VirtExcResetPendingException(vcpu, EXCEPTION_PAGE_FAULT);
            }
        }
    }
    if (CleanupInterfaces)
    {
        memzero(&gHypervisorGlobalData.Introspection.GlueIface, sizeof(gHypervisorGlobalData.Introspection.GlueIface));
        memzero(&gIntroModuleInterface, sizeof(gIntroModuleInterface));
    }
    return CX_STATUS_SUCCESS;
}

///
/// @brief        Un-Init callback function for the Introspection module, it is called after the module was successfully updated with the new data,
///               un-initializes the old module data. It stops the Introspection engine for the period of the update.
///
/// @param[in]    OldInfo                          #UPD_HV_INFO structure describing the old Introspection module
/// @param[in]    NewInfo                          #UPD_HV_INFO structure describing the new Introspection module
/// @param[in]    ContextPtr                       Additional context buffer, unused here.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See LdGetModule(), _HandleControlMemoryIntrospection(), HpFreeAndNullWithTag()
///                                                or _HvCleanupHvIntroData() for possible return codes.
///
static
CX_STATUS
_HvIntroUpdateUninit(
    _In_ UPD_HV_INFO *OldInfo,
    _In_ UPD_HV_INFO *NewInfo,
    _In_opt_ CX_VOID *ContextPtr
)
{
    NTSTATUS status;
    LD_NAPOCA_MODULE *dll;

    UNREFERENCED_PARAMETER(ContextPtr);

    LOG("Uninit - Old data VA: 0x%016llx\n", OldInfo->VaInfo.Data);
    LOG("Uninit - New data VA: 0x%016llx\n", NewInfo->VaInfo.Data);

    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_INTRO_CORE, &dll);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }

    status = _HandleControlMemoryIntrospection(gHypervisorGlobalData.Guest[0], FALSE, FALSE, 0); // call disable
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HandleControlMemoryIntrospection", status);
        goto cleanup;
    }

    // if we did not load a new module don't uninitialize the old one
    if (NewInfo->VaInfo.Data && OldInfo->VaInfo.Data)
    {
        // call the uninit routine of the currently loaded introcore
        if (gIntroModuleInterface.IntUninit != NULL)
        {
            LOG("Unload old intro with gIntroModuleInterface.IntUninit = %p\n", gIntroModuleInterface.IntUninit);
            status = gIntroModuleInterface.IntUninit();
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("IntUninit", status);
                goto cleanup;
            }
        }
        else LOG("We have nothing to do here\n");

        // Cannot free in _HvIntroUpdateDone because HpFreeAndNullWithTag would actually re-use the physical pages
        // which were remapped at intro image base
        // Because at the first call to _HvIntroUpdateUninit we may actually have the loader allocated data we need
        // to check if we actually need to free the address through the Heap
        if (OldInfo->VaInfo.Data != NULL)
        {
            if (HpIsValidHeapAddress((VOID*)OldInfo->VaInfo.Data))
            {
                status = HpFreeAndNullWithTag((VOID**)&OldInfo->VaInfo.Data, TAG_MODULE);
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("HpFreeAndNullWithTag", status);
                    goto cleanup;
                }
            }
        }
        else LOG("NewInfo->VaInfo.Data is NULL!\n");

        LOG("Cleaning up hv structures\n");
        status = _HvCleanupHvIntroData(NULL, TRUE);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_HvCleanupHvIntroData", status);
            goto cleanup;
        }
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    return status;
}

///
/// @brief        Done callback function for the Introspection module update, it is called after the update is committed (and the old one
///               was un-inited and freed). It fully initializes the Introspection module and starts the engine if requested.
///
/// @param[in]    Info                             #UPD_HV_INFO structure describing the updated Introspection module
/// @param[in]    ContextPtr                       #HV_INTRO_MODULE_INTERFACE describing the Init callbacks for the Introspection module
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See LdGetModule(), MmMap(), NapIntFullInit(), _HandleControlMemoryIntrospection(),
///                                                LdSetModule() or _HvCleanupHvIntroData() for possible return codes.
static
CX_STATUS
_HvIntroUpdateDone(
    _In_ UPD_HV_INFO *Info,
    _In_ CX_VOID *ContextPtr
)
{
    NTSTATUS status;
    HV_INTRO_MODULE_INTERFACE *introModuleInterface;
    LD_NAPOCA_MODULE *dll;

    if (Info == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (ContextPtr == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    LOG("Done - Data VA: 0x%016llx\n", Info->VaInfo.Data);

    introModuleInterface = (HV_INTRO_MODULE_INTERFACE*)ContextPtr;

    LOG("Intro interface: Base=%p, size=%d, introModuleInterface->IntInit=%p\n",
        introModuleInterface->ImageBase, introModuleInterface->Size, introModuleInterface->IntInit);

    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_INTRO_CORE, &dll);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }

    // map the buffer to its proper image base
    if (IoGetPerCpuPhase() < IO_CPU_ROOT_CYCLE)
    {
        status = MmMap(&gHvMm, (MM_UNALIGNED_VA)introModuleInterface->ImageBase, Info->DataPa, NULL, NULL, 0, NULL, introModuleInterface->Size, TAG_INTRO_MOD, MM_RIGHTS_RWX, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmMap", status);
            goto cleanup;
        }
    }
    else
    {
        PINTRO_CONTROL_MODULE_DATA icmd = (PINTRO_CONTROL_MODULE_DATA)Info->VaInfo.CustomData;

        // if we did not load a new module - leave the old one
        if (Info->VaInfo.Data)
        {
            // unchain / destroy the mappings of the old module
            VOID *tmp = (VOID*)introModuleInterface->ImageBase;
            status = MmFree(&gHvMm, TRUE, TRUE, TAG_INTRO_MOD, MM_GUARD_NONE, (MM_UNALIGNED_VA*)&tmp);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmFree", status);
                MEM_PAGE_COUNT pageCount = PAGE_COUNT(NULL, Info->VaInfo.DataSize);

                LOG("Manual free address %p and 0x%x pages\n", introModuleInterface->ImageBase, pageCount);

                status = TasWalkPagesEx(gHvMm.Tas,
                                (MEM_ALIGNED_VA)introModuleInterface->ImageBase,
                                pageCount,
                                gTasUnmapSetProps, gTasUnmapClearProps, gTasUnmapLackProps, gTasUnmapLackProps,
                                NULL, NULL, 0, NULL, &pageCount, NULL);
                if (!SUCCESS(status)) LOG_FUNC_FAIL("TasWalkPagesEx", status);
                else
                {
                        status = HvaInvalidateTlbRange(
                            (VOID *)introModuleInterface->ImageBase,
                            pageCount,
                            TRUE,
                            FALSE
                        );
                        if (!SUCCESS(status)) LOG_FUNC_FAIL("HvaInvalidateTlbRange", status);
                }
                // continue
            }

            // map the new introcore buffer to its final address (image base) (by translating the data buffer to the PAs backing it up)
            MM_GET_HPA_FOR_HVA_CALLBACK_CONTEXT ctx = { .Mm = &gHvMm };
            status = MmMap(&gHvMm, (MM_UNALIGNED_VA) introModuleInterface->ImageBase, 0, NULL, MmGetHpaForHvaCallback, PAGE_BASE_VA((SIZE_T)Info->VaInfo.Data), &ctx, Info->VaInfo.DataSize, TAG_INTRO_MOD, MM_RIGHTS_RWX, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmMap", status);
                goto cleanup;
            }

            //
            // Load the new introcore (since it's an update, it won't load the new protected guest again (already loaded))
            //
            LOG("Init new introcore\n");
            status = NapIntFullInit(introModuleInterface, FALSE);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("NapIntFullInit", status);
                goto cleanup;
            }
            LOG("New intro is now initialized!\n");
        }

        if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_VERBOSITY) CfgFeaturesIntrospectionVerbosity = icmd->ControlData.Verbosity;

        LOG("Set intro log verbosity level\n");
        status = NapIntUpdateIntrospectionVerbosityLogs(gHypervisorGlobalData.Guest[0], CfgFeaturesIntrospectionVerbosity);
        if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntUpdateIntrospectionVerbosityLogs", status);

        if (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_OPTIONS) CfgFeaturesIntrospectionOptions = icmd->ControlData.Options;

        // apply the operation regardless of new or old module
        if (icmd->ControlData.Enable && (icmd->ControlFieldsToApply & FLAG_INTRO_CONTROL_STATE))
        {
            LOG("Enable new introcore\n");
            status = _HandleControlMemoryIntrospection(gHypervisorGlobalData.Guest[0], TRUE, FALSE, CfgFeaturesIntrospectionOptions);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("_HandleControlMemoryIntrospection", status);
                goto cleanup;
            }
        }
        // else - the engine should be stopped already
    }

    if (Info->VaInfo.Data)
    {
        // update the module to reflect its image base and make sure it's kept mapped across cr3 changes
        status = LdSetModule(gBootModules, LD_MAX_MODULES, LD_MODID_INTRO_CORE, introModuleInterface->ImageBase, dll->Pa, dll->Size, dll->Flags | LD_MODFLAG_PERMANENT);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("LdSetModule", status);
            goto cleanup;
        }

        gIntroModuleInterface = *introModuleInterface;
    }

    if (gIntroModuleInterface.IntVersion)
    {
        Info->VaInfo.High = gIntroModuleInterface.IntVersion->VersionInfo.Major;
        Info->VaInfo.Low = gIntroModuleInterface.IntVersion->VersionInfo.Minor;
        Info->VaInfo.Revision = gIntroModuleInterface.IntVersion->VersionInfo.Revision;
        Info->VaInfo.Build = gIntroModuleInterface.IntVersion->VersionInfo.Build;
    }
    else memset(&Info->VaInfo, 0, sizeof(Info->VaInfo));

    status = CX_STATUS_SUCCESS;
cleanup:

    if (!SUCCESS(status))
    {
        CX_STATUS cleanUpStatus = _HvCleanupHvIntroData(NULL, FALSE);
        if (!SUCCESS(cleanUpStatus))
        {
            LOG_FUNC_FAIL("_HvCleanupHvIntroData", cleanUpStatus);
        }
    }

    return status;
}

///
/// @brief        Init callback function for Introspection module update, it is called before anything else during the update of the module.
///
/// @param[in]    OldInfo                          #UPD_HV_INFO structure describing the old Introspection module, optional
/// @param[in]    NewInfo                          #UPD_HV_INFO structure describing the new Introspection module
/// @param[in, out] ContextPtr                     A pointer, pointing towards the address of #HV_INTRO_MODULE_INTERFACE, if that pointer is NULL, the
///                                                function completes it with an address towards a #HV_INTRO_MODULE_INTERFACE.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - in case NewInfo is and invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - in case ContextPtr is and invalid pointer
/// @returns      CX_STATUS_INVALID_DATA_TYPE      - in case the module id is not of the Introspections
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the new module has no data payload, but also the old module has no data payload
/// @returns      CX_STATUS_INVALID_DATA_VALUE     - in case the new module has an invalid PE signature (DOS or the NT signature)
/// @returns      CX_STATUS_DATA_OUT_OF_RANGE      - in case the new modules size is smaller then the minimum size required by the header structures
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case the new modules size is smaller then the size of image described in the optional headers
/// @returns      CX_STATUS_DATA_NOT_FOUND         - in case the new module misses one of the required introcore module exports or the version definition
/// @returns      CX_STATUS_XXX                    - on other errors. See CheckCompatibility() for possible return codes.
static
CX_STATUS
_HvIntroUpdateInit(
    _In_opt_ UPD_HV_INFO* OldInfo,
    _In_ UPD_HV_INFO *NewInfo,
    _Inout_ CX_VOID **ContextPtr
)
{
    NTSTATUS status;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD index;
    DWORD *names, *functions;
    WORD *ordinals;
    QWORD base;
    QWORD size;
    HV_INTRO_MODULE_INTERFACE *introModuleInterface = NULL;
    INT_VERSION_INFO *introVersion = NULL;

    // validate input data
    if (NewInfo == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    if (ContextPtr == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    if (*ContextPtr == NULL) *ContextPtr = &gIntroUpdatedModuleInterface;

    if (OldInfo != NULL) LOG("Init - Old data VA: 0x%016llx\n", OldInfo->VaInfo.Data);
    LOG("Init - New data VA: 0x%016llx\n", NewInfo->VaInfo.Data);

    if (LD_MODID_INTRO_CORE != NewInfo->VaInfo.ModId) return CX_STATUS_INVALID_DATA_TYPE;

    // we did not load a new module, nothing to do here.
    if (!NewInfo->VaInfo.Data)
    {
        if (OldInfo != NULL && OldInfo->VaInfo.Data == NULL)
        {
            ERROR("Unable to perform any operation without a module (not loaded, nor given)\n");
            return CX_STATUS_NOT_INITIALIZED;
        }

        LOG("No new module, nothing to do\n");

        return CX_STATUS_SUCCESS;
    }

    introModuleInterface = *ContextPtr;
    memzero(introModuleInterface, sizeof(*introModuleInterface));

    // parse the headers to find out it's image base
    base = NewInfo->VaInfo.Data;
    size = NewInfo->VaInfo.DataSize;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERROR("invalid LD_MODID_INTRO_CORE PE image (incorrect IMAGE_DOS_SIGNATURE)\n");
        status = CX_STATUS_INVALID_DATA_VALUE;
        goto cleanup;
    }

    if (size < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64))
    {
        ERROR("invalid LD_MODID_INTRO_CORE PE image (incorrect e_lfanew or buffer too small)\n");
        status = CX_STATUS_DATA_OUT_OF_RANGE;
        goto cleanup;
    }

    nt = (IMAGE_NT_HEADERS64 *)(PVOID)(SIZE_T)(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        ERROR("invalid LD_MODID_INTRO_CORE PE image (incorrect IMAGE_NT_SIGNATURE)\n");
        status = CX_STATUS_INVALID_DATA_VALUE;
        goto cleanup;
    }

    if (size < nt->OptionalHeader.SizeOfImage)
    {
        ERROR("invalid LD_MODID_INTRO_CORE PE image (incorrect SizeOfImage or data buffer too small)\n");
        LOG("size=%d vs nt->OptionalHeader.SizeOfImage=%d\n", size, nt->OptionalHeader.SizeOfImage);
        status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    // get the exports
    if ((nt->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT)
        || (0 == nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
        || (0 == nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        )
    {
        ERROR("invalid LD_MODID_INTRO_CORE PE image (missing or incorrect exports)\n");
        status = CX_STATUS_INVALID_DATA_VALUE;
        goto cleanup;
    }
    exp = (IMAGE_EXPORT_DIRECTORY*)(VOID*)(SIZE_T)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD*)(VOID*)(SIZE_T)(base + exp->AddressOfNames);
    ordinals = (WORD*)(VOID*)(SIZE_T)(base + exp->AddressOfNameOrdinals);
    functions = (DWORD*)(VOID*)(SIZE_T)(base + exp->AddressOfFunctions);

    introModuleInterface->ImageBase = nt->OptionalHeader.ImageBase;
    introModuleInterface->Size = (DWORD)size;

    for (index = 0; index < exp->NumberOfNames; index++)
    {
        if (0 == strncmp((char *)(VOID*)(SIZE_T)(base + names[index]), "IntPreinit", sizeof("IntPreinit")))
        {
            if (ordinals[index] < exp->NumberOfFunctions)
            {
                introModuleInterface->IntPreinit = (PFUNC_IntPreinit)(SIZE_T)(nt->OptionalHeader.ImageBase + functions[ordinals[index]]);
                LOG("Found IntPreinit at %p\n", introModuleInterface->IntPreinit);
            }
        }
        else if (0 == strncmp((char *)(VOID*)(SIZE_T)(base + names[index]), "IntInit", sizeof("IntInit")))
        {
            if (ordinals[index] < exp->NumberOfFunctions)
            {
                introModuleInterface->IntInit = (PFUNC_IntInit)(SIZE_T)(nt->OptionalHeader.ImageBase + functions[ordinals[index]]);
                LOG("Found IntInit at %p\n", introModuleInterface->IntInit);
            }
        }
        else if (0 == strncmp((char *)(VOID*)(SIZE_T)(base + names[index]), "IntUninit", sizeof("IntUninit")))
        {
            if (ordinals[index] < exp->NumberOfFunctions)
            {
                introModuleInterface->IntUninit = (PFUNC_IntUninit)(SIZE_T)(nt->OptionalHeader.ImageBase + functions[ordinals[index]]);
                LOG("Found IntUninit at %p\n", introModuleInterface->IntUninit);
            }
        }
        else if (0 == strncmp((char *)(VOID*)(SIZE_T)(base + names[index]), "IntHviVersion", sizeof("IntHviVersion")))
        {
            if (ordinals[index] < exp->NumberOfFunctions)
            {
                introVersion = (PINT_VERSION_INFO)(SIZE_T)(base + functions[ordinals[index]]);
                introModuleInterface->IntVersion = (PINT_VERSION_INFO)(SIZE_T)(nt->OptionalHeader.ImageBase + functions[ordinals[index]]);
                LOG("Found IntVersion at %p\n", introModuleInterface->IntVersion);
            }
        }
        else
        {
            LOG("Orphan export: %s\n", (char *)(VOID*)(SIZE_T)(base + names[index]));
        }
    }

    // validate that we have ALL the required exports
    if (
        (introModuleInterface->IntInit == NULL) ||
        (introModuleInterface->IntPreinit == NULL) ||
        (introModuleInterface->IntUninit == NULL) ||
        (introModuleInterface->IntVersion == NULL)
        )
    {
        ERROR("Not all required introcore module exports were found\n");
        status = CX_STATUS_DATA_NOT_FOUND;
        goto cleanup;
    }

    // validate that we have intro Version
    if (!introVersion)
    {
        ERROR("Introspection version not found!\n");
        status = CX_STATUS_DATA_NOT_FOUND;
        goto cleanup;
    }

    NAPOCA_VERSION supported = { 0 };
    NAPOCA_VERSION current = { 0 };

    supported.High = INTRO_MIN_SUPPORTED_MAJOR;
    supported.Low = INTRO_MIN_SUPPORTED_MINOR;

    current.High = introVersion->VersionInfo.Major;
    current.Low = introVersion->VersionInfo.Minor;

    LOG("Checking introcore version. Minimum supported is %d.%d\n", INTRO_MIN_SUPPORTED_MAJOR, INTRO_MIN_SUPPORTED_MINOR);
    status = CheckCompatibility(&current, &supported);
    if (!NT_SUCCESS(status))
    {
        ERROR("Unsupported Introspection version: %d.%d.%d.%d! Introspection will not be initialized!\n",
            introVersion->VersionInfo.Major, introVersion->VersionInfo.Minor,
            introVersion->VersionInfo.Revision, introVersion->VersionInfo.Build);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    if (!SUCCESS(status))
    {
        //if we had any fail in this function it means that we won't have introspection, so we must NULL all the functions
        if (introModuleInterface != NULL) memzero(introModuleInterface, sizeof(*introModuleInterface));
    }

    return status;
}

///
/// @brief        Dummy Init callback function for module updates which require no special module initialization.
///
/// @param[in]    OldInfo                          Unreferenced, specified only to keep the callback interface compatibility
/// @param[in]    NewInfo                          Unreferenced, specified only to keep the callback interface compatibility
/// @param[in, out] ContextPtr                     Unreferenced, specified only to keep the callback interface compatibility
///
/// @returns      CX_STATUS_SUCCESS                - always
///
static
CX_STATUS
_HvNewModuleInit(
    _In_opt_ UPD_HV_INFO* OldInfo,
    _In_ UPD_HV_INFO* NewInfo,
    _Inout_ CX_VOID **ContextPtr
)
{
    UNREFERENCED_PARAMETER((NewInfo, OldInfo, ContextPtr));

    return CX_STATUS_SUCCESS;
}

///
/// @brief        Un-Init callback function for module updates, it is called after the module was successfully updated with the new data,
///               can be used to any module that has no special Initialization, nor some special un-init needs.
///
/// @param[in]    OldInfo                          #UPD_HV_INFO structure describing the old module, not used as it is not completed if there is no Init
///                                                callback, so it is safer just to query the actual module (the old one).
/// @param[in]    NewInfo                          #UPD_HV_INFO structure describing the new module
/// @param[in]    ContextPtr                       Unreferenced, specified only to keep the callback interface compatibility
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See LdGetModule() or HpFreeAndNullWithTag() for possible return codes.
///
static
CX_STATUS
_HvOldModuleUninit(
    _In_ UPD_HV_INFO *OldInfo,
    _In_ UPD_HV_INFO *NewInfo,
    _In_opt_ CX_VOID *ContextPtr
)
{
    NTSTATUS status;
    LD_NAPOCA_MODULE *module;


    UNREFERENCED_PARAMETER(ContextPtr);
    UNREFERENCED_PARAMETER(OldInfo); // not completed if there isn't an Init callback also for the module update

    status = LdGetModule(gBootModules, LD_MAX_MODULES, NewInfo->VaInfo.ModId, &module);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }

    LOG("Uninit - Old data VA: 0x%016llx\n", module->Va);

    // if we did not load a new module don't uninitialize the old one
    if (NewInfo->VaInfo.Data && module->Va)
    {
        // Because the first buffer is allocated by the loader we need
        // to check if we actually need to free the address through the Heap
        if (HpIsValidHeapAddress((VOID*)module->Va))
        {
            status = HpFreeAndNullWithTag((VOID**)&module->Va, TAG_MODULE);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("HpFreeAndNullWithTag", status);
                goto cleanup;
            }
            else LOG("Freed successfully old data buffer!\n");
        }
        else LOG("OldInfo->VaInfo.Data is not a valid heap address!\n");
    }
    else ERROR("Module update is with a NULL module data buffer\n");

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

///
/// @brief        Done callback function for Introspection Exceptions module update, it is called after the update is committed
///               (and the old one was un-inited and freed). Calls the active introspection engine to pass the Exceptions version.
///
/// @param[in]    Info                             #UPD_HV_INFO structure describing the exceptions module which was updated successfully
/// @param[in]    ContextPtr                       Unreferenced, specified only to keep the callback interface compatibility
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See NapIntUpdateExceptions() for possible return codes.
///
static
NTSTATUS
_HvIntroExceptionsUpdateDone(
    _In_ UPD_HV_INFO *Info,
    _In_ CX_VOID *ContextPtr)
{
    NTSTATUS status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    UNREFERENCED_PARAMETER(ContextPtr);

    status = NapIntUpdateExceptions(HvGetCurrentVcpu()->Guest, (BYTE*)Info->VaInfo.Data, Info->VaInfo.DataSize, 0);
    if (NT_SUCCESS(status))
    {
        Info->VaInfo.High = Info->VaInfo.Low = Info->VaInfo.Revision = Info->VaInfo.Build = 0;
        gHypervisorGlobalData.Introspection.GlueIface.GetExceptionsVersion(HvGetCurrentVcpu()->Guest, (WORD*)&Info->VaInfo.High, (WORD*)&Info->VaInfo.Low, &Info->VaInfo.Build);
    }

    return status;
}

///
/// @brief        Done callback function for Introspection Live Update module update, it is called after the update is committed
///               (and the old one was un-inited and freed). Calls the active introspection engine to pass the new live-update payload
///               if the engine is running, otherwise starts tries to start the engine to instrospect the Guest with the new support.
///
/// @param[in]    Info                             #UPD_HV_INFO structure describing the live-update module which was updated successfully
/// @param[in]    ContextPtr                       Unreferenced, specified only to keep the callback interface compatibility
///
/// @returns      CX_STATUS_SUCCESS                - always
///
static
NTSTATUS
_HvIntroLiveUpdateDone(
    _In_ UPD_HV_INFO *Info,
    _In_ CX_VOID *ContextPtr)
{
    NTSTATUS status;
    VCPU* vcpu = HvGetCurrentVcpu();

    UNREFERENCED_PARAMETER(ContextPtr);

    // update cached values in gHyperVisorGlobalData
    gHypervisorGlobalData.Introspection.IntroUpdatesVa = Info->VaInfo.Data;
    gHypervisorGlobalData.Introspection.IntroUpdatesSize = Info->VaInfo.DataSize;

    if (vcpu->Guest->Intro.IntrospectionEnabled)
    {
        status = NapIntUpdateSupport(vcpu->Guest, (BYTE*)Info->VaInfo.Data, Info->VaInfo.DataSize);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("NapIntUpdateSupport", status);
        }
        else
        {
            Info->VaInfo.High = Info->VaInfo.Low = Info->VaInfo.Revision = Info->VaInfo.Build = 0;

            // ignore status as to not overwrite the success of update
            NapIntGetSupportVersion(vcpu->Guest, &Info->VaInfo.High, &Info->VaInfo.Low, &Info->VaInfo.Build);
            INFO("Intro Live Update(CAMI) module was updated to version: %u.%u.%u\n",
                Info->VaInfo.High, Info->VaInfo.Low, Info->VaInfo.Build);
        }
    }
    else if (!vcpu->Guest->Intro.IntrospectionEnabled && CfgFeaturesIntrospectionEnabled)
    {
        if (vcpu->Guest->Intro.IntroReportedErrorStates & INTRO_OS_COMPATIBILITY_ERROR_STATES)
        {
            // reset error state
            vcpu->Guest->Intro.IntroReportedErrorStates = 0;

            // try to start introspection engine if it is not enabled, maybe with the update it supports now the OS
            status = NapIntNotifyAboutNewGuest(
                vcpu->Guest, CfgFeaturesIntrospectionOptions,
                (BYTE*)Info->VaInfo.Data,
                Info->VaInfo.DataSize
            );
            if (!NT_SUCCESS(status)) ERROR("NapIntNotifyAboutNewGuest failed: 0x%08x\n", status);
            else vcpu->Guest->Intro.IntrospectionEnabled = TRUE;
        }
        else
        {
            ERROR("Introspection problem can't be solved by live update!\n");
            status = CX_STATUS_NOT_INITIALIZED;
        }
    }
    else
    {
        status = CX_STATUS_NOT_INITIALIZED;
        ERROR("Intro module is not set... We cannot update intro_live_update.bin... \n");
    }

    // enforce SUCCESS, as CAMI module update was with SUCCESS, intro error is returned in a separate callback
    status = CX_STATUS_SUCCESS;

    return status;
}

///
/// @brief        Gets the module described by id and in case of the Introspection Exceptions and Introspection Live-Updates module it caches
///               in the global data of the hypervisor to avoid future queries.
///
/// @param[out]   Module                           The address to the #LD_NAPOCA_MODULE structure, which describes the module requested by the id.
/// @param[in]    DllModId                         The module id
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - on errors. See _HvSetupModule() for possible return codes.
static
NTSTATUS
_HvSetupModule(
    _Inout_ LD_NAPOCA_MODULE **Module,
    _In_    DWORD              DllModId
)
{
    NTSTATUS status;

    status = LdGetModule(gBootModules, LD_MAX_MODULES, DllModId, Module);
    if (!SUCCESS(status))
    {
        ERROR("LdGetModule failed with %s for module[%d] = %s\n", NtStatusToString(status), DllModId, LdGetModuleName(DllModId));
        goto cleanup;
    }

    //
    // Save the data of the exceptions' module
    //
    if (DllModId == LD_MODID_INTRO_EXCEPTIONS)
    {
        gHypervisorGlobalData.Introspection.ExceptionsUpdateVa = (*Module)->Va;
        gHypervisorGlobalData.Introspection.ExceptionsUpdateSize = (*Module)->Size;
    }

    //
    // Save/cache the data of the intro_live_update module (CAMI)
    //
    if (DllModId == LD_MODID_INTRO_LIVE_UPDATE)
    {
        gHypervisorGlobalData.Introspection.IntroUpdatesVa = (*Module)->Va;
        gHypervisorGlobalData.Introspection.IntroUpdatesSize = (*Module)->Size;
    }

cleanup:
    return status;
}

NTSTATUS
HvSetupIntro(
    void
)
{
    NTSTATUS status;
    UPD_HV_INFO update = { 0 };
    LD_NAPOCA_MODULE *dll = NULL;
    LD_NAPOCA_MODULE *exceptions = NULL;
    LD_NAPOCA_MODULE *liveUpdate = NULL;
    PVOID context = NULL;

    // Validate the exception module
    status = _HvSetupModule(&exceptions, LD_MODID_INTRO_EXCEPTIONS);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HvSetupModule", status);
        goto cleanup;
    }

    // Validate introcore
    status = _HvSetupModule(&dll, LD_MODID_INTRO_CORE);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HvSetupModule", status);
        goto cleanup;
    }

    // Validate intro-live-update module
    status = _HvSetupModule(&liveUpdate, LD_MODID_INTRO_LIVE_UPDATE);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HvSetupModule", status);
        goto cleanup;
    }

    // prepare an update data structure for signaling the init
    update.DataPa = dll->Pa;
    update.VaInfo.Data = dll->Va;
    update.VaInfo.DataSize = dll->Size;
    update.VaInfo.ModId = LD_MODID_INTRO_CORE;

    // set up update callbacks for intro related modules

    status = UpdSetCallbacks(LD_MODID_INTRO_CORE, _HvIntroUpdateInit, _HvIntroUpdateUninit, _HvIntroUpdateDone);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("UpdSetCallbacks", status);
        goto cleanup;
    }

    status = UpdSetCallbacks(LD_MODID_INTRO_EXCEPTIONS, _HvNewModuleInit, _HvOldModuleUninit, _HvIntroExceptionsUpdateDone);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("UpdSetCallbacks", status);
        goto cleanup;
    }

    status = UpdSetCallbacks(LD_MODID_INTRO_LIVE_UPDATE, _HvNewModuleInit, _HvOldModuleUninit, _HvIntroLiveUpdateDone);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("UpdSetCallbacks", status);
        goto cleanup;
    }

    // run the init callback manually
    context = &gIntroModuleInterface;
    status = _HvIntroUpdateInit(NULL, &update, &context);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HvIntroUpdateInit", status);
        goto cleanup;
    }

    // we're done, run the callback
    status = _HvIntroUpdateDone(&update, context);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_HvIntroUpdateDone", status);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    if (!SUCCESS(status))
    {
        // If any of these failed, then we don't have any introspection
        // Everything must be nulled so that we will know we don't have a valid intro
        memzero(&gBootModules[LD_MODID_INTRO_CORE], sizeof(gBootModules[LD_MODID_INTRO_CORE]));
    }
    return status;
}

NTSTATUS HvGetLoadedHviVersion(
    _Out_ INT_VERSION_INFO* Version
)
{
    if (Version == NULL)
    {
        ERROR("Invalid version (Version == NULL)\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }
    if (gIntroModuleInterface.IntVersion == NULL)
    {
        ERROR("Introspection engine not yet loaded(?)\n");
        return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    }

    Version->Raw = gIntroModuleInterface.IntVersion->Raw;

    return CX_STATUS_SUCCESS;
}

HV_INTRO_MODULE_INTERFACE* HvGetCurrentIntroModuleInterface(
    VOID
)
{
    return &gIntroModuleInterface;
}

///@}