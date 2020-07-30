/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introspection
///@{

/** @file introengine.c
*   @brief INTROENGINE - hypervisor introspection initialization.
*
*/

#include "napoca.h"
#include "common/kernel/napoca_compatibility.h"
#include "kernel/kernel.h"
#include "introstatus.h"
#include "introspection/introengine.h"
#include "introspection/intronapoca.h"
#include "introspection/intromodule.h"
#include "guests/intro.h"
#include "common/boot/cpu_features.h"
#include "version.h"
#include "common/kernel/napoca_version.h"

///
/// @brief        Checks for minimum Introcore version required by Napoca
///
/// @param[in]    IntroModuleCallbacks             The #HV_INTRO_MODULE_INTERFACE containing the version of the Introcore
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case the Introspection version is not compatible/unsupported or the version is unknown
/// @returns      CX_STATUS_XXX                    - on errors. See _HvSetupModule() for possible return codes.
///
/// @remark       IMPORTANT: Must be called before IntInit to ensure compatibility between Napoca and Introcore
///
static
NTSTATUS
_NapIntVersionCompatible(
    _In_ HV_INTRO_MODULE_INTERFACE *IntroModuleCallbacks
)
{
    DWORD introMajor = 0;
    DWORD introMinor = 0;
    DWORD introRevision = 0;
    DWORD introBuildNumber = 0;
    NTSTATUS status;

    LOG("Checking Introcore compatibility with Napoca. "
        "Minimum supported version: %d.%d\n", INTRO_MIN_SUPPORTED_MAJOR, INTRO_MIN_SUPPORTED_MINOR);

    if (!IntroModuleCallbacks->IntVersion)
    {
        LOG("Hvi version info not available... assuming incompatible!\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    NAPOCA_VERSION supported = { 0 };
    NAPOCA_VERSION current = { 0 };

    supported.High = INTRO_MIN_SUPPORTED_MAJOR;
    supported.Low = INTRO_MIN_SUPPORTED_MINOR;

    current.High = IntroModuleCallbacks->IntVersion->VersionInfo.Major;
    current.Low = IntroModuleCallbacks->IntVersion->VersionInfo.Minor;

    status = CheckCompatibility(&current, &supported);
    if (!NT_SUCCESS(status))
    {
        WARNING("[WARNING] Unsupported Introspection version: %d.%d.%d.%d! Introspection will not be initialized!\n",
            introMajor, introMinor, introRevision, introBuildNumber);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    return CX_STATUS_SUCCESS;
}

///
/// @brief        Calls Introspections Init callback, to initialize the Introcore and the glue interfaces
///
/// @param[in]    IntroModuleCallbacks             A pointer to a #HV_INTRO_MODULE_INTERFACE containing the introcores' Init callback
/// @param[in]    GlueIface                        The address of the GLUE_IFACE structure, interface for integrating the introspection.
/// @param[in]    UpperIface                       The address of the UPPER_IFACE structure, interface for offering low level functionality
///                                                support for the Introspection engine.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - in case the Introspection Init callback was successful, but the needed APIs were not populated
/// @returns      CX_STATUS_XXX                    - on errors. See PFUNC_IntInit for possible return codes.
///
static
NTSTATUS
_NapIntInitIntrocore(
    _In_ HV_INTRO_MODULE_INTERFACE*  IntroModuleCallbacks,
    _In_ PGLUE_IFACE                 GlueIface,
    _In_ PUPPER_IFACE                UpperIface
    )
{
    NTSTATUS status;

    status = IntroModuleCallbacks->IntInit(GlueIface, UpperIface);
    if (!NT_SUCCESS(status))
    {
        HvPrint("[CPU %d] ERROR: IntInit failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
        return status;
    }

    if (gHypervisorGlobalData.Introspection.GlueIface.NewGuestNotification == NULL || gHypervisorGlobalData.Introspection.GlueIface.DisableIntro == NULL)
    {
        HvPrint("[CPU %d] ERROR: IntInit failed, NewGuestNotification/DisableIntro was not populated by IntInit as expected.\n", HvGetCurrentApicId());
        return CX_STATUS_INVALID_INTERNAL_STATE;
    }

    return CX_STATUS_SUCCESS;
}

///
/// @brief        Verifies the minimal export requirements of the Introspection module, in order to be able to use it.
///
/// @param[in]    IntroModuleCallbacks             A pointer to a #HV_INTRO_MODULE_INTERFACE containing the introcores' exported functions
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case the minimal required exports are not present
///
static
NTSTATUS
_NapIntMinReqExports(
    _In_ HV_INTRO_MODULE_INTERFACE*  IntroModuleCallbacks
    )
{
    // Make sure we have all the needed introcore exports
    if (IntroModuleCallbacks->IntPreinit == NULL || IntroModuleCallbacks->IntInit == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    return CX_STATUS_SUCCESS;
}

///
/// @brief        Should be called only when a new protected guest is loaded. It identifies the operating system and starts the memory
///               Introspection engine on the specified guest.
///
/// @param[in]    Guest                            Napoca specific guest-identifier
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case Guest is an invalid pointer
/// @returns      CX_STATUS_XXX                    - on errors. See NapIntNotifyAboutNewGuest() for possible return codes.
///
static
NTSTATUS
_NapIntStartMemoryIntrospection(
    _In_ GUEST* Guest
    )
{
    NTSTATUS status;

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvAcquireRwSpinLockExclusive(&Guest->Intro.IntroCallbacksLock);
    Guest->Intro.RawIntroEptCallback = NULL;
    Guest->Intro.RawIntroMsrCallback = NULL;
    Guest->Intro.RawIntroCrCallback = NULL;
    Guest->Intro.RawIntroDescriptorTableCallback = NULL;
    Guest->Intro.RawIntroTimerCallback = NULL;
    Guest->Intro.RawIntroCallCallback = NULL;
    Guest->Intro.RawIntroXcrCallback = NULL;
    HvReleaseRwSpinLockExclusive(&Guest->Intro.IntroCallbacksLock);

    status = NapIntUpdateIntrospectionVerbosityLogs(Guest, CfgFeaturesIntrospectionVerbosity);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("NapIntUpdateIntrospectionVerbosityLogs", status);

    // Identify the operating system and start the memory introspection engine for this guest
    status = NapIntNotifyAboutNewGuest(Guest, CfgFeaturesIntrospectionOptions, (BYTE*)gHypervisorGlobalData.Introspection.IntroUpdatesVa, gHypervisorGlobalData.Introspection.IntroUpdatesSize);
    if (!NT_SUCCESS(status))
    {
        ERROR("NapIntNotifyAboutNewGuest failed: %s\n", NtStatusToString(status));
        return status;
    }

    // We can also send the update since the intro engine can accept them
    status = NapIntUpdateExceptions(Guest, (BYTE*)gHypervisorGlobalData.Introspection.ExceptionsUpdateVa, gHypervisorGlobalData.Introspection.ExceptionsUpdateSize, 0);
    if (!NT_SUCCESS(status))
    {
        ERROR("NapIntUpdateExceptions failed, error code: %s\n", NtStatusToString(status));

        // Don't exit with an error! (the HV will unload itself)
        status = CX_STATUS_SUCCESS;
    }

    return status;
}

NTSTATUS
NapIntFullInit(
    _In_ PVOID   IntroModuleCallbacks,
    _In_ BOOLEAN LoadNewProtectedGuest
    )
{
    NTSTATUS status;
    HV_INTRO_MODULE_INTERFACE* introModuleCallbacks = (HV_INTRO_MODULE_INTERFACE*)IntroModuleCallbacks;

    if (!IntroModuleCallbacks) return CX_STATUS_INVALID_PARAMETER_1;

    if (!VmxIsEptExecuteOnlyPagesAvailable())
    {
        WARNING("This cpu does not support EPT Execute only pages! Introspection will not be initialized!\n");
        CfgFeaturesIntrospectionEnabled = 0;
        return CX_STATUS_NOT_SUPPORTED;
    }


    GUEST *guest = HvGetCurrentGuest();

    if (!guest) return CX_STATUS_INVALID_INTERNAL_STATE;

    // Initialize Intro errors to 0, in case Intro will be not supported and support comes later via live update
    guest->Intro.IntroReportedErrorStates = 0;

    // Minimum required exports from Introcore dll
    status = _NapIntMinReqExports(introModuleCallbacks);
    if (!NT_SUCCESS(status))
    {
        ERROR("[ERROR] Not all introcore exports were loaded! Introspection will not be initialized!\n");
        return status;
    }

    // Check first if we have a valid introcore, before initializing interfaces
    status = _NapIntVersionCompatible(introModuleCallbacks);
    if (!NT_SUCCESS(status))
    {
        ERROR("Introspection is incompatible with this Napoca version! Introspection will not be initialized!\n");
        return status;
    }

    // Pre-init must be the first function called before the init function.
    introModuleCallbacks->IntPreinit();

    // Initialize Introspection Glue Interface
    status = IntNapInitGlueInterface(&gHypervisorGlobalData.Introspection.GlueIface, GLUE_IFACE_VERSION_LATEST_SIZE, GLUE_IFACE_VERSION_LATEST);
    if (!NT_SUCCESS(status))
    {
        ERROR("Introspection Glue Interface couldn't be initialized, error code: %s\n", NtStatusToString(status));
        return status;
    }

    // Initialize Introspection Upper Interface
    status = IntNapInitUpperInterface(&gHypervisorGlobalData.Introspection.UpperIface, UPPER_IFACE_VERSION_LATEST_SIZE, UPPER_IFACE_VERSION_LATEST);
    if (!NT_SUCCESS(status))
    {
        ERROR("Introspection Upper Interface couldn't be initialized, error code: %s\n", NtStatusToString(status));
        return status;
    }

    status = _NapIntInitIntrocore(introModuleCallbacks, &gHypervisorGlobalData.Introspection.GlueIface, &gHypervisorGlobalData.Introspection.UpperIface);
    if (!NT_SUCCESS(status))
    {
        ERROR("Failed to initialize introspection engine, error code: %s\n", NtStatusToString(status));
        return status;
    }

    LOG("Introspection default flags: NAPOCA 0x%x, XEN 0x%x. Activation flags are: 0x%llx\n",
        INTRO_OPT_DEFAULT_OPTIONS, INTRO_OPT_DEFAULT_XEN_OPTIONS, CfgFeaturesIntrospectionOptions);


    if (LoadNewProtectedGuest)
    {
        status = _NapIntStartMemoryIntrospection(guest);
        if (!NT_SUCCESS(status))
        {
            ERROR("Couldn't load new protected guest, error code: %s\n", NtStatusToString(status));
            return status;
        }
    }

    //
    // In case of no other failure return, mark this as a success
    //
    return CX_STATUS_SUCCESS;
}

///@}