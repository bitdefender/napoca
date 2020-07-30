/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introspection
///@{

/** @file intromodule.h
*   @brief INTROMODULE -  NAPOCA hypervisor introspection module related APIs
*
*/

#ifndef _INTROMODULE_H_
#define _INTROMODULE_H_
#include "core.h"

#include "wrappers/cx_winsal.h"
#include "introstatus.h"

#include "glueiface.h"


/// @brief Holds the callback functions not directly part of the GLUEIFACE, but which are extracted from loading and parsing the introcore binary
typedef struct _HV_INTRO_MODULE_INTERFACE
{
    /// Image base of introcore (preferred VA where introcore is loaded in Napoca's virtual address space)
    QWORD                       ImageBase;

    /// Size of introspection module
    DWORD                       Size;

    /// The init function takes two arguments: one is a pointer to an initialized GLUE_IFACE structure, the other is a pointer
    /// to an initialized UPPER_IFACE structure. Initializes the introspection.
    PFUNC_IntInit               IntInit;

    /// The pre-init function takes no arguments. It must be the first function called before the init function.
    PFUNC_IntPreinit            IntPreinit;

    /// The uninit function will uninitialize the introspection engine. This will do all the necessary cleanup, including
    /// disabling protection for all the protected guests. This function can be called even if the protection was
    /// not enabled for any of the guests or even if the protection was enabled for an arbitrary number of guests.
    PFUNC_IntUninit             IntUninit;

    /// Introspection version info
    PINT_VERSION_INFO           IntVersion;
} HV_INTRO_MODULE_INTERFACE;


///
/// @brief Validate introcore image, resolve exports and setup callbacks necessary for supporting on-the-fly updates
///
/// Validates introcore by validating every introcore related module(introcore, intro live-update and exceptions).
/// The signatures are validated and the modules are set up. After that it sets up the necessary callbacks for
/// on-the-fly update of each of the modules. After that runs manually the Introcore UpdateInit in order to initialize
/// the module.
///
/// @returns    CX_STATUS_SUCCESS               - if everything was with success.
/// @returns    OTHER                           - other potential internal STATUS error value raised during HvSetupModule,
///                                             UpdSetCallback or at IntroUpdateInit and IntroUpdateDone (too many types
///                                             of error statuses to enlist here).
///
NTSTATUS
HvSetupIntro(
    void
);

///
/// @brief Retrieves the loaded Introcore module version.
///
/// @param[out] Version     Will contain the Introcore version which is currently loaded on return of the function.
///
/// @returns    CX_STATUS_SUCCESS               - if the version is retrieved with success
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if Version is NULL.
/// @returns    CX_STATUS_UNINITIALIZED_STATUS_VALUE - if the Intro module is not initialized
///
NTSTATUS HvGetLoadedHviVersion(
    _Out_ INT_VERSION_INFO* Version
);

///
/// @brief Retrieves the INTRO_MODULE_INTERFACE used at the initialization of the Intro module.
///
/// @returns    HV_INTRO_MODULE_INTERFACE*      - the address of the INTRO_MODULE_INTERFACE structure.
///
HV_INTRO_MODULE_INTERFACE* HvGetCurrentIntroModuleInterface(
    VOID
);


#endif //_INTROMODULE_H_


///@}