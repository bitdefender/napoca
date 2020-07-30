/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup introspection
///@{

/** @file introengine.h
*   @brief INTROENGINE - hypervisor introspection initialization.
*
*/

#ifndef _INTROENGINE_H
#define _INTROENGINE_H

#include "napoca.h"

///
/// @brief Initializes the memory introspection engine core and the interfaces corresponding to the engine (Glue/Upper Interfaces)
///
/// If LoadNewProtectedGuest is TRUE, memory introspection engine will be started for the primary guest (update cases when it's already loaded),
/// otherwise only the interfaces are set up. Introspection can be started only when the Guest is loaded. FALSE case is applied on on-the-fly
/// updates where there is no necessity in loading a new protected guest if it is already loaded and protected.
///
/// @param[in] IntroModuleCallbacks     A HV_INTRO_MODULE_INTERFACE structure, already initialized with the basic callbacks of the intro module.
/// @param[in] LoadNewProtectedGuest    TRUE if the engine must be started for the primary guest or FALSE if not.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if the CPU doesn't supports EPT execute only pages
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE    - if IntroModuleCallbacks is NULL or is not completed correctly (MinRequirements) or if
///                                                 the current Guest pointer is not valid
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if Introcore version is not compatible or not present.
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE    - if IntInit was successful, but the callbacks NewGuestNotification and DisableIntro were not
///                                                 populated inside the GLUEIFACE structure by introcore
/// @returns    OTHER                               - other NTSTATUS values returned by Intro initialization callbacks or by NewGuestNotifications
///
NTSTATUS
NapIntFullInit(
    _In_ PVOID   IntroModuleCallbacks,
    _In_ BOOLEAN LoadNewProtectedGuest
    );

#endif // _INTROENGINE_H


///@}