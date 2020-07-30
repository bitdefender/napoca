/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _WINGUESTDLL_H_
#define _WINGUESTDLL_H_

#include "dacia_types.h"

#ifdef DLL_EXPORTS
#define WINGUEST_DLL_API __declspec(dllexport)
#else
#define WINGUEST_DLL_API __declspec(dllimport)
#endif

#define WINGUEST_CALLING_CONV    __cdecl

//
// function definitions
//

#ifdef __cplusplus
extern "C"
{
#endif

/**
@brief Main initialization function for user mode library
@ingroup integration

This function performs global initialization steps for the user mode library. It must be called before any other user mode
functions that are exposed by this module. It is responsible for allocating any globaly needed resources and perform setup steps
that other functions rely upon.

@remark WinguestResetHvConfiguration() function may be called without  initalizing the user mode library by calling WinguestInitialize().

@return STATUS_SUCCESS - initialization completed successfully
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestInitialize(
    void
    );

/**
 * @brief Main un-initialization function for user mode library
 * @ingroup integration
 *
 * This function performs global un-initialization steps for the user mode library. No other user mode exposed functions should be called
 * after this one. It is responsible for freeing any globaly needed resources and perform other cleanup steps.
 * After a call to this function, the client application must perform a call to WinguestInitialize() function and examine the return of that function.
 *
 * @return STATUS_SUCCESS - initialization completed successfully
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestUninitialize(
    void
    );

/**
 * @brief This is an emergency routine that attempts to disable and remove the hypervisor configuration in case problems are encountered.
 * @ingroup integration
 *
 * This api tries to perform a complete removal of hypervisor start-up binaries and firmware variables if they cannot be remove by standard means.
 * It performs the cleanup steps even if the kernel mode components cannot be found. It has no dependencies and does not need WinguestInitialize() to be called beforehand
 *
 * @return STATUS_SUCCESS - initialization completed successfully
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestResetHvConfiguration(
    void
    );

#ifdef __cplusplus
}
#endif
//
// function definitions end
//

typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestInitialize)(
    void
    );


typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestUninitialize)(
    void
    );

typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestResetHvConfiguration)(
    void
    );

//
// callback definitions
//

/// @defgroup int_callbacks Integration callbacks
/// @ingroup integration
/// @{
/**
 * @brief These represent the possible callback types that can be registered.
*/
typedef enum
{
    wgCallbackInvalid = 0,          /**< Invalid callback type */
    wgCallbackIntroError,           /**< Indicates that the callback to be registered is to be used to report error conditions as they are reported by hvi engine*/
    wgCallbackIntroAlert,
    wgCallbackIncompatibleHvConfig, /**< Indicates that the callback to be registered is to be used to report hw/sw changes that make current platform incompatible with the hypervisor*/
    wgCallbackResumeComplete,       /**< Indicates that the callback to be registered is to be used to notify that a transition (power state change) is completed and the um/km/hv is ready to receive configuration data*/
}WINGUEST_CALLBACK_ID;

/**
 * @brief The "introspection error callback" should be set by the 3rd party application, to be called from WINGUESTDLL when DACIA detects an introspection error. This callback can be set using WinguestRegisterCallback api.
 *
 * @param Type - the possible error types
 * @param ErrorData - pointer to a structure coresponding to Type parameter
 * @param Context - context pointer from the 3rd party application
 *
 * @return The callback should always return STATUS_SUCCESS.
 *
 */
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PWINGUEST_INTROSPECTION_ERROR_CALLBACK) (
    _In_ QWORD Type,
    _In_ PVOID ErrorData,
    _In_ PVOID Context
    );


/**
 *
 * @brief The "introspection alert callback" should be set by the 3rd party application, to be called from WINGUESTDLL when DACIA detects a certain event. This callback can be set using WinguestRegisterCallback api.
 *
 * @param Type - the possible alert types
 * @param AlertData - pointer to a structure coresponding to Type parameter
 * @param Context - context pointer from the 3rd party application
 *
 * @return The callback should always return STATUS_SUCCESS.
 */
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PWINGUEST_INTROSPECTION_ALERT_CALLBACK) (
    _In_ QWORD Type,
    _In_ PVOID AlertData,
    _In_ PVOID Context
    );

/**
 *
 * @brief The "incompatible load mode callback" should be set by the 3rd party application, to be called from WINGUESTDLL if the current load mode is not supported anymore. This callback can be set using WinguestRegisterCallback api.
 *
 * @param MissingFeatures - a pointer to LOAD_MODE_MISSING_FEATURES structure, where are specified the missing features requested by current load mode
 * @param Context - context pointer from 3rd party application
 *
 * @return The callback should always return STATUS_SUCCESS.
 */
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PWINGUEST_INCOMPATIBLE_HV_CONFIGURATION_CALLBACK) (
    _In_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures,
    _In_ PVOID Context
    );

/**
 *
 * @brief This callback is called when the computer has resumed from hibernation and the hypervisor underwent a full reboot. Therefore settings that are not permanent need to be reaplied. (protected processes, etc).
 *
 * @param Context - context pointer from 3rd party application
 *
 * @return The callback should always return STATUS_SUCCESS.
 */
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PWINGUEST_VOLATILE_SETTINGS_REQUEST_CALLBACK) (
    _In_ PVOID Context
    );

typedef union _WINGUEST_CALLBACK
{
    PWINGUEST_INTROSPECTION_ERROR_CALLBACK IntrospectionErrorCallback;
    PWINGUEST_INTROSPECTION_ALERT_CALLBACK IntrospectionAlertCallback;
    PWINGUEST_INCOMPATIBLE_HV_CONFIGURATION_CALLBACK IncompatCallback;
    PWINGUEST_VOLATILE_SETTINGS_REQUEST_CALLBACK VolatileSettingsRequestCallback;
}WINGUEST_CALLBACK;
/// @}

#endif //_WINGUESTDLL_H_
