/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __LIBAPIS_INT_H__
#define __LIBAPIS_INT_H__

#include "dacia_types.h"
#include "winguestdll.h"

#include <mutex>

#define EVENT_TIMER_DEFAULT_GRANULARITY                     10              // every 10 seconds
#define EVENT_TIMER_DEFAULT_FEEDBACK_CLEANUP_GRANULARITY    (10 * 60)       // every 10 minutes
#define EVENT_TIMER_DEFAULT_HV_CONFIGURATION_CHECK_INTERVAL (6 * 60 * 60)   // every 6 h
#define EVENT_TIMER_DEFAULT_INTRO_THROTTLE_HASHMAP_CLEANUP  60              // every 60 seconds

#define EVENT_TAG_HASHMAP_THROTTLE_CLEANUP                  "hashmap_throttle_cleanup"

typedef struct _UM_CALLBACKS
{
    PWINGUEST_INTROSPECTION_ERROR_CALLBACK IntrospectionErrorCallback;
    PWINGUEST_INTROSPECTION_ALERT_CALLBACK IntrospectionAlertCallback;
    PWINGUEST_INCOMPATIBLE_HV_CONFIGURATION_CALLBACK IncompatibleHvConfigurationCallback;
    PWINGUEST_VOLATILE_SETTINGS_REQUEST_CALLBACK VolatileSettingsRequestCallback;
    /// Add here callbacks
} UM_CALLBACKS, *PUM_CALLBACKS;

typedef struct _UM_CONTEXTS
{
    PVOID IntrospectionErrorCallbackContext;
    PVOID IntrospectionAlertCallbackContext;
    PVOID IncompatibleHvConfigurationContext;
    PVOID VolatileSettingsRequestContex;
}UM_CONTEXTS, *PUM_CONTEXTS;

extern UM_CALLBACKS gCallbacks;
extern UM_CONTEXTS gContexts;
extern std::mutex gCallbacksMutex;

#endif //__LIBAPIS_INT_H__
