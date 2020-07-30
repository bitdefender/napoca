/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _REG_OPTS_H_
#define _REG_OPTS_H_

#define REG_SUBKEY_SYSTEM_PARTITION                     L"SYSTEM\\Setup"                // ! subkey of HKLM
#define REG_VALUE_SYSTEM_PARTITION                      L"SystemPartition"              // REG_SZ

// DACIA key paths
#define REG_SUBKEY_GENERAL_SETTINGS                     L"Software\\DACIA"              // ! subkey of HKLM
#define REG_KEY_SOFTWARE_UM                             L"Software"

/// KERNEL MODE

#define REG_VALUE_REINIT_MAX_CALL_COUNT                 L"ReinitMaxCallCount"
#define REG_VALUE_RESERVE_HVLOG_BUFFER                  L"ReserveHvLogBuffer"

/// USER MODE

// general settings
#define REG_VALUE_EVENT_TIMER_GRANULARITY               L"EventTimerGranularity"        // REG_DWORD    (default value set by winguestdll)
#define REG_VALUE_FEEDBACK_CLEANUP_GRANULARITY          L"FeedbackCleanupInterval"      // REG_DWORD    (default value set by winguestdll)
#define REG_VALUE_HV_CONFIG_CHECK_INTERVAL              L"HvConfigCheckInterval"        // REG_DWORD    (default value set by winguestdll)
#define REG_VALUE_CONFIG_LEGACY_INSTALL_PARTITION       L"ConfigLegacyInstallPartition" // REG_SZ (value set by the legacy configuration code)
#define REG_VALUE_HV_CONFIGURATION                      L"HvConfiguration"
#define REG_VALUE_CHANGES_LIST                          L"ChangeList"                   // REG_BINARY (serialized list of hashes based on installer.cfg entries)

// paths
#define REG_VALUE_SDK_BASE_PATH                         L"SDKBasePath"
#define REG_VALUE_UPDATES_INTRO_PATH                    L"IntroUpdatesPath"
#define REG_VALUE_FEEDBACK_PATH                         L"FeedbackPath"

// other
#define REG_KEY_LOADER_RESERVED_PHYSICAL_MEMORY_MAP     L"\\REGISTRY\\MACHINE\\HARDWARE\\RESOURCEMAP\\System Resources\\Loader Reserved"
#define REG_VALUE_LOADER_RESERVED_MEMORY_MAP            L".Raw"

#define REG_KEY_SERVICES                                L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"
#define REG_SUBKEY_SMBIOS                               L"System\\CurrentControlSet\\services\\mssmbios\\data\\"        // ! subkey of HKLM

#define REG_SUBKEY_WINDOWS_VERSION                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define REG_VALUE_UPDATE_BUILD_REVISION                 L"UBR"

#endif //_REG_OPTS_H_