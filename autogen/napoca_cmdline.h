#ifndef _NAPOCA_CMDLINE_H_
#define _NAPOCA_CMDLINE_H_

#include "userdata.h"
#define CFG_DEBUG_HOOKBAREMINIMUMPCI                     1
#define CFG_DEBUG_INTERCEPT_HWP                          0
#define CFG_DEBUG_OUTPUT_DEBUGGERONLY                    0
#define CFG_DEBUG_OUTPUT_ENABLED                         0
#define CFG_DEBUG_OUTPUT_SERIAL_ENABLED                  0
#define CFG_DEBUG_OUTPUT_VGA_ENABLED                     0
#define CFG_DEBUG_STARTINDEBUGGER                        0
#define CFG_DEBUG_TRACE_ACPI                             0
#define CFG_DEBUG_TRACE_APIC                             0
#define CFG_DEBUG_TRACE_CRASHLOG                         3
#define CFG_DEBUG_TRACE_EMULATOR_ENABLED                 0
#define CFG_DEBUG_TRACE_EMULATOR_UNIQUE                  0
#define CFG_DEBUG_TRACE_GUESTEXCEPTIONS                  0
#define CFG_DEBUG_TRACE_HWP                              0
#define CFG_DEBUG_TRACE_MEMORYMAPS                       0
#define CFG_DEBUG_TRACE_MSIX                             0
#define CFG_DEBUG_TRACE_PCI                              0
#define CFG_DEBUG_TRACE_PCIDEVICE_BUS                    0
#define CFG_DEBUG_TRACE_PCIDEVICE_DEVICE                 0
#define CFG_DEBUG_TRACE_PCIDEVICE_ENABLED                0
#define CFG_DEBUG_TRACE_PCIDEVICE_FUNCTION               0
#define CFG_DEBUG_TRACE_PERIODICSTATS_ENABLED            0
#define CFG_DEBUG_TRACE_PERIODICSTATS_FASTALLOCATORS     0
#define CFG_DEBUG_TRACE_PERIODICSTATS_PERFORMANCE        0
#define CFG_FEATURES_ACTIVATEHWP                         2
#define CFG_FEATURES_HIBERNATEPERSISTANCE                1
#define CFG_FEATURES_HIDEPHYSICALX2APIC                  1
#define CFG_FEATURES_INTROSPECTION_CALLTIMER             1
#define CFG_FEATURES_INTROSPECTION_ENABLED               1
#define CFG_FEATURES_INTROSPECTION_OPTIONS               0x293BFFFFF
#define CFG_FEATURES_INTROSPECTION_VERBOSITY             3
#define CFG_FEATURES_NMIPERFORMANCECOUNTERTICKSPERSECOND 0
#define CFG_FEATURES_UNLOADONERRORS_ENABLED              1
#define CFG_FEATURES_VIRTUALIZATION_ENLIGHT_CPUMANAGEMENT 2
#define CFG_FEATURES_VIRTUALIZATION_ENLIGHT_ENABLED      1
#define CFG_FEATURES_VIRTUALIZATION_ENLIGHT_REFCOUNTER   1
#define CFG_FEATURES_VIRTUALIZATION_ENLIGHT_TSCPAGE      1
#define CFG_FEATURES_VIRTUALIZATION_ENLIGHT_TSCPAGEWORKAROUND 1
#define CFG_FEATURES_VIRTUALIZATION_MONITORGUESTACTIVITYSTATECHANGES 1
#define CFG_FEATURES_VIRTUALIZATION_PREEMPTIONTIMEREXITSPERHOUR 3600
#define CFG_FEATURES_VIRTUALIZATION_SINGLESTEPUSINGLARGEPAGES 1
#define CFG_FEATURES_VIRTUALIZATION_SPP                  1
#define CFG_FEATURES_VIRTUALIZATION_TSC_EXIT             0
#define CFG_FEATURES_VIRTUALIZATION_TSC_OFFSETTING       1
#define CFG_FEATURES_VIRTUALIZATION_VE                   1
#define CFG_FEATURES_VIRTUALIZATION_VMFUNC               1
#define CFG_HACKS_WINHVRREDUCEDENLIGHTENMENT             1


extern UD_NUMBER       CfgDebugHookBareMinimumPci;
extern UD_NUMBER       CfgDebugInterceptHwp;
extern UD_NUMBER       CfgDebugOutputDebuggerOnly;
extern UD_NUMBER       CfgDebugOutputEnabled;
extern UD_NUMBER       CfgDebugOutputSerialEnabled;
extern UD_NUMBER       CfgDebugOutputVgaEnabled;
extern UD_NUMBER       CfgDebugStartInDebugger;
extern UD_NUMBER       CfgDebugTraceAcpi;
extern UD_NUMBER       CfgDebugTraceApic;
extern UD_NUMBER       CfgDebugTraceCrashLog;
extern UD_NUMBER       CfgDebugTraceEmulatorEnabled;
extern UD_NUMBER       CfgDebugTraceEmulatorUnique;
extern UD_NUMBER       CfgDebugTraceGuestExceptions;
extern UD_NUMBER       CfgDebugTraceHwp;
extern UD_NUMBER       CfgDebugTraceMemoryMaps;
extern UD_NUMBER       CfgDebugTraceMsix;
extern UD_NUMBER       CfgDebugTracePci;
extern UD_NUMBER       CfgDebugTracePciDeviceBus;
extern UD_NUMBER       CfgDebugTracePciDeviceDevice;
extern UD_NUMBER       CfgDebugTracePciDeviceEnabled;
extern UD_NUMBER       CfgDebugTracePciDeviceFunction;
extern UD_NUMBER       CfgDebugTracePeriodicStatsEnabled;
extern UD_NUMBER       CfgDebugTracePeriodicStatsFastAllocators;
extern UD_NUMBER       CfgDebugTracePeriodicStatsPerformance;
extern UD_NUMBER       CfgFeaturesActivateHwp;
extern UD_NUMBER       CfgFeaturesHibernatePersistance;
extern UD_NUMBER       CfgFeaturesHidePhysicalX2Apic;
extern UD_NUMBER       CfgFeaturesIntrospectionCallTimer;
extern UD_NUMBER       CfgFeaturesIntrospectionEnabled;
extern UD_NUMBER       CfgFeaturesIntrospectionOptions;
extern UD_NUMBER       CfgFeaturesIntrospectionVerbosity;
extern UD_NUMBER       CfgFeaturesNmiPerformanceCounterTicksPerSecond;
extern UD_NUMBER       CfgFeaturesUnloadOnErrorsEnabled;
extern UD_NUMBER       CfgFeaturesVirtualizationEnlightCpuManagement;
extern UD_NUMBER       CfgFeaturesVirtualizationEnlightEnabled;
extern UD_NUMBER       CfgFeaturesVirtualizationEnlightRefCounter;
extern UD_NUMBER       CfgFeaturesVirtualizationEnlightTscPage;
extern UD_NUMBER       CfgFeaturesVirtualizationEnlightTscPageWorkaround;
extern UD_NUMBER       CfgFeaturesVirtualizationMonitorGuestActivityStateChanges;
extern UD_NUMBER       CfgFeaturesVirtualizationPreemptionTimerExitsPerHour;
extern UD_NUMBER       CfgFeaturesVirtualizationSingleStepUsingLargePages;
extern UD_NUMBER       CfgFeaturesVirtualizationSpp;
extern UD_NUMBER       CfgFeaturesVirtualizationTscExit;
extern UD_NUMBER       CfgFeaturesVirtualizationTscOffsetting;
extern UD_NUMBER       CfgFeaturesVirtualizationVe;
extern UD_NUMBER       CfgFeaturesVirtualizationVmFunc;
extern UD_NUMBER       CfgHacksWinhvrReducedEnlightenment;


typedef enum
{
    _CfgDebugHookBareMinimumPci_                     = 0,
    _CfgDebugInterceptHwp_                           = 1,
    _CfgDebugOutputDebuggerOnly_                     = 2,
    _CfgDebugOutputEnabled_                          = 3,
    _CfgDebugOutputSerialEnabled_                    = 4,
    _CfgDebugOutputVgaEnabled_                       = 5,
    _CfgDebugStartInDebugger_                        = 6,
    _CfgDebugTraceAcpi_                              = 7,
    _CfgDebugTraceApic_                              = 8,
    _CfgDebugTraceCrashLog_                          = 9,
    _CfgDebugTraceEmulatorEnabled_                   = 10,
    _CfgDebugTraceEmulatorUnique_                    = 11,
    _CfgDebugTraceGuestExceptions_                   = 12,
    _CfgDebugTraceHwp_                               = 13,
    _CfgDebugTraceMemoryMaps_                        = 14,
    _CfgDebugTraceMsix_                              = 15,
    _CfgDebugTracePci_                               = 16,
    _CfgDebugTracePciDeviceBus_                      = 17,
    _CfgDebugTracePciDeviceDevice_                   = 18,
    _CfgDebugTracePciDeviceEnabled_                  = 19,
    _CfgDebugTracePciDeviceFunction_                 = 20,
    _CfgDebugTracePeriodicStatsEnabled_              = 21,
    _CfgDebugTracePeriodicStatsFastAllocators_       = 22,
    _CfgDebugTracePeriodicStatsPerformance_          = 23,
    _CfgFeaturesActivateHwp_                         = 24,
    _CfgFeaturesHibernatePersistance_                = 25,
    _CfgFeaturesHidePhysicalX2Apic_                  = 26,
    _CfgFeaturesIntrospectionCallTimer_              = 27,
    _CfgFeaturesIntrospectionEnabled_                = 28,
    _CfgFeaturesIntrospectionOptions_                = 29,
    _CfgFeaturesIntrospectionVerbosity_              = 30,
    _CfgFeaturesNmiPerformanceCounterTicksPerSecond_ = 31,
    _CfgFeaturesUnloadOnErrorsEnabled_               = 32,
    _CfgFeaturesVirtualizationEnlightCpuManagement_  = 33,
    _CfgFeaturesVirtualizationEnlightEnabled_        = 34,
    _CfgFeaturesVirtualizationEnlightRefCounter_     = 35,
    _CfgFeaturesVirtualizationEnlightTscPage_        = 36,
    _CfgFeaturesVirtualizationEnlightTscPageWorkaround_ = 37,
    _CfgFeaturesVirtualizationMonitorGuestActivityStateChanges_ = 38,
    _CfgFeaturesVirtualizationPreemptionTimerExitsPerHour_ = 39,
    _CfgFeaturesVirtualizationSingleStepUsingLargePages_ = 40,
    _CfgFeaturesVirtualizationSpp_                   = 41,
    _CfgFeaturesVirtualizationTscExit_               = 42,
    _CfgFeaturesVirtualizationTscOffsetting_         = 43,
    _CfgFeaturesVirtualizationVe_                    = 44,
    _CfgFeaturesVirtualizationVmFunc_                = 45,
    _CfgHacksWinhvrReducedEnlightenment_             = 46,
} UD_NAME_ORDINALS;


#define UD_VAR_INFO_TABLE \
{\
   {UD_TYPE_NUMBER,          "CfgDebugHookBareMinimumPci",          &CfgDebugHookBareMinimumPci,           sizeof(CfgDebugHookBareMinimumPci),       (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugInterceptHwp",                &CfgDebugInterceptHwp,                 sizeof(CfgDebugInterceptHwp),             (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugOutputDebuggerOnly",          &CfgDebugOutputDebuggerOnly,           sizeof(CfgDebugOutputDebuggerOnly),       (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugOutputEnabled",               &CfgDebugOutputEnabled,                sizeof(CfgDebugOutputEnabled),            (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugOutputSerialEnabled",         &CfgDebugOutputSerialEnabled,          sizeof(CfgDebugOutputSerialEnabled),      (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugOutputVgaEnabled",            &CfgDebugOutputVgaEnabled,             sizeof(CfgDebugOutputVgaEnabled),         (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugStartInDebugger",             &CfgDebugStartInDebugger,              sizeof(CfgDebugStartInDebugger),          (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceAcpi",                   &CfgDebugTraceAcpi,                    sizeof(CfgDebugTraceAcpi),                (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceApic",                   &CfgDebugTraceApic,                    sizeof(CfgDebugTraceApic),                (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceCrashLog",               &CfgDebugTraceCrashLog,                sizeof(CfgDebugTraceCrashLog),            (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceEmulatorEnabled",        &CfgDebugTraceEmulatorEnabled,         sizeof(CfgDebugTraceEmulatorEnabled),     (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceEmulatorUnique",         &CfgDebugTraceEmulatorUnique,          sizeof(CfgDebugTraceEmulatorUnique),      (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceGuestExceptions",        &CfgDebugTraceGuestExceptions,         sizeof(CfgDebugTraceGuestExceptions),     (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceHwp",                    &CfgDebugTraceHwp,                     sizeof(CfgDebugTraceHwp),                 (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceMemoryMaps",             &CfgDebugTraceMemoryMaps,              sizeof(CfgDebugTraceMemoryMaps),          (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTraceMsix",                   &CfgDebugTraceMsix,                    sizeof(CfgDebugTraceMsix),                (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePci",                    &CfgDebugTracePci,                     sizeof(CfgDebugTracePci),                 (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePciDeviceBus",           &CfgDebugTracePciDeviceBus,            sizeof(CfgDebugTracePciDeviceBus),        (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePciDeviceDevice",        &CfgDebugTracePciDeviceDevice,         sizeof(CfgDebugTracePciDeviceDevice),     (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePciDeviceEnabled",       &CfgDebugTracePciDeviceEnabled,        sizeof(CfgDebugTracePciDeviceEnabled),    (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePciDeviceFunction",      &CfgDebugTracePciDeviceFunction,       sizeof(CfgDebugTracePciDeviceFunction),   (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePeriodicStatsEnabled",   &CfgDebugTracePeriodicStatsEnabled,    sizeof(CfgDebugTracePeriodicStatsEnabled), (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePeriodicStatsFastAllocators", &CfgDebugTracePeriodicStatsFastAllocators, sizeof(CfgDebugTracePeriodicStatsFastAllocators), (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgDebugTracePeriodicStatsPerformance", &CfgDebugTracePeriodicStatsPerformance, sizeof(CfgDebugTracePeriodicStatsPerformance), (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesActivateHwp",              &CfgFeaturesActivateHwp,               sizeof(CfgFeaturesActivateHwp),           (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesHibernatePersistance",     &CfgFeaturesHibernatePersistance,      sizeof(CfgFeaturesHibernatePersistance),  (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesHidePhysicalX2Apic",       &CfgFeaturesHidePhysicalX2Apic,        sizeof(CfgFeaturesHidePhysicalX2Apic),    (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesIntrospectionCallTimer",   &CfgFeaturesIntrospectionCallTimer,    sizeof(CfgFeaturesIntrospectionCallTimer), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesIntrospectionEnabled",     &CfgFeaturesIntrospectionEnabled,      sizeof(CfgFeaturesIntrospectionEnabled),  (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesIntrospectionOptions",     &CfgFeaturesIntrospectionOptions,      sizeof(CfgFeaturesIntrospectionOptions),  (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesIntrospectionVerbosity",   &CfgFeaturesIntrospectionVerbosity,    sizeof(CfgFeaturesIntrospectionVerbosity), (RUNTIME)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesNmiPerformanceCounterTicksPerSecond", &CfgFeaturesNmiPerformanceCounterTicksPerSecond, sizeof(CfgFeaturesNmiPerformanceCounterTicksPerSecond), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesUnloadOnErrorsEnabled",    &CfgFeaturesUnloadOnErrorsEnabled,     sizeof(CfgFeaturesUnloadOnErrorsEnabled), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationEnlightCpuManagement", &CfgFeaturesVirtualizationEnlightCpuManagement, sizeof(CfgFeaturesVirtualizationEnlightCpuManagement), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationEnlightEnabled", &CfgFeaturesVirtualizationEnlightEnabled, sizeof(CfgFeaturesVirtualizationEnlightEnabled), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationEnlightRefCounter", &CfgFeaturesVirtualizationEnlightRefCounter, sizeof(CfgFeaturesVirtualizationEnlightRefCounter), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationEnlightTscPage", &CfgFeaturesVirtualizationEnlightTscPage, sizeof(CfgFeaturesVirtualizationEnlightTscPage), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationEnlightTscPageWorkaround", &CfgFeaturesVirtualizationEnlightTscPageWorkaround, sizeof(CfgFeaturesVirtualizationEnlightTscPageWorkaround), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationMonitorGuestActivityStateChanges", &CfgFeaturesVirtualizationMonitorGuestActivityStateChanges, sizeof(CfgFeaturesVirtualizationMonitorGuestActivityStateChanges), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationPreemptionTimerExitsPerHour", &CfgFeaturesVirtualizationPreemptionTimerExitsPerHour, sizeof(CfgFeaturesVirtualizationPreemptionTimerExitsPerHour), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationSingleStepUsingLargePages", &CfgFeaturesVirtualizationSingleStepUsingLargePages, sizeof(CfgFeaturesVirtualizationSingleStepUsingLargePages), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationSpp",        &CfgFeaturesVirtualizationSpp,         sizeof(CfgFeaturesVirtualizationSpp),     (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationTscExit",    &CfgFeaturesVirtualizationTscExit,     sizeof(CfgFeaturesVirtualizationTscExit), (PROTECTED)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationTscOffsetting", &CfgFeaturesVirtualizationTscOffsetting, sizeof(CfgFeaturesVirtualizationTscOffsetting), (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationVe",         &CfgFeaturesVirtualizationVe,          sizeof(CfgFeaturesVirtualizationVe),      (0)},\
   {UD_TYPE_NUMBER,          "CfgFeaturesVirtualizationVmFunc",     &CfgFeaturesVirtualizationVmFunc,      sizeof(CfgFeaturesVirtualizationVmFunc),  (0)},\
   {UD_TYPE_NUMBER,          "CfgHacksWinhvrReducedEnlightenment",  &CfgHacksWinhvrReducedEnlightenment,   sizeof(CfgHacksWinhvrReducedEnlightenment), (0)},\
}
#endif
