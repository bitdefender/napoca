#ifndef _EFI_CMDLINE_H_
#define _EFI_CMDLINE_H_

#include "userdata.h"
#define CFG_ACTIVEOSLOAD                                 1
#define CFG_ALLOWEDRETRIES                               3
#define CFG_BYPASSHV                                     0
#define CFG_DEBUG_BYPASSONERRORS                         1
#define CFG_DEBUG_CONFIRMERRORS                          0
#define CFG_DEBUG_CONFIRMHV                              0
#define CFG_DEBUG_CONFIRMOS                              0
#define CFG_DEBUG_DUMP_CRASHLOG                          1
#define CFG_DEBUG_DUMP_ENVIRONMENTVARIABLES              0
#define CFG_DEBUG_DUMP_LASTLOG                           1
#define CFG_DEBUG_DUMP_RUNTIMETABLES                     0
#define CFG_DEBUG_DUMP_VERSION                           1
#define CFG_DEBUG_EXCEPTIONHANDLING                      0
#define CFG_DEBUG_GOPOUTPUT                              0
#define CFG_DEBUG_HALTONERRORS                           0
#define CFG_DEBUG_SIMULATESECONDLOAD                     0
#define CFG_FEEDBACKBUFFERSIZE                           0x800000
#define CFG_FILES_EFIHV                                  ""
#define CFG_FILES_EFIHVENABLED                           0
#define CFG_FILES_HVLOG                                  "EFI\\NapocaHv\\HvLog.bin"
#define CFG_FILES_OS                                     "EFI\\Microsoft\\Boot\\BOOTMGFW.EFI"
#define CFG_FILES_OSBACKUP                               "EFI\\Boot\\bootx64.efi"
#define CFG_USERINTERRACTION_ALLOWKEYBOARDBYPASS         1
#define CFG_USERINTERRACTION_BYPASSMESSAGE               "Press ESC to start without system virtualization"
#define CFG_USERINTERRACTION_BYPASSONSCANCODE            23
#define CFG_USERINTERRACTION_TIMEOUTINSECONDS            5


extern UD_NUMBER       CfgActiveOsLoad;
extern UD_NUMBER       CfgAllowedRetries;
extern UD_NUMBER       CfgBypassHv;
extern UD_NUMBER       CfgDebugBypassOnErrors;
extern UD_NUMBER       CfgDebugConfirmErrors;
extern UD_NUMBER       CfgDebugConfirmHv;
extern UD_NUMBER       CfgDebugConfirmOs;
extern UD_NUMBER       CfgDebugDumpCrashLog;
extern UD_NUMBER       CfgDebugDumpEnvironmentVariables;
extern UD_NUMBER       CfgDebugDumpLastLog;
extern UD_NUMBER       CfgDebugDumpRuntimeTables;
extern UD_NUMBER       CfgDebugDumpVersion;
extern UD_NUMBER       CfgDebugExceptionHandling;
extern UD_NUMBER       CfgDebugGopOutput;
extern UD_NUMBER       CfgDebugHaltOnErrors;
extern UD_NUMBER       CfgDebugSimulateSecondLoad;
extern UD_NUMBER       CfgFeedbackBufferSize;
extern UD_ASCII_STRING CfgFilesEfiHv;
extern UD_NUMBER       CfgFilesEfiHvEnabled;
extern UD_ASCII_STRING CfgFilesHvLog;
extern UD_ASCII_STRING CfgFilesOs;
extern UD_ASCII_STRING CfgFilesOsBackup;
extern UD_NUMBER       CfgUserInterractionAllowKeyboardBypass;
extern UD_ASCII_STRING CfgUserInterractionBypassMessage;
extern UD_NUMBER       CfgUserInterractionBypassOnScanCode;
extern UD_NUMBER       CfgUserInterractionTimeOutInSeconds;


typedef enum
{
    _CfgActiveOsLoad_                                = 0,
    _CfgAllowedRetries_                              = 1,
    _CfgBypassHv_                                    = 2,
    _CfgDebugBypassOnErrors_                         = 3,
    _CfgDebugConfirmErrors_                          = 4,
    _CfgDebugConfirmHv_                              = 5,
    _CfgDebugConfirmOs_                              = 6,
    _CfgDebugDumpCrashLog_                           = 7,
    _CfgDebugDumpEnvironmentVariables_               = 8,
    _CfgDebugDumpLastLog_                            = 9,
    _CfgDebugDumpRuntimeTables_                      = 10,
    _CfgDebugDumpVersion_                            = 11,
    _CfgDebugExceptionHandling_                      = 12,
    _CfgDebugGopOutput_                              = 13,
    _CfgDebugHaltOnErrors_                           = 14,
    _CfgDebugSimulateSecondLoad_                     = 15,
    _CfgFeedbackBufferSize_                          = 16,
    _CfgFilesEfiHv_                                  = 17,
    _CfgFilesEfiHvEnabled_                           = 18,
    _CfgFilesHvLog_                                  = 19,
    _CfgFilesOs_                                     = 20,
    _CfgFilesOsBackup_                               = 21,
    _CfgUserInterractionAllowKeyboardBypass_         = 22,
    _CfgUserInterractionBypassMessage_               = 23,
    _CfgUserInterractionBypassOnScanCode_            = 24,
    _CfgUserInterractionTimeOutInSeconds_            = 25,
} UD_NAME_ORDINALS;


#define UD_VAR_INFO_TABLE \
{\
   {UD_TYPE_NUMBER,          "CfgActiveOsLoad",                     &CfgActiveOsLoad,                      sizeof(CfgActiveOsLoad),                  (0)},\
   {UD_TYPE_NUMBER,          "CfgAllowedRetries",                   &CfgAllowedRetries,                    sizeof(CfgAllowedRetries),                (0)},\
   {UD_TYPE_NUMBER,          "CfgBypassHv",                         &CfgBypassHv,                          sizeof(CfgBypassHv),                      (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugBypassOnErrors",              &CfgDebugBypassOnErrors,               sizeof(CfgDebugBypassOnErrors),           (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugConfirmErrors",               &CfgDebugConfirmErrors,                sizeof(CfgDebugConfirmErrors),            (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugConfirmHv",                   &CfgDebugConfirmHv,                    sizeof(CfgDebugConfirmHv),                (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugConfirmOs",                   &CfgDebugConfirmOs,                    sizeof(CfgDebugConfirmOs),                (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugDumpCrashLog",                &CfgDebugDumpCrashLog,                 sizeof(CfgDebugDumpCrashLog),             (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugDumpEnvironmentVariables",    &CfgDebugDumpEnvironmentVariables,     sizeof(CfgDebugDumpEnvironmentVariables), (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugDumpLastLog",                 &CfgDebugDumpLastLog,                  sizeof(CfgDebugDumpLastLog),              (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugDumpRuntimeTables",           &CfgDebugDumpRuntimeTables,            sizeof(CfgDebugDumpRuntimeTables),        (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugDumpVersion",                 &CfgDebugDumpVersion,                  sizeof(CfgDebugDumpVersion),              (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugExceptionHandling",           &CfgDebugExceptionHandling,            sizeof(CfgDebugExceptionHandling),        (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugGopOutput",                   &CfgDebugGopOutput,                    sizeof(CfgDebugGopOutput),                (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugHaltOnErrors",                &CfgDebugHaltOnErrors,                 sizeof(CfgDebugHaltOnErrors),             (0)},\
   {UD_TYPE_NUMBER,          "CfgDebugSimulateSecondLoad",          &CfgDebugSimulateSecondLoad,           sizeof(CfgDebugSimulateSecondLoad),       (0)},\
   {UD_TYPE_NUMBER,          "CfgFeedbackBufferSize",               &CfgFeedbackBufferSize,                sizeof(CfgFeedbackBufferSize),            (0)},\
   {UD_TYPE_ASCII_STRING,    "CfgFilesEfiHv",                       CfgFilesEfiHv,                         sizeof(CfgFilesEfiHv),                    (0)},\
   {UD_TYPE_NUMBER,          "CfgFilesEfiHvEnabled",                &CfgFilesEfiHvEnabled,                 sizeof(CfgFilesEfiHvEnabled),             (0)},\
   {UD_TYPE_ASCII_STRING,    "CfgFilesHvLog",                       CfgFilesHvLog,                         sizeof(CfgFilesHvLog),                    (0)},\
   {UD_TYPE_ASCII_STRING,    "CfgFilesOs",                          CfgFilesOs,                            sizeof(CfgFilesOs),                       (0)},\
   {UD_TYPE_ASCII_STRING,    "CfgFilesOsBackup",                    CfgFilesOsBackup,                      sizeof(CfgFilesOsBackup),                 (0)},\
   {UD_TYPE_NUMBER,          "CfgUserInterractionAllowKeyboardBypass", &CfgUserInterractionAllowKeyboardBypass, sizeof(CfgUserInterractionAllowKeyboardBypass), (0)},\
   {UD_TYPE_ASCII_STRING,    "CfgUserInterractionBypassMessage",    CfgUserInterractionBypassMessage,      sizeof(CfgUserInterractionBypassMessage), (0)},\
   {UD_TYPE_NUMBER,          "CfgUserInterractionBypassOnScanCode", &CfgUserInterractionBypassOnScanCode,  sizeof(CfgUserInterractionBypassOnScanCode), (0)},\
   {UD_TYPE_NUMBER,          "CfgUserInterractionTimeOutInSeconds", &CfgUserInterractionTimeOutInSeconds,  sizeof(CfgUserInterractionTimeOutInSeconds), (0)},\
}
#endif
