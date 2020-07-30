/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _FEEDBACK_H_
#define _FEEDBACK_H_

#include "json.hpp"

extern "C" {
#include "common/communication/commands.h"
}

#define FEEDBACK_EXT_INTRO                  "intro"
#define FEEDBACK_EXT_COMPAT                 "compat"

#define DEFAULT_THROTTLE_TIME               1ULL    // seconds


typedef enum _FEEDBACK_TYPES
{
    feedbackIntroEpt = 0,
    feedbackIntroMsr,
    feedbackIntroCr,
    feedbackIntroXcr,
    feedbackIntroIntegrity,
    feedbackIntroTranslation,
    feedbackIntroMemcopy,
    feedbackIntroDtr,
    feedbackIntroProcessCreation,
    feedbackIntroModuleLoad,

    feedbackMax = feedbackIntroModuleLoad
}FEEDBACK_FILE_TYPES, *PFEDBACK_FILE_TYPES;


typedef struct _FEEDBACK_FILE_CONFIG
{
    PCHAR       Extension;
    BOOLEAN     Generate;
}FEEDBACK_FILE_CONFIG, *PFEEDBACK_FILE_CONFIG;

typedef struct _FEEDBACK_OPTIONS
{
    BOOLEAN Internal;
    QWORD LocalBackupDuration;

    FEEDBACK_FILE_CONFIG Files[feedbackMax + 1];

    QWORD ThrottleTime;

} FEEDBACK_OPTIONS, *PFEEDBACK_OPTIONS;

void
CleanupFeedbackFolder(void);

NTSTATUS
FeedbackWriteCompatHwInfo(
    _In_ nlohmann::json &jsonRoot
    );

NTSTATUS
FeedbackWriteIntroAlertFile(
    _In_ INTROSPECTION_ALERT const& AlertCmd
    );

#endif // _FEEDBACK_H_
