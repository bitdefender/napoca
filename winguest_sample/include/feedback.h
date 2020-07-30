/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _FEEDBACK_H_
#define _FEEDBACK_H_

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#ifndef QWORD
#define QWORD unsigned __int64
#endif

/*
    Note: this component uses functions exported by winguestdll.dll.
    So before using it you must initialize the imports by calling the ImportsInit function
*/

// Note: feedback folder should be configured. See 'setpath' command
// TimeToWaitBeforeDelete   -   Time (in seconds) that the files
//                              will be kept on the machine before being deleted.
// ThrottleTime             -   Time (in seconds) that will be used for throttling
//                              introspection alerts. Setting it on 0 will disable throttling mechanism.
/**/ NTSTATUS FeedbackEnable(_In_ QWORD *TimeToWaitBeforeDelete, _In_ QWORD *ThrottleTime);
/**/ NTSTATUS FeedbackSetVerbosity(_In_ BOOLEAN Enable);

#endif // !_FEEDBACK_H_
