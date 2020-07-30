/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "feedback.h"

#include "imports.h"

#include <ntstatus.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>

/* Silent/Verbose callbacks */
// From msdn: The parameters for this function (interlocked..) must be aligned on a 32-bit boundary;
// otherwise, the function will behave unpredictably
// on multiprocessor x86 systems and any non-x86 systems.
static __declspec(align(32)) volatile LONG gSilentCallbacks = TRUE;

/* Callbacks */
static NTSTATUS _IntroAlertCallback(_In_ QWORD Type, _In_ VOID *AlertData, _In_ VOID *Context);

/**/
NTSTATUS
FeedbackEnable(
    _In_ QWORD *TimeToWaitBeforeDelete,
    _In_ QWORD *ThrottleTime
)
//
// As an observation, the two APIs used below, ie WinguestConfigureFeedback and WinguestRegisterCallback can be used independently
// The first deals with generating feedback on the disk (notice that you had to set the path to the feedback folder before,
// see the "setpath" command) and the second only records a callback that will be called for you when an event occurs.
// In other words, you can record a callback even without configuring your feedback to be generated on disk.
// The code below is just an example that includes both APIs, feel free to use them as you wish.
//
{
    //
    // Drop the feedback files to disk
    //
    FEEDBACK_CONFIG_TYPES feedbackConfig =
    {
        .Flags = (QWORD)-1,    // Enable all
    };

    NTSTATUS status = Winguest.ConfigureFeedback(
        &feedbackConfig,
        NULL,
        TimeToWaitBeforeDelete,
        ThrottleTime
    );
    if (!NT_SUCCESS(status)) { return status; }

    //
    // Activate callbacks that help us "catch" alerts in this application.
    // So far they are silent, but verbosity can be enabled using "feedback" command
    //
    // Note that WINGUEST_CALLBACK is a union,
    // so only a callback can be set to a RegisterCallback function call
    WINGUEST_CALLBACK callback = { .IntrospectionAlertCallback = _IntroAlertCallback };
    status = Winguest.RegisterCallback(
        wgCallbackIntroAlert,
        callback,
        NULL
    );

    return status;
}

/**/
NTSTATUS
FeedbackSetVerbosity(
    _In_ BOOLEAN Enable
)
{
    InterlockedExchange(&gSilentCallbacks, !Enable);
    return STATUS_SUCCESS;
}

/* Callbacks */
static
NTSTATUS
_IntroAlertCallback(
    _In_ QWORD  Type,
    _In_ VOID   *AlertData,
    _In_ VOID   *Context
)
//
// The callback we previously recorded using the WinguestRegisterCallback API.
// We receive the alert type (first param), a memory area with information specific to each alert (second param) and a context (third param).
// Note that we did not set a context when recording the callback. If we had set, it would have returned during this callback.
//
{
    UNREFERENCED_PARAMETER(Context);

    if (InterlockedCompareExchange(&gSilentCallbacks, TRUE, TRUE)) { return STATUS_SUCCESS; }

    switch(Type)
    {
    case introEventEptViolation:
    {
        EVENT_EPT_VIOLATION *event = (EVENT_EPT_VIOLATION *)AlertData;

        wprintf(L"[HVI] EPT Violation from (%d) %S\n",
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventMsrViolation:
    {
        EVENT_MSR_VIOLATION *event = (EVENT_MSR_VIOLATION *)AlertData;

        wprintf(L"[HVI] MSR 0x%x Violation from (%d) %S\n",
               event->Victim.Msr,
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventCrViolation:
    {
        EVENT_CR_VIOLATION *event = (EVENT_CR_VIOLATION *)AlertData;

        wprintf(L"[HVI] CR 0x%x Violation from (%d) %S\n",
               event->Victim.Cr,
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventXcrViolation:
    {
        EVENT_XCR_VIOLATION *event = (EVENT_XCR_VIOLATION *)AlertData;

        wprintf(L"[HVI] XCR 0x%x Violation from (%d) %S\n",
               event->Victim.Xcr,
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventIntegrityViolation:
    {
        EVENT_INTEGRITY_VIOLATION *event = (EVENT_INTEGRITY_VIOLATION *)AlertData;

        wprintf(L"[HVI] Integrity Violation from (%d) %S\n",
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventTranslationViolation:
    {
        EVENT_TRANSLATION_VIOLATION *event = (EVENT_TRANSLATION_VIOLATION *)AlertData;

        wprintf(L"[HVI] Translation Violation from (%d) %S\n",
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventInjectionViolation: // MemCopy Violation
    {
        EVENT_MEMCOPY_VIOLATION *event = (EVENT_MEMCOPY_VIOLATION *)AlertData;

        wprintf(L"[HVI] MemCopy Violation from (%d) %S\n",
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventDtrViolation:
    {
        EVENT_DTR_VIOLATION *event = (EVENT_DTR_VIOLATION *)AlertData;

        wprintf(L"[HVI] DTR Violation from (%d) %S\n",
               event->Header.CurrentProcess.Pid,
               event->Header.CurrentProcess.ImageName);
    }
    break;

    case introEventMessage:
    {
        EVENT_INTROSPECTION_MESSAGE *event = (EVENT_INTROSPECTION_MESSAGE *)AlertData;

        wprintf(L"[HVI] Message: `%S`\n", event->Message);
    }
    break;

    case introEventProcessEvent:
    {
        EVENT_PROCESS_EVENT *event = (EVENT_PROCESS_EVENT *)AlertData;

        wprintf(L"[HVI] Process Event from (%d) %S -> %s%s (%d) %S\n",
               event->Parent.Pid,
               event->Parent.ImageName,
               event->Protected ? L"protected " : L"",
               event->Created ? L"created" : L"terminated",
               event->Child.Pid,
               event->Child.ImageName);
    }
    break;

    case introEventAgentEvent:
    {
        EVENT_AGENT_EVENT *event = (EVENT_AGENT_EVENT *)AlertData;

        wprintf(L"[HVI] Agent %s Event\n",
               event->Event == agentInjected ?      L"Injected"     :
               event->Event == agentInitialized ?   L"Initialized"  :
               event->Event == agentStarted ?       L"Started"      :
               event->Event == agentTerminated ?    L"Terminated"   :
               event->Event == agentMessage ?       L"Message"      :
               event->Event == agentError ?         L"Error"        : L"Invalid state");
    }
    break;

    case introEventModuleEvent:
    {
        EVENT_MODULE_EVENT *event = (EVENT_MODULE_EVENT *)AlertData;

        wprintf(L"[HVI] Module Event from (%d) %S -> %s%s %s\n",
               event->CurrentProcess.Pid,
               event->CurrentProcess.ImageName,
               event->Protected ? L"protected " : L"",
               event->Loaded ? L"loaded" : L"unloaded",
               event->Module.Name);
    }
    break;

    case introEventCrashEvent:
    {
        EVENT_CRASH_EVENT *event = (EVENT_CRASH_EVENT *)AlertData;

        wprintf(L"[HVI] Crash 0x%llx Event from (%d) %S\n",
               event->Reason,
               event->CurrentProcess.Pid,
               event->CurrentProcess.ImageName);
    }
    break;

    case introEventExceptionEvent:
    {
        EVENT_EXCEPTION_EVENT *event = (EVENT_EXCEPTION_EVENT *)AlertData;

        wprintf(L"[HVI] Exception 0x%llx Event from (%d) %S\n",
               event->ExceptionCode,
               event->CurrentProcess.Pid,
               event->CurrentProcess.ImageName);
    }
    break;

    case introEventConnectionEvent:
    {
        EVENT_CONNECTION_EVENT *event = (EVENT_CONNECTION_EVENT *)AlertData;

        wprintf(L"[HVI] Connection Event from (%d) %S\n",
               event->Owner.Pid,
               event->Owner.ImageName);
    }
    break;

    case introEventProcessCreationViolation:
    {
        EVENT_PROCESS_CREATION_VIOLATION *event = (EVENT_PROCESS_CREATION_VIOLATION *)AlertData;

        wprintf(L"[HVI] Process Creation Violation from (%d) %S -> (%d) %S\n",
               event->Originator.Pid,
               event->Originator.ImageName,
               event->Victim.Pid,
               event->Victim.ImageName);
    }
    break;

    case introEventModuleLoadViolation:
    {
        EVENT_MODULE_LOAD_VIOLATION *event = (EVENT_MODULE_LOAD_VIOLATION *)AlertData;

        wprintf(L"[HVI] Module Load Violation from %s -> %s into (%d) %S\n",
               event->Originator.ReturnModule.Name,
               event->Originator.Module.Name,
               event->Victim.Pid,
               event->Victim.ImageName);
    }
    break;

    case introEventEnginesDetectionViolation:
    {
        EVENT_ENGINES_DETECTION_VIOLATION *event = (EVENT_ENGINES_DETECTION_VIOLATION *)AlertData;

        wprintf(L"[HVI] Engines Detection Violation from (%d) %S -> (%d) %S\n",
               event->CmdLineViolation.Originator.Pid,
               event->CmdLineViolation.Originator.ImageName,
               event->CmdLineViolation.Victim.Pid,
               event->CmdLineViolation.Victim.ImageName);
    }
    break;

    default:
        wprintf(L"[HVI] Unknown introspection event! Type: %lld\n", Type);
    }

    return STATUS_SUCCESS;
}