/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file kerncomm_int.cpp
*   @brief Handlers for driver/hypervisor messages
*/

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "kerncomm_int.h"
extern "C" {
#include "common/communication/commands.h"
}
#include "feedback.h"
#include <SetupAPI.h>
#include "deploy_legacy.h"
#include "deploy_uefi.h"
#include "helpers.h"
#include "load_monitor.h"
#include "deploy_validation.h"
#include "winguest_status.h"
#include "trace.h"
#include "kerncomm_int.tmh"
#include "intro_types.h"
#include "crc32.h"

#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <set>
#include <time.h>
#include <chrono>

extern UM_CALLBACKS gCallbacks;
extern UM_CONTEXTS gContexts;
extern std::mutex gCallbacksMutex;
extern FEEDBACK_OPTIONS gFeedbackCfg;


static volatile bool gIntroWorkersStop = false;

static std::thread                      gIntroErrorsThread;
static std::mutex                       gIntroErrorsMutex;
static std::condition_variable          gIntroErrorsCondVar;
static std::queue<INTROSPECTION_ERROR>  gIntroErrors;

static std::thread                  gIntroAlertsThread;
static std::mutex                   gIntroAlertsMutex;
static std::mutex                   gIntroThrottleMutex;
static std::condition_variable      gIntroAlertsCondVar;
static auto cmpAlert = [](const INTROSPECTION_ALERT &lfh, const INTROSPECTION_ALERT &rfh) { return lfh.IndexInQueue < rfh.IndexInQueue; };
static std::multiset<INTROSPECTION_ALERT, decltype(cmpAlert)> gOrderedIntroAlerts(cmpAlert);
static std::unordered_map<DWORD, INTRO_HASH_INFO> gHashedIntroAlerts;

/**
 * @brief Handler for resume (power transition) event
 *
 * Can inform the integrator that volatile settings were lost due to power transitions and need to be reapplied
 *
 * @param[in] VolatileSettingsLost              If volatile settings were lost
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
ResumeCallbackProcess(
    BOOLEAN VolatileSettingsLost
)
{
    if (!VolatileSettingsLost)
        return STATUS_SUCCESS;

    if (gCallbacks.VolatileSettingsRequestCallback) // optimization to skip locking
    {
        std::lock_guard<std::mutex> guard(gCallbacksMutex);

        if (gCallbacks.VolatileSettingsRequestCallback)
        {
            gCallbacks.VolatileSettingsRequestCallback(gContexts.VolatileSettingsRequestContex);
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Forward an introspection alert to be processed by feedback code
 *
 * @param[in] IntroViolationHeader              Common introspection engine violation header
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
bool
_ForwardAlertToFeedback(
    _In_ INTRO_VIOLATION_HEADER const* IntroViolationHeader
    )
{
    bool forwardAlert = true;

    if (gFeedbackCfg.ThrottleTime && IntroViolationHeader->ExHeader.Valid)
    {
        DWORD introHashedAlert;
        QWORD currentAlertTime;

        introHashedAlert = Crc32(0, (PVOID)IntroViolationHeader->Exception, sizeof(IntroViolationHeader->Exception));
        currentAlertTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        std::lock_guard<std::mutex> throttleLock(gIntroThrottleMutex);

        // hash of current exception not found, insert it
        if (gHashedIntroAlerts.find(introHashedAlert) == gHashedIntroAlerts.end())
        {
            gHashedIntroAlerts[introHashedAlert] = INTRO_HASH_INFO{ currentAlertTime , currentAlertTime , 1 };
        }
        else
        {
            if ((currentAlertTime - gHashedIntroAlerts[introHashedAlert].LastSeen) < gFeedbackCfg.ThrottleTime)
            {
                // same alert was received in less than <gThrottleOptions.ThrottleTime>, will not be forwarded further to feedback, but update it's timestamp
                forwardAlert = false;
            }

            gHashedIntroAlerts[introHashedAlert].LastSeen = currentAlertTime;
            gHashedIntroAlerts[introHashedAlert].Count++;
        }
    }

    return forwardAlert;
}

/**
 * @brief Process introspection alerts
 *
 * @param[in] IntroAlert            Introspection alert
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
IntrospectionAlertProcess(
    _In_ INTROSPECTION_ALERT const& IntroAlert
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    bool feedbackOnly = false;
    INTRO_VIOLATION_HEADER const *pViolationHeader = NULL;

    switch (IntroAlert.Type)
    {
        case introEventEptViolation:
        {
            EVENT_EPT_VIOLATION const& event = IntroAlert.Event.EptViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] EPT Violation from (%d) %s\n",
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventMsrViolation:
        {
            EVENT_MSR_VIOLATION const& event = IntroAlert.Event.MsrViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] MSR 0x%x Violation from (%d) %s\n",
                event.Victim.Msr,
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventCrViolation:
        {
            EVENT_CR_VIOLATION const& event = IntroAlert.Event.CrViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] CR 0x%x Violation from (%d) %s\n",
                event.Victim.Cr,
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventXcrViolation:
        {
            EVENT_XCR_VIOLATION const& event = IntroAlert.Event.XcrViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] XCR 0x%x Violation from (%d) %s\n",
                event.Victim.Xcr,
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventIntegrityViolation:
        {
            EVENT_INTEGRITY_VIOLATION const& event = IntroAlert.Event.IntegrityViolation;
            pViolationHeader  = &event.Header;

            LogWarning("[HVI] Integrity Violation from (%d) %s\n",
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventTranslationViolation:
        {
            EVENT_TRANSLATION_VIOLATION const& event = IntroAlert.Event.TranslationViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] Translation Violation from (%d) %s\n",
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventInjectionViolation:
        {
            EVENT_MEMCOPY_VIOLATION const& event = IntroAlert.Event.MemcopyViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] MemCopy Violation from (%d) %s\n",
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventDtrViolation:
        {
            EVENT_DTR_VIOLATION const& event = IntroAlert.Event.DtrViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] DTR Violation from (%d) %s\n",
                event.Header.CurrentProcess.Pid,
                event.Header.CurrentProcess.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventMessage:
        {
            EVENT_INTROSPECTION_MESSAGE const& event = IntroAlert.Event.IntrospectionMessage;

            LogVerbose("[HVI] Message: `%s`\n", event.Message);
            break;
        }

        case introEventProcessEvent:
        {
            EVENT_PROCESS_EVENT const& event = IntroAlert.Event.ProcessEvent;

            LogVerbose("[HVI] Process Event from (%d) %s -> %s%s (%d) %s\n",
                event.Parent.Pid,
                event.Parent.ImageName,
                event.Protected ? "protected " : "",
                event.Created ? "created" : "terminated",
                event.Child.Pid,
                event.Child.ImageName);

            break;
        }

        case introEventAgentEvent:
        {
            EVENT_AGENT_EVENT const& event = IntroAlert.Event.AgentEvent;

            LogVerbose("[HVI] Agent %s Event\n",
                event.Event == agentInjected ? "Injected" :
                event.Event == agentInitialized ? "Initialized" :
                event.Event == agentStarted ? "Started" :
                event.Event == agentTerminated ? "Terminated" :
                event.Event == agentMessage ? "Message" :
                event.Event == agentError ? "Error" : "Invalid state");

            break;
        }

        case introEventModuleEvent:
        {
            EVENT_MODULE_EVENT const& event = IntroAlert.Event.ModuleEvent;

            LogVerbose("[HVI] Module Event from (%d) %s -> %s%s %S\n",
                event.CurrentProcess.Pid,
                event.CurrentProcess.ImageName,
                event.Protected ? "protected " : "",
                event.Loaded ? "loaded" : "unloaded",
                event.Module.Name);

            break;
        }

        case introEventCrashEvent:
        {
            EVENT_CRASH_EVENT const& event = IntroAlert.Event.CrashEvent;

            LogVerbose("[HVI] Crash 0x%llx Event from (%d) %s\n",
                event.Reason,
                event.CurrentProcess.Pid,
                event.CurrentProcess.ImageName);

            break;
        }

        case introEventExceptionEvent:
        {
            EVENT_EXCEPTION_EVENT const& event = IntroAlert.Event.ExceptionEvent;

            LogVerbose("[HVI] Exception 0x%llx Event from (%d) %s\n",
                event.ExceptionCode,
                event.CurrentProcess.Pid,
                event.CurrentProcess.ImageName);

            break;
        }

        case introEventConnectionEvent:
        {
            EVENT_CONNECTION_EVENT const& event = IntroAlert.Event.ConnectionEvent;

            LogVerbose("[HVI] Connection Event from (%d) %s\n",
                event.Owner.Pid,
                event.Owner.ImageName);

            break;
        }

        case introEventProcessCreationViolation:
        {
            EVENT_PROCESS_CREATION_VIOLATION const& event = IntroAlert.Event.ProcessCreationViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] Process Creation Violation from (%d) %s -> (%d) %s\n",
                event.Originator.Pid,
                event.Originator.ImageName,
                event.Victim.Pid,
                event.Victim.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventModuleLoadViolation:
        {
            EVENT_MODULE_LOAD_VIOLATION const& event = IntroAlert.Event.ModuleLoadViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] Module Load Violation from %S -> %S into (%d) %s\n",
                event.Originator.ReturnModule.Name,
                event.Originator.Module.Name,
                event.Victim.Pid,
                event.Victim.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        case introEventEnginesDetectionViolation:
        {
            EVENT_ENGINES_DETECTION_VIOLATION const& event = IntroAlert.Event.EnginesDetectionViolation;
            pViolationHeader = &event.Header;

            LogWarning("[HVI] Engines Detection Violation from (%d) %s -> (%d) %s\n",
                event.CmdLineViolation.Originator.Pid,
                event.CmdLineViolation.Originator.ImageName,
                event.CmdLineViolation.Victim.Pid,
                event.CmdLineViolation.Victim.ImageName);

            feedbackOnly = (event.Header.Flags & ALERT_FLAG_FEEDBACK_ONLY) != 0;
            break;
        }

        default:
            LogError("[HVI] Unrecognized introspection event! Type: %d", IntroAlert.Type);
            return STATUS_UNRECOGNIZED_MEDIA;
    }

    if (pViolationHeader == NULL || _ForwardAlertToFeedback(pViolationHeader))
    {
        status = FeedbackWriteIntroAlertFile(IntroAlert);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "FeedbackWriteIntroAlertFile");
        }
    }
    else
    {
        LogVerbose("Alert (Type: %d) was not uploaded to feedback due to throttling mechanism.\n", IntroAlert.Type);
        status = STATUS_SUCCESS;
    }

    if (feedbackOnly)
    {
        return status;
    }

    if (!gCallbacks.IntrospectionAlertCallback) // optimization to skip locking
    {
        return status;
    }

    std::lock_guard<std::mutex> guard(gCallbacksMutex);

    if (gCallbacks.IntrospectionAlertCallback)
    {
        gCallbacks.IntrospectionAlertCallback(IntroAlert.Type, const_cast<INTROSPECTION_EVENT*>(&IntroAlert.Event), gContexts.IntrospectionAlertCallbackContext);
    }

    return status;
}

/**
 * @brief Thread that handles queued introspection alerts received from the hypervisor
 *
 * Takes alerts from the alert queue and processes them
 */
static
void
InstrospectionAlertThread(
    void
    )
{
    QWORD lastMsg = 0;
    while (!gIntroWorkersStop)
    {
        BYTE okToExecute = 0;
        std::unique_lock<std::mutex> lockGuard(gIntroAlertsMutex);
        gIntroAlertsCondVar.wait(lockGuard, [] {return (!gOrderedIntroAlerts.empty() || gIntroWorkersStop); });

        // we process elements while we have elements and we are not signaled to stop
        // this is in order to be able to respond quickly to integrators requests
        // even though we lose some alerts - in case of heavy loads
        while (!gOrderedIntroAlerts.empty() && !gIntroWorkersStop)
        {
            // get the first element from the set (we've got a copy of it, won't be destroyed after erasing it from set)
            INTROSPECTION_ALERT introAlert = *gOrderedIntroAlerts.begin();

            while ((lastMsg != 0) && (introAlert.IndexInQueue - lastMsg > 1) && okToExecute < 3)
            {
                lockGuard.unlock();
                Sleep(80);
                lockGuard.lock();
                okToExecute++;
                introAlert = *gOrderedIntroAlerts.begin();
            }

            lastMsg = introAlert.IndexInQueue;
            // remove the first element from the set
            gOrderedIntroAlerts.erase(gOrderedIntroAlerts.begin());

            // unlock to allow new alerts to be added to the vector while dispatching the current alert
            lockGuard.unlock();

            // dispatch the alert with the lock released
            IntrospectionAlertProcess(introAlert);

            // acquire the lock in order to process other queued alerts
            lockGuard.lock();
        }
    }

    return;
}

/**
 * @brief Receive introspection alerts from the hypervisor.
 *
 * Puts alerts in a queue to be processed later. In order to keep the communication channel as free as possible we cannot afford to wait for full alert processing.
 *
 * @param[in] Buffer                Buffer that stores the alert
 * @param[in] BufferSize            Size of alert Buffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
InstrospectionAlertReceive(
    __in PVOID Buffer,
    __in DWORD BufferSize
    )
{
    PCMD_SEND_INTROSPECTION_ALERT cmd = (PCMD_SEND_INTROSPECTION_ALERT)Buffer;

    if (cmd->Count == 0)
    {
        LogError("Received malformed introspection alert message!");
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (BufferSize != sizeof(CMD_SEND_INTROSPECTION_ALERT) + (cmd->Count - 1) * sizeof(INTROSPECTION_ALERT))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // skip everything in case we have to stop
    if (gIntroWorkersStop)
    {
        return STATUS_SUCCESS;
    }

    std::lock_guard<std::mutex> lockGuard(gIntroAlertsMutex);
    std::multiset<INTROSPECTION_ALERT>::iterator it;

    it = gOrderedIntroAlerts.insert(cmd->Alerts[0]);
    for (int i = 1; i < cmd->Count; i++)
    {
        it = gOrderedIntroAlerts.insert(it, cmd->Alerts[i]);
    }

    gIntroAlertsCondVar.notify_one();

    return STATUS_SUCCESS;
}

/**
 * @brief Process introspection errors
 *
 * @param[in] IntroError           Common introspection error container
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
static
NTSTATUS
IntrospectionErrorProcess(
    _In_ INTROSPECTION_ERROR const& IntroError
    )
{
    switch (IntroError.Type)
    {
        case intErrGuestNotIdentified:
            LogError("[HVI] Guest not identified\n");
            break;

        case intErrGuestNotSupported:
            LogError("[HVI] Guest not supported\n");
            break;

        case intErrGuestKernelNotFound:
            LogError("[HVI] Guest Kernel not found\n");
            break;

        case intErrGuestApiNotFound:
            LogError("[HVI] Guest api not found\n");
            break;

        case intErrGuestExportNotFound:
            LogError("[HVI] Guest export not found\n");
            break;

        case intErrGuestStructureNotFound:
            LogError("[HVI] Guest structure not found\n");
            break;

        case intErrUpdateFileNotSupported:
            LogError("[HVI] CAMI update file not supported\n");
            break;

        case intErrProcNotProtectedNoMemory:
        {
            INTRO_ERROR_CONTEXT const &errorContext = IntroError.Context;

            LogError("[HVI] Process not protected due to insufficient memory: %S\n", errorContext.ProcessProtection.Process.Path);
            break;
        }

        case intErrProcNotProtectedInternalError:
        {
            INTRO_ERROR_CONTEXT const &errorContext = IntroError.Context;

            LogError("[HVI] Process not protected due to internal error: %S\n", errorContext.ProcessProtection.Process.Path);
            break;
        }

        default:
            LogError("[HVI] Unknown introspection error! Type: %lld\n", IntroError.Type);
    }


    if (!gCallbacks.IntrospectionErrorCallback) // optimization to skip locking
    {
        return STATUS_SUCCESS;
    }

    std::lock_guard<std::mutex> guard(gCallbacksMutex);

    if (gCallbacks.IntrospectionErrorCallback)
    {
        gCallbacks.IntrospectionErrorCallback(IntroError.Type, const_cast<INTRO_ERROR_CONTEXT*>(&IntroError.Context), gContexts.IntrospectionErrorCallbackContext);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Thread that handles queued introspection errors received from the hypervisor
 */
static
void
InstrospectionErrorThread(
    void
    )
{
    while (!gIntroWorkersStop)
    {
        std::unique_lock<std::mutex> lockGuard(gIntroErrorsMutex);
        gIntroErrorsCondVar.wait(lockGuard, [] {return (!gIntroErrors.empty() || gIntroWorkersStop); });

        // we process elements while we have elements and we are not signaled to stop
        // this is in order to be able to respond quickly to integrators requests
        // even though we lose some errors - in case of heavy loads
        while (!gIntroErrors.empty() && !gIntroWorkersStop)
        {
            INTROSPECTION_ERROR introError = gIntroErrors.front();
            gIntroErrors.pop();

            // unlock to allow new errors to be added to the vector while dispatching the current alert
            lockGuard.unlock();

            // dispatch the alert with the lock released
            IntrospectionErrorProcess(introError);

            // acquire the lock in order to process other queued alerts
            lockGuard.lock();
        }
    }

    return;
}

/**
 * @brief Receive introspection errors from the hypervisor.
 *
 * Puts errors in a queue to be processed later. In order to keep the communication channel as free as possible we cannot afford to wait for full error processing.
 *
 * @param[in] Buffer                Buffer that stores the error
 * @param[in] BufferSize            Size of error Buffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                    Other potential internal error
 */
NTSTATUS
IntrospectionErrorReceive(
    __in PVOID Buffer,
    __in DWORD BufferSize
)
{
    PCMD_REPORT_INTROSPECTION_ERROR cmd = (PCMD_REPORT_INTROSPECTION_ERROR)Buffer;

    if (BufferSize != sizeof(CMD_REPORT_INTROSPECTION_ERROR))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // skip everything in case we have to stop
    if (gIntroWorkersStop)
    {
        return STATUS_SUCCESS;
    }

    std::lock_guard<std::mutex> lockGuard(gIntroErrorsMutex);

    LogError("Introspection error %d.", cmd->Error.Type);
    gIntroErrors.push(cmd->Error);

    gIntroErrorsCondVar.notify_one();

    return STATUS_SUCCESS;
}

/**
 * @brief Handler for cmdSendPowerStateChange
 *
 * @param[in]  InputBuffer              Message Input Buffer
 * @param[in]  InputBufferLength        Size of input message (including common header)
 * @param[in]  OutputBuffer             Buffer where reply message will be stored
 * @param[in]  OutputBufferLength       Size of reply message buffer (including common header)
 * @param[out] BytesReturned            Actual size written to OutputBuffer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
InternalPowerStateChanged(
    __in PVOID InputBuffer,
    __in DWORD InputBufferLength,      // this includes the size of any msg header
    __out_opt PVOID OutputBuffer,
    __in_opt DWORD OutputBufferLength,
    __out DWORD* BytesReturned
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PCMD_SEND_POWER_STATE_CHANGED cmd = (PCMD_SEND_POWER_STATE_CHANGED)InputBuffer;

    UNREFERENCED_PARAMETER((OutputBuffer, OutputBufferLength));

    if (NULL == BytesReturned)
    {
        return STATUS_INVALID_PARAMETER_5;
    }

    if ((NULL == InputBuffer) || (InputBufferLength < sizeof(CMD_SEND_POWER_STATE_CHANGED)) ||
        (NULL == OutputBuffer) || (OutputBufferLength < sizeof(CMD_SEND_POWER_STATE_CHANGED)))
    {
        *BytesReturned = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (cmd->PowerState)
    {
        LogInfo("Wakeup from Sleep/Hibernate\n");

        CheckLoadMonitor();

        ResumeCallbackProcess(cmd->ResumeVolatileSettingsLost);
    }
    else
    {
        LogInfo("Sleep/Hibernate/Shutdown/Reboot\n");
    }

    status = STATUS_SUCCESS;
    *BytesReturned = sizeof(CMD_SEND_POWER_STATE_CHANGED);

    return status;
}

/**
 * @brief Initialize message processing threads
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
InitMessageConsumers(
    void
)
{
    NTSTATUS status = STATUS_SUCCESS;

    gIntroWorkersStop = false;

    try
    {
        std::thread alertThread(InstrospectionAlertThread);

        gIntroAlertsThread.swap(alertThread);
    }
    catch (std::system_error &ex)
    {
        LogError("Exception while creating alerts thread! 0x%x", ex.code().value());
        status = STATUS_WINGUEST_EXCEPTION_ENCOUNTERED;
    }

    try
    {
        std::thread introErrorsThread(InstrospectionErrorThread);

        gIntroErrorsThread.swap(introErrorsThread);
    }
    catch (std::system_error &ex)
    {
        LogError("Exception while creating alerts thread! 0x%x", ex.code().value());
        status = STATUS_WINGUEST_EXCEPTION_ENCOUNTERED;
    }

    return status;
}

/**
 * @brief Uninitialize message processing threads
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
UninitMessageConsumers(
    void
)
{
    NTSTATUS status = STATUS_SUCCESS;

    gIntroWorkersStop = true;
    gIntroAlertsCondVar.notify_all();
    gIntroErrorsCondVar.notify_all();

    if (gIntroAlertsThread.joinable())
    {
        try
        {
            gIntroAlertsThread.join();
        }
        catch (const std::system_error& ex)
        {
            LogError("Exception while waiting for alerts thread to finish! 0x%x", ex.code().value());
            status = STATUS_WINGUEST_EXCEPTION_ENCOUNTERED;
        }
    }

    if (gIntroErrorsThread.joinable())
    {
        try
        {
            gIntroErrorsThread.join();
        }
        catch (const std::system_error& ex)
        {
            LogError("Exception while waiting for errors thread to finish! 0x%x", ex.code().value());
            status = STATUS_WINGUEST_EXCEPTION_ENCOUNTERED;
        }
    }

    return status;
}

/**
 * @brief Cleanup alert throttling hashmap
 */
void
CleanupThrottleHashmap(
    void
    )
{
    LogVerbose("Clearing all hashes older than [%llu] seconds\n", gFeedbackCfg.ThrottleTime);

    std::lock_guard<std::mutex> throttleLock(gIntroThrottleMutex);
    QWORD currentAlertTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    for (auto it = gHashedIntroAlerts.cbegin(); it != gHashedIntroAlerts.cend();)
    {
        if ((currentAlertTime - it->second.LastSeen) >= gFeedbackCfg.ThrottleTime)
        {
            LogVerbose("[DELETE] Hash[0x%08x] : { FirstSeen = %llu, LastSeen = %llu, Current = %llu, Diff = %llu, Count = %llu }\n",
                it->first, it->second.FirstSeen, it->second.LastSeen, currentAlertTime, currentAlertTime - it->second.LastSeen, it->second.Count);

            it = gHashedIntroAlerts.erase(it);
        }
        else
        {
            it++;
        }
    }
}