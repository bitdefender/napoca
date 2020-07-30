/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file event_timer.cpp
*   @brief Event timer to enable running scheduled repeating tasks
*/

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "event_timer.h"
#include "winguest_status.h"
#include "trace.h"
#include "event_timer.tmh"

static
NTSTATUS
StopTimer(
    PEVENT_TIMER Timer
    );

static
DWORD WINAPI
EventTimerTicker(
    __in PVOID Context
    );

/**
 * @brief Initialize a timer
 *
 * @param[in,out] Timer         Event Timer
 * @param[in]     Granularity   Tick granularity (in seconds). Specifies how often to check if events expired
 *
 * @return STATUS_SUCCESS
 * @return STATUS_WG_ALREADY_INITIALIZED    Timer already initialized
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
InitializeTimer(
    PEVENT_TIMER Timer,
    DWORD Granularity
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr = ERROR_SUCCESS;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (0 == Granularity)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    std::lock_guard<std::mutex> guard(Timer->TimerEntryListMutex);

    if (Timer->Initialized)
    {
        return STATUS_WG_ALREADY_INITIALIZED;
    }

    Timer->EndEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (NULL == Timer->EndEvent)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "CreateEvent");
        goto cleanup;
    }

    Timer->Granularity = Granularity;

    Timer->Initialized = TRUE;

    status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(status))
    {
        if (Timer->EndEvent) { CloseHandle(Timer->EndEvent); Timer->EndEvent = NULL; }
        Timer->Initialized = FALSE;
    }

    return status;
}

/**
 * @brief Uninitialize a timer
 *
 * @param[in,out] Timer     Event Timer
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
UninitializeTimer(
    PEVENT_TIMER Timer
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!Timer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    std::lock_guard<std::mutex> guard(Timer->TimerEntryListMutex);

    if (Timer->Initialized == FALSE)
    {
        return STATUS_SUCCESS;
    }

    Timer->Initialized = FALSE;

    status = StopTimer(Timer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "StopTimer");
    }

    CloseHandle(Timer->EndEvent);
    Timer->EndEvent= NULL;

    Timer->TimerEntryList.clear();

    return status;
}

/**
 * @brief Start timer ticking
 *
 * @param[in] Timer         Event Timer
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
StartTimer(
    PEVENT_TIMER Timer
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    try
    {
        Timer->Thread = std::thread(EventTimerTicker, Timer);
    }
    catch (std::system_error &ex)
    {
        LogError("Exception while creating feedback timer notification thread! 0x%x", ex.code().value());
    }
    return status;
}

/**
 * @brief Stop timer ticking
 *
 * @param[in] Timer         Event Timer
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
StopTimer(
    PEVENT_TIMER Timer
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Timer->Thread.joinable() == false)
    {
        return STATUS_SUCCESS;
    }

    SetEvent(Timer->EndEvent);

    if (Timer->Thread.joinable())
    {
        Timer->Thread.join();
    }

    // manual reset event
    // - must be reset here so other waits on it work properly
    // - used also when checking if uninitialize has been called and processing loops should stop
    ResetEvent(Timer->EndEvent);

    return status;
}

/**
 * @brief Register Timer Event
 *
 * @param[in] Timer         Event Timer
 * @param[in] Tag           Value that uniquely identifies the event
 * @param[in] Interval      How often the event should be triggered (in seconds)
 * @param[in] Callback      Event callback
 *
 * @return STATUS_SUCCESS
 * @return STATUS_ALREADY_REGISTERED    Event with Tag already registered
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
RegisterEvent(
    PEVENT_TIMER Timer,
    std::string const& Tag,
    DWORD Interval,
    PVOID Callback
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    bool timerStopped = false;

    if (!Timer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (!Interval)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (!Callback)
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    std::lock_guard<std::mutex> guard(Timer->TimerEntryListMutex);

    status = StopTimer(Timer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "StopTimer");
        goto cleanup;
    }

    timerStopped = true;

    for (auto const &entry : Timer->TimerEntryList)
    {
        if (entry->Tag == Tag)
        {
            status = STATUS_ALREADY_REGISTERED;
            break;
        }
    }

    // check to see if timer has already been registered
    if (status != STATUS_ALREADY_REGISTERED)
    {
        auto newEntry = std::make_unique<TIMER_ENTRY>();

        memset(newEntry.get(), 0, sizeof(TIMER_ENTRY));

        newEntry->Tag = Tag;
        newEntry->Interval = Interval;
        newEntry->LastTrigger = 0;
        newEntry->Callback = (PFUNC_TimerCallback)Callback;

        Timer->TimerEntryList.push_back(std::move(newEntry));
    }

cleanup:
    if (timerStopped)
    {
        status = StartTimer(Timer);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "StartTimer");
        }
    }

    return status;
}

/**
 * @brief Unregister Timer Event
 *
 * @param[in] Timer         Event Timer
 * @param[in] Tag           Value that uniquely identifies the event
 *
 * @return STATUS_SUCCESS
 * @return OTHER                        Other potential internal error
 */
NTSTATUS
UnregisterEvent(
    PEVENT_TIMER Timer,
    std::string const& Tag
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    bool timerStopped = false;

    if (!Timer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    std::lock_guard<std::mutex> guard(Timer->TimerEntryListMutex);

    status = StopTimer(Timer);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "StopTimer");
        goto cleanup;
    }

    timerStopped = true;

    for (auto it = Timer->TimerEntryList.begin();
        it != Timer->TimerEntryList.end();
        ++it)
    {
        auto const &entry = (*it);
        if (entry->Tag == Tag)
        {
            Timer->TimerEntryList.erase(it);
            break;
        }
    }

cleanup:
    if (timerStopped)
    {
        status = StartTimer(Timer);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "StartTimer");
        }
    }

    return status;
}

/**
 * @brief Perform a timer tick and check if Events expired
 *
 * @param[in] Timer         Event Timer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                        Other potential internal error
 */
static
NTSTATUS
TickTimer(
    PEVENT_TIMER Timer
    )
{
    if (!Timer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Timer->TimerEntryListMutex.try_lock())
    {
        Timer->TimeStamp += Timer->Granularity;

        for (auto &entry : Timer->TimerEntryList)
        {
            if (Timer->TimeStamp - entry->LastTrigger >= entry->Interval)
            {
                entry->LastTrigger = Timer->TimeStamp;
                entry->Callback();
            }
        }

        Timer->TimerEntryListMutex.unlock();
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Event Timer thread that ticks and calls Events
 *
 * @param[in] Context           Event Timer
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
static
DWORD WINAPI
EventTimerTicker(
    __in PVOID Context
    )
{
    NTSTATUS status;
    DWORD ret;
    PEVENT_TIMER timer = (PEVENT_TIMER)Context;
    BOOLEAN keepTicking = TRUE;

    if (NULL == Context)
    {
        return (DWORD)STATUS_INVALID_PARAMETER_1;
    }

    while (keepTicking)
    {
        ret = WaitForSingleObject(timer->EndEvent, timer->Granularity * 1000);

        switch (ret)
        {
        case WAIT_OBJECT_0:
            {
                LogVerbose("Stopping EventTimerTicker thread because stop event is set\n");
                keepTicking = FALSE;
            }
            break;

        case WAIT_TIMEOUT:
            {
                status = TickTimer(timer);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "TickTimer");
                }
            }
            break;

        case WAIT_FAILED:
        default:
            LogError("WaitForSingleObject returned 0x%x, error: %d\n", ret, GetLastError());
            break;
        }
    }

    return ERROR_SUCCESS;
}

/**
 * @brief Checks if Event Timer is stopping
 *
 * @param[in] Timer         Event Timer
 *
 * @return true             Timer not performing transition
 * @return false            Timer is currently being disabled
 */
bool
StopTimerPending(
    _In_ PEVENT_TIMER Timer
)
{
    DWORD ret = WaitForSingleObject(Timer->EndEvent, 0);

    switch (ret)
    {
    case WAIT_OBJECT_0:
        return true;

    default:
        return false;
    }
}
