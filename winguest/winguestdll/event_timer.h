/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _EVENT_TIMER_H_
#define _EVENT_TIMER_H_

#include <list>
#include <mutex>
#include <thread>

typedef
VOID
(*PFUNC_TimerCallback)();

typedef struct _TIMER_ENTRY
{
    DWORD Interval;
    DWORD LastTrigger;
    PFUNC_TimerCallback Callback;
    std::string Tag;
}TIMER_ENTRY, *PTIMER_ENTRY;

typedef struct _EVENT_TIMER
{
    BOOLEAN Initialized;
    DWORD   TimeStamp;
    std::mutex TimerEntryListMutex;
    std::list<std::unique_ptr<TIMER_ENTRY>> TimerEntryList;
    DWORD   Granularity;
    std::thread  Thread;
    HANDLE  EndEvent;
}EVENT_TIMER, *PEVENT_TIMER;



NTSTATUS
InitializeTimer(
    PEVENT_TIMER Timer,
    DWORD Granularity           // Tick granularity (in seconds)
    );

NTSTATUS
UninitializeTimer(
    PEVENT_TIMER Timer
    );

NTSTATUS
RegisterEvent(
    PEVENT_TIMER Timer,
    std::string const& Tag,
    DWORD Interval,
    PVOID Callback
    );

NTSTATUS
UnregisterEvent(
    PEVENT_TIMER Timer,
    std::string const& Tag
    );

bool
StopTimerPending(
    _In_ PEVENT_TIMER Timer
    );
#endif // _EVENT_TIMER_H_
