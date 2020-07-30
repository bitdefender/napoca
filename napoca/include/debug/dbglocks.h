/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DBG_LOCKS_H_
#define _DBG_LOCKS_H_

#define DL_WAIT_BLOCKING    1
#define DL_WAIT_TRY         0

typedef enum _DL_OPTIONS
{
    DL_FLAG_SHARED = 1 << 1,         // this is a RW_SPINLOCK
    //...                       // add any other spinlock type info (interruptible, for example)

    // from 31 backwards - for disabling specific warnings
    DL_FLAG_SILENT_REENTRANCE = 1 << 31,
    DL_FLAG_SILENT_NOT_ON_TOP = 1 << 30,
    DL_FLAG_SILENT_NOT_INITIALIZED = 1 << 29,
}DL_OPTIONS;

//
// CFG_DEBUG_TRACE_SPINLOCKS possible values:
// -> 0 = disabled
// -> 1 = fast
// -> 2 = full (all features)
// -> bit(7) = 1 => apply to release buils too
//
#if (0 != (3&CFG_DEBUG_TRACE_SPINLOCKS)) && ((defined DEBUG) || (CFG_DEBUG_TRACE_SPINLOCKS & 0x80))
#define DBG_LOCKS_ENABLED
#if (0 != (2&CFG_DEBUG_TRACE_SPINLOCKS))
#define DBG_LOCKS_ORDERING_ENABLED
#endif
#endif

#ifndef DBG_LOCKS_ENABLED
//
// remove all traces of any spinlock debugging code
//
#define DlInitSpinlock(Name, File, Line, LockHeader, Shared)    File, Line, Name
#define DlEnableSpinlockOptions(LockHeader, DL_OPTIONS_TO_SET)
#define DlUninitSpinlock(File, Line, LockHeader)
#define DlWaitSpinlock(File, Line, LockHeader, DlWaitType)
#define DlAcquireSpinlock(File, Line, LockHeader)
#define DlReleaseSpinlock(File, Line, LockHeader)
#define DlCheckTimeout(SpinStartTsc, LockHeader, File, Line)
#define DlPrintLockStats(LockHeader)
#define DlReinitLockStats(...)
#define DlResetLockStats(...)
#define DlDumpStack(...)
#define DlDumpAllStacks(...)
#define DlDumpGlobalStats(...)
#define DlDumpOrderingInfo(...)
#define DlDumpAllStats(...)
#define DlProbeSpinlockAcquireWouldHang(...)    0
#define DlGetLockInfo(...)    CX_STATUS_COMPONENT_NOT_FOUND
#else

//
// DEBUG LOCKS build
//
#include "core.h"
#include "kernel/kerneldefs.h"

#define SPINLOCK_SPIN_TIMEOUT   (10 * gTscSpeed) // 10 seconds

#pragma pack(push, 1)
typedef struct _DBG_LOCK_HEADER
{
    char *LockName;
    char *InitFilename;
    CX_UINT32 InitLineNumber;
    CX_UINT32 LockIndex;
    CX_UINT64 Flags;
    CX_UINT64 Magic;
}DBG_LOCK_HEADER;
#pragma pack(pop)

__forceinline
void
DlEnableSpinlockOptions(
    _Inout_ DBG_LOCK_HEADER *LockHeader,
    _In_ DL_OPTIONS OptionsToSet
    )
{
    LockHeader->Flags |= OptionsToSet;
}

void
DlInitSpinlock(
    _In_ char *Name,
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ CX_BOOL Shared
    );

void
DlUninitSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    );

CX_BOOL
DlProbeSpinlockAcquireWouldHang(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    );

void
DlWaitSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ CX_BOOL TryOnly
    );

void
DlAcquireSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    );

void
DlReleaseSpinlock(
    _In_ char *File,
    _In_ CX_UINT32 Line,
    _In_ DBG_LOCK_HEADER *LockHeader
    );

void
DlCheckTimeout(
    _In_ CX_UINT64 *SpinStartTsc,
    _In_ DBG_LOCK_HEADER *LockHeader,
    _In_ char* File,
    _In_ CX_UINT32 Line
);

void
DlPrintLockStats(
    _In_ DBG_LOCK_HEADER *LockHeader
    );

void
DlResetLockStats(
    void
    );

void
DlReinitLockStats(
    void
    );

void
DlDumpStack(
    _In_ CX_UINT32 CpuIndex,
    _In_ CX_BOOL LockHeader
    );

void
DlDumpAllStacks(
    void
    );

void
DlDumpGlobalStats(
    void
    );

#ifdef DBG_LOCKS_ORDERING_ENABLED
void
DlDumpOrderingInfo(
    void
    );
#else
#define DlDumpOrderingInfo(...)
#endif

void
DlDumpAllStats(
    void
    );

CX_STATUS
DlGetLockInfo(
    _In_ DBG_LOCK_HEADER *LockHeader,
    __out_opt char **LastOwnerFile,
    __out_opt CX_UINT32 *LastOwnerLine,
    __out_opt CX_UINT32 *LastOwnerCpuId,
    __out_opt CX_UINT64 *TotalWaitingTsc,
    __out_opt CX_UINT64 *TotalOwningTsc
);

#endif // DBG_LOCKS_ENABLED

#endif // _DBG_LOCKS_H_
