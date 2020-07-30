/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup hvcallintro
///@{

/** @file intro.h
*   @brief INTRO -  NAPOCA hypervisor glue layer, introspection engine utilities, glue functions with semantic of hypervisor -> introspection
*
*/

#ifndef _INTRO_H_
#define _INTRO_H_

#include "wrappers/cx_winsal.h"
#include "napoca.h"
#include "glueiface.h"
#include "kernel/rwspinlock.h"

/// Intro error states relevant for OS compatibility (states that can be solved by an update to live-update.bin)
#define INTRO_OS_COMPATIBILITY_ERROR_STATES     \
    ( BIT(intErrGuestNotIdentified)             \
    | BIT(intErrGuestNotSupported)              \
    | BIT(intErrGuestKernelNotFound)            \
    | BIT(intErrGuestApiNotFound)               \
    | BIT(intErrGuestExportNotFound)            \
    | BIT(intErrGuestStructureNotFound)         \
    | BIT(intErrUpdateFileNotSupported) )

/// Fatal intro state returned by callbacks, having the meaning of introspection needs to be disabled in any case)
#define INTRO_FATAL_ERROR_STATES INTRO_OS_COMPATIBILITY_ERROR_STATES

/// Status conversion macro for Napoca specific status values into Introspection specific status values (only for some special
/// statuses, for which the introspection engine verifies explicitly after calling the hypervisor in some cases)
#define HV_STATUS_TO_INTRO_STATUS(x) ((x) == STATUS_NO_MAPPING_STRUCTURES ? INT_STATUS_NO_MAPPING_STRUCTURES : \
                                      (x) == STATUS_PAGE_NOT_PRESENT ? INT_STATUS_PAGE_NOT_PRESENT : (x))

/// Wrapper macro for ValidateIntroCallbacksLockEx function
#define ValidateIntroCallbacksLock(RwLock) ValidateIntroCallbacksLockEx(RwLock, __FILE__, __FUNCTION__, __LINE__)

///
/// @brief Validate introCallback lock, checks if the the callbacks lock is taken exclusively or not.
///
/// @param[in] RwLock           The RW spinlock to be validated, it should be Guest.Intro.IntroCallbacksLock
/// @param[in] File             The file name where the lock is validated
/// @param[in] Function         The function in which the lock is validated
/// @param[in] Line             The line of the file, at which the lock is validated
///
/// @remark It only verifies and logs an error, no action is taken
///
VOID
ValidateIntroCallbacksLockEx(
    _In_ RW_SPINLOCK* RwLock,
    _In_ char* File,
    _In_ char* Function,
    _In_ DWORD Line
);

///
/// @brief  Notifies introcore that the guest must be introspected
///
/// @param[in]  Guest           Napoca-specific guest identifier. The introspection engine
///                             treats this as an opaque value. It will be passed back to the
///                             integrator when calling GLUE_IFACE APIs. It should not change
///                             while the introspection engine is running
/// @param[in]  Options         Activation and protection flags
/// @param[in]  UpdateBuffer    The CAMI buffer that will be used by introcore for information about the guest. It
///                             must remain valid until a new buffer comes by from the on-the-fly mechanism.
/// @param[in]  BufferLength    The size of the buffer, in bytes
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_ALREADY_INITIALIZED_HINT  - if the guest is already introspected
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if the CAMI buffer is not valid.
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if the CAMI buffer length is 0.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the NewGuestNotification callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the NewGuestNotification
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
/// @remarks    Note that even if the function exits with success, certain aspects of the initialization are
///             done on VMEXIT events, thus other errors could stop introcore from properly introspecting a
///             a guest. GLUE_IFACE.NotifyIntrospectionErrorState will be used to report such errors
///
NTSTATUS
NapIntNotifyAboutNewGuest(
    _In_ PVOID Guest,
    _In_ QWORD Options,
    _In_reads_(BufferLength) PBYTE UpdateBuffer,
    _In_ DWORD BufferLength
);

///
/// @brief  Disables the introspection engine
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Flags           Flags that control the disable method. Can be 0 or IG_DISABLE_IGNORE_SAFENESS
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_ALREADY_INITIALIZED_HINT  - if the guest has no initialized introspection (not introspected Guest)
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the DisableIntro callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the DisableIntro
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
/// @remarks    Note that using IG_DISABLE_IGNORE_SAFENESS may put the guest in an unstable state
///
NTSTATUS
NapIntDisable(
    _In_ PVOID GuestHandle,
    _In_ QWORD Flags
);

///
/// @brief  Notifies introcore about a guest power state change
///
/// @param[in]  Guest           Napoca-specific guest identifier
/// @param[in]  Resume          The guest is resuming from hibernate or sleep
/// @param[in]  AcpiPowerState  The ACPI power state to which the guest is transitioning to from active state
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the NotifyGuestPowerStateChange callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the NotifyGuestPowerStateChange
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntNotifyGuestPowerStateChange(
    _In_           PVOID                Guest,
    _In_           BOOLEAN              Resume,
    _In_opt_       BYTE                 AcpiPowerState
);

///
/// @brief  Executes a debugger command of the Introspection engine
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  CpuNumber       The current VCPU number
/// @param[in]  Argc            The number of arguments
/// @param[in]  Argv            An array of NULL terminated strings
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the DebugProcessCommand callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the DebugProcessCommand
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntDebugProcessCommand(
    _In_ PVOID GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ DWORD Argc,
    _In_ CHAR* Argv[]
);

///
/// @brief      Loads a new exceptions version into introcore.
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Buffer          Buffer with the exception contents. This buffer should remain
///                             valid until this function returns
/// @param[in]  Length          The size of the buffer, in bytes
/// @param[in]  Flags           Optional flags that control the update. No such flags exist at the moment
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if the Exceptions buffer is not valid.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Length of Buffer is 0.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the UpdateExceptions callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the UpdateExceptions
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
/// @remarks    After a successful call, the previously loaded exceptions are removed. Exceptions loaded
///             with GLUE_IFACE.AddExceptionFromAlert are not removed
///
NTSTATUS
NapIntUpdateExceptions(
    _In_ PVOID GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
);

///
/// @brief      Get the current exceptions version
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[out] Major           The major version
/// @param[out] Minor           The minor version
/// @param[out] BuildNumber     The build number
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Major is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Minor is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if BuildNumber is NULL.
/// @returns    CX_STATUS_OPERATION_NOT_SUPPORTED   - if the GetExceptionsVersion callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the GetExceptionsVersion
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntGetExceptionsVersion(
    _In_ PVOID GuestHandle,
    _Out_ WORD* Major,
    _Out_ WORD* Minor,
    _Out_ DWORD* BuildNumber
);


///
/// @brief  Get a description of the introspected guest
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[out] GuestInfo       A pointer to a GUEST_INFO structure that will contain
///                             information about the guest
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if GuestInfo is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the GetGuestInfo callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the GetGuestInfo
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntGetGuestInfo(
    _In_ PVOID GuestHandle,
    _Out_ GUEST_INFO* GuestInfo
);

///
/// @brief  Abort the introcore loading process
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Abort           TRUE or FALSE, to abort or not introcore loading process
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the SetIntroAbortStatus callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the SetIntroAbortStatus
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntSetIntroAbortStatus(
    _In_ PVOID GuestHandle,
    _In_ BOOLEAN Abort
);


///
/// @brief      Adds an exception for an alert reported by introcore.
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Event           Exception information supplied by introcore on GLUE_IFACE.NotifyIntroEvent
///                             calls. If Exception is True, this buffer has the contents of the
///                             INTRO_VIOLATION_HEADER.Exception field. If it is set to False, this buffer
///                             should contain the entire alert
/// @param[in]  Type            The type of the event
/// @param[in]  Exception       The type of contents in the buffer
/// @param[in]  Context         Integrator-specific exception identifier. Can be 0
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Event is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the AddExceptionFromAlert callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the AddExceptionFromAlert
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntAddExceptionFromAlert(
    _In_ PVOID GuestHandle,
    _In_ const void* Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
);

///
/// @brief      Removes a custom exception added with GLUE_IFACE.AddExceptionFromAlert.
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Context         The context of the exception that must be removed. All exceptions
///                             that share the same context will be removed
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the RemoveException callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the RemoveException
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntRemoveException(
    _In_ PVOID GuestHandle,
    _In_opt_ QWORD Context
);

///
/// @brief      Removes all the custom exceptions added with GLUE_IFACE.AddExceptionFromAlert.
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the FlushAlertExceptions callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the FlushAlertExceptions
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntFlushAlertExceptions(
    _In_ PVOID GuestHandle
);

///
/// @brief  Toggles protection for a process
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  FullPath        The name or the full path of the process
/// @param[in]  ProtectionMask  Protection flags. A combination of PROC_OPT_PROC_*
///                             values, as defined in intro_types.h. Ignored if Add is False
/// @param[in]  Add             True if the process should be protected, False if the protection
///                             should be removed
/// @param[in]  Context         Napoca-specific context that will be passed back by introcore
///                             when sending notifications related tot his process
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if FullPath is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the AddRemoveProtectedProcessUtf16 callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the AddRemoveProtectedProcessUtf16
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
/// @remark     Napoca only offers the possibility to add or remove processes using WCHAR(UTF-16) paths.
///
NTSTATUS
NapIntAddRemoveProtectedProcess(
    _In_ PVOID GuestHandle,
    _In_z_ const WCHAR* FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
);

///
/// @brief  Removes the protection policies for all processes
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the RemoveAllProtectedProcesses callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the RemoveAllProtectedProcesses
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntRemoveAllProtectedProcesses(
    _In_ PVOID GuestHandle
);

///
/// @brief  Modifies the introcore options
///
/// @param[in]  GuestHandle         Napoca-specific guest identifier
/// @param[in]  NewDynamicOptions   The new options. See the INTRO_OPT_PROT_* values in intro_types.h
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the ModifyDynamicOptions callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the ModifyDynamicOptions
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntModifyDynamicOptions(
    _In_ PVOID GuestHandle,
    _In_ QWORD NewDynamicOptions
);

///
/// @brief  Get the currently used introcore options
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[out] IntroOptions    The options that are used. See the INTRO_OPT_PROT_* values in intro_types.h
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if IntroOptions is NULL
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the GetCurrentIntroOptions callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the GetCurrentIntroOptions
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntGetCurrentIntroOptions(
    _In_  PVOID GuestHandle,
    _Out_ QWORD* IntroOptions
);

///
/// @brief      Loads a new CAMI version
///
/// @param[in]  GuestHandle     Napoca-specific guest identifier
/// @param[in]  Buffer          Buffer with the update contents.
/// @param[in]  Length          The size of the buffer, in bytes
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if Buffer is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if Length is 0.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the UpdateSupport callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the UpdateSupport
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
/// @remarks    After a successful call, the previously loaded CAMI settings are removed
///
NTSTATUS
NapIntUpdateSupport(
    _In_ PVOID GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length
);

///
/// @brief  Get the current version of CAMI
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[out] MajorVersion    The major version
/// @param[out] MinorVersion    The minor version
/// @param[out] BuildNumber     The build number
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if GuestHandle is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if MajorVersion is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if MinorVersion is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if BuildNumber is NULL.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the GetSupportVersion callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the GetSupportVersion
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntGetSupportVersion(
    _In_ PVOID GuestHandle,
    _Out_ DWORD* MajorVersion,
    _Out_ DWORD* MinorVersion,
    _Out_ DWORD* BuildNumber
);

///
/// @brief  Sets the Introspections logging level
///
/// @param[in]  Guest           Integrator-specific guest identifier
/// @param[in]  LogLevel        The new log level
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Guest is NULL.
///
/// @remark     Try and return always SUCCESS as there are cases when intro is not yet loaded or initialized, but can still set
///             the logging level inside our CFG and intro will start with that logging level.
///
NTSTATUS
NapIntUpdateIntrospectionVerbosityLogs(
    _In_  PVOID        Guest,
    _In_  IG_LOG_LEVEL LogLevel
);

///
/// @brief  Get the version string information for the current guest
///
/// @param[in]  FullStringSize      The size, in bytes, of the FullString buffer, including the NULL terminator
/// @param[in]  VersionStringSize   The size, in bytes, of the VersionString buffer, including the NULL terminator
/// @param[out] FullString          A NULL-terminated string containing detailed version information
/// @param[out] VersionString       A NULL-terminated string containing human-readable version information
///
/// @returns    CX_STATUS_SUCCESS                   - in case of success
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if FullStringSize is 0.
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - if VersionStringSize is 0.
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - if FullString is NULL.
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - if VersionString is NULL.
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE    - if we don't have a valid Guest pointer.
/// @returns    CX_STATUS_NOT_INITIALIZED           - if the GetVersionString callback was not initialized by the
///                                                 introcore.
/// @returns    OTHER                               - other introspection statuses returned by the GetVersionString
///                                                 callback, see in GLUEIFACE for the possible statuses.
///
NTSTATUS
NapIntGetGuestVersionString(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR* FullString,
    _Out_ CHAR* VersionString
);

#endif // _INTRO_H_


///@}