/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file io.h
*   @brief IO - global legacy/UEFI wrapper I/O functions
*
*/

#ifndef _IO_H_
#define _IO_H_

#include "io/serial.h"
#include "io/vga.h"
#include "kernel/queue_ipc_common.h"
#include "kernel/spinlock.h"

// forward declaration
typedef struct _LD_BOOT_CONTEXT LD_BOOT_CONTEXT;

#define MAX_IO_PER_CPU_DATA_COUNT       256                       ///< Maximum number IO_PER_CPU_DATA structures supported by Napoca

/// @brief Data structures representing the necessary IO data per each CPU for IO operations control
typedef struct _IO_PER_CPU_DATA
{
    BOOLEAN Initialized;                        ///< If this structure was initialized with data
    BOOLEAN Enabled;                            ///< TRUE if the IO output is enabled for the CPU
    volatile QWORD CpuId;                       ///< The id of the CPU which is represented by this data structure
    volatile INT32 CpuPhase;                    ///< The phase in which the CPU currently it is, it influences if have IO output from it or not
    volatile INT32 CpuPhaseRestore;             ///< Used to store the current CPU phase if it is only change for a short period of time and then restored
    volatile LD_BOOT_CONTEXT *BootContext;      ///< Stores a pointer to the CPUs original boot context
    volatile IPC_STATE IpcState;                ///< The current interruptibility state of the processor
}IO_PER_CPU_DATA;

extern IO_PER_CPU_DATA gIoPerCpuData[MAX_IO_PER_CPU_DATA_COUNT];   ///< Per CPU IO data used for every CPU to control the IO operations for logging
extern volatile DWORD gIoPerCpuDataIndex;                          ///< Counter of gIoPerCpuData elements

/// @brief Enumeration of every CPU phase which is of particular interest for IO operations
typedef enum
{
    IO_CPU_PHASE_INIT64             = 0,                           ///< The CPU is in the early init phase
    IO_CPU_PHASE1                   = 1,                           ///< The CPU started phase 1 initialization after completing the early init stage
    IO_CPU_PHASE2                   = 2,                           ///< The CPU started phase 2 after completing phase 1
    IO_CPU_ROOT_CYCLE               = 3,                           ///< The CPU completed phase 2 and now it is in a cycle of scheduling the Guest
    IO_CPU_OTHERS_FROZEN            = -1,                          ///< The CPU is a special phase, where every other CPU is frozen
} IO_CPU_PHASE;


extern volatile BOOLEAN gVideoVgaInited;        ///< TRUE - VGA / GOP init successfully done
extern volatile BOOLEAN gSerialInited;          ///< TRUE - SERIAL init successfully done
extern volatile BOOLEAN gSerialEnabled;         ///< TRUE - SERIAL logging is enabled


///
/// @brief Used for printing while executing a NMI handler or other exception handlers in cases when the regular gIoLock might been taken
///
extern SPINLOCK gNmiPrintLock;



///
/// @brief        Initializes the IO interfaces requested for tracing the HVs execution
///
/// @param[in]    InitVideo                        TRUE if video VGA text-mode should be initialized
/// @param[in]    InitSerial                       TRUE if one of the available serial interfaces that we know to use should be initialized
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - in case serial was requested both the interface initialization failed
///
NTSTATUS
IoInitForTrace(
    _In_ BOOLEAN InitVideo,
    _In_ BOOLEAN InitSerial
);



///
/// @brief        Returns the IO_PER_CPU_DATA data structure associated with the current CPU if it was initialized, if not initializes one.
///
/// @param[out]   CpuData                          Pointer to where in memory the address to the IO_PER_CPU_DATA should be stored
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER      - in case CpuData is an invalid pointer
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case we have no space left for a new CPU
///
NTSTATUS
IoGetPerCpuData(
    _Out_ IO_PER_CPU_DATA **CpuData
);



///
/// @brief        Returns the current Phase of the current CPU.
///
/// @returns      IO_CPU_PHASE of the current CPU
///
IO_CPU_PHASE
IoGetPerCpuPhase(
     void
);



///
/// @brief        Enables or disable the IO output for the current CPU.
///
/// @param[in]    OutputEnabled                    TRUE to enable output, FALSE to disable IO output
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - in case something failed (getting the per CPU IO data)
///
NTSTATUS
IoSetPerCpuOutputEnabled(
    _In_ BOOLEAN OutputEnabled
);



///
/// @brief        Checks if the current CPU has the IO output enabled for it.
///
/// @returns      TRUE if enabled, FALSE otherwise
///
BOOLEAN
IoIsCpuOutputEnabled(
    VOID
);



///
/// @brief        Set the current phase of the CPU
/// @param[in]    CurrentCpuPhase                  The current CPU phase
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_XXX                    - in case something failed (getting the per CPU IO data)
///
NTSTATUS
IoSetPerCpuPhase(
    _In_ IO_CPU_PHASE CurrentCpuPhase
);



///
/// @brief        Writes the text of the VGA screen which appears as a Banner for the screen, if the VGA display is initialized and enabled.
///
/// @param[in]    String1                          The first string to be displayed on the banner, the current Napoca version usually
/// @param[in]    String2                          The second string to be displayed on the banner, the company name usually
///
/// @returns      CX_STATUS_SUCCESS                - always
///

NTSTATUS
IoVgaSetBanner(
    _In_ CHAR *String1,
    _In_ CHAR *String2
);



///
/// @brief        Sets the progress of loading the Hypervisor in percentage. Must be called after every major step/phase/component load.
///               The percentage is displayed as a load bar inside the banner of the VGA screen. The progress only appears on the VGA display.
///
/// @param[in]    Percentage                       The current percentage of Hypervisor booting
///
VOID
IoVgaSetLoadProgress(
    _In_ BYTE Percentage
);



///
/// @brief        If the serial is initialized for IO operations
///
/// @returns      TRUE if yes and FALSE otherwise
///
BOOLEAN
IoSerialIsInited(
    void
);



///
/// @brief        Enable or disable the IO on the serial interface (enables both output and input)
/// @param[in]    Enable                           TRUE to enable, FALSE for disable
///
/// @returns      CX_STATUS_SUCCESS                - always
///
NTSTATUS
IoEnableSerial(
    _In_ BOOLEAN Enable
);



///
/// @brief        Checks if the IO output is enabled on the serial interface
///
/// @returns      TRUE if yes and FALSE otherwise
///
BOOLEAN IoSerialOutputIsEnabled(
    void
);



///
/// @brief        Enable or disable the IO output on the serial interface (enables only output)
///
/// @param[in]    Enable                           TRUE to enable, FALSE for disable
///
VOID
IoEnableSerialOutput(
    _In_ BOOLEAN Enable
);



///
/// @brief        If the serial is enabled for IO operations
///
/// @returns      TRUE if yes and FALSE otherwise
///
BOOLEAN
IoSerialIsEnabled(
    void
);



///
/// @brief        Higher level function offered for direct dumping trough the serial interface, should be used only for special purposes.
///
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case not everything needed is enabled or initialized
/// @returns      CX_STATUS_XXX                    - in case there are other problems during writing to the current serial interface
///
NTSTATUS
IoSerialWrite(
    _In_ CHAR *Buffer,
    _In_ DWORD Length
);



///
/// @brief        Verifies if serial interface is both initialized and enabled, the output for the CPU is enabled and that the HV received
///               an input trough the serial interface which is available an ready to be read.
///
/// @returns      TRUE if an input is ready FALSE otherwise
///
BOOLEAN
IoSerialIsDataReady(
    void
);



///
/// @brief        Higher level function offered for debug purposes, it offers the ability for the Hypervisor to read commands passed through
///               the serial interface.
///
/// @param[out]   Buffer                           Buffer where the text is read from the serial interface
/// @param[in]    MaxLength                        The maximum length in bytes of the buffer
/// @param[out]   Length                           The actual length of the message which was read
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case Buffer is an invalid address
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - in case MaxLength is 0
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - in case Length is an invalid address
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case not everything needed is enabled or initialized
/// @returns      CX_STATUS_XXX                    - in case there are other problems during reading from the current serial interface
///
NTSTATUS
IoSerialRead(
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
);



///
/// @brief        Trace print the formatted message described by buffer with the variadic arguments passed as a list.
///               It assures that the writing is synchronized with global IO lock and that the CPU can't
///               be interrupted by messages from other CPUs in the middle of writing.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    Args                             The effective list of the variadic arguments passed to the print functions
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - in case Buffer is an invalid address
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
NTSTATUS
TracePrintVa(
    _In_opt_ const CHAR* File,
    _In_opt_ DWORD Line,
    _In_ const CHAR* Buffer,
    _In_ va_list Args
);



///
/// @brief        Trace print the formatted message described by buffer with all the variadic arguments passed to the function.
///               It assures that the writing is synchronized with global IO lock and that the CPU can't
///               be interrupted by messages from other CPUs in the middle of writing. Finally, important is that it
///               also takes the DumpLock implicitly so, by printing with this function, you can't interfere with the
///               long dumps of several messages done by other CPUs.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
/// @remark       Important is that it also takes the DumpLock implicitly so, by printing with this function, you can't interfere
///               with the long dumps of several messages done by other CPUs.
///
NTSTATUS
TracePrint(
    _In_opt_ const CHAR* File,
    _In_opt_ DWORD Line,
    _In_ const CHAR* Buffer,
    ... );



///
/// @brief        Print function used to print from NMI interrupts, it is useful in this sensitive case, because it doesn't tries
///               to acquire the IO lock, it only acquires a separate lock which only assures mutual exclusion just in case multiple CPUs
///               handle in the same time a similar critical/sensitive event.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
/// @remark       Important is that it doesn't takes the DumpLock, so it can interfere with any dumping going on on another CPU.
///
NTSTATUS
HvPrintNmiLog(
    _In_opt_ CHAR *File,
    _In_opt_ DWORD Line,
    _In_ CHAR *Buffer,
    ... );



///
/// @brief        Print function used to print from exceptions, it is useful in this sensitive case, because it tries to acquire the IO lock
///               but only for a short period of time, if it didn't succeeds than it only acquires a separate lock (NMI print lock) which
///               only assures mutual exclusion just in case multiple CPUs handle in the same time a similar critical/sensitive event.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
/// @remark       Important is that it doesn't takes the DumpLock, so it can interfere with any dumping going on on another CPU.
///
NTSTATUS
HvPrintException(
    _In_opt_ CHAR *File,
    _In_opt_ DWORD Line,
    _In_ CHAR *Buffer,
    ...);



/// @brief        Print the formatted message described by buffer with all the variadic arguments passed to the function.
///               It assures that the writing is synchronized with global IO spinlock and that the CPU can't
///               be interrupted by messages from other CPUs in the middle of writing. Finally, important is that it
///               doesn't takes the DumpLock implicitly so, by printing with this function, you can interfere with the
///               long dumps of several messages done by other CPUs.
///
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
/// @remark       Important is that it doesn't takes the DumpLock, so it can interfere with any dumping going on on another CPU.
///
NTSTATUS
HvPrint(
    _In_ CHAR *Buffer,
    ... );



/// @brief        Print the formatted message described by buffer with all the variadic arguments passed to the function.
///               It assures only that the CPU can't be interrupted by messages from other CPUs in the middle of writing.
///               Is is important that it doesn't takes neither the DumpLock, nor the global IO lock implicitly, so by
///               printing with this function, you can interfere with both trace prints and prints from other CPUs and with
///               long dumps of several messages done by other CPUs.
///
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
/// @remark       Important is that it doesn't takes neither the DumpLock nor the global IO lock. It can interfere with any IO operation in progress.
///
NTSTATUS
HvPrintNoLock(
    _In_ CHAR *Buffer,
    ... );

//
// use this locking mechanism for long dumps serialization
// to avoid multiple CPUs dumping large structures for example
// this locking mechanism permits multiple acquires from the same CPU (needing same number of releases)

#define DUMP_BEGIN          DbgAcquireDumpLock(__FILE__, __LINE__)      ///< start a compact sequence of logs where no other CPUs can interfere
#define DUMP_END            DbgReleaseDumpLock(__FILE__, __LINE__)      ///< finished logging a block of text, allow other CPUs to log


///
/// @brief        Acquires the Dump lock for this CPU. Can assure a safety sequence of messages in the exact consecutive order as the prints are
///               called, as far as no other CPU uses IO functions in the same time which avoid this lock.
///
/// @param[in]    File                             Character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Line number from the place where the log/print functions were called
///
/// @returns      CX_STATUS_SUCCESS                - always
///
NTSTATUS
DbgAcquireDumpLock(
    _In_ CHAR *File,
    _In_ DWORD Line
);



///
/// @brief        Releases the Dump lock acquired by this CPU.
///
/// @param[in]    File                             Character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Line number from the place where the log/print functions were called
///
/// @returns      CX_STATUS_SUCCESS                - always
///
NTSTATUS
DbgReleaseDumpLock(
    _In_ CHAR *File,
    _In_ DWORD Line
);


//
// [IMPORTANT]: - N appended to macros means no file and line printing
//              - TracePrint takes DumpLock while HvPrint don't
//

#define LOG(...)       TracePrint(__FILE__, __LINE__, __VA_ARGS__)                  ///< simple file-line labeled message
#define INFO(...)      TracePrint(__FILE__, __LINE__, "[INFO] " __VA_ARGS__)        ///< info-file-line labeled message
#define WARNING(...)   TracePrint(__FILE__, __LINE__, "[WARNING] " __VA_ARGS__)     ///< warning-file-line labeled message
#define ERROR(...)     TracePrint(__FILE__, __LINE__, "[ERROR] " __VA_ARGS__)       ///< error-file-line labeled message
#define CRITICAL(...)  TracePrint(__FILE__, __LINE__, "[CRITICAL] " __VA_ARGS__)    ///< critical-file-line labeled message

//
// vcpu-labeled messages prefixed with "VCPU[guest.cpuindex]: " and containing rip, exit count and current exit reason
//
#define VCPUPRIOLOG(pVcpu, fmt, ...) (\
    pVcpu ? (TracePrint(__FILE__, __LINE__, ("#%d.%d-%p (%lld)(%02d): " fmt), (pVcpu)->GuestIndex, (pVcpu)->GuestCpuIndex, (pVcpu)->PseudoRegs.CsRip, (pVcpu)->ExitCount, (pVcpu)->CurrentExitReason, __VA_ARGS__))\
          : (TracePrint(__FILE__, __LINE__, ("#Z.Z-Z (Z)(Z): " fmt), __VA_ARGS__))) ///< vcpu-labeled messages prefixed with "VCPU[guest.cpuindex]: " and containing rip, exit count and current exit reason

#define VCPULOG(pVcpu, x, ...)            VCPUPRIOLOG(pVcpu, x, __VA_ARGS__)               ///< simple vcpu-labeled message
#define VCPUINFO(pVcpu, x, ...)           VCPUPRIOLOG(pVcpu, "[INFO] " x, __VA_ARGS__)     ///< info-vcpu-labeled message
#define VCPUWARNING(pVcpu, x, ...)        VCPUPRIOLOG(pVcpu, "[WARNING] " x, __VA_ARGS__)  ///< warning-vcpu-labeled message
#define VCPUERROR(pVcpu, x, ...)          VCPUPRIOLOG(pVcpu, "[ERROR] " x, __VA_ARGS__)    ///< error-vcpu-labeled message
#define VCPUCRITICAL(pVcpu, x, ...)       VCPUPRIOLOG(pVcpu, "[CRITICAL] " x, __VA_ARGS__) ///< critical-vcpu-labeled message


#define LOG_FUNC_FAIL(FunctionName, Status)             ERROR(FunctionName " failed, status = %s\n", NtStatusToString(Status)) ///< log level 3, function failure log wrapper
#define VCPU_FUNC_FAIL(pVcpu, FunctionName, Status)     VCPUERROR(pVcpu, FunctionName " failed, status = %s\n", NtStatusToString(Status)) ///< log level 3, function failure log wrapper with vcpu-labeled message

#define LOGN(...)          HvPrint(__VA_ARGS__)            ///< Simple printing, no labels appended, no dump lock taken, only the gIoSpinLock is taken

#define NMILOG(...)        HvPrintNmiLog(__FILE__, __LINE__, __VA_ARGS__)    ///< Acquires special NMI lock for printing from NMI interrupt handlers, doesn't takes the dump lock
#define NMILOGN(...)       HvPrintNmiLog(NULL, 0, __VA_ARGS__)               ///< Acquires special NMI lock for printing from NMI interrupt handlers, doesn't takes the dump lock, no file and line labeling
#define EXCEPTION_LOG(...) HvPrintException(__FILE__, __LINE__, __VA_ARGS__) ///< Tries to acquire the best lock possible from printing from exceptions, doesn't takes the dump lock

#endif // _IO_H_


///@}