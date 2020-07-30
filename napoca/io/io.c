/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup io Input and output support
///@{

/** @file io.c
*   @brief IO - global legacy/UEFI wrapper I/O functions
*
*/

#include "napoca.h"
#include "kernel/kernel.h"
#include "io/io.h"
#include "kernel/time.h"
#include "kernel/spinlock.h"
#include "kernel/recspinlock.h"
#include "common/kernel/vmxdefs.h"
#include "version.h"
#include "guests/pci_tools.h"
#include "common/debug/memlog.h"
#include "debug/dumpers.h"

#define IO_ENCODING_ERROR_STRING "<encoding error>"        ///< Default message returned on _IoPrepareLogBuffer, if we fail to prepare the buffer with the log message formatted.
#define MAX_TRACE_LENGTH            ((WORD)1400)           ///< Maximum length of temporary buffer used to prepare the log message, a. k. a. the maximum message length in bytes for printing.

IO_PER_CPU_DATA gIoPerCpuData[MAX_IO_PER_CPU_DATA_COUNT];  ///< Per CPU IO data used for every CPU to control the IO operations for logging
volatile DWORD gIoPerCpuDataIndex = 0;                     ///< Counter of gIoPerCpuData elements

volatile BOOLEAN gVideoVgaInited = FALSE;                  ///< TRUE - VGA / GOP init successfully done
volatile BOOLEAN gSerialInited = FALSE;                    ///< TRUE - SERIAL init successfully done
volatile BOOLEAN gSerialEnabled = TRUE;                    ///< TRUE - serial input & output is enabled

SPINLOCK gNmiPrintLock;                                    ///< used for printing while in executing a NMI or some other exceptions

static volatile BOOLEAN gIoPreinited = FALSE;              ///< TRUE - io preinited - spinlock and resources available for logging
static volatile BOOLEAN gSerialOutputEnabled = TRUE;       ///< TRUE - serial output (only) is enabled
static RECSPINLOCK gIoSpinlock;                            ///< Lock used to serialize any IO operation for logging purposes

static SPINLOCK DbgDumpLock;                               ///< this locking mechanism is used for long dumps serialization, in order to avoid multiple cpus dumping large structures for example
static volatile DWORD DbgDumpLockInitializing = 0;         ///< used to avoid double or multiple initializations by CPUs in the same time
static volatile QWORD DbgDumpLockInited = 0;               ///< flag for verification of initialization of the #DbgDumpLock
static volatile QWORD DbgDumpLockOwnerCpu = (QWORD)-1;     ///< allow for multiple 'acquire' operations from the same CPU for #DbgDumpLock
static volatile QWORD DbgDumpLockOwnedCount = 0;           ///< how many times #DbgDumpLock must be released it before it is available

extern HV_FEEDBACK_HEADER *gFeedback;                      ///< feedback data used for memory logging
extern volatile BOOLEAN gInDebugger;                       ///< when we entered the debugger


///
/// @brief        Preinitializes global gIoPerCpuData and gIoSpinlock.
///
__forceinline
static
void
_IoPreinit(
    void
    )
{
    if (CxInterlockedBeginOnce(&gIoPreinited))
    {
        HvInitRecSpinLock(&gIoSpinlock, 2, "gIoSpinLock");
        DlEnableSpinlockOptions(&SPINLOCK_HEADER(&gIoSpinlock.Lock), DL_FLAG_SILENT_REENTRANCE);
        memzero(gIoPerCpuData, sizeof(IO_PER_CPU_DATA) * MAX_IO_PER_CPU_DATA_COUNT);

        CxInterlockedEndOnce(&gIoPreinited);
    }

    return;
}



///
/// @brief        Helper function for the serial interface. If the chosen serial interface is the Oxford module, it maps the physical address
///               found in the given BAR (read from PCI configuration space of the Oxford module) to Virtual Address as device memory.
///
/// @param[in]    SerialBarPa                        The physical address from the BAR of the Oxford module
///
/// @returns      The Virtual Address of the mapped memory.
///
static
BYTE *
_IoSetupOxfordModule(
    _In_ QWORD SerialBarPa
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    MM_UNALIGNED_VA va;

    status = MmMapDevMem(&gHvMm, SerialBarPa, NAPOCA_OXFORD_VA_SIZE, TAG_OXFORD, &va);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmMapDevMem", status);
        goto cleanup;
    }

cleanup:
    return (BYTE *)va;
}



///
/// @brief        Writes Buffer of Length to the Memory feedback logger after verifications.
///
/// @param[in]    Buffer                           The buffer containing the message to be written.
/// @param[in]    Length                           The length of Buffer in bytes.
///
/// @returns      CX_STATUS_SUCCESS                - on success
/// @returns      STATUS_XXX                       - errors statuses coming from #MemLogAppend
///
static
NTSTATUS
_IoMemLogWrite(
    _In_ CHAR *Buffer,
    _In_ DWORD Length
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    if (!IoIsCpuOutputEnabled()) return status;

    if (gFeedback && gFeedback->Logger.Initialized) status = MemLogAppend(&gFeedback->Logger, Buffer, Length);

    return status;
}



///
/// @brief        Writes Buffer of Length to the VGA text-mode screen after verifications.
///
/// @param[in]    Buffer                           The buffer containing the message to be written.
/// @param[in]    Length                           The length of Buffer in bytes.
///
/// @returns      CX_STATUS_SUCCESS                - on success
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - if VGA is not initialized
///
static
NTSTATUS
_IoVideoWrite(
    _In_ CHAR *Buffer,
    _In_ WORD Length
)
{
    if (!IoIsCpuOutputEnabled()) return CX_STATUS_SUCCESS;

    if (CfgDebugOutputDebuggerOnly && !gInDebugger) return CX_STATUS_SUCCESS;

    if (!gVideoVgaInited) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    return VgaWrite(Buffer, Length);
}



///
/// @brief        Initializes only once the DbgDumpLock and its related data.
///
/// @returns      CX_STATUS_SUCCESS                - on success
/// @returns      CX_STATUS_NOT_INITIALIZED        - if CPU didn't complete its phase2 yet
///
/// @remark       A call to this function might result in blocking(yielding) the CPU until another CPU finishes the initialization which was started by it.
///
static
NTSTATUS
_DbgPrepareDumpLock(
    void
    )
{
    if (IoGetPerCpuPhase() >= IO_CPU_PHASE2)
    {
        if ((!DbgDumpLockInited) && (0 == HvInterlockedCompareExchangeU32(&DbgDumpLockInitializing, 1, 0)))
        {
            HvInitSpinLock((SPINLOCK*)&DbgDumpLock, "DbgDumpLock", NULL);
            DbgDumpLockOwnerCpu = (QWORD)-1;
            DbgDumpLockOwnedCount = 0;
            DbgDumpLockInited = 1;
        }
        while(!DbgDumpLockInited)
        {
            // wait until it is initialized by whoever took DbgDumpLockInitializing
            CpuYield();
        }
    }
    else return CX_STATUS_NOT_INITIALIZED;

    return CX_STATUS_SUCCESS;
}

NTSTATUS
DbgAcquireDumpLock(
    _In_ CHAR *File,
    _In_ DWORD Line
    )
{
    NTSTATUS status;

    status = _DbgPrepareDumpLock();
    if (!CX_SUCCESS(status)) return status;

    // check lock ownership,
    if (DbgDumpLockOwnerCpu == HvGetInitialLocalApicIdFromCpuid())
    {
        // nothing to do, already mine and will remain owned until I release it
        CxInterlockedIncrement64(&DbgDumpLockOwnedCount);
    }
    else
    {
        HvAcquireSpinLockNoInterrupts2(&DbgDumpLock, File, Line);
        DbgDumpLockOwnerCpu = HvGetInitialLocalApicIdFromCpuid();
        CxInterlockedIncrement64(&DbgDumpLockOwnedCount);
    }
    return CX_STATUS_SUCCESS;
}

NTSTATUS
DbgReleaseDumpLock(
    _In_ CHAR *File,
    _In_ DWORD Line
    )
{
    BOOLEAN owned; // might not be owned if it was 'acquired' while being initialized by another cpu
    NTSTATUS status;

    status = _DbgPrepareDumpLock();
    if (!CX_SUCCESS(status)) return status;

    owned = (HvGetInitialLocalApicIdFromCpuid() == DbgDumpLockOwnerCpu);

    if (owned && (DbgDumpLockOwnedCount != 0))
    {
        // don't allow negative values in case of forced releases
        CxInterlockedDecrement64(&DbgDumpLockOwnedCount);
    }

    // safe to actually release it if we really finished using it
    if (DbgDumpLockOwnedCount == 0)
    {
        // first make sure no one will see the lock as owned by themselves until the lock is acquired
        DbgDumpLockOwnerCpu = (QWORD) -1;
        // make it available
        HvReleaseSpinLock2(&DbgDumpLock, File, Line);
    }
    return CX_STATUS_SUCCESS;
}

NTSTATUS
IoGetPerCpuData(
    _Out_ IO_PER_CPU_DATA **CpuData
    )
    //
    // Return the already assigned entry for the current CPU
    // or alloc a new entry and commit it to this CPU
    //
{
    DWORD i = 0;
    DWORD cpuId = 0;

    _IoPreinit();

    if (!CpuData) return CX_STATUS_INVALID_PARAMETER;

    *CpuData = NULL;

    if (HvDoWeHaveValidCpu() && HvGetCurrentCpu()->IoPerCpuData && HvGetCurrentCpu()->IoPerCpuData->Initialized)
    {
        *CpuData = HvGetCurrentCpu()->IoPerCpuData;
        return CX_STATUS_SUCCESS;
    }

    cpuId = HvGetInitialLocalApicIdFromCpuid();

    for (i = 0; i < MAX_IO_PER_CPU_DATA_COUNT; i++)
    {
        if (gIoPerCpuData[i].CpuId == cpuId && gIoPerCpuData[i].Initialized)
        {
            if (HvDoWeHaveValidCpu()) HvGetCurrentCpu()->IoPerCpuData = &(gIoPerCpuData[i]);

            *CpuData = &(gIoPerCpuData[i]);

            return CX_STATUS_SUCCESS;
        }
    }

    // assign a new array element if none was found
    i = HvInterlockedIncrementU32(&gIoPerCpuDataIndex) - 1;
    if (i < MAX_IO_PER_CPU_DATA_COUNT)
    {
        gIoPerCpuData[i].CpuId  = cpuId;
        gIoPerCpuData[i].Initialized = TRUE;

        *CpuData = &(gIoPerCpuData[i]);

        if (HvDoWeHaveValidCpu()) HvGetCurrentCpu()->IoPerCpuData = &(gIoPerCpuData[i]);

        return CX_STATUS_SUCCESS;
    }
    else return CX_STATUS_DATA_BUFFER_TOO_SMALL;
}

NTSTATUS
IoSetPerCpuOutputEnabled(
    _In_ BOOLEAN OutputEnabled
    )
{
    IO_PER_CPU_DATA *cpuData;
    NTSTATUS status;

    if (CX_SUCCESS((status = IoGetPerCpuData(&cpuData)))) cpuData->Enabled = OutputEnabled;

    return status;
}

BOOLEAN
IoIsCpuOutputEnabled(
    VOID
)
{
    IO_PER_CPU_DATA *cpuData;

    if (CX_SUCCESS(IoGetPerCpuData(&cpuData))) return cpuData->Enabled;

    return FALSE;
}

NTSTATUS
IoSetPerCpuPhase(
    _In_ IO_CPU_PHASE CurrentCpuPhase
    )
{
    IO_PER_CPU_DATA *cpuData;
    NTSTATUS status;

    if (CX_SUCCESS((status = IoGetPerCpuData(&cpuData)))) cpuData->CpuPhase = CurrentCpuPhase;

    return status;
}

IO_CPU_PHASE
IoGetPerCpuPhase(
    void
)
{
    IO_PER_CPU_DATA *cpuData;

    if (CX_SUCCESS(IoGetPerCpuData(&cpuData))) return cpuData->CpuPhase;

    return 0;
}

NTSTATUS
IoInitForTrace(
    _In_ BOOLEAN InitVideo,
    _In_ BOOLEAN InitSerial
    )
{
    NTSTATUS status;
    BYTE height;

    gVideoVgaInited = FALSE;
    gSerialInited = FALSE;
    gSerialEnabled = TRUE;

    if (InitVideo && !gVideoVgaInited)
    {
        // call the right Init function
        height = BOOT_OPT_BIOS_ENVIRONMENT ? 50 : 25;
        status = VgaInit(height);
        if (!CX_SUCCESS(status)) goto cleanup;

        gVideoVgaInited = TRUE;

        HvPrint("[DEBUG] VIDEO INITED\n");
    }

    if (gVideoVgaInited) PrintVersionInfo();

    // same code for both UEFI and legacy
    if (InitSerial)
    {
        SERIAL_INTERFACE iface = {0};

        // setup serial interface
        iface.InByte = PciConfigInByte;
        iface.InWord = PciConfigInWord;
        iface.InDword = PciConfigInDword;
        iface.OutByte = PciConfigOutByte;
        iface.OutWord = PciConfigOutWord;
        iface.OutDword = PciConfigOutDword;

        iface.DumpersMorse64 = DumpersMorse64;
        iface.PciLookupBridgeForPciBus = PciLookupBridgeForPciBus;
        iface.PciPowerOnPciDevice = PciPowerOnPciDevice;
        iface.SetupOxfordModule = _IoSetupOxfordModule;
        iface.SerHvPrint = HvPrint;
        iface.SerHvPrintNoLock = HvPrintNoLock;

        status = UartInitInterface(&iface);
        if (!NT_SUCCESS(status)) goto cleanup;

        status = UartSerialInit(0);             // use 0 to force lookup
        if (!CX_SUCCESS(status)) goto cleanup;

        HvPrint("[DEBUG] SERIAL INITED\n");
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

BOOLEAN
IoSerialIsInited(
    void
    )
{
    return gSerialInited;
}

VOID
IoEnableSerialOutput(
    _In_ BOOLEAN Enable
    )
{
    if (!gIoPreinited) return;

    CxInterlockedExchange8(&gSerialOutputEnabled, Enable);
}

NTSTATUS IoEnableSerial(
    _In_ BOOLEAN enable
    )
{
    if (!gIoPreinited) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    HvAcquireRecSpinLockNoInterrupts(&gIoSpinlock);
    gSerialEnabled = enable;
    HvReleaseRecSpinLock(&gIoSpinlock);

    return CX_STATUS_SUCCESS;
}

BOOLEAN IoSerialIsEnabled(
    void
    )
{
    return gSerialEnabled;
}

BOOLEAN IoSerialOutputIsEnabled(
    void
    )
{
    BOOLEAN enabled;

    if (!gIoPreinited) return FALSE;

    enabled = CxInterlockedOr8(&gSerialOutputEnabled, CX_FALSE);

    return enabled;
}

NTSTATUS
IoSerialWrite(
    _In_ CHAR  *Buffer,
    _In_ DWORD Length
    )
{
    if (UartGetUsedEntry() == serialNone) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (!gSerialInited || !gSerialEnabled) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (CfgDebugOutputDebuggerOnly && !gInDebugger) return CX_STATUS_SUCCESS;

    if ((!CxInterlockedOr8(&gSerialOutputEnabled, CX_FALSE)) || (!IoIsCpuOutputEnabled())) return CX_STATUS_SUCCESS;

    NTSTATUS status = UartSerialWrite(Buffer, Length);

    if (status == CX_STATUS_REINITIALIZED_HINT)
    {
        CHAR *msg = "\n***** REINITIALIZED *****\n";
        UartSerialWrite(msg, (WORD)strlen(msg));
    }

    return status;
}

BOOLEAN
IoSerialIsDataReady(
    void
    )
{
    if (!IoIsCpuOutputEnabled()) return FALSE;

    if (!gSerialInited || !gSerialEnabled) return FALSE;

    return UartSerialIsDataReady();
}

NTSTATUS
IoSerialRead(
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
    )
{
    // Output is verified because otherwise no message would be displayed on commands
    if ((!gIoPreinited) || (!gSerialInited || !gSerialEnabled) || (!IoIsCpuOutputEnabled())) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_1;
    if (MaxLength == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Length) return CX_STATUS_INVALID_PARAMETER_3;

    return UartSerialRead(Buffer, MaxLength, Length);
}



///
/// @brief        Gets from file the last k bytes.
/// @param[in]    File                             A NULL terminated character string of the file name and path.
/// @param[in]    K                                The number of bytes/characters from the end of the file to get.
///
/// @returns      The start address from File for the last K characters or File if K is bigger than the length of File.
///
static
__forceinline
const char *lastchars(
    _In_ const char *File,
    _In_ int K
)
{
    int len;

    len = (int)strlen(File);

    if ((int)len < K) return File;
    else return File + len - K;
}



///
/// @brief        Prepares the IO log buffer
///
///               Prepares the log message buffer, based on the passed message, the current linear time and mete information like the
///               the file and line of the logging. It also takes the message formatter and solves the changing of formatter characters
///               with the variadic arguments passed to the function
///
/// @param[out]   LogBuffer                        The buffer which will be completed by the function
/// @param[in]    LogBufferMaxLength               The maximum length for LogBuffer
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    FormatBuffer                     The format buffer, used to passed what type of variadic arguments we have and how they should be printed
/// @param[in]    Args                             The effective list of the variadic arguments passed to the log/print functions
///
/// @returns      The final number of the resulted buffers length in bytes
///
static
CX_UINT16
_IoPrepareLogBuffer(
    _Out_ CHAR* LogBuffer,
    _In_ WORD LogBufferMaxLength,
    _In_opt_ const CHAR* File,
    _In_opt_ DWORD Line,
    _In_ const CHAR* FormatBuffer,
    _In_ va_list Args
)
{
    CX_INT32 snpCnt = 0, vsnCnt = 0;
    WORD finalCount;

    if (File)
    {
        QWORD linTime;

        linTime = HvApproximateLinearTimeInMicrosecondsFast();

        snpCnt = snprintf(LogBuffer, LogBufferMaxLength, "%u.%06u, %14s, %4u: ",
            (DWORD)(linTime / 1000000), (DWORD)(linTime % 1000000), lastchars(File, 14), Line);
        if (snpCnt < 0)
        {
            char failMessage[] = IO_ENCODING_ERROR_STRING;
            strcpy_s(LogBuffer, LogBufferMaxLength, failMessage);
            snpCnt = sizeof(failMessage) - 1;
        }
    }
    vsnCnt = vsnprintf(&LogBuffer[snpCnt], (CX_UINT64)LogBufferMaxLength - snpCnt, FormatBuffer, Args);
    if (vsnCnt < 0)
    {
        char failMessage[] = IO_ENCODING_ERROR_STRING;
        strcpy_s(LogBuffer, LogBufferMaxLength, failMessage);
        vsnCnt = sizeof(failMessage) - 1;
    }

    // adjust the count in case of truncation
    if (snpCnt + vsnCnt > (CX_INT32)LogBufferMaxLength - 1) finalCount = LogBufferMaxLength - 1;
    else finalCount = (WORD)(snpCnt + vsnCnt);

    return finalCount;
}



///
/// @brief        Generic IO print function which prints the message given on any available logging channel.
///
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
static
__forceinline
VOID
_IoPrintLogBuffer(
    _In_ CHAR *Buffer,
    _In_ DWORD  Length
)
{
    _IoMemLogWrite(Buffer, Length);

    if (gVideoVgaInited) _IoVideoWrite(Buffer, (WORD)Length);

    if (gSerialInited && gSerialEnabled) IoSerialWrite(Buffer, Length);
}



///
/// @brief        Trace print the buffer given, it assures that the writing is synchronized with global IO spinlock and that the CPU can't
///               be interrupted by messages from other CPUs in the middle of writing.
///
/// @param[in]    Buffer                           The buffer to be printed out
/// @param[in]    Length                           The length of Buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - always
///
static
__forceinline
NTSTATUS
_TracePrintBuffer(
    _In_ CHAR   *Buffer,
    _In_ DWORD  Length
)
{
    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    HvAcquireRecSpinLockNoInterrupts(&gIoSpinlock);

    _IoPrintLogBuffer(Buffer, Length);

    HvReleaseRecSpinLock(&gIoSpinlock);

    IpcSetInterruptibilityState(orig);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
TracePrintVa(
    _In_opt_ const CHAR* File,
    _In_opt_ DWORD Line,
    _In_ const CHAR* Buffer,
    _In_ va_list Args
    )
{
    char tempCharBuffer[MAX_TRACE_LENGTH];
    WORD cnt = 0;
    tempCharBuffer[0] = 0;

    if (!gIoPreinited) return CX_STATUS_NOT_INITIALIZED;

    if ((!gVideoVgaInited) && (!gSerialInited) && (!gFeedback || !gFeedback->Logger.Initialized)) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    cnt = _IoPrepareLogBuffer(tempCharBuffer, MAX_TRACE_LENGTH, File, Line, Buffer, Args);

    return _TracePrintBuffer(tempCharBuffer, cnt);
}

NTSTATUS
TracePrint(
    _In_opt_ const CHAR *File,
    _In_opt_ DWORD Line,
    _In_ const CHAR *Buffer,
    ...)
{
    NTSTATUS status;
    va_list var;
    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    DUMP_BEGIN; // log when there's no OTHER cpu with a block-dump in progress, doesn't self-block

    va_start(var, Buffer);
    status = TracePrintVa(File, Line, Buffer, var);
    va_end(var);

    DUMP_END;

    IpcSetInterruptibilityState(orig);

    return status;
}



///
/// @brief        Print function used to print from NMI interrupts, it is useful in this sensitive case, because it doesn't tries
///               to acquire the IO lock, it only acquires a separate lock which only assures mutual exclusion just in case multiple CPUs
///               handle in the same time a similar critical/sensitive event.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    Args                             The effective list of the variadic arguments passed to the print functions
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
static
NTSTATUS
_HvPrintNmiLogVa(
    _In_opt_ CHAR *File,
    _In_opt_ DWORD Line,
    _In_ CHAR *Buffer,
    _In_ va_list Args
)
{
    char tempCharBuffer[MAX_TRACE_LENGTH];
    WORD cnt = 0;
    tempCharBuffer[0] = 0;

    if (!gIoPreinited) return CX_STATUS_NOT_INITIALIZED;

    if ((!gVideoVgaInited) && (!gSerialInited) && (!gFeedback || !gFeedback->Logger.Initialized)) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    cnt = _IoPrepareLogBuffer(tempCharBuffer, MAX_TRACE_LENGTH, File, Line, Buffer, Args);

    HvAcquireSpinLockNoInterrupts(&gNmiPrintLock);

    _IoPrintLogBuffer(tempCharBuffer, cnt);

    HvReleaseSpinLock(&gNmiPrintLock);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvPrintNmiLog(
    _In_opt_ CHAR *File,
    _In_opt_ DWORD Line,
    _In_ CHAR *Buffer,
    ...)
{
    NTSTATUS status;
    va_list var;

    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    va_start(var, Buffer);
    status = _HvPrintNmiLogVa(File, Line, Buffer, var);
    va_end(var);

    IpcSetInterruptibilityState(orig);

    return status;
}



///
/// @brief        A function used during exception handling, it tries to acquire the normal IO lock to synchronize with the rest of the CPUs over
///               any message, but if it fails to do that in a short period of time, it reverts to the special NMI lock.
///
static
BOOLEAN
_HvAcquireExceptionPrintLock(void)
{
    QWORD timeout;

    if (!gIoPreinited) return FALSE;

    timeout = HvApproximateLinearTimeInMicrosecondsFast() + 4 * ONE_SECOND_IN_MICROSECONDS;;

    //
    // Try for 5 seconds to acquire the print lock
    //
    while (HvApproximateLinearTimeInMicrosecondsFast() < timeout)
    {
        if (HvTryToAcquireRecSpinLock(&gIoSpinlock))
        {
            //
            // Acquired the print lock
            //
            return TRUE;
        }
    }

    HvAcquireSpinLockNoInterrupts(&gNmiPrintLock);

    return FALSE;
}

///
/// @brief        Print function used to print from exceptions, it is useful in this sensitive case, because it tries to acquire the IO lock
///               but only for a short period of time, if it didn't succeeds than it only acquires a separate lock (NMI print lock) which
///               only assures mutual exclusion just in case multiple CPUs handle in the same time a similar critical/sensitive event.
///
/// @param[in]    File                             Optional character string with the name and path of the file (relative path)
///                                                 from which the log/print function were called
/// @param[in]    Line                             Optional line number from the place where the log/print functions were called
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    Args                             The effective list of the variadic arguments passed to the print functions
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case IO module was not initialized
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case IO module has no initialized and available output channel
///
static
NTSTATUS
_HvPrintExceptionVa(
    _In_opt_ CHAR  *File,
    _In_opt_ DWORD Line,
    _In_ CHAR  *Buffer,
    _In_ va_list Args
)
{
    char tempCharBuffer[MAX_TRACE_LENGTH];
    WORD cnt;
    BOOLEAN normalLock;

    if (!gIoPreinited) return CX_STATUS_NOT_INITIALIZED;

    if ((!gVideoVgaInited) && (!gSerialInited) && (!gFeedback || !gFeedback->Logger.Initialized)) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    cnt = _IoPrepareLogBuffer(tempCharBuffer, MAX_TRACE_LENGTH, File, Line, Buffer, Args);

    //
    // Acquire the best possible printing lock (try for 5 seconds to acquire the normal printing lock; acquire the NmiPrintLock if failed first step)
    //
    normalLock = _HvAcquireExceptionPrintLock();

    _IoPrintLogBuffer(tempCharBuffer, cnt);

    if (normalLock) HvReleaseRecSpinLock(&gIoSpinlock);
    else HvReleaseSpinLock(&gNmiPrintLock);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvPrintException(
    _In_opt_ CHAR  *File,
    _In_opt_ DWORD Line,
    _In_ CHAR  *Buffer,
    ... )
{
    NTSTATUS status;
    va_list var;

    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    va_start(var, Buffer);
    status = _HvPrintExceptionVa(File, Line, Buffer, var);
    va_end(var);

    IpcSetInterruptibilityState(orig);

    return status;
}

NTSTATUS
HvPrint(
    _In_ CHAR *Buffer,
    ... )
{
    char tempCharBuffer[MAX_TRACE_LENGTH];
    va_list var;
    WORD cnt;

    if (!gIoPreinited) return CX_STATUS_NOT_INITIALIZED;

    if ((!gVideoVgaInited) && (!gSerialInited) && (!gFeedback || !gFeedback->Logger.Initialized)) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    va_start(var, Buffer);

    cnt = _IoPrepareLogBuffer(tempCharBuffer, MAX_TRACE_LENGTH, NULL, 0, Buffer, var);

    va_end(var);

    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    HvAcquireRecSpinLockNoInterrupts(&gIoSpinlock);

    _IoPrintLogBuffer(tempCharBuffer, cnt);

    HvReleaseRecSpinLock(&gIoSpinlock);

    IpcSetInterruptibilityState(orig);

    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvPrintNoLock(
    _In_ CHAR *Buffer,
    ... )
{
    char tempCharBuffer[MAX_TRACE_LENGTH];
    va_list var;
    WORD cnt;

    if (!gIoPreinited) return CX_STATUS_NOT_INITIALIZED;

    if ((!gVideoVgaInited) && (!gSerialInited) && (!gFeedback || !gFeedback->Logger.Initialized)) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    va_start(var, Buffer);

    cnt = _IoPrepareLogBuffer(tempCharBuffer, MAX_TRACE_LENGTH, NULL, 0, Buffer, var);

    va_end(var);

    _IoPrintLogBuffer(tempCharBuffer, cnt);

    IpcSetInterruptibilityState(orig);

    return CX_STATUS_SUCCESS;
}

void
IoVgaSetLoadProgress(
    _In_ BYTE Percentage
    )
{
    if (gHypervisorGlobalData.BootFlags.IsWakeup) return;

    if (!gVideoVgaInited) return;

    if (!BOOT_OPT_VGA_MEM) return;

    VgaSetLoadProgress(Percentage);

    return;
}

NTSTATUS
IoVgaSetBanner(
    _In_ CHAR *String1,
    _In_ CHAR *String2
    )
{
    if (gVideoVgaInited) VgaSetBanner(String1, String2);

    return CX_STATUS_SUCCESS;
}


///@}