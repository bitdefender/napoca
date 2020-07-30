/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// ACPIOSXF - callback function stub for INTEL ACPICA library

#include "napoca.h"
#pragma warning (push)
#include "acpi.h"
#pragma warning (pop)
#include "kernel/kernel.h"
#include "guests/pci_tools.h"

/*

...

OSL Interfaces:

The interfaces to the PCI configuration space have been changed to add
the PCI Segment number and to split the single 32-bit combined DeviceFunction
field into two 16-bit fields. This was accomplished by moving the four values
that define an address in PCI configuration space (segment, bus, device, and
function) to the new ACPI_PCI_ID structure.

The changes to the PCI configuration space interfaces led to a
reexamination of the complete set of address space access
interfaces for PCI, I/O, and Memory.  The previously existing 18
interfaces have proven difficult to maintain (any small change
must be propagated across at least 6 interfaces) and do not easily
allow for future expansion to 64 bits if necessary.  Also, on some
systems, it would not be appropriate to demultiplex the access
width (8, 16, 32,or 64) before calling the OSL if the
corresponding native OS interfaces contain a similar access width
parameter.  For these reasons, the 18 address space interfaces
have been replaced by these 6 new ones:

AcpiOsReadPciConfiguration
AcpiOsWritePciConfiguration
AcpiOsReadMemory
AcpiOsWriteMemory
AcpiOsReadPort
AcpiOsWritePort

Added a new interface named AcpiOsGetRootPointer to allow the OSL
to perform the platform and/or OS-specific actions necessary to
obtain the ACPI RSDP table pointer. On IA-32 platforms, this
interface will simply call down to the CA core to perform the low-
memory search for the table. On IA-64, the RSDP is obtained from
EFI. Migrating this interface to the OSL allows the CA core to
remain OS and platform independent.

Added a new interface named AcpiOsSignal to provide a generic
"function code and pointer" interface for various miscellaneous
signals and notifications that must be made to the host OS. The
first such signals are intended to support the ASL Fatal and
Breakpoint operators. In the latter case, the AcpiOsBreakpoint
interface has been obsoleted.

The definition of the AcpiFormatException interface has been
changed to simplify its use. The caller no longer must supply a
buffer to the call; A pointer to a const string is now returned
directly. This allows the call to be easily used in printf
statements, etc. since the caller does not have to manage a local
buffer.

...

*/



/*
 * OSL Initialization and shutdown primitives
 */
ACPI_STATUS
AcpiOsInitialize(
    void
    )
{
    return AE_OK;
}

ACPI_STATUS
AcpiOsTerminate(
    void
    )
{
    return AE_OK;
}

/*
 * ACPI Table interfaces
 */
ACPI_PHYSICAL_ADDRESS
AcpiOsGetRootPointer(
    void
    )
{
    ACPI_STATUS status;
    ACPI_PHYSICAL_ADDRESS pa;

    status = AcpiFindRootPointer(&pa);
    if (!ACPI_SUCCESS(status))
    {
        if (BOOT_UEFI && (gLoaderCustom != NULL))
        {
            LOG("Asked for UEFI ROOT pointer. Giving: %p\n", gLoaderCustom->Uefi.RSDPPhysicalAddress);
            return gLoaderCustom->Uefi.RSDPPhysicalAddress;
        }

        return 0;
    }
    else return pa;
}

ACPI_STATUS
AcpiOsPredefinedOverride(
    const ACPI_PREDEFINED_NAMES *InitVal,
    ACPI_STRING                 *NewVal
    )
{
    UNREFERENCED_PARAMETER(InitVal);

    /* No override */
    *NewVal = NULL;

    return AE_OK;
}

ACPI_STATUS
AcpiOsTableOverride(
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_TABLE_HEADER       **NewTable
    )
{
    UNREFERENCED_PARAMETER(ExistingTable);

    *NewTable = NULL;

    return AE_OK;
}

ACPI_STATUS
AcpiOsPhysicalTableOverride(
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_PHYSICAL_ADDRESS   *NewAddress,
    UINT32                  *NewTableLength
    )
{
    UNREFERENCED_PARAMETER(ExistingTable);

    *NewAddress = NULL;
    *NewTableLength = 0;

    return AE_OK;
}

/*
 * Spinlock primitives
 */
ACPI_STATUS
AcpiOsCreateLock(
    ACPI_SPINLOCK           *OutHandle
    )
{
    *OutHandle = AcpiOsAllocate(sizeof(ACPI_SPINLOCK));

    return AE_OK;
}

void
AcpiOsDeleteLock(
    ACPI_SPINLOCK           Handle
    )
{
    AcpiOsFree(&Handle);

    return;
}

ACPI_CPU_FLAGS
AcpiOsAcquireLock(
    ACPI_SPINLOCK           Handle
    )
{
    UNREFERENCED_PARAMETER(Handle);

    return 0;
}

void
AcpiOsReleaseLock(
    ACPI_SPINLOCK           Handle,
    ACPI_CPU_FLAGS          Flags
    )
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(Flags);

    return;
}


/*
 * Semaphore primitives
 */
ACPI_STATUS
AcpiOsCreateSemaphore(
    UINT32                  MaxUnits,
    UINT32                  InitialUnits,
    ACPI_SEMAPHORE          *OutHandle
    )
{
    UNREFERENCED_PARAMETER(MaxUnits);
    UNREFERENCED_PARAMETER(InitialUnits);

    *OutHandle = AcpiOsAllocate(sizeof(ACPI_SEMAPHORE));

    return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteSemaphore(
    ACPI_SEMAPHORE          Handle
    )
{
    AcpiOsFree(&Handle);

    return AE_OK;
}

ACPI_STATUS
AcpiOsWaitSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units,
    UINT16                  Timeout
    )
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(Units);
    UNREFERENCED_PARAMETER(Timeout);

    return AE_OK;
}

ACPI_STATUS
AcpiOsSignalSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units
    )
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(Units);

    return AE_OK;
}


/*
 * Mutex primitives. May be configured to use semaphores instead via
 * ACPI_MUTEX_TYPE (see platform/acenv.h)
 */
#if (ACPI_MUTEX_TYPE != ACPI_BINARY_SEMAPHORE)

ACPI_STATUS
AcpiOsCreateMutex(
    ACPI_MUTEX              *OutHandle
    );

void
AcpiOsDeleteMutex(
    ACPI_MUTEX              Handle
    );

ACPI_STATUS
AcpiOsAcquireMutex(
    ACPI_MUTEX              Handle,
    UINT16                  Timeout
    );

void
AcpiOsReleaseMutex(
    ACPI_MUTEX              Handle
    );
#endif


/*
 * Memory allocation and mapping
 */
void *
AcpiOsAllocate(
    ACPI_SIZE               Size
    )
{
    BYTE* addr = NULL;

    NTSTATUS status = HpAllocWithTagCore(&addr, (DWORD)Size, TAG_ACPI);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("HpAllocWithTagCore", status);

    return (VOID*)addr;
}


void
AcpiOsFree(
    void *                  Memory
)
{
    HpFreeAndNullWithTag(&Memory, TAG_ACPI);
}


VOID*
AcpiOsMapMemory(
    _In_ ACPI_PHYSICAL_ADDRESS Where,
    _In_ ACPI_SIZE Length
)
{
    MM_UNALIGNED_VA va;

    NTSTATUS status = MmMapMem(&gHvMm, Where, Length, TAG_ACPA, &va);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmMapMem", status);
        return NULL;
    }

    return va;
}



void
AcpiOsUnmapMemory(
    _In_ VOID* LogicalAddress,
    _In_ ACPI_SIZE Length
)
{
    UNREFERENCED_PARAMETER(Length);

    NTSTATUS status = MmUnmapMem(&gHvMm, TRUE, TAG_ACPA, &LogicalAddress);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmUnmapMem", status);
    }
}


ACPI_STATUS
AcpiOsGetPhysicalAddress(
    void                    *LogicalAddress,
    ACPI_PHYSICAL_ADDRESS   *PhysicalAddress
)
{
    UNREFERENCED_PARAMETER(LogicalAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}


// Allow ACPICA to use alternate fallback functions
///*
// * Memory/Object Cache
// */
//ACPI_STATUS
//AcpiOsCreateCache(
//    char                    *CacheName,
//    UINT16                  ObjectSize,
//    UINT16                  MaxDepth,
//    ACPI_CACHE_T            **ReturnCache
//)
//{
//    UNREFERENCED_PARAMETER(CacheName);
//    UNREFERENCED_PARAMETER(ObjectSize);
//    UNREFERENCED_PARAMETER(MaxDepth);
//    UNREFERENCED_PARAMETER(ReturnCache);
//
//    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);
//
//    return AE_ERROR;
//}
//
//ACPI_STATUS
//AcpiOsDeleteCache(
//    ACPI_CACHE_T            *Cache
//)
//{
//    UNREFERENCED_PARAMETER(Cache);
//
//    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);
//
//    return AE_ERROR;
//}
//
//ACPI_STATUS
//AcpiOsPurgeCache(
//    ACPI_CACHE_T            *Cache
//)
//{
//    UNREFERENCED_PARAMETER(Cache);
//
//    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);
//
//    return AE_ERROR;
//}
//
//void *
//AcpiOsAcquireObject(
//    ACPI_CACHE_T            *Cache
//)
//{
//    UNREFERENCED_PARAMETER(Cache);
//
//    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);
//
//    return NULL;
//}
//
//ACPI_STATUS
//AcpiOsReleaseObject(
//    ACPI_CACHE_T            *Cache,
//    void                    *Object
//)
//{
//    UNREFERENCED_PARAMETER(Cache);
//    UNREFERENCED_PARAMETER(Object);
//
//    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);
//
//    return AE_ERROR;
//}


/*
 * Interrupt handlers
 */
ACPI_STATUS
AcpiOsInstallInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine,
    void                    *Context
    )
{
    UNREFERENCED_PARAMETER(InterruptNumber);
    UNREFERENCED_PARAMETER(ServiceRoutine);
    UNREFERENCED_PARAMETER(Context);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

ACPI_STATUS
AcpiOsRemoveInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine
    )
{
    UNREFERENCED_PARAMETER(InterruptNumber);
    UNREFERENCED_PARAMETER(ServiceRoutine);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}


/*
 * Threads and Scheduling
 */
ACPI_THREAD_ID
AcpiOsGetThreadId(
    void
    )
{
    return 1;
}

ACPI_STATUS
AcpiOsExecute(
    ACPI_EXECUTE_TYPE       Type,
    ACPI_OSD_EXEC_CALLBACK  Function,
    void                    *Context
    )
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Context);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

void
AcpiOsWaitEventsComplete(
    void
)
{
    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}

void
AcpiOsSleep(
    UINT64                  Milliseconds
    )
{
    HvSpinWait(Milliseconds * 1000);

    return;
}

void
AcpiOsStall(
    UINT32                  Microseconds
    )
{
    HvSpinWait(Microseconds);

    return;
}


/*
 * Platform and hardware-independent I/O interfaces
 */
ACPI_STATUS
AcpiOsReadPort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  *Value,
    UINT32                  Width
    )
{
    switch (Width)
    {
    case 1 * 8:
        *Value = __inbyte((unsigned short)Address);
        break;
    case 2 * 8:
        *Value = __inword((unsigned short)Address);
        break;
    case 4 * 8:
        *Value = __indword((unsigned short)Address);
        break;
    default:
        return AE_ERROR;
    }

    return AE_OK;
}

ACPI_STATUS
AcpiOsWritePort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  Value,
    UINT32                  Width
    )
{
    switch (Width)
    {
    case 1 * 8:
        __outbyte((unsigned short)Address, (unsigned char)Value);
        break;
    case 2 * 8:
        __outword((unsigned short)Address, (unsigned short)Value);
        break;
    case 4 * 8:
        __outdword((unsigned short)Address, (unsigned long)Value);
        break;
    default:
        return AE_ERROR;
    }

    return AE_OK;
}


/*
 * Platform and hardware-independent physical memory interfaces
 */
ACPI_STATUS
AcpiOsReadMemory(
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  *Value,
    UINT32                  Width
    )
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Value);
    UNREFERENCED_PARAMETER(Width);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;

}

ACPI_STATUS
AcpiOsWriteMemory(
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  Value,
    UINT32                  Width
    )
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Value);
    UNREFERENCED_PARAMETER(Width);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}


/*
 * Platform and hardware-independent PCI configuration space access
 * Note: Can't use "Register" as a parameter, changed to "Reg" --
 * certain compilers complain.
 */
ACPI_STATUS
AcpiOsReadPciConfiguration(
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  *Value,
    UINT32                  Width
    )
{
    ACPI_STATUS acpiStatus = AE_OK;
    PCI_CONFIG* pciConfig;

    pciConfig = PciGetConfigSpaceVa(PciId->Bus, PciId->Device, PciId->Function);
    if (pciConfig)
    {
        switch (Width)
        {
        case 8:
            *Value = GET_VOLATILE_BYTE(pciConfig->Raw, Reg);
            break;
        case 16:
            *Value = GET_VOLATILE_WORD(pciConfig->Raw, Reg);
            break;
        case 32:
            *Value = GET_VOLATILE_DWORD(pciConfig->Raw, Reg);
            break;
        case 64:
            *Value = GET_VOLATILE_QWORD(pciConfig->Raw, Reg);
            break;
        default:
            acpiStatus = AE_ERROR;
            break;
        }
    }
    else
    {
        switch (Width)
        {
        case 8:
            *Value = PciConfigInByte(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg);
            break;
        case 16:
            *Value = PciConfigInWord(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg);
            break;
        case 32:
            *Value = PciConfigInDword(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg);
            break;
        case 64:
        default:
            acpiStatus = AE_ERROR;
            break;
        }
    }

    return acpiStatus;
}

ACPI_STATUS
AcpiOsWritePciConfiguration(
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  Value,
    UINT32                  Width
    )
{
    ACPI_STATUS acpiStatus = AE_OK;
    PCI_CONFIG* pciConfig;

    pciConfig = PciGetConfigSpaceVa(PciId->Bus, PciId->Device, PciId->Function);
    if (pciConfig)
    {
        switch (Width)
        {
        case 8:
            PUT_VOLATILE_BYTE(pciConfig->Raw, Reg, (BYTE)Value);
            break;
        case 16:
            PUT_VOLATILE_WORD(pciConfig->Raw, Reg, (WORD)Value);
            break;
        case 32:
            PUT_VOLATILE_DWORD(pciConfig->Raw, Reg, (DWORD)Value);
            break;
        case 64:
            PUT_VOLATILE_QWORD(pciConfig->Raw, Reg, Value);
            break;
        default:
            acpiStatus = AE_ERROR;
            break;
        }
    }
    else
    {
        switch (Width)
        {
        case 8:
            PciConfigOutByte(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg, (BYTE)Value);
            break;
        case 16:
            PciConfigOutWord(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg, (WORD)Value);
            break;
        case 32:
            PciConfigOutDword(PciId->Bus, PciId->Device, PciId->Function, (WORD)Reg, (DWORD)Value);
            break;
        case 64:
        default:
            acpiStatus = AE_ERROR;
            break;
        }

        acpiStatus = AE_ERROR;
    }

    return acpiStatus;
}


/*
 * Miscellaneous
 */
BOOLEAN
AcpiOsReadable(
    void                    *Pointer,
    ACPI_SIZE               Length
)
{
    UNREFERENCED_PARAMETER(Pointer);
    UNREFERENCED_PARAMETER(Length);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return FALSE;
}

BOOLEAN
AcpiOsWritable(
    void                    *Pointer,
    ACPI_SIZE               Length
)
{
    UNREFERENCED_PARAMETER(Pointer);
    UNREFERENCED_PARAMETER(Length);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return FALSE;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsGetTimer
 *
 * PARAMETERS:  None
 *
 * RETURN:      Current ticks in 100-nanosecond units
 *
 * DESCRIPTION: Get the value of a system timer
 *
 ******************************************************************************/

UINT64
AcpiOsGetTimer(
    void
    )
{
    return HvGetLinearTimeIn100Ns();
}

ACPI_STATUS
AcpiOsSignal(
    UINT32                  Function,
    void                    *Info
    )
{
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Info);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}


/*
 * Debug print routines
 */
void ACPI_INTERNAL_VAR_XFACE
AcpiOsPrintf(
    const char              *Format,
    ...
)
{
    va_list args;

    va_start(args,Format);
    AcpiOsVprintf(Format, args);
    va_end(args);
}

void
AcpiOsVprintf(
    const char              *Format,
    va_list                 Args
    )
{
    if (CfgDebugTraceAcpi == 2)
    {
        TracePrintVa(NULL, 0, (char*)Format, Args);
    }
}

void
AcpiOsRedirectOutput (
    void                    *Destination
)
{
    UNREFERENCED_PARAMETER(Destination);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}


/*
 * Debug input
 */
UINT32
AcpiOsGetLine(
    char                    *Buffer,
    UINT32                  BufferLength,
    UINT32                  *BytesRead
    )
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(BytesRead);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return 0;
}


/*
 * Directory manipulation
 */
void *
AcpiOsOpenDirectory(
    char                    *Pathname,
    char                    *WildcardSpec,
    char                    RequestedFileType
    )
{
    UNREFERENCED_PARAMETER(Pathname);
    UNREFERENCED_PARAMETER(WildcardSpec);
    UNREFERENCED_PARAMETER(RequestedFileType);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return NULL;
}

/* RequesteFileType values */

#define REQUEST_FILE_ONLY                   0
#define REQUEST_DIR_ONLY                    1


char *
AcpiOsGetNextFilename (
    void                    *DirHandle
)
{
    UNREFERENCED_PARAMETER(DirHandle);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return NULL;
}

void
AcpiOsCloseDirectory (
    void                    *DirHandle
)
{
    UNREFERENCED_PARAMETER(DirHandle);

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}


/******************************************************************************
 *
 * FUNCTION:    AcpiOsEnterSleep
 *
 * PARAMETERS:  SleepState          - Which sleep state to enter
 *              RegaValue           - Register A value
 *              RegbValue           - Register B value
 *
 * RETURN:      Status
 *
 * DESCRIPTION: A hook before writing sleep registers to enter the sleep
 *              state. Return AE_CTRL_SKIP to skip further sleep register
 *              writes.
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsEnterSleep(
    UINT8                   SleepState,
    UINT32                  RegaValue,
    UINT32                  RegbValue
)
{
    UNREFERENCED_PARAMETER((SleepState, RegaValue, RegbValue));

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWaitCommandReady
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Negotiate with the debugger foreground thread (the user
 *              thread) to wait the readiness of a command.
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsWaitCommandReady(
    void
)
{
    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsNotifyCommandComplete
 *
 * PARAMETERS:  void
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Negotiate with the debugger foreground thread (the user
 *              thread) to notify the completion of a command.
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsNotifyCommandComplete(
    void
)
{
    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsInitializeDebugger
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Initialize OSPM specific part of the debugger
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsInitializeDebugger(
    void
)
{
    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsTerminateDebugger
 *
 * PARAMETERS:  None
 *
 * RETURN:      None
 *
 * DESCRIPTION: Terminate signals used by the multi-threading debugger
 *
 *****************************************************************************/

void
AcpiOsTerminateDebugger(
    void
)
{
    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}

/*******************************************************************************
 *
 * FUNCTION:    MpSaveGpioInfo
 *
 * PARAMETERS:  Resource                - GPIO resource descriptor
 *              PinCount                - From GPIO descriptor
 *              PinList                 - From GPIO descriptor
 *              DeviceName              - The "ResourceSource" name
 *
 * RETURN:      None
 *
 * DESCRIPTION: External Interface.
 *              Save GPIO resource descriptor information.
 *              Creates new GPIO info blocks, one for each pin defined by the
 *              GPIO descriptor.
 *
 ******************************************************************************/

void
MpSaveGpioInfo(
    VOID*                   Op,
    VOID*                   Resource,
    UINT32                  PinCount,
    UINT16                  *PinList,
    char                    *DeviceName
)
{
    UNREFERENCED_PARAMETER((Op, Resource, PinCount, PinList, DeviceName));

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}

/*******************************************************************************
 *
 * FUNCTION:    MpSaveSerialInfo
 *
 * PARAMETERS:  Resource                - A Serial resource descriptor
 *              DeviceName              - The "ResourceSource" name.
 *
 * RETURN:      None
 *
 * DESCRIPTION: External Interface.
 *              Save serial resource descriptor information.
 *              Creates a new serial info block.
 *
 ******************************************************************************/

void
MpSaveSerialInfo(
    VOID*                   Op,
    VOID*                   Resource,
    char                    *DeviceName
)
{
    UNREFERENCED_PARAMETER((Op, Resource, DeviceName));

    LOG_FUNC_FAIL(__FUNCTION__, AE_ERROR);

    return;
}
