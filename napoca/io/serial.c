/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file serial.c
*   @brief SERIAL - legacy serial (UART 16550A) functions
*
*/

#include "napoca.h"
#include "io/serial.h"
#include "guests/pci_tools.h"
#include "kernel/time.h"
#include "guests/pci.h"


///
/// @brief        Function prototype for writing a message through the given port
///
/// @param[in]    Port                             The port of the serial entry interface where the writing has to happen
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
typedef
NTSTATUS (*SerialWrite)(
    _In_ QWORD Port,
    _In_ CHAR  *Buffer,
    _In_ DWORD Length
    );


///
/// @brief        Function prototype for reading a message through the given port
///
/// @param[in]    Port                             The port of the serial entry interface from where the reading has to happen
/// @param[out]   Buffer                           Buffer where the text is read from the serial interface
/// @param[in]    MaxLength                        The maximum length in bytes of the buffer
/// @param[out]   Length                           The actual length of the message which was read
///
typedef
NTSTATUS (*SerialRead) (
    _In_ QWORD Port,
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
    );


///
/// @brief        Function prototype for probing(verifying availability and support) for the serial entry interface.
///
/// @param[in]    VendorId                         VendorId of the device identified
/// @param[in]    DeviceId                         DeviceId of the device identified
/// @param[out]   Found                            TRUE if the device is available and supported (it works for us)
///
typedef
NTSTATUS (*SerialProbe) (
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
    );


///
/// @brief        Function prototype for Initializing this serial entry. In case of PCI connected devices
///               Bus Device and Function numbers are needed.
///
/// @param[in, out]    SerialEntry                 The serial entry interface to be initialized
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
///
typedef
NTSTATUS (*SerialInit) (
    _Inout_ VOID *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
    );


///
/// @brief        Function prototype for port verification before write operations for this serial entry
///
/// @param[in]    SerialEntry                      The serial entry interface to be checked
///
typedef
NTSTATUS (*SerialCheckPorts) (
    _In_ volatile VOID *SerialEntry
    );


///
/// @brief        Function prototype for checking if there is available data for read operation through the specified port
///
/// @param[in]    Port                             The port number for which to verify data availability
///
/// @returns      TRUE if there is data available for read, FALSE otherwise
///
typedef
BOOLEAN (*SerialIsDataReady) (
    _In_ QWORD Port
    );

/// @brief A serial entry containing all the necessary information about a serial interface in order to realize communication with it if available
typedef struct _SERIAL_ENTRY {
    SERIAL_TYPE         Type;        ///< Type of the serial entry
    SERIAL_IO_MODE      IoMode;      ///< Communication mode of the serial entry
    SerialProbe         Probe;       ///< Function for probing(verifying availability) this serial entry
    SerialInit          Init;        ///< Function for Initializing this serial entry
    SerialRead          Read;        ///< Function for reading a message through this serial entry
    SerialWrite         Write;       ///< Function for writing a message through this serial entry
    SerialIsDataReady   IsDataReady; ///< Function for checking if there is available data for read operation through this serial entry
    SerialCheckPorts    CheckPorts;  ///< Function for port verification before write operations for this serial entry
    QWORD               Port;        ///< The port used by Napoca
    QWORD               PortPa;      ///< Set on to the physical address of the MMIO space used by oxford card
    QWORD               PortSize;    ///< For oxford card, defines the size of the used port (MMIO)
    BYTE                Segment;     ///< PCIE segment number for this serial entry, only for PCI connected cards
    BYTE                Bus;         ///< PCIE bus number for this serial entry, only for PCI connected cards
    BYTE                Dev;         ///< PCIE device number for this serial entry, only for PCI connected cards
    BYTE                Func;        ///< PCIE function number for this serial entry, only for PCI connected cards
    WORD                VendorId;    ///< The serial entry vendor ID, only for PCI connected cards
    WORD                DeviceId;    ///< The serial entry device ID, only for PCI connected cards
}SERIAL_ENTRY;

static SERIAL_INTERFACE gSerIface = {0};                 ///< The high level serial interface needed by serial module(entry) to establish the low level interface

static DWORD gParentBridgeBase = 0;                      ///< The PCI Bridge IO space base (used for MOSCHIP serial card)
static DWORD gParentBridgeLimit = 0;                     ///< The PCI Bridge IO space limit (used for MOSCHIP serial card)

static volatile SERIAL_ENTRY *gUsedSerialEntry = NULL;   ///< The address of the used serial entry from the all known serial entries list


//
// short-hand defines for field offsets
//
#define PCI_BRIDGE_CONFIG_IO_BASE_HI        FIELD_OFFSET(PCI_CONFIG, PciBridge.IoBaseUpper16)
#define PCI_BRIDGE_CONFIG_IO_BASE           FIELD_OFFSET(PCI_CONFIG, PciBridge.IoBase)
#define PCI_BRIDGE_CONFIG_IO_LIMIT_HI       FIELD_OFFSET(PCI_CONFIG, PciBridge.IoLimitUpper16)
#define PCI_BRIDGE_CONFIG_IO_LIMIT          FIELD_OFFSET(PCI_CONFIG, PciBridge.IoLimit)
#define PCI_BRIDGE_CONFIG_MEMORY_BASE       FIELD_OFFSET(PCI_CONFIG, PciBridge.MemoryBase)
#define PCI_BRIDGE_CONFIG_MEMORY_LIMIT      FIELD_OFFSET(PCI_CONFIG, PciBridge.MemoryLimit)
#define PCI_CONFIG_BAR0                     FIELD_OFFSET(PCI_CONFIG, PciBridge.BarUnused)
#define PCI_CONFIG_COMMAND_REGISTER         FIELD_OFFSET(PCI_CONFIG, Header.Command)
#define PCI_CONFIG_CACHE_LINE_SIZE          FIELD_OFFSET(PCI_CONFIG, Header.CacheLineSize)


///
/// @brief        Generic smart read function for any UART based serial entry interface, which can read 1 byte both from IO and MMIO depending on
///               serial entry interfaces type.
///
/// @param[in]    SerialEntry                      The serial entry interface through which we read (needed for operation type)
/// @param[in]    Offset                           The offset from the base port
/// @param[out]   Value                            Address to a memory zone where we can write the byte read from UART
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if Value is an invalid pointer
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - if the serial entry interface has unknown IO mode specified
///
static
NTSTATUS
_UartRead(
    _In_ SERIAL_ENTRY *SerialEntry,
    _In_ WORD Offset,
    _Out_ BYTE *Value
);


///
/// @brief        Generic smart write function for any UART based serial entry interface, which can write 1 byte both through IO and MMIO depending on
///               serial entry interfaces type.
///
/// @param[in]    SerialEntry                      The serial entry interface through which we write (needed for operation type)
/// @param[in]    Offset                           The offset from the base port
/// @param[out]   Value                            The value to be written
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - if the serial entry interface has unknown IO mode specified
///
static
NTSTATUS
_UartWrite(
    _In_ SERIAL_ENTRY *SerialEntry,
    _In_ WORD Offset,
    _In_ BYTE Value
);


///
/// @brief        Probe MosChip MCS9900 UART (16450 mode).
///
/// @param[in]    VendorId                         The vendor id to probe
/// @param[in]    DeviceId                         The device id to probe
/// @param[out]   Found                            TRUE if found to match what we need, FALSE otherwise
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if VendorId is an invalid value
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if DeviceId is an invalid value
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if Found is an invalid pointer
///
static
NTSTATUS
_UartProbeMCS9900DualPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
);


///
/// @brief        Probe OXPCIe952 dual serial card.
///
/// @param[in]    VendorId                         The vendor id to probe
/// @param[in]    DeviceId                         The device id to probe
/// @param[out]   Found                            TRUE if found to match what we need, FALSE otherwise
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if VendorId is an invalid value
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if DeviceId is an invalid value
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if Found is an invalid pointer
/// @returns      CX_STATUS_DATA_NOT_FOUND         - if DeviceId is not exactly what we know, but the vendor id matches and the device mask is good
///
static
NTSTATUS
_UartProbeOXPCIe952DualPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
);


///
/// @brief        Init serial entry interface of MosChip MCS9900 UART (16450 mode).
///
/// @param[in, out] SerialEntry                    The serial entry interface which it describes it
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - if IoBase is smaller than IoLimit and we can't restore the bridge configuration
/// @returns      CX_STATUS_UNINITIALIZED_STATUS_VALUE - if the reprogram failed
///
static
NTSTATUS
_UartInitMCS9900DualPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
);


///
/// @brief        Init serial entry interface of OXPCIe952 dual serial card.
///
/// @param[in, out] SerialEntry                    The serial entry interface which it describes it
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
/// @returns      CX_STATUS_NOT_INITIALIZED        - if the SERIAL_INTERFACE is not complete for the Oxford module
/// @returns      CX_STATUS_UNEXPECTED_IO_ERROR    - if the PCI BAR of the device is not MMIO type or it is not configured and the
///                                                 parent bridge can't be found.
///
static
NTSTATUS
_UartInitOXPCIe952DualPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
);


///
/// @brief        Reads a message through the OXPCIe952 dual serial card.
///
/// @param[in]    Port                             The port of the serial entry interface from where the reading has to happen
/// @param[out]   Buffer                           Buffer where the text is read from the serial interface
/// @param[in]    MaxLength                        The maximum length in bytes of the buffer
/// @param[out]   Length                           The actual length of the message which was read
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if Buffer is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - if Length is an invalid pointer
///
static
NTSTATUS
_UartOXPCIe952Read(
    _In_ QWORD Port,
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
);


///
/// @brief        Writes a message through the OXPCIe952 dual serial cards port.
///
/// @param[in]    Port                             The port of the serial entry interface where the writing has to happen
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Port is 0
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if Buffer is an invalid pointer
///
static
NTSTATUS
_UartOXPCIe952Write(
    _In_ QWORD Port,
    _In_ CHAR  *Buffer,
    _In_ DWORD Length
);


///
/// @brief        Checks if there is available data for read operation through the specified port of the OXPCIe952 dual serial card.
///
/// @param[in]    Port                             The port number for which to verify data availability
///
/// @returns      TRUE if there is data available for read, FALSE otherwise
///
static
BOOLEAN
_UartInitOXPCIe952IsDataReady(
    _In_ QWORD Port
);


///
/// @brief        Probe Legacy 16550A UART COM port
///
/// @param[in]    VendorId                         Unreferenced
/// @param[in]    DeviceId                         Unreferenced
/// @param[out]   Found                            TRUE if it works, FALSE otherwise
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_3    - if Found is an invalid pointer
///
static
NTSTATUS
_UartProbeLegacyPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
);


///
/// @brief        Init serial entry interface of Legacy 16550A UART COM port
///
/// @param[in, out] SerialEntry                    The serial entry interface which it describes it
/// @param[in]    Bus                              Unreferenced
/// @param[in]    Dev                              Unreferenced
/// @param[in]    Func                             Unreferenced
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
///
static
NTSTATUS
_UartInitLegacyPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
);


///
/// @brief        Reads a message through the Legacy 16550A UART COM port
///
/// @param[in]    Port                             The port of the serial entry interface from where the reading has to happen
/// @param[out]   Buffer                           Buffer where the text is read from the serial interface
/// @param[in]    MaxLength                        The maximum length in bytes of the buffer
/// @param[out]   Length                           The actual length of the message which was read
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if Buffer is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - if Length is an invalid pointer
/// @returns      CX_STATUS_NOT_INITIALIZED        - if the Serial entry is not available
///
static
NTSTATUS
_UartLegacyRead(
    _In_ QWORD Port,
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
);


///
/// @brief        Writes a message through the Legacy 16550A UART COM port
///
/// @param[in]    Port                             The port of the serial entry interface where the writing has to happen
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Buffer is an invalid pointer
/// @returns      CX_STATUS_DEVICE_NOT_READY       - if the device is not ready for writing
/// @returns      CX_STATUS_NOT_INITIALIZED        - if the Serial entry is not available
///
static
NTSTATUS
_UartLegacyWrite(
    _In_ QWORD Port,
    _In_ CHAR  *Buffer,
    _In_ DWORD Length
);


///
/// @brief        Checks if there is available data for read operation through the specified port of the Legacy 16550A UART COM port
///
/// @param[in]    Port                             The port number for which to verify data availability
///
/// @returns      TRUE if there is data available for read, FALSE otherwise
///
static
BOOLEAN
_UartLegacyIsDataReady(
    _In_ QWORD Port
);


///
/// @brief        Custom write function, calls the current serial entry interfaces write function directly
///
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_OPERATION_NOT_IMPLEMENTED - if serial entry interface has no write function initialized
/// @returns      CX_STATUS_NOT_INITIALIZED        - if the Serial entry is not available or it has an invalid Port
///
static
NTSTATUS
_UartSerialWriteCustom(
    _In_ CHAR *Buffer,
    _In_ WORD Length
);

/// @brief All of the known serial entries/interfaces by us
static SERIAL_ENTRY gAllKnownSerialList[] = {
    {
        serialOXPCIe952,
        serialMemIo,
        _UartProbeOXPCIe952DualPort,
        _UartInitOXPCIe952DualPort,
        _UartOXPCIe952Read,
        _UartOXPCIe952Write,
        _UartInitOXPCIe952IsDataReady,
        NULL,
        0,0,0,0,0,0,0,0,0
    },
    {
        serialMCS9900,
        serialPortIo,
        _UartProbeMCS9900DualPort,
        _UartInitMCS9900DualPort,
        _UartLegacyRead,
        _UartLegacyWrite,
        _UartLegacyIsDataReady,
        NULL,
        0,0,0,0,0,0,0,0,0
    },
    {
        serialLegacy,
        serialPortIo,
        _UartProbeLegacyPort,
        _UartInitLegacyPort,
        _UartLegacyRead,
        _UartLegacyWrite,
        _UartLegacyIsDataReady,
        NULL,
        0,0,0,0,0,0,0,0,0
    },
};


///
/// @brief        Returns the list of all known serial entries
///
/// @returns      The address of the lists first element
///
static
__forceinline
SERIAL_ENTRY *
GetKnownSerialList(
    void
)
{
    return gAllKnownSerialList;
}


///
/// @brief        Returns the count of the list of all known serial entries
///
/// @returns      The length of the list
///
static
__forceinline
DWORD
GetKnownSerialListCount(
    void
)
{
    return sizeof(gAllKnownSerialList) / sizeof(SERIAL_ENTRY);
}

#define SERIAL_LIST     (GetKnownSerialList())         ///< Returns the list of all known serial entries
#define SERIAL_COUNT    GetKnownSerialListCount()      ///< Returns the count of the list of all known serial entries



static
NTSTATUS
_UartRead(
    _In_ SERIAL_ENTRY *SerialEntry,
    _In_ WORD Offset,
    _Out_ BYTE *Value
    )
{
    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_3;

    switch (SerialEntry->IoMode)
    {
        case serialMemIo:
        {
            BYTE *addr = (BYTE*)(SIZE_T)SerialEntry->Port + Offset;
            gSerIface.SerHvPrint("Reading from %p (offset 0x%x)\n", addr, Offset);
            *Value = *addr;
            break;
        }
        case serialPortIo:
        {
            WORD port = (WORD)SerialEntry->Port + Offset;
            gSerIface.SerHvPrint("Reading from 0x%x (offset 0x%x)\n", port, Offset);
            *Value = __inbyte(port);
            break;
        }
        default:
        {
            gSerIface.SerHvPrint("[ERROR] Invalid I/O mode [%d] in SerialEntry!", SerialEntry->IoMode);
            return CX_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartWrite(
    _In_ SERIAL_ENTRY *SerialEntry,
    _In_ WORD Offset,
    _In_ BYTE Value
    )
{
    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;

    switch (SerialEntry->IoMode)
    {
        case serialMemIo:
        {
            BYTE *addr = (BYTE*)(SIZE_T)SerialEntry->Port + Offset;
            *addr = Value;
            break;
        }
        case serialPortIo:
        {
            WORD port = (WORD)(SIZE_T)SerialEntry->Port + Offset;
            __outbyte(port, Value);
            break;
        }
        default:
        {
            gSerIface.SerHvPrint("[ERROR] Invalid I/O mode [%d] in SerialEntry!", SerialEntry->IoMode);
            return CX_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    return CX_STATUS_SUCCESS;
}


///
/// @brief        Default Initializer function for any UART supported serial entry interface.
///
/// @param[in]    SerialEntry                      The serial entry interface used
/// @param[in]    DLL                              The  Divisor Latch Low Byte register value (Baud-Rate specification)
/// @param[in]    DLH                              The Divisor Latch High Byte register value (Baud-Rate specification)
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if SerialEntry is an invalid pointer
///
static
NTSTATUS
_UartDefaultInit(
    _In_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE DLL,
    _In_ BYTE DLH
    )
{
    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;

    _UartWrite(SerialEntry, UART_IER, 0);                  // disable interrupts
    _UartWrite(SerialEntry, UART_LCR, UART_LCR_DLAB);      // set DLAB ON
    _UartWrite(SerialEntry, UART_DLL, DLL);                // set DLL
    _UartWrite(SerialEntry, UART_DLH, DLH);                // set DLH
    _UartWrite(SerialEntry, UART_LCR, UART_LCR_8BIT_WORD); // 8 Bits, No Parity, 1 Stop Bit
    _UartWrite(SerialEntry, UART_FCR, UART_FCR_INIT_FIFO); // enable + flush FIFO
    _UartWrite(SerialEntry, UART_MCR, UART_MCR_DEF_INIT);  // turn on DTR, RTS, and OUT2

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartProbeMCS9900DualPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
    )
{
    if (VendorId == 0xFFFF || VendorId == 0) return CX_STATUS_INVALID_PARAMETER_1;
    if (DeviceId == 0xFFFF || DeviceId == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Found) return CX_STATUS_INVALID_PARAMETER_3;

    //
    // try to detect MosChip MCS9900 UART (16450 mode) on PCI Express Bus
    //

    *Found = FALSE;
    if ((VendorId == SERIAL_MCS9900_VENDOR_ID) &&     // MosChip
        (DeviceId == SERIAL_MCS9900_DEVICE_ID))       // MCS9900 in 2S+1P mode (9912)
    {
        *Found = TRUE;
        gSerIface.SerHvPrintNoLock("[DEBUG] MCS9900 serial port found\n");
    }

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartProbeOXPCIe952DualPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
    )
{
    if (VendorId == 0xFFFF || VendorId == 0) return CX_STATUS_INVALID_PARAMETER_1;
    if (DeviceId == 0xFFFF || DeviceId == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Found) return CX_STATUS_INVALID_PARAMETER_3;

    *Found = FALSE;
    if ((VendorId == OXFORD_PCIE952_CARD_VENDOR) &&             // Oxford Semiconductor Ltd
        ((DeviceId & 0xFF00) == OXFORD_PCIE952_DUAL_SERIAL_CARD_DEVICE_ID_MASK))    // OXPCIe952 dual serial card
    {
        struct OXPCIE952_DEVICEID_SETTINGS{
            union {
                WORD DeviceId;
                struct{
                    WORD FunctionNumber : 2;
                    WORD GPIO_EN : 1;
                    WORD UART_EN : 1;
                    WORD MODE : 3;
                    WORD Udef : 9;
                };
            };
        } OxPciSettings;

        gSerIface.SerHvPrintNoLock("[SERIAL-INIT] OXPCIe952 card (0x%04X, 0x%04X) found on PCI\n", VendorId, DeviceId);

        // Check device settings
        OxPciSettings.DeviceId = DeviceId;
        gSerIface.SerHvPrintNoLock("   * OXPCIe952 features:\n");
        gSerIface.SerHvPrintNoLock("       - UART_EN : %d\n", OxPciSettings.UART_EN);
        gSerIface.SerHvPrintNoLock("       - GPIO_EN : %d\n", OxPciSettings.GPIO_EN);
        gSerIface.SerHvPrintNoLock("       - MODE    : %d\n", OxPciSettings.MODE);
        gSerIface.SerHvPrintNoLock("       - Func    : %d\n", OxPciSettings.FunctionNumber);

        if (DeviceId != 0xC158 && DeviceId != 0xC138)
        {
            gSerIface.SerHvPrintNoLock( "[SERIAL-INIT] Found VendorId: 0x%04X, DeviceId: 0x%04X (expected: 0xC158)\n", VendorId, DeviceId );
            return CX_STATUS_DATA_NOT_FOUND;
        }

        *Found = TRUE;
    }

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartProbeLegacyPort(
    _In_ WORD VendorId,
    _In_ WORD DeviceId,
    _Out_ BOOLEAN *Found
    )
{
    if (!Found) return CX_STATUS_INVALID_PARAMETER_3;

    UNREFERENCED_PARAMETER(VendorId);
    UNREFERENCED_PARAMETER(DeviceId);

    *Found = FALSE;

    // we use a trick: try to enable 16550A UART FIFOs using FCR and check if they show up as validly enabled under IIR,
    // then try to disable FIFOs and check that they show up as disabled under IIR
    __outbyte(COM1 + UART_FCR, 0xC7);                 // FCR (FIFO Control Register), enable FIFO with trigger at 14 chars
    if ((__inbyte(COM1 + UART_FCR) & UART_IIR_FIFOS_EN) == UART_IIR_FIFOS_EN)   // IIR (Interrupt Identification Register), 0xC0 means 'FIFO Enabled'
    {
        __outbyte(COM1 + UART_FCR, 0xC6);
        if ((__inbyte(COM1 + UART_FCR) & UART_IIR_FIFOS_EN) == 0x00)
        {
            gSerIface.SerHvPrintNoLock("[DEBUG] 16550A UART found at legacy COM1 0x3F8 (FIFO enable / disable test passed)\n");

            *Found = TRUE;
            return CX_STATUS_SUCCESS;
        }
    }

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartInitLegacyPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
    )
{
    WORD divisor = 0;

    UNREFERENCED_PARAMETER(Bus);
    UNREFERENCED_PARAMETER(Dev);
    UNREFERENCED_PARAMETER(Func);

    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;

    SerialEntry->IoMode = serialPortIo;
    divisor = Baud115200;                                 // 115,200 bps
    SerialEntry->Port = COM1;
    _UartDefaultInit(SerialEntry, divisor & 0xFF, (divisor >> 8) & 0xFF);

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartInitMCS9900DualPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
    )
{
    NTSTATUS status;
    DWORD bar0 = 0, cmd = 0;
    DWORD base = 0;
    WORD port = 0;
    WORD divisor = 0;

    WORD bus = 0, dev = 0, func = 0;

    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;

    status = gSerIface.PciLookupBridgeForPciBus(Bus, &bus, &dev, &func);
    if (!NT_SUCCESS(status))
    {
        gSerIface.SerHvPrintNoLock("[ERROR] Parent Bridge not found\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    // check if the bridge has IO ports configured
    {
        WORD commandRegister = 0;
        DWORD iobase = (((gSerIface.InWord(bus, dev, func, PCI_BRIDGE_CONFIG_IO_BASE_HI) << 16) | (gSerIface.InByte(bus, dev, func, PCI_BRIDGE_CONFIG_IO_BASE) << 8)) & 0xFFFFF000);
        DWORD ioLimit = (((gSerIface.InWord(bus, dev, func, PCI_BRIDGE_CONFIG_IO_LIMIT_HI) << 16) | (gSerIface.InByte(bus, dev, func, PCI_BRIDGE_CONFIG_IO_LIMIT) << 8)) & 0xFFFFF000) | 0xFFF;

        if (ioLimit < iobase)
        {
            if (gParentBridgeBase == 0 || gParentBridgeLimit == 0)
            {
                gSerIface.SerHvPrintNoLock("Cannot restore BRIDGE config\n");
                return CX_STATUS_INVALID_INTERNAL_STATE;
            }

            // invalid bridge configured, try reconfigure
            gSerIface.SerHvPrintNoLock("[ERROR] Parent PORTIO not configured\n");

            // disable MMIO & mastering
            commandRegister |= (0xFFF8 & gSerIface.InWord(bus, dev, func, PCI_CONFIG_COMMAND_REGISTER));
            commandRegister |= 0x4; // mastering enable
            gSerIface.OutWord(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, commandRegister);

            gSerIface.SerHvPrintNoLock("Will set BAR: 0x%04X and Limit: 0x%04X\n", gParentBridgeBase, gParentBridgeLimit);

            // setup PORTIO base & limit
            gSerIface.OutByte(bus, dev, func, PCI_BRIDGE_CONFIG_IO_BASE, ((gParentBridgeBase >> 8) & 0xFF));
            gSerIface.OutWord(bus, dev, func, PCI_BRIDGE_CONFIG_IO_BASE_HI, (gParentBridgeBase >> 16) & 0xFFFF);

            gSerIface.OutByte(bus, dev, func, PCI_BRIDGE_CONFIG_IO_LIMIT, (((gParentBridgeLimit & 0xFFFFF000) >> 8) & 0xFF));
            gSerIface.OutWord(bus, dev, func, PCI_BRIDGE_CONFIG_IO_BASE_HI, ((gParentBridgeLimit & 0xFFFFF000) >> 16) & 0xFFFF);

            // done
            commandRegister |= (0xFFF8 & gSerIface.InWord(bus, dev, func, PCI_CONFIG_COMMAND_REGISTER));
            commandRegister |= 0x4 | 0x1; // mastering enable & PORTIO enable
            gSerIface.OutWord(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, commandRegister);
        }
        else
        {
            gParentBridgeBase = iobase;
            gParentBridgeLimit = ioLimit;
        }
    }

    bar0 = 0;

    // reprogram the BASE I/O reg to def values if zero
    {
        bar0 = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_BAR0);
        base = (bar0 & 0x0000FFFC);

        {
            gSerIface.SerHvPrintNoLock("[DEBUG] MCS9900 serial port found at PCI Bus %d, Dev %d, Func %d with I/O base ZERO ==> will reprogram (for PG DEBUG)\n", Bus, Dev, Func);

            // we need to locate bridge and do a +0x20 / +0x30 from the address range exposed through the bridge
            base = gParentBridgeBase + 0x20;     // default I/O base
            bar0 = base | 0x1;

            PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_BAR0, bar0);

            // also enable I/O, Mem and BusMaster, then also set cache line size
            PciConfigOutWord(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, 0x0007);

            PciConfigOutByte(Bus, Dev, Func, PCI_CONFIG_CACHE_LINE_SIZE, 0x0010); // 0x0C - PCI reg CACHE LINE SIZE

            // check we done it right
            bar0 = PciConfigInWord(Bus, Dev, Func, PCI_CONFIG_BAR0);// 0x10 - PCI reg BAR #0

            base = (bar0 & 0x0000FFFC);

            if (0x0000 == base)
            {
                gSerIface.SerHvPrintNoLock("[DEBUG] oops, reprogramm failed :-(\n");
                return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
            }
        }
    }

    // validate and decode I/O Space BAR layout
    if ((bar0 & 0x3) == 0x1)
    {
        gSerIface.PciPowerOnPciDevice(Bus, Dev, Func);

        base = (bar0 & 0x0000FFFC);

        gSerIface.SerHvPrintNoLock("[DEBUG] MCS9900 serial port found at PCI Bus %d, Dev %d, Func %d with I/O base 0x%04x (for PG DEBUG)\n", Bus, Dev, Func, base);

        // now, we need to enable it (read PCI Command register and enable I/O response)

        cmd = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER); // 0x04 - PCI cmd COMMAND

        cmd |= 0x0001;      // enable device response to I/O space
        cmd |= 0x0400;      // disable device capability to generate interrupts

        PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, cmd); // 0x04 - PCI cmd COMMAND

        // now, the device shall be up & running
        port = (WORD)base;
        SerialEntry->Port = port;
        SerialEntry->Segment = 0;
        SerialEntry->Bus = Bus;
        SerialEntry->Dev = Dev;
        SerialEntry->Func = Func;
    }

    SerialEntry->IoMode = serialPortIo;
    divisor = Baud115200;                     // 115,200 bps
    _UartDefaultInit(SerialEntry, divisor & 0xFF, (divisor >> 8) & 0xFF);

    SerialEntry->Segment = 0;
    SerialEntry->Bus = Bus;
    SerialEntry->Dev = Dev;
    SerialEntry->Func = Func;

    return CX_STATUS_SUCCESS;
}


///
/// @brief        Special initializer for Oxford Cards, must be called before the default UartInit function
///
/// @param[in]    PortBaseAddr                     Virtual Address decoded from the oxford module for MMIO data space
///
static
VOID
_SetupOXPCIe952UARTPort(
    _In_ BYTE *PortBaseAddr
    )
{
    // reset the UART
    *(PortBaseAddr + 0x07) = UART_OX952_SEL_CSR;    // select the CSR - page 26
    *(PortBaseAddr + UART_OX952_ICR) = 0;           // write 0 to CSR, resetting the UART

    // quirky BAUD rate, requires non-default CPR/CPR2/TPR for 115200
    *(PortBaseAddr + 0x07) = UART_OX952_SEL_CPR;    // select the CPR
    *(PortBaseAddr + UART_OX952_ICR) = 0x20;        // set CPR to 00100/000 (page 59)
    // when CPR is set, CPR2 defaults to 0; TPR is 0 after reset
}



static
BOOLEAN
_UartInitOXPCIe952IsDataReady(
    _In_ QWORD Port
    )
{
    volatile BYTE *portAddr = (BYTE*)(SIZE_T)Port;

    return ((*( portAddr + 5) & 1) != 0);
}



static
NTSTATUS
_UartInitOXPCIe952DualPort(
    _Inout_ SERIAL_ENTRY *SerialEntry,
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
    )
{
    NTSTATUS status;
    DWORD bar, cmd, barsize;
    BYTE *serialBarVa = 0;
    QWORD serialBarPa = 0;
    QWORD serialBarPaSize = 0;

    if (!SerialEntry) return CX_STATUS_INVALID_PARAMETER_1;
    if (!gSerIface.SetupOxfordModule) return CX_STATUS_NOT_INITIALIZED;

    gSerIface.PciPowerOnPciDevice(Bus, Dev, Func);

    // read BAR0
    bar = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_BAR0); // 0x10 - PCI cmd BAR #0
    if ((bar & 0x1) == 1)
    {
        gSerIface.SerHvPrintNoLock("[ERROR] BAR0 expected to be used for MEMIO\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    // get size
    gSerIface.OutDword(Bus, Dev, Func, PCI_CONFIG_BAR0, (DWORD)-1);
    barsize = gSerIface.InDword(Bus, Dev, Func, PCI_CONFIG_BAR0);
    barsize = (((~barsize) | 0xF) + 1) & 0xFFFFFFFF;

    // set BAR0 back
    gSerIface.OutDword(Bus, Dev, Func, PCI_CONFIG_BAR0, bar);

    if ((bar & (~0x3)) == 0)
    {
        WORD bus = 0, dev = 0, func = 0;

        gSerIface.SerHvPrintNoLock("[ERROR] Oxford BAR0 for MEMIO not configured\n");
        status = gSerIface.PciLookupBridgeForPciBus(Bus, &bus, &dev, &func);
        if (!NT_SUCCESS(status))
        {
            gSerIface.SerHvPrintNoLock("[ERROR] Parent Bridge not found\n");
            return CX_STATUS_UNEXPECTED_IO_ERROR;
        }

        bar = (gSerIface.InWord(bus, dev, func, 0x1C) & 0xFFF0) << 16;
        if (bar == 0)
        {
            WORD commandRegister = 0;

            gSerIface.SerHvPrintNoLock("[ERROR] Parent BAR0 for MEMIO not configured\n");

            bar = (DWORD)serialBarPa;
            barsize = (DWORD)serialBarPaSize;

            // setup parent bridge base address and limit

            // disable MMIO & mastering
            commandRegister |= (0xFFF8 & gSerIface.InWord(bus, dev, func, PCI_CONFIG_COMMAND_REGISTER));
            commandRegister |= 0x4 | 0x2; // mastering enable & MEMIO enable
            gSerIface.OutWord(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, commandRegister);

            gSerIface.SerHvPrintNoLock("Will set BAR: 0x%04X and Limit: 0x%04X\n", bar, barsize);

            // setup MMIO base & limit
            gSerIface.OutWord(bus, dev, func, PCI_BRIDGE_CONFIG_MEMORY_BASE, (WORD)(bar >> 16));
            gSerIface.OutWord(bus, dev, func, PCI_BRIDGE_CONFIG_MEMORY_LIMIT, (WORD)((bar + barsize) >> 16));

            // done
            commandRegister |= (0xFFF8 & gSerIface.InWord(bus, dev, func, PCI_CONFIG_COMMAND_REGISTER));
            commandRegister |= 0x4 | 0x2; // mastering enable & MEMIO enable
            gSerIface.OutWord(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, commandRegister);
        }

        gSerIface.SerHvPrintNoLock("[SERIAL-INIT] Bar0 at 0x%08X\n", bar);

        // initialize the device - disable MEM-IO
        cmd = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER); // 0x04 - PCI cmd COMMAND

        cmd &= ~0x0002;      // enable device response to Memory Space space

        PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, cmd);

        // write new BAR0
        PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_BAR0, bar); // 0x10 - PCI cmd BAR #0

        // initialize the device - enable MEM-IO
        cmd = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER);

        cmd |= 0x0002;      // enable device response to Memory Space space
        PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, cmd);

        serialBarPa = (bar & 0xfffff000);
        serialBarPaSize = (barsize & 0xfffff000);
    }
    else
    {
        gSerIface.SerHvPrintNoLock("[SERIAL-INIT] Bar0 at 0x%08X\n", bar);

        // initialize the device - enable MEM-IO
        cmd = PciConfigInDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER);

        cmd |= 0x0002;      // enable device response to Memory Space space

        PciConfigOutDword(Bus, Dev, Func, PCI_CONFIG_COMMAND_REGISTER, cmd);

        serialBarPa = (bar & 0xfffff000);
        serialBarPaSize = (barsize & 0xfffff000);
    }

    serialBarVa = gSerIface.SetupOxfordModule(serialBarPa);

    if (*(PDWORD)serialBarVa != 0x07000200)
    {
        gSerIface.SerHvPrintNoLock("[ERROR] Classcode & RevisionID don't match (current: 0x%08X, expected: 0x07000200\n", *(PDWORD)serialBarVa);
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    // Global UART IRQ Enable set to 0
    *(DWORD*)(serialBarVa + 0xC) = 0;

    // Global UART IRQ Disable set to 3
    *(DWORD*)(serialBarVa + 0x10) = 3;

    SerialEntry->IoMode = serialMemIo;

    _SetupOXPCIe952UARTPort(serialBarVa + 0x1000);
    SerialEntry->Port = (QWORD)serialBarVa + 0x1000;
    _UartDefaultInit(SerialEntry, 0x22, 0);

    SerialEntry->PortPa = serialBarPa;
    SerialEntry->PortSize = serialBarPaSize;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
UartInitInterface(
    _In_ SERIAL_INTERFACE *Interface
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    gSerIface = *Interface;

    // check if all needed functions are set
    if (!gSerIface.PciPowerOnPciDevice) return CX_STATUS_INVALID_PARAMETER_1;

    // SetupOxfordModule is optional
    if (!gSerIface.DumpersMorse64) return CX_STATUS_INVALID_PARAMETER_4;

    if (!gSerIface.InDword) return CX_STATUS_INVALID_PARAMETER_5;

    if (!gSerIface.InWord) return CX_STATUS_INVALID_PARAMETER_6;

    if (!gSerIface.InByte) return CX_STATUS_INVALID_PARAMETER_7;

    if (!gSerIface.OutDword) return CX_STATUS_INVALID_PARAMETER_8;

    if (!gSerIface.OutWord) return CX_STATUS_INVALID_PARAMETER_9;

    if (!gSerIface.OutByte) return CX_STATUS_INVALID_PARAMETER_10;

    if (!gSerIface.SerHvPrint) return CX_STATUS_INVALID_PARAMETER_11;

    if (!gSerIface.SerHvPrintNoLock) return CX_STATUS_INVALID_PARAMETER_12;

    gSerIface.Initialized = TRUE;

    return status;
}



NTSTATUS
UartSerialInit(
    _In_ WORD Port
    )
{
    NTSTATUS status;
    DWORD j = 0;
    BOOLEAN found = FALSE;
    WORD bus = 0, dev = 0, func = 0;
    WORD divisor = 0;
    SERIAL_ENTRY *serialEntry = NULL;

    if (!gSerIface.Initialized) return CX_STATUS_INVALID_DEVICE_STATE;

    // are we in forced lookup state?
    if (Port != 0)
    {
        // init primary port
        serialEntry = &SERIAL_LIST[0];
        serialEntry->Port = Port;
        serialEntry->IoMode = serialPortIo;
        divisor = Baud115200;                     // 115,200 bps
        _UartDefaultInit(serialEntry, divisor & 0xFF, (divisor >> 8) & 0xFF);

        gUsedSerialEntry = serialEntry;

        return CX_STATUS_SUCCESS;
    }
    else
    {
        found = FALSE;

        for (j = 0; j < SERIAL_COUNT && FALSE == found; j++)
        {
            for (bus = 0; bus <= 255 && FALSE == found; bus++)
            {
                for (dev = 0; dev <= 31 && FALSE == found; dev++)
                {

                    DWORD vendAndDev;
                    WORD vendorId = 0;
                    WORD deviceId = 0;

                    serialEntry = &SERIAL_LIST[j];

                    vendAndDev = PciConfigInDword(bus, dev, func, 0x00);

                    if ((vendAndDev & 0xFFFF) == 0xFFFF)
                    {
                        continue;
                    }

                    vendorId = (vendAndDev & 0xFFFF);
                    deviceId = ((vendAndDev >> 16) & 0xFFFF);

                    status = SERIAL_LIST[j].Probe(vendorId, deviceId, &found);
                    if (!_SUCCESS(status) || !found)
                    {
                        continue;
                    }

                    serialEntry->DeviceId = deviceId;
                    serialEntry->VendorId = vendorId;
                    serialEntry->Segment = 0;
                    serialEntry->Bus = (BYTE)bus;
                    serialEntry->Dev = (BYTE)dev;
                    serialEntry->Func = (BYTE)func;

                    gSerIface.SerHvPrintNoLock("Found serial device VendorId: 0x%04X DeviceId: 0x%04X\n", vendorId, deviceId);

                    status = SERIAL_LIST[j].Init(&SERIAL_LIST[j], (BYTE)bus, (BYTE)dev, (BYTE)func);
                    if (!_SUCCESS(status))
                    {
                        found = FALSE;
                        gSerIface.SerHvPrintNoLock("[ERROR] Init function for serial config %d failed, status = 0x%08X\n", j, status);

                        memset(serialEntry, 0, sizeof(SERIAL_ENTRY));

                        continue;
                    }


                    gSerialInited = TRUE;

                    _UartSerialWriteCustom("[DEBUG] UART1\n", sizeof("[DEBUG] UART1\n"));

                    if (serialEntry && serialEntry->Port != 0)
                    {
                        gSerIface.SerHvPrintNoLock("[DEBUG] SERIAL INITED at 0x%04x\n", serialEntry->Port);
                    }

                    gUsedSerialEntry = serialEntry;

                    goto done;
                }
            }
        }

        if (!found)
        {
            gSerIface.SerHvPrintNoLock("Serial device not found\n");
        }
    }

done:
    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartLegacyWrite(
    _In_ QWORD Port,
    _In_ CHAR *Buffer,
    _In_ DWORD Length
    )
{
    NTSTATUS status;
    BOOLEAN fail;
    QWORD timeout;
    DWORD i;
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    fail = FALSE;
    timeout = 0;

    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_1;
    if (!serialEntry) return CX_STATUS_NOT_INITIALIZED;

    for (i = 0; i < Length; i++)
    {
        //
        // check the state of the LSR.Empty Transmitter Holding Register (bit 5) or LSR.Empty Data Holding Registers (bit 6) from LSR (base + 5)
        //
        fail = FALSE;
        timeout = HvApproximateTimeGuardFast(2 * ONE_SECOND_IN_MICROSECONDS);  // 2 seconds

        while ((__inbyte((WORD)(Port + UART_LSR)) & (UART_LSR_TX_EMPTY | UART_LSR_THR_EMPTY)) == 0)
        {
            if (HvTimeout(timeout))
            {
                fail = TRUE;
                break;
            }
            _mm_pause();
        }

        // handle serial I/O failure (hangup / freeze)
        if (fail)
        {
            // somehow try to beep / signal the issue
            gSerIface.DumpersMorse64("-- . .-. .-. -.--  -.-. .... .-. .. ... - -- .- ...");
        }

        __outbyte((WORD)Port, Buffer[i]);
    }

    if (fail)
    {
        status = CX_STATUS_DEVICE_NOT_READY;
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}



static
NTSTATUS
_UartSerialWriteCustom(
    _In_ CHAR *Buffer,
    _In_ WORD Length
    )
{
    NTSTATUS status;
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!serialEntry) return CX_STATUS_NOT_INITIALIZED;
    if (!serialEntry->Write) return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    if (serialEntry->Port == 0) return CX_STATUS_NOT_INITIALIZED;

    status = serialEntry->Write(serialEntry->Port, Buffer, Length);

    return status;
}



//
// _UartSerialCheckDataReady - returns !=0 if some data was received and is available
//
static
BOOLEAN
_UartLegacyIsDataReady(
    _In_ QWORD Port
    )
{
    BYTE lineStatus;

    if (!gUsedSerialEntry) return FALSE;

    lineStatus = __inbyte((WORD)(Port + UART_LINE_STATUS_REGISTER));

    return ((lineStatus & UART_LINE_STATUS_REGISTER_DATA_READY) != 0);
}



static
NTSTATUS
_UartLegacyRead(
    _In_ QWORD Port,
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
    )
{
    WORD bufferIndex = 0;
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Length) return CX_STATUS_INVALID_PARAMETER_4;
    if (!serialEntry) return CX_STATUS_NOT_INITIALIZED;

    // read data until we would have to wait before another byte is available
    while (serialEntry->IsDataReady(Port) && (bufferIndex < MaxLength) )
    {
        Buffer[bufferIndex] = __inbyte((WORD)(Port + UART_DATA_REGISTER));
        bufferIndex++;
    }

    *Length = bufferIndex;

    return CX_STATUS_SUCCESS;
}


static
NTSTATUS
_UartOXPCIe952Read(
    _In_ QWORD Port,
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
    )
{
    WORD bufferIndex = 0;
    volatile BYTE *portAddr = (BYTE*)(SIZE_T)Port;

    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Length) return CX_STATUS_INVALID_PARAMETER_4;

    // clear RTS bit in MCR
    *(portAddr + 4) &= ~0x02;

    // read data until we would have to wait before another byte is available
    while ((bufferIndex < MaxLength) && (0 != (*( portAddr + 5 ) & 1)) )
    {
        Buffer[bufferIndex] = *portAddr;
        bufferIndex++;
    }

    // check overrun
    if (*(portAddr + 5) & 0x02) gSerIface.SerHvPrint("[WARNING] Buffer overrun on Oxford serial port!");

    // set RTS bit in MCR
    *(portAddr + 4) |= 0x02;

    *Length = bufferIndex;

    return CX_STATUS_SUCCESS;
}



static
NTSTATUS
_UartOXPCIe952Write(
    _In_ QWORD Port,
    _In_ CHAR *Buffer,
    _In_ DWORD Length
    )
{
    DWORD i;

    volatile BYTE *portAddr = (BYTE*)(SIZE_T)Port;

    if (!Port) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Buffer) return CX_STATUS_INVALID_PARAMETER_2;

    for (i = 0; i < Length; i++)
    {
        // wait for THR to become empty
        while ((*(portAddr+5) & 0x20) == 0);

        // we have CTS, send the char
        *portAddr = Buffer[i];
    }

    return CX_STATUS_SUCCESS;
}



NTSTATUS
UartSerialWrite(
    _In_ CHAR *Buffer,
    _In_ DWORD Length
    )
{
    NTSTATUS status;
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!serialEntry) return CX_STATUS_NOT_INITIALIZED;
    if (!serialEntry->Write) return CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    if (serialEntry->Port == 0) return CX_STATUS_NOT_INITIALIZED;

    if (serialEntry->CheckPorts != NULL)
    {
        status = serialEntry->CheckPorts(serialEntry);
        if (!NT_SUCCESS(status)) return status;
    }

    status = serialEntry->Write(serialEntry->Port, Buffer, Length);

    return status;
}



NTSTATUS
UartSerialRead(
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
    )
{
    NTSTATUS status;
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!serialEntry) return CX_STATUS_NOT_INITIALIZED;
    if (!serialEntry->Read) return CX_STATUS_OPERATION_NOT_IMPLEMENTED;

    status = serialEntry->Read(serialEntry->Port, Buffer, MaxLength, Length);

    return status;
}



BOOLEAN
UartSerialIsDataReady(
    void
    )
{
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!serialEntry) return FALSE;
    if (!serialEntry->IsDataReady) return FALSE;

    if (serialEntry->CheckPorts != NULL)
    {
        NTSTATUS status = serialEntry->CheckPorts(serialEntry);
        if (!NT_SUCCESS(status)) return FALSE;
    }

    return serialEntry->IsDataReady(serialEntry->Port);
}



SERIAL_TYPE
UartGetUsedEntry(
    VOID
    )
{
    volatile SERIAL_ENTRY *serialEntry = gUsedSerialEntry;

    if (!serialEntry) return serialNone;

    return serialEntry->Type;
}

///@}