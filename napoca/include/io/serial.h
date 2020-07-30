/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file serial.h
*   @brief SERIAL - legacy serial (UART 16550A) functions
*
*/


#ifndef _SERIAL_H_
#define _SERIAL_H_

#include "core.h"

#define COM1              0x03F8                                     ///< UART serial COM port 1
#define COM2              0x02F8                                     ///< UART serial COM port 2
#define Baud600           192                                        ///< Baud-rate 600 bts (bits per second)
#define Baud1200          96                                         ///< Baud-rate 1200 bts (bits per second)
#define Baud2400          48                                         ///< Baud-rate 2400 bts (bits per second)
#define Baud4800          24                                         ///< Baud-rate 4800 bts (bits per second)
#define Baud9600          12                                         ///< Baud-rate 9600 bts (bits per second)
#define Baud19200         6                                          ///< Baud-rate 19200 bts (bits per second)
#define Baud38400         3                                          ///< Baud-rate 38400 bts (bits per second)
#define Baud57600         2                                          ///< Baud-rate 57600 bts (bits per second)
#define Baud115200        1                                          ///< Baud-rate 115200 bts (bits per second)

#define UART_LINE_STATUS_REGISTER                           5        ///< Port offset for UART line status register
#define UART_LINE_STATUS_REGISTER_DATA_READY                1        ///< This bit signifies that we have at least a byte of data ready to be read from UART
#define UART_DATA_REGISTER                                  0        ///< Port offset for UART data register

#define UART_THR                    0                                ///< Port offset from base port to UART Transmitter Holding Buffer Register (Write)
#define UART_RBR                    0                                ///< Port offset from base port to UART Receiver Buffer Register (Read)
#define UART_IER                    1                                ///< Port offset from base port to UART Interrupt Enable Register (Read/Write)
#define UART_IIR                    2                                ///< Port offset from base port to UART Interrupt Identification Register (Read)
#define UART_FCR                    2                                ///< Port offset from base port to UART FIFO Control Register (Write)
#define UART_LCR                    3                                ///< Port offset from base port to UART Line Control Register (Read/Write)
#define UART_MCR                    4                                ///< Port offset from base port to UART Modem Control Register (Read/Write)
#define UART_LSR                    5                                ///< Port offset from base port to UART Line Status Register (Read/Write)
#define UART_MSR                    6                                ///< Port offset from base port to UART Modem Status Register (Read/Write)
#define UART_SPR                    7                                ///< Port offset from base port to UART Scratch Register (Read/Write)

#define UART_DLL                    0                                ///< Port offset from base port to UART Divisor Latch Low Byte register (Read/Write)
#define UART_DLH                    1                                ///< Port offset from base port to UART Divisor Latch High Byte register (Read/Write)

#define UART_LCR_DLAB               0x80                             ///< Activate DLAB (Divisor Latch Access Bit), to be able to set up the baud-rate
#define UART_LCR_8BIT_WORD          0x03                             ///< UART 8 bits mode with no Parity and 1 Stop bit

#define UART_FCR_FIFO_EN            0x01                             ///< Enable and flush FIFO
#define UART_FCR_FIFO_RX_FLUSH      0x02                             ///< Clear receiver FIFO
#define UART_FCR_FIFO_TX_FLUSH      0x04                             ///< Clear transmit FIFO
#define UART_FCR_INIT_FIFO          (UART_FCR_FIFO_EN | UART_FCR_FIFO_RX_FLUSH | UART_FCR_FIFO_TX_FLUSH)  ///< Init FCR (enable, clear, flush FIFOs)

#define UART_MCR_OUT2               0x08                             ///< Enable Auxiliary Output 2
#define UART_MCR_RTS                0x02                             ///< Enable Request To Send
#define UART_MCR_DTR                0x01                             ///< Enable Data Terminal Ready
#define UART_MCR_DEF_INIT           (UART_MCR_OUT2 | UART_MCR_RTS | UART_MCR_DTR)   ///< Default MCR initializer

#define UART_LSR_THR_EMPTY          0x20                             ///< Empty Transmitter Holding Register bit
#define UART_LSR_TX_EMPTY           0x40                             ///< Empty Empty Data Holding Registers bit

#define UART_IIR_FIFOS_EN           0xC0                             ///< The current status of FIFO buffers is enabled

#define UART_OX952_ICR              0x5
#define UART_OX952_SEL_CPR          0x1
#define UART_OX952_SEL_CSR          0xC

#define SERIAL_MCS9900_VENDOR_ID     0x9710                          ///< Vendor id for Moschip 9900 PCI to Serial converter card
#define SERIAL_MCS9900_DEVICE_ID     0x9912                          ///< Device id for Moschip 9900 PCI to Serial converter card

#define OXFORD_PCIE952_CARD_VENDOR  0x1415                           ///< Vendor id for Oxford PCIE952 dual serial card
#define OXFORD_PCIE952_DUAL_SERIAL_CARD_DEVICE_ID_MASK 0xC100        ///< Device id MASK for Oxford PCIE952 dual serial card

/// @brief Enumeration of the supported serial interfaces
typedef enum {
    serialNone = 0,                             ///< No supported serial interface (only for verifications)
    serialOXPCIe952,                            ///< Oxford PCIE952 dual serial card interface
    serialMCS9900,                              ///< Moschip 9900 PCI to Serial converter card interface
    serialLegacy,                               ///< Legacy serial interface (COM ports)
} SERIAL_TYPE;

/// @brief Enumeration of the modes in which we can use the serial interfaces
typedef enum {
    serialUndefIo,                              ///< Undefined IO mode (only for verifications)
    serialPortIo,                               ///< Port IO mode
    serialMemIo                                 ///< Memory mapped IO mode
} SERIAL_IO_MODE;



///
/// @brief        Function prototype for looking up a PCI-to-PCI bridge device that exposes a certain Bus on the secondary side.
///
/// @param[in]    BusOfDev                         The exposed Bus number for the bridge device have to be found
/// @param[in, out] Bus                            The address where to store the found bridges bus number
/// @param[in, out] Dev                            The address where to store the found bridges device number
/// @param[in, out] Func                           The address where to store the found bridges function number
///
typedef
NTSTATUS (*FUNCPciLookupBridgeForPciBus) (
    _In_ WORD BusOfDev,
    _Inout_ WORD* Bus,
    _Inout_ WORD* Dev,
    _Inout_ WORD* Func
    );


///
/// @brief        Function prototype for powering on to D0 a certain PCI device defined by BFC.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
///
typedef
NTSTATUS (*FUNCPciPowerOnPciDevice) (
    _In_ BYTE Bus,
    _In_ BYTE Dev,
    _In_ BYTE Func
    );


///
/// @brief        Function prototype for reading 4 bytes from a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
///
typedef
DWORD (*FUNCInDword) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg
    );


///
/// @brief        Function prototype for reading 2 bytes from a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
///
typedef
WORD (*FUNCInWord) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg
    );


///
/// @brief        Function prototype for reading 1 byte from a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
///
typedef
BYTE (*FUNCInByte) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg
    );


///
/// @brief        Function prototype for writing 4 bytes to a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
/// @param[in]    Value                            The value to be written to the register
///
typedef
VOID (*FUNCOutDword) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg,
    _In_ DWORD Value
    );


///
/// @brief        Function prototype for writing 2 bytes to a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
/// @param[in]    Value                            The value to be written to the register
///
typedef
VOID (*FUNCOutWord) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg,
    _In_ WORD Value
    );


///
/// @brief        Function prototype for writing 1 byte to a certain register found in the PCI config space of the device given by BDF.
///
/// @param[in]    Bus                              The bus number of the device
/// @param[in]    Dev                              The device number of the device
/// @param[in]    Func                             The function number of the device
/// @param[in]    Reg                              The register offset inside the PCI config space
/// @param[in]    Value                            The value to be written to the register
///
typedef
VOID (*FUNCOutByte) (
    _In_ WORD Bus,
    _In_ WORD Dev,
    _In_ WORD Func,
    _In_ WORD Reg,
    _In_ BYTE Value
    );


///
/// @brief        Function prototype for internal serial error signaling to the outside world using the beeper to emit morse code.
///
/// @param[in]    Message                          The morse code to be emitted(character sequence of '.' and '_').
///
typedef
VOID (*FUNCMorse64) (
    _In_ CHAR *Message
    );


///
/// @brief        Function prototype for mapping in memory the physical address specified in the BAR of the Oxford module.
///
/// @param[in]    BarPa                           The physical address from the PCI BAR
///
typedef
PBYTE (*FUNCSetupOxfordModule) (
    _In_ QWORD BarPa
    );


///
/// @brief        Function prototype for a synchronized print function, used to print information during interface initialization, for other IO interfaces
///
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
typedef
NTSTATUS (*FUNCHvPrint)(
    _In_ CHAR *Buffer,
    ... );


///
/// @brief        Function prototype for a NOT synchronized print function, used to print information during interface initialization, for other IO interfaces
///
/// @param[in]    Buffer                           The buffer containing the format string of the message
/// @param[in]    ...                              A sequence of additional arguments, their interpretation depending on the format string in Buffer.
///
typedef
void (*FUNCHvPrintNoLock)(
    _In_ CHAR *Buffer,
    ... );

/// @brief Structure defining the high level serial interface needed by serial module to establish the low level interface
typedef struct _SERIAL_INTERFACE{
    BOOLEAN                         Initialized;                               ///< TRUE if this interface was initialized
    FUNCPciPowerOnPciDevice         PciPowerOnPciDevice;                       ///< Function pointer to the function which is capable of powering on a PCI device
    FUNCPciLookupBridgeForPciBus    PciLookupBridgeForPciBus;                  ///< Function which is capable of locating the PCI-to-PCI bridge that exposes on the secondary side the specified Bus

    FUNCSetupOxfordModule           SetupOxfordModule;                         ///< Function which maps in memory the physical address specified in BAR of the Oxford module

    FUNCMorse64                     DumpersMorse64;                            ///< Function capable of emitting morse code with the buzzer, used to emit noise if the serial is not working and by logging we cause an extreme slow-down or hang

    FUNCInDword                     InDword;                                   ///< Function capable of reading four bytes from the specified register from the given device's configuration space (BDF format)
    FUNCInWord                      InWord;                                    ///< Function capable of reading two bytes from the specified register from the given device's configuration space (BDF format)
    FUNCInByte                      InByte;                                    ///< Function capable of reading one byte from the specified register from the given device's configuration space (BDF format)

    FUNCOutDword                    OutDword;                                  ///< Function capable of writing four bytes from the specified register from the given device's configuration space (BDF format)
    FUNCOutWord                     OutWord;                                   ///< Function capable of writing two bytes from the specified register from the given device's configuration space (BDF format)
    FUNCOutByte                     OutByte;                                   ///< Function capable of writing one byte from the specified register from the given device's configuration space (BDF format)

    FUNCHvPrint                     SerHvPrint;                                ///< IO print function, used to print information during interface initialization, to print out for other IO interfaces
    FUNCHvPrintNoLock               SerHvPrintNoLock;                          ///< IO print function with no lock, used to print information during interface initialization, to print out for other IO interfaces
} SERIAL_INTERFACE;



///
/// @brief        Initialize a serial entry interface, either the primary serial port or by trying a lookup for all the known serial interfaces.
///
/// @param[in]    Port                             The port number for the primary serial (COM ports), if 0 a lookup is started for all the known serial interfaces
///
/// @returns      CX_STATUS_SUCCESS                - in case a serial entry interface has been initialized
/// @returns      CX_STATUS_INVALID_DEVICE_STATE   - in case the high level serial interface was not initialized
///
NTSTATUS
UartSerialInit(
    _In_ WORD Port
);



///
/// @brief        Verifies the given SERIAL_INTERFACE if it was initialized with everything needed for the serial support and confirms the initialization.
///
/// @param[in]    Interface                        The high-level serial interface.
///
/// @returns      CX_STATUS_SUCCESS                - in case everything is fine
/// @returns      CX_STATUS_INVALID_PARAMETER_X    - in case something is not initialized for the interface
///
NTSTATUS
UartInitInterface(
    _In_ SERIAL_INTERFACE *Interface
);



///
/// @brief        Returns the used serial entry interface type.
///
/// @returns      The serial entry type used or SERIAL_TYPE.serialNone if there is no serial active.
///
SERIAL_TYPE
UartGetUsedEntry(
    VOID
);



///
/// @brief        Verifies if serial entry interface is both initialized and enabled, and that the HV received
///               an input trough the serial interface which is available an ready to be read.
///
/// @returns      TRUE if an input is ready FALSE otherwise
///
BOOLEAN
UartSerialIsDataReady(
    void
);



///
/// @brief        Low level function offered for direct dumping trough the serial interface, should be used only for special purposes.
///
/// @param[in]    Buffer                           The buffer to be written
/// @param[in]    Length                           Length of the buffer in bytes
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_OPERATION_NOT_IMPLEMENTED - in case there is no implementation for writing to the current used serial entry interface
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the serial interface is not initialized
/// @returns      CX_STATUS_XXX                    - in case there are other problems during writing to the current serial interface
///
NTSTATUS
UartSerialWrite(
    _In_ CHAR  *Buffer,
    _In_ DWORD Length
);



///
/// @brief        Low level function offered for debug purposes, it offers the ability for the Hypervisor to read commands passed through
///               the serial interface.
///
/// @param[out]   Buffer                           Buffer where the text is read from the serial interface
/// @param[in]    MaxLength                        The maximum length in bytes of the buffer
/// @param[out]   Length                           The actual length of the message which was read
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_OPERATION_NOT_IMPLEMENTED - in case there is no implementation for reading from the current used serial entry interface
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the serial interface is not initialized
/// @returns      CX_STATUS_XXX                    - in case there are other problems during reading from the current serial interface
///
NTSTATUS
UartSerialRead(
    _Out_ CHAR *Buffer,
    _In_ WORD MaxLength,
    _Out_ WORD *Length
);


#endif // _SERIAL_H_

///@}