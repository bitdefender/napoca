/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// PCI - PCI / PCI Express parsing and virtualization

#ifndef _PCI_H_
#define _PCI_H_

#include "core.h"
#include "kernel/spinlock.h"

#define MAX_MEMORY_BAR_RECONFIGURATIONS     64 ///< The maximum number of saved PCI BAR information

/// @brief Generic structure for PCI BAR reconfiguration saving for hibernate restoration purposes. Will be guarded by the Pci scanlock
typedef struct _PCI_BAR_RECONF_INFO{
    struct {
        CX_UINT64       BarAddress;                      ///< The decoded address from a BAR
        CX_UINT64       Size;                            ///< The size of the decoded address from a BAR
    } Reconfigurations[MAX_MEMORY_BAR_RECONFIGURATIONS]; ///< The list of the saved BARs
    CX_UINT32           EntryCount;                      ///< The count of the saved BARs
} PCI_BAR_RECONF_INFO;


typedef struct _PCI_SYSTEM PCI_SYSTEM;

/// \addtogroup hooks
/// @{

/// @brief Structure used to describe a PCI function range
typedef struct _PCICFG_ID
{
    CX_UINT16 Segment;  ///< Segment number of the function
    CX_UINT16 Bus;      ///< Bus number of the function
    CX_UINT16 Device;   ///< Device number of the function
    CX_UINT16 Function; ///< Function number of the function
} PCICFG_ID;

/// @brief Structure used to pass relevant information to PCI config space hooks
typedef struct _PCICFG_CONTEXT
{
    PCICFG_ID PciId;        ///< The PCI Id of the hook
    CX_VOID *Context;       ///< The optional data registered with the callback
    CX_BOOL IsMmioAndNotIo; ///< TRUE if the access happened through MMIO, FALSE in case of an I/O access
} PCICFG_CONTEXT;

/// @brief The callback prototype for read operations on a hooked PCI configuration space
///
/// @param[in]  Offset          The exact I/O port OR Address on which the read was intended to be executed
/// @param[in]  Length          The length of the operation
/// @param[out] Value           The value that will be seen by the guest
/// @param[in]  PciCfgContext   Relevant data about the operation, including the Context, registered when the hook was set
typedef CX_STATUS (*PFUNC_DevReadPciConfig)(_In_ CX_UINT16 Offset, _In_ CX_UINT16 Length, _Out_ CX_UINT8 *Value, _In_ PCICFG_CONTEXT* PciCfgContext);
/// @brief The callback prototype for write operations on a hooked PCI configuration space
///
/// @param[in]  Offset          The exact I/O port OR Address on which the write was intended to be executed
/// @param[in]  Length          The length of the operation
/// @param[in]  Value           The value that the guest intended to write
/// @param[in]  PciCfgContext   Relevant data about the operation, including the Context, registered when the hook was set
typedef CX_STATUS (*PFUNC_DevWritePciConfig)(_In_ CX_UINT16 Offset, _In_ CX_UINT16 Length, _In_ CX_UINT8 *Value, _In_ PCICFG_CONTEXT* PciCfgContext);

#define PCICFG_FULL_RANGE CX_UINT16_MAX_VALUE ///< Full range for bus, device and function

/// @}

typedef struct _GUEST GUEST;

//
// PCI / PCI Express structures
//

#define PCI_CONFIG_ADDRESS_PORT         0xcf8
#define PCI_CONFIG_DATA_PORT            0xcfc
#define PCI_CONFING_RESET_PORT          0xcf9

#pragma pack(push,1)
typedef union _PCI_CONFIG_REGISTER
{
    struct
    {
        CX_UINT8    RegisterNumber;
        CX_UINT8    FunctionNumber  : 3;
        CX_UINT8    DeviceNumber    : 5;
        CX_UINT8    BusNumber;
        CX_UINT8    __Reserved24_30 : 7;
        CX_UINT8    EnableBit       : 1;
    };
    CX_UINT32       Raw;
} PCI_CONFIG_REGISTER;
#pragma pack(pop)

#define MAX_PCI_HOST_CONTROLLER     4   ///< Maximum number of potentially supported PCI Host Controllers
#define MAX_PCI_BUS_PER_CONTROLLER  256 ///< Maximum number of buses per controller
#define MAX_PCI_DEVICE_PER_BUS      32  ///< Maximum number of devices per bus
#define MAX_PCI_FUNCTION_PER_DEVICE 8   ///< Maximum number of functions per device

#define PCI_FUNCTION_MMIO_SIZE 0x1000   ///< The size of a PCI config space

//
// PCI Capabilities
#define PCI_CAP_ID_PM           0x01    /* Power Management */
#define PCI_PM_CTRL             4       /* PM control and status register */
#define  PCI_PM_CTRL_STATE_MASK     0x0003  /* Current power state (D0 to D3) */
#define  PCI_PM_CTRL_NO_SOFT_RESET  0x0008  /* No reset for D3hot->D0 */
#define  PCI_PM_CTRL_PME_STATUS     0x8000  /* PME pin status */
#define  PCI_PM_CTRL_PME_ENABLE     0x0100  /* PME pin enable */

#define PCI_CAP_ID_MSI          0x05    /* MSI */

#define PCI_CAP_ID_EXP          0x10    /* PCI Express */
#define PCI_EXP_DEVCAP          4       /* Device capabilities */
#define  PCI_EXP_DEVCAP_FLR     0x10000000 /* Function Level Reset */
#define PCI_EXP_DEVCTL          8       /* Device Control */
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  /* Bridge Configuration Retry / FLR */
#define PCI_EXP_DEVSTA          10      /* Device Status */
#define  PCI_EXP_DEVSTA_TRPND   0x20    /* Transactions Pending */

#define PCI_CAP_ID_MSI_X        0x11    /* MSI-X */

#define PCI_CAP_ID_AF           0x13     /* PCI Advanced Features */
#define PCI_AF_CAP              3
#define  PCI_AF_CAP_TP          0x01
#define  PCI_AF_CAP_FLR         0x02
#define PCI_AF_CTRL             4
#define  PCI_AF_CTRL_FLR        0x01
#define PCI_AF_STATUS           5
#define  PCI_AF_STATUS_TP       0x01

#define PCI_D0          0
#define PCI_D1          1
#define PCI_D2          2
#define PCI_D3hot       3
#define PCI_D3cold      4

// pci express extended capabilities
#define PCI_EXT_CAP_ID(header)          (header & 0x0000ffff)
#define PCI_EXT_CAP_VER(header)         ((header >> 16) & 0xf)
#define PCI_EXT_CAP_NEXT(header)        ((header >> 20) & 0xffc)

#define PCI_EXT_CAP_ID_PASID            0x1B    /* Process Address Space ID */

// PCI device classes
#define PCI_CLS_MASS_STORAGE_CONTROLLER     0x01
#define PCI_CLS_NETWORK_CONTROLLER          0x02
#define PCI_CLS_DISPLAY_CONTROLLER          0x03
#define PCI_CLS_MULTIMEDIA_CONTROLLER       0x04
#define PCI_CLS_MEMORY_CONTROLLER           0x05
#define PCI_CLS_BRIDGE_DEVICE               0x06
#define PCI_CLS_SIMPLE_COMM_CONTROLLERS     0x07
#define PCI_CLS_BASE_SYSTEM_PERIPHERALS     0x08
#define PCI_CLS_INPUT_DEVICES               0x09
#define PCI_CLS_DOCKING_STATIONS            0x0A
#define PCI_CLS_PROCESSORS                  0x0B
#define PCI_CLS_SERIAL_BUS_CONTROLLERS      0x0C
#define PCI_CLS_WIRELESS_CONTROLLERS        0x0D
#define PCI_CLS_INTELLIGENT_IO_CONTROLLERS  0x0E
#define PCI_CLS_SATELLITE_COMM_CONTROLLERS  0x0F
#define PCI_CLS_ENC_DEC_CONTROLLERS         0x10
#define PCI_CLS_DSP_CONTROLLERS             0x11

#define PCI_SUBCLS_HOST_BRIDGE              0x00
#define PCI_SUBCLS_PCIPCI_BRIDGE            0x04

// Valid for PCI_CLS_BASE_SYSTEM_PERIPHERALS
#define PCI_SUBCLS_SD_HOST_CONTROLLER       0x5

// Valid for PCI_CLS_SERIAL_BUS_CONTROLLERS
#define PCI_SUBCLS_USB_CONTROLLER           0x03

#define PCI_GET_IOBAR_BASE(barptr)  ((barptr)->Raw & 0x0000FFFC)
#define PCI_GET_MEMBAR_BASE(barptr) (((barptr)->MemWidth == 2)?( (((__int64)((barptr + 1)->Raw)) << 32) | ((barptr)->Raw & 0x0FFFFFFF0ULL) ):( (barptr)->Raw & 0x0FFFFFFF0ULL) )

#define MAX_PCI_BARS_TYPE0                6
#define MAX_PCI_BARS_TYPE1                2

#pragma pack(push)
#pragma pack(1)

// bar register
typedef union _PCI_BAR{
    CX_UINT32       Raw;
    struct {
        CX_UINT32       IoSpace : 1;      // 1 for I/O BARs, 0 for MEMORY BARs
        CX_UINT32       Reserved : 1;
        CX_UINT32       IoBase : 30;      // CX_UINT32 aligned base address I/O port
    };
    struct {
        CX_UINT32       NotMemSpace : 1;     // 1 for I/O BARs, 0 for MEMORY BARs
        CX_UINT32       MemWidth : 2;     // 0 - 32 bit wide, 2 - 64 bit wide, using two consecutive BARs
        CX_UINT32       Prefetchable : 1; // 1 for prefetchable memory resources
        CX_UINT32       MemBase : 28;     // 16 byte PARAGRAPH aligned base address memory window
    };
} volatile PCI_BAR;

typedef union _PCI_COMMAND
{
    CX_UINT16        Raw;
    struct {
        CX_UINT16 IO_EN : 1; //I/O Access Enable.
        CX_UINT16 MEM_EN : 1; //Memory Access Enable.
        CX_UINT16 MASTERING_EN : 1; //Enable Mastering.
        CX_UINT16 SCM : 1; //Special Cycle Monitoring.
        CX_UINT16 MEM_WRITE : 1; //Memory Write and Invalidate Enable.
        CX_UINT16 PS_EN : 1; //Palette Snoop Enable.
        CX_UINT16 PARITY_ERR : 1; //Parity Error Response.
        CX_UINT16 WAITC_EN : 1; //Wait Cycle Enable.
        CX_UINT16 SERR_EN : 1; //SERR# Enable
        CX_UINT16 FBB_EN : 1; //Fast Back-to-Back Enable.
        CX_UINT16 INT_DISABLE : 1; //Interrupt Disable (INTA# or CSA signaled).
        CX_UINT16 Reserved : 1; //Reserved.
    } COMMAND_BITS;
} PCI_COMMAND;
static_assert(sizeof(PCI_COMMAND) == 2, "See PCI Local Bus Specification Revision 3.0 Section 6.2.2");

typedef union _PCI_STATUS
{
    CX_UINT16        Raw;
    struct {
        CX_UINT16 Reserved : 3; // 2-0    Reserved.
        CX_UINT16 INT_STATUS : 1; // 3      Interrupt Status.
        CX_UINT16 EXT_CAPS : 1; // 4      Indicates that an Ethernet controller implements Extended Capabilities.
        CX_UINT16 MHZ66 : 1; // 5      66 MHz Capable.
        CX_UINT16 UDF : 1; // 6      UDF Supported. Hardwired to 0b for PCI 2.3a.
        CX_UINT16 BTOB : 1; // 7      Fast Back-to-Back Capable.
        CX_UINT16 PARITY : 1; // 8      Data Parity Reported.
        CX_UINT16 DEVSEL : 2; // 10-9   DEVSEL Timing.
        CX_UINT16 SIG_ABORT : 1; // 11     Signaled Target Abort.
        CX_UINT16 REC_ABORT : 1; // 12     Received Target Abort.
        CX_UINT16 MASTER_ABORT : 1; // 13     Received Master Abort.
        CX_UINT16 SIG_ERROR : 1; // 14     Signaled System Error
        CX_UINT16 DET_ERROR : 1; // 15     Detected Parity Error.
    } STATUS_BITS;
} PCI_STATUS;

typedef struct _PCI_CONFIG_HEADER
{
    CX_UINT16        VendorID;
    CX_UINT16        DeviceID;
    PCI_COMMAND Command;
    PCI_STATUS  Status;

    CX_UINT8        RevisionID;
    CX_UINT8        ProgIf;
    CX_UINT8        Subclass;
    CX_UINT8        Class;
    CX_UINT8        CacheLineSize;
    CX_UINT8        LatencyTimer;
    union
    {
        CX_UINT8 Raw;
        struct
        {
            CX_UINT8 Type : 7;
            CX_UINT8 MultiFunction : 1;
        };
    }HeaderType;
    CX_UINT8        BIST;
} volatile PCI_CONFIG_HEADER;

#define SIZEOF_PCI_CONFIG_LEGACY      0x100

typedef union _PCI_CONFIG {
    struct {
        PCI_CONFIG_HEADER Header;
        union {
            // standard PCI / PCI Express device (0x00)
            struct {
                PCI_BAR Bar[MAX_PCI_BARS_TYPE0];  // for PCI devices we have 6 BARs (0-5)
                CX_UINT32   CardBusCisPtr;
                CX_UINT16    SubsysVendorID;
                CX_UINT16    SubsysID;
                CX_UINT32   RomBaseAddress;
                CX_UINT8    CapsPtr;
                CX_UINT8    Reserved[7];
                CX_UINT8    IntLine;
                CX_UINT8    IntPin;
                CX_UINT8    MinGrant;
                CX_UINT8    MaxLatency;
                /// ...
            };
            // PCI-to-PCI bridge (0x01)
            struct {
                PCI_BAR BarUnused[MAX_PCI_BARS_TYPE1];         // for PCI-to-PCI bridges we have only two BARs (0-1)
                CX_UINT8    PrimaryBusNumber;
                CX_UINT8    SecondaryBusNumber;
                CX_UINT8    SubordinateBusNumber;
                CX_UINT8    SecondaryLatencyTimer;
                CX_UINT8    IoBase;
                CX_UINT8    IoLimit;
                CX_UINT16    SecondaryStatus;
                CX_UINT16    MemoryBase;
                CX_UINT16    MemoryLimit;
                CX_UINT16    PrefMemoryBase; // prefetchable
                CX_UINT16    PrefMemoryLimit;
                CX_UINT32   PrefBaseUpper32;
                CX_UINT32   PrefLimitUpper32;
                CX_UINT16    IoBaseUpper16;
                CX_UINT16    IoLimitUpper16;
                CX_UINT8    CapsPtr;
                CX_UINT8    Reserved[3];
                CX_UINT32   RomBaseAddress;
                CX_UINT8    IntLine;
                CX_UINT8    IntPin;
                CX_UINT16    BridgeControl;
                CX_UINT8    ChipControl;
                CX_UINT8    DiagnosticControl;
                CX_UINT16    ArbiterControl;
                /// ...
            } PciBridge;
            // PCI-to-CardBus bridge (0x02)
            struct {
                CX_UINT32   SocketBaseAddress;
                // not supported
            } CardBusBridge;
        };
    };
    CX_UINT8        Raw[0x1000];            // the PCI Express config space in MMIO is 4K
} volatile PCI_CONFIG;
static_assert(sizeof(PCI_CONFIG) == 0x1000,
    "PCI EXPRESS BASE SPECIFICATION, REV. 3.0 Section 7.2. PCI Express Configuration Mechanisms");
#pragma pack(pop)

#define PCI_BASE_CONFIG_SPACE_SIZE                  0x40
#define PWR_PCI_CFG_SPACE_SAVE_SIZE                 PCI_BASE_CONFIG_SPACE_SIZE

typedef struct _PCI_FUNC {
    PCI_CONFIG      *Config;                 ///< Direct VA pointer to the PCI Express MMIO config space
    CX_UINT64        ConfigPa;               ///< PA for the PCI MMIO config space

    CX_UINT16        BusNumber;              ///< Bus number
    CX_UINT16        DevNumber;              ///< Device number
    CX_UINT16        FuncNumber;             ///< Function number

    CX_UINT16        DepthLvl;               ///< 0 in case of a host controller, +1 per bridge connection
} PCI_FUNC, *PPCI_FUNC;

/// @brief The callback prototype used for PCI config space walks
///
/// @param[in]  PciFunction     The PCI function for which the callback was called
/// @param[in]  Parent          The PCI function's parent function
/// @param[in]  Context         The optional data register with the callback
typedef CX_STATUS (FUNC_PciFunctionWalkCallback)(_In_ PCI_FUNC* PciFunction, _In_opt_ PCI_FUNC* Parent, _In_opt_ CX_VOID* Context);
typedef FUNC_PciFunctionWalkCallback* PFUNC_PciDeviceWalkCallback;

/// @brief The structure describes a PCI host controller
typedef struct _PCI_HOSTCTRL {
    PCI_SYSTEM      *PciSystem;     ///< A pointer to the PCI system of which this controller is taking part of
    CX_UINT8        HostCtrlIndex;  ///< The host controller's index
    CX_UINT8        BusCount;       ///< The number of buses in the controller
    CX_UINT64       ConfigPa;       ///< The starting physical address of the controller's configuration space
    PCI_CONFIG      *Config;        ///< The starting virtual address of the controller's configuration space
    CX_UINT64       ConfigLen;      ///< The length of the configuration space
    CX_UINT16       PciSegment;     ///< The segment number of the controller
    CX_UINT8        StartBusNumber; ///< The first bus number of the controller
    CX_UINT8        EndBusNumber;   ///< The last bus number of the controller
} PCI_HOSTCTRL;

/// @brief The structure describes all the relevant information about PCI in the system
typedef struct _PCI_SYSTEM {
    CX_UINT8                    HostCtrlCount;                      ///< The number of the existing PCI host controllers
    CX_UINT8                    BusCount;                           ///< The overall bus count in the system
    SPINLOCK                    ScanLock;                           ///< The lock used for BAR rescanning in the whole system
    PCI_BAR_RECONF_INFO         BarReconfigurations;                ///< The list of the reconfigured BARs
    PCI_HOSTCTRL                *HostCtrl[MAX_PCI_HOST_CONTROLLER]; ///< The list of the host controllers in the system
} PCI_SYSTEM;

typedef struct _GUEST GUEST;

/// @brief Allocates and initializes a PCI_SYSTEM structure, locks, etc ...
///
/// @param[out]  PciSystem          The structure that will be initialized
///
/// @returns    OTHER                               - Other internal error
CX_STATUS
PciPreinitSystemPci(
    _Out_ PCI_SYSTEM** PciSystem
);

/// @brief Allocates, initializes and adds a PCI controller to the PCI_SYSTEM structure
///
/// Maps the whole configuration space 1-to-1
/// WARNING: the HV supports only 1 PCI controller
///
/// @param[in]  PciSystem          The PCI system structure will get the controller
/// @param[in]  PhysicalAddress    The start of the PCI controllers's configuration spaces
/// @param[in]  PciSegment         The PCI segment of the PCI controller
/// @param[in]  StartBusNumber     The first bus of the PCI controller
/// @param[in]  EndBusNumber       The last bus of the PCI controller
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the controller was added
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - PciSystem can not be CX_NULL
/// @returns    STATUS_TOO_MANY_DEVICES             - The maximum number of PCI controllers was achieved
/// @returns    OTHER                               - Other internal error
CX_STATUS
PciConfigAddControllerToHost(
    _In_ PCI_SYSTEM* PciSystem,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT16 PciSegment,
    _In_ CX_UINT8 StartBusNumber,
    _In_ CX_UINT8 EndBusNumber
    );

/// @brief Will walk though all of the PCI functions in DFS order by bridges, and call the given callback
///
/// Failure in callback will stop the walk
///
/// @param[in]  Callback           The callback that'll be called for every valid PCI function found
/// @param[in]  Context            An optional, generic argument that'll passed to the callback upon calling them
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the walk through was successful
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Callback can not be CX_NULL
/// @returns    OTHER                               - Other internal error, or error returned by the callback at any point
CX_STATUS
PciWalkFunctions(
    _In_ FUNC_PciFunctionWalkCallback* Callback,
    _In_opt_ CX_VOID* Context
);

/// @brief Will return the address of the configuration space of the specified PCI device
///
/// @param[in]  Bus             The bus number of the for which we need the address
/// @param[in]  Dev             The device number of the from which we need the address
/// @param[in]  Func            The function number of the device from which we need the address
///
/// @returns                    The directly accessible virtual (and volatile) address to the specified PCI device, CX_NULL if anything goes wrong
PCI_CONFIG*
PciGetConfigSpaceVa(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func
    );

/// @brief Will return the physical address of the configuration space of the specified PCI device
///
/// @param[in]  Bus             The bus number of the for which we need the address
/// @param[in]  Dev             The device number of the from which we need the address
/// @param[in]  Func            The function number of the device from which we need the address
///
/// @returns                    The physical address to the specified PCI device, CX_NULL if anything goes wrong
CX_UINT64
PciGetConfigSpacePa(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func
);

/// @brief Returns the Class string for the well class codes
///
/// @param[in]  Class           Device's class number
/// @param[in]  Subclass        Device's subclass number
/// @param[in]  ProgIf          Device's Prog IF number
///
/// @returns The class string
CX_INT8 *PciClassToString(
    _In_ CX_UINT8 Class,
    _In_ CX_UINT8 Subclass,
    _In_ CX_UINT8 ProgIf
    );

/// @brief Returns the vendor string for the well known vendor ids
///
/// @param[in]  VendorID        Device's vendor ID
///
/// @returns The vendor string
CX_INT8 *PciVendorToString(
    _In_ CX_UINT16 VendorID
    );


/// @brief Returns the vendor/device string for the well known device/vendor ids
///
/// @param[in]  VendorID        Device's vendor ID
/// @param[in]  DeviceID        Device's device ID
///
/// @returns The device string
CX_INT8 *
PciDeviceToString(
    _In_ CX_UINT16 VendorID,
    _In_ CX_UINT16 DeviceID
    );


/// @brief Will try to decode the Base Address Register of a PCI device and return all the relevant information
///
/// WARNING: Will write/read to/from the given bar in order to obtain information
///
/// @param[in]  Bar                The directly accessible address of the Base Address Register
/// @param[out] Addr               The decoded address from the BAR (I/O or MMIO)
/// @param[out] Size               The size of the address range (I/O or MMIO)
/// @param[out] Is64BitWide        CX_TRUE if the address is 64 bit wide, only MMIO (occupies two bars), CX_FALSE otherwise
/// @param[out] Implemented        CX_TRUE if the BAR is implemented, CX_FALSE otherwise
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the BAR is decoded (or the BAR is 0)
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Callback can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - Address can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - Size can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - Is64BitWide can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - Implemented can not be CX_NULL
CX_STATUS
PciDecodeBar(
    _In_ PCI_BAR *Bar,
    _Out_ CX_UINT64 *Addr,
    _Out_ CX_UINT64 *Size,
    _Out_ CX_BOOL *Is64BitWide,
    _Out_ CX_BOOL *Implemented
    );


/// @brief Will scan trough all of the PCI devices and decodes every BAR in order to check if they are added in to the guest EPT
///
/// Additionally, saves the BARs to be able to restore them in case of an S4 power state change
CX_STATUS
PciScanAllPciDeviceBarReconfigurations(
    CX_VOID
);

/// @brief Restore BAR informations from persistent storage in case of an S4 power state change
///
/// @param[in]  BarReconfigurations The reconfiguration data structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, all of the devices were rescanned
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - BarReconfiguration can not be CX_NULL
/// @returns    OTHER                               - Other internal error
CX_STATUS
PciRestoreBarReconfigurationDataOnHibernate(
    _In_             PCI_BAR_RECONF_INFO     *BarReconfigurations
);

/// @brief Stores the BAR informations for persistent storage in case of an S4 power state change
///
/// @param[in,out] BarReconfigurations The reconfiguration data structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, all of the devices were rescanned
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - BarReconfiguration can not be CX_NULL
/// @returns    OTHER                               - Other internal error
CX_STATUS
PciStoreBarReconfigurationDataOnHibernate(
    _Inout_         PCI_BAR_RECONF_INFO     *BarReconfigurations
);

/// \addtogroup hooks
/// @{

/// @brief Sets read and/or write callback for the hypervisor to call when intercepts a read and/or write on the PCI config space of the specified PCI device.
///
/// Both MMIO and I/O port accesses are intercepted.
///
/// @param[in]  Guest           The guest for which the hook will be set
/// @param[in]  PciId           Specified PCI device will be hooked, BDF format. PCICFG_FULL_RANGE can be used to cover every bus, device or function
/// @param[in]  ReadCb          The callback to be called in case of a read operation over the configuration space of the device specified in PciId, optional if the WriteCb is set
/// @param[in]  WriteCb         The callback to be called in case of a write operation over the configuration space of the device specified in PciId, optional if the ReadCb is set
/// @param[in]  Context         An optional, generic argument that'll passed to the callback upon calling them
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the callback was set
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - ReadCb and WriteCb can not be both CX_NULL
/// @returns    STATUS_HOOK_ALREADY_SET             - At least one device overlaps with an already hooked device range
/// @returns    STATUS_TOO_MANY_HOOKS               - The amount of hooks set reached the maximum supported value
/// @returns    OTHER                               - Other internal error
CX_STATUS
PciSetPciCfgHook(
    _In_ GUEST* Guest,
    _In_ PCICFG_ID PciId,
    _In_ PFUNC_DevReadPciConfig ReadCb,
    _In_ PFUNC_DevWritePciConfig WriteCb,
    _In_opt_ CX_VOID* Context
);

/// @brief Adds a device to the list of hidden devices, the actual hiding will take place only after calling PciApplyPciCfgHooksForHiding()
///
/// Hiding means returning 0xFF for Device and Vendor ID and return 0x0 for the rest of the PCI config space
///
/// @param[in]  PciId           Specified PCI device will be hidden, BDF format. PCICFG_FULL_RANGE can be used to cover every bus, device or function
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the device is added to the list
/// @returns    CX_STATUS_NO_MORE_ENTRIES           - The maximum amount of hide-able device was reached
CX_STATUS PciAddPciCfgToHiddenList(
    _In_ PCICFG_ID PciId
);

/// @brief Checks if the given device is hidden
///
/// @param[in]  PciId           Specified PCI device that we want to check
///
/// @returns    CX_TRUE                                - If the device is on the hidden devices list
/// @returns    CX_FALSE                               - If the device is not on the hidden devices list
CX_BOOL
PciIsPciCfgHidden(
    _In_ PCICFG_ID PciId
);

/// @brief Applies the hiding hooks for all the devices in the list, added with PciAddPciCfgToHiddenList()
///
/// Hiding means returning 0xFF for Device and Vendor ID and return 0x0 for the rest of the PCI config space
///
/// @param[in]  Guest           The guest for which the hook will be set
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, hiding hooks were applied
/// @returns    OTHER                               - Other internal error, see PciSetPciCfgHook()
CX_STATUS PciApplyPciCfgHooksForHiding(
    _In_ GUEST* Guest
);

/// @brief Sets a tracing hook for the given device
///
/// Tracing means intercepting the read/write and executing it bare metal afterwards
///
/// @param[in]  Guest           The guest for which we activate the device tracing
/// @param[in]  PciId           Specified PCI device will be traced, BDF format. PCICFG_FULL_RANGE can be used to cover every bus, device or function
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, hiding hooks were applied
/// @returns    OTHER                               - Other internal error, see PciSetPciCfgHook()
CX_STATUS PciTraceDevice(
    _In_ GUEST* Guest,
    _In_ PCICFG_ID PciId
);

/// @brief Dump basic information about the current(live) state of the PCI configurations space
///
///
/// @param[in]  DumpResources   CX_TRUE if the content of the BARs should be decoded and dumped
///
/// returns     OTHER                               - Internal error
CX_STATUS
PciDumpDevice3(
    CX_BOOL DumpResources
);

/// @brief In order to make the hidden devices functional again (while being hidden from the guest)
/// we must save and restore the PCI config space partially. Additionally some of the devices might need to be started
///
/// @param[in]  Save            CX_TRUE in case of saving the data (and stopping the devices), CX_FALSE in case of restoring the data (and starting the devices)
CX_VOID
PciSaveRestoreHiddenDevicesState(
    _In_ CX_BOOL Save
);

/// @}

#endif // _PCI_H_
