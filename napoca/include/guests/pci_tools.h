/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _PCI_TOOLS_H_
#define _PCI_TOOLS_H_

#include "core.h"

/// @brief Initializes everything needed for using the functionalities exposed by this header
///
CX_VOID
PciToolsInit(
    void
);

/// @brief Search for the bridge device connected to the given bus(secondary side), using only I/O operations
///
/// @param[in]  BusOfDev        The bus number for what we are searching on a bridge
/// @param[out] Bus             The bus number of the bridge
/// @param[out] Dev             The device number of the bridge
/// @param[out] Func            The function number of the bridge
///
/// @returns    CX_STATUS_SUCCESS                   - The bridge was found
/// @returns    CX_STATUS_DATA_NOT_FOUND            - The bridge was not found
CX_STATUS
PciLookupBridgeForPciBus(
    _In_ CX_UINT16 BusOfDev,
    _Out_ CX_UINT16* Bus,
    _Out_ CX_UINT16* Dev,
    _Out_ CX_UINT16* Func
);

/// @brief Reads one byte from the specified register from the given device's configuration space (BDF format)
///
/// The read is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the from which the read is intended
/// @param[in]  Dev             The device number of the from which the read is intended
/// @param[in]  Func            The function number of the device from which the read is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device from which the read is intended
///
/// @returns                    The byte read from the specified register
CX_UINT8
PciConfigInByte(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
);

/// @brief Writes one byte in the specified register for the given device's configuration space (BDF format)
///
/// The write is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the for which the write is intended
/// @param[in]  Dev             The device number of the for which the write is intended
/// @param[in]  Func            The function number of the device for which the write is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device for which the write is intended
/// @param[in]  Value           The value which should be written
CX_VOID
PciConfigOutByte(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT8 Value
);

/// @brief Reads two bytes from the specified register from the given device's configuration space (BDF format)
///
/// The read is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the from which the read is intended
/// @param[in]  Dev             The device number of the from which the read is intended
/// @param[in]  Func            The function number of the device from which the read is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device from which the read is intended
///
/// @returns                    The bytes read from the specified register
CX_UINT16
PciConfigInWord(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
);

/// @brief Writes two bytes in the specified register for the given device's configuration space (BDF format)
///
/// The write is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the for which the write is intended
/// @param[in]  Dev             The device number of the for which the write is intended
/// @param[in]  Func            The function number of the device for which the write is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device for which the write is intended
/// @param[in]  Value           The value which should be written
CX_VOID
PciConfigOutWord(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT16 Value
);

/// @brief Reads four bytes from the specified register from the given device's configuration space (BDF format)
///
/// The read is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the from which the read is intended
/// @param[in]  Dev             The device number of the from which the read is intended
/// @param[in]  Func            The function number of the device from which the read is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device from which the read is intended
///
/// @returns                    The bytes read from the specified register
CX_UINT32
PciConfigInDword(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
);

/// @brief Writes four bytes in the specified register for the given device's configuration space (BDF format)
///
/// The write is locked on the hypervisor level, not synchronized with the guest
///
/// @param[in]  Bus             The bus number of the for which the write is intended
/// @param[in]  Dev             The device number of the for which the write is intended
/// @param[in]  Func            The function number of the device for which the write is intended
/// @param[in]  Reg             The target register inside of the configuration space of the device for which the write is intended
/// @param[in]  Value           The value which should be written
CX_VOID
PciConfigOutDword(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT32 Value
);

/// @brief Will try to enable(D0) the PCI device (BFG format) through I/O port operations
///
/// Will try multiple times if the device does not start
///
/// @param[in]  Bus             The bus number of the device for which the enable operation is intended
/// @param[in]  Dev             The device number of the device for which the enable operation is intended
/// @param[in]  Func            The function number of the device for which the enable operation is intended
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected the device is ON (with or without power management capability)
/// @returns    CX_STATUS_DEVICE_POWER_FAILURE      - Failed to turn the device ON
CX_STATUS
PciPowerOnPciDevice(
    _In_ CX_UINT8 Bus,
    _In_ CX_UINT8 Dev,
    _In_ CX_UINT8 Func
);

/// @brief Will try to disable(D3) the PCI device (BFG format) through I/O port operations
///
/// Will try multiple times if the device does not stop
///
/// @param[in]  Bus             The bus number of the device for which the disable operation is intended
/// @param[in]  Dev             The device number of the device for which the disable operation is intended
/// @param[in]  Func            The function number of the device for which the disable operation is intended
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected the device is OFF (with or without power management capability)
/// @returns    CX_STATUS_DEVICE_POWER_FAILURE      - Failed to turn the device OFF
CX_STATUS
PciPowerOffPciDevice(
    _In_ CX_UINT8 Bus,
    _In_ CX_UINT8 Dev,
    _In_ CX_UINT8 Func
);
#endif // _PCI_TOOLS_H_
