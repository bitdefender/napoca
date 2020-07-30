/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// PCI - PCI / PCI Express parsing and virtualization

#include "kernel/kernel.h"
#include "guests/pci_tools.h"

/// @brief Lock used for synchronizing reads/writes to the PCI_CONFIG_ADDRESS_PORT and the PCI_CONFIG_DATA_PORT
static SPINLOCK gPciConfigPortsLock;

CX_VOID
PciToolsInit(
    void
)
{
    HvInitSpinLock(&gPciConfigPortsLock, "gPciConfigPortsLock", CX_NULL);
}

/// @brief Same as PciConfigInByte(), but without synchronization on hypervisor level
__forceinline
static
CX_UINT8
_PciConfigInByteNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    return __inbyte(PCI_CONFIG_DATA_PORT + offs);
}

/// @brief Same as PciConfigOutByte(), but without synchronization on hypervisor level
__forceinline
static
CX_VOID
_PciConfigOutByteNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT8 Value
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    __outbyte(PCI_CONFIG_DATA_PORT + offs, Value);
}

/// @brief Same as PciConfigInWord(), but without synchronization on hypervisor level
__forceinline
static
CX_UINT16
_PciConfigInWordNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    return __inword(PCI_CONFIG_DATA_PORT + offs);
}

/// @brief Same as PciConfigOutWord(), but without synchronization on hypervisor level
__forceinline
static
CX_VOID
_PciConfigOutWordNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT16 Value
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    __outword(PCI_CONFIG_DATA_PORT + offs, Value);
}

/// @brief Same as PciConfigInDword(), but without synchronization on hypervisor level
__forceinline
static
CX_UINT32
_PciConfigInDwordNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    return __indword(PCI_CONFIG_DATA_PORT + offs);
}

/// @brief Same as PciConfigOutDword(), but without synchronization on hypervisor level
__forceinline
static
CX_VOID
_PciConfigOutDwordNoLock(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT32 Value
)
{
    CX_UINT16 offs = Reg & 0x3;
    CX_UINT16 reg = Reg & (~0x3);

    __outdword(PCI_CONFIG_ADDRESS_PORT, 0x80000000 | (((CX_UINT32)Bus) << 16) | (((CX_UINT32)Dev) << 11) | (((CX_UINT32)Func) << 8) | reg);
    __outdword(PCI_CONFIG_DATA_PORT + offs, Value);
}

CX_STATUS
PciLookupBridgeForPciBus(
    _In_ CX_UINT16 BusOfDev,
    _Out_ CX_UINT16* Bus,
    _Out_ CX_UINT16* Dev,
    _Out_ CX_UINT16* Func
)
{
    CX_STATUS status = CX_STATUS_DATA_NOT_FOUND;
    CX_UINT16 bus, dev, func;

    // locate the PCI-to-PCI bridge that exposes on the secondary side the specified BusOfDev
    for (bus = 0; bus <= 255; bus++)
    {
        for (dev = 0; dev <= 31; dev++)
        {
            for (func = 0; func <= 7; func++)
            {
                CX_UINT32 vendAndDev;
                CX_UINT32 classSubclassAndRev;
                CX_UINT32 busNumbers;

                vendAndDev = PciConfigInDword(bus, dev, func, 0x00);

                if (0x0000FFFF == (vendAndDev & 0x0000FFFF)) continue;

                // now, check if this is a PCI-to-PCI bridge
                classSubclassAndRev = PciConfigInDword(bus, dev, func, 0x08);

                // Class == 6, SubClass == 4 for PCI-to-PCI bridges
                if (0x06040000 != (classSubclassAndRev & 0xFFFF0000)) continue;

                // then, check if the secondary side of the bridge points to BusOfDev
                busNumbers = PciConfigInDword(bus, dev, func, 0x18);

                // SecondaryBusNumber
                if (BusOfDev != ((busNumbers & 0x0000FF00) >> 8)) continue;

                *Bus = bus;
                *Dev = dev;
                *Func = func;
                status = CX_STATUS_SUCCESS;

                goto cleanup;
            }
        }
    }

    LOG("[DEBUG] WARNING, no PCI-to-PCI bridge found with secondary side bus %d\n", BusOfDev);

cleanup:

    return status;
}

CX_UINT8
PciConfigInByte(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT8 val;

    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);
    val = _PciConfigInByteNoLock(Bus, Dev, Func, Reg);
    HvReleaseSpinLock(&gPciConfigPortsLock);

    return val;
}

CX_VOID
PciConfigOutByte(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT8 Value
)
{
    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);
    _PciConfigOutByteNoLock(Bus, Dev, Func, Reg, Value);
    HvReleaseSpinLock(&gPciConfigPortsLock);

    return;
}

CX_UINT16
PciConfigInWord(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT16 val;
    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);
    val = _PciConfigInWordNoLock(Bus, Dev, Func, Reg);
    HvReleaseSpinLock(&gPciConfigPortsLock);

    return val;
}

CX_VOID
PciConfigOutWord(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT16 Value
)
{
    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);
    _PciConfigOutWordNoLock(Bus, Dev, Func, Reg, Value);
    HvReleaseSpinLock(&gPciConfigPortsLock);

    return;
}

CX_UINT32
PciConfigInDword(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg
)
{
    CX_UINT32 val;

    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);
    val = _PciConfigInDwordNoLock(Bus, Dev, Func, Reg);
    HvReleaseSpinLock(&gPciConfigPortsLock);

    return val;
}

CX_VOID
PciConfigOutDword(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func,
    _In_ CX_UINT16 Reg,
    _In_ CX_UINT32 Value
)
{
    HvAcquireSpinLockNoInterrupts(&gPciConfigPortsLock);

    _PciConfigOutDwordNoLock(Bus, Dev, Func, Reg, Value);

    HvReleaseSpinLock(&gPciConfigPortsLock);

    return;
}

#define MAX_PCI_POWER_TRANSITION_RETRIES 20 ///< The maximum number of tries for enabling/disabling a device

CX_STATUS
PciPowerOnPciDevice(
    _In_ CX_UINT8 Bus,
    _In_ CX_UINT8 Dev,
    _In_ CX_UINT8 Func
)
{
    CX_UINT16 csr = 0;
    CX_UINT8 capsPointer = 0;
    CX_UINT8 capId = 0;
    CX_UINT32 retries = 0;

    capsPointer = PciConfigInByte(Bus, Dev, Func, 0x34);

    while ((capsPointer) && (0xFF != capsPointer))
    {
        capId = PciConfigInByte(Bus, Dev, Func, capsPointer);

        if (PCI_CAP_ID_PM == capId)
        {
            csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);

            csr &= ~PCI_PM_CTRL_STATE_MASK;
            csr |= PCI_D0;

            PciConfigOutWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL, csr);

            csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);

            while ((csr & PCI_PM_CTRL_STATE_MASK) != PCI_D0)
            {
                csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);
                if (retries < MAX_PCI_POWER_TRANSITION_RETRIES) retries++;
                else return CX_STATUS_DEVICE_POWER_FAILURE;
            }
            break;
        }

        capsPointer = PciConfigInByte(Bus, Dev, Func, capsPointer + 1);
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciPowerOffPciDevice(
    _In_ CX_UINT8 Bus,
    _In_ CX_UINT8 Dev,
    _In_ CX_UINT8 Func
)
{
    CX_UINT16 csr = 0;
    CX_UINT8 capsPointer = 0;
    CX_UINT8 capId = 0;
    CX_UINT32 retries = 0;

    capsPointer = PciConfigInByte(Bus, Dev, Func, 0x34);

    while ((capsPointer) && (0xFF != capsPointer))
    {
        capId = PciConfigInByte(Bus, Dev, Func, capsPointer);

        if (PCI_CAP_ID_PM == capId)
        {
            csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);

            csr &= ~PCI_PM_CTRL_STATE_MASK;
            csr |= PCI_D3hot;

            PciConfigOutWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL, csr);

            csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);

            while ((csr & PCI_PM_CTRL_STATE_MASK) != PCI_D3hot)
            {
                csr = PciConfigInWord(Bus, Dev, Func, capsPointer + PCI_PM_CTRL);
                if (retries < MAX_PCI_POWER_TRANSITION_RETRIES) retries++;
                else break;
            }
            break;
        }

        capsPointer = PciConfigInByte(Bus, Dev, Func, capsPointer + 1);
    }

    return CX_STATUS_SUCCESS;
}