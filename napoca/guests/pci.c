/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "kernel/kerneldefs.h"
#include "kernel/kernel.h"
#include "guests/pci.h"
#include "guests/power.h"
#include "guests/pci_tools.h"
#include "memory/cachemap.h"

/// \addtogroup hooks
/// @{

/// @brief All the relevant information about a PCI config space hook
typedef struct _PCICFG_HOOK
{
    PCICFG_ID PciId;                 ///< The PCI config space range hooked
    PFUNC_DevReadPciConfig ReadCb;   ///< The callback to be called in case of a read operation
    PFUNC_DevWritePciConfig WriteCb; ///< The callback to be called in case of a write operation
} PCICFG_HOOK;

#define PCICFG_MAX_HOOK_COUNT 64 ///< The maximum number of PCI config space hooks supported

typedef struct _PCICFG_HOOK_TABLE
{
    PCICFG_HOOK Hook[PCICFG_MAX_HOOK_COUNT]; ///< PCI config space hooks
    CX_UINT32 Count;                         ///< PCI config space hook count
    CX_BOOL IoPortsHooked;                   ///< TRUE if the PCI config address and data ports are hooked already

    PCICFG_HOOK LastHookThroughIo;           ///< The last hook that was matched after a write on the PCI config address port
    PCI_CONFIG_REGISTER LastPciCfgRegValue;  ///< The last value written in the PCI config address port
    CX_BOOL IsLastHookThroughIoValid;        ///< TRUE if the saved data after a write in the PCI config address port is valid

    RW_SPINLOCK Lock;                        ///< The PCI config hook lock
} PCICFG_HOOK_TABLE;

static PCICFG_HOOK_TABLE gCfgHookTable; ///< The PCI config hook table

#define MAX_PCICFG_HIDDEN_DEVICE_COUNT 32 ///< The maximum number of hidden PCI config space supported

/// @brief All the relevant information about a hidden PCI config space
typedef struct _PCI_HIDDEN_DEV
{
    PCICFG_ID PciId;                                       ///< The PCI config space range hidden
    CX_UINT8 CfgPartialShadow[PCI_BASE_CONFIG_SPACE_SIZE]; ///< The partially saved PCI config space (in case of power transitions)
}PCI_HIDDEN_DEV;
static PCI_HIDDEN_DEV gHiddenPciDevices[MAX_PCICFG_HIDDEN_DEVICE_COUNT]; ///< The list of the hidden PCI config spaces
static CX_UINT8 gHiddenPciDeviceCount;                                   ///< The hidden PCI config space count

/// @brief Calculates the physical address range for a given PCI Id
///
/// @param[in]  PciId            The PCI Id for which the range is requested
/// @param[out] RangeStart       The start of the physical range
/// @param[out] RangeEnd         The end of the physical range
static
inline
CX_VOID
_GetCfgMemRange(
    _In_ PCICFG_ID PciId,
    _Out_ CX_UINT64* RangeStart,
    _Out_ CX_UINT64* RangeEnd
)
{
    *RangeStart = gHypervisorGlobalData.Pci->HostCtrl[0]->ConfigPa;

    if (PciId.Bus == PCICFG_FULL_RANGE)
    {
        *RangeEnd = *RangeStart + CX_MIN(gHypervisorGlobalData.Pci->HostCtrl[0]->BusCount, MAX_PCI_BUS_PER_CONTROLLER)
            * (CX_UINT64)MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE;
    }
    else if (PciId.Device == PCICFG_FULL_RANGE)
    {
        *RangeStart += (CX_UINT64)PciId.Bus * MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE;
        *RangeEnd = *RangeStart + MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE;
    }
    else if (PciId.Function == PCICFG_FULL_RANGE)
    {
        *RangeStart += ((CX_UINT64)PciId.Bus * MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE)
            + ((CX_UINT64)PciId.Device * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE);
        *RangeEnd = *RangeStart + MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE;
    }
    else
    {
        *RangeStart += ((CX_UINT64)PciId.Bus * MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE)
            + ((CX_UINT64)PciId.Device * MAX_PCI_FUNCTION_PER_DEVICE * PCI_FUNCTION_MMIO_SIZE)
            + ((CX_UINT64)PciId.Function * PCI_FUNCTION_MMIO_SIZE);
        *RangeEnd = *RangeStart + PCI_FUNCTION_MMIO_SIZE;
    }

    --*RangeEnd;
}

/// @brief Check if any PCI config space is already hooked in the given PCI Id range
///
/// @param[in]  PciId            The PCI Id for which we are checking the already set hooks
/// @param[out] PciHook          Optionally, return the hook that was an exact match for the given PciId
///
/// @returns    TRUE                                - If the an hook was matched
/// @returns    FALSE                               - No hooks were matched
static
inline
CX_BOOL
_IsPciCfgRangeHooked(
    _In_ PCICFG_ID PciId,
    __out_opt PCICFG_HOOK** PciHook
)
{
    for (CX_UINT32 hookIndex = 0; hookIndex < gCfgHookTable.Count; ++hookIndex)
    {
        if (PciHook != CX_NULL) *PciHook = &gCfgHookTable.Hook[hookIndex];

        if (gCfgHookTable.Hook[hookIndex].PciId.Bus == PCICFG_FULL_RANGE) return CX_TRUE;
        else if (gCfgHookTable.Hook[hookIndex].PciId.Bus == PciId.Bus)
        {
            if (gCfgHookTable.Hook[hookIndex].PciId.Device == PCICFG_FULL_RANGE) return CX_TRUE;
            else if (gCfgHookTable.Hook[hookIndex].PciId.Device == PciId.Device)
            {
                if (gCfgHookTable.Hook[hookIndex].PciId.Function == PCICFG_FULL_RANGE) return CX_TRUE;
                else if (gCfgHookTable.Hook[hookIndex].PciId.Function == PciId.Function) return CX_TRUE;
            }
        }
    }

    return CX_FALSE;
}

/// @brief Calculate the PCI Id based on the PCI config space address
///
/// @param[in] Address          The physical address for which the PCI Id will be calculated
///
/// @returns The calculated PCI Id
static
inline
PCICFG_ID
_GetPciIdFromAddress(
    _In_ CX_UINT64 Address
)
{
    PCICFG_ID pciId;
    CX_UINT64 temp = (Address - gHypervisorGlobalData.Pci->HostCtrl[0]->ConfigPa) / PCI_FUNCTION_MMIO_SIZE;

    pciId.Segment = 0;
    pciId.Function = temp % MAX_PCI_FUNCTION_PER_DEVICE;
    temp /= MAX_PCI_FUNCTION_PER_DEVICE;
    pciId.Device = temp % MAX_PCI_DEVICE_PER_BUS;
    temp /= MAX_PCI_DEVICE_PER_BUS;
    pciId.Bus = (CX_UINT16)temp;

    return pciId;
}

/// @brief Calculate the PCI Id based on the PCI config register value
///
/// @param[in] CfgReg           The PCI config register value
///
/// @returns The calculated PCI Id
static
inline
PCICFG_ID
_GetPciIdFromCfgRegValue(
    PCI_CONFIG_REGISTER CfgReg
)
{
    PCICFG_ID pciId;

    pciId.Segment = 0;
    pciId.Bus = CfgReg.BusNumber;
    pciId.Device = CfgReg.DeviceNumber;
    pciId.Function = CfgReg.FunctionNumber;

    return pciId;
}

/// @brief Check if two PCI Ids overlap
///
/// @param[in] PciId1           The first PCI Id to compare
/// @param[in] PciId2           The second PCI Id to compare
///
/// @returns    TRUE                                - If the PCI Ids are overlapping
/// @returns    FALSE                               - If the PCI Ids are not overlapping
static
inline
CX_BOOL
_PciIdOverlap(
    _In_ PCICFG_ID PciId1,
    _In_ PCICFG_ID PciId2
)
{
    if (PciId1.Bus == PCICFG_FULL_RANGE || PciId2.Bus == PCICFG_FULL_RANGE) return CX_TRUE;
    else if (PciId1.Bus == PciId2.Bus)
    {
        if (PciId1.Device == PCICFG_FULL_RANGE || PciId2.Device == PCICFG_FULL_RANGE) return CX_TRUE;
        else if (PciId1.Device == PciId2.Device)
        {
            if (PciId1.Function == PCICFG_FULL_RANGE || PciId2.Function == PCICFG_FULL_RANGE) return CX_TRUE;
            else if (PciId1.Function == PciId2.Function)  return CX_TRUE;
        }
    }

    return CX_FALSE;
}

/// @brief Get the virtual address of a PCI config space
///
/// Based on the VA where the PCI configuration spaces of the very first PCI controller was mapped at boot
///
/// @param[in] PciCfgPa         The physical address of a PCI config space
///
/// @returns The calculated virtual address
static
inline
CX_UINT8*
_GetPciCfgVa(
    _In_ CX_UINT64 PciCfgPa
)
{
    return (CX_UINT8*)gHypervisorGlobalData.Pci->HostCtrl[0]->Config + (PciCfgPa - gHypervisorGlobalData.Pci->HostCtrl[0]->ConfigPa);
}

/// @brief Callback used to intercept reads on the PCI address and data ports
static
CX_STATUS
_PciCfgIoPortRead(
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _Out_ CX_UINT8* Value,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;

    HvAcquireRwSpinLockShared(&gCfgHookTable.Lock);

    if (IoPort == PCI_CONFIG_ADDRESS_PORT || Length != sizeof(CX_UINT32))
    {
        status = STATUS_EXECUTE_ON_BARE_METAL;
        goto cleanup;
    }
    else if (IoPort == PCI_CONFIG_DATA_PORT)
    {
        if (gCfgHookTable.IsLastHookThroughIoValid)
        {
            PCICFG_CONTEXT pciCfgCtx = { .PciId = _GetPciIdFromCfgRegValue(gCfgHookTable.LastPciCfgRegValue), .Context = Context, .IsMmioAndNotIo = CX_FALSE};

            if (gCfgHookTable.LastHookThroughIo.ReadCb != CX_NULL)
            {
                status = gCfgHookTable.LastHookThroughIo.ReadCb(gCfgHookTable.LastPciCfgRegValue.RegisterNumber, sizeof(CX_UINT32), Value, &pciCfgCtx);
                if (!CX_SUCCESS(status) && status != STATUS_EXECUTE_ON_BARE_METAL)
                {
                    LOG_FUNC_FAIL("ReadCb", status);
                    goto cleanup;
                }
            }

            gCfgHookTable.IsLastHookThroughIoValid = CX_FALSE;
        }
        else
        {
            status = STATUS_EXECUTE_ON_BARE_METAL;
            goto cleanup;
        }
    }
    else
    {
        status = STATUS_EXECUTE_ON_BARE_METAL;
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    HvReleaseRwSpinLockShared(&gCfgHookTable.Lock);

    return status;
}

/// @brief Callback used to intercept writes on the PCI address and data ports
static
CX_STATUS
_PciCfgIoPortWrite(
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _In_ CX_UINT8* Value,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;

    HvAcquireRwSpinLockShared(&gCfgHookTable.Lock);

    if (IoPort == PCI_CONFIG_ADDRESS_PORT && Length == sizeof(CX_UINT32))
    {
        PCICFG_ID pciId;
        PCI_CONFIG_REGISTER configValue;
        PCICFG_HOOK* hook;

        configValue.Raw = GET_DWORD(Value, 0);
        pciId = _GetPciIdFromCfgRegValue(configValue);

        if (configValue.EnableBit && _IsPciCfgRangeHooked(pciId, &hook))
        {
            gCfgHookTable.LastHookThroughIo = *hook;
            gCfgHookTable.LastPciCfgRegValue = configValue;
            gCfgHookTable.IsLastHookThroughIoValid = CX_TRUE;
        }
        else
        {
            status = STATUS_EXECUTE_ON_BARE_METAL;
            goto cleanup;
        }
    }
    else if (IoPort == PCI_CONFIG_DATA_PORT)
    {
        if (gCfgHookTable.IsLastHookThroughIoValid && Length == sizeof(CX_UINT32))
        {
            PCICFG_CONTEXT pciCfgCtx = { .PciId = _GetPciIdFromCfgRegValue(gCfgHookTable.LastPciCfgRegValue), .Context = Context, .IsMmioAndNotIo = CX_FALSE};
            if (gCfgHookTable.LastHookThroughIo.WriteCb != CX_NULL)
            {
                status = gCfgHookTable.LastHookThroughIo.WriteCb(gCfgHookTable.LastPciCfgRegValue.RegisterNumber, sizeof(CX_UINT32), Value, &pciCfgCtx);
                if (!CX_SUCCESS(status) && status != STATUS_EXECUTE_ON_BARE_METAL)
                {
                    LOG_FUNC_FAIL("WriteCb", status);
                    goto cleanup;
                }
            }

            gCfgHookTable.IsLastHookThroughIoValid = CX_FALSE;
        }
        else
        {
            status = STATUS_EXECUTE_ON_BARE_METAL;
            goto cleanup;
        }
    }
    else if (IoPort == PCI_CONFING_RESET_PORT && Length == sizeof(CX_UINT8))
    {
        PwrReboot(CX_FALSE, CX_FALSE);
    }
    else
    {
        status = STATUS_EXECUTE_ON_BARE_METAL;
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    HvReleaseRwSpinLockShared(&gCfgHookTable.Lock);

    return status;
}

/// @brief Callback used to intercept every read on the PCI config spaces
static
CX_STATUS
_PciCfgMemRead(
    _In_ CX_UINT64 Address,
    _In_ CX_UINT32 Length,
    _Out_ CX_UINT8* Value,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;
    PCICFG_CONTEXT pciCfgCtx = { .PciId = _GetPciIdFromAddress(Address), .Context = Context, .IsMmioAndNotIo = CX_TRUE};
    PCICFG_HOOK *hook;

    HvAcquireRwSpinLockShared(&gCfgHookTable.Lock);

    if (_IsPciCfgRangeHooked(pciCfgCtx.PciId, &hook))
    {
        if (hook->ReadCb != CX_NULL)
        {
            status = hook->ReadCb(Address % PCI_FUNCTION_MMIO_SIZE, (CX_UINT16)Length, Value, &pciCfgCtx);
            if (!CX_SUCCESS(status) && status != STATUS_EXECUTE_ON_BARE_METAL)
            {
                LOG_FUNC_FAIL("ReadCb", status);
                goto cleanup;
            }
        }
        else
        {
            ERROR("Matching hook, without callback\n");
            status = STATUS_EXECUTE_ON_BARE_METAL;
        }
    }
    else
    {
        ERROR("EPT violation, without the matching hook\n");
        status = STATUS_EXECUTE_ON_BARE_METAL;
    }

    if (status == STATUS_EXECUTE_ON_BARE_METAL)
    {
        CX_UINT8* readFrom = _GetPciCfgVa(Address);

        switch (Length)
        {
        case 1:
            PUT_BYTE(Value, 0, GET_VOLATILE_BYTE(readFrom, 0));
            break;
        case 2:
            PUT_WORD(Value, 0, GET_VOLATILE_WORD(readFrom, 0));
            break;
        case 4:
            PUT_DWORD(Value, 0, GET_VOLATILE_DWORD(readFrom, 0));
            break;
        case 8:
            // support for accessing cross boundary DWORDs is Root Complex implementation specific
            // => read 2 DWORDs
            PUT_DWORD(Value, 0, GET_VOLATILE_DWORD(readFrom, 0));
            PUT_DWORD(Value, sizeof(CX_UINT32), GET_VOLATILE_DWORD(readFrom, sizeof(CX_UINT32)));
            break;
        }
        status = CX_STATUS_SUCCESS;
    }

cleanup:
    HvReleaseRwSpinLockShared(&gCfgHookTable.Lock);

    return status;
}

/// @brief Callback used to intercept every write on the PCI config spaces
static
CX_STATUS
_PciCfgMemWrite(
    _In_ CX_UINT64 Address,
    _In_ CX_UINT32 Length,
    _In_ CX_UINT8* Value,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;
    PCICFG_CONTEXT pciCfgCtx = { .PciId = _GetPciIdFromAddress(Address), .Context = Context, .IsMmioAndNotIo = CX_TRUE};
    PCICFG_HOOK* hook;

    HvAcquireRwSpinLockShared(&gCfgHookTable.Lock);

    if (_IsPciCfgRangeHooked(pciCfgCtx.PciId, &hook))
    {
        if (hook->WriteCb != CX_NULL)
        {
            status = hook->WriteCb(Address % PCI_FUNCTION_MMIO_SIZE, (CX_UINT16)Length, Value, &pciCfgCtx);
            if (!CX_SUCCESS(status) && status != STATUS_EXECUTE_ON_BARE_METAL)
            {
                LOG_FUNC_FAIL("WriteCb", status);
                goto cleanup;
            }
        }
        else
        {
            ERROR("Matching hook, without callback\n");
            status = STATUS_EXECUTE_ON_BARE_METAL;
        }
    }
    else
    {
        ERROR("EPT violation, without the matching hook\n");
        status = STATUS_EXECUTE_ON_BARE_METAL;
    }

    if (STATUS_EXECUTE_ON_BARE_METAL == status)
    {
        CX_UINT8* writeTo = _GetPciCfgVa(Address);

        switch (Length)
        {
        case 1:
            PUT_VOLATILE_BYTE(writeTo, 0, GET_BYTE(Value, 0));
            break;
        case 2:
            PUT_VOLATILE_WORD(writeTo, 0, GET_WORD(Value, 0));
            break;
        case 4:
            PUT_VOLATILE_DWORD(writeTo, 0, GET_DWORD(Value, 0));
            break;
        case 8:
            // support for accessing cross boundary DWORDs is Root Complex implementation specific
            // => write 2 DWORDs
            PUT_VOLATILE_DWORD(writeTo, 0, GET_DWORD(Value, 0));
            PUT_VOLATILE_DWORD(writeTo, sizeof(CX_UINT32), GET_DWORD(Value, sizeof(CX_UINT32)));
            break;
        }
        status = CX_STATUS_SUCCESS;
    }
cleanup:
    HvReleaseRwSpinLockShared(&gCfgHookTable.Lock);

    return status;
}

CX_STATUS
PciSetPciCfgHook(
    _In_ GUEST* Guest,
    _In_ PCICFG_ID PciId,
    _In_ PFUNC_DevReadPciConfig ReadCb,
    _In_ PFUNC_DevWritePciConfig WriteCb,
    _In_opt_ CX_VOID* Context
    )
{
    CX_STATUS status;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (ReadCb == CX_NULL && WriteCb == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (gCfgHookTable.Count >= PCICFG_MAX_HOOK_COUNT) return STATUS_TOO_MANY_HOOKS;

    HvAcquireRwSpinLockExclusive(&gCfgHookTable.Lock);

    for (CX_UINT16 hookIndex = 0; hookIndex < gCfgHookTable.Count; ++hookIndex)
    {
        if (_PciIdOverlap(gCfgHookTable.Hook[hookIndex].PciId, PciId))
        {
            status = STATUS_HOOK_ALREADY_SET;
            goto cleanup;
        }
    }

    if (!gCfgHookTable.IoPortsHooked)
    {
        status = HkSetIoHook(Guest, PCI_CONFIG_ADDRESS_PORT, PCI_CONFIG_DATA_PORT, 0, _PciCfgIoPortRead, _PciCfgIoPortWrite, Context);
        if (!CX_SUCCESS(status))
        {
            ERROR("HkSetIoHook failed on 0x%X - 0x%X with %s\n", PCI_CONFIG_ADDRESS_PORT, PCI_CONFIG_DATA_PORT, NtStatusToString(status));
            goto cleanup;
        }

        gCfgHookTable.IoPortsHooked = CX_TRUE;
    }

    CX_UINT64 start, end;
    _GetCfgMemRange(PciId, &start, &end);
    status = HkSetEptHook(Guest, start, end, 0, _PciCfgMemRead, _PciCfgMemWrite, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        ERROR("HkSetEptHook failed on 0x%016llX - 0x%016llX with %s\n", start, end, NtStatusToString(status));
        goto cleanup;
    }

    LOG("PCI CFG mem range hooked: 0x%016llX - 0x%016llX\n", start, end);

    gCfgHookTable.Hook[gCfgHookTable.Count].PciId = PciId;
    gCfgHookTable.Hook[gCfgHookTable.Count].ReadCb = ReadCb;
    gCfgHookTable.Hook[gCfgHookTable.Count].WriteCb = WriteCb;
    ++gCfgHookTable.Count;

    status = CX_STATUS_SUCCESS;
cleanup:
    HvReleaseRwSpinLockExclusive(&gCfgHookTable.Lock);

    return status;
}

/// @brief Callback used to intercept the reads of a hidden PCI config space (I/O and MMIO)
static
CX_STATUS
_PciHideReadPciConfig(
    _In_ CX_UINT16 Offset,
    _In_ CX_UINT16 Length,
    _Out_ CX_UINT8* Value,
    _In_ PCICFG_CONTEXT* PciCfgCtx
)
{
    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (((CX_SIZE_T)Offset + Length) > sizeof(PCI_CONFIG)) return CX_STATUS_INVALID_PARAMETER_1;
    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (PciCfgCtx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    if (Offset < FIELD_OFFSET(PCI_CONFIG_HEADER, Command))
    {
        // we want to return 0xFFFF's for Vendor and Device ID
        // we want to return 0x0000's for anything else in the PCI config space
        CX_UINT8 noOfBytesToSetToFF = (CX_UINT8)CX_MIN(Length, FIELD_OFFSET(PCI_CONFIG_HEADER, Command) - Offset);

        memset(Value, 0xFF, noOfBytesToSetToFF);

        if (Length > noOfBytesToSetToFF)
        {
            memset(PTR_ADD(Value, noOfBytesToSetToFF), 0x00, Length - noOfBytesToSetToFF);
        }

        if (CfgDebugTracePci)
        {
            LOG("HIDE: [%s] READ on PCI-CONFIG %d / %d / %d / 0x%03x, %d total bytes (give back %u bytes of 0xFF and %u bytes of 0x00) (RIP: %p)\n",
                PciCfgCtx->IsMmioAndNotIo ? "MMIO" : "IO", PciCfgCtx->PciId.Bus, PciCfgCtx->PciId.Device, PciCfgCtx->PciId.Function, Offset, Length, noOfBytesToSetToFF,
                Length - noOfBytesToSetToFF, HvGetCurrentVcpu()->ArchRegs.RIP);
        }
    }
    else
    {
        memset(Value, 0xFF, Length);

        if (CfgDebugTracePci)
        {
            LOG("HIDE: [%s] READ on PCI-CONFIG %d / %d / %d / 0x%03x, %d total bytes (give back 0xFF) (RIP: %p)\n",
                PciCfgCtx->IsMmioAndNotIo ? "MMIO" : "IO", PciCfgCtx->PciId.Bus, PciCfgCtx->PciId.Device, PciCfgCtx->PciId.Function,
                Offset, Length, HvGetCurrentVcpu()->ArchRegs.RIP);
        }
    }

    return CX_STATUS_SUCCESS;
}

/// @brief Callback used to intercept the writes of a hidden PCI config space (I/O and MMIO)
static
CX_STATUS
_PciHideWritePciConfig(
    _In_ CX_UINT16 Offset,
    _In_ CX_UINT16 Length,
    _Out_ CX_UINT8* Value,
    _In_ PCICFG_CONTEXT* PciCfgCtx
)
{
    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (((CX_SIZE_T)Offset + Length) > sizeof(PCI_CONFIG)) return CX_STATUS_INVALID_PARAMETER_1;
    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (PciCfgCtx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    // nothing to do, simply ignore
    if (CfgDebugTracePci)
    {
        LOG("HIDE: [%s] WRITE on PCI-CONFIG %d / %d / %d / 0x%03x, %d bytes (ignore) (RIP: %p)\n",
            PciCfgCtx->IsMmioAndNotIo ? "MMIO" : "IO", PciCfgCtx->PciId.Bus, PciCfgCtx->PciId.Device, PciCfgCtx->PciId.Function,
            Offset, Length, HvGetCurrentVcpu()->ArchRegs.RIP);
    }

    return CX_STATUS_SUCCESS;
}

/// @brief Callback used for tracing the reads of a PCI config space (I/O and MMIO)
static
CX_STATUS
_PciTraceReadPciConfig(
    _In_ CX_UINT16 Offset,
    _In_ CX_UINT16 Length,
    _Out_ CX_UINT8* Value,
    _In_ PCICFG_CONTEXT* PciCfgCtx
)
{
    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (((CX_SIZE_T)Offset + Length) > sizeof(PCI_CONFIG)) return CX_STATUS_INVALID_PARAMETER_1;
    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (PciCfgCtx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    LOG("[%s] READ on PCI-CONFIG %d:%d:%d / 0x%03x, %d total bytes (RIP: %p)\n",
        PciCfgCtx->IsMmioAndNotIo ? "MMIO" : "IO", PciCfgCtx->PciId.Bus, PciCfgCtx->PciId.Device, PciCfgCtx->PciId.Function,
        Offset, Length, HvGetCurrentVcpu()->ArchRegs.RIP);

    return STATUS_EXECUTE_ON_BARE_METAL;
}

/// @brief Callback used for tracing the writes of a PCI config space (I/O and MMIO)
static
CX_STATUS
_PciTraceWritePciConfig(
    _In_ CX_UINT16 Offset,
    _In_ CX_UINT16 Length,
    _Out_ CX_UINT8* Value,
    _In_ PCICFG_CONTEXT* PciCfgCtx
)
{
    if (Length == 0) return CX_STATUS_INVALID_PARAMETER_2;
    if (((CX_SIZE_T)Offset + Length) > sizeof(PCI_CONFIG)) return CX_STATUS_INVALID_PARAMETER_1;
    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (PciCfgCtx == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    LOG("[%s] WRITE on PCI-CONFIG %d:%d:%d / 0x%03x, %d total bytes (RIP: %p)\n",
        PciCfgCtx->IsMmioAndNotIo ? "MMIO" : "IO", PciCfgCtx->PciId.Bus, PciCfgCtx->PciId.Device, PciCfgCtx->PciId.Function,
        Offset, Length, HvGetCurrentVcpu()->ArchRegs.RIP);

    return STATUS_EXECUTE_ON_BARE_METAL;
}

CX_STATUS
PciAddPciCfgToHiddenList(
    _In_ PCICFG_ID PciId
)
{
    if (gHiddenPciDeviceCount == MAX_PCICFG_HIDDEN_DEVICE_COUNT) return CX_STATUS_NO_MORE_ENTRIES;

    gHiddenPciDevices[gHiddenPciDeviceCount++].PciId = PciId;

    return CX_STATUS_SUCCESS;
}

CX_BOOL
PciIsPciCfgHidden(
    _In_ PCICFG_ID PciId
)
{
    for (CX_UINT8 index = 0; index < gHiddenPciDeviceCount; ++index)
    {
        if (_PciIdOverlap(PciId, gHiddenPciDevices[index].PciId))
        {
            return CX_TRUE;
        }
    }

    return CX_FALSE;
}

CX_STATUS
PciApplyPciCfgHooksForHiding(
    _In_ GUEST* Guest
)
{
    for (CX_UINT8 index = 0; index < gHiddenPciDeviceCount; ++index)
    {
        CX_STATUS status = PciSetPciCfgHook(Guest, gHiddenPciDevices[index].PciId, _PciHideReadPciConfig, _PciHideWritePciConfig, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            ERROR("PciSetPciCfgHook failed for %u:%u:%u with %s\n",
                gHiddenPciDevices[index].PciId.Bus, gHiddenPciDevices[index].PciId.Device, gHiddenPciDevices[index].PciId.Function,
                NtStatusToString(status));
            return status;
        }
        else
        {
            LOG("[HIDE] %u:%u:%u hooked for hiding\n",
                gHiddenPciDevices[index].PciId.Bus, gHiddenPciDevices[index].PciId.Device, gHiddenPciDevices[index].PciId.Function);
        }
    }

    return CX_STATUS_SUCCESS;
}

CX_VOID
PciSaveRestoreHiddenDevicesState(
    _In_ CX_BOOL Save
)
{
    for (CX_UINT8 index = 0; index < gHiddenPciDeviceCount; ++index)
    {
        volatile CX_UINT8* cfgShadow = (CX_UINT8*)PciGetConfigSpaceVa(gHiddenPciDevices[index].PciId.Bus, gHiddenPciDevices[index].PciId.Device, gHiddenPciDevices[index].PciId.Function);
        if (Save)
        {
            for (CX_UINT8 i = 0; i < PCI_BASE_CONFIG_SPACE_SIZE; i++)
            {
                gHiddenPciDevices[index].CfgPartialShadow[i] = cfgShadow[i];
            }

            PciPowerOffPciDevice((CX_UINT8)gHiddenPciDevices[index].PciId.Bus, (CX_UINT8)gHiddenPciDevices[index].PciId.Device, (CX_UINT8)gHiddenPciDevices[index].PciId.Function);
        }
        else
        {
            for (CX_UINT8 i = 0; i < 16; i++)
            {
                cfgShadow[i] = gHiddenPciDevices[index].CfgPartialShadow[i];
            }

            PciPowerOnPciDevice((CX_UINT8)gHiddenPciDevices[index].PciId.Bus, (CX_UINT8)gHiddenPciDevices[index].PciId.Device, (CX_UINT8)gHiddenPciDevices[index].PciId.Function);
        }
    }
}

CX_STATUS PciTraceDevice(
    _In_ GUEST* Guest,
    _In_ PCICFG_ID PciId
)
{
    CX_STATUS status = PciSetPciCfgHook(Guest, PciId, _PciTraceReadPciConfig, _PciTraceWritePciConfig, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        ERROR("PciSetPciCfgHook failed for %u:%u:%u with %s\n", PciId.Bus, PciId.Device, PciId.Function, NtStatusToString(status));
    }
    else
    {
        LOG("[TRACE] %u:%u:%u hooked for tracing\n", PciId.Bus, PciId.Device, PciId.Function);
    }

    return status;
}

/// @}

CX_STATUS
PciPreinitSystemPci(
    _Out_ PCI_SYSTEM** PciSystem
    )
{
    CX_UINT32 i;
    PCI_SYSTEM* ps;

    if (PciSystem == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    CX_STATUS status = HpAllocWithTagCore(&ps, sizeof(PCI_SYSTEM), TAG_DEV);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore failed", status);
        return status;
    }

    ps->HostCtrlCount = 0;
    ps->BusCount = 0;

    for (i = 0; i < MAX_PCI_HOST_CONTROLLER; i++)
    {
        ps->HostCtrl[i] = CX_NULL;
    }

    memzero(&ps->BarReconfigurations, sizeof(PCI_BAR_RECONF_INFO));

    memzero(&gCfgHookTable, sizeof(gCfgHookTable));
    HvInitRwSpinLock(&gCfgHookTable.Lock, "PciCfgHook", CX_NULL);

    HvInitSpinLock(&ps->ScanLock, "PciScanlock", CX_NULL);

    *PciSystem = ps;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciConfigAddControllerToHost(
    _In_ PCI_SYSTEM* PciSystem,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT16 PciSegment,
    _In_ CX_UINT8 StartBusNumber,
    _In_ CX_UINT8 EndBusNumber
    )
{
    CX_STATUS status;
    PCI_HOSTCTRL* ctrl;

    if (PciSystem == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (PciSystem->HostCtrlCount >= MAX_PCI_HOST_CONTROLLER)
    {
        LOG("WARNING: too many PCI Express HOST controllers !!!\n");
        return STATUS_TOO_MANY_DEVICES;
    }

    status = HpAllocWithTagCore(&ctrl, sizeof(PCI_HOSTCTRL), TAG_DEV);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        return status;
    }

    PciSystem->HostCtrl[PciSystem->HostCtrlCount] = ctrl;

    ctrl->HostCtrlIndex = PciSystem->HostCtrlCount;
    ctrl->BusCount = 0;
    ctrl->ConfigPa = PhysicalAddress;
    ctrl->Config = CX_NULL;
    ctrl->PciSegment = PciSegment;
    ctrl->StartBusNumber = StartBusNumber;
    ctrl->EndBusNumber = EndBusNumber;
    ctrl->ConfigLen = ((CX_UINT64)EndBusNumber - StartBusNumber + 1) * MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE * 4096;    // 4K MMIO space / function

    // if below 1T, map directly (identity mapping) to HV VA space
    if ((PhysicalAddress < NAPOCA_KERNEL_BASE) &&
        (PhysicalAddress + ctrl->ConfigLen - 1 < NAPOCA_KERNEL_BASE))
    {
        status = MmMap(&gHvMm, (MM_UNALIGNED_VA)PhysicalAddress, PhysicalAddress, CX_NULL, CX_NULL, 0, CX_NULL, ctrl->ConfigLen, TAG_PCI, MM_RIGHTS_RW, MM_CACHING_UC, MM_GUARD_NONE, MM_GLUE_NONE, (MM_UNALIGNED_VA)&ctrl->Config, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG("ERROR: couldn't reserve identity 1:1 VA space for PCI Express HOST ctrl at PA %018p / length %018p!!!\n", ctrl->ConfigPa, ctrl->ConfigLen);
            return status;
        }
    }
    else
    {
        LOG("ERROR: PCI Express HOST controller over 1T at %018p, can't configure !!!\n", PhysicalAddress);
        return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    }

    PciSystem->HostCtrlCount++;

    return CX_STATUS_SUCCESS;
}

/// @brief A recursive function used to walk through every PCI function, based on the bridge connections
///
/// @param[in] PciFunc         The starting PCI function of the walk (generally a host bridge)
/// @param[in] Parent          The parent function (generally a bridge) of the PCI function, 0 for a host bridge
/// @param[in] Callback        The callback that will be called for every PCI function
/// @param[in] Context         The optional, generic data passed for every callback
///
/// @returns    CX_STATUS_SUCCESS                   - Successful walk, every callback ran with success
/// @returns    OTHER                               - Internal error
static
CX_STATUS
_PciWalkFunctionsRec(
    _In_ PCI_FUNC *PciFunc,
    _In_opt_ PCI_FUNC *Parent,
    _In_ FUNC_PciFunctionWalkCallback* Callback,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;
    PCI_CONFIG* cfg = PciFunc->Config;

    if (CfgDebugTracePci)
    {
        LOG("PCI: found device at (%p) Bus %d, Device %d, Func %d with Vendor ID 0x%04x  Device ID 0x%04x  HeaderType %d  Class %d / %d  - " "%s %s 0x%018x\n",
            cfg, PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber, cfg->Header.VendorID, cfg->Header.DeviceID, cfg->Header.HeaderType.Type, cfg->Header.Class, cfg->Header.Subclass,
            PciVendorToString(cfg->Header.VendorID), PciClassToString(cfg->Header.Class, cfg->Header.Subclass, cfg->Header.ProgIf), cfg->Bar[0]);
    }

    status = Callback(PciFunc, Parent, Context);
    if (!CX_SUCCESS(status))
    {
        ERROR("Callback for %u:%u:%u failed with %s\n", PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber, NtStatusToString(status));
        return status;
    }

    // handle only simple PCI-to-PCI bridges and the host bridge
    if (cfg->Header.Class == PCI_CLS_BRIDGE_DEVICE && (cfg->Header.Subclass == PCI_SUBCLS_HOST_BRIDGE || cfg->Header.Subclass == PCI_SUBCLS_PCIPCI_BRIDGE))
    {
        // avoid multiple host bridges connected to bus 0 (?)
        if (cfg->Header.Subclass == PCI_SUBCLS_HOST_BRIDGE && Parent != CX_NULL) return CX_STATUS_SUCCESS;

        CX_UINT16 b = (Parent == CX_NULL) ? 0 : cfg->PciBridge.SecondaryBusNumber;

        for (CX_UINT16 d = (cfg->Header.Subclass == PCI_SUBCLS_HOST_BRIDGE) ? 1 : 0; d < MAX_PCI_DEVICE_PER_BUS; d++)
        {
            for (CX_UINT16 f = 0; f < MAX_PCI_FUNCTION_PER_DEVICE; f++)
            {
                cfg = PciGetConfigSpaceVa(b, d, f);

                // check Vendor ID - conform PCI / PCI Express specs, it will read 0xFFFF if no device / function present
                if (cfg->Header.VendorID == 0xFFFF) continue;

                PCI_FUNC pciFunc = { 0 };

                pciFunc.BusNumber = b;
                pciFunc.DevNumber = d;
                pciFunc.FuncNumber = f;

                pciFunc.DepthLvl = PciFunc->DepthLvl + 1;

                pciFunc.Config = cfg;
                pciFunc.ConfigPa = PciGetConfigSpacePa(pciFunc.BusNumber, pciFunc.DevNumber, pciFunc.FuncNumber);

                status = _PciWalkFunctionsRec(&pciFunc, PciFunc, Callback, Context);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("_PciWalkFunctionsRec", status);
                    return status;
                }
            }
        }
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciWalkFunctions(
    _In_ FUNC_PciFunctionWalkCallback* Callback,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;
    PCI_FUNC pciFunc = { 0 };

    if (Callback == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    pciFunc.BusNumber = 0;
    pciFunc.DevNumber = 0;
    pciFunc.FuncNumber = 0;

    pciFunc.DepthLvl = 0;

    pciFunc.Config = PciGetConfigSpaceVa(pciFunc.BusNumber, pciFunc.DevNumber, pciFunc.FuncNumber);
    pciFunc.ConfigPa = PciGetConfigSpacePa(pciFunc.BusNumber, pciFunc.DevNumber, pciFunc.FuncNumber);

    status = _PciWalkFunctionsRec(&pciFunc, CX_NULL, Callback, Context);
    if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("_PciWalkFunctionsRec", status);

    return status;
}

inline
PCI_CONFIG*
PciGetConfigSpaceVa(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func
)
{
    if (gHypervisorGlobalData.Pci == CX_NULL || gHypervisorGlobalData.Pci->HostCtrl == CX_NULL || gHypervisorGlobalData.Pci->HostCtrl[0]->Config == CX_NULL) return CX_NULL;
    else return gHypervisorGlobalData.Pci->HostCtrl[0]->Config + ((CX_UINT64)Bus * MAX_PCI_DEVICE_PER_BUS * MAX_PCI_FUNCTION_PER_DEVICE + (CX_UINT64)Dev * MAX_PCI_FUNCTION_PER_DEVICE + Func);
}

inline
CX_UINT64
PciGetConfigSpacePa(
    _In_ CX_UINT16 Bus,
    _In_ CX_UINT16 Dev,
    _In_ CX_UINT16 Func
)
{
    if (gHypervisorGlobalData.Pci == CX_NULL || gHypervisorGlobalData.Pci->HostCtrl == CX_NULL || gHypervisorGlobalData.Pci->HostCtrl[0]->Config == CX_NULL) return CX_NULL;
    else return (CX_UINT64)PciGetConfigSpaceVa(Bus, Dev, Func) - (CX_UINT64)gHypervisorGlobalData.Pci->HostCtrl[0]->Config + gHypervisorGlobalData.Pci->HostCtrl[0]->ConfigPa;
}


CX_INT8 *PciClassToString(
    _In_ CX_UINT8 Class,
    _In_ CX_UINT8 Subclass,
    _In_ CX_UINT8 ProgIf
    )
{
    switch (Class)
    {
    case 0x00: return "(class 0x00 legacy device)";
    case 0x01: return "Mass Storage Controller";
    case 0x02:
        switch(Subclass)
        {
        case 0x00:
            return "Network Controller";
        case 0x80:
            return "WiFi Network Controller";
        default:
            return "(unknown controller type)";
        }
    case 0x03: return "Display Controller";
    case 0x04: return "Multimedia Controller";
    case 0x05: return "Memory Controller";
    case 0x06:
        switch (Subclass)
        {
        case 0x00: return "Host Bridge";
        case 0x01: return "PCI-to-ISA Bridge";
        case 0x04: return "PCI-to-PCI Bridge";
        case 0x05: return "PCI-to-PCMCIA Bridge";
        case 0x07: return "PCI-to-CardBus Bridge";
        default:
            return "(unknown Bridge Device)";
        }
    case 0x07: return "Simple Communication Controller";
    case 0x08: return "Base System Peripheral";
    case 0x09: return "Input Device";
    case 0x0A: return "Docking Station";
    case 0x0B: return "Processor";
    case 0x0C:
        switch (Subclass)
        {
        case 0x00: return "IEEE 1394 Controller";
        case 0x03:
            switch (ProgIf)
            {
            case 0x00: return "USB - UHCI Controller";
            case 0x10: return "USB - OHCI Controller";
            case 0x20: return "USB - EHCI Controller";
            case 0x30: return "USB - xHCI Controller";
            default:
                return "(unknown USB Controller)";
            }
        case 0x05: return "SMBUS Controller";
        default:
            return "(unknown Serial Bus Controller)";
        }
    case 0x0D: return "Wireless Controller";
    case 0x0E: return "Intelligent I/O Controller";
    case 0x0F: return "Satellite Communication Controller";
    case 0x10: return "Encryption/Decryption Controller";
    case 0x11: return "Data Acquisition and Signal Processing Controller";
    case 0xFF: return "(class 0xFF unclassified device)";
    default:
        return "(unknown class)";
    }
}

CX_INT8 *PciVendorToString(
    _In_ CX_UINT16 VendorID
    )
{
    switch (VendorID)
    {
    case 0x1002: return "ATI";
    case 0x1028: return "DELL";
    case 0x104c: return "Texas Instruments";
    case 0x10ec: return "Realtek";
    case 0x1432: return "Edimax";
    case 0x1462: return "Micro-Star Intl.";
    case 0x14E4: return "Broadcom";
    case 0x168C: return "Atheros";
    case 0x8086: return "INTEL";
    case 0x9710: return "MosChip";

    default:
        return "(unknown vendor)";
    }
}

CX_INT8 *PciDeviceToString(
    _In_ CX_UINT16 VendorID,
    _In_ CX_UINT16 DeviceID
    )
{
    switch (VendorID)
    {
    case 0x1002:
        switch (DeviceID)
        {
        default:
            return "(unknown ATI device)";
        }
    case 0x1028:
        switch (DeviceID)
        {
        default:
            return "(unknown DELL device)";
        }
    case 0x104c:
        switch (DeviceID)
        {
        default:
            return "(unknown TI device)";
        }
    case 0x1106:
        switch(DeviceID)
        {
        case 0x3403:
            return "VIA IEEE 1394";
        }
    case 0x1432:
        switch (DeviceID)
        {
        default:
            return "(unknown Edimax device)";
        }
    case 0x1462:
        switch (DeviceID)
        {
        default:
            return "(unknown Micro-Star device)";
        }
    case 0x168C:
        switch (DeviceID)
        {
        case 0x0034:
            return "Atheros AR9462 Wireless Network Adapter";
        default:
            return "(unknown Atheros device)";
        }
    case 0x1814:
        switch (DeviceID)
        {
        case 0x3062:
            return "Ralink RT3062 Wireless Network Adapter";
        default:
            return "(unknown Ralink device)";
        }
    case 0x1415:
        switch (DeviceID)
        {
        case 0xC158:
            return "Oxford OXPCIe952 (2 Native UARTs)";
        case 0xC138:
            return "Oxford OXPCIe952 (1 Native UART)";
        default:
            return "(undefined Oxford Semiconductor Ltd. device)";
        }
    case 0x8086:
        switch (DeviceID)
        {
        case 0x0100:
            return "Intel DRAM Controller";
        case 0x0102:
            return "Intel Integrated Graphics Controller";
        case 0x107c:
            return "Intel 82541PI Gigabit Ethernet Controller";
        case 0x1502:
            return "Intel 82579LM Network Adapter";
        case 0x1c02:
            return "Intel SATA AHCI Controller";
        case 0x1c20:
            return "Intel Cougar Point High Definition Audio Controller";
        case 0x1c22:
            return "SMBus Controller";
        case 0x1c26:
            return "Intel USB Enhanced Host Controller #1";
        case 0x1c2d:
            return "Intel USB Enhanced Host Controller #2";
        case 0x1c3a:
            return "Intel MEI Controller #1";
        case 0x1c4c:
            return "Q65 Express Chipset Family LPC Controller";
        case 0x10d3:
            return "Intel Gigabit CT Desktop Adapter";
        case 0x105e:
            return "Intel PRO/1000 PT Server Adapter";
        case 0x4232:
            return "WiFi Link 5100 AGN";
        case 0x1c10:
            return "PCI Express Root Port 1";
        case 0x1c12:
            return "PCI Express Root Port 2";
        case 0x1c14:
            return "PCI Express Root Port 3";
        case 0x1c16:
            return "PCI Express Root Port 4";
        case 0x1c18:
            return "PCI Express Root Port 5";
        case 0x1c1a:
            return "PCI Express Root Port 6";
        case 0x1c1c:
            return "PCI Express Root Port 7";
        case 0x1c1e:
            return "PCI Express Root Port 8";
        default:
            return "(unknown INTEL device)";
        }
    case 0x9710:
        switch (DeviceID)
        {
        case 0x9912:
            return "MosChip - PCIe to Multifunction Peripheral Controller";
        default:
            return "(unknown MosChip device)";
        }
    default:
        return "(unknown vendor & device)";
    }
}

CX_STATUS
PciDecodeBar(
    _In_ PCI_BAR *Bar,
    _Out_ CX_UINT64 *Addr,
    _Out_ CX_UINT64 *Size,
    _Out_ CX_BOOL *Is64BitWide,
    _Out_ CX_BOOL *Implemented
    )
{
    CX_UINT64 addr = 0, size = 0, mask = 0;
    CX_BOOL isImplemented = CX_FALSE;
    CX_UINT32 origBar32 = 0;
    CX_UINT64 origBar64 = 0;
    CX_UINT32 bar32 = 0;
    CX_UINT64 bar64 = 0;
    CX_UINT8 j = 0;

    if (Bar == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Addr == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if (Size == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if (Is64BitWide == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;
    if (Implemented == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;

    if (Bar->Raw == 0)
    {
        // not implemented
        *Implemented = CX_FALSE;
        return CX_STATUS_SUCCESS;
    }

    //When you want to retrieve the actual base address of a BAR, be sure to mask the lower bits.
    //For 16-Bit Memory Space BARs, you calculate (BAR[x] & 0xFFF0). For 32-Bit Memory Space BARs, you calculate
    //(BAR[x] & 0xFFFFFFF0). For 64-Bit Memory Space BARs, you calculate ((BAR[x] & 0xFFFFFFF0) + ((BAR[x+1] & 0xFFFFFFFF) << 32))
    //For I/O Space BARs, you calculate (BAR[x] & 0xFFFFFFFC).
    addr = (Bar->IoSpace == 1)?PCI_GET_IOBAR_BASE(Bar):PCI_GET_MEMBAR_BASE(Bar);
    addr &= 0x00000000ffffffffULL;

    isImplemented = CX_TRUE;

    //To determine the amount of address space needed by a PCI device, you must save the original value of the BAR,
    //write a value of all 1's to the register, then read it back. The amount of memory can then be determined by masking the information bits,
    //performing a logical NOT, and incrementing the value by 1. The original value of the BAR should then be restored.

    //save the original value of the BAR
    origBar32 = Bar->Raw;

    // write 0xFFFFFFFF to the bar, and then read back
    Bar->Raw = 0xFFFFFFFFUL;
    bar32 = Bar->Raw;

    *Is64BitWide = CX_FALSE;

    // check whether it is an i/o or mem
    if (Bar->IoSpace == 0)
    {
        // init the mask for memory bar
        mask = 0xFFFFFFFFFFFFFFC0ULL;       // the lsb 7 bits are reserved, a memory bar is at least 128 bytes

        if (Bar->MemWidth == 0)
        {
            // 32 bit decoder
            for (j = 7; j < 32; j++)
            {
                if (bar32 & (1UL << j))
                {
                    // found it
                    size = 1ULL << j;
                    break;
                }
                mask = mask & ~(1ULL << j);
            }

            addr = origBar32 & (CX_UINT32)mask;

            // put back original stuff
            Bar->Raw = origBar32;
        }
        else
        {
            // 64 bit decoder
            CX_UINT32 barHigh = 0;
            CX_UINT32 oldBarHigh = 0;
            PCI_BAR *pciBarHigh;

            pciBarHigh = Bar + 1;

            oldBarHigh = pciBarHigh->Raw;
            barHigh = pciBarHigh->Raw;
            origBar64 = ((CX_UINT64)origBar32 & 0x0FFFFFFFFULL) | (CX_UINT64)((CX_UINT64)barHigh << 32);
            // write 0xFFFFFFFF to bar64 high
            pciBarHigh->Raw = 0xFFFFFFFFUL;

            // read back the needed bar64 high
            barHigh = pciBarHigh->Raw;
            bar64 = ((CX_UINT64)bar32 & 0x0FFFFFFFFULL) | (CX_UINT64) ((CX_UINT64)barHigh << 32);

            for (j = 7; j < 64; j++)
            {
                if (bar64 & (1ULL << j))
                {
                    // found it
                    size = 1ULL << j;
                    break;
                }
                mask = mask & ~(1ULL << j);
            }

            addr = origBar64 & mask;

            // put back the original bar
            pciBarHigh->Raw = oldBarHigh;
            Bar->Raw = (CX_UINT32)origBar64;

            *Is64BitWide = CX_TRUE;
        }
    }
    else
    {
        // i/o space bar
        mask = 0xFFFFFFFFFFFFFFFCULL;   // the lsb 2 bits are reserved

        // i/o space bars are always 32 bit decoders
        for (j = 2; j < 32; j++)
        {
            if (bar32 & (1UL << j))
            {
                // found it
                size = 1ULL << j;
                break;
            }
            mask = mask & ~(1ULL << j);
        }

        addr = origBar32 & (CX_UINT32)mask;

        // put back original value
        Bar->Raw = origBar32;
    }

    *Addr = addr;
    *Size = size;
    *Implemented = isImplemented;

    return CX_STATUS_SUCCESS;
}


CX_STATUS
PciStoreBarReconfigurationDataOnHibernate(
    _Inout_         PCI_BAR_RECONF_INFO     *BarReconfigurations
)
{
    if (BarReconfigurations == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;

    PCI_SYSTEM* pciSystem = gHypervisorGlobalData.Pci;

    HvAcquireSpinLock(&pciSystem->ScanLock);

    // reset the Count in the Hibernate Persistence data structure as the memory zone is consistent and the count is
    // continued otherwise.
    BarReconfigurations->EntryCount = 0;

    for (CX_UINT32 i = 0; i < pciSystem->BarReconfigurations.EntryCount; i++)
    {
        BarReconfigurations->EntryCount++;
        BarReconfigurations->Reconfigurations[i] = pciSystem->BarReconfigurations.Reconfigurations[i];
    }

    HvReleaseSpinLock(&pciSystem->ScanLock);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciRestoreBarReconfigurationDataOnHibernate(
    _In_               PCI_BAR_RECONF_INFO     *BarReconfigurations

)
{
    CX_STATUS status;

    if (BarReconfigurations == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;

    GUEST* guest = HvGetCurrentGuest();
    if (guest == CX_NULL) return CX_STATUS_INVALID_INTERNAL_STATE;

    PCI_SYSTEM* pciSystem = gHypervisorGlobalData.Pci;

    HvAcquireSpinLock(&pciSystem->ScanLock);

    status = CX_STATUS_SUCCESS;

    for (CX_UINT32 i = 0; i < BarReconfigurations->EntryCount; i++)
    {
        CX_STATUS localStatus;
        pciSystem->BarReconfigurations.EntryCount++;
        pciSystem->BarReconfigurations.Reconfigurations[i] = BarReconfigurations->Reconfigurations[i];

        LOG("Reconfigured BAR address is %p aligned address is %p, size is 0x%X (pages: 0x%X)\n",
            pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress,
            PAGE_BASE_PA(pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress),
            pciSystem->BarReconfigurations.Reconfigurations[i].Size,
            CX_PAGE_COUNT_4K(pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress, pciSystem->BarReconfigurations.Reconfigurations[i].Size));

        localStatus = EptMapDevMem(
                GstGetEptOfPhysicalMemory(guest),
                pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress,
                pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress,
                pciSystem->BarReconfigurations.Reconfigurations[i].Size);
        if (!CX_SUCCESS(localStatus))
        {
            LOG_FUNC_FAIL("EptMapDevMem", localStatus);
            status = localStatus;
        }
        else
        {
            MEM_MAP_ENTRY entry = { 0 };

            entry.StartAddress = PAGE_BASE_PA(pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress);
            entry.Length = CX_PAGE_COUNT_4K(pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress, pciSystem->BarReconfigurations.Reconfigurations[i].Size) * CX_PAGE_SIZE_4K;
            entry.DestAddress = PAGE_BASE_PA(pciSystem->BarReconfigurations.Reconfigurations[i].BarAddress);
            entry.Type = BOOT_MEM_TYPE_AVAILABLE;
            entry.CacheAndRights = (EPT_RAW_CACHING_UC | EPT_RAW_RIGHTS_RWX);

            localStatus = MmapApplyNewEntry(&guest->MmioMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
            if (!CX_SUCCESS(localStatus))
            {
                LOG_FUNC_FAIL("MmapApplyNewEntry", status);
                status = localStatus;
            }
        }

    }

    HvReleaseSpinLock(&pciSystem->ScanLock);

    return status;
}

/// @brief Callback used for BAR reconfiguration scanning
static
CX_STATUS
_PciScanAllPciDeviceBarReconfigurationsCallback(
    _In_ PCI_FUNC* PciFunc,
    _In_opt_ PCI_FUNC* Parent,
    _In_opt_ CX_VOID* Context
)
{
    CX_STATUS status;
    PCI_CONFIG* cfg = PciFunc->Config;

    GUEST* guest = HvGetCurrentGuest();

    if (guest == CX_NULL) return CX_STATUS_INVALID_INTERNAL_STATE;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Parent);

    if (cfg->Header.Class == PCI_CLS_BRIDGE_DEVICE && (cfg->Header.Subclass == PCI_SUBCLS_HOST_BRIDGE || cfg->Header.Subclass == PCI_SUBCLS_PCIPCI_BRIDGE))
    {
        // skip the "bridges"
        return CX_STATUS_SUCCESS;
    }

    for (CX_UINT8 i = 0; i < MAX_PCI_BARS_TYPE0;)
    {
        CX_UINT64 addr = 0, size = 0;
        CX_BOOL Is64BitWide = CX_FALSE, Implemented = CX_FALSE;

        status = PciDecodeBar(&PciFunc->Config->Bar[i], &addr, &size, &Is64BitWide, &Implemented);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("PciDecodeBar", status);
        }
        else if ((!PciFunc->Config->Bar[i].NotMemSpace) && (size > 0) && (Implemented) && (addr > 0))
        {
            CX_UINT64 hpa;
            // check if it is already mapped
            status = ChmGpaToHpa(guest, addr, &hpa);
            if (!CX_SUCCESS(status) || hpa == 0)
            {
                if (CfgDebugTracePci) VCPULOG(HvGetCurrentVcpu(), "Reconfigured BAR address is %p aligned address is %p, size is 0x%X (pages: 0x%X)\n",
                    addr, PAGE_BASE_PA(addr), size, CX_PAGE_COUNT_4K(addr, size));
                status = EptMapDevMem(GstGetEptOfPhysicalMemory(guest), addr, addr, size);
                if (!CX_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("EptMapDevMem", status);
                }
                else
                {
                    MEM_MAP_ENTRY entry = { 0 };
                    CX_STATUS localStatus;

                    entry.StartAddress = PAGE_BASE_PA(addr);
                    entry.Length = CX_PAGE_COUNT_4K(addr, size) * CX_PAGE_SIZE_4K;
                    entry.DestAddress = PAGE_BASE_PA(addr);
                    entry.Type = BOOT_MEM_TYPE_AVAILABLE;
                    entry.CacheAndRights = (EPT_RAW_CACHING_UC | EPT_RAW_RIGHTS_RWX);

                    localStatus = MmapApplyNewEntry(&guest->MmioMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
                    if (!CX_SUCCESS(localStatus))
                    {
                        LOG_FUNC_FAIL("MmapApplyNewEntry", localStatus);
                    }
                    else
                    {
                        PCI_BAR_RECONF_INFO* pbri = &gHypervisorGlobalData.Pci->BarReconfigurations;
                        // add to BarReconfigurations to restore on hibernate resume, avoid 9Fs on certain machines
                        if (pbri->EntryCount < MAX_MEMORY_BAR_RECONFIGURATIONS)
                        {
                            pbri->Reconfigurations[pbri->EntryCount].BarAddress = addr;
                            pbri->Reconfigurations[pbri->EntryCount].Size = size;
                            pbri->EntryCount++;
                        }
                        else
                        {
                            WARNING("Maximum hibernate persistent BAR Reconfigurations exceeded!\n");
                        }
                        CpuVmxInvEpt(2, 0, 0);
                    }
                }
            }
        }

        if (Is64BitWide) i += 2;
        else i++;
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciScanAllPciDeviceBarReconfigurations(
    CX_VOID
)
{
    CX_STATUS status;

    HvAcquireSpinLock(&gHypervisorGlobalData.Pci->ScanLock);

    status = PciWalkFunctions(_PciScanAllPciDeviceBarReconfigurationsCallback, CX_NULL);
    if (!CX_SUCCESS(status)) ERROR("PciWalkFunctions failed for PCI BAR reconfigurations with %s\n", NtStatusToString(status));

    HvReleaseSpinLock(&gHypervisorGlobalData.Pci->ScanLock);

    return status;
}

/// @brief Callback used to print information about PCI devices
static
CX_STATUS
_PciCfgDump(
    _In_ PCI_FUNC* PciFunc,
    _In_opt_ PCI_FUNC* Parent,
    _In_opt_ CX_VOID* Context
)
{
    CX_INT8 padding[32] = { 0 };
    PCI_CONFIG* cfg = PciFunc->Config;

    UNREFERENCED_PARAMETER(Parent);

    memset(padding, ' ', (CX_SIZE_T)2 * PciFunc->DepthLvl);

    LOGN("%s<PCI FUNCTION on %u:%u:%u |%s cfgva: 0x%018X cfgpa: 0x%018X> 0x%04X/0x%04X %s - %s (class: 0x%02X subclass: 0x%02X)\n",
        padding,
        PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber,
        PciIsPciCfgHidden((PCICFG_ID) { 0, PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber }) ? "HIDDEN|" : "",
        PciGetConfigSpaceVa(PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber),
        PciGetConfigSpacePa(PciFunc->BusNumber, PciFunc->DevNumber, PciFunc->FuncNumber),
        cfg->Header.VendorID, cfg->Header.DeviceID,
        PciDeviceToString(cfg->Header.VendorID, cfg->Header.DeviceID),
        PciClassToString(cfg->Header.Class, cfg->Header.Subclass, cfg->Header.ProgIf),
        cfg->Header.Class, cfg->Header.Subclass);

    CX_BOOL* toDumpResources = Context;
    if (*toDumpResources)
    {
        CX_UINT8 barCount;

        if (cfg->Header.HeaderType.Type == 0x00) barCount = MAX_PCI_BARS_TYPE0;
        else barCount = MAX_PCI_BARS_TYPE1;

        CX_UINT8 idx = 0;
        while (idx < barCount)
        {
            PCI_BAR* bar = &(cfg->Bar[idx]);
            CX_UINT64 length;
            CX_UINT64 baseAddress;
            CX_BOOL is64, implemented, isIoBar;

            isIoBar = !!bar->IoSpace;

            CX_STATUS status = PciDecodeBar(bar, &baseAddress, &length, &is64, &implemented);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("PciDecodeBar", status);
                return status;
            }

            // if the bar is not valid, skip it
            if (!implemented)
            {
                if (is64) idx += 2;
                else ++idx;
                continue;
            }

            if (isIoBar) LOGN("%s  I/O:  0x%04X - 0x%04X\n", padding, baseAddress, baseAddress + length - 1);
            else LOGN("%s  MMIO: 0x%018X - 0x%018X\n", padding, baseAddress, baseAddress + length - 1);

            if (is64) idx += 2;
            else ++idx;
        }
    }

    return CX_STATUS_SUCCESS;
}

CX_STATUS
PciDumpDevice3(
    CX_BOOL DumpResources
)
{
    CX_BOOL dumpRes = DumpResources;

    return PciWalkFunctions(_PciCfgDump, &dumpRes);
}
