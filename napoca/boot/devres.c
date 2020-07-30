/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "boot/devres.h"
#include "kernel/kernel.h"

#pragma warning (push)
#define ACPI_USE_SYSTEM_CLIBRARY       // We disabled the C Runtime Library at build in ACPICA but we don't want it to pollute our namespace with its own implementation
#include "accommon.h"
#include "acnamesp.h"
#pragma warning (pop)

/// @brief Checks for the validity of an Address Space Resource Descriptor
///
/// Based on ACPI documentation(ACPI_6_3_final_Jan30): 6.4.3.5 Address Space Resource Descriptors
///
/// @param[in]  Min             Minimum Address Fixed
/// @param[in]  Max             Maximum Address Fixed
/// @param[in]  Length          Range length
///
/// @returns    TRUE                                - The descriptor is valid
/// @returns    FALSE                               - The descriptor is invalid
static
CX_BOOL
_AcpiIsAddressSpaceDescriptorValid(
    _In_ CX_UINT64 Min,
    _In_ CX_UINT64 Max,
    _In_ CX_UINT64 Length
)
{
    // ACPI 6.1 - 6.4.3.5 Address Space Resource Descriptors
    if ((Min && Max && !Length) ||
        (Min != Max && Length))
        // additional verification might be needed(example Min == 0 && Max == 0 && Length = 1 (?))
    {
        return CX_FALSE;
    }

    return CX_TRUE;
}

/// @brief Callback passed to AcpiWalkResources, helping us to dissect/filter the resources of the given device
static
ACPI_STATUS
_AcpiAddMemEntriesWalkCallback(
    _In_ ACPI_RESOURCE           *Resource,
    _In_ void                    *Context
)
{
    CX_STATUS status;
    MEM_MAP_ENTRY newEntry;
    CX_UINT64 startAddress;
    CX_UINT64 length;

    UNREFERENCED_PARAMETER(Context);

    // out of 20 types of resources 7 of them can be memory related
    switch (Resource->Type)
    {
    case ACPI_RESOURCE_TYPE_MEMORY24:
    {
        if (CfgDebugTraceAcpi)
        {
            LOG("   Type MEMORY24: 0x%06X - 0x%06X(length 0%06X), rights 0x%02X\n",
                Resource->Data.Memory24.Minimum << 8,
                Resource->Data.Memory24.Maximum << 8,
                Resource->Data.Memory24.AddressLength << 8,
                Resource->Data.Memory24.WriteProtect);
        }

        startAddress = (CX_UINT64)Resource->Data.Memory24.Minimum << 8;
        length = (CX_UINT64)Resource->Data.Memory24.AddressLength << 8;

        break;
    }
    case ACPI_RESOURCE_TYPE_MEMORY32:
    {
        if (CfgDebugTraceAcpi)
        {
            LOG("   Type MEMORY32: 0x%08X - 0x%08X(length 0%08X), rights 0x%02X\n",
                Resource->Data.Memory32.Minimum,
                Resource->Data.Memory32.Maximum,
                Resource->Data.Memory32.AddressLength,
                Resource->Data.Memory32.WriteProtect);
        }

        startAddress = (CX_UINT64)Resource->Data.Memory32.Minimum;
        length = (CX_UINT64)Resource->Data.Memory32.AddressLength;

        break;
    }
    case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
    {
        if (CfgDebugTraceAcpi)
        {
            LOG("   Type FIXED_MEMORY32: 0x%08X - 0x%08X, rights 0x%02X\n",
                Resource->Data.FixedMemory32.Address,
                Resource->Data.FixedMemory32.AddressLength,
                Resource->Data.FixedMemory32.WriteProtect);
        }

        startAddress = (CX_UINT64)Resource->Data.FixedMemory32.Address;
        length = (CX_UINT64)Resource->Data.FixedMemory32.AddressLength;

        break;
    }
    case ACPI_RESOURCE_TYPE_ADDRESS16:
    {
        if (Resource->Data.Address16.ResourceType == ACPI_MEMORY_RANGE &&
            _AcpiIsAddressSpaceDescriptorValid(
                Resource->Data.Address16.MinAddressFixed,
                Resource->Data.Address16.MaxAddressFixed,
                Resource->Data.Address16.Address.AddressLength
            ))
        {
            if (CfgDebugTraceAcpi)
            {
                LOG("   Type ADDRESS16: 0x%04X - 0x%04X(length 0x%04X), rights 0x%02X, caching 0x%02X\n",
                    Resource->Data.Address16.Address.Minimum,
                    Resource->Data.Address16.Address.Maximum,
                    Resource->Data.Address16.Address.AddressLength,
                    Resource->Data.Address16.Info.Mem.WriteProtect,
                    Resource->Data.Address16.Info.Mem.Caching);
            }

            startAddress = Resource->Data.Address16.Address.Minimum;
            length = Resource->Data.Address16.Address.AddressLength;
        }
        else
        {
            // not a memory descriptor OR an invalid one
            return AE_OK;
        }

        break;
    }
    case ACPI_RESOURCE_TYPE_ADDRESS32:
    {
        if (Resource->Data.Address32.ResourceType == ACPI_MEMORY_RANGE &&
            _AcpiIsAddressSpaceDescriptorValid(
                Resource->Data.Address32.MinAddressFixed,
                Resource->Data.Address32.MaxAddressFixed,
                Resource->Data.Address32.Address.AddressLength
            ))
        {
            if (CfgDebugTraceAcpi)
            {
                LOG("   Type ADDRESS32: 0x%08X - 0x%08X(length 0x%08X), rights 0x%02X, caching 0x%02X\n",
                    Resource->Data.Address32.Address.Minimum,
                    Resource->Data.Address32.Address.Maximum,
                    Resource->Data.Address32.Address.AddressLength,
                    Resource->Data.Address32.Info.Mem.WriteProtect,
                    Resource->Data.Address32.Info.Mem.Caching);
            }

            startAddress = Resource->Data.Address32.Address.Minimum;
            length = Resource->Data.Address32.Address.AddressLength;
        }
        else
        {
            // not a memory descriptor OR an invalid one
            return AE_OK;
        }

        break;
    }
    case ACPI_RESOURCE_TYPE_ADDRESS64:
    {
        if (Resource->Data.Address64.ResourceType == ACPI_MEMORY_RANGE &&
            _AcpiIsAddressSpaceDescriptorValid(
                Resource->Data.Address64.MinAddressFixed,
                Resource->Data.Address64.MaxAddressFixed,
                Resource->Data.Address64.Address.AddressLength
            ))
        {
            if (CfgDebugTraceAcpi)
            {
                LOG("   Type ADDRESS64: %018p - %018p(length %018p), rights 0x%02X, caching 0x%02X\n",
                    Resource->Data.Address64.Address.Minimum,
                    Resource->Data.Address64.Address.Maximum,
                    Resource->Data.Address64.Address.AddressLength,
                    Resource->Data.Address64.Info.Mem.WriteProtect,
                    Resource->Data.Address64.Info.Mem.Caching);
            }

            startAddress = Resource->Data.Address64.Address.Minimum;
            length = Resource->Data.Address64.Address.AddressLength;
        }
        else
        {
            // not a memory descriptor OR an invalid one
            return AE_OK;
        }

        break;
    }
    case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
    {
        if (Resource->Data.ExtAddress64.ResourceType == ACPI_MEMORY_RANGE &&
            _AcpiIsAddressSpaceDescriptorValid(
                Resource->Data.ExtAddress64.MinAddressFixed,
                Resource->Data.ExtAddress64.MaxAddressFixed,
                Resource->Data.ExtAddress64.Address.AddressLength
            ))
        {
            if (CfgDebugTraceAcpi)
            {
                LOG("   Type EXTENDED_ADDRESS64: %018p - %018p(length %018p), rights 0x%08X, caching 0x%08X\n",
                    Resource->Data.ExtAddress64.Address.Minimum,
                    Resource->Data.ExtAddress64.Address.Maximum,
                    Resource->Data.ExtAddress64.Address.AddressLength,
                    Resource->Data.ExtAddress64.Info.Mem.WriteProtect,
                    Resource->Data.ExtAddress64.Info.Mem.Caching);
            }

            startAddress = (CX_UINT64)Resource->Data.ExtAddress64.Address.Minimum;
            length = (CX_UINT64)Resource->Data.ExtAddress64.Address.AddressLength;
        }
        else
        {
            // not a memory descriptor OR an invalid one
            return AE_OK;
        }

        break;
    }
    case ACPI_RESOURCE_TYPE_END_TAG:
    {
        if (CfgDebugTraceAcpi) LOG("   Type END_TAG (the correct end of the resource buffer)\n");

        return AE_OK;
    }
    default:
        // any other type of resource will be ignored
        if (CfgDebugTraceAcpi) LOG("   Unhandled / uninteresting resource type: %d\n", Resource->Type);

        return AE_OK;
    }

    if (0 == length)
    {
        // sometimes we find entries with 0 length
        if (CfgDebugTraceAcpi) LOG("   Length is 0, IGNORING the entry\n");

        return AE_OK;
    }

    if (CX_PAGE_OFFSET_4K(startAddress) != 0)
    {
        // sometime we find entries with funky addresses
        if (CfgDebugTraceAcpi) LOG("   Start address is UNALIGNED, IGNORING the entry\n");

        return AE_OK;
    }

    // only in case of a valid descriptor
    newEntry.Type = BOOT_MEM_TYPE_AVAILABLE;
    newEntry.Length = CX_PAGE_SIZE_4K * CX_PAGE_COUNT_4K(startAddress, length);
    newEntry.StartAddress = PAGE_BASE_PA(startAddress);
    newEntry.CacheAndRights = 0;
    newEntry.DestAddress = 0;

    status = MmapApplyNewEntry(&gHypervisorGlobalData.MemInfo.AcpiMap, &newEntry, MMAP_SPLIT_AND_KEEP_NEW);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyNewEntry", status);
        return AE_ERROR;
    }

    return AE_OK;
}

/// @brief Checks for the presence of a given device
///
/// Based on the return value of the _STA method
///
/// @param[in]  ObjHandle       ACPI handle to the device for which the _STA will be executed
///
/// @returns    TRUE                                - The device is present
/// @returns    FALSE                               - The device is not present
static
CX_BOOL
_AcpiIsDevicePresent(
    _In_ ACPI_HANDLE ObjHandle
)
{
    ACPI_STATUS acpiStatus;
    ACPI_OBJECT outArg = { 0 };
    ACPI_BUFFER outBuffer;

    outBuffer.Length = sizeof(outArg);
    outBuffer.Pointer = &outArg;
    acpiStatus = AcpiEvaluateObject(ObjHandle, METHOD_NAME__STA, CX_NULL, &outBuffer);
    if (ACPI_FAILURE(acpiStatus))
    {
        if (CfgDebugTraceAcpi) ERROR("Failed to call %s! status 0x%x\n", METHOD_NAME__STA, acpiStatus);
    }
    else
    {
        if (outArg.Type == ACPI_TYPE_INTEGER && !outArg.Integer.Value)
        {
            if (CfgDebugTraceAcpi) LOG("Skip device due to ACPI _STA value %d\n", outArg.Integer.Value);
            return CX_FALSE;
        }
    }

    // return "present" even in case of a failure (_STA not present must be included)
    return CX_TRUE;
}


/// @brief Callback passed to AcpiWalkNamespace, helping to query _CRS for every device
static
ACPI_STATUS
_AcpiAddMemEntries(
    _In_ ACPI_HANDLE                  ObjHandle,
    _In_ CX_UINT32                    NestingLevel,
    _In_ CX_VOID                      *Context,
    __out_opt void                    **ReturnValue
)
{
    ACPI_STATUS acpiStatus;

    UNREFERENCED_PARAMETER(NestingLevel);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ReturnValue);

    if (ObjHandle == CX_NULL) return AE_OK;

    if (CfgDebugTraceAcpi)
    {
        char *DevicePath = CX_NULL;

        DevicePath = AcpiNsGetExternalPathname(ACPI_CAST_PTR(ACPI_NAMESPACE_NODE, ObjHandle));
        if (!DevicePath) return AE_NO_MEMORY;

        LOG("Device path: %s\n", DevicePath);
        ACPI_FREE(DevicePath);
    }

    ACPI_DEVICE_INFO *adi;
    CX_BOOL skipDevice = CX_FALSE;

    acpiStatus = AcpiGetObjectInfo(ObjHandle, &adi);
    if (ACPI_SUCCESS(acpiStatus))
    {
        if (adi->Flags & ACPI_PCI_ROOT_BRIDGE)
        {
            if (CfgDebugTraceAcpi) LOG("Skipping device: ROOT bridge\n");
            skipDevice = CX_TRUE;
        }
    }
    ACPI_FREE(adi);

    if (!_AcpiIsDevicePresent(ObjHandle)) skipDevice = CX_TRUE;

    if (skipDevice) return AE_OK;

    acpiStatus = AcpiWalkResources(ObjHandle, METHOD_NAME__CRS, _AcpiAddMemEntriesWalkCallback, CX_NULL);
    if (ACPI_FAILURE(acpiStatus))
    {
        if (CfgDebugTraceAcpi) ERROR("AcpiWalkResources failed with %s\n", AcpiFormatException(acpiStatus));
    }

    return AE_OK;
}

CX_STATUS
DevresLoadMemoryResourcesAcpi(
    CX_VOID
    )
{
    CX_STATUS status;
    ACPI_STATUS acpiStatus;

    do
    {
        // allocate entries for memory map
        status = MmapAllocMapEntries(&gHypervisorGlobalData.MemInfo.AcpiMap, 64);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmapAllocMapEntries", status);
            break;
        }

        acpiStatus = AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT, ACPI_UINT32_MAX, _AcpiAddMemEntries, CX_NULL, CX_NULL, CX_NULL);
        if (ACPI_FAILURE(acpiStatus))
        {
            ERROR("AcpiWalkNamespace failed with status=%s\n", AcpiFormatException(acpiStatus));
            status = CX_STATUS_INVALID_INTERNAL_STATE;
            break;
        }

        status = CX_STATUS_SUCCESS;

    } while (0);

    return status;
}
