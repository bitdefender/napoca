/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "debug.h"
#include "debug_guids.h"

void
UefiDbgDumpMemoryMap(
    void
    )
{
    EFI_MEMORY_DESCRIPTOR   *descriptor;
    UINT64                  i;
    EFI_MEMORY_DESCRIPTOR   *MemoryMap;
    UINT64                  DescriptorSize;
    UINT64                  NumberOfMemoryDescriptors;


    //
    // Get a fresh memory map
    //
    if (EFI_ERROR(UefiGetMemoryMap(&MemoryMap, &DescriptorSize, &NumberOfMemoryDescriptors, NULL))) // reuse the stack vars
    {
        TRACE(L"Failed getting a memory map\r\n");
        return;
    }

    //
    // Parse the map
    //
    for (i = 0; i < NumberOfMemoryDescriptors; i++)
    {
        descriptor = (EFI_MEMORY_DESCRIPTOR*) ((BYTE*)MemoryMap + (i * DescriptorSize));

        TRACE(L"0x%016LX - 0x%016LX  (%Ld pages)",
            descriptor->PhysicalStart, 4096 * descriptor->NumberOfPages, descriptor->NumberOfPages);

        if (descriptor->Type == EfiReservedMemoryType) TRACE(L"    --> EfiReservedMemoryType");
        else if (descriptor->Type == EfiLoaderCode) TRACE(L"    --> EfiLoaderCode");
        else if (descriptor->Type == EfiLoaderData) TRACE(L"    --> EfiLoaderData");
        else if (descriptor->Type == EfiBootServicesCode) TRACE(L"    --> EfiBootServicesCode");
        else if (descriptor->Type == EfiBootServicesData) TRACE(L"    --> EfiBootServicesData");
        else if (descriptor->Type == EfiRuntimeServicesCode) TRACE(L"    --> EfiRuntimeServicesCode");
        else if (descriptor->Type == EfiRuntimeServicesData) TRACE(L"    --> EfiRuntimeServicesData");
        else if (descriptor->Type == EfiConventionalMemory) TRACE(L"    --> EfiConventionalMemory");
        else if (descriptor->Type == EfiUnusableMemory) TRACE(L"    --> EfiUnusableMemory");
        else if (descriptor->Type == EfiACPIReclaimMemory) TRACE(L"    --> EfiACPIReclaimMemory");
        else if (descriptor->Type == EfiACPIMemoryNVS) TRACE(L"    --> EfiACPIMemoryNVS");
        else if (descriptor->Type == EfiMemoryMappedIO) TRACE(L"    --> EfiMemoryMappedIO");
        else if (descriptor->Type == EfiMemoryMappedIOPortSpace) TRACE(L"    --> EfiMemoryMappedIOPortSpace");
        else if (descriptor->Type == EfiPalCode) TRACE(L"    --> EfiPalCode");
        else if (descriptor->Type == EfiMaxMemoryType) TRACE(L"    --> EfiMaxMemoryType");
        else TRACE(L"    --> !UNKNOWN TYPE!");
        TRACE(L".%LX\r\n", descriptor->Attribute);

    }
    UefiBootServices->FreePool(MemoryMap);
}


BOOLEAN
InternalListHandlesAndProtocols(
    void
    )
{
    EFI_HANDLE *buffer;
    UINTN handlesCount, i,j;
    EFI_STATUS status;
    EFI_GUID **guidArray;
    UINTN guidCount;

    status = UefiBootServices->LocateHandleBuffer(AllHandles, NULL, NULL, &handlesCount, &buffer);
    if (EFI_ERROR(status))
    {
        TRACE(L"LocateHandleBuffer error, status = %S\r\n", UefiStatusToText(status));
        return FALSE;
    }
    TRACE(L"Total %d handles\r\n", handlesCount);
    for (i = 0; i < handlesCount; i++)
    {
        status = UefiBootServices->ProtocolsPerHandle(buffer[i], &guidArray, &guidCount);
        if (EFI_ERROR(status))
        {
            TRACE(L"ProtocolsPerHandle failed, status = %S\r\n", UefiStatusToText(status));
        }
        TRACE(L"HANDLE[%d] - %d associated protocols\r\n", i, guidCount);
        for (j = 0; j < guidCount; j++)
        {
            TRACE(L"  %S [%g]\r\n", GuidToText(guidArray[j]), guidArray[j]);
            }

        status = UefiBootServices->FreePool(guidArray);
        if (EFI_ERROR(status))
        {
            TRACE(L"Failed to free the array!\r\n");
        }

    }

    status = UefiBootServices->FreePool(buffer);
    if (EFI_ERROR(status))
    {
        TRACE(L"Failed to free the handles array!\r\n");
    }
    return TRUE;
}


