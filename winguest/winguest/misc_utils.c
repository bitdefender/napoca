/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file misc_utils.c
*   @brief Miscellaneous utilities and helpers
*/

#include "winguest_types.h"
#include "memory.h"
#include "misc_utils.h"
#include "reg_opts.h"
#include "winguest_status.h"
#include "introstatus.h"
#include "comm_hv.h"
#include "trace.h"
#include "misc_utils.tmh"

_At_(String->Buffer, __drv_allocatesMem(Mem))
_At_(String->Buffer, _Post_writable_size_(Length))
/**
 * @brief Allocate a UNICODE_STRING
 *
 * @param[out] String           Unicode string
 * @param[in]  Length           Size of string in characters
 *
 * @return STATUS_SUCCESS
 * @return STATUS_INSUFFICIENT_RESOURCES    Insufficient resources to allocate string
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
CreateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_  USHORT Length
)
{
    if (String == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Length > 0)
    {
        String->Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, Length * sizeof(WCHAR), TAG_STR);
        if (String->Buffer == NULL)
        {
            LogFuncErrorStatus(STATUS_INSUFFICIENT_RESOURCES, "ExAllocatePoolWithTag");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = Length * sizeof(WCHAR);

    return STATUS_SUCCESS;
}

_At_(String->Buffer, __drv_freesMem(Mem))
_At_(String->Buffer, _Post_ptr_invalid_)
/**
 * @brief Free the buffer associated with a UNICODE_STRING
 *
 * @param[in] String           Unicode string
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
VOID
FreeUnicodeString(
    _Inout_ PUNICODE_STRING String
)
{
    if (String->MaximumLength != 0)
    {
        String->Length = String->MaximumLength = 0;
        ExFreePoolWithTagAndNull(&String->Buffer, TAG_STR);
    }
}

/**
 * @brief Read a configuration parameter from the registry
 *
 * @param[in]  RegistryPath         Registry path where settings are stored
 * @param[in]  Param                Identifier for which setting is requested
 * @param[out] Buffer               Buffer to store the setting
 * @param[out] BufferSize           Size of Buffer
 *
 * @return STATUS_SUCCESS
 * @return STATUS_INSUFFICIENT_RESOURCES    Insufficient resources to perform request
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
WinhostReadHvParameter(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HvParameter Param,
    _Out_writes_bytes_all_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES obj;
    HANDLE hKey = NULL;
    PWCHAR regVal = NULL;
    DWORD *intVal = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = NULL;
    ULONG len;
    UNICODE_STRING regValUnicode;
    DWORD keyInfoSize = 0;

    if (RegistryPath == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (BufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    __try
    {
        InitializeObjectAttributes(&obj, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&hKey, KEY_READ | KEY_WOW64_64KEY, &obj);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ZwOpenKey");
            __leave;
        }

        switch (Param)
        {
        case hvParamReinitRoutineCallCount:
            intVal = (DWORD*)Buffer;
            regVal = REG_VALUE_REINIT_MAX_CALL_COUNT;
            break;

        case hvParamReserveHvLogBuffer:
            intVal = (DWORD*)Buffer;
            regVal = REG_VALUE_RESERVE_HVLOG_BUFFER;
            break;

        case hvParamUnknown:
        default:
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        status = STATUS_NOT_SUPPORTED;

        if (BufferSize < ((intVal != NULL) ? sizeof(DWORD) : sizeof(UNICODE_STRING)))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        keyInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION)
            + ((intVal != NULL)
                ? sizeof(QWORD)
                : DEFAULT_BUFFER_SIZE * sizeof(WCHAR));

        kvpi = ExAllocatePoolWithTag(NonPagedPoolNx, keyInfoSize, TAG_BUF);
        if (NULL == kvpi)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        status = RtlUnicodeStringInit(&regValUnicode, regVal);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RtlUnicodeStringInit");
            __leave;
        }

        status = ZwQueryValueKey(hKey, &regValUnicode, KeyValuePartialInformation, kvpi, keyInfoSize, &len);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ZwQueryValueKey");
            __leave;
        }

        if (kvpi->Type == REG_DWORD)
        {
            *intVal = GET_DWORD_LE(kvpi->Data, 0);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_REGISTRY_CORRUPT;
        }
    }
    __finally
    {
        ExFreePoolWithTagAndNull(&kvpi, TAG_BUF);

        ZwClose(hKey);
        hKey = NULL;
    }

    return status;
}

/**
 * @brief Parse raw memory data in the format used in registry for storing memory data
 *
 * The input for this function must be read from one of the entries in "HKLM\Hardware\resourcemap\".
 *
 * @param[out]    RawBuffer                 Buffer containing raw data.
 * @param[in]     RawBufferSize             Size of RawBuffer.
 * @param[in]     MemTypeHint               The type of memory that is in the RawBuffer.
 * @param[in]     TotalMemorySize           On return contains the total amount of memory. Can be NULL.
 * @param[in,out] PhyMemMap                 Buffer where to store the parsed results
 * @param[in,out] PhyMemCount               Current number of entries in PhyMemMap before call and total number of entries after call
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
MemMapParseRawMemoryData(
    _In_ BYTE *RawBuffer,
    _In_ ULONG RawBufferSize,
    _In_ BYTE MemTypeHint,
    _Out_opt_ QWORD* TotalMemorySize,
    _Inout_ MEM_MAP_ENTRY* PhyMemMap,
    _Inout_ WORD *PhyMemCount
    )
{
    PCM_RESOURCE_LIST resList = (PCM_RESOURCE_LIST)RawBuffer;
    PCM_FULL_RESOURCE_DESCRIPTOR resDesc = { 0 };
    PCM_PARTIAL_RESOURCE_DESCRIPTOR partialResDesc = { 0 };
    ULONG idx = 0, idx1 = 0;
    WORD idxPhyBootMem = *PhyMemCount;
    BOOLEAN skipEntry = FALSE;
    QWORD memSize = 0;

    if (NULL == RawBuffer)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (0 == RawBufferSize)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == PhyMemMap)
    {
        return STATUS_INVALID_PARAMETER_5;
    }
    if (NULL == PhyMemCount)
    {
        return STATUS_INVALID_PARAMETER_6;
    }

    for (idx = 0; idx < resList->Count; idx++)
    {
        resDesc = &resList->List[idx];

        for (idx1 = 0; idx1 < resDesc->PartialResourceList.Count; idx1++)
        {
            if (idxPhyBootMem >= BOOT_MAX_PHY_MEM_COUNT)
            {
                LogInfo("Reached the maximum number of entries in the physical memory map for boot info! The following memory range will be skipped!\n");
                LogInfo("Start: 0x%I64x, length: 0x%I64x, type: 0x%x\n", PhyMemMap[idxPhyBootMem].StartAddress,
                    PhyMemMap[idxPhyBootMem].Length,
                    PhyMemMap[idxPhyBootMem].Type);

                // maybe it is better to break out of here for performance reasons
                // however there is a slight possibility to reach this limit
                // and in that case we would like to have some kind of trace
                continue;
            }

            skipEntry = FALSE;
            partialResDesc = &resDesc->PartialResourceList.PartialDescriptors[idx1];

            switch (partialResDesc->Type)
            {
            case CmResourceTypeMemory:
                PhyMemMap[idxPhyBootMem].StartAddress = partialResDesc->u.Memory.Start.QuadPart;
                PhyMemMap[idxPhyBootMem].Length = partialResDesc->u.Memory.Length;
                break;
            case CmResourceTypeMemoryLarge:
            {
                if (partialResDesc->Flags & CM_RESOURCE_MEMORY_LARGE_40)
                {
                    //LogInfo("Large memory (40) detected!\n");
                    PhyMemMap[idxPhyBootMem].StartAddress = partialResDesc->u.Memory40.Start.QuadPart;
                    PhyMemMap[idxPhyBootMem].Length = (QWORD)partialResDesc->u.Memory40.Length40 << 8;
                }
                else if (partialResDesc->Flags & CM_RESOURCE_MEMORY_LARGE_48)
                {
                    PhyMemMap[idxPhyBootMem].StartAddress = partialResDesc->u.Memory48.Start.QuadPart;
                    PhyMemMap[idxPhyBootMem].Length = (QWORD)partialResDesc->u.Memory48.Length48 << 16;
                    //LogInfo("Large memory (48) detected!\n");
                }
                else if (partialResDesc->Flags & CM_RESOURCE_MEMORY_LARGE_64)
                {
                    PhyMemMap[idxPhyBootMem].StartAddress = partialResDesc->u.Memory64.Start.QuadPart;
                    PhyMemMap[idxPhyBootMem].Length = (QWORD)partialResDesc->u.Memory64.Length64 << 32;
                    //LogInfo("Large memory (64) detected!\n");
                }
                else
                {
                    LogWarning("Invalid flags for this type of memory resource! Entry will be skipped! Resource type: 0x%x, Flags: 0x%x\n", partialResDesc->Type, partialResDesc->Flags);
                    skipEntry = TRUE;
                }
            }
            break;
            default:
                LogWarning("Invalid type of memory resource! Entry will be skipped! Resource type: 0x%x\n", partialResDesc->Type);
                skipEntry = TRUE;
                break;
            }

            if (skipEntry)
            {
                continue;
            }
            else
            {
                // do whatever is needed to improve the memory type provided by this hint
                // by checking additional info in PCM_XXX structures available here
                PhyMemMap[idxPhyBootMem].Type = MemTypeHint;

                memSize += PhyMemMap[idxPhyBootMem].Length;

                //LogInfo("Added physical memory range: Start: 0x%I64x, length: 0x%I64x, type: 0x%x index: %d\n",
                //    PhyMemMap[idxPhyBootMem].StartAddress,
                //    PhyMemMap[idxPhyBootMem].Length,
                //    PhyMemMap[idxPhyBootMem].Type,
                //    idxPhyBootMem);

                idxPhyBootMem++;
            }
        }
    }

    if (TotalMemorySize)
    {
        *TotalMemorySize = memSize;
    }

    if (PhyMemCount)
    {
        *PhyMemCount = idxPhyBootMem;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Read and parse raw memory data in the registry resource maps
 *
 * Parse information found in "HKLM\Hardware\resourcemap\".
 *
 * @param[in]     RegKey                    Registry Key where the parsed value is stored
 * @param[in]     RegValue                  Actual value to be parsed
 * @param[in]     MemTypeHint               The type of memory that is in the RawBuffer.
 * @param[in]     MemorySize                On return contains the total amount of memory. Can be NULL.
 * @param[in,out] PhyMemMap                 Buffer where to store the parsed results
 * @param[in,out] PhyMemCount               Current number of entries in PhyMemMap before call and total number of entries after call
 *
 * @return STATUS_SUCCESS
 * @return STATUS_INSUFFICIENT_RESOURCES    Insufficient resources to perform request
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
ParseRegistryMemoryMap(
    _In_ PWCHAR RegKey,
    _In_ PWCHAR RegValue,
    _In_ BYTE MemTypeHint,
    _Out_opt_ QWORD* MemorySize,
    _Inout_ MEM_MAP_ENTRY* PhyMemMap,
    _Inout_ WORD *PhyMemCount
)
{
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = NULL;
    OBJECT_ATTRIBUTES obj;
    HANDLE hKey = NULL;
    UNICODE_STRING regKey;
    UNICODE_STRING regValue;
    ULONG len = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (RegKey == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (RegValue == NULL)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    __try
    {
        status = RtlUnicodeStringInit(&regKey, RegKey);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RtlUnicodeStringInit");
            __leave;
        }

        status = RtlUnicodeStringInit(&regValue, RegValue);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RtlUnicodeStringInit");
            __leave;
        }

        InitializeObjectAttributes(&obj, &regKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&hKey, KEY_READ | KEY_WOW64_64KEY, &obj);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ZwOpenKey");
            __leave;
        }

        kvpi = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE * sizeof(WCHAR), TAG_BUF);
        if (NULL == kvpi)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        status = ZwQueryValueKey(hKey, &regValue, KeyValuePartialInformation, kvpi, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE * sizeof(WCHAR), &len);
        if ((STATUS_BUFFER_OVERFLOW == status) || (STATUS_BUFFER_TOO_SMALL == status)) // The initial buffer is not be large enough
        {
            ExFreePoolWithTagAndNull(&kvpi, TAG_BUF);
            kvpi = ExAllocatePoolWithTag(NonPagedPoolNx, len, TAG_BUF);
            if (kvpi == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            status = ZwQueryValueKey(hKey, &regValue, KeyValuePartialInformation, kvpi, len, &len);
        }
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "ZwQueryValueKey");
            __leave;
        }

        if ((kvpi->Type != REG_RESOURCE_LIST))
        {
            status = STATUS_REGISTRY_CORRUPT;
            __leave;
        }

        status = MemMapParseRawMemoryData(kvpi->Data, len, MemTypeHint, MemorySize, PhyMemMap, PhyMemCount);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "MemMapParseRawMemoryData");
            __leave;
        }
    }
    __finally
    {
        ExFreePoolWithTagAndNull(&kvpi, TAG_BUF);

        if (NULL != hKey)
        {
            ZwClose(hKey);
            hKey = NULL;
        }
    }

    return status;
}
