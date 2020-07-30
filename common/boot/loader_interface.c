/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "common/boot/loader_interface.h"

/// @brief The pseudovariable __ImageBase
/// represents the DOS header of the module, which happens to
/// be what a Win32 module begins with.
/// In other words, it's the base address of the module.
/// (NOTE: valid only with Microsoft compiler)
extern CX_UINT8 __ImageBase;

/// @brief Structure which containt info about a module
typedef struct
{
    char *Name;

    // Add here other informations you think
    // are relevant about a module
}LD_MODULE_INFO;

/// @brief List containing information about each module.
static LD_MODULE_INFO ModuleInformation[LD_MAX_MODULES] = {
   [LD_MODID_INVALID] =             { .Name = "LD_MODID_INVALID",           },
   [LD_MODID_BOOT_CONTEXT] =        { .Name = "LD_MODID_BOOT_CONTEXT",      },
   [LD_MODID_NAPOCA_IMAGE] =        { .Name = "LD_MODID_NAPOCA_IMAGE",      },
   [LD_MODID_NAPOCA_STACK] =        { .Name = "LD_MODID_NAPOCA_STACK",      },
   [LD_MODID_MEMORY_MAP] =          { .Name = "LD_MODID_MEMORY_MAP",        },
   [LD_MODID_HVMEMORY_MAP] =        { .Name = "LD_MODID_HVMEMORY_MAP",      },
   [LD_MODID_COMMAND_LINE] =        { .Name = "LD_MODID_COMMAND_LINE",      },
   [LD_MODID_FREE_MEMORY] =         { .Name = "LD_MODID_FREE_MEMORY",       },
   [LD_MODID_INTRO_EXCEPTIONS] =    { .Name = "LD_MODID_INTRO_EXCEPTIONS",  },
   [LD_MODID_INTRO_CORE] =          { .Name = "LD_MODID_INTRO_CORE",        },
   [LD_MODID_INTRO_LIVE_UPDATE] =   { .Name = "LD_MODID_INTRO_LIVE_UPDATE", },
   [LD_MODID_ORIG_MBR] =            { .Name = "LD_MODID_ORIG_MBR",          },
   [LD_MODID_LOADER_CUSTOM] =       { .Name = "LD_MODID_LOADER_CUSTOM",     },
   [LD_MODID_BOOT_STATE] =          { .Name = "LD_MODID_BOOT_STATE",        },
   [LD_MODID_NVS] =                 { .Name = "LD_MODID_NVS",               },
   [LD_MODID_FEEDBACK] =            { .Name = "LD_MODID_FEEDBACK",          },
   [LD_MODID_MBR_SETTINGS] =        { .Name = "LD_MODID_MBR_SETTINGS",      },
};

/// @brief Structure that helps us convert E820 memory type to HV memory type
static LD_HV_MEM_TYPE LdE820ToHv[] =
{
    BOOT_MEM_TYPE_INVALID,          ///< E820_TYPE_INVALID
    BOOT_MEM_TYPE_AVAILABLE,        ///< E820_TYPE_MEMORY
    BOOT_MEM_TYPE_RESERVED,         ///< E820_TYPE_RESERVED
    BOOT_MEM_TYPE_ACPI,             ///< E820_TYPE_ACPI
    BOOT_MEM_TYPE_NVS,              ///< E820_TYPE_NVS
    BOOT_MEM_TYPE_UNUSABLE,         ///< E820_TYPE_UNUSABLE
    BOOT_MEM_TYPE_DISABLED,         ///< E820_TYPE_DISABLED
};

/// @brief Structure that helps us convert Efi memory type to HV memory type
static LD_HV_MEM_TYPE LdEfiToHv[] =
{
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_RESERVED_MEMORY_TYPE
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_LOADER_CODE
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_LOADER_DATA
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_BOOT_SERVICES_CODE
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_BOOT_SERVICES_DATA
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_RUNTIME_SERVICES_CODE
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_RUNTIME_SERVICES_DATA
    BOOT_MEM_TYPE_AVAILABLE,        ///< EFI_CONVENTIONAL_MEMORY
    BOOT_MEM_TYPE_UNUSABLE,         ///< EFI_UNUSABLE_MEMORY
    BOOT_MEM_TYPE_ACPI,             ///< EFI_ACPIRECLAIM_MEMORY
    BOOT_MEM_TYPE_NVS,              ///< EFI_ACPIMEMORY_NVS
    BOOT_MEM_TYPE_RESERVED,         ///< EFI_MEMORY_MAPPED_IO
    BOOT_MEM_TYPE_MMIO,             ///< EFI_MEMORY_MAPPED_IOPORT_SPACE
    BOOT_MEM_TYPE_PAL_CODE,         ///< EFI_PAL_CODE
};

/// @brief Structure that helps us convert HV memory type to E820 memory type
static LD_E820_MEM_TYPE LdHvToE820[] =
{
    E820_TYPE_INVALID,              ///< BOOT_MEM_TYPE_INVALID,
    E820_TYPE_MEMORY,               ///< BOOT_MEM_TYPE_AVAILABLE,
    E820_TYPE_RESERVED,             ///< BOOT_MEM_TYPE_RESERVED,
    E820_TYPE_ACPI,                 ///< BOOT_MEM_TYPE_ACPI,
    E820_TYPE_NVS,                  ///< BOOT_MEM_TYPE_NVS,
    E820_TYPE_UNUSABLE,             ///< BOOT_MEM_TYPE_UNUSABLE,
    E820_TYPE_DISABLED,             ///< BOOT_MEM_TYPE_DISABLED
    E820_TYPE_RESERVED,             ///< BOOT_MEM_TYPE_MMIO,
    E820_TYPE_RESERVED,             ///< BOOT_MEM_TYPE_PAL_CODE,
    BOOT_MEM_TYPE_RESERVED,         ///< BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED,
    BOOT_MEM_TYPE_RESERVED,         ///< BOOT_MEM_TYPE_RAM_HYPERVISOR_SHARED,
    BOOT_MEM_TYPE_RESERVED,         ///< BOOT_MEM_TYPE_LAPIC,
};

///
/// @brief Returns the next page in the paging hierarchy if it exists. If it does not exist, allocate a new page and return it
///
/// @param[in]      Mapper          The data structure that helps us manage memory mapping within loader interface
/// @param[in]      AccessRights    Access rights to use if new page created
/// @param[out]     RootEntryPa     Returned page physical address
///
/// @returns        CX_STATUS_SUCCESS               - if all good
/// @returns        CX_STATUS_INVALID_PARAMETER_1   - if Mapper is NULL
/// @returns        CX_STATUS_INVALID_PARAMETER_3   - if RootEntryPa is NULL
/// @returns        OTHER                           - error statuses from APIs used inside the function
///
static CX_STATUS _LdGetNextLevelTable(_In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT8 AccessRights, _Out_ CX_UINT64 *RootEntryPa);

static CX_UINT8 _LdReadByteAligned(_In_ void *Address);

LD_HV_MEM_TYPE
LdConvertE820MemTypeToHvMemType(
    _In_ LD_E820_MEM_TYPE E820Type
)
{
    if (E820Type < (sizeof(LdE820ToHv) / sizeof(LD_HV_MEM_TYPE)))
    {
        return LdE820ToHv[E820Type];
    }
    return BOOT_MEM_TYPE_RESERVED;
}

LD_HV_MEM_TYPE
LdConvertEfiMemTypeToHvMemType(
    _In_ LD_EFI_MEM_TYPE EfiType
)
{
    if (EfiType < (sizeof(LdEfiToHv) / sizeof(LD_HV_MEM_TYPE)))
    {
        return LdEfiToHv[EfiType];
    }
    return BOOT_MEM_TYPE_RESERVED;
}

LD_E820_MEM_TYPE
LdConvertHvMemTypeToE820MemType(
    _In_ LD_HV_MEM_TYPE HvType
)
{
    if (HvType < (sizeof(LdHvToE820) / sizeof(LD_E820_MEM_TYPE)))
    {
        return LdHvToE820[HvType];
    }
    return E820_TYPE_RESERVED;
}

CX_BOOL
LdIsHvMemTypeAvailableToGuests(
    _In_ LD_HV_MEM_TYPE HvType
)
{
    return !(
        (HvType == BOOT_MEM_TYPE_DISABLED) ||
        (HvType == BOOT_MEM_TYPE_INVALID) ||
        (HvType == BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED)
    );
}

char *
LdGetModuleName(
    _In_ LD_MODID ModuleId
)
{
    if (ModuleId < LD_MAX_MODULES)
    {
        return ModuleInformation[ModuleId].Name;
    }
    else
    {
        return "N/A";
    }
}

CX_STATUS
LdAlloc(
    _Inout_ LD_MEM_BUFFER *MemoryRegion,
    _In_ CX_UINT64 Size,
    _In_ CX_UINT32 AlignedTo,
    __out_opt CX_UINT64 *Address,
    __out_opt CX_UINT64 *PhysicalAddress
)
{
    CX_UINT64 newBlock;
    if (MemoryRegion == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Address != CX_NULL) *Address = (CX_UINT64)CX_NULL;
    if (AlignedTo == 0) AlignedTo = 1;
    if (PhysicalAddress != CX_NULL) *PhysicalAddress = 0;

    newBlock = (CX_UINT64)MemoryRegion->NextFreeAddress;
    newBlock = AlignedTo * ((newBlock + (AlignedTo - 1)) / AlignedTo);

    if ((Size + newBlock) > (MemoryRegion->Va + MemoryRegion->Length)) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    MemoryRegion->NextFreeAddress = (newBlock + Size);
    if (Address != CX_NULL) *Address = newBlock;

    if (PhysicalAddress != CX_NULL) *PhysicalAddress = newBlock - MemoryRegion->Va + MemoryRegion->Pa;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdGetModule(
    _In_ LD_NAPOCA_MODULE *Modules,
    _In_ CX_UINT32 NumberOfModules,
    _In_ CX_UINT32 ModuleId,
    _Out_ LD_NAPOCA_MODULE **Result
)

{
    if (Modules == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Result == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    *Result = CX_NULL; // preinit result just in case

    if (ModuleId > NumberOfModules) return CX_STATUS_DATA_NOT_FOUND;
    if (Modules[ModuleId].Size == 0) return CX_STATUS_NOT_INITIALIZED;

    *Result = &(Modules[ModuleId]);
    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdSetModule(
    _In_ LD_NAPOCA_MODULE *Modules,
    _In_ CX_UINT32 MaxModules,
    _In_ CX_UINT32 ModuleId,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT32 Size,
    _In_ CX_UINT32 Flags
)
{
    if (Modules == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (ModuleId > MaxModules) return CX_STATUS_OUT_OF_RANGE;

    Modules[ModuleId].Pa = Pa;
    Modules[ModuleId].Va = Va;
    Modules[ModuleId].Size = Size;
    Modules[ModuleId].Flags = Flags;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdMapPage(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT8 Rights,
    _Inout_ CX_UINT64 *TablesRoot,
    _In_ CX_UINT8 TablesDepth
)
{
    CX_UINT64 *ptr, tmp;
    CX_STATUS status;
    CX_UINT16 lvl6, lvl5, lvl4, lvl3, lvl2, lvl1, offset;
    CX_UINT8 nonLeafRights = 3; // present and all access for all intermediate entries

    if (Mapper == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (TablesRoot == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;

    //
    // Decode the table indexes from the given Va
    //
    tmp = Va;
    offset = tmp & (CX_PAGE_SIZE_4K - 1); tmp = tmp >> 12;
    lvl1 = tmp & 511; tmp = tmp >> 9;
    lvl2 = tmp & 511; tmp = tmp >> 9;
    lvl3 = tmp & 511; tmp = tmp >> 9;
    lvl4 = tmp & 511; tmp = tmp >> 9;
    lvl5 = tmp & 511; tmp = tmp >> 9;
    lvl6 = tmp & 511; tmp = tmp >> 9;

    // root - lvl 6/5/4.. table
    ptr = TablesRoot;
    status = _LdGetNextLevelTable(Mapper, 0, ptr);
    if (!CX_SUCCESS(status))
    {
        LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
        goto cleanup;
    }

    // lvl 5 table
    if (TablesDepth > 5)
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl6;
        status = _LdGetNextLevelTable(Mapper, nonLeafRights, ptr);
        if (!CX_SUCCESS(status))
        {
            LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
            goto cleanup;
        }
    }

    // lvl 4 table
    if (TablesDepth > 4)
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl5;
        status = _LdGetNextLevelTable(Mapper, nonLeafRights, ptr);
        if (!CX_SUCCESS(status))
        {
            LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
            goto cleanup;
        }
    }

    // lvl 3 table
    if (TablesDepth > 3)
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl4;
        status = _LdGetNextLevelTable(Mapper, nonLeafRights, ptr);
        if (!CX_SUCCESS(status))
        {
            LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
            goto cleanup;
        }
    }

    // lvl 2 table
    ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl3;
    status = _LdGetNextLevelTable(Mapper, nonLeafRights, ptr);
    if (!CX_SUCCESS(status))
    {
        LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
        goto cleanup;
    }

    // lvl 1 table
    ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl2;
    status = _LdGetNextLevelTable(Mapper, nonLeafRights, ptr);
    if (!CX_SUCCESS(status))
    {
        LD_LOG_FUNC_FAIL("_LdGetNextLevelTable", status);
        goto cleanup;
    }

    // lvl 1 entry - set the actual mapping
    ptr = (CX_UINT64*)(CX_SIZE_T)(LdPaToVa(Mapper, CX_PAGE_BASE_MASK_4K & (*ptr))) + lvl1;
    *ptr = (CX_PAGE_BASE_MASK_4K & Pa) | (Rights & (CX_PAGE_SIZE_4K - 1));
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

CX_STATUS
LdMapPages(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT8 Rights,
    _In_ CX_UINT64 NumberOfPages,
    _Inout_ CX_UINT64 *TablesRoot,
    _In_ CX_UINT8 TablesDepth
    )
{
    CX_STATUS status;

    if (Mapper == CX_NULL)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        LD_LOG_FUNC_FAIL("Mapper", status);
        goto cleanup;
    }
    if (TablesRoot == CX_NULL)
    {
        status = CX_STATUS_INVALID_PARAMETER_6;
        LD_LOG_FUNC_FAIL("TablesRoot", status);
        goto cleanup;
    }

    for (CX_UINT32 i = 0; i < NumberOfPages; i++)
    {
        status = LdMapPage(Mapper, (Va + ((CX_UINT64)i * CX_PAGE_SIZE_4K)), Pa + ((CX_UINT64)i * CX_PAGE_SIZE_4K), Rights, TablesRoot, TablesDepth);
        if (!CX_SUCCESS(status))
        {
            LD_LOG_FUNC_FAIL("LdMapPage", status);
            goto cleanup;
        }
    }
    status = CX_STATUS_SUCCESS;
cleanup:
    return status;
}

CX_STATUS
LdMapRange(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 VirtualAddress,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Rights,
    _In_ CX_UINT64 NumberOfBytes,
    _Inout_ CX_UINT64 *TablesRoot,              // address of a void pointer which should contain (and will receive) the address of the page tables root
    _In_ CX_UINT8 TablesDepth                   // from 4 to max 6: 4 for VA, 6 for VT-d
)
{
    CX_STATUS status;
    CX_UINT64 pa, va;
    CX_UINT32 pageCount, pageOffset;

    if (Mapper == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (TablesRoot == CX_NULL) return CX_STATUS_INVALID_PARAMETER_6;

    pa = CX_PAGE_BASE_4K(PhysicalAddress);
    va = CX_PAGE_BASE_4K(VirtualAddress);
    pageCount = (CX_UINT32)CX_PAGE_COUNT_4K(PhysicalAddress, NumberOfBytes);
    pageOffset = CX_PAGE_OFFSET_4K(PhysicalAddress);

    if ((CX_PAGE_OFFSET_4K(VirtualAddress)) != pageOffset)
    {
        return CX_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    status = LdMapPages(Mapper, va, pa, Rights, pageCount, TablesRoot, TablesDepth);
    if (!CX_SUCCESS(status))
    {
        LD_LOG_FUNC_FAIL("LdMapPages", status);
        goto cleanup;
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

CX_UINT64
LdPaToVa(
    _In_ LD_VA_MAPPER* VaMapper,
    _In_ CX_UINT64 Pa
    )
{
    CX_STATUS status;
    CX_UINT32 i;
    CX_UINT64 va;
    LD_NAPOCA_MODULE *module;
    CX_BOOL found;
    CX_UINT32 numberOfModules;
    LD_NAPOCA_MODULE *modules;

    if (VaMapper == CX_NULL) return 0;

    numberOfModules = VaMapper->NumberOfModules;
    modules = VaMapper->Modules;

    if (VaMapper->CustomPhysicalToVirtual != CX_NULL)
    {
        return VaMapper->CustomPhysicalToVirtual(Pa, VaMapper->CustomContextPhysicalToVirtual);
    }

    va = Pa; // consider identity mapped any address outside of the modules
    found = CX_FALSE;
    for (i = 0; i < numberOfModules; i++)
    {
        status = LdGetModule(modules, numberOfModules, i, &module);
        if (CX_SUCCESS(status))
        {
            if ((Pa >= module->Pa) && (module->Pa + module->Size > Pa))
            {
                if (module->Va != 0) found = CX_TRUE;
                va = module->Va + (Pa - module->Pa);
            }
            else if (i == LD_MODID_FREE_MEMORY)
            {
                LD_MEM_BUFFER *mem;
                mem = (LD_MEM_BUFFER*)(CX_SIZE_T)module->Va;
                if (mem != CX_NULL)
                {
                    if ((Pa >= mem->Pa) && (mem->Pa + mem->Length > Pa))
                    {
                        if (mem->Va != (CX_UINT64)CX_NULL)
                        {
                            found = CX_TRUE;
                        }
                        va = mem->Va + (Pa - mem->Pa);
                    }
                }
            }
        }
    }
    if (!found) va = Pa;
    return va;
}

CX_UINT64
LdVaToPa(
    _In_ LD_VA_MAPPER* VaMapper,
    _In_ CX_UINT64 Va
    )
{
    CX_STATUS status;
    CX_UINT32 i;
    CX_UINT64 pa;
    LD_NAPOCA_MODULE *module;
    CX_UINT32 numberOfModules;
    LD_NAPOCA_MODULE *modules;

    if (VaMapper == CX_NULL) return 0;

    numberOfModules = VaMapper->NumberOfModules;
    modules = VaMapper->Modules;

    if (VaMapper->CustomVirtualToPhysical != CX_NULL)
    {
        return VaMapper->CustomVirtualToPhysical(Va, VaMapper->CustomContextVirtualToPhysical);
    }


    pa = Va;    // consider identity mapped any address outside of the modules

    for (i = 0; i < numberOfModules; i++)
    {
        status = LdGetModule(modules, numberOfModules, i, &module);
        if (CX_SUCCESS(status))
        {
            if ((Va >= module->Va) && (module->Va + module->Size > Va))
            {
                pa = module->Pa + (Va - module->Va);
            }
            // special case if inside the temp mem buffer
            else if (i == LD_MODID_FREE_MEMORY)
            {
                LD_MEM_BUFFER *mem;
                mem = (LD_MEM_BUFFER*)(CX_SIZE_T)module->Va;
                if ((Va >= mem->Va) && (mem->Va + mem->Length > Va))
                {
                    pa = mem->Pa + (Va - mem->Va);
                }
            }
            // also special case for the PE image
            if (i == LD_MODID_NAPOCA_IMAGE)
            {
                CX_UINT64 selfBase = (CX_UINT64)(&__ImageBase);
                CX_UINT64 selfEnd = selfBase + module->Size;
                if ((Va >= selfBase) && (selfEnd > Va))
                {
                    pa = module->Pa + (Va - selfBase);
                }
            }
        }
    }

    return pa;
}

CX_STATUS
LdEstimateRequiredHvMem(
    _In_ CX_UINT64 TotalSystemMemory,
    _In_ CX_UINT32 NumberOfGuests,
    _In_ CX_UINT32 SharedBufferSize,
    __out_opt CX_UINT64 *TotalRequiredMemory,
    __out_opt CX_UINT64 *TotalGuestsMemory
    )
{
    CX_UINT64 hvMem, guestMem;
    CX_UINT64 actualGuests = ((NumberOfGuests > 0) ? (NumberOfGuests - 1) : 0);


    hvMem = NAPOCA_MEM_ESTIMATE_FIXED +
        (TotalSystemMemory * NAPOCA_MEM_ESTIMATE_PERCENT) / 100;
    hvMem = CX_ROUND_UP(hvMem, 256 * CX_KILO);


    if (TotalSystemMemory >= (3 * (CX_UINT64)CX_GIGA))
    {
        guestMem = actualGuests * 512 * CX_MEGA;
    }
    else
    {
        guestMem = actualGuests * 128 * CX_MEGA;
    }

    if (TotalRequiredMemory != CX_NULL) *TotalRequiredMemory = hvMem + guestMem + SharedBufferSize;
    if (TotalGuestsMemory != CX_NULL) *TotalGuestsMemory = guestMem;

    return CX_STATUS_SUCCESS;
}

CX_UINT64
LdWalkTablesDump(
    _In_ CX_UINT64 Cr3,
    _In_ CX_UINT64 Adr,
    _In_opt_ PFUNC_PhysicalToVirtual Callback
    )
{
    CX_UINT64 adr = Adr;
    CX_UINT64 adrLow = adr & 0xFFFFFFFF;
    CX_UINT64 *ptr;
    CX_UINT16 lvl4, lvl3, lvl2, lvl1, offset;

    if (Callback)
    {
        ptr = (CX_UINT64*)((CX_SIZE_T)Callback(Cr3, CX_NULL));
    }
    else
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)Cr3;
    }

    offset = adr & (CX_PAGE_SIZE_4K - 1); adr = adr >> 12;
    lvl1 = adr & 511; adr = adr >> 9;
    lvl2 = adr & 511; adr = adr >> 9;
    lvl3 = adr & 511; adr = adr >> 9;
    lvl4 = adr & 511; adr = adr >> 9;


    LD_LOGN("Translation for " LD_UINT64_FMT ": indexes = [%03d]->[%03d]->[%03d]->[%03d], walk = ", Adr, lvl4, lvl3, lvl2, lvl1);

    if (ptr == CX_NULL) goto cleanup;

    LD_LOGN("4[%03d]:" LD_UINT64_FMT " ", lvl4, ptr[lvl4]);

    if (Callback)
    {
        ptr = (CX_UINT64*)((CX_SIZE_T)Callback((CX_SIZE_T)(ptr[lvl4] & CX_PAGE_BASE_MASK_4K), CX_NULL));
    }
    else
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(ptr[lvl4] & CX_PAGE_BASE_MASK_4K);
    }

    if (ptr == CX_NULL) goto cleanup;

    LD_LOGN("3[%03d]:" LD_UINT64_FMT " ", lvl3, ptr[lvl3]);

    if (Callback)
    {
        ptr = (CX_UINT64*)((CX_SIZE_T)Callback((CX_SIZE_T)(ptr[lvl3] & CX_PAGE_BASE_MASK_4K), CX_NULL));
    }
    else
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(ptr[lvl3] & CX_PAGE_BASE_MASK_4K);
    }

    if (ptr == CX_NULL) goto cleanup;

    LD_LOGN("2[%03d]:" LD_UINT64_FMT " ", lvl2, ptr[lvl2]);

    if (Callback)
    {
        ptr = (CX_UINT64*)((CX_SIZE_T)Callback((CX_SIZE_T)(ptr[lvl2] & CX_PAGE_BASE_MASK_4K), CX_NULL));
    }
    else
    {
        ptr = (CX_UINT64*)(CX_SIZE_T)(ptr[lvl2] & CX_PAGE_BASE_MASK_4K);
    }

    if (ptr == CX_NULL) goto cleanup;
    LD_LOGN("1[%03d]:" LD_UINT64_FMT " base: " LD_UINT64_FMT "\n", lvl1, ptr[lvl1], CX_PAGE_BASE_4K(ptr[lvl1]) - CX_PAGE_BASE_4K(adrLow));
    return (CX_UINT64)(ptr[lvl1] & CX_PAGE_BASE_MASK_4K);
cleanup:
    LD_LOGN("<CX_NULL>\n");
    return (CX_UINT64)CX_NULL;
}

CX_STATUS
LdDumpMemory(
    _In_opt_ char *Message,
    _In_ void *Address,
    _In_ CX_UINT32 Length
    )
{
    CX_UINT8 *p;
    CX_UINT32 i;
    char line[17];

    if (Address == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    p = Address;

    if (Message != CX_NULL) LD_LOGN("Dumping %d bytes from %p - %s\n", Length, Address, Message);

    for (i = 0; i < Length; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                line[16] = 0;
                LD_LOGN("%s\n", line);
            }
            LD_LOGN("%018p: ", p);

        }
        line[i % 16] = _LdReadByteAligned(p);
        if ((line[i % 16] < 32) || (line[i % 16] > 127))
        {
            line[i % 16] = '.';
        }
        LD_LOGN("%02X ", _LdReadByteAligned(p));
        p++;
    }

    while ((i % 16) != 0)
    {
        LD_LOGN("XX ");
        line[i % 16] = 'X';
        i++;
    }
    line[16] = 0;
    LD_LOGN("%s\n", line);
    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdDumpMemBuffer(
    _In_opt_ CX_INT8 *Message,
    _In_ LD_MEM_BUFFER *Mem
    )
{
    if (Message != CX_NULL) LD_LOG("%s\n", Message);

    if (Mem == CX_NULL)
    {
        LD_LOG("CX_NULL memory buffer pointer!\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    LD_LOG("--> %-18s  <%016p>\n", "Va", Mem->Va);
    LD_LOG("--> %-18s  <%016p>\n", "Pa", Mem->Pa);
    LD_LOG("--> %-18s  <%016p>\n", "Length", Mem->Length);
    LD_LOG("--> %-18s  <%016p>\n", "NextFreeAddress", Mem->NextFreeAddress);
    LD_LOG("--> %-18s  <%d>\n", "Used(KB)", (Mem->NextFreeAddress - Mem->Va) / CX_PAGE_SIZE_4K);
    LD_LOG("--> %-18s  <%d>\n", "Free(KB)", (Mem->Length - (Mem->NextFreeAddress - Mem->Va)) / 1024);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdDumpLdNapocaModule2(
    _In_ LD_NAPOCA_MODULE *Ptr,
    _In_ CX_UINT32 Depth,
    _In_ CX_UINT32 MaxDepth,
    _In_ CX_BOOL FollowPointers,
    _In_ CX_UINT64 ArraysMaxIterationCount
    )
{
    CX_INT8 *prefix = "->";

    FollowPointers, ArraysMaxIterationCount;
    if (Ptr == CX_NULL)
    {
        LD_LOG("CX_NULL LD_NAPOCA_MODULE pointer\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (Depth >= MaxDepth)
    {
        LD_LOG("%-10s - LD_NAPOCA_MODULE: max depth reached\n", prefix);
        return CX_STATUS_SUCCESS;
    }
    LD_LOG("%-10s - %016p: dumping LD_NAPOCA_MODULE\n", prefix, Ptr);
    LD_LOG("%-10s - %016p: %-46s %016p\n", prefix, &(Ptr->Va), "(CX_UINT64) Va", Ptr->Va);
    LD_LOG("%-10s - %016p: %-46s %016p\n", prefix, &(Ptr->Pa), "(CX_UINT64) Pa", Ptr->Pa);
    LD_LOG("%-10s - %016p: %-46s 0x%08X\n", prefix, &(Ptr->Size), "(CX_UINT32) Size", Ptr->Size);
    LD_LOG("%-10s - %016p: %-46s 0x%08X\n", prefix, &(Ptr->Flags), "(CX_UINT32) Flags", Ptr->Flags);
    return CX_STATUS_SUCCESS;
}

CX_STATUS
LdDumpLdBootContext2(
    _In_ LD_BOOT_CONTEXT *Ptr,
    _In_ CX_UINT32 Depth,
    _In_ CX_UINT32 MaxDepth,
    _In_ CX_BOOL FollowPointers,
    _In_ CX_UINT64 ArraysMaxIterationCount
    )
{
    CX_UINT64 i;
    CX_INT8 *prefix = "->";

    if (Ptr == CX_NULL)
    {
        LD_LOG("CX_NULL LD_BOOT_CONTEXT pointer\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (Depth >= MaxDepth)
    {
        LD_LOG("%-10s - LD_BOOT_CONTEXT: max depth reached\n", prefix);
        return CX_STATUS_SUCCESS;
    }
    LD_LOG("%-10s - %016p: dumping LD_BOOT_CONTEXT\n", prefix, Ptr);
    LD_LOG("%-10s - %016p: %-46s 0x%08X\n", prefix, &(Ptr->BootMode), "(CX_UINT32) BootMode", Ptr->BootMode);
    for (i = 0; (FollowPointers) && (i < ArraysMaxIterationCount) && (i < LD_MAX_MODULES); i++)
    {
        LD_LOG("%-10s - %016p: %-42s[%s]* %016p\n", prefix, &(Ptr->Modules[i]), "(LD_NAPOCA_MODULE) *Modules[]", LdGetModuleName(i), Ptr->Modules[i]);
        if ((FollowPointers) && (&((Ptr->Modules)[i]) != CX_NULL))
        {
            LdDumpLdNapocaModule2(&((Ptr->Modules)[i]), Depth + 1, MaxDepth, FollowPointers, ArraysMaxIterationCount);
        }
        else
        {
            LD_LOG("%-10s - N/A\n", prefix);
        }
    }
    LD_LOG("%-10s - %016p: %-46s %016p\n", prefix, &(Ptr->ModulesPa), "(CX_UINT64) ModulesPa", Ptr->ModulesPa);
    LD_LOG("%-10s - %016p: %-46s 0x%08X\n", prefix, &(Ptr->NumberOfModules), "(CX_UINT32) NumberOfModules", Ptr->NumberOfModules);

    LD_LOG("%-10s - %016p: %-46s %016p\n", prefix, &(Ptr->Cr3), "(CX_UINT64) Cr3", Ptr->Cr3);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
_LdGetNextLevelTable(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT8 AccessRights,
    _Out_ CX_UINT64 *RootEntryPa                // pointer to where the PA to the allocated page should be stored
)
{
    CX_STATUS status;
    CX_UINT32 *page;

    if (Mapper == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (RootEntryPa == CX_NULL)
    {
        LD_LOG("RootEntryPa is CX_NULL");
        status = CX_STATUS_INVALID_PARAMETER_3;
        LD_LOG_FUNC_FAIL("RootEntryPa", status);
        goto cleanup;
    }


    if (0 != (CX_PAGE_BASE_MASK_4K & *RootEntryPa))
    {
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }

    status = LdAlloc(Mapper->MemBuffer, CX_PAGE_SIZE_4K, CX_PAGE_SIZE_4K, CX_NULL, RootEntryPa);
    if (!CX_SUCCESS(status))
    {
        LD_LOG_FUNC_FAIL("LdAlloc", status);
        goto cleanup;
    }

    page = (CX_UINT32 *)(CX_SIZE_T)LdPaToVa(Mapper, *RootEntryPa);
    for (CX_UINT32 i = 0; i < CX_PAGE_SIZE_4K / sizeof(CX_UINT32); i++)
    {
        page[i] = 0;
    }
    *RootEntryPa |= AccessRights;

cleanup:
    return status;
}

static
CX_UINT8
_LdReadByteAligned(
    _In_ void *Address
)

{
    CX_UINT32 *aligned;

    if (Address == CX_NULL) return 0xFF;

    // round down the address to be CX_UINT32 aligned
    aligned = (CX_UINT32 *)(CX_SIZE_T)((((CX_SIZE_T)Address) >> 2) << 2);

    // get a CX_UINT32 and shift it to the right to eliminate 0 to 3 bytes
    return 0xFF & ((*aligned) >> (8 * (((CX_SIZE_T)Address) & 3)));
}