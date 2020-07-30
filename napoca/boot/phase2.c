/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file phase2.c Guest virtual machine configuration

/// \defgroup phase2 Phase 2 - Configuration of the guest virtual machine
/// \ingroup hvinit
/// @{

#include "napoca.h"
#include "kernel/kernel.h"
#include "boot/vmstate.h"
#include "boot/phase2.h"
#include "boot/init64.h"
#include "kernel/mtrr.h"
#include "communication/comm_guest.h"
#include "debug/debug_store.h"
#include "guests/hooks.h"
#include "guests/bios_handlers.h"
#include "kernel/intelhwp.h"

extern BYTE __GuestPxeMbrLoaderCode;
extern BYTE __GuestPxeMbrLoaderCodeEnd;
extern BYTE __GuestPxeGrubInfo;

/// @brief Apply any patching needed for the physical memory space of the guest
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, patching was successful
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2SetupInitialMtrrsAndMemoryMaps(
    _In_ GUEST* Guest
    )
{
    NTSTATUS status;

    // Init MTRRs
    status = GstInitMtrrs(Guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstInitMtrrs", status);
        goto cleanup;
    }

    // Init PhysMap, update MTRRs to cover it
    status = GstInitPhysMap(Guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstInitPhysMap", status);
        goto cleanup;
    }

    // Setup E820 OS memory map for the PRIMARY GUEST (PgOsMap = PgSpace - ReservedHookSpace - ReservedAcpiWakeSpace)
    // Free all temporary reserved memory regions so that the primary guest can use them
    LD_NAPOCA_MODULE* module;
    QWORD totalFreed = 0;

    LOG("reclaiming memory for guest (from modules that are not used anymore)\n");

    // check each map entry if it's not marked as BOOT_MEM_TYPE_HYPERVISOR_IN_USE
    for (DWORD physMapIndex = 0; physMapIndex < Guest->PhysMap.Count; physMapIndex++)
    {
        BOOLEAN availableToOs = ((Guest->PhysMap.Entry[physMapIndex].Type & BOOT_MEM_TYPE_HYPERVISOR_IN_USE) == 0);

        if (!availableToOs)
        {
            availableToOs = TRUE;

            // check if somebody is using it permanently and free it if not
            for (DWORD j = 0; availableToOs && (j < LD_MAX_MODULES); j++)
            {
                NTSTATUS localStatus = LdGetModule(gBootModules, LD_MAX_MODULES, j, &module);
                if (SUCCESS(localStatus) && (module->Flags & LD_MODFLAG_PERMANENT))
                {
                    LD_NAPOCA_MODULE tmp;
                    tmp = *module;
                    tmp.Size = PAGE_SIZE * PAGE_COUNT(tmp.Pa, tmp.Size);
                    tmp.Pa = PAGE_BASE_PA(tmp.Pa);

                    // check if the mem entry is part of a permanent module
                    if (DO_RANGES_OVERLAP_BY_SIZE(Guest->PhysMap.Entry[physMapIndex].StartAddress, Guest->PhysMap.Entry[physMapIndex].Length, tmp.Pa, tmp.Size))
                    {
                        LOG("Module %s (%p:%p..%p) overlaps with PhysMap entry #%d (%p..%p)\n",
                            LdGetModuleName(j), tmp.Pa, (QWORD)tmp.Size, tmp.Pa + tmp.Size,
                            physMapIndex, Guest->PhysMap.Entry[physMapIndex].StartAddress, Guest->PhysMap.Entry[physMapIndex].StartAddress + Guest->PhysMap.Entry[physMapIndex].Length);
                        availableToOs = FALSE;
                    }
                }
            }

            // and also don't allow the loader-provided memory buffer be left free for the guest to use
            if (DO_RANGES_OVERLAP_BY_SIZE(Guest->PhysMap.Entry[physMapIndex].StartAddress, Guest->PhysMap.Entry[physMapIndex].Length, gTempMem->Pa, gTempMem->Length))
            {
                availableToOs = FALSE;
            }

            if (availableToOs)
            {
                // clear the BOOT_MEM_TYPE_HYPERVISOR_IN_USE flag to mark it 'available' again
                Guest->PhysMap.Entry[physMapIndex].Type -= BOOT_MEM_TYPE_HYPERVISOR_IN_USE;
                totalFreed += Guest->PhysMap.Entry[physMapIndex].Length;
            }
        }

    }
    LOG("Reclaimed %d KBytes for guest from temporary modules\n", totalFreed / PAGE_SIZE);

    // Setup memory for communication ring buffer
    Guest->SharedBufferHPA = gHypervisorGlobalData.Comm.SharedBufferHpa;
    Guest->SharedBufferGPA = gHypervisorGlobalData.Comm.SharedBufferHpa;
    LOG("Primary guest: Shared mem buffer GPA: [%p, %p)\n", Guest->SharedBufferHPA, Guest->SharedBufferHPA + SHARED_MEM_SIZE);

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nPRIMARY GUEST physical memory maps follow...\n");
        MmapDump(&Guest->PhysMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->PhysMap, ");
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


/// @brief Set up the VMCS of for the guest's VCPUs
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, VCPUs are set up
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2SetupVcpusAndVmcs(
    _In_ GUEST* Guest
    )
{
    NTSTATUS status;
    VCPU* vcpu;

    // Set up VCPUs
    status = GstSetupVcpus(Guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstSetupVcpus", status);
        goto cleanup;
    }

    // Setup VMCSs for each VCPU of the guest
    // NOTE: all VMCSs, including those of the AP processors are set up here, on the BSP, except their host-state
    for (DWORD i = 0; i < Guest->VcpuCount; i++)
    {
        status = VmstateConfigureVmcs(Guest->Vcpu[i], VMCS_CONFIGURE_SETTINGS_BOOT);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
            goto cleanup;
        }
    }

    // Setup the vcpu VA translations cache & cached pages
    for (DWORD i = 0; i < Guest->VcpuCount; i++)
    {
        vcpu = (Guest->Vcpu[i]);
        vcpu->CachedTranslations.Entries = vcpu->TranslationsArray;
        vcpu->CachedTranslations.NumberOfEntries = CHM_VA_TRANSLATIONS;
        vcpu->CachedTranslations.NumberOfUsedEntries = 0;
    }

    // for other boot modes it is done in GstActivateGuest
    if (BOOT_OPT_MULTIPROCESSOR)
    {
        status = GstAssignVCpusToPCpus(Guest, TRUE);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstAssignVCpusToPCpus", status);
            return status;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/// @brief Generate the EPT map for the guest
///
/// @param[in]  Guest                     The guest structure
/// @param[in]  NumberOfEntriesToAllocate Number of map entries to allocate in the EPT map
/// @param[in]  MaxPhysicalAddress        Maximum physical address
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, EPT map is created
/// @returns    CX_STATUS_INSUFFICIENT_RESOURCES    - Not enough map entries allocated
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2GenerateEptMap(
    _In_ GUEST* Guest,
    _In_ DWORD NumberOfEntriesToAllocate,
    _In_ QWORD MaxPhysicalAddress
    )
{
    NTSTATUS status;

    // allocate entries for memory map
    status = MmapAllocMapEntries(&Guest->EptMap, NumberOfEntriesToAllocate);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapAllocMapEntries", status);
        goto cleanup;
    }

    // copy from PhysMap all entries and compact them
    // we are not interested in memory type here
    // we care only to have all ranges of memory available
    // regardless of their type
    // cache type will be set at the end by looking at MTRRs
    MEM_MAP_ENTRY entry = { 0 };
    MEM_MAP_ENTRY *pEntry;
    BOOLEAN addEntry = TRUE;

    entry.StartAddress = Guest->PhysMap.Entry[0].StartAddress;
    entry.Length = Guest->PhysMap.Entry[0].Length;

    for (DWORD i = 0; i < Guest->PhysMap.Count; i++)
    {
        // special case for last entry for which we do not have an entryIndex+1 entry
        if (i == Guest->PhysMap.Count - 1) addEntry = TRUE;
        else
        {
            // check if there is no GAP between entry and entryIndex+1
            addEntry = ((Guest->PhysMap.Entry[i].StartAddress + Guest->PhysMap.Entry[i].Length) == Guest->PhysMap.Entry[i + 1].StartAddress) ? (FALSE) : (TRUE);
        }

        if (addEntry)
        {
            // split and keep new entries here because we will apply cache information later
            status = MmapApplyNewEntry(&Guest->EptMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
            if (!SUCCESS(status)) LOG_FUNC_FAIL("MmapApplyNewEntry", status);

            // update entry
            entry.StartAddress = Guest->PhysMap.Entry[i + 1].StartAddress;
            entry.Length = Guest->PhysMap.Entry[i + 1].Length;
        }
        else
        {
            // if yes just increase the size
            entry.Length += Guest->PhysMap.Entry[i + 1].Length;
        }

        addEntry = FALSE;
    }

    // apply entries in guest MMIO map
    // add ACPI memory map is merged into MMIO map
    // split and keep new entries here because we will apply cache information later
    status = MmapApplyFullMap(&Guest->EptMap,
        &Guest->MmioMap,
        MMAP_SPLIT_AND_KEEP_NEW
    );
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap", status);
        goto cleanup;
    }

    if (CfgDebugTraceMemoryMaps) MmapDump(&gHypervisorGlobalData.MemInfo.AcpiMap, BOOT_MEM_TYPE_ACPI, "ACPI map:\n");

    // make sure the first 4GB are covered
    // we do this due to various legacy devices mapped below
    // we are not interested in the actual memory type and cache yet
    entry = (MEM_MAP_ENTRY){ 0 };
    entry.StartAddress = 0;
    entry.Length = (4ULL * ONE_GIGABYTE);
    entry.Type = BOOT_MEM_TYPE_AVAILABLE;

    status = MmapApplyNewEntry(&Guest->EptMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyNewEntry", status);
        goto cleanup;
    }

    // make sure EPT map ends after MaxPhysicalAddress is covered
    for (DWORD i = 0; i < Guest->EptMap.Count; i++)
    {
        pEntry = &Guest->EptMap.Entry[i];
        if (pEntry->StartAddress >= MaxPhysicalAddress)
        {
            Guest->EptMap.Count = i;
            break;
        }
    }

    // update TARGET and RIGHTS fields
    for (DWORD i = 0; i < Guest->EptMap.Count; i++)
    {
        pEntry = &Guest->EptMap.Entry[i];

        pEntry->DestAddress = pEntry->StartAddress; // 1:1 identity map
        pEntry->CacheAndRights = 0; // 0 Cache and Rights
        pEntry->Type = BOOT_MEM_TYPE_AVAILABLE; // everything that is in EPT map is available
    }

    // assign cache type based on MTRRs
    // might end up splitting into more entries
    QWORD physAddr;
    BOOLEAN found = FALSE;
    WORD prevCacheAndRights = (Guest->EptMap.Entry[0].CacheAndRights & EPT_RAW_CACHING_MASK);
    WORD currentCacheAndRights = EPT_RAW_CACHING_WB;
    DWORD entryIndex = 0;

    while (entryIndex < Guest->EptMap.Count)
    {
        pEntry = &Guest->EptMap.Entry[entryIndex];
        prevCacheAndRights = (Guest->EptMap.Entry[entryIndex].CacheAndRights & EPT_RAW_CACHING_MASK);

        for (physAddr = pEntry->StartAddress; physAddr < pEntry->StartAddress + pEntry->Length - 1; physAddr += PAGE_SIZE)
        {
            currentCacheAndRights = EPT_RAW_CACHING_WB;

            for (DWORD k = 0; k < Guest->Mtrr->Map.Count; k++)
            {
                if ((physAddr >= Guest->Mtrr->Map.Entry[k].StartAddress) &&
                    (physAddr <= Guest->Mtrr->Map.Entry[k].StartAddress + Guest->Mtrr->Map.Entry[k].Length - 1)
                    )
                {
                    if (currentCacheAndRights > (Guest->Mtrr->Map.Entry[k].CacheAndRights & EPT_RAW_CACHING_MASK))
                    {
                        currentCacheAndRights = (Guest->Mtrr->Map.Entry[k].CacheAndRights & EPT_RAW_CACHING_MASK);
                    }

                    found = TRUE;
                }
            }


            if (!found)
            {
                currentCacheAndRights = ((Guest->Mtrr->DefType << 3) & EPT_RAW_CACHING_MASK);

                // in case the default is UC override it o WB
                // EFI firmware sets default cache type to UC
                // but Windows will update MTRRs and insert one
                // big entry to cover entire physical memory with
                // with cache type WB
                if (currentCacheAndRights == EPT_RAW_CACHING_UC) currentCacheAndRights = EPT_RAW_CACHING_WB;
            }

            // if cache type has changed then we have to split the pEntry
            if (prevCacheAndRights != currentCacheAndRights)
            {
                LOG("Cache changes for physical address %p from 0x%x to 0x%x. Entry[%d] start address: %p length: %p\n",
                    physAddr, prevCacheAndRights, currentCacheAndRights, entryIndex, Guest->EptMap.Entry[entryIndex].StartAddress, Guest->EptMap.Entry[entryIndex].Length);

                if (Guest->EptMap.Entry[entryIndex].StartAddress == physAddr)
                {
                    Guest->EptMap.Entry[entryIndex].CacheAndRights &= ~((WORD)EPT_RAW_CACHING_MASK);      // set CACHE to zero
                    Guest->EptMap.Entry[entryIndex].CacheAndRights |= (currentCacheAndRights & EPT_RAW_CACHING_MASK);

                    // update known cache value
                    prevCacheAndRights = (currentCacheAndRights & EPT_RAW_CACHING_MASK);
                }
                else
                {
                    QWORD originalEntryLen;

                    if (Guest->EptMap.MaxCount <= Guest->EptMap.Count)
                    {
                        status = CX_STATUS_INSUFFICIENT_RESOURCES;
                        goto cleanup;
                    }

                    // shift right entries
                    for (DWORD j = Guest->EptMap.Count; j > entryIndex; j--)
                    {
                        Guest->EptMap.Entry[j] = Guest->EptMap.Entry[j - 1];
                    }
                    Guest->EptMap.Count++;


                    LOG("Resize entry %d. Start: %p, Length %p, ResizeAddress: %p\n",
                        entryIndex, Guest->EptMap.Entry[entryIndex].StartAddress, Guest->EptMap.Entry[entryIndex].Length, physAddr);

                    // resize pEntry at entryIndex
                    originalEntryLen = Guest->EptMap.Entry[entryIndex].Length;
                    Guest->EptMap.Entry[entryIndex].Length = physAddr - Guest->EptMap.Entry[entryIndex].StartAddress;

                    // insert the new entry at entryIndex + 1
                    Guest->EptMap.Entry[entryIndex + 1].StartAddress = physAddr;
                    Guest->EptMap.Entry[entryIndex + 1].DestAddress = Guest->EptMap.Entry[entryIndex + 1].StartAddress + originalEntryLen - Guest->EptMap.Entry[entryIndex].Length;
                    Guest->EptMap.Entry[entryIndex + 1].Length = originalEntryLen - Guest->EptMap.Entry[entryIndex].Length;
                    Guest->EptMap.Entry[entryIndex + 1].CacheAndRights = (Guest->EptMap.Entry[entryIndex].CacheAndRights & EPT_RAW_CACHING_MASK);
                    Guest->EptMap.Entry[entryIndex + 1].Type = Guest->EptMap.Entry[entryIndex].Type;

                    Guest->EptMap.Entry[entryIndex + 1].CacheAndRights &= ~((WORD)EPT_RAW_CACHING_MASK);      // set CACHE to zero
                    Guest->EptMap.Entry[entryIndex + 1].CacheAndRights |= (currentCacheAndRights & EPT_RAW_CACHING_MASK);

                    LOG("Entry %d: Start %p, Length %p CacheAndRights: 0x%x\n",
                        entryIndex, Guest->EptMap.Entry[entryIndex].StartAddress, Guest->EptMap.Entry[entryIndex].Length, Guest->EptMap.Entry[entryIndex].CacheAndRights);

                    LOG("Entry %d: Start %p, Length %p CacheAndRights: 0x%x\n",
                        entryIndex + 1, Guest->EptMap.Entry[entryIndex + 1].StartAddress, Guest->EptMap.Entry[entryIndex + 1].Length, Guest->EptMap.Entry[entryIndex + 1].CacheAndRights);

                    // update known cache value
                    prevCacheAndRights = (currentCacheAndRights & EPT_RAW_CACHING_MASK);
                }
            }
        }

        ++entryIndex;
    }

    //  update TARGET and RIGHTS fields
    for (DWORD i = 0; i < Guest->EptMap.Count; i++)
    {
        pEntry = &Guest->EptMap.Entry[i];

        pEntry->DestAddress = pEntry->StartAddress; // 1:1 identity map
        pEntry->CacheAndRights &= ~((WORD)EPT_RAW_RIGHTS_MASK); // set RIGHTS to zero
        pEntry->CacheAndRights |= EPT_RAW_RIGHTS_RWX; // full RWX rights

        pEntry->Type = BOOT_MEM_TYPE_AVAILABLE; // everything that is in EPT map is available
    }

    // remove HYPERVISOR and GUEST-RESERVED ranges
    // we will add special EPT mappings for OS Load in order to allow the OS to read his memory for hibernate and memory dump cases
    status = MmapApplyFullMap(&Guest->EptMap, &gHypervisorGlobalData.MemInfo.HyperMap, MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap", status);
        goto cleanup;
    }

    status = MmapApplyFullMap(&Guest->EptMap, &gHypervisorGlobalData.MemInfo.GuestAreaMap, MMAP_SPLIT_AND_REMOVE_OLD_NO_INSERT);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap", status);
        goto cleanup;
    }

    // add the shared memory buffer
    entry = (MEM_MAP_ENTRY){ 0 };
    entry.StartAddress = Guest->SharedBufferGPA;
    entry.DestAddress = Guest->SharedBufferGPA;
    entry.Length = SHARED_MEM_SIZE;
    entry.Type = BOOT_MEM_TYPE_AVAILABLE;
    entry.CacheAndRights = EPT_RAW_CACHING_WB | EPT_RAW_RIGHTS_RW;
    status = MmapApplyNewEntry(&Guest->EptMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyNewEntry", status);
        goto cleanup;
    }

    // ensure local APIC is mapped through EPT
    entry = (MEM_MAP_ENTRY){ 0 };

    entry.Type = BOOT_MEM_TYPE_AVAILABLE;
    entry.CacheAndRights = BOOT_MEM_CACHE_UC | BOOT_MEM_RWX;
    entry.StartAddress = gBootInfo->CpuMap[0].LocalApicBase & 0xfffffffffffff000ULL;
    entry.Length = PAGE_SIZE;
    entry.DestAddress = entry.StartAddress; // identity map

    status = MmapApplyNewEntry(&Guest->EptMap, &entry, MMAP_SPLIT_AND_KEEP_NEW);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyNewEntry", status);
        goto cleanup;
    }

cleanup:

    if (CfgDebugTraceMemoryMaps) MmapDump(&Guest->EptMap, BOOT_MEM_TYPE_AVAILABLE, "Final EPT map!\n");

    return status;
}

/// @brief Callback used to add resources to the MMIO map based on the BAR content of the PCI devices
static
NTSTATUS
_AddResourcesToMmioMap(
    _In_ PCI_FUNC* PciFunction,
    _In_opt_ PCI_FUNC* Parent,
    _In_opt_ VOID* Context
)
{
    PCI_CONFIG* cfg = PciFunction->Config;

    UNREFERENCED_PARAMETER(Parent);

    // skip bridges
    if (cfg->Header.Class == PCI_CLS_BRIDGE_DEVICE) return CX_STATUS_SUCCESS;

    // skip hidden devices
    PCICFG_ID pciId = { .Segment = 0, .Bus = PciFunction->BusNumber, .Device = PciFunction->DevNumber, .Function = PciFunction->FuncNumber };
    if (PciIsPciCfgHidden(pciId)) return CX_STATUS_SUCCESS;

    // ignoring bridge limit ranges (?)

    CX_UINT8 barCount = MAX_PCI_BARS_TYPE0;
    CX_UINT8 idx = 0;
    while (idx < barCount)
    {
        PCI_BAR* bar = &(cfg->Bar[idx]);
        QWORD length;
        QWORD baseAddress;
        BOOLEAN is64, implemented;

        if (!bar->IoSpace)
        {
            NTSTATUS status = PciDecodeBar(bar, &baseAddress, &length, &is64, &implemented);
            if (!NT_SUCCESS(status))
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

            MEM_MAP_ENTRY tempEntry = { 0 };
            tempEntry.Type = BOOT_MEM_TYPE_AVAILABLE;

            // fist, make sure to account the in-page offset for the correct page-aligned length
            tempEntry.Length = PAGE_SIZE * PAGE_COUNT(baseAddress, length);
            // now we can safely align the base address
            tempEntry.StartAddress = CX_PAGE_BASE_4K(baseAddress);
            tempEntry.DestAddress = tempEntry.StartAddress;
            tempEntry.CacheAndRights = EPT_RAW_RIGHTS_R | EPT_RAW_RIGHTS_W;

            status = MmapApplyNewEntry(Context, &tempEntry, MMAP_SPLIT_AND_KEEP_NEW);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmapApplyNewEntry", status);
                LOG("Entry: StartAddress %p  Length %lld  Cache&Rights 0x%04x  DestAddress %p\n",
                    tempEntry.StartAddress, tempEntry.Length, tempEntry.CacheAndRights, tempEntry.DestAddress);
                return status;
            }
        }
        else is64 = FALSE;

        if (is64) idx += 2;
        else ++idx;
    }

    return CX_STATUS_SUCCESS;
}


/// @brief Performs all of the EPT related initializations
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2UpdateMapsAndMtrrsThenGenerateEptTree(
    _In_ GUEST* Guest
    )
{
    NTSTATUS status;

    //
    // Generate MMIO map based on resources
    //

    // preinitialize MMIO map
    status = MmapAllocMapEntries(&Guest->MmioMap, 256 + gHypervisorGlobalData.MemInfo.AcpiMap.Count); // gross estimate, 256 mem zones shall be more then enough
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapAllocMapEntries", status);
        goto cleanup;
    }

    status = PciWalkFunctions(_AddResourcesToMmioMap, &Guest->MmioMap);
    if (!SUCCESS(status))
    {
        ERROR("PciWalkFunctions failed for adding resources to MMIO map with %s\n", NtStatusToString(status));
        goto cleanup;
    }

    // merge MMIO map and ACPI map
    status = MmapApplyFullMap(&Guest->MmioMap, &gHypervisorGlobalData.MemInfo.AcpiMap, MMAP_SPLIT_AND_KEEP_NEW);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyFullMap", status);
        goto cleanup;
    }

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nPRIMARY GUEST MMIO map follows...\n");
        MmapDump(&Guest->MmioMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->MmioMap, ");
    }

    QWORD maxPhysicalAddress;
    MEM_MAP_ENTRY *lastEntry;
    QWORD tmpMaxAddr;

    // determine maximum covered GPA address by Guest->PhysMap
    lastEntry = &Guest->PhysMap.Entry[Guest->PhysMap.Count - 1];
    maxPhysicalAddress = lastEntry->StartAddress + lastEntry->Length;
    maxPhysicalAddress = ROUND_UP(maxPhysicalAddress, PAGE_SIZE);

    // we need only max physical RAM memory (reported by phys map to the guest)
    Guest->MaxPhysicalAddress = maxPhysicalAddress;

    // determine maximum covered GPA address by Guest->MmioMap
    lastEntry = &(Guest->MmioMap.Entry[Guest->MmioMap.Count - 1]);
    tmpMaxAddr = lastEntry->StartAddress + lastEntry->Length;
    tmpMaxAddr = ROUND_UP(tmpMaxAddr, PAGE_SIZE);

    if (maxPhysicalAddress < tmpMaxAddr) maxPhysicalAddress = tmpMaxAddr;

    //
    // Generate EPT map for PRIMARY GUEST (1:1 mappings)
    //

    DWORD numberOfEntries = MAX(((Guest->PhysMap.Count * 120) / 100), 100) + Guest->MmioMap.Count * 2;
    for (DWORD tempI = 0; tempI < 10; tempI++)
    {
        LOG("Generate guest EPT map iteration %d. Using a maximum of %d entries and maximum physical address: %p.\n", tempI, numberOfEntries, maxPhysicalAddress);
        status = _Phase2GenerateEptMap(Guest, numberOfEntries, maxPhysicalAddress);
        if (!SUCCESS(status))
        {
            if ((status == CX_STATUS_INSUFFICIENT_RESOURCES) || (status == CX_STATUS_DATA_BUFFER_TOO_SMALL))
            {
                MmapFreeMapEntries(&Guest->EptMap);

                numberOfEntries = (numberOfEntries * 13) / 10;  // increase with 30%
            }
            else
            {
                LOG_FUNC_FAIL("_Phase2GenerateEptMap", status);
                break;
            }
        }
        else break;
    }

    if (!SUCCESS(status))
    {
        ERROR("Failed to generate EPT map for guest! status = 0x%x\n", status);
        goto cleanup;
    }

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nPRIMARY GUEST EPT map follow...\n");
        MmapDump(&Guest->EptMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->EptMap, ");
    }
    LOG("will now setup PG's EPT space...\n");

    //
    // Setup guest memory domains based on guest->EptMap for both the physical memory and the single-step memory of the guest
    //

    // copy the memory mappings to the actual guest memory domains
    GUEST_MEMORY_DOMAIN_INDEX domainIndex[2] = { GuestPredefinedMemoryDomainIdPhysicalMemory, GuestPredefinedMemoryDomainIdSingleStepMemory };
    for (CX_UINT32 k = 0; k < ARRAYSIZE(domainIndex); k++)
    {
        EPT_DESCRIPTOR* ept;
        status = GstGetEptDescriptorEx(Guest, domainIndex[k], &ept);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("GstGetEptDescriptor", status);
            goto cleanup;
        }
        status = EptCopyTranslationsFromMemoryMap(ept, &Guest->EptMap);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("EptCopyTranslationsFromMemoryMap", status);
            goto cleanup;
        }

        LOG("Ept[%d]\n", k);
        EptDumpMappings(ept);
    }

    if (CfgFeaturesHibernatePersistance)
    {
        status = HvHibApplyMemoryHooks(Guest);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HvHibApplyMemoryHooks", status);
            goto cleanup;
        }
    }

    LOG("total memory used for guest EPT mappings: %llu KB\n", GstGetDomainsMemoryConsumption(Guest));

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/// @brief Apply the legacy memory patches (VGA, E820)
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, IVT is patched
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2ApplyGuestMemoryPatches(
    _In_ GUEST* Guest
    )
{
    NTSTATUS status;

    // load PXE trampoline code into memory to 0x0000:0x7E00
    if (BOOT_MBR_PXE)
    {
        if (gHypervisorGlobalData.BootFlags.IsGrub)
        {
            LOG("Patching with grub values: GrubBoot: %x, BootSector: %x, BootDrive: %x\n", 1, 2, gLoaderCustom->Legacy.BiosOsDrive.Drive);
            ((GRUB_INFO*)(&__GuestPxeGrubInfo))->GrubBoot = 1;
            ((GRUB_INFO*)(&__GuestPxeGrubInfo))->BootSector = 2;
            ((GRUB_INFO*)(&__GuestPxeGrubInfo))->BootDrive = gLoaderCustom->Legacy.BiosOsDrive.Drive;
        }
        memcpy((PVOID)0x7E00ULL, &__GuestPxeMbrLoaderCode, ((SIZE_T)&__GuestPxeMbrLoaderCodeEnd - (SIZE_T)&__GuestPxeMbrLoaderCode));
    }

    LOG("Patching interrupt handlers\n");
    status = HkInitBiosHooks(Guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HkInitBiosHooks", status);
        goto cleanup;
    }

    // Video services
    if (CfgDebugOutputVgaEnabled)
    {
        //If we don't have VGA enabled, there is no point into hooking int 10
        status = HkSetBiosHook(Guest, 0x10, &BhInt0x10, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HkSetBiosHook", status);
            goto cleanup;
        }
    }

    // int 0x15: E820 memory map
    status = HkSetBiosHook(Guest, 0x15, &BhInt0x15, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HkSetBiosHook", status);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}


/// @brief Performs all the major steps of the guest initialization
///
/// @param[out]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the guest is set up
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase2SetupGuest(
    _Out_ GUEST** Guest
)
{
    NTSTATUS status;
    GUEST* guest;

    LOG("\n\n ***** PHASE 2 / PRIMARY GUEST ***** \n\n");

    status = GstAllocAndPreinitGuest(&guest, gBootInfo->CpuCount);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstAllocAndPreinitGuest (PG)", status);
        goto cleanup;
    }

    status = _Phase2SetupInitialMtrrsAndMemoryMaps(guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase2SetupInitialMtrrsAndMemoryMaps", status);
        goto cleanup;
    }

    status = _Phase2SetupVcpusAndVmcs(guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase2SetupVcpusAndVmcs", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(40);

    LOG("\n\n ***** PHASE 2 / PRIMARY GUEST CORE INITED ***** \n\n");

    IoVgaSetLoadProgress(45);

    if (PwrIsSystemSupported())
    {
        status = PwrHookPm1a(guest);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("PwrHookPm1a", status);
            goto cleanup;
        }
    }

    status = _Phase2UpdateMapsAndMtrrsThenGenerateEptTree(guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase2UpdateMapsAndMtrrsThenGenerateEptTree", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(50);

    // Setup the BIOS interrupt hooks
    if (BOOT_OPT_BIOS_ENVIRONMENT)
    {
        status = _Phase2ApplyGuestMemoryPatches(guest);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_Phase2ApplyGuestMemoryPatches", status);
            goto cleanup;
        }
    }

    status = PciApplyPciCfgHooksForHiding(guest);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("PciApplyPciCfgHooksForHiding", status);
        goto cleanup;
    }

    status = GstInitRipCache(&guest->RipCache, RIP_CACHE_MAX_ENTRIES);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstInitRipCache", status);
        goto cleanup;
    }

    // Signal we have initialized primary guest and corresponding VCPUs
    gHypervisorGlobalData.BootProgress.PrimaryGuestInited = TRUE;

    LOG("\n\n ***** PHASE 2 / PRIMARY GUEST FULLY INITED ***** \n\n");
    *Guest = guest;

cleanup:
    return status;
}


NTSTATUS
Phase2BspStageTwo(
    void
)
{
    NTSTATUS status;
    GUEST* guest;

    IoSetPerCpuPhase(IO_CPU_PHASE2);

    // Now setup communication
    status = CommSetupHostRingBuffer();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("CommSetupHostRingBuffer", status);
        goto cleanup;
    }

    if (CfgDebugTraceMemoryMaps) MmapDump(&gHypervisorGlobalData.MemInfo.GuestAreaMap, BOOT_MEM_TYPE_AVAILABLE, " GuestAreaMap \n");

    // PHASE 2 - BSP only part, effectively initialize GUEST structures
    status = _Phase2SetupGuest(&guest);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase2SetupGuest", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(65);

    status = NdEmuInit(gBootInfo->CpuCount);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("NdEmuInit", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(70);

    status = GstActivateGuest(guest, TRUE);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstActivateGuest", status);
        goto cleanup;
    }

    // trigger APs to perform STAGE II init
    gStageTwoCanProceedOnAps = TRUE;

    // PHASE 2 - common BSP / AP per-PCPU flow (so we simply call the AP path from the BSP also)
    status = Phase2ApStageTwo();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("InitApStageTwo (BSP)", status);
        goto cleanup;
    }

    // signal that the BSP also completed stage II
    LOG("[CPU %d]: stage II init done\n", HvGetCurrentApicId());
    HvInterlockedIncrementU32(&gStageTwoInitedCpuCount);

    // wait for all AP processors to signal that they successfully completed stage II
    LOG("[BSP] wait for all APs to finish their STAGE II initialization...\n");
    while (gStageTwoInitedCpuCount < CPU_COUNT_TO_WAIT)
    {
        CpuYield();
    }
    LOG("[BSP] received STAGE II init completion signal from all %d AP processors\n", CPU_COUNT_TO_WAIT - 1);

    // IMPORTANT: signal that stage two initialization is successfully completed
    gHypervisorGlobalData.BootProgress.StageTwoDone = TRUE;

    IoVgaSetLoadProgress(75);

cleanup:

    return status;
}



NTSTATUS
Phase2ApStageTwo(
    void
    )
{
    NTSTATUS status;

    IoSetPerCpuPhase(IO_CPU_PHASE2);

    // PHASE 2 - common BSP / AP per-PCPU flow
    HvInterlockedBitTestAndSetU64(&gHypervisorGlobalData.Debug.AffinifyMask, HvGetCurrentCpuIndex());

    // initialize VMCS host state for all VCPUs associated with this PCPU
    status = VmstateConfigureVmcs(HvGetCurrentCpu()->Vcpu, VMCS_CONFIGURE_SETTINGS_INIT_HOST_STATE);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
        goto cleanup;
    }

    // invalidate all VMX / EPT / VPID caches before we start to schedule the VCPUs
    status = CpuVmxInvEpt(INVEPT_TYPE_ALL_CONTEXT, 0, 0);
    if (!SUCCESS(status))
    {
        LOG("[CPU %d] CpuVmxInvEpt (TYPE 2) failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
        goto cleanup;
    }

    status = CpuVmxInvVpid(2, NULL, 0); // TYPE 2: All-context invalidation
    if (!SUCCESS(status))
    {
        LOG("[CPU %d] CpuVmxInvVpid (TYPE 2) failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
        goto cleanup;
    }

    // Initialize branch storing mechanisms
    // We return CX_STATUS_NOT_SUPPORTED if this debug feature is disabled.  So do not print the error.
    status = DbgDsInit(HvGetCurrentCpu());
    if (!NT_SUCCESS(status) && status != CX_STATUS_NOT_SUPPORTED) LOG_FUNC_FAIL("DbgDsInit", status);
    else LOG("[CPU %d] Successfully initialized DS area!\n", HvGetCurrentApicId());

    if (CfgFeaturesActivateHwp == 1) // if the activation is for any Windows
    {
        HvActivatePerformanceMode();
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/// @}
