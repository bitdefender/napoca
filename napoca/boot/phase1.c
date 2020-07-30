/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file phase1.c Host system scanning and hypervisor configuration

/// \defgroup phase1 Phase 1 - Configuration of the hypervisor
/// \ingroup hvinit
/// @{

#include "napoca.h"
#include "kernel/kernel.h"
#include "kernel/mtrr.h"
#include "boot/phase1.h"
#include "boot/init64.h"
#include "memory/pagepool.h"
#include "memory/fastmap.h"
#include "guests/power.h"
#include "boot/devres.h"
#include "version.h"
#include "kernel/gs_utils.h"

static PCPU** gCpuPointersArray = NULL; ///< Each CPU structure once allocated and initialized is stored (as a pointer) in this array, same indexing with the boot cpu structures array

static BOOLEAN gCpuIpcQueuesAllocated = FALSE; ///< TRUE if the queues are allocated for the interprocess communication

extern CPUSTATE_BOOT_GUEST_STATE *gBootState;

extern SPINLOCK gFreezeCpusLock;


PCPU *
HvGetCpu(
    _In_ CX_UINT32 BootCpuIndex
)
{
    if (BootCpuIndex >= gBootInfo->CpuCount || !gCpuPointersArray) return NULL;

    return gCpuPointersArray[BootCpuIndex];
}

/// @brief Get the current PCPU, useful while the CPU is still being initialized and GS doesn't yet point to the correct/final structure
///
/// @returns The requested PCPU, NULL if something went wrong
static
__forceinline
PCPU *
_Phase1GetCurrentCpu(
    VOID
)
{
    return HvGetCpu(CpuGetBootIndexForLocalApicId(HvGetInitialLocalApicIdFromCpuid()));
}


/// @brief Dummy callback to turn off VMX on unload, needed as each CPU has to know if to __vmx_off or not
static
NTSTATUS
_CpuVmxCleanupCallback(
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(OriginalState);

    CpuPerformVmxoff(HvGetCurrentCpu());

    return CX_STATUS_SUCCESS;
}


/// @brief Check if the IPC queues are initialized
///
/// @returns TRUE if the IPC queues are initialized, FALSE otherwise
BOOLEAN HvDoWeHaveIpcQueues(
    VOID
)
{
    return gCpuIpcQueuesAllocated;
}

/// @brief Initializes the first (0-th) entry from gBootInto->CpuMap[] to reflect the BSP's features.
///
/// Validates also that we have the minimum required CPU features for virtualization to work right.
///
/// @returns    CX_STATUS_SUCCESS                     - Required features are present
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE      - We couldn't determine all the required CPU features
/// @returns    OTHER                                 - Other internal error
static
NTSTATUS
_Phase1InitBspAndValidateFeatures(
    void
)
{
    NTSTATUS status;

    assert(gBootInfo->CpuCount == 0);

    memset(&gVirtFeatures, 0, sizeof(VIRTUALIZATION_FEATURES));

    // NOTE: we ALWAYS place the BSP at index 0 in gBootInfo
    if (!InitCpuEntry(&gBootInfo->CpuMap[0]))
    {
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }

    if (!InitCpuVirtualizationFeatures(&gBootInfo->CpuMap[0], &gVirtFeatures))
    {
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }


    // increment CPU count - after this, the APs can also run their identification phase
    HvInterlockedIncrementU32(&gBootInfo->CpuCount);

    // we save this globally
    gHypervisorGlobalData.CpuData.IsIntel = gBootInfo->CpuMap[0].ProcessorType.Intel;

    CpuidCollectMaxLeafValues(
        &gHypervisorGlobalData.CpuData.MaxBasicCpuidInputValue,
        &gHypervisorGlobalData.CpuData.MaxExtendedCpuidInputValue);

    status = CpuCheckFeatures(&gBootInfo->CpuMap[0], &gVirtFeatures);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("CpuCheckFeatures", status);
        goto cleanup;
    }

cleanup:

    return status;
}



void
Phase1InitializeHostControlRegisters(
    void
)
{
    // disable interrupts
    _disable();

    __writemsr(MSR_IA32_LSTAR, 0x0);

    __writecr0((__readcr0() | CR0_WP | CR0_NE) & ~(CR0_CD|CR0_NW));

    __writecr4(__readcr4() & (~CR4_PGE));
    __writecr4(__readcr4() | CR4_OSFXSR); // conform Intel vol 3A, chap 2.5 (needed for VmWare)

    __writecr4(__readcr4() | CR4_MCE | CR4_OSXMMEXCPT);

    __writemsr(
        MSR_IA32_MISC_ENABLE,
        __readmsr(MSR_IA32_MISC_ENABLE) & ~(MISC_XD_BIT_DISABLE | MISC_LIMIT_CPUID_MAXVAL));


    // disable fast strings due to Skylake cpu bug
    // As per SKW82 in http://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/xeon-e3-1200v5-spec-update.pdf,
    // this is a CPU issue.
    if ( (gBootInfo->CpuMap[0].FamilyFields.Family == 0x06) &&
        (gBootInfo->CpuMap[0].FamilyFields.Model == 0x0e) &&
        ((gBootInfo->CpuMap[0].FamilyFields.ExtendedModel == 4) ||
        (gBootInfo->CpuMap[0].FamilyFields.ExtendedModel == 5))
        )
    {
        __writemsr(MSR_IA32_MISC_ENABLE,(__readmsr(MSR_IA32_MISC_ENABLE) & (~MISC_ENABLE_FAST_STRINGS)));
    }
    else
    {
        LOG("Not a Skylake processor: family = %x, model = %x, extended = %x! Will leave MISC ENABLE msr alone!\n",
            gBootInfo->CpuMap[0].FamilyFields.Family,
            gBootInfo->CpuMap[0].FamilyFields.Model,
            gBootInfo->CpuMap[0].FamilyFields.ExtendedModel
        );
    }

    //
    // When CPUID executes with EAX set to 1, feature information is returned in ECX and EDX.
    //
    // ECX.26 - XSAVE, a value of 1 indicates that the processor supports the XSAVE/XRSTOR processor extended states feature, the
    // XSETBV/XGETBV instructions, and XCR0.
    //
    // EDX.24 - FXSR FXSAVE and FXRSTOR Instructions. The FXSAVE and FXRSTOR instructions are supported for fast save and restore
    // of the floating point context. Presence of this bit also indicates that CR4.OSFXSR is available for an operating system to
    // indicate that it supports the FXSAVE and FXRSTOR instructions.
    //
    // If CPUID.01H:ECX.XSAVE[bit 26] is 1, the processor supports one or more extended control registers (XCRs).
    // Currently, the only such register defined is XCR0.
    //
    // CR4:OSXSAVE[bit 18]
    // XSAVE and Processor Extended States-Enable Bit (bit 18 of CR4) -
    // When set, this flag: (1) indicates (via CPUID.01H:ECX.OSXSAVE[bit 27])
    // that the operating system supports the use of the XGETBV, XSAVE and
    // XRSTOR instructions by general software; (2) enables the XSAVE and
    // XRSTOR instructions to save and restore the x87 FPU state (including MMX
    // registers), the SSE state (XMM registers and MXCSR), along with other
    // processor extended states enabled in XCR0; (3) enables the processor to
    // execute XGETBV and XSETBV instructions in order to read and write XCR0.
    // See Section 2.6 and Chapter 13, "System Programming for Instruction Set
    // Extensions and Processor Extended States".
    //

    //
    // XSETBV support: not all CPUs support this (for ex. first gen Intel Core i5-650, socket 1156 doesn't support it),
    // however, this MUST be enabled for CPUs using XSETBV
    //
    {
        int cpuInfo[4] = {0};

        __cpuid(cpuInfo, 1);

        // CPUID.01H:ECX.XSAVE
        if (cpuInfo[2] & BIT_AT(26)) __writecr4(__readcr4() | CR4_OSXSAVE);
    }

    // initializes the FPU (finit)
    FpuSseInit();
}


__declspec(align(16)) GDT gTempBspGdt;                ///< Temporary GDT for boot
__declspec(align(16)) INTERRUPT_GATE gTempBspIdt[32]; ///< Temporary IDT for boot

static DUMMY_CPU gGlobalDummyCpu;

/// @brief Set up a minimal initial IDT for the BSP to be used for exception handling.
static
NTSTATUS
_Phase1SetupInitialExceptionHandlingForBsp(
    void
)
{
    LOG("[BSP] will setup initial exception handling...\n");

    memzero(&gTempBspIdt, sizeof(INTERRUPT_GATE) * 32);

    // init and load temp GDT for BSP
    GDT* gdt;
    DWORD gdtSize;
    LGDT lgdt;

    gdt = (GDT*)&gTempBspGdt;
    gdtSize = sizeof(GDT);

    memzero(gdt, gdtSize);

    gdt->Null = 0x0000000000000000ULL;
    gdt->Code64 = 0x002f9A000000ffffULL;            // L = 1, D = 0
    gdt->Data64 = 0x00cf92000000ffffULL;
    gdt->Gs64.Raw[0] = 0x00cf92000000ffffULL;
    /// FIXME: setup GS64 base
    gdt->Code32Compat = 0x004f9A000000ffffULL;      // L = 0, D = 1

    // load GDT
    lgdt.GdtAddress = (QWORD)gdt;
    lgdt.Size = (WORD)(gdtSize - 1);

    _lgdt(&lgdt);

    // force reload hidden part of CS, FS, GS descriptors inside the CPU (SS, DS, ES are NOT used on x64 mode)
    CpuSetCS(CODE64_SELECTOR);
    CpuSetFS(NULL_SELECTOR);
    CpuSetGS(GS64_SELECTOR); // take care, this does NOT load the upper 32 bits (must be written by MSR below)

    // setup GS base
    CpuBindStructureToGs((PCPU*)&gGlobalDummyCpu);

    // init and load temp IDT for BSP
    INTERRUPT_GATE* idt;
    DWORD idtSize;
    LIDT lidt;

    idt = (INTERRUPT_GATE*)&gTempBspIdt;
    idtSize = (32 * sizeof(INTERRUPT_GATE));

    memzero(idt, idtSize);

    HvInitExceptionHandlers(idt, FALSE);

    // load IDT
    lidt.IdtAddress = (QWORD)idt;
    lidt.Size = (WORD)(idtSize - 1); // 32 x 16 bytes, check out "6.14.1 64-Bit Mode IDT" from Intel Vol 3A

    __lidt(&lidt);

    LOG("[BSP] initial exception handling successfully setup\n");

    return CX_STATUS_SUCCESS;
}


/// @brief Mark a memory range as being used by the hypervisor
///
/// @param[in]  Pa              Starting physical address of the range to be marked
/// @param[in]  Size            The size of the range
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the given range is marked
/// @returns    CX_STATUS_DATA_OUT_OF_RANGE         - Too many map entries
static
NTSTATUS
_Phase1MarkMemInUse(
    _In_ MM_UNALIGNED_PA Pa,
    _In_ MM_SIZE_IN_BYTES Size
)
{
    BOOLEAN dirty;
    NTSTATUS status = CX_STATUS_SUCCESS;

    MM_ALIGNED_PA alignedPa = PAGE_BASE_PA(Pa);
    MM_SIZE_IN_BYTES alignedSize = PAGE_COUNT(Pa, Size) * PAGE_SIZE;

    // while there are overlapping entries split and define separately each block
    do
    {
        dirty = FALSE;
        for (DWORD i = 0; (i < gBootInfo->PhyMemCount) && (!dirty); i++)
        {
            INT64 l = 0, r = 0;
            QWORD pa = 0, dest = 0, size = 0;
            BYTE entries = 0, type = 0;
            DWORD current = 0;

            if ((alignedPa + alignedSize) <= gBootInfo->PhyMemMap[i].StartAddress) continue;
            if ((gBootInfo->PhyMemMap[i].StartAddress + gBootInfo->PhyMemMap[i].Length) <= alignedPa) continue;

            if (gBootInfo->PhyMemMap[i].Type & BOOT_MEM_TYPE_HYPERVISOR_IN_USE) continue; // already marked

            // the tmp is overlapping with the memory entry, split and properly define each region

            l = (INT64)(alignedPa - gBootInfo->PhyMemMap[i].StartAddress);
            r = (INT64)((gBootInfo->PhyMemMap[i].StartAddress + gBootInfo->PhyMemMap[i].Length) - (alignedPa + alignedSize));

            if (l < 0) l = 0; // nothing left to the left :p
            if (r < 0) r = 0; // nothing left to the right

            // we need +1 entry for each interval
            entries = (l > 0) + (r > 0);

            // shift all other entries to the right to make space
            if ((entries > 0) && (entries + gBootInfo->PhyMemCount >= BOOT_MAX_PHY_MEM_COUNT))
            {
                status = CX_STATUS_DATA_OUT_OF_RANGE;
                goto cleanup;
            }

            if (entries > 0)
            {
                for (DWORD k = gBootInfo->PhyMemCount - 1; k >= i; k--)
                {
                    gBootInfo->PhyMemMap[k + entries] = gBootInfo->PhyMemMap[k];
                }
                gBootInfo->PhyMemCount += entries;
            }

            // setup the new entries
            current = i;
            pa = gBootInfo->PhyMemMap[current].StartAddress;
            dest = gBootInfo->PhyMemMap[current].DestAddress;
            size = gBootInfo->PhyMemMap[current].Length;
            type = gBootInfo->PhyMemMap[current].Type;
            LOG("Marking [%p, %p) as being used in the memory map\n", alignedPa, (alignedPa + alignedSize) - 1);

            // setup the interval on the left
            if (l > 0)
            {
                gBootInfo->PhyMemMap[current].Length = l;
                current++;
            }

            // setup the tmp entry
            gBootInfo->PhyMemMap[current].StartAddress = pa + l;
            gBootInfo->PhyMemMap[current].Type = type | BOOT_MEM_TYPE_HYPERVISOR_IN_USE; // DON'T allocate memory from this range!!
            gBootInfo->PhyMemMap[current].Length = size - (l + r);
            current++;

            // setup right side interval
            if (r > 0)
            {
                gBootInfo->PhyMemMap[current].StartAddress = pa + (size - r);
                gBootInfo->PhyMemMap[current].Type = type;
                gBootInfo->PhyMemMap[current].Length = r;///size - (l + r);
                current++;
            }
            dirty = (l + r) > 0;  // re-parse the map
        }// end for map entries(i)
    } while (dirty);

cleanup:
    return status;
}

/// @brief Mark our own modules in the physical memory map to avoid overwriting our memory.
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, all the relevant ranges are marked
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1PhysicalMemoryMapMarkModules(
    void
)
{
    NTSTATUS status;
    LD_NAPOCA_MODULE *module;

    for (DWORD modId = 0; modId < LD_MAX_MODULES; modId++)
    {
        status = LdGetModule(gBootModules, LD_MAX_MODULES, modId, &module);
        if (!SUCCESS(status)) continue; // no such module is defined / in use

        status = _Phase1MarkMemInUse(module->Pa, module->Size);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_Phase1MarkMemInUse", status);
            goto cleanup;
        }
    }

    status = _Phase1MarkMemInUse(gTempMem->Pa, gTempMem->Length);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("_Phase1MarkMemInUse", status);

cleanup:
    return status;
};



/// @brief Parses the raw E820 data (from BIOS INT 15h) and creates a memory map into gBootInfo->PhyMemMap.
///
///  Also validates that we have enough physical RAM to run the hypervisor
///
/// @returns    CX_STATUS_SUCCESS                     - All good, the map was created
/// @returns    CX_STATUS_INSUFFICIENT_RESOURCES      - If the host system has less physical memory than the minimum needed (currently 0.9 GB)
/// @returns    CX_STATUS_DATA_OUT_OF_RANGE           - Most probably memory too fragmented
/// @returns    STATUS_INVALID_MEMORY_TYPE            - Invalid memory type found
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE      - No entries in the physical map
/// @returns    OTHER                                 - Other internal error
static
NTSTATUS
_Phase1GetPhysicalMemoryMap(
    void
)
{
    NTSTATUS status;
    QWORD totalRequiredMemory;
    QWORD guestsRequiredMemory;

    if (BOOT_MBR_PXE) gBootInfo->PhyMemCount = 0;

    if ((gBootInfo->PhyMemCount == 0) && (gTempE820 != NULL))
    {
        LD_MEMORY_MAP *map = (LD_MEMORY_MAP *)gTempE820;

        for (DWORD i = 0; i < map->NumberOfEntries; i++)
        {
            QWORD address;
            QWORD length;
            LD_MEM_TYPE type;

            // retrieve and validate entry info
            address = map->Entries[i].BaseAddress;;
            length = map->Entries[i].Length;
            type.Raw = map->Entries[i].Type.Raw;
            if (map->MapType == LD_MEMORY_MAP_TYPE_E820) type.Hv = LdConvertE820MemTypeToHvMemType(type.E820);
            else if (map->MapType == LD_MEMORY_MAP_TYPE_EFI) type.Hv = LdConvertEfiMemTypeToHvMemType(type.Efi);

            if (type.Hv == BOOT_MEM_TYPE_INVALID)
            {
                ERROR("Invalid memory type in the loader memory map!\n");
                return STATUS_INVALID_MEMORY_TYPE;
            }

            // add the new map entry
            if (gBootInfo->PhyMemCount >= BOOT_MAX_PHY_MEM_COUNT) return CX_STATUS_DATA_OUT_OF_RANGE;

            gBootInfo->PhyMemMap[gBootInfo->PhyMemCount].StartAddress = address;
            gBootInfo->PhyMemMap[gBootInfo->PhyMemCount].Length = length;
            gBootInfo->PhyMemMap[gBootInfo->PhyMemCount].Type = type.Hv;

            gBootInfo->PhyMemCount++;
        }
    }

    // ... without physical memory map, we can't go on
    if (gBootInfo->PhyMemCount == 0)
    {
        CRITICAL("gBootInfo->PhyMemCount cannot be 0\n");
        return CX_STATUS_INVALID_INTERNAL_STATE;
    }

    // ensure that the PhyMemMap is sorted
    for (WORD i = 0; i < gBootInfo->PhyMemCount - 1; i++)
    {
        for (WORD j = i+1; j < gBootInfo->PhyMemCount; j++)
        {
            if (gBootInfo->PhyMemMap[i].StartAddress > gBootInfo->PhyMemMap[j].StartAddress)
            {
                MEM_MAP_ENTRY tmp = {0};

                tmp = gBootInfo->PhyMemMap[i];
                gBootInfo->PhyMemMap[i] = gBootInfo->PhyMemMap[j];
                gBootInfo->PhyMemMap[j] = tmp;
            }
        }
    }

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("total physical ram{1} = %zd bytes  (%10.3f MB)\n",
            gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory, (double)gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory / (double)ONE_MEGABYTE);
        for (WORD i = 0; i < gBootInfo->PhyMemCount; i++)
        {
             LOG("%018p - %018p - %d - %10.3f MB\n",
                 gBootInfo->PhyMemMap[i].StartAddress,
                 gBootInfo->PhyMemMap[i].StartAddress + gBootInfo->PhyMemMap[i].Length - 1,
                 gBootInfo->PhyMemMap[i].Type, (double)gBootInfo->PhyMemMap[i].Length / (double)ONE_MEGABYTE);
        }
    }

    // mark our own modules
    status = _Phase1PhysicalMemoryMapMarkModules();
    if (!SUCCESS(status)) return status;

    // determine the total amount of available physical RAM
    for (WORD i = 0; i < gBootInfo->PhyMemCount; i++)
    {
        if (BOOT_MEM_TYPE_AVAILABLE == gBootInfo->PhyMemMap[i].Type) gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory += gBootInfo->PhyMemMap[i].Length;
    }

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("Modules map:\n");
        for(WORD i = 0; i < LD_MAX_MODULES; i++)
        {
            LD_NAPOCA_MODULE *module = NULL;

            if (_SUCCESS(LdGetModule(gBootModules, LD_MAX_MODULES, i, &module)))
            {
                LOG("%018p - %018p - %d - %10.3f MB - %s\n",
                    module->Pa,
                    module->Pa + module->Size - 1,
                    module->Flags, (double)module->Size / (double)ONE_MEGABYTE,
                    LdGetModuleName(i));
            }
        }
        // dump out total RAM amount + physical layout
        LOG("total physical ram = %zd bytes  (%10.3f MB)\n",
            gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory, (double)gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory / (double)ONE_MEGABYTE);
        if (CfgDebugTraceMemoryMaps)
        {
            for (WORD i = 0; i < gBootInfo->PhyMemCount; i++)
            {
                LOG("%018p - %018p - %d - %10.3f MB\n",
                    gBootInfo->PhyMemMap[i].StartAddress,
                    gBootInfo->PhyMemMap[i].StartAddress + gBootInfo->PhyMemMap[i].Length - 1,
                    gBootInfo->PhyMemMap[i].Type, (double)gBootInfo->PhyMemMap[i].Length / (double)ONE_MEGABYTE);
            }
        }
    }

    // we need at least 0.9 GB physical memory
    if (gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory < (1ULL * ONE_GIGABYTE - 100 * ONE_MEGABYTE))
    {
        return CX_STATUS_INSUFFICIENT_RESOURCES;
    }

    // determine the estimated length of total HV zone
    status = LdEstimateRequiredHvMem(
        gHypervisorGlobalData.MemInfo.TotalSystemPhysicalMemory,
        1,
        NAPOCA_MEM_SHARED_BUFFER,
        &totalRequiredMemory,
        &guestsRequiredMemory);
    if (!SUCCESS(status)) return status;

    gHypervisorGlobalData.MemInfo.EstimatedHvLength = totalRequiredMemory - guestsRequiredMemory;


    // dump out the estimated total HV zone length
    LOG("estimated total HV zone ram = %zd bytes  (%10.3f MB), totalRequiredMemory=%p, guestsRequiredMemory=%p\n",
        gHypervisorGlobalData.MemInfo.EstimatedHvLength, (double)gHypervisorGlobalData.MemInfo.EstimatedHvLength / (double)ONE_MEGABYTE, totalRequiredMemory, guestsRequiredMemory);

    // reserve also space for guests
    gHypervisorGlobalData.MemInfo.TotalGuestSpace = guestsRequiredMemory;
    gHypervisorGlobalData.MemInfo.FreeGuestSpace = gHypervisorGlobalData.MemInfo.TotalGuestSpace;

    LOG("estimated GUEST zone ram = %zd bytes  (%10.3f MB)\n",
        gHypervisorGlobalData.MemInfo.TotalGuestSpace, (double)gHypervisorGlobalData.MemInfo.TotalGuestSpace / (double)ONE_MEGABYTE);

    return CX_STATUS_SUCCESS;
}



/// @brief  Creates a memory map into gBootInfo->HvMemMap to describe the physical memory chunks that are reserved for the hypervisor.
///
/// @returns    CX_STATUS_SUCCESS                     - All good, the zone was created
/// @returns    CX_STATUS_INVALID_INTERNAL_STATE      - Some sort of consistency issue
/// @returns    CX_STATUS_INSUFFICIENT_RESOURCES      - We couldn't reserve enough space for the hypervisor to cover the estimated needs
static
NTSTATUS
_Phase1GetHvZoneMemoryMap(
    void
)
{
    NTSTATUS status;

    // if we do NOT have included the KZ area, we have some inconsistency
    if (gBootInfo->HvMemMap->HvZoneCount == 0) return CX_STATUS_INVALID_INTERNAL_STATE;

    if (gBootInfo->Flags & BIF_HV_ZONE_MAPS_ONLY_KZ)
    {
        INT32 i, first = -1;
        QWORD firstPa = 0;
        QWORD totalSize, initialTotalSize = 0;
        QWORD neededSize;
        BOOLEAN guestChunk;
        QWORD delta = 0;

        // determine how much RAM we need to take from the host system for the HV and for the guest
        neededSize = gHypervisorGlobalData.MemInfo.EstimatedHvLength + gHypervisorGlobalData.MemInfo.TotalGuestSpace;

        // determine from where to start (from the highest memory zones)
        // because PhyMemMap is sorted, we need to count down from the highest PhyMemMap entry downwards
        // count in any already reserved entry
        for (i = 0; i < (INT32)gBootInfo->HvMemMap->HvZoneCount; i++)
        {
            initialTotalSize = initialTotalSize + gBootInfo->HvMemMap->Entries[i].Length;

            LOG("already reserved (%d)  %018p - %018p\n", i, gBootInfo->HvMemMap->Entries[i].StartAddress, gBootInfo->HvMemMap->Entries[i].StartAddress + gBootInfo->HvMemMap->Entries[i].Length - 1);
        }
        totalSize = initialTotalSize;

        // start counting downward from the highest address (last PhyMemCount entry)
        i = gBootInfo->PhyMemCount-1;
        while ((i >= 0) && (totalSize < neededSize))
        {
            // skip any chunk that is NOT available RAM
            if (BOOT_MEM_TYPE_AVAILABLE != gBootInfo->PhyMemMap[i].Type)
            {
                i--;
                continue;
            }

            // do we need the whole chunk from PhyMemMap[i] ?
            if ((gBootInfo->PhyMemMap[i].Length + totalSize) < neededSize)
            {
                totalSize = totalSize + gBootInfo->PhyMemMap[i].Length;
                i--;
                continue;
            }

            // this must be the first chunk we need to allocate from
            // starting PA: round DOWN to PAGE_SIZE the position that is 'end-of-this-chunk MINUS how-much-more-do-we-still-need'
            firstPa = ROUND_DOWN(gBootInfo->PhyMemMap[i].StartAddress + gBootInfo->PhyMemMap[i].Length - (neededSize - totalSize), PAGE_SIZE);
            first = i;

            break;
        }

        // did we found enough RAM chunks?
        if (first == -1)
        {
            ERROR("No memory chunks were found!\n");
            status = CX_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        // effectively build up any new HvZone entries
        i = first;

        totalSize = initialTotalSize;
        guestChunk = FALSE;
        gBootInfo->HvMemMap->GuestZoneCount = 0;

        while (i <= gBootInfo->PhyMemCount-1)
        {
            // skip any chunk that is NOT available RAM
            if (BOOT_MEM_TYPE_AVAILABLE != gBootInfo->PhyMemMap[i].Type)
            {
                i++;
                continue;
            }

            if (gBootInfo->HvMemMap->HvZoneCount >= gBootInfo->HvMemMap->TotalNumberOfEntries)
            {
                ERROR("Out of HvMemMap entries\n");
                return CX_STATUS_INSUFFICIENT_RESOURCES;
            }

            // first of all, copy all chunk info (include the whole chunk)
            gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount] = gBootInfo->PhyMemMap[i];
            gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Type = BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED;

            // IMPORTANT: for the first chunk (which can be just part-of-a-chunk) we need to do adjustments
            if (i == first)
            {
                delta = firstPa - gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress;

                gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress += delta;
                gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length -= delta;
            }

            // IMPORTANT: keep counting size to be able to split the last chunk in two,
            // if the currently set chunk has space both for the HV and the guests
            totalSize = totalSize + gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length;
            if ((totalSize >= (neededSize - gHypervisorGlobalData.MemInfo.TotalGuestSpace)) && (!guestChunk) && (gHypervisorGlobalData.MemInfo.TotalGuestSpace))
            {
                guestChunk = TRUE; // from now one, the chunks will be for the guest area

                // do we need to split this chunk?
                if (totalSize > (neededSize - gHypervisorGlobalData.MemInfo.TotalGuestSpace))
                {
                    totalSize = totalSize - gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length;

                    LOG("need to split chunk (GUEST) %018p - %018p\n",
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress,
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress + gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length-1);

                    // we need to split chunk: cut down delta bytes into a new chunk (this new chunk will be the first
                    // chunk to be used to store data for guest machines)
                    gBootInfo->HvMemMap->HvZoneCount++;

                    delta = (neededSize - gHypervisorGlobalData.MemInfo.TotalGuestSpace) - totalSize;

                    // duplicate chunk
                    gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount] = gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount-1];

                    // the first of the chunks must have it's length decreased
                    gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount-1].Length = delta;
                    totalSize = totalSize + delta;

                    LOG("...first half (GUEST) %018p - %018p\n",
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount-1].StartAddress,
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount-1].StartAddress + gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount-1].Length-1);

                    // the next chunk must start from a different address
                    gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress += delta;
                    gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length -= delta;

                    LOG("...second half (GUEST) %018p - %018p\n",
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress,
                        gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].StartAddress + gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length-1);

                    totalSize = totalSize + gBootInfo->HvMemMap->Entries[gBootInfo->HvMemMap->HvZoneCount].Length;
                }
            }

            if (guestChunk) gBootInfo->HvMemMap->GuestZoneCount++;

            gBootInfo->HvMemMap->HvZoneCount++;

            // go to next chunk
            i++;
        }
    }

    LOG("HvZoneCount %d  GuestZoneCount %d\n",
        gBootInfo->HvMemMap->HvZoneCount, gBootInfo->HvMemMap->GuestZoneCount);

    // without hypervisor memory map, we can't go on
    if (gBootInfo->HvMemMap->HvZoneCount < 2)
    {
        ERROR("No hypervisor memory map, HvZoneCount < 2\n");
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    // determine the real total HV zone size, the SUM of the length of all chunks reserved
    // for the HV ***MINUS the space reserved for GUESTS*** (both are stored in HvMemMap)
    gHypervisorGlobalData.MemInfo.TotalHvLength = 0;
    {
        for (DWORD i = 0; i < gBootInfo->HvMemMap->HvZoneCount; i++)
        {
            if (BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED == gBootInfo->HvMemMap->Entries[i].Type)
            {
                gHypervisorGlobalData.MemInfo.TotalHvLength = gHypervisorGlobalData.MemInfo.TotalHvLength + gBootInfo->HvMemMap->Entries[i].Length;
            }
            else
            {
                LOG("Invalid HvMemMap entry[%d] found, type=%d\n", i, gBootInfo->HvMemMap->Entries[i].Type);
                status = CX_STATUS_INVALID_INTERNAL_STATE;
                goto cleanup;
            }
        }

        // make sure we have enough memory
        if (ROUND_DOWN(gHypervisorGlobalData.MemInfo.TotalHvLength, PAGE_SIZE) < gHypervisorGlobalData.MemInfo.TotalGuestSpace)
        {
            ERROR("Not enough memory allocated! Total HV length: %10.3f MB, Total guest space: %10.3f MB\n",
                ((double)gHypervisorGlobalData.MemInfo.TotalHvLength / (double)ONE_MEGABYTE),
                ((double)gHypervisorGlobalData.MemInfo.TotalGuestSpace / (double)ONE_MEGABYTE)
                );

            return CX_STATUS_INSUFFICIENT_RESOURCES;
        }

        // ensure total length is multiple of PAGE_SIZE
        gHypervisorGlobalData.MemInfo.TotalHvLength = ROUND_DOWN(gHypervisorGlobalData.MemInfo.TotalHvLength, PAGE_SIZE) - gHypervisorGlobalData.MemInfo.TotalGuestSpace;

        // dump out total HV RAM amount + layout
        if (CfgDebugTraceMemoryMaps)
        {
            DWORD j = 0;

            LOG("real total HV zone ram = %zd bytes (%10.3f MB), map follows\n",
                gHypervisorGlobalData.MemInfo.TotalHvLength, (double)gHypervisorGlobalData.MemInfo.TotalHvLength / (double)ONE_MEGABYTE);

            for (DWORD i = 0; i < (gBootInfo->HvMemMap->HvZoneCount - gBootInfo->HvMemMap->GuestZoneCount); i++)
            {
                LOGN("%018p - %018p - %d - %10.3f MB\n",
                     gBootInfo->HvMemMap->Entries[i].StartAddress,
                     gBootInfo->HvMemMap->Entries[i].StartAddress + gBootInfo->HvMemMap->Entries[i].Length - 1,
                     gBootInfo->HvMemMap->Entries[i].Type, (double)gBootInfo->HvMemMap->Entries[i].Length / (double)ONE_MEGABYTE);
            }

            LOG("guest zone ram = %zd bytes (%10.3f MB), map follows\n",
                gHypervisorGlobalData.MemInfo.TotalGuestSpace, (double)gHypervisorGlobalData.MemInfo.TotalGuestSpace / (double)ONE_MEGABYTE);

            for (DWORD i = 0; i < gBootInfo->HvMemMap->GuestZoneCount; i++)
            {
                j = i + (gBootInfo->HvMemMap->HvZoneCount - gBootInfo->HvMemMap->GuestZoneCount);

                LOGN("%018p - %018p - %d - %10.3f MB\n",
                     gBootInfo->HvMemMap->Entries[j].StartAddress,
                     gBootInfo->HvMemMap->Entries[j].StartAddress + gBootInfo->HvMemMap->Entries[j].Length - 1,
                     gBootInfo->HvMemMap->Entries[j].Type, (double)gBootInfo->HvMemMap->Entries[j].Length / (double)ONE_MEGABYTE);
            }
        }
    }

    // check that the real total HV zone is at least 99% of the size of the estimated zone
    if (gHypervisorGlobalData.MemInfo.TotalHvLength < (gHypervisorGlobalData.MemInfo.EstimatedHvLength * 99 / 100))
    {
        status = CX_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


/// @brief Determines the memory layout for the KZ(kernel zone) | PP(page pool) ranges, based on the total HV length.
static
void
_Phase1DetermineKzSmPfnPpZoneSizes(
    void
)
{
    gHypervisorGlobalData.MemInfo.KzBase = (PBYTE)NAPOCA_KERNEL_BASE;
    gHypervisorGlobalData.MemInfo.KzLength = ROUND_UP(gHypervisorGlobalData.MemInfo.KernelImageLength, PAGE_SIZE);

    gHypervisorGlobalData.MemInfo.PpBase = gHypervisorGlobalData.MemInfo.KzBase + gHypervisorGlobalData.MemInfo.KzLength;
    gHypervisorGlobalData.MemInfo.PpLength = gHypervisorGlobalData.MemInfo.TotalHvLength - gHypervisorGlobalData.MemInfo.KzLength;

    // dump out HV zone ranges + layout
    LOG("VA map for NAPOCA follows...\n");
    LOG("%018p - %018p - %10.3f MB  (KZ)\n",
        gHypervisorGlobalData.MemInfo.KzBase, gHypervisorGlobalData.MemInfo.KzBase + gHypervisorGlobalData.MemInfo.KzLength - 1,
        (double)gHypervisorGlobalData.MemInfo.KzLength / (double)ONE_MEGABYTE);
    LOG("%018p - %018p - %10.3f MB  (PP)\n",
        gHypervisorGlobalData.MemInfo.PpBase, gHypervisorGlobalData.MemInfo.PpBase + gHypervisorGlobalData.MemInfo.PpLength - 1,
        (double)gHypervisorGlobalData.MemInfo.PpLength / (double)ONE_MEGABYTE);
}


 /// @brief  Determines the number of host system CPU cores (or threads in the case of HT) based on ACPI tables.
 ///
 /// @retval  CX_STATUS_SUCCESS                     Function succeeded to retrieve the number of processors available
 /// @retval  CX_STATUS_INVALID_COMPONENT_STATE     AcpiGetTable method failed to retrieve MADT table
static
NTSTATUS
_Phase1DetermineAvailableProcessors(
    void
    )
{
    ACPI_STATUS acpiStatus;
    ACPI_TABLE_MADT* madt;

    // For more information check ACPI Specification Version 6.2, chapter 5.2.12 "Multiple APIC Description Table (MADT)"
    acpiStatus = AcpiGetTable(ACPI_SIG_MADT, 0, (ACPI_TABLE_HEADER**)&madt);
    if (!ACPI_SUCCESS(acpiStatus))
    {
        ERROR("AcpiGetTable for MADT failed, acpiStatus=0x%08x\n", acpiStatus);
        return CX_STATUS_INVALID_COMPONENT_STATE;
    }

    // According to ACPI Specification Version 6.2: 'Immediately after the Flags value in the MADT
    // is a list of interrupt controller structures that declare the interrupt features of the machine.'
    // It might be useful to check ACPI_SUBTABLE_HEADER also.
    ACPI_SUBTABLE_HEADER* subHead = (PVOID)(madt + 1);            // MADT + 44 bytes

    // Parse the list of interrupt controller structures, taking into consideration only Local APIC Entries.
    // Each local APIC entry determines a physical thread of the CPU.
    while ((QWORD)subHead < ((QWORD)madt + madt->Header.Length))
    {
        if (subHead->Type == ACPI_MADT_TYPE_LOCAL_APIC)
        {
            ACPI_MADT_LOCAL_APIC* cpu = (ACPI_MADT_LOCAL_APIC*)(PVOID)subHead;

            // If the current LAPIC is signaled as enabled by the firmware and it is not the BSP's,
            // initialize a CpuMap entry for it.
            if ((cpu->LapicFlags & ACPI_MADT_ENABLED) &&
                gBootInfo->CpuMap[0].Id != cpu->Id) // The BSP is always the first entry in the CpuMap list.
            {
                gBootInfo->CpuMap[gBootInfo->CpuCount].LocalApicBase = madt->Address;
                gBootInfo->CpuMap[gBootInfo->CpuCount].Topology.IsBsp = 0;
                gBootInfo->CpuMap[gBootInfo->CpuCount].Id = cpu->Id;
                gBootInfo->CpuCount++;
            }
        }
        // go to the next ACPI subtable
        subHead = (PVOID)((QWORD)subHead + subHead->Length);
    }

    gHypervisorGlobalData.CpuData.CpuCount = gBootInfo->CpuCount;
    LOG("CPU COUNT = %d\n", gBootInfo->CpuCount);

    return CX_STATUS_SUCCESS;
}



CX_STATUS
FinalAllocPagingStructureCallback(
    _In_ TAS_DESCRIPTOR *Mapping,
    _In_ CX_UINT8 TableDepth,
    _Out_ MEM_ALIGNED_VA *Va,
    _Out_ MEM_ALIGNED_PA *Pa
)
{
    UNREFERENCED_PARAMETER(TableDepth); // PAE paging uses 4K paging structures at all levels

    BYTE buf[SINGLE_ENTRY_MDL_SIZE];
    MDL *mdl = (MDL*)buf;
    MdlInit(mdl, sizeof(buf));

    NTSTATUS status = PpAlloc(mdl, 1, (PP_OPTIONS) { 0 }, (PP_ALLOCATOR) { .Type = PP_ALLOCATOR_BY_TYPE, .Value = { .ByType = PP_ALLOCATOR_DEFAULT } }, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("PpAlloc", status);
        goto cleanup;
    }

    *Pa = (MEM_ALIGNED_PA)(PAGE_BASE_4K(mdl->Entry[0].BaseAddress));

    // use the identity mapping for the allocated page
    status = Mapping->GetTableVa(*Pa, Va);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Mapping->GetTableVa", status);
        goto cleanup;
    }

cleanup:
    return status;
}




CX_STATUS
FinalFreePagingStructureCallback(
    _In_ TAS_DESCRIPTOR *Mapping,
    _In_ MEM_ALIGNED_VA Va,
    _In_ MEM_ALIGNED_PA Pa
)
{
    UNREFERENCED_PARAMETER((Mapping, Va));
    BYTE buf[SINGLE_ENTRY_MDL_SIZE];
    MDL *mdl = (MDL*)buf;
    MdlInit(mdl, sizeof(buf));
    NTSTATUS status = MdlAddRange(mdl, PAGE_BASE_PA(Pa), PAGE_SIZE);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MdlAddRange", status);
        goto cleanup;
    }

    status = PpFree(mdl);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("PpFree", status);
        goto cleanup;
    }

    // the VA:PA mapping itself is left unchanged because this VA is part of
    // the 1:1 static mapping of the page-pool, mapping that must be kept intact

cleanup:
    return status;
}



CX_STATUS
FinalAllocVaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA *Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER(Mm);
    VAMGR_ALLOCATOR_ID allocator = VAMGR_MAXFREE_ALLOCATOR;
    if (AllocatorId) allocator.Raw = AllocatorId;

    CX_STATUS status = VaMgrAllocPages(NumberOfPages, Va, CX_NULL, allocator, Tag);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("VaMgrAllocPages", status);
        goto cleanup;
    }
cleanup:
    return status;
}


CX_STATUS
FinalFreeVaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA *Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, NumberOfPages, AllocatorId));
    return VaMgrFreePages(Va, Tag, CX_NULL);
}


/// @brief Final callback used for allocating physical pages, using final page pool
static
CX_STATUS
_FinalAllocatePaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _Out_ MDL *Mdl,
    _Out_ MM_ALIGNED_PA *Pa,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _In_ CX_BOOL Continuous,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, Pa, Tag)); // we're only capable of continuous memory allocations at boot-time

    if (!AllocatorId) AllocatorId = PP_ALLOCATOR_MAXFREE;

    VOID *dummy;

    PP_OPTIONS options = { .AcceptIncompleteAllocation = 1 };
    options.Continuos = !!Continuous;

    PP_ALLOCATOR allocator;
    allocator.Raw = AllocatorId;

    NTSTATUS status = PpAlloc(Mdl, NumberOfPages, options, allocator, &dummy);
    if (!SUCCESS(status))
    {
        ///LOG_FUNC_FAIL("PpAlloc", status); // don't log as at least STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW is an expected 'error'
        goto cleanup;
    }

cleanup:
    return status;
}


/// @brief Final callback used for freeing physical pages, using final page pool
static
CX_STATUS
_FinalFreePaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _In_ MDL *Mdl,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, AllocatorId, Tag));
    return PpFree(Mdl);
}

/// @brief Set up the virtual address space
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the space is set up
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1SetupVirtualAddressSpace(
    VOID
)
{
    NTSTATUS status;

    if (BOOT_OPT_VGA_MEM)
    {
        status = MmMap(&gHvMm, (MM_UNALIGNED_VA)(1 * PAGE_SIZE), 1 * PAGE_SIZE, NULL, NULL, 0, NULL, (ONE_MEGABYTE - PAGE_SIZE), TAG_FIRST_MEGA, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmMap", status);
            goto cleanup;
        }
        LOG("legacy VGA identity map successfully done\n");
    }

    // prepare TAS properties for creating a relocated image of the physical pages used for quick PA2VA transformations
    // note: some addresses might have already been populated and we need to accept their presence
    TAS_PROPERTIES set;
    status = MmGetAllocationTasProperties(gTasMapSetProps, MM_RIGHTS_RW, MM_CACHING_WB, &set);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmGetAllocationTasProperties", status);
        goto cleanup;
    }
    TAS_PROPERTIES lack = gTasMapLackProps;
    lack.InUse = 0; // allow the new mapping to overwrite any pre-existing mappings

    QWORD currentBase = (QWORD)gHypervisorGlobalData.MemInfo.KzBase;
    for (DWORD i = 0; i < gBootInfo->HvMemMap->HvZoneCount; i++)
    {
        LOG("Mapping %p -> %p: %lld\n", currentBase, gBootInfo->HvMemMap->Entries[i].StartAddress, gBootInfo->HvMemMap->Entries[i].Length);
        status = MmMap(&gHvMm, (MM_UNALIGNED_VA)currentBase, gBootInfo->HvMemMap->Entries[i].StartAddress, NULL, NULL, 0, NULL, gBootInfo->HvMemMap->Entries[i].Length, TAG_PAGEPOOL, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, NULL, NULL);
        if (!SUCCESS(status))
        {
            ERROR("MmMap[%d]: %s for %p %lld\n", i, NtStatusToString(status), currentBase, gBootInfo->HvMemMap->Entries[i].Length);
            goto cleanup;
        }

        MEM_UNALIGNED_VA va;
        status = gHvMm.Tas->GetTableVa(gBootInfo->HvMemMap->Entries[i].StartAddress, &va);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("gHvMm->Tas->GetTableVa", status);
            goto cleanup;
        }

        // create a relocated image of the physical pages used for quick PA2VA calculation for the paging structures
        LOG("        %p -> %p: %lld\n", va, gBootInfo->HvMemMap->Entries[i].StartAddress, gBootInfo->HvMemMap->Entries[i].Length);
        status = TasMapRangeEx(&gHva, va, gBootInfo->HvMemMap->Entries[i].Length, set, gTasMapClearProps, gTasMapHaveProps, lack, (MEM_ALIGNED_PA)gBootInfo->HvMemMap->Entries[i].StartAddress, NULL);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("TasMapRangeEx", status);
            goto cleanup;
        }

        currentBase += ROUND_UP(gBootInfo->HvMemMap->Entries[i].Length, PAGE_SIZE);
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    return status;
}




/// @brief Initializes the most important memory maps that describe the host system:
///
///   gHypervisorGlobalData.PhysMap        - MMAP describing the physical memory chunks of the host system
///   gHypervisorGlobalData.HyperMap       - MMAP describing the physical memory chunks reserved for the hypervisor
///   gHypervisorGlobalData.GuestAreaMap   - MMAP describing the physical memory chunks reserved for the guest VMs (except the primary guest, which
///                        gets the memory roughly like PhysMap - HyperMap - GuestAreaMap
/// These maps are based on the maps from gBootInfo, processed in #_Phase1GetPhysicalMemoryMap and #_Phase1GetHvZoneMemoryMap.
///
/// @returns    CX_STATUS_SUCCESS                   - Always
static
NTSTATUS
_Phase1InitializeMemoryMaps(
    void
)
{
    // setup memory maps to point directly to gBootInfo boot memory entries
    gHypervisorGlobalData.MemInfo.PhysMap.MaxCount = gBootInfo->PhyMemCount;
    gHypervisorGlobalData.MemInfo.PhysMap.Count = gHypervisorGlobalData.MemInfo.PhysMap.MaxCount;
    gHypervisorGlobalData.MemInfo.PhysMap.Entry = gBootInfo->PhyMemMap;

    gHypervisorGlobalData.MemInfo.HyperMap.MaxCount = gBootInfo->HvMemMap->HvZoneCount - gBootInfo->HvMemMap->GuestZoneCount;
    gHypervisorGlobalData.MemInfo.HyperMap.Count = gHypervisorGlobalData.MemInfo.HyperMap.MaxCount;
    gHypervisorGlobalData.MemInfo.HyperMap.Entry = gBootInfo->HvMemMap->Entries;

    gHypervisorGlobalData.MemInfo.GuestAreaMap.MaxCount = gBootInfo->HvMemMap->GuestZoneCount;
    gHypervisorGlobalData.MemInfo.GuestAreaMap.Count = gHypervisorGlobalData.MemInfo.GuestAreaMap.MaxCount;
    gHypervisorGlobalData.MemInfo.GuestAreaMap.Entry = &(gBootInfo->HvMemMap->Entries[gHypervisorGlobalData.MemInfo.HyperMap.Count]);

    // also initialize DEST addresses
    for (DWORD i = 0; i < gHypervisorGlobalData.MemInfo.PhysMap.Count; i++)
    {
        gHypervisorGlobalData.MemInfo.PhysMap.Entry[i].DestAddress = 0;
    }

    QWORD base = NAPOCA_KERNEL_BASE;
    for (DWORD i = 0; i < gHypervisorGlobalData.MemInfo.HyperMap.Count; i++)
    {
        gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].DestAddress = base;
        base += gHypervisorGlobalData.MemInfo.HyperMap.Entry[i].Length;
    }

    // for GuestAreaMap we use 1:1 mapping here
    for (DWORD i = 0; i < gHypervisorGlobalData.MemInfo.GuestAreaMap.Count; i++)
    {
        gHypervisorGlobalData.MemInfo.GuestAreaMap.Entry[i].DestAddress = 0;
    }

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nHOST SYSTEM physical memory maps follow...\n");
        MmapDump(&gHypervisorGlobalData.MemInfo.PhysMap, BOOT_MEM_TYPE_AVAILABLE, "gHypervisorGlobalData.PhysMap, ");
        MmapDump(&gHypervisorGlobalData.MemInfo.HyperMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "gHypervisorGlobalData.HyperMap, ");
        MmapDump(&gHypervisorGlobalData.MemInfo.GuestAreaMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "gHypervisorGlobalData.GuestAreaMap, ");
    }

    // everything done just fine
    return CX_STATUS_SUCCESS;
}



/// @brief Initializes the PP (HPA space), VA (HVA space) and HEAP memory allocators to be used by the hypervisor.
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went well, the allocators are initialized
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1InitMemoryAllocators(
    void
)
{
    NTSTATUS status;

    PpPreinitAllocator(gHypervisorGlobalData.MemInfo.PpBase, NULL);
    HpPreinit();
    VaMgrPreinitAllocator();
    FmPreinit();

    // Page-pool initialization (it doesn't depend on other components)
    status = PpInitAllocator(gHypervisorGlobalData.MemInfo.PpLength,
                             gHypervisorGlobalData.CpuData.MaxParallel,
                             &gHypervisorGlobalData.MemInfo.PerPpaPageCount);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("PpInitAllocator", status);
        goto cleanup;
    }

    // TAS with the final page-pool allocator
    gHva.AllocPagingStructure = FinalAllocPagingStructureCallback;
    gHva.FreePagingStructure = FinalFreePagingStructureCallback;

    // Set the memory manager to use the final page-pool (and use the boot VA allocator still)
    status = MmInitDescriptor(&gHva, IniBootAllocVaCallback, NULL, IniBootFreeVaCallback, NULL, _FinalAllocatePaCallback, NULL, _FinalFreePaCallback, NULL, &gHvMm);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmInitDescriptor", status);
        goto cleanup;
    }

    // Allocate and init the heap allocators (it needs the memory manager API -- which uses the final page-pool already)
    status = HpInitHeap(HpDefault);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpInitHeap", status);
        goto cleanup;
    }

    // Init the final VA allocator (it requires heap support)
    status = VaMgrInitAllocator();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("VaMgrInitAllocator", status);
        goto cleanup;
    }

    // Final memory management (requires final page-pool, VA allocators and heap)
    status = MmInitDescriptor(&gHva, FinalAllocVaCallback, NULL, FinalFreeVaCallback, NULL, _FinalAllocatePaCallback, NULL, _FinalFreePaCallback, NULL, &gHvMm);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmInitDescriptor", status);
        goto cleanup;
    }

    LOG("Final allocators are now active!\n");

    // Fast map
    status = FmInit();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("FmInit", status);
        goto cleanup;
    }


#ifdef DEBUG
    PpDumpAllocStats();
    HpDumpHeapAllocStats();
    VaMgrDumpVaAllocStats();
    FmDumpStats(0);
#endif

cleanup:

    return status;
}



/// @brief Allocate and initialize the PCPU structure for a given physical CPU
///
/// @param[in]  PcpuIndex       Index of the physical cpu
/// @param[in]  LapicId         Local ACIC ID of the CPU
/// @param[out] Cpu             The allocated and pre-initialized PCPU structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, PCPU is pre-initialized
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1CreateCpuStructure(
    _In_ DWORD PcpuIndex,
    _In_ DWORD LapicId,
    _Out_ PCPU** Cpu
)
{
    NTSTATUS status;
    PCPU *cpu;
    CPU_ENTRY *pCpuEntry = &gBootInfo->CpuMap[0];

    status = MmAllocMem(&gHvMm, sizeof(PCPU), TAG_CPU, &cpu);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMem", status);
        return status;
    }

    MmRegisterVaInfo(cpu, sizeof(PCPU), "PCPU[%d]", PcpuIndex);

    // initialize basic PCPU fields
    memzero(cpu, sizeof(PCPU));
    cpu->Self = cpu;
    cpu->VmxActivated = 0;
    cpu->Id = LapicId;
    cpu->BootInfoIndex = PcpuIndex;
    cpu->Affinity = 1ULL << PcpuIndex;

    cpu->StartTsc = 0;
    cpu->IsIntel = gHypervisorGlobalData.CpuData.IsIntel;
    cpu->Vcpu = NULL;
    cpu->VmxOnPa = 0;
    cpu->HasRepGranularityBug = (pCpuEntry->FamilyFields.Family == 0x6 && pCpuEntry->FamilyFields.Model == 0xD &&
                                 pCpuEntry->FamilyFields.ExtendedModel == 0x4);
    *Cpu = cpu;

    return status;
}



NTSTATUS
Phase1SetupCpuIpcQueue(
    _In_ PCPU* Cpu
)
{
    NTSTATUS status;
    for (DWORD i = 0; i < IPC_PRIORITY_TOTAL_DISTINCT_LEVELS; i++)
    {
        DWORD queueBufferSize = CX_LLQUEUE_STORAGE_REQUREMENT(gCpuIpcQueueProperties[i].NumberOfEntries, sizeof(IPC_MESSAGE));

        if (!gHypervisorGlobalData.BootFlags.IsWakeup)
        {
            if (Cpu->Ipc.Queue[i].Initialized) continue;

            status = HpAllocWithTagAndInfoAligned(&Cpu->Ipc.Queue[i].QueueBuffer, queueBufferSize, 0, TAG_IPC, PAGE_SIZE);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("HpAllocWithTagAndInfoAligned", status);
                return status;
            }
        }

        status = CxLlQueueInitialize(&Cpu->Ipc.Queue[i].Queue, gCpuIpcQueueProperties[i].NumberOfEntries, sizeof(IPC_MESSAGE), Cpu->Ipc.Queue[i].QueueBuffer, queueBufferSize);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("CxLlQueueInitialize", status);
            return status;
        }

        Cpu->Ipc.Queue[i].Initialized = TRUE;
        Cpu->Ipc.Queue[i].Priority = (BYTE)i;
        Cpu->Ipc.Queue[i].Enabled = TRUE;
        Cpu->Ipc.Queue[i].CustomQueueConsumerRoutine = gCpuIpcQueueProperties[i].CustomConsumer;
        Cpu->Ipc.QueueIsBeingDrained = FALSE;

        LOG("IPC QUEUE[%d][%d] initialized: %d entries -> %p custom handler!\n", Cpu->BootInfoIndex, i, gCpuIpcQueueProperties[i].NumberOfEntries, Cpu->Ipc.Queue[i].CustomQueueConsumerRoutine);
    }

    return CX_STATUS_SUCCESS;
}


/// @brief Allocates and initializes the PCPU structures for each physical CPU from the system, including in-HV,
/// NMI and double fault stacks and so on. Also initializes per-PCPU and global VMX-root vs VMX-non-root stat counters.
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, initializations are done successfully
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1InitializePhysicalCpuDataStructures(
    CX_VOID
)
{
    NTSTATUS status;

    for (DWORD i = 0; i < gBootInfo->CpuCount; i++)
    {
        CPU_ENTRY *bootCpu = &gBootInfo->CpuMap[i];
        PCPU* cpu;

        // CPU structure
        status = _Phase1CreateCpuStructure(i, bootCpu->Id, &cpu);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_Phase1CreateCpuStructure", status);
            goto cleanup;
        }
        gCpuPointersArray[i] = cpu;

        LOG("PCPU for LAPIC ID %d at %018p\n", bootCpu->Id, cpu);

        gHypervisorGlobalData.CpuData.Cpu[i] = cpu; // set the global PCPU pointer corresponding to current index, to this CPU structure

        if (i == 0) InitCpuSmxFeatures(bootCpu, &cpu->SmxCapabilities);

        // IDT & GDT & TSS memory
        status = MmAllocMemEx(&gHvMm, sizeof(NAPOCA_IDT_GDT_TSS), TAG_PIGT, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.IdtGdtTss), CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            goto cleanup;
        }
        MmRegisterVaInfo(cpu->MemoryResources.IdtGdtTss, sizeof(NAPOCA_IDT_GDT_TSS), "IdtGdtTss[%d]", i);

        // Stack
        status = MmAllocMemEx(&gHvMm, NAPOCA_CPU_STACK_SIZE, TAG_STACK, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.Stack), CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            goto cleanup;
        }
        MmRegisterVaInfo(cpu->MemoryResources.Stack, NAPOCA_CPU_STACK_SIZE, "Stack[%d]", i);

        // IMPORTANT: reserve at TOS 0x20 more bytes for home registers
        cpu->TopOfStack = ((QWORD)cpu->MemoryResources.Stack + NAPOCA_CPU_STACK_SIZE - 0x20);

        // Double-Fault stack
        status = MmAllocMemEx(&gHvMm, NAPOCA_CPU_DBF_STACK_SIZE, TAG_DBF_STACK, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.DfStack), CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            goto cleanup;
        }
        MmRegisterVaInfo(cpu->MemoryResources.DfStack, NAPOCA_CPU_DBF_STACK_SIZE, "DfStack[%d]", i);

        // NMI stack
        if (NAPOCA_USE_DISTINCT_NMI_STACK)
        {
            status = MmAllocMemEx(&gHvMm, NAPOCA_CPU_NMI_STACK_SIZE, TAG_NMI_STACK, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.NmiStack), CX_NULL);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmAllocMemEx", status);
                goto cleanup;
            }
            MmRegisterVaInfo(cpu->MemoryResources.NmiStack, NAPOCA_CPU_NMI_STACK_SIZE, "NmiStack[%d]", i);
        }

        // Machine-Check stack
        status = MmAllocMemEx(&gHvMm, NAPOCA_CPU_MC_STACK_SIZE, TAG_MC_STACK, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.McStack), CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            goto cleanup;
        }
        MmRegisterVaInfo(cpu->MemoryResources.McStack, NAPOCA_CPU_MC_STACK_SIZE, "McStack[%d]", i);

        // VMXON region (structure)
        status = MmAllocMemEx(&gHvMm, NAPOCA_CPU_VMX_ON_SIZE, TAG_VMXON, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_BOTH, &(cpu->MemoryResources.VmxonRegion), &cpu->VmxOnPa);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMemEx", status);
            goto cleanup;
        }
        MmRegisterVaInfo(cpu->MemoryResources.VmxonRegion, NAPOCA_CPU_MC_STACK_SIZE, "VmxonRegion[%d]", i);

        // IPC queue
        status = Phase1SetupCpuIpcQueue(cpu);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("Phase1SetupCpuIpcQueue", status);
            goto cleanup;
        }
    } // for-each-PCPU

    gCpuIpcQueuesAllocated = TRUE;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/// @brief Switch to the final cpu stack
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the switch was successful
/// @returns    CX_STATUS_DATA_NOT_READY            - CPU is not yet ready
/// @returns    CX_STATUS_DATA_NOT_FOUND            - Boot context data not found
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1SwitchToFinalCpuStack(
    void
)
{
    NTSTATUS status;
    IO_PER_CPU_DATA *perCpuData;
    PCPU* cpu = _Phase1GetCurrentCpu();
    QWORD tos;
    QWORD rsp = CpuGetRSP();
    QWORD delta, newRsp;

    if (!cpu) return CX_STATUS_DATA_NOT_READY;;

    // for wakeup, we were running with the final stack right from IniInit64
    if (gHypervisorGlobalData.BootFlags.IsWakeup)
    {
        tos = cpu->TopOfStack + 0x20;
        goto do_copy;
    }

    // for boot modes where the HV starts the APs, only the BSP has a loader stack, the other CPUs were started with final stacks
    if (!BOOT_OPT_MULTIPROCESSOR)
    {
        if (CpuIsCurrentCpuTheBsp())
        {
            // retrieve the BootContext structure of this CPU
            status = IoGetPerCpuData(&perCpuData);
            if (SUCCESS(status) && perCpuData && perCpuData->BootContext)
            {
                tos = perCpuData->BootContext->OriginalStackTop;
                goto do_copy;
            }
            return CX_STATUS_DATA_NOT_FOUND;
        }

        tos = cpu->TopOfStack + 0x20;
        goto do_copy;
    }

    // retrieve the BootContext structure of this CPU
    status = IoGetPerCpuData(&perCpuData);
    if (SUCCESS(status) && perCpuData && perCpuData->BootContext) tos = perCpuData->BootContext->OriginalStackTop;
    else return CX_STATUS_DATA_NOT_FOUND;

do_copy:
    delta = tos - rsp;
    newRsp = cpu->TopOfStack + 0x20 - delta;

    // copy the old stack content to the new stack
    __invlpg((PVOID)newRsp);
    memcpy((PVOID)newRsp, (PVOID)rsp, delta);

    // switch BSP to new stack
    CpuSetRSP(newRsp);

    status = GsUtilsNotifyStackChange((PVOID)tos, (PVOID)(cpu->TopOfStack + 0x20), (DWORD)delta);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GsUtilsNotifyStackChange", status);
        return status;
    }

    return CX_STATUS_SUCCESS;
}



NTSTATUS
Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu(
    VOID
)
{
    NTSTATUS status;
    VOID *idt, *gdt, *tss;
    PCPU* cpu = _Phase1GetCurrentCpu();
    if (!cpu) return CX_STATUS_DATA_NOT_READY;

    idt = cpu->MemoryResources.IdtGdtTss->Idt;
    gdt = cpu->MemoryResources.IdtGdtTss->Gdt;
    tss = cpu->MemoryResources.IdtGdtTss->Tss;

    status = HvLoadGdtTssIdtGs(gdt, tss, idt, (QWORD)cpu);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HvLoadGdtTssIdtGs", status);
        goto cleanup;
    }

cleanup:

    return status;
}

NTSTATUS
Phase1InitExceptionHandling(
    void
)
{
    NTSTATUS status;

    // Initialize the global IPI & NMI Locks
    HvInitSpinLock(&gFreezeCpusLock, "gFreezeCpusLock", NULL);
    HvInitSpinLock(&gVmxOffLock, "gVmxOffLock", NULL);
    HvInitSpinLock(&gNmiPrintLock, "gNmiPrintLock", NULL);

    // setup GDT, TSS, IDT tables *for all CPUs*
    for (DWORD i = 0; i < gBootInfo->CpuCount; i++)
    {
        PCPU *cpu = HvGetCpu(i);
        if (!cpu) return CX_STATUS_DATA_NOT_READY;

        PVOID idt, gdt, tss;

        idt = cpu->MemoryResources.IdtGdtTss->Idt;
        gdt = cpu->MemoryResources.IdtGdtTss->Gdt;
        tss = cpu->MemoryResources.IdtGdtTss->Tss;

        // save the IDT in PCPU (will be needed for external interrupt handling)
        gHypervisorGlobalData.CpuData.Cpu[i]->IdtBase = idt;

        status = HvInitGdtTssIdt(cpu);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HvInitGdtTssIdt", status);
            goto cleanup;
        }
    }

    // load GDT/TSS/IDT on the physical CPU; we are right now on BSP (PcpuIndex == 0), but this
    // must be run also on each physical AP processor
    status = Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu", status);
        goto cleanup;
    }

cleanup:

    return status;
}


/// @brief Preinitialize the gBootState structure, used to store the x86 arch context for the VCPUs of the guest.
///
/// @returns    CX_STATUS_SUCCESS                   - Always
static
NTSTATUS
_Phase1PreinitCapturedBootStates(
    void
)
{
    // initialize VMCS BOOT STATE entries
    if (BOOT_OPT_BIOS_ENVIRONMENT)
    {
        gBootState->NumberOfInitializedEntries = 0;

        // mark all entries as uninitialized
        for (DWORD k = 0; k < CPUSTATE_MAX_GUEST_CPU_COUNT; k++)
        {
            gBootState->BootVcpuState[k].IsStructureInitialized = FALSE;
        }
    }

    // everything done just fine
    return CX_STATUS_SUCCESS;
}



NTSTATUS
Phase1WakeupAllApProcessorsAndThemIntoPhase1(
    void
)
{
    NTSTATUS status;

    if (!gHypervisorGlobalData.BootFlags.IsWakeup)
    {
        // we do NOT need to wakeup CPUs if all cpus were already used before starting the HV
        if (!BOOT_OPT_MULTIPROCESSOR)
        {
            status = IpiWakeupAllApProcessors(FALSE);
            if (!NT_SUCCESS(status))
            {
                LOG_FUNC_FAIL("IpiWakeupAllApProcessors", status);
                return status;
            }
        }
    }
    else
    {
        status = IpiWakeupAllApProcessors(TRUE);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("IpiWakeupAllApProcessors", status);
            return status;
        }
    }

    return CX_STATUS_SUCCESS;
}



/// @brief Scan/initialize PCI controller(s) and power management related data based on the ACPI tables
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected
/// @returns    CX_STATUS_INVALID_DATA_VALUE        - Something went wrong with the ACPI tables
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_Phase1ScanAcpiAndDetectDevices(
    void
)
{
    NTSTATUS status;
    ACPI_STATUS acpiStatus;

    ACPI_TABLE_MCFG* mcfg;
    ACPI_TABLE_FADT* fadt;
    ACPI_TABLE_FACS* facs;

    // get the MCFG table - for PCI / PCI Express host controllers with MMIO space
    acpiStatus = AcpiGetTable(ACPI_SIG_MCFG, 0, (ACPI_TABLE_HEADER**)&mcfg);
    if (!ACPI_SUCCESS(acpiStatus))
    {
        ERROR("AcpiGetTable for MCFG failed, acpiStatus=0x%08x\n", acpiStatus);
        return CX_STATUS_INVALID_DATA_VALUE;
    }

    acpiStatus = AcpiGetTable(ACPI_SIG_FADT, 0, (ACPI_TABLE_HEADER**)&fadt);
    if (!ACPI_SUCCESS(acpiStatus))
    {
        ERROR("AcpiGetTable for FADT failed, acpiStatus=0x%08x\n", acpiStatus);
        return CX_STATUS_INVALID_DATA_VALUE;
    }

    PwrInitAcpiSleepStates();

    if (fadt->Facs || fadt->XFacs)
    {
        if (!(fadt->Facs) && fadt->XFacs)
        {
            WARNING("This system has a XFacs address but not a FACS address, we do not support this \n");
            facs = NULL;
            // we could drop this limitation by using XFacs if we didn't have to support 32 bit guests
        }

        // according to ACPI 4.0 FACS address is 64 bit aligned
        if (fadt->Facs & 0x3full)
        {
            WARNING("FACS HPA 0x%x is not 64 bit aligned \n", fadt->Facs);
            facs = NULL;
        }

        PVOID facsVa = NULL;
        status = MmMapMem(&gHvMm, CX_PAGE_BASE_4K(fadt->Facs), PAGE_SIZE, TAG_FACS, &facsVa);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmMapMem", status);
            facs = NULL;
        }
        else facs = (ACPI_TABLE_FACS*)((PBYTE)facsVa + PAGE_OFFSET(fadt->Facs));
    }
    else facs = NULL;

    gHypervisorGlobalData.AcpiData.Mcfg = mcfg;
    gHypervisorGlobalData.AcpiData.Fadt = fadt;
    gHypervisorGlobalData.AcpiData.Facs = facs;

    LOG("ACPI tables: MCFG %p, FADt %p, FACS %p\n",
        gHypervisorGlobalData.AcpiData.Mcfg,
        gHypervisorGlobalData.AcpiData.Fadt,
        gHypervisorGlobalData.AcpiData.Facs);

    // parse MCFG table
    DWORD entryCount;
    ACPI_MCFG_ALLOCATION* entry;

    entryCount = (mcfg->Header.Length - 44) / 16;

    if (entryCount == 0)
    {
        ERROR("ACPI MCFG table with 0 entries\n");
        return CX_STATUS_INVALID_DATA_VALUE;
    }

    entry = (ACPI_MCFG_ALLOCATION*)(((PBYTE)mcfg) + 44);

    for (DWORD i = 0; i < entryCount; i++, entry++)
    {
        status = PciConfigAddControllerToHost(gHypervisorGlobalData.Pci, entry->Address, entry->PciSegment, entry->StartBusNumber, entry->EndBusNumber);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("PciConfigAddControllerToHost", status);
            goto cleanup;
        }

        LOG("[ACPI] found PCI host controller BASE %018p,  PCI segment %d  BUS %d -> %d\n",
            entry->Address, entry->PciSegment, entry->StartBusNumber, entry->EndBusNumber);
    }

    // get info from FADT and FACS tables (for Power Management)
    {
        if (fadt == NULL || facs == NULL)
        {
            ERROR("Power management not possible without FADT and FACS!\n");
            goto skip_pm_init;
        }

        // we need to validate that
        // - we ARE in ACPI mode, ACPI is enabled (PM1Control.SCI_EN)
        // - we are NOT running on a HW-reduced system (FADT.Flags.HW_REDUCED_ACPI)
        // - we do NOT support S4BIOS (FACS.Flags.S4BIOS_F)
        // - we DO support 64 bit wake (FACS.Flags.64BIT_WAKE_SUPPORTED_F)

        LOG("ACPI Revision 0x%x \n", fadt->Header.Revision);
        if (fadt->Header.Length < 244)          // 244 bytes in ACPI 2.0, 3.0, 4.0, 268 bytes in ACPI 5.0
        {
            LOG("ACPI.FADT.Length %d < 244, no x64 fields, we will stop here\n", fadt->Header.Length);
            goto skip_pm_init;
        }

        if (fadt->Flags & ACPI_FADT_HW_REDUCED)
        {
            LOG("ACPI.FADT.Flags.HW_REDUCED_ACPI == 1, we will stop here\n");
            goto skip_pm_init;
        }

        // if we are running on low - power S0 capable system(FADT.Flags.LOW_POWER_S0_IDLE_CAPABLE)
        if (fadt->Flags & ACPI_FADT_LOW_POWER_S0)
        {
            LOG("[ACPI] FADT.Flags.ACPI_FADT_LOW_POWER_S0 == 1\n");
        }

        if (facs->Flags & ACPI_FACS_S4_BIOS_PRESENT)
        {
            LOG("ACPI.FACS.Flags.S4BIOS_F == 1, we will stop here\n");
            goto skip_pm_init;
        }

        // initialize POWER MANAGEMENT specific data structures
        status = PwrInitDataStructsPhase1(fadt, facs);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("PwrInitDataStructsPhase1", status);
            goto skip_pm_init;
        }
    }

skip_pm_init:

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


/// @brief Callback used for marking the PCI devices that we want to hide
static
NTSTATUS
_MarkPciDevicesHiddenFromPrimaryGuestCallback(
    _In_ PCI_FUNC* PciFunction,
    _In_opt_ PCI_FUNC* Parent,
    _In_opt_ VOID* Context
)
{
    NTSTATUS status;
    PCI_CONFIG* cfg = PciFunction->Config;

    if (CfgDebugOutputSerialEnabled && cfg->Header.VendorID == SERIAL_MCS9900_VENDOR_ID && cfg->Header.DeviceID == SERIAL_MCS9900_DEVICE_ID)
    {
        PCICFG_ID pciId = { .Segment = 0, .Bus = (WORD)PciFunction->BusNumber, .Device = (WORD)PciFunction->DevNumber, .Function = (WORD)PciFunction->FuncNumber };
        status = PciAddPciCfgToHiddenList(pciId);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("PciAddPciCfgToHiddenList", status);
            return status;
        }
        else
        {
            LOG("[HIDE] Device reserved for debugging on PCI bus %d device %d func %d, %s\n",
                pciId.Bus, pciId.Device, pciId.Function, PciDeviceToString(cfg->Header.VendorID, cfg->Header.DeviceID));
        }

        BOOLEAN* isParentBridgeAlreadyHidden = Context;
        if (!*isParentBridgeAlreadyHidden)
        {
            pciId.Segment = 0;
            pciId.Bus = Parent->BusNumber;
            pciId.Device = Parent->DevNumber;
            pciId.Function = Parent->FuncNumber;

            status = PciAddPciCfgToHiddenList(pciId);
            if (!NT_SUCCESS(status))
            {
                LOG_FUNC_FAIL("PciAddPciCfgToHiddenList", status);
                return status;
            }
            else
            {
                LOG("[HIDE] Device(bridge) reserved for debugging on PCI bus %d device %d func %d, %s\n",
                    pciId.Bus, pciId.Device, pciId.Function, PciDeviceToString(cfg->Header.VendorID, cfg->Header.DeviceID));
            }

            *isParentBridgeAlreadyHidden = TRUE;
        }
    }

    return CX_STATUS_SUCCESS;
}

/// @brief Mark the relevant PCI devices for hiding
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, devices were marked
/// @returns    OTHER                               - Other internal errors from #PciWalkFunctions
static
NTSTATUS
_Phase1MarkPciDevicesHiddenFromPrimaryGuest(
    VOID
)
{
    BOOLEAN bridgeAlreadyHiddenForSerial = FALSE;
    return PciWalkFunctions(_MarkPciDevicesHiddenFromPrimaryGuestCallback, &bridgeAlreadyHiddenForSerial);
}

void
Phase1InitializePerCpuFxRestoration(
    void
)
{
    int cpuidRegs[4];
    PCPU* pcr;
    BOOLEAN useFxRestoration = FALSE;

    pcr = HvGetCurrentCpu();

    // check if CPU supports XSAVE/etc
    __cpuid(cpuidRegs, 1);
    if (cpuidRegs[2] & CPUID_01_ECX_FLAG_XSAVE)
    {
        // check if CPUID leaf 0xD is available
        __cpuid(cpuidRegs, 0);
        if (cpuidRegs[0] >= 0xD) useFxRestoration = TRUE;
        else WARNING("CPU supports FXSAVE/etc but can not be used because CPUID is limited by firmware.\n");
    }

    if (useFxRestoration)
    {
        pcr->UseXsave = TRUE;

        // determine the available bits in XCR0 by doing a CPUID with leaf 0xD
        // see Table 3-17. Information Returned by CPUID Instruction (Contd.) leaf 0xD

        __writecr4(__readcr4() | CR4_OSXSAVE);

        __cpuidex(cpuidRegs, 0xD, 0x0);

        //
        //Leaf 0DH main leaf (ECX = 0).
        //  EAX Bits 31-00: Reports the valid bit fields of the lower 32 bits of XCR0. If
        //  a bit is 0, the corresponding bit field in XCR0 is reserved.
        //  Bit 00: legacy x87
        //  Bit 01: 128-bit SSE
        //  Bit 02: 256-bit AVX
        //  Bits 31- 03: Reserved
        //
        //  EBX Bits 31-00: Maximum size (bytes, from the beginning of the
        //  XSAVE/XRSTOR save area) required by enabled features in XCR0. May
        //  be different than ECX if some features at the end of the XSAVE save
        //  area are not enabled.
        //
        //  ECX Bit 31-00: Maximum size (bytes, from the beginning of the
        //  XSAVE/XRSTOR save area) of the XSAVE/XRSTOR save area required
        //  by all supported features in the processor, i.e all the valid bit fields in
        //  XCR0.
        //
        //  EDX Bit 31-00: Reports the valid bit fields of the upper 32 bits of XCR0. If a
        //  bit is 0, the corresponding bit field in XCR0 is reserved.
        //

        pcr->Xcr0AvailMaskLow   = cpuidRegs[0]; // EAX
        pcr->Xcr0AvailMaskHigh  = cpuidRegs[3]; // EDX

        // ECX - the maximum size of all supported features - assume the worst + 64 required for alignment
        // the ROUND_UP is required because we use STOSQ in assembly to zero memory area
        pcr->FpuSaveSize = ROUND_UP(cpuidRegs[2], sizeof(QWORD)) + 64;
        pcr->StartupXCR0 = __xgetbv(0);

        LOG("[%u] -> Will use XSAVE / XRSTOR for FPU, FpuSaveSize = %d bytes, XCR0AvailLow = 0x%08x, XCR0AvailHigh = 0x%08x XCR0 = %p\n",
            pcr->BootInfoIndex, pcr->FpuSaveSize, pcr->Xcr0AvailMaskLow, pcr->Xcr0AvailMaskHigh, pcr->StartupXCR0);

        // set into XCR0 all the supported features
        __xsetbv(0, pcr->Xcr0AvailMask);

        // now check if we have XSAVEOPT
        __cpuidex(cpuidRegs, 0xD, 0x1);

        pcr->UseXsaveopt = cpuidRegs[0] & 1;
    }
    else
    {
        pcr->UseXsave = FALSE;
        pcr->UseXsaveopt = FALSE;

        // default size for FXSAVE / FXRSTOR + 64 required for alignment
        pcr->FpuSaveSize = 512 + 64;

        LOG("[%u] -> Will use FXSAVE / FXRSTOR for FPU, FpuSaveSize = %d bytes\n",
              pcr->BootInfoIndex, pcr->FpuSaveSize, pcr->Xcr0AvailMaskLow, pcr->Xcr0AvailMaskHigh);
    }

    pcr->HostMxcsr = _mm_getcsr();
}



NTSTATUS
Phase1InitializePerCpuVmxOnZone(
    void
)
{
    QWORD temp;

    // turn on IA32_FEATURE_CONTROL.bit2 if needed, check out Intel Vol 3B, "Table B-2. IA-32 Architectural MSRs"
    temp = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(temp & 0x4)) // VMX outside of SMX
    {
        if (temp & 0x1) // lock bit is set, we can't change it anymore
        {
            ERROR("Can't set IA32_FEATURE_CONTROL, bit 0 is already locked. Enable Virtualization Support from BIOS(?) \n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }

        LOG("[CPU %d] MSR 0x3A = 0x%016zx... ", HvGetCurrentApicId(), temp);
        __writemsr(MSR_IA32_FEATURE_CONTROL, temp | 0x4);
        LOG("[CPU %d] MSR 0x3A = 0x%016zx\n", HvGetCurrentApicId(), __readmsr(0x3A));
    }

    // IA32_FEATURE_CONTROL.Bit 0 is a lock bit. If the lock bit is clear, an attempt to execute VMXON will cause
    //  a general-protection exception
    temp = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(temp & 1)) __writemsr(MSR_IA32_FEATURE_CONTROL, temp | 1);

    // setup VMXON structure; check out Intel Vol 3B, Appendix G.1, "Basic VMX information",
    // Vol 3B, 21.2, "Format of the VMCS region" and also Vol 3B, 21.10.5, "VMXON region"
    temp = __readmsr(MSR_IA32_VMX_BASIC);       // IA32_VMX_BASIC_MSR

    // set VMCS revision number
    *(PDWORD)(HvGetCurrentCpu()->MemoryResources.VmxonRegion) = (DWORD)temp;

    // execute VMXON
    LOG("[CPU %d] will try to do VMXON on PA %018p / VA %018p\n", HvGetCurrentApicId(), HvGetCurrentCpu()->VmxOnPa, HvGetCurrentCpu()->MemoryResources.VmxonRegion);

    // effectively do VMX_ON
    BYTE ret = CpuPerformVmxon(HvGetCurrentCpu());
    if (ret != 0)
    {
        ERROR("__vmx_on failed, return = %d\n", ret);
        return CX_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = CLN_REGISTER_SELF_HANDLER(_CpuVmxCleanupCallback, NULL, NULL);
    if (!_SUCCESS(status)) LOG_FUNC_FAIL("CLN_REGISTER_SELF_HANDLER", status);

    return CX_STATUS_SUCCESS;
}

/// @brief Context structure passed for the TSC synchronizing IPI
typedef struct _HV_SYNC_TSC_CONTEXT
{
    QWORD TotalCpuCount;                 ///< Total CPU count
    volatile QWORD SyncCpuCount;         ///< Synchronized cpu count before setting the TSC
    QWORD TscValue;                      ///< TSC value
    QWORD CpuNewTsc[BOOT_MAX_CPU_COUNT]; ///< New TSC value
    volatile QWORD DoneSyncCpuCount;     ///< Synchronized cpu count after setting the TSC
}HV_SYNC_TSC_CONTEXT;


/// @brief Callback for the TSC synchronizing IPI
static
NTSTATUS
_Phase1SyncPhysicalCpuTscIpiHandler(
    _In_ PVOID Context,
    _In_ HV_TRAP_FRAME* TrapFrame
)
{
    UNREFERENCED_PARAMETER(TrapFrame);

    HV_SYNC_TSC_CONTEXT* ctx = (HV_SYNC_TSC_CONTEXT*)Context;
    QWORD newTsc;
    register QWORD targetTsc = ctx->TscValue;
    register QWORD totalCpuCount = ctx->TotalCpuCount;

    HvInterlockedIncrementU64(&ctx->SyncCpuCount);

    while (totalCpuCount != ctx->SyncCpuCount)
    {
        ;
    }

    __writemsr(MSR_IA32_TSC, targetTsc);

    newTsc = __readmsr(MSR_IA32_TSC);

    ctx->CpuNewTsc[HvGetCurrentCpuIndex()] = newTsc;

    HvInterlockedIncrementU64(&ctx->DoneSyncCpuCount);

    return CX_STATUS_SUCCESS;
}


/// @brief Synchronize the TSCs on every CPU (as close as possible)
///
/// @returns    CX_STATUS_SUCCESS                     - All good, TSCs are synchronized
/// @returns    OTHER                                 - Other internal errors
static
NTSTATUS
_Phase1SyncPhysicalCpuTsc(
    _In_ QWORD Tsc
)
{
    NTSTATUS status;
    HV_SYNC_TSC_CONTEXT ctx = { 0 };
    IPC_INTERRUPTIBILITY_STATE intState = IpcSetInterruptibilityValues(
        TRUE, IPC_INTERRUPTS_ENABLED,
        TRUE, TRUE,
        TRUE, IPC_PRIORITY_IPI);

    ctx.TotalCpuCount = gHypervisorGlobalData.CpuData.CpuCount;
    ctx.TscValue = Tsc;
    ctx.DoneSyncCpuCount = 0;

    LOG("Synchronizing TSC on %d physical cpus with value %p\n", ctx.TotalCpuCount, ctx.TscValue);

    status = IntSendIpcMessage(_Phase1SyncPhysicalCpuTscIpiHandler, &ctx, AFFINITY_ALL_EXCLUDING_SELF, FALSE);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("IntSendIpcMessage", status);

    _Phase1SyncPhysicalCpuTscIpiHandler(&ctx, NULL);

    while (ctx.DoneSyncCpuCount != ctx.TotalCpuCount)
    {
        ;
    }

    for (DWORD i = 0; i < ctx.TotalCpuCount; i++)
    {
        LOG("Cpu with index %d has TSC: %p\n", i, ctx.CpuNewTsc[i]);
    }

    IpcSetInterruptibilityState(intState);

    return status;
}



#define ACPI_MAX_INIT_TABLES        64                              ///< Maximum number of ACPI tables
static ACPI_TABLE_DESC gAcpiTableArray[ACPI_MAX_INIT_TABLES] = {0}; ///< List of the ACPI tables

/// @brief Initialize ACPI related system state
///
/// @returns    CX_STATUS_SUCCESS                     - Everything went as expected
/// @returns    STATUS_ACPI_FATAL                     - An ACPI error occurred
/// @returns    OTHER                                 - Other internal errors
static
NTSTATUS
_Phase1InitializeFullAcpi(void)
{
    ACPI_STATUS acpiStatus;
    UINT32 acpiFlags;

    // Initialize the ACPICA subsystem
    acpiStatus = AcpiInitializeSubsystem();
    if (ACPI_FAILURE(acpiStatus))
    {
        ERROR("AcpiInitializeSubsystem failed with %s!\n", AcpiFormatException(acpiStatus));
        goto cleanup;
    }

    // Initialize the ACPICA Table Manager and get all ACPI tables
    acpiStatus = AcpiInitializeTables(gAcpiTableArray, ACPI_MAX_INIT_TABLES, FALSE);
    if (ACPI_FAILURE(acpiStatus))
    {
        ERROR("AcpiInitializeTables failed with %s!\n", AcpiFormatException(acpiStatus));
        goto cleanup;
    }

    // Create the ACPI namespace from ACPI tables
    acpiStatus = AcpiLoadTables();
    if (ACPI_FAILURE(acpiStatus))
    {
        ERROR("AcpiLoadTables failed with %s!\n", AcpiFormatException(acpiStatus));
        goto cleanup;
    }

    // Note: Local handlers should be installed here

    // Initialize the ACPI hardware
    acpiFlags = 0
        //| ACPI_FULL_INITIALIZATION
        //| ACPI_NO_ADDRESS_SPACE_INIT
        | ACPI_NO_HANDLER_INIT
        | ACPI_NO_ACPI_ENABLE
        ;
    acpiStatus = AcpiEnableSubsystem(acpiFlags);
    if (ACPI_FAILURE(acpiStatus))
    {
        ERROR("AcpiEnableSubsystem failed with %s!\n", AcpiFormatException(acpiStatus));
        goto cleanup;
    }

    acpiFlags = 0
        //| ACPI_FULL_INITIALIZATION
        //| ACPI_NO_ADDRESS_SPACE_INIT
        | ACPI_NO_EVENT_INIT
        | ACPI_NO_DEVICE_INIT
        //| ACPI_NO_OBJECT_INIT
        ;
    /* Complete the ACPI namespace object initialization */
    acpiStatus = AcpiInitializeObjects(acpiFlags);
    if (ACPI_FAILURE(acpiStatus))
    {
        ERROR("AcpiInitializeObjects failed with %s!\n", AcpiFormatException(acpiStatus));
        goto cleanup;
    }

cleanup:
    if (ACPI_FAILURE(acpiStatus)) return STATUS_ACPI_FATAL;
    else return CX_STATUS_SUCCESS;
}


NTSTATUS
Phase1BspStageOne(
    void
)
{
    NTSTATUS status;

    IoSetPerCpuPhase(IO_CPU_PHASE1);

    IoVgaSetBanner(STRINGIFY_VER(" Napoca ", NAPOCA_VERSION_MAJOR, NAPOCA_VERSION_MINOR, NAPOCA_VERSION_REVISION, NAPOCA_VERSION_BUILDNUMBER), "");

    status = _Phase1InitBspAndValidateFeatures();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1InitBspAndValidateFeatures", status);
        CpuPrintCpuidFeatures(&gBootInfo->CpuMap[0]);
        goto cleanup;
    }

    CpuPrintMiscFeatures(&gBootInfo->CpuMap[0]);

    Phase1InitializeHostControlRegisters();

    status = _Phase1SetupInitialExceptionHandlingForBsp();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1SetupInitialExceptionHandlingForBsp", status);
        goto cleanup;
    }

    status = MtrrBuildState(&gHypervisorGlobalData.MemInfo.MtrrState);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MtrrBuildState", status);
        goto cleanup;
    }

    status = _Phase1GetPhysicalMemoryMap();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1GetPhysicalMemoryMap", status);
        goto cleanup;
    }

    status = _Phase1GetHvZoneMemoryMap();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1GetHvZoneMemoryMap", status);
        goto cleanup;
    }

    _Phase1DetermineKzSmPfnPpZoneSizes();

    status = _Phase1SetupVirtualAddressSpace();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1SetupVirtualAddressSpace", status);
        goto cleanup;
    }

    gHypervisorGlobalData.CpuData.MaxParallel = NAPOCA_MAX_PARALLELIZATION;
    status = _Phase1InitMemoryAllocators();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1InitMemoryAllocators", status);
        goto cleanup;
    }

    // first initialization of ACPICA with temporary mappings
    status = _Phase1InitializeFullAcpi();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1InitializeFullAcpi", status);
        goto cleanup;
    }

    status = _Phase1DetermineAvailableProcessors();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1DetermineAvailableProcessors", status);
        goto cleanup;
    }

    //
    // Up to this point the hypervisor only used pre-allocated (protected) memory
    //

    status = _Phase1InitializeMemoryMaps();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1InitializeMemoryMaps", status);
        goto cleanup;
    }

    status = HpAllocWithTagCore((PVOID*)&gCpuPointersArray, sizeof(PCPU*) * gBootInfo->CpuCount, TAG_CPU);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        goto cleanup;
    }

    status = _Phase1InitializePhysicalCpuDataStructures();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1InitializePhysicalCpuDataStructures", status);
        goto cleanup;
    }

    status = _Phase1SwitchToFinalCpuStack();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1SwitchToFinalCpuStack", status);
        goto cleanup;
    }
    gHypervisorGlobalData.BootProgress.StageFinalMappings = TRUE;

    status = LapicInit();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LapicInit", status);
        goto cleanup;
    }

    //
    // for the Sleep Wakeup case this was done earlier
    //
    status = Phase1InitExceptionHandling();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1InitExceptionHandling", status);
        goto cleanup;
    }

    status = DbgInit();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("DbgInit", status);
        goto cleanup;
    }

    status = _Phase1PreinitCapturedBootStates();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1PreinitCapturedBootStates", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(5);

    status = Phase1WakeupAllApProcessorsAndThemIntoPhase1();
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1WakeupAllApProcessorsAndThemIntoPhase1", status);
        goto cleanup;
    }

    if (gNeedToUnload)
    {
        status = STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
        goto cleanup;
    }
    IoVgaSetLoadProgress(10);


    //
    // perform all system scanning and device / resource related stuffs
    //

    status = PciPreinitSystemPci(&gHypervisorGlobalData.Pci);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("PciPreinitSystemPci", status);
        goto cleanup;
    }

    status = _Phase1ScanAcpiAndDetectDevices();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1ScanAcpiAndDetectDevices", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(20);

    status = _Phase1MarkPciDevicesHiddenFromPrimaryGuest();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1MarkPciDevicesHiddenFromPrimaryGuest", status);
        goto cleanup;
    }

    LOG("***** LOAD RESOURCES FROM ACPI ***** \n");

    status = DevresLoadMemoryResourcesAcpi();
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("DevresLoadMemoryResourcesAcpi", status);
        return status;
    }

    IoVgaSetLoadProgress(25);

    // initialize FXSAVE / XSAVE settings for the current PCPU
    Phase1InitializePerCpuFxRestoration();

    IoVgaSetLoadProgress(30);

    //
    // execute PHASE I on all AP processors
    //
    status = Phase1TriggerAPsToStartAndWaitForCompletion();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1TriggerAPsToStartAndWaitForCompletion", status);
        goto cleanup;
    }

    // sync TSCs
    _Phase1SyncPhysicalCpuTsc(__rdtsc());

    // turn ON VMX mode
    status = Phase1InitializePerCpuVmxOnZone();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1InitializePerCpuVmxOnZone", status);
        goto cleanup;
    }

    IoVgaSetLoadProgress(35);

    // everything done successfully
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

NTSTATUS
Phase1ApStageOne(
    void
)
{
    NTSTATUS status;

    IoSetPerCpuPhase(IO_CPU_PHASE1);

    Phase1InitializeHostControlRegisters();

    // setup GDT, TSS, IDT
    status = Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu", status);
        goto cleanup;
    }

    status = _Phase1SwitchToFinalCpuStack();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_Phase1SwitchToFinalCpuStack", status);
        goto cleanup;
    }

    Phase1InitializePerCpuFxRestoration();

    // turn ON VMX mode
    status = Phase1InitializePerCpuVmxOnZone();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1InitializePerCpuVmxOnZone", status);
        goto cleanup;
    }

cleanup:

    return status;
}



NTSTATUS
Phase1TriggerAPsToStartAndWaitForCompletion(
    void
)
{
    LOG("[BSP] wait for all (%d) APs to finish their STAGE I initialization...\n", CPU_COUNT_TO_WAIT);

    // trigger APs to perform STAGE I init, then
    // wait for all AP processors to signal that they are up & running in 1T x64 mode, IDT, stack, etc setup done, ready for APIC takeover
    gStageOneInitedCpuCount = 1;            // BSP
    gStageOneCanProceedOnAps = TRUE;

    while ((gStageOneInitedCpuCount < CPU_COUNT_TO_WAIT) && (!gNeedToUnload))
    {
        CpuYield();
    }
    if (gNeedToUnload) return STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;

    LOG("[BSP] received STAGE I init completion signal from all %d AP processors\n", CPU_COUNT_TO_WAIT - 1);

#ifdef DEBUG
        for (DWORD i = 0; i < gStageOneInitedCpuCount; i++)
        {
            HvPrint("CPU_MAP[%d] - ", i);
            if (i == 0) CpuPrintMiscFeatures(&gBootInfo->CpuMap[i]);
            else CpuPrintLocalApic(&gBootInfo->CpuMap[i]);
        }
#endif

    return CX_STATUS_SUCCESS;
}

/// @}
