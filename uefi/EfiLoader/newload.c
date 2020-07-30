/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//#define X64
#include "uefi_internal.h"
#include "newload.h"
#include "common/boot/loader_interface.h"
#include "pedefs.h"
#include "IndustryStandard/Acpi30.h"
#include "Guid/acpi.h"
#include "common/kernel/cpu_state.h"
#include "hvefi.h"
#include "dacia_types.h"
#include "FileOperationsLib/FileOperationsLib.h"

#define MIN_ACCEPTED_HV_VERSION 1

#define UEFI_HVMEM_ENTRIES  16
#define UEFI_SYSMEM_ENTRIES 512
EFI_GUID gBdHvGuid = HVSEC_BDHV_GUID;

LD_MEM_BUFFER UefiMemBuffer = {0};
LD_VA_MAPPER UefiVaMapper = {0};
LD_NAPOCA_MODULE UefiModules[LD_MAX_MODULES] = {0};
LD_LOADER_CUSTOM *UefiCustom = NULL;

LD_HVMEMORY_MAP *UefiHvMemoryMap = NULL;
DWORD UefiHvMemoryMapEntries = 0;

LD_MEMORY_MAP *UefiSystemMemoryMap = NULL;
DWORD UefiSystemMemoryMapEntries = 0;

UINT8 *gHvLogPhysicalAddress = NULL;
UINT32 gHvLogSize = 0;

EFI_GUID  gEfiAcpiTableGuid = EFI_ACPI_TABLE_GUID;
EFI_GUID  gEfiAcpi10TableGuid = ACPI_10_TABLE_GUID;
EFI_GUID  gEfiAcpi20TableGuid = EFI_ACPI_20_TABLE_GUID;
EFI_GUID  gEfiAcpi30TableGuid = EFI_ACPI_TABLE_GUID; ///ACPI 2.0 or newer tables should use EFI_ACPI_TABLE_GUID


VOID
EFIAPI
DummyNotifyMe(
    IN  EFI_EVENT                       Event,
    IN  VOID                            *Context
    );

typedef struct _UEFI_HIBERNATE_BUFFER
{
    PVOID PhysicalAddress;
    QWORD Size;
}UEFI_HIBERNATE_BUFFER, * PUEFI_HIBERNATE_BUFFER;

static UEFI_HIBERNATE_BUFFER gHibernateBuffer;

extern BYTE UefiToHypervisorTrampoline64End;

extern HV_FEEDBACK_HEADER *HvFeedback;

NTSTATUS
UefiSetAndMapModule(
    LD_VA_MAPPER *VaMapper,
    LD_NAPOCA_MODULE *Modules,
    DWORD NumberOfModules,
    QWORD *Cr3,
    QWORD Va,
    QWORD Pa,
    DWORD NumberOfBytes,
    DWORD ModuleId
    )
{
    NTSTATUS status;

    if ((NULL == VaMapper) || (NULL == Modules) || (0 == NumberOfModules) || (NULL == Cr3))
    {
      status = CX_STATUS_INVALID_PARAMETER;
      goto cleanup;
    }

    status = LD_MAP_RANGE(VaMapper, Va, Pa, NumberOfBytes, 3, Cr3, 4);
    if (!SUCCESS(status))
    {
      ERR_NT("LD_MAP_RANGE", status);
      goto cleanup;
    }

    status = LdSetModule(Modules, NumberOfModules, ModuleId, Va, Pa, NumberOfBytes, LD_MODFLAG_PERMANENT);
    if (!SUCCESS(status))
    {
      ERR_NT("LdSetModule", status);
      goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

#pragma warning( push )
#pragma warning( disable: 4047 )
#pragma warning( disable: 4024 )
EFI_STATUS
UefiAllocHibernateBuffer(
    IN UINTN Size
)
{
    EFI_STATUS status;

    gHibernateBuffer.Size = Size;
    gHibernateBuffer.PhysicalAddress = NULL;

    // Allocate a NVS area for storing data that should be persistent over a hibernate
    status = UefiBootServices->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS, (Size + PAGE_SIZE - 1) / PAGE_SIZE, &gHibernateBuffer.PhysicalAddress);
    if (EFI_ERROR(status))
    {
        ERR("UefiBootServices->AllocatePool", status);
        return status;
    }

    return EFI_SUCCESS;
}
#pragma warning( pop )

#define PER_CPU_STACK_SIZE (32 * CX_KILO)
#pragma pack(push, 1)


typedef struct _HV_PER_CPU_STACK
{
    BYTE Stack[PER_CPU_STACK_SIZE];
}HV_PER_CPU_STACK, *PHV_PER_CPU_STACK;

HV_PER_CPU_STACK            *HvPerCpuStacks;
CPUSTATE_BOOT_GUEST_STATE   *HvPerCpuStates;
LD_BOOT_CONTEXT             *HvPerCpuBootContexts;

// parameter type for waking up processors
typedef struct _AP_DATA
{
    LD_BOOT_CONTEXT *BootContext;
    QWORD HvEntryPoint;
    QWORD Cr3;
}AP_DATA, *PAP_DATA;

typedef struct _TRAMPOLINE_DATA // keep in synch with vasetup.nasm definition
{
    QWORD           ApicId;
    QWORD           Cr3;
    QWORD           StackTop;
    QWORD           BootContextPa;
    QWORD           HvEntryPointVa;
    QWORD           CpuBootStateVa;
}TRAMPOLINE_DATA, *PTRAMPOLINE_DATA;
#pragma pack(pop)

volatile DWORD gNumberOfCpusPrepared = 0;
volatile DWORD NumberOfVirtualizedCpus = 0;
volatile BOOLEAN UefiNeedToHijackBsp = TRUE;
volatile AP_DATA *UefiApData;
volatile BOOLEAN UefiBspHijacked;
volatile DWORD HvErrors = 0;

NTSTATUS
UefiToHypervisorTrampoline64(
    _In_ TRAMPOLINE_DATA *TrampolineData
    );


void AsmException(void);


void
EFIAPI
AllCpusProc(
    void *Buffer
    )
{
    DWORD index;
    QWORD stackTop;
    AP_DATA *data = (AP_DATA *)Buffer;
    TRAMPOLINE_DATA trampoline = {0};

    // assign a cpu entry
    index = UefiInterlockedIncrement(&gNumberOfCpusPrepared) - 1;
    UefiInterlockedIncrement(&(HvPerCpuStates->NumberOfInitializedEntries));

    // prepare a stack
    stackTop = (QWORD)&HvPerCpuStacks[index+1]; //((QWORD)&(HvPerCpuData[index].Stack)) + PER_CPU_STACK_SIZE; // stack top = next stack as the stack goes down

    // prepare a boot context
    CopyMem(&(HvPerCpuBootContexts[index]), data->BootContext, sizeof(LD_BOOT_CONTEXT));

    HvPerCpuBootContexts[index].BootMode = bootUefi;
    HvPerCpuBootContexts[index].Modules = UefiModules;
    HvPerCpuBootContexts[index].ModulesPa = (QWORD)(SIZE_T)UefiModules;
    HvPerCpuBootContexts[index].NumberOfModules = LD_MAX_MODULES;
    HvPerCpuBootContexts[index].OriginalStackTop = stackTop;
    HvPerCpuBootContexts[index].Cr3 = data->Cr3;


    trampoline.BootContextPa = (QWORD)&(HvPerCpuBootContexts[index]);
    trampoline.CpuBootStateVa = (QWORD)&(HvPerCpuStates->BootVcpuState[index]);
    trampoline.Cr3 = data->Cr3;
    trampoline.HvEntryPointVa = data->HvEntryPoint;
    trampoline.StackTop = stackTop;
    trampoline.ApicId = UefiGetLocalApicId();

    if (!CfgBypassHv)
    {
        NTSTATUS status;

        status = UefiToHypervisorTrampoline64(&trampoline);
        if (0 != status)
        {
            UefiInterlockedIncrement(&HvErrors);
        }
    }

#if (UEFI_TEST_EXCEPTIONS)
    if (!CfgBypassHv)
    {
        HV_PRINT(L"Exception!\n");
        AsmException();
        AsmHvBreak();
    }
#endif
    UefiInterlockedIncrement(&NumberOfVirtualizedCpus);
}



#pragma warning( push )
#pragma warning( disable: 4090 )
#pragma warning( disable: 4047 )
#pragma warning( disable: 4244 )
VOID
EFIAPI
NotifyBspHanged(
    IN  EFI_EVENT                       Event,
    IN  VOID                            *Context
    )
{
    if (UefiNeedToHijackBsp)
    {
        // this code is not interruptible by our main thread
        UefiNeedToHijackBsp = FALSE;
        UefiBspHijacked = TRUE;

        HV_PRINT(L"Trying to hijack the bsp!\n");

        AllCpusProc(UefiApData);
        HV_PRINT(L"Hijacked the BSP into HV with a timed trap...\n");
    }
}

// pass the MP table's physical address to the HV
VOID
UefiFindAndSaveMpConfigTableAddress(
    VOID
)
{
    EFI_GUID vMPS_TABLE_GUID = { 0xeb9d2d2f,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d };

    for (UINTN ii = 0; ii < UefiSystemTable->NumberOfTableEntries; ii++)
    {
        if (SAME_GUID(&UefiSystemTable->ConfigurationTable[ii].VendorGuid, &vMPS_TABLE_GUID))
        {
            TRACE(L"MP table: 0x%08llX\n", UefiSystemTable->ConfigurationTable[ii].VendorTable);
            UefiCustom->Uefi.MpPhysicalAddress = UefiSystemTable->ConfigurationTable[ii].VendorTable;
        }
    }
}


EFI_STATUS
UefiSetupModules(
    QWORD TempMemNumberOfBytes,
    QWORD *Cr3,
    QWORD NapocaBase,
    QWORD NapocaLength,
    QWORD NumberOfGuests
    )
{
    EFI_STATUS efiStatus;
    NTSTATUS ntStatus;
    EFI_PHYSICAL_ADDRESS efiBuffer;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    QWORD rsp;
    UINTN numberOfCpus;
    efiStatus = EFI_SUCCESS;

TRACE(L"Allocating memory for most of the loader modules...\n");
    // allocate memory for modules
    UefiSystemMemoryMap = (LD_MEMORY_MAP*) UefiAllocHv(LD_MEMORY_MAP_SIZE(UEFI_SYSMEM_ENTRIES), TRUE);
    if (NULL == UefiSystemMemoryMap)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }

    UefiHvMemoryMap = (LD_HVMEMORY_MAP *) UefiAllocHv(LD_HVMEMORY_MAP_SIZE(UEFI_HVMEM_ENTRIES), TRUE);
    if (NULL == UefiHvMemoryMap)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }
    UefiCustom = (LD_LOADER_CUSTOM *) UefiAllocHv(sizeof(LD_LOADER_CUSTOM), TRUE);
    if (NULL == UefiCustom)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }

    HvPerCpuStates = (CPUSTATE_BOOT_GUEST_STATE*) UefiAllocHv(sizeof(CPUSTATE_BOOT_GUEST_STATE), TRUE);
    if (NULL == HvPerCpuStates)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }

    gHvLogPhysicalAddress = (UINT8*) UefiAllocHv(HV_LOG_LENGTH, TRUE);
    if (NULL == gHvLogPhysicalAddress)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }
    gHvLogSize = HV_LOG_LENGTH;

    //
    // setup the memory buffer
    //
    efiBuffer = (EFI_PHYSICAL_ADDRESS)(SIZE_T)UefiAllocHv(TempMemNumberOfBytes, FALSE);
    if (0 == efiBuffer)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("AllocatePages", efiStatus);
        goto cleanup;
    }

    UefiMemBuffer.Pa = (QWORD)efiBuffer;
    UefiMemBuffer.Va = (QWORD)efiBuffer;
    UefiMemBuffer.NextFreeAddress = efiBuffer;
    UefiMemBuffer.Length = TempMemNumberOfBytes;

    UefiVaMapper.MemBuffer = &UefiMemBuffer;
    UefiVaMapper.Modules = UefiModules;
    UefiVaMapper.NumberOfModules = LD_MAX_MODULES;
//UEFI_LOG(L"Mapping the modules memory...\n");
    // map the modules memory region
    ntStatus = LD_MAP_RANGE(&UefiVaMapper, (QWORD)&UefiModules, (QWORD)&UefiModules, sizeof(LD_NAPOCA_MODULE)*LD_MAX_MODULES, 3, Cr3, 4);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        TRACE(L"uvm=%p, um=%p, sz=%d, cr3=%d\n", &UefiVaMapper, &UefiModules, sizeof(LD_NAPOCA_MODULE)*LD_MAX_MODULES, Cr3);
        ERR_NT("LD_MAP_RANGE", ntStatus);
        goto cleanup;
    }

    TRACE(L"Mapping the hv log range...");
    ntStatus = LD_MAP_RANGE(&UefiVaMapper, (QWORD)gHvLogPhysicalAddress, (QWORD)gHvLogPhysicalAddress, HV_LOG_LENGTH, 3, Cr3, 4);
    if (!SUCCESS(ntStatus))
    {
        ERR_NT("LD_MAP_RANGE", ntStatus);
        efiStatus = EFI_UNSUPPORTED;
        goto cleanup;
    }

    // register the static modules (the ones loaded from disk) except for napoca.bin which must be treated specially
    {
        DWORD i;
        PVOID ptr;
        for (i = 0; i < LD_MAX_MODULES; i++)
        {
            if ((i != LD_MODID_NAPOCA_IMAGE) && (UefiModules[i].Pa != 0) && (UefiModules[i].Size != 0))
            {
                // allocate a new buffer with the correct mem attributes
                ptr = UefiAllocHv(UefiModules[i].Size, FALSE);
                if (NULL == ptr)
                {
                    efiStatus = EFI_OUT_OF_RESOURCES;
                    ERR("UefiAllocHv", efiStatus);
                    goto cleanup;
                }
                // make the copy
                UefiBootServices->CopyMem(ptr, (PVOID)(SIZE_T)UefiModules[i].Pa, UefiModules[i].Size);

                // free the original one
                //FoUnloadFile((PVOID)(SIZE_T)UefiModules[i].Pa, UefiModules[i].Size);

                // map and finish any other preparations of this loader module
                ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                    (QWORD)(SIZE_T)ptr, (QWORD)(SIZE_T)ptr, (QWORD)(SIZE_T)UefiModules[i].Size, i);
                if (!SUCCESS(ntStatus))
                {
                    efiStatus = EFI_UNSUPPORTED;
                    ERR_NT("UefiSetAndMapModule", ntStatus);
                    goto cleanup;
                }
            }
        }
    }

TRACE(L"Registering the free memory range...\n");
    //
    // register the 'free memory' module
    //
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
      (QWORD)&UefiMemBuffer, (QWORD)&UefiMemBuffer, sizeof(LD_MEM_BUFFER), LD_MODID_FREE_MEMORY);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR_NT("UefiSetAndMapModule", ntStatus);
        goto cleanup;
    }

TRACE(L"Mapping the free memory region...\n");
    // map the free memory region
    ntStatus = LD_MAP_RANGE(&UefiVaMapper, efiBuffer, efiBuffer, TempMemNumberOfBytes, 3, Cr3, 4);
    if (!SUCCESS(ntStatus))
    {
        ERR_NT("LD_MAP_RANGE", ntStatus);
        efiStatus = EFI_UNSUPPORTED;
        goto cleanup;
    }

    {
        PVOID ptr;
        // allocate a new HV image of the right memory type
        ptr = UefiAllocHv(NapocaLength, FALSE);
        if (NULL == ptr)
        {
            efiStatus = EFI_OUT_OF_RESOURCES;
            ERR("UefiAllocHv", efiStatus);
            goto cleanup;
        }
        UefiBootServices->CopyMem(ptr, (PVOID)(SIZE_T)NapocaBase, NapocaLength);

        /// todo: free the original image
        NapocaBase = (QWORD)(SIZE_T)ptr;
    }

TRACE(L"Parsing and validating the napoca.bin PE image...\n");
    // map also to its imagebase
    dos = (IMAGE_DOS_HEADER *)NapocaBase;
    if ((dos->e_magic) != 'ZM')
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("mz", efiStatus);
        goto cleanup;
    }

    if ((dos->e_lfanew) > PAGE_SIZE)
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("pe", efiStatus);
        goto cleanup;
    }

    nt = (IMAGE_NT_HEADERS64 *)((BYTE*)NapocaBase + dos->e_lfanew);
    if (nt->Signature != 0x00004550)
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("signature", efiStatus);
        goto cleanup;
    }


TRACE(L"Registering and mapping the Napoca module...\n");
    //
    // register the actual napoca image
    //
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                                 (QWORD)nt->OptionalHeader.ImageBase, (QWORD)NapocaBase, (DWORD)NapocaLength, LD_MODID_NAPOCA_IMAGE);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }

    efiStatus = InternalGetCpuCount(&numberOfCpus);
    if (EFI_ERROR(efiStatus))
    {
        ERR("InternalGetCpuCount", efiStatus);
        goto cleanup;
    }

    HvPerCpuStacks = (HV_PER_CPU_STACK*)UefiAllocHv(numberOfCpus * sizeof(HV_PER_CPU_STACK), TRUE);
    if (NULL == HvPerCpuStacks)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }

TRACE(L"Registering and mapping the Napoca stacks module...\n");
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
        (QWORD)HvPerCpuStacks, (QWORD)HvPerCpuStacks, (DWORD)(numberOfCpus * sizeof(HV_PER_CPU_STACK)), LD_MODID_NAPOCA_STACK);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }

TRACE(L"Registering and mapping the Napoca boot Cpu contexts...\n");
    HvPerCpuBootContexts = (LD_BOOT_CONTEXT *)UefiAllocHv(numberOfCpus * sizeof(LD_BOOT_CONTEXT), TRUE);
    if (NULL == HvPerCpuBootContexts)
    {
        efiStatus = EFI_OUT_OF_RESOURCES;
        ERR("UefiAlloc", efiStatus);
        goto cleanup;
    }
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
        (QWORD)HvPerCpuBootContexts, (QWORD)HvPerCpuBootContexts, (DWORD)(numberOfCpus * sizeof(LD_BOOT_CONTEXT)), LD_MODID_BOOT_CONTEXT);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }

TRACE(L"Allocating the HV physical and memory pool...\n");
    //
    // prepare and register the memory maps (system and hv)
    //
    {
        EFI_MEMORY_DESCRIPTOR   *memoryMap, *memoryDescriptor;
        UINT64                  descriptorSize, numberOfMemoryDescriptors;
        UINT64                  totalSystemPhysicalMemory;
        QWORD                   estimatedHvLength;
        DWORD                   retries;
        QWORD                   pages, remaining;
        QWORD                   lastPagesTried, pos;
        EFI_PHYSICAL_ADDRESS    pa;

        UefiHvMemoryMap->Entries[0].StartAddress = NapocaBase;
        UefiHvMemoryMap->Entries[0].DestAddress = NapocaBase;
        UefiHvMemoryMap->Entries[0].Length = CX_ROUND_UP(NapocaLength, PAGE_SIZE);
        UefiHvMemoryMap->Entries[0].Type = BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED;
        UefiHvMemoryMapEntries++;

        // investigate the current system memory map to decide how much memory to reserve for the HV
        efiStatus = UefiGetMemoryMap(&memoryMap, &descriptorSize, &numberOfMemoryDescriptors, &totalSystemPhysicalMemory);
        if (EFI_ERROR(efiStatus))
        {
            TRACE(L"ERROR: Could not get the initial efi memory map!\r\n");
            goto cleanup;
        }

        ntStatus = LdEstimateRequiredHvMem(totalSystemPhysicalMemory, (DWORD)NumberOfGuests, NAPOCA_MEM_SHARED_BUFFER, &estimatedHvLength, NULL);
        if (!SUCCESS(ntStatus))
        {
            efiStatus = EFI_UNSUPPORTED;
            ERR("LdEstimateRequiredHvMem", efiStatus);
            goto cleanup;
        }

        // allocate all the memory needed by the HV
        pages = (estimatedHvLength+PAGE_SIZE) / PAGE_SIZE;
        remaining = pages;
        lastPagesTried = pages;
        retries = 0;

        do{
            efiStatus = UefiBootServices->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, pages, &pa);

            if (efiStatus == EFI_OUT_OF_RESOURCES)
            {
                pages = (pages * 2)/3;
                continue;
            }
            else if (EFI_ERROR(efiStatus))
            {
                TRACE(L"ERROR: InternalAllocateHvMemory failed with status = %S\r\n", UefiStatusToText(efiStatus));
                goto cleanup;
            }

            // got some memory, save an entry
            if (UefiHvMemoryMapEntries >= UEFI_HVMEM_ENTRIES)
            {
                efiStatus = EFI_BUFFER_TOO_SMALL;
                ERR("UefiHvMemoryMapEntries", efiStatus);
                goto cleanup;
            }

            UefiHvMemoryMap->Entries[UefiHvMemoryMapEntries].StartAddress = pa;
            UefiHvMemoryMap->Entries[UefiHvMemoryMapEntries].DestAddress = pa;
            UefiHvMemoryMap->Entries[UefiHvMemoryMapEntries].Length = PAGE_SIZE * pages;
            UefiHvMemoryMap->Entries[UefiHvMemoryMapEntries].Type = BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED;

            UefiHvMemoryMapEntries++;
            remaining -= pages; // pages <= remaining at first iteration and kept <= after

            if (pages > remaining)
            {
                pages = remaining;
            }
            retries++;
        }while ((retries < 20) && (remaining != 0));

        if (remaining != 0)
        {
            efiStatus = EFI_NOT_FOUND;
            ERR("remaining != 0", efiStatus);
            goto cleanup;
        }
        UefiHvMemoryMap->HvZoneCount = UefiHvMemoryMapEntries;
        UefiHvMemoryMap->TotalNumberOfEntries = UefiHvMemoryMapEntries;
TRACE(L"HvMemoryMap: entries=%d\n", UefiHvMemoryMapEntries);
        // free this map, it's useless now that we've allocated a lot of memory
        UefiBootServices->FreePool(memoryMap);
        memoryMap = NULL;


        // get an up-to-date efi system memory map
        efiStatus = UefiGetMemoryMap(&memoryMap, &descriptorSize, &numberOfMemoryDescriptors, NULL);
        if (EFI_ERROR(efiStatus))
        {
            TRACE(L"ERROR: Failed to get the efi memory map!\r\n");
            goto cleanup;
        }

        pos = 0;
        memoryDescriptor = memoryMap;
        UefiSystemMemoryMap->MapType = LD_MEMORY_MAP_TYPE_EFI;
        while (pos < (numberOfMemoryDescriptors * descriptorSize))
        {
            if (UefiSystemMemoryMapEntries >= UEFI_SYSMEM_ENTRIES)
            {
                efiStatus = EFI_BUFFER_TOO_SMALL;
                ERR("UefiSystemMemoryMapEntries >= UEFI_SYSMEM_ENTRIES", efiStatus);
                goto cleanup;
            }

            UefiSystemMemoryMap->Entries[UefiSystemMemoryMapEntries].BaseAddress = memoryDescriptor->PhysicalStart;
            UefiSystemMemoryMap->Entries[UefiSystemMemoryMapEntries].Length = PAGE_SIZE * memoryDescriptor->NumberOfPages;
            UefiSystemMemoryMap->Entries[UefiSystemMemoryMapEntries].Type.Efi = memoryDescriptor->Type;
            UefiSystemMemoryMap->Entries[UefiSystemMemoryMapEntries].Attributes = (DWORD)memoryDescriptor->Attribute; /// ?
// UEFI_LOG(L"MemMap[%d]: base=%p len=%p type=%p attr=%p\n", UefiSystemMemoryMapEntries,
//          memoryDescriptor->PhysicalStart,
//          PAGE_SIZE * memoryDescriptor->NumberOfPages,
//          memoryDescriptor->Type,
//          memoryDescriptor->Attribute);

            UefiSystemMemoryMapEntries++;
            pos += descriptorSize;
            memoryDescriptor = (EFI_MEMORY_DESCRIPTOR*) ((BYTE*)memoryDescriptor + descriptorSize);
        }

        UefiSystemMemoryMap->NumberOfEntries = UefiSystemMemoryMapEntries;

        UefiBootServices->FreePool(memoryMap);
        memoryMap = NULL;
    }
TRACE(L"UefiSystemMemoryMap: entries=%d\n", UefiSystemMemoryMapEntries);
TRACE(L"Registering and mapping the physical memory map module...\n");
    // map and register the LD_MODID_MEMORY_MAP
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                (QWORD)UefiSystemMemoryMap, (QWORD)UefiSystemMemoryMap, LD_MEMORY_MAP_SIZE(UEFI_SYSMEM_ENTRIES), LD_MODID_MEMORY_MAP);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }

TRACE(L"Registering and mapping the HV memory map module...\n");
    // map and register the LD_MODID_HVMEMORY_MAP
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                (QWORD)UefiHvMemoryMap, (QWORD)UefiHvMemoryMap, LD_HVMEMORY_MAP_SIZE(UEFI_HVMEM_ENTRIES), LD_MODID_HVMEMORY_MAP);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }

TRACE(L"Mapping the trampoline stack...\n");
    // map the napoca stack
    rsp = (UINT64) UefiGetRSP();
    rsp = CX_ROUND_UP(rsp, PAGE_SIZE);
    ntStatus = LD_MAP_RANGE(&UefiVaMapper, (QWORD)rsp - 128*CX_KILO, (QWORD)rsp - 128*CX_KILO, 128*CX_KILO,
        3, Cr3, 4);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("UefiSetAndMapModule", efiStatus);
        goto cleanup;
    }


    ntStatus = LD_MAP_RANGE(&UefiVaMapper, (QWORD)(SIZE_T)UefiToHypervisorTrampoline64, (QWORD)(SIZE_T)UefiToHypervisorTrampoline64,
      (QWORD)(SIZE_T)PTR_DELTA(&UefiToHypervisorTrampoline64End, (QWORD)(SIZE_T)UefiToHypervisorTrampoline64), 3, Cr3, 4);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR("LD_MAP_RANGE", efiStatus);
        goto cleanup;
    }

TRACE(L"Registering and mapping the 'loader-custom' module...\n");
    UefiCustom->Uefi.BootMode = bootUefi;

    UefiFindAndSaveMpConfigTableAddress();

    UefiCustom->Uefi.RSDPPhysicalAddress = 0;
    {
        UINTN i = 0;
        BOOLEAN found = FALSE;
        EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp = NULL;
        PVOID rsdpV1 = NULL;
        PVOID rsdpCurrent = NULL;

        //
        // Find ACPI table RSD_PTR from system table
        //

        // The OS loader for an ACPI - compatible OS will search for an RSDP structure pointer using the current revision GUID first and if it finds one,
        // will use the corresponding RSDP structure pointer.
        // If the GUID is not found then the OS loader will search for the RSDP structure pointer using the ACPI 1.0 version GUID

        found = FALSE;
        for (i = 0, rsdp = NULL; i < UefiSystemTable->NumberOfTableEntries; i++)
        {
            if (SAME_GUID(&(UefiSystemTable->ConfigurationTable[i].VendorGuid), &gEfiAcpiTableGuid))
            {
                rsdpCurrent = UefiSystemTable->ConfigurationTable[i].VendorTable;

                // optimize - do not search if both values are found
                if (rsdpV1)
                {
                    break;
                }
            }
            else if (SAME_GUID(&(UefiSystemTable->ConfigurationTable[i].VendorGuid), &gEfiAcpi10TableGuid))
            {
                rsdpV1 = UefiSystemTable->ConfigurationTable[i].VendorTable;

                // optimize - do not search if both values are found
                if (rsdpCurrent)
                {
                    break;
                }
            }
        }

        if (rsdpCurrent)
        {
            rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)rsdpCurrent;
        }
        else if (rsdpV1)
        {
            rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)rsdpV1;
        }

        if (rsdp)
        {
            found = TRUE;
        }

        if ((found) && (NULL != rsdp))
        {
            UefiCustom->Uefi.RSDPPhysicalAddress    = (QWORD)rsdp; //rsdp->RsdtAddress; //(EFI_ACPI_DESCRIPTION_HEADER *)
        }
    }

    UefiCustom->Uefi.HibernateNvsPhysicalAddress = gHibernateBuffer.PhysicalAddress;
    UefiCustom->Uefi.HibernateNvsSize = gHibernateBuffer.Size;

    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                (QWORD)UefiCustom, (QWORD)UefiCustom, sizeof(LD_UEFI_CUSTOM), LD_MODID_LOADER_CUSTOM);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR_NT("UefiSetAndMapModule", ntStatus);
        goto cleanup;
    }

    // Map the previously allocated memory area as a LD_MODID_NVS module; will be used to save/load hibernate data
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
        (QWORD)gHibernateBuffer.PhysicalAddress, (QWORD)UefiCustom->Uefi.HibernateNvsPhysicalAddress, UefiCustom->Uefi.HibernateNvsSize, LD_MODID_NVS);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR_NT("UefiSetAndMapModule", ntStatus);
        goto cleanup;
    }

TRACE(L"Registering and mapping the Napoca boot Cpu states module : %p...\n", (QWORD)sizeof(CPUSTATE_BOOT_GUEST_STATE));
    ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
        (QWORD)(HvPerCpuStates), (QWORD)(HvPerCpuStates), sizeof(CPUSTATE_BOOT_GUEST_STATE), LD_MODID_BOOT_STATE);
    if (!SUCCESS(ntStatus))
    {
        efiStatus = EFI_UNSUPPORTED;
        ERR_NT("UefiSetAndMapModule", ntStatus);
        goto cleanup;
    }


TRACE(L"Registering and mapping the Napoca feedback module\n");
    if (0 != CfgFeedbackBufferSize)
    {
        PVOID hvFeedback;
        hvFeedback = UefiAllocHv(CfgFeedbackBufferSize, TRUE);
        if (NULL != hvFeedback)
        {
            ntStatus = UefiSetAndMapModule(&UefiVaMapper, UefiModules, LD_MAX_MODULES, Cr3,
                (QWORD)(SIZE_T)(hvFeedback), (QWORD)(SIZE_T)(hvFeedback), (DWORD)CfgFeedbackBufferSize, LD_MODID_FEEDBACK);
            if (!SUCCESS(ntStatus))
            {
                efiStatus = EFI_UNSUPPORTED;
                ERR_NT("UefiSetAndMapModule", ntStatus);
                goto cleanup;
            }
            HvFeedback = (HV_FEEDBACK_HEADER*) hvFeedback;
        }
    }
    //
    // Last chance to bypass the HV on user behalf
    //
    if (CfgUserInterractionAllowKeyboardBypass)
    {
        UINTN safeGuard;
        safeGuard = 0; // make sure we don't wait forever (allow 15s at most)

TRACE(L"UefiBypassTimeout = %d\n", UefiBypassTimeout);
        while ((FALSE == UefiBypassTimeout) && (safeGuard < (15*SECOND_FROM_MICROSECOND)))
        {
            //LOG(L"[%p]", safeGuard);
            UefiBootServices->Stall(100*MILISECOND_FROM_MICROSECOND);
            safeGuard += 100*MILISECOND_FROM_MICROSECOND;
            if (EFI_ABORTED == UefiCheckUserHvBypass())
            {
                efiStatus = EFI_ABORTED;
                goto cleanup;
            }
        }

TRACE(L"UefiBypassTimeout=%d/(safeGuard < (15*ONE_SECOND))=%d - Checking keyboard buffer\n", UefiBypassTimeout, (safeGuard < (15*SECOND_FROM_MICROSECOND)));
    if (EFI_ABORTED == UefiCheckUserHvBypass())
    {
        efiStatus = EFI_ABORTED;
        goto cleanup;
    }

TRACE(L"UefiBypassTimeout=%d without abort!\n", UefiBypassTimeout);
    }
// UefiWaitKey();
// if (&UefiBypassTimeout)
// {
//     efiStatus = EFI_ABORTED;
//     //ONE_SECOND
//     goto cleanup;
// }

TRACE(L"Waking up any additional CPUs(%d) and entering the HV...\n", numberOfCpus - 1);
    {
        QWORD entryPoint = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
        LD_BOOT_CONTEXT ctx = {0};
        EFI_EVENT apEvent;
        EFI_EVENT bspHangedEvent;

        UefiApData = UefiAlloc(sizeof(AP_DATA));
        if (NULL == UefiApData)
        {
            efiStatus = EFI_OUT_OF_RESOURCES;
            goto cleanup;
        }

        // prepare an event used to signal the BSP when the APs finished their job (useless for us but needed by the API/firmware)
        efiStatus = UefiBootServices->CreateEvent(EVT_NOTIFY_WAIT, TPL_NOTIFY, DummyNotifyMe, NULL, &apEvent);
        if (EFI_ERROR(efiStatus))
        {
            TRACE(L"[bsp]CreateEvent failed with status = %S\r\n", UefiStatusToText(efiStatus));
            goto cleanup;
        }

        // prepare an event used to interrupt the BSP if it gets stuck in firmware code when waking-up the APs
        efiStatus = UefiBootServices->CreateEvent(EVT_TIMER|EVT_NOTIFY_SIGNAL, TPL_NOTIFY, NotifyBspHanged, NULL, &bspHangedEvent);
        if (EFI_ERROR(efiStatus))
        {
            TRACE(L"[bsp]CreateEvent failed with status = %S\r\n", UefiStatusToText(efiStatus));
            goto cleanup;
        }

        // setup a timed routine to hijack the BSP and enter the HV if the BSP is blocked
        efiStatus = UefiBootServices->SetTimer(bspHangedEvent, TimerRelative, 2 * SECOND_FROM_100_NANOSECOND);
        if (EFI_ERROR(efiStatus))
        {
            TRACE(L"[bsp]CreateEvent failed with status = %S\r\n", UefiStatusToText(efiStatus));
            goto cleanup;
        }

        ctx.BootMode = bootUefi;
        ctx.Modules = UefiModules;
        ctx.NumberOfModules = LD_MAX_MODULES;
        ctx.ModulesPa = (QWORD)(SIZE_T)&UefiModules;
        ctx.NumberOfLoaderCpus = (DWORD)numberOfCpus;

        UefiApData->BootContext = &ctx;
        UefiApData->Cr3 = *Cr3;
        UefiApData->HvEntryPoint = (QWORD)entryPoint;

        UefiVirtualized = !CfgBypassHv;
        efiStatus = InternalStartupAllApProcessors(AllCpusProc, UefiApData, apEvent);

        ///todo: check for RACE CONDITION (??)
        // make sure we don't allow the timed routine to hijack the BSP once we got here
        UefiNeedToHijackBsp = FALSE;
        if (EFI_ERROR(efiStatus))
        {
            ERR("InternalStartupAllApProcessors", efiStatus);
//             if (EFI_TIMEOUT != efiStatus)
//             {
//                 goto cleanup;
//             }
        }


        // make sure we didn't start the HV already by means of the timer handler hook
        if (!UefiBspHijacked)
        {
            AllCpusProc(UefiApData); // BSP enters the HV
        }

        /// todo: this might not be safe, we need to synch with the APs after they come back from the HV
        if (0 != HvErrors)
        {
            TRACE(L"HV didn't succeed and returned to loader\n");
            efiStatus = EFI_NOT_STARTED;
            UefiVirtualized = FALSE;
            goto cleanup;
        }
    }
    {
        int r[4];
        __cpuid(r, 1);
        UefiVirtualized = (r[2] < 0);
        TRACE(L"Done, back to UEFI, virtualized = %d (0x%08X), hijacked = %d\n", UefiVirtualized, r[2], UefiBspHijacked);
    }
    efiStatus = EFI_SUCCESS;

cleanup:
    return efiStatus;
}
#pragma warning( pop )




char* DaciaStatusToString(int Status, int ReturnNullIfUnknown);
char* CxNtStatusToString(int Status, int ReturnNullIfUnknown);
char* CxStatusToString(int Status, int ReturnNullIfUnknown);

char *
NtStatusToString(
    _In_ NTSTATUS Status
    )
{
    char *str = DaciaStatusToString(Status, 1);
    if (!str)
    {
        str = CxStatusToString(Status, 1);
    }
    if (!str)
    {
        str = CxNtStatusToString(Status, 0);
    }

    return "UNKNOWN NT STATUS\n";
}