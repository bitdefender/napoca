/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @file init64.c Common entry point for the hypervisor(from any boot loading method)

/// \defgroup hvinit Hypervisor boot and initialization
/// \defgroup phase0 Phase 0 - Boot of the hypervisor
/// \ingroup hvinit
/// @{

#include "napoca.h"
#include "boot/init64.h"
#include "boot/phase1.h"
#include "boot/phase2.h"
#include "kernel/kernel.h"
#include "kernel/newcore.h"
#include "version.h"
#include "common/debug/memlog.h"
#include "introspection/intromodule.h"
#include "introspection/introengine.h"
#include "guests/pci_tools.h"
#include "memory/hibernate.h"

extern TAS_DESCRIPTOR gHva;

BOOT_MODE gBootMode; ///< The boot mode of the hypervisor

CPUSTATE_BOOT_GUEST_STATE *gBootState; ///< x86/x64 CPU boot states (without FPU, SSE), including segments and interruptibility, used to initialize VCPUs for the guest
BOOT_INFO *gBootInfo = NULL; ///< The hypervisor's boot information (memory map, cpu map, ...)
LD_LOADER_CUSTOM *gLoaderCustom = NULL; ///< Boot mode dependent custom loader data for the hypervisor

HV_FEEDBACK_HEADER *gFeedback = NULL; ///< Pointer to HV's feedback header

volatile BOOLEAN gBasicInitDoneByBSP = FALSE; ///< Used by BSP and AP's to synchronize their initialization, TRUE if the BSP is done with the initialization, FALSE otherwise

volatile BOOLEAN gStageOneCanProceedOnAps = FALSE;   ///< TRUE if the BSP is done with phase1 and the APs can proceed, FALSE otherwise
volatile DWORD gStageOneInitedCpuCount = 0;          ///< The number of CPUs finished with phase1
volatile BOOLEAN gStageTwoCanProceedOnAps = FALSE;   ///< TRUE if the BSP is done with phase2 and the APs can proceed, FALSE otherwise
volatile DWORD gStageTwoInitedCpuCount = 0;          ///< The number of CPUs finished with phase2
volatile BOOLEAN gStageThreeCanProceedOnAps = FALSE; ///< TRUE if the BSP is done with phase3 and the APs can proceed, FALSE otherwise

volatile DWORD gCpuReachedInit64 = 0; ///< The number of CPUs reached the IniInit64 function
volatile BOOLEAN gNeedToUnload = FALSE; ///< TRUE if the hypervisor needs to unload (something went wrong ... ), FALSE otherwise

UD_VAR_INFO HvCommandLineVariablesInfo[] = UD_VAR_INFO_TABLE;                                       ///< The global configuration variables list
DWORD HvCommandLineVariablesInfoCount = (sizeof(HvCommandLineVariablesInfo) / sizeof(UD_VAR_INFO)); ///< The count of the global configuration variables

LD_BOOT_CONTEXT *gBootContext; ///< The boot context passed to the hypervisor
LD_NAPOCA_MODULE gBootModules[LD_MAX_MODULES]; ///< The module list for the hypervisor
LD_MEM_BUFFER *gTempMem = NULL; ///< Temporary memory buffer for hypervisor
volatile QWORD gDebuggerSynch = 0; ///< Used for synchronization when entering the debugger

/// @brief Callback registered for the hypervisor's ASSERT failures
static
void
_AssertCallback(
    _In_ const char *File,
    _In_ int Line,
    _In_opt_ char *Message
    )
{
    ERROR("assert failed in file %s line %d, message %s\n", File, Line, Message);
    DbgEnterDebugger();

    return; // WARNING: this function isn't expecting DbgEnterDebugger to return back the control
}

/// @brief initialize basic Cpu features
///
/// @returns    CX_STATUS_SUCCESS                   - Always
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_IniSetupInit64BasicCpuFeatures(
    void
    )
{
    CpuInitAddressWidthData();

    NTSTATUS status = HvaActivateL1tfMitigations();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("HvaActivateL1tfMitigations", status);
        // we can live without it ...
    }

    // enable SSE exceptions
    // If the OSXMMEXCEPT bit is clear,
    // the processor generates an invalid-opcode exception (#UD) on the first SSE or SSE2
    // instruction that detects a SIMD floating-point exception condition
    __writecr0(__readcr0() & (~(CR0_TS | CR0_EM)));
    __writecr4(__readcr4() | CR4_OSXMMEXCPT | CR4_OSFXSR);
    HvSetupSseExceptions();

    return CX_STATUS_SUCCESS;
}


/// @brief This is used to have a 'valid' GS as early as possible
///
/// While GS points to this structure HvGetCurrentCpu will return NULL
/// because the value corresponding to the Self field in the CPU structure will be NULL
static DUMMY_CPU gGlobalDummyCpu;

/// @brief Sets up gTempMem to make it available at HV boot initializations
///
/// @param[in]  BootContext     Boot context
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went well, gTempMem is initialized
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_IniSetupLoaderMemoryManager(
    _In_ LD_BOOT_CONTEXT *BootContext
    )
{
    LD_NAPOCA_MODULE *module;

    NTSTATUS status = LdGetModule(BootContext->Modules, LD_MAX_MODULES, LD_MODID_FREE_MEMORY, &module);
    if (!SUCCESS(status))
    {
        gTempMem = NULL;
        LOG_FUNC_FAIL("LdGetModule", status);
        return status;
    }

    gTempMem = (LD_MEM_BUFFER*) module->Va;
    LOG("temp memory buffer (gTempMem)\n");
    LOG("--> %-18s  <%018p>\n", "Va", gTempMem->Va);
    LOG("--> %-18s  <%018p>\n", "Pa", gTempMem->Pa);
    LOG("--> %-18s  <%018p>\n", "Length", gTempMem->Length);
    LOG("--> %-18s  <%018p>\n", "NextFreeAddress", gTempMem->NextFreeAddress);
    LOG("--> %-18s  <%d>\n", "Used(KB)", ((SIZE_T)gTempMem->NextFreeAddress - (SIZE_T)gTempMem->Va)/PAGE_SIZE);
    LOG("--> %-18s  <%d>\n", "Free(KB)", (gTempMem->Length - ((SIZE_T)gTempMem->NextFreeAddress - (SIZE_T)gTempMem->Va)) / 1024);

    return CX_STATUS_SUCCESS;
}


/// @brief Sets up hypervisor's initial memory management
///
/// @param[in]  Context     Boot context
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went well, the memory management was initialized
/// @returns    OTHER                               - Other internal error
static
NTSTATUS
_IniSetupBootMemoryManagement(
    _In_ LD_BOOT_CONTEXT *Context
)
{
    CpuInitIa32Pat();

    NTSTATUS status = _IniSetupLoaderMemoryManager(Context);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniSetupLoaderMemoryManager", status);
        goto cleanup;
    }

    gHva.RootPa = __readcr3();
    gHva.GetTableVa = HvaGetHvaPagingStructureVaCallback;
    gHva.AllocPagingStructure = IniBootAllocPagingStructureCallback;
    gHva.FreePagingStructure = IniBootFreePagingStructureCallback;

    status = MmInitDescriptor(&gHva, IniBootAllocVaCallback, NULL, IniBootFreeVaCallback, NULL, IniBootAllocPaCallback, NULL, IniBootFreePaCallback, NULL, &gHvMm);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmInitDescriptor", status);
        goto cleanup;
    }

    // copy gHvMm descriptor to gHvLowerMem (gHvLowerMem will never change from now on, thus using gHvLowerMem you'll be able to allocate loader memory)
    gHvLowerMem = gHvMm;

    // make sure no one maps the NULL page (by mistake, with MmUnlock or by using the low-level Tas* functions it is still possible)
    NTSTATUS info = MmLockVa(&gHvMm, (MM_UNALIGNED_VA)NULL, PAGE_SIZE);
    if (!SUCCESS(info))
    {
        LOG_FUNC_FAIL("MmLockVa", info);
        // not a big deal, let the code continue...
    }

    info = HvaActivateHvaPagingStructuresOffsetting();
    if (!SUCCESS(info))
    {
        LOG_FUNC_FAIL("HvaActivateHvaPagingStructuresOffsetting", info);
        // will continue execution with identity-mapped page tables
    }
cleanup:
    return status;
}



#define HV_MODULE_MUST_EXIST            1
#define HV_MODULE_FAIL_IF_TOO_SMALL     2

/// @brief Retrieves or, if necessary, creates (and memzero) a new module
///
/// @param[in]  Modules            List of the modules
/// @param[in]  NumberOfModules    Number of the modules
/// @param[in]  ModuleId           The module ID to be potentially initialized
/// @param[in]  NewFlags           Module flags, how to register the existing or newly created module
/// @param[in]  HvModFlags         Hypervisor module flags (HV_MODULE_*)
/// @param[in]  MinValidSize       In case we've got insufficient space prepared by the loader
/// @param[in]  DefaultModuleSize  How much memory to allocate if the module isn't present
/// @param[out] Module             The initialized module
/// @param[out] ModuleVa           The module's virtual address
/// @param[out] ModulePa           The module's physical address
/// @param[out] AlreadyPresent     TRUE if the module already present, FALSE otherwise
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, we got the module
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Modules can not be NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - ModulesId is bigger then the NumberofModules
/// @returns    CX_STATUS_DATA_BUFFER_TOO_SMALL     - Module's size is bigger then the MinValidSize and it's forced to fail
/// @returns    OTHER                               - Internal error
static
NTSTATUS
_IniInitModule(
    _In_ LD_NAPOCA_MODULE *Modules,
    _In_ DWORD NumberOfModules,
    _In_ DWORD ModuleId,
    _In_ DWORD NewFlags,
    _In_ DWORD HvModFlags,
    _In_opt_ DWORD MinValidSize,
    _In_opt_ DWORD DefaultModuleSize,
    __out_opt LD_NAPOCA_MODULE **Module,
    __out_opt PVOID *ModuleVa,
    __out_opt QWORD *ModulePa,
    __out_opt BOOLEAN *AlreadyPresent
    )
{
    NTSTATUS status;
    LD_NAPOCA_MODULE *module = NULL;
    QWORD va = NULL, pa = 0;
    DWORD size, flags;
    BOOLEAN present = FALSE, allocated = FALSE;

    if (Modules == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (ModuleId >= NumberOfModules) return CX_STATUS_INVALID_PARAMETER_3;

    size = DefaultModuleSize;
    flags = NewFlags;

    status = LdGetModule(Modules, NumberOfModules, ModuleId, &module);
    if (SUCCESS(status))
    {
        present = TRUE;

        if (module->Size >= MinValidSize)
        {
            va = module->Va;
            pa = module->Pa;
            size = module->Size;
            flags = module->Flags;
        }
        else
        {
            if (HvModFlags & HV_MODULE_FAIL_IF_TOO_SMALL)
            {
                status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
                goto cleanup;
            }
        }
    }
    else if (HvModFlags & HV_MODULE_MUST_EXIST) goto cleanup;

    if (va == NULL)
    {
        // no initialized module was prepared, allocate memory and initialize it
        status = MmAllocMem(&gHvMm, size, TAG_LD_MODULE, (MM_ALIGNED_VA*)&va);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmAllocMem", status);
            goto cleanup;
        }
        else
        {
            status = MmQueryPa(&gHvMm, (MM_ALIGNED_VA)va, &pa);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmQueryPa", status);
                goto cleanup;
            }
            allocated = TRUE;
        }

        // initialize the newly allocated map
        memzero((PVOID)va, size);
    }

    if (flags == LD_MODFLAG_DEFAULT) flags = LD_MODFLAG_PERMANENT;

    if ((allocated) && (Modules[LD_MODID_FREE_MEMORY].Flags < flags))
    {
        Modules[LD_MODID_FREE_MEMORY].Flags = flags; // the free memory should last at least as much as the newly allocated module
    }

    // register the module
    status = LdSetModule(Modules, NumberOfModules, ModuleId, va, pa, size, flags);
    if (!SUCCESS(status)) goto cleanup;

    // always reflect the updated module back to caller
    status = LdGetModule(Modules, NumberOfModules, ModuleId, &module);
    if (!SUCCESS(status)) goto cleanup;

    status = CX_STATUS_SUCCESS;

cleanup:
    if (AlreadyPresent != NULL) *AlreadyPresent = present;
    if (Module != NULL) *Module = module;
    if (ModuleVa != NULL) *ModuleVa = (PVOID)va;
    if (ModulePa != NULL) *ModulePa = pa;

    return status;
}

/// @brief Used for initial basic synchronization between CPUs
///
/// @param[in]  ZeroVariable    In: zero initialized variable, Out: number of CPUs that reached this code
/// @param[in]  NumberOfCpus    Total CPUs that should get synchronized
///
/// @returns    CX_STATUS_SUCCESS                     - The waiting condition was met
/// @returns    CX_STATUS_INVALID_PARAMETER_1         - ZeroVariable can not be NULL
/// @returns    STATUS_HV_UNLOAD_REQUESTED_INTERNALLY - The wait was abandoned because the HV needs to unload
static
NTSTATUS
_IniSynchronizeCpus(
    _Inout_ volatile QWORD *ZeroVariable,
    _In_ QWORD NumberOfCpus
    )
{
    if (ZeroVariable == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    HvInterlockedIncrementU64(ZeroVariable);

    while ((*ZeroVariable < NumberOfCpus) && (!gNeedToUnload))
    {
        CpuYield();
    }

    if (gNeedToUnload) return STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;

    return CX_STATUS_SUCCESS;
}

/// @brief Waits until the passed boolean becomes TRUE
///
/// @param[in]  Signal          Variable to wait on
///
/// @returns    CX_STATUS_SUCCESS                     - The waiting condition was met
/// @returns    STATUS_HV_UNLOAD_REQUESTED_INTERNALLY - The wait was abandoned because the HV needs to unload
static
CX_STATUS
_IniWaitForAStageSignal(
    volatile BOOLEAN *Signal
)
{
    while (!*Signal)
    {
        if (gNeedToUnload) return STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
        CpuYield();
    }

    return CX_STATUS_SUCCESS;
}

/// @brief Special pre-initialization, prepares the cleanup system, global and per-cpu variables. Required before 'generic' code can be run on this cpu
///
/// @param[in]  BootContext      Boot context
/// @param[out] ClnLoaderState  The preinitialized cleanup state
/// @param[out] ClnHandler      Optional, self-handler
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the cleanup is preinitialized
/// @returns    OTHER                               - Internal error
static
NTSTATUS
_IniPreinitCleanupAndGlobals(
    _In_ LD_BOOT_CONTEXT *BootContext,
    _Out_ CPU_ORIGINAL_STATE *ClnLoaderState,
    __out_opt CLN_HANDLER **ClnHandler
    )
{
    NTSTATUS status;
    IO_PER_CPU_DATA *perCpuData;
    CLN_HANDLER *handler = NULL;
    volatile static QWORD globalSynch = 0;
    volatile static QWORD cleanupSynch = 0;

    // mark phase on all cpus
    IoSetPerCpuPhase(IO_CPU_PHASE_INIT64);

    // BSP-only global initializations
    if (CpuIsCurrentCpuTheBsp())
    {
        ClnInitialize();

        gBootContext = BootContext;
        HvSetBootMode((BOOT_MODE)BootContext->BootMode);

        SetOnlyOnceCrtAssertCallback(&_AssertCallback);
    }

    // sync after initializations to make sure no one is using the cleanup system or globals before they're initialed
    status = _IniSynchronizeCpus(&globalSynch, BootContext->NumberOfLoaderCpus);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniSynchronizeCpus", status);
        goto cleanup;
    }

    // setup the CPU cleanup structure for this/each cpu
    ClnLoaderState->LoaderBootContext = BootContext;
    ClnLoaderState->Flags = 0;

    memzero(&ClnLoaderState->Msrs, sizeof(ClnLoaderState->Msrs));
    ClnLoaderState->Msrs.MaxArrayElements = ARRAYSIZE(ClnLoaderState->Msrs.Msrs);

    status = ClnAddMsrToRestoreArea(
        &ClnLoaderState->Msrs,
        MSR_IA32_MISC_ENABLE,
        __readmsr(MSR_IA32_MISC_ENABLE));
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("ClnAddMsrToRestoreArea", status);
        goto cleanup;
    }

    // save the per-cpu boot context pointer for persistence
    status = IoGetPerCpuData(&perCpuData);
    if (SUCCESS(status)) perCpuData->BootContext = BootContext;

    // prepare the cpu cleanup support for this/each cpu
    CLN_REGISTER_SELF_HANDLER((CLN_CALLBACK)ClnCpuRestoreState, (CLN_ORIGINAL_STATE*)ClnLoaderState, &handler);
    if (ClnHandler != NULL) *ClnHandler = handler;

    // synchronize again to avoid partial HV unload (before all CPUs have the cleanup system ready)
    status = _IniSynchronizeCpus(&cleanupSynch, BootContext->NumberOfLoaderCpus);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniSynchronizeCpus", status);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



/// @brief Processes the command line to load the configuration variables
///
/// @param[out] Accepted        Optional, TRUE if the commandline was valid, FALSE otherwise
///
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the commandline was processed
/// @returns    CX_STATUS_DATA_NOT_FOUND            - No command line was found, nothing to process
/// @returns    CX_STATUS_INVALID_PARAMETER         - Invalid commandline detected
/// @returns    CX_STATUS_INVALID_DATA_TYPE         - Unsupported variable type marked as protected
/// @returns    OTHER                               - Internal error
static
NTSTATUS
_IniProcessCommandLine(
    __out_opt BOOLEAN *Accepted
    )
{
    NTSTATUS status;
    BOOLEAN acceptedCommandLine = FALSE;
    LD_NAPOCA_MODULE *module;
    CHAR *cmdline;
    DWORD cmdlineLength;
    QWORD consumed;

    //
    // Parse the command line before to extract the sent values for our commandline variables
    //

    // get the address and size
    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_COMMAND_LINE, &module);
    if (!SUCCESS(status))
    {
        // no command line was sent
        cmdline = NULL;
        status = CX_STATUS_DATA_NOT_FOUND;
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }
    cmdline = (CHAR*)(module->Va);
    cmdlineLength = module->Size;

    // call the parser
    if (!UdMatchVariablesFromText(HvCommandLineVariablesInfo, HvCommandLineVariablesInfoCount, cmdline, cmdlineLength, &consumed))
    {
        LOG("[CMDLINE] Processing has failed, consumed = %d, length = %d\n", consumed, cmdlineLength);
        LOG("unmatched part of the command line: %s\n", &cmdline[consumed]);
        status = CX_STATUS_INVALID_PARAMETER;
        LOG_FUNC_FAIL("UdMatchVariablesFromText", status);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    if (Accepted != NULL) *Accepted = acceptedCommandLine;

    // Validate consistency and enforce master control over minor keys (vars)
    if (!CfgDebugOutputEnabled)
    {
        CfgDebugOutputSerialEnabled         = 0;
        CfgDebugOutputVgaEnabled            = 0;
        CfgDebugStartInDebugger             = 0;
    }

    return status;
}



/// @brief Initializes Input/Output (serial, VGA)
///
/// @returns    CX_STATUS_SUCCESS                   - Always
static
NTSTATUS
_IniInitializeIo(
    void
)
{
    // first of all, init minimal IO for tracing / logging support
    BOOLEAN initSerialIo, initVgaOutput;

    initSerialIo = (CfgDebugOutputSerialEnabled != 0);
    initVgaOutput = (CfgDebugOutputVgaEnabled && BOOT_OPT_VGA_MEM);

    // we don't even log / trace the error, as we just tried to init the tracing stuff
    IoInitForTrace(initVgaOutput, initSerialIo);

    IoSetPerCpuOutputEnabled(TRUE);

    IpcSetInterruptibilityValues(FALSE, 0, TRUE, IPC_ENABLED, TRUE, IPC_PRIORITY_LOWEST);

    return CX_STATUS_SUCCESS;
}



/// @brief Retrieve/init all the necessary modules
///  - Napoca image
///  - Memory map
///  - Hypervisor memory map
///  - Non volatile storage
///  - Boot state
///  - Custom loader
///  - Feedback
///
/// @param[in]  Context         Boot context
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, all the modules are belong to us
/// @returns    OTHER                               - Internal error
static
NTSTATUS
_IniRetrieveLoaderModules(
    _In_ LD_BOOT_CONTEXT *Context
    )
{
    NTSTATUS status;
    QWORD pa;
    LD_NAPOCA_MODULE *module;
    PVOID tmp;
    BOOLEAN alreadyPresent;

    // make a global copy of the modules array large enough to fit all HV used entries
    for (DWORD i = 0; (i < Context->NumberOfModules) && (i < LD_MAX_MODULES); i++)
    {
        if (Context->Modules[i].Size != 0) gBootModules[i] = Context->Modules[i];
        else memzero(&(gBootModules[i]), sizeof(LD_NAPOCA_MODULE));
    }
    if (Context->NumberOfModules < LD_MAX_MODULES)
    {
        memzero(&(gBootModules[Context->NumberOfModules]), (LD_MAX_MODULES - Context->NumberOfModules) * sizeof(LD_NAPOCA_MODULE));
    }

    // get the napoca module
    status = _IniInitModule(gBootModules, LD_MAX_MODULES,
        LD_MODID_NAPOCA_IMAGE, LD_MODFLAG_PERMANENT, HV_MODULE_MUST_EXIST,
        0, 0, &module, &tmp, &pa, NULL);
    if (!SUCCESS(status))
    {
        LOG("!!!CRITICAL: NAPOCA MODULE memory space is not defined!\n");
        goto cleanup;
    }

    // round it up, there are some problems later unless the kernel size is aligned
    module->Size = ROUND_UP(module->Size, PAGE_SIZE); // no need for PAGE_COUNT&Co, the base address of napoca.bin is already page-aligned

    // make sure we have a memory map unless BOOT_OPT_NONSTANDARD_MEMORY_MAP
    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_MEMORY_MAP, &module);
    gTempE820 = (SUCCESS(status) ? (PVOID)(SIZE_T)(module->Va) : NULL);

    // get/prepare the gBootInfo structure
    status = MmAllocMem(&gHvMm, sizeof(BOOT_INFO), TAG_MODULE, &gBootInfo);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAllocMem", status);
        goto cleanup;
    }
    memzero(gBootInfo, sizeof(BOOT_INFO));
    gBootInfo->PredetCpuCount = gBootContext->NumberOfLoaderCpus;

    //
    // get/prepare the HvMemMap structure unless we've got a valid HvMemMap from a BOOT_OPT_NONSTANDARD_HV_MEMORY_MAP loader
    //
    status = _IniInitModule(gBootModules, LD_MAX_MODULES,
        LD_MODID_HVMEMORY_MAP, LD_MODFLAG_DEFAULT, HV_MODULE_FAIL_IF_TOO_SMALL,
        sizeof(LD_HVMEMORY_MAP), LD_HVMEMORY_MAP_SIZE(BOOT_MAX_HV_ZONE_COUNT),
        NULL, &(gBootInfo->HvMemMap), NULL, &alreadyPresent);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniInitModule", status);
        goto cleanup;
    }
    if (!alreadyPresent) gBootInfo->HvMemMap->TotalNumberOfEntries = BOOT_MAX_HV_ZONE_COUNT;

    if (gBootInfo->HvMemMap->HvZoneCount <= 1)
    {
        status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_NAPOCA_IMAGE, &module);
        if (!SUCCESS(status)) goto cleanup;

        LOG("Setting implicit gBootInfo->HvMemMap->Entries[0].Length = %p\n", (QWORD)((SIZE_T)module->Size));

        gBootInfo->HvMemMap->HvZoneCount = 1;
        gBootInfo->Flags = BIF_HV_ZONE_MAPS_ONLY_KZ;
        gBootInfo->HvMemMap->Entries[0].StartAddress = module->Pa;
        gBootInfo->HvMemMap->Entries[0].Length = module->Size;
        gBootInfo->HvMemMap->Entries[0].Type = BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED;
        LOG("gBootInfo->HvMemMap->Entries[0]: StartAddress=%p, Length=%X\n",
            gBootInfo->HvMemMap->Entries[0].StartAddress, gBootInfo->HvMemMap->Entries[0].Length);
    }
    else gBootInfo->Flags = 0;

    LOG("HvMemMap: total=%d, HV=%d, guests=%d [0]=(%p, %p, %d)\n",
        gBootInfo->HvMemMap->TotalNumberOfEntries,
        gBootInfo->HvMemMap->HvZoneCount,
        gBootInfo->HvMemMap->GuestZoneCount,
        gBootInfo->HvMemMap->Entries[0].StartAddress,
        gBootInfo->HvMemMap->Entries[0].Length,
        gBootInfo->HvMemMap->Entries[0].Type
        );

    // get(for UEFI)/prepare(for Legacy) the NVS memory area used to store hibernate data
    status = _IniInitModule(gBootModules, LD_MAX_MODULES,
        LD_MODID_NVS, LD_MODFLAG_PERMANENT,
        (BOOT_UEFI ? HV_MODULE_MUST_EXIST | HV_MODULE_FAIL_IF_TOO_SMALL : HV_MODULE_FAIL_IF_TOO_SMALL),
        GST_HIBERNATE_CONTEXT_RESTORE_AREA_SIZE,
        GST_HIBERNATE_CONTEXT_RESTORE_AREA_SIZE,
        NULL, NULL, NULL, NULL);
    if (!SUCCESS(status))
    {
        if (status == CX_STATUS_DATA_NOT_FOUND) ERROR("NVS Module was not initialized by the loader\n");

        LOG_FUNC_FAIL("_IniInitModule", status);
        // hibernate data is not critical enough to unload the hv if this fails, this may change depending on the data saved in this area
    }

    // get/prepare gBootState
    status = _IniInitModule(gBootModules, LD_MAX_MODULES, LD_MODID_BOOT_STATE,
        LD_MODFLAG_PERMANENT, HV_MODULE_FAIL_IF_TOO_SMALL,
        sizeof(CPUSTATE_BOOT_GUEST_STATE), sizeof(CPUSTATE_BOOT_GUEST_STATE),
        NULL, &gBootState, NULL, &alreadyPresent);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniInitModule", status);
        goto cleanup;
    }


    //
    // get/prepare space needed for ACPI Sleep
    //
    PwrPreinit();

    // loader specific data module
    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_LOADER_CUSTOM, &module);
    if (SUCCESS(status))
    {
        gLoaderCustom = (LD_LOADER_CUSTOM*) module->Va;
        if ((gLoaderCustom == NULL) && (BOOT_MBR_PXE || BOOT_UEFI))
        {
            status = CX_STATUS_INVALID_INTERNAL_STATE;
            goto cleanup;
        }
        else if (BOOT_MBR_PXE) gHypervisorGlobalData.BootFlags.IsGrub = CX_TRUE;
    }

    // feedback module
    status = _IniInitModule(gBootModules, LD_MAX_MODULES, LD_MODID_FEEDBACK,
        LD_MODFLAG_PERMANENT, 0, 0, (8 * ONE_MEGABYTE),
        NULL, &gFeedback, NULL, &alreadyPresent);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniInitModule", status);
        goto cleanup;
    }

    // loader specific data module
    status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_FEEDBACK, &module);
    if (SUCCESS(status))
    {
        // set default header if none was already configured by the loader
        if (!gFeedback->Version)
        {
            memzero(gFeedback, sizeof(HV_FEEDBACK_HEADER));
            gFeedback->Version = FEEDBACK_VERSION;
            gFeedback->Logger.BufferSize = module->Size - sizeof(HV_FEEDBACK_HEADER);
            gFeedback->Logger.Circular = TRUE;
            gFeedback->Logger.Initialized = TRUE;
        }
    }

    IoSetPerCpuOutputEnabled(TRUE);    // enable output from this CPU on memory log

    //
    // (Final) modules listing
    //
    QWORD totalSize = 0;
    for (DWORD i = 0; i < LD_MAX_MODULES; i++)
    {
        if (gBootModules[i].Size != 0)
        {
            totalSize += gBootModules[i].Size;
            LOG("Processed module %-32s(%d): PA:%08llX, VA:%012llX, SIZE:%08X, FLAGS:%08X\n", LdGetModuleName(i), i,
                gBootModules[i].Pa, gBootModules[i].Va, gBootModules[i].Size, gBootModules[i].Flags);
        }
    }
    LOG("Total size of all modules: %fMB\n", ((float)totalSize / ONE_MEGABYTE));

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}



/// @brief Validate and make available the modules/data sent by the loader
///
/// @param[in]  Context         Boot context
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Invalid boot mode
/// @returns    OTHER                               - Internal error
static
NTSTATUS
_IniInitializeCpuLoaderData(
    _In_ LD_BOOT_CONTEXT *Context
    )
{
    NTSTATUS status;
    volatile static QWORD readyCpus = 0;

    if (CpuIsCurrentCpuTheBsp())
    {
        // get the default configuration root pointer
        // validate BootMode
        if (!BOOT_MBR && !BOOT_MBR_PXE && !BOOT_UEFI)
        {
            status = CX_STATUS_INVALID_PARAMETER_1;
            goto cleanup;
        }

        //
        // Parse the loader given boot state structures
        //
        status = _IniRetrieveLoaderModules(Context);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_IniRetrieveLoaderModules", status);
            goto cleanup;
        }

    }

    // make sure everyone got to this point before continuing
    status = _IniSynchronizeCpus(&readyCpus, Context->NumberOfLoaderCpus);
    if (!SUCCESS(status)) goto cleanup;

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}


/// @brief The main entry point, handling all the initializations until the execution of the guest
///
/// The primary x64 entry point. Contains the backbone code that links together PHASE1, PHASE2, PHASE3.
/// This routine is called for both the BSP and the APs, but has different flow according to the CPU (BSP vs APs) is
/// running on. The BSP flow is much more complex, as it contains most of the initialization code.
///
/// @param[in]  Context         Containing all the relevant information needed for initialization, generated by the loader
__declspec(dllexport)
void
IniInit64(
    _In_ LD_BOOT_CONTEXT *Context
    )
{
    NTSTATUS status;
    CPU_ORIGINAL_STATE loaderState; // original cpu state info used by the cleanup system
    BOOLEAN acceptedCommandLine;

    CpuBindStructureToGs((PCPU*)&gGlobalDummyCpu);

    HvInterlockedIncrementU32(&gCpuReachedInit64);

    if (Context == NULL)
    {
        CRITICAL("NULL BootContext structure\n");
        __halt(); // no cleanup is possible without loader context data
    }

    if (CfgDebugOutputVgaEnabled == 2) // this particular if checks against the built-in value as the actual commandline is not yet parsed at this point
    {
        if (((Context->BootMode & bootModeLimit) == bootMbr) || ((Context->BootMode & bootModeLimit) == bootMbrPxe))
        {
            BYTE height = ((Context->BootMode & bootModeLimit) == bootMbrPxe || (Context->BootMode & bootModeLimit) == bootMbr) ? 50 : 25;

            status = VgaInit(height);
            if (_SUCCESS(status)) gVideoVgaInited = TRUE;
        }
    }

    // make sure the XD support is activated on any/all CPUs before we're using/setting it for any new data mappings
    status = CpuActivateNxe();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("CpuActivateNxe", status);
        // we can live without NX
    }

    if (CpuIsCurrentCpuTheBsp())
    {
        status = _IniSetupBootMemoryManagement(Context);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_IniSetupBootMemoryManagement", status);
            goto cleanup;
        }
    }

    // all cpus: preinitialize internal HV global state variables and make the cleanup system available for later code
    status = _IniPreinitCleanupAndGlobals(Context, &loaderState, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniPreinitCleanupAndGlobals", status);
        __halt(); // no unload is available unless the cleanup is initialized
    }

    status = _IniInitializeCpuLoaderData(Context);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniInitializeCpuLoaderData", status);
        goto cleanup;
    }

    // prepare basic cpu features (NXE, FPU/SSE/.. support and/or exception handling etc..)
    status = _IniSetupInit64BasicCpuFeatures();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_IniSetupInit64BasicCpuFeatures", status);
        goto cleanup;
    }

    //
    // BSP - are we running the initialization on the BSP CPU?
    //
    if (CpuIsCurrentCpuTheBsp())
    {
        //
        // === STAGE I, scan host system and initialize hypervisor ===
        //

        status = HvInitTime();
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HvInitTime", status);
            goto cleanup;
        }

        acceptedCommandLine = FALSE;
#if (defined(CFG_FEATURES_CMDLINE_ENABLED) && !CFG_FEATURES_CMDLINE_ENABLED)
        LOG("[CMDLINE] Command line support is disabled in this build via CFG_FEATURES_CMDLINE_ENABLED\n");
#else
        status = _IniProcessCommandLine(&acceptedCommandLine);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_IniProcessCommandLine", status);
            goto cleanup;
        }

        if (acceptedCommandLine) LOG("[CMDLINE] The new values were applied to the configuration variables\n");
        else LOG("[CMDLINE] Using the built-in configuration variables\n");
#endif

        PciToolsInit();

        status = _IniInitializeIo();
        if (!SUCCESS(status)) LOG_FUNC_FAIL("_IniInitializeIo", status);

        PrintVersionInfo();
        HvPrintTimeInfo();

        // setup introcore module (validate introcore image,
        //  resolve exports and setup callbacks necessary for supporting on-the-fly updates)
        if (CfgFeaturesIntrospectionEnabled)
        {
            status = HvSetupIntro();
            if (!SUCCESS(status)) LOG_FUNC_FAIL("HvSetupIntro", status);
        }

        if (gHypervisorGlobalData.BootFlags.IsGrub)
        {
            LOG("Hv was legacy booted, will load original MBR from boot drive: %x\n", gLoaderCustom->Legacy.BiosOsDrive.Drive);
        }

        // IMPORTANT: initialize the kernel image length to the length of the first entry in BOOT_INFO::HvMemMap
        // This is true for all boot modes
        gHypervisorGlobalData.MemInfo.KernelImageLength = gBootInfo->HvMemMap->Entries[0].Length;

        // signal APs that they can begin
        gBasicInitDoneByBSP = TRUE;

        // effectively do the PHASE1 in bulk
        status = Phase1BspStageOne();
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("Phase1BspStageOne", status);
            goto cleanup;
        }

        //
        // === STAGE II, initialize guest VMs ===
        //
        status = Phase2BspStageTwo();
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("Phase2BspStageTwo", status);
            goto cleanup;
        }

        if (CfgFeaturesIntrospectionEnabled)
        {
            //
            // Perform a full initialization of the Memory Introspection engine
            // Following interfaces are implemented: GlueIFace, UpperIface
            // Since it's first time when loading protected guest, second parameter is true
            //
            status = NapIntFullInit(HvGetCurrentIntroModuleInterface(), TRUE);
            if (!NT_SUCCESS(status))
            {
                ERROR("Memory Introspection engine couldn't be initialized, status=%s\n", NtStatusToString(status));
            }
        }

        if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
        {
            status = LapicSetupPerfNMI();
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("LapicSetupPerfNMI", status);
        }

        //
        // === STAGE III, run / schedule guests ===
        //

        // trigger APs to perform STAGE III
        gStageThreeCanProceedOnAps = TRUE;

        CpuYield();     // wait for a very short time on the BSP - shall better match the moment with the APs for StartTsc
        CpuYield();

        HvGetCurrentCpu()->StartTsc = __rdtsc();

        // perform stage III on the BSP also
        LOG("[BSP] STAGE III / HvPcpuRootMainCycle will start (TSC = %lld)...\n", HvGetCurrentCpu()->StartTsc);

        if (HvGetCurrentCpu()->UseXsave) __xsetbv(0, HvGetCurrentCpu()->StartupXCR0);

        if (CfgDebugStartInDebugger)
        {
            LOG("Last-chance breakpoint before entering guest\n");
            DbgBreakIgnoreCleanupIKnowWhatImDoing();
            _IniSynchronizeCpus(&gDebuggerSynch, CPU_COUNT_TO_WAIT);
        }

        // run the core cycle of PHASE 3
        IoSetPerCpuPhase(IO_CPU_ROOT_CYCLE);
        HvPcpuRootMainCycle();

        LOG("[BSP] STAGE III / ... HvPcpuRootMainCycle terminated!\n");
        status = CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    }
    //
    // AP - we are running on one of the AP CPUs...
    //
    else
    {
        // wait for BSP to signal that basic init has been done
        status = _IniWaitForAStageSignal(&gBasicInitDoneByBSP);
        if (status == STATUS_HV_UNLOAD_REQUESTED_INTERNALLY) goto cleanup;

        // wait for BSP to signal we can proceed with STAGE I on APs
        status = _IniWaitForAStageSignal(&gStageOneCanProceedOnAps);
        if (status == STATUS_HV_UNLOAD_REQUESTED_INTERNALLY) goto cleanup;

        //
        // === STAGE I ===
        //
        // IMPORTANT: we must switch PDBR here due to stack relocation in case of direct os load; this is
        // also tricky, because, even if we are currently running on the old, intermediate VA mappings, the
        // MmQueryPa will give us correct address in the context of the new final VA mappings (SM)
        //

        if (BOOT_OPT_MULTIPROCESSOR) __writecr3(gHva.RootPa);

        IoSetPerCpuOutputEnabled(TRUE);

        IpcSetInterruptibilityValues(FALSE, 0, TRUE, IPC_ENABLED, TRUE, IPC_PRIORITY_LOWEST);

        // perform PHASE I on this AP
        status = Phase1ApStageOne();
        if (!SUCCESS(status))
        {
            ERROR("Phase1ApStageOne failed on AP %d, status=%s\n", HvGetInitialLocalApicIdFromCpuid(), NtStatusToString(status));
            goto cleanup;
        }

        // signal to BSP that this AP finished STAGE I
        LOG("[AP %d] STAGE I done\n", HvGetCurrentApicId());
        HvInterlockedIncrementU32(&gStageOneInitedCpuCount);

        //
        // === STAGE II ===
        //

        // wait for BSP to signal we can proceed with STAGE II on APs
        status = _IniWaitForAStageSignal(&gStageTwoCanProceedOnAps);
        if (status == STATUS_HV_UNLOAD_REQUESTED_INTERNALLY) goto cleanup;

        status = Phase2ApStageTwo();
        if (!SUCCESS(status))
        {
            ERROR("Phase2ApStageTwo failed on AP %d, status=%s\n", HvGetInitialLocalApicIdFromCpuid(), NtStatusToString(status));
            goto cleanup;
        }

        // signal to BSP that this AP finished STAGE II
        LOG("[AP %d] STAGE II done\n", HvGetCurrentApicId());
        HvInterlockedIncrementU32(&gStageTwoInitedCpuCount);

        if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
        {
            status = LapicSetupPerfNMI();
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("LapicSetupPerfNMI", status);
        }

        //
        // === STAGE III ===
        //

        // wait for BSP to signal we can proceed with stage III
        status = _IniWaitForAStageSignal(&gStageThreeCanProceedOnAps);
        if (status == STATUS_HV_UNLOAD_REQUESTED_INTERNALLY) goto cleanup;

        HvGetCurrentCpu()->StartTsc = __rdtsc();

        // perform stage III on this AP
        LOG("[AP %d] STAGE III / HvPcpuRootMainCycle will start (TSC = %lld)...\n",
            HvGetCurrentApicId(), HvGetCurrentCpu()->StartTsc);

        if (HvGetCurrentCpu()->UseXsave) __xsetbv(0, HvGetCurrentCpu()->StartupXCR0);

        if (CfgDebugStartInDebugger) _IniSynchronizeCpus(&gDebuggerSynch, CPU_COUNT_TO_WAIT);

        // run the core cycle of PHASE 3
        IoSetPerCpuPhase(IO_CPU_ROOT_CYCLE);
        HvPcpuRootMainCycle();

        LOG("[AP %d] STAGE III / ... HvPcpuRootMainCycle terminated!\n", HvGetCurrentApicId());

        status = CX_STATUS_OPERATION_NOT_IMPLEMENTED;
    } // end-of-AP-code

cleanup:

    if (!SUCCESS(status)) CLN_UNLOAD(status);

    return;
}

CX_STATUS
IniBootAllocPagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ CX_UINT8 TableDepth,
    _Out_ MEM_ALIGNED_VA* Va,
    _Out_ MEM_ALIGNED_PA* Pa
)
{
    UNREFERENCED_PARAMETER(TableDepth);     // PAE paging uses 4K paging structures at all levels

    CX_STATUS status = LdAlloc(gTempMem, PAGE_SIZE, PAGE_SIZE, Va, Pa);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdAlloc", status);
        goto cleanup;
    }

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
IniBootFreePagingStructureCallback(
    _In_ TAS_DESCRIPTOR* Mapping,
    _In_ MEM_ALIGNED_VA Va,
    _In_ MEM_ALIGNED_PA Pa
)
{
    UNREFERENCED_PARAMETER((Mapping, Pa));
    WARNING("Leaked loader memory page: %p (due to early VA mapping of a similar address on two CPUs at the same time)\n", Va);
    return CX_STATUS_SUCCESS;
}

CX_STATUS
IniBootAllocVaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA *Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, AllocatorId, Tag));
    static volatile CX_UINT64 NextFree = NAPOCA_DYNAMIC_VA_START;

    CX_UINT64 allocSize = CX_PAGE_SIZE_4K * (CX_UINT64)NumberOfPages;
    MM_ALIGNED_VA nextVa = (MM_ALIGNED_VA)_InterlockedExchangeAdd64((volatile CX_INT64*)&NextFree, allocSize);

    // check for the full allocation to be inside the NAPOCA DYNAMIC VA Range
    if ((QWORD)PTR_ADD(nextVa, allocSize) > NAPOCA_DYNAMIC_VA_END) return CX_STATUS_OUT_OF_MEMORY;

    *Va = nextVa;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
IniBootFreeVaCallback(
    _In_ MM_DESCRIPTOR* Mm,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _Out_ MM_ALIGNED_VA* Va,
    _In_opt_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, NumberOfPages, Va, AllocatorId, Tag));
    return CX_STATUS_SUCCESS;
}

CX_STATUS
IniBootAllocPaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _Out_ MDL *Mdl,
    _Out_ MM_ALIGNED_PA *Pa,
    _In_ MM_PAGE_COUNT NumberOfPages,
    _In_ CX_BOOL Continuous,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, Mdl, Continuous, AllocatorId, Tag)); // we're only capable of continuous memory allocations at boot-time

    QWORD va;

    NTSTATUS status = LdAlloc(gTempMem, NumberOfPages * PAGE_SIZE, PAGE_SIZE, &va, Pa);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdAlloc", status);
        goto cleanup;
    }
    LOG("=>PA %p:%p\n", *Pa, *Pa + ((QWORD)NumberOfPages * PAGE_SIZE) - 1);
cleanup:
    return status;
}


CX_STATUS
IniBootFreePaCallback(
    _In_ MM_DESCRIPTOR *Mm,
    _In_ MDL *Mdl,
    _In_ CX_UINT64 AllocatorId,
    _In_ MM_TAG Tag
)
{
    UNREFERENCED_PARAMETER((Mm, AllocatorId, Tag));
    WARNING("freeing boot-buffer memory is not supported, the memory (MDL dump follows) was leaked!\n");
    MdlDump("Leaked MDL:", Mdl);
    return CX_STATUS_SUCCESS;
}

/// @}
