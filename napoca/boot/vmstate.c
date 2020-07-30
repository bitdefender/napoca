/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file vmstate.c
 *  @brief VMCS configuration APIs
 */

 /// \addtogroup vmcs
 /// @{

#include "napoca.h"
#include "boot/vmstate.h"
#include "kernel/kerneldefs.h"
#include "kernel/newcore.h"
#include "memory/mdl.h"
#include "guests/guests.h"
#include "kernel/kernel.h"

extern CPUSTATE_BOOT_GUEST_STATE *gBootState;

/** @name PXE boot
 *  @brief Used to know the address where we send the BSP in case of a boot via PXE
 */
///@{
extern BYTE __GuestPxeMbrLoaderCode;
extern BYTE __GuestPxeMbrLoaderEntry;
#define VMCS_DEFAULT_PXE_LOADED_BOOT_CODE_ADDRESS   0x7e00
#define VMCS_DEFAULT_PXE_STACK_ADDRESS              0x7c00
///@}

/// @brief The address of the code to be run by BSP in case of a boot through MBR
#define VMCS_DEFAULT_MBR_LOADED_BOOT_CODE_ADDRESS 0x7c00

/// @brief Mask to apply when read MSR_IA32_VMX_BASIC msr
#define VMCS_REVISION_MASK 0xffffffffU

/// @brief Configures whether we have exits on guest exceptions based on CfgDebugTraceGuestExceptions
#define VMCS_VCPU_INTERCEPTED_EXCEPTIONS_BITMAP  (CfgDebugTraceGuestExceptions ? 0xFFFFFFFFULL : 0x00004000ULL)

/** @brief Default value for Pin-Based VM-Execution Controls
 *
 * No External-interrupt exiting, no NMI exiting, no Virtual NMIs, no Activate VMXpreemption timer
 * and no Process posted interrupts
 *
 */
#define VMCS_PIN_EXEC_CTRL_DEFAULT       0U

/** @brief Default value for Primary Processor-Based VM-Execution Controls
 *
 * We use I/O bitmaps, MSR bitmaps and the secondary processor-based VM-execution controls.
 *
 */
#define VMCS_PROC_EXEC_CTRL_DEFAULT      0U | VMCSFLAG_PROCEXEC_USE_IO_BITMAPS | VMCSFLAG_PROCEXEC_USE_MSR_BITMAPS | VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2

/** @brief Default value for Secondary Processor-Based VM-Execution Controls
 *
 * We use EPT, RDTSCP do not causes \c \#UD and guest software may run
 * in unpaged protected mode or in real address mode.
 *
 */
#define VMCS_PROC_EXEC_CTRL_2_DEFAULT    0U | VMCSFLAG_PROCEXEC2_ENABLE_EPT | VMCSFLAG_PROCEXEC2_ALLOW_RDTSCP | VMCSFLAG_PROCEXEC2_UNRESTRICTED_GUEST

/** @brief Default value for VM-Exit Controls
 *
 * DR7 and the IA32_DEBUGCTL MSR are saved on VM exit, processor is in 64-bit mode after VM exit (host address-space size),
 * IA32_EFER MSR is saved on VM exit, IA32_EFER MSR is loaded on VM exit.
 *
 */
#define VMCS_VM_EXIT_CTRL_DEFAULT        0U | VMCSFLAG_VMEXIT_SAVE_DEBUG_CONTROLS | VMCSFLAG_VMEXIT_64BIT_HOST | VMCSFLAG_VMEXIT_SAVE_IA32_EFER_TO_VMCS | VMCSFLAG_VMEXIT_LOAD_IA32_EFER_FROM_HOST

/** @brief Default value for VM-Entry Controls
 *
 * DR7 and the IA32_DEBUGCTL MSR are loaded on VM entry, the IA32_EFER MSR is loaded on VM entry.
 *
 */
#define VMCS_VM_ENTRY_CTRL_DEFAULT       0U | VMCSFLAG_VMENTRY_LOAD_DEBUG_CONTROLS | VMCSFLAG_VMENTRY_LOAD_IA32_EFER_FROM_VMCS

/** @name Segmentation default
 *  @brief Default values for code & data segments
 */
///@{
#define VMCS_SEG_CODE_DEFAULT (SEG_TYPE_CODE_EXECUTE_READ_ACCESSED | SEG_PRESENT | SEG_DESCRIPTOR_TYPE_CODE_OR_DATA)
#define VMCS_SEG_DATA_DEFAULT (SEG_TYPE_DATA_RW_ACCESSED | SEG_PRESENT | SEG_DESCRIPTOR_TYPE_CODE_OR_DATA)
///@}

/// @brief SMBASE default address
#define VMCS_SM_BASE_DEFAULT_ADDRESS 0xA0000

/** @brief VMCS link pointer from Guest Non-Register State
 *
 * If the "VMCS shadowing" VM-execution control is 1, the VMREAD and VMWRITE
 * instructions access the VMCS referenced by this pointer (see Section 24.10). Otherwise, software should set
 * this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry failures
 *
 */
#define VMCS_LINK_POINTER_DEFAULT_VALUE 0xFFFFFFFFFFFFFFFFULL

///
/// @brief Method for passing smbase address in case a more complex logic needs to be implemented
///
/// @returns UINT32         - Now returns only the address considered default for SMBASE
///
static
inline
CX_UINT32
_VmcsGetSmBaseAddress()
{
    return VMCS_SM_BASE_DEFAULT_ADDRESS;
}

/// @brief Default state for real mode vmcs guest fields
static
const
CPUSTATE_GUEST_STATE_INFO defaultBspRMCpuState = {
    // For BSP the current state is Active
    .ActivityState = VMCS_ACTIVITY_STATE_ACTIVE,

    // Set control registers and rflags
    .Cr0 = CR0_WP | CR0_ET | CR0_NE,
    .Cr3 = 0,
    .Rflags = RFLAGS_MUST_BE_1 | RFLAGS_PF,

    // Set segment selectors limit and access rights
    .CsLimit = 0xffff,
    .SsLimit = 0xffff,
    .DsLimit = 0xffff,
    .EsLimit = 0xffff,
    .FsLimit = 0xffff,
    .GsLimit = 0xffff,

    .CsAccessRights = VMCS_SEG_CODE_DEFAULT,
    .SsAccessRights = VMCS_SEG_DATA_DEFAULT,
    .SsAccessRights = VMCS_SEG_DATA_DEFAULT,
    .DsAccessRights = VMCS_SEG_DATA_DEFAULT,
    .EsAccessRights = VMCS_SEG_DATA_DEFAULT,
    .FsAccessRights = VMCS_SEG_DATA_DEFAULT,
    .GsAccessRights = VMCS_SEG_DATA_DEFAULT,

    // Setup a dummy TR to pass VMCS checks
    .Tr = 8,
    .TrBase = 0x0,
    .TrLimit = 0xc0,
    .TrAccessRights = 0x8b,

    // Setup LDTR registers
   .Ldtr = 0,
   .LdtrBase = 0,
   .LdtrLimit = 0xfffff,
   .LdtrAccessRights = 0x00010082,

   // Setup GDTR register
   .GdtrBase = 0,
   .GdtrLimit = (sizeof(GDT) - 1),

   // Set the IDTR to point to the IVT
   .IdtrBase = 0,
   .IdtrLimit = (256 * sizeof(INTERRUPT_GATE)) - 1,


   .IsStructureInitialized = CX_TRUE,

   .InterruptibilityState = 0,   // conform Intel Vol 3B, 21.4.2, Table 21-3
   .PendingDebugExceptions = 0,  // conform Intel Vol 3B, 21.4.2, Table 21-4

   .Ia32Pat = 0,

   // Mandatory settings
   .LinkPointer = VMCS_LINK_POINTER_DEFAULT_VALUE,
   .SmBase = VMCS_SM_BASE_DEFAULT_ADDRESS,
   .Cr4 = CR4_VMXE
};

/** @name VMCS INITIALIZATION METHODS
 *
 */
///@{

/**
 *   @brief  Clears the Vmcs structure of the given vcpu along with the guest register values. Sets the vmcs revision.
 *
 *   @param[in]  Vcpu                           Pointer to the Vcpu structure containing the Vmcs needed to be initialized
 *
 *   @retval  CX_STATUS_SUCCESS                 Function succeeded to initialize the Vmcs structure, otherwise function failed
 */
static
CX_STATUS
_VmstateInitializeVmcsRegion(
    _In_ VCPU* Vcpu
)
{
    CX_STATUS status;

    // Initialize the new VMCS by clearing its fields and setting the revision value
    status = MmAlterRights(&gHvMm, Vcpu->Vmcs, PAGE_SIZE, MM_RIGHTS_RW);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAlterRights", status);
        return status;
    }
    // Clear the VMCS structure
    memzero(Vcpu->Vmcs, PAGE_SIZE);

    // Set VMCS revision
    *(CX_UINT32*)(Vcpu->Vmcs) = __readmsr(MSR_IA32_VMX_BASIC) & VMCS_REVISION_MASK;

    status = MmAlterRights(&gHvMm, Vcpu->Vmcs, PAGE_SIZE, MM_RIGHTS_RO);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmAlterRights", status);
        return status;
    }

    memzero(&Vcpu->VmcsConfig, sizeof(VMCS_CONFIG));

    return status;
}

///@}

/** @name VMCS GUEST STATE RELATED METHODS
 *
 */
///@{

/**
 *   @brief  Resets the given GuestState structure to the default guest real mode state.
 *
 *   @param[in,out]  GuestState                      Pointer to the CPUSTATE_GUEST_STATE_INFO structure to be modified.
 *   @param[in]      Cs                              Value of the Cs register in the guest state.
 *   @param[in]      Ip                              Value of the Ip register in the guest state.
 *   @param[in]      Ss                              Value of the Ss register in the guest state.
 *   @param[in]      Sp                              Value of the Sp register in the guest state.
 *   @param[in]      ActivityState                   The VMCS_GUEST_ACTIVITY_STATE_VALUE describing the activity state in which the guest will be launched/resumed.
 *   @param[in]      SingleStep                      True if single stepping is activated in some way, will set the trap flag
 *
 *   @retval  CX_STATUS_SUCCESS               Function succeeded to reset the structure.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1   GuestState is invalid.
 */
static
CX_STATUS
_VmstateSetGuestRealMode(
    _Inout_ CPUSTATE_GUEST_STATE_INFO *GuestState,
    _In_ CX_UINT16 Cs,
    _In_ CX_UINT16 Ip,
    _In_ CX_UINT16 Ss,
    _In_ CX_UINT16 Sp,
    _In_ VMCS_GUEST_ACTIVITY_STATE_VALUE  ActivityState,
    _In_ CX_BOOL SingleStep
)
{
    if (!GuestState) return CX_STATUS_INVALID_PARAMETER_1;

    memcpy(GuestState, &defaultBspRMCpuState, sizeof(CPUSTATE_GUEST_STATE_INFO));

    // EXPERIMENTAL
    GuestState->Dr7 = __readdr(7);

    // configurable values
    GuestState->Rsp = Sp;
    GuestState->Rip = Ip;
    GuestState->Cs = Cs;
    GuestState->Ss = Ss;

    // segment bases
    // memzero =>  BootState->DsBase = BootState->EsBase= ... = 0
    GuestState->CsBase = Cs * 16;
    GuestState->SsBase = Ss * 16;

    // msr and other special values
    // Q: it is right to take them from the host system? (will be set later by GUEST itself)
    GuestState->Ia32Debugctl = __readmsr(MSR_IA32_DEBUGCTL);
    GuestState->Ia32SysenterCs = (CX_UINT32)__readmsr(MSR_IA32_SYSENTER_CS);
    GuestState->Ia32SysenterEsp = __readmsr(MSR_IA32_SYSENTER_RSP);
    GuestState->Ia32SysenterEip = __readmsr(MSR_IA32_SYSENTER_RIP);
    GuestState->Ia32PerfGlobalCtrl = __readmsr(MSR_IA32_PERF_GLOBAL_CTRL);

    if (gBootInfo->CpuMap[0].IntelFeatures.Edx.PAT)
    {
        GuestState->Ia32Pat = __readmsr(MSR_IA32_PAT);
    }

    if (SingleStep)
    {
        GuestState->Rflags |= RFLAGS_TF;
    }

    GuestState->LapicId = HvGetInitialLocalApicIdFromCpuid();

    GuestState->ActivityState = ActivityState;


    GuestState->IsStructureInitialized = CX_TRUE;


    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Applies common flags/values required for the guest state to pass vmcs checks.
 *
 *   @param[in,out]  GuestState                      Pointer to the CPUSTATE_GUEST_STATE_INFO structure to be modified.
 *   @param[in]      IsGuestState64Bits              A VMCS_CONTROL_FEATURE_STATE enum controlling the Task Segment Limit used
 *
 *   @retval  CX_STATUS_SUCCESS               Function succeeded to update the structure.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1   GuestState is invalid.
 */
static
CX_STATUS
_VmstateSetRequiredVmcsGuestFields(
    _Inout_ CPUSTATE_GUEST_STATE_INFO *GuestState,
    _In_ VMCS_CONTROL_FEATURE_STATE IsGuestState64Bits
)
{
    if (!GuestState) return CX_STATUS_INVALID_PARAMETER_1;

    GuestState->SmBase = _VmcsGetSmBaseAddress();
    GuestState->Cr4 |= CR4_VMXE;
    GuestState->Cr0 |= CR0_NE;

    GuestState->LinkPointer = VMCS_LINK_POINTER_DEFAULT_VALUE;     // conform Intel Vol 3B, 21.4.2

    // If the guest hasn't set a TR, set a dummy one to pass VMCS validations
    if (!GuestState->Tr)
    {
        GuestState->Tr = 0;
        GuestState->TrBase = 0x0;
        GuestState->TrLimit = 0x2c;          // conform Intel Vol 3A, 7.6, "16-bit Task-State Segement"
        GuestState->TrAccessRights = 0x8b;   // type = BUSY 32-bit TSS

        if (IsGuestState64Bits == VMCS_CONTROL_FEATURE_ENABLE)
        {
            GuestState->TrLimit = 0x67;
        }

        LOG("Dummy tr: 0x%x, 0x%x, 0x%x, 0x%x\n", GuestState->Tr, GuestState->TrBase, GuestState->TrLimit, GuestState->TrAccessRights);
    }

    // everything done just fine
    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Retrieves the boot state saved at the beginning of the HV's boot for the given Vcpu.
 *
 *   @param[in]   Vcpu                           Pointer to a VCPU structure. The VCPU LapicId is used as the target for the searched boot state.
 *   @param[out]  BootState                      The found CPUSTATE_GUEST_STATE_INFO structure for the given Vcpu. CX_NULL if no matching structure found.
 *
 *   @retval  CX_STATUS_SUCCESS                   Function found the matching CPUSTATE_GUEST_STATE_INFO structure for the given
 *   @retval  CX_STATUS_NOT_FOUND                 No matching structure found.
 */
static
CX_STATUS
_VmstateRetrieveBootState(
    _In_ VCPU* Vcpu,
    _Out_ CPUSTATE_GUEST_STATE_INFO** BootState
)
{
    *BootState = CX_NULL;
    for (CX_UINT32 i = 0; i < CPUSTATE_MAX_GUEST_CPU_COUNT; i++)
    {
        if ((gBootState->BootVcpuState[i].IsStructureInitialized) &&
            (gBootState->BootVcpuState[i].LapicId == Vcpu->LapicId))
        {
            *BootState = &(gBootState->BootVcpuState[i]);
            return CX_STATUS_SUCCESS;
        }
    }

    return CX_STATUS_NOT_FOUND;
}

/**
 *   @brief  Sets a real mode boot state with the CS:IP adequately pointing at the beginning of the guest boot routine, mimicking legacy boot. APs are placed in HLT state.
 *
 *   @param[in]   Vcpu                           Pointer to a VCPU structure. Used to decide if the created guest state is BSP or AP.
 *   @param[out]  BootState                      The created CPUSTATE_GUEST_STATE_INFO structure.
 *
 *   @retval  CX_STATUS_SUCCESS                   The BootState was created successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1       The given Vcpu structure is invalid.
 *   @retval  otherwise                           The function failed.
 */
static
CX_STATUS
_VmstateCreateRealModeBootState(
    _In_ VCPU* Vcpu,
    _Out_ CPUSTATE_GUEST_STATE_INFO** BootState
)
{
    CX_STATUS status;
    CPUSTATE_GUEST_STATE_INFO* crtBootState;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    // As we're in a legacy BIOS environment, no VCPU states will actually be initialized
    crtBootState = &gBootState->BootVcpuState[gBootState->NumberOfInitializedEntries];

    if (Vcpu->IsBsp)
    {
        if (BOOT_MBR_PXE)
        {
            // Place the guest bsp in real mode. Set the CS:IP at the entry point address extracted from the MBR structure
            status = _VmstateSetGuestRealMode(
                crtBootState, 0,
                (CX_UINT16)(VMCS_DEFAULT_PXE_LOADED_BOOT_CODE_ADDRESS + (CX_SIZE_T)&__GuestPxeMbrLoaderEntry - (CX_SIZE_T)&__GuestPxeMbrLoaderCode),
                0, VMCS_DEFAULT_PXE_STACK_ADDRESS, VMCS_GUEST_ACTIVITY_STATE_ACTIVE, Vcpu->DebugContext.SingleStep
            );
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateSetGuestRealMode", status);
                return status;
            }

            LOG("Guest BSP is prepared to run the boot sector (PXE)\n");
        }
        else if (BOOT_MBR)
        {
            LD_NAPOCA_MODULE *module = NULL;
            LD_LEGACY_CUSTOM* legacyCustom = NULL;
            status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_LOADER_CUSTOM, &module);
            if (!CX_SUCCESS(status))
            {
                ERROR("Legacy MBR boot with missing LD_MODID_LOADER_CUSTOM module\n");
                return status;
            }
            legacyCustom = (LD_LEGACY_CUSTOM*)module->Va;

            status = LdGetModule(gBootModules, LD_MAX_MODULES, LD_MODID_ORIG_MBR, &module);
            if (!CX_SUCCESS(status))
            {
                ERROR("Legacy MBR boot with missing LD_MODID_ORIG_MBR module\n");
                return status;
            }

            // Move the boot sector to 0x7C00 to reproduce the actual boot state
            if (module->Pa != VMCS_DEFAULT_MBR_LOADED_BOOT_CODE_ADDRESS)
            {
                memcpy((PVOID)(SIZE_T)VMCS_DEFAULT_MBR_LOADED_BOOT_CODE_ADDRESS, (PVOID)(SIZE_T)module->Va, 0x200);     //check for overlapping buffers
            }

            // Create a guest state with CS:IP pointing at the default address for MBR loaded code
            // and a stack just behind that address
            status = _VmstateSetGuestRealMode(crtBootState, 0, VMCS_DEFAULT_MBR_LOADED_BOOT_CODE_ADDRESS,
                0, VMCS_DEFAULT_MBR_LOADED_BOOT_CODE_ADDRESS, VMCS_GUEST_ACTIVITY_STATE_ACTIVE, Vcpu->DebugContext.SingleStep);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateSetGuestRealMode", status);
                return status;
            }

            // Set the boot drive in dx
            crtBootState->Rdx = legacyCustom->BiosOsDrive.Drive;

            LOG("Guest BSP is prepared to run the boot sector (LEGACY) to boot from drive %02X\n", 0xFF & crtBootState->Rdx);
        }
    }
    // For APs, each one of them will be placed in real mode wait-for-sipi state in order to reproduce the actual initial state during a legacy boot
    else
    {
        status = _VmstateSetGuestRealMode(crtBootState, 0, 0x7E00, 0, 0x7B90, VMCS_GUEST_ACTIVITY_STATE_HLT, Vcpu->DebugContext.SingleStep);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateSetGuestRealMode", status);
            return status;
        }
    }

    crtBootState->LapicId = Vcpu->LapicId;
    gBootState->NumberOfInitializedEntries++;

    *BootState = crtBootState;
    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Populates a VCPU structure with the register values which will be loaded at guest launching.
 *
 *   @param[in]  Vcpu                           Pointer to a VCPU structure. Used to store the register values.
 *   @param[in]  GuestState                     The boot state which describe the guest register values.
 *
 *   @retval  CX_STATUS_SUCCESS                   The Vcpu structure was populated successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1       The given Vcpu structure is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_2       The given GuestState structure is invalid.
 */
static
CX_STATUS
_VmstateSetGuestStateRegisters(
    _In_ VCPU* Vcpu,
    _In_ CPUSTATE_GUEST_STATE_INFO* GuestState
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GuestState) return CX_STATUS_INVALID_PARAMETER_2;

    Vcpu->ArchRegs.CR8 = GuestState->Cr8;

    // links to cpu state data
    Vcpu->BootState = GuestState;

    // Set guest's control registers, debug register, flags, stack and instruction pointer
    Vcpu->ArchRegs.CR0 = GuestState->Cr0;
    Vcpu->ArchRegs.CR3 = GuestState->Cr3;
    Vcpu->ArchRegs.CR4 = GuestState->Cr4;
    Vcpu->ArchRegs.DR7 = GuestState->Dr7;
    Vcpu->ArchRegs.RFLAGS = GuestState->Rflags;
    Vcpu->ArchRegs.RSP = GuestState->Rsp;
    Vcpu->ArchRegs.RIP = GuestState->Rip;

    // Set guest's general use registers
    Vcpu->ArchRegs.RAX = GuestState->Rax;
    Vcpu->ArchRegs.RBX = GuestState->Rbx;
    Vcpu->ArchRegs.RBP = GuestState->Rbp;
    Vcpu->ArchRegs.RCX = GuestState->Rcx;
    Vcpu->ArchRegs.RDX = GuestState->Rdx;
    Vcpu->ArchRegs.RDI = GuestState->Rdi;
    Vcpu->ArchRegs.RSI = GuestState->Rsi;
    Vcpu->ArchRegs.R8 = GuestState->R8;
    Vcpu->ArchRegs.R9 = GuestState->R9;
    Vcpu->ArchRegs.R10 = GuestState->R10;
    Vcpu->ArchRegs.R11 = GuestState->R11;
    Vcpu->ArchRegs.R12 = GuestState->R12;
    Vcpu->ArchRegs.R13 = GuestState->R13;
    Vcpu->ArchRegs.R14 = GuestState->R14;
    Vcpu->ArchRegs.R15 = GuestState->R15;

    // setup SHADOW control registers and EFER
    Vcpu->ReadShadowCR0 = Vcpu->ArchRegs.CR0;
    Vcpu->GuestHostMaskCR0 = CR0_PG | CR0_CD | CR0_PE | CR0_NE;        // shadowed bits ('owned' by HOST)
    Vcpu->ReadShadowCR4 = Vcpu->ArchRegs.CR4;
    Vcpu->GuestHostMaskCR4 = CR4_VMXE |
        CR4_PAE |
        CR4_PSE |
        (CpuHasSmep() ? CR4_SMEP : 0) |
        (CpuHasSmap() ? CR4_SMAP : 0);     // shadowed bits ('owned' by HOST). Modifications
                                                  // of these bits inside the guest will cause a
                                                  // VMEXIT.

    // Setup IDTR/GDTR info per VCPU.
    Vcpu->ArchRegs.IdtrBase = GuestState->IdtrBase;
    Vcpu->ArchRegs.IdtrLimit = (CX_UINT16)GuestState->IdtrLimit;
    Vcpu->ArchRegs.GdtrBase = GuestState->GdtrBase;
    Vcpu->ArchRegs.GdtrLimit = (CX_UINT16)GuestState->GdtrLimit;

    // everything done just fine
    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Decides the guest state created for further use by the main logic based on the provided Options.
 *
 *   @param[in]   Vcpu                            Pointer to a VCPU structure.
 *   @param[in]   Options                         VMCS_GUEST_OPTIONS structure. Provide by API client used to decide the created guest state.
 *   @param[in]   Config                          Pointer to a VMCS_GUEST_CONFIGURATION structure. Used to pass specific guest state values.
 *   @param[out]  GuestState                      The created guest state.
 *   @param[out]  Is64BitMode                     Indicates if the guest is in IA32e mode or not. Used further by the main logic.
 *
 *   @retval  CX_STATUS_SUCCESS                   The GuestState structure was created successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1       The given Vcpu structure is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_3       The given Config structure is not suitable for the requested guest options.
 *   @retval  CX_STATUS_INVALID_PARAMETER_4       The GuestState pointer is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_5       The Is64BitMode pointer is invalid.
 *   @retval  CX_STATUS_UNSUPPORTED_DATA_VALUE    An unknown guest option was requested.
 *   @retval  otherwise                           The function failed.
 */
static
CX_STATUS
_VmstatePrepareGuestStructure(
    _In_ VCPU* Vcpu,
    _In_ VMCS_GUEST_OPTIONS Options,
    _In_ VMCS_GUEST_CONFIGURATION *Config,
    _Out_ CPUSTATE_GUEST_STATE_INFO** GuestState,
    _Out_ VMCS_CONTROL_FEATURE_STATE* Is64BitMode
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CPUSTATE_GUEST_STATE_INFO* guestState = CX_NULL;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Config && (Options == VMCS_GUEST_REAL_MODE)) return CX_STATUS_INVALID_PARAMETER_3;
    if (!GuestState) return CX_STATUS_INVALID_PARAMETER_4;
    if (!Is64BitMode) return CX_STATUS_INVALID_PARAMETER_5;

    if (Options == VMCS_GUEST_BOOT_STATE)
    {
        if (BOOT_UEFI)
        {
            status = _VmstateRetrieveBootState(Vcpu, &guestState);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateRetrieveBootState", status);
                return status;
            }

            guestState->CsLimit = 0xffffffff;
            guestState->SsLimit = 0xffffffff;
            guestState->DsLimit = 0xffffffff;
            guestState->EsLimit = 0xffffffff;

            *Is64BitMode = VMCS_CONTROL_FEATURE_ENABLE;
        }
        else
        {
            status = _VmstateCreateRealModeBootState(Vcpu, &guestState);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateCreateRealModeBootState", status);
                return status;
            }
            *Is64BitMode = VMCS_CONTROL_FEATURE_DISABLE;
        }
    }
    else if (Options == VMCS_GUEST_REAL_MODE)
    {
        status = _VmstateSetGuestRealMode(Vcpu->BootState, Config->RealModeState.Cs, Config->RealModeState.Ip,
            Config->RealModeState.Sp, Config->RealModeState.Ss, Config->RealModeState.ActivityState, Vcpu->DebugContext.SingleStep);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateSetGuestRealMode", status);
            return status;
        }

        guestState = Vcpu->BootState;

        *Is64BitMode = VMCS_CONTROL_FEATURE_DISABLE;
    }
    else
    {
        ERROR("Unknown guest state option\n");
        return CX_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    *GuestState = guestState;
    return status;
}

/**
 *   @brief  Effectively loads the guest state into the vmcs structure.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *   @param[in]   GuestState                        Pointer to a CPUSTATE_GUEST_STATE_INFO structure. Contains the data loaded in the VMCS.
 *
 *   @retval  CX_STATUS_SUCCESS                     The GuestState structure was flushed successfully into vmcs.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu structure is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_2         The given GuestState structure is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmwrite instruction failed.
 *   @retval  CX_STATUS_INVALID_INTERNAL_STATE      The CR0_CD bit in CR0 MASK is not set.
 */
static
CX_STATUS
_VmstateFlushGuestStateToVmcs(
    _In_ VCPU *Vcpu,
    _In_ CPUSTATE_GUEST_STATE_INFO *GuestState
)
{

    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_UINT32 apicId;

    apicId = HvGetCurrentApicId();

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GuestState) return CX_STATUS_INVALID_PARAMETER_2;

    // activity state
    if (vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GuestState->ActivityState))    // conform Intel Vol 3B, 21.4.2
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);

        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    // EFER MSR
    if (vmx_vmwrite(VMCS_GUEST_IA32_EFER, GuestState->Ia32Efer))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    // write CR0 and CR4 shadows to VMCS, conform Intel Vol 3B, 21.6.6
    // We make sure that we do not allow the changes on the Cache Disable bit
    // to execute bare metal but only within the guest
    if (!(Vcpu->GuestHostMaskCR0 & CR0_CD))
    {
        LOG("ERROR: VMCS_GUEST_CR0_MASK has NO CR0.CD set, so CR0.CD will be guest owned !!!!\n");
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }

    if ((vmx_vmwrite(VMCS_GUEST_CR0_MASK, Vcpu->GuestHostMaskCR0)) ||
        (vmx_vmwrite(VMCS_GUEST_CR0_READ_SHADOW, Vcpu->ReadShadowCR0)) ||
        (vmx_vmwrite(VMCS_GUEST_CR4_MASK, Vcpu->GuestHostMaskCR4)) ||
        (vmx_vmwrite(VMCS_GUEST_CR4_READ_SHADOW, Vcpu->ReadShadowCR4)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    // CS, SS, DS, ES, FS, GS, TR, LDTR selectors and base addresses; GDTR, IDTR base addresses
    if ((vmx_vmwrite(VMCS_GUEST_CS, GuestState->Cs)) ||
        (vmx_vmwrite(VMCS_GUEST_CS_BASE, GuestState->CsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_CS_LIMIT, GuestState->CsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, GuestState->CsAccessRights)) ||      // conform Intel Vol 3B, 21.4.1, Table 21-1; see also GDT initialization above
        (vmx_vmwrite(VMCS_GUEST_SS, GuestState->Ss)) ||
        (vmx_vmwrite(VMCS_GUEST_SS_BASE, GuestState->SsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_SS_LIMIT, GuestState->SsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, GuestState->SsAccessRights)) ||
        (vmx_vmwrite(VMCS_GUEST_DS, GuestState->Ds)) ||
        (vmx_vmwrite(VMCS_GUEST_DS_BASE, GuestState->DsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_DS_LIMIT, GuestState->DsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, GuestState->DsAccessRights)) ||
        (vmx_vmwrite(VMCS_GUEST_ES, GuestState->Es)) ||
        (vmx_vmwrite(VMCS_GUEST_ES_BASE, GuestState->EsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_ES_LIMIT, GuestState->EsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, GuestState->EsAccessRights)) ||
        (vmx_vmwrite(VMCS_GUEST_FS, GuestState->Fs)) ||
        (vmx_vmwrite(VMCS_GUEST_FS_BASE, GuestState->FsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_FS_LIMIT, GuestState->FsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, GuestState->FsAccessRights)) ||
        (vmx_vmwrite(VMCS_GUEST_GS, GuestState->Gs)) ||
        (vmx_vmwrite(VMCS_GUEST_GS_BASE, GuestState->GsBase)) ||
        (vmx_vmwrite(VMCS_GUEST_GS_LIMIT, GuestState->GsLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, GuestState->GsAccessRights)) ||
        (vmx_vmwrite(VMCS_GUEST_TR, GuestState->Tr)) ||
        (vmx_vmwrite(VMCS_GUEST_TR_BASE, GuestState->TrBase)) ||
        (vmx_vmwrite(VMCS_GUEST_TR_LIMIT, GuestState->TrLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, GuestState->TrAccessRights)) ||      // type = BUSY 64-bit TSS
        (vmx_vmwrite(VMCS_GUEST_LDTR, GuestState->Ldtr)) ||
        (vmx_vmwrite(VMCS_GUEST_LDTR_BASE, GuestState->LdtrBase)) ||
        (vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, GuestState->LdtrLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, GuestState->LdtrAccessRights)) ||    // type = LDT
        (vmx_vmwrite(VMCS_GUEST_GDTR_BASE, GuestState->GdtrBase)) ||
        (vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, GuestState->GdtrLimit)) ||
        (vmx_vmwrite(VMCS_GUEST_IDTR_BASE, GuestState->IdtrBase)) ||
        (vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, GuestState->IdtrLimit)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    // write also ARCH regs to VMCS
    // NOTE: this is for debugging only, as this will also be written on each VCPU load
    if ((vmx_vmwrite(VMCS_GUEST_CR0, Vcpu->ArchRegs.CR0)) ||
        (vmx_vmwrite(VMCS_GUEST_CR3, Vcpu->ArchRegs.CR3)) ||
        (vmx_vmwrite(VMCS_GUEST_CR4, Vcpu->ArchRegs.CR4)) ||
        (vmx_vmwrite(VMCS_GUEST_DR7, Vcpu->ArchRegs.DR7)) ||
        (vmx_vmwrite(VMCS_GUEST_RSP, Vcpu->ArchRegs.RSP)) ||
        (vmx_vmwrite(VMCS_GUEST_RIP, Vcpu->ArchRegs.RIP)) ||
        (vmx_vmwrite(VMCS_GUEST_RFLAGS, Vcpu->ArchRegs.RFLAGS)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    // write special fields also
    if ((vmx_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, GuestState->Ia32Debugctl)) ||
        (vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, GuestState->Ia32SysenterCs)) ||
        (vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_RSP, GuestState->Ia32SysenterEsp)) ||
        (vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_RIP, GuestState->Ia32SysenterEip)) ||
        (vmx_vmwrite(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, GuestState->Ia32PerfGlobalCtrl)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

    if (vmx_vmwrite(VMCS_GUEST_SMBASE, GuestState->SmBase))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
    }

    if (gBootInfo->CpuMap[0].IntelFeatures.Edx.PAT)
    {
        if (vmx_vmwrite(VMCS_GUEST_IA32_PAT, GuestState->Ia32Pat))
        {
            ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
            status = CX_STATUS_INVALID_DATA_STATE;
            goto cleanup;
        }
    }

    // GUEST non-register state: VMCS link pointer, interruptibility state, pending debug exceptions
    if ((vmx_vmwrite(VMCS_GUEST_LINK_POINTER, GuestState->LinkPointer)) ||             // conform Intel Vol 3B, 21.4.2
        (vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, GuestState->InterruptibilityState)) ||   // conform Intel Vol 3B, 21.4.2, Table 21-3
        (vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, GuestState->PendingDebugExceptions)))   // conform Intel Vol 3B, 21.4.2, Table 21-4
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        goto cleanup;
    }

cleanup:

    return status;
}
///@}

/** @name VMCS HOST STATE RELATED METHODS
 *
 */
///@{

/**
 *   @brief  Writes the current HV registers/msr values in the vmcs host state.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *
 *   @retval  CX_STATUS_SUCCESS                     The host state was initialized successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu structure is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmwrite instruction failed.
 */
static
CX_STATUS
_VmstatePrepareHostState(
    _In_ VCPU* Vcpu
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_UINT32 apicId;
    PCPU* cpu;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    apicId = HvGetCurrentApicId();
    cpu = HvGetCurrentCpu();

    if (!gHypervisorGlobalData.BootFlags.IsWakeup)
    {
        Vcpu->Pcpu = cpu;
        cpu->Vcpu = Vcpu;
    }

    // CR0, CR3, CR4, RSP, RIP
    if ((vmx_vmwrite(VMCS_HOST_CR0, __readcr0())) ||
        (vmx_vmwrite(VMCS_HOST_CR3, __readcr3())) ||
        (vmx_vmwrite(VMCS_HOST_CR4, __readcr4())) ||
        (vmx_vmwrite(VMCS_HOST_RSP, cpu->TopOfStack)) ||  // TopOfStack accounts for the 0x20 hime registers space (it's 0x20 lower than the actual limit)
        (vmx_vmwrite(VMCS_HOST_RIP, (size_t)&HvVmxHandleVmExitAsm)))
    {
        ERROR("[CPU %d] _vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        return status;
    }

    // CS, SS, DS, ES, FS, GS, TR selectors, FS, GS, TR, GDTR, IDTR base addresses
    {
        if ((vmx_vmwrite(VMCS_HOST_CS, (CX_UINT32)CpuGetCS())) ||
            (vmx_vmwrite(VMCS_HOST_SS, (CX_UINT32)CpuGetSS())) ||
            (vmx_vmwrite(VMCS_HOST_DS, (CX_UINT32)CpuGetDS())) ||
            (vmx_vmwrite(VMCS_HOST_ES, (CX_UINT32)CpuGetES())) ||
            (vmx_vmwrite(VMCS_HOST_FS, (CX_UINT32)CpuGetFS())) ||
            (vmx_vmwrite(VMCS_HOST_FS_BASE, 0x0ULL)) ||
            (vmx_vmwrite(VMCS_HOST_GS, (CX_UINT32)CpuGetGS())) ||
            (vmx_vmwrite(VMCS_HOST_GS_BASE, (CX_UINT64)(cpu))) ||
            (vmx_vmwrite(VMCS_HOST_TR, (CX_UINT32)CpuGetTR())) ||
            (vmx_vmwrite(VMCS_HOST_TR_BASE, (CX_UINT64)cpu->MemoryResources.IdtGdtTss->Tss)) ||
            (vmx_vmwrite(VMCS_HOST_GDTR_BASE, (CX_UINT64)cpu->MemoryResources.IdtGdtTss->Gdt)) ||
            (vmx_vmwrite(VMCS_HOST_IDTR_BASE, (CX_UINT64)cpu->MemoryResources.IdtGdtTss->Idt)))
        {
            ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
            status = CX_STATUS_INVALID_DATA_STATE;
            return status;
        }
    }

    // IA32_SYSENTER_CS, IA32_SYSENTER_RSP, IA32_SYSENTER_EIP,
    // IA32_PERF_GLOBAL_CTRL, IA32_PAT, IA32_EFER
    if ((vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_CS, (CX_UINT32)__readmsr(MSR_IA32_SYSENTER_CS))) ||
        (vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_RSP, __readmsr(MSR_IA32_SYSENTER_RSP))) ||
        (vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_RIP, __readmsr(MSR_IA32_SYSENTER_RIP))) ||
        (vmx_vmwrite(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, __readmsr(MSR_IA32_PERF_GLOBAL_CTRL))) ||
        (vmx_vmwrite(VMCS_HOST_IA32_EFER, __readmsr(MSR_IA32_EFER))))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        status = CX_STATUS_INVALID_DATA_STATE;
        return status;
    }

    if (gBootInfo->CpuMap[0].IntelFeatures.Edx.PAT)
    {
        if (vmx_vmwrite(VMCS_HOST_IA32_PAT, __readmsr(MSR_IA32_PAT)))
        {
            ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
            status = CX_STATUS_INVALID_DATA_STATE;
            return status;
        }
    }

    return status;
}
///@}

/** @name VMCS CONTROL FIELDS STATE RELATED METHODS
 *
 */
///@{

/**
 *   @brief  Applies global values to the vmcs control fields. The resulting state of the control fields is the 'default' one.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *
 *   @retval  CX_STATUS_SUCCESS                     The vmcs control fields set to default values succeeded.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 */
static
CX_STATUS
_VmstateResetControlStructure(
    _In_ VCPU *Vcpu
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    Vcpu->VmcsConfig.PinExecCtrl = VMCS_PIN_EXEC_CTRL_DEFAULT
        | ((CfgFeaturesNmiPerformanceCounterTicksPerSecond) || (VmxIsVmfuncAvailable() && VmxIsVeAvailable()) ? VMCSFLAG_PINEXEC_NMI : 0)
        | (((CfgFeaturesNmiPerformanceCounterTicksPerSecond) || (VmxIsVmfuncAvailable() && VmxIsVeAvailable())) ? VMCSFLAG_PINEXEC_VIRTUAL_NMIS : 0)
        | VMCSFLAG_PINEXEC_PREEMPTION_TIMER * (((gVirtFeatures.VmxPinBased.Raw >> 32)& VMCSFLAG_PINEXEC_PREEMPTION_TIMER) != 0);

    Vcpu->VmcsConfig.ProcExecCtrl = VMCS_PROC_EXEC_CTRL_DEFAULT
        | (VMCSFLAG_PROCEXEC_USE_TSC_OFFSETTING * (CfgFeaturesVirtualizationTscOffsetting != 0))
        | (VMCSFLAG_PROCEXEC_RDTSC_EXIT * (CfgFeaturesVirtualizationTscExit != 0))
        | (CfgFeaturesVirtualizationMonitorGuestActivityStateChanges ? VMCSFLAG_PROCEXEC_HLT_EXIT : 0);

    Vcpu->VmcsConfig.ProcExecCtrl2 = VMCS_PROC_EXEC_CTRL_2_DEFAULT
        | VMCSFLAG_PROCEXEC2_ENABLE_VPID * VmxIsInvVpidSupported()
        | VMCSFLAG_PROCEXEC2_ENABLE_XSAVES_XRSTORS * VmxIsEnableXsavesXrstorsAvailable()
        | VMCSFLAG_PROCEXEC2_CONCEAL_VMX_FROM_PT * VmxIsConcealVmxFromPtAvailable()
        // If we'll decide at one time to use different VPIDs we'll also have to exit on INVPCID to perform the invalidation for all VPIDs
        | VMCSFLAG_PROCEXEC2_INVPCID_ENABLE * VmxIsEnableInvpcidAvailable();

    Vcpu->VmcsConfig.VmExitCtrl = VMCS_VM_EXIT_CTRL_DEFAULT
        | (VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS * (((gVirtFeatures.VmxExit.VmxExitRaw >> 32)& VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS) != 0))
        | (VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST * (((gVirtFeatures.VmxExit.VmxExitRaw >> 32)& VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST) != 0))
        | (VMCSFLAG_VMEXIT_SAVE_TIMER * (((gVirtFeatures.VmxExit.VmxExitRaw >> 32)& VMCSFLAG_VMEXIT_SAVE_TIMER) != 0))
        | (VMCSFLAG_VMEXIT_CONCEAL_VMEXITS_FROM_PT * (((gVirtFeatures.VmxExit.VmxExitRaw >> 32)& VMCSFLAG_VMEXIT_CONCEAL_VMEXITS_FROM_PT) != 0));

    Vcpu->VmcsConfig.VmEntryCtrl = VMCS_VM_ENTRY_CTRL_DEFAULT
        | (VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS * (((gVirtFeatures.VmxEntry.VmxEntryRaw >> 32)& VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS) != 0))
        | (VMCSFLAG_VMENTRY_CONCEAL_VMENTRIES_FROM_PT * (((gVirtFeatures.VmxEntry.VmxEntryRaw >> 32)& VMCSFLAG_VMENTRY_CONCEAL_VMENTRIES_FROM_PT) != 0));

    if (VmxIsVmfuncAvailable())
    {
        Vcpu->VmcsConfig.VmfuncCtrl = VMCSFLAG_VMFUNC_EPTP_SWITCHING;
    }

    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Reset the vmcs control fields related structures to their default values.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *
 *   @retval  CX_STATUS_SUCCESS                     The vmcs control fields related structures have been reset successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmwrite instruction failed.
 *   @retval  CX_STATUS_UNSUPPORTED_DATA_VALUE      EPTP cannot be set due to machine hardware restrictions.
 */
static
CX_STATUS
_VmstateResetControlFieldsRelatedStructures(
    _In_ VCPU* Vcpu
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    CX_UINT32 apicId;
    GUEST* guest;
    int ret;

    guest = Vcpu->Guest;
    apicId = HvGetCurrentApicId();


    // Setup the requested features according to the VmcsConfig value

    // Preemption timer
    if (Vcpu->VmcsConfig.PinExecCtrl & VMCSFLAG_PINEXEC_PREEMPTION_TIMER)
    {
        CX_UINT64 vmxTimerRate = 0, vmxTimerPerSec = 0;

        // The timer counts down by 1 every time bit X in the TSC changes due to a TSC increment. The value of X is in the
        // range 0-31 and can be determined by consulting the VMX capability MSR IA32_VMX_MISC
        vmxTimerRate = __readmsr(MSR_IA32_VMX_MISC) & 0x1FULL;      // bits 4-0
        vmxTimerPerSec = (gTscSpeed >> vmxTimerRate);               // conform Intel Vol 3B, 22.7.1, second paragraph

        // Compute the time quanta required
        Vcpu->VmxTimerQuantum = ((3600 * vmxTimerPerSec) / CfgFeaturesVirtualizationPreemptionTimerExitsPerHour);

        // Bsp will exit at least once a second
        if (Vcpu->IsBsp)
        {
            Vcpu->VmxTimerQuantum = MIN(vmxTimerPerSec, Vcpu->VmxTimerQuantum);
        }
        // Ensure we don't overflow the APs timer quanta
        else
        {
            Vcpu->VmxTimerQuantum = MIN(CX_UINT32_MAX_VALUE, Vcpu->VmxTimerQuantum);
        }

        LOG("[CPU Id %d] INFO: TSC SPEED %zd/sec,  VMX TIMER X RATE %zd BIT,  VMX SPEED %zd/sec, VMX Timer Quantum %zd Exits every %f seconds\n",
            apicId, gTscSpeed, vmxTimerRate, vmxTimerPerSec, Vcpu->VmxTimerQuantum, (Vcpu->VmxTimerQuantum / (float)vmxTimerPerSec));

        // Set the timer quanta
        ret = vmx_vmwrite(VMCS_VMX_PREEMPTION_TIMER, (CX_UINT32)Vcpu->VmxTimerQuantum);
        if (ret)
        {
            ERROR("[CPU %d] vmx_vmwrite failed, ret = %d\n", apicId, ret);
            return CX_STATUS_INVALID_DATA_STATE;
        }
    }

    // APIC Accesses
    if (Vcpu->VmcsConfig.ProcExecCtrl2 & VMCSFLAG_PROCEXEC2_VIRTUALIZE_APIC_ACCESSES)
    {
        CX_UINT64 lapicBasePa = LapicGetPa();
        LOG("Using VIRTUALIZE_APIC_ACCESS, will write ApicAccessAddr = %p\n", lapicBasePa);

        // Set the APIC access address to the default APIC page address.
        if (vmx_vmwrite(VMCS_APIC_ACCESS_ADDR, (CX_SIZE_T)lapicBasePa))
        {
            ERROR("[CPU %d] ERROR: vmx_vmwrite failed\n", apicId);
            return CX_STATUS_INVALID_DATA_STATE;
        }
    }

    // TPR Threshold
    if (Vcpu->VmcsConfig.ProcExecCtrl & VMCSFLAG_PROCEXEC_USE_TPR_SHADOW)
    {
        CX_UINT64 lapicBasePa = LapicGetPa();
        LOG("Using TPR_SHADOW, will write VirtualApicAddr = %p\n", lapicBasePa);

        if ((vmx_vmwrite(VMCS_TPR_THRESHOLD, 0)) || (vmx_vmwrite(VMCS_VIRTUAL_APIC_ADDR, (CX_SIZE_T)lapicBasePa)))
        {
            ERROR("[CPU %d] ERROR: vmx_vmwrite failed\n", apicId);
            return CX_STATUS_INVALID_DATA_STATE;
        }
    }

    // MSR and IO bitmaps
    if ((vmx_vmwrite(VMCS_IO_BITMAP_A, guest->IoBitmapPa)) ||
        (vmx_vmwrite(VMCS_IO_BITMAP_B, guest->IoBitmapPa + PAGE_SIZE)) ||
        (vmx_vmwrite(VMCS_MSR_BITMAP, guest->MsrBitmapPa)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        return CX_STATUS_INVALID_DATA_STATE;
    }

    // Set default values for entering the guest:
    if ((vmx_vmwrite(VMCS_VM_ENTRY_EVENT_INJECTION, 0)) ||
        (vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE, 0)) ||
        (vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LENGTH, 0)) ||
        (vmx_vmwrite(VMCS_EXCEPTION_BITMAP, VMCS_VCPU_INTERCEPTED_EXCEPTIONS_BITMAP)) ||  // PF #14 + DB #02 only, special case
        (vmx_vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MASK, 0x00000000)) ||    // conform vol 3B, 22.3, "Other causes of VM exits"
        (vmx_vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, 0xffffffff)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        return CX_STATUS_INVALID_DATA_STATE;
    }

    // CR3 target count - disable CR3 target values
    if ((vmx_vmwrite(VMCS_CR3_TARGET_COUNT, 0)) ||
        (vmx_vmwrite(VMCS_CR3_TARGET_VALUE_0, 0xFFFFFFFFFFFFFFFFULL)) ||
        (vmx_vmwrite(VMCS_CR3_TARGET_VALUE_1, 0xFFFFFFFFFFFFFFFFULL)) ||
        (vmx_vmwrite(VMCS_CR3_TARGET_VALUE_2, 0xFFFFFFFFFFFFFFFFULL)) ||
        (vmx_vmwrite(VMCS_CR3_TARGET_VALUE_3, 0xFFFFFFFFFFFFFFFFULL)))
    {
        ERROR("[CPU %d] vmx_vmwrite failed\n", apicId);
        return CX_STATUS_INVALID_DATA_STATE;
    }

    // tsc offseting initially set to 0
    vmx_vmwrite(VMCS_TSC_OFFSET, 0);

    //
    // check out also Vol 3B, Chapter 25, "VMX Support for Address Translations"
    //
    // set VPID (16 bit VPID, from GUEST INDEX + CPU INDEX), conform Intel Vol 3B, 21.6.12, "Virtual-Processor Identifier (VPID)"
    // we use GuestIndex + 1 (1-based guest numbering) because VPID 0x0000 is reserved
    //

    // Set Vcpu's VPID
    if (Vcpu->VmcsConfig.ProcExecCtrl2 & VMCSFLAG_PROCEXEC2_ENABLE_VPID)
    {
        Vcpu->Vpid = (CX_UINT16)((((Vcpu->GuestIndex + 1) & 0xFF) << 8));
    }
    else
    {
        Vcpu->Vpid = 0;
    }

    ret = vmx_vmwrite(VMCS_VPID, Vcpu->Vpid);
    if (ret)
    {
        ERROR("[CPU %d] vmx_vmwrite failed, ret = %d\n", apicId, ret);
        return CX_STATUS_INVALID_DATA_STATE;
    }

    // set EPTP (Extended Page Table Pointer), conform Intel Vol 3B, 21.6.11, "Extended-Page-Table Pointer (EPTP)"
    if (Vcpu->VmcsConfig.ProcExecCtrl & VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2)
    {
        // NOTE: we support only page-walk length 4 and WB (6) memory for EPT
        if (!VmxIsEptPageWalkLength4Available())
        {
            ERROR("[CPU %d] VMX CAPS does NOT support page-walk length 4, MSR_IA32_VMX_EPT_VPID_CAP = 0x%08x\n",
                apicId, (CX_UINT32)gVirtFeatures.EptVpidFeatures.Raw);
            return CX_STATUS_UNSUPPORTED_DATA_VALUE;
        }
        if (!VmxIsEptWBSupportAvailable())
        {
            ERROR("[CPU %d] VMX CAPS does NOT support WB memory, MSR_IA32_VMX_EPT_VPID_CAP = 0x%08x\n",
                apicId, (CX_UINT32)gVirtFeatures.EptVpidFeatures.Raw);
            return CX_STATUS_UNSUPPORTED_DATA_VALUE;
        }
    }

    // Set the EPTP pointers page, if VMFUNC support is present and activated.
    if (VmxIsVmfuncAvailable())
    {
        // Store the address of the page in VMCS.
        ret = vmx_vmwrite(VMCS_EPTP_LIST_ADDRESS, Vcpu->Guest->EptpPagePa);
        if (ret)
        {
            ERROR("[CPU %d] vmx_vmwrite failed, ret = %d\n", apicId, ret);
            return CX_STATUS_INVALID_DATA_STATE;
        }
    }

    // Ensure XSAVES/XRSTORS don't generate VMexits.
    if (VmxIsEnableXsavesXrstorsAvailable())
    {
        LOG("Using Enable XSAVES/XRSTORS, setting up XSS bitmap to 0\n");

        // XRSTORS causes a VM exit if any bit is set in the logical-AND of the following three values: EDX:EAX,
        // the IA32_XSS MSR, and the XSS - exiting bitmap
        ret = vmx_vmwrite(VMCS_XSS_EXIT_BITMAP, 0);
        if (ret)
        {
            ERROR("[CPU %d] vmx_vmwrite failed, ret = %d\n", apicId, ret);
            return CX_STATUS_INVALID_DATA_STATE;
        }
    }

    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Applies custom features based on the given VMCS_CONTROL_FEATURE_CONFIGURATION structure.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *   @param[in]   Config                            VMCS_CONTROL_FEATURE_CONFIGURATION structure which determines the required controls to be enabled/disabled.
 *   @param[in]   IsGuestState64Bits                VMCS_CONTROL_FEATURE_STATE value denoting the state of the vmcs guest configuration.
 *
 *   @retval  CX_STATUS_SUCCESS                     The control fields have been updated successfully.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 */
static
CX_STATUS
_VmstateSetCustomControlFeatures(
    _In_ VCPU *Vcpu,
    _In_ VMCS_CONTROL_FEATURE_CONFIGURATION Config,
    _In_ VMCS_CONTROL_FEATURE_STATE IsGuestState64Bits
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    if (Config.FeatureExitOnHalt == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl |= VMCSFLAG_PROCEXEC_HLT_EXIT;
    }
    else if (Config.FeatureExitOnHalt == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl &= ~VMCSFLAG_PROCEXEC_HLT_EXIT;
    }

    if (Config.FeatureExitAllIoPorts == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl |= VMCSFLAG_PROCEXEC_UNCONDITIONAL_IO_EXIT;

        // We MUST remove the USE_IO_BITMAPS flag when using UNCONDITIONAL_IO_EXIT, because otherwise the bitmaps will be used!
        Vcpu->VmcsConfig.ProcExecCtrl &= ~VMCSFLAG_PROCEXEC_USE_IO_BITMAPS;
    }

    if (Config.FeatureExitAllMsrs == VMCS_CONTROL_FEATURE_ENABLE) Vcpu->VmcsConfig.ProcExecCtrl &= (~VMCSFLAG_PROCEXEC_USE_MSR_BITMAPS);

    if (Config.FeatureCr3LoadExit == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl |= VMCSFLAG_PROCEXEC_CR3_LOAD_EXIT;
    }
    else if (Config.FeatureCr3LoadExit == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl &= ~VMCSFLAG_PROCEXEC_CR3_LOAD_EXIT;
    }

    if (Config.FeatureDescriptorExit == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl2 |= VMCSFLAG_PROCEXEC2_DESC_TABLE_EXIT;

    }
    else if (Config.FeatureDescriptorExit == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.ProcExecCtrl2 &= ~VMCSFLAG_PROCEXEC2_DESC_TABLE_EXIT;
    }

    if (Config.FeatureVeInfoPageSet != VMCS_CONTROL_FEATURE_NO_UPDATE)
    {
        if (vmx_vmwrite(VMCS_VE_INFORMATION_ADDRESS, Vcpu->VirtualizationException.InfoPageHpa))
        {
            ERROR("vmx_vmwrite failed\n");
        }

        if (Config.FeatureVeInfoPageSet == VMCS_CONTROL_FEATURE_ENABLE)
        {
            Vcpu->VmcsConfig.ProcExecCtrl2 |= (VMCSFLAG_PROCEXEC2_EPT_VE | VMCSFLAG_PROCEXEC2_VMFUNC_ENABLE);
        }
        else
        {
            Vcpu->VmcsConfig.ProcExecCtrl2 &= ~(VMCSFLAG_PROCEXEC2_EPT_VE | VMCSFLAG_PROCEXEC2_VMFUNC_ENABLE);
        }
    }

    if (Config.FeatureSpptp == VMCS_CONTROL_FEATURE_ENABLE)
    {
        VCPULOG(Vcpu, "Will write to SPPTP to %018p / %018p\n", Vcpu->Guest->SpptRootPa, Vcpu->Guest->SpptRootVa);
        if (vmx_vmwrite(VMCS_SPPTP, Vcpu->Guest->SpptRootPa))
        {
            ERROR("vmx_vmwrite failed\n");
        }

        Vcpu->VmcsConfig.ProcExecCtrl2 |= VMCSFLAG_PROCEXEC2_SPP;

        Vcpu->IsSppActive = TRUE;
    }

    // By default breakpoint exits are disabled
    if (Config.FeatureBreakpointExit == VMCS_CONTROL_FEATURE_ENABLE)
    {
        CX_UINT64 exceptionBitmap = 0;
        vmx_vmread(VMCS_EXCEPTION_BITMAP, &exceptionBitmap);
        exceptionBitmap |= (1 << 3);
        vmx_vmwrite(VMCS_EXCEPTION_BITMAP, exceptionBitmap);
    }
    else if (Config.FeatureBreakpointExit == VMCS_CONTROL_FEATURE_DISABLE)
    {
        CX_UINT64 exceptionBitmap = 0;
        vmx_vmread(VMCS_EXCEPTION_BITMAP, &exceptionBitmap);
        exceptionBitmap &= ~(1 << 3);
        vmx_vmwrite(VMCS_EXCEPTION_BITMAP, exceptionBitmap);
    }

    // By default preemption timer is activated, only disable it if specifically requested
    if (Config.PreemptionTimerEnableState == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.PinExecCtrl &= ~VMCSFLAG_PINEXEC_PREEMPTION_TIMER;
    }
    else if (Config.PreemptionTimerEnableState == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.PinExecCtrl |= VMCSFLAG_PINEXEC_PREEMPTION_TIMER;
    }

    // By default preemption timer is activated, only disable it if specifically requested
    if (Config.PreemptionTimerSaveState == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.VmExitCtrl &= ~VMCSFLAG_VMEXIT_SAVE_TIMER;
    }
    else if (Config.PreemptionTimerSaveState == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.PinExecCtrl |= VMCSFLAG_VMEXIT_SAVE_TIMER;
    }

    if (IsGuestState64Bits == VMCS_CONTROL_FEATURE_ENABLE)
    {
        Vcpu->VmcsConfig.VmEntryCtrl |= VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA;
    }
    else if (IsGuestState64Bits == VMCS_CONTROL_FEATURE_DISABLE)
    {
        Vcpu->VmcsConfig.VmEntryCtrl &= ~VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA;
    }

    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Sets the reserved bits in the vmcs control fields to the hardware required values in order to pass vmcs checks.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *
 *   @retval  CX_STATUS_SUCCESS                     The reserved bits have been set to their appropriate values.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 *   @retval  CX_STATUS_OPERATION_NOT_SUPPORTED     The machine does not support all requested PAT features.
 */
static
CX_STATUS
_VmstateApplyReservedBitsValues(
    _In_ VCPU *Vcpu
)
{
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    CX_UINT64 msrPinBasedSupport, msrProcBasedSupport, msrProcBasedSupport2, msrVmExitSupport, msrVmEntrySupport;
    CX_BOOL vmentryLoadPat1 = CX_FALSE, vmexitSavePat1 = CX_FALSE, vmexitLoadPat1 = CX_FALSE;
    CX_BOOL vmentryLoadPat2 = CX_FALSE, vmexitSavePat2 = CX_FALSE, vmexitLoadPat2 = CX_FALSE;
    CX_UINT64 msrVmfuncSupport = 0;
    CX_UINT64 msrBasicVmx;

    // apply default values from capability MSR's; check out Intel Vol 3B, 21.6, "All other bits in this..." like paragraphs after tables
    msrBasicVmx = __readmsr(MSR_IA32_VMX_BASIC);       // conform Intel Vol 3B, Appendix G.1, "Basic VMX Information"

    // Set the reserved bits to their appropriate values in order to ensure VM entry won't fail

    // If bit 55 of the IA32_VMX_BASIC MSR is read as 1, not all the default1 controls are reserved, and some(but not necessarily all) may be 0.
    // The CPU supports four(4) new VMX capability MSRs : IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS, IA32_VMX_TRUE_EXIT_CTLS, and IA32_VMX_TRUE_ENTRY_CTLS.
    if (msrBasicVmx & CX_BIT(55))
    {
        msrPinBasedSupport = __readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
        msrProcBasedSupport = __readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
        msrProcBasedSupport2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);         // this has NO 'TRUE' variant
        msrVmExitSupport = __readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
        msrVmEntrySupport = __readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    }
    else
    {
        msrPinBasedSupport = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
        msrProcBasedSupport = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
        msrProcBasedSupport2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
        msrVmExitSupport = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
        msrVmEntrySupport = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);
    }

    // If we support VMFUNC, read the VMFUNC capability MSR. If VMX_PROCBASED_CTLS_2 is not supported, we won't load!
    if (VmxIsVmfuncAvailable())
    {
        msrVmfuncSupport = __readmsr(MSR_IA32_VMFUNC);
    }

    if ((gVirtFeatures.VmxEntry.VmxEntryRaw >> 32)& VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS)
    {
        vmentryLoadPat1 = ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS) != 0);
        vmexitSavePat1 = ((Vcpu->VmcsConfig.VmExitCtrl & VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS) != 0);
        vmexitLoadPat1 = ((Vcpu->VmcsConfig.VmExitCtrl & VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST) != 0);
    }

    // 1 bit in LOW DWORD ==> must be 1 always (do |=) and
    // 0 bit in HIGH DWORD ==> must be 0 always (do &=)
    Vcpu->VmcsConfig.PinExecCtrl |= (CX_UINT32)msrPinBasedSupport;
    Vcpu->VmcsConfig.PinExecCtrl &= (CX_UINT32)(msrPinBasedSupport >> 32);
    Vcpu->VmcsConfig.ProcExecCtrl |= (CX_UINT32)msrProcBasedSupport;
    Vcpu->VmcsConfig.ProcExecCtrl &= (CX_UINT32)(msrProcBasedSupport >> 32);
    Vcpu->VmcsConfig.ProcExecCtrl2 |= (CX_UINT32)msrProcBasedSupport2;
    Vcpu->VmcsConfig.ProcExecCtrl2 &= (CX_UINT32)(msrProcBasedSupport2 >> 32);
    Vcpu->VmcsConfig.VmExitCtrl |= (CX_UINT32)msrVmExitSupport;
    Vcpu->VmcsConfig.VmExitCtrl &= (CX_UINT32)(msrVmExitSupport >> 32);
    Vcpu->VmcsConfig.VmEntryCtrl |= (CX_UINT32)msrVmEntrySupport;
    Vcpu->VmcsConfig.VmEntryCtrl &= (CX_UINT32)(msrVmEntrySupport >> 32);

    // This one's different: VM function X is supported if bit X inside MSR_IA32_VMFUNC is set.
    Vcpu->VmcsConfig.VmfuncCtrl &= (CX_UINT32)msrVmfuncSupport;

    if ((gVirtFeatures.VmxEntry.VmxEntryRaw >> 32)& VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS)
    {
        vmentryLoadPat2 = ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS) != 0);
        vmexitSavePat2 = ((Vcpu->VmcsConfig.VmExitCtrl & VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS) != 0);
        vmexitLoadPat2 = ((Vcpu->VmcsConfig.VmExitCtrl & VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST) != 0);

        if (vmentryLoadPat1 != vmentryLoadPat2)
        {
            ERROR("VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS not supported\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }

        if (vmexitSavePat1 != vmexitSavePat2)
        {
            ERROR("VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS not supported\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }

        if (vmexitLoadPat1 != vmexitLoadPat2)
        {
            ERROR("VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST not supported\n");
            return CX_STATUS_OPERATION_NOT_SUPPORTED;
        }
    }

    return CX_STATUS_SUCCESS;
}

/**
 *   @brief  Effectively loads the control fields into the vmcs structure.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *
 *   @retval  CX_STATUS_SUCCESS                     The control fields have successfully been flushed to vmcs.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmwrite instruction failed.
 */
static
CX_STATUS
_VmstateFlushControlFieldsToVmcs(
    _In_ VCPU *Vcpu
)
{
    int ret = 0;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    if (((ret = vmx_vmwrite(VMCS_PIN_BASED_EXEC_CONTROL, Vcpu->VmcsConfig.PinExecCtrl)) != 0) ||
        ((ret = vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL, Vcpu->VmcsConfig.ProcExecCtrl)) != 0) ||
        ((ret = vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL_2, Vcpu->VmcsConfig.ProcExecCtrl2)) != 0) ||
        ((ret = vmx_vmwrite(VMCS_VM_EXIT_CONTROL, Vcpu->VmcsConfig.VmExitCtrl)) != 0) ||
        ((ret = vmx_vmwrite(VMCS_VM_ENTRY_CONTROL, Vcpu->VmcsConfig.VmEntryCtrl)) != 0)
        )
    {
        ERROR("vmx_vmwrite failed, ret = 0x%x / %d\n", ret, ret);
        return CX_STATUS_INVALID_DATA_STATE;
    }

    if (VmxIsVmfuncAvailable())
    {
        if ((ret = vmx_vmwrite(VMCS_VMFUNC_CONTROL, Vcpu->VmcsConfig.VmfuncCtrl)) != 0)
        {
            ERROR("vmx_vmwrite failed, ret = 0x%x / %d\n", ret, ret);
            return CX_STATUS_INVALID_DATA_STATE;
        }

    }

    return CX_STATUS_SUCCESS;
}
///@}

/** @name VMCS APIs
 *
 */
///@{

/**
 *   @brief  Interface exposed by the algorithm for managing the configuration of a vmcs structure.
 *
 *   @param[in]   Vcpu                              Pointer to a VCPU structure.
 *   @param[in]   Options                           Pointer to a VMCS_CONFIGURE_SETTINGS structure. Used to guide the vmcs creation logic.
 *
 *   @retval  CX_STATUS_SUCCESS                     The control fields have successfully been flushed to vmcs.
 *   @retval  CX_STATUS_INVALID_PARAMETER_1         The given Vcpu pointer is invalid.
 *   @retval  CX_STATUS_INVALID_PARAMETER_2         The given Options pointer is invalid.
 *   @retval  CX_STATUS_INVALID_DATA_STATE          Vmclear or vmptrld instructions failed.
 *   @retval  otherwise                             The algorithm failed internally.
 */
CX_STATUS
VmstateConfigureVmcs(
    _In_ VCPU* Vcpu,
    _In_ VMCS_CONFIGURE_SETTINGS* Options
)
{
    CX_STATUS status = CX_STATUS_SUCCESS;
    VMCS_CONTROL_FEATURE_STATE isGuestState64Bits = VMCS_CONTROL_FEATURE_NO_UPDATE;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Options) return CX_STATUS_INVALID_PARAMETER_2;

    // Step I: Ensure the correct VMCS is loaded on the current CPU and, if required, clear all preexistent data within the VMCS.

    // Clear the current VMCS to ensure CPU's VMCS is in a known state. (Inactive, Not Current, Clear)
    if(Options->SetNewVmcs)
    {
        if (__vmx_vmclear(&Vcpu->VmcsPa)) return CX_STATUS_INVALID_DATA_STATE;
        Vcpu->State = VCPU_STATE_NOT_ACTIVE;
    }

    // Initialize the VMCS area: erase all data from the VMCS page, set the VMCS's revision and clear the guest registers.
    if (Options->InitVmcs)
    {
        status = _VmstateInitializeVmcsRegion(Vcpu);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_InitializeVmcsRegion", status);
            return status;
        }
    }

    // Set the current VMCS to the current CPU in order to further modify it.
    if(Options->SetNewVmcs)
    {
        if (__vmx_vmptrld(&Vcpu->VmcsPa)) return CX_STATUS_INVALID_DATA_STATE;
    }

    // Step II: if requested by the api client, change the state of the guest from the currently loaded VMCS
    if (Options->GuestOptions != VMCS_GUEST_NO_UPDATE)
    {
        CPUSTATE_GUEST_STATE_INFO* guestVmcsState = CX_NULL;

        // Create the new guest state based on the api client's request.
        status = _VmstatePrepareGuestStructure(
            Vcpu,
            Options->GuestOptions,
            &Options->GuestConfig,
            &guestVmcsState,
            &isGuestState64Bits
        );
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstatePrepareGuestStructure", status);
            return status;
        }

        // Ensure that the created guest state meets the requirements to pass VMCS checks
        status = _VmstateSetRequiredVmcsGuestFields(guestVmcsState, isGuestState64Bits);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateSetRequiredVmcsGuestFields", status);
            return status;
        }

        // Load the guest registers values with which the guest will be launched
        status = _VmstateSetGuestStateRegisters(Vcpu, guestVmcsState);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateSetGuestStateRegisters", status);
            return status;
        }

        // Load the guest VMCS fields
        status = _VmstateFlushGuestStateToVmcs(Vcpu,guestVmcsState);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateFlushGuestStateToVmcs", status);
            return status;
        }
    }

    // Step III: if requested by the api client, load the VMCS host fields with the current HV values.
    if (Options->HostOptions != VMCS_HOST_NO_UPDATE)
    {
        status = _VmstatePrepareHostState(Vcpu);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstatePrepareHostState", status);
            return status;
        }
    }

    // Step IV: if requested by the api client or required by the new guest state, change or update the VMCS control fields.
    if (Options->ControlsOptions != VMCS_CONTROLS_NO_UPDATE ||
        isGuestState64Bits != VMCS_CONTROL_FEATURE_NO_UPDATE)
    {
        // If requested by the api client, reset the VMCS control fields to their default values along with other related VMCS fields
        if (Options->ControlsOptions == VMCS_CONTROLS_RESET_ONLY ||
            Options->ControlsOptions == VMCS_CONTROLS_RESET_AND_CHANGES)
        {
            // Reinitialize counters
            if (Vcpu->VmcsConfig.ProcExecCtrl & VMCSFLAG_PROCEXEC_CR3_LOAD_EXIT) Vcpu->Cr3LoadExitEnabledCount = 1;

            if (Vcpu->VmcsConfig.ProcExecCtrl2 & VMCSFLAG_PROCEXEC2_DESC_TABLE_EXIT) Vcpu->DescTableExitEnabledCount = 1;

            // Reset default vmcs control fields values.
            status = _VmstateResetControlStructure(Vcpu);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateResetControlStructure", status);
                return status;
            }

            // Reset control-related fields in the VMCS based on the control field values.
            status = _VmstateResetControlFieldsRelatedStructures(Vcpu);
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateResetControlFieldsRelatedStructures", status);
                return status;
            }
        }

        // If requested by api client or required by the vmcs guest state, enable/disable custom control features.
        if (Options->ControlsOptions == VMCS_CONTROLS_APPLY_CHANGES_ONLY ||
            Options->ControlsOptions == VMCS_CONTROLS_RESET_AND_CHANGES ||
            isGuestState64Bits != VMCS_CONTROL_FEATURE_NO_UPDATE)
        {
            status = _VmstateSetCustomControlFeatures(
                Vcpu,
                Options->ControlsConfigState,
                isGuestState64Bits
            );
            if (!CX_SUCCESS(status))
            {
                LOG_FUNC_FAIL("_VmstateSetCustomControlFeatures", status);
                return status;
            }
        }

        // Ensure the current control field values meet the requirements to pass VMCS checks.
        status = _VmstateApplyReservedBitsValues(Vcpu);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateApplyReservedBitsValues", status);
            return status;
        }

        // Finally flush the control fields to VMCS.
        status = _VmstateFlushControlFieldsToVmcs(Vcpu);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_VmstateFlushControlFieldsToVmcs", status);
            return status;
        }
    }

    // Step V: if requested by api client, activate the ept domain.
    if (Options->ActivateGuestDomain)
    {
        // Let the VCPU transition to it's default memory domain.
        status = VcpuActivateDomain(Vcpu, GuestPredefinedMemoryDomainIdPhysicalMemory);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("VcpuActivateDomain", status);
            return status;
        }
    }

    // Step VI: if requested by api client, clear the VMCS from the cpu to ensure all previous changes have been successfully flushed.
    // This step is required when one CPU updates multiple VMCS structures.
    if(Options->ClearVmcsFromCpu)
    {
        if (__vmx_vmclear(&Vcpu->VmcsPa)) return CX_STATUS_INVALID_DATA_STATE;
        Vcpu->State = VCPU_STATE_NOT_ACTIVE;
    }

    return status;
}

VOID
VmstateControlNMIWindowExiting(
    _In_ BOOLEAN Enable
)
{
    QWORD procCtrl = 0;

    // enable NMI-window exiting, because we couldn't inject right now the NMI
    vmx_vmread(VMCS_PROC_BASED_EXEC_CONTROL, &procCtrl);
    procCtrl = (Enable) ? (procCtrl | (QWORD)VMCSFLAG_PROCEXEC_NMI_WINDOW_EXIT) : (procCtrl & (~(QWORD)VMCSFLAG_PROCEXEC_NMI_WINDOW_EXIT));
    vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL, procCtrl);
}

NTSTATUS
VmstateUpdateVmcsForIntrospection(
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL Force,
    _In_ CX_BOOL LoadAndClearVmcsFromCpu
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;

    VMCS_CONFIGURE_SETTINGS options = {
            .InitVmcs = CX_FALSE,
            .ActivateGuestDomain = CX_FALSE,
            .GuestOptions = VMCS_GUEST_NO_UPDATE,
            .ControlsOptions = VMCS_CONTROLS_APPLY_CHANGES_ONLY,
            .HostOptions = VMCS_HOST_NO_UPDATE,
            .ClearVmcsFromCpu = CX_TRUE,
            .SetNewVmcs = CX_TRUE,
            .ControlsConfigState = { 0 }
    };

    // According to the use-case we might (not) need to load the Vcpu structure/clear it after
    options.ClearVmcsFromCpu = !!LoadAndClearVmcsFromCpu;
    options.SetNewVmcs = !!LoadAndClearVmcsFromCpu;


    // If the introspection requested exit to be generated on descriptor table access or CR3, make sure to enable
    // those features.
    if (HvInterlockedBitTestAndResetU64(&Vcpu->Guest->Intro.IntroVcpuMask, Vcpu->GuestCpuIndex) || Force)
    {

        // Process CR3 load exiting.
        Vcpu->Cr3LoadExitEnabledCount += (Vcpu->Guest->Intro.IntroEnableCr3LoadExit ? 1 : (Vcpu->Cr3LoadExitEnabledCount ? -1 : 0));

        // Process Descriptor table load exiting.
        Vcpu->DescTableExitEnabledCount += (Vcpu->Guest->Intro.IntroEnableDescLoadExit ? 1 : (Vcpu->DescTableExitEnabledCount ? -1 : 0));

        // Process breakpoint exiting.
        Vcpu->BreakpointExitEnabledCount += (Vcpu->Guest->Intro.IntroEnableBreakpointExit ? 1 : (Vcpu->BreakpointExitEnabledCount ? -1 : 0));

        // Request update for CR3 Load Exit feature to the vmcs configure api
        options.ControlsConfigState.FeatureCr3LoadExit = (Vcpu->Cr3LoadExitEnabledCount ? VMCS_CONTROL_FEATURE_ENABLE : VMCS_CONTROL_FEATURE_DISABLE);

        // Request update for Descriptor Table Load Exit Exit feature to the vmcs configure api
        options.ControlsConfigState.FeatureDescriptorExit = (Vcpu->DescTableExitEnabledCount ? VMCS_CONTROL_FEATURE_ENABLE : VMCS_CONTROL_FEATURE_DISABLE);

        // Request update for Breakpoint Exit feature to the vmcs configure api
        options.ControlsConfigState.FeatureBreakpointExit = (Vcpu->BreakpointExitEnabledCount ? VMCS_CONTROL_FEATURE_ENABLE : VMCS_CONTROL_FEATURE_DISABLE);

        // Request update for #VE Page feature to the vmcs configure api
        if (VmxIsVeAvailable() && VmxIsVmfuncAvailable())
        {
            options.ControlsConfigState.FeatureVeInfoPageHpa = Vcpu->VirtualizationException.InfoPageHpa;
            options.ControlsConfigState.FeatureVeInfoPageSet = (Vcpu->VirtualizationException.InfoPageHpa ? VMCS_CONTROL_FEATURE_ENABLE : VMCS_CONTROL_FEATURE_DISABLE);
        }

        // Request update for Spptp feature to the vmcs configure api
        if ((Vcpu->Guest->SpptRootVa != NULL) && !Vcpu->IsSppActive)
        {
            options.ControlsConfigState.FeatureSpptp = VMCS_CONTROL_FEATURE_ENABLE;
        }

        // Submit requests for the current vcpu
        status = VmstateConfigureVmcs(Vcpu, &options);
        if (!CX_SUCCESS(status))

        {
            LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
            return status;
        }
    }

    return status;
}
///@}

/// @}
