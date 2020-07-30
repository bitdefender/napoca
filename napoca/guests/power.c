/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup power ACPI power management and support for all power state trasitions (reboot, S3, S4, etc..)
///@{

/** @file power.c
*   @brief POWER - ACPI power management support
*
*/
#include "napoca.h"
#include "kernel/kerneldefs.h"
#include "kernel/kernel.h"
#include "guests/power.h"
#include "boot/init64.h"
#include "debug/dumpers.h"
#include "boot/boot.h"
#include "apic/lapic.h"
#include "kernel/cleanup.h"
#include "boot/phase1.h"
#include "boot/vmstate.h"
#include "kernel/newcore.h"
#include "guests/pci_tools.h"
#include "memory/cachemap.h"
#include "kernel/queue_ipc.h"
#include "kernel/intelhwp.h"
#include "guests/intro.h"
#include "memory/tas.h"
#include "acpica/source/include/aclocal.h"

/// Timeout for VMXOFF broadcast IPC
#define VMXOFF_BROADCAST_TIMEOUT_US         (5 * MICROSECONDS_PER_SECOND)

/// Power State Change minimal VMCALL count, executed for Init consumption reasons.
#define PSC_MINIM_VMCALL_COUNT 4

/// Power State Change minimal VMCALL timeout, executed for Init consumption reasons.
#define PSC_VMCALL_TIMEOUT     (256 * MICROSECONDS_PER_MILISECOND)

/// @brief Function pointer type for the <1MB wakeup-time cleanup function
typedef void (*WAKEUP_RUN_ORIGINAL_VECTOR)(
    _In_ WORD OriginalVectorSegment,
    _In_ WORD OriginalVectorOffset
    );

///
/// @brief Structure for power transitions related data
///
typedef struct _POWER {
    ACPI_TABLE_FADT             *Fadt;              ///< Store locally the pointer to FADT table, quicker usage
    ACPI_TABLE_FACS             *Facs;              ///< Store locally the pointer to FACS table, quicker usage
    DWORD                       Pm1aPort;           ///< I/O port, we need to put a hook on this (2 bytes) to intercept SLP_TYPa | SLP_ENa commands
    BYTE                        Pm1aLength;         ///< in bytes
    VOID                        *OriginalGuestMem;  ///< backup of the overwritten OS trampoline memory
    WORD                        OldWakeOfs16;       ///< BSP wakeup code offset inside the segment
    WORD                        OldWakeSeg16;       ///< BSP wakeup code segment in 16-bit real address mode
    QWORD                       Port;               ///< The port used for sleep
    QWORD                       Value;              ///< The value written to the respective port
    BOOLEAN                     SupportedSystem;    ///< True if we managed to get everything set up with ACPI
} POWER;

///
/// @brief Context structure for VMX_OFF broadcast during power transitions to S3 and S4
///
typedef struct _HV_VMX_OFF_CONTEXT
{
    volatile QWORD              TotalCpuCount;               ///< Total number of CPUs executing the VMX_OFF operation
    QWORD                       SenderId;                    ///< The APIC id of the sender CPU, usually the BPS (id 0)
    volatile QWORD              SyncCpuCountBeforeVmxOff;    ///< Counter used as a barrier for synchronizing CPUs before doing VMX_OFF
    volatile QWORD              SyncCpuCountAfterVmxOff;     ///< Counter used as a barrier for synchronizing CPUs after doing VMX_OFF
    BOOL                        ConsumeInits;                ///< If True, Inits resulting from are IPIs which catch the CPUs in Host are consumed by re-entering a short flow inside the Guest
    DWORD                       CodeStart;                   ///< The start of the wakeup routine code below 1MB.
}HV_VMX_OFF_CONTEXT;

//
// Extern global variables and functions that are exposed by the assembly files
//

// from acpi_wakeup.nasm

/// @brief Assembly label, start of the code which is copied below 1MB to be executed for the Guest until all Inits resulting from VMXOFF are consumed
extern UINT8 GuestPscStub;

/// @brief Assembly label, end of the code which is copied below 1MB to be executed for the Guest until all Inits resulting from VMXOFF are consumed
extern UINT8 GuestPscStubEnd;

/// @brief Assembly label, start of the code routine in assembly, which in executed as cleanup after the HV encountered some critical error during wakeup
extern BYTE WakeupRunOriginalVector;

/// @brief Assembly label, end of the code routine in assembly, which in executed as cleanup after the HV encountered some critical error during wakeup
extern BYTE WakeupRunOriginalVectorEnd;

#pragma pack(push, 1)

/// @brief This structure corresponds to the one in assembly (acpi_wakeup.nasm), is used to store some crucial values needed at the wakeup process.
typedef struct _WAKEUP_DATA
{
    QWORD FinalRsp;         ///< Final RSP for the stack before entering the 64-bit C code
    QWORD FinalPml4Pa;      ///< The Physical address of the PML4 page table after entering 64-bit Long address mode
    DWORD FinalCr4;         ///< The CR4 value for the host before entering, which is restored after wakeup
    DWORD FinalCr0;         ///< The CR0 value for the host before entering, which is restored after wakeup
    QWORD FinalEfer;        ///< The IA32_EFER value for the host before entering, which is restored after wakeup
    QWORD EntryPoint64;     ///< The entry point in 64-bit C code for the wakeup process (BSP only)
    DWORD ZoneSize;         ///< The size of the assembly wakeup code
    BYTE EntryFlags;        ///< Boot mode flag for sleep wakeup
}WAKEUP_DATA;

#pragma pack(pop)

/// @brief Wakeup data for sleep power transitions
extern WAKEUP_DATA gWakeupData;

/// @brief Acpi wakeup procedure code start (assembly label)
extern BYTE gWakeupStart;

/// @brief Acpi wakeup procedure code end (assembly label)
extern BYTE gWakeupEnd;

/// @brief Used to patch the value of loaded into edx as the base of the dynamically allocated wakeup region
extern BYTE gWakeupPatchedInstruction[6];

//
// Static variables, globals to this file
//

// Predefined \_Sx states, starting from \_S0 through \_S5 (0 = not initialized)
static BYTE gPowerTransType[ACPI_S_STATE_COUNT] = { 0, 1, 0, 5, 6, 7 };

/// @brief Every bit set means that the \_Sx state was found by acpi
static BYTE gPowerTransTypeFound = 0;

/// @brief Generic Power structure containing power transition relevant information for the machine
static POWER Power;

/// @brief Original overwritten guest memory below 1MB, which is overwritten during sleep
static VOID *gOriginalGuestMem;

/// @brief Dummy CPU structure until we have CPU initialized correctly for APs on resume
static DUMMY_CPU gGlobalDummyCpu;

//
// Global variables exposed from here
//

/// @brief Lock used on cases of power transitions when we want to broadcast VMX_OFF, locking only one CPU to broadcast
/// @remark Lock is never released. But, it is reinitialized on wakeup, which is basically the same thing.
SPINLOCK gVmxOffLock;

//
// Local function prototypes
//


///
/// @brief        Sends the Virtual CPU of the Guest into 16-bit real mode and tries to consume the sent out Inits for
///               the CPU by making a maximum of 4 quick resumes with the help of a code stub placed under 1MB for the
///               Guest VCPU to execute VMCALLs. If there were Inits which were sent to this CPU when it was in Host
///               state, than those will be delivered to the CPU when entering back in Guest mode and will generate
///               VM exits back inside the function. In this way we can consume left-over Init interrupts. Left-over Inits
///               can originate from our message sending mechanism by sending Inits to every CPU and hitting one in Root mode.
///
/// @param[in]    Vcpu                             The current Virtual CPU
/// @param[in]    Cs                               The 16-bit real mode code segment, where the Guest starts its execution after resume
/// @param[in]    Ip                               The 16-bit real mode instruction pointer, where the Guest starts its execution after resume
///
/// @returns      CX_STATUS_SUCCESS                - in case we managed to send the Guest to real mode
/// @returns      OTHER                            - different errors statuses in case #VmstateConfigureVmcs fails
///
static
NTSTATUS
_PwrSendToRealModeAndConsumeInits(
    _In_ VCPU* Vcpu,
    _In_ WORD Cs,
    _In_ WORD Ip
);


///
/// @brief        IPI handler for executing the VMX_OFF operation on every CPU, in a synchronized manner with the rest.
///               Only the BSP returns from this function, the rest of the CPUs (APs) are halted after executing the VMX_OFF instruction.
///               If Consume Inits is specified inside the context, than it first sends every CPU back to Guest mode into a special exit-resume
///               cycle in order to handle the queued Inits on the CPU, if the Inits came when the CPU was in Root mode.
///
/// @param[in]    Context                          A #HV_VMX_OFF_CONTEXT data structure which holds everything needed for the synchronized execution
///                                                of the VMX_OFF operation on the CPUs.
/// @param[in]    TrapFrame                        Unused in this function, needed in order to adhere to the interface of IPI handlers.
///
/// @returns      CX_STATUS_SUCCESS                - if everything went well, but only the BSP can have this return value, the rest of
///                                                the processors are halted.
///
/// @remark       If #_PwrSendToRealModeAndConsumeInits fails, than the system is rebooted.
///
static
NTSTATUS
_PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpusIpiHandler(
    _In_ VOID *Context,
    _In_ HV_TRAP_FRAME *TrapFrame
);


///
/// @brief        Overwrites a memory zone under 1MB starting from BaseAddress with the hyper-visors wakeup code. This code is a trampoline
///               code, meaning it brings back the BSP processor from 16-bit to 32-bit protected mode and then to 64-bit long mode.
///               This wakeup routine is only written for S3 (Sleep wakeup). The function assures that also the overwritten region
///               is mapped identically in the Virtual address space and that the overwritten portion is saved first, in order to restore it
///               after the wakeup. Also, it assures to complete the #gWakeupData found inside the trampoline code with the target resume function
///               written in C (#PwrResumeHostBsp), the values for control registers, EFER MSR, RSP and boot-flags, etc. #gWakeupData can be found
///               alongside the trampoline code inside acpi_wakeup.nasm (#gWakeupStart --> #gWakeupEnd).
///
/// @param[in]    BaseAddress                      Base physical address for the trampoline code under 1MB.
///
/// @returns      CX_STATUS_SUCCESS                - if everything was with success
/// @returns      CX_STATUS_DATA_NOT_READY         - if we can't retrieve the CPU structure for the BSP (it should never happen)
/// @returns      OTHER                            - other error statuses arising from #TasMapRangeEx or from #HpAllocWithTagCore.
///
static
NTSTATUS
_PwrOverwriteWakeupTrampoline(
    _In_ DWORD BaseAddress
);

///
/// @brief        Routine which broadcasts an IPI message to every CPU in order to enter the routine of #_PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpusIpiHandler
///               which will do a VMX_OFF on the CPUs and HALT every other CPU than the BSP. Initializes #HV_VMX_OFF_CONTEXT structure.
///
/// @param[in]    ConsumeInits                     TRUE if the Init IPIs should be consumed (Sleep-S3 transition), FALSE otherwise (when we only
///                                                want to make sure that every CPU dose a VMX_OFF before any power transition.
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - in case we don't have a Guest pointer
/// @returns      OTHER                            - other error statuses arising from #EptSetRights or from #IpcSendCpuMessage.
///
static
NTSTATUS
_PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpus(
    _In_ BOOL ConsumeInits
);


///
/// @brief        Read Callback for hooking the Pm1a IO port. Currently it only lets read operations through.
///
/// @param[in]    IoPort                           The exact port number on which the read was issued by the guest (we can have a range of ports)
/// @param[in]    Length                           The length of the read (requested a byte or a word)
/// @param[out]   Value                            The value read through the port
/// @param[in]    Context                          Not used here, needed for adhering to the Hooking Callback interface
///
/// @returns      CX_STATUS_SUCCESS                - in case we tried to read through the requested port
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - in case Value is a NULL pointer
///
static
NTSTATUS
_PwrReadPm1a(
    _In_ WORD IoPort,
    _In_ BYTE Length,
    _Out_ BYTE *Value,
    _In_opt_ VOID* Context
    );


///
/// @brief        Write Callback for hooking the Pm1a IO port. Writing to this port can cause power transitions from S1 to S5. The backbone
///               of going to these states is written here. If it is a power transition initiated by the Guest, then this function should
///               never return.
///
/// @param[in]    IoPort                           The exact port number on which the write was issued by the guest (we can have a range of ports)
/// @param[in]    Length                           The length of the write (written a byte or a word)
/// @param[in]    Value                            The value written through the port
/// @param[in]    Context                          Not used here, needed for adhering to the Hooking Callback interface
///
/// @returns      CX_STATUS_SUCCESS                - in case we let the write to go through because it wasn't a power transition
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - in case Value is a NULL pointer
///
static
NTSTATUS
_PwrWritePm1a(
    _In_ WORD IoPort,
    _In_ BYTE Length,
    _In_ BYTE *Value,
    _In_opt_ VOID* Context
    );


///
/// @brief        Resumes VMCS state from wakeup for any VCPU. It does the basic setup for the VMCS of the current VCPU of this CPU. This setup
///               only visions the Host state setup.
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well
/// @returns      OTHER                            - other error statuses arising from #VmstateConfigureVmcs or from #CpuVmxInvEpt.
///
static
NTSTATUS
_PwrResumeVmcsState(void);


///
/// @brief        Resumes the Host processor, it does basically the needed phase1 initialization for the BSP. It also wakes up all the AP processors
///               and waits for them also to complete their initialization.
///
/// @returns      STATUS_HV_UNLOAD_REQUESTED_INTERNALLY - in case during AP wakeup and initialization we met a fatal internal failure so we should
///                                                     unload the hyper-visor.
/// @returns      OTHER                            - other error statuses arising from #Phase1InitExceptionHandling or from
///                                                #Phase1WakeupAllApProcessorsAndThemIntoPhase1 or from #Phase1InitializePerCpuVmxOnZone.
///
static
NTSTATUS
_PwrResumeHost(void);


///
/// @brief        Resumes the Guest, for every VCPU it initializes completely the VMCS and sends every CPU for the guest to Real-mode, the BSP
///               into active state to execute the sleep wakeup code of the Guest and the APs into HALT state (the Guest will wake them up using)
///               INIT-SIPI-SIPI sequence. This function represents the phase II of the resume.
///
/// @returns      CX_STATUS_SUCCESS                - in case everything went well
/// @returns      CX_STATUS_UNINITIALIZED_STATUS_VALUE - in case we don't have initialized VCPUs
/// @returns      OTHER                            - other error statuses arising from: #VmstateConfigureVmcs, #_PwrResumeVmcsState,
///                                                #ChmGpaToHpa and #GstInitRipCache.
///
static
NTSTATUS
_PwrResumeGuest(void);


///
/// @brief        Restores the Guests original wakeup code, as we have overwritten it before going into sleep. It also unmaps the identically mapped
///               region from our VA mappings and tries to make sure that we will have from now on the NULL page locked, in order to not have
///               valid NULL pointers.
///
/// @returns      CX_STATUS_SUCCESS                - always, as any error arising from here shouldn't be anything critical for us
///
static
NTSTATUS
_PwrRestoreWakeupTrampoline(void);


///
/// @brief        Generic function for reading and writing to IO port with different access width. Configured to Pm1a port, as also stated in
///               official ACPICA documentation, it should only support byte access or word access widths.
///
/// @param[in]    Read                             TRUE if we want to read from the port, FALSE if we want to write
/// @param[in]    Port                             The exact port number
/// @param[in, out] Value                          Based on Read, it is either the Value to be written or the place in memory were the
///                                                value read from the port should be stored
/// @param[in]    AccessWidth                      The length of the read/write, for Pm1a only (BYTE or WORD access is supported)
///
static
VOID
_PwrReadWritePm1aValue(
    _In_ BOOLEAN Read,
    _In_ WORD Port,
    _Inout_ BYTE* Value,
    _In_ BYTE AccessWidth
);


///
/// @brief        Cleanup handler registered for every CPU, in case of an unsuccessful wakeup the hyper-visor is unloaded and this
///               cleanup handler is called for every CPU in order to clean what is needed for giving back control to the loader and
///               let the Guest be loaded without the Hyper-visor.
///
/// @param[in]    OriginalState                    Unused in this function, needed in order to adhere to the interface of Cleanup handlers.
/// @param[in]    Context                          Unused in this function, needed in order to adhere to the interface of Cleanup handlers.
///
static
NTSTATUS
_PwrCpuCleanup(
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
);


///
/// @brief        Utility function, used to extract and get the sleep state in which the Guest tries to enter when it writes to the Pm1a port.
///               It searches for the sleep states found in ACPI tables, if not, it uses the predefined ones.
///
/// @param[in]    SleepTypeVal                     The bits written in Pm1a which denote the type of the power transition (bits[12:10])
/// @param[out]   AcpiSleepType                    The found AcpiSleepType or 0 if not found.
///
/// @returns      CX_STATUS_SUCCESS                - in case the sleep type has been found
/// @returns      CX_STATUS_NOT_INITIALIZED        - in case the sleep type was not found.
///
static
NTSTATUS
_PwrGetSleepState(
    _In_  BYTE SleepTypeVal,
    _Out_ BYTE *AcpiSleepType
);


///
/// @brief         Generic function for writing to IO port or MMIO zone with different access width. In either case the writing should determine
///                a platform reboot.
///
/// @param[in]    Ptr                              The address in memory where the write of Value will determine a platform reboot.
/// @param[in]    Port                             The exact port number of the reset port in case the reset is don through IO operation.
/// @param[in]    Value                            It is the address to the value which has to be written for reset either by IO or MMIO.
/// @param[in]    AccessWidth                      The length of the write operation, how many bytes has to written.
///
static
VOID
_PwrPlatformWriteResetValue(
    _In_opt_ VOID* Ptr,
    _In_opt_ WORD Port,
    _In_ QWORD Value,
    _In_ BYTE AccessWidth
);


///
/// @brief        Tries to reboot the platform. The first mechanism used is through ACPI and the FADT_RESET_REGISTER, here depending on what
///               it was found inside the ACPI FADT table, it can resort to reboot through IO port or through MMIO (either through the
///               PCI config space or other memory zones found int FADT). If the reset through ACPI is not successful, then we revert
///               to try resetting the platform via the legacy Keyboard Controller if it is present. If that also fails to do the reset,
///               we will use the PCI address space reboot option, by writing to the RST_CNT(reset control) register.
///
static
VOID
_PwrPlatformReboot(
    VOID
);


///
/// @brief        The resume/wakeup function in 64-bit long mode of the BSP entered during the wakeup after an S3 transition. It stats initializing
///               the most critical CPU support features, setting up Interrupt handling, time module and then calls #_PwrResumeHost
///               to resume the host completely (phase1), after that by calling #_PwrResumeGuest, the Guest state is set of for its wakeup.
///               After that, the wakeup trampoline is cleaned up and everything is ready in order for the hyper-visor to enter phase3,
///               #HvPcpuRootMainCycle, where ultimately the Guest will be launched.
///
void
PwrResumeHostBsp(
    void
    )
{
    NTSTATUS status;

    // Set up the current CPU structure inside GS
    CpuBindStructureToGs(gHypervisorGlobalData.CpuData.Cpu[0]);
    CpuActivateNxe();

    // reset every phase indicator
    gVideoVgaInited = FALSE;
    gSerialInited = FALSE;

    gBasicInitDoneByBSP = FALSE;
    gStageOneCanProceedOnAps = FALSE;
    gStageOneInitedCpuCount = 0;
    gStageTwoCanProceedOnAps = FALSE;
    gStageTwoInitedCpuCount = 0;
    gStageThreeCanProceedOnAps = FALSE;
    gCpuReachedInit64 = 0;
    gHypervisorGlobalData.BootProgress.StageTwoDone = FALSE;
    DlReinitLockStats();
    IoSetPerCpuPhase(IO_CPU_PHASE_INIT64);
    DumpersResetPeriodicTimers();

    // reset all cleanup entries registered at the previous HV initialization
    gClnAlreadyInitialized = 0;
    ClnInitialize();
    status = CLN_REGISTER_SELF_HANDLER((CLN_CALLBACK)_PwrCpuCleanup, NULL, NULL);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("register _PwrCpuCleanup", status);

    // this message will show up only when backup legacy logging is activated on COM1
    LOG("\n\n\n\n\n\n\n*********************\n Waking up! \n\n\n\n\n\n");

    // init and load temp IDT for BSP
    {
        INTERRUPT_GATE *idt;
        DWORD idtSize;
        LIDT lidt = {0};

        idt = (INTERRUPT_GATE*)&gTempBspIdt;
        idtSize = (32 * sizeof(INTERRUPT_GATE));

        memzero(idt, idtSize);

        HvInitExceptionHandlers(idt, FALSE);

        // load IDT
        lidt.IdtAddress = (QWORD)idt;
        lidt.Size = (WORD)(idtSize - 1);        // 32 x 16 bytes, check out "6.14.1 64-Bit Mode IDT" from Intel Vol 3A

        __lidt(&lidt);
    }

    status = HvInitTime();
    if (!SUCCESS(status))
    {
        LOG("ERROR: HvInitTime failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    PciSaveRestoreHiddenDevicesState(FALSE);

    gHypervisorGlobalData.BootFlags.IsWakeup = CX_TRUE;
    gHypervisorGlobalData.BootFlags.WakeupPerformedAtLeastOnce = CX_TRUE;

    if (CfgDebugOutputSerialEnabled) IoInitForTrace(FALSE, TRUE);

    LOG("\n\n\n**** S3 Wakeup flow started ****\n\n\n\n");
    LOG("Power.Port 0x%x Power.Value 0x%x \n", Power.Port, Power.Value);

    HvPrintTimeInfo();

    //
    // We have entered a lower sleep state from an IO Port Hook callback
    // before the callback was called this lock was acquired but never released
    // which is normal because when we enter a sleep state we purposely turn off the platform
    HvReleaseRwSpinLockShared(&gHypervisorGlobalData.Guest[0]->IoHooks.Lock);

    // alter init flows inside phases
    BOOT_MODE originalBootMode = HvGetBootMode();
    HvSetBootMode(bootMbrPxe);

    // signal APs that they can begin
    gBasicInitDoneByBSP = TRUE;

    HvInterlockedIncrementU32(&gCpuReachedInit64);

    status = _PwrResumeHost();
    if (!SUCCESS(status))
    {
        LOG("ERROR: _PwrResumeHost failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }
    IoSetPerCpuPhase(IO_CPU_PHASE1);

    //
    // Wakeup STAGE II, resume guest VMs
    //
    status = _PwrResumeGuest();
    if (!SUCCESS(status))
    {
        LOG("ERROR: _PwrResumeGuest failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    gHypervisorGlobalData.BootProgress.StageTwoDone = TRUE;
    IoSetPerCpuPhase(IO_CPU_PHASE2);

    //
    // === STAGE III, run / schedule guests ===
    //

    // trigger APs to perform STAGE III
    gStageThreeCanProceedOnAps = TRUE;

    // restore original boot mode before going into Stage III
    HvSetBootMode(originalBootMode);

    // Notify introspection about power state transition
    if (CfgFeaturesIntrospectionEnabled)
    {
        NapIntNotifyGuestPowerStateChange(HvGetCurrentGuest(), TRUE, ACPI_STATE_UNKNOWN);
    }

    gHypervisorGlobalData.BootFlags.IsWakeup = CX_FALSE;

    CpuYield();     // wait for a very short time on the BSP - shall better match the moment with the APs for StartTsc
    CpuYield();

    HvGetCurrentCpu()->StartTsc = __rdtsc();

    // we had to overwrite some memory below 1mb for our 16 bit wakeup code
    // restore that memory before we resume the guest
    _PwrRestoreWakeupTrampoline();

    // perform stage III on the BSP also
    LOG("[BSP][WAKEUP]: STAGE III / HvPcpuRootMainCycle will start (TSC = %lld)...\n", HvGetCurrentCpu()->StartTsc);

    if (HvGetCurrentCpu()->UseXsave)
    {
        __xsetbv(0, HvGetCurrentCpu()->StartupXCR0);
    }

    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
    {
        status = LapicSetupPerfNMI();
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("LapicSetupPerfNMI", status);
    }

    // run the core cycle of PHASE 3 - repeatedly get a VCPU on this CPU and execute it
    IoSetPerCpuPhase(IO_CPU_ROOT_CYCLE);
    HvPcpuRootMainCycle();

    // we should never get here
    status = CX_STATUS_SUCCESS;

cleanup:
    // always unload if we've got to this point
    CLN_UNLOAD(status);
}

void
PwrPreinit(
    void
    )
{
    memzero(&Power, sizeof(POWER));
}

BOOLEAN
PwrIsSystemSupported(
    void
)
{
    return Power.SupportedSystem;
}

NTSTATUS
PwrInitDataStructsPhase1(
    _In_ ACPI_TABLE_FADT *Fadt,
    _In_ ACPI_TABLE_FACS *Facs
    )
{
    if (NULL == Fadt)
    {
        ERROR("ACPI Power Management without FADT table not supported\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    Power.Fadt = Fadt;

    if (NULL == Facs)
    {
        ERROR("ACPI Power Management without FACS table not supported\n");
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    Power.Facs = Facs;

    // determine PM1A control I/O port
    Power.Pm1aPort = (DWORD)Fadt->XPm1aControlBlock.Address;
    Power.Pm1aLength = Fadt->Pm1ControlLength;
    Power.SupportedSystem = TRUE;

    MM_UNALIGNED_PA facsPa = 0;
    // CRITICAL: we don't know what address (->Facs or ->XFacs) does the system use :-( so we try to get from the ACPICA mapped address
    NTSTATUS status = MmQueryPa(&gHvMm, Facs, &facsPa);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmQueryPa", status);
        return CX_STATUS_SUCCESS; // overwrite as we only do logging from here on.
    }

    // NOTE: wake zones are setup in phase2 and basic initialization is done at module loading

    LOG("[POWER-ACPI] HwReduced %d  S4Bios %d  LowPowerS0 %d\n",
        (Fadt->Flags & ACPI_FADT_HW_REDUCED),
        (Facs->Flags & ACPI_FACS_S4_BIOS_PRESENT),
        (Fadt->Flags & ACPI_FADT_LOW_POWER_S0));
    LOG("[POWER-ACPI] FACS PA %018p  FACS %018p  /  XFACS %018p  Length %d  FACS HVA %018p\n", facsPa, (QWORD)(Fadt->Facs), (QWORD)(Fadt->XFacs), Facs->Length, Power.Facs);
    LOG("[POWER-ACPI] SMI CMD I/O port 0x%04x  S4BIOS_REQ 0x%02x\n", Fadt->SmiCommand, Fadt->S4BiosRequest);
    LOG("[POWER-ACPI] PM1A I/O port 0x%04x  Length %d\n", Power.Pm1aPort, Power.Pm1aLength);

    // everything done just fine
    return CX_STATUS_SUCCESS;
}

static
NTSTATUS
_PwrOverwriteWakeupTrampoline(
    _In_ DWORD BaseAddress
    )
{
    NTSTATUS status;
    VOID *mapped = (VOID*)(SIZE_T)BaseAddress;
    DWORD zoneSize = (DWORD)(&gWakeupEnd - &gWakeupStart);

    //
    // Identity map the overwritten region, needed both for running the 16-32-64 bit wakeup trampoline code and for backing up
    // the lower memory before applying the changes
    //
    // NOTE: this mapping will overwrite any other mappings present in targeted VA interval where only identity-mapped memory might be expected to
    // already be present
    //

    TAS_PROPERTIES lack = gTasMapLackProps;
    lack.InUse = 0; // allow the new mapping overwrite any pre-existing mappings in the HVA [0..1MB)

    status = TasMapRangeEx(&gHva, (MEM_UNALIGNED_VA)BaseAddress, zoneSize, gTasMapSetProps, gTasMapClearProps, gTasMapHaveProps, lack, (MEM_ALIGNED_PA)BaseAddress, NULL);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasMapRangeEx", status);
        goto cleanup;
    }

    //
    // fill-in the parameters for waking-up the CPU
    //
    PCPU *bsp = HvGetCpu(0);
    if (!bsp)
    {
        status = CX_STATUS_DATA_NOT_READY;
        goto cleanup;
    }

    LOG("Filling in data at %p, cr3 = %p\n", &gWakeupData, __readcr3());
    gWakeupData.EntryFlags = BOOT_MODE_FLAG_ACPI_S3_WAKEUP;
    gWakeupData.EntryPoint64 = (QWORD)&PwrResumeHostBsp;
    gWakeupData.FinalCr0 = (DWORD)__readcr0();
    gWakeupData.FinalCr4 = (DWORD)__readcr4();
    gWakeupData.FinalEfer = (__readmsr(MSR_IA32_EFER) & 0xFFFFFFFFFFFFFBFFULL);   // remove EFER.LMA bit (0x400)
    gWakeupData.FinalPml4Pa = __readcr3();
    gWakeupData.FinalRsp = (QWORD)bsp->MemoryResources.Stack + NAPOCA_CPU_STACK_SIZE;
    gWakeupData.ZoneSize = zoneSize;

    //
    // setup the trampoline memory below 1MB
    //

    // backup the <1MB memory we need to overwrite
    if (NULL == gOriginalGuestMem)
    {
        status = HpAllocWithTagCore(&gOriginalGuestMem, zoneSize, TAG_POWR);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTagCore", status);
            goto cleanup;
        }
        Power.OriginalGuestMem = gOriginalGuestMem;
    }

    LOG("Copying %p to %p\n", mapped, Power.OriginalGuestMem);
    memcpy(Power.OriginalGuestMem, mapped, zoneSize);

    // patch the mov edx, 0xFFFFFFFF instruction (acpi_wakeup.nasm) to reference the correct linear address
    *((DWORD*)&gWakeupPatchedInstruction[2]) = BaseAddress;

    // overwrite the region with our wakeup trampoline
    LOG("Copying %p to %p\n", &gWakeupStart, mapped);
    memcpy(mapped, &gWakeupStart, zoneSize);


    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

static
NTSTATUS
_PwrRestoreWakeupTrampoline(
    void
    )
{
    DWORD zoneSize = (DWORD)(&gWakeupEnd - &gWakeupStart);
    PVOID mapped = (PVOID)((SIZE_T)Power.OldWakeOfs16 + ((SIZE_T)Power.OldWakeSeg16 * (SIZE_T)16));

    // restore what was originally in the wakeup-zone
    memcpy(mapped, Power.OriginalGuestMem, zoneSize);

    //
    // Remove the NULL page if the OS trampoline starts in the very fist 4K of memory
    //
    if ((QWORD)mapped < PAGE_SIZE)
    {
        TAS_PROPERTIES have = gTasUnmapHaveProps;
        have.CompleteChain = 0;

        // remove anything already mapped to VA = 0
        NTSTATUS status = TasAlterRangeEx(&gHva, (MEM_UNALIGNED_VA)NULL, PAGE_SIZE, gTasUnmapSetProps, gTasUnmapClearProps, have, gTasUnmapLackProps, NULL);
        if (!SUCCESS(status)) ERROR("Failed to unmap the NULL-pointer page out of the HVA space (%s)!\n", NtStatusToString(status));

        // and lock the NULL page
        status = MmLockVa(&gHvMm, (MM_UNALIGNED_VA)NULL, PAGE_SIZE);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmLockVa", status);
            // not such a big deal, let the code continue...
        }
    }
    return CX_STATUS_SUCCESS;
}

NTSTATUS
PwrHookPm1a(
    _In_ GUEST *Guest
    )
{
    if (NULL == Guest) return CX_STATUS_INVALID_PARAMETER_1;

    LOG("[POWER-ACPI] will IO hook PM1A ACPI regs, range 0x%04x - 0x%04x\n", (WORD)Power.Pm1aPort, (WORD)(Power.Pm1aPort + Power.Pm1aLength - 1));
    NTSTATUS status = HkSetIoHook(Guest, (WORD)Power.Pm1aPort, (WORD)(Power.Pm1aPort + Power.Pm1aLength - 1), 0, _PwrReadPm1a, _PwrWritePm1a, NULL);
    if (!NT_SUCCESS(status))
    {
        ERROR("HkSetIoHook failed on %u - %u with %s\n", (WORD)Power.Pm1aPort, (WORD)(Power.Pm1aPort + Power.Pm1aLength - 1), NtStatusToString(status));
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

// " Accesses to PM1 control registers are accessed through byte and word accesses."
// (Advanced Configuration and Power Interface (ACPI) Specification, version 6.3)
static
__forceinline
VOID
_PwrReadWritePm1aValue(
    _In_ BOOLEAN Read,
    _In_ WORD Port,
    _Inout_ BYTE *Value,
    _In_ BYTE AccessWidth
)
{
    if (Read)
    {
        switch (AccessWidth)
        {
            case sizeof(BYTE) :
            {
                ((BYTE*)(Value))[0] = __inbyte(Port);
                break;
            }
            case sizeof(WORD) :
            {
                ((WORD*)(Value))[0] = __inword(Port);
                break;
            }
            default:
            {
                ERROR("_PwrReadWritePm1aValue doesn't support access width: %d\n", AccessWidth);
                *Value = 0;
                break;
            }
        }
    }
    else
    {
        switch (AccessWidth)
        {
            case sizeof(BYTE) :
            {
                __outbyte(Port, ((BYTE*)(Value))[0]);
                break;
            }
            case sizeof(WORD) :
            {
                __outword(Port, ((WORD*)(Value))[0]);
                break;
            }
            default:
            {
                ERROR("_PwrReadWritePm1aValue doesn't support access width: %d\n", AccessWidth);
                break;
            }
        }
    }
}

static
NTSTATUS
_PwrReadPm1a(
    _In_ WORD IoPort,
    _In_ BYTE Length,
    _Out_ BYTE *Value,
    _In_opt_ VOID* Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (!Value) return CX_STATUS_INVALID_PARAMETER_4;

    _PwrReadWritePm1aValue(TRUE, IoPort, Value, Length);

    return CX_STATUS_SUCCESS;
}

static
NTSTATUS
_PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpus(
    _In_ BOOL ConsumeInits
    )
{
    // Only acquired here, not released until we enter the sleep state, on comeback the lock is reinitialized in phase1
    HvAcquireSpinLock(&gVmxOffLock);

    NTSTATUS status;
    HV_VMX_OFF_CONTEXT ctx = { 0 };
    IPC_INTERRUPTIBILITY_STATE intState;
    GUEST *guest = HvGetCurrentGuest();

    if (!guest) return CX_STATUS_INVALID_INTERNAL_STATE;

    ctx.TotalCpuCount = gHypervisorGlobalData.CpuData.CpuCount;
    ctx.SenderId = HvGetCurrentCpu()->Id;
    ctx.ConsumeInits = ConsumeInits;

    intState = IpcSetInterruptibilityValues(
        TRUE, IPC_INTERRUPTS_ENABLED,
        TRUE, TRUE,
        TRUE, IPC_PRIORITY_IPI);

    LOG("Pausing all CPUs!\n");

    // at every exit in the resume phase (HvPcpuRootMainCycle, we check it, if active we are halting CPUs on IPI-1 level) == Pausing
    HvInterlockedExchangeI32((volatile int*)&guest->PowerState, GstPowerTransitionOccurring);

    // The Intel's documentation states the following:
    // "The INIT signal is blocked whenever a logical processor is in VMX root operation. It is not blocked in VMX non-root operation. Instead, INITs cause VM exits".
    // As it turns out "blocking" means queuing in this case. Executing VMXOFF while there's an undelivered INIT signal on the LAPIC would instantly send the processor to fairyland.
    // Given the fact that there's a chance that we send an INIT while a processor is in root mode (in case of an inter processor message, the INITs are sent unconditionally to the destination processors), we must consume them.
    // Consuming means :
    // - synchronize all the processors and making sure that nobody sends additional INITs
    // - send the guest to execute a tiny loop with a vmcall(copied with the wake - up code)
    // - expect every cpu to execute those few vmcalls while ignoring any other exits(including the INIT ones), assuming that in the mean time the INIT(if there's one) will generate an exit
    //
    // NOTE: Init consumption is currently active only in case of an S3 power state change
    if (ConsumeInits)
    {
        WORD codeLength = (WORD)(&GuestPscStubEnd - &GuestPscStub);
        ctx.CodeStart = Power.Facs->FirmwareWakingVector + (DWORD)(&GuestPscStub - &gWakeupStart);

        // the consuming code is inside of the wakeup code, which is already copied and the overwritten data is already saved and will be restored on wakeup
        // make sure that the guest can execute the consuming code
        status = EptSetRights(GstGetEptOfPhysicalMemory(guest), ctx.CodeStart, codeLength, EPT_RIGHTS_RX);
        if (!_SUCCESS(status)) LOG_FUNC_FAIL("EptSetCacheAndRights", status);
    }

    IPC_MESSAGE msg;
    msg.MessageType = IPC_MESSAGE_TYPE_IPI_HANDLER;
    msg.OperationParam.IpiHandler.CallbackFunction = _PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpusIpiHandler;
    msg.OperationParam.IpiHandler.CallbackContext = &ctx;
    status = IpcSendCpuMessage(&msg, IPC_CPU_DESTINATION_ALL_EXCLUDING_SELF, IPC_PRIORITY_IPI, TRUE, IPC_WAIT_COMPLETION_NONE, FALSE);
    if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("IpcSendCpuMessage", status);

    LOG("Broadcast vmx off to %d cpus!\n", ctx.TotalCpuCount);

    _PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpusIpiHandler(&ctx, NULL);

    LOG("Vmx off done on %d cpus!\n", ctx.SyncCpuCountAfterVmxOff);

    return status;
}

static
NTSTATUS
_PwrSendToRealModeAndConsumeInits(
    _In_ VCPU* Vcpu,
    _In_ WORD Cs,
    _In_ WORD Ip
)
{
    NTSTATUS status;

    // Place the guest in real mode
    VMCS_CONFIGURE_SETTINGS options = {
       .InitVmcs = CX_FALSE,
       .ActivateGuestDomain = CX_FALSE,
       .GuestOptions = VMCS_GUEST_REAL_MODE,
       .ControlsOptions = VMCS_CONTROLS_RESET_AND_CHANGES,
       .HostOptions = VMCS_HOST_NO_UPDATE,
       .ClearVmcsFromCpu = CX_FALSE,
       .SetNewVmcs = CX_TRUE
    };

    options.GuestConfig.RealModeState.Cs = Cs;
    options.GuestConfig.RealModeState.Ip = Ip;
    options.GuestConfig.RealModeState.Ss = Cs;
    options.GuestConfig.RealModeState.Sp = Ip;
    options.GuestConfig.RealModeState.ActivityState = VMCS_GUEST_ACTIVITY_STATE_ACTIVE;

    // disable preemption timer
    options.ControlsConfigState.PreemptionTimerEnableState = VMCS_CONTROL_FEATURE_DISABLE;
    options.ControlsConfigState.PreemptionTimerSaveState = VMCS_CONTROL_FEATURE_DISABLE;

    status = VmstateConfigureVmcs(
        Vcpu,
        &options
    );
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
        return status;
    }

    WORD vmCallCount = 0;
    QWORD timeoutForPscVmcalls = HvGetTimeGuard(PSC_VMCALL_TIMEOUT);
    do
    {
        QWORD exitReason;

        // a shortcuted resume that'll continue the execution here
        HvVmxSwitchFromHostToVmGuestWithContinuation();

        vmx_vmread(VMCS_VM_EXIT_REASON, &exitReason);
        if (exitReason == EXIT_REASON_VMCALL) ++vmCallCount;

    } while (vmCallCount < PSC_MINIM_VMCALL_COUNT && !HvTimeout(timeoutForPscVmcalls));

    if (HvTimeout(timeoutForPscVmcalls))
    {
        WARNING("Failed to execute %u VMCALLs in real mode under %u microseconds, the CPU might have leftover INITs\n",
            PSC_MINIM_VMCALL_COUNT, PSC_VMCALL_TIMEOUT);
    }

    return CX_STATUS_SUCCESS;
}

static
NTSTATUS
_PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpusIpiHandler(
    _In_ VOID *Context,
    _In_ HV_TRAP_FRAME *TrapFrame
    )
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    HV_VMX_OFF_CONTEXT *ctx = (HV_VMX_OFF_CONTEXT*)Context;
    VCPU* vcpu = HvGetCurrentVcpu();

    UNREFERENCED_PARAMETER(TrapFrame);

    // disable NMI watchdog
    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond) LapicDisablePerfNMI();

    // As noted in Section 24.1, the processor may optimize VMX operation by maintaining the state of an
    // active VMCS(one for which VMPTRLD has been executed) on the processor.Before relinquishing
    // control to other system software that may, without informing the VMM, remove power from the
    // processor(e.g., for transitions to S3 or S4) or leave VMX operation, a VMM must VMCLEAR all active
    // VMCSs.This ensures that all VMCS data cached by the processor are flushed to memory and that
    // no other software can corrupt the current VMM's VMCS data.It is also recommended that the VMM
    // execute VMXOFF after such executions of VMCLEAR.

    HvInterlockedIncrementU64(&ctx->SyncCpuCountBeforeVmxOff);

    // once we want to perform a power transition we really don't want to be interrupted by anyone
    IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    // force them to timeout non-synchronously
    QWORD timeoutBeforeBroadcast = HvGetTimeGuard(VMXOFF_BROADCAST_TIMEOUT_US + (HvGetCurrentCpu()->Id * MICROSECONDS_PER_SECOND));

    while (ctx->SyncCpuCountBeforeVmxOff != ctx->TotalCpuCount && !HvTimeout(timeoutBeforeBroadcast))
    {
        CpuYield();
    }

    if (HvTimeout(timeoutBeforeBroadcast))
    {
        // not all CPUs are here right now, some Inits can come from those CPUs afterwards
        WARNING("Failed to synchronize CPUs in HV, additional INITs might arrive\n");
    }

    if (vcpu != NULL && ctx->ConsumeInits && GstIsSafeToInterrupt(HvGetCurrentGuest()))
    {
        // extract IP and CS from the 20-bit start address (real-mode)
        status = _PwrSendToRealModeAndConsumeInits(vcpu, (WORD)(ctx->CodeStart >> 4), (WORD)(ctx->CodeStart % 0x10));
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("_PwrSendToRealModeAndConsumeInits", status);
            PwrReboot(FALSE, TRUE);
        }
    }

    QWORD activeVmcs;
    // store VMCS and clear the active vmcs
    __vmx_vmptrst(&activeVmcs);
    __vmx_vmclear(&activeVmcs);

    CpuPerformVmxoff(HvGetCurrentCpu());

    HvInterlockedIncrementU64(&ctx->SyncCpuCountAfterVmxOff);

    if (HvGetCurrentCpu()->Id != ctx->SenderId)
    {
        __wbinvd();

        __halt(); // halt every other CPU than the sender
    }
    else
    {
        // BSP waits for every AP to halt itself
        QWORD timeoutAfterVmxOff = HvGetTimeGuard(VMXOFF_BROADCAST_TIMEOUT_US);
        while ((ctx->SyncCpuCountAfterVmxOff != ctx->TotalCpuCount) && !HvTimeout(timeoutAfterVmxOff))
        {
            CpuYield();
        }

        if (HvTimeout(timeoutAfterVmxOff)) WARNING("Failed to synchronize CPUs in HV after VMX broadcast ...\n");
    }

    return status;
}

static
NTSTATUS
_PwrWritePm1a(
    _In_ WORD IoPort,
    _In_ BYTE Length,
    _In_ BYTE *Value,
    _In_opt_ VOID* Context
    )
{
    NTSTATUS status;
    DWORD value = 0;
    BYTE length = Length;

    UNREFERENCED_PARAMETER(Context);

    if (!Value) return CX_STATUS_INVALID_PARAMETER_4;

    if (Power.Pm1aLength != Length)
    {
        WARNING("[POWER-ACPI] write on PM1A at 0x%04x with unsupported length %d. Will truncate to supported length %d\n", IoPort, Length, Power.Pm1aLength);
        length = Power.Pm1aLength;
    }

    switch (length)
    {
        case sizeof(BYTE) :
        {
            value = *(BYTE*)Value;
            break;
        }
        case sizeof(WORD) :
        {
            value = *(WORD*)Value;
            break;
        }
        case sizeof(DWORD) :
        {
            value = *(DWORD*)Value;
            break;
        }
        default:
        {
            ERROR("_PwrWritePm1a doesn't support access width: %d\n", length);
            value = 0;
            break;
        }
    }

    if (0 != (value & ACPI_BITMASK_SLEEP_ENABLE))
    {
        BOOLEAN oldWakeIsX;
        QWORD oldWake;
        BYTE powerState = (value >> 10) & 0x7;
        BYTE acpiPowerState;

        oldWakeIsX = FALSE;
        // old wakeup vector completed inside ACPI table
        oldWake = Power.Facs->FirmwareWakingVector;

        status = _PwrGetSleepState(powerState, &acpiPowerState);

        // CRITICAL: on Optiplex 790 we have an issue: even if docs says it shall NOT be possible, we have
        // both the X wake vector and the legacy wake vector present and non-zero; so we can't decide which
        // one shall be used... we use the legacy one (16 bit, REAL MODE)
        // Solution is to always use the legacy wakeup vector

        if (acpiPowerState == ACPI_STATE_S1)
        {
            VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI]: Entering S1 \n");
            VCPULOG(HvGetCurrentVcpu(), "Power.Facs->FirmwareWakingVector %p Power.Facs->XFirmwareWakingVector %p Power.Facs->Flags 0x%x \n", Power.Facs->FirmwareWakingVector, Power.Facs->XFirmwareWakingVector, Power.Facs->Flags);

            __wbinvd();

            // entering requested power state
            _PwrReadWritePm1aValue(FALSE, IoPort, (BYTE*)&value, length);

            VCPULOG(HvGetCurrentVcpu(), "\n\n\n**** S1 Wakeup started ****\n\n\n\n");
            goto all_done;

        }
        else if (acpiPowerState == ACPI_STATE_S3)
        {
            VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI]: Entering S3 -> Sleep/Hybrid Sleep \n");
            VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI] write 0x%04x to PM1A, will induce ACPI SLEEP (wakeup vector: %018p)\n", value, oldWake);
            VCPULOG(HvGetCurrentVcpu(), "Power.Facs->FirmwareWakingVector %p Power.Facs->XFirmwareWakingVector %p Power.Facs->Flags 0x%x \n", Power.Facs->FirmwareWakingVector, Power.Facs->XFirmwareWakingVector, Power.Facs->Flags);

            // disable NMI if active
            if (CfgFeaturesNmiPerformanceCounterTicksPerSecond) LapicDisablePerfNMI();

            // store old 16 bit REAL MODE wake vector
            Power.OldWakeOfs16 = (((DWORD)oldWake) & 0x000F);               // 16-bit offset
            Power.OldWakeSeg16 = ((((DWORD)oldWake) >> 4) & 0xFFFF);        // 16-bit segment
            status = _PwrOverwriteWakeupTrampoline((DWORD)oldWake);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("_PwrOverwriteWakeupTrampoline", status);
                goto cleanup;
            }

            Power.Port = IoPort;
            Power.Value = value;
        }
        else if (acpiPowerState == ACPI_STATE_S4)
        {
            VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI]: Entering S4 -> Hibernate \n");
        }
        else if (acpiPowerState == ACPI_STATE_S5)
        {
            VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI]: Entering S5 -> Shutdown \n");
        }
        else
        {
            VCPULOG(HvGetCurrentVcpu(), "[ERROR] [POWER-ACPI]: Entering unknown Sleep state \n");
        }

        __wbinvd();

        // Notify introspection about power state transition
        if (CfgFeaturesIntrospectionEnabled)
        {
            NapIntNotifyGuestPowerStateChange(HvGetCurrentGuest(), FALSE, acpiPowerState);
        }

        // As noted in Section 24.1, the processor may optimize VMX operation by maintaining the state of an
        // active VMCS(one for which VMPTRLD has been executed) on the processor.Before relinquishing
        // control to other system software that may, without informing the VMM, remove power from the
        // processor(e.g., for transitions to S3 or S4) or leave VMX operation, a VMM must VMCLEAR all active
        // VMCSs.This ensures that all VMCS data cached by the processor are flushed to memory and that
        // no other software can corrupt the current VMM's VMCS data.It is also recommended that the VMM
        // execute VMXOFF after such executions of VMCLEAR.

        // NOTE: As we do regular initialization and start-up on hibernate mostly, don't broadcast vmx_off
        if ((acpiPowerState != ACPI_STATE_S4) && (acpiPowerState != ACPI_STATE_S5))
        {
            _PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpus(TRUE);
        }

        IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

        PciSaveRestoreHiddenDevicesState(TRUE);

        HvPrintTimeInfo();

        // entering requested power state
        LOG("Put platform into requested power state now...\n");

        __wbinvd();

        _PwrReadWritePm1aValue(FALSE, IoPort, (BYTE*)&value, length);

        //
        // On Toshiba Tecra pt530e the cpu doesn't enter the power state right away as we program it
        // through IO port and continues execution at next instruction but eventually the system actually
        // enters the sleep state; this is the reason we have an Wait instruction here in an infinite loop
        //

        VCPULOG(HvGetCurrentVcpu(), "funky system that does not enter the lower power-state right away -> WAIT \n");

        while (&status)
        {
            HvSpinWait(10000);
        }

        // we shall never get here
        ERROR("[POWER-ACPI] after write 0x%04x to PM1A (you shall never see this, was a SLEEP command)\n", value);
        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        goto cleanup;
    }
    else
    {
        VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI] write 0x%04x to PM1A...\n", value);
        __wbinvd();

        _PwrReadWritePm1aValue(FALSE, IoPort, (BYTE*)&value, length);
        VCPULOG(HvGetCurrentVcpu(), "[POWER-ACPI] after write 0x%04x to PM1A\n", value);
    }
all_done:

    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
NTSTATUS
_PwrResumeHost(
    void
    )
{
    NTSTATUS status;

    Phase1InitializeHostControlRegisters();

    status = Phase1InitExceptionHandling();
    if (!SUCCESS(status))
    {
        LOG("ERROR: Phase1InitExceptionHandling failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    DbgInit();

    // NOTE: The final stack is setup from assembly because we saved it before entering sleep

    for (DWORD i = 0; i < gHypervisorGlobalData.CpuData.CpuCount; i++)
    {
        status = Phase1SetupCpuIpcQueue(gHypervisorGlobalData.CpuData.Cpu[i]);
        if (!SUCCESS(status)) LOG_FUNC_FAIL("Phase1SetupCpuIpcQueue", status);
    }
    IpcSetInterruptibilityValues(FALSE, 0, TRUE, IPC_ENABLED, TRUE, IPC_PRIORITY_LOWEST);

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

    //
    // execute PHASE I on all AP processors
    //
    status = Phase1TriggerAPsToStartAndWaitForCompletion();
    if (!SUCCESS(status))
    {
        LOG("ERROR: Phase1TriggerAPsToStartAndWaitForCompletion failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // initialize FXSAVE / XSAVE settings for the current PCPU
    Phase1InitializePerCpuFxRestoration();

    // turn ON VMX mode
    status = Phase1InitializePerCpuVmxOnZone();
    if (!SUCCESS(status))
    {
        LOG("ERROR: Phase1InitializePerCpuVmxOnZone failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

cleanup:
    return status;
}

NTSTATUS
PwrResumeHostAp(
    void
    )
{
    NTSTATUS status;

    CpuBindStructureToGs((PCPU*)&gGlobalDummyCpu);

    HvInterlockedIncrementU32(&gCpuReachedInit64);
    IoSetPerCpuPhase(IO_CPU_PHASE_INIT64);
    CpuActivateNxe();

    //
    // Make sure we don't enable output before setting the gdt and other initialization stuff
    // to avoid faults and hangs
    //
    IoSetPerCpuOutputEnabled(FALSE);

    status = CLN_REGISTER_SELF_HANDLER((CLN_CALLBACK)_PwrCpuCleanup, NULL, NULL);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("register _PwrCpuCleanup", status);

    // wait for BSP to signal we can proceed with STAGE I on APs
    {
        while (!gStageOneCanProceedOnAps)
        {
            if (gNeedToUnload)
            {
                status = STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
                goto cleanup;
            }

            CpuYield();
        }
    }

    Phase1InitializeHostControlRegisters();

    // setup GDT, TSS, IDT, GS:[0]
    status = Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu();
    if (!SUCCESS(status))
    {
        LOG("ERROR: Phase1LoadGdtTssIdtRegsOnCurrentPhysicalCpu failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // allow output from this CPU (maybe we could do it a bit earlier, you can try if you need output..)
    IoSetPerCpuOutputEnabled(TRUE);

    Phase1InitializePerCpuFxRestoration();

    IpcSetInterruptibilityValues(FALSE, 0, TRUE, IPC_ENABLED, TRUE, IPC_PRIORITY_LOWEST);

    // turn ON VMX mode
    status = Phase1InitializePerCpuVmxOnZone();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("Phase1InitializePerCpuVmxOnZone", status);
        goto cleanup;
    }


    LOG("[AP %d][WAKEUP] STAGE I done\n", HvGetCurrentApicId());
    HvInterlockedIncrementU32(&gStageOneInitedCpuCount);

    if (CfgFeaturesActivateHwp == 1) // if the activation is for any Windows
    {
        HvActivatePerformanceMode();
    }
    // wait for BSP to signal we can proceed with STAGE II on APs
    while ((!gStageTwoCanProceedOnAps))
    {
        if (gNeedToUnload)
        {
            status = STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
            goto cleanup;
        }

        CpuYield();
    }

    IoSetPerCpuPhase(IO_CPU_PHASE1);

    status = _PwrResumeVmcsState();
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_PwrResumeVmcsState", status);
        goto cleanup;
    }

    // signal to BSP that this AP finished STAGE II
    LOG("[AP %d] STAGE II done\n", HvGetCurrentApicId());
    HvInterlockedIncrementU32(&gStageTwoInitedCpuCount);
    IoSetPerCpuPhase(IO_CPU_PHASE2);

    //
    // === STAGE III ===
    //

    // wait for BSP to signal we can proceed with stage III
    while ((!gStageThreeCanProceedOnAps))
    {
        if (gNeedToUnload)
        {
            status = STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
            goto cleanup;
        }

        CpuYield();
    }

    HvGetCurrentCpu()->StartTsc = __rdtsc();

    LOG("[AP %d][WAKEUP]  STAGE III / HvPcpuRootMainCycle will start (TSC = %lld)...\n",
        HvGetCurrentApicId(), HvGetCurrentCpu()->StartTsc);

    if (HvGetCurrentCpu()->UseXsave) __xsetbv(0, HvGetCurrentCpu()->StartupXCR0);

    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
    {
        status = LapicSetupPerfNMI();
        if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("LapicSetupPerfNMI", status);
    }

    // run the core cycle of PHASE 3 - repeatedly get a VCPU on this CPU and execute it
    IoSetPerCpuPhase(IO_CPU_ROOT_CYCLE);
    HvPcpuRootMainCycle();

    LOG("[AP %d] STAGE III / ...HvPcpuRootMainCycle terminated!\n", HvGetCurrentApicId());

    status = CX_STATUS_SUCCESS;

cleanup:
    // always try to unload if an AP gets to this point
    CLN_UNLOAD(status);
    return status;
}

static
NTSTATUS
_PwrResumeGuest(
    void
    )
{
    NTSTATUS status;
    VCPU* primaryGuestVcpu;
    QWORD tsc;
    BOOLEAN resetVirtualTsc;

    VMCS_CONFIGURE_SETTINGS options = {
       .InitVmcs = CX_TRUE,
       .ActivateGuestDomain = CX_TRUE,
       .GuestOptions = VMCS_GUEST_REAL_MODE,
       .ControlsOptions = VMCS_CONTROLS_RESET_ONLY,
       .HostOptions = VMCS_HOST_DEFAULT,
       .ClearVmcsFromCpu = CX_TRUE,
       .SetNewVmcs = CX_TRUE
    };

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-

    if (0 == gHypervisorGlobalData.Guest[0]->VcpuCount)
    {
        LOG("[CRITICAL] 0 == gHypervisorGlobalData.Guest[0].VcpuCount \n");
        goto cleanup;
    }

    // If the real TSC is smaller than the TSC of the last VM-entry, we assume the TSC has been reset at wakeup, and we
    // reset the virtual TSC as well.
    // Some CPUs may have constant TSC (which doesn't get reset on resume); however, I didn't find any
    // ref to this in Intel docs, and the Xen source reveal that the feature might be emulated by the hypervisor
    // only.
    tsc = __rdtsc();

    resetVirtualTsc = tsc < HvGetCurrentVcpu()->LastEntryTsc;
    gHypervisorGlobalData.Guest[0]->SipiCount = 1; // BSP will NOT receive a SIPI
    gHypervisorGlobalData.Guest[0]->SipiMask = 1; // BSP will NOT receive a SIPI
    gHypervisorGlobalData.Guest[0]->PowerState = GstNoPowerTransition;

    for (DWORD i = 0; i < gHypervisorGlobalData.Guest[0]->VcpuCount; i++)
    {
        primaryGuestVcpu = gHypervisorGlobalData.Guest[0]->Vcpu[i];

        primaryGuestVcpu->VcpuPauseCount = 0;
        primaryGuestVcpu->FirstApInitExitState = BEFORE_FIRST_INIT_EXIT;
        primaryGuestVcpu->CurrentExitReason = EXIT_REASON_INVALID;
        primaryGuestVcpu->MemoryDomain.HistoryIndex = 0;

        // Reset the virtual TSC.
        if (resetVirtualTsc)
        {
            primaryGuestVcpu->VirtualTsc = 0;
            primaryGuestVcpu->LinearTsc = 0;
        }

        primaryGuestVcpu->Schedulable = TRUE;


        // send guest CPUs to 16-bit mode to make the guests wakeup from sleep
        if (0 == i)
        {

            options.GuestConfig.RealModeState.Cs = Power.OldWakeSeg16;
            options.GuestConfig.RealModeState.Ip = Power.OldWakeOfs16;
            options.GuestConfig.RealModeState.Ss = 0;
            options.GuestConfig.RealModeState.Sp = 0;
            options.GuestConfig.RealModeState.ActivityState = VMCS_GUEST_ACTIVITY_STATE_ACTIVE;

        }
        else
        {
            options.GuestConfig.RealModeState.Cs = 0;
            options.GuestConfig.RealModeState.Ip = 0x7c00;
            options.GuestConfig.RealModeState.Ss = 0;
            options.GuestConfig.RealModeState.Sp = 0;
            options.GuestConfig.RealModeState.ActivityState = VMCS_GUEST_ACTIVITY_STATE_HLT;
        }

        status = VmstateConfigureVmcs(
            primaryGuestVcpu,
            &options
        );
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
            return status;
        }

        status = VmstateUpdateVmcsForIntrospection(primaryGuestVcpu, TRUE, TRUE);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("VmstateUpdateVmcsForIntrospection", status);

        primaryGuestVcpu->RestoreExtState = FALSE;
        primaryGuestVcpu->UsedExitReasonEntries = 0;

        // reset saved VCPU CR8, else we may restore the CR8 from before the sleep transition
        primaryGuestVcpu->PlatformCr8AtExit = 0;
    }

    // trigger APs to perform STAGE II init
    gStageTwoCanProceedOnAps = TRUE;

    //
    // common BSP / AP per-PCPU flow (so we simply call the AP path from the BSP also)
    //
    status = _PwrResumeVmcsState();
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

    gHypervisorGlobalData.Guest[0]->SharedBufferGPA = gHypervisorGlobalData.Comm.SharedBufferHpa; // IDENTITY MAPPED ALWAYS
    LOG("Shared mem buffer GPA on WAKEUP: %p\n", gHypervisorGlobalData.Guest[0]->SharedBufferGPA);

    status = ChmGpaToHpa(gHypervisorGlobalData.Guest[0], gHypervisorGlobalData.Guest[0]->SharedBufferGPA, &gHypervisorGlobalData.Guest[0]->SharedBufferHPA);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("ChmGpaToHpa", status);
        goto cleanup;
    }

    gHypervisorGlobalData.Comm.SharedBufferHpa = gHypervisorGlobalData.Guest[0]->SharedBufferHPA;
    gHypervisorGlobalData.Comm.SharedMem->Initialized = TRUE;
    gHypervisorGlobalData.Comm.SharedMem->DenyAlloc = FALSE;

    INFO("ShMem HPA on WAKEUP: %p\n", gHypervisorGlobalData.Comm.SharedBufferHpa);

    status = GstInitRipCache(
        &gHypervisorGlobalData.Guest[0]->RipCache,
        RIP_CACHE_MAX_ENTRIES);
    if (!NT_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstInitRipCache", status);
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
NTSTATUS
_PwrResumeVmcsState(
    void
    )
{
    NTSTATUS status;

    HvInterlockedBitTestAndSetU64(&gHypervisorGlobalData.Debug.AffinifyMask, HvGetCurrentCpuIndex());

    // initialize VMCS host state for the VCPU associated to the current PCPU
    status = VmstateConfigureVmcs(HvGetCurrentCpu()->Vcpu, VMCS_CONFIGURE_SETTINGS_INIT_HOST_STATE);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("VmstateConfigureVmcs", status);
        goto cleanup;
    }

    //
    // invalidate all VMX / EPT / VPID caches before we start to schedule the VCPUs
    //
    {
        status = CpuVmxInvEpt(2, 0, 0);        // TYPE 2: All-context invalidation
        if (!SUCCESS(status))
        {
            LOG("[CPU %d] CpuVmxInvEpt (TYPE 2) failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
            goto cleanup;
        }

        status = CpuVmxInvVpid(2, NULL, 0);     // TYPE 2: All-context invalidation
        if (!SUCCESS(status))
        {
            LOG("[CPU %d] CpuVmxInvVpid (TYPE 2) failed, status=%s\n", HvGetCurrentApicId(), NtStatusToString(status));
            goto cleanup;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
NTSTATUS
_PwrCpuCleanup(
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
    )
{
    VOID *destination;
    WAKEUP_RUN_ORIGINAL_VECTOR CpuUnload;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(OriginalState);

    LOG("[CPU %d] [CLN] preparing to run the cpu cleanup routine\n", CLN_GET_CURRENT_CPUID());

    // park all APs in halt
    if (CLN_GET_CURRENT_CPUID() != CLN_BSP_ID)
    {
        LOG("[CPU %d] [CLN] AP parked in a halted state awaiting a SIPI\n", CLN_GET_CURRENT_CPUID());
        ClnUnlockApCleanupHandler(0, 0, FALSE); // release the LOCK so that the next CPU can continue
        gClnNumberOfExitedCpus++;
        IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
        __halt();
    }

    // restore memory state for the os 16bit resume
    LOG("[CPU %d] [CLN] Restoring overwritten memory...\n", CLN_GET_CURRENT_CPUID());
    _PwrRestoreWakeupTrampoline();

    // find free <1MB memory storage for the HV to guest trampoline code and copy our code
    LOG("[CPU %d] [CLN] Copying trampoline code...\n", CLN_GET_CURRENT_CPUID());
    destination = (VOID*)((SIZE_T)(57*ONE_KILOBYTE));
    memcpy(destination, &WakeupRunOriginalVector, (SIZE_T)&WakeupRunOriginalVectorEnd - (SIZE_T)&WakeupRunOriginalVector);

    CpuUnload = (WAKEUP_RUN_ORIGINAL_VECTOR) (SIZE_T)destination;

    // goodbye cruel wakeup
    LOG("[CPU %d] exiting HV by running the original wakeup vector...\n", CLN_GET_CURRENT_CPUID());
    ClnUnlockApCleanupHandler(0, 0, FALSE); // release the LOCK so that the next CPU can continue
    gClnNumberOfExitedCpus++;

    // call WakeupRunOriginalVector via its copy located at CpuUnload
    CpuUnload(Power.OldWakeSeg16, Power.OldWakeOfs16);

    // this can't be happening... :|
    CRITICAL("[CPU %d] we couldn't unload and wakeup the guest\n", CLN_GET_CURRENT_CPUID());
    __halt();

    return CX_STATUS_SUCCESS;
}

void
PwrInitAcpiSleepStates(
    void
    )
{
    UINT8 typeA;
    UINT8 typeB;
    ACPI_STATUS acpiStatus = AE_ERROR;

    for (UINT8 state = ACPI_STATE_S0; state <= ACPI_S_STATES_MAX; state++)
    {
        acpiStatus = AcpiGetSleepTypeData(state, &typeA, &typeB);

        if (acpiStatus != AE_NOT_FOUND)
        {
            gPowerTransTypeFound |= 1 << state;
            gPowerTransType[state] = typeA | typeB;
        }
    }
}

static
NTSTATUS
_PwrGetSleepState(
    _In_  BYTE SleepTypeVal,
    _Out_ BYTE *AcpiSleepType
    )
{
    NTSTATUS status = CX_STATUS_NOT_INITIALIZED;
    UINT8 state;

    *AcpiSleepType = 0;

    for (state = ACPI_STATE_S0; state <= ACPI_S_STATES_MAX; state++)
    {
        if (SleepTypeVal == gPowerTransType[state])
        {
            *AcpiSleepType = state;

            // Check if the value we have found was found by ACPI or predefined by us
            if (!(gPowerTransTypeFound & (1 << state))) WARNING("Using predefined sleep type for S%d, value=%d", state, gPowerTransType[state]);
            else status = CX_STATUS_SUCCESS;

            break;
        }
    }

    if (state == ACPI_S_STATES_MAX + 1) WARNING("Couldn't match value %d with any of the \\_Sx types", SleepTypeVal);

    return status;
}

static
VOID
_PwrPlatformWriteResetValue(
    _In_opt_ VOID* Ptr,
    _In_opt_ WORD Port,
    _In_ QWORD Value,
    _In_ BYTE AccessWidth
)
{
    if (Ptr)
    {
        switch (AccessWidth)
        {
            case sizeof(BYTE) :
            {
                ((BYTE*)(Ptr))[0] = (BYTE)Value;
                break;
            }
            case sizeof(WORD) :
            {
                ((WORD*)(Ptr))[0] = (WORD)Value;
                break;
            }
            case sizeof(DWORD) :
            {
                ((DWORD*)(Ptr))[0] = (DWORD)Value;
                break;
            }
            default:
            {
                ((QWORD*)(Ptr))[0] = (QWORD)Value;
                break;
            }
        }
    }
    else
    {
        switch (AccessWidth)
        {
            case sizeof(BYTE) :
            {
                __outbyte(Port, (BYTE)Value);
                break;
            }
            case sizeof(WORD) :
            {
                __outword(Port, (WORD)Value);
                break;
            }
            default:
            {
                __outdword(Port, (DWORD)Value);
                break;
            }
        }
    }
}

static
VOID
_PwrPlatformReboot(
    VOID
)
//
// Tries all possible methods reboot
//
{
    //
    // ACPI reboot -- Verify if system reset via the FADT RESET_REG is supported
    //
    if ((Power.Fadt != NULL) && (Power.Fadt->Flags & ACPI_FADT_RESET_REGISTER))
    {
        NTSTATUS status = CX_STATUS_SUCCESS;
        VCPULOG(HvGetCurrentVcpu(), "FADT RESET_REG is supported, reboot CPU by ACPI Reset Register!\n");

        if (Power.Fadt->ResetRegister.SpaceId == ACPI_ADR_SPACE_SYSTEM_IO)
        {
            _PwrPlatformWriteResetValue(NULL, (WORD)Power.Fadt->ResetRegister.Address, Power.Fadt->ResetValue, Power.Fadt->ResetRegister.AccessWidth);

            HvSpinWait(1000);
        }
        else if (Power.Fadt->ResetRegister.SpaceId == ACPI_ADR_SPACE_SYSTEM_MEMORY)
        {
            BYTE *hva = NULL;
            status = MmMapDevMem(&gHvMm, Power.Fadt->ResetRegister.Address, PAGE_SIZE, TAG_RESET, &hva);
            if (SUCCESS(status))
            {
                _PwrPlatformWriteResetValue(hva, 0, Power.Fadt->ResetValue, Power.Fadt->ResetRegister.AccessWidth);

                HvSpinWait(1000);
            }
        }
        else if (Power.Fadt->ResetRegister.SpaceId == ACPI_ADR_SPACE_PCI_CONFIG)
        {
            WORD bus, dev, func, offset;
            PCI_CONFIG* pciConfig = NULL;

            offset = Power.Fadt->ResetRegister.Address & 0xFFFF;
            func = ((Power.Fadt->ResetRegister.Address >> 16) & 0xFFFF);
            dev = ((Power.Fadt->ResetRegister.Address >> 32) & 0xFFFF);
            bus = 0;

            pciConfig = PciGetConfigSpaceVa(bus, dev, func);
            _PwrPlatformWriteResetValue((VOID*)&pciConfig->Raw[offset], 0, Power.Fadt->ResetValue, Power.Fadt->ResetRegister.AccessWidth);

            HvSpinWait(1000);
        }
        else CRITICAL("Acpi reset space id %d not supported!\n", Power.Fadt->ResetRegister.SpaceId);

    }

    //
    //  Keyboard controller
    //
    if ((Power.Fadt != NULL) && (Power.Fadt->BootFlags & ACPI_FADT_8042))
    {
        VCPULOG(HvGetCurrentVcpu(), "We have Keyboard Controller, Try to reboot CPU with it!\n");
        __outbyte(0x64, 0xFE);
    }

    //
    // PCI address space reboot - power cycle
    //
    // RST_CNT register reset: --> refer to 30.6.4 of "Intel Atom Processor E3800 Product Family: Datasheet"
    //
    VCPULOG(HvGetCurrentVcpu(), "Reset via Reset Control Register, Try to reboot CPU with it!\n");
    __outbyte(0xCF9, 0x2);  // set up hard reset bit
    HvSpinWait(10);         // little wait recommended for some older platforms
    __outbyte(0xcf9, 0x06); // --> 0x0e full reset, 0x06 - not full power cycle (warm reset)

    //
    // PCI address space reboot - hardcore reset --> full power cycle reboot (cold reset)
    //
    __outbyte(0xCF9, 0xFF);
}

VOID
PwrReboot(
    _In_    BOOLEAN     PerformVmxoffBroadcast,
    _In_    BOOLEAN     IsEmergency
)
{
    if (PerformVmxoffBroadcast && (HvGetCurrentCpu() != NULL) && (HvGetCurrentCpu()->VmxActivated))
    {
        _PwrBroadcastVmxOffBeforePowerTransitionAndHaltOtherCpus(FALSE);
    }

    BOOLEAN doHalt = IsEmergency && !DumpersTryToDumpEmergencyLogs();
    if (doHalt)
    {
        CRITICAL("HALT!\n");
        __halt();
    }
    else
    {
        _PwrPlatformReboot();
    }
}

///@}