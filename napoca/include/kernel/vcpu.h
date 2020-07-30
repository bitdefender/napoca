/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file vcpu.h
*   @brief VCPU - VCPU definitions and functions for Guest Memory Domain management
*
*/

#ifndef _VCPU_H_
#define _VCPU_H_

#include "core.h"
#include "common/external_interface/disasm_types.h"
#include "common/kernel/vmxdefs.h"
#include "common/kernel/cpu_state.h"
#include "kernel/emu.h"
#include "kernel/emhv.h"
#include "kernel/pcpu.h"
#include "memory/cachedef.h"
#include "kernel/spinlock.h"
#include "kernel/rwspinlock.h"
#include "kernel/guestenlight.h"
#include "debug/perfstats.h"
#include "guests/virt_exceptions.h"
#include "memory/tas.h"
#include "memory/ept.h"

typedef struct _GUEST_MEMORY_DOMAIN GUEST_MEMORY_DOMAIN; ///< Structure describing a guests entire memory usage
typedef CX_UINT8 GUEST_MEMORY_DOMAIN_INDEX;

/// @brief Enumeration of the states of a Virtual CPU
typedef enum // should be kept in sync with the values in the vcpu64.nasm
{
    VCPU_STATE_INVALID                  = 0, ///< Invalid state
    VCPU_STATE_NOT_ACTIVE               = 1, ///< The VMCS of the current VCPU was not launched
    VCPU_STATE_ACTIVE                   = 2, ///< The VCMS of the current VCPU was launched
    VCPU_STATE_ERROR                    = 3, ///< The VMLAUNCH or the VMRESUME operation failed
    VCPU_STATE_TOTAL_VALUES             = 4  ///< Maximum value
}VCPU_STATE;

/// @brief Enumeration of the states for a VCPU regarding the pausing mechanism
typedef enum
{
    VCPU_PAUSING_STATE_RUNNING          = 0, ///< The guest is running, none of the VCPUs requested pausing
    VCPU_PAUSING_STATE_PAUSED           = 1, ///< The guest is paused, none of the VCPU are allowed to run
    VCPU_PAUSING_STATE_TOTAL_VALUES     = 2  ///< Maximum value
}VCPU_PAUSING_STATE;

#define MAX_CSRIP_TRACE                 8       ///< multiple of 4, the maximum number of stored RIP and CS values for single-stepping
#define LAST_EXIT_REASONS_COUNT         16      ///< multiple of 2, preferable 2^N -- how many exit reasons to keep in memory
#define EXIT_REASONS_COUNT              16      ///< multiple of 2, preferable 2^N -- how many exit reasons to keep in memory

#define MAX_VCPU_DOMAIN_HISTORY              8

/// @brief Structure holding the VMCS control registers content
typedef struct _VMCS_CONFIG
{
    CX_UINT32 PinExecCtrl;                  ///< Pin-Based VM-Execution Controls
    CX_UINT32 ProcExecCtrl;                 ///< Primary Processor-Based VM-Execution Controls
    CX_UINT32 ProcExecCtrl2;                ///< Secondary Processor-Based VM-Execution Controls
    CX_UINT32 VmExitCtrl;                   ///< VM-Exit Controls
    CX_UINT32 VmEntryCtrl;                  ///< VM-Entry Controls
    CX_UINT32 VmfuncCtrl;                   ///< VM-Function Controls
} VMCS_CONFIG;

/// @brief Data-structure representing a Virtual CPU.
typedef struct _VCPU
{
#pragma pack(push)
#pragma pack(1)
    struct __VCPU_ASM_FIELDS__ // please keep in sync with vcpu64.nasm
    {
        volatile CX_UINT16 State;                    ///< Mostly used to deduct if the VCPU needs to be launched/resumed or failed(VCPU_STATE_*)
        volatile CX_BOOL Schedulable;                ///< CX_TRUE if the VCPU can be scheduled
        PCPU* Pcpu;                                  ///< CX_NULL if this VCPU is NOT running on a PCPU or a valid PCPU

        GUEST* Guest;                                ///< The guest this VCPU is associated with
        CX_VOID* GuestExitRoutine;                   ///< Per-VCPU exit routine (currently we use a single one in the whole hypervisor)
        volatile CX_INT64 ExitCount;                 ///< Total VM exits count on the current VCPU
        CX_UINT16 Vpid;                              ///< Hypervisor wide unique VPID
        CX_UINT8 GuestIndex;                         ///< 0-based GUEST index in hypervisor
        CX_UINT8 GuestCpuIndex;                      ///< 0-based VCPU index in guest's VCPU array

        CX_UINT32 LapicId;                           ///< Virtual LAPIC ID associated with this VCPU (currently equals to it's PCPU's LAPIC ID)

        CX_UINT64 LastExitTsc;                       ///< Saved value of the TSC right after the last EXIT occurred
        CX_UINT64 LastEntryTsc;                      ///< Saved value of the TSC right after before the ENTRY occurred
        CX_UINT64 PrevInHostTscDuration;             ///< How many ticks did the previous exit handling (root-mode code execution) took on current VCPU
        CX_UINT64 PrevInGuestTscDuration;            ///< How many ticks did the VCPU spent uninterrupted before this exit
        CX_UINT64 LinearTsc;                         ///< Linear TSC (start when HV loads, doesn't get ever rewritten, can be used for timers)
        CX_UINT64 VirtualTsc;                        ///< The TSC that the guest sees (when reading/writing the IA32_TSC MSR)

        ARCH_REGS ArchRegs;                          ///< Basic x86/x64 registers (0x100 in length)

        CPU_EXT_STATE* ExtState;                     ///< Extended state (usually 4K+, for FPU/SSE/AVX/...)
        CX_BOOL RestoreExtState;                     ///< CX_TRUE if we have to restore the extended FPU/SSE state upon the next VM-entry

        struct
        {
            CX_UINT64 GuestHaltedCsRip;              ///< The execution point where the VCPU was last halted
            CX_UINT64 TimesHalted;                   ///< Total amount of halts
            CX_BOOL IsInactive;                      ///< CX_TRUE if currently the VCPU is halted by guest
        } GuestActivityMonitor;
    };
    /// END-OF-ASM-FIELDS
#pragma pack(pop)

    CX_VOID* Vmcs;                                   ///< HVA pointing to the VMCS structure
    CX_UINT64 VmcsPa;                                ///< HPA pointing to the VMCS structure

    MTRR_STATE* Mtrr;                                ///< Contains a per-VCPU MTRR state, both for fixed and variable range MTRRs
                                                     ///< IMPORTANT: even if we DO have a per-VCPU copy of the MTRR MSRs, we do NOT have a complete per-VCPU EPT table set,
                                                     ///< but a single one, based on a per-GUEST MTRR MSR set (configured according to the BSP's MTRR settings)

    CPUSTATE_GUEST_STATE_INFO* BootState;            ///< Pointer to the guest VCPU state structure for initialization
    PSEUDO_REGS PseudoRegs;                          ///< Read-only values for segment-based pointer registers or other non-elementary architectural values

    VMCS_CONFIG VmcsConfig;                          ///< VMCS configuration info for this VCPU

    struct
    {
        CX_UINT64 InfoPageHpa;                       ///< HPA of the \#VE information page
        VEINFOPAGE* InfoPageHva;                     ///< HVA of the \#VE information page
        CX_UINT64 InfoPageGpa;                       ///< GPA of the \#VE information page
    } VirtualizationException;

    CX_UINT64 VmxTimerQuantum;                       ///< The value of the preemption timer in the VMCS

    CX_UINT64 ReadShadowCR0;                         ///< Read shadow of the CR0 register in the VMCS
    CX_UINT64 GuestHostMaskCR0;                      ///< Guest/host mask of the CR0 register in the VMCS
    CX_UINT64 ReadShadowCR4;                         ///< Read shadow of the CR4 register in the VMCS
    CX_UINT64 GuestHostMaskCR4;                      ///< Guest/host mask of the CR4 register in the VMCS

    CX_BOOL EmulatingEptViolation;                   ///< CX_TRUE if currently emulating EPT violation
    CX_BOOL SafeToReExecute;                         ///< CX_TRUE if it is safe to re-execute an instruction using the fall-back mechanism

    CX_BOOL RexecPending;                            ///< CX_TRUE if a re-execution is pending on this VCPU

    CX_UINT64 OldProcExecControls;                   ///< A saved value of the Processor Execution Control field if it was altered

    struct
    {
        CX_UINT64 OldRcxValue;
        CX_UINT64 OldRipValue;
        CX_UINT64 OldRsiValue;
    } RepWorkaroundContext;                          ///< Fields for the workaround for "Intel(R) Atom(TM) CPU C2550 @ 2.41GHz"

    CX_BOOL PagingStructureViolation;                ///< CX_TRUE if it is a paging structure violation, concluded from the exit qualification field
    CX_UINT64 LastPageWalkRip;                       ///< The last RIP for which we emulated a page-walk
    CX_UINT64 LastPageWalkGla;                       ///< The last GLA on what we executed a page-walk

    volatile CX_UINT32 VcpuPauseCount;               ///< The total number of pauses of this VCPU

    struct {
        CX_BOOL BufferValid;                         ///< CX_TRUE if we have a valid emulation buffer for the introspection engine
        CX_UINT32 BufferSize;                        ///< The size of the emulation buffer
        CX_UINT8 Buffer[ND_MAX_OPERAND_SIZE];        ///< The actual emulation buffer
        CX_UINT8 BufferBackup[ND_MAX_OPERAND_SIZE];  ///< A backup emulation buffer
        CX_UINT64 BufferGla;                         ///< GLA for the emulation buffer
        struct {
            CX_UINT8* Buffer;                        ///< Buffer used for single stepping
            CX_UINT64 BufferSize;                    ///< The size of the buffer used for single stepping
            CX_UINT64 BufferPa;                      ///< The HPA for the buffer used for single stepping
        } SingleStep;
    } IntroEmu;

    CX_BOOL IntroRequestedTrapInjection;             ///< CX_TRUE if the introspection engine requested a trap injection

    CX_UINT64 IntroTimer;                            ///< The last time the introspection's timer was called
    CX_UINT64 Cr3LoadExitEnabledCount;               ///< The number of activations for the CR3 load exiting (~ref counter)
    CX_UINT64 DescTableExitEnabledCount;             ///< The number of activations for the descriptor table exiting (~ref counter)
    CX_UINT64 BreakpointExitEnabledCount;            ///< The number of activations for the \#BP exception exiting (~ref counter)

    struct _VCPU_CACHE_MAP
    {
        CHM_CACHE CachedTranslations;                           ///< Volatile cache info for guest VA addresses
        CHM_CACHE_ENTRY TranslationsArray[CHM_VA_TRANSLATIONS]; ///< The actual volatile cache entries
    };

    struct _VCPU_DEBUG_CONTEXT
    {
        CX_INT8 *BreakOnCondition;                   ///< An expression that whenever is seen as !=0 will break into debugger
        CX_INT8 *TriggerCondition;                   ///< An expression that should trigger a debugger command evaluation
        CX_INT8 *TriggerCommand;                     ///< The operation to perform when the TriggerCondition is !=0
        CX_BOOL BreakOnCondMatched;                  ///< CX_TRUE if the BreakOnCondition was met
        CX_BOOL TriggerOnCondMatched;                ///< CX_TRUE if the TriggerCondition was met
        CX_UINT8 SingleStep;                         ///< A saved state from the TRACING_CONFIG enumeration
        CX_BOOL StopTracingAfterExit;                ///< CX_TRUE if the instruction tracing needs to be stopped after this exit
        CX_BOOL EnableIfOnTrap;                      ///< CX_TRUE if we need to set the interrupt flag (workaround for BLOCKING_BY_STI)
        CX_UINT16 LastCs[MAX_CSRIP_TRACE];           ///< The last code segments saved used, for single-step-debugging
        CX_UINT64 LastCsBase[MAX_CSRIP_TRACE];       ///< The last code segment bases saved, used for single-step-debugging
        CX_UINT64 LastRip[MAX_CSRIP_TRACE];          ///< The last RIP saved, used for single-step-debugging
    } DebugContext;

    struct _LAST_EXIT_DATA{
        CX_UINT64 Reason;
        CX_UINT64 DiffTsc;
        CX_UINT64 Rip;
    } LastExitReasons[LAST_EXIT_REASONS_COUNT];      ///< Circular buffer containing the exit response
    CX_UINT32   LastExitReasonIndex;                 ///< Index of the latest used entry
    CX_UINT32   UsedExitReasonEntries;               ///< 0 to LAST_EXIT_REASONS_COUNT - 1

    PCPU* AttachedPcpu;                              ///< A permanent pointer to the logical processor that this VCPU is scheduled on

    struct
    {
        volatile CX_UINT32 ExceptionInjectionMask;   ///< Each bit selects an exception. If the bit is set, the according exception must be injected
        EXCEPTION_INFO ExceptionInfo[EXCEPTION_END]; ///< Exception info, common & specific per exception
    } VcpuException;

    CX_BOOL IsBsp;                                   ///< TRUE is VCPU is BSP for the guest

    volatile CX_UINT32  CalledGstPauseCount;         ///< The number of pauses called for the guest per VCPU

    volatile struct
    {
        CX_UINT32 Ept;                               ///< VCPU memory domain updates synchronization state -- when 0: not started, 1: acquiring the global guest lock, sign bit = 1: update in progress
        CX_UINT32 Reexec;                            ///< VCPU instruction re-execution synchronization state -- when 0: not started, 1: acquiring the global guest lock, sign bit = 1: re-execution in progress
    } SynchronizedUpdate;

    CX_UINT64 CurrentExitReason;                     ///< The current exit's reason
    CX_UINT64 PrevExitReason;                        ///< The previous exit's reason
    CX_UINT64 PrevCr8;                               ///< The previous exit's CR8 value

    struct _VCPU_MS_HV_INTERFACE
    {
        CX_UINT64 MsftMsr[HV_X64_MSR_MAX_COUNT];     ///< Synthetic MSRs
        HV_REFERENCE_TSC_PAGE   *ReferenceTscPage;   ///< HVA of reference TSC page
        CX_UINT64 PartitionReferenceTime;            ///< Snapshot of partition counter to be used during current exit on this VCPU
    };

    CX_UINT64 PlatformCr8AtExit;                     ///< Saved value of the PCPU's CR8, only for consistency

    struct
    {
        PERF_STATS ExitStats[EXIT_REASON_MAX];       ///< Statistical data about the exit
        PERF_STATS HostStats;                        ///< Statistical data for the host
        PERF_STATS GuestStats;                       ///< Statistical data for the guest
        CX_UINT64 LastPauseTransitionTsc;            ///< Saved TSC value for the last transition in/from pause
        PERF_STATS PausingStats[VCPU_PAUSING_STATE_TOTAL_VALUES]; ///< Statistical data for guest pausing
    };

    enum
    {
        BEFORE_FIRST_INIT_EXIT = 0,                  ///< Before the first Init IPI is received
        AT_FIRST_INIT_EXIT = 1,                      ///< The first Init IPI arrived
        AFTER_FIRST_INIT_EXIT = 2                    ///< After the first Init IPI arrived
    } FirstApInitExitState;                          ///< When 1, it's  a time-critical exit and we shouldn't spend too much time handling it

    CX_BOOL IsSppActive;                             ///< Sub-page protection is active

    struct {
        GUEST_MEMORY_DOMAIN* ActiveDomain;           ///< Memory domain currently used by this VCPU
        GUEST_MEMORY_DOMAIN* History[MAX_VCPU_DOMAIN_HISTORY]; ///< Stack of previously active domains used for undoing a list of VcpuActivateDomain calls
        volatile CX_UINT8 HistoryIndex;              ///< The number of #History stack entries currently populated / in use
        SPINLOCK Lock;                               ///< Domain stack synchronization lock
    } MemoryDomain;
} VCPU;


///
/// @brief        Pre-initialize the VCPU structure, allocates single-step buffer, VMCS page, sets up the Guest exit routine and initializes some other VCPU fields.
///
/// @param[in, out] Vcpu                           The VCPU structure which is initialized.
/// @param[in]    Guest                            The Guest to whom the VCPU is attached.
/// @param[in]    VcpuIndex                        The index of the VCPU in the Guests VCPU array.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_XXX                    - if one of the memory allocations failed
///
///
CX_STATUS
VcpuPreinit(
    _Inout_ VCPU                        *Vcpu,
    _In_ GUEST                          *Guest,
    _In_ CX_UINT32                      VcpuIndex
);


///
/// @brief        Remembers the current domain(Guest Memory Domain) and switches to the new one
///
/// @param[in]    Vcpu                             The VCPU for which the domain is activated/changed
/// @param[in]    Domain                           Pointer to the new Guest Memory Domain
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - if the Memory Domain History is full already (no more stack space to track the domain changes history)
/// @returns      CX_STATUS_XXX                    - if Domain given is not initialized/valid entirely for this operation to complete
///
CX_STATUS
VcpuActivateDomainEx(
    _In_ VCPU *Vcpu,
    _In_ GUEST_MEMORY_DOMAIN        *Domain
);


///
/// @brief        Remembers the current domain(Guest Memory Domain) and switches to the new one
///
/// @param[in]    Vcpu                             The VCPU for which the domain is activated/changed.
/// @param[in]    DomainIndex                      The domain index inside the Guests Memory Domains array.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - if the Memory Domain History is full already (no more stack space to track the domain changes history)
/// @returns      CX_STATUS_XXX                    - if Domain given is not initialized/valid entirely for this operation to complete or it is not to be found
///
CX_STATUS
VcpuActivateDomain(
    _In_ VCPU                           *Vcpu,
    _In_ GUEST_MEMORY_DOMAIN_INDEX      DomainIndex
);


///
/// @brief        Restores and activates the previous domain, if there is one.
///
/// @param[in]    Vcpu                             The VCPU for which the domain is deactivated/changed.
/// @param[in]    ActiveDomain                     Optional, used only for a sanity check, to validate that the domain given was indeed the active one for the Vcpu
/// @param[in]    ForceDeactivation                Transition even if the current memory domain is not ActiveDomain (i.e. it's not the expected one)
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_DATA_ALTERED_FROM_OUSIDE - if the given domain was not the active domain and no forced deactivation was requested
/// @returns      CX_STATUS_XXX                    - if the Domain from the history is somehow not initialized or can't be set to active (should not be possible)
///
CX_STATUS
VcpuDeactivateDomainEx(
    _In_ VCPU                       *Vcpu,
    _In_opt_ GUEST_MEMORY_DOMAIN    *ActiveDomain,
    _In_ CX_BOOL                    ForceDeactivation
);


///
/// @brief        Restores and activates the previous domain, if there is one.
///
/// @param[in]    Vcpu                             The VCPU for which the domain is deactivated/changed.
/// @param[in]    DomainIndex                      The domain index inside the Guests Memory Domains array, optional, used only for a sanity check,
///                                                to validate that the domain given was indeed the active one for the Vcpu.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_DATA_ALTERED_FROM_OUSIDE - if the given domain was not the active domain and no forced deactivation was requested
/// @returns      CX_STATUS_XXX                    - if the Domain from the history is somehow not initialized or can't be set to active (should not be possible)
///
CX_STATUS
VcpuDeactivateDomain(
    _In_ VCPU                           *Vcpu,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *DomainIndex
);


///
/// @brief        Returns the active Memory Domains index inside the Guests Memory Domains array.
///
/// @param[in]    Vcpu                             The VCPU for which the active domains index is requested.
/// @param[out]   DomainIndex                      Pointer to where the domain index should be returned.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_COMPONENT_NOT_READY    - if the Vcpu has no current active domain.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Vcpu is an invalid pointer.
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - if DomainIndex is an invalid pointer.
///
CX_STATUS
VcpuGetActiveMemoryDomainIndex(
    _In_ VCPU                           *Vcpu,
    _Out_ GUEST_MEMORY_DOMAIN_INDEX *DomainIndex
);


///
/// @brief        Returns the current active Memory Domains EPT descriptor if EPT pointer is valid, otherwise only validates the domain.
///
/// @param[in]    Vcpu                             The VCPU for which the active domains ept descriptor is requested.
/// @param[out]   Ept                              Optional, pointer to where the EPT_DESCRIPTORs address should be stored.
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_COMPONENT_NOT_READY    - if the Vcpu has no current active domain.
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - if Vcpu is an invalid pointer.
/// @returns      CX_STATUS_XXX                    - if there were other internal problems for getting the Domain and the Ept descriptor
///
CX_STATUS
VcpuGetActiveEptDescriptor(
    _In_ VCPU                           *Vcpu,
    _Out_opt_ EPT_DESCRIPTOR            **Ept
);


///
/// @brief        Check/account for automatic \#VE memory domain transition occurred during the last guest execution session, validates the current
///               active domain against what is really present on the hardware. It only does a validation, as for now it is not important which is the
///               currently active EPTP throughout the exit handling
///
/// @param[in]    Vcpu                             The VCPU for which the refresh/check is done
///
/// @returns      CX_STATUS_SUCCESS                - if it was with success
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - if the Vcpu has an active memory domain which is not matching the EPTP of the VPCU
/// @returns      CX_STATUS_XXX                    - if there were other internal problems for getting the Ept descriptor and its' root physical address
///
CX_STATUS
VcpuRefreshActiveMemoryDomain(
    _In_ VCPU *Vcpu
);

#endif // _VCPU_H_
