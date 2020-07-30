/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// GUESTS - GUEST definitions

#ifndef _GUESTS_H_
#define _GUESTS_H_

#ifdef NAPOCA_BUILD
#include "core.h"
#endif

#include "kernel/kerneldefs.h"
#include "boot/boot.h"
#include "kernel/vcpu.h"
#include "memory/mmap.h"
#include "common/communication/commands.h"
#include "guests/hooks.h"
#include "kernel/emhv.h"
#include "guests/pci.h"
#include "memory/cachedef.h"
#include "memory/hibernate.h"
#include "guests/os_detect.h"
#include "kernel/recspinlock.h"
#include "debug/perfstats.h"
#include "memory/ept.h"
#include "wrappers/cx_winsal.h"

#include "introstatus.h"
#include "glueiface.h"
#include "upperiface.h"


/// @addtogroup introspection
///@{

/// @brief Additional data structure holding Introspection specific callbacks (dynamically registered) and other flags used for the Introspection.
///
/// INTROSPECTION ENGINE specific callbacks; functions work like this:
/// - Return CX_STATUS_DATA_NOT_FOUND if no hook was found on that page/MSR -> must emulate
/// - Return CX_STATUS_SUCCESS if everything went fine; In this case, the variable Action will
///   contain the desired action:
///   - Allow -> emulate
///   - NotAllow -> skip
///   - AllowPatched -> emulation/re-execution with modified read values
///   - AllowVirtual -> the action was emulated by introcore
///   This way, we maintain compatibility with existing code inside intro & with the old HV.
/// - Return STATUS_* - any other error, we must fail.
/// We register the callbacks with specific APIs instead of having them inside the glue_iface, so
/// intro can't modify them anytime.
typedef struct _GUEST_INTROSPECTION
{
    CX_BOOL                                 IntrospectionEnabled;           ///< TRUE if Introspection engine is enabled and running
    CX_BOOL                                 IntroRequestedToBeDisabled;     ///< The Introspection engine returned that it needs to be disabled after calling a callback, either on purpose or due to a critical fault
    CX_BOOL                                 IntrospectionActivated;         ///< TRUE if intro notified the hypervisor that the engine is active, FALSE if it notified that the engine is not active anymore

    PFUNC_IntEPTViolationCallback           RawIntroEptCallback;            ///< The raw callback which was registered by the introspection, must be called on EPT violation VMEXITs.
    PFUNC_IntMSRViolationCallback           RawIntroMsrCallback;            ///< The raw callback which was registered by the introspection, must be called on MSR violation VMEXITs.
    PFUNC_IntIntroCallCallback              RawIntroCallCallback;           ///< The raw callback which was registered by the introspection, must be called on VMCALL VMEXITs.
    PFUNC_IntIntroTimerCallback             RawIntroTimerCallback;          ///< The raw callback which was registered by the introspection, must be called when one second elapsed (Preemption timer VMEXITs).
    PFUNC_IntIntroDescriptorTableCallback   RawIntroDescriptorTableCallback;///< The raw callback which was registered by the introspection, must be called on Descriptor Table register accesses of the Guest.
    PFUNC_IntCrWriteCallback                RawIntroCrCallback;             ///< The raw callback which was registered by the introspection, must be called on Control Registers modifications of the Guest.
    PFUNC_IntXcrWriteCallback               RawIntroXcrCallback;            ///< The raw callback which was registered by the introspection, must be called on Extended Control Registers modifications of the Guest.
    PFUNC_IntBreakpointCallback             RawIntroBreakpointCallback;     ///< The raw callback which was registered by the introspection, must be called when the Guest hits a breakpoint.
    PFUNC_IntEventInjectionCallback         RawIntroEventInjectionCallback; ///< The raw callback which was registered by the introspection, must be called on Exception injection to the Guest.


    PFUNC_IntEPTViolationCallback           IntroEptCallback;               ///< The wrapper callback over the registered one by the introspection, must be called on EPT violation VMEXITs.
    PFUNC_IntMSRViolationCallback           IntroMsrCallback;               ///< The wrapper callback over the registered one by the introspection, must be called on MSR violation VMEXITs.
    PFUNC_IntIntroCallCallback              IntroCallCallback;              ///< The wrapper callback over the registered one by the introspection, must be called on VMCALL VMEXITs.
    PFUNC_IntIntroTimerCallback             IntroTimerCallback;             ///< The wrapper callback over the registered one by the introspection, must be called when one second elapsed (Preemption timer VMEXITs).
    PFUNC_IntIntroDescriptorTableCallback   IntroDescriptorTableCallback;   ///< The wrapper callback over the registered one by the introspection, must be called on Descriptor Table register accesses of the Guest.
    PFUNC_IntCrWriteCallback                IntroCrCallback;                ///< The wrapper callback over the registered one by the introspection, must be called on Control Registers modifications of the Guest.
    PFUNC_IntXcrWriteCallback               IntroXcrCallback;               ///< The wrapper callback over the registered one by the introspection, must be called on Extended Control Registers modifications of the Guest.
    PFUNC_IntBreakpointCallback             IntroBreakpointCallback;        ///< The wrapper callback over the registered one by the introspection, must be called when the Guest hits a breakpoint.
    PFUNC_IntEventInjectionCallback         IntroEventInjectionCallback;    ///< The wrapper callback over the registered one by the introspection, must be called on Exception injection to the Guest.

    RW_SPINLOCK                             IntroCallbacksLock;             ///< RW spinlock which must be taken in before calling any intro callback as they might get changed by the introspection in the same time

    volatile CX_UINT64                      IntroVcpuMask;                  ///< Each bit indicates that the subsequent VCPU must enable or disable exit on CR3 or Descriptor table access.

    CX_BOOL                                 IntroEnableCr3LoadExit;         ///< Set to TRUE by a request from the intro engine to enable VMEXITs on CR3 loads, FALSE to disable them.
    CX_BOOL                                 IntroEnableDescLoadExit;        ///< Set to TRUE by a request from the intro engine to enable VMEXITs on Descriptor Table loads, FALSE to disable them.
    CX_BOOL                                 IntroEnableBreakpointExit;      ///< Set to TRUE by a request from the intro engine to enable VMEXITs on Breakpoint hits, FALSE to disable them.

    CX_BOOL                                 IntroDisableRepOptimization;    ///< Set to TRUE by a request from the intro engine to enable REP optimizations (MOV instruction emulation with REP prefixes), FALSE to disable them.

    CX_UINT64                               IntroReportedErrorStates;       ///< Holds the last error state reported by Intro at Init
}GUEST_INTROSPECTION;

///@}


typedef struct _RIP_CACHE_ENTRY
{
    CX_UINT64               Rip;
} RIP_CACHE_ENTRY;

#define RIP_CACHE_MAX_ENTRIES           16

typedef struct _RIP_CACHE
{
    CX_UINT32               MaxEntries;
    CX_UINT32               ValidEntries;

    // Index of the entry where we found or inserted the last RIP we searched for
    CX_UINT32               CurrentIndex;

    RIP_CACHE_ENTRY         Entries[RIP_CACHE_MAX_ENTRIES];
} RIP_CACHE;

typedef enum _GUEST_POWER_STATE
{
    GstNoPowerTransition,
    GstPowerTransitionOccurring,
} GUEST_POWER_STATE;

#define MAX_DYNAMIC_DOMAINS_COUNT       4   ///< for each guest a maximum of 4 memory domains are supported besides/alongside the predefined ones
#define MAX_TOTAL_DOMAINS_COUNT         (GuestPredefinedMemoryDomainIdValues + MAX_DYNAMIC_DOMAINS_COUNT) ///< the number of supported domains, including the predefined ones

typedef enum _GUEST_PREDEFINED_MEMORY_DOMAIN_ID
{
    GuestPredefinedMemoryDomainIdPhysicalMemory,
    GuestPredefinedMemoryDomainIdSingleStepMemory,

    // add any new entries above this line
    GuestPredefinedMemoryDomainIdValues
}GUEST_PREDEFINED_MEMORY_DOMAIN_ID;


/// @brief Data structure containing all the state information needed for managing a guest memory domain (a guest physical memory view that describes the amount of memory, at what address intervals and the access rights and restrictions a guest has when that particular memory domain is said to be active on a #VCPU)
typedef struct _GUEST_MEMORY_DOMAIN
{
    EPT_DESCRIPTOR              Ept;            ///< The #EPT_DESCRIPTOR used for calling the ept.h functions for managing the GPA to HPA translations for this domain
    GUEST_MEMORY_DOMAIN_INDEX   Index;          ///< The domain's index
    CX_BOOL                     AllowVmfunc;    ///< When true, this domain is a valid target for VMFUNC and the internal EPT index is registered with the VMX interface as an element of the EPTP list
    volatile CX_BOOL            Initialized;    ///< Used for avoiding race conditions at domain creation, signals if the domain was created and is now ready for use
}GUEST_MEMORY_DOMAIN;


///@brief Defines enum values that can be used as arguments for the VmFuncPolicy parameter of the GstCreateMemoryDomain function
typedef enum _GUEST_MEMORY_DOMAIN_VMFUNC
{
    GUEST_MEMORY_DOMAIN_VMFUNC_ALLOW,           ///< VMFUNC is allowed with this memory domain
    GUEST_MEMORY_DOMAIN_VMFUNC_DENY             ///< VMFUNC is not allowed with this memory domain
}GUEST_MEMORY_DOMAIN_VMFUNC;

typedef enum _GST_UPDATE_REASON GST_UPDATE_REASON;

typedef struct _GUEST {
    CX_UINT16 Index;                                                  ///< Index of the guest
    volatile GUEST_POWER_STATE PowerState;                            ///< Power state of the guest, representing if the guest is going through a power state change or not, member of GUEST_POWER_STATE
    CX_UINT32 VcpuCount;                                              ///< The count of the VCPUs assigned to this guest
    VCPU* Vcpu[NAPOCA_MAX_PER_GUEST_CPU];                             ///< Array of VCPU pointers of this guest
    CX_UINT64 *MsrBitmap;                                             ///< The HVA for the MSR permission bitmap, content of which will get written directly in the VMCS
    CX_UINT64 MsrBitmapPa;                                            ///< The HPA for the MSR permission bitmap, content of which will get written directly in the VMCS
    CX_UINT64 *IoBitmap;                                              ///< The HVA for the I/O permission bitmap, content of which will get written directly in the VMCS
    CX_UINT64 IoBitmapPa;                                             ///< The HPA for the I/O permission bitmap, content of which will get written directly in the VMCS
    CX_UINT64 *EptpPage;                                              ///< The HVA for the EPTP list, content of which will get written directly in the VMCS
    CX_UINT64 EptpPagePa;                                             ///< The HPA for the EPTP list, content of which will get written directly in the VMCS
    CX_UINT64 *SpptRootVa;                                            ///< The HVA for the SPPTP, content of which will get written directly in the VMCS
    CX_UINT64 SpptRootPa;                                             ///< The HPA for the SPPTP, content of which will get written directly in the VMCS

    CX_BOOL SingleStepUsing1GEpt;                                     ///< CX_TRUE if we use large pages(1Gb) for single-stepping
    CX_BOOL GuestPausedForSingleStep;                                 ///< CX_TRUE if there's an ongoing single-stepping while using large pages
    CX_UINT64 MaxPhysicalAddress;                                     ///< The maximum physical address available for the guest

    EMHV_INTERFACE EmhvIface;                                         ///< Interface for instruction emulation callbacks (read/write mem,I/O ports and MSRs)

    MTRR_STATE* Mtrr;                                                 ///< MTRR state (points to the BSPs MTRR state)
    MMAP PhysMap;                                                     ///< Memory map used to represent the physical memory space of the guest (RAM, usually not including devices)

    MMAP MmioMap;                                                     ///< Memory map used to represent all device / resource specific memory zones
    MMAP EptMap;                                                      ///< Memory map used to represent the EPT mappings for the guest
    CX_UINT8 *RealModeMemory;                                         ///< HVA to the first 1 MB of the guest's GPA space
    CX_UINT32 BiosTopOfStubsStack;                                    ///< Original value of BIOS EBDA base address
    CX_UINT32 RealModeMemReservedBytes;                               ///< How much memory are we using inside the guest's real mode memory

    HIBERNATE_DATA  HibernateData;                                    ///< Support for persistence in case of hibernate

    GUEST_IO_HOOK_TABLE IoHooks;                                      ///< I/O port hook table
    GUEST_MSR_HOOK_TABLE MsrHooks;                                    ///< MSR hook table
    GUEST_EPT_HOOK_TABLE EptHooks;                                    ///< EPT hook table

    SPINLOCK MsrHookLockGlb;                                          ///< Global spinlock used both by the HV and the INTRO paths to avoid conflicts)

    volatile CX_UINT64 MtrrUpdateBitmaskActual;                       ///< A mask representing the CPUs that already went through the MTRR update sequence

    PFUNC_DevReadIoPort ReadIoPort;                                   ///< Default I/O read hook callback
    PFUNC_DevWriteIoPort WriteIoPort;                                 ///< Default I/O write hook callback
    PFUNC_DevReadMsr ReadMsr;                                         ///< Default MSR read hook callback
    PFUNC_DevWriteMsr WriteMsr;                                       ///< Default Msr write hook callback

    GUEST_INTROSPECTION Intro;                                        ///< Most of the introspection engine related informations (state, callbacks, ... )

    CX_UINT64 SharedBufferGPA;                                        ///< GPA for a buffer used for communication with the guest
    CX_UINT64 SharedBufferHPA;                                        ///< HPA for a buffer used for communication with the guest

    RECSPINLOCK PauseVcpusLock;                                       ///< Lock used for VCPU pausing contention

    struct _GUEST_OS_DETECTION
    {
        volatile CX_BOOL UseOsSigScan;                                ///< CX_TRUE if we use OS detection based on signatures
        volatile OS_SCAN_VERDICT OsScanVerdict;                       ///< The verdict of the OS detection based on signatures
        RIP_CACHE RipCache;                                           ///< A cache for the already checked RIPs
    };

    volatile CX_UINT32 SipiCount;                                     ///< The amount of the SIPIs intercepted
    volatile CX_UINT64 SipiMask;                                      ///< A mask based on which processor did we intercept already at least one SIPI

    struct _MS_HV_INTERFACE
    {
        volatile CX_UINT32 MicrosoftHvInterfaceFlags;                 ///< A field needed when exposing a Microsoft Hypervisor Interface
        CX_UINT8 *HypercallPage;                                      ///< The HVA of Guest Hypercall Page
        BOOLEAN HypercallPageActive;                                  ///< TRUE if the hypervisor is accepting hypercalls
        volatile CX_UINT64 PartitionReferenceTime;                    ///< The partition reference counter

        CX_ONCE_INIT0 TscWorkaroundInit;                              ///< Needed for hooking only once the TSC page for the guest in order to overwrite the Guest's mapping structures (set PWT), to fix hibernate issue on Win 10 RS4.
    };

    struct
    {
        volatile GST_UPDATE_REASON Reasons;                           ///< The reason for global update (affecting all VCPUs)
        volatile CX_UINT64 PausedCount;                               ///< The number of VCPUs already paused for the global update
        SPINLOCK InternalConsistencyLock;                             ///< An additional lock for internal consistency
        struct
        {
            SPINLOCK Ept;                                             ///< An update lock only for EPT modifications
            SPINLOCK Reexec;                                          ///< An update lock only for re-execution
        }Locks;
    }GlobalUpdate;

    struct _ALERTS_CACHE
    {
        INTROSPECTION_ALERT* Buffer;                                  ///< A buffer for caching the alerts from the introspection engine, before sending back to the guest
        CX_UINT16 Size;                                               ///< The size of this buffer
        CX_UINT16 Count;                                              ///< The amount of the alerts in this buffer
        CX_UINT64 Tsc;                                                ///< The TSC for the last time when the content of this buffer was sent
        SPINLOCK Spinlock;                                            ///< A lock for accessing this buffer
    } AlertsCache;

    struct
    {
        PERF_STATS ExitStats[EXIT_REASON_MAX];                        ///< Statistical data about the exits
        PERF_STATS HostStats;                                         ///< Statistical data for the host
        PERF_STATS GuestStats;                                        ///< Statistical data for the guest
        CX_UINT64 LastPauseTransitionTsc;                             ///< Saved TSC value for the last transition in/from pause
        PERF_STATS PausingStats[VCPU_PAUSING_STATE_TOTAL_VALUES];     ///< Statistical data about pausing
        PERF_STATS Cr8Stats[16];                                      ///< Statistical data about the guest's CR8 when interrupted by an exit
    };

    volatile CX_UINT64 TaskSwitchVcpuMask;                            ///< A mask representing the VCPUs that executed a task-switch already

    GUEST_MEMORY_DOMAIN MemoryDomains[MAX_TOTAL_DOMAINS_COUNT];       ///< The guest's memory domains
    volatile GUEST_MEMORY_DOMAIN_INDEX DynamicDomainsCount;           ///< The dynamic memory domain count
} GUEST;



///
/// @brief        Calculate the total number of domains known for a guest (the predefined ones are always reported, no matter if they're initialized or not)
/// @param[in]    Guest                            Target Guest
/// @returns      the number of currently defined/knwon domains (returned as a GUEST_MEMORY_DOMAIN_INDEX that would correspond to the first domain array entry not yet in use)
///
__forceinline
GUEST_MEMORY_DOMAIN_INDEX
GstGetMemoryDomainsCount(
    _In_ GUEST                      *Guest
)
{
    if (!Guest) return 0;
    return GuestPredefinedMemoryDomainIdValues + Guest->DynamicDomainsCount;
}



///
/// @brief        Retrieve a guest's memory domain by its index
/// @param[in]    Guest                            Guest owning the domain in question
/// @param[in]    MemoryDomainIndex                The index of the domain (the ResultedDomainIndex value returned by GstCreateMemoryDomain())
/// @param[out]   MemoryDomain                     Returns the pointer to the subject #GUEST_MEMORY_DOMAIN
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - Guest must be non-NULL
/// @returns      CX_STATUS_INVALID_PARAMETER_2    - The value of the MemoryDomainIndex argument is not a valid memory domain index
/// @returns      CX_STATUS_DATA_NOT_INITIALIZED   - The domain index corresponds to a domain that exists but it's not yet initialized
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
GstGetMemoryDomain(
    _In_ GUEST                      *Guest,
    _In_ GUEST_MEMORY_DOMAIN_INDEX  MemoryDomainIndex,
    __out_opt GUEST_MEMORY_DOMAIN   **MemoryDomain
)
{
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (MemoryDomainIndex >= GstGetMemoryDomainsCount(Guest)) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Guest->MemoryDomains[MemoryDomainIndex].Initialized) return CX_STATUS_DATA_NOT_INITIALIZED;
    if (MemoryDomain) *MemoryDomain = &Guest->MemoryDomains[MemoryDomainIndex];
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Retrieve the internal #EPT_DESCRIPTOR needed for calling the EPT API for managing a domain's mappings
/// @param[in]    MemoryDomain                     Memory domain in question
/// @param[out]   Ept                              Parameter to receive the pointer to the EPT_DESCRIPTOR
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - MemoryDomain is NULL
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
GstGetMemoryDomainEptDescriptor(
    _In_ GUEST_MEMORY_DOMAIN        *MemoryDomain,
    __out_opt EPT_DESCRIPTOR        **Ept
)
{
    if (!MemoryDomain || !MemoryDomain->Initialized) return CX_STATUS_INVALID_PARAMETER_1;
    if (Ept) *Ept = &MemoryDomain->Ept;
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Retrieve the internal #EPT_DESCRIPTOR needed for calling the EPT API for managing a domain's mappings
/// @param[in]    Guest                            Target #GUEST structure
/// @param[in]    MemoryDomainIndex                The index of the domain wanted
/// @param[out]   Ept                              Output argument to receive the EPT_DESCRIPTOR pointer
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
GstGetEptDescriptorEx(
    _In_ GUEST                      *Guest,
    _In_ GUEST_MEMORY_DOMAIN_INDEX  MemoryDomainIndex,
    __out_opt EPT_DESCRIPTOR        **Ept
)
{
    GUEST_MEMORY_DOMAIN *domain;
    CX_STATUS status = GstGetMemoryDomain(Guest, MemoryDomainIndex, &domain);
    if (!CX_SUCCESS(status)) return status;
    if (Ept) *Ept = &domain->Ept;
    return CX_STATUS_SUCCESS;
}



///
/// @brief        Retrieve the internal #EPT_DESCRIPTOR needed for calling the EPT API for managing a domain's mappings
/// @param[in]    Guest                            Target #GUEST structure
/// @param[in]    MemoryDomainIndex                The index of the domain wanted
/// @returns      the pointer of the #EPT_DESCRIPTOR used for managing the domain or NULL if some argument is invalid or the domain doesn't exist
///
__forceinline
EPT_DESCRIPTOR *
GstGetEptDescriptor(
    _In_ GUEST                      *Guest,
    _In_ GUEST_MEMORY_DOMAIN_INDEX  MemoryDomainIndex
)
{
    EPT_DESCRIPTOR *ept;
    CX_STATUS status = GstGetEptDescriptorEx(Guest, MemoryDomainIndex, &ept);
    if (!CX_SUCCESS(status)) return CX_NULL;
    return ept;
}



///
/// @brief        Retrieve the internal #EPT_DESCRIPTOR needed for calling the EPT API on the primary physical memory domain of a given #GUEST
/// @param[in]    Guest                            Target #GUEST structure
/// @returns      the #EPT_DESCRIPTOR corresponding to the main/primary memory domain of the Guest
///
__forceinline
EPT_DESCRIPTOR *
GstGetEptOfPhysicalMemory(
    _In_ GUEST                          *Guest
)
{
    return GstGetEptDescriptor(Guest, GuestPredefinedMemoryDomainIdPhysicalMemory);
}



///
/// @brief        Retrieve the internal #EPT_DESCRIPTOR needed for calling the EPT API on the memory domain used temporarily (for a single guest intruction) when an (EPT) intercepted instruction needs to be allowed to perform its operation
/// @param[in]    Guest                            Target #GUEST
/// @returns      the EPT_DESCRIPTOR corresponding to an unrestricted memory of the physical memory of the guest
///
__forceinline
EPT_DESCRIPTOR *
GstGetEptOfSingleStepMemory(
    _In_ GUEST                          *Guest
)
{
    return GstGetEptDescriptor(Guest, GuestPredefinedMemoryDomainIdSingleStepMemory);
}


CX_STATUS
GstCreateMemoryDomain(
    _In_ GUEST                          *Guest,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *WantedDomainIndex,
    _In_ GUEST_MEMORY_DOMAIN_VMFUNC     VmFuncPolicy,
    _In_opt_ MMAP                       *InitFromThisMemoryMap,
    _In_opt_ GUEST_MEMORY_DOMAIN_INDEX  *CopyThisDomain,     // if both initializers are given, the translations from domain with index=*CopyThisDomain will override any memory map intervals
    __out_opt GUEST_MEMORY_DOMAIN       **Domain,
    __out_opt GUEST_MEMORY_DOMAIN_INDEX *ResultedDomainIndex
);

CX_STATUS
GstDestroyMemoryDomain(
    _In_ GUEST                          *Guest,
    _In_ GUEST_MEMORY_DOMAIN_INDEX      DomainIndex
);

CX_UINT64
GstGetDomainsMemoryConsumption(
    _In_ GUEST                          *Guest
);

/// @brief Allocate and pre-initialize the guest
///
/// @param[out] Guest          The guest structure to be pre-initialized
/// @param[in] VcpuCount       Number of VCPUs assigned to this guest
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the guest is pre-initialized
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - Invalid VcpuCount
/// @returns    OTHER                               - Internal error
CX_STATUS
GstAllocAndPreinitGuest(
    _Out_ GUEST* *Guest,
    _In_ CX_UINT32 VcpuCount
    );

/// @brief Activate the guest
///
/// @param[in]  Guest                The guest structure
/// @param[in]  MarkVcpusSchedulable TRUE if we want to mark the VCPUs schedulable
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, guest was activated
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    OTHER                               - Internal error
CX_STATUS
GstActivateGuest(
    _In_ GUEST* Guest,
    _In_ CX_BOOL MarkVcpusSchedulable
    );

/// @brief Assign virtual processors to physical processors
///
/// @param[in]  Guest                The guest structure
/// @param[in]  MarkVcpusSchedulable TRUE if we want to mark the VCPUs schedulable
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
GstAssignVCpusToPCpus(
    _In_ GUEST* Guest,
    _In_ CX_BOOL MarkVcpusSchedulable
    );

/// @brief Initialize the a RIP cache
///
/// @param[out] Cache           The initialized RIP cache
/// @param[in]  MaxEntries      Maximum number of entries the RIP cache will have
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the cache is initialized
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - Invalid MaxEntries
STATUS
GstInitRipCache(
    _Out_ RIP_CACHE* Cache,
    _In_ CX_UINT32 MaxEntries
    );

/// @brief Search and potentially add a RIP in the given RIP cache
///
/// @param[in,out] Cache           The cache in which the search will be executed
/// @param[in]     Rip             RIP to be searched
/// @param[out]    FoundRip        TRUE if the RIP was found, FALSE otherwise
/// @param[in]     AddIfNotFound   TRUE if the RIP should be added to the cache if not found
///
/// @returns    CX_STATUS_SUCCESS                   - Always
STATUS
GstSearchRipInCache(
    _Inout_ RIP_CACHE* Cache,
    _In_ CX_UINT64 Rip,
    _Out_ CX_BOOL* FoundRip,
    _In_ CX_BOOL AddIfNotFound
    );

/// @brief Initialize the guests physical map
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the map was initialized
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - The Guest can not be NULL
/// @returns    OTHER                               - Internal error
CX_STATUS
GstInitPhysMap(
    _In_ GUEST* Guest
);

/// @brief Set up the MTRR state for each VCPU; the global one points to VCPU[0] and generates the MTRR map.
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the MTRR state was initialized
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    OTHER                               - Internal error
CX_STATUS
GstInitMtrrs(
    _In_ GUEST* Guest
);

/// @brief Basic VCPU setup
///
/// @param[in]  Guest           The guest structure
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the VCPUs were set up
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    OTHER                               - Internal error
CX_STATUS
GstSetupVcpus(
    _In_ GUEST* Guest
);

/// @brief Get the operating mode of the VCPU
///
/// @param[in]  Vcpu            The VCPU's operating mode we are interested
/// @param[out] OperatingMode   The operating mode of the Vcpu (ND_CODE_*)
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, we got the operating mode back
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Vcpu can not be NULL
CX_STATUS
GstGetVcpuMode(
    _In_ VCPU* Vcpu,
    _Out_ CX_UINT8* OperatingMode
);

typedef enum _GST_UPDATE_REASON
{
    // low-level operations
    _GST_UPDATE_REASON_EPT_LOCK              = BIT(0),
    _GST_UPDATE_REASON_REEXEC_LOCK           = BIT(1),

    _GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST = BIT(2),
    _GST_UPDATE_REASON_POSTPONED_OPERATIONS_MASK = _GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST,

    // high-level reasons for locking or pausing the guest
    GST_UPDATE_REASON_EPT_CHANGES           = _GST_UPDATE_REASON_EPT_LOCK | _GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST,
    GST_UPDATE_REASON_EPT_READ              = _GST_UPDATE_REASON_EPT_LOCK, // don't invalidate for reads (_GST_UPDATE_REASON_POSTPONE_EPT_INVLD_BROADCAST)

    GST_UPDATE_REASON_REEXEC_CHANGES        = _GST_UPDATE_REASON_REEXEC_LOCK,

    GST_UPDATE_REASON_INSTR_CACHE_CHANGES   = _GST_UPDATE_REASON_EPT_LOCK,
    GST_UPDATE_REASON_INSTR_CACHE_READ      = _GST_UPDATE_REASON_EPT_LOCK,

    GST_UPDATE_REASON_PAUSE_GUEST           = BIT(3),
    GST_UPDATE_REASON_RESUME_EXECUTION      = BIT(4),


}GST_UPDATE_REASON;

typedef enum
{
    GST_UPDATE_MODE_NOT_LOCKED      = 0,        ///< Don't acquire the exclusive lock
    GST_UPDATE_MODE_NOT_PAUSED      = 0,        ///< Don't stop the guest execution while the update is in progress
    GST_UPDATE_MODE_LOCKED          = BIT(0),   ///< Acquire the exclusive lock
    GST_UPDATE_MODE_PAUSED          = BIT(1),   ///< Stop the guest execution while the update is in progress
}GST_UPDATE_MODE;


#define GstBeginUpdateEx(...) GstBeginUpdateEx2(__VA_ARGS__, __FILE__, __LINE__)
CX_STATUS
GstBeginUpdateEx2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_MODE UpdateMode,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
);


#define GstEndUpdateEx(...) GstEndUpdateEx2(__VA_ARGS__, __FILE__, __LINE__)
CX_STATUS
GstEndUpdateEx2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_MODE UpdateMode,
    _In_ GST_UPDATE_REASON Reason,
    _In_opt_ CX_BOOL IgnoreVcpuPauseNestingWhenResuming,
    _In_ char *File,
    _In_ CX_UINT32 Line
);


#define GstLock(...) GstLock2(__VA_ARGS__, __FILE__, __LINE__)
/// @brief Start performing atomic changes over the global (affecting all VCPUs) guest state
__forceinline
CX_STATUS
GstLock2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    return GstBeginUpdateEx2(Guest, GST_UPDATE_MODE_LOCKED, Reason, File, Line);
}

#define GstUnlock(...) GstUnlock2(__VA_ARGS__, __FILE__, __LINE__)
/// @brief End performing atomic changes over the global (affecting all VCPUs) guest state
__forceinline
CX_STATUS
GstUnlock2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    return GstEndUpdateEx2(Guest, GST_UPDATE_MODE_LOCKED, Reason, CX_FALSE, File, Line);
}


#define GstPause(...) GstPause2(__VA_ARGS__, __FILE__, __LINE__)
/// @brief Take the global guest lock and stop guest execution for applying some atomic changes over the global (hardware-affecting all VCPUs) guest state
__forceinline
CX_STATUS
GstPause2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    return GstBeginUpdateEx2(Guest, GST_UPDATE_MODE_LOCKED | GST_UPDATE_MODE_PAUSED, Reason, File, Line);
}


#define GstUnpause(...) GstUnpause2(__VA_ARGS__, __FILE__, __LINE__)
/// @brief Release the global guest lock and (at least mark) resume guest execution after applying some atomic guest changes
__forceinline
CX_STATUS
GstUnpause2(
    _In_ GUEST* Guest,
    _In_ GST_UPDATE_REASON Reason,
    _In_ char *File,
    _In_ CX_UINT32 Line
)
{
    return GstEndUpdateEx2(Guest, GST_UPDATE_MODE_LOCKED | GST_UPDATE_MODE_PAUSED, Reason, CX_FALSE, File, Line);
}


/// @brief Remember/postpone some operation to be executed before resuming guest execution
__forceinline
CX_VOID
GstUpdateRememberReasons(
    _Inout_ GUEST* Guest,
    _In_ GST_UPDATE_REASON Reason
)
{
    HvInterlockedOrU32((volatile CX_UINT32 *)&Guest->GlobalUpdate.Reasons, Reason);
}

__forceinline
CX_BOOL
GstIsSafeToInterrupt(
    _In_ GUEST* Guest
)
{
    return  (__popcnt64(Guest->SipiMask) >= Guest->VcpuCount);
}


CX_STATUS
GstDumpMemoryDomains(
    _In_ GUEST *Guest
);

#endif // _GUESTS_H_

