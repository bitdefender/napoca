/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file ipi.c
 *  @brief IPI - Inter Processor Interrupts handling
 */

 /// \addtogroup ipi
 /// @{

#include "napoca.h"
#include "apic/ipi.h"
#include "kernel/kernel.h"
#include "boot/boot.h"
#include "boot/init64.h"
#include "debug/dumpers.h"
#include "apic/lapic.h"
#include "kernel/spinlock.h"
#include "boot/boot.h"

//
// See Intel Manual Volume 3 CHAPTER 10: ADVANCED PROGRAMMABLE INTERRUPT CONTROLLER (APIC)
//

/** @name Freezing support
 *  @brief  The data structures used by the functions IpiFreezeCpus(Silent) and IpiResumeCpus
 */
///@{
/// @brief Lock used so that only one processor can process the freeze command
SPINLOCK gFreezeCpusLock;

/** @brief Id of a freeze request.
 *
 *  Used internally mainly to know when to unfreeze the processor and
 *  the reason why the freeze was requested so that the freezing function knows what to do.
 *  This structure is allocated when one (or more) processors are required to freeze.
 *  The address of the structure is returned to the caller of the IpiFreezeCpus(Silent) function
 *  in the form of an ID, this ID being used by the IpiResumeCpus function to unfreeze.
 *
 */
typedef struct _IPI_FREEZE_REQUEST
{
    volatile INTERRUPT_FREEZE_REASON    Reason;                         ///< Freeze reason. For more info see #INTERRUPT_FREEZE_REASON from ipi.h
    volatile CX_UINT32                  ResumeExecution;                ///< Used internally to know when to unfreeze the processor.
    volatile HV_TRAP_FRAME              *TrapFrame;                     ///< Not used for now.
    volatile IPC_INTERRUPTIBILITY_STATE OriginalInterruptibilityState;  ///< When the freezing of the processor is required, the interrupts will be blocked and in this field the back is made to current Interruptibility State.
} IPI_FREEZE_REQUEST;
///@}

/** @name APs wake up support
 *  @brief Structures used for APs wake up sequence
 */
 ///@{
#define TRAMPOLINE_16BIT_REAL_CODE      0x8000  ///< Address in real mode where the 16bit trampoline code will be copied

#pragma pack(push, 1)
/// @brief Per CPU data used for wake-up sequence
typedef struct _AP_POINTERS
{
    CX_UINT32       LapicId;        ///< Processor LAPIC ID
    CX_UINT64       StackTop;       ///< Top of the stack address
    CX_UINT64       CpuMapEntry;    ///< Various information about this processor (MiscIntelFeatures, PhysicalAddressWidth, etc.)
    CX_UINT64       GsBase;         ///< Used to hold the CPU structure address for this processor
}AP_POINTERS;

/** @brief Data required for APs to start
 *
 *  AP_POINTERS and AP_STARTUP_DATA are structures that are also defined
 *  in ap_initialization.nasm. They are used to transmit information to the
 *  AP trampoline code written in the assembly.
 *  Please keep these structures in sync with those in the .nasm file
 *
 */
typedef struct _AP_STARTUP_DATA
{
    CX_UINT32       BaseAddress;                        ///< Must be set by napoca. Base physical address for APs
                                                        ///< wake up trampoline code

    CX_UINT64       BaseAddressVa;                      ///< Virtual address of wake up trampoline code
    CX_UINT64       StartupCr3;                         ///< Intermediate cr3 below 4GB for long mode initialization
    CX_UINT64       BspCr3;                             ///< BSP final cr3
    CX_UINT32       UefiEvent;                          ///< Used by UEFI
    CX_UINT64       UefiEntry;                          ///< UEFI APs will run this code
    CX_UINT64       BootContext;                        ///< Pointer to the boot context which will be used as param for init64
    CX_UINT64       IsWakeUp;                           ///< If wake up from S3
    AP_POINTERS ApPointers[CPUSTATE_MAX_GUEST_CPU_COUNT];   ///< Storage for per cpu pointers to structures
}AP_STARTUP_DATA;

/** Trampoline code & help data for wake up addresses
 *
 *  Through these symbols we can access the trampoline code and the area where
 *  we have to save the information so that the APs can start.
 *
 */
/// @brief Used to be able to patch the assembly code with the information needed for the APs to run the trampoline code.
extern AP_STARTUP_DATA gApStartupData;
/// @brief Start address of wake up trampoline code
extern CX_UINT8 gApTrampoline16;
/// @brief End address of wake up trampoline code
extern CX_UINT8 gApTrampoline16End;

/** @brief Memory backup support
 *
 *  The structure used to restore the overwritten
 *  memory with the trampoline code
 *
 */
typedef struct _RM_MEM_BACKUP
{
    CX_UINT64   Lvl4, Lvl3, Lvl2;                       // lvl4, 3 and 2 entries
    CX_UINT64   Lvl1[CX_MEGA / CX_PAGE_SIZE_4K];
    CX_UINT8    ApTrampoline[1];
}RM_MEM_BACKUP;
///@}
#pragma pack(pop)

/* Static functions */

///
/// @brief Wait until current IPI is successfully sent
///
static __forceinline CX_VOID _IpiWaitForIdle(CX_VOID);

///
/// @brief Effectively send IPI
///
/// @param[in]  Icr     The value of the ICR register that will be written to trigger the IPI
///
static __forceinline CX_VOID _IpiIssueIpi(_In_ ICR Icr);

///
/// @brief Send IPIs to all processors and wait 10 milliseconds as MP initialization protocol states.
///
static CX_VOID _IpiBroadcastInitAndWait(CX_VOID);

///
/// @brief Broadcast a Startup IPI to all other CPUs, and wait 200 microseconds (part of MP initialization protocol).
///
/// @param[in]  CodeBase    The address where the trampoline code is prepared for APs
///
static CX_VOID _IpiBroadcastStartupAndWait(_In_ CX_UINT32 CodeBase);

///
/// @brief When a CPU is sent a freezing IPI, it will spin inside this function, with IRQL = IPI, until signaled to resume execution
///
/// @param[in]  FreezeRequest       Id of the current freeze request. Used internally mainly to know when to unfreeze the processor
/// @param[in]  TrapFrame           Unused for now.
///
/// @returns    CX_STATUS_SUCCESS                   - if everything went with success.
/// @returns    CX_STATUS_INVALID_PARAMETER         - if FreezeRequest (Id) is NULL
///
static CX_STATUS _IpiFreezingHandler(_In_ IPI_FREEZE_REQUEST* FreezeRequest, _In_ HV_TRAP_FRAME* TrapFrame);

CX_STATUS
IpiWakeupAllApProcessors(
    _In_ CX_BOOL IsS3Wakeup
)
//
// Runs the MP initialization protocol to wake up all AP processors
//
{
    CX_UINT64 tmp = 0, tmpCr3 = 0;
    CX_UINT16 size = 0;
    CX_UINT16  i = 0;
    RM_MEM_BACKUP *backup = CX_NULL;
    CX_STATUS status = CX_STATUS_SUCCESS;
    CX_VOID *apTrampolineVa = CX_NULL;
    CX_BOOL unmapTrampoline = CX_FALSE;
    CX_UINT32 lengthToBackup = 0;

    unmapTrampoline = CX_FALSE;
    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    apTrampolineVa = CX_NULL;

    if (gBootInfo->CpuCount > CPUSTATE_MAX_GUEST_CPU_COUNT)
    {
        CRITICAL("!!MAXIMUM SUPPORTED AP COUNT EXCEEDED, fix the .nasm AP initialization code!!\n");

        status = CX_STATUS_OPERATION_NOT_SUPPORTED;
        return status;
    }

    size = (CX_UINT16)((CX_SIZE_T)&gApTrampoline16End - (CX_SIZE_T)&gApTrampoline16 + 1);

    lengthToBackup = CX_ROUND_UP(size, CX_PAGE_SIZE_4K) + CX_PAGE_SIZE_4K * 5;

    //
    // Backup the overwritten real-mode memory
    //
    if (!gHypervisorGlobalData.MemInfo.ApTrampolineBackup)
    {
        status = HpAllocWithTagCore(&gHypervisorGlobalData.MemInfo.ApTrampolineBackup, sizeof(RM_MEM_BACKUP) + lengthToBackup, TAG_APM);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTagCore", status);
            return status;
        }
    }

    backup = (RM_MEM_BACKUP*)gHypervisorGlobalData.MemInfo.ApTrampolineBackup;

    // make sure the area we're backing up and using is actually mapped / accessible
    TAS_PROPERTIES lack = gTasMapLackProps;
    lack.InUse = 0; // allow the new mapping overwrite any pre-existing mappings in the HVA [0..1MB)

    status = TasMapRangeEx(&gHva, (MEM_UNALIGNED_VA)TRAMPOLINE_16BIT_REAL_CODE, lengthToBackup, gTasMapSetProps, gTasMapClearProps, gTasMapHaveProps, lack, (MEM_ALIGNED_PA)TRAMPOLINE_16BIT_REAL_CODE, CX_NULL);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("TasMapRangeEx", status);
        goto cleanup;
    }

    memcpy(backup->ApTrampoline, (CX_VOID *)(CX_UINT64) TRAMPOLINE_16BIT_REAL_CODE, lengthToBackup);
    //
    // Prepare 1/1 mapping for the first 1MB of ram as the initial paging structures for APs
    //
    tmpCr3 = CX_ROUND_UP(TRAMPOLINE_16BIT_REAL_CODE + size, CX_PAGE_SIZE_4K);

    tmp = tmpCr3;
    backup->Lvl4 = ((CX_UINT64*)(CX_SIZE_T) tmp)[0];
    ((CX_UINT64*)(CX_SIZE_T) tmp)[0] = (tmp + CX_PAGE_SIZE_4K) | 3;      //lvl4[0] -> tmp+page_size

    tmp += CX_PAGE_SIZE_4K;
    backup->Lvl3 = ((CX_UINT64*)(CX_SIZE_T) tmp)[0];
    ((CX_UINT64*)(CX_SIZE_T) tmp)[0] = (tmp + CX_PAGE_SIZE_4K) | 3;      //lvl3[0] -> tmp+page_size

    tmp += CX_PAGE_SIZE_4K;
    backup->Lvl2 = ((CX_UINT64*)(CX_SIZE_T) tmp)[0];
    ((CX_UINT64*)(CX_SIZE_T) tmp)[0] = (tmp + CX_PAGE_SIZE_4K) | 3;      //lvl2[0] -> tmp+page_size

    tmp += CX_PAGE_SIZE_4K;

    // fill in 256 lvl1 entries to cover 4K*256 = 1MB
    for (i = 0; i < (CX_MEGA / CX_PAGE_SIZE_4K); i++)
    {
        backup->Lvl1[i] = ((CX_UINT64*)(CX_SIZE_T) tmp)[i];
        ((CX_UINT64*)(CX_SIZE_T) tmp)[i] = (i * CX_PAGE_SIZE_4K) | 3;    //lvl1[0] -> i*page_size
    }

    //
    // Prepare AP parameters
    //

    gApStartupData.BaseAddress      = TRAMPOLINE_16BIT_REAL_CODE;
    gApStartupData.BaseAddressVa    = (CX_SIZE_T) &gApTrampoline16;
    gApStartupData.BootContext      = (CX_SIZE_T) gBootContext;
    gApStartupData.BspCr3           = __readcr3();
    gApStartupData.StartupCr3       = tmpCr3;

    LOG("AP initialization parameters: TEMPCR3=%p, &gApTrampoline16:%p\n", tmpCr3, &gApTrampoline16);
    for (i = 0; i < gBootInfo->CpuCount; i++)
    {
        PCPU *cpu = HvGetCpu(i);
        if (!cpu)
        {
            status = CX_STATUS_DATA_NOT_READY;
            goto cleanup;
        }

        gApStartupData.ApPointers[i].LapicId = gBootInfo->CpuMap[i].Id;
        gApStartupData.ApPointers[i].CpuMapEntry = (CX_SIZE_T)&(gBootInfo->CpuMap[i]);
        gApStartupData.ApPointers[i].GsBase = (CX_UINT64)cpu;
        gApStartupData.ApPointers[i].StackTop = (CX_UINT64)cpu->MemoryResources.Stack + NAPOCA_CPU_STACK_SIZE;
        if (IsS3Wakeup)
        {
            gApStartupData.IsWakeUp = CX_TRUE;
        }
        else
        {
            gApStartupData.IsWakeUp = CX_FALSE;
        }

        LOG("AP[%d]: lapic=%d, CpuMapEntry=%p, GsBase=%p, StackTop=%p\n", i,
            gApStartupData.ApPointers[i].LapicId, gApStartupData.ApPointers[i].CpuMapEntry, gApStartupData.ApPointers[i].GsBase, gApStartupData.ApPointers[i].StackTop);

    }

    memcpy((CX_VOID *)(CX_SIZE_T)TRAMPOLINE_16BIT_REAL_CODE, &gApTrampoline16, size);

    LOG("[BSP] will broadcast INIT IPI to all APs...\n");
    _IpiBroadcastInitAndWait();
    LOG("[BSP] will broadcast first STARTUP IPI to all APs...\n");
    _IpiBroadcastStartupAndWait((CX_UINT32)(CX_SIZE_T)TRAMPOLINE_16BIT_REAL_CODE);
    LOG("[BSP] will broadcast second STARTUP IPI to all APs...\n");
    _IpiBroadcastStartupAndWait((CX_UINT32)(CX_SIZE_T)TRAMPOLINE_16BIT_REAL_CODE);
    LOG("[BSP] after broadcasting complete INIT-STARTUP-STARTUP sequence\n");

    // wait for APs to reach Init64
    LOG("waiting for APs to reach Init64\n");
    while ((gCpuReachedInit64 != CPU_COUNT_TO_WAIT)&&(!gNeedToUnload))
    {
        CpuYield();
    }
    if (gNeedToUnload)
    {
        CLN_UNLOAD(CX_STATUS_INVALID_INTERNAL_STATE);
    }

    LOG("all APs reached Init64\n");
    // we can now safely restore the memory used for AP trampoline
    // this must be done when waking up from S3 sleep because that memory is in use by guests
    memcpy((CX_VOID *)(CX_SIZE_T)TRAMPOLINE_16BIT_REAL_CODE, backup->ApTrampoline, lengthToBackup);
    status = CX_STATUS_SUCCESS;
cleanup:
    return status;

}

CX_VOID
IpiSelfInit(
    CX_VOID
)
//
// Perform a self-init, that should reset the CPU
//
{
    ICR_LOW icr = {0};

    icr.Value = 0;
    icr.DstShorthand = IPI_DST_SELF;
    icr.TriggerMode = IPI_TRIGGER_LEVEL;
    icr.Level = IPI_LEVEL_ASSERT;
    icr.DstMode = IPI_DST_MODE_PHYSICAL;
    icr.DeliveryMode = IPI_DELIVERY_INIT;
    icr.Vector = 0;

    LOG("[%d] Sending Lapic INIT to self\n", HvGetCurrentCpuIndex());

    // Issue the IPI
    LapicWrite(APIC_INTERRUPT_COMMAND_REGISTER_LOW, icr.Value);
}

CX_VOID
IpiSendVector(
    _In_ CX_UINT64    Affinity,   // A bitfield denoting the cpu id for which interrupts have to be issued
    _In_ CX_UINT8     Vector      // Vector of the interrupt
)
//
// Send an IPI to the given Affinity CPUs, with the given vector.
// Remarks:
//  - If the Vector is 2, the delivery mode will be NMI, otherwise it will be "fixed".
//  - The function tries to optimize the IPI delivery (e.g.: if the Affinity specifies all other running CPUs excepting the current one,
//    only one IPI will be sent with SHORTHAND set to ALL_EXCLUDING SELF)
//
{
    ICR icr = {0};
    CX_UINT32 targetCpuIndex = 0;

    if (Affinity == 0)  return;

    //
    // Create a shadow of the Interrupt Control Register. Set the common fields and issue interrupts to the required cpus
    //
    if (Vector == NAPOCA_NMI_VECTOR)
    {
        icr.Low.DeliveryMode = IPI_DELIVERY_NMI;
    }
    else if (Vector == NAPOCA_IPC_INIT_VECTOR)
    {
        icr.Low.DeliveryMode = IPI_DELIVERY_INIT;
    }
    else
    {
        icr.Low.DeliveryMode = IPI_DELIVERY_FIXED;
    }

    icr.Low.DstMode = IPI_DST_MODE_PHYSICAL;
    icr.Low.Level = IPI_LEVEL_ASSERT;
    icr.Low.TriggerMode = IPI_TRIGGER_EDGE;
    icr.Low.Vector = (Vector == NAPOCA_IPC_INIT_VECTOR) ? 0 : Vector;

    if (Affinity == AFFINITY_ALL_EXCLUDING_SELF)
    {
        // Program LAPIC only once, with shorthand = all excluding self
        icr.Low.DstShorthand = IPI_DST_ALL_EXCLUDING_SELF;

        _IpiIssueIpi(icr);
    }
    else
    {
        // Issue an interrupt for each cpu in the Affinity bitfield
        while (HvBitScanForwardU64(&targetCpuIndex, Affinity))
        {
            // Clear this bit in local Affinity
            HvBitTestAndResetU64(&Affinity, targetCpuIndex);
            if (targetCpuIndex >= gHypervisorGlobalData.CpuData.CpuCount)
            {
                ERROR("GOT CPUIDX=%d\n", targetCpuIndex);
                return;
            }
            icr.Low.DstShorthand = IPI_DST_NO_SHORTHAND;
            icr.High.Value = gHypervisorGlobalData.CpuData.Cpu[targetCpuIndex]->Id << 24;

            _IpiIssueIpi(icr);
        }
    }
}

CX_STATUS
IpiFreezeCpus2(
    _In_ CX_UINT64                Affinity,
    _In_ INTERRUPT_FREEZE_REASON  Reason,
    _Out_ CX_VOID                 **Id,
    _In_ CX_INT8                  *File,
    _In_ CX_UINT16                Line,
    _In_ CX_BOOL                  Silent
)
//
// Freezes the CPUs specified in Affinity.
//
{
    if (!Id) return CX_STATUS_INVALID_PARAMETER_3;

    if ((IoGetPerCpuPhase() < IO_CPU_ROOT_CYCLE) || (HvGetCurrentGuest()->SipiCount < gHypervisorGlobalData.CpuData.CpuCount))
    {
        LOG("Cannot freeze cpus! They are not initialized yet (HvGetCurrentGuest()->SipiCount=%d; gHypervisorGlobalData.CpuCount=%d)!\n",
            HvGetCurrentGuest()->SipiCount, gHypervisorGlobalData.CpuData.CpuCount);
        return CX_STATUS_NOT_INITIALIZED;

    }

    if (!Silent && File) LOG("Freeze requested from %s:%d\n", File, Line);

    if (HvTryToAcquireSpinLock(&gFreezeCpusLock) == CX_FALSE)
    {
        WARNING("Cpu freeze lock is already acquired!\n");
        return CX_STATUS_INVALID_INTERNAL_STATE;
    }

    // Signal that we are the only active CPU
    {
        IO_PER_CPU_DATA *cpuData = CX_NULL;
        if (CX_SUCCESS(IoGetPerCpuData(&cpuData)))
        {
            cpuData->CpuPhaseRestore = cpuData->CpuPhase;
        }
        IoSetPerCpuPhase(IO_CPU_OTHERS_FROZEN);
    }

    // Allocate the structure in heap
    IPI_FREEZE_REQUEST *freezeReq;
    CX_STATUS status = HpAllocWithTagCore(&freezeReq,
                            sizeof(IPI_FREEZE_REQUEST),
                            TAG_IFR
                            );
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        LOG("CPU%d unlocked gFreezeCpusLock: %p\n", HvGetCurrentCpuIndex(), &gFreezeCpusLock);
        HvReleaseSpinLock(&gFreezeCpusLock);
        return status;
    }

    // Initialize structure
    freezeReq->OriginalInterruptibilityState = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
    freezeReq->Reason = Reason;
    freezeReq->ResumeExecution = 0;

    // Before sending the IPC, disable the interrupts. We must not be interrupting while all other CPUs are blocked.
    // Send the IPC to the given CPUs
    status = IntSendIpcMessage(_IpiFreezingHandler, // The function that will spin until the ResumeExecution is signaled
                       freezeReq,                   // The context will be the allocated structure
                       Affinity,                    // Pass the affinity
                       CX_FALSE                     // Must not wait for completion, because the handler actually blocks
                       );
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("IntSendIpcMessage", status);
        HpFreeAndNullWithTag(&freezeReq, TAG_IFR);
        HvReleaseSpinLock(&gFreezeCpusLock);
        return status;
    }

    *Id = (CX_VOID*)freezeReq;

    HvReleaseSpinLock(&gFreezeCpusLock);

    return status;
}

CX_STATUS
IpiResumeCpus2(
    _In_ CX_VOID      **Id,
    _In_ CX_INT8      *File,
    _In_ CX_UINT16    Line
)
//
// Resumes the CPUs that have been frozen by a call to IpiFreezeCpus(). Id is returned by IpiFreezeCpus(), and must not be modified.
// The Id structure will be freed, and its pointer set to CX_NULL before returning from this function.
//
{


    if (!Id)
    {
        LOG("[%d] [FATAL] FreezeRequest is null form [%s:%d].\n", HvGetCurrentApicId(), File, Line);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!(*Id))
    {
        // nothing to resume
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (CpuInterruptsAreEnabled())
    {
        LOG("[%d] [FATAL] Interrupts are enabled, they shouldn't be.\n", HvGetCurrentApicId());
        return CX_STATUS_INVALID_DEVICE_STATE;
    }

    IPI_FREEZE_REQUEST *freezeRequest = *((IPI_FREEZE_REQUEST**)Id);

    // Signal the target processors they can resume execution
    HvInterlockedIncrementU32(&(freezeRequest)->ResumeExecution);

    // If the interrupts were enabled before we frozen the CPUs, re-enable them here
    IpcSetInterruptibilityState((freezeRequest)->OriginalInterruptibilityState);

    // Signal that we are not the only active CPU anymore
    {
        IO_PER_CPU_DATA *cpuData = CX_NULL;
        if (CX_SUCCESS(IoGetPerCpuData(&cpuData)))
        {
            IoSetPerCpuPhase(cpuData->CpuPhaseRestore);
        }
    }

    // Free the FreezeRequest structure
    HpFreeAndNullWithTag(Id, TAG_IFR);

    return CX_STATUS_SUCCESS;
}

/* Static functions */
static
__forceinline
CX_VOID
_IpiWaitForIdle(
    CX_VOID
)
{
    ICR_LOW icrLow;
    icrLow.Value = LapicRead(APIC_INTERRUPT_COMMAND_REGISTER_LOW);

    while (icrLow.DeliveryStatus == IPI_STATUS_SEND_PENDING)
    {
        CpuYield();
        icrLow.Value = LapicRead(APIC_INTERRUPT_COMMAND_REGISTER_LOW);
    }

    return;
}

static
__forceinline
CX_VOID
_IpiIssueIpi(
    _In_ ICR Icr
)
{
    IPC_INTERRUPTIBILITY_STATE orig = IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);

    _IpiWaitForIdle();

    CX_UINT32 savedHighValue = LapicRead(APIC_INTERRUPT_COMMAND_REGISTER_HIGH);
    LapicWrite(APIC_INTERRUPT_COMMAND_REGISTER_HIGH, Icr.High.Value);
    LapicWrite(APIC_INTERRUPT_COMMAND_REGISTER_LOW, Icr.Low.Value);

    _IpiWaitForIdle();

    LapicWrite(APIC_INTERRUPT_COMMAND_REGISTER_HIGH, savedHighValue);

    IpcSetInterruptibilityState(orig);
}

static
CX_VOID
_IpiBroadcastInitAndWait(
    CX_VOID
)
//
// Broadcast an Init IPI to all other CPUs, and wait 10 milliseconds (part of MP initialization protocol)
//
{
    ICR icr = { 0 };

    icr.Low.DstShorthand = IPI_DST_ALL_EXCLUDING_SELF;
    icr.Low.TriggerMode = IPI_TRIGGER_EDGE;
    icr.Low.Level = IPI_LEVEL_ASSERT;
    icr.Low.DstMode = IPI_DST_MODE_PHYSICAL;
    icr.Low.DeliveryMode = IPI_DELIVERY_INIT;

    _IpiIssueIpi(icr);

    //
    // The MP initialization protocol states that wee need to wait 10 milliseconds here
    //
    HvSpinWait(10000);
}

static
CX_VOID
_IpiBroadcastStartupAndWait(
    _In_ CX_UINT32 CodeBase                     // Real mode address where the CPUs should start executing code from
)
//
// Broadcast a Startup IPI to all other CPUs, and wait 200 microseconds (part of MP initialization protocol)
//
{
    ICR icr = { 0 };

    icr.Low.DstShorthand = IPI_DST_ALL_EXCLUDING_SELF;
    icr.Low.TriggerMode = IPI_TRIGGER_EDGE;
    icr.Low.Level = IPI_LEVEL_ASSERT;
    icr.Low.DstMode = IPI_DST_MODE_PHYSICAL;
    icr.Low.DeliveryMode = IPI_DELIVERY_STARTUP;
    icr.Low.Vector = CodeBase >> 12;

    _IpiIssueIpi(icr);

    //
    // The MP initialization protocol states that wee need to wait 200 microseconds here
    //
    HvSpinWait(200);
}

static
CX_STATUS
_IpiFreezingHandler(
    _In_ IPI_FREEZE_REQUEST* FreezeRequest,
    _In_ HV_TRAP_FRAME* TrapFrame
)
//
// When a CPU is sent a freezing IPI, it will spin inside this function, with IRQL = IPI,
// until signaled to resume execution
//
{
    UNREFERENCED_PARAMETER(TrapFrame);

    if (!FreezeRequest) return CX_STATUS_INVALID_PARAMETER;

    if (FreezeRequest->Reason == IFR_REASON_DEBUGGER && HvDoWeHaveValidCpu())
    {
        // At this point each CPU needs to flush its vmcs because
        // the debugger can request information related to the vmcs of different VCPUs,
        // and we do not want the data to be cached.

        VCPU* currentVcpu = HvGetCurrentVcpu();
        if (currentVcpu)
        {
            CX_UINT64 activeVmcs;
            __vmx_vmptrst(&activeVmcs);

            // Perform a VMCLEAR operation on the source logical processor.
            // This ensures that all VMCS data that may be cached by the processor are flushed to memory.
            __vmx_vmclear(&activeVmcs);

            // The memory operand of the VMCLEAR instruction is also the address of a VMCS. After execution of the
            // instruction, that VMCS is neither active nor current on the logical processor. If the VMCS had been current on
            // the logical processor, the logical processor no longer has a current VMCS.
            // => make this VMCS the current one again
            __vmx_vmptrld(&activeVmcs);

            // The memory operand of the VMCLEAR instruction is the address of a VMCS. After execution of the instruction,
            // the launch state of that VMCS is "clear".
            // the VMLAUNCH instruction requires a VMCS whose launch state is "clear"; the VMRESUME instruction requires a VMCS
            // whose launch state is "launched".
            // => we must point out that we have to execute VMLAUNCH and NOT VMRESUME
            currentVcpu->State = VCPU_STATE_NOT_ACTIVE;
        }
    }

    HvGetCurrentCpu()->Ipc.QueueIsBeingDrained = 0;

    while (0 == FreezeRequest->ResumeExecution)
    {
        // Spin, spin...
        CpuYield();
    }

    HvGetCurrentCpu()->Ipc.QueueIsBeingDrained = 1;

    return CX_STATUS_SUCCESS;
}

/// @}