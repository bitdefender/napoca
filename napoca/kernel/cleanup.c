/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "kernel/kernel.h"
#include "kernel/spinlock.h"
#include "kernel/cleanup.h"
#include "debug/dumpers.h"
#include "guests/pci_tools.h"

/** @file cleanup.c
 * @brief cleanup.c - Implementation for cleanup.h interface.
 */

static CLN_HANDLER gClnHanlers[CLN_MAX_HANDLERS];
static CX_UINT64 gClnUsedHandlers;
static SPINLOCK gClnLock;
static volatile CX_UINT32 gClnNumberOfEnteredCpus;
volatile CX_UINT32 gClnNumberOfExitedCpus;
volatile CX_UINT64 gClnAlreadyInitialized = 0;
static volatile UNLOAD_CONTEXT gClnContext;

extern volatile CX_BOOL gNeedToUnload;

// _init32.nasm
CX_VOID LdReturnToLoader(_In_ LD_BOOT_CONTEXT *Context);        ///< Assembly method defined in _init32.nasm. Used for returning to the hv loader.

#define CL_LOG LOG          ///< Wrapper for Log

CX_VOID
ClnInitialize(
    CX_VOID
    )
{
    // avoid reinitialization of the cleanup lock
    if (HvInterlockedCompareExchangeU64(&gClnAlreadyInitialized, 1, 0) == 0)
    {
        HvInitSpinLock((SPINLOCK*)&gClnLock, "gClnLock", CX_NULL);
        gClnUsedHandlers = 0;
        gClnNumberOfEnteredCpus = 0;
        gClnNumberOfExitedCpus = 0;
        gNeedToUnload = 0;
    }
}



CX_STATUS
ClnRegisterCleanupHandler(
    _In_ CLN_CALLBACK CleanupFunction,
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_ CX_UINT64 OriginatorId,
    __out_opt CLN_HANDLER **Handler,
    _In_ CX_UINT32 CpuId
    )
{
    CX_UINT32 i;
    CX_BOOL different;

    // refuse to add new handlers once the onload process was triggered
    if (gNeedToUnload)
    {
        // forcefully free/release the gNmiPrintLock lock
        HvUnloadReleaseSpinlock(&gNmiPrintLock);
        NMILOG("[CLEANUP] CPU[%d] failed to register a new callback handler, the cleanup being already in progress\n",
            HvGetInitialLocalApicIdFromCpuid()
            );
        CLN_UNLOAD(STATUS_HV_UNLOAD_REQUESTED_INTERNALLY);
        return STATUS_HV_UNLOAD_REQUESTED_INTERNALLY;
    }
    if (CleanupFunction == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (gClnUsedHandlers >= CLN_MAX_HANDLERS) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    HvAcquireSpinLock((SPINLOCK*)&gClnLock);

    different = CX_TRUE;
    for (i = 0; i < gClnUsedHandlers; i++)
    {
        if (gClnHanlers[i].CpuId == CpuId) different = CX_FALSE;
    }

    if (Handler != CX_NULL) *Handler = (CLN_HANDLER*)&(gClnHanlers[i]);

    gClnHanlers[gClnUsedHandlers].CleanupFunction = CleanupFunction;
    gClnHanlers[gClnUsedHandlers].OriginatorId = OriginatorId;
    gClnHanlers[gClnUsedHandlers].OriginalState = OriginalState;
    gClnHanlers[gClnUsedHandlers].CpuId = CpuId;
    gClnUsedHandlers++;

    gClnNumberOfEnteredCpus += (different != 0);
    {
        CX_UINT16 originatorFile = 0;
        CX_UINT16 originatorLine = 0;
        CLN_HANDLER *handler;

        handler = (CLN_HANDLER*)&(gClnHanlers[gClnUsedHandlers-1]);
        if ((handler->OriginatorId & 0xBD00000000000000ULL) == 0xBD00000000000000ULL)
        {
            originatorFile = (handler->OriginatorId >> 16) & 0xFFFF;
            originatorLine = (handler->OriginatorId) & 0xFFFF;
        }
        else
        {
            originatorFile = (CX_UINT16)-1;
            originatorLine = 0;
        }
        CL_LOG("[CLEANUP] CPU[%d] has registered a handler[%d] from <%s:%d> targeted to %p\n",
            CLN_GET_CURRENT_CPUID(), gClnUsedHandlers-1, "", originatorLine, (CX_UINT64)CpuId);
    }

    HvReleaseSpinLock((SPINLOCK*)&gClnLock);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
ClnUnregisterCleanupHandler(
    _In_ _Post_invalid_ CLN_HANDLER*    ClnHandler
    )
{
    CX_STATUS status = CX_STATUS_SUCCESS;

    if ((ClnHandler == CX_NULL) // CX_NULL validation not actually required because of the 2nd validation but keep it for clarity
        || (ClnHandler < gClnHanlers)
        )
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    HvAcquireSpinLock((SPINLOCK*)&gClnLock);

    // find index in cleanup handlers
    CX_UINT32 cleanupHandlerIndex = (CX_UINT32)(ClnHandler - gClnHanlers);

    // check index only after lock was taken (gClnUsedHandlers) may be changed
    if (cleanupHandlerIndex >= gClnUsedHandlers)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }

    CX_UINT32 cpuId = ClnHandler->CpuId;

    for (CX_UINT32 i = cleanupHandlerIndex; i < gClnUsedHandlers - cleanupHandlerIndex - 1; ++i)
    {
        // can't use memcpy on whole buffer because it would be overlapping (we do not have memmove)
        memcpy(
            &gClnHanlers[cleanupHandlerIndex],
            &gClnHanlers[cleanupHandlerIndex + 1],
            sizeof(CLN_HANDLER)
        );
    }

    gClnUsedHandlers--;

    memzero(&gClnHanlers[gClnUsedHandlers], sizeof(CLN_HANDLER));

    // see if the CPU is still present in cleanup list (if it still has any handlers)
    // if not => decrement gClnNumberOfEnteredCpus
    CX_BOOL present = CX_FALSE;
    for (CX_UINT32 i = 0; i < gClnUsedHandlers; ++i)
    {
        if (gClnHanlers[i].CpuId == cpuId)
        {
            present = CX_TRUE;
            break;
        }
    }

    if (!present) gClnNumberOfEnteredCpus--;

cleanup:
    HvReleaseSpinLock((SPINLOCK*)&gClnLock);

    return status;
}

/**
 * @brief Iterate the list of registered callbacks in reversed order and restore original state of all system resources whose state had changed since the HV was started.
 *
 * @param[in]       CleanupContext          Informational context about what happened
 *
 * @returns CX_STATUS_SUCCESS               Always
 */
static
CX_STATUS
_ClnCallCleanupHandlers(
    _In_opt_ CLN_CONTEXT *CleanupContext
    )
{
    CX_STATUS status;
    CX_BOOL bsp;
    CX_UINT32 cpuId;

    bsp = CX_FALSE;
    cpuId = CLN_GET_CURRENT_CPUID();

    if (CpuIsCurrentCpuTheBsp())
    {
        CX_UINT32 last = (gClnNumberOfEnteredCpus - gClnNumberOfExitedCpus) - 1;
        CL_LOG("[CLEANUP] BSP waiting for %d APs (%d - %d - 1)\n", (gClnNumberOfEnteredCpus - gClnNumberOfExitedCpus) - 1, gClnNumberOfEnteredCpus, gClnNumberOfExitedCpus);
        // wait for all APs to finish their cleanup before taking the lock
        while ((gClnNumberOfEnteredCpus - gClnNumberOfExitedCpus) != 1)
        {
            if (((gClnNumberOfEnteredCpus - gClnNumberOfExitedCpus) - 1) != last)
            {
                last = (gClnNumberOfEnteredCpus - gClnNumberOfExitedCpus) - 1;
                CL_LOG("[CLEANUP] Waiting for %d APs..\n", last);
            }
            CpuYield();
        }
        bsp = CX_TRUE;
    }

    HvAcquireSpinLock((SPINLOCK*)&gClnLock);
    CL_LOG("[CLN] CPU[%d] handling cleanup\n", cpuId);
    for (CX_UINT64 i = gClnUsedHandlers; i > 0; i--)
    {
        CLN_HANDLER *handler;
        CX_UINT16 originatorFile = 0;
        CX_UINT16 originatorLine = 0;

        handler = (CLN_HANDLER*)&(gClnHanlers[i-1]);
        if ((handler->OriginatorId & 0xBD00000000000000ULL) == 0xBD00000000000000ULL)
        {
            originatorFile = (handler->OriginatorId >> 16) & 0xFFFF;
            originatorLine = (handler->OriginatorId) & 0xFFFF;
        }
        else
        {
            originatorFile = (CX_UINT16)-1;
            originatorLine = 0;
        }

        if (handler->CpuId != cpuId) continue; // skip any other's cpu handlers unless this is bsp and the cpuId is -1

        if (handler->CleanupFunction != CX_NULL)
        {
            CL_LOG("[CLEANUP] CPU[%d] <%s:%d> running cleanup callback[%d], CleanupFunction=%p, OriginalState=%p\n",
                cpuId, "", originatorLine, i, handler->CleanupFunction, handler->OriginalState);

            status = handler->CleanupFunction(handler->OriginalState, CleanupContext);
            if (!CX_SUCCESS(status))
            {
                // the cleanup handler returned some error, log it and CONTINUE THE CLEANUP ANYWAY
                CRITICAL("[CLEANUP] CPU[%d] <%s:%d> FAILED with status %d (%s)\n",
                    cpuId, "", originatorLine, status, NtStatusToString(status));
            }
        }
        else
        {
            CRITICAL("[CLEANUP] CPU[%d] CX_NULL cleanup callback [ordinal=%d, fileId=%d, line=%d]\n",
                cpuId, i, originatorFile, originatorLine);
        }
    }
    // this CPU has finished the cleanup process (unreached, the CPU state handler exits the hv)
    gClnNumberOfExitedCpus++;

    HvReleaseSpinLock((SPINLOCK*)&gClnLock);

    status = CX_STATUS_SUCCESS;

    return status;
}



CX_STATUS
ClnLockApCleanupHandler(
    _In_ CX_UINT64 OriginatorId,
    _In_ CX_UINT32 CpuId,
    __out_opt CLN_HANDLER **Handler,
    _In_ CX_BOOL LockAlreadyOwned
    )
{
    CX_STATUS status;
    CX_BOOL found;
    CX_UINT32 i;

    if (!LockAlreadyOwned) HvAcquireSpinLock((SPINLOCK*)&gClnLock);

    found = CX_FALSE;
    for (i = 0; i < gClnUsedHandlers; i++)
    {
        if ((gClnHanlers[i].CpuId == CpuId) && (gClnHanlers[i].OriginatorId == OriginatorId))
        {
            found = CX_TRUE;
            if (Handler != CX_NULL) *Handler = (CLN_HANDLER*)&(gClnHanlers[i]);
        }
    }

    if ((0 == OriginatorId) && (0 == CpuId) && (CX_NULL == Handler)) found = CX_TRUE;

    status = found ? CX_STATUS_SUCCESS : CX_STATUS_DATA_NOT_FOUND;
    if ((!CX_SUCCESS(status)) && (!LockAlreadyOwned)) HvReleaseSpinLock((SPINLOCK*)&gClnLock);

    // leave the lock taken
    return status;
}



CX_STATUS
ClnUnlockApCleanupHandler(
    _In_ CX_UINT64 OriginatorId,
    _In_ CX_UINT32 CpuId,
    _In_ CX_BOOL LockAlreadyOwned
    )
{
    UNREFERENCED_PARAMETER(OriginatorId);
    UNREFERENCED_PARAMETER(CpuId);

    if (!LockAlreadyOwned) HvReleaseSpinLock((SPINLOCK*)&gClnLock);

    return CX_STATUS_SUCCESS;
}


/**
 * @brief Internal unload routine, revert any changes made since we were started and try to chain-unload the HV.
 *
 * @param[in]       CleanupContext          Optional, should contain information about the error
 *
 * @returns This method should not return in HV
 */
static
CX_STATUS
_ClnReturnToLoader(
    _In_opt_ CLN_CONTEXT *CleanupContext
    )
{
    gNeedToUnload = CX_TRUE;

    _ClnCallCleanupHandlers(CleanupContext);

    // we just halt the system if the backbone failed
    IoEnableSerialOutput(CX_TRUE);
    LOG("[CLEANUP] [CPU=%d] Status: 0x%x - %s\n", CLN_GET_CURRENT_CPUID(), *(CX_STATUS*)CleanupContext, NtStatusToString(*(CX_STATUS*)CleanupContext));
    CfgFeaturesUnloadOnErrorsEnabled = CX_FALSE;
    DbgBreak();

    return CX_STATUS_SUCCESS;
}



CX_STATUS
ClnUnload(
    _In_ CX_STATUS StatusToReturn
    )
{
    CX_BOOL isRebootRecommended = DumpersTryToDumpEmergencyLogs();

    if (IoGetPerCpuPhase() < IO_CPU_ROOT_CYCLE)
    {
        gNeedToUnload = CX_TRUE;
        gClnContext.Status = StatusToReturn;
        _ClnReturnToLoader((CLN_CONTEXT*)&gClnContext);

        CRITICAL("[UNLOAD] Couldn't return to loader\n");
    }
    else
    {
        // it's too late, we've already started the guest and the guest-assisted unload protocol
        // is not yet implemented
        CRITICAL("[UNLOAD] Unload is not supported after the guest was started\n");
    }

    if (isRebootRecommended)
    {
        CRITICAL("REBOOT!\n");
        PwrReboot(CX_FALSE, CX_FALSE);
    }
    else
    {
        CRITICAL("HALT!\n");
        __halt();
    }

    return CX_STATUS_OPERATION_NOT_SUPPORTED;
}

CX_STATUS
ClnAddMsrToRestoreArea(
    _Inout_     MSR_RESTORE_VALUES          *MsrValues,
    _In_        CX_UINT32                   MsrIndex,
    _In_        CX_UINT64                   MsrValue
)
{
    if (MsrValues == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (MsrValues->CurentArrayElements >= MsrValues->MaxArrayElements) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    MSR_INDEX_VALUE_PAIR *msrPair = &MsrValues->Msrs[MsrValues->CurentArrayElements++];

    msrPair->Index = MsrIndex;
    msrPair->Value = MsrValue;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
ClnCpuRestoreState(
    _In_ CPU_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
    )
{
    CPU_ORIGINAL_STATE *state;
    CX_UINT32 cpuId;
    UNLOAD_CONTEXT *ctx;
    CX_UINT32 last;
    cpuId = CLN_GET_CURRENT_CPUID();
    state = (CPU_ORIGINAL_STATE*)OriginalState;
    ctx = (UNLOAD_CONTEXT*)Context;

    // all AP processors should be left in 'wait-for-sipi' for single cpu loader environments
    if ( !(CpuIsCurrentCpuTheBsp() || BOOT_OPT_MULTIPROCESSOR) )
    {
        // this CPU was not active before the HV, halt it (should be in wait for sipi state.. :|)
        gClnNumberOfExitedCpus++; // signal the bsp that we're done
        ClnUnlockApCleanupHandler(0, 0, CX_FALSE); // release the LOCK so that the next CPU can continue
        IpcSetInterruptibilityState(IPC_INTERRUPTIBILITY_BLOCK_ALL);
        __halt();
    }

    // overwrite the loader's RAX with the unload status value
    if (ctx != CX_NULL) OriginalState->LoaderBootContext->Rax = ctx->Status;

    ClnUnlockApCleanupHandler(0, 0, CX_FALSE); // release the LOCK so that the next CPU can continue

    if (CpuIsCurrentCpuTheBsp())
    {
        LD_BOOT_CONTEXT *Ptr = OriginalState->LoaderBootContext;
        char *prefix = "";
        CX_UINT8 *tmp1;

        // forcefully free/release the gNmiPrintLock lock
        HvUnloadReleaseSpinlock(&gNmiPrintLock);

        NMILOG("[CPU-CLN] %-10s - %018p: dumping LD_BOOT_CONTEXT\n", prefix, Ptr);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s 0x%08X\n", prefix, &(Ptr->BootMode), "(CX_UINT32) BootMode", Ptr->BootMode);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->ModulesPa), "(CX_UINT64) ModulesPa", Ptr->ModulesPa);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s 0x%08X\n", prefix, &(Ptr->NumberOfModules), "(CX_UINT32) NumberOfModules", Ptr->NumberOfModules);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Cr3), "(CX_UINT64) Cr3", Ptr->Cr3);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Cr4), "(CX_UINT64) Cr4", Ptr->Cr4);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Cr0), "(CX_UINT64) Cr0", Ptr->Cr0);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Cr8), "(CX_UINT64) Cr8", Ptr->Cr8);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s 0x%04X\n", prefix, &(Ptr->GdtLimit), "(CX_UINT16) GdtLimit", Ptr->GdtLimit);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->GdtBase), "(CX_UINT64) GdtBase", Ptr->GdtBase);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s 0x%04X\n", prefix, &(Ptr->IdtLimit), "(CX_UINT16) IdtLimit", Ptr->IdtLimit);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->IdtBase), "(CX_UINT64) IdtBase", Ptr->IdtBase);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rax), "(CX_UINT64) Rax", Ptr->Rax);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rbx), "(CX_UINT64) Rbx", Ptr->Rbx);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rcx), "(CX_UINT64) Rcx", Ptr->Rcx);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rdx), "(CX_UINT64) Rdx", Ptr->Rdx);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rsi), "(CX_UINT64) Rsi", Ptr->Rsi);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rdi), "(CX_UINT64) Rdi", Ptr->Rdi);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rbp), "(CX_UINT64) Rbp", Ptr->Rbp);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->Rsp), "(CX_UINT64) Rsp", Ptr->Rsp);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R8), "(CX_UINT64) R8", Ptr->R8);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R9), "(CX_UINT64) R9", Ptr->R9);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R10), "(CX_UINT64) R10", Ptr->R10);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R11), "(CX_UINT64) R11", Ptr->R11);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R12), "(CX_UINT64) R12", Ptr->R12);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R13), "(CX_UINT64) R13", Ptr->R13);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R14), "(CX_UINT64) R14", Ptr->R14);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->R15), "(CX_UINT64) R15", Ptr->R15);
        NMILOG("[CPU-CLN] %-10s - %018p: %-46s %018p\n", prefix, &(Ptr->RFlags), "(CX_UINT64) RFlags", Ptr->RFlags);
        tmp1 = (CX_UINT8 *)(CX_SIZE_T)Ptr->Rsp;
        tmp1 += sizeof(LD_BOOT_CONTEXT) + 0x20;
        NMILOG("[CPU-CLN] COMPUTED LOADER STACK: %p\n", tmp1);
    }

    gClnNumberOfExitedCpus++; // signal that we have finished the cleanup process (need only to return)

    last = gClnNumberOfExitedCpus;
    // all CPUs should get to this point BEFORE entering the loader
    while (gClnNumberOfEnteredCpus != gClnNumberOfExitedCpus)
    {
        if (gClnNumberOfExitedCpus != last) last = gClnNumberOfExitedCpus;
        CpuYield();
    }

    for (CX_UINT32 i = 0; i < OriginalState->Msrs.CurentArrayElements; ++i)
    {
        __writemsr(
            OriginalState->Msrs.Msrs[i].Index,
            OriginalState->Msrs.Msrs[i].Value);
    }

    // all CPUs that get to this point must have a loader defined state, restore it and return
    LdReturnToLoader(OriginalState->LoaderBootContext);

    return CX_STATUS_SUCCESS;
}
