/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \defgroup hooks Resource access interception (hooks)
/// @{

#include "napoca.h"
#include "kernel/kernel.h"
#include "guests/guests.h"
#include "guests/hooks.h"
#include "memory/cachemap.h"

CX_STATUS
HkPreinitGuestHookTables(
    _In_ GUEST* Guest
    )
{
    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    memzero(&(Guest->IoHooks), sizeof(GUEST_IO_HOOK_TABLE));
    memzero(&(Guest->MsrHooks), sizeof(GUEST_MSR_HOOK_TABLE));
    memzero(&(Guest->EptHooks), sizeof(GUEST_EPT_HOOK_TABLE));

    HvInitRwSpinLock(&Guest->IoHooks.Lock, "IOHOOKS lock for Guest", Guest);
    HvInitRwSpinLock(&Guest->MsrHooks.Lock, "MSRHOOKS lock for Guest", Guest);
    HvInitRwSpinLock(&Guest->EptHooks.Lock, "EPTHOOKS lock for Guest", Guest);

    // initialize global locks also
    HvInitSpinLock(&Guest->MsrHookLockGlb, "Guest->MsrHookLockGlb", Guest);

    return CX_STATUS_SUCCESS;
}


CX_STATUS
HkSetIoHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT16 BasePort,
    _In_ CX_UINT16 MaxPort,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadIoPort ReadCb,
    _In_ PFUNC_DevWriteIoPort WriteCb,
    _In_opt_ CX_VOID* Context
    )
{
    CX_STATUS status;
    CX_BOOL found;
    CX_UINT32 i, k;

    found = CX_FALSE;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (MaxPort < BasePort) return CX_STATUS_INVALID_PARAMETER_3;
    if (ReadCb == CX_NULL && WriteCb == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;
    if (Guest->IoHooks.Count >= MAX_IO_HOOKS) return STATUS_TOO_MANY_HOOKS;

    // get hypervisor specific I/O port hook rwlock exclusively
    HvAcquireRwSpinLockExclusive(&Guest->IoHooks.Lock);

    // check we can put the hook (on hypervisor level)
    for (i = 0; i < Guest->IoHooks.Count; i++)
    {
        GUEST_IO_HOOK* hook;

        hook = &Guest->IoHooks.Hook[i];

        if (((BasePort >= hook->Port) && (BasePort <= hook->MaxPort)) ||
            ((MaxPort >= hook->Port) && (MaxPort <= hook->MaxPort)))
        {
            // oops, those overlap, we fail
            found = CX_TRUE;
            break;
        }
    }

    if (found)
    {
        status = STATUS_HOOK_ALREADY_SET;
        goto unlock_hv_lock;
    }

    // check that we can put the hook (on global level)
    for (i = BasePort; i <= MaxPort; i++)
    {
        if (0 != (Guest->IoBitmap[i >> 6] & BIT_AT(i & 0x3f)))      // port / 64, port % 64
        {
            found = CX_TRUE;
            break;
        }
    }

    if (found)
    {
        LOG("[G%d] Hook on port range 0x%04x->0x%04x already set in I/O Bitmap!\n", Guest->Index, BasePort, MaxPort);

        status = STATUS_HOOK_ALREADY_SET_GLOBAL;
        goto unlock_hv_lock;
    }

    LOG("[G%d] Will hook port range 0x%04x->0x%04x\n", Guest->Index, BasePort, MaxPort);

    // put the hook into hypervisor specific list
    i = 0;
    while (i < Guest->IoHooks.Count)
    {
        // is hook from index i placed on a greater destination?
        if (Guest->IoHooks.Hook[i].Port > MaxPort)
        {
            // ...yes, then we MUST place the new hook to position i, to maintain ascending order
            break;
        }

        // ...no, then we check the next entry
        i++;
    }

    // do we need to move items upwards?
    for (k = Guest->IoHooks.Count; k >= i + 1; k--)
    {
        Guest->IoHooks.Hook[k] = Guest->IoHooks.Hook[k - 1];
    }

    // effectively insert new hook
    Guest->IoHooks.Hook[i].Port = BasePort;
    Guest->IoHooks.Hook[i].MaxPort = MaxPort;
    Guest->IoHooks.Hook[i].Context = Context;
    Guest->IoHooks.Hook[i].Flags = Flags;
    Guest->IoHooks.Hook[i].ReadCb = ReadCb;
    Guest->IoHooks.Hook[i].WriteCb = WriteCb;
    Guest->IoHooks.Count++;

    // if successfully placed into hypervisor specific list, place hook also into global table
    for (i = BasePort; i <= MaxPort; i++)
    {
        Guest->IoBitmap[i >> 6] |= BIT_AT(i & 0x3f);
    }

    // everything done just fine, proceed to cleanup
    status = CX_STATUS_SUCCESS;

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockExclusive(&Guest->IoHooks.Lock);

    return status;
}


CX_STATUS
HkRemoveIoHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT16 BasePort
    )
{
    CX_STATUS status;
    CX_BOOL found;
    CX_UINT16 maxPort;
    CX_UINT32 i, k;

    found = CX_FALSE;
    maxPort = 0;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    // get hypervisor specific I/O port hook rwlock exclusively
    HvAcquireRwSpinLockExclusive(&Guest->IoHooks.Lock);

    // locate hook matching BasePort
    for (i = 0; i < Guest->IoHooks.Count; i++)
    {
        GUEST_IO_HOOK* hook;

        hook = &Guest->IoHooks.Hook[i];

        if (BasePort == hook->Port)
        {
            // bingo, we found it!
            found = CX_TRUE;
            maxPort = hook->MaxPort;
            break;
        }
    }

    if (!found)
    {
        status = CX_STATUS_DATA_NOT_FOUND;
        goto unlock_hv_lock;
    }

    // remove hook from global table
    for (i = BasePort; i <= maxPort; i++)
    {
        Guest->IoBitmap[i >> 6] &= ~BIT_AT(i & 0x3f);       // port / 64, port % 64
    }

    // remove hook from hypervisor specific list
    for (k = i; k < Guest->IoHooks.Count - 1; k++)
    {
        Guest->IoHooks.Hook[k] = Guest->IoHooks.Hook[k + 1];
    }
    Guest->IoHooks.Count--;

    // everything done just fine, proceed to cleanup
    status = CX_STATUS_SUCCESS;

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockExclusive(&Guest->IoHooks.Lock);

    return status;
}


CX_STATUS
HkCallIoHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT16 Port,
    _In_ CX_UINT64 ExitQual,
    __out_opt GUEST_IO_HOOK* IoHook
    )
{
    CX_STATUS status;
    GUEST* guest;
    GUEST_IO_HOOK* hook;
    CX_UINT32 i;

    hook = CX_NULL;

    if ((Vcpu == CX_NULL) || (Vcpu->Guest == CX_NULL)) return CX_STATUS_INVALID_PARAMETER_1;

    guest = Vcpu->Guest;

    // get hypervisor specific I/O port hook rwlock shared
    HvAcquireRwSpinLockShared(&guest->IoHooks.Lock);

    // locate hook
    for (i = 0; i < guest->IoHooks.Count; i++)
    {
        hook = &guest->IoHooks.Hook[i];

        if ((Port >= hook->Port) && (Port <= hook->MaxPort))
        {
            // bingo, hook matched
            break;
        }
        else
        {
            hook = CX_NULL;
        }
    }

    if (hook == CX_NULL)
    {
        status = STATUS_NO_HOOK_MATCHED;
        goto unlock_hv_lock;
    }

    // do we have a STRING INSTRUX and/or a REP prefix?  ==> MUST EMULATE
    if (0 != (ExitQual & 0x30))
    {
        // also give back a pointer to the Resource
        if (IoHook != CX_NULL) IoHook = hook;

        status = STATUS_NEEDS_EMULATION;
        goto unlock_hv_lock;
    }

    // perform callback (only NON-string and NON-REP-prefix cases)
    {
        CX_BOOL inOp;                   // CX_TRUE for IN, CX_FALSE for OUT
        CX_UINT8 opWidth;
        CX_UINT8* value;

        // get operation direction and width
        inOp = (0 != (ExitQual & 0x8));
        opWidth = (CX_UINT8)((ExitQual & 0x7) + 1);

        // IMPORTANT: we assume that only AL/AX/EAX is used as a parameter (no STRING or REP prefixed IN/OUT)
        value = (CX_UINT8*)&(Vcpu->ArchRegs.EAX);

        if (inOp) status = hook->ReadCb(Port, opWidth, value, hook->Context);
        else status = hook->WriteCb(Port, opWidth, value, hook->Context);

        if ((!CX_SUCCESS(status)) &&
            (STATUS_NEEDS_EMULATION != status) &&
            (STATUS_EXECUTE_ON_BARE_METAL != status))
        {
            LOG_FUNC_FAIL("ReadCb/WriteCb", status);
            LOG("Callback failed on port range 0x%x->0x%x (%s)\n",
                    hook->Port, hook->MaxPort, (inOp ? "read" : "write"));
        }

        // return a copy of it
        if (IoHook != CX_NULL) *IoHook = *hook;
    }

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockShared(&guest->IoHooks.Lock);

    return status;
}


/// @brief Set the hook in the internal MSR bit map
///
/// @param[in] Guest           The guest for which the bit map will be changed
/// @param[in] Msr             The MSR to be hooked
/// @param[in] SetRead         TRUE if we want to set read hook for the given MSR
/// @param[in] SetWrite        TRUE if we want to set write hook for the given MSR
static
CX_VOID
_HkSetMsrBitmapExit(
    _In_ GUEST* Guest,
    _In_ CX_UINT32 Msr,
    _In_ CX_BOOL SetRead,
    _In_ CX_BOOL SetWrite
)
{
    CX_UINT32 msr;
    CX_UINT32 delta;

    if (Msr <= 0x00001FFF)
    {
        msr = Msr;
        delta = 0;
    handle_common_case_set:
        // MSR bitmaps, conform INTEL 21.6.9
        //    0..1023 -   0..127 - read bitmap for LOW MSRs(0x00000000 - 0x00001FFF)
        // 1024..2047 - 128..255 - read bitmap for HIGH MSRs(0xC0000000 - 0xC0001FFF)
        // 2048..3071 - 256..383 - write bitmap for LOW MSRs (0x00000000 - 0x00001FFF)
        // 3072..4095 - 384..511 - write bitmap for HIGH MSRs (0xC0000000 - 0xC0001FFF)
        if (SetRead) Guest->MsrBitmap[0 + delta + (msr >> 6)] |= BIT_AT(msr & 0x3f); // READ map
        if (SetWrite) Guest->MsrBitmap[256 + delta + (msr >> 6)] |= BIT_AT(msr & 0x3f); // WRITE map
    }
    else if ((Msr >= 0xC0000000) && (Msr <= 0xC0001FFF))
    {
        msr = Msr - 0xC0000000;
        delta = 128;                    // LOW to HIGH delta in QWORDs
        goto handle_common_case_set;
    }
    else
    {
        // nothing to do here, exit will happen always
    }

    return;
}



CX_STATUS
HkSetMsrHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT32 BaseMsr,
    _In_ CX_UINT32 MaxMsr,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadMsr ReadCb,
    _In_ PFUNC_DevWriteMsr WriteCb,
    _In_opt_ CX_VOID* Context
    )
{
    CX_STATUS status;
    CX_BOOL found;
    CX_UINT32 i, k;

    found = CX_FALSE;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (MaxMsr < BaseMsr) return CX_STATUS_INVALID_PARAMETER_3;
    if (ReadCb == CX_NULL && WriteCb == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;
    if (Guest->MsrHooks.Count >= MAX_MSR_HOOKS) return STATUS_TOO_MANY_HOOKS;

    // get hypervisor specific MSR hook rwlock exclusively
    HvAcquireRwSpinLockExclusive(&Guest->MsrHooks.Lock);

    // check we can put the hook (on hypervisor level)
    for (i = 0; i < Guest->MsrHooks.Count; i++)
    {
        GUEST_MSR_HOOK* hook;

        hook = &Guest->MsrHooks.Hook[i];

        if (((BaseMsr >= hook->Msr) && (BaseMsr <= hook->MaxMsr)) ||
            ((MaxMsr >= hook->Msr) && (MaxMsr <= hook->MaxMsr)))
        {
            // oops, those overlap, we fail
            found = CX_TRUE;
            break;
        }
    }

    if (found)
    {
        status = STATUS_HOOK_ALREADY_SET;
        goto unlock_hv_lock;
    }

    // acquire global MSR hook spinlock
    HvAcquireSpinLock(&Guest->MsrHookLockGlb);

    // put the hook into hypervisor specific list
    i = 0;
    while (i < Guest->MsrHooks.Count)
    {
        // is hook from index i placed on a greater destination?
        if (Guest->MsrHooks.Hook[i].Msr > MaxMsr)
        {
            // ...yes, then we MUST place the new hook to position i, to maintain ascending order
            break;
        }

        // ...no, then we check the next entry
        i++;
    }

    // do we need to move items upwards?
    for (k = Guest->MsrHooks.Count; k >= i + 1; k--)
    {
        Guest->MsrHooks.Hook[k] = Guest->MsrHooks.Hook[k - 1];
    }

    // effectively insert new hook
    Guest->MsrHooks.Hook[i].Msr = BaseMsr;
    Guest->MsrHooks.Hook[i].MaxMsr = MaxMsr;
    Guest->MsrHooks.Hook[i].Context = Context;
    Guest->MsrHooks.Hook[i].Flags = Flags;
    Guest->MsrHooks.Hook[i].ReadCb = ReadCb;
    Guest->MsrHooks.Hook[i].WriteCb = WriteCb;
    Guest->MsrHooks.Count++;

    // if successfully placed into hypervisor specific list, place hook also into global table
    for (i = BaseMsr; i <= MaxMsr; i++)
    {
        _HkSetMsrBitmapExit(Guest, i, !!ReadCb, !!WriteCb);
    }

    // everything done just fine, proceed to cleanup
    status = CX_STATUS_SUCCESS;

    // unlock global spinlock
    HvReleaseSpinLock(&Guest->MsrHookLockGlb);

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockExclusive(&Guest->MsrHooks.Lock);

    return status;
}


CX_STATUS
HkCallMsrHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT32 Msr,
    _In_ CX_BOOL ItIsWrite,
    _Inout_ CX_UINT64 *Value,
    __out_opt GUEST_MSR_HOOK* MsrHook
    )
{
    CX_STATUS status;
    GUEST* guest;
    GUEST_MSR_HOOK* hook;
    CX_UINT32 i;

    if ((Vcpu == CX_NULL) || (Vcpu->Guest == CX_NULL)) return CX_STATUS_INVALID_PARAMETER_1;
    if (Value == CX_NULL) return CX_STATUS_INVALID_PARAMETER_4;

    hook = CX_NULL;
    guest = Vcpu->Guest;

    // get hypervisor specific MSR hook rwlock shared
    HvAcquireRwSpinLockShared(&guest->MsrHooks.Lock);

    // locate hook
    for (i = 0; i < guest->MsrHooks.Count; i++)
    {
        hook = &guest->MsrHooks.Hook[i];

        if ((Msr >= hook->Msr) && (Msr <= hook->MaxMsr))
        {
            // bingo, hook matched
            break;
        }
        else
        {
            hook = CX_NULL;
        }
    }

    if (hook == CX_NULL)
    {
        status = STATUS_NO_HOOK_MATCHED;
        goto unlock_hv_lock;
    }

    // perform callback
    if (ItIsWrite)
    {
        if (hook->WriteCb != CX_NULL) status = hook->WriteCb(Msr, *Value, hook->Context);
        else status = STATUS_NO_HOOK_MATCHED;
    }
    else if (hook->ReadCb != CX_NULL)
    {
        status = hook->ReadCb(Msr, Value, hook->Context);
    }
    else
    {
        status = STATUS_NO_HOOK_MATCHED;
    }

    if ((!CX_SUCCESS(status)) &&
        (STATUS_NEEDS_EMULATION != status) &&
        (STATUS_EXECUTE_ON_BARE_METAL != status) &&
        (STATUS_NO_HOOK_MATCHED != status))
    {
        LOG_FUNC_FAIL("hook->Resource->ReadMsr/WriteMsr", status);
    }

    if (MsrHook != CX_NULL) *MsrHook = *hook;

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockShared(&guest->MsrHooks.Lock);

    return status;
}


/// @brief Gets the already set hook for the given address
///
/// @param[in]     Vcpu            The VCPU for which the EPT hook is searched
/// @param[in]     Address         The address based on what the hook will be searched
/// @param[out]    EptHook         The returned hook, if it was found
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook was found
/// @returns    STATUS_NO_HOOK_MATCHED              - Hook not found
static
CX_STATUS
_HkGetEptHook(
    _In_  VCPU* Vcpu,
    _In_  CX_UINT64 Address,
    __out_opt GUEST_EPT_HOOK** EptHook
    )
{
    CX_STATUS status;
    GUEST* guest;
    GUEST_EPT_HOOK* hook;

    hook = CX_NULL;
    guest = Vcpu->Guest;

    // get hypervisor specific EPT hook rwlock shared
    HvAcquireRwSpinLockShared(&guest->EptHooks.Lock);

    // locate hook
    for (CX_UINT32 i = 0; i < guest->EptHooks.Count; i++)
    {
        hook = &guest->EptHooks.Hook[i];

        if ((Address >= hook->BaseAddress) && (Address <= hook->MaxAddress))
        {
            // bingo, hook matched
            break;
        }
        else
        {
            hook = CX_NULL;
        }
    }

    if (hook != CX_NULL)
    {
        *EptHook = hook;
        status = CX_STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_NO_HOOK_MATCHED;
    }

    HvReleaseRwSpinLockShared(&guest->EptHooks.Lock);

    return status;
}


CX_STATUS
HkSetEptHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT64 BaseAddress,
    _In_ CX_UINT64 MaxAddress,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadMem ReadCb,
    _In_ PFUNC_DevWriteMem WriteCb,
    _In_opt_ CX_VOID* Context
    )
{
    CX_STATUS status;
    CX_BOOL found;
    CX_UINT32 i, k;
    GUEST_EPT_HOOK* hook;

    found = CX_FALSE;
    hook = CX_NULL;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (MaxAddress < BaseAddress) return CX_STATUS_INVALID_PARAMETER_3;
    if (ReadCb == CX_NULL && WriteCb == CX_NULL) return CX_STATUS_INVALID_PARAMETER_5;
    if (Guest->EptHooks.Count >= MAX_EPT_HOOKS) return STATUS_TOO_MANY_HOOKS;

    // get hypervisor specific EPT hook rwlock exclusively
    HvAcquireRwSpinLockExclusive(&Guest->EptHooks.Lock);

    // check we can put the hook (on hypervisor level)

    for (i = 0; i < Guest->EptHooks.Count; i++)
    {
        hook = &Guest->EptHooks.Hook[i];

        if (DO_RANGES_OVERLAP(BaseAddress, MaxAddress, hook->BaseAddress, hook->BaseAddress))
        {
            // oops, those overlap, we fail
            CRITICAL("Found hook at %p <-> %p\n", hook->BaseAddress, hook->MaxAddress);

            found = CX_TRUE;
            break;
        }
    }

    if (found)
    {
        status = STATUS_HOOK_ALREADY_SET;
        goto unlock_hv_lock;
    }

    // acquire global EPT hook spinlock
    GstLock(Guest, GST_UPDATE_REASON_EPT_CHANGES);

    // check that we can put the hook (on global level)
    if (!EptIsMemMapped(GstGetEptOfPhysicalMemory(Guest), BaseAddress, MaxAddress - BaseAddress + 1))
    {
        ERROR("EptIsMemMapped failed for GPA [%018p, %018p]\n", BaseAddress, MaxAddress - BaseAddress);
        status = STATUS_NO_MAPPING_STRUCTURES;
        goto unlock_global_lock;
    }

    // put the hook into hypervisor specific list
    i = 0;
    while (i < Guest->EptHooks.Count)
    {
        // is hook from index i placed on a greater destination?
        if (Guest->EptHooks.Hook[i].BaseAddress > MaxAddress)
        {
            // ...yes, then we MUST place the new hook to position i, to maintain ascending order
            break;
        }

        // ...no, then we check the next entry
        i++;
    }

    // do we need to move items upwards?
    for (k = Guest->EptHooks.Count; k >= i+1; k--)
    {
        Guest->EptHooks.Hook[k] = Guest->EptHooks.Hook[k-1];
    }

    // effectively insert new hook
    hook = &Guest->EptHooks.Hook[i];

    hook->BaseAddress = BaseAddress;
    hook->MaxAddress = MaxAddress;
    hook->Context = Context;
    hook->ReadCb = ReadCb;
    hook->WriteCb = WriteCb;
    hook->Flags = Flags;
    Guest->EptHooks.Count++;

    // if successfully placed into hypervisor specific list, place hook also into global table
    // compose final rights mask to handle correctly RWX hooks individually
    EPT_RIGHTS nrights = { 0 };
    nrights.Read = !(ReadCb);
    nrights.Write = !(WriteCb);
    nrights.Special = 1;
    status = EptSetRights(GstGetEptOfPhysicalMemory(Guest), BaseAddress, MaxAddress - BaseAddress + 1, nrights);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptSetRights", status);
        goto unlock_global_lock;
    }

    // everything done just fine, proceed to cleanup
    status = CX_STATUS_SUCCESS;

    // unlock global spinlock
unlock_global_lock:
    GstUnlock(Guest, GST_UPDATE_REASON_EPT_CHANGES);

    // release hypervisor specific lock
unlock_hv_lock:
    HvReleaseRwSpinLockExclusive(&Guest->EptHooks.Lock);

    return status;
}


CX_STATUS
HkCallEptHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Address,
    __out_opt GUEST_EPT_HOOK* EptHook
    )
{
    CX_STATUS status;
    GUEST_EPT_HOOK* hook;

    if ((Vcpu == CX_NULL) || (Vcpu->Guest == CX_NULL)) return CX_STATUS_INVALID_PARAMETER_1;

    status = _HkGetEptHook(Vcpu, Address, &hook);
    if (!CX_SUCCESS(status)) return status;

    // do emulation directly, so return STATUS_NEEDS_EMULATION
    status = STATUS_NEEDS_EMULATION;

    if (EptHook != CX_NULL) *EptHook = *hook;

    return status;
}


///
/// BIOS
///

// BIOS interrupt hook stub (defined in bios_hooks.nasm)
extern CX_UINT8 __RealModeHookPre;     ///< The start of the pre-hook code
extern CX_UINT8 __RealModeHookPost;    ///< The start of the post-hook code
extern CX_UINT8 __RealModeHookStubEnd; ///< End of the hook(s)

BIOS_INT_HOOK gBiosHooks[MAX_BIOS_HOOKS]; ///< All registered BIOS interrupt hooks
CX_UINT32 gNumberOfBiosHooks = 0;         ///< Amount of current hooks


CX_STATUS
HkInitBiosHooks(
    _In_ GUEST* Guest
    )
{
    CX_STATUS status;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Guest->RealModeMemory == CX_NULL)
    {
        CX_UINT32 pages = (CX_MEGA / CX_PAGE_SIZE_4K);
        LOG("Mapping lower mem %d pages (%dKB)\n", pages, (pages * CX_PAGE_SIZE_4K) / 1024);
        status = ChmMapContinuousGuestGpaPagesToHost(Guest, 0, pages, 0, &Guest->RealModeMemory, 0, TAG_BHK);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("ChmMapContinuousGuestGpaPagesToHost", status);
            goto cleanup;
        }
    }

    Guest->BiosTopOfStubsStack = 0x400; // at the end of the real-mode IDT (IVT)
    Guest->RealModeMemReservedBytes = 0;

    status = CX_STATUS_SUCCESS;
cleanup:
    return status;
}



CX_STATUS
HkUnloadBiosHooks(
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
    )
{
    UNREFERENCED_PARAMETER(OriginalState);
    UNREFERENCED_PARAMETER(Context);

    for (CX_INT32 i = 0; i < gHypervisorGlobalData.GuestCount; i++)
    {
        GUEST *guest;
        guest = gHypervisorGlobalData.Guest[i];
        for (CX_UINT32 hookIndex = 0; hookIndex < gNumberOfBiosHooks; hookIndex++)
        {
            if (gBiosHooks[hookIndex].GuestIndex == i)
            {
                LOG("GUEST[%d] [INT 0x%X] Hook unloaded\n", i, gBiosHooks[hookIndex].InterruptNumber);
                HkRemoveBiosHook(guest, &gBiosHooks[hookIndex]);
            }
        }
    }

    return CX_STATUS_SUCCESS;
}


CX_STATUS
HkSetBiosHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT8 InterruptNumber,
    _In_ HK_BIOS_HOOK_HANDLER Handler,
    __out_opt BIOS_INT_HOOK **Hook
    )
{
    CX_STATUS status;
    CX_UINT32 guestHookAddr;
    BIOS_INT_HOOK hook = {0};
    CX_UINT64 hookIndex;

    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Handler == CX_NULL) return CX_STATUS_INVALID_PARAMETER_3;
    if ((Guest->RealModeMemory == CX_NULL) || (Guest->Index != 0)) return CX_STATUS_NOT_INITIALIZED;
    if (gNumberOfBiosHooks >= MAX_BIOS_HOOKS) return CX_STATUS_INSUFFICIENT_RESOURCES;

    // remember to cleanup the hooks when setting the very first one
    if (gNumberOfBiosHooks == 0)
    {
        status = CLN_REGISTER_BSP_HANDLER(HkUnloadBiosHooks, CX_NULL, CX_NULL);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("CLN_REGISTER_BSP_HANDLER", status);
            return status;
        }
    }

    CX_UINT32 hookSize = (CX_UINT32)((CX_UINT64)(&__RealModeHookStubEnd) - (CX_UINT64)(&__RealModeHookPre));
    CX_UINT32 initialNumberOfReservedBytes;
    CX_BOOL isMemoryUsed = CX_FALSE;
    CX_UINT8 *memoryContent;

    Guest->RealModeMemReservedBytes += hookSize;
    guestHookAddr = Guest->BiosTopOfStubsStack - Guest->RealModeMemReservedBytes;
    initialNumberOfReservedBytes = Guest->RealModeMemReservedBytes += hookSize;
    memoryContent = Guest->RealModeMemory + guestHookAddr;

    for (CX_UINT8 i = 0; i < hookSize; i++)
    {
        if (memoryContent[i] != 0) isMemoryUsed = CX_TRUE;
    }

    while (isMemoryUsed && guestHookAddr >= hookSize)
    {
        guestHookAddr -= hookSize;
        Guest->RealModeMemReservedBytes += hookSize;
        memoryContent = Guest->RealModeMemory + guestHookAddr;
        isMemoryUsed = CX_FALSE;

        for (CX_UINT8 i = 0; i < hookSize; i++)
        {
            if (memoryContent[i] != 0) isMemoryUsed = CX_TRUE;
        }
    }

    //if there is no free entry, use the last entry of IVT
    if (guestHookAddr < hookSize && isMemoryUsed)
    {
        WARNING("Couldn't find any free space in IVT.. Will hook at the end of IVT\n");
        Guest->RealModeMemReservedBytes = initialNumberOfReservedBytes;
        guestHookAddr = InterruptNumber == 0x10 ? 0x3F2 : 0x402;
        //We only hook int 0x10 if CfgDebugOutputVgaEnabled = 1
        //0x402 - serial ports 2,3,4 and parallel port 1
    }

    memcpy(Guest->RealModeMemory + guestHookAddr, &__RealModeHookPre, (CX_UINT64)(&__RealModeHookStubEnd) - (CX_UINT64)(&__RealModeHookPre));

    // init the hook structure
    hook.InGuestHookAddress = guestHookAddr;
    hook.InterruptNumber = InterruptNumber;
    hook.OldOffset = ((CX_UINT16*)(Guest->RealModeMemory + (InterruptNumber * 4)))[0];
    hook.OldSegment = ((CX_UINT16*)(Guest->RealModeMemory + (InterruptNumber * 4)))[1];
    hook.Handler = Handler;
    hook.GuestIndex = Guest->Index;

    LOG("[INT 0x%X] Hooked in guest %d to EBDA stub at 0x%08X\n", InterruptNumber, Guest->Index, guestHookAddr);
    // set the actual hook
    ((CX_UINT16*)(Guest->RealModeMemory + (InterruptNumber * 4)))[0] = (CX_UINT16)(guestHookAddr % 16);       // offset
    ((CX_UINT16*)(Guest->RealModeMemory + (InterruptNumber * 4)))[1] = (CX_UINT16)(guestHookAddr / 16);       // segment

    // IMPORTANT:
    // this might actually need 'real' synchronization if called outside of the single-processor vcpu/guest initialization code

    hookIndex = gNumberOfBiosHooks;

    gBiosHooks[hookIndex] = hook;

    if (Hook != CX_NULL) *Hook = &(gBiosHooks[hookIndex]);

    gNumberOfBiosHooks++;

    return CX_STATUS_SUCCESS;
}


CX_STATUS
HkRemoveBiosHook(
    _In_ GUEST* Guest,
    _In_ BIOS_INT_HOOK *Hook
)
{
    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Hook == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if ((Guest->RealModeMemory == CX_NULL) || (Guest->Index != 0)) return CX_STATUS_NOT_INITIALIZED;

    // set back the old handler
    ((CX_UINT16*)(Guest->RealModeMemory + (Hook->InterruptNumber * 4)))[0] = Hook->OldOffset;        // offset
    ((CX_UINT16*)(Guest->RealModeMemory + (Hook->InterruptNumber * 4)))[1] = Hook->OldSegment;       // segment

    return CX_STATUS_SUCCESS;
}



CX_STATUS
HkGetBiosHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT64 LinearInstructionAddress,
    __out_opt BIOS_INT_HOOK **Hook,
    __out_opt CX_BOOL *IsPostHook
    )
{
    if (Guest == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    for (CX_UINT32 i = 0; i < gNumberOfBiosHooks; i++)
    {
        if ((gBiosHooks[i].InGuestHookAddress == LinearInstructionAddress)&&(Guest->Index == gBiosHooks[i].GuestIndex))
        {
            if (Hook != CX_NULL) *Hook = &(gBiosHooks[i]);
            if (IsPostHook != CX_NULL) *IsPostHook = CX_FALSE;
            return CX_STATUS_SUCCESS;
        }
        // check the post-hook too
        if (
            ((CX_UINT32)((&__RealModeHookPost - &__RealModeHookPre) + gBiosHooks[i].InGuestHookAddress) == LinearInstructionAddress)&&
            (Guest->Index == gBiosHooks[i].GuestIndex)
            )
        {
            if (Hook != CX_NULL) *Hook = &(gBiosHooks[i]);
            if (IsPostHook != CX_NULL) *IsPostHook = CX_TRUE;

            return CX_STATUS_SUCCESS;
        }
    }

    return CX_STATUS_DATA_NOT_FOUND;
}

/// @}
