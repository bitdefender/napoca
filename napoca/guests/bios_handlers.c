/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup hooks
/// @{
#include "napoca.h"
#include "kernel/kernel.h"
#include "memory/cachemap.h"
#include "guests/guests.h"
#include "guests/hooks.h"
#include "guests/bios_handlers.h"

#pragma pack(push)
#pragma pack(1)
/// @brief Collects the data reported by the INT15(AX=0xE820)
typedef struct _E820_MEM_MAP_ENTRY
{
    CX_UINT64           BaseAddress; ///< Base address of a memory range
    CX_UINT64           Length;      ///< Length of a memory range
    CX_UINT32           Type;        ///< Type of the memory range
}E820_MEM_MAP_ENTRY;
#pragma pack(pop)

CX_STATUS
BhInt0x10(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    )
{
    CX_STATUS status;

    if (Hook == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if (IsPostHook) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    VCPULOG(Vcpu, "Will do an INT 10h, AH = 0h VIDEO mode change to mode %d\n ***IMPORTANT*** will disable video tracing\n",
        (CX_UINT8)Vcpu->ArchRegs.RAX);

    gVideoVgaInited = CX_FALSE;
    status = HkRemoveBiosHook(Vcpu->Guest, Hook);
    if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("HkRemoveBiosHook", status);
    VCPULOG(Vcpu, "INT 0x10 HOOK REMOVED!\n");

    return STATUS_EXECUTE_ORIGINAL_HANDLER;
}


CX_STATUS
BhInt0x15(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    )
{
    CX_STATUS status;
    ARCH_REGS *regs;
    CX_UINT64 adr;
    MMAP *map;
    CX_UINT32 i, startIndex;
    CX_UINT64 lastEndAddr;
    CX_UINT32 type;
    E820_MEM_MAP_ENTRY entry;

    if (Hook == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if (Vcpu->Guest == CX_NULL) return CX_STATUS_INVALID_INTERNAL_STATE;
    if (IsPostHook) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    regs = &(Vcpu->ArchRegs);
    map = &(Vcpu->Guest->PhysMap);

    // let all requests other then 0xe820 be handled by the original BIOS interrupt handler
    if (regs->EAX != 0xe820) return STATUS_EXECUTE_ORIGINAL_HANDLER;

    if (
        (regs->ECX < 20)
        || (regs->EDX != 0x534D4150 /*SMAP*/)
        || (regs->EBX >= map->Count)
        )
    {
        // error, set the carry flag and exit
        regs->EAX = 0x534D4150; /*SMAP*/
        regs->RFLAGS |= RFLAGS_CF;
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }

    // set our signature
    regs->EAX = 0x534D4150; /*SMAP*/

    startIndex = regs->EBX;
    type = map->Entry[startIndex].Type;
    lastEndAddr = map->Entry[startIndex].StartAddress + map->Entry[startIndex].Length;
    for (i = startIndex; i < map->Count; i++)
    {
        // check continuity if not at the first entry
        if (i > startIndex)
        {
            // same type?
            if (type != (CX_UINT32)map->Entry[i].Type) break;
            // continuous address?
            if (lastEndAddr != map->Entry[i].StartAddress) break;
        }

        lastEndAddr = map->Entry[i].StartAddress + map->Entry[i].Length;
    }

    entry.Type = LdConvertHvMemTypeToE820MemType(map->Entry[startIndex].Type);
    entry.BaseAddress = map->Entry[startIndex].StartAddress;
    entry.Length = lastEndAddr - entry.BaseAddress;

    // if last entry
    if (i == map->Count) regs->EBX = 0;
    // intermediate entry
    else regs->EBX = i;

    // find out where to save the data
    if (0 != vmx_vmread(VMCS_GUEST_ES, &adr))
    {
        status = CX_STATUS_INVALID_INTERNAL_STATE;
        goto cleanup;
    }

    adr = (adr & 0xFFFF) * 16 + (regs->EDI & 0xFFFF);
    // save data
    memcpy(Vcpu->Guest->RealModeMemory + adr, &entry, CX_MIN(regs->ECX, sizeof(E820_MEM_MAP_ENTRY)));

    // signal the success of the operation
    regs->RFLAGS &= ~((CX_UINT64)RFLAGS_CF);
    regs->ECX = CX_MIN(regs->ECX, sizeof(E820_MEM_MAP_ENTRY));

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}


CX_STATUS
BhIntTraceOnly(
    _In_ BIOS_INT_HOOK *Hook,
    _In_ VCPU* Vcpu,
    _In_ CX_BOOL IsPostHook
    )
{
    if (Vcpu == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;

    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(IsPostHook);

    VCPULOG(Vcpu, "BIOS Interrupt[0x%X] was called\n");
    return STATUS_EXECUTE_ORIGINAL_HANDLER;
}

/// @}