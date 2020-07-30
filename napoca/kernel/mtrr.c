/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "kernel/mtrr.h"
#include "memory/ept.h"
#include "debug/dumpers.h"

/// @brief Ordered list of fixed MTRRs used for lookup
/// The order here is VERY IMPORTANT and must be preserved.
/// We rely on this in GetMtrrFixedEntry() when we index the
/// MTRR_STATE::Fixed array
static DWORD msr_mtrr[MAX_FIXED_MTRR / 8] = { MSR_IA32_MTRR_FIX64K_00000,
                                                MSR_IA32_MTRR_FIX16K_80000,
                                                MSR_IA32_MTRR_FIX16K_A0000,
                                                MSR_IA32_MTRR_FIX4K_C0000,
                                                MSR_IA32_MTRR_FIX4K_C8000,
                                                MSR_IA32_MTRR_FIX4K_D0000,
                                                MSR_IA32_MTRR_FIX4K_D8000,
                                                MSR_IA32_MTRR_FIX4K_E0000,
                                                MSR_IA32_MTRR_FIX4K_E8000,
                                                MSR_IA32_MTRR_FIX4K_F0000,
                                                MSR_IA32_MTRR_FIX4K_F8000 };

static
NTSTATUS
_MtrrScanFixedRange(
    _In_ DWORD Mtrr,
    _Inout_ MTRR_STATE* MtrrState,
    _Inout_ BYTE* MtrrEntryCount
);

static
NTSTATUS
_MtrrScanVariableRange(
    _Inout_ MTRR_STATE* MtrrState
);

static
NTSTATUS
_MtrrGetFixedMtrrBaseAddressAndSize(
    _In_ DWORD Mtrr,
    _Out_ DWORD* BaseAddress,
    _Out_ DWORD* SizeInBytes
);

NTSTATUS
MtrrBuildState(
    _Inout_ MTRR_STATE* MtrrState
    )
{
    NTSTATUS status;

    // clean start
    memzero(MtrrState, sizeof(MTRR_STATE));

    // read MSR's related to MTRRs
    MtrrState->MtrrCapMsr = __readmsr(MSR_IA32_MTRRCAP);
    MtrrState->MtrrDefMsr = __readmsr(MSR_IA32_MTRR_DEF_TYPE);

    // read fixed length MTRRs if they are supported and enabled
    if (MtrrState->FixedSupport && MtrrState->FixedEnabled)
    {
        BYTE mtrrEntryCount = 0;

        for (DWORD i = 0; i < MAX_FIXED_MTRR / 8; i++)
        {
            status = _MtrrScanFixedRange(msr_mtrr[i], MtrrState, &mtrrEntryCount);
            if (!NT_SUCCESS(status)) LOG_FUNC_FAIL("_MtrrScanFixedRange", status);
        }
    }

    // read variable length MTRRs
    status = _MtrrScanVariableRange(MtrrState);
    if (!SUCCESS(status)) LOG_FUNC_FAIL("_MtrrScanVariableRange", status);

    return status;
}


/// @brief Scan fixed Mtrr ranges
///
/// Iterates through all fixed range MTRRs and retrieves information about each of them
/// filling in the MTRR_STATE::Fixed array
///
/// @param Mtrr                 MSR representing a MTRR
/// @param MtrrState            pointer to a memory area where details about the given MTRR will be stored; preallocated by the caller
/// @param MtrrEntryCount       on input it will provide the number of items in the MTRR_STATE::Fixed array; on output it will be updated with the new number of items in the same array
/// @return CX_STATUS_SUCCESS   On success
static
NTSTATUS
_MtrrScanFixedRange(
    _In_ DWORD Mtrr,
    _Inout_ MTRR_STATE* MtrrState,
    _Inout_ BYTE* MtrrEntryCount
    )
{
    NTSTATUS status;
    QWORD mtrrVal;
    DWORD baseAddr = 0, sizeInBytes = 0;

    status = _MtrrGetFixedMtrrBaseAddressAndSize(Mtrr, &baseAddr, &sizeInBytes);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("_MtrrGetFixedMtrrBaseAddressAndSize", status);
        goto cleanup;
    }

    mtrrVal = __readmsr(Mtrr);

    for (DWORD i = 0; i < 8; i++)
    {
        MtrrState->Fixed[*MtrrEntryCount].MinAddr = baseAddr + (i * sizeInBytes);
        MtrrState->Fixed[*MtrrEntryCount].MaxAddr = MtrrState->Fixed[*MtrrEntryCount].MinAddr + sizeInBytes - 1;
        MtrrState->Fixed[*MtrrEntryCount].Type = (BYTE)((mtrrVal >> (i * 8)) & 0xFF);

        (*MtrrEntryCount)++;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}

/// @brief Scan variable range of MTRRs
///
/// Iterates through all variable range MTRRs and retrieves information about each of them
/// filling in the MTRR_STATE::Var array
///
/// @param MtrrState        pointer to a memory area where details about the given MTRR will be stored; preallocated by the caller
/// @return CX_STATUS_SUCCESS   On success
static
NTSTATUS
_MtrrScanVariableRange(
    _Inout_ MTRR_STATE* MtrrState
    )
{
    QWORD rangeBaseAddress, rangeSize, rangeEndAddress;

    for (BYTE i = 0; i < MtrrState->VarCount; i++)
    {
        MtrrState->Var[i].BaseMsr = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (2*i));
        MtrrState->Var[i].MaskMsr = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (2*i));

        // scan only valid MTRRs to determine the maximum physical address
        if (MtrrState->Var[i].Valid)
        {
            rangeBaseAddress = (MtrrState->Var[i].BaseMsr & (CpuGetMaxPhysicalAddress()) ) & (VAR_MTRR_BASE_MASK);
            rangeSize = ((~((MtrrState->Var[i].MaskMsr & (CpuGetMaxPhysicalAddress()) ) & VAR_MTRR_MASK_MASK)) & CpuGetMaxPhysicalAddress()) + 1;

            // update maximum physical address if needed
            rangeEndAddress = rangeBaseAddress + rangeSize - 1;
            if ( rangeEndAddress > MtrrState->MaxAddr )
            {
                MtrrState->MaxAddr = rangeEndAddress;
            }
        }
    }

    return CX_STATUS_SUCCESS;
}

/// @brief Decodes fixed MTRR range
///
/// Determines the base address and size in bytes of a given MTRR. It must be a fixed range MTRR.
///
/// @param Mtrr                         Fixed MTRR that will be decoded
/// @param BaseAddress                  Will hold the base address of the given MTRR
/// @param SizeInBytes                  Will hold the size in bytes of the given MTRR
/// @return CX_STATUS_INVALID_PARAMETER_1   Mtrr is invalid
/// @return CX_STATUS_SUCCESS               On success
static
NTSTATUS
_MtrrGetFixedMtrrBaseAddressAndSize(
    _In_ DWORD Mtrr,
    _Out_ DWORD* BaseAddress,
    _Out_ DWORD* SizeInBytes
    )
{
    NTSTATUS status;

    status = CX_STATUS_SUCCESS;

    switch (Mtrr)
    {
    case MSR_IA32_MTRR_FIX64K_00000:
        *BaseAddress = 0x0;
        *SizeInBytes = 0x10000;
        break;
    case MSR_IA32_MTRR_FIX16K_80000:
        *BaseAddress = 0x80000;
        *SizeInBytes = 0x4000;
        break;
    case MSR_IA32_MTRR_FIX16K_A0000:
        *BaseAddress = 0xA0000;
        *SizeInBytes = 0x4000;
        break;
    case MSR_IA32_MTRR_FIX4K_C0000:
        *BaseAddress = 0xC0000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_C8000:
        *BaseAddress = 0xC8000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_D0000:
        *BaseAddress = 0xD0000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_D8000:
        *BaseAddress = 0xD8000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_E0000:
        *BaseAddress = 0xE0000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_E8000:
        *BaseAddress = 0xE8000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_F0000:
        *BaseAddress = 0xF0000;
        *SizeInBytes = 0x1000;
        break;
    case MSR_IA32_MTRR_FIX4K_F8000:
        *BaseAddress = 0xF8000;
        *SizeInBytes = 0x1000;
        break;
    default:
        *BaseAddress = 0;
        *SizeInBytes = 0;
        status = CX_STATUS_INVALID_PARAMETER_1;
    }

    return status;
}

NTSTATUS
MtrrGenerateMapFromState(
    _In_ MTRR_STATE* Mtrr
    )
{
    NTSTATUS status;
    MEM_MAP_ENTRY tempEntry = {0};
    DWORD i;

    if (!Mtrr) return CX_STATUS_INVALID_PARAMETER_1;

    // if not allocated, allocate now space for MTRR map entries
    if (!Mtrr->Map.MaxCount)
    {
        Mtrr->Map.MaxCount = (DWORD)(4 * Mtrr->VarCount + 88);      // there are 88 ranges described by fixed MTRRs

        // allocate map to heap
        status = MmapAllocMapEntries(&Mtrr->Map, Mtrr->Map.MaxCount);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmapAllocMapEntries", status);
            goto cleanup;
        }
    }

    //delete all previously calculated map entries (if any)
    Mtrr->Map.Count = 0;

    // apply all fixed MTRR entries to the map
    if (Mtrr->FixedSupport && Mtrr->FixedEnabled)   // bit 8 - FIX - fixed range MTRRs supported, conform Intel Vol 3A, 11.11.1, "MTRR Feature Identification"
    {                                               // bit 10 - RE - fixed range MTRRs are enabled, conform Intel Vol 3A, 11.11.2.1
        for (i = 0; i < MAX_FIXED_MTRR; i++)
        {
            tempEntry.Type = BOOT_MEM_TYPE_AVAILABLE;
            tempEntry.StartAddress = Mtrr->Fixed[i].MinAddr;
            tempEntry.CacheAndRights = (Mtrr->Fixed[i].Type & 0x7) << 3;    // bits 5:3;
            tempEntry.DestAddress = 0;                                      // not used
            tempEntry.Length = (Mtrr->Fixed[i].MaxAddr - Mtrr->Fixed[i].MinAddr + 1);

            status = MmapApplyNewEntry(&Mtrr->Map, &tempEntry, MMAP_SPLIT_AND_KEEP_LESS_CACHED);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmapApplyNewEntry / fixed-MTRR-entry", status);
                goto cleanup;
            }
        }
    }

    // apply a HUGE block with default MTRR memory caching for everything over 1MB
    {
        // IMPORTANT: we DO assume that MaxAddr is already correctly calculated (and updated on MTRR writes)
        tempEntry.Type = BOOT_MEM_TYPE_AVAILABLE;
        tempEntry.CacheAndRights = EPT_RAW_CACHING_DEFAULT;
        tempEntry.DestAddress = 0;                      // not used

        if (Mtrr->FixedEnabled && Mtrr->FixedSupport)
        {
            // first 1 MB already explicitly mapped
            tempEntry.Length = Mtrr->MaxAddr - ONE_MEGABYTE + 1;
            tempEntry.StartAddress = ONE_MEGABYTE;
        }
        else
        {
            tempEntry.Length = Mtrr->MaxAddr + 1;
            tempEntry.StartAddress = 0;
        }

        status = MmapApplyNewEntry(&Mtrr->Map, &tempEntry, MMAP_SPLIT_AND_KEEP_LESS_CACHED);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmapApplyNewEntry / default-MTRR-cache-HUGE-entry", status);
            goto cleanup;
        }
    }

    // apply all variable MTRR entries to the map
    if (Mtrr->Enabled && (Mtrr->VarCount > 0))
    {
        for (i = 0; i < Mtrr->VarCount; i++)
        {
            QWORD base, mask;
            QWORD first, last, size;
            BYTE cache;

            if (!Mtrr->Var[i].Valid) continue;

            base = Mtrr->Var[i].BaseMsr;
            mask = Mtrr->Var[i].MaskMsr;
            cache = (BYTE)(base & 0x07);

            first = (base & 0xfffffffffffff000ULL) & CpuGetMaxPhysicalAddress();
            size = ((~(mask & 0xfffffffffffff000ULL)) & CpuGetMaxPhysicalAddress()) + 1;
            last = first + size - 1;

            tempEntry.Type = BOOT_MEM_TYPE_AVAILABLE;
            tempEntry.StartAddress = first;
            tempEntry.CacheAndRights = ((cache) << 3);      // bits 5:3
            tempEntry.DestAddress = 0;                      // not used
            tempEntry.Length = size;

            status = MmapApplyNewEntry(&Mtrr->Map, &tempEntry, MMAP_SPLIT_AND_KEEP_LESS_CACHED);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("MmapApplyNewEntry / variable-MTRR-entry", status);
                goto cleanup;
            }
        }
    }

    // replace all DEFAULT cache zones with correct values
    {
        WORD def;

        def = (WORD)((Mtrr->DefType & 0x07) << 3);

        for (i = 0; i < Mtrr->Map.Count; i++)
        {
            if (EPT_RAW_CACHING_DEFAULT == (Mtrr->Map.Entry[i].CacheAndRights & EPT_RAW_CACHING_MASK))
            {
                Mtrr->Map.Entry[i].CacheAndRights = (Mtrr->Map.Entry[i].CacheAndRights & 0xFFC7) | def;
            }
        }
    }

    // zero down DEST addresses
    for (i = 0; i < Mtrr->Map.Count; i++)
    {
        Mtrr->Map.Entry[i].DestAddress = 0;
    }

    // NOTE: we might wish to try to compact MTRR based memory map, but it is not strictly required

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:
    return status;
}


MTRR_FIX_ENTRY*
MtrrGetFixedRangeEntryAndIndex(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Mtrr,
    __out_opt DWORD* FixedEntryIndex
    )
{
    MTRR_FIX_ENTRY* fixEntry;
    DWORD index;

    // validate parameters
    if (!MtrrState) return NULL;

    // init vars
    fixEntry = NULL;
    index = MAX_FIXED_MTRR;

    // determine which MTRR MSR is this
    if (Mtrr == MSR_IA32_MTRR_FIX64K_00000)
    {
        index = 0;
    }
    else if ( (Mtrr == MSR_IA32_MTRR_FIX16K_A0000) || (Mtrr == MSR_IA32_MTRR_FIX16K_80000) )
    {
        index = 8 * ((DWORD)Mtrr - MSR_IA32_MTRR_FIX16K_80000 + 1);
    }
    else if ( (Mtrr >= MSR_IA32_MTRR_FIX4K_C0000) && (Mtrr <= MSR_IA32_MTRR_FIX4K_F8000) )
    {
        index = 8 * ((DWORD)Mtrr - MSR_IA32_MTRR_FIX4K_C0000 + 3);
    }

    // if we have a valid index the prepare to return them
    if (index < MAX_FIXED_MTRR)
    {
        fixEntry = &MtrrState->Fixed[index];

        // return index if requested
        if (FixedEntryIndex) *FixedEntryIndex = index;
    }

    return fixEntry;
}


MTRR_VAR_ENTRY*
MtrrGetVarRangeEntryAndIndex(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Mtrr,
    __out_opt DWORD* VarEntryIndex
    )
{
    DWORD idx;
    MTRR_VAR_ENTRY* varEntry;

    if (!MtrrState) return NULL;

    varEntry = NULL;

    // determine entry index
    idx = ((DWORD)Mtrr - MSR_IA32_MTRR_PHYSBASE0) / 2;

    // if this is a valid index
    if (idx < MtrrState->VarCount)
    {
        varEntry = &MtrrState->Var[idx];

        // return index if requested
        if (VarEntryIndex) *VarEntryIndex = idx;
    }

    return varEntry;
}


NTSTATUS
MtrrGetFixedRangeValue(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Msr,
    _Out_ QWORD* Value
    )
{
    NTSTATUS status;
    MTRR_FIX_ENTRY* fixEntry;
    DWORD i, index = 0;

    if (!MtrrState) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_3;

    // check to see if fixed MTRRs are supported and enabled
    if (!MtrrState->FixedSupport)
    {
        ERROR("Fixed range MTRRs not supported or not enabled! Supported: %d, Enabled: %d\n", MtrrState->FixedSupport, MtrrState->FixedEnabled);
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    status = CX_STATUS_SUCCESS;
    *Value = 0;

    // get first fixed entry and its index
    fixEntry = MtrrGetFixedRangeEntryAndIndex(MtrrState, Msr, &index);
    if (fixEntry)
    {
        // get next 8 entries and compute the MSR value
        for (i = 0; i < 8; i++)
        {
            *Value |= (MtrrState->Fixed[index + i].Type << (8 * i));
        }
    }
    else
    {
        status = CX_STATUS_DATA_NOT_FOUND;
        ERROR("Fixed MTRR entry for MSR 0x%x, %s not found!\n", Msr, ConvertMsrToString(Msr));
    }

    return status;
}


NTSTATUS
MtrrGetVarRangeValue(
    _In_ MTRR_STATE* MtrrState,
    _In_ QWORD Msr,
    _Out_ QWORD* Value
    )
{
    NTSTATUS status;
    MTRR_VAR_ENTRY* varEntry;
    DWORD index = 0;

    if (!MtrrState) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_3;

    // check if we have variable length MTRRs
    if (!MtrrState->VarCount)
    {
        ERROR("Variable length MTRRs count is: %d!\n", MtrrState->VarCount);
        return CX_STATUS_DATA_NOT_FOUND;
    }

    status = CX_STATUS_SUCCESS;

    // get var entry and its index
    varEntry = MtrrGetVarRangeEntryAndIndex(MtrrState, Msr, &index);
    if (varEntry)
    {
        // is this a mask MSR
        if ( (Msr - MSR_IA32_MTRR_PHYSBASE0 - (2 * index)) != 0 )
        {
            *Value = varEntry->MaskMsr;
        }
        else
        {
            *Value = varEntry->BaseMsr;
        }
    }
    else
    {
        ERROR("Variable MTRR entry for MSR 0x%x, %s not found!\n", Msr, ConvertMsrToString(Msr));
        status = CX_STATUS_DATA_NOT_FOUND;
    }

    return status;
}

/// @brief Updates maximum physical address covered by MTRR
///
/// Updates the maximum physical memory address that is covered by the given MTRR state.
///
/// @param MtrrState                      pointer to a memory area where details about the given MTRR will be stored; preallocated by the caller
/// @param OldMaxPhysicalAddress          location where to store the old value of the maximum physical memory address covered by the given MTRR state
/// @return CX_STATUS_INVALID_PARAMETER_1           Mtrr is NULL
/// @return CX_STATUS_INVALID_PARAMETER_3           Value is NULL
/// @return CX_STATUS_SUCCESS               On success
NTSTATUS
MtrrUpdateMaxPhysicalAddressInState(
    _Inout_ MTRR_STATE* MtrrState,
    _Out_ QWORD* OldMaxPhysicalAddress
    )
{
    NTSTATUS status;
    QWORD rangeBaseAddress, rangeSize, physicalAddressMask, rangeEndAddress;

    if (!MtrrState) return CX_STATUS_INVALID_PARAMETER_1;
    if (!OldMaxPhysicalAddress) return CX_STATUS_INVALID_PARAMETER_2;

    status = CX_STATUS_SUCCESS;

    // compute the physical memory address mask supported by this CPU
    physicalAddressMask = CpuGetMaxPhysicalAddress();

    // save the old max physical address
    *OldMaxPhysicalAddress = MtrrState->MaxAddr;

    rangeEndAddress = 0;

    // loop through all MTRRs
    for (BYTE i = 0; i < MtrrState->VarCount; i++)
    {
        // scan only valid MTRRs to determine the maximum physical address
        if (MtrrState->Var[i].Valid)
        {
            rangeBaseAddress = (MtrrState->Var[i].BaseMsr & (physicalAddressMask) ) & (VAR_MTRR_BASE_MASK);
            rangeSize = ((~((MtrrState->Var[i].MaskMsr & (physicalAddressMask) ) & VAR_MTRR_MASK_MASK)) & physicalAddressMask ) + 1;

            // update maximum physical address if needed
            rangeEndAddress = rangeBaseAddress + rangeSize - 1;
            if ( rangeEndAddress > MtrrState->MaxAddr )
            {
                MtrrState->MaxAddr = rangeEndAddress;
            }
        }
    }

    return status;
}
