/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup cachemap
/// @ingroup memory
/// @{
#include "napoca.h"
#include "kernel/kernel.h"
#include "guests/guests.h"
#include "memory/cachemap.h"

#define CHMWARNING

#define PML4_P          BIT(0)
#define PML4_RW         BIT(1)
#define PML4_US         BIT(2)
#define PML4_PWT        BIT(3)
#define PML4_PCD        BIT(4)
#define PML4_A          BIT(5)
#define PML4_LNK        BIT(9)
#define PML4_CHAINED    BIT(10)
#define PML4_RESERVED   BIT(11)

#define PDP_P           BIT(0)
#define PDP_RW          BIT(1)
#define PDP_US          BIT(2)
#define PDP_PWT         BIT(3)
#define PDP_PCD         BIT(4)
#define PDP_A           BIT(5)
#define PDP_D           BIT(6)
#define PDP_PS          BIT(7)
#define PDP_LNK         BIT(9)
#define PDP_CHAINED     BIT(10)
#define PDP_RESERVED    BIT(11)

#define PD_P            BIT(0)
#define PD_RW           BIT(1)
#define PD_US           BIT(2)
#define PD_PWT          BIT(3)
#define PD_PCD          BIT(4)
#define PD_A            BIT(5)
#define PD_D            BIT(6)
#define PD_PS           BIT(7)
#define PD_G            BIT(8)
#define PD_LNK          BIT(9)
#define PD_CHAINED      BIT(10)
#define PD_RESERVED     BIT(11)

#define PT_P            BIT(0)
#define PT_RW           BIT(1)
#define PT_US           BIT(2)
#define PT_PWT          BIT(3)
#define PT_PCD          BIT(4)
#define PT_A            BIT(5)
#define PT_D            BIT(6)
#define PT_PS           BIT(7)
#define PT_G            BIT(8)
#define PT_LNK          BIT(9)
#define PT_CHAINED      BIT(10)
#define PT_RESERVED     BIT(11)
#define PT_XD           BIT(63)


static
NTSTATUS
_ChmCacheLocate(
    _In_        CHM_CACHE       *Cache,
    _In_        QWORD           SrcAddress,
    _Out_       CHM_CACHE_ENTRY **Result,
    __out_opt   DWORD           *PriorityIndex
);

static
NTSTATUS
_ChmCacheAdd(
    _In_    CHM_CACHE           *Cache,
    _In_    QWORD               SrcAddress,
    _In_    QWORD               DstAddress,
    _Out_   CHM_CACHE_ENTRY     **Result
);

static
__forceinline
NTSTATUS
_ChmGvaToGpaAndHpaEx(
    _In_        VCPU            *Vcpu,
    _In_        QWORD           Gva,
    __out_opt   QWORD           *Gpa,
    _Out_       QWORD           *Hpa,
    __out_opt   PVOID           *PtEntryHva
);


NTSTATUS
ChmGetPhysicalPageTypeFromMtrrs(
    _In_ GUEST* Guest,
    _In_ QWORD Gpa,
    _Out_ PBYTE MemType
    )
{
    NTSTATUS status;
    DWORD i;
    WORD car;
    BOOLEAN found;

    if (Guest == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (MemType == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    found = FALSE;
    car = IG_MEM_UNKNOWN;
    status = CX_STATUS_SUCCESS;

    //
    // 1. Intel 11.11.4.1: If the physical address falls within the first 1 MByte of physical memory and
    // fixed MTRRs are enabled, the processor uses the memory type stored for the appropriate fixed-range MTRR
    //
    if (Gpa < 0x100000)
    {
        DWORD maxFixed;

        //
        // This values are fixed, 8 ranges per register (Intel 11.11.2.2)
        //
        if (Gpa < 0x80000)
        {
            i = 0;
        }
        else if (Gpa < 0xA0000)
        {
            i = 8;
        }
        else if (Gpa < 0xC0000)
        {
            i = 16;
        }
        else if (Gpa < 0xC8000)
        {
            i = 24;
        }
        else if (Gpa < 0xD0000)
        {
            i = 32;
        }
        else if (Gpa < 0xD8000)
        {
            i = 40;
        }
        else if (Gpa < 0xE0000)
        {
            i = 48;
        }
        else if (Gpa < 0xE8000)
        {
            i = 56;
        }
        else if (Gpa < 0xF0000)
        {
            i = 64;
        }
        else if (Gpa < 0xF8000)
        {
            i = 72;
        }
        else
        {
            i = 80;
        }

        maxFixed = i + 8;
        for (; i < maxFixed; i++)
        {
            if (Gpa >= Guest->Mtrr->Fixed[i].MinAddr &&
                Gpa < Guest->Mtrr->Fixed[i].MaxAddr)
            {
                found = TRUE;
                car = (WORD)Guest->Mtrr->Fixed[i].Type;
                goto done;
            }
        }
    }

    //
    // 2. Intel 11.11.4.1: Otherwise, the processor attempts to match the physical address with a memory type
    // set by the variable-range MTRRs
    //
    for (i = 0; i < Guest->Mtrr->VarCount; i++)
    {
        QWORD rangeBaseAddress, rangeSize;

        if (0 == Guest->Mtrr->Var[i].Valid)
        {
            // Invalid MTRR, skip it.
            continue;
        }

        rangeBaseAddress = (Guest->Mtrr->Var[i].BaseMsr & CpuGetMaxPhysicalAddress()) & (VAR_MTRR_BASE_MASK);
        rangeSize = ((~((Guest->Mtrr->Var[i].MaskMsr & CpuGetMaxPhysicalAddress()) & VAR_MTRR_MASK_MASK)) & CpuGetMaxPhysicalAddress()) + 1;

        if (Gpa >= rangeBaseAddress && Gpa < rangeBaseAddress + rangeSize)
        {
            // found it, get caching rights
            found = TRUE;

            if (car == IG_MEM_UNKNOWN)
            {
                // It's the first one found
                car = (WORD)Guest->Mtrr->Var[i].Type;
            }
            else if (car == (WORD)Guest->Mtrr->Var[i].Type)
            {
                // Intel 11.11.4.1: If two or more variable memory ranges match and the memory types
                // are identical, then that memory type is used
                continue;
            }
            else if ((WORD)Guest->Mtrr->Var[i].Type == IG_MEM_UC)
            {
                // Intel 11.11.4.1: If two or more variable memory ranges match and one of the
                // memory types is UC, the UC memory type used.
                car = IG_MEM_UC;
            }
            else if ((WORD)Guest->Mtrr->Var[i].Type == IG_MEM_WT && car == IG_MEM_WB) // we don't care if it's already WT
            {
                // Intel 11.11.4.1: If two or more variable memory ranges match and the memory types
                // are WT and WB, the WT memory type is used
                car = IG_MEM_WT;
            }
            else
            {
                // Intel 11.11.4.1: For overlaps not defined by the above rules, processor behavior is undefined.
                /// TODO: return CX_STATUS_OPERATION_NOT_SUPPORTED ?
                car = (WORD)Guest->Mtrr->Var[i].Type;
            }
        }
    }

    if (found) goto done;

    //
    // 3. Intel 11.11.4.1: If no fixed or variable memory range matches, the processor uses the default memory type
    //
    car = (WORD)Guest->Mtrr->DefType;
    found = TRUE;

done:
    if (found)
    {
        if (car >= IG_MEM_UC_MINUS) return STATUS_INVALID_MEMORY_TYPE;

        status = CX_STATUS_SUCCESS;
        *MemType = (BYTE)car;
    }
    else
    {
        status = CX_STATUS_DATA_NOT_FOUND;
    }

    return status;
}


NTSTATUS
ChmInvalidateVACache(
    _In_    VCPU            *Vcpu
    )
{
    if (NULL == Vcpu) return CX_STATUS_INVALID_PARAMETER_1;

    Vcpu->CachedTranslations.NumberOfUsedEntries = 0;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
ChmMapGpaRange(
    _In_ VCPU* Vcpu,
    _In_ QWORD GuestPhysAddress,
    _In_ QWORD NumberOfBytesToMap,
    _In_ CHM_FLAGS Options,
    _Out_ PVOID *HostVa,
    _In_opt_ VOID *TargetReservedHostVa,
    _In_ DWORD Tag
    )
{

    NTSTATUS status;

    if (NULL == Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!NumberOfBytesToMap) return CX_STATUS_INVALID_PARAMETER_3;
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_5;

    Options &= ~((DWORD)CHM_FLAG_AUTO_ALIGN);

    status = ChmMapContinuousGuestGpaPagesToHost(
        Vcpu->Guest,
        PAGE_BASE_PA(GuestPhysAddress),
        PAGE_COUNT(GuestPhysAddress, NumberOfBytesToMap),
        Options,
        HostVa,
        TargetReservedHostVa,
        Tag);

    if (SUCCESS(status)) *HostVa = (PVOID) ((PBYTE)(*HostVa) + PAGE_OFFSET(GuestPhysAddress));

    return status;
}


NTSTATUS
ChmUnmapGpaRange(
    _In_ PVOID *HostVa,
    _In_ DWORD Tag
    )
{
    return ChmUnmapContinuousGuestGpaPagesFromHost(HostVa, Tag);
}

/// @brief Context for #_ChmMapGpaGetHpaCallback that is used to translate a guest physical address to a host physical address
typedef struct
{
    GUEST *Guest;           ///< The guest for which translation will be performed
    CHM_FLAGS Options;      ///< Options that control behavior and triggers validations
}CHM_MAP_GPA_GET_HPA_CONTEXT;

/// @brief This function fills-in a PA for a GPA such that the MmMap function can be used over a GPA space (via #ChmMapContinuousGuestGpaPagesToHost)
///
/// @param Context          custom callback data passed-through to the callback at each iteration step
/// @param AlienAddress     the current address (in some custom/alien address-space) to process for which we need the physical address
/// @param PageIndex        Not used
/// @param Pa               Translated physical address
/// @return CX_STATUS_SUCCESS       On success
/// @return CX_STATUS_XXX           For internal errors
static
NTSTATUS
_ChmMapGpaGetHpaCallback(
    _In_ CX_VOID *Context,
    _In_ CX_UINT64 AlienAddress,
    _In_ MM_PAGE_COUNT PageIndex,
    _Out_ MM_ALIGNED_PA *Pa
)
{
    UNREFERENCED_PARAMETER(PageIndex);
    CHM_MAP_GPA_GET_HPA_CONTEXT *ctx = (CHM_MAP_GPA_GET_HPA_CONTEXT*) Context;
    QWORD hPa = (QWORD)-1;

    // get current translation and check constraints
    CX_STATUS status = ChmGpaToHpa(ctx->Guest, AlienAddress, &hPa);
    if (!SUCCESS(status))
    {
        if (!(CHM_FLAG_ACCEPT_EPT_GAPS & ctx->Options))
        {
            CHMWARNING("_ChmGpaToHpa failed, status=%s\n", NtStatusToString(status));
            goto cleanup;
        }
    }

    if (ctx->Options & CHM_FLAG_MAP_ONLY_WB_MEM)
    {
        BYTE memType;
        status = ChmGetPhysicalPageTypeFromMtrrs(ctx->Guest, AlienAddress, &memType);
        if (!SUCCESS(status))
        {
            WARNING("Failed to get the memory type from MTRRs for GPA = %p, status = %s\n",
                AlienAddress, NtStatusToString(status));
            if (!(ctx->Options & CHM_FLAG_ACCEPT_EPT_GAPS))
            {
                goto cleanup;
            }
        }
        else if (memType != IG_MEM_WB)
        {
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
            goto cleanup;
        }
    }

    *Pa = hPa;

cleanup:
    return status;
}


NTSTATUS
ChmMapContinuousGuestGpaPagesToHost(
    _In_ GUEST* Guest,
    _In_ QWORD GuestPhysAddress,
    _In_ DWORD PageCount,
    _In_ CHM_FLAGS Options,
    _Out_ PVOID *HostVa,
    _In_opt_ VOID *TargetReservedHostVa,
    _In_ DWORD Tag
)
{
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_5;
    if (!Guest) return CX_STATUS_INVALID_PARAMETER_1;
    if (!PageCount) return CX_STATUS_INVALID_PARAMETER_3;

    *HostVa = NULL;

    WORD pageOffset = PAGE_OFFSET(GuestPhysAddress);
    if ((CHM_FLAG_AUTO_ALIGN == (Options & CHM_FLAG_AUTO_ALIGN)) && (0 != pageOffset))
    {
        GuestPhysAddress = PAGE_BASE_PA(GuestPhysAddress);
        PageCount++;
    }

    CHM_MAP_GPA_GET_HPA_CONTEXT ctx = { 0 };
    ctx.Guest = Guest;
    ctx.Options = Options;
    CX_STATUS status = MmMap(&gHvMm, TargetReservedHostVa, 0, NULL, _ChmMapGpaGetHpaCallback, GuestPhysAddress, &ctx, PAGE_SIZE * PageCount, Tag, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, HostVa, NULL);
    if (!SUCCESS(status)) goto cleanup;

    if (CHM_FLAG_AUTO_ALIGN == (Options & CHM_FLAG_AUTO_ALIGN)) *HostVa = (PVOID)((QWORD)(*HostVa)+pageOffset);

cleanup:
    return status;
}



NTSTATUS
ChmUnmapContinuousGuestGpaPagesFromHost(
    _Inout_ PVOID *HostVa,
    _In_    DWORD   Tag
    )
{
    return MmUnmapMem(&gHvMm, TRUE, Tag, HostVa);
}


NTSTATUS
ChmMapGvaRange(
    _In_ VCPU* Vcpu,
    _In_ QWORD GuestVirtAddress,
    _In_ QWORD NumberOfBytesToMap,
    _In_ CHM_FLAGS Options,
    _Out_ PVOID *HostVa,
    _In_opt_ VOID *TargetReservedHostVa,
    _In_ DWORD Tag
    )
{
    NTSTATUS status;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!NumberOfBytesToMap) return CX_STATUS_INVALID_PARAMETER_3;
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_5;

    Options &= ~((DWORD)CHM_FLAG_AUTO_ALIGN);

    status = ChmMapGuestGvaPagesToHost(Vcpu, PAGE_BASE_VA(GuestVirtAddress), PAGE_COUNT(GuestVirtAddress, NumberOfBytesToMap), Options, HostVa, TargetReservedHostVa, Tag);
    if (SUCCESS(status)) *HostVa = (PVOID) ((PBYTE)(*HostVa) + PAGE_OFFSET(GuestVirtAddress));

    return status;
}



NTSTATUS
ChmUnmapGvaRange(
    _In_ PVOID *HostVa,
    _In_ DWORD Tag
    )
{
    return ChmUnmapGuestGvaPages(HostVa, Tag);
}


/// @brief Context for #_ChmMapGvaGetHpaCallback that is used to translate a guest virtual address to a host physical address
typedef struct
{
    VCPU *Vcpu;         ///< The Vcpu for which translation will be performed
    CHM_FLAGS Options;  ///< Options that control behavior and triggers validations
}CHM_MAP_GVA_GET_HPA_CONTEXT;


/// @brief  This function fills-in a host physical address for a guest physical address such that the #MmMap function can be used over a GPA space (via #ChmMapContinuousGuestGpaPagesToHost)
///
/// @param Context          custom callback data passed-through to the callback at each iteration step
/// @param AlienAddress     This is the current address (in some custom/alien address-space) to process for which we need the PA
/// @param PageIndex        Not used
/// @param Pa               translated physical address
/// @return CX_STATUS_SUCCESS   On success
/// @return CX_STATUS_XXX           For internal errors
static
NTSTATUS
_ChmMapGvaGetHpaCallback(
    _In_ CX_VOID *Context,
    _In_ CX_UINT64 AlienAddress,
    _In_ MM_PAGE_COUNT PageIndex,
    _Out_ MM_ALIGNED_PA *Pa
)
//
{
    UNREFERENCED_PARAMETER(PageIndex);
    CHM_MAP_GVA_GET_HPA_CONTEXT *ctx = (CHM_MAP_GVA_GET_HPA_CONTEXT*)Context;
    QWORD hPa;
    CX_STATUS status;
    QWORD currentGpa;

    // get current translation
    if (ctx->Options & CHM_FLAG_MAP_ONLY_WB_MEM)
    {
        status = ChmGvaToGpaAndHpa(ctx->Vcpu, AlienAddress, &currentGpa, &hPa);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmGvaToHpa failed for GVA = %p, status=%s\n", AlienAddress, NtStatusToString(status));
            if (!(ctx->Options & CHM_FLAG_ACCEPT_EPT_GAPS)) goto cleanup;
        }

        BYTE memType = 0;

        // get the memory type for the current gpa
        status = ChmGetPhysicalPageTypeFromMtrrs(ctx->Vcpu->Guest, currentGpa, &memType);
        if (!SUCCESS(status))
        {
            WARNING("Failed to get the memory type from MTRRs for GVA = %p, GPA = %p, status = %s\n",
                AlienAddress, currentGpa, NtStatusToString(status));
            if (!(ctx->Options & CHM_FLAG_ACCEPT_EPT_GAPS)) goto cleanup;
        }
        else if (memType != IG_MEM_WB)
        {
            status = CX_STATUS_OPERATION_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    else
    {
        status = ChmGvaToGpaAndHpa(ctx->Vcpu, AlienAddress, NULL, &hPa);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmGvaToHpa failed for GVA = %p, status=%s\n", AlienAddress, NtStatusToString(status));
            if (!(ctx->Options & CHM_FLAG_ACCEPT_EPT_GAPS)) goto cleanup;
        }
    }

    *Pa = hPa;

cleanup:
    return status;
}


NTSTATUS
ChmMapGuestGvaPagesToHost(
    _In_ VCPU* Vcpu,
    _In_ QWORD GuestVirtAddress,
    _In_ DWORD PageCount,
    _In_ CHM_FLAGS Options,
    _Out_ PVOID *HostVa,
    _In_opt_ VOID *TargetReservedHostVa,
    _In_ DWORD Tag
)
{
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_5;
    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!PageCount) return CX_STATUS_INVALID_PARAMETER_3;

    *HostVa = NULL;

    WORD pageOffset = PAGE_OFFSET(GuestVirtAddress);

    if (((Options & CHM_FLAG_AUTO_ALIGN) == CHM_FLAG_AUTO_ALIGN) && (pageOffset))
    {
        GuestVirtAddress = PAGE_BASE_VA(GuestVirtAddress);
        PageCount++;
    }

    CHM_MAP_GVA_GET_HPA_CONTEXT ctx = { 0 };
    ctx.Vcpu = Vcpu;
    ctx.Options = Options;

    NTSTATUS status = MmMap(&gHvMm, TargetReservedHostVa, 0, NULL, _ChmMapGvaGetHpaCallback, GuestVirtAddress, &ctx, PAGE_SIZE * PageCount, Tag, MM_RIGHTS_RW, MM_CACHING_WB, MM_GUARD_NONE, MM_GLUE_NONE, HostVa, NULL);
    if (!NT_SUCCESS(status))
    {
        WARNING("MmMap failed in ChmMapGuestGvaPagesToHost with status=%s for GVA=%p, pages=%d, Options=%x\n", NtStatusToString(status), GuestVirtAddress, PageCount, Options);
        goto cleanup;
    }

    if ((Options & CHM_FLAG_AUTO_ALIGN) == CHM_FLAG_AUTO_ALIGN) *HostVa = (PVOID)((QWORD)*HostVa + pageOffset);

cleanup:
    return status;
}


NTSTATUS
ChmUnmapGuestGvaPages(
    _Inout_ PVOID *HostVa,
    _In_ DWORD Tag
    )
{
    return MmUnmapMem(&gHvMm, TRUE, Tag, HostVa);
}


/// @brief Tries to locate a cached translation
/// @param Cache            The cache in which to look
/// @param SrcAddress       Address to look for
/// @param Result           Found cache entry or NULL if not found
/// @param PriorityIndex    Priority index / Hit count
/// @return CX_STATUS_DATA_NOT_FOUND        If address is not found in cache
/// @return CX_STATUS_SUCCESS               If address is found in cache
static
NTSTATUS
_ChmCacheLocate(
    _In_        CHM_CACHE       *Cache,
    _In_        QWORD          SrcAddress,
    _Out_       CHM_CACHE_ENTRY **Result,
    __out_opt   DWORD           *PriorityIndex
    )

//
{
    DWORD i;
    WORD pageOffset;

    pageOffset = SrcAddress & PAGE_OFFSET_MASK;
    SrcAddress &= PAGE_MASK;

    if (PriorityIndex) *PriorityIndex = 0xFFFFFFFF;

    *Result = NULL;

    for (i = 0; i < Cache->NumberOfUsedEntries; i++)
    {
        if (Cache->Entries[i].SrcAddress == SrcAddress)
        {
            // update hitcount
            if (Cache->Entries[i].Priority < 0xFFFFFFFF) Cache->Entries[i].Priority++;

            // find out its priority index
            if (PriorityIndex)
            {
                DWORD j;
                *PriorityIndex = 0;
                for (j = 0; j < Cache->NumberOfUsedEntries; j++)
                {
                    if (Cache->Entries[j].Priority > Cache->Entries[i].Priority) (*PriorityIndex)++;
                }
            }

            *Result = &(Cache->Entries[i]) + pageOffset;
            return CX_STATUS_SUCCESS;
        }
    }
    return CX_STATUS_DATA_NOT_FOUND;
}

/// @brief Add an address to cache
/// @param Cache        The cache to add to
/// @param SrcAddress   The address to be cached
/// @param DstAddress   The associated address
/// @param Result       The cache entry where the data was cached
/// @return CX_STATUS_INVALID_PARAMETER_3   If addresses have different offsets
/// @return CX_STATUS_SUCCESS               On success
static
NTSTATUS
_ChmCacheAdd(
    _In_    CHM_CACHE       *Cache,
    _In_    QWORD          SrcAddress,
    _In_    QWORD          DstAddress,
    _Out_   CHM_CACHE_ENTRY **Result
    )
{
    DWORD position = 0;
    BOOLEAN replaceNeeded;
    WORD pageOffset;

    pageOffset = SrcAddress & PAGE_OFFSET_MASK;
    if (pageOffset != (DstAddress & PAGE_OFFSET_MASK)) return CX_STATUS_INVALID_PARAMETER_3;

    SrcAddress &= PAGE_MASK;
    DstAddress &= PAGE_MASK;

    *Result = NULL;

    //
    // first case: there's room for the new entry
    //
    if (Cache->NumberOfUsedEntries < Cache->NumberOfEntries)
    {
        position = Cache->NumberOfUsedEntries;
        Cache->NumberOfUsedEntries++;
        replaceNeeded = FALSE;
    }
    else
    {
        replaceNeeded = TRUE;
    }
    //
    // update the cache 'freshness' and select an existing element to replace if needed
    //
    {
        DWORD minPriority = (DWORD) -1;
        for (DWORD i = 0; i < Cache->NumberOfEntries; i++)
        {
            // replacement element selection
            if ((replaceNeeded) && (Cache->Entries[i].Priority < minPriority))
            {
                position = i;
                minPriority = Cache->Entries[i].Priority;
            }

            // update the freshness
            if (Cache->Entries[i].Priority > 0) Cache->Entries[i].Priority--;
        }
    }

    Cache->Entries[position].SrcAddress = SrcAddress;
    Cache->Entries[position].DstAddress = DstAddress;
    Cache->Entries[position].Priority = 0x7fffffff;
    *Result = &(Cache->Entries[position]);

    return CX_STATUS_SUCCESS;
}


NTSTATUS
ChmGpaToHpa(
    _In_    GUEST          *Guest,
    _In_    QWORD          Gpa,
    _Out_   QWORD          *Hpa
    )
{
    NTSTATUS status;
    MEM_ALIGNED_PA hPa = 0;
    WORD pageOffset;

    if (!Guest)return CX_STATUS_INVALID_PARAMETER_1;
    if (!Hpa) return CX_STATUS_INVALID_PARAMETER_3;

    pageOffset = Gpa & PAGE_OFFSET_MASK;
    Gpa &= PAGE_MASK;

    status = EptGetHpa(GstGetEptOfPhysicalMemory(Guest), CX_PAGE_BASE_4K(Gpa), &hPa);
    if (SUCCESS(status)) *Hpa = hPa;

    return status;
}

NTSTATUS
ChmGvaToGpaAndHpa(
    _In_        VCPU    *Vcpu,
    _In_        QWORD    Gva,
    __out_opt   QWORD   *Gpa,
    _Out_       QWORD   *Hpa
)
{
    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Hpa) return CX_STATUS_INVALID_PARAMETER_4;

    return _ChmGvaToGpaAndHpaEx(Vcpu, Gva, Gpa, Hpa, NULL);
}

NTSTATUS
ChmGvaToGpaAndHpaEx(
    _In_        VCPU    *Vcpu,
    _In_        QWORD   Gva,
    __out_opt   QWORD   *Gpa,
    _Out_       QWORD   *Hpa,
    __out_opt   PVOID   *PtEntryHva
)
{
    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Hpa) return CX_STATUS_INVALID_PARAMETER_4;

    return _ChmGvaToGpaAndHpaEx(Vcpu, Gva, Gpa, Hpa, PtEntryHva);
}


/// @brief Retrieves corresponding guest physical address and host physical address for a given guest virtual address
///
/// This function will translate the given guest virtual address through guest page-tables to retrieve the associated guest phsyical address.
/// Once the guest physical address is retrieved it will be translated through EPT to retrieve the associated host physical address.
///
/// @param Vcpu         Vcpu for which translation will be attempted
/// @param Gva          Guest virtual address to be translated.
/// @param Gpa          Corresponding guest physical address found in guest page-tables
/// @param Hpa          Corresponding host physical address found in EPT
/// @param PtEntryHva   Host virtual address that points to the guest page-table that contains the mapping; Must be unmapped by caller on success.
///
/// @return CX_STATUS_INVALID_PARAMETER_1   Vcpu is NULL or it is not associated with any guest
/// @return CX_STATUS_INVALID_PARAMETER_4   Hpa is NULL
/// @return STATUS_NO_MAPPING_STRUCTURES    There is no mapping available
/// @return STATUS_PAGE_NOT_PRESENT         Page is not present. Maybe it is swapped out.
static
__forceinline
NTSTATUS
_ChmGvaToGpaAndHpaEx(
    _In_        VCPU    *Vcpu,
    _In_        QWORD   Gva,
    __out_opt   QWORD   *Gpa,
    _Out_       QWORD   *Hpa,
    __out_opt   PVOID   *PtEntryHva
    )
{
    NTSTATUS status;
    DWORD translatedBy = 0;
    DWORD priority = 0;
    CHM_CACHE_ENTRY *result = NULL;

    QWORD translated = (QWORD)-1;
    WORD pageOffset;

    pageOffset = Gva & PAGE_OFFSET_MASK;
    Gva &= PAGE_MASK;

    if (Gpa != NULL)
    {
        *Gpa = NULL;
    }

    if (PtEntryHva != NULL)
    {
        *PtEntryHva = NULL;
    }

    *Hpa = NULL;

    // check the cache only if we don't need the GPA or the PtEntry, else we NEED to walk all tables regardless of any existing cached translations
    if (Gpa == NULL && PtEntryHva == NULL)
    {
        // check if cached -- no synchronization needed, there's only one 'thread' for a given VCPU
        status = _ChmCacheLocate(&(Vcpu->CachedTranslations), Gva, &result, &priority);
        if (CX_STATUS_SUCCESS == status)
        {
            *Hpa = result->DstAddress + pageOffset;
            return status;
        }
        else if (CX_STATUS_DATA_NOT_FOUND != status)
        {
            *Hpa = NULL;
            return status;
        }
    }

    //
    // translate and cache it for CX_STATUS_DATA_NOT_FOUND
    //
    status = CX_STATUS_SUCCESS; // to succeed if no api call is needed

    //
    // According to Intel, Vol. 3A 4-39, "Paging": bits 52-63 from every paging structure are ignored.
    // According to Intel, Vol. 3A 4-7, "Paging": CPUID.80000008H:EAX[7:0] reports the physical-address width supported by
    // the processor. (For processors that do not support CPUID function 80000008H,
    // the width is generally 36 if CPUID.01H:EDX.PAE [bit 6] = 1 and 32 otherwise.)
    // This width is referred to as MAXPHYADDR. MAXPHYADDR is at most 52. Therefore, any physical address
    // will not exceed 52 bit in width.
    //

    // determine VCPU operating mode: 64 bit paged, 32 bit paged, 32 bit non-paged, 16 bit
    // based on VMCS controls and CR0 arch reg bits
    if ((Vcpu->VmcsConfig.VmEntryCtrl & VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA))
    {
        PQWORD pml4, pdp, pd, pt;
        QWORD pdpAddr, pdAddr, ptAddr, pageAddr;

        // 64 bit guest, LMA = 1; use CR3 to get and map PML4, PDP, PD and PT tables
        pml4 = NULL;
        pdp = NULL;
        pd = NULL;
        pt = NULL;

        status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, Vcpu->ArchRegs.CR3, 1, 0, &pml4, NULL, TAG_CHMT);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for CR3 %018p (can't get PML4)\n", Vcpu->ArchRegs.CR3);
            goto cleanup_64;
        }

        // get PDP address
        pdpAddr = pml4[((QWORD)Gva >> (9+9+9+12)) & 0x1ff];
        if (!(pdpAddr & PML4_P))
        {
            status = STATUS_NO_MAPPING_STRUCTURES;
            goto cleanup_64;
        }

        status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(pdpAddr), 1, 0, &pdp, NULL, TAG_CHMT);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PDP)\n", pdpAddr);
            goto cleanup_64;
        }

        // get PD address
        pdAddr = pdp[((QWORD)Gva >> (9+9+12)) & 0x1ff];
        if (!(pdAddr & PDP_P))
        {
            status = STATUS_NO_MAPPING_STRUCTURES;
            goto cleanup_64;
        }

        // Check if this is a huge, 1G page
        if ((pdAddr & PDP_PS))
        {
            pageAddr = (pdAddr & CpuGetMaxPhysicalAddress() & 0xffffffffc0000fff) | ((DWORD)(QWORD)Gva & 0x3FFFF000);
            goto using_1g_page;
        }

        status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(pdAddr), 1, 0, &pd, NULL, TAG_CHMT);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PD)\n", pdAddr);
            goto cleanup_64;
        }

        // get PT address
        ptAddr = pd[((QWORD)Gva >> (9+12)) & 0x1ff];
        if (!(ptAddr & PD_P))
        {
            status = STATUS_NO_MAPPING_STRUCTURES;
            goto cleanup_64;
        }

        // is this a 2M page (is PD.PS = 1, bit 7)?
        if ((ptAddr & PD_PS))
        {
            pageAddr = (ptAddr & CpuGetMaxPhysicalAddress() & 0xffffffffffe00fff) | ((DWORD)(QWORD)Gva & 0x001ff000);
            goto using_2m_page;
        }

        status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(ptAddr), 1, 0, &pt, NULL, TAG_CHMT);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PT)\n", pt);
            goto cleanup_64;
        }

        // get PAGE address
        pageAddr = pt[((QWORD)Gva >> 12) & 0x1ff];
        if (!(pageAddr & PT_P))
        {
            CHMWARNING("PTe not present: PT = %p, PTe offset = %d\n", pt, ((QWORD)Gva >> 12) & 0x1ff);
            status = STATUS_PAGE_NOT_PRESENT;
            goto cleanup_64;
        }
        goto using_4k_page;

using_1g_page:
        if (PtEntryHva)
        {
            *PtEntryHva = &pdp[((QWORD)Gva >> (9 + 9 + 12)) & 0x1ff];
            pdp = NULL;
            goto last_step;
        }
using_2m_page:
        if (PtEntryHva)
        {
            *PtEntryHva = &pd[((QWORD)Gva >> (9 + 12)) & 0x1ff];
            pd = NULL;
            goto last_step;
        }
using_4k_page:
        if (PtEntryHva)
        {
            *PtEntryHva = &pt[((QWORD)Gva >> 12) & 0x1ff];
            pt = NULL;
        }
last_step:
        translated = CLEAR_PHY_ADDR(pageAddr);
        translatedBy = __LINE__;
cleanup_64:
        if (pml4)
        {
            MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pml4);
        }

        if (pdp)
        {
            MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pdp);
        }

        if (pd)
        {
            MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pd);
        }

        if (pt)
        {
            MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pt);
        }
    }
    else if ((Vcpu->ArchRegs.CR0 & CR0_PG))
    {
        // do we have PAE enabled?
        if ((Vcpu->ArchRegs.CR4 & CR4_PAE)) // 32 bit PM, PAE
        {
            PQWORD pdpte, pd, pt;
            QWORD pdAddr, ptAddr, pageAddr;
            PQWORD pdptePage = NULL;
            QWORD pdptePageAddr;

            // 32 bit paged guest, CR0.PG = 1
            pdpte = NULL;
            pd = NULL;
            pt = NULL;

            pdptePageAddr = CLEAR_PHY_ADDR(Vcpu->ArchRegs.CR3);
            status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, pdptePageAddr, 1, 0, &pdptePage, NULL, TAG_CHMT);
            if (!SUCCESS(status))
            {
                CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for CR3 %018p (can't get PDPTE)\n", Vcpu->ArchRegs.CR3);
                goto cleanup_32_pae;
            }
            // NOTE: we are assured that this can NOT span across multiple pages (CR3 is 0x20 aligned for 32-bit PAE paging)
            pdpte = (PQWORD)(((PBYTE)pdptePage) + (Vcpu->ArchRegs.CR3 & 0xFE0));

            // get PD address
            pdAddr = pdpte[((QWORD)Gva >> (9+9+12)) & 0x3];    // 2 bits wide !!!
            if (!(pdAddr & PDP_P))
            {
                status = STATUS_NO_MAPPING_STRUCTURES;
                goto cleanup_32_pae;
            }

            status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(pdAddr), 1, 0, &pd, NULL, TAG_CHMT);
            if (!SUCCESS(status))
            {
                CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PD)\n", pd);
                goto cleanup_32_pae;
            }

            // get PT address
            ptAddr = pd[((QWORD)Gva >> (9+12)) & 0x1ff];
            if (!(ptAddr & PD_P))
            {
                status = STATUS_NO_MAPPING_STRUCTURES;
                goto cleanup_32_pae;
            }

            // is this a 2M page (is PD.PS = 1, bit 7)?
            if ((ptAddr & PD_PS))
            {
                pageAddr = (ptAddr & CpuGetMaxPhysicalAddress() & 0xffffffffffe00000) | ((DWORD)(QWORD)Gva & 0x001fffff);
                goto using_2m_page_pae;
            }

            status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(ptAddr), 1, 0, &pt, NULL, TAG_CHMT);
            if (!SUCCESS(status))
            {
                CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PT)\n", pt);
                goto cleanup_32_pae;
            }

            // get PAGE address
            pageAddr = pt[((QWORD)Gva >> 12) & 0x1ff];
            if (!(pageAddr & PT_P))
            {
                CHMWARNING("PTe not present for Gva=%p: PT = %p (GPA=%p), PTe offset = %d\n", Gva, pt, CLEAR_PHY_ADDR(ptAddr), ((QWORD)Gva >> 12) & 0x1ff);
                status = STATUS_PAGE_NOT_PRESENT;
                goto cleanup_32_pae;
            }

            pageAddr = (pageAddr & CpuGetMaxPhysicalAddress() & 0xfffffffffffff000) | ((DWORD)(QWORD)Gva & 0xfff);
            goto using_4k_page_pae;

using_2m_page_pae:
            if (PtEntryHva)
            {
                *PtEntryHva = &pd[((QWORD)Gva >> (9 + 12)) & 0x1ff];
                pd = NULL;
                goto last_step_pae;
            }
using_4k_page_pae:
            if (PtEntryHva)
            {
                *PtEntryHva = &pt[((QWORD)Gva >> 12) & 0x1ff];
                pt = NULL;
            }
last_step_pae:
            translated = CLEAR_PHY_ADDR(pageAddr);
            translatedBy = __LINE__;

cleanup_32_pae:
            if (pdptePage)
            {
                MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pdptePage);
            }

            if (pd)
            {
                MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pd);
            }

            if (pt)
            {
                MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pt);
            }
        }
        else // 32 bit PM, non-PAE
        {
            PDWORD pd, pt;
            QWORD ptAddr, pageAddr;

            // 32 bit paged guest, CR0.PG = 1
            pd = NULL;
            pt = NULL;

            status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, Vcpu->ArchRegs.CR3, 1, 0, &pd, NULL, TAG_CHMT);
            if (!SUCCESS(status))
            {
                CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for CR3 %018p (can't get PD)\n", Vcpu->ArchRegs.CR3);
                goto cleanup_32;
            }

            // get PT address
            ptAddr = pd[((DWORD)(QWORD)Gva >> (10+12)) & 0x3ff];      // 10 bits wide !!!
            if (!(ptAddr & PD_P))
            {
                status = STATUS_NO_MAPPING_STRUCTURES;
                goto cleanup_32;
            }

            // is this a 4M page (is PD.PS = 1, bit 7)?
            if ((ptAddr & PD_PS))
            {
                pageAddr = (ptAddr & 0xffc00fff) | ((DWORD)(QWORD)Gva & 0x003ff000);
                goto using_4m_page;
            }

            status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest, CLEAR_PHY_ADDR(ptAddr), 1, 0, &pt, NULL, TAG_CHMT);
            if (!SUCCESS(status))
            {
                CHMWARNING("ChmMapContinuousGuestGpaPagesToHost failed for %018p (can't get PT)\n", pt);
                goto cleanup_32;
            }

            // get PAGE address
            pageAddr = pt[((QWORD)Gva >> 12) & 0x3ff];         // 10 bits wide !!!
            if (!(pageAddr & PT_P))
            {
                CHMWARNING("PTe not present: PT = %p, PTe offset = %d\n", pt, ((QWORD)Gva >> 12) & 0x3ff);
                status = STATUS_PAGE_NOT_PRESENT;
                goto cleanup_32;
            }
            goto using_4k_page_32;
using_4m_page:
            if (PtEntryHva)
            {
                *PtEntryHva = &pd[((DWORD)(QWORD)Gva >> (10 + 12)) & 0x3ff];
                pd = NULL;
                goto last_step_32;
            }
using_4k_page_32:
            if (PtEntryHva)
            {
                *PtEntryHva = &pt[((QWORD)Gva >> 12) & 0x3ff];
                pt = NULL;
            }
last_step_32:
            translated = CLEAR_PHY_ADDR(pageAddr);
            translatedBy = __LINE__;
cleanup_32:
            if (pd)
            {
                MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pd);
            }

            if (pt)
            {
                MmUnmapMem(&gHvMm, TRUE, TAG_CHMT, &pt);
            }
        } // non-PAE
    }
    else if ((Vcpu->ArchRegs.CR0 & CR0_PE))
    {
        // 32 bit non-paged guest, CR0.PG = 0, CR0.PE = 1
        // ==> simply use the virtual address as a physical address
        translated = Gva;
        translatedBy = __LINE__;
    }
    else
    {
        // 16 bit real mode guest -- Gva is a linear address (== segment*16 + offset)
        translated = Gva;
        translatedBy = __LINE__;
    }

    if (!SUCCESS(status)) return status;

    if (Gpa) *Gpa = translated + pageOffset;

    // translate to host PA
    {
        QWORD hostAddress = 0;

        status = ChmGpaToHpa(Vcpu->Guest, translated, &hostAddress);
        if (!SUCCESS(status))
        {
            CHMWARNING("ChmGpaToHpa has failed for GVA = %p ==> at %d GPA = %p, status = %s\n", Gva, translatedBy, translated, NtStatusToString(status));
            return status;
        }
        translated = hostAddress;
    }

    *Hpa = translated + pageOffset;

    // cache it
    _ChmCacheAdd(&(Vcpu->CachedTranslations), Gva, translated, &result);
    return status;
}
/// @}
