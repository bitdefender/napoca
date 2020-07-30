/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup hva
/// @{

#ifndef _HVA_H_
#define _HVA_H_

#include "base/cx_sal.h"
#include "wrappers/cx_winsal.h"
#include "memory/tas.h"
#include "kernel/kerneldefs.h"

#define HVA_PAGING_DEPTH                        4
#define HVA_GLOBAL_INVLD_PAGE_COUNT_THRESHOLD   8192  // when this number of pages need invalidation we'll do a global invalidation
#define HVA_PAGE_OFFSET_BITS                    12ull
#define HVA_TABLE_INDEX_BITS                    9
#define HVA_TABLE_ENTRY_MASK                    511
#define HVA_PTE_PHYSICAL_ADDRESS_WIDTH          52

extern TAS_DESCRIPTOR gHva;

typedef CX_VOID     *HVA_ALIGNED_VA;
typedef CX_VOID     *HVA_UNALIGNED_VA;
typedef CX_UINT64   HVA_ALIGNED_PA;
typedef CX_UINT64   HVA_UNALIGNED_PA;
typedef CX_UINT32   HVA_PAGE_COUNT;
typedef CX_UINT64   HVA_SIZE_IN_BYTES;

CX_STATUS
CpuGetIa32Pat(
    _Out_ CX_UINT64 *Pat
);

#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

typedef union
{
    struct
    {
        CX_UINT64 Present           : CX_BITFIELD(0, 0);   // Present; must be 1 to map a 4-KByte page
        CX_UINT64 Write             : CX_BITFIELD(1, 1);   // Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
        CX_UINT64 Supervisor        : CX_BITFIELD(2, 2);   // User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry
        CX_UINT64 WriteThrough      : CX_BITFIELD(3, 3);   // Page-level write-through; indirectly determines the memory type used to access the 4-KByte page
        CX_UINT64 CacheDisable      : CX_BITFIELD(4, 4);   // Page-level cache disable; indirectly determines the memory type used to access the 4-KByte page
        CX_UINT64 Accessed          : CX_BITFIELD(5, 5);   // Accessed; indicates whether software has accessed the 4-KByte page referenced by this entry
        CX_UINT64 Dirty             : CX_BITFIELD(6, 6);   // Dirty; indicates whether software has written to the 4-KByte page referenced by this entry (see Section 4.8)
        CX_UINT64 Pat               : CX_BITFIELD(7, 7);   // If the PAT is supported, indirectly determines the memory type used to access the 4-KByte page referenced by
        CX_UINT64 Global            : CX_BITFIELD(8, 8);   // Global; if CR4.PGE = 1, determines whether the translation is global
        CX_UINT64 HvChainLimit      : CX_BITFIELD(9, 9);   // marks the first and last page (boundaries) in a chained allocation
        CX_UINT64 HvChained         : CX_BITFIELD(10, 10);
        CX_UINT64 HvInUse           : CX_BITFIELD(11, 11); // the old "reserved" flag, this VA is NOT free but known/reserved or already used
        CX_UINT64 PageFrame         : CX_BITFIELD(62, 12);
        CX_UINT64 ExecuteDisable    : CX_BITFIELD(63, 63);
    };
    CX_UINT64                       Raw;
    CX_UINT16                       PteCacheAndRights;
}HVA_PTE_RAW;
typedef volatile HVA_PTE_RAW HVA_PTE;
static_assert(sizeof(HVA_PTE) == sizeof(CX_UINT64), "the PTE entries are QWORDs");

typedef enum
{
    HVA_CACHING_UC                  = 0,                // Uncacheable
    HVA_CACHING_WC                  = 1,                // Write Combining
    HVA_CACHING_WT                  = 4,                // Write Through
    HVA_CACHING_WP                  = 5,                // Write Protected
    HVA_CACHING_WB                  = 6,                // Write Back
    HVA_CACHING_UC_                 = 7                 // UC- => UC_ ...
}HVA_PAT_VALUES, HVA_CACHING_TYPE;

typedef struct {
    CX_UINT8 Read : 1;
    CX_UINT8 Write : 1;
    CX_UINT8 Execute : 1;
}HVA_RIGHTS;

// the structure of the IA32_PAT MSR
typedef union
{
    CX_UINT8 PageAttributeFields[8]; // a HVA_CACHING_TYPE value is encoded for each entry
    CX_UINT64 Raw;
}HVA_PAT;


typedef union
{
    struct
    {
        CX_UINT8 PWT            : CX_BITFIELD(0, 0);   // page-level write-through
        CX_UINT8 PCD            : CX_BITFIELD(1, 1);   // page-level cache disable
        CX_UINT8 PAT            : CX_BITFIELD(2, 2);
    };
    CX_UINT8 Raw;                                   // given a PTE, the index is equal to 4 * pte.PAT + 2 * pte.PCD + pte.PWT
}HVA_PAT_INDEX, HVA_PTE_CACHING_BITS;

#pragma warning(pop)


extern const HVA_PAT gStandardCompatibilityPat;

CX_STATUS
HvaActivateL1tfMitigations(
    CX_VOID
);


__forceinline
HVA_PAT
HvaGetPat(
    CX_VOID
)
{
    HVA_PAT pat;
    CX_STATUS status = CpuGetIa32Pat(&pat.Raw);
    return CX_SUCCESS(status) ? pat : gStandardCompatibilityPat;
}



__forceinline
HVA_PAT_INDEX
HvaPteToPatIndex(
    _In_ HVA_PTE *Pte
)
{
    HVA_PAT_INDEX idx = { 0 };
    idx.PAT = (CX_UINT8)Pte->Pat;
    idx.PCD = (CX_UINT8)Pte->CacheDisable;
    idx.PWT = (CX_UINT8)Pte->WriteThrough;
    return idx;
}


__forceinline
HVA_CACHING_TYPE
HvaGetPatEntry(_In_ HVA_PAT_INDEX PatIndex)
{
    HVA_PAT pat = HvaGetPat();
    return (HVA_CACHING_TYPE)(pat.PageAttributeFields[PatIndex.Raw]);
}


__forceinline
HVA_CACHING_TYPE
HvaGetCachingType(_In_ HVA_PAT_INDEX PatIndex)
{
    return HvaGetPatEntry(PatIndex);
}


__forceinline
HVA_CACHING_TYPE
HvaPteBitsToCachingType(_In_ HVA_PTE *Pte)
{
    return HvaGetPatEntry(HvaPteToPatIndex(Pte));
}


__forceinline
CX_STATUS
HvaCachingTypeToPteBits(
    _In_ HVA_CACHING_TYPE CacheType,
    _Out_ HVA_PTE_CACHING_BITS *Result
)
{
    HVA_PAT pat;

    pat = HvaGetPat();
    for (HVA_PAT_INDEX patIndex = { 0 }; patIndex.Raw < 8; patIndex.Raw++)
    {
        if (pat.PageAttributeFields[patIndex.Raw] == CacheType)
        {
            *Result = patIndex;
            return CX_STATUS_SUCCESS;
        }
    }

    return CX_STATUS_DATA_NOT_FOUND;
}


CX_UINT64
HvaGetPlatformL1tfMitigationPageFrameBitsMask(
    CX_VOID
);

//
// TLB invalidation support
//

CX_STATUS
HvaInvalidateTlbRange(
    _In_ CX_VOID *Address,
    _In_ HVA_PAGE_COUNT PageCount,
    _In_ CX_BOOL Broadcast,
    _In_ CX_BOOL InclGlobalPages
);

CX_STATUS
HvaInvalidateTlbComplete(
    _In_ CX_BOOL Broadcast,
    _In_ CX_BOOL InclGlobalPages
);


CX_VOID
HvaDumpPte(
    _In_ HVA_PTE Pte
);

CX_VOID
HvaDumpProperties(
    _In_ TAS_PROPERTIES Properties
);

CX_STATUS
HvaDumpTranslationInfo(
    _In_ CX_VOID *Va
);

CX_VOID
HvaDumpRangeInfo(
    _In_ CX_VOID *Va,
    _In_ HVA_PAGE_COUNT PageCount
);

CX_STATUS
HvaIterateTables(
    _In_ TAS_DESCRIPTOR             *Mapping,
    _In_ MEM_ALIGNED_PA             TablePa,
    __out_opt MEM_ALIGNED_VA        *TableVa,
    _In_ CX_UINT8                   TableDepth,
    _Inout_ MEM_TABLE_OFFSET        *TableByteIndex,
    __out_opt MEM_ALIGNED_PA        *SizeIncrement,
    __out_opt MEM_ALIGNED_PA        *NextLevelTablePa,
    __out_opt CX_BOOL               *NextLevelTableValid,
    __out_opt CX_BOOL               *IsLeaf
);

CX_STATUS
HvaGetHvaPagingStructureVaCallback(
    _In_ MEM_UNALIGNED_PA Pa,
    _Out_ MEM_UNALIGNED_VA* Va
);

CX_STATUS
HvaActivateHvaPagingStructuresOffsetting(
    CX_VOID
);
#endif // _HVA_H_
/// @}
