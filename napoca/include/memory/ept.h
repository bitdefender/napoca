/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file ept.h
///  @brief Data types and function declarations for managing the Intel's Extended Page Tables virtualization feature.
///

/// @ingroup ept
/// @{


#ifndef _EPT_H_
#define _EPT_H_


#include "core.h"
#include "kernel/kerneltypes.h"
#include "memory/tas.h"
#include "memory/memmgr.h"
#include "kernel/rwspinlock.h"

typedef struct _EPT_DESCRIPTOR EPT_DESCRIPTOR;

typedef
CX_STATUS
(EPT_NOTIFY_INVALIDATION_CB)(
    EPT_DESCRIPTOR              *EptDescriptor,                 ///< EPT descriptor of the domain needing invalidation
    CX_VOID                     *CallbackContext                ///< callback-specific data, if any (as registered at EPT domain creation via #EptInitDescriptor)
);

typedef struct _EPT_DESCRIPTOR
{
    struct _EPT_DESCRIPTOR_INTERNAL
    {
        TAS_DESCRIPTOR          Tas;                            ///< Underlying TAS descriptor
        CX_BOOL                 InvalidationNeeded;             ///< Automatically set by the low-level table entry callback called by TAS and also automatically flushed (set to 0 when performing needed invalidations) by the upper-level EPT functions.
        CX_BOOL                 Use1GbPages;                    ///< Use 1Gbyte pages for this domain
    };
    EPT_NOTIFY_INVALIDATION_CB *InvalidationRoutine;            ///< callback function provided by the guest using this EPT and called automatically when changes that need invalidations had occured
    CX_VOID                     *InvalidationRoutineContext;    ///< optional callback-specific data, the guest has full control over its type and use.
    RW_SPINLOCK                 DestroyLock;                    ///< multi-reader / single-writer lock that guarantees structures can't be freed while in active use by some other code.
}EPT_DESCRIPTOR;


typedef struct _GUEST GUEST;

typedef TAS_PROPERTIES          EPT_PROPERTIES, EPT_RIGHTS;     ///< Logic view over the access rights, caching types, VE, SPP or other such properties of an EPT address translation

static const EPT_RIGHTS         gEptNone   = { .Raw = 0 };                              ///< low-level constant, the use of #EPT_PROPERTIES_NONE or #EPT_RIGHTS_NONE is recommended instead
static const EPT_RIGHTS         gEptR      = { .Read = 1 };                             ///< low-level constant, the use of #EPT_PROPERTIES_R or #EPT_RIGHTS_R is recommended instead
static const EPT_RIGHTS         gEptW      = { .Write = 1 };                            ///< low-level constant, the use of #EPT_PROPERTIES_W or #EPT_RIGHTS_W is recommended instead
static const EPT_RIGHTS         gEptX      = { .Execute = 1 };                          ///< low-level constant, the use of #EPT_PROPERTIES_X or #EPT_RIGHTS_X is recommended instead
static const EPT_RIGHTS         gEptRw     = { .Read = 1, .Write = 1 };                 ///< low-level constant, the use of #EPT_PROPERTIES_RW or #EPT_RIGHTS_RW is recommended instead
static const EPT_RIGHTS         gEptRx     = { .Read = 1, .Execute = 1 };               ///< low-level constant, the use of #EPT_PROPERTIES_RX or #EPT_RIGHTS_RX is recommended instead
static const EPT_RIGHTS         gEptRwx    = { .Read = 1, .Write = 1, .Execute = 1 };   ///< low-level constant, the use of #EPT_PROPERTIES_RWX or #EPT_RIGHTS_RWX is recommended instead

#define EPT_PROPERTIES_NONE     gEptNone            ///< Neither READ, WRITE nor EXECUTE #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_R        gEptR               ///< .Read with neither .Write nor .Execute #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_W        gEptW               ///< .Write without either Read or Execute #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_X        gEptX               ///< .Execute with neither .Read nor .Write #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_RW       gEptRw              ///< .Read and .Write without .Execute #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_RX       gEptRx              ///< .Read and .Execute but without .Write #EPT_PROPERTIES constant to use when calling any EPT function that needs an argument of this type
#define EPT_PROPERTIES_RWX      gEptRwx             ///< .Read, .Write and .Execute #EPT_RIGHTS EPT_PROPERTIES to use when calling any EPT function that needs an argument of this type

#define EPT_RIGHTS_NONE         EPT_PROPERTIES_NONE ///< Neither READ, WRITE nor EXECUTE #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_R            EPT_PROPERTIES_R    ///< .Read with neither .Write nor .Execute #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_W            EPT_PROPERTIES_W    ///< .Write without either Read or Execute #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_X            EPT_PROPERTIES_X    ///< .Execute with neither .Read nor .Write #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_RW           EPT_PROPERTIES_RW   ///< .Read and .Write without .Execute #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_RX           EPT_PROPERTIES_RX   ///< .Read and .Execute but without .Write #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument
#define EPT_RIGHTS_RWX          EPT_PROPERTIES_RWX  ///< .Read, .Write and .Execute #EPT_RIGHTS constant to use when calling any EPT function that needs a #EPT_RIGHTS argument

///
/// @brief A logic view over the EPT memory type and Ignore PAT settings
/// @remark The #EPT_CACHING_WB and #EPT_CACHING_UC constants are meant to be used wherever possible (although the low-level structure might still be needed for more specialized scenarios)
///
typedef union
{
    struct
    {
        CX_UINT16 MemoryType    : CX_BITFIELD(2, 0); ///< value for the EPT Memory Type PTE field, same semantics as the HVA_CACHING_TYPE, 0 = UC; 1 = WC; 4 = WT; 5 = WP; and 6 = WB. Other values are reserved and cause EPT misconfigurations
        CX_UINT16 IgnorePat     : CX_BITFIELD(3, 3); ///< value for the EPT Ignore Pat bit
        CX_UINT16 Ignored       : CX_BITFIELD(15, 4);
    };
    CX_UINT16 Raw;
}EPT_CACHING;

static const EPT_CACHING        gEptUc = { .IgnorePat = 0, .MemoryType = 0 };   ///< low-level constant, use of #EPT_CACHING_UC is recommended instead
static const EPT_CACHING        gEptWc = { .IgnorePat = 0, .MemoryType = 1 };
static const EPT_CACHING        gEptWt = { .IgnorePat = 0, .MemoryType = 4 };
static const EPT_CACHING        gEptWp = { .IgnorePat = 0, .MemoryType = 5 };
static const EPT_CACHING        gEptWb = { .IgnorePat = 0, .MemoryType = 6 };   ///< low-level constant, use of #EPT_CACHING_WB is recommended instead

#define EPT_CACHING_WB          gEptWb ///< Write-Back constant (of type #EPT_CACHING) to use when calling any EPT function that needs a #EPT_CACHING argument
#define EPT_CACHING_UC          gEptUc ///< Uncacheable constant (of type #EPT_CACHING) to use when calling any EPT function that needs a #EPT_CACHING argument

CX_STATUS
EptInitDescriptor(
    _Out_ EPT_DESCRIPTOR                *Ept,
    _In_opt_ EPT_NOTIFY_INVALIDATION_CB *InvalidationRoutine,
    _In_opt_ CX_VOID                    *InvalidationRoutineContext,
    _In_ CX_BOOL                        UseLimitedLargePages
);

NTSTATUS
EptDestroy(
    _Inout_ EPT_DESCRIPTOR *Ept
);

CX_STATUS
EptGetRootPa(
    _In_ EPT_DESCRIPTOR         *Ept,
    __out_opt MEM_ALIGNED_PA    *Hpa
);

CX_STATUS
EptGetRawEptpValue(
    _In_ EPT_DESCRIPTOR         *Ept,
    __out_opt CX_UINT64         *RawEptpValue
);

CX_UINT64
EptGetStructuresSize(
    _In_ EPT_DESCRIPTOR *Ept
);

CX_UINT64
EptPropsToPteCachingAndRightsBits(
    _In_ EPT_PROPERTIES Props
);

CX_STATUS
EptAlterMappingsEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         SetProperties,
    _In_ EPT_PROPERTIES         ClearProperties,
    _In_ MEM_UNALIGNED_PA       NewHpa,
    __out_opt EPT_PROPERTIES    *OriginalProperties,
    __out_opt MEM_UNALIGNED_PA  *OriginalHpa
);

CX_STATUS
EptAlterMappings(
    _In_ EPT_DESCRIPTOR *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         SetProperties,
    _In_ EPT_PROPERTIES         ClearProperties
);

CX_STATUS
EptSetCacheAndRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights,
    _In_ EPT_CACHING            Caching
);

CX_STATUS
EptSetRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights
);

CX_STATUS
EptSetCaching(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_CACHING            Caching
);

CX_STATUS
EptSetHpa(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa
);


CX_STATUS
EptQueryProperties(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    __out_opt EPT_PROPERTIES    *Properties,
    __out_opt MEM_UNALIGNED_PA  *Hpa
);

CX_STATUS
EptGetRights(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    __out_opt EPT_RIGHTS        *Rights
);

CX_STATUS
EptGetHpa(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    __out_opt MEM_UNALIGNED_PA  *Hpa
);

CX_BOOL
EptIsMemMapped(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_BOOL
EptIsMemReadable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_BOOL
EptIsMemWriteable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_BOOL
EptIsMemExecutable(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

NTSTATUS
EptUpdateCachingFromMtrrs(
    _Inout_ EPT_DESCRIPTOR      *Ept,
    _In_ MTRR_STATE             *Mtrr
);

// mapping functions

CX_STATUS
EptMapEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_PROPERTIES         Set,
    _In_ EPT_PROPERTIES         Clear,
    _In_ EPT_PROPERTIES         MustHave,
    _In_ EPT_PROPERTIES         MustLack
);

CX_STATUS
EptUnmapEx(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_STATUS
EptMap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes,
    _In_ EPT_RIGHTS             Rights,
    _In_ EPT_CACHING            Caching
);

CX_STATUS
EptUnmap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_STATUS
EptMapMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_STATUS
EptUnmapMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_STATUS
EptMapDevMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_ MEM_UNALIGNED_PA       Hpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

CX_STATUS
EptUnmapDevMem(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MEM_UNALIGNED_PA       Gpa,
    _In_opt_ MEM_SIZE_IN_BYTES  NumberOfBytes
);

///////////////////////////////


NTSTATUS
EptCopyTranslationsFromMemoryMap(
    _In_ EPT_DESCRIPTOR         *Ept,
    _In_ MMAP*                  EptMap
);

CX_STATUS
EptCopyTranslations(
    _Inout_ EPT_DESCRIPTOR      *DestinationEpt,
    _In_ EPT_DESCRIPTOR         *SourceEpt
);


NTSTATUS
EptInvalidateTlbs(
    _In_ GUEST* Guest,
    _In_ QWORD Context,
    _In_ BOOLEAN WaitForCompletion
);

//
// These are actually logical details from the memory maps => where should they go?
//
#define EPT_RAW_RIGHTS_R                    BIT(0) ///< Low-level (avoid whenever possible) EPT PTE raw bit value/mask for the READ access right
#define EPT_RAW_RIGHTS_W                    BIT(1) ///< Low-level (avoid whenever possible) EPT PTE raw bit value/mask for the WRITE access right
#define EPT_RAW_RIGHTS_X                    BIT(2) ///< Low-level (avoid whenever possible) EPT PTE raw bit value/mask for the EXECUTE access right
#define EPT_RAW_RIGHTS_RW                   (EPT_RAW_RIGHTS_R | EPT_RAW_RIGHTS_W) ///< Low-level (avoid whenever possible) EPT PTE raw bits value/mask for the READ and WRITE access rights
#define EPT_RAW_RIGHTS_RWX                  (EPT_RAW_RIGHTS_R | EPT_RAW_RIGHTS_W | EPT_RAW_RIGHTS_X) ///< Low-level (avoid whenever possible) EPT PTEE raw bits value/mask for the READ, WRITE and EXECUTE access rights
#define EPT_RAW_RIGHTS_MASK                 0x007  ///< Low-level (avoid whenever possible) EPT PTE raw bits value/mask for the READ, WRITE and EXECUTE access rights

#define EPT_RAW_CACHING_WB                  0x030  ///< Low-level (avoid whenever possible) EPT PTE raw bits value for Write Back (WB) memory type (bits[5:3] = 6)
#define EPT_RAW_CACHING_UC                  0x000  ///< Low-level (avoid whenever possible) EPT PTE raw bits value for Uncacheable (UC) memory type (bits[5:3] = 0)
#define EPT_RAW_CACHING_MASK                0x038  ///< Low-level (avoid whenever possible) EPT PTE raw bitmask value for the memory type (bits [5:3] considered set)
#define EPT_RAW_CACHING_DEFAULT             0x038  ///< Intermediate/initialization low-level (avoid whenever possible) value for the EPT PTE bits defining the memory type that in the end reduces to the MTRR defaults

// deprecated, invalidation logic would preferably be implicit not explicit (if we can afford it like that)
#define EPT_INVD_ANY_CONTEXT                     0

CX_STATUS
EptDumpMappings(
    _In_ EPT_DESCRIPTOR     *Ept
);

CX_STATUS
EptDumpTranslationInfo(
    _In_ EPT_DESCRIPTOR     *Ept,
    _In_ MEM_UNALIGNED_PA   Gpa
);

#endif // _EPT_H_
/// @}
