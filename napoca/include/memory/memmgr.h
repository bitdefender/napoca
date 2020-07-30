/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file memmgr.h
///  @brief Defines the public API of the HV memory management subsystem (virtual/physical memory allocations, mapping, access rights management)
///

/// @ingroup memmgr
/// @{

#ifndef _MEMMGR_H_
#define _MEMMGR_H_
#include "cx_native.h"
#include "memory/vamgr.h"
#include "memory/hva.h"
#include "memory/memtags.h"

typedef CX_VOID             *MM_ALIGNED_VA;     ///< a host Virtual Address that has to start at the first byte of a page
typedef CX_VOID             *MM_UNALIGNED_VA;   ///< a host Virtual Address that that has no need to meet any alignment requirements
typedef CX_UINT64           MM_ALIGNED_PA;      ///< a host Physical Address that has to correspond to the fist byte of a memory page
typedef CX_UINT64           MM_UNALIGNED_PA;    ///< a host Physical Address that has no alignment constraints
typedef CX_UINT32           MM_PAGE_COUNT;      ///< a number of 4KiB memory pages
typedef CX_UINT64           MM_SIZE_IN_BYTES;   ///< number of bytes to operate upon
typedef VAMGR_TAG           MM_TAG;             ///< marks a virtual address (or VA interval) for debugging purposes and sanity checks
typedef HVA_CACHING_TYPE    MM_CACHING;         ///< the CPU is allowed to use its internal data caches when accessing memory, a MM_CACHING value define restrictions on when and how the CPU is allowed to intermediate the content of the memory through the data cache
typedef HVA_RIGHTS          MM_RIGHTS;          ///< access rights for accessing some memory address (namely if read, write and execute accesses are allowed)

extern const MM_RIGHTS      gMmRo;              ///< avoid, use MM_RIGHTS_RO instead, provided only for the compiler
extern const MM_RIGHTS      gMmRw;              ///< avoid, use MM_RIGHTS_RW instead, provided only for the compiler
extern const MM_RIGHTS      gMmRx;              ///< avoid, use MM_RIGHTS_RX instead, provided only for the compiler
extern const MM_RIGHTS      gMmRwx;             ///< avoid, use MM_RIGHTS_RWX instead, provided only for the compiler

#define MM_RIGHTS_RO        gMmRo               ///< defines/allows read without write or execute access
#define MM_RIGHTS_RW        gMmRw               ///< read and write are allowed while instruction execution is denied
#define MM_RIGHTS_RX        gMmRx               ///< read and execute are allowed, write accesses are denied
#define MM_RIGHTS_RWX       gMmRwx              ///< full (read, write and execute) access is granted
#define MM_CACHING_UC       HVA_CACHING_UC      ///< Uncacheable memory
#define MM_CACHING_WC       HVA_CACHING_WC      ///< allow Write-Combining caching
#define MM_CACHING_WT       HVA_CACHING_WT      ///< Write Through
#define MM_CACHING_WP       HVA_CACHING_WP      ///< Write Protected
#define MM_CACHING_WB       HVA_CACHING_WB      ///< Write Back caching type
#define MM_CACHING_UC_      HVA_CACHING_UC_     ///< UC- caching type

typedef struct _MM_DESCRIPTOR MM_DESCRIPTOR;



///
/// @brief        Callback function allowing MmMap to obtain physical addresses backing up some alien address space that is to be mapped inside the host virtual memory space
/// @param[in]    Context                          Custom callback data passed-through to the callback at each iteration step
/// @param[in]    AlienAddress                     This is the current address (in some custom/alien address-space) to process for which we need the PA
/// @param[in]    PageIndex                        Inside the allocation/mapping in progress, this AlienAddress is located at PageIndex
/// @param[out]   Pa                               Response to be filled-in by the callback: the AlienAddress corresponds to this Pa
/// @returns      CX_STATUS_SUCCESS                on success
///
typedef
CX_STATUS
(*MM_GET_PA_CALLBACK)(
    _In_ CX_VOID *Context,
    _In_ CX_UINT64 AlienAddress,
    _In_ MM_PAGE_COUNT PageIndex,
    _Out_ MM_ALIGNED_PA *Pa
    );



///
/// @brief        Callback function that handles all the needs of virtual address allocations for a memory manager
/// @param[in]    Mm                               Memory manager that is trying to allocate virtual addresses
/// @param[in]    NumberOfPages                    Number of 4KiB pages needed
/// @param[out]   Va                               Resulting virtual address pointing to the start of the virtual memory allocated
/// @param[in]    AllocatorId                      Callback-only known identification information of where or from should the VA be allocated OR 0
/// @param[in]    Tag                              Tag (left to the callback's implementation to decide on its usage, can even be ignored)
/// @returns      CX_STATUS_SUCCESS                on success
///
typedef
CX_STATUS
(*MM_ALLOC_VA)(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_PAGE_COUNT              NumberOfPages,
    _Out_ MM_ALIGNED_VA             *Va,
    _In_opt_ CX_UINT64              AllocatorId,
    _In_ MM_TAG                     Tag
    );



///
/// @brief        Callback function to dispose of MM_ALLOC_VA previously allocated virtual addresses
/// @param[in]    Mm                               Memory manager performing the operation
/// @param[in]    NumberOfPages                    How many 4KiB pages to free
/// @param[out]   Va                               Starting virtual address
/// @param[in]    AllocatorId                      Callback-only known identification information of where or from should the VA be allocated OR 0
/// @param[in]    Tag                              Tag (left to the callback's implementation to decide on its usage, can even be ignored)
/// @returns      CX_STATUS_SUCCESS                on success
///
typedef
CX_STATUS
(*MM_FREE_VA)(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_PAGE_COUNT              NumberOfPages,
    _Out_ MM_ALIGNED_VA             *Va,
    _In_opt_ CX_UINT64              AllocatorId,
    _In_ MM_TAG                     Tag
    );



///
/// @brief        Physical memory allocation callback for the memory manager, will be called whenever the memory manager neeeds physical memory
/// @param[in]    Mm                               Memory manager performing the request
/// @param[out]   Mdl                              Mdl to fill-in with the allocated pages. Return STATUS_INCOMPLETE_ALLOC_MDL_OVERFLOW (with the MDL full) if there's not enough room for NumberOfPages
/// @param[out]   Pa                               If the allocated memory is continuous, Mdl can be left unpopulated and the starting PA is to be returned through this output argument
/// @param[in]    NumberOfPages                    The number of 4KiB pages to allocate
/// @param[in]    Continuous                       A logically true value if the memory has to be physically continuous or FALSE if no such constraint needs to be met
/// @param[in]    AllocatorId                      Callback-only known identification information of where or from should the VA be allocated OR 0
/// @param[in]    Tag                              Tag for the allocation, the implementation defines its semantics (or is simply free to ignore it)
/// @returns      CX_STATUS_SUCCESS                on success
///
typedef
CX_STATUS
(*MM_ALLOC_PA)(
    _In_ MM_DESCRIPTOR              *Mm,
    _Out_ MDL                       *Mdl,
    _Out_ MM_ALIGNED_PA             *Pa,
    _In_ MM_PAGE_COUNT              NumberOfPages,
    _In_ CX_BOOL                    Continuous,
    _In_ CX_UINT64                  AllocatorId,
    _In_ MM_TAG                     Tag
);



///
/// @brief        Free some memory pages previously allocated through the #MM_ALLOC_PA callback
/// @param[in]    Mm                               The memory manager that owns the physical pages
/// @param[in]    Mdl                              #MDL describing the pages that are to be reclaimed
/// @param[in]    AllocatorId                      callback-only known identification information of where or from should the VA be allocated OR 0
/// @param[in]    Tag                              Tag for the allocation, the implementation defines its semantics (or is simply free to ignore it)
/// @returns      CX_STATUS_SUCCESS                on success
///
typedef
CX_STATUS
(*MM_FREE_PA)(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MDL                        *Mdl,
    _In_ CX_UINT64                  AllocatorId,    // callback-only known identification information of where or from should the VA be allocated OR 0
    _In_ MM_TAG                     Tag
    );


/// @brief Data structure covering any needed virtual-address allocation information
typedef struct
{
    struct
    {
        CX_UINT8                    Dynamic : 1;            ///< the VA is managed (dynamic)
        CX_UINT8                    LeftGuard : 1;          ///< the VA needs a guard page outside its left side
        CX_UINT8                    RightGuard : 1;         ///< the VA needs a guard page outside, on the right side
    }VaType;                                                ///< specifies VA origin and properties

    union
    {
        MM_ALIGNED_VA               FixedVa;                ///< when VaType is not Dynamic, FixedVa contains the unmanaged address to use for an allocation (being unmanaged, room for the page guard/s must be included!)
        struct
        {
            CX_UINT64               AllocatorId;            ///< implementation-specific identifier for the allocator to be used, will be forwarded to the allocator callback function
            MM_TAG                  Tag;                    ///< Tag value to be forwarded to the allocator callback function
        }DynamicVa;                                         ///< parameters for the allocation
    };
}MM_VA_ALLOCATION;


/// @brief Data structure covering any needed physical-address allocation information
typedef struct
{
    enum {
        MM_PA_NONE                  = 0,    ///< no physical memory is to be manipulated at this allocation (most likely the operation is a mere memory reservation with nothing being committed)
        MM_PA_FIXED                 = 1,    ///< the physical memory is unmanaged and we simply have its starting hardcoded/predefined address
        MM_PA_MDL                   = 2,    ///< the physical memory is described by a MDL
        MM_PA_CALLBACK              = 3,    ///< the MM_GET_PA_CALLBACK Function is to be used for finding out the physical addresses to use for the operation
        MM_PA_DYNAMIC               = 4,    ///< physical memory is to be automatically allocated as needed
        MM_PA_DYNAMIC_CONTINUOUS    = 5,    ///< the physical memory is allocated automatically and has to be continuous
    }PaType;

    union
    {
        MM_ALIGNED_PA               FixedPa;            ///< unmanaged physical address when PaType = MM_PA_FIXED
        MDL                         *Mdl;               ///< MDL providing the physical addresses when PaType = MM_PA_MDL
        struct
        {
            MM_GET_PA_CALLBACK      Function;           ///< Function to call for querying the physical addresses when PaType = MM_PA_CALLBACK
            CX_UINT64               AlienAddress;       ///< Starting alien address to forward to the callback (will be auto-advanced as the operation progresses)
            CX_VOID                 *CallbackContext;   ///< Custom callback-defined data to send to Function
        }Callback;                                      ///< Data needed when PaType == MM_PA_CALLBACK

        struct
        {
            CX_UINT64               AllocatorId;        ///< implementation-defined allocator identification data forwarded to the #MM_ALLOC_PA callback
            MM_TAG                  Tag;                ///< tag to send to the allocator callback function
        }DynamicPa;                                     ///< data needed for both MM_PA_DYNAMIC and MM_PA_DYNAMIC_CONTINUOUS
    }Pa;                                                ///< arguments for the allocation
}MM_PA_ALLOCATION;


///@brief Define if and what guard pages are used for an allocation or memory mapping
typedef enum
{
    MM_GUARD_NONE                   = 0,                                ///< do not include/use guard pages
    MM_GUARD_LEFT                   = 1,                                ///< a guard page precedes the actual allocation
    MM_GUARD_RIGHT                  = 2,                                ///< a guard page succeeds the allocation/mapping
    MM_GUARD_BOTH                   = MM_GUARD_LEFT | MM_GUARD_RIGHT    ///< the allocation/mapping is guarded by trap pages on both sides
}MM_GUARD;


///@brief Specifies if the chaining information is to be sealed or left open for glueing together a larger allocation/mapping from multiple parts
/// @remark glued regions can't be freed and/or unmapped until they are committed by calling MmMarkMappingComplete()
typedef enum
{
    MM_GLUE_NONE                    = 0,    ///< the chaining will be sealed (closed on both ends)
    MM_GLUE_BOTH                    = 1     ///< keep both sides of the chain open to be able to glue mappings together, piece by piece
}MM_GLUE;

/// @brief Encapsulates the state and behavior of a memory manager
typedef struct _MM_DESCRIPTOR
{
    TAS_DESCRIPTOR                  *Tas;               ///< The underlying TranslatedAddressSpace interface descriptor for page table structures management
    MM_ALLOC_VA                     AllocVa;            ///< VA Allocation function used by this memory manager
    CX_VOID                         *AllocVaContext;    ///< Custom data for the VA allocator
    MM_FREE_VA                      FreeVa;             ///< Free VA callback
    CX_VOID                         *FreeVaContext;     ///< Context information for the Free VA callback
    MM_ALLOC_PA                     AllocPa;            ///< Physical pages allocator callback
    CX_VOID                         *AllocPaContext;    ///< Callback-specific data for the PP allocator
    MM_FREE_PA                      FreePa;             ///< Callback for freeing back the physical memory
    CX_VOID                         *FreePaContext;     ///< Context pointer for the PP Free callback
}MM_DESCRIPTOR;


extern MM_DESCRIPTOR gHvMm;                             ///< Public memory manager configured with dynamic allocators for all-around purposes
extern MM_DESCRIPTOR gHvLowerMem;                       ///< Special memory manager built on top of the loader's memory buffer (sent at boot time to the Init64 function)


CX_STATUS
MmInitDescriptor(
    _In_ TAS_DESCRIPTOR             *TasDescriptor,
    _In_ MM_ALLOC_VA                AllocVa,
    _In_opt_ CX_VOID                *AllocVaContext,
    _In_ MM_FREE_VA                 FreeVa,
    _In_opt_ CX_VOID                *FreeVaContext,
    _In_ MM_ALLOC_PA                AllocPa,
    _In_opt_ CX_VOID                *AllocPaContext,
    _In_ MM_FREE_PA                 FreePa,
    _In_opt_ CX_VOID                *FreePaContext,
    _Out_ MM_DESCRIPTOR             *Descriptor
);


CX_STATUS
MmRegisterVaInfo(
    _In_ MM_UNALIGNED_VA            Va,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ const char                 *FormatString,
    ...
);


CX_STATUS
MmGetAllocationTasProperties(
    _In_ TAS_PROPERTIES             InitialProperties,
    _In_ MM_RIGHTS                  Rights,
    _In_ MM_CACHING                 Caching,
    _Out_ TAS_PROPERTIES            *Properties
);


CX_STATUS
MmAllocEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ TAS_PROPERTIES             Properties,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
);


CX_STATUS
MmFreeEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_VA_ALLOCATION           *VaAllocation,
    _In_opt_ MM_PA_ALLOCATION       *PaAllocation,
    _In_ MM_ALIGNED_VA              Va
);


CX_STATUS
MmAlloc(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_opt_ MDL                    *Mdl,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _In_opt_ MM_GLUE                Glue,
    _Out_opt_ MM_UNALIGNED_VA       *Va,
    _Out_opt_ MM_UNALIGNED_PA       *Pa
);


CX_STATUS
MmFree(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,
    _In_opt_ CX_BOOL                FixedPa,
    _In_opt_ MM_TAG                 Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_UNALIGNED_VA         *Va
);


CX_STATUS
MmReserveVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _Out_ MM_UNALIGNED_VA           *Va
);


CX_STATUS
MmUnreserveVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,
    _In_opt_ MM_TAG                 Tag,
    _Inout_ MM_UNALIGNED_VA         *Va
);


CX_STATUS
MmLockVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size
);


CX_STATUS
MmUnLockVa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            FixedVa,
    _In_ MM_SIZE_IN_BYTES           Size
);


CX_STATUS
MmAllocMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
);

CX_STATUS
MmFreeMemEx(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_ALIGNED_VA           *Va
);


CX_STATUS
MmAllocMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_ALIGNED_VA             *Va
);


CX_STATUS
MmFreeMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_ALIGNED_VA           *Va
);


CX_STATUS
MmAllocDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_ALIGNED_VA             *Va,
    _Out_opt_ MM_ALIGNED_PA         *Pa
);


CX_STATUS
MmFreeDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_ALIGNED_VA           *Va
);


CX_STATUS
MmMap(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_VA        FixedVa,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_opt_ MDL                    *Mdl,
    _In_opt_ MM_GET_PA_CALLBACK     Callback,
    _In_opt_ CX_UINT64              AlienAddress,
    _In_opt_ CX_VOID                *CallbackContext,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_opt_ MM_TAG                 Tag,
    _In_ MM_RIGHTS                  Rights,
    _In_ HVA_CACHING_TYPE           Caching,
    _In_opt_ MM_GUARD               Guard,
    _In_opt_ MM_GLUE                Glue,
    _Out_opt_ MM_UNALIGNED_VA       *Va,
    _Out_opt_ MM_UNALIGNED_PA       *Pa
);


CX_STATUS
MmUnmap(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ CX_BOOL                FixedVa,
    _In_opt_ CX_BOOL                FixedPa,
    _In_opt_ MM_TAG                 Tag,
    _In_opt_ MM_GUARD               Guard,
    _Inout_ MM_UNALIGNED_VA         *Va
);


CX_STATUS
MmMapMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_UNALIGNED_VA           *Va
);


CX_STATUS
MmUnmapMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ CX_BOOL                    FixedPa,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_UNALIGNED_VA         *Va
);


CX_STATUS
MmMapDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_opt_ MM_UNALIGNED_PA        FixedPa,
    _In_ MM_SIZE_IN_BYTES           Size,
    _In_ MM_TAG                     Tag,
    _Out_ MM_UNALIGNED_VA           *Va
);


CX_STATUS
MmUnmapDevMem(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ CX_BOOL                    FixedPa,
    _In_ MM_TAG                     Tag,
    _Inout_ MM_UNALIGNED_VA         *Va
);


CX_STATUS
MmMarkMappingComplete(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_ MM_SIZE_IN_BYTES           Size
);


CX_STATUS
MmAlterRights(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_RIGHTS                  Rights
);


CX_STATUS
MmAlterCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_CACHING                 Caching
);


CX_STATUS
MmAlterRightsAndCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _In_ MM_RIGHTS                  Rights,
    _In_ MM_CACHING                 Caching
);


CX_STATUS
MmQuery(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_opt_ MM_RIGHTS             *Rights,
    _Out_opt_ MM_CACHING            *Caching,
    _Out_opt_ MM_ALIGNED_PA         *StartPa,
    _Out_opt_ MM_PAGE_COUNT         *ChainedPages
);


CX_STATUS
MmQueryRights(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_ MM_RIGHTS                 *Rights
);


CX_STATUS
MmQueryCaching(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size,
    _Out_ MM_CACHING                *Caching
);


CX_STATUS
MmQueryPa(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _Out_ MM_UNALIGNED_PA           *Pa
);



///
/// @brief        Check if the memory at Va is safely readable
/// @param[in]    Mm                               Memory manager descriptor
/// @param[in]    Va                               Virtual address to inspect
/// @param[in]    Size                             Optional number of bytes to check, will cover a whole (fully-chained) allocation/mapping if 0
/// @returns      a true value if the memory is readable or FALSE otherwise
///
__forceinline
CX_BOOL
MmIsMemReadable(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size
)
{
    MM_RIGHTS rights;
    CX_STATUS status = MmQueryRights(Mm, Va, Size, &rights);
    if (!CX_SUCCESS(status)) return CX_FALSE;
    return rights.Read;
}



///
/// @brief        Verify if the memory identified by Va and Size is writable
/// @param[in]    Mm                               Memory manager
/// @param[in]    Va                               Address to verify
/// @param[in]    Size                             Optional number of bytes to verity, if 0, it will check all memory up to the end of the allocation/mapping pointed by Va
/// @returns      a true value if the memory is writable or FALSE otherwise
///
__forceinline
CX_BOOL
MmIsMemWriteable(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size
)
{
    MM_RIGHTS rights;
    CX_STATUS status = MmQueryRights(Mm, Va, Size, &rights);
    if (!CX_SUCCESS(status)) return CX_FALSE;
    return rights.Write;
}



///
/// @brief        Verify if the memory identified by Va and Size is executable
/// @param[in]    Mm                               Memory manager
/// @param[in]    Va                               Address to verify
/// @param[in]    Size                             Optional number of bytes to verity, if 0, it will check all memory up to the end of the allocation/mapping pointed by Va
/// @returns      a true value if the memory is executable or FALSE otherwise
///
__forceinline
CX_BOOL
MmIsMemExecutable(
    _In_ MM_DESCRIPTOR              *Mm,
    _In_ MM_UNALIGNED_VA            Va,
    _In_opt_ MM_SIZE_IN_BYTES       Size
)
{
    MM_RIGHTS rights;
    CX_STATUS status = MmQueryRights(Mm, Va, Size, &rights);
    if (!CX_SUCCESS(status)) return CX_FALSE;
    return rights.Execute;
}


/// @brief MmGetHpaForHvaCallback type for the CallbackContext argument of the #MmMap function
typedef struct
{
    MM_DESCRIPTOR *Mm;              ///< The memory manager that's performing the operation
}MM_GET_HPA_FOR_HVA_CALLBACK_CONTEXT;


NTSTATUS
MmGetHpaForHvaCallback(
    _In_ CX_VOID *Context,
    _In_ CX_UINT64 AlienAddress,
    _In_ MM_PAGE_COUNT PageIndex,
    _Out_ MM_ALIGNED_PA *Pa
);

#endif // _MEMMGR_H_

/// @}