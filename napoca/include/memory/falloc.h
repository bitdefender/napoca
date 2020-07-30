/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

///
///  @file falloc.h
///  @brief Declarations for the API of a fast allocator of constant-size memory elements. Each allocator assumes a continuous virtual-address memory space that contains both the metadata and room for the actual elements, it starts with a minimal amount of actual physical memory and expands the used physical memory automatically based on pool usage, never releasing it back.
///

/// @ingroup falloc
/// @{

#ifndef _FALLOC_H_
#define _FALLOC_H_

#include "core.h"
#include "memory/heapfa.h"


#ifndef FA_STACK_MAX_MEM_PER_SIZE
#define FA_STACK_MAX_MEM_PER_SIZE   (48*CX_MEGA)    ///< total physical memory an allocator is allowed to manage
#endif

#ifndef FA_MAX_REALLOCS
#define FA_MAX_REALLOCS             20              ///< a limit on how many times we're allowed to double in size (starting with 4KB)
#endif



//
// External functions needed by this component (an implementation is expected to be provided at link-time)
//

///
/// @brief        Reserve a page-aligned virtual address range of PageCount 4K pages and write the Va pointer with it's starting address. The backing physical pages will be allocated on demand, later on, via explicit calls to #FaAllocAndMapPages
/// @param[in]    Va                               Address of the pointer whose value is to be written
/// @param[in]    PageCount                        Number of 4K pages needed to be reserved (and only reserved, no memory needs to be committed yet)
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS   FaReserveVa(_Out_ CX_VOID **Va, _In_ CX_UINT32 PageCount);



///
/// @brief        Free a virtual address space reservation obtained through a previous #FaReserveVa call, tear down the existing mappings and release the backing physical pages, if any
/// @param[in]    Va                               The start of the address of the virtual memory range
/// @param[in]    Size                             Size in bytes of the memory region to be freed
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS   FaFreeVa(_In_ CX_VOID *Va, _In_ CX_UINT32 Size);



///
/// @brief        Allocate PageCount physical pages and map them in the continuous virtual-address space starting at address Va
/// @param[in]    Va                               Starting virtual address (page aligned) where allocated phyical pages must be mapped to
/// @param[in]    PageCount                        Number of (both) phyical pages and virtual pages to process
/// @returns      CX_STATUS_SUCCESS                on success
///
CX_STATUS   FaAllocAndMapPages(_In_ CX_VOID *Va, _In_ CX_UINT32 PageCount);



///
/// @brief        Prepare a spinlock for use
/// @param[out]   Lock                             Address of the spinlock data/structure
/// @param[in?]   Name                             Provides a name for the newly initialized spinlock, the implementation may choose to ignore this parameter
///
CX_VOID     FaInitSpinlock(_Out_ FA_LOCK *Lock, char *Name);



///
/// @brief        Acquire a lock exclusively
/// @param[in, out] Lock                             Address of the lock data/structure
///
CX_VOID     FaLock(_Inout_ FA_LOCK *Lock);



///
/// @brief        Release an already acquired spinlock
/// @param[in, out] Lock                             Address of the previously acquired lock that needs to be released
///
CX_VOID     FaUnlock(_Inout_ FA_LOCK *Lock);


//
// Public symbols offered by the allocator
//

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

typedef union
{
    struct
    {
        CX_UINT32  Index : 31;                          ///< index of the array element linked by this stack entry
        CX_UINT32  Empty : 1;                           ///< when 0, the Index field is considered valid (there exists an array entry linked to this stack entry) and otherwise it is invalid
    };
    CX_UINT32 Raw;
}FA_STACK_LIST;                                         ///< The free memory managed by an allocator is an array whose free entries are tracked by a stack of the free indexes (implemented inplace, over the same unused array entries)

typedef union _FA_ALLOCATOR
{
    // start with a header
    struct
    {
        // Entries array index of the last pushed element
        struct
        {
            volatile CX_UINT32  TotalEntries;           ///< 16 bits in fact but use 32 for avoiding arithmetic overflows
            CX_UINT32           TotalSize;
            CX_UINT16           ElementSize;            ///< how much memory each entry uses
            CX_UINT16           RawElementSize;         ///< the actually requested entry size
        }ManagedAllocations;

        struct
        {
            volatile CX_BOOL8   Failed;                 //< marked when a reallocation fails, used for avoiding needless retries
            CX_ONCE_INIT0       Init[FA_MAX_REALLOCS];  //< allow only one caller to enlarge the buffer (can't double in size more than 16 times without overflowing the 16-bit index)
            volatile CX_UINT32  Counter;                //< how many times did we enlarge the pool
            CX_UINT8            *NextAllocationsBuffer; //< pointer indicating where the next allocated buffer for the ManagedAllocations should be mapped
            CX_UINT8            *NextStackBuffer;       //< pointer indicating where the next allocated buffer for the ManagedAllocations should be mapped
        } Reallocs;

        volatile CX_UINT64      PushCount;              ///< track the total number of allocations
        volatile CX_UINT64      PopCount;               ///< track the all time total number of freed elements
        volatile FA_STACK_LIST  Tos;                    ///< head container for a stack entry always kept as the top-of-stack
        FA_LOCK Lock;                                   ///< synchronization lock for the whole array/stack/allocator
    } Header;

    // add the actual stack entries at the next page boundary and setup a label for the managed allocations buffer
    struct
    {
        CX_UINT8 _skip_aligned_header[CX_PAGE_SIZE_4K]; // IMPORTANT: keep this field updated when/if increasing the Header sub-structure past a single 4KB page !!!
        CX_UINT8  Allocations[1];                       ///< the array of constant-sized entries that are managed by this allocator
    };
}FA_ALLOCATOR;                                          ///< Data structure/descriptor defining an allocator and all of its properties
#pragma warning(pop)



///
/// @brief        Call this function to query the memory requirements and properties for a new allocator
/// @param[out]   MaxRequiredTotalVaSpace          Optional, will be filled with the total memory that might be committed at any time for a new allocator
/// @param[out]   MaxRequiredHeaderSize            Optional, will be filled with the maximum amount of memory needed for the allocator's metadata only
/// @param[out]   MaxRequiredDataVaSpace           Optional, will be filled with the maximum amount of memory needed for the allocator's actual data storage
/// @param[out]   MinMappedVaSpace                 Minimum amount of memory that would need backing physical memory
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
FaGetMemRequirements(
    _Out_opt_ CX_UINT32 *MaxRequiredTotalVaSpace,
    _Out_opt_ CX_UINT32 *MaxRequiredHeaderSize,
    _Out_opt_ CX_UINT32 *MaxRequiredDataVaSpace,
    _Out_opt_ CX_UINT32 *MinMappedVaSpace
)
{
    FA_ALLOCATOR *dummy = (FA_ALLOCATOR *)CX_NULL;

    CX_UINT32 totalHeaderSize   = CX_ROUND_UP(sizeof(dummy->Header), CX_PAGE_SIZE_4K);
    CX_UINT32 totalDataSize     = FA_STACK_MAX_MEM_PER_SIZE;

    if (MaxRequiredHeaderSize)   *MaxRequiredHeaderSize   = totalHeaderSize;
    if (MaxRequiredDataVaSpace)  *MaxRequiredDataVaSpace  = totalDataSize;
    if (MaxRequiredTotalVaSpace) *MaxRequiredTotalVaSpace = totalHeaderSize + totalDataSize;
    if (MinMappedVaSpace)        *MinMappedVaSpace        = totalHeaderSize;

    return CX_STATUS_SUCCESS;
}



///
/// @brief        Returns the minimum address of any allocations managed by this allocator (the address of the very first managed allocation array entry)
/// @param[in]    Allocator                        Address of an allocator structure
/// @returns      Minimum VA used for managing the memory pool of this allocator, corresponding to the address of the first managed array entry
///
__forceinline
CX_VOID*
FaGetDataVaStart(
    _In_ FA_ALLOCATOR *Allocator
)
{
    return &Allocator->Allocations[0];
}

CX_STATUS
FaCreate(
    _Out_opt_ FA_ALLOCATOR **Allocator, // needed unless an AlreadyReservedVa is given
    _In_ CX_UINT16 ElementSize,
    _In_opt_ CX_VOID *AlreadyReservedVa,
    _In_opt_ CX_UINT32 AlreadyReservedVaSize
);


CX_STATUS
FaAllocEx(
    _In_ FA_ALLOCATOR *Allocator,
    _Out_ CX_VOID **Data
);



///
/// @brief        Allocate a new element from this allocator. Use FaFree when done and the allocation is not needed anymore.
/// @param[in]    Allocator                        Address of the allocator descriptor
/// @param[out]   Data                             Address of a pointer that will receive the address of the new allocation
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
FaAlloc(
    _In_ FA_ALLOCATOR *Allocator,
    _Out_ CX_VOID **Data
)
{
    return FaAllocEx(Allocator, Data);
}


CX_STATUS
FaFreeEx(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *Data
);



///
/// @brief        Free an allocation obtained via a previous call to #FaAlloc, making the memory available to be allocated again at a later time.
/// @param[in]    Allocator                        Address of the allocator descriptor where the allocated memory resides
/// @param[in]    Data                             Address of the memory returned by a previous FaAlloc call
/// @returns      CX_STATUS_SUCCESS                on success
///
__forceinline
CX_STATUS
FaFree(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *Data
)
{
    return FaFreeEx(Allocator, Data);
}



///
/// @brief        Returns the internal array index corresponding to some Data allocated from the given Allocator
/// @param[in]    Allocator                        Allocator where Data has been allocated from
/// @param[in]    Data                             Pointer returned by a call to FaAlloc
/// @return       -1 if the Data address is foreign to this allocator or a non-negative value equal to the internal index corresponding to Data inside the managed array of elements
///
__forceinline
CX_INT32
FaGetAllocationIndex(
    _In_ FA_ALLOCATOR *Allocator,
    _In_ CX_VOID *Data
)
{
    CX_SIZE_T index = ((CX_SIZE_T)Data - (CX_SIZE_T)Allocator->Allocations) / Allocator->Header.ManagedAllocations.ElementSize;
    if (index >= Allocator->Header.ManagedAllocations.TotalEntries)
    {
        return -1;
    }
    return (CX_INT32)index;
}


#endif // _FALLOC_H_
/// @}
