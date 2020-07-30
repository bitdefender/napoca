/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Generic symbolic definitions to provide added semantics throughout the code
//

#ifndef _CX_DEFS_H_
#define _CX_DEFS_H_

//
// Constants
//

#define CX_TRUE                             1
#define CX_FALSE                            0

#define CX_NULL                             0

#define CX_KILO                             1024ULL
#define CX_MEGA                             (CX_KILO * CX_KILO)
#define CX_GIGA                             (CX_KILO * CX_MEGA)
#define CX_TERA                             (CX_KILO * CX_GIGA)
#define CX_PETA                             (CX_KILO * CX_TERA)
#define CX_EXA                              (CX_KILO * CX_PETA)

//
// Math
//

#define CX_MIN(a, b)                        ((a) < (b) ? (a) : (b))
#define CX_MAX(a, b)                        ((a) > (b) ? (a) : (b))
#define CX_ABS(a)                           ((a) >= 0 ? (a) : -(a))

#define CX_ROUND_UP(what, to)               ((to) * (((what) + ((to) - 1)) / (to)))
#define CX_ROUND_DOWN(what, to)             ((to) * ((what) / (to)))
#define CX_IS_ALIGNED(what, to)             ((what) % (to) == 0)

//
// Memory
//

#define CX_COUNTOF(Array)                           (sizeof(Array) / sizeof(Array[0]))

#define CX_BIT(b)                                   (1ULL << (b))
#define CX_BITFIELD(BitPos1, BitPos2)               (1 + (((BitPos1) >= (BitPos2))? (BitPos1) - (BitPos2) : (BitPos2) - (BitPos1)))
#define CX_BITRANGE_MASK(leftShift, count)          (((1ULL << (count)) - 1) << (leftShift))
#define CX_BITRANGE_VAL(source, leftShift, count)   (((source) & CX_BITRANGE_MASK((leftShift),(count))) >> (leftShift))

#define CX_FIELD_OFFSET(type, field)                ((CX_SIZE_T)(&((type *)0)->field))
#define CX_CONTAINING_RECORD(ptr, type, field)      ((type *)((CX_SIZE_T)(ptr) - CX_FIELD_OFFSET(type, field)))
#define CX_FIELD_SIZE(type, field)                  (sizeof(((type *)0)->field))

#define CX_PTR_ADD(a, b)                            (CX_VOID*)((CX_SIZE_T)(a) + (CX_SIZE_T)(b))
#define CX_PTR_SUB(a, b)                            (CX_VOID*)((CX_SIZE_T)(a) - (CX_SIZE_T)(b))

#define CX_RANGES_OVERLAP(start1, end1, start2, end2)               ((start1) <= (end2) && ((start2) <= (end1)))
#define CX_RANGES_OVERLAP_BY_SIZE(start1, size1, start2, size2)     CX_RANGES_OVERLAP((CX_SIZE_T)start1, (CX_SIZE_T)start1 + (CX_SIZE_T)size1, (CX_SIZE_T)start2, (CX_SIZE_T)start2 + (CX_SIZE_T)size2)

#define CX_READ_UINT8(ptr, offset)                  (               ((CX_UINT8 *)(ptr))[offset])
#define CX_READ_UINT16(ptr, offset)                 (*(CX_UINT16 *)&((CX_UINT8 *)(ptr))[offset])
#define CX_READ_UINT32(ptr, offset)                 (*(CX_UINT32 *)&((CX_UINT8 *)(ptr))[offset])
#define CX_READ_UINT64(ptr, offset)                 (*(CX_UINT64 *)&((CX_UINT8 *)(ptr))[offset])

#define CX_READ_VOLATILE_UINT8(ptr, offset)         (*(CX_UINT8  volatile *)&(((CX_UINT8 *)(ptr))[offset]))
#define CX_READ_VOLATILE_UINT16(ptr, offset)        (*(CX_UINT16 volatile *)&(((CX_UINT8 *)(ptr))[offset]))
#define CX_READ_VOLATILE_UINT32(ptr, offset)        (*(CX_UINT32 volatile *)&(((CX_UINT8 *)(ptr))[offset]))
#define CX_READ_VOLATILE_UINT64(ptr, offset)        (*(CX_UINT64 volatile *)&(((CX_UINT8 *)(ptr))[offset]))

#define CX_WRITE_UINT8(ptr, offset, val)            (                ((CX_UINT8 *)(ptr))[offset]  = val)
#define CX_WRITE_UINT16(ptr, offset, val)           (*(CX_UINT16 *)&(((CX_UINT8 *)(ptr))[offset]) = val)
#define CX_WRITE_UINT32(ptr, offset, val)           (*(CX_UINT32 *)&(((CX_UINT8 *)(ptr))[offset]) = val)
#define CX_WRITE_UINT64(ptr, offset, val)           (*(CX_UINT64 *)&(((CX_UINT8 *)(ptr))[offset]) = val)

#define CX_WRITE_VOLATILE_UINT8(ptr, offset, val)   (*(CX_UINT8  volatile *)&(((CX_UINT8 *)(ptr))[offset]) = val)
#define CX_WRITE_VOLATILE_UINT16(ptr, offset, val)  (*(CX_UINT16 volatile *)&(((CX_UINT8 *)(ptr))[offset]) = val)
#define CX_WRITE_VOLATILE_UINT32(ptr, offset, val)  (*(CX_UINT32 volatile *)&(((CX_UINT8 *)(ptr))[offset]) = val)
#define CX_WRITE_VOLATILE_UINT64(ptr, offset, val)  (*(CX_UINT64 volatile *)&(((CX_UINT8 *)(ptr))[offset]) = val)

//
// Paging
//

#define CX_PAGE_SIZE_4K                     (4 * CX_KILO)
#define CX_PAGE_OFFSET_MASK_4K              (CX_PAGE_SIZE_4K - 1)
#define CX_PAGE_MAX_OFFSET_4K               CX_PAGE_OFFSET_MASK_4K
#define CX_PAGE_BASE_MASK_4K                (0xFFFFFFFFFFFFFFFFULL - CX_PAGE_MAX_OFFSET_4K)
#define CX_PAGE_BASE_4K(addr)               ((addr) & CX_PAGE_BASE_MASK_4K)
#define CX_PAGE_OFFSET_4K(addr)             ((addr) & CX_PAGE_OFFSET_MASK_4K)
#define CX_PAGE_FRAME_NUMBER_4K(addr)       ((addr) >> 12ULL) // 12 = log2(CX_PAGE_SIZE_4K)
#define CX_PAGE_COUNT_4K(addr, bytes)       (CX_PAGE_FRAME_NUMBER_4K(CX_PAGE_OFFSET_4K(addr) + (bytes) + CX_PAGE_MAX_OFFSET_4K))


#define CX_PAGE_SIZE_2M                     (2 * CX_MEGA)
#define CX_PAGE_OFFSET_MASK_2M              (CX_PAGE_SIZE_2M - 1)
#define CX_PAGE_MAX_OFFSET_2M               CX_PAGE_OFFSET_MASK_2M
#define CX_PAGE_BASE_MASK_2M                (0xFFFFFFFFFFFFFFFFULL - CX_PAGE_MAX_OFFSET_2M)
#define CX_PAGE_BASE_2M(addr)               ((addr) & CX_PAGE_BASE_MASK_2M)
#define CX_PAGE_OFFSET_2M(addr)             ((addr) & CX_PAGE_OFFSET_MASK_2M)
#define CX_PAGE_FRAME_NUMBER_2M(addr)       ((addr) >> 21ULL) // 21 = log2(CX_PAGE_SIZE_2M)
#define CX_PAGE_COUNT_2M(addr, bytes)       (CX_PAGE_FRAME_NUMBER_2M(CX_PAGE_OFFSET_2M(addr) + (bytes) + CX_PAGE_MAX_OFFSET_2M))


#define CX_PAGE_SIZE_4M                     (4 * CX_MEGA)
#define CX_PAGE_OFFSET_MASK_4M              (CX_PAGE_SIZE_4M - 1)
#define CX_PAGE_MAX_OFFSET_4M               CX_PAGE_OFFSET_MASK_4M
#define CX_PAGE_BASE_MASK_4M                (0xFFFFFFFFFFFFFFFFULL - CX_PAGE_MAX_OFFSET_4M)
#define CX_PAGE_BASE_4M(addr)               ((addr) & CX_PAGE_BASE_MASK_4M)
#define CX_PAGE_OFFSET_4M(addr)             ((addr) & CX_PAGE_OFFSET_MASK_4M)
#define CX_PAGE_FRAME_NUMBER_4M(addr)       ((addr) >> 22ULL) // 22 = log2(CX_PAGE_SIZE_4M)
#define CX_PAGE_COUNT_4M(addr, bytes)       (CX_PAGE_FRAME_NUMBER_4M(CX_PAGE_OFFSET_4M(addr) + (bytes) + CX_PAGE_MAX_OFFSET_4M))


#define CX_PAGE_SIZE_1G                     (CX_GIGA)
#define CX_PAGE_OFFSET_MASK_1G              (CX_PAGE_SIZE_1G - 1)
#define CX_PAGE_MAX_OFFSET_1G               CX_PAGE_OFFSET_MASK_1G
#define CX_PAGE_BASE_MASK_1G                (0xFFFFFFFFFFFFFFFFULL - CX_PAGE_MAX_OFFSET_1G)
#define CX_PAGE_BASE_1G(addr)               ((addr) & CX_PAGE_BASE_MASK_1G)
#define CX_PAGE_OFFSET_1G(addr)             ((addr) & CX_PAGE_OFFSET_MASK_1G)
#define CX_PAGE_FRAME_NUMBER_1G(addr)       ((addr) >> 30ULL) // 30 = log2(CX_PAGE_SIZE_1G)
#define CX_PAGE_COUNT_1G(addr, bytes)       (CX_PAGE_FRAME_NUMBER_1G(CX_PAGE_OFFSET_1G(addr) + (bytes) + CX_PAGE_MAX_OFFSET_1G))

//
// Other
//

#define _CX_STRINGIFY_HELPER(val)           #val                        // helper that ensures that other macros sent as parameter get expanded
#define CX_STRINGIFY(val)                   _CX_STRINGIFY_HELPER(val)   // converts a static value to CHAR string

#define _CX_WIDEN_HELPER(str)               L ## str                    // helper that ensures that other macros sent as parameter get expanded
#define CX_WIDEN(str)                       _CX_WIDEN_HELPER(str)       // converts a static CHAR string to WCHAR

#define CX_STATIC_STRING_LENGTH(str)        (CX_COUNTOF(str) - 1)

#define CX_EMPTY(...)                       (__VA_ARGS__)
#define CX_UNREFERENCED_SYMBOL(...)         CX_EMPTY(__VA_ARGS__)
#define CX_UNREFERENCED_PARAMETER(...)      CX_UNREFERENCED_SYMBOL(__VA_ARGS__)
#define CX_UNREFERENCED_LOCAL_VARIABLE(...) CX_UNREFERENCED_SYMBOL(__VA_ARGS__)


#endif // _CX_DEFS_H_
