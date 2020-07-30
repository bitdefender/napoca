/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// TODO: most of the declarations are generic enough to be moved to codex, some of them being already part of codex
// TODO2: should we avoid actually using the existing codex macros only due to their prefix?
//

#ifndef _CORE_DEFS_H_
#define _CORE_DEFS_H_

#include "cx_native.h"

typedef CX_STATUS NTSTATUS;

// these SUCCESS macros are customized by napocadefs.h when napoca.h or napocadefs.h are included
#define _SUCCESS                            CX_SUCCESS
#define NTSUCCESS                           CX_SUCCESS
#define NT_SUCCESS                          CX_SUCCESS
#define SUCCESS                             CX_SUCCESS


#if ((!defined PAGE_SIZE) || (defined PAGE_SIZE && (PAGE_SIZE != 0x1000ULL)))
#define PAGE_SIZE                           0x1000ULL
#endif

#define ONE_KILOBYTE                        CX_KILO
#define ONE_MEGABYTE                        CX_MEGA
#define ONE_GIGABYTE                        CX_GIGA
#define ONE_TERABYTE                        CX_TERA

#define PAGE_SIZE_2_MEGA                    (2 * ONE_MEGABYTE)
#define PAGE_SIZE_1_GIGA                    (1 * ONE_GIGABYTE)
#define PAGE_SHIFT                          12L
#define PAGE_MASK                           0xFFFFFFFFFFFFF000ULL
#define PAGE_OFFSET_MASK                    (PAGE_SIZE - 1)
#define PAGE_OFFSET_MASK_2_MEGA             (PAGE_SIZE_2_MEGA - 1)
#define PAGE_OFFSET_MASK_1_GIGA             (PAGE_SIZE_1_GIGA - 1)
#define PAGE_BASE_PA(adr)                   (((QWORD)((SIZE_T)adr)) & (QWORD)PAGE_PHYSICAL_MASK)
#define PAGE_BASE_VA(adr)                   (((QWORD)((SIZE_T)adr)) & (QWORD)PAGE_MASK)
#define PAGE_OFFSET(adr)                    (((QWORD)(adr)) & (QWORD)PAGE_OFFSET_MASK)
#define PAGE_COUNT(adr,bytes)               ((PAGE_BASE_VA(((QWORD)(adr)) + (bytes) + (PAGE_SIZE-1)) - PAGE_BASE_VA((QWORD)(adr)))/PAGE_SIZE)
#define PAGE_MAX_ADDR(adr,bytes)            (PAGE_BASE_VA((QWORD)(adr) + (bytes) - 1) + PAGE_SIZE - 1)

#define PAGE_FRAME(adr)                     ((adr) >> PAGE_SHIFT)

#define GET_BYTE(ptr,pos)                   (*((BYTE*)(((BYTE*)(ptr)) + (pos))))
#define GET_WORD(ptr,pos)                   (*((WORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_DWORD(ptr,pos)                  (*((DWORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_QWORD(ptr,pos)                  (*((QWORD*)(((BYTE*)(ptr)) + (pos))))
#define QWORD_AT(ptr, index)                (*((QWORD*)((BYTE *)(ptr) + (index))))
#define DWORD_AT(ptr, index)                (*((DWORD*)((BYTE *)(ptr) + (index))))

#define GET_VOLATILE_BYTE(ptr,pos)          (*((volatile BYTE*)(((BYTE*)(ptr)) + (pos))))
#define GET_VOLATILE_WORD(ptr,pos)          (*((volatile WORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_VOLATILE_DWORD(ptr,pos)         (*((volatile DWORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_VOLATILE_QWORD(ptr,pos)         (*((volatile QWORD*)(((BYTE*)(ptr)) + (pos))))

#define PUT_QWORD(ptr,pos,val)              *(QWORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_DWORD(ptr,pos,val)              *(DWORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_WORD(ptr,pos,val)               *(WORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_BYTE(ptr,pos,val)               *(BYTE*)((BYTE*)(ptr)+ (pos)) = (val)

#define PUT_VOLATILE_QWORD(ptr,pos,val)     *(volatile QWORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_VOLATILE_DWORD(ptr,pos,val)     *(volatile DWORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_VOLATILE_WORD(ptr,pos,val)      *(volatile WORD*)((BYTE*)(ptr)+ (pos)) = (val)
#define PUT_VOLATILE_BYTE(ptr,pos,val)      *(volatile BYTE*)((BYTE*)(ptr)+ (pos)) = (val)


#define BIT_AT(pos)                         ((QWORD)((QWORD)(1) << (QWORD)(pos)))
#define BIT_TEST(value, bitIdx)             ((value) & BIT_AT(bitIdx))
#define BITS(value, bitIdx, bitCount)       ((value)>>(bitIdx) & ((1 << (bitCount)) - 1))
#define FIELD_MASK(count)                   (0xFFFFFFFFFFFFFFFFULL >> (63 - (count)))
#define PTR_ADD(a,b)                        (PVOID)((SIZE_T)(a) + (SIZE_T)(b))
#define PTR_DELTA(a,b)                      (PVOID)((SIZE_T)(a) - (SIZE_T)(b))

#define BITRANGE_MASK(pos,count)            ((((QWORD)1 << (QWORD)(count)) - 1) << (QWORD)(pos))
#define BITRANGE_VAL(val,pos,count)         (((val) & BITRANGE_MASK((pos),(count))) >> (QWORD)(pos))

// checks for overlap between [start1, end1] vs [start2, end2]
#define DO_RANGES_OVERLAP(start1, end1, start2, end2) ((start1) <= (end2) && ((start2) <= (end1)))
// checks for overlap between [start1, start1 + size) vs [start2, start2 + size2)
#define DO_RANGES_OVERLAP_BY_SIZE(start1, size1, start2, size2)  ((start1) < ((start2) + (size2)) && (start2) < ((start1) + (size1)))


#ifdef NAPOCA_BUILD
__forceinline CX_UINT64 CpuGetMaxPhysicalAddress(CX_VOID);

#define PAGE_PHYSICAL_MASK                  (CpuGetMaxPhysicalAddress() & 0xFFFFFFFFFFFFF000ULL)
#define PAGE_PHYSICAL_MASK_2_MEGA           (CpuGetMaxPhysicalAddress() & 0xFFFFFFFFFFE00000ULL)
#define PAGE_PHYSICAL_MASK_1_GIGA           (CpuGetMaxPhysicalAddress() & 0xFFFFFFFFC0000000ULL)
#define VALID_PA(adr)                       (0 == ((~(QWORD)CpuGetMaxPhysicalAddress()) & (QWORD)adr))

#define ARRAYSIZE(A)                        (sizeof(A) / sizeof((A)[0]))
#define CLEAR_PHY_ADDR(x)                   (((x) & CpuGetMaxPhysicalAddress()) & 0xFFFFFFFFFFFFF000ULL)
#define BIT(n)                              (1ull << (n))
#define ABS_VAL(x)                          ((x) >= 0 ? (x) : -(x))
#define OVERLAPPED_RANGES(Start1, Size1, Start2, Size2) ( MAX((Start1), (Start2)) <= MIN(((Start1) + (Size1)), ((Start2) + (Size2))) )

#else
#define PAGE_PHYSICAL_MASK                  (0xFFFFFFFFFFFFF000ULL)
#define PAGE_PHYSICAL_MASK_2_MEGA           (0xFFFFFFFFFFE00000ULL)
#define PAGE_PHYSICAL_MASK_1_GIGA           (0xFFFFFFFFC0000000ULL)
#endif

//
// flag (single bit) and field (multiple bits) related macros
//
#define QueryFlag(Flag, Mask)               (((Flag) & (Mask)) != 0)
#define SetFlag(Flag, Mask)                 { (Flag) |= (Mask); }
#define ClearFlag(Flag, Mask)               { (Flag) &= (~Mask); }
#define QueryFlagStr(Flag, Mask)            (((Flag) & (Mask))?"TRUE":"")

// field related macros
#define QueryField(Flag, Mask, Value)       (((Flag) & (Mask)) == (Value))
#define CheckField(Flag, MaskValue)         (((Flag) & (MaskValue)) == (MaskValue))
#define GetField(Flag, Mask)                ((Flag) & (Mask))
#define SetField(Flag, Mask, Value)         { (Flag) &= (~Mask); (Flag) |= (Value); }
#define ClearField(Flag, Mask)              (Flag) &= (~Mask)

// interlocked flag (single bit) macros
#define QueryFlagInterlocked(Flag, Mask)    (((Flag) & (Mask)) != 0)        // we have no reason to use any

// interlocked stuff for a query
#define SetFlagInterlocked(Flag, Mask)      (VOID)InterlockedOr((volatile LONG*)&Flag, (Mask))      // we use & to be consistent with
#define ClearFlagInterlocked(Flag, Mask)    (VOID)InterlockedAnd((volatile LONG*)&Flag, ~(Mask))    // non-interlocked SetFlag() stuff




#endif //_CORE_DEFS_H_
