/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __HV_INTRIN_H__
#define __HV_INTRIN_H__


#define _MM_HINT_NTA    0
#define _MM_HINT_T0     1
#define _MM_HINT_T1     2
#define _MM_HINT_T2     3
#define _MM_HINT_ENTA   4

#include "core.h"

// define additional intrinsic functions
extern void __xsetbv(__int32 index, __int64 Value);
extern unsigned __int64 __xgetbv(unsigned int xcr);


__forceinline
unsigned __int64
HvInterlockedIncrementU64(
    _Inout_ volatile unsigned __int64 *Destination
)
{
    return (unsigned __int64)_InterlockedIncrement64((volatile __int64*)Destination);
}

__forceinline
unsigned __int32
HvInterlockedIncrementU32(
    _Inout_ volatile unsigned __int32 *Destination
)
{
    return (unsigned __int32)_InterlockedIncrement((volatile long*)Destination);
}

__forceinline
unsigned __int16
HvInterlockedIncrementU16(
    _Inout_ volatile unsigned __int16 *Destination
)
{
    return (unsigned __int16)_InterlockedIncrement16((volatile __int16*)Destination);
}

__forceinline
unsigned __int8
HvInterlockedIncrementU8(
    _Inout_ volatile unsigned __int8 *Destination
)
{
    unsigned __int8 oldValue;
    do
    {
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile __int8*)Destination, oldValue + 1, oldValue));
    return (unsigned __int8)(oldValue + 1);
}

__forceinline
unsigned __int64
HvInterlockedDecrementU64(
    _Inout_ volatile unsigned __int64 *Destination
)
{
    return (unsigned __int64)_InterlockedDecrement64((volatile __int64*)Destination);
}

__forceinline
unsigned __int32
HvInterlockedDecrementU32(
    _Inout_ volatile unsigned __int32 *Destination
)
{
    return (unsigned __int32)_InterlockedDecrement((volatile long*)Destination);
}

__forceinline
unsigned __int16
HvInterlockedDecrementU16(
    _Inout_ volatile unsigned __int16 *Destination
)
{
    return (unsigned __int16)_InterlockedDecrement16((volatile __int16*)Destination);
}

__forceinline
unsigned __int8
HvInterlockedDecrementU8(
    _Inout_ volatile unsigned __int8 *Destination
)
{
    unsigned __int8 oldValue;
    do
    {
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile __int8*)Destination, oldValue - 1, oldValue));
    return (unsigned __int8)(oldValue - 1);
}


__forceinline
__int64
HvInterlockedIncrementI64(
    _Inout_ volatile __int64 *Destination
)
{
    return (__int64)_InterlockedIncrement64((volatile __int64*)Destination);
}

__forceinline
__int32
HvInterlockedIncrementI32(
    _Inout_ volatile __int32 *Destination
)
{
    return (__int32)_InterlockedIncrement((volatile long*)Destination);
}

__forceinline
__int16
HvInterlockedIncrementI16(
    _Inout_ volatile __int16 *Destination
)
{
    return (__int16)_InterlockedIncrement16((volatile __int16*)Destination);
}

__forceinline
__int8
HvInterlockedIncrementI8(
    _Inout_ volatile __int8 *Destination
)
{
    __int8 oldValue;
    do
    {
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile __int8*)Destination, oldValue + 1, oldValue));
    return (__int8)(oldValue + 1);
}

__forceinline
__int64
HvInterlockedDecrementI64(
    _Inout_ volatile __int64 *Destination
)
{
    return (__int64)_InterlockedDecrement64((volatile __int64*)Destination);
}

__forceinline
__int32
HvInterlockedDecrementI32(
    _Inout_ volatile __int32 *Destination
)
{
    return (__int32)_InterlockedDecrement((volatile long*)Destination);
}

__forceinline
__int16
HvInterlockedDecrementI16(
    _Inout_ volatile __int16 *Destination
)
{
    return (__int16)_InterlockedDecrement16((volatile __int16*)Destination);
}

__forceinline
__int8
HvInterlockedDecrementI8(
    _Inout_ volatile __int8 *Destination
)
{
    __int8 oldValue;
    do
    {
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile __int8*)Destination, oldValue - 1, oldValue));
    return (__int8)(oldValue - 1);
}


__forceinline
unsigned __int64
HvInterlockedCompareExchangeU64(
    _Inout_ volatile unsigned __int64 *Destination,
    _In_ unsigned __int64 WantedNewValue,
    _In_ unsigned __int64 OldMandatoryValue
)
{
    return (unsigned __int64)_InterlockedCompareExchange64((volatile __int64*)Destination, (__int64)WantedNewValue, (__int64)OldMandatoryValue);
}

__forceinline
unsigned __int32
HvInterlockedCompareExchangeU32(
    _Inout_ volatile unsigned __int32 *Destination,
    _In_ unsigned __int32 WantedNewValue,
    _In_ unsigned __int32 OldMandatoryValue
)
{
    return (unsigned __int32)_InterlockedCompareExchange((volatile long*)Destination, (__int32)WantedNewValue, (__int32)OldMandatoryValue);
}

__forceinline
unsigned __int16
HvInterlockedCompareExchangeU16(
    _Inout_ volatile unsigned __int16 *Destination,
    _In_ unsigned __int16 WantedNewValue,
    _In_ unsigned __int16 OldMandatoryValue
)
{
    return (unsigned __int16)_InterlockedCompareExchange16((volatile __int16*)Destination, (__int16)WantedNewValue, (__int16)OldMandatoryValue);
}

__forceinline
unsigned __int8
HvInterlockedCompareExchangeU8(
    _Inout_ volatile unsigned __int8 *Destination,
    _In_ unsigned __int8 WantedNewValue,
    _In_ unsigned __int8 OldMandatoryValue
)
{
    return (unsigned __int8)_InterlockedCompareExchange8((volatile __int8*)Destination, (__int8)WantedNewValue, (__int8)OldMandatoryValue);
}

__forceinline
__int64
HvInterlockedCompareExchangeI64(
    _Inout_ volatile __int64 *Destination,
    _In_ __int64 WantedNewValue,
    _In_ __int64 OldMandatoryValue
)
{
    return (__int64)_InterlockedCompareExchange64((volatile __int64*)Destination, WantedNewValue, OldMandatoryValue);
}

__forceinline
__int32
HvInterlockedCompareExchangeI32(
    _Inout_ volatile __int32 *Destination,
    _In_ __int32 WantedNewValue,
    _In_ __int32 OldMandatoryValue
)
{
    return (__int32)_InterlockedCompareExchange((volatile long*)Destination, (__int32)WantedNewValue, (__int32)OldMandatoryValue);
}

__forceinline
__int16
HvInterlockedCompareExchangeI16(
    _Inout_ volatile __int16 *Destination,
    _In_ __int16 WantedNewValue,
    _In_ __int16 OldMandatoryValue
)
{
    return (__int16)_InterlockedCompareExchange16((volatile __int16*)Destination, (__int16)WantedNewValue, (__int16)OldMandatoryValue);
}

__forceinline
__int8
HvInterlockedCompareExchangeI8(
    _Inout_ volatile __int8 *Destination,
    _In_ __int8 WantedNewValue,
    _In_ __int8 OldMandatoryValue
)
{
    return (__int8)_InterlockedCompareExchange8((volatile __int8*)Destination, (__int8)WantedNewValue, (__int8)OldMandatoryValue);
}


__forceinline
unsigned __int64
HvInterlockedAddU64(
    _Inout_ volatile unsigned __int64 *Destination,
    _In_ unsigned __int64 AddedValue
)
{
    unsigned __int64 old;
    do
    {
        old = *Destination;
    } while (old != (unsigned __int64)_InterlockedCompareExchange64((volatile __int64*)Destination, (__int64)(old + AddedValue), (__int64)old));
    return (unsigned __int64)(old + AddedValue);
}

__forceinline
unsigned __int32
HvInterlockedAddU32(
    _Inout_ volatile unsigned __int32 *Destination,
    _In_ unsigned __int32 AddedValue
)
{
    unsigned __int32 old;
    do
    {
        old = *Destination;
    } while (old != (unsigned __int32)_InterlockedCompareExchange((volatile long*)Destination, (__int32)(old + AddedValue), (__int32)old));
    return (unsigned __int32)(old + AddedValue);
}

__forceinline
unsigned __int16
HvInterlockedAddU16(
    _Inout_ volatile unsigned __int16 *Destination,
    _In_ unsigned __int16 AddedValue
)
{
    unsigned __int16 old;
    do
    {
        old = *Destination;
    } while (old != (unsigned __int16)_InterlockedCompareExchange16((volatile __int16*)Destination, (__int16)(old + AddedValue), (__int16)old));
    return (unsigned __int16)(old + AddedValue);
}

__forceinline
unsigned __int8
HvInterlockedAddU8(
    _Inout_ volatile unsigned __int8 *Destination,
    _In_ unsigned __int8 AddedValue
)
{
    unsigned __int8 old;
    do
    {
        old = *Destination;
    } while (old != (unsigned __int8)_InterlockedCompareExchange8((volatile __int8*)Destination, (__int8)(old + AddedValue), (__int8)old));
    return (unsigned __int8)(old + AddedValue);
}


__forceinline
__int64
HvInterlockedAddI64(
    _Inout_ volatile __int64 *Destination,
    _In_ __int64 AddedValue
)
{
    __int64 old;
    do
    {
        old = *Destination;
    } while (old != (__int64)_InterlockedCompareExchange64((volatile __int64*)Destination, old + AddedValue, old));
    return (__int64)(old + AddedValue);
}

__forceinline
__int32
HvInterlockedAddI32(
    _Inout_ volatile __int32 *Destination,
    _In_ __int32 AddedValue
)
{
    __int32 old;
    do
    {
        old = *Destination;
    } while (old != (__int32)_InterlockedCompareExchange((volatile long*)Destination, old + AddedValue, old));
    return (__int32)(old + AddedValue);
}

__forceinline
__int16
HvInterlockedAddI16(
    _Inout_ volatile __int16 *Destination,
    _In_ __int16 AddedValue
)
{
    __int16 old;
    do
    {
        old = *Destination;
    } while (old != (__int16)_InterlockedCompareExchange16((volatile __int16*)Destination, old + AddedValue, old));
    return (__int16)(old + AddedValue);
}

__forceinline
__int8
HvInterlockedAddI8(
    _Inout_ volatile __int8 *Destination,
    _In_ __int8 AddedValue
)
{
    __int8 old;
    do
    {
        old = *Destination;
    } while (old != (__int8)_InterlockedCompareExchange8((volatile __int8*)Destination, old + AddedValue, old));
    return (__int8)(old + AddedValue);
}

__forceinline
unsigned __int8
HvInterlockedAndU8(
    _Inout_ unsigned __int8 volatile * Value,
    _In_ unsigned __int8 Mask
)
{
    return (unsigned __int8)_InterlockedAnd8((__int8 *)Value, (__int8)Mask);
}

__forceinline
unsigned __int16
HvInterlockedAndU16(
    _Inout_ unsigned __int16 volatile * Value,
    _In_ unsigned __int16 Mask
)
{
    return (unsigned __int16)_InterlockedAnd16((__int16 *)Value, (__int16)Mask);
}

__forceinline
unsigned __int32
HvInterlockedAndU32(
    _Inout_ unsigned __int32 volatile * Value,
    _In_ unsigned __int32 Mask
)
{
    return (unsigned __int32)_InterlockedAnd((long *)Value, (long)Mask);
}

__forceinline
unsigned __int64
HvInterlockedAndU64(
    _Inout_ unsigned __int64 volatile * Value,
    _In_ unsigned __int64 Mask
)
{
    return (unsigned __int64)_InterlockedAnd64((__int64 *)Value, (__int64)Mask);
}

__forceinline
__int8
HvInterlockedAndI8(
    _Inout_ __int8 volatile * Value,
    _In_ __int8 Mask
)
{
    return _InterlockedAnd8(Value, Mask);
}

__forceinline
__int16
HvInterlockedAndI16(
    _Inout_ __int16 volatile * Value,
    _In_ __int16 Mask
)
{
    return _InterlockedAnd16(Value, Mask);
}

__forceinline
__int32
HvInterlockedAndI32(
    _Inout_ __int32 volatile * Value,
    _In_ __int32 Mask
)
{
    return _InterlockedAnd((long*)Value, Mask);
}

__forceinline
__int64
HvInterlockedAndI64(
    _Inout_ __int64 volatile * Value,
    _In_ __int64 Mask
)
{
    return _InterlockedAnd64(Value, Mask);
}

__forceinline
unsigned __int8
HvBitTestI32(
    _Inout_ __int32 const *Value,
    _In_ __int32 BitIndex
)
{
    return _bittest((long*)Value, BitIndex);
}

__forceinline
unsigned __int8
HvBitTestU32(
    _Inout_ unsigned __int32 const *Value,
    _In_ unsigned __int32 BitIndex
)
{
    return _bittest((long*)Value, BitIndex);
}

__forceinline
unsigned __int8
HvInterlockedBitTestAndSetI32(
    _Inout_ __int32 volatile *Value,
    _In_ __int32 BitIndex
)
{
    return _interlockedbittestandset((long volatile*)Value, BitIndex);
}

__forceinline
unsigned __int8
HvInterlockedBitTestAndSetU32(
    _Inout_ unsigned __int32 volatile *Value,
    _In_ unsigned __int32 BitIndex
)
{
    return _interlockedbittestandset((long volatile*)Value, BitIndex);
}

__forceinline
unsigned __int8
HvInterlockedBitTestAndSetI64(
    _Inout_ __int64 volatile *Value,
    _In_ __int64 BitIndex // yes, a high-precision bit index encoded on a qword..
)
{
    return _interlockedbittestandset64((__int64 volatile*)Value, BitIndex);
}

__forceinline
unsigned __int8
HvInterlockedBitTestAndSetU64(
    _Inout_ unsigned __int64 volatile *Value,
    _In_ unsigned __int64 BitIndex // yes, a high-precision bit index encoded on a qword..
)
{
    return _interlockedbittestandset64((__int64 volatile*)Value, BitIndex);
}


__forceinline
unsigned char
HvInterlockedBitTestAndResetI32(
    _Inout_ __int32 volatile *Value,
    _In_ __int32 BitIndex
)
{
    return _interlockedbittestandreset((long volatile *)Value, BitIndex);
}

__forceinline
unsigned char
HvInterlockedBitTestAndResetU32(
    _Inout_ unsigned __int32 volatile *Value,
    _In_ unsigned __int32 BitIndex
)
{
    return _interlockedbittestandreset((long volatile *)Value, BitIndex);
}


__forceinline
unsigned char
HvInterlockedBitTestAndResetI64(
    _Inout_ __int64 volatile *Value,
    _In_ __int64 BitIndex
)
{
    return _interlockedbittestandreset64((long long volatile *)Value, BitIndex);
}

__forceinline
unsigned char
HvInterlockedBitTestAndResetU64(
    _Inout_ unsigned __int64 volatile *Value,
    _In_ unsigned __int64 BitIndex
)
{
    return _interlockedbittestandreset64((long long volatile *)Value, BitIndex);
}

__forceinline
unsigned char
HvBitScanReverseI32(
    _Inout_ __int32 *BitIndex,
    _In_ unsigned __int32 Value
)
{
    return _BitScanReverse((unsigned long *)BitIndex, Value);
}

__forceinline
unsigned char
HvBitScanReverseU32(
    _Inout_ unsigned __int32 *BitIndex,
    _In_ unsigned __int32 Value
)
{
    return _BitScanReverse((unsigned long *)BitIndex, Value);
}

// Microsoft intrinsics for BSR64 take a pointer to an unsigned long
// whilst the Intel documentation states that these instructions need
// an R64/MEM64 location so pointer to (unsigned) __int64
__forceinline
unsigned char
HvBitScanReverseI64(
    _Inout_ __int64 *BitIndex,
    _In_ unsigned __int64 Value
)
{
    return _BitScanReverse64((unsigned long*)BitIndex, Value);
}

__forceinline
unsigned char
HvBitScanReverseU64(
    _Inout_ unsigned __int64 *BitIndex,
    _In_ unsigned __int64 Value
)
{
    return _BitScanReverse64((unsigned long*)BitIndex, Value);
}

//unsigned char _BitScanForward64(unsigned long * _Index, unsigned __int64 _Mask)
__forceinline
unsigned char
HvBitScanForwardI64(
    _Inout_ __int32 *BitIndex,
    _In_ unsigned __int64 Value
)
{
    return _BitScanForward64((unsigned long *)BitIndex, Value);
}

__forceinline
unsigned char
HvBitScanForwardU64(
    _Inout_ unsigned __int32 *BitIndex,
    _In_ unsigned __int64 Value
)
{
    return _BitScanForward64((unsigned long *)BitIndex, Value);
}

__forceinline
unsigned char
HvBitScanForwardI32(
    _Inout_ __int32 *BitIndex,
    _In_ unsigned __int32 Value
)
{
    return _BitScanForward((unsigned long *)BitIndex, Value);
}

__forceinline
unsigned char
HvBitScanForwardU32(
    _Inout_ unsigned __int32 *BitIndex,
    _In_ unsigned __int32 Value
)
{
    return _BitScanForward((unsigned long *)BitIndex, Value);
}

// unsigned char _bittestandreset64(__int64 *, __int64)
__forceinline
unsigned char
HvBitTestAndSetI64(
    _Inout_ __int64 *Value,
    _In_ unsigned __int64 BitIndex
)
{
    return _bittestandset64(Value, (__int64)BitIndex);
}

__forceinline
unsigned char
HvBitTestAndSetU64(
    _Inout_ unsigned __int64 *Value,
    _In_ unsigned __int64 BitIndex
)
{
    return _bittestandset64((__int64 *)Value, (__int64)BitIndex);
}


__forceinline
unsigned char
HvBitTestAndResetI64(
    _Inout_ __int64 *Value,
    _In_ unsigned __int64 BitIndex
)
{
    return _bittestandreset64(Value, (__int64)BitIndex);
}

__forceinline
unsigned char
HvBitTestAndResetU64(
    _Inout_ unsigned __int64 *Value,
    _In_ unsigned __int64 BitIndex
)
{
    return _bittestandreset64((__int64 *)Value, (__int64)BitIndex);
}

//long __MACHINECALL_CDECL_OR_DEFAULT _InterlockedExchange(long volatile * _Target, long _Value)
__forceinline
__int32
HvInterlockedExchangeI8(
    _Inout_ __int8 volatile *Target,
    _In_ __int8 NewValue
)
{
    return (__int32)_InterlockedExchange8((__int8 volatile*)Target, (long)NewValue);
}

__forceinline
unsigned __int32
HvInterlockedExchangeU8(
    _Inout_ unsigned __int8 volatile *Target,
    _In_ unsigned __int8 NewValue
)
{
    return (unsigned)_InterlockedExchange8((__int8 volatile*)Target, (long)NewValue);
}

__forceinline
__int32
HvInterlockedExchangeI32(
    _Inout_ __int32 volatile *Target,
    _In_ __int32 NewValue
)
{
    return (__int32)_InterlockedExchange((long volatile*)Target, (long)NewValue);
}

__forceinline
unsigned __int32
HvInterlockedExchangeU32(
    _Inout_ unsigned __int32 volatile *Target,
    _In_ unsigned __int32 NewValue
)
{
    return (unsigned)_InterlockedExchange((long volatile*)Target, (long)NewValue);
}

__forceinline
__int64
HvInterlockedExchangeI64(
    _Inout_ __int64 volatile *Target,
    _In_ __int64 NewValue
)
{
    return _InterlockedExchange64((__int64 volatile *)Target, NewValue);
}

__forceinline
unsigned __int64
HvInterlockedExchangeU64(
    _Inout_ unsigned __int64 volatile *Target,
    _In_ unsigned __int64 NewValue
)
{
    return (unsigned __int64)_InterlockedExchange64((__int64 volatile *)Target, (__int64)NewValue);
}

__forceinline
unsigned __int32
HvInterlockedOrU32(
    _Inout_ unsigned __int32 volatile *Value,
    _In_ unsigned __int32 volatile Mask
)
{
    return (unsigned __int32)_InterlockedOr((long volatile*)Value, Mask);
}

// __int64 _InterlockedOr64(__int64 volatile * _Value, __int64 _Mask)
__forceinline
__int64
HvInterlockedOrI64(
    _Inout_ __int64 volatile *Value,
    _In_ __int64 volatile Mask
)
{
    return _InterlockedOr64(Value, Mask);
}

__forceinline
unsigned __int64
HvInterlockedOrU64(
    _Inout_ unsigned __int64 volatile *Value,
    _In_ unsigned __int64 volatile Mask
)
{
    return (unsigned __int64)_InterlockedOr64((__int64 volatile *)Value, Mask);
}

__forceinline
__int64
HvImul128(
    _In_    __int64    Multiplier,
    _In_    __int64    Multiplicand,
    _Out_   __int64    *HighProduct
)
{
    return _mul128(Multiplier, Multiplicand, HighProduct);
}

__forceinline
unsigned __int64
HvMul128(
    _In_    unsigned __int64    Multiplier,
    _In_    unsigned __int64    Multiplicand,
    _Out_   unsigned __int64    *HighProduct
)
{
    return _umul128(Multiplier, Multiplicand, HighProduct);
}

#endif //__HV_INTRIN_H__
