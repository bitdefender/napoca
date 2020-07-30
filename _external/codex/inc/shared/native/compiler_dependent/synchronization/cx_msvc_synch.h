/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_VCSYNCH_H_
#define _CX_VCSYNCH_H_

#include "cx_native.h"
#include "base/cx_synchronization.h"
#include "base/cx_intrin.h"
typedef volatile CX_UINT8 CX_ONCE_INIT0;

//
// CxInterlockedExchange*
//
__forceinline
CX_INT8
CxInterlockedExchangeInt8(_Inout_ CX_INT8 volatile* Target, CX_INT8 Value)
{
    return (CX_INT8)_InterlockedExchange8((char volatile*)Target, (char)Value);
}

__forceinline
CX_INT16
CxInterlockedExchangeInt16(_Inout_ CX_INT16 volatile* Target, CX_INT16 Value)
{
    return (CX_INT16)_InterlockedExchange16((short volatile*)Target, (short)Value);
}

__forceinline
CX_INT32
CxInterlockedExchangeInt32(_Inout_ CX_INT32 volatile* Target, CX_INT32 Value)
{
    return (CX_INT32)_InterlockedExchange((long volatile*)Target, (long)Value);
}

__forceinline
CX_INT64
CxInterlockedExchangeInt64(_Inout_ CX_INT64 volatile* Target, CX_INT64 Value)
{
    return (CX_INT32)_InterlockedExchange64((__int64 volatile*)Target, (__int64)Value);
}

__forceinline
CX_UINT8
CxInterlockedExchange8(_Inout_ CX_UINT8 volatile* Target, CX_UINT8 Value)
{
    return (CX_UINT8)_InterlockedExchange8((char volatile*)Target, (char)Value);
}

__forceinline
CX_UINT16
CxInterlockedExchange16(_Inout_ CX_UINT16 volatile* Target, CX_UINT16 Value)
{
    return (CX_UINT16)_InterlockedExchange16((short volatile*)Target, (short)Value);
}

__forceinline
CX_UINT32
CxInterlockedExchange32(_Inout_ CX_UINT32 volatile* Target, CX_UINT32 Value)
{
    return (CX_UINT32)_InterlockedExchange((long volatile*)Target, (long)Value);
}

__forceinline
CX_UINT64
CxInterlockedExchange64(_Inout_ CX_UINT64 volatile* Target, CX_UINT64 Value)
{
    return (CX_UINT64)_InterlockedExchange64((__int64 volatile*)Target, (__int64)Value);
}

//
// CxInterlockedAnd*
//
__forceinline
CX_INT8
CxInterlockedAndInt8(CX_INT8 volatile* _Value, CX_INT8 Mask)
{
    return (CX_INT8)_InterlockedAnd8((char volatile *)_Value, (char)Mask);
}

__forceinline
CX_INT16
CxInterlockedAndInt16(CX_INT16 volatile* _Value, CX_INT16 Mask)
{
    return (CX_INT16)_InterlockedAnd16((short volatile *)_Value, (short)Mask);
}

__forceinline
CX_INT32
CxInterlockedAndInt32(CX_INT32 volatile* _Value, CX_INT32 Mask)
{
    return (CX_INT32)_InterlockedAnd((long volatile *)_Value, (long)Mask);
}

__forceinline
CX_INT64
CxInterlockedAndInt64(CX_INT64 volatile* _Value, CX_INT64 Mask)
{
    return (CX_INT64)_InterlockedAnd64((__int64 volatile *)_Value, (__int64)Mask);
}



__forceinline
CX_UINT8
CxInterlockedAnd8(CX_UINT8 volatile* _Value, CX_UINT8 Mask)
{
    return (CX_UINT8)_InterlockedAnd8((char volatile *)_Value, (char)Mask);
}

__forceinline
CX_UINT16
CxInterlockedAnd16(CX_UINT16 volatile* _Value, CX_UINT16 Mask)
{
    return (CX_UINT16)_InterlockedAnd16((short volatile *)_Value, (short)Mask);
}

__forceinline
CX_UINT32
CxInterlockedAnd32(CX_UINT32 volatile* _Value, CX_UINT32 Mask)
{
    return (CX_UINT32)_InterlockedAnd((long volatile *)_Value, (long)Mask);
}
__forceinline
CX_UINT64
CxInterlockedAnd64(CX_UINT64 volatile* _Value, CX_UINT64 Mask)
{
    return (CX_INT64)_InterlockedAnd64((__int64 volatile *)_Value, (__int64)Mask);
}



//
// CxInterlockedOr*
//
__forceinline
CX_INT8
CxInterlockedOrInt8(CX_INT8 volatile* _Value, CX_INT8 Mask)
{
    return (CX_INT8)_InterlockedOr8((char volatile *)_Value, (char)Mask);
}

__forceinline
CX_INT16
CxInterlockedOrInt16(CX_INT16 volatile* _Value, CX_INT16 Mask)
{
    return (CX_INT16)_InterlockedOr16((short volatile *)_Value, (short)Mask);
}

__forceinline
CX_INT32
CxInterlockedOrInt32(CX_INT32 volatile* _Value, CX_INT32 Mask)
{
    return (CX_INT32)_InterlockedOr((long volatile *)_Value, (long)Mask);
}

__forceinline
CX_INT64
CxInterlockedOrInt64(CX_INT64 volatile* _Value, CX_INT64 Mask)
{
    return (CX_INT64)_InterlockedOr64((__int64 volatile *)_Value, (__int64)Mask);
}



__forceinline
CX_UINT8
CxInterlockedOr8(CX_UINT8 volatile* _Value, CX_UINT8 Mask)
{
    return (CX_UINT8)_InterlockedOr8((char volatile *)_Value, (char)Mask);
}

__forceinline
CX_UINT16
CxInterlockedOr16(CX_UINT16 volatile* _Value, CX_UINT16 Mask)
{
    return (CX_UINT16)_InterlockedOr16((short volatile *)_Value, (short)Mask);
}

__forceinline
CX_UINT32
CxInterlockedOr32(CX_UINT32 volatile* _Value, CX_UINT32 Mask)
{
    return (CX_UINT32)_InterlockedOr((long volatile *)_Value, (long)Mask);
}
__forceinline
CX_UINT64
CxInterlockedOr64(CX_UINT64 volatile* _Value, CX_UINT64 Mask)
{
    return (CX_INT64)_InterlockedOr64((__int64 volatile *)_Value, (__int64)Mask);
}


//
// CxInterlockedIncrement*
//
__forceinline
CX_UINT64
CxInterlockedIncrement64(
    _Inout_ volatile CX_UINT64 *Destination
)
{
    return (CX_UINT64)_InterlockedIncrement64((volatile CX_INT64*)Destination);
}

__forceinline
CX_UINT32
CxInterlockedIncrement32(
    _Inout_ volatile CX_UINT32 *Destination
)
{
    return (CX_UINT32)_InterlockedIncrement((volatile long*)Destination);
}

__forceinline
CX_UINT16
CxInterlockedIncrement16(
    _Inout_ volatile CX_UINT16 *Destination
)
{
    return (CX_UINT16)_InterlockedIncrement16((volatile CX_INT16*)Destination);
}

__forceinline
CX_UINT8
CxInterlockedIncrement8(
    _Inout_ volatile CX_UINT8 *Destination
)
{
    CX_UINT8 oldValue;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile CX_INT8*)Destination, oldValue + 1, oldValue));
    return (CX_UINT8)(oldValue + 1);
}


__forceinline
CX_SIZE_T
CxInterlockedIncrementSizeT(
    _Inout_ volatile CX_SIZE_T *Destination
)
{
#ifdef CX_ARCH32
    return CxInterlockedIncrement32((CX_UINT32*)Destination);
#else
    return CxInterlockedIncrement64((CX_UINT64*)Destination);
#endif
}

__forceinline
CX_UINT64
CxInterlockedDecrement64(
    _Inout_ volatile CX_UINT64 *Destination
)
{
    return (CX_UINT64)_InterlockedDecrement64((volatile CX_INT64*)Destination);
}

__forceinline
CX_UINT32
CxInterlockedDecrement32(
    _Inout_ volatile CX_UINT32 *Destination
)
{
    return (CX_UINT32)_InterlockedDecrement((volatile long*)Destination);
}

__forceinline
CX_UINT16
CxInterlockedDecrement16(
    _Inout_ volatile CX_UINT16 *Destination
)
{
    return (CX_UINT16)_InterlockedDecrement16((volatile CX_INT16*)Destination);
}

__forceinline
CX_UINT8
CxInterlockedDecrement8(
    _Inout_ volatile CX_UINT8 *Destination
)
{
    CX_UINT8 oldValue;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile CX_INT8*)Destination, oldValue - 1, oldValue));
    return (CX_UINT8)(oldValue - 1);
}

__forceinline
CX_SIZE_T
CxInterlockedDecrementSizeT(
    _Inout_ volatile CX_SIZE_T *Destination
)
{
#ifdef CX_ARCH32
    return CxInterlockedDecrement32((CX_UINT32*)Destination);
#else
    return CxInterlockedDecrement64((CX_UINT64*)Destination);
#endif
}

__forceinline
CX_INT64
CxInterlockedIncrementInt64(
    _Inout_ volatile CX_INT64 *Destination
)
{
    return (CX_INT64)_InterlockedIncrement64((volatile CX_INT64*)Destination);
}

__forceinline
CX_INT32
CxInterlockedIncrementInt32(
    _Inout_ volatile CX_INT32 *Destination
)
{
    return (CX_INT32)_InterlockedIncrement((volatile long*)Destination);
}

__forceinline
CX_INT16
CxInterlockedIncrementInt16(
    _Inout_ volatile CX_INT16 *Destination
)
{
    return (CX_INT16)_InterlockedIncrement16((volatile CX_INT16*)Destination);
}

__forceinline
CX_INT8
CxInterlockedIncrementInt8(
    _Inout_ volatile CX_INT8 *Destination
)
{
    CX_INT8 oldValue;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile CX_INT8*)Destination, oldValue + 1, oldValue));
    return (CX_INT8)(oldValue + 1);
}

__forceinline
CX_SSIZE_T
CxInterlockedIncrementSSizeT(
    _Inout_ volatile CX_SSIZE_T *Destination
)
{
#ifdef CX_ARCH32
    return CxInterlockedIncrementInt32((CX_INT32*)Destination);
#else
    return CxInterlockedIncrementInt64((CX_INT64*)Destination);
#endif
}

__forceinline
CX_INT64
CxInterlockedDecrementInt64(
    _Inout_ volatile CX_INT64 *Destination
)
{
    return (CX_INT64)_InterlockedDecrement64((volatile CX_INT64*)Destination);
}

__forceinline
CX_INT32
CxInterlockedDecrementInt32(
    _Inout_ volatile CX_INT32 *Destination
)
{
    return (CX_INT32)_InterlockedDecrement((volatile long*)Destination);
}

__forceinline
CX_INT16
CxInterlockedDecrementInt16(
    _Inout_ volatile CX_INT16 *Destination
)
{
    return (CX_INT16)_InterlockedDecrement16((volatile CX_INT16*)Destination);
}

__forceinline
CX_INT8
CxInterlockedDecrementInt8(
    _Inout_ volatile CX_INT8 *Destination
)
{
    CX_INT8 oldValue;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        oldValue = *Destination;
    } while (oldValue != _InterlockedCompareExchange8((volatile CX_INT8*)Destination, oldValue - 1, oldValue));
    return (CX_INT8)(oldValue - 1);
}

__forceinline
CX_SSIZE_T
CxInterlockedDecrementSSizeT(
    _Inout_ volatile CX_SSIZE_T *Destination
)
{
#ifdef CX_ARCH32
    return CxInterlockedDecrementInt32((CX_INT32*)Destination);
#else
    return CxInterlockedDecrementInt64((CX_INT64*)Destination);
#endif
}


__forceinline
CX_UINT64
CxInterlockedCompareExchange64(
    _Inout_ volatile CX_UINT64 *Destination,
    _In_ CX_UINT64 WantedNewValue,
    _In_ CX_UINT64 OldMandatoryValue
)
{
    return (CX_UINT64)_InterlockedCompareExchange64((volatile CX_INT64*)Destination, (CX_INT64)WantedNewValue, (CX_INT64)OldMandatoryValue);
}

__forceinline
CX_BOOL
CxInterlockedCompareExchange128(
    _Inout_ volatile CX_UINT64 *Destination128,
    _In_ CX_UINT64 WantedNewValueHighPart,
    _In_ CX_UINT64 WantedNewValueLowPart,
    _In_ CX_UINT64 const *OldMandatoryValue128
)
{
    return _InterlockedCompareExchange128(
        (volatile long long *)Destination128,
        (long long)WantedNewValueHighPart,
        (long long)WantedNewValueLowPart,
        (long long *)OldMandatoryValue128);
}



__forceinline
CX_UINT32
CxInterlockedCompareExchange32(
    _Inout_ volatile CX_UINT32 *Destination,
    _In_ CX_UINT32 WantedNewValue,
    _In_ CX_UINT32 OldMandatoryValue
)
{
    return (CX_UINT32)_InterlockedCompareExchange((volatile long*)Destination, (CX_INT32)WantedNewValue, (CX_INT32)OldMandatoryValue);
}

__forceinline
CX_UINT16
CxInterlockedCompareExchange16(
    _Inout_ volatile CX_UINT16 *Destination,
    _In_ CX_UINT16 WantedNewValue,
    _In_ CX_UINT16 OldMandatoryValue
)
{
    return (CX_UINT16)_InterlockedCompareExchange16((volatile CX_INT16*)Destination, (CX_INT16)WantedNewValue, (CX_INT16)OldMandatoryValue);
}

__forceinline
CX_UINT8
CxInterlockedCompareExchange8(
    _Inout_ volatile CX_UINT8 *Destination,
    _In_ CX_UINT8 WantedNewValue,
    _In_ CX_UINT8 OldMandatoryValue
)
{
    return (CX_UINT8)_InterlockedCompareExchange8((volatile CX_INT8*)Destination, (CX_INT8)WantedNewValue, (CX_INT8)OldMandatoryValue);
}

__forceinline
CX_SIZE_T
CxInterlockedCompareExchangeSizeT(
    _Inout_ volatile CX_SIZE_T *Destination,
    _In_ CX_SIZE_T WantedNewValue,
    _In_ CX_SIZE_T OldMandatoryValue
)
{
#ifdef CX_ARCH32
    return (CX_SIZE_T)CxInterlockedCompareExchange32((CX_UINT32*)Destination, (CX_UINT32)WantedNewValue, (CX_UINT32)OldMandatoryValue);
#else
    return (CX_SIZE_T)CxInterlockedCompareExchange64((CX_UINT64*)Destination, (CX_UINT64)WantedNewValue, (CX_UINT64)OldMandatoryValue);
#endif
}


__forceinline
_Ret_writes_((Unknown))
CX_VOID *
CxInterlockedCompareExchangePointer(
    _Inout_ _At_(*Destination,
        _Pre_writable_byte_size_((Unknown))
        _Post_writable_byte_size_((Unknown)))
     PCX_VOID volatile *Destination,
    _In_opt_ PCX_VOID WantedNewValue,
    _In_opt_ PCX_VOID OldMandatoryValue
)
{
#ifdef CX_ARCH32
    return (CX_VOID*)(CX_SIZE_T)CxInterlockedCompareExchange32((CX_UINT32*)(CX_SIZE_T)Destination, (CX_UINT32)(CX_SIZE_T)WantedNewValue, (CX_UINT32)(CX_SIZE_T)OldMandatoryValue);
#else
    return (CX_VOID*)(CX_SIZE_T)CxInterlockedCompareExchange64((CX_UINT64*)(CX_SIZE_T)Destination, (CX_UINT64)(CX_SIZE_T)WantedNewValue, (CX_UINT64)(CX_SIZE_T)OldMandatoryValue);
#endif
}

__forceinline
CX_INT64
CxInterlockedCompareExchangeInt64(
    _Inout_ volatile CX_INT64 *Destination,
    _In_ CX_INT64 WantedNewValue,
    _In_ CX_INT64 OldMandatoryValue
)
{
    return (CX_INT64)_InterlockedCompareExchange64((volatile CX_INT64*)Destination, WantedNewValue, OldMandatoryValue);
}

__forceinline
CX_INT32
CxInterlockedCompareExchangeInt32(
    _Inout_ volatile CX_INT32 *Destination,
    _In_ CX_INT32 WantedNewValue,
    _In_ CX_INT32 OldMandatoryValue
)
{
    return (CX_INT32)_InterlockedCompareExchange((volatile long*)Destination, (CX_INT32)WantedNewValue, (CX_INT32)OldMandatoryValue);
}

__forceinline
CX_INT16
CxInterlockedCompareExchangeInt16(
    _Inout_ volatile CX_INT16 *Destination,
    _In_ CX_INT16 WantedNewValue,
    _In_ CX_INT16 OldMandatoryValue
)
{
    return (CX_INT16)_InterlockedCompareExchange16((volatile CX_INT16*)Destination, (CX_INT16)WantedNewValue, (CX_INT16)OldMandatoryValue);
}

__forceinline
CX_INT8
CxInterlockedCompareExchangeInt8(
    _Inout_ volatile CX_INT8 *Destination,
    _In_ CX_INT8 WantedNewValue,
    _In_ CX_INT8 OldMandatoryValue
)
{
    return (CX_INT8)_InterlockedCompareExchange8((volatile CX_INT8*)Destination, (CX_INT8)WantedNewValue, (CX_INT8)OldMandatoryValue);
}

__forceinline
CX_SSIZE_T
CxInterlockedCompareExchangeSSizeT(
    _Inout_ volatile CX_SSIZE_T *Destination,
    _In_ CX_SSIZE_T WantedNewValue,
    _In_ CX_SSIZE_T OldMandatoryValue
)
{
#ifdef CX_ARCH32
    return CxInterlockedCompareExchangeInt32((CX_INT32*)Destination, (CX_INT32)WantedNewValue, (CX_INT32)OldMandatoryValue);
#else
    return CxInterlockedCompareExchangeInt64((CX_INT64*)Destination, (CX_INT64)WantedNewValue, (CX_INT64)OldMandatoryValue);
#endif
}

__forceinline
CX_BOOL
CxInterlockedCompareExchangeInt128(
    _Inout_ volatile CX_INT64 *Destination128,
    _In_ CX_INT64 WantedNewValueHighPart,
    _In_ CX_INT64 WantedNewValueLowPart,
    _In_ CX_INT64 const *OldMandatoryValue128
)
{
    return _InterlockedCompareExchange128(
        (volatile long long *)Destination128,
        (long long)WantedNewValueHighPart,
        (long long)WantedNewValueLowPart,
        (long long *)OldMandatoryValue128);
}

__forceinline
CX_UINT64
CxInterlockedAdd64(
    _Inout_ volatile CX_UINT64 *Destination,
    _In_ CX_UINT64 AddedValue
)
{
    CX_UINT64 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_UINT64)_InterlockedCompareExchange64((volatile CX_INT64*)Destination, (CX_INT64)(old + AddedValue), (CX_INT64)old));
    return (CX_UINT64)(old + AddedValue);
}

__forceinline
CX_UINT32
CxInterlockedAdd32(
    _Inout_ volatile CX_UINT32 *Destination,
    _In_ CX_UINT32 AddedValue
)
{
    CX_UINT32 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_UINT32)_InterlockedCompareExchange((volatile long*)Destination, (CX_INT32)(old + AddedValue), (CX_INT32)old));
    return (CX_UINT32)(old + AddedValue);
}

__forceinline
CX_UINT16
CxInterlockedAdd16(
    _Inout_ volatile CX_UINT16 *Destination,
    _In_ CX_UINT16 AddedValue
)
{
    CX_UINT16 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_UINT16)_InterlockedCompareExchange16((volatile CX_INT16*)Destination, (CX_INT16)(old + AddedValue), (CX_INT16)old));
    return (CX_UINT16)(old + AddedValue);
}

__forceinline
CX_UINT8
CxInterlockedAdd8(
    _Inout_ volatile CX_UINT8 *Destination,
    _In_ CX_UINT8 AddedValue
)
{
    CX_UINT8 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_UINT8)_InterlockedCompareExchange8((volatile CX_INT8*)Destination, (CX_INT8)(old + AddedValue), (CX_INT8)old));
    return (CX_UINT8)(old + AddedValue);
}


__forceinline
CX_INT64
CxInterlockedAddInt64(
    _Inout_ volatile CX_INT64 *Destination,
    _In_ CX_INT64 AddedValue
)
{
    CX_INT64 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_INT64)_InterlockedCompareExchange64((volatile CX_INT64*)Destination, old + AddedValue, old));
    return (CX_INT64)(old + AddedValue);
}

__forceinline
CX_INT32
CxInterlockedAddInt32(
    _Inout_ volatile CX_INT32 *Destination,
    _In_ CX_INT32 AddedValue
)
{
    CX_INT32 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_INT32)_InterlockedCompareExchange((volatile long*)Destination, old + AddedValue, old));
    return (CX_INT32)(old + AddedValue);
}

__forceinline
CX_INT16
CxInterlockedAddInt16(
    _Inout_ volatile CX_INT16 *Destination,
    _In_ CX_INT16 AddedValue
)
{
    CX_INT16 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_INT16)_InterlockedCompareExchange16((volatile CX_INT16*)Destination, old + AddedValue, old));
    return (CX_INT16)(old + AddedValue);
}

__forceinline
CX_INT8
CxInterlockedAddInt8(
    _Inout_ volatile CX_INT8 *Destination,
    _In_ CX_INT8 AddedValue
)
{
    CX_INT8 old;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        old = *Destination;
    } while (old != (CX_INT8)_InterlockedCompareExchange8((volatile CX_INT8*)Destination, old + AddedValue, old));
    return (CX_INT8)(old + AddedValue);
}

//
// CxInterlockedExchangeAdd*
//
__forceinline
CX_UINT64
CxInterlockedExchangeAdd64(volatile CX_UINT64 *_Tgt, CX_UINT64 _Value)
{
    CX_UINT64 _Oldval, _Newval;
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    _ReadWriteBarrier();
    do
    {
        CX_SIGNAL_BUSY_WAITING();
        _Oldval = *_Tgt;
        _Newval = _Oldval + _Value;
    } while (_Oldval != CxInterlockedCompareExchange64(_Tgt, _Newval, _Oldval));
    _ReadWriteBarrier();
    return (_Oldval);
}

__forceinline
CX_INT64
CxInterlockedExchangeAddInt64(volatile CX_INT64 *_Tgt, CX_INT64 _Value)
{
    return (CX_INT64)CxInterlockedExchangeAdd64((volatile CX_UINT64 *)_Tgt, (CX_UINT64)_Value);
}

enum
{
    CX_INTERLOCKED_ONCE_NOT_STARTED = 0,
    CX_INTERLOCKED_ONCE_IN_PROGRESS = 1,
    CX_INTERLOCKED_ONCE_SUCCESSFUL  = 2,
    CX_INTERLOCKED_ONCE_FAILED      = 3
};

__forceinline
CX_BOOL
CxInterlockedPerformedOnce(
    _In_ CX_ONCE_INIT0 *AlreadyPerformed
)
//
// Returns a true value iff the 'perform once' operation (associated with AlreadyPerformed) has already
// been performed and it did end successfully.
//
{
    // iff we can transition from successful to successful we.. were successful
    return CX_INTERLOCKED_ONCE_SUCCESSFUL == CxInterlockedCompareExchange8(AlreadyPerformed, CX_INTERLOCKED_ONCE_SUCCESSFUL, CX_INTERLOCKED_ONCE_SUCCESSFUL);
}


__forceinline
CX_BOOL
CxInterlockedBeginOnce(
    _Inout_ CX_ONCE_INIT0 *AlreadyConsumed
)
//
// Returns a true value (and makes you responsible to actually perform the task) if you
// can perform the supposed 'only once' code associated with the sent data; in this case, use CxInterlockedEndOnce 
// to reflect that the task is finished (to the external world) as the last step of the 'only once' code,
// CxInterlockedAbortOnce if you abandon and postpone the operation for some other time or someone else or
// CxInterlockedFailOnce to mark it as failed without leaving someone else the opportunity of performing it
//
// Returns false when you shouldn't perform the operation. Call CxInterlockedPerformedOnce to make sure someone else did it
//
{
    // NOT_STARTED => IN_PROGRESS
    if (CX_INTERLOCKED_ONCE_NOT_STARTED == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_IN_PROGRESS, CX_INTERLOCKED_ONCE_NOT_STARTED))
    {
        // we won the race, we now have exclusive access for performing the operation
        return CX_TRUE;
    }
    
    // we didn't win the race, someone else probably did and is performing the operation
    // now we only have to (busy) wait while the operation is still in progress
    CX_SIGNAL_BEGIN_BUSY_WAITING();
    while (CX_INTERLOCKED_ONCE_IN_PROGRESS == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_IN_PROGRESS, CX_INTERLOCKED_ONCE_IN_PROGRESS))
    {
        CX_SIGNAL_BUSY_WAITING();
    }

    // no matter how the operation ended (successful, failed, aborted), return FALSE as this caller should not perform the operation
    return CX_FALSE;
}


__forceinline
CX_BOOL
CxInterlockedEndOnce(
    _Inout_ CX_ONCE_INIT0 *AlreadyConsumed
)
//
// Returns a true value iff the 'perform once' operation can be finished successfully
//
{
    // a logically false value is only returned when someone else did a CxInterlockedEndOnce/CxInterlockedAbortOnce on your data
    // or some memory corruption occurred
    // IMPORTANT: the program's state and behavior shouldn't be trusted / is undefined in this case!

    // IN_PROGRESS => SUCCESSFUL
    return CX_INTERLOCKED_ONCE_IN_PROGRESS == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_SUCCESSFUL, CX_INTERLOCKED_ONCE_IN_PROGRESS);
}


__forceinline
CX_BOOL
CxInterlockedAbortOnce(
    _Inout_ CX_ONCE_INIT0 *AlreadyConsumed
)
//
// Returns a true value iff the 'perform once' operation can be abandoned successfully (as if it never was started in the first place)
//
{
    // a logically false value is only returned when someone else did a CxInterlockedEndOnce/CxInterlockedAbortOnce on your data
    // or some memory corruption occurred
    // IMPORTANT: the program's state and behavior shouldn't be trusted / is undefined in this case!

    // IN_PROGRESS => NOT_STARTED
    return CX_INTERLOCKED_ONCE_IN_PROGRESS == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_NOT_STARTED, CX_INTERLOCKED_ONCE_IN_PROGRESS);
}

__forceinline
CX_BOOL
CxInterlockedFailOnce(
    _Inout_ CX_ONCE_INIT0 *AlreadyConsumed
)
//
// Returns a true value iff the 'perform once' operation can be (and do transition to) failed (not performed and not retriable)
// The state is forced to failed even if the returned value might be false but the program's state and behavior shouldn't be trusted anymore
//
{
    // a logically false value is only returned when someone else did a CxInterlockedEndOnce/CxInterlockedAbortOnce on your data
    // or some memory corruption occurred
    // IMPORTANT: the program's state and behavior shouldn't be trusted / is undefined in this case!

    // IN_PROGRESS => FAILED
    if (CX_INTERLOCKED_ONCE_IN_PROGRESS == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_FAILED, CX_INTERLOCKED_ONCE_IN_PROGRESS))
    {
        return CX_TRUE;
    }

    // always force it to failed (even if it wasn't in a proper state)
    *AlreadyConsumed = CX_INTERLOCKED_ONCE_FAILED;
    return CX_FALSE;
}


__forceinline
CX_BOOL
CxInterlockedResetFailedOnce(
    _In_ CX_ONCE_INIT0 *AlreadyConsumed
)
//
// return TRUE if the opeation was marked as failed and this caller successfully resets it to the "never performed" state
// when the result is FALSE, the state of the operation is unknown and unchanged
//
{
    // FAILED => NOT_STARTED
    return (CX_INTERLOCKED_ONCE_FAILED == CxInterlockedCompareExchange8(AlreadyConsumed, CX_INTERLOCKED_ONCE_NOT_STARTED, CX_INTERLOCKED_ONCE_FAILED));
}


//
// CxInterlockedBitTestAndSet*
//
__forceinline
CX_UINT8
CxInterlockedBitTestAndSet64(
    _In_ CX_UINT64 volatile *_BitBase,
    _In_ CX_UINT64 _BitPos
)
{
    return _interlockedbittestandset64((__int64*)_BitBase, _BitPos);
}

__forceinline
CX_INT8
CxInterlockedBitTestAndSetInt64(
    _In_ CX_INT64 volatile *_BitBase,
    _In_ CX_INT64 _BitPos
)
{
    return _interlockedbittestandset64((__int64*)_BitBase, _BitPos);
}

__forceinline
CX_UINT8
CxInterlockedBitTestAndSet32(
    _In_ CX_UINT32 volatile *_BitBase,
    _In_ CX_UINT32 _BitPos
)
{
    return _interlockedbittestandset((long*)_BitBase, _BitPos);
}

__forceinline
CX_INT8
CxInterlockedBitTestAndSetInt32(
    _In_ CX_INT32 volatile *_BitBase,
    _In_ CX_INT32 _BitPos
)
{
    return _interlockedbittestandset((long*)_BitBase, _BitPos);
}

//
// CxBitTestAndReset*
//
__forceinline
CX_UINT8
CxInterlockedBitTestAndReset64(
    _In_ CX_UINT64 volatile *_BitBase,
    _In_ CX_UINT64 _BitPos
)
{
    return _interlockedbittestandreset64((__int64*)_BitBase, _BitPos);
}

__forceinline
CX_INT8
CxInterlockedBitTestAndResetInt64(
    _In_ CX_INT64 volatile *_BitBase,
    _In_ CX_INT64 _BitPos
)
{
    return _interlockedbittestandreset64((__int64*)_BitBase, _BitPos);
}

__forceinline
CX_UINT8
CxInterlockedBitTestAndReset32(
    _In_ CX_UINT32 volatile *_BitBase,
    _In_ CX_UINT32 _BitPos
)
{
    return _interlockedbittestandreset((long*)_BitBase, _BitPos);
}

__forceinline
CX_INT8
CxInterlockedBitTestAndResetInt32(
    _In_ CX_INT32 volatile *_BitBase,
    _In_ CX_INT32 _BitPos
)
{
    return _interlockedbittestandreset((long*)_BitBase, _BitPos);
}

#endif // _CX_VCSYNCH_H_
