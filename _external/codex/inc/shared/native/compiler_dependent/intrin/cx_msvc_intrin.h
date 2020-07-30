/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_MSVC_INTRIN_H_
#define _CX_MSVC_INTRIN_H_

#include "cx_native.h"
#include "base/cx_env.h"

extern int _AddSatInt(int, int);
extern void * _AddressOfReturnAddress(void);
extern unsigned char _BitScanForward(unsigned long * _Index, unsigned long _Mask);
extern unsigned char _BitScanForward64(unsigned long * _Index, unsigned __int64 _Mask);
extern unsigned char _BitScanForward64(unsigned long * _Index, unsigned __int64 _Mask);
extern unsigned char _BitScanReverse(unsigned long * _Index, unsigned long _Mask);
extern unsigned char _BitScanReverse64(unsigned long * _Index, unsigned __int64 _Mask);
extern unsigned char _BitScanReverse64(unsigned long * _Index, unsigned __int64 _Mask);
extern double _CopyDoubleFromInt64(__int64);
extern float _CopyFloatFromInt32(__int32);
extern __int32 _CopyInt32FromFloat(float);
extern __int64 _CopyInt64FromDouble(double);
extern unsigned int _CountLeadingOnes(unsigned long);
extern unsigned int _CountLeadingOnes64(unsigned __int64);
extern unsigned int _CountLeadingSigns(long);
extern unsigned int _CountLeadingSigns64(__int64);
extern unsigned int _CountLeadingZeros(unsigned long);
extern unsigned int _CountLeadingZeros64(unsigned __int64);
extern unsigned int _CountOneBits(unsigned long);
extern unsigned int _CountOneBits64(unsigned __int64);
extern int _DAddSatInt(int, int);
extern int _DSubSatInt(int, int);
extern long _InterlockedAdd(long volatile * _Addend, long _Value);
extern __int64 _InterlockedAdd64(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedAdd64_acq(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedAdd64_nf(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedAdd64_rel(__int64 volatile * _Addend, __int64 _Value);
extern long _InterlockedAddLargeStatistic(__int64 volatile * _Addend, long _Value);
extern long _InterlockedAdd_acq(long volatile * _Addend, long _Value);
extern long _InterlockedAdd_nf(long volatile * _Addend, long _Value);
extern long _InterlockedAdd_rel(long volatile * _Addend, long _Value);
extern long _InterlockedAnd(long volatile * _Value, long _Mask);
extern short _InterlockedAnd16(short volatile * _Value, short _Mask);
extern short _InterlockedAnd16_acq(short volatile * _Value, short _Mask);
extern short _InterlockedAnd16_nf(short volatile * _Value, short _Mask);
extern short _InterlockedAnd16_np(short volatile * _Value, short _Mask);
extern short _InterlockedAnd16_rel(short volatile * _Value, short _Mask);
extern __int64 _InterlockedAnd64(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedAnd64_acq(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedAnd64_nf(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedAnd64_np(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedAnd64_rel(__int64 volatile * _Value, __int64 _Mask);
extern char _InterlockedAnd8(char volatile * _Value, char _Mask);
extern char _InterlockedAnd8_acq(char volatile * _Value, char _Mask);
extern char _InterlockedAnd8_nf(char volatile * _Value, char _Mask);
extern char _InterlockedAnd8_np(char volatile * _Value, char _Mask);
extern char _InterlockedAnd8_rel(char volatile * _Value, char _Mask);
extern long _InterlockedAnd_acq(long volatile * _Value, long _Mask);
extern long _InterlockedAnd_nf(long volatile * _Value, long _Mask);
extern long _InterlockedAnd_np(long volatile * _Value, long _Mask);
extern long _InterlockedAnd_rel(long volatile * _Value, long _Mask);
extern long __cdecl _InterlockedCompareExchange(long volatile * _Destination, long _Exchange, long _Comparand);
extern long _InterlockedCompareExchange(long volatile * _Destination, long _Exchange, long _Comparand);
extern unsigned char _InterlockedCompareExchange128(__int64 volatile * _Destination, __int64 _ExchangeHigh, __int64 _ExchangeLow, __int64 * _ComparandResult);
extern unsigned char _InterlockedCompareExchange128_acq(__int64 volatile * _Destination, __int64 _ExchangeHigh, __int64 _ExchangeLow, __int64 * _ComparandResult);
extern unsigned char _InterlockedCompareExchange128_nf(__int64 volatile * _Destination, __int64 _ExchangeHigh, __int64 _ExchangeLow, __int64 * _ComparandResult);
extern unsigned char _InterlockedCompareExchange128_np(__int64 volatile * _Destination, __int64 _ExchangeHigh, __int64 _ExchangeLow, __int64 * _ComparandResult);
extern unsigned char _InterlockedCompareExchange128_rel(__int64 volatile * _Destination, __int64 _ExchangeHigh, __int64 _ExchangeLow, __int64 * _ComparandResult);
extern short _InterlockedCompareExchange16(short volatile * _Destination, short _Exchange, short _Comparand);
extern short _InterlockedCompareExchange16_acq(short volatile * _Destination, short _Exchange, short _Comparand);
extern short _InterlockedCompareExchange16_nf(short volatile * _Destination, short _Exchange, short _Comparand);
extern short _InterlockedCompareExchange16_np(short volatile * _Destination, short _Exchange, short _Comparand);
extern short _InterlockedCompareExchange16_rel(short volatile * _Destination, short _Exchange, short _Comparand);
extern __int64 _InterlockedCompareExchange64(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
extern __int64 _InterlockedCompareExchange64_acq(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
extern __int64 _InterlockedCompareExchange64_nf(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
extern __int64 _InterlockedCompareExchange64_np(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
extern __int64 _InterlockedCompareExchange64_rel(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
extern char _InterlockedCompareExchange8(char volatile * _Destination, char _Exchange, char _Comparand);
extern char _InterlockedCompareExchange8_acq(char volatile * _Destination, char _Exchange, char _Comparand);
extern char _InterlockedCompareExchange8_nf(char volatile * _Destination, char _Exchange, char _Comparand);
extern char _InterlockedCompareExchange8_rel(char volatile * _Destination, char _Exchange, char _Comparand);
extern void * _InterlockedCompareExchangePointer(void * volatile * _Destination, void * _Exchange, void * _Comparand);
extern void * _InterlockedCompareExchangePointer_acq(void * volatile * _Destination, void * _Exchange, void * _Comparand);
extern void * _InterlockedCompareExchangePointer_nf(void * volatile * _Destination, void * _Exchange, void * _Comparand);
extern void * _InterlockedCompareExchangePointer_np(void * volatile * _Destination, void * _Exchange, void * _Comparand);
extern void * _InterlockedCompareExchangePointer_rel(void * volatile * _Destination, void * _Exchange, void * _Comparand);
extern long _InterlockedCompareExchange_acq(long volatile * _Destination, long _Exchange, long _Comparand);
extern long _InterlockedCompareExchange_nf(long volatile * _Destination, long _Exchange, long _Comparand);
extern long _InterlockedCompareExchange_np(long volatile * _Destination, long _Exchange, long _Comparand);
extern long _InterlockedCompareExchange_rel(long volatile * _Destination, long _Exchange, long _Comparand);
extern long __cdecl _InterlockedDecrement(long volatile * _Addend);
extern long _InterlockedDecrement(long volatile * _Addend);
extern short _InterlockedDecrement16(short volatile * _Addend);
extern short _InterlockedDecrement16_acq(short volatile * _Addend);
extern short _InterlockedDecrement16_nf(short volatile * _Addend);
extern short _InterlockedDecrement16_rel(short volatile * _Addend);
extern __int64 _InterlockedDecrement64(__int64 volatile * _Addend);
extern __int64 _InterlockedDecrement64_acq(__int64 volatile * _Addend);
extern __int64 _InterlockedDecrement64_nf(__int64 volatile * _Addend);
extern __int64 _InterlockedDecrement64_rel(__int64 volatile * _Addend);
extern long _InterlockedDecrement_acq(long volatile * _Addend);
extern long _InterlockedDecrement_nf(long volatile * _Addend);
extern long _InterlockedDecrement_rel(long volatile * _Addend);
extern long __cdecl _InterlockedExchange(long volatile * _Target, long _Value);
extern long __cdecl _InterlockedExchange(long volatile * _Target, long _Value);
extern short _InterlockedExchange16(short volatile * _Target, short _Value);
extern short _InterlockedExchange16_acq(short volatile * _Target, short _Value);
extern short _InterlockedExchange16_nf(short volatile * _Target, short _Value);
extern short _InterlockedExchange16_rel(short volatile * _Target, short _Value);
extern __int64 _InterlockedExchange64(__int64 volatile * _Target, __int64 _Value);
extern __int64 _InterlockedExchange64_acq(__int64 volatile * _Target, __int64 _Value);
extern __int64 _InterlockedExchange64_nf(__int64 volatile * _Target, __int64 _Value);
extern __int64 _InterlockedExchange64_rel(__int64 volatile * _Target, __int64 _Value);
extern char _InterlockedExchange8(char volatile * _Target, char _Value);
extern char _InterlockedExchange8_acq(char volatile * _Target, char _Value);
extern char _InterlockedExchange8_nf(char volatile * _Target, char _Value);
extern char _InterlockedExchange8_rel(char volatile * _Target, char _Value);
extern long __cdecl _InterlockedExchangeAdd(long volatile * _Addend, long _Value);
extern short _InterlockedExchangeAdd16(short volatile * _Addend, short _Value);
extern short _InterlockedExchangeAdd16_acq(short volatile * _Addend, short _Value);
extern short _InterlockedExchangeAdd16_nf(short volatile * _Addend, short _Value);
extern short _InterlockedExchangeAdd16_rel(short volatile * _Addend, short _Value);
extern __int64 _InterlockedExchangeAdd64(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedExchangeAdd64_acq(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedExchangeAdd64_nf(__int64 volatile * _Addend, __int64 _Value);
extern __int64 _InterlockedExchangeAdd64_rel(__int64 volatile * _Addend, __int64 _Value);
extern char _InterlockedExchangeAdd8(char volatile * _Addend, char _Value);
extern char _InterlockedExchangeAdd8_acq(char volatile * _Addend, char _Value);
extern char _InterlockedExchangeAdd8_nf(char volatile * _Addend, char _Value);
extern char _InterlockedExchangeAdd8_rel(char volatile * _Addend, char _Value);
extern long _InterlockedExchangeAdd_acq(long volatile * _Addend, long _Value);
extern long _InterlockedExchangeAdd_nf(long volatile * _Addend, long _Value);
extern long _InterlockedExchangeAdd_rel(long volatile * _Addend, long _Value);
extern void * _InterlockedExchangePointer(void * volatile * _Target, void * _Value);
extern void * _InterlockedExchangePointer_acq(void * volatile * _Target, void * _Value);
extern void * _InterlockedExchangePointer_nf(void * volatile * _Target, void * _Value);
extern void * _InterlockedExchangePointer_rel(void * volatile * _Target, void * _Value);
extern long _InterlockedExchange_acq(long volatile * _Target, long _Value);
extern long _InterlockedExchange_nf(long volatile * _Target, long _Value);
extern long _InterlockedExchange_rel(long volatile * _Target, long _Value);
extern long __cdecl _InterlockedIncrement(long volatile * _Addend);
extern long _InterlockedIncrement(long volatile * _Addend);
extern short _InterlockedIncrement16(short volatile * _Addend);
extern short _InterlockedIncrement16_acq(short volatile * _Addend);
extern short _InterlockedIncrement16_nf(short volatile * _Addend);
extern short _InterlockedIncrement16_rel(short volatile * _Addend);
extern __int64 _InterlockedIncrement64(__int64 volatile * _Addend);
extern __int64 _InterlockedIncrement64_acq(__int64 volatile * _Addend);
extern __int64 _InterlockedIncrement64_nf(__int64 volatile * _Addend);
extern __int64 _InterlockedIncrement64_rel(__int64 volatile * _Addend);
extern long _InterlockedIncrement_acq(long volatile * _Addend);
extern long _InterlockedIncrement_nf(long volatile * _Addend);
extern long _InterlockedIncrement_rel(long volatile * _Addend);
extern long _InterlockedOr(long volatile * _Value, long _Mask);
extern short _InterlockedOr16(short volatile * _Value, short _Mask);
extern short _InterlockedOr16_acq(short volatile * _Value, short _Mask);
extern short _InterlockedOr16_nf(short volatile * _Value, short _Mask);
extern short _InterlockedOr16_np(short volatile * _Value, short _Mask);
extern short _InterlockedOr16_rel(short volatile * _Value, short _Mask);
extern __int64 _InterlockedOr64(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedOr64_acq(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedOr64_nf(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedOr64_np(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedOr64_rel(__int64 volatile * _Value, __int64 _Mask);
extern char _InterlockedOr8(char volatile * _Value, char _Mask);
extern char _InterlockedOr8_acq(char volatile * _Value, char _Mask);
extern char _InterlockedOr8_nf(char volatile * _Value, char _Mask);
extern char _InterlockedOr8_np(char volatile * _Value, char _Mask);
extern char _InterlockedOr8_rel(char volatile * _Value, char _Mask);
extern long _InterlockedOr_acq(long volatile * _Value, long _Mask);
extern long _InterlockedOr_nf(long volatile * _Value, long _Mask);
extern long _InterlockedOr_np(long volatile * _Value, long _Mask);
extern long _InterlockedOr_rel(long volatile * _Value, long _Mask);
extern long _InterlockedXor(long volatile * _Value, long _Mask);
extern short _InterlockedXor16(short volatile * _Value, short _Mask);
extern short _InterlockedXor16_acq(short volatile * _Value, short _Mask);
extern short _InterlockedXor16_nf(short volatile * _Value, short _Mask);
extern short _InterlockedXor16_np(short volatile * _Value, short _Mask);
extern short _InterlockedXor16_rel(short volatile * _Value, short _Mask);
extern __int64 _InterlockedXor64(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedXor64_acq(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedXor64_nf(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedXor64_np(__int64 volatile * _Value, __int64 _Mask);
extern __int64 _InterlockedXor64_rel(__int64 volatile * _Value, __int64 _Mask);
extern char _InterlockedXor8(char volatile * _Value, char _Mask);
extern char _InterlockedXor8_acq(char volatile * _Value, char _Mask);
extern char _InterlockedXor8_nf(char volatile * _Value, char _Mask);
extern char _InterlockedXor8_np(char volatile * _Value, char _Mask);
extern char _InterlockedXor8_rel(char volatile * _Value, char _Mask);
extern long _InterlockedXor_acq(long volatile * _Value, long _Mask);
extern long _InterlockedXor_nf(long volatile * _Value, long _Mask);
extern long _InterlockedXor_np(long volatile * _Value, long _Mask);
extern long _InterlockedXor_rel(long volatile * _Value, long _Mask);
extern unsigned int _MoveFromCoprocessor(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int _MoveFromCoprocessor2(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned __int64 _MoveFromCoprocessor64(unsigned int, unsigned int, unsigned int);
extern void _MoveToCoprocessor(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
extern void _MoveToCoprocessor2(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
extern void _MoveToCoprocessor64(unsigned __int64, unsigned int, unsigned int, unsigned int);
extern long _MulHigh(long, long);
extern unsigned long _MulUnsignedHigh(unsigned long, unsigned long);
extern void _ReadBarrier(void);
#ifdef CX_ARCH32
extern int _ReadStatusReg(int);
#else
extern __int64 _ReadStatusReg(int);
#endif
extern unsigned __int64 __getReg(int);
extern unsigned __int64 __getCallerReg(int);
extern double __getRegFp(int);
extern double __getCallerRegFp(int);
extern void _ReadWriteBarrier(void);
extern void * _ReturnAddress(void);
extern int _SubSatInt(int, int);
extern void _WriteBarrier(void);
extern void __setReg(int, unsigned __int64);
extern void __setCallerReg(int, unsigned __int64);
extern void __setRegFp(int, double);
extern void __setCallerRegFp(int, double);
extern void __addfsbyte(unsigned long, unsigned char);
extern void __addfsdword(unsigned long, unsigned long);
extern void __addfsword(unsigned long, unsigned short);
extern void __addgsbyte(unsigned long, unsigned char);
extern void __addgsdword(unsigned long, unsigned long);
extern void __addgsqword(unsigned long, unsigned __int64);
extern void __addgsword(unsigned long, unsigned short);
extern void __addx18byte(unsigned long, unsigned char);
extern void __addx18dword(unsigned long, unsigned long);
extern void __addx18qword(unsigned long, unsigned __int64);
extern void __addx18word(unsigned long, unsigned short);
extern void __code_seg(const char *);
extern void __cpuid(int[4], int);
extern void __cpuidex(int[4], int, int);
extern void __cdecl __debugbreak(void);
extern void __emit(unsigned __int32);
extern __int64 __emul(int, int);
extern unsigned __int64 __emulu(unsigned int, unsigned int);
extern __declspec(noreturn) void __fastfail(unsigned int);
extern void __faststorefence(void);
extern unsigned int __getcallerseflags(void);
extern void __halt(void);
extern unsigned int __hvc(unsigned int, ...);
extern void __break(int);
extern unsigned char __inbyte(unsigned short);
extern void __inbytestring(unsigned short, unsigned char *, unsigned long);
extern void __incfsbyte(unsigned long);
extern void __incfsdword(unsigned long);
extern void __incfsword(unsigned long);
extern void __incgsbyte(unsigned long);
extern void __incgsdword(unsigned long);
extern void __incgsqword(unsigned long);
extern void __incgsword(unsigned long);
extern void __incx18byte(unsigned long);
extern void __incx18dword(unsigned long);
extern void __incx18qword(unsigned long);
extern void __incx18word(unsigned long);
extern unsigned long __indword(unsigned short);
extern void __indwordstring(unsigned short, unsigned long *, unsigned long);
extern void __int2c(void);
extern void __invlpg(void *);
extern unsigned short __inword(unsigned short);
extern void __inwordstring(unsigned short, unsigned short *, unsigned long);
extern __int16 __iso_volatile_load16(const volatile __int16 *);
extern __int32 __iso_volatile_load32(const volatile __int32 *);
extern __int64 __iso_volatile_load64(const volatile __int64 *);
extern __int8 __iso_volatile_load8(const volatile __int8 *);
extern void __iso_volatile_store16(volatile __int16 *, __int16);
extern void __iso_volatile_store32(volatile __int32 *, __int32);
extern void __iso_volatile_store64(volatile __int64 *, __int64);
extern void __iso_volatile_store8(volatile __int8 *, __int8);
extern __int64 __ldrexd(const volatile __int64 *);
extern void __lidt(void *);
extern unsigned __int64 __ll_lshift(unsigned __int64, int);
extern __int64 __ll_rshift(__int64, int);
extern unsigned int __lzcnt(unsigned int);
extern unsigned short __lzcnt16(unsigned short);
extern unsigned __int64 __lzcnt64(unsigned __int64);
extern void __movsb(unsigned char *, unsigned char const *, CX_SIZE_T);
extern void __movsd(unsigned long *, unsigned long const *, CX_SIZE_T);
extern void __movsq(unsigned long long *, unsigned long long const *, CX_SIZE_T);
extern void __movsw(unsigned short *, unsigned short const *, CX_SIZE_T);
extern __int64 __mulh(__int64, __int64);
extern void __nop(void);
extern void __nvreg_restore_fence(void);
extern void __nvreg_save_fence(void);
extern void __outbyte(unsigned short, unsigned char);
extern void __outbytestring(unsigned short, unsigned char *, unsigned long);
extern void __outdword(unsigned short, unsigned long);
extern void __outdwordstring(unsigned short, unsigned long *, unsigned long);
extern void __outword(unsigned short, unsigned short);
extern void __outwordstring(unsigned short, unsigned short *, unsigned long);
extern unsigned int __popcnt(unsigned int);
extern unsigned short __popcnt16(unsigned short);
extern unsigned __int64 __popcnt64(unsigned __int64);
extern void __cdecl __prefetch(const void *);
extern void __cdecl __prefetchw(const void *);
extern unsigned __int64 __rdpmccntr64(void);
extern unsigned __int64 __rdtsc(void);
extern unsigned __int64 __rdtscp(unsigned int *);
#ifdef CX_ARCH64
extern unsigned __int64 __readcr0(void);
extern unsigned __int64 __readcr2(void);
extern unsigned __int64 __readcr3(void);
extern unsigned __int64 __readcr4(void);
extern unsigned __int64 __readcr8(void);
extern unsigned __int64 __readdr(unsigned int);
extern unsigned __int64 __readeflags(void);
#else
extern unsigned long __readcr0(void);
extern unsigned long __readcr2(void);
extern unsigned long __readcr3(void);
extern unsigned long __readcr4(void);
extern unsigned long __readcr8(void);
extern unsigned int __readdr(unsigned int);
extern unsigned int __readeflags(void);
#endif
extern unsigned char __readfsbyte(unsigned long);
extern unsigned long __readfsdword(unsigned long);
extern unsigned __int64 __readfsqword(unsigned long);
extern unsigned short __readfsword(unsigned long);
extern unsigned char __readgsbyte(unsigned long);
extern unsigned long __readgsdword(unsigned long);
extern unsigned __int64 __readgsqword(unsigned long);
extern unsigned short __readgsword(unsigned long);
extern unsigned __int64 __readmsr(unsigned long);
extern unsigned __int64 __readpmc(unsigned long);
extern unsigned char __readx18byte(unsigned long);
extern unsigned long __readx18dword(unsigned long);
extern unsigned __int64 __readx18qword(unsigned long);
extern unsigned short __readx18word(unsigned long);
extern unsigned long __segmentlimit(unsigned long);
extern void __sev(void);
extern unsigned __int64 __shiftleft128(unsigned __int64 _LowPart, unsigned __int64 _HighPart, unsigned char _Shift);
extern unsigned __int64 __shiftright128(unsigned __int64 _LowPart, unsigned __int64 _HighPart, unsigned char _Shift);
extern void __sidt(void *);
extern void __static_assert(int, const char *);
extern void __stosb(unsigned char *, unsigned char, CX_SIZE_T);
extern void __stosd(unsigned long *, unsigned long, CX_SIZE_T);
extern void __stosq(unsigned __int64 *, unsigned __int64, CX_SIZE_T);
extern void __stosw(unsigned short *, unsigned short, CX_SIZE_T);
extern void __svm_clgi(void);
extern void __svm_invlpga(void *, int);
extern void __svm_skinit(int);
extern void __svm_stgi(void);
extern void __svm_vmload(CX_SIZE_T);
extern void __svm_vmrun(CX_SIZE_T);
extern void __svm_vmsave(CX_SIZE_T);
extern unsigned int __swi(unsigned int, ...);
extern unsigned int __svc(unsigned int, ...);
extern unsigned int __hlt(unsigned int, ...);
extern unsigned int __sys(int, __int64);
extern int __trap(int, ...);
extern void __ud2(void);
extern unsigned __int64 __ull_rshift(unsigned __int64, int);
extern unsigned __int64 __umulh(unsigned __int64, unsigned __int64);
extern void __vmx_off(void);
extern unsigned char __vmx_on(unsigned __int64 *);
extern unsigned char __vmx_vmclear(unsigned __int64 *);
extern unsigned char __vmx_vmlaunch(void);
extern unsigned char __vmx_vmptrld(unsigned __int64 *);
extern void __vmx_vmptrst(unsigned __int64 *);
extern unsigned char __vmx_vmread(CX_SIZE_T, CX_SIZE_T *);
extern unsigned char __vmx_vmresume(void);
extern unsigned char __vmx_vmwrite(CX_SIZE_T, CX_SIZE_T);
extern void __wbinvd(void);
extern void __wfe(void);
extern void __wfi(void);
#ifdef CX_ARCH64
extern void __writecr0(unsigned __int64);
extern void __writecr3(unsigned __int64);
extern void __writecr4(unsigned __int64);
extern void __writecr8(unsigned __int64);
extern void __writedr(unsigned int, unsigned __int64);
extern void __writeeflags(unsigned __int64);
#else
extern void __writecr0(unsigned int);
extern void __writecr3(unsigned int);
extern void __writecr4(unsigned int);
extern void __writecr8(unsigned int);
extern void __writedr(unsigned int, unsigned int);
extern void __writeeflags(unsigned int);
#endif
extern void __writefsbyte(unsigned long, unsigned char);
extern void __writefsdword(unsigned long, unsigned long);
extern void __writefsqword(unsigned long, unsigned __int64);
extern void __writefsword(unsigned long, unsigned short);
extern void __writegsbyte(unsigned long, unsigned char);
extern void __writegsdword(unsigned long, unsigned long);
extern void __writegsqword(unsigned long, unsigned __int64);
extern void __writegsword(unsigned long, unsigned short);
extern void __writemsr(unsigned long, unsigned __int64);
extern void __writex18byte(unsigned long, unsigned char);
extern void __writex18dword(unsigned long, unsigned long);
extern void __writex18qword(unsigned long, unsigned __int64);
extern void __writex18word(unsigned long, unsigned short);
extern void __yield(void);
extern unsigned char _bittest(long const *, long);
extern unsigned char _bittest64(__int64 const *, __int64);
extern unsigned char _bittestandcomplement(long *, long);
extern unsigned char _bittestandcomplement64(__int64 *, __int64);
extern unsigned char _bittestandreset(long *, long);
extern unsigned char _bittestandreset64(__int64 *, __int64);
extern unsigned char _bittestandset(long *, long);
extern unsigned char _bittestandset64(__int64 *, __int64);
extern unsigned __int64 __cdecl _byteswap_uint64(unsigned __int64);
extern unsigned long __cdecl _byteswap_ulong(unsigned long);
extern unsigned short __cdecl _byteswap_ushort(unsigned short);
extern void __cdecl _disable(void);
extern void __cdecl _enable(void);
extern unsigned char _interlockedbittestandreset(long volatile *, long);
extern unsigned char _interlockedbittestandreset64(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandreset_acq(long volatile *, long);
extern unsigned char _interlockedbittestandreset_nf(long volatile *, long);
extern unsigned char _interlockedbittestandreset_rel(long volatile *, long);
extern unsigned char _interlockedbittestandreset64_acq(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandreset64_rel(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandreset64_nf(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandset(long volatile *, long);
extern unsigned char _interlockedbittestandset64(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandset_acq(long volatile *, long);
extern unsigned char _interlockedbittestandset_nf(long volatile *, long);
extern unsigned char _interlockedbittestandset_rel(long volatile *, long);
extern unsigned char _interlockedbittestandset64_acq(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandset64_rel(__int64 volatile *, __int64);
extern unsigned char _interlockedbittestandset64_nf(__int64 volatile *, __int64);
extern unsigned __int32 __crc32b(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32h(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32w(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32d(unsigned __int32, unsigned __int64);
extern unsigned __int32 __crc32cb(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32ch(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32cw(unsigned __int32, unsigned __int32);
extern unsigned __int32 __crc32cd(unsigned __int32, unsigned __int64);
extern int _isunordered(double, double);
extern int _isunorderedf(float, float);
extern unsigned long __cdecl _lrotl(unsigned long, int);
extern unsigned long __cdecl _lrotr(unsigned long, int);
extern void _m_empty(void);
extern void _m_femms(void);
extern void _m_prefetch(void *);
extern void _m_prefetchw(volatile const void *);
extern void _mm_clflush(void const *);
extern void _mm_clflushopt(void const *);
extern void _mm_clwb(void const *);
extern void _mm_clzero(void const *);
extern unsigned int _mm_crc32_u16(unsigned int, unsigned short);
extern unsigned int _mm_crc32_u32(unsigned int, unsigned int);
extern unsigned __int64 _mm_crc32_u64(unsigned __int64, unsigned __int64);
extern unsigned int _mm_crc32_u8(unsigned int, unsigned char);
extern unsigned int _mm_getcsr(void);
extern void _mm_lfence(void);
extern void _mm_mfence(void);
extern void _mm_monitor(void const *, unsigned int, unsigned int);
extern void _mm_mwait(unsigned int, unsigned int);
extern void _mm_pause(void);
extern int _mm_popcnt_u32(unsigned int);
extern __int64 _mm_popcnt_u64(unsigned __int64);
extern void _mm_prefetch(char const *, int);
extern void _mm_setcsr(unsigned int);
extern void _mm_sfence(void);
extern void _mm_stream_si32(int *, int);
extern void _mm_stream_si64x(__int64 *, __int64);
extern __int64 _mul128(__int64 _Multiplier, __int64 _Multiplicand, __int64 * _HighProduct);
extern unsigned int __cdecl _rotl(unsigned int _Value, int _Shift);
extern unsigned short __cdecl _rotl16(unsigned short _Value, unsigned char _Shift);
extern unsigned __int64 __cdecl _rotl64(unsigned __int64 _Value, int _Shift);
extern unsigned char __cdecl _rotl8(unsigned char _Value, unsigned char _Shift);
extern unsigned int __cdecl _rotr(unsigned int _Value, int _Shift);
extern unsigned short __cdecl _rotr16(unsigned short _Value, unsigned char _Shift);
extern unsigned __int64 __cdecl _rotr64(unsigned __int64 _Value, int _Shift);
extern unsigned char __cdecl _rotr8(unsigned char _Value, unsigned char _Shift);
extern unsigned __int64 _umul128(unsigned __int64 _Multiplier, unsigned __int64 _Multiplicand, unsigned __int64 * _HighProduct);
extern void _rsm(void);
extern void _lgdt(void *);
extern void _sgdt(void *);
extern void _clac(void);
extern void _stac(void);
extern unsigned char __cdecl _addcarry_u8(unsigned char, unsigned char, unsigned char, unsigned char *);
extern unsigned char __cdecl _subborrow_u8(unsigned char, unsigned char, unsigned char, unsigned char *);
extern unsigned char __cdecl _addcarry_u16(unsigned char, unsigned short, unsigned short, unsigned short *);
extern unsigned char __cdecl _subborrow_u16(unsigned char, unsigned short, unsigned short, unsigned short *);
extern unsigned char __cdecl _addcarry_u32(unsigned char, unsigned int, unsigned int, unsigned int *);
extern unsigned char __cdecl _subborrow_u32(unsigned char, unsigned int, unsigned int, unsigned int *);
extern unsigned char __cdecl _addcarry_u64(unsigned char, unsigned __int64, unsigned __int64, unsigned __int64 *);
extern unsigned char __cdecl _subborrow_u64(unsigned char, unsigned __int64, unsigned __int64, unsigned __int64 *);
extern void _mm_monitorx(void const *, unsigned int, unsigned int);
extern void _mm_mwaitx(unsigned int, unsigned int, unsigned int);
extern unsigned __int64 __cdecl _xgetbv(unsigned int);


//
// Bit Twiddling
//
__forceinline CX_UINT8
CxRotL8(CX_UINT8 Value, CX_UINT8 Shift)
{
    return _rotl8(Value, Shift);
}

__forceinline CX_UINT8
CxRotR8(CX_UINT8 Value, CX_UINT8 Shift)
{
    return _rotr8(Value, Shift);
}

__forceinline CX_UINT16
CxRotL16(CX_UINT16 Value, CX_UINT8 Shift)
{
    return _rotl16(Value, Shift);
}

__forceinline CX_UINT16
CxRotR16(CX_UINT16 Value, CX_UINT8 Shift)
{
    return _rotr16(Value, Shift);
}

static
__forceinline CX_UINT64
CxRotL64(CX_UINT64 Value, CX_INT32 Shift)
{
    return _rotl64(Value, Shift);
}

static
__forceinline CX_UINT64
CxRotR64(CX_UINT64 Value, CX_INT32 Shift)
{
    return _rotr64(Value, Shift);
}



//
// Bit Counting and Testing
//
__forceinline CX_UINT8
CxBitScanForward32(CX_UINT32 *_Index, CX_UINT32 _Mask)
{
    return _BitScanForward((unsigned long *)_Index, (unsigned long)_Mask);
}

__forceinline CX_UINT8
CxBitScanReverse32(CX_UINT32 *_Index, CX_UINT32 _Mask)
{
    return _BitScanReverse((unsigned long *)_Index, (unsigned long)_Mask);
}

__forceinline CX_UINT16
CxPopCnt16(CX_UINT16 _Value)
{
    return __popcnt16((unsigned short)_Value);
}

__forceinline CX_UINT32
CxPopCnt32(CX_UINT32 _Value)
{
    return __popcnt((unsigned int)_Value);
}

__forceinline CX_UINT8
CxBitTestInt32(CX_INT32 const *_BitBase, CX_INT32 _BitPos)
{
    return _bittest((long const *)_BitBase, (long)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndComplementInt32(CX_INT32 *_BitBase, CX_INT32 _BitPos)
{
    return _bittestandcomplement((long *)_BitBase, (long)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndResetInt32(CX_INT32 *_BitBase, CX_INT32 _BitPos)
{
    return _bittestandreset((long *)_BitBase, (long)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndSetInt32(CX_INT32 *_BitBase, CX_INT32 _BitPos)
{
    return _bittestandset((long *)_BitBase, (long)_BitPos);
}


#ifdef CX_ARCH64
__forceinline CX_UINT8
CxBitScanForward64(CX_UINT32 *_Index, CX_UINT64 _Mask)
{
    return _BitScanForward64((unsigned long *)_Index, (unsigned __int64)_Mask);
}

__forceinline CX_UINT8
CxBitScanReverse64(CX_UINT32 *_Index, CX_UINT64 _Mask)
{
    return _BitScanReverse64((unsigned long *)_Index, (unsigned __int64)_Mask);
}

__forceinline static
CX_UINT64
CxPopCnt64(CX_UINT64 _Value)
{
    return __popcnt64((unsigned __int64)_Value);
}

__forceinline CX_UINT8
CxBitTestInt64(CX_INT64 const *_BitBase, CX_INT64 _BitPos)
{
    return _bittest64((__int64 const *)_BitBase, (__int64)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndComplementInt64(CX_INT64 *_BitBase, CX_INT64 _BitPos)
{
    return _bittestandcomplement64((__int64 *)_BitBase, (__int64)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndResetInt64(CX_INT64 *_BitBase, CX_INT64 _BitPos)
{
    return _bittestandreset64((__int64 *)_BitBase, (__int64)_BitPos);
}

__forceinline CX_UINT8
CxBitTestAndSetInt64(CX_INT64 *_BitBase, CX_INT64 _BitPos)
{
    return _bittestandset64((__int64 *)_BitBase, (__int64)_BitPos);
}

#endif




//
// readfs, readgs
// (Pointers in address space #256 and #257 are relative to the GS and FS
// segment registers, respectively.)
//


__forceinline CX_UINT8
CxReadFs8(CX_UINT64 __offset)
{
    return __readfsbyte((unsigned long)__offset);
}

__forceinline CX_UINT16
CxReadFs16(CX_UINT64 __offset)
{
    return __readfsword((unsigned long)__offset);
}

__forceinline CX_UINT32
CxReadFs32(CX_UINT64 __offset)
{
    return __readfsdword((unsigned long)__offset);
}

__forceinline CX_UINT64
CxReadFs64(CX_UINT64 __offset)
{
    return __readfsqword((unsigned long)__offset);
}

__forceinline CX_UINT8
CxReadGs8(CX_UINT64 __offset)
{
    return __readgsbyte((unsigned long)__offset);
}

__forceinline CX_UINT16
CxReadGs16(CX_UINT64 __offset)
{
    return __readgsword((unsigned long)__offset);
}

__forceinline CX_UINT32
CxReadGs32(CX_UINT64 __offset)
{
    return __readgsdword((unsigned long)__offset);
}

__forceinline CX_UINT64
CxReadGs64(CX_UINT64 __offset)
{
    return __readgsqword((unsigned long)__offset);
}


//
// movs, stos
//
__forceinline CX_VOID
CxMovsb(CX_UINT8 *__dst, CX_UINT8 const *__src, CX_SIZE_T __n)
{
    __movsb((unsigned char *)__dst, (unsigned char const *)__src, (CX_SIZE_T)__n);
}

__forceinline CX_VOID
CxMovsw(CX_UINT16 *__dst, CX_UINT16 const *__src, CX_SIZE_T __n)
{
    __movsw((unsigned short *)__dst, (unsigned short const *)__src, (CX_SIZE_T)__n);
}

__forceinline CX_VOID
CxMovsd(CX_UINT32 *__dst, CX_UINT32 const *__src, CX_SIZE_T __n)
{
    __movsd((unsigned long *)__dst, (unsigned long const *)__src, (CX_SIZE_T)__n);
}


__forceinline CX_VOID
CxStosb(CX_UINT8 *__dst, CX_UINT8 __x, CX_SIZE_T __n)
{
    __stosb((unsigned char *)__dst, (unsigned char)__x, (CX_SIZE_T)__n);
}

__forceinline CX_VOID
CxStosw(CX_UINT16 *__dst, CX_UINT16 __x, CX_SIZE_T __n)
{
    __stosw((unsigned short *)__dst, (unsigned short)__x, (CX_SIZE_T)__n);
}

__forceinline CX_VOID
CxStosd(CX_UINT32 *__dst, CX_UINT32 __x, CX_SIZE_T __n)
{
    __stosd((unsigned long *)__dst, (unsigned long)__x, (CX_SIZE_T)__n);
}

#ifdef CX_ARCH64
__forceinline CX_VOID
CxMovsq(CX_UINT64 *__dst, CX_UINT64 const *__src, CX_SIZE_T __n)
{
    __movsq((unsigned long long *)__dst, (unsigned long long const *)__src, (CX_SIZE_T)__n);
}

__forceinline CX_VOID
CxStosq(CX_UINT64 *__dst, CX_UINT64 __x, CX_SIZE_T __n)
{
    __stosq((unsigned long long *)__dst, (unsigned __int64)__x, (CX_SIZE_T)__n);
}
#endif

//
// Misc
//
__forceinline CX_VOID *
CxAddressOfReturnAddress(CX_VOID)
{
    return _AddressOfReturnAddress();
}

__forceinline CX_VOID *
CxReturnAddress(CX_VOID)
{
    return (CX_VOID *)_ReturnAddress();
}

__forceinline CX_VOID
CxCpuid(CX_INT32 __info[4], CX_INT32 __level)
{
    __cpuid(__info, __level);
}

__forceinline CX_VOID
CxCpuidEx(CX_INT32 __info[4], CX_INT32 __level, CX_INT32 __ecx)
{
    __cpuidex(__info, __level, __ecx);
}

__forceinline CX_UINT64 __cdecl
CxXgetbv(CX_UINT32 __xcr_no)
{
    return _xgetbv(__xcr_no);
}

__forceinline CX_VOID
CxHalt(CX_VOID)
{
    __halt();
}

__forceinline CX_VOID
CxMmPrefetch(CX_VOID const *p, int i)
{
    switch (i)
    {
    case 0:_mm_prefetch((const char *)p, 0); break;
    case 1:_mm_prefetch((const char *)p, 1); break;
    case 2:_mm_prefetch((const char *)p, 2); break;
    case 3:_mm_prefetch((const char *)p, 3); break;
    default:
        return;
    }
}

__forceinline CX_VOID
CxMmPause(CX_VOID)
{
    _mm_pause();
}

__forceinline CX_UINT64
CxRdtsc(CX_VOID)
{
    return __rdtsc();
}


//
// Privileged intrinsics
//
__forceinline CX_UINT64
CxReadMsr(CX_UINT32 __register)
{
    // Loads the contents of a 64-bit model specific register (MSR) specified in
    // the ECX register into registers EDX:EAX. The EDX register is loaded with
    // the high-order 32 bits of the MSR and the EAX register is loaded with the
    // low-order 32 bits. If less than 64 bits are implemented in the MSR being
    // read, the values returned to EDX:EAX in unimplemented bit locations are
    // undefined.
    return __readmsr((unsigned long)__register);
}
__forceinline CX_VOID
CxWriteMsr(CX_UINT32 __register, CX_UINT64 __value)
{
    __writemsr((unsigned long)__register, (unsigned long long)__value);
}


__forceinline CX_UINT64
CxReadCr0(CX_VOID)
{
    return __readcr0();
}

__forceinline CX_UINT64
CxReadCr3(CX_VOID)
{
    return __readcr3();
}

__forceinline CX_UINT64
CxReadCr4(CX_VOID)
{
    return __readcr4();
}

__forceinline CX_UINT64
CxReadCr8(CX_VOID)
{
    return __readcr8();
}

__forceinline CX_VOID
CxWriteCr0(CX_UINT64 __cr0_val)
{
    __writecr0((CX_SIZE_T)__cr0_val);
}

__forceinline CX_VOID
CxWriteCr3(CX_UINT64 __cr3_val)
{
    __writecr3((CX_SIZE_T)__cr3_val);
}

__forceinline CX_VOID
CxWriteCr4(CX_UINT64 __cr4_val)
{
    __writecr4((CX_SIZE_T)__cr4_val);
}

__forceinline CX_VOID
CxWriteCr8(CX_UINT64 __cr8_val)
{
    __writecr8((CX_SIZE_T)__cr8_val);
}

__forceinline CX_VOID
CxInvlpg(CX_VOID *Address)
{
    __invlpg((void*)Address);
}

#endif // _CX_MSVC_INTRIN_H_

