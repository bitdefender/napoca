/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_CX_WINTYPES_H
#include crt_INC_SETTINGS_CX_WINTYPES_H // define it to some .h file name/path if you want to provide settings
#endif


//
// Undecorated (no CX_) wrapper over cx_types.h
// IMPORTANT: cx_types.h provides safer equivalent definitions for reusable/generic/library code
// NOTE: might not be a complete wrapper, feel free to add any relevant missing definitions here
//

#ifndef _CX_WINYPES_H_
#define _CX_WINYPES_H_


#include "base/cx_types.h"

#if ( !defined(CRT_SKIP_DECL_CHAR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_CHAR))  )
typedef CX_INT8     CHAR;
#endif

#if ( !defined(CRT_SKIP_DECL_SHORT) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SHORT))  )
typedef CX_INT16    SHORT;
#endif

#if ( !defined(CRT_SKIP_DECL_LONG) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONG))  )
typedef CX_INT32    LONG;
#endif

#if ( !defined(CRT_SKIP_DECL_LONGLONG) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONGLONG))  )
typedef CX_INT64    LONGLONG;
#endif


#if ( !defined(CRT_SKIP_DECL_PCHAR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PCHAR))  )
typedef CX_INT8     *PCHAR;
#endif

#if ( !defined(CRT_SKIP_DECL_PSHORT) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PSHORT))  )
typedef CX_INT16    *PSHORT;
#endif

#if ( !defined(CRT_SKIP_DECL_PLONG) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PLONG))  )
typedef CX_INT32    *PLONG;
#endif

#if ( !defined(CRT_SKIP_DECL_PLONGLONG) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PLONGLONG))  )
typedef CX_INT64    *PLONGLONG;
#endif



#if ( !defined(CRT_SKIP_DECL_BYTE) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_BYTE))  )
typedef CX_UINT8    BYTE, UCHAR, BOOLEAN;
#endif

#if ( !defined(CRT_SKIP_DECL_WORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_WORD))  )
typedef CX_UINT16   WORD, USHORT, WCHAR;
#endif

#if ( !defined(CRT_SKIP_DECL_DWORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_DWORD))  )
typedef CX_UINT32   DWORD, ULONG;
#endif

#if ( !defined(CRT_SKIP_DECL_QWORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_QWORD))  )
typedef CX_UINT64   QWORD, ULONGLONG;
#endif


#if ( !defined(CRT_SKIP_DECL_PBYTE) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PBYTE))  )
typedef CX_UINT8    *PBYTE, *PUCHAR, *PBOOLEAN;
#endif

#if ( !defined(CRT_SKIP_DECL_PWORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PWORD))  )
typedef CX_UINT16   *PWORD, *PUSHORT, *PWCHAR;
#endif

#if ( !defined(CRT_SKIP_DECL_PDWORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PDWORD))  )
typedef CX_UINT32   *PDWORD, *PULONG;
#endif

#if ( !defined(CRT_SKIP_DECL_PQWORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PQWORD))  )
typedef CX_UINT64   *PQWORD, *PULONGLONG;
#endif


#ifdef CX_ARCH64
#if ( !defined(CRT_SKIP_DECL_INT_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_INT_PTR))  )
typedef CX_INT64    INT_PTR, *PINT_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_UINT_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_UINT_PTR))  )
typedef CX_UINT64   UINT_PTR, *PUINT_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_LONG_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONG_PTR))  )
typedef CX_INT64    LONG_PTR, *PLONG_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_ULONG_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONG_PTR))  )
typedef CX_UINT64   ULONG_PTR, *PULONG_PTR;
#endif

#else
#if ( !defined(CRT_SKIP_DECL_INT_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_INT_PTR))  )
typedef CX_INT32    INT_PTR, *PINT_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_UINT_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_UINT_PTR))  )
typedef CX_UINT32   UINT_PTR, *PUINT_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_LONG_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONG_PTR))  )
typedef CX_INT32    LONG_PTR, *PLONG_PTR;
#endif

#if ( !defined(CRT_SKIP_DECL_ULONG_PTR) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONG_PTR))  )
typedef CX_INT32    ULONG_PTR, *PULONG_PTR;
#endif

#endif

#if ( !defined(CRT_SKIP_DECL_STATUS) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_STATUS))  )
typedef CX_STATUS   STATUS;
#endif

#if ( !defined(CRT_SKIP_DECL_PSTATUS) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PSTATUS))  )
typedef CX_STATUS   *PSTATUS;
#endif


// windows/nt themed wrapper might get added -- keep *VOID* defined once
#ifndef _CX_DEFS_VOID_
#if ( !defined(CRT_SKIP_DECL__CX_DEFS_VOID_) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL__CX_DEFS_VOID_))  )
#define _CX_DEFS_VOID_
#endif

#if ( !defined(CRT_SKIP_DECL_VOID) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_VOID))  )
typedef CX_VOID  VOID;
#endif

#if ( !defined(CRT_SKIP_DECL_PVOID) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PVOID))  )
typedef PCX_VOID PVOID;
#endif

#endif //_CX_DEFS_VOID_

#if ( !defined(CRT_SKIP_DECL_CHAR_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_CHAR_MIN))  )
#define CHAR_MIN                    CX_INT8_MIN_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_CHAR_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_CHAR_MAX))  )
#define CHAR_MAX                    CX_INT8_MAX_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_SHORT_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SHORT_MIN))  )
#define SHORT_MIN                   CX_INT16_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_SHORT_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SHORT_MAX))  )
#define SHORT_MAX                   CX_INT16_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_LONG_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONG_MIN))  )
#define LONG_MIN                    CX_INT32_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_LONG_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONG_MAX))  )
#define LONG_MAX                    CX_INT32_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_LONGLONG_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONGLONG_MIN))  )
#define LONGLONG_MIN                CX_INT64_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_LONGLONG_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_LONGLONG_MAX))  )
#define LONGLONG_MAX                CX_INT64_MAX_VALUE  
#endif


#if ( !defined(CRT_SKIP_DECL_BYTE_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_BYTE_MIN))  )
#define BYTE_MIN                    CX_UINT8_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_BYTE_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_BYTE_MAX))  )
#define BYTE_MAX                    CX_UINT8_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_UCHAR_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_UCHAR_MIN))  )
#define UCHAR_MIN                   CX_UINT8_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_UCHAR_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_UCHAR_MAX))  )
#define UCHAR_MAX                   CX_UINT8_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_WORD_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_WORD_MIN))  )
#define WORD_MIN                    CX_UINT16_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_WORD_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_WORD_MAX))  )
#define WORD_MAX                    CX_UINT16_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_USHORT_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_USHORT_MIN))  )
#define USHORT_MIN                  CX_UINT16_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_USHORT_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_USHORT_MAX))  )
#define USHORT_MAX                  CX_UINT16_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_WCHAR_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_WCHAR_MIN))  )
#define WCHAR_MIN                   CX_UINT16_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_WCHAR_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_WCHAR_MAX))  )
#define WCHAR_MAX                   CX_UINT16_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_DWORD_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_DWORD_MIN))  )
#define DWORD_MIN                   CX_UINT32_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_DWORD_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_DWORD_MAX))  )
#define DWORD_MAX                   CX_UINT32_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_ULONG_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONG_MIN))  )
#define ULONG_MIN                   CX_UINT32_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_ULONG_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONG_MAX))  )
#define ULONG_MAX                   CX_UINT32_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_QWORD_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_QWORD_MIN))  )
#define QWORD_MIN                   CX_UINT64_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_QWORD_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_QWORD_MAX))  )
#define QWORD_MAX                   CX_UINT64_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_ULONGLONG_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONGLONG_MIN))  )
#define ULONGLONG_MIN               CX_UINT64_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_ULONGLONG_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_ULONGLONG_MAX))  )
#define ULONGLONG_MAX               CX_UINT64_MAX_VALUE 
#endif



// windows/nt themed wrapper might get added -- keep *SIZE_T* defined once
#ifndef _CX_DEFS_SIZE_T_
#if ( !defined(CRT_SKIP_DECL__CX_DEFS_SIZE_T_) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL__CX_DEFS_SIZE_T_))  )
#define _CX_DEFS_SIZE_T_
#endif

#if ( !defined(CRT_SKIP_DECL_SIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SIZE_T))  )
typedef CX_SIZE_T   SIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_PSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PSIZE_T))  )
typedef CX_SIZE_T   *PSIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T))  )
typedef CX_SSIZE_T  SSIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_PSSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_PSSIZE_T))  )
typedef CX_SSIZE_T  *PSSIZE_T;
#endif


#if ( !defined(CRT_SKIP_DECL_SIZE_T_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SIZE_T_MIN))  )
#define SIZE_T_MIN                  CX_SIZE_T_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SIZE_T_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SIZE_T_MAX))  )
#define SIZE_T_MAX                  CX_SIZE_T_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T_MIN))  )
#define SSIZE_T_MIN                 CX_SSIZE_T_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_WINTYPES_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T_MAX))  )
#define SSIZE_T_MAX                 CX_SSIZE_T_MAX_VALUE 
#endif

#endif //_CX_DEFS_SIZE_T_


#endif // _CX_WINYPES_H_
