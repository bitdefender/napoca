/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_CX_TYPES_SHORT_H
#include crt_INC_SETTINGS_CX_TYPES_SHORT_H // define it to some .h file name/path if you want to provide settings
#endif


//
// Undecorated (no CX_) wrapper over cx_types.h
// IMPORTANT: cx_types.h provides safer equivalent definitions for reusable/generic/library code
// NOTE: might not be a complete wrapper, some definitions might be missing if this file is not kept up-to-date
//

#ifndef _CX_TYPES_SHORT_H_
#define _CX_TYPES_SHORT_H_


#include "base/cx_types.h"

#if ( !defined(CRT_SKIP_DECL_INT8) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT8))  )
typedef CX_INT8         INT8;
#endif

#if ( !defined(CRT_SKIP_DECL_INT16) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT16))  )
typedef CX_INT16        INT16;
#endif

#if ( !defined(CRT_SKIP_DECL_INT32) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT32))  )
typedef CX_INT32        INT32;
#endif

#if ( !defined(CRT_SKIP_DECL_INT64) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT64))  )
typedef CX_INT64        INT64;
#endif


#if ( !defined(CRT_SKIP_DECL_PINT8) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PINT8))  )
typedef CX_INT8         *PINT8;
#endif

#if ( !defined(CRT_SKIP_DECL_PINT16) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PINT16))  )
typedef CX_INT16        *PINT16;
#endif

#if ( !defined(CRT_SKIP_DECL_PINT32) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PINT32))  )
typedef CX_INT32        *PINT32;
#endif

#if ( !defined(CRT_SKIP_DECL_PINT64) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PINT64))  )
typedef CX_INT64        *PINT64;
#endif



#if ( !defined(CRT_SKIP_DECL_UINT8) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT8))  )
typedef CX_UINT8        UINT8;
#endif

#if ( !defined(CRT_SKIP_DECL_UINT16) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT16))  )
typedef CX_UINT16       UINT16;
#endif

#if ( !defined(CRT_SKIP_DECL_UINT32) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT32))  )
typedef CX_UINT32       UINT32;
#endif

#if ( !defined(CRT_SKIP_DECL_UINT64) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT64))  )
typedef CX_UINT64       UINT64;
#endif


#if ( !defined(CRT_SKIP_DECL_PUINT8) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PUINT8))  )
typedef CX_UINT8        *PUINT8;
#endif

#if ( !defined(CRT_SKIP_DECL_PUINT16) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PUINT16))  )
typedef CX_UINT16       *PUINT16;
#endif

#if ( !defined(CRT_SKIP_DECL_PUINT32) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PUINT32))  )
typedef CX_UINT32       *PUINT32;
#endif

#if ( !defined(CRT_SKIP_DECL_PUINT64) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PUINT64))  )
typedef CX_UINT64       *PUINT64;
#endif



#if ( !defined(CRT_SKIP_DECL_BOOL) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_BOOL))  )
typedef CX_BOOL64       BOOL;
#endif

#if ( !defined(CRT_SKIP_DECL_PBOOL) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PBOOL))  )
typedef CX_BOOL64       *PBOOL;
#endif


#if ( !defined(CRT_SKIP_DECL_STATUS) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_STATUS))  )
typedef CX_STATUS       STATUS;
#endif

#if ( !defined(CRT_SKIP_DECL_PSTATUS) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PSTATUS))  )
typedef CX_STATUS       *PSTATUS;
#endif

#if ( !defined(CRT_SKIP_DECL_INTMAXTYPE) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INTMAXTYPE))  )
typedef CX_INTMAXTYPE   INTMAXTYPE;
#endif

#if ( !defined(CRT_SKIP_DECL_UINTMAXTYPE) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINTMAXTYPE))  )
typedef CX_UINTMAXTYPE  UINTMAXTYPE;
#endif


// windows/nt themed wrapper might get added -- keep *VOID* defined once
#ifndef _CX_DEFS_VOID_
#if ( !defined(CRT_SKIP_DECL__CX_DEFS_VOID_) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL__CX_DEFS_VOID_))  )
#define _CX_DEFS_VOID_
#endif

#if ( !defined(CRT_SKIP_DECL_VOID) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_VOID))  )
typedef CX_VOID  VOID;
#endif

#if ( !defined(CRT_SKIP_DECL_PVOID) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PVOID))  )
typedef PCX_VOID PVOID;
#endif

#endif //_CX_DEFS_VOID_

#if ( !defined(CRT_SKIP_DECL_BOOL_WIDTH) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_BOOL_WIDTH))  )
#define BOOL_WIDTH                  CX_BOOL_WIDTH
#endif

#if ( !defined(CRT_SKIP_DECL_INT8_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT8_MIN))  )
#define INT8_MIN                    CX_INT8_MIN_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_INT8_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT8_MAX))  )
#define INT8_MAX                    CX_INT8_MAX_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_INT16_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT16_MIN))  )
#define INT16_MIN                   CX_INT16_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_INT16_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT16_MAX))  )
#define INT16_MAX                   CX_INT16_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_INT32_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT32_MIN))  )
#define INT32_MIN                   CX_INT32_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_INT32_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT32_MAX))  )
#define INT32_MAX                   CX_INT32_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_INT64_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT64_MIN))  )
#define INT64_MIN                   CX_INT64_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_INT64_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INT64_MAX))  )
#define INT64_MAX                   CX_INT64_MAX_VALUE  
#endif


#if ( !defined(CRT_SKIP_DECL_UINT8_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT8_MIN))  )
#define UINT8_MIN                   CX_UINT8_MIN_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_UINT8_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT8_MAX))  )
#define UINT8_MAX                   CX_UINT8_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_UINT16_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT16_MIN))  )
#define UINT16_MIN                  CX_UINT16_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_UINT16_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT16_MAX))  )
#define UINT16_MAX                  CX_UINT16_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_UINT32_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT32_MIN))  )
#define UINT32_MIN                  CX_UINT32_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_UINT32_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT32_MAX))  )
#define UINT32_MAX                  CX_UINT32_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_UINT64_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT64_MIN))  )
#define UINT64_MIN                  CX_UINT64_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_UINT64_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINT64_MAX))  )
#define UINT64_MAX                  CX_UINT64_MAX_VALUE
#endif


#if ( !defined(CRT_SKIP_DECL_INTMAXTYPE_WIDTH) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INTMAXTYPE_WIDTH))  )
#define INTMAXTYPE_WIDTH            CX_INTMAXTYPE_WIDTH       
#endif

#if ( !defined(CRT_SKIP_DECL_UINTMAXTYPE_WIDTH) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINTMAXTYPE_WIDTH))  )
#define UINTMAXTYPE_WIDTH           CX_UINTMAXTYPE_WIDTH      
#endif

#if ( !defined(CRT_SKIP_DECL_INTMAXTYPE_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INTMAXTYPE_MIN))  )
#define INTMAXTYPE_MIN              CX_INTMAXTYPE_MIN_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_INTMAXTYPE_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_INTMAXTYPE_MAX))  )
#define INTMAXTYPE_MAX              CX_INTMAXTYPE_MAX_VALUE   
#endif

#if ( !defined(CRT_SKIP_DECL_UINTMINTYPE_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINTMINTYPE_MAX))  )
#define UINTMINTYPE_MAX             CX_UINTMAXTYPE_MAX_VALUE  
#endif

#if ( !defined(CRT_SKIP_DECL_UINTMAXTYPE_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_UINTMAXTYPE_MAX))  )
#define UINTMAXTYPE_MAX             CX_UINTMAXTYPE_MAX_VALUE  
#endif

// windows/nt themed wrapper might get added -- keep *SIZE_T* defined once
#ifndef _CX_DEFS_SIZE_T_
#if ( !defined(CRT_SKIP_DECL__CX_DEFS_SIZE_T_) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL__CX_DEFS_SIZE_T_))  )
#define _CX_DEFS_SIZE_T_
#endif

#if ( !defined(CRT_SKIP_DECL_SIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SIZE_T))  )
typedef CX_SIZE_T   SIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_PSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PSIZE_T))  )
typedef CX_SIZE_T   *PSIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T))  )
typedef CX_SSIZE_T  SSIZE_T;
#endif

#if ( !defined(CRT_SKIP_DECL_PSSIZE_T) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_PSSIZE_T))  )
typedef CX_SSIZE_T  *PSSIZE_T;
#endif


#if ( !defined(CRT_SKIP_DECL_SIZE_T_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SIZE_T_MIN))  )
#define SIZE_T_MIN                  CX_SIZE_T_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SIZE_T_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SIZE_T_MAX))  )
#define SIZE_T_MAX                  CX_SIZE_T_MAX_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T_MIN))  )
#define SSIZE_T_MIN                 CX_SSIZE_T_MIN_VALUE 
#endif

#if ( !defined(CRT_SKIP_DECL_SSIZE_T_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_TYPES_SHORT_H_DECL) || defined(CRT_WANT_DECL_SSIZE_T_MAX))  )
#define SSIZE_T_MAX                 CX_SSIZE_T_MAX_VALUE 
#endif

#endif //_CX_DEFS_SIZE_T_




#endif // _CX_TYPES_SHORT_H_
