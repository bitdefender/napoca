/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_CX_DEFS_SHORT_H
#include crt_INC_SETTINGS_CX_DEFS_SHORT_H // define it to some .h file name/path if you want to provide settings
#endif


//
// Undecorated (no CX_) wrapper over cx_defs.h
// IMPORTANT: cx_defs.h provides safer equivalent definitions for reusable/generic/library code
// NOTE: might not be a complete wrapper, some definitions might be missing if this file is not kept up-to-date
//

#ifndef _CX_DEFS_SHORT_H_
#define _CX_DEFS_SHORT_H_

#include "base/cx_defs.h"

#if ( !defined(CRT_SKIP_DECL_TRUE) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_TRUE))  )
#define TRUE                            CX_TRUE
#endif

#if ( !defined(CRT_SKIP_DECL_FALSE) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_FALSE))  )
#define FALSE                           CX_FALSE
#endif


#if ( !defined(CRT_SKIP_DECL_NULL) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_NULL))  )
#define NULL                            CX_NULL
#endif


#if ( !defined(CRT_SKIP_DECL_KILO) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_KILO))  )
#define KILO                            CX_KILO
#endif

#if ( !defined(CRT_SKIP_DECL_MEGA) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_MEGA))  )
#define MEGA                            CX_MEGA
#endif

#if ( !defined(CRT_SKIP_DECL_GIGA) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_GIGA))  )
#define GIGA                            CX_GIGA
#endif

#if ( !defined(CRT_SKIP_DECL_TERA) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_TERA))  )
#define TERA                            CX_TERA
#endif


#if ( !defined(CRT_SKIP_DECL_PAGE_SIZE_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_SIZE_4K))  )
#define PAGE_SIZE_4K                    CX_PAGE_SIZE_4K
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_OFFSET_MASK_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_OFFSET_MASK_4K))  )
#define PAGE_OFFSET_MASK_4K             CX_PAGE_OFFSET_MASK_4K
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_MAX_OFFSET_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_MAX_OFFSET_4K))  )
#define PAGE_MAX_OFFSET_4K              CX_PAGE_MAX_OFFSET_4K
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_BASE_MASK_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_BASE_MASK_4K))  )
#define PAGE_BASE_MASK_4K               CX_PAGE_BASE_MASK_4K
#endif


#if ( !defined(CRT_SKIP_DECL_PAGE_SIZE_2M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_SIZE_2M))  )
#define PAGE_SIZE_2M                    CX_PAGE_SIZE_2M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_OFFSET_MASK_2M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_OFFSET_MASK_2M))  )
#define PAGE_OFFSET_MASK_2M             CX_PAGE_OFFSET_MASK_2M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_MAX_OFFSET_2M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_MAX_OFFSET_2M))  )
#define PAGE_MAX_OFFSET_2M              CX_PAGE_MAX_OFFSET_2M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_BASE_MASK_2M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_BASE_MASK_2M))  )
#define PAGE_BASE_MASK_2M               CX_PAGE_BASE_MASK_2M
#endif


#if ( !defined(CRT_SKIP_DECL_PAGE_SIZE_4M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_SIZE_4M))  )
#define PAGE_SIZE_4M                    CX_PAGE_SIZE_4M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_OFFSET_MASK_4M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_OFFSET_MASK_4M))  )
#define PAGE_OFFSET_MASK_4M             CX_PAGE_OFFSET_MASK_4M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_MAX_OFFSET_4M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_MAX_OFFSET_4M))  )
#define PAGE_MAX_OFFSET_4M              CX_PAGE_MAX_OFFSET_4M
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_BASE_MASK_4M) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_BASE_MASK_4M))  )
#define PAGE_BASE_MASK_4M               CX_PAGE_BASE_MASK_4M
#endif


#if ( !defined(CRT_SKIP_DECL_PAGE_SIZE_1G) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_SIZE_1G))  )
#define PAGE_SIZE_1G                    CX_PAGE_SIZE_1G
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_OFFSET_MASK_1G) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_OFFSET_MASK_1G))  )
#define PAGE_OFFSET_MASK_1G             CX_PAGE_OFFSET_MASK_1G
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_MAX_OFFSET_1G) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_MAX_OFFSET_1G))  )
#define PAGE_MAX_OFFSET_1G              CX_PAGE_MAX_OFFSET_1G
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_BASE_MASK_1G) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_BASE_MASK_1G))  )
#define PAGE_BASE_MASK_1G               CX_PAGE_BASE_MASK_1G
#endif



#if ( !defined(CRT_SKIP_DECL_MIN) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_MIN))  )
#define MIN(a,b)                        CX_MIN(a,b)
#endif

#if ( !defined(CRT_SKIP_DECL_MAX) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_MAX))  )
#define MAX(a,b)                        CX_MAX(a,b)
#endif


#if ( !defined(CRT_SKIP_DECL_ROUND_UP) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_ROUND_UP))  )
#define ROUND_UP(what, to)              CX_ROUND_UP(what, to)
#endif

#if ( !defined(CRT_SKIP_DECL_ROUND_DOWN) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_ROUND_DOWN))  )
#define ROUND_DOWN(what, to)            CX_ROUND_DOWN(what, to)
#endif


#if ( !defined(CRT_SKIP_DECL_PAGE_BASE_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_BASE_4K))  )
#define PAGE_BASE_4K(addr)              CX_PAGE_BASE_4K(addr)
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_OFFSET_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_OFFSET_4K))  )
#define PAGE_OFFSET_4K(addr)            CX_PAGE_OFFSET_4K(addr)
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_FRAME_NUMBER_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_FRAME_NUMBER_4K))  )
#define PAGE_FRAME_NUMBER_4K(addr)      CX_PAGE_FRAME_NUMBER_4K(addr)
#endif

#if ( !defined(CRT_SKIP_DECL_PAGE_COUNT_4K) && (!defined(CRT_DEFAULT_SKIP_CX_DEFS_SHORT_H_DECL) || defined(CRT_WANT_DECL_PAGE_COUNT_4K))  )
#define PAGE_COUNT_4K(addr, bytes)      CX_PAGE_COUNT_4K(addr, bytes)
#endif


#ifndef CONTAINING_RECORD
#if ( !defined(CRT_SKIP_DECL_CONTAINING_RECORD) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_CONTAINING_RECORD))  )
#define CONTAINING_RECORD(address, type, field)     CX_CONTAINING_RECORD(address, type, field)
#endif
#endif

#ifndef FIELD_OFFSET
#if ( !defined(CRT_SKIP_DECL_FIELD_OFFSET) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_FIELD_OFFSET))  )
#define FIELD_OFFSET(type, field)                   CX_FIELD_OFFSET(type, field)
#endif
#endif

#ifndef FIELD_SIZE
#if ( !defined(CRT_SKIP_DECL_FIELD_SIZE) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_FIELD_SIZE))  )
#define FIELD_SIZE(type, field)                     CX_FIELD_SIZE(type, field)
#endif
#endif



#endif // _CX_DEFS_SHORT_H_
