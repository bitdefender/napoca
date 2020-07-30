/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// REFCOUNT - minimal reference counting and free-after-last-dereference for runtimelib-like objects

#ifndef _REFCOUNT_H_
#define _REFCOUNT_H_


//
// FreeObject Callback
//
typedef NTSTATUS (*PFUNC_FreeObject)(_In_ PVOID Object);

//
// Flags
//
#define RFC_FLAG_INITIALIZED            0x00000001
#define RFC_FLAG_STATIC                 0x00000002
#define RFC_FLAG_DONT_CHECK_0_TO_1      0x00000004

//
// Object Type Masks
//
#define RFC_MASK_REF_COUNT_RESERVED     0x000000FF
#define RFC_MASK_OBJECT_TYPE            0x0000FF00
#define RFC_MASK_OBJECT_TYPE_MAJOR      0x00000F00
#define RFC_MASK_OBJECT_TYPE_MINOR      0x0000F000
#define RFC_MASK_CUSTOM                 0xFFFF0000
#define RFC_MASK_ALLOWED_TO_SET         (RFC_MASK_OBJECT_TYPE | RFC_MASK_CUSTOM)

//
// Structures
//
typedef struct _REF_COUNTER
{
    DWORD               ObjectType;     // Unique ID to identify object type to which this REF_COUNT belongs to
    volatile DWORD      Flags;          // Per-object flags
    PFUNC_FreeObject    FreeRoutine;    // Optional routine to be used to free any non static object when ref-count reaches 0
    volatile __int32    RefCount;       // Current reference count
} REF_COUNTER, *PREF_COUNTER;

//
// prototypes
//
VOID
RfcPreInit(
    _In_ PREF_COUNTER RefCnt
    );

NTSTATUS
RfcInit(
    _In_ PREF_COUNTER RefCnt,
    _In_ DWORD Flags,
    _In_ DWORD ObjectType,
    _In_ PFUNC_FreeObject FreeRoutine
    );

NTSTATUS
RfcUninit(
    _In_ PREF_COUNTER RefCnt
    );

PREF_COUNTER
RfcReference(
    _In_ PREF_COUNTER RefCnt
    );

NTSTATUS
RfcDereference(
    _Inout_ PREF_COUNTER *RefCnt
    );

//
// Object Types (Major) - Mask: 0x00000F00
//
#define RFC_OBJ_TYPE_LIST               0x00000100
/// ...

//
// Object Sub-types (Minor) - Mask: 0x0000F000 (for each Major Type)
//

// RFC_OBJ_TYPE_LIST
#define RFC_OBJ_SUBTYPE_DLL_LIST        0x00001000
#define RFC_OBJ_SUBTYPE_SLL_LIST        0x00002000
#define RFC_OBJ_SUBTYPE_LRLW_LIST       0x00003000


#endif // _REFCOUNT_H_