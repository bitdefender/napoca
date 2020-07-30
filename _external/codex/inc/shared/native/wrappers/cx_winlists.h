/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_CX_WINLISTS_H
#include crt_INC_SETTINGS_CX_WINLISTS_H // define it to some .h file name/path if you want to provide settings
#endif


//
// Undecorated (no CX_) variant of cx_lists.h
// IMPORTANT: cx_lists.h provides safer equivalent definitions for reusable/generic/library code
//
#ifndef _CX_WINLISTS_H_
#define _CX_WINLISTS_H_

#include "base/cx_types.h"
#include "base/cx_synchronization.h"
#include "wrappers/cx_wintypes.h"
#include "wrappers/cx_defs_short.h"
#include "base/cx_defs.h"




//
// WDK like doubly linked lists
//

#if ( !defined(CRT_SKIP_DECL__LIST_ENTRY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL__LIST_ENTRY))  )
typedef struct _LIST_ENTRY {
    union {
        struct _LIST_ENTRY *Flink;
        struct _LIST_ENTRY *Head;
    };
    union {
        struct _LIST_ENTRY *Blink;
        struct _LIST_ENTRY *Tail;
    };
} LIST_ENTRY, LIST_HEAD, *PLIST_ENTRY, *PLIST_HEAD;
#endif


#if ( !defined(CRT_SKIP_DECL_INITIALIZELISTHEAD) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INITIALIZELISTHEAD))  )
__forceinline CX_VOID
InitializeListHead(
    _Out_ PLIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}
#endif


#if ( !defined(CRT_SKIP_DECL_ISLISTEMPTY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_ISLISTEMPTY))  )
__forceinline BOOLEAN
IsListEmpty(
    _In_ const LIST_ENTRY * ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}
#endif


#if ( !defined(CRT_SKIP_DECL_REMOVEENTRYLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_REMOVEENTRYLIST))  )
__forceinline BOOLEAN
RemoveEntryList(
    _In_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    Entry->Flink = NULL;
    Entry->Blink = NULL;
    return (BOOLEAN)(Flink == Blink);
}
#endif


#if ( !defined(CRT_SKIP_DECL_REMOVEHEADLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_REMOVEHEADLIST))  )
__forceinline PLIST_ENTRY
RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}
#endif


#if ( !defined(CRT_SKIP_DECL_REMOVETAILLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_REMOVETAILLIST))  )
__forceinline PLIST_ENTRY
RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}
#endif


#if ( !defined(CRT_SKIP_DECL_INSERTTAILLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INSERTTAILLIST))  )
__forceinline CX_VOID
InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}
#endif


#if ( !defined(CRT_SKIP_DECL_INSERTHEADLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INSERTHEADLIST))  )
__forceinline CX_VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}
#endif


#if ( !defined(CRT_SKIP_DECL_INSERTAFTERLIST) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INSERTAFTERLIST))  )
__forceinline CX_VOID InsertAfterList(
    _Inout_ PLIST_ENTRY Pivot,
    _Inout_ PLIST_ENTRY Item
    )
{
    Pivot->Flink->Blink = Item;
    Item->Flink = Pivot->Flink;
    Pivot->Flink = Item;
    Item->Blink = Pivot;
}
#endif




//
// WDK like singly linked interlocked stack
//
#if ( !defined(CRT_SKIP_DECL_INTERLOCKED_STACK) || defined(CRT_WANT_DECL_INTERLOCKED_STACK) )

#if ( !defined(CRT_SKIP_DECL_STACK_LOCKED_FOR_POP) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_STACK_LOCKED_FOR_POP))  )
#define STACK_LOCKED_FOR_POP            0x1
#endif


#if ( !defined(CRT_SKIP_DECL__STACK_ENTRY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL__STACK_ENTRY))  )
typedef struct _STACK_ENTRY {
    struct _STACK_ENTRY * volatile Next;
} STACK_ENTRY, STACK_HEAD, *PSTACK_ENTRY, *PSTACK_HEAD;
#endif


#if ( !defined(CRT_SKIP_DECL_INITIALIZESTACKHEAD) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INITIALIZESTACKHEAD))  )
__forceinline CX_VOID
InitializeStackHead(
    _Inout_ PSTACK_HEAD StackHead
    )
{
    StackHead->Next = NULL;
}
#endif


#if ( !defined(CRT_SKIP_DECL_ISSTACKEMPTY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_ISSTACKEMPTY))  )
__forceinline BOOLEAN
IsStackEmpty(
    _In_ const PSTACK_HEAD StackHead
    )
{
    return (BOOLEAN)(NULL == StackHead->Next);
}
#endif


#if ( !defined(CRT_SKIP_DECL_INTERLOCKEDPOPSTACKENTRY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INTERLOCKEDPOPSTACKENTRY))  )
__forceinline PSTACK_ENTRY
InterlockedPopStackEntry(
    _Inout_ PSTACK_HEAD StackHead
    )
{
    PSTACK_ENTRY top, next, old;

    while (TRUE)
    {
        top = (PSTACK_ENTRY)StackHead->Next;
        if (NULL == top)
        {
            break;
        }

        // do NOT push if TOP-OF-STACK is marked for POP
        if ((CX_INT64)top & STACK_LOCKED_FOR_POP)
            continue;

        // lock this item
        old = CxInterlockedCompareExchangePointer(&StackHead->Next, (CX_VOID*)((CX_SIZE_T)top & STACK_LOCKED_FOR_POP), top);

        // if we coundn't lock, retry
        if (old != top)
            continue;

        // get next
        next = (PSTACK_ENTRY)top->Next;

        // simply write back the pointer (check out Intel manuals, '8.1.1 Guaranteed Atomic Operations')
        StackHead->Next = next;
        ///old = _InterlockedCompareExchangePointer(&StackHead->Next, next, (top & STACK_LOCKED_FOR_POP));
        break;  // will return top
    }

    return top;
}
#endif


#if ( !defined(CRT_SKIP_DECL_INTERLOCKEDPUSHSTACKENTRY) && (!defined(CRT_DEFAULT_SKIP_CX_WINLISTS_H_DECL) || defined(CRT_WANT_DECL_INTERLOCKEDPUSHSTACKENTRY))  )
__forceinline CX_VOID
InterlockedPushStackEntry(
    _Inout_ PSTACK_HEAD StackHead,
    _Inout_ PSTACK_ENTRY Entry
    )
{
    PSTACK_ENTRY top, old;

    while (TRUE)
    {
        top = (PSTACK_ENTRY)(StackHead->Next);

        // do NOT push if TOP-OF-STACK is marked for POP
        if ((CX_INT64)top & STACK_LOCKED_FOR_POP)
            continue;

        Entry->Next = top;

        old = CxInterlockedCompareExchangePointer(&StackHead->Next, Entry, top);

        // could we successfully switch? if yes, then exit out...
        if (old == top)
            break;
    }
}
#endif

#endif

#endif // _CX_WINLISTS_H_
