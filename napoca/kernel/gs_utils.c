/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"

extern CX_UINT64 __security_cookie;

#define MAX_SUPPORTED_STACK_FRAME_SIZE              (16 * CX_KILO)      ///< Maximum supported stack size

CX_STATUS
GsUtilsNotifyStackChange(
    _In_ _Inout_updates_bytes_(StackSize)
          CX_VOID      *OldStackTop,
    _In_ _Inout_updates_bytes_(StackSize)
          CX_VOID      *NewStackTop,
    _In_  CX_UINT64       StackSize
)
{
    UNREFERENCED_PARAMETER(StackSize);
    if (OldStackTop == CX_NULL) return STATUS_GS_INVALID_OLD_STACK;
    if (NewStackTop == CX_NULL) return STATUS_GS_INVALID_NEW_STACK;
    if (PAGE_OFFSET((CX_SIZE_T)OldStackTop) != PAGE_OFFSET((CX_SIZE_T)NewStackTop)) return STATUS_GS_INEQUAL_STACK_OFFSETS;

    CX_VOID *newRsp = _AddressOfReturnAddress();
    CX_UINT64 *oldStack = (CX_UINT64 *)((CX_SIZE_T)OldStackTop + (CX_SIZE_T)newRsp - (CX_SIZE_T)NewStackTop);
    CX_UINT64 *newStack = (CX_UINT64 *)(newRsp);
    CX_UINT32 totalStackEntries = (CX_UINT32)(((CX_SIZE_T)OldStackTop - (CX_SIZE_T)oldStack) / sizeof(CX_UINT64));

    for (CX_UINT32 i = 0; i < totalStackEntries; i++)
    {
        // the value of each cookie = __security_cookie xor (it's address + some delta)
        // find the delta by xoring the cookie back with __security_cookie and subtracting its address => if the resulting delta
        // is small enough, it is highly likely (based on how "random" the __security_cookie value is) this is indeed a cookie and
        // we can reuse the delta for relocating the cookie to its new address (on the new stack)

        CX_INT64 rspCookieDelta = (oldStack[i] ^ __security_cookie) - ((CX_INT64)&oldStack[i]);
        if (CX_ABS(rspCookieDelta) < MAX_SUPPORTED_STACK_FRAME_SIZE)
        {
            CX_UINT64 newCookie = __security_cookie ^ (((CX_SIZE_T)&newStack[i]) + rspCookieDelta);
            oldStack[i] = newStack[i] = newCookie;
        }
    }

    return CX_STATUS_SUCCESS;
}

#ifdef DEBUG

// unused
void __chkstk(void) {}

#endif // DEBUG
