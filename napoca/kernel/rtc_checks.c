/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"

#define RTC_UNUSED_PATTERN                  (CX_UINT32)0xCCCCCCCCUL                     ///< Constant for marking stack space areas

#define GET_RETURN_ADDRESS                  *((CX_VOID **)_AddressOfReturnAddress())    ///< Return address of the current function

#pragma pack(push, 8)
typedef struct _RTC_vardesc
{
    // offsets from ESP
    CX_UINT32 addr;
    CX_UINT32 size;
    char *name;
} _RTC_vardesc;

typedef struct _RTC_framedesc
{
    CX_UINT32           varCount;
    CX_UINT32           __alignment;
    _RTC_vardesc*   variables;
} _RTC_framedesc;
#pragma pack(pop)

/**
 * @brief Run-Time Error Checks method. Logs the error and unloads the hypervisor.
 * @brief NOT referenced anywhere in code.
*/
__declspec(noreturn)
CX_VOID
__cdecl
_RTC_Shutdown(
    CX_VOID
)
{
    CRITICAL("Function which corrupted the stack is %018p\n", GET_RETURN_ADDRESS);

    CLN_UNLOAD(STATUS_RTC_SHUTDOWN);
}

/**
 * @brief Run-Time Error Checks method. Logs the error and unloads the hypervisor.
 * @brief NOT referenced anywhere in code.
*/
__declspec(noreturn)
CX_VOID
__cdecl
_RTC_InitBase(
    CX_VOID
)
{
    CRITICAL("Function which corrupted the stack is %018p\n", GET_RETURN_ADDRESS);

    CLN_UNLOAD(STATUS_RTC_INIT_BASE);
}

/**
 * @brief Run-Time Error Checks method for checking buffer overflows near protected variables.
 * @brief If a buffer overflow is detected the error is logged and the hypervisor is unloaded.
*/
CX_VOID
__fastcall
_RTC_CheckStackVars(
    CX_VOID          *Rsp,
    _RTC_framedesc *_Fd
)
{
    for (CX_UINT32 i = 0; i < _Fd->varCount; ++i)
    {
        CX_UINT32 baseValue, endValue;

        CX_UINT32 *varStartVA = (CX_UINT32 *)PTR_ADD(Rsp, _Fd->variables[i].addr);
        CX_UINT32 *varEndVa = (CX_UINT32 *)PTR_ADD(varStartVA, _Fd->variables[i].size);

        baseValue = *(varStartVA - 1);
        endValue = *varEndVa;

        if ((baseValue != RTC_UNUSED_PATTERN) || (endValue != RTC_UNUSED_PATTERN))
        {
            LOG("Corruption occurred near variable [%s]\n"
                "Value before variable is 0x%08X at %018p\n"
                "Value after variable is 0x%08X at %018p\n"
                "Both values should be 0x%08X\n"
                "RA (Faulting Function) at %018p\n",
                _Fd->variables[i].name,
                baseValue, varStartVA - 1,
                endValue, varEndVa,
                RTC_UNUSED_PATTERN,
                GET_RETURN_ADDRESS);

            CLN_UNLOAD(STATUS_RTC_STACK_CORRUPT);
        }
    }
}