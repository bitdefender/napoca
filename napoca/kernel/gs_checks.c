/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"

#define GET_RETURN_ADDRESS                  *((CX_VOID **)_AddressOfReturnAddress())    ///< Address of the current stack

#define DEFAULT_SECURITY_COOKIE_VALUE       0x3D79'CF46'20CA'B10EULL        ///< Security value used to check the integrity of the stack

const CX_UINT64 __security_cookie = DEFAULT_SECURITY_COOKIE_VALUE;          ///< Wrapper for DEFAULT_SECURITY_COOKIE_VALUE

// Called when a buffer bound check fails
// From what I've seen in the disassembly no parameters passed => we can only print the location where the instruction occurred

/**
 * @brief GS Buffer Security Check method.
 * @brief Logs the security error and unloads the Hypervisor
*/
__declspec(noreturn)
CX_VOID
__report_rangecheckfailure(
    CX_VOID
)
{
    CRITICAL("Function which corrupted the stack is %018p\n", GET_RETURN_ADDRESS);

    CLN_UNLOAD(STATUS_GS_RANGE_CHECK_FAILURE);
}

#pragma optimize( "", off)

/**
 * @brief GS Buffer Security Check method.
 * @brief Logs the security error and unloads the Hypervisor
*/
__declspec(noreturn)
CX_VOID
__GSHandlerCheck(
    CX_VOID
)
{
    CRITICAL("Function which corrupted the stack is %018p\n", GET_RETURN_ADDRESS);

    CLN_UNLOAD(STATUS_GS_HANDLER_CHECK_FAILURE);
}
#pragma optimize( "", on)


/**
 * @brief GS Buffer Security Check method.
 * @brief Logs the cookie-stack error and unloads the hypervisor.
*/
__declspec(noreturn)
CX_VOID
__cdecl
__report_cookie_corruption(
    _In_ CX_UINT64 StackCookie
)
{
    LOG("Security cookie is %018p but should have been %018p. Function which corrupted the stack is %018p\n",
        StackCookie, __security_cookie, GET_RETURN_ADDRESS);
    CLN_UNLOAD(STATUS_GS_COOKIE_BITTEN);
}
