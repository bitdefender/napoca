/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Generic data structure interface for data that supports adding and removing pointer elements
//
#ifndef _CX_ADDREMOVE_INTERFACE_H_
#define _CX_ADDREMOVE_INTERFACE_H_

#include "cx_native.h"

typedef void CX_ADDREMOVE_VALUE;
typedef void CX_ADDREMOVE_DATA;

typedef struct _CX_ADDREMOVE_INTERFACE  CX_ADDREMOVE_INTERFACE;

typedef
CX_STATUS
(*CX_ADDREMOVE_ADD)(
    _In_ CX_ADDREMOVE_INTERFACE         *AddRemove,
    _In_ CX_ADDREMOVE_VALUE             *Value
    );

typedef
CX_STATUS
(*CX_ADDREMOVE_REMOVE)(
    _In_ CX_ADDREMOVE_INTERFACE         *AddRemove,
    _Out_ CX_ADDREMOVE_VALUE            **Value
    );

typedef struct _CX_ADDREMOVE_INTERFACE
{
    CX_ADDREMOVE_DATA                   *Data;
    CX_ADDREMOVE_ADD                    Add;
    CX_ADDREMOVE_REMOVE                 Remove;
}CX_ADDREMOVE_INTERFACE;


#endif // _CX_ADDREMOVE_INTERFACE_H_
