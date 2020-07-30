/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Generic interface for a queue of pointers to data
//

#ifndef _CX_QUEUE_INTERFACE_H_
#define _CX_QUEUE_INTERFACE_H_

#include "cx_native.h"

typedef void CX_QUEUE_VALUE;
typedef void CX_QUEUE_DATA;

typedef struct _CX_QUEUE_INTERFACE      CX_QUEUE_INTERFACE;

typedef
CX_STATUS
(*CX_QUEUE_ENQUEUE)(
    _In_ CX_QUEUE_INTERFACE             *Queue,
    _In_ CX_QUEUE_VALUE                 *Value
    );

typedef
CX_STATUS
(*CX_QUEUE_DEQUEUE)(
    _In_ CX_QUEUE_INTERFACE             *Queue,
    _Out_ CX_QUEUE_VALUE                **Value
    );

typedef struct _CX_QUEUE_INTERFACE
{
    CX_QUEUE_DATA                       *Data;
    CX_QUEUE_ENQUEUE                    Enqueue;
    CX_QUEUE_DEQUEUE                    Dequeue;
}CX_QUEUE_INTERFACE;


#endif // _CX_QUEUE_INTERFACE_H_
