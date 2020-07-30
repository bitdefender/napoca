/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEBUG_STORE_H_
#define _DEBUG_STORE_H_

//
// Set this to CX_TRUE if you want this feature enable
//
#define CFG_ENABLE_DEBUG_STORE CX_FALSE

#include "coredefs.h"
#include "base/cx_sal.h"
#include "base/cx_defs.h"

CX_STATUS
DbgDsInit(
    _In_ PCPU *Pcpu
    );

CX_STATUS
DbgDsUninit(
    _In_ PCPU *Pcpu
    );

CX_STATUS
DbgDsStartBranchRecording(
    _In_ PCPU *Pcpu
    );

CX_STATUS
DbgDsStopBranchRecording(
    _In_ PCPU *Pcpu
    );

CX_STATUS
DbDsDumpBranches(
    _In_ PCPU *Pcpu
    );


#endif // _DEBUG_STORE_H_
