/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file documents the interface declarations needed for
// compiling the ringbuffer as part of a project
//


#ifndef COMM_INFO
#error "#define COMM_INFO(...) is not defined"
#endif

#ifndef COMM_LOG
#error "#define COMM_LOG(...) is not defined"
#endif

#ifndef COMM_FUNC_FAIL
#error "#define COMM_FUNC_FAIL(fnname, status) is not defined"
#endif

#ifndef COMM_ERROR
#error "#define COMM_ERROR(...) is not defined"
#endif

#ifndef COMM_FATAL
#error "#define COMM_FATAL(...) is not defined"
#endif

#ifndef CRT_COMPONENT
#error "#define CRT_COMPONENT is not defined (see target* definitions in commands.h)"
#endif



CX_STATUS
CommInitCustom(
    CX_VOID
);


CX_BOOL
CommBlockingAllowed(
    CX_VOID
);

CX_BOOL
CommIsBufferingEnabled(
    CX_VOID
);

CX_BOOL
CommCanAffordToWait(
    CX_VOID
);

CX_STATUS
CommSignalMessage(
    _In_ COMMAND_CODE CommandCode,
    _In_ CX_SIZE_T MessageOffset
);

CX_STATUS
CommSignalEvent(
    _In_ PCOMM_SHMEM_HEADER SharedMem,
    _In_ CX_UINT8 Event,
    _In_opt_ CX_UINT64 QDetail1,
    _In_opt_ CX_UINT64 QDetail2,
    _In_opt_ CX_UINT32 DDetail1,
    _In_opt_ CX_UINT32 DDetail2
);

CX_STATUS
CommDumpBufferedMessages(
    CX_VOID
);

CX_STATUS
CommFlushBufferedMessages(
    _In_ PCOMM_SHMEM_HEADER SharedMem       /// ...
);