/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "kernel/kernel.h"
#include "guests/code_scan.h"
#include "kernel/simplechecksum.h"

CX_STATUS
HvScanBuffer(
    _In_ HV_CODE_SIG_PACKAGE *SigPackage,
    _In_ CX_VOID *Buffer,
    _In_ CX_UINT32 BufferSize,
    __out_opt CX_UINT32 *Verdict
)
{
    CX_UINT8 *bytes = Buffer;
    CX_UINT32 hash;

    if (SigPackage == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (bytes == CX_NULL) return CX_STATUS_INVALID_PARAMETER_2;
    if (BufferSize < sizeof(CX_UINT32)) return CX_STATUS_DATA_BUFFER_TOO_SMALL;

    // check the DOWRD hash
    hash = *(CX_UINT32*)bytes;
    for (CX_UINT32 i = 0; i < SigPackage->NumberOfSignatures; i++)
    {
        if (SigPackage->Signatures[i].Hash == hash)
        {
            CX_UINT64 currentChecksum;

            // avoid signatures that require more then the available buffer size
            if (SigPackage->Signatures[i].Length >= BufferSize) continue;

            // check the actual content checksum
            currentChecksum = HvChecksum64(bytes, SigPackage->Signatures[i].Length);
            if (currentChecksum == SigPackage->Signatures[i].Checksum)
            {
                LOG("Matched signature <%016llX> verdict = %d\n", currentChecksum, SigPackage->Signatures[i].Verdict);

                if (Verdict) *Verdict = SigPackage->Signatures[i].Verdict;

                return CX_STATUS_SUCCESS;
            }
        }
    }

    return CX_STATUS_DATA_NOT_FOUND;
}