/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "kernel/kernel.h"
#include "guests/os_detect.h"
#include "guests/code_scan.h"
#include "memory/cachemap.h"

//
// Static guest loader signatures array
//

static HV_CODE_SIG gOsDetectionSignatures[] =
{
///    HASH    |    VERDICT   | LEN | BUFFER CHECKSUM

    /// windows 7 signatures on some CPUID exit points
    {0x0489A20F, OS_SCAN_WIN7,  91, 0x3AA9716407CC2DA7},// 0F A2 89 04 24 81 FB 41 75 74 68 75 45 81 F9 63 41 4D 44 75 3D 81 FA 65 6E 74 69 75 35 33 C9 41 B9 01 00 00 00 41 8B C1 0F A2 89 54 24 0C 8B D0 89 5C 24 04 C1 FA 08 89 4C 24 08 83 E2 0F 83 FA 0F 72 08 C1 F8 14 0F B6 C8 03 D1 83 FA 15 45 0F 42 C1 41 8B C0 48 83 C4 10 5B C3 // w7_01.txt
    {0x5489A20F, OS_SCAN_WIN7,  51, 0x780DD46A5F61DC1},// 0F A2 89 54 24 0C 8B D0 89 5C 24 04 C1 FA 08 89 4C 24 08 83 E2 0F 83 FA 0F 72 08 C1 F8 14 0F B6 C8 03 D1 83 FA 15 45 0F 42 C1 41 8B C0 48 83 C4 10 5B C3 // w7_02.txt
    {0xBA0FA20F, OS_SCAN_WIN7,  83, 0xFA2EB2DCC44C2327},// 0F A2 0F BA E1 19 89 44 24 20 89 5C 24 24 89 54 24 2C 73 18 E8 34 FF FF FF 0F B6 0D A5 86 02 00 85 C0 41 0F 44 CB 88 0D 99 86 02 00 44 89 1D 96 86 02 00 44 8B E5 4C 8B C5 49 8B D2 41 C1 FC 02 49 8B CD 41 8D 5C 24 06 E8 80 BC FF FF 8D 43 01 48 63 F0 // w7_03.txt
};

static HV_CODE_SIG_PACKAGE gOsDetectionSigsPackage =
{
    gOsDetectionSignatures, ARRAYSIZE(gOsDetectionSignatures)
};

CX_STATUS
OdCheckOsSignatures(
    _In_  VCPU            *Vcpu,
    _Out_ OS_SCAN_VERDICT *Verdict
)
{
    CX_STATUS status;
    CX_UINT32 tmp, size;
    CX_UINT8 *va = CX_NULL;

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Verdict) return CX_STATUS_INVALID_PARAMETER_2;

    // map one page of memory, it's more than enough given the fact that all signatures should be below 100-200 bytes long buffers
    size = CX_PAGE_SIZE_4K;
    status = ChmMapGvaRange(Vcpu, Vcpu->PseudoRegs.CsRip, size, 0, &va, CX_NULL, TAG_OSSC);
    if (!CX_SUCCESS(status))
    {
        // try again, this time mapping only the remaining bytes found in the current page
        if (PAGE_OFFSET(Vcpu->PseudoRegs.CsRip))
        {
            size = CX_PAGE_SIZE_4K - PAGE_OFFSET(Vcpu->PseudoRegs.CsRip);
            va = CX_NULL;
            status = ChmMapGvaRange(Vcpu, Vcpu->PseudoRegs.CsRip, size, 0, &va, CX_NULL, TAG_OSSC);
        }
        if (!CX_SUCCESS(status))
        {
            VCPULOG(Vcpu, "Failed mapping from %p 0x%x bytes. Status 0x%x\n", Vcpu->PseudoRegs.CsRip, size, status);
            goto cleanup;
        }
    }

    status = HvScanBuffer(&gOsDetectionSigsPackage, va, size, &tmp);
    *Verdict = tmp;
    if (!CX_SUCCESS(status))
    {
        if (status == CX_STATUS_DATA_NOT_FOUND)
        {
            *Verdict = OS_SCAN_NOTHING_DETECTED;
            status = CX_STATUS_SUCCESS;
            goto cleanup;
        }

        LOG_FUNC_FAIL("HvScanBuffer", status);
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    if (va) ChmUnmapGvaRange(&va, TAG_OSSC);

    return status;
}

CX_STATUS
OdDetectGuestOs(
    _Inout_ GUEST* Guest,
    _In_ VCPU* Vcpu
)
{
    CX_STATUS status;
    CX_BOOL bFoundRip;

    if ((Vcpu->Guest->OsScanVerdict != OS_SCAN_INVALID) && (Vcpu->Guest->OsScanVerdict != OS_SCAN_NOTHING_DETECTED))
    {
        return CX_STATUS_SUCCESS;
    }

    status = GstSearchRipInCache(
        &Guest->RipCache,
        Vcpu->PseudoRegs.CsRip,
        &bFoundRip,
        CX_TRUE);
    if (!CX_SUCCESS(status)) bFoundRip = CX_FALSE;

    if (bFoundRip) return CX_STATUS_SUCCESS;

    if (Vcpu->Guest->UseOsSigScan)
    {
        VCPULOG(Vcpu, "Os scanning verdict 0x%x. Scanning...\n", Vcpu->Guest->OsScanVerdict);
        status = OdCheckOsSignatures(Vcpu, (OS_SCAN_VERDICT*)&Vcpu->Guest->OsScanVerdict);
        if (!CX_SUCCESS(status)) LOG_FUNC_FAIL("OdCheckOsSignatures", status);
        else
        {
            if (Vcpu->Guest->OsScanVerdict != OS_SCAN_NOTHING_DETECTED)
            {
                VCPULOG(Vcpu, "OS-DETECTION: Verdict = %s\n",
                    OS_SCAN_INVALID == Vcpu->Guest->OsScanVerdict ? "INVALID" :
                    OS_SCAN_WIN7 == Vcpu->Guest->OsScanVerdict ? "WIN7" :
                    OS_SCAN_WIN10 == Vcpu->Guest->OsScanVerdict ? "WIN10" :
                    "UNKNOWN VERDICT"
                );
            }
        }
    }

    return status;
}

