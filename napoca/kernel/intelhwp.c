/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file intelhwp.c
*   @brief Intel Hardware-Controlled Performance States support
*/

#include "core.h"
#include "kernel/intelhwp.h"
#include "kernel/kerneltypes.h"
#include "debug/dumpers.h"
#include "common/kernel/vmxdefs.h"
#include "io/io.h"

CX_VOID
HvActivatePerformanceMode(
    CX_VOID
)
{
    int a[4];

    __cpuidex(a, 6, 0);

    //CPUID.06H:EAX[bit 7]
    if (a[0] & CPUID_06_EAX_FLAG_HWP)
    {
        // HWP_ENABLE(bit 0, R / W1Once) - Software sets this bit to enable HWP with autonomous selection of
        //     processor P - States.When set, the processor will disregard input from the legacy performance control interface
        //     (IA32_PERF_CTL).Note this bit can only be enabled once from the default value.Once set, writes to the
        //     HWP_ENABLE bit are ignored.Only RESET will clear this bit.Default = zero(0).
        // Bits 63 :1 are reserved and must be zero.
        IA32_PM_ENABLE pmEnable = { 0 };
        pmEnable.Raw = __readmsr(MSR_IA32_PM_ENABLE);

        pmEnable.HwpEnable = 1;

        LOG("Enable HWP! Writting to msr %d (%s) value %p\n",
            MSR_IA32_PM_ENABLE, ConvertMsrToString(MSR_IA32_PM_ENABLE), pmEnable.Raw);

        __writemsr(MSR_IA32_PM_ENABLE, pmEnable.Raw);

        if (a[0] & CPUID_06_EAX_FLAG_HWP_EN_PERF_PREF) // CPUID.06H:EAX.EPP[bit 10]
        {
            //Availability of HWP energy / performance preference control, CPUID.06H:EAX[bit 10] : If this bit is set, HWP
            //    allows software to set an energy / performance preference hint in the IA32_HWP_REQUEST MSR.

            IA32_HWP_CAPABILITIES hwpCapabilities = { 0 };
            IA32_HWP_REQUEST hwpReq = { 0 }, newHwpReq = { 0 };

            hwpCapabilities.Raw = __readmsr(MSR_IA32_HWP_CAPABILITIES);
            hwpReq.Raw = __readmsr(MSR_IA32_HWP_REQUEST);

            newHwpReq.Raw = hwpReq.Raw;

            LOG("HWP capabilities %p! Original HWP request: %p! New request %p\n",
                hwpCapabilities.Raw, hwpReq.Raw, newHwpReq.Raw);

            __writemsr(MSR_IA32_HWP_REQUEST, newHwpReq.Raw);
        }
        else if (a[2] & CPUID_06_ECX_FLAG_PERF_ENERGY_BIAS) // CPUID.06H:ECX.SETBH[bit 3]
        {
            // Software can program the lowest four bits of IA32_ENERGY_PERF_BIAS MSR with a value from 0 - 15. The values
            // represent a sliding scale, where a value of 0 (the default reset value) corresponds to a hint preference for highest
            // performance and a value of 15 corresponds to the maximum energy savings.A value of 7 roughly translates into a
            // hint to balance performance with energy consumption.
            CX_UINT64 perfBias = __readmsr(MSR_IA32_PERF_ENERGY_BIAS);
            CX_UINT64 newPerfBias = perfBias & ~(0xF);

            LOG("Overwritting perf bias from %p do %p!\n",
                perfBias, newPerfBias);

            __writemsr(MSR_IA32_PERF_ENERGY_BIAS, newPerfBias);

        }

    }
    else
    {
        LOG("HWP not available! Not performance mode applied!\n");
    }

    return;
}