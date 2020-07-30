/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// EMHV - emulator to hypervisor interface
#include "napoca.h"
#include "kernel/vmx.h"
#include "guests/guests.h"
#include "memory/cachemap.h"
#include "kernel/emu.h"
#include "common/kernel/vmxdefs.h"

//
// local prototypes - EMHV implementation
//
static
NTSTATUS
_EmhvTranslateVirtualAddress(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 GuestVirtAddress,
    _Inout_ CX_UINT64* GuestPhysicalAddress
);

static
NTSTATUS
_EmhvGetMemType(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PhysicalPageAddress,
    _In_ CX_UINT32 PageCount,
    _Out_ CX_UINT32* Flags
);

static
NTSTATUS
_EmhvMapPhysicalMemory(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PageAddress,
    _In_ CX_UINT32 PageCount,
    _Inout_ CX_VOID** Hva);

static
NTSTATUS
_EmhvMapVirtualMemory(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PageAddress,
    _In_ CX_UINT32 PageCount,
    _Inout_ CX_VOID** Hva);

static
NTSTATUS
_EmhvUnmapVirtualMemory(
    _Inout_ CX_VOID** Hva);

static
NTSTATUS
_EmhvUnmapPhysicalMemory(
    _Inout_ CX_VOID** Hva);

static
NTSTATUS
_EmhvReadDevMem(
    _In_ VCPU* Vcpu,
    _In_ CX_VOID* Context,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Length,
    _Out_ CX_UINT8* Value
);

static
NTSTATUS
_EmhvWriteDevMem(
    _In_ VCPU* Vcpu,
    _In_ CX_VOID* Context,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Length,
    _In_ CX_UINT8* Value
);

static
NTSTATUS
_EmhvReadIoPort(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _Out_ CX_UINT8* Value
);

static
NTSTATUS
_EmhvWriteIoPort(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _In_ CX_UINT8* Value
);

static
NTSTATUS
_EmhvReadMsr(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT32 Msr,
    _Out_ CX_UINT64* Value
);

static
NTSTATUS
_EmhvWriteMsr(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT32 Msr,
    _In_ CX_UINT64 Value
);

static
NTSTATUS
_EmHvVmxRead(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Id,
    _Out_ CX_UINT64* Value
);

static
NTSTATUS
_EmHvVmxWrite(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Id,
    _In_ CX_UINT64 Value
);

static
NTSTATUS
_EmHvSaveCpuState(
    _In_ VCPU* Vcpu,
    _In_ EMHV_SAVE_STATE cpuSaveState
);


NTSTATUS
EmhvStartHandlingEptViolation(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Gpa,
    _In_ CX_UINT64 Gla,
    _In_ CX_UINT16 RequiredAccess
    )
{
    NTSTATUS status;
    CX_UINT64 intState, actState;

    UNREFERENCED_PARAMETER(RequiredAccess);

    // pre-init
    status = CX_STATUS_SUCCESS;
    intState = actState = 0;

    GstLock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);

    //LOG("Singlestepping %p!\n", Gpa);

    Vcpu->RexecPending = TRUE;

    // in case of singlestepping with EPT using 1G pages and a valid intro buffer we should
    // split that 1G page and go all the way to 4K pages in order to have one or two backup pages
    // for the actual patched data
    // for now log and allow execution:
    //  - restore the original data in PHYSICAL memory - will be seen by all cores
    //  - allow singlestepping for current core
    //  - restore the patched data
    // there is a race condition that other cores will see/use the original content of the physical memory
    // this is an issue for HVI hooked pages for R but not for X
    if (Vcpu->IntroEmu.BufferValid && Vcpu->Guest->SingleStepUsing1GEpt)
    {
        VCPUWARNING(Vcpu, "Single-stepping while using 1G ept pages! Gpa %p, Gla %p Access: 0x%x\n",
            Gpa, Gla, RequiredAccess);

        // this is needed in order to resolve the race condition mentioned above without
        // breaking down paging structures in EPT down to 4K pages and then
        // coalesce them back
        // might be a source of performance loss - sound hickups
        {
            NTSTATUS localstatus = GstPause(Vcpu->Guest, GST_UPDATE_REASON_PAUSE_GUEST);
            if (!NT_SUCCESS(localstatus))
            {
                LOG_FUNC_FAIL("GstPause", localstatus);
            }
            else
            {
                Vcpu->Guest->GuestPausedForSingleStep = TRUE;
            }
        }
    }

    // if we have a valid emu buffer we need to patch the data in memory before single-stepping
     if (Vcpu->IntroEmu.BufferValid)
     {
         CX_UINT64 gpa = 0, hpa = 0;

         if (Vcpu->IntroEmu.BufferGla != Gla)
         {
             VCPUERROR(Vcpu, "Inconsistent GLA values! Gla %p emu gla %p!\n", Gla, Vcpu->IntroEmu.BufferGla);
         }

         CX_UINT32 pages = PAGE_COUNT(Vcpu->IntroEmu.BufferGla, Vcpu->IntroEmu.BufferSize);
         if (pages > Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE)
         {
             VCPUERROR(Vcpu, "Intro buffer to big! Requested size is: %d pages; Max is %d pages\n", pages, Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE);
         }

         if (pages != 1 && pages != 2)
         {
             VCPUERROR(Vcpu, "Unsupported number of pages! Requested %d supported %d\n", pages, Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE);
         }

         status = ChmGvaToGpaAndHpa(Vcpu, Vcpu->IntroEmu.BufferGla, &gpa, &hpa);
         if (!NT_SUCCESS(status))
         {
             LOG_FUNC_FAIL("ChmGvaToGpaAndHpa", status);
             goto cleanup_and_exit;
         }

         if (Gpa != gpa)
         {
             VCPUERROR(Vcpu, "Inconsistent GPA values! Gpa %p emu gpa %p!\n", Gpa, gpa);
         }

         // make sure we do not overflow
         if (Vcpu->IntroEmu.SingleStep.BufferSize > Vcpu->IntroEmu.BufferSize + PAGE_OFFSET(Vcpu->IntroEmu.BufferGla))
         {
             memcpy(Vcpu->IntroEmu.SingleStep.Buffer + PAGE_OFFSET(Vcpu->IntroEmu.BufferGla), Vcpu->IntroEmu.Buffer, Vcpu->IntroEmu.BufferSize);
         }
         else
         {
             VCPUERROR(Vcpu, "Single step buffer size %d is to small! Required %d\n",
                 Vcpu->IntroEmu.SingleStep.BufferSize, Vcpu->IntroEmu.BufferSize + PAGE_OFFSET(Vcpu->IntroEmu.BufferGla));

             status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
             goto cleanup_and_exit;
         }

         if (Vcpu->Guest->SingleStepUsing1GEpt)
         {
             CX_UINT8* hva;
             status = ChmMapGpaRange(Vcpu, gpa, Vcpu->IntroEmu.BufferSize, CHM_FLAG_AUTO_ALIGN, &hva, NULL, TAG_INTR);
             if (!SUCCESS(status))
             {
                 LOG_FUNC_FAIL("ChmMapGpaRange", status);
             }

             memcpy_s(Vcpu->IntroEmu.BufferBackup, Vcpu->IntroEmu.BufferSize, hva, Vcpu->IntroEmu.BufferSize);

             memcpy_s(hva, Vcpu->IntroEmu.BufferSize, Vcpu->IntroEmu.Buffer, Vcpu->IntroEmu.BufferSize);

             ChmUnmapGpaRange(&hva, TAG_INTR);
         }
         else
         {
             status = EptSetHpa(GstGetEptOfSingleStepMemory(Vcpu->Guest), PAGE_BASE_PA(gpa), Vcpu->IntroEmu.SingleStep.BufferPa);
             if (!NT_SUCCESS(status))
             {
                 LOG_FUNC_FAIL("EptSetHpa", status);
                 goto cleanup_and_exit;
             }

             if (pages == 2)
             {
                 status = ChmGvaToGpaAndHpa(Vcpu, (Vcpu->IntroEmu.BufferGla + Vcpu->IntroEmu.BufferSize), &gpa, &hpa);
                 if (!NT_SUCCESS(status))
                 {
                     LOG_FUNC_FAIL("ChmGvaToGpaAndHpa", status);
                     goto cleanup_and_exit;
                 }

                 status = EptSetHpa(GstGetEptOfSingleStepMemory(Vcpu->Guest), PAGE_BASE_PA(gpa), (Vcpu->IntroEmu.SingleStep.BufferPa + PAGE_SIZE));
                 if (!NT_SUCCESS(status))
                 {
                     LOG_FUNC_FAIL("EptSetHpa", status);
                     goto cleanup_and_exit;
                 }
             }
         }
     }

     vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, (VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS));

     if (vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, &actState))
     {
         ERROR("vmx_vmread has failed!\n");
         status = CX_STATUS_UNEXPECTED_IO_ERROR;
         goto cleanup_and_exit;
     }

     if (actState == VMCS_ACTIVITY_STATE_HLT)
     {
         if (vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, VMCS_ACTIVITY_STATE_ACTIVE))
         {
             ERROR("vmx_vmwrite has failed!\n");
             status = CX_STATUS_UNEXPECTED_IO_ERROR;
             goto cleanup_and_exit;
         }
     }

     // Activate MTF - Monitor Trap Flag
     if (vmx_vmread(VMCS_PROC_BASED_EXEC_CONTROL, &Vcpu->OldProcExecControls))
     {
         ERROR("vmx_vmread has failed!\n");
         status = CX_STATUS_UNEXPECTED_IO_ERROR;
         goto cleanup_and_exit;
     }

     if (vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL,
         Vcpu->OldProcExecControls | VMCSFLAG_PROCEXEC_MONITOR_TRAP_FLAG_EXIT))
     {
         ERROR("vmx_vmwrite has failed!\n");
         status = CX_STATUS_UNEXPECTED_IO_ERROR;
         goto cleanup_and_exit;
     }

     //if it is a REP instruction set RCX to 1 for Intel(R) Atom(TM) CPU C2550 and save the ex rcx so it can be set again to the right value later
     if (Vcpu->Pcpu->HasRepGranularityBug)
     {
          NTSTATUS status2 = CX_STATUS_SUCCESS;
          CX_UINT8* rip = NULL;

          if (Vcpu->RepWorkaroundContext.OldRipValue == Vcpu->ArchRegs.RIP)
          {
              Vcpu->RepWorkaroundContext.OldRcxValue = Vcpu->ArchRegs.RCX;
              Vcpu->RepWorkaroundContext.OldRipValue = Vcpu->ArchRegs.RIP;
              Vcpu->RepWorkaroundContext.OldRsiValue = Vcpu->ArchRegs.RSI;
              Vcpu->ArchRegs.RCX = 1;
          }
          else
          {
              // ask to map 2 bytes only - and do not cross page-boundry if not needed
              status2 = ChmMapGvaRange(Vcpu, Vcpu->PseudoRegs.CsRip, 2, CHM_FLAG_AUTO_ALIGN, &rip, NULL, 0);
              if (NT_SUCCESS(status2))
              {
                  if ((rip[0] == ND_PREFIX_G1_REPE_REPZ || rip[0] == ND_PREFIX_G1_REPNE_REPNZ) && (rip[1] != 0x0f && rip[1] != 0x90))
                  {
                      //Two - byte opcodes that are 3 bytes in length begin with a mandatory prefix(66H, F2H, or F3H) and the escape opcode(0FH).
                      //f390 is PAUSE, so we should avoid treating it as a REP instruction
                      Vcpu->RepWorkaroundContext.OldRcxValue = Vcpu->ArchRegs.RCX;
                      Vcpu->RepWorkaroundContext.OldRipValue = Vcpu->ArchRegs.RIP;
                      Vcpu->ArchRegs.RCX = 1;
                  }
                  else
                  {
                      Vcpu->RepWorkaroundContext.OldRipValue = 0;
                  }

                  ChmUnmapGvaRange(&rip, 0);
              }
          }
     }

     Vcpu->EmulatingEptViolation = TRUE;
     status = VcpuActivateDomain(Vcpu, GuestPredefinedMemoryDomainIdSingleStepMemory);
     if (!SUCCESS(status))
     {
         LOG_FUNC_FAIL("VcpuActivateDomain", status);
         goto cleanup_and_exit;
     }

     // All good!
     status = CX_STATUS_SUCCESS;

cleanup_and_exit:
    if (!NT_SUCCESS(status))
    {
        // Any error is a bug-check condition; if we can't single-step an instruction, we can't re-enter the guest
        // safely.
    }

    return status;
}


NTSTATUS
EmhvEndHandlingEptViolation(
    _In_ VCPU* Vcpu
    )
{
    NTSTATUS status;
    CX_UINT64 gpa, hpa;

    if (Vcpu->IntroEmu.BufferValid)
    {
        CX_UINT32 pages = PAGE_COUNT(Vcpu->IntroEmu.BufferGla, Vcpu->IntroEmu.BufferSize);
        if (pages > Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE)
        {
            VCPUERROR(Vcpu, "Intro buffer to big! Requested size is: %d pages; Max is %d pages\n", pages, Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE);
        }

        if (pages != 1 && pages != 2)
        {
            VCPUERROR(Vcpu, "Unsupported number of pages! Requested %d supported %d\n", pages, Vcpu->IntroEmu.SingleStep.BufferSize / PAGE_SIZE);
        }

        status = ChmGvaToGpaAndHpa(Vcpu, Vcpu->IntroEmu.BufferGla, &gpa, &hpa);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("ChmGvaToGpaAndHpa", status);
            goto cleanup_and_exit;
        }

        if (Vcpu->Guest->SingleStepUsing1GEpt)
        {
            CX_UINT8* hva;
            status = ChmMapGpaRange(Vcpu, gpa, Vcpu->IntroEmu.BufferSize, CHM_FLAG_AUTO_ALIGN, &hva, NULL, TAG_INTR);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("ChmMapGpaRange", status);
            }

            memcpy_s(hva, Vcpu->IntroEmu.BufferSize, Vcpu->IntroEmu.BufferBackup, Vcpu->IntroEmu.BufferSize);

            ChmUnmapGpaRange(&hva, TAG_INTR);
        }
        else
        {
            status = EptSetHpa(GstGetEptOfSingleStepMemory(Vcpu->Guest), PAGE_BASE_PA(gpa), PAGE_BASE_PA(gpa));
            if (!NT_SUCCESS(status))
            {
                LOG_FUNC_FAIL("EptSetHpa", status);
                goto cleanup_and_exit;
            }

            if (pages == 2)
            {
                status = ChmGvaToGpaAndHpa(Vcpu, (Vcpu->IntroEmu.BufferGla + Vcpu->IntroEmu.BufferSize), &gpa, &hpa);
                if (!NT_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("ChmGvaToGpaAndHpa", status);
                    goto cleanup_and_exit;
                }

                status = EptSetHpa(GstGetEptOfSingleStepMemory(Vcpu->Guest), PAGE_BASE_PA(gpa), PAGE_BASE_PA(gpa));
                if (!NT_SUCCESS(status))
                {
                    LOG_FUNC_FAIL("EptSetHpa", status);
                    goto cleanup_and_exit;
                }
            }
        }
    }

    GUEST_MEMORY_DOMAIN *expectedDomain;
    status = GstGetMemoryDomain(Vcpu->Guest, GuestPredefinedMemoryDomainIdSingleStepMemory, &expectedDomain);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("GstGetMemoryDomain", status);
        goto cleanup_and_exit;
    }

    CX_STATUS revertStatus = VcpuDeactivateDomainEx(Vcpu, expectedDomain, CX_TRUE);
    if (!CX_SUCCESS(revertStatus))
    {
        LOG_FUNC_FAIL("VcpuDeactivateDomainEx", status);
        if (revertStatus != CX_STATUS_DATA_ALTERED_FROM_OUSIDE)
        {
            // the revert operation itself actually failed, and not merely the expected domain vs actual domain validation/constraint
            status = revertStatus;
        }
    }

cleanup_and_exit:

    Vcpu->IntroEmu.BufferValid = FALSE;
    Vcpu->IntroEmu.BufferGla = 0;
    Vcpu->IntroEmu.BufferSize = 0;

    // Clear the VMCSFLAG_PROCEXEC_MONITOR_TRAP_FLAG_EXIT flag.
    if (vmx_vmread(VMCS_PROC_BASED_EXEC_CONTROL, &Vcpu->OldProcExecControls))
    {
        ERROR("vmx_vmread has failed!\n");
    }

    if (vmx_vmwrite(VMCS_PROC_BASED_EXEC_CONTROL, Vcpu->OldProcExecControls & (~VMCSFLAG_PROCEXEC_MONITOR_TRAP_FLAG_EXIT)))
    {
        ERROR("vmx_vmwrite has failed!\n");
    }

    // Clear any other flags & resume other CPUs
    Vcpu->EmulatingEptViolation = FALSE;

    // Mark that we're done with re-execution and it's safe again to process EPT violations.
    Vcpu->RexecPending = FALSE;

    if (Vcpu->RepWorkaroundContext.OldRcxValue)
    {
        Vcpu->ArchRegs.RCX = Vcpu->RepWorkaroundContext.OldRcxValue - (Vcpu->RepWorkaroundContext.OldRsiValue != Vcpu->ArchRegs.RSI ? 1 : 0);

        if (Vcpu->ArchRegs.RCX != 0)
        {
            Vcpu->ArchRegs.RIP = Vcpu->RepWorkaroundContext.OldRipValue;
        }
        else
        {
            Vcpu->RepWorkaroundContext.OldRipValue = 0;
        }

        Vcpu->RepWorkaroundContext.OldRcxValue = 0;
    }

    if (Vcpu->Guest->GuestPausedForSingleStep)
    {
        NTSTATUS localstatus = GstUnpause(Vcpu->Guest, GST_UPDATE_REASON_PAUSE_GUEST);
        if (!NT_SUCCESS(localstatus))
        {
            LOG_FUNC_FAIL("GstPause", localstatus);
        }
        else
        {
            Vcpu->Guest->GuestPausedForSingleStep = CX_FALSE;
        }
    }

    GstUnlock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);

    return status;
}

NTSTATUS
EmhvInitGenericPerGuestIface(
    _In_ GUEST* Guest
    )
{
    if (!Guest)  return CX_STATUS_INVALID_PARAMETER_1;

    memzero(&(Guest->EmhvIface), sizeof(EMHV_INTERFACE));

    Guest->EmhvIface.TranslateVirtualAddress = &_EmhvTranslateVirtualAddress;
    Guest->EmhvIface.GetMemType = &_EmhvGetMemType;
    Guest->EmhvIface.MapPhysicalMemory = &_EmhvMapPhysicalMemory;
    Guest->EmhvIface.MapVirtualMemory = &_EmhvMapVirtualMemory;
    Guest->EmhvIface.UnmapVirtualMemory = &_EmhvUnmapVirtualMemory;
    Guest->EmhvIface.UnmapPhysicalMemory = &_EmhvUnmapPhysicalMemory;
    Guest->EmhvIface.ReadDevMem = &_EmhvReadDevMem;
    Guest->EmhvIface.WriteDevMem = &_EmhvWriteDevMem;
    Guest->EmhvIface.ReadIoPort = &_EmhvReadIoPort;
    Guest->EmhvIface.WriteIoPort = &_EmhvWriteIoPort;
    Guest->EmhvIface.ReadMsr = &_EmhvReadMsr;
    Guest->EmhvIface.WriteMsr = &_EmhvWriteMsr;

    Guest->EmhvIface.VmxRead = &_EmHvVmxRead;
    Guest->EmhvIface.VmxWrite = &_EmHvVmxWrite;

    Guest->EmhvIface.SaveCpuState = &_EmHvSaveCpuState;

    Guest->EmhvIface.Initialized = TRUE;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
EmhvDecodeInGuestContext(
    _In_ VCPU* Vcpu,
    _Out_ INSTRUX* Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_UINT64 Gpa
    )
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Gpa);

#define MAX_INSTRUCTION_SIZE 16
    NTSTATUS status;
    CX_UINT8 bInstructionBytes[MAX_INSTRUCTION_SIZE];
    CX_UINT8 bOperatingMode;
    CX_UINT64 linearRip;
    CX_UINT8* guestRipHva;
    BOOLEAN partialFetch = FALSE;
    SIZE_T fetchedBytes;
    EMHV_INTERFACE* iface = &Vcpu->Guest->EmhvIface;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Instrux) return CX_STATUS_INVALID_PARAMETER_2;
    if (!iface->Initialized) return STATUS_NO_EMHV_INITIALIZED;

    // Init buffer
    memset(bInstructionBytes, 0, sizeof(bInstructionBytes));

    linearRip = Vcpu->PseudoRegs.CsRip;

    //
    // Map the RIP virtual address, and fetch 24 bytes of data; Note than in some rare cases,
    // an instruction length can exceed 16 bytes, so we don't want to risk anything, therefore,
    // we fetch 24 bytes.
    //
    status = iface->MapVirtualMemory(Vcpu, PAGE_BASE_VA(linearRip), PAGE_COUNT_4K(linearRip, MAX_INSTRUCTION_SIZE), &guestRipHva);
    if (! NT_SUCCESS(status))
    {
        // Mapping the all needed pages failed, but this doesn't mean that we cannot fetch an entire instruction;
        // We will assume that at least 1 valid instruction will be fetched from the curent page
        status = iface->MapVirtualMemory(Vcpu, PAGE_BASE_VA(linearRip), 1, &guestRipHva);
        if (!NTSUCCESS(status))
        {
            LOG("ERROR: EmhvIface.MapVirtualMemory failed for %018p, status=%s\n", linearRip, NtStatusToString(status));
            return status;
        }

        partialFetch = TRUE;
    }

    fetchedBytes = MIN(partialFetch ? (PAGE_SIZE_4K - PAGE_OFFSET_4K(linearRip)) : MAX_INSTRUCTION_SIZE, MAX_INSTRUCTION_SIZE);
    memcpy_s(bInstructionBytes, fetchedBytes, guestRipHva + PAGE_OFFSET_4K(linearRip), fetchedBytes);

    // Unmap the page
    status = iface->UnmapVirtualMemory(&guestRipHva);
    if (! NT_SUCCESS(status))
    {
        LOG("ERROR: EmhvIface.UnmapMemory failed, status=%s\n", NtStatusToString(status));
        return status;
    }

    GstGetVcpuMode(Vcpu, &bOperatingMode);

    //
    // We fetched enough data, decode the instruction, and leave. Also. handle the case where only a partial fetch was done.
    // There are 2 possible cases when a partial fetch doesn't fetch enough data:
    // - NdDecode returns error, in which case re-execution will be attempted.
    // - The instruction is decoded with success, and the length exceeds the page - we will return PAGE_NOT_PRESENT, in order to
    //   force the re-execution of the faulting instruction.
    // Also, normally, this case shouldn't occur (ever), since a #PF would be generated inside the guest, ensuring that any page
    // containing the instruction is present in memory.
    //
    status = NdDecodeEx(Instrux, bInstructionBytes, fetchedBytes, bOperatingMode, bOperatingMode);
    if ((status == ND_STATUS_BUFFER_TOO_SMALL) && (partialFetch)) return STATUS_PAGE_NOT_PRESENT;

    return status;
}


NTSTATUS
EmhvDecodeInstructionLenInGuestContext(
    _In_ VCPU* Vcpu,
    _Out_ CX_UINT8 *InstructionLen
    )
{
    NTSTATUS status;
    INSTRUX instrux = {0};

    if (!Vcpu) return CX_STATUS_INVALID_PARAMETER_1;
    if (!InstructionLen) return CX_STATUS_INVALID_PARAMETER_2;

    status = EmhvDecodeInGuestContext(Vcpu, &instrux, 0, 0);
    if (NT_SUCCESS(status)) *InstructionLen = (CX_UINT8)instrux.Length;

    return status;
}



NTSTATUS
EmhvDecodeAndEmulateInGuestContext(
    _In_ VCPU* Vcpu,
    _In_opt_ PINSTRUX Instrux,
    _In_ CX_UINT32 Flags,
    _In_opt_ CX_UINT64 Gpa,
    _In_opt_ CX_VOID* Context
    )
{
    NTSTATUS status;
    INSTRUX instrux;
    BOOLEAN decoded;
    CX_UINT64 exitQual, gla;

    memzero(&instrux, sizeof(INSTRUX));
    decoded = FALSE;
    exitQual = 0;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;

    //
    // This is a tricky stuff: if we protect the paging structures of the guest, EPT violations may be
    // generated with a special exit qualification, which indicates us that the EPT violation took place
    // because the CPU tried to update the A or D flag from inside the page table entry. Those situations
    // must be handled using the instruction re-execution mechanism, because simply emulating the instruction
    // will not fix the issue.
    //
    // We can emulate the entire page walk. This is how the situation is handled from now on.
    // In the rare cases where 2 consecutive violations are generated from the same RIP on the same GPA, we
    // will use the re-execution mechanism (those situations should be rare; we assume we did something wrong,
    // or it is an unsupported case).
    //

    // Use standard decoder & emulator for this instruction.

    // do we have an already decoded instrux?
    if (Instrux) instrux = *Instrux;

    vmx_vmread(VMCS_VM_EXIT_QUALIFICATION, &exitQual);
    vmx_vmread(VMCS_GUEST_LINEAR, &gla);

    // In case of paging-structure violations due to A/D bits update, we can skip directly to page-walk emulation.
    if (Vcpu->PagingStructureViolation)
    {
        goto skip_decode;
    }

    // check if the violated GPA has RWX access. If so, we can safely re-enter the guest. That would mean that someone
    // (most likely the introspection engine) marked the violated address as RWX, ie, it removed the protection from it.
    if ((Gpa) && (!Context) && (Vcpu->CurrentExitReason == EXIT_REASON_EPT_VIOLATION))
    {
        // We don't have to invalidate the icache here. We are interested in the raw EPT rights.
        EPT_RIGHTS rights;
        status = EptGetRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), Gpa, 0, &rights);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("NeptQueryRights", status);
            goto skip_fast_checks;
        }

        // accessible == for each right, either exitQual doesn't account for that bit as being missing or that right has been granted
        if ((rights.Read && rights.Write && rights.Execute))
        //if ((!(exitQual & BIT(0)) || rights.Read) && (!(exitQual & BIT(1)) || rights.Write) && (!(exitQual & BIT(2)) || rights.Execute))
        {
            // The access for which a violation was generated has been granted meanwhile.
            return CX_STATUS_SUCCESS;
        }
        // The access for which a violation was generated has been granted meanwhile.
        if (((rights.Raw & EPT_RAW_RIGHTS_MASK) & ((exitQual & EPT_RAW_RIGHTS_MASK))) == (exitQual & EPT_RAW_RIGHTS_MASK))
        {
            return CX_STATUS_SUCCESS;
        }

skip_fast_checks:
        ;
    }

    // If we have execution violation, we will always re-execute the instruction. We don't emulate such instructions,
    // since the emulator is optimized & fine-tuned for read/write EPT violations.
    if ((Vcpu->CurrentExitReason == EXIT_REASON_EPT_VIOLATION) && ((exitQual & EPT_RAW_RIGHTS_X) != 0) && Vcpu->SafeToReExecute)
    {
        goto reexecute;
    }
/*
    // In case of memory-introspection induced faults, we want re-execution all the time, since the emulator
    // bypasses EPT checks, so an instruction like MOVS may cause problems (load - store, the load causes a dummy
    // fault, and the store will be emulated, bypassing EPT restrictions), or RMW instructions.
    // REP prefixed instructions are not an issue, since Intel SDM 25.5.2 tells us that a MTF event is generated
    // after every iteration (must be manually checked, though).
    // However, in case of write faults, we can emulate them, since the write fault is generated after an instruction
    // fetch and after any data read that might have been made.
    if ((EXIT_REASON_EPT_VIOLATION == exitReason) && (0 == (exitQual & EPT_RAW_RIGHTS_W)) && Vcpu->SafeToReExecute)
    {
        goto reexecute;
    }
*/

    if (Vcpu->SafeToReExecute && Context == NULL)
    {
        goto reexecute;
    }

    // do we need to decode instrux?
    if (!Instrux)
    {
        status = EmhvDecodeInGuestContext(Vcpu, &instrux, Flags, Gpa);
        if (!SUCCESS(status))
        {
            goto reexecute;
        }

        decoded = TRUE;
    }

skip_decode:

    // We need to make sure interrupts are disabled, otherwise an IPI may interfere with us. The problem is that
    // another VCPU, which is inside the guest, may send an IPI to us in order to modify a memory translation. If we
    // receive that IPI, the sender may be able to actually modify the memory translation right under our feet,
    // leaving us with an inconsistent memory translation.

    if ((!Context) && !Vcpu->RexecPending)
    {
        // If this is not device memory, we will acquire a spinlock and we'll disable the interrupts. Otherwise,
        // another VCPU may race with us and modify memory translations inside the guest.
        GstLock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);
    }

    if (Vcpu->PagingStructureViolation)
    {
        status = NdEmulatePageWalk(Vcpu, gla, exitQual);
    }
    else
    {
        status = NdEmulateInstruction(Vcpu, &instrux, Flags, Context, Gpa);
    }

    if ((!Context) && !Vcpu->RexecPending)
    {
        GstUnlock(Vcpu->Guest, GST_UPDATE_REASON_REEXEC_CHANGES);
    }

    if (SUCCESS(status))
    {
        // If the emulation succeeded, we must advance RIP to the next instruction
        if ((STATUS_EMU_DONT_ADVANCE_RIP != status) && (!Vcpu->PagingStructureViolation))
        {
            Vcpu->ArchRegs.RIP += instrux.Length;

            // Very important: if the Trap Flag is set, we need to inject a single-step trap, because we updated the
            // instruction pointer.
            if (Vcpu->ArchRegs.RFLAGS & RFLAGS_TF)
            {
                // Bit 14 inside DR6 must be set, to indicate that the #DB took place due to a single-step trap.
                __writedr(6, __readdr(6) | (1ULL << 14));

                // Signal that a #DB must be injected.
                VirtExcInjectException(NULL, Vcpu, EXCEPTION_DEBUG, 0, 0);
            }
        }

        // If we were emulating an EPT violation, stop it now.
        if (Vcpu->EmulatingEptViolation)
        {
            status = EmhvEndHandlingEptViolation(Vcpu);
            if (!NT_SUCCESS(status))
            {
                ERROR("EmhvEndHandlingEptViolation failed: 0x%08x\n", status);
            }
        }

        Vcpu->PagingStructureViolation = FALSE;
    }
    else if (STATUS_EMU_EXCEPTION_INJECTED == status)
    {
        char text[ND_MIN_BUF_SIZE] = {0};

        NdToText(&instrux, Vcpu->ArchRegs.RIP, ND_MIN_BUF_SIZE, text);

        LOG("[CPU %d] EMU injected exception, RIP %018p: %s, GPA: %018p, qual: %018p as part of: %s\n",
              Vcpu->GuestCpuIndex,
              Vcpu->ArchRegs.RIP,
              text,
              Gpa,
              exitQual,
              Vcpu->PagingStructureViolation ? "pagewalk" : "emulation"
              );

        status = CX_STATUS_SUCCESS;
    }
    else if ((Gpa) && (Vcpu->SafeToReExecute))
    {
        CX_UINT16 requiredAccess = 0;
    reexecute:
        // Violation generated by EPT violation or other event that isn't related to a virtual device.

        //char text[ND_MIN_BUF_SIZE] = { 0 };
        //NdToText(&instrux, Vcpu->ArchRegs.RIP, ND_MIN_BUF_SIZE, text);
        //
        //TRACE("[CPU %d] Will single-step at RIP %018p: %s, GPA: %018p, qual: %018p as part of: %s.\n",
        //      Vcpu->GuestCpuIndex,
        //      Vcpu->ArchRegs.RIP,
        //      text,
        //      Gpa,
        //      exitQual,
        //      Vcpu->PagingStructureViolation ? "pagewalk" : "emulation"
        //      );

        // Compute the required access needed to safely re-execute the instruction.
        switch (exitQual & EPT_RAW_RIGHTS_MASK)
        {
        case EPT_RAW_RIGHTS_R:
            requiredAccess = EPT_RAW_RIGHTS_R;
            break;
        case EPT_RAW_RIGHTS_W:
            requiredAccess = EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W;
            break;
        case EPT_RAW_RIGHTS_X:
            requiredAccess = VmxIsEptExecuteOnlyPagesAvailable() ? EPT_RAW_RIGHTS_X : EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_X;
            break;
        case EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W:
            requiredAccess = EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W;
            break;
        case EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_X:
            requiredAccess = EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_X;
            break;
        case EPT_RAW_RIGHTS_W|EPT_RAW_RIGHTS_X:
            requiredAccess = EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W|EPT_RAW_RIGHTS_X;
            break;
        case EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W|EPT_RAW_RIGHTS_X:
            requiredAccess = EPT_RAW_RIGHTS_R|EPT_RAW_RIGHTS_W|EPT_RAW_RIGHTS_X;
            break;
        default:
            // We should not get here. Ever.
            requiredAccess = 0;
            break;
        }

        status = EmhvStartHandlingEptViolation(Vcpu, Gpa, gla, requiredAccess);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("EmhvStartHandlingEptViolation", status);
        }
    }
    else
    {
        // This will lead to an endless loop of guest entry/exit trying to emulate/singlestep this instruction over and over again
        char text[ND_MIN_BUF_SIZE] = {0};
        NdToText(&instrux, Vcpu->ArchRegs.RIP, ND_MIN_BUF_SIZE, text);

        LOG("[ERROR] NdEmulate failed with status %08x, exitReason: %018p, exitQual: %018p, GPA: %018p\n", status, Vcpu->CurrentExitReason, exitQual, Gpa);
        LOG("[ERROR] Failed at: %p -> '%s'\n", Vcpu->ArchRegs.RIP, text);
    }

    return status;
}


///
/// @brief Retrieves the memory type of a given range from EPT tables
///
/// This function will get the flags for the given Physical address as stored inside the EPT entry. Flags will contain
/// access rights (read, write, execute) and caching rights (UC, WB, WT, etc.).
///
/// @param Vcpu                              Vcpu used to translate the memory address.
/// @param PhysicalPageAddress               Physical address who's memory type will be fetched.
/// @param PageCount                         Number of pages.
/// @param Flags                             EPT flags of the given physical page.
///
/// @return CX_STATUS_SUCCESS               If the flags from the EPT have been succesfully extracted.
///
static
NTSTATUS
_EmhvGetMemType(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PhysicalPageAddress,
    _In_ CX_UINT32 PageCount,
    _Out_ CX_UINT32 *Flags
    )
{
    NTSTATUS status;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!PageCount) return CX_STATUS_INVALID_PARAMETER_3;
    if (!Flags) return CX_STATUS_INVALID_PARAMETER_4;

    // for now, simply execute directly the EPT function for 1 page
    if (PageCount != 1) return CX_STATUS_OPERATION_NOT_IMPLEMENTED;

    EPT_PROPERTIES props;
    status = EptQueryProperties(GstGetEptOfPhysicalMemory(Vcpu->Guest), CX_PAGE_BASE_4K(PhysicalPageAddress), PageCount * CX_PAGE_SIZE_4K, &props, CX_NULL);
    if (CX_SUCCESS(status))
    {
        CX_UINT64 ptebits = EptPropsToPteCachingAndRightsBits(props);
        if (props.Special) ptebits |= EMU_MEMTYPE_DEVICE;
        *Flags = (CX_UINT16)ptebits;
    }

    return status;
}

///
/// @brief Maps guest physical memory in hypervisor virtual space
///
/// Will map, using the cachemap, the given PageAddress inside the host VA space, and will return the
/// VA addres of the new mapping via the HostVa argument.
///
/// @param Vcpu             Vcpu used for mapping the page.
/// @param PageAddress      Guest physical address of the page to be mapped.
/// @param PageCount        Number of pages to be mapped.
/// @param HostVa           Will contain upon exit the pointer to the host virtual address that will point to PageAddress.
///
/// @return  CX_STATUS_SUCCESS   If the page has been succesfully mapped.
/// @return  CX_STATUS_XXX       On error.
///
static
NTSTATUS
_EmhvMapPhysicalMemory(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PageAddress,
    _In_ CX_UINT32 PageCount,
    _Inout_ CX_VOID** HostVa
    )
{
    NTSTATUS status;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!PageCount) return CX_STATUS_INVALID_PARAMETER_3;
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_4;

    status = ChmMapContinuousGuestGpaPagesToHost(Vcpu->Guest,
                PageAddress,
                PageCount,
                CHM_FLAG_AUTO_ALIGN,
                HostVa,
                NULL, TAG_EMU);

    return status;
}


///
/// @brief Translates a guest virtual address to a guest physical address
///
/// Will translate the GuestVirtAddress into a Guest Physical Address, and will return the obtained
/// address via the GuestPhysicalAddress pointer.
///
/// NOTE: If STATUS_PAGE_NOT_PRESENT is returned, the obtained GPA is still valid, however, trying
/// to map any of the GVA or GPA will fail.
///
/// @param Vcpu                             // Vcpu used to translate the address.
/// @param GuestVirtAddress                 // The guest virtual address to be translated.
/// @param GuestPhysicalAddress             // Will contain upon exit the guest physical address.
///
/// @return STATUS_NO_EMHV_INITIALIZED If the EMHV interface has not yet been initialized.
/// @return STATUS_NO_MAPPING_STRUCTURES If, at any given moment, a mapping structure is not found in memory.
/// @return STATUS_PAGE_NOT_PRESENT If the page is not present in memory (P bit == 0).
/// @return CX_STATUS_SUCCESS If the translation process was succesfull.
///
static
NTSTATUS
_EmhvTranslateVirtualAddress(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 GuestVirtAddress,
    _Inout_ CX_UINT64 *GuestPhysicalAddress
    )
{
    CX_UINT64 hpa;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!GuestPhysicalAddress) return CX_STATUS_INVALID_PARAMETER_3;

    return ChmGvaToGpaAndHpa(Vcpu, GuestVirtAddress, GuestPhysicalAddress, &hpa);
}

///
/// @brief Map guest virtual address into hypervisor virtual space
///
/// Will map the given virtual page using the cachemap functions.
///
/// NOTE: This function supports mapping more than 1 page.
///
/// @param Vcpu                 The Vcpu used to map this page.
/// @param PageAddress          The address of the page to be mapped.
/// @param PageCount            Number of pages to be mapped.
/// @param HostVa               Will contain upon exit the host VA pointing to the new mapped page including page offset
///
/// \ret STATUS_POINTER_MUST_BE_PAGE_ALLIGNED If PageAddress is not page aligned.
/// \ret CX_STATUS_SUCCESS If the page has been succesfully mapped.
///
static
NTSTATUS
_EmhvMapVirtualMemory(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 PageAddress,
    _In_ CX_UINT32 PageCount,
    _Inout_ CX_VOID* *HostVa
    )
{
    NTSTATUS status;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!PageCount) return CX_STATUS_INVALID_PARAMETER_3;
    if (!HostVa) return CX_STATUS_INVALID_PARAMETER_4;

    status = ChmMapGuestGvaPagesToHost(Vcpu,
                PageAddress,
                PageCount,
                0,
                HostVa,
                NULL,
                TAG_EMU);

    return status;
}


///
/// @brief Unmap guest virtual memory from hypervisor virtual space
///
/// Will unmap a page previously mapped using _EmhvMapVirtualMemory.
///
/// @param HostVa                   Host VA containing a pointer to a page previosuly mapped.
///
/// @return CX_STATUS_SUCCESS       If the page has been succesfully unmapped.
/// @return STATUS_XXX              If an error occures.
///
static
NTSTATUS
_EmhvUnmapVirtualMemory(
    _Inout_ CX_VOID** HostVa
    )
{
    NTSTATUS status;

    if ((!HostVa) || (!(*HostVa))) return CX_STATUS_SUCCESS;

    status = ChmUnmapGuestGvaPages(HostVa, TAG_EMU);

    return status;
}

///
/// @brief Unmap guest physical memory from hypervisor virtual address space
///
/// Will unmap the page previously mapped using EmhvMapPhysicalMemory.
///
/// NOTE: This function supports mapping more than 1 page.
///
/// @param HostVa                   Host VA containing a pointer to a page previosuly mapped.
///
/// @return CX_STATUS_SUCCESS       If the page was succesfully unmapped.
/// @return STATUS_XXX              If an error occured.
///
static
NTSTATUS
_EmhvUnmapPhysicalMemory(
    _Inout_ CX_VOID** HostVa
    )
{
    NTSTATUS status;

    if ((!HostVa) || (!(*HostVa))) return CX_STATUS_SUCCESS;

    status = ChmUnmapContinuousGuestGpaPagesFromHost(HostVa, TAG_EMU);

    return status;
}

///
/// @brief Read device memory for emulation purposes
///
/// This function Will handle device-specific memory read accesses. Will call the specific handler for the given
/// memory range, if a device has registered with MMIO space in that region.
///
/// @param Vcpu                  Current Vcpu (context used for reading device memory).
/// @param Context               Device context.
/// @param PhysicalAddress       Physical address that was accessed
/// @param Length                Length can be 1, 2, 4, 8, 16 or 32 bytes, however, device memory is typically accessed as 1, 2, 4 or 8 bytes / instrux only
/// @param Value                 Value data
///
/// @return CX_STATUS_SUCCESS        If the read attempt has been handled succesfully.
/// @return STATUS_XXX               If an error occures.
///
static
NTSTATUS
_EmhvReadDevMem(
    _In_ VCPU* Vcpu,
    _In_ CX_VOID* Context,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Length,
    _Out_ CX_UINT8* Value
    )
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Vcpu);

    if (!Context) return CX_STATUS_INVALID_PARAMETER_2;
    if ((Length != 1) && (Length != 2) && (Length != 4) && (Length != 8) && (Length != 16) && (Length != 32)) return CX_STATUS_INVALID_PARAMETER_4;

    GUEST_EPT_HOOK* hook = (GUEST_EPT_HOOK*)Context;

    status = hook->ReadCb(PhysicalAddress, Length, Value, hook->Context);
    if (!SUCCESS(status))
    {
        LOG("ERROR: res->ReadMem failed on %018p, status=%s\n", PhysicalAddress, NtStatusToString(status));
    }

    return status;
}

///
/// @brief Write device memory for emulation purposes
///
/// This function will handle device-specific memory write accesses. Will call the specific handler for the given
/// memory range, if a device has registered with MMIO space in that region.
///
/// @param Vcpu                  Current Vcpu (context used for reading device memory).
/// @param Context               Device context.
/// @param PhysicalAddress       Physical address that was accessed
/// @param Length                Length can be 1, 2, 4, 8, 16 or 32 bytes, however, device memory is typically accessed as 1, 2, 4 or 8 bytes / instrux only
/// @param Value                 Value data
///
/// @return CX_STATUS_SUCCESS        If the write attempt has been handled succesfully.
/// @return STATUS_XXX               If an error occures.
static
NTSTATUS
_EmhvWriteDevMem(
    _In_ VCPU* Vcpu,
    _In_ CX_VOID* Context,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Length,
    _In_ CX_UINT8* Value
    )
{
    NTSTATUS status;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Context) return CX_STATUS_INVALID_PARAMETER_2;

    if ((Length != 1) && (Length != 2) && (Length != 4) && (Length != 8) && (Length != 16) && (Length != 32)) return CX_STATUS_INVALID_PARAMETER_4;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_5;

    GUEST_EPT_HOOK* hook = (GUEST_EPT_HOOK*)Context;

    status = hook->WriteCb(PhysicalAddress, Length, Value, hook->Context);
    if (!SUCCESS(status))
    {
        LOG("ERROR: res->WriteMem failed on %018p, status=%s\n", PhysicalAddress, NtStatusToString(status));
    }

    return status;
}


///
/// @brief IO port read for emulation purposes
///
/// This function will handle the I/O port access by calling the device callbacks that were registered for I/O ports.
/// If context is NULL, will attempt to call the per-guest handler. Otherwise, it will handle the request
/// bare-metal.
///
/// @param Vcpu              Current Vcpu (context used for handling the request).
/// @param Context           Device specific context.
/// @param IoPort            I/O port accessed.
/// @param Length            Length can be 1,2 or 4 bytes
/// @param Value             Value that will be returned upon exit by the device.
///
/// @return STATUS_STATUS_NOT_SUPPORTED      If no device has registered a I/O port range that covers this port.
/// @return CX_STATUS_SUCCESS                If the request was handled succesfully.
/// @return STATUS_XXX                       If any other error occures. See device specific handlers for possible return codes.
///
static
NTSTATUS
_EmhvReadIoPort(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _Out_ CX_UINT8* Value
    )
{
    NTSTATUS status;
    GUEST* guest;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if ((Length != 1) && (Length != 2) && (Length != 4))  return CX_STATUS_INVALID_PARAMETER_4;

    // I/O port must be alligned according to Length
    if (((Length - 1) > 0) && (0 != (IoPort & (Length - 1)))) return CX_STATUS_INVALID_PARAMETER_3;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_5;

    guest = Vcpu->Guest;

    if (Context)
    {
        GUEST_IO_HOOK* hook = Context;

        status = hook->ReadCb(IoPort, Length, Value, hook->Context);
        if (!SUCCESS(status))
        {
            LOG("ERROR: res->ReadCb failed on 0x%08x, status=%s\n", IoPort, NtStatusToString(status));
        }
    }
    else
    {
        if (guest->ReadIoPort)
        {
            // 2. try to execute using per-guest callbacks
            status = guest->ReadIoPort(IoPort, Length, Value, NULL);
        }
        else
        {
            // 3. execute on bare-metal level
            if (1 == Length)
            {
                *Value = __inbyte(IoPort);
            }
            else if (2 == Length)
            {
                *(CX_UINT16*)Value = __inword(IoPort);
            }
            else
            {
                *(CX_UINT32*)Value = __indword(IoPort);
            }

            status = CX_STATUS_SUCCESS;
        }
    }

    return status;
}


///
/// @brief IO port write for emulation purposes
///
/// This function Will handle the I/O port access by calling the device callbacks that were registered for I/O ports.
/// If context is NULL, will attempt to call the per-guest handler. Otherwise, it will handle the request
/// bare-metal.
///
/// @param Vcpu              Current Vcpu (context used for handling the request).
/// @param Context           Device specific context.
/// @param IoPort            I/O port accessed.
/// @param Length            Length can be 1,2 or 4 bytes
/// @param Value             Value that will be written upon exit on the device.
///
/// @return STATUS_STATUS_NOT_SUPPORTED      If no device has registered a I/O port range that covers this port.
/// @return CX_STATUS_SUCCESS                If the request was handled succesfully.
/// @return STATUS_XXX                       If any other error occures. See device specific handlers for possible return codes.
///

static
NTSTATUS
_EmhvWriteIoPort(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT16 IoPort,
    _In_ CX_UINT8 Length,
    _In_ CX_UINT8* Value
    )
{
    NTSTATUS status;
    GUEST* guest;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE; //-

    if ((NULL == Vcpu) || (NULL == Vcpu->Guest))
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    // validate length
    if ((1 != Length) && (2 != Length) && (4 != Length))
    {
        return CX_STATUS_INVALID_PARAMETER_4;
    }

    // I/O port must be alligned according to Length
    if (((Length - 1) > 0) && (0 != (IoPort & (Length - 1))))
    {
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Value)
    {
        return CX_STATUS_INVALID_PARAMETER_5;
    }

    guest = Vcpu->Guest;

    if (NULL != Context)
    {
        GUEST_IO_HOOK* hook = Context;

        status = hook->WriteCb(IoPort, Length, Value, hook->Context);
        if (!SUCCESS(status))
        {
            LOG("ERROR: res->WriteCb failed on 0x%04X, status=%s\n", IoPort, NtStatusToString(status));
        }
    }
    else
    {
        if (NULL != guest->WriteIoPort)
        {
            // 2. try to execute using per-guest callbacks
            status = guest->WriteIoPort(IoPort, Length, Value, NULL);
        }
        else
        {
            // 3. execute on bare-metal level
            if (1 == Length)
            {
                __outbyte(IoPort, (CX_UINT8)(*Value & 0xFF));
            }
            else if (2 == Length)
            {
                __outword(IoPort, (CX_UINT16)(*(CX_UINT16*)Value & 0xFFFF));
            }
            else
            {
                __outdword(IoPort, (CX_UINT32)(*(CX_UINT32*)Value & 0xFFFFFFFF));
            }

            status = CX_STATUS_SUCCESS;
        }
    }

    return status;
}

///
/// @brief MSR read for emulation purposes
///
/// this function will handle MSR read attempts, by calling devices that registered handlers for MSRs.
/// If context is NULL, will attempt to call the per-guest handler. Otherwise, it will
/// handle the access bare-metal.
///
/// @param Vcpu            Current Vcpu (context used for handling the request).
/// @param Context         Device specific context.
/// @param Msr             Msr read
/// @param Value           The value of the MSR as returned by the handler.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED      If context is not NULL, and no device has registered handler for MSRs.
/// @return CX_STATUS_SUCCESS                      On succesfull handling of the instruction.
static
NTSTATUS
_EmhvReadMsr(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT32 Msr,
    _Out_ CX_UINT64 *Value
    )
{
    NTSTATUS status;
    GUEST* guest;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;
    if (!Value) return CX_STATUS_INVALID_PARAMETER_4;

    guest = Vcpu->Guest;

    if (Context)
    {
        GUEST_MSR_HOOK* hook = Context;

        status = hook->ReadCb(Msr, Value, hook->Context);
        if (!SUCCESS(status))
        {
            LOG("ERROR: res->ReadCb failed on 0x%08x, status=%s\n", Msr, NtStatusToString(status));
        }
    }
    else
    {
        if (guest->ReadMsr)
        {
            // 2. try to execute using per-guest callbacks
            status = guest->ReadMsr(Msr, Value, NULL);
        }
        else
        {
            // 3. execute on bare-metal level
            *Value = __readmsr(Msr);

            status = CX_STATUS_SUCCESS;
        }
    }

    return status;
}

///
/// @brief MSR write for emulation purposes
///
/// This function will handle MSR read attempts, by calling devices that registered handlers for MSRs.
/// If context is NULL, will attempt to call the per-guest handler. Otherwise, it will
/// handle the access bare-metal.
///
/// @param Vcpu            Current Vcpu (context used for handling the request).
/// @param Context         Device specific context.
/// @param Msr             Msr written
/// @param Value           The value of the MSR to be written.
///
/// @return CX_STATUS_OPERATION_NOT_SUPPORTED      If context is not NULL, and no device has registered handler for MSRs.
/// @return CX_STATUS_SUCCESS                      On succesfull handling of the instruction.
static
NTSTATUS
_EmhvWriteMsr(
    _In_ VCPU* Vcpu,
    _In_opt_ CX_VOID* Context,
    _In_ CX_UINT32 Msr,
    _In_ CX_UINT64 Value
    )
{
    NTSTATUS status;
    GUEST* guest;

    if ((!Vcpu) || (!Vcpu->Guest)) return CX_STATUS_INVALID_PARAMETER_1;

    guest = Vcpu->Guest;

    if (Context)
    {
        GUEST_MSR_HOOK* hook = Context;

        status = hook->WriteCb(Msr, Value, hook->Context);
        if (!SUCCESS(status))
        {
            LOG("ERROR: res->WriteCb failed on 0x%08x, status=%s\n", Msr, NtStatusToString(status));
        }
    }
    else
    {
        if (guest->WriteMsr)
        {
            // 2. try to execute using per-guest callbacks
            status = guest->WriteMsr(Msr, Value, NULL);
        }
        else
        {
            // 3. execute on bare-metal level
            __writemsr(Msr, Value);

            status = CX_STATUS_SUCCESS;
        }
    }

    return status;
}


///
/// @brief VMCS read for emulation purposes
///
/// This function will handle VMCS read attempts.
///
/// @param Vcpu            Current Vcpu (context used for handling the request).
/// @param Id              VMCS field id
/// @param Value           The value returned from VMCS
///
/// \ret CX_STATUS_OPERATION_NOT_SUPPORTED      If the effective access to VMCS fails
/// \ret CX_STATUS_SUCCESS                      On success
static
NTSTATUS
_EmHvVmxRead(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Id,
    _Out_ CX_UINT64* Value
    )
{
    UNREFERENCED_PARAMETER(Vcpu);

    return (vmx_vmread(Id, Value) == 0) ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
}

///
/// @brief VMCS write for emulation purposes
///
/// This function will handle VMCS write attempts.
///
/// @param Vcpu            Current Vcpu (context used for handling the request).
/// @param Id              VMCS field id
/// @param Value           The value to be written in VMCS
///
/// \ret CX_STATUS_OPERATION_NOT_SUPPORTED      If the effective access to VMCS fails
/// \ret CX_STATUS_SUCCESS                      On success
static
NTSTATUS
_EmHvVmxWrite(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Id,
    _In_ CX_UINT64 Value
    )
{
    UNREFERENCED_PARAMETER(Vcpu);

    return (vmx_vmwrite(Id, Value) == 0) ? CX_STATUS_SUCCESS : CX_STATUS_OPERATION_NOT_SUPPORTED;
}

///
/// @brief VCPU state access
///
/// This function will save VCPU specific state. Only FPU state is supported.
///
/// @param Vcpu                 Current Vcpu (context used for handling the request).
/// @param CpuSaveState         Saved FPU state
///
/// \ret CX_STATUS_OPERATION_NOT_SUPPORTED      If the operation could not be performed
/// \ret CX_STATUS_SUCCESS                      On success
static
NTSTATUS
_EmHvSaveCpuState(
    _In_ VCPU* Vcpu,
    _In_ EMHV_SAVE_STATE CpuSaveState
    )
{
    UNREFERENCED_PARAMETER((Vcpu));

    if (CpuSaveState == emhvSaveFpuState)
    {
        // there's nothing to do, we save the guest FPU state on every VM exit
        return CX_STATUS_SUCCESS;
    }

    return CX_STATUS_OPERATION_NOT_SUPPORTED;
}


