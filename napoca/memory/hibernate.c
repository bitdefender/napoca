/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup hibernate Support for the Guests' power transition into power state S4 (Hibernate)
/// @ingroup power
///@{

/** @file hibernate.c
 *  @brief HV_HIBERNATE - Support for saving data to persistent memory area, during of the power transition of the Guest into S4(Hibernate) state.
 *
 *  The persistent memory area is obtained from the loader and comes as a separate module. And it will look like this:
 *  [guard page][....useful buffer....][guard page]
 *
 *  @remark Our solution is based on letting the Guest do the salvation of the data including our data also.
 *
 *  Algorithm for entering hibernate:
 *      - hook for read access the first guard page to detect when guest begins to save our NVS memory;
 *      - when hook is triggered we save our useful data
 *      - remove read access hook and allow guest to save all data
 *  Algorithm for resuming from hibernate:
 *      - hook for write access the last guard page to detect when the guest ends to restore our NVS memory
 *      - when hook is triggered we change the internal state of hibernate to HibernateResumeEnd
 *      - remove write access hook and allow guest to restore the guard page
 *      - on the next exits we try the restoration by verifying the checksum on the persistent area to match the saved checksum
 *      - if the checksum matches we restore the saved data and once more remove the access rights of the guard pages to be ready for the next hibernate
 */

#include "napoca.h"
#include "memory/hibernate.h"
#include "kernel/vcpu.h"
#include "guests/guests.h"
#include "memory/memmgr.h"
#include "memory/heap.h"
#include "memory/ept.h"
#include "kernel/simplechecksum.h"

#include "kernel/kernel.h"
#include "memory/cachemap.h"

 ///
 /// @brief        Calls the Get callback for every hibernate client in order to save data before entering in the hibernate state.
 ///
 /// @param[in]    Guest                            Napoca-specific guest identifier.
 ///
 /// @returns      CX_STATUS_SUCCESS                - always, when we attempt this store the clients must be sure to store their data properly
 ///
static
NTSTATUS
_HvHibSaveDataBeforeHibernate(
    _In_ GUEST *Guest
)
{
    // ignore statuses as some of the clients may fail and others may succeed (failing of saving the data at this point is really unlikely)
    for (BYTE i = 0; i < Guest->HibernateData.NumberOfClients; i++)
    {
        if (Guest->HibernateData.Clients[i].GetCallback)
        {
            Guest->HibernateData.Clients[i].GetCallback(
                Guest->HibernateData.Clients[i].StartOffset,
                Guest->HibernateData.Clients[i].Size
            );
        }
    }
    return CX_STATUS_SUCCESS;
}

///
/// @brief        Calls the Put callback for every hibernate client in order to restore data on a wakeup from hibernate.
///
/// @param[in]    Guest                            Napoca-specific guest identifier.
///
/// @returns      CX_STATUS_SUCCESS                - always, when we attempt this restore the clients must be sure to restore their data properly
///
static
NTSTATUS
_HvHibRestoreDataAfterHibernate(
    _Inout_ GUEST *Guest
)
{
    // ignore statuses as some of the clients may fail and others may succeed (failing of restoration at this point is really unlikely)
    for (BYTE i = 0; i < Guest->HibernateData.NumberOfClients; i++)
    {
        if (Guest->HibernateData.Clients[i].PutCallback)
        {
            Guest->HibernateData.Clients[i].PutCallback(
                Guest->HibernateData.Clients[i].StartOffset,
                Guest->HibernateData.Clients[i].Size
            );
        }
    }
    return CX_STATUS_SUCCESS;
}

NTSTATUS
HvHibInitialize(
    _Inout_ GUEST *Guest
)
{
    NTSTATUS status;
    MEM_MAP_ENTRY tempEntryGuestPhysMap;
    VOID *hva;
    QWORD hpa;
    LD_NAPOCA_MODULE *module = NULL;

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nPRIMARY GUEST physical memory maps follows ... \n");
        MmapDump(&Guest->PhysMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->PhysMap, ");
    }

    // allocate HibernateContextRestoreGuestPhysMap map
    status = MmapAllocMapEntries(&Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap, GST_HIBERNATE_CONTEXT_RESTORE_AREA_COUNT);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapAllocMapEntries", status);
        goto cleanup;
    }

    // get the LD_MODID_NVS module previously allocated
    status = LdGetModule(gBootModules, LD_MAX_MODULES,LD_MODID_NVS, &module);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("LdGetModule", status);
        goto cleanup;
    }

    // get the hva/hpa associated to the module
    hva = (VOID*)module->Va;
    hpa = module->Pa;

    // create the entry for the physical memory map that holds information about the NVS area
    tempEntryGuestPhysMap.Type = BOOT_MEM_TYPE_NVS;
    tempEntryGuestPhysMap.StartAddress = hpa;
    tempEntryGuestPhysMap.CacheAndRights = EPT_RAW_CACHING_WB | EPT_RAW_RIGHTS_RW;
    tempEntryGuestPhysMap.DestAddress = hpa;
    tempEntryGuestPhysMap.Length = GST_HIBERNATE_CONTEXT_RESTORE_AREA_SIZE;
    status = EptMapMem(GstGetEptOfPhysicalMemory(Guest), hpa, hpa, GST_HIBERNATE_CONTEXT_RESTORE_AREA_SIZE);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("EptMapMem", status);
        goto cleanup;
    }

    if (!BOOT_UEFI)
    {
        // If we are on legacy add the entry to the physical map in order to acknowledge Windows about this area
        status = MmapApplyNewEntry(&Guest->PhysMap, &tempEntryGuestPhysMap, MMAP_SPLIT_AND_KEEP_NEW);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("MmapApplyNewEntry", status);
            goto cleanup;
        }
    }

    // Save the hibernate context save areas in dedicated map also
    status = MmapApplyNewEntry(&Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap, &tempEntryGuestPhysMap, MMAP_SPLIT_AND_KEEP_NEW);
    if (!SUCCESS(status))
    {
        LOG_FUNC_FAIL("MmapApplyNewEntry", status);
        goto cleanup;
    }

    //                 |----------|--------------------------------|-----|----------------------------------|----------------------------|
    // Buffer Start -> | CHECKSUM |           CLIENT 0             | ... |             CLIENT N             |         FREE SPACE         | <- Buffer Start + Buffer Size
    //                 |----------|--------------------------------|-----|----------------------------------|----------------------------|
    Guest->HibernateData.State = HibernateNotStarted;
    Guest->HibernateData.Buffer = hva;
    Guest->HibernateData.BufferSize = (GST_HIBERNATE_CONTEXT_RESTORE_AREA_NO_OF_PAGES * PAGE_SIZE);
    Guest->HibernateData.FreeOffset = (VOID*)((BYTE*)hva + sizeof(QWORD)); // Make sure the first 4 bytes from the restored area are reserved for the hash
    Guest->HibernateData.FreeSize = (GST_HIBERNATE_CONTEXT_RESTORE_AREA_NO_OF_PAGES * PAGE_SIZE) - sizeof(QWORD);
    Guest->HibernateData.NumberOfClients = 0;
    Guest->HibernateData.CrtRetryHibernateRestoreCheck = 0;
    Guest->HibernateData.MaxNumberOfHibernateRestoreChecks = MAX_NUMBER_OF_HIBERNATE_RESTORE_CHECKS;

    if (CfgDebugTraceMemoryMaps)
    {
        LOG("\nPRIMARY GUEST physical memory maps follows ...\n");
        MmapDump(&Guest->PhysMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->PhysMap, ");

        LOG("\nPRIMARY GUEST HibernateContextRestoreMap follows ...\n");
        MmapDump(&Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap, BOOT_MEM_TYPE_AVAILABLE, "PrimaryGuest->HibernateContextRestoreMap, ");
    }

cleanup:
    return status;
}

NTSTATUS
HvHibApplyMemoryHooks(
    _Inout_ GUEST *Guest
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    MEM_MAP_ENTRY *entry = NULL;
    QWORD gpa, hpa;
    int page_no = 0;

    for (DWORD i = 0; i < Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Count; i++)
    {
        entry = &Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[i];

        for (gpa = entry->StartAddress, hpa = entry->DestAddress;
            gpa < entry->StartAddress + entry->Length;
            gpa += PAGE_SIZE, hpa += PAGE_SIZE, page_no++)
        {
            NTSTATUS localStatus;
            // guard pages - intercept so we know when to start doing stuff (save/restore)
            if ( (page_no == 0) || (page_no == (GST_HIBERNATE_CONTEXT_RESTORE_AREA_NO_OF_PAGES - 1)))
            {
                localStatus = EptSetRights(GstGetEptOfPhysicalMemory(Guest), CX_PAGE_BASE_4K(gpa), 0, EPT_RIGHTS_NONE);
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("EptSetRights", localStatus);
                    status = localStatus;
                }
            }
            else // pages - useful buffer we do not need hooks here
            {
                localStatus = EptSetRights(GstGetEptOfPhysicalMemory(Guest), CX_PAGE_BASE_4K(gpa), 0, EPT_RIGHTS_RW);
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("EptSetRights", localStatus);
                    status = localStatus;
                }
            }
        }

    }
    return status;
}

BOOLEAN
HvHibIsHibernateMemoryAddress(
    _In_ GUEST *Guest,
    _In_ QWORD Gpa
)
{
    DWORD area;
    BOOLEAN found = FALSE;

    for (area = 0; area < Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Count; area++)
    {
        if (
            (Gpa >= Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[area].StartAddress) &&
            (Gpa < Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[area].StartAddress + Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[area].Length)
            )
        {
            found = TRUE;
            break;
        }
    }

    return found;
}

NTSTATUS
HvHibHandleHibernateMemory(
    _In_ GUEST *Guest,
    _In_ VCPU  *Vcpu,
    _In_ QWORD Gpa,
    _In_ QWORD Qualification
)
{
    NTSTATUS status = CX_STATUS_SUCCESS;
    QWORD guard1, guard2;
    MEM_MAP_ENTRY *firstEntry = NULL;
    MEM_MAP_ENTRY *lastEntry = NULL;

    firstEntry = &Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[0];
    lastEntry = &Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[Guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Count - 1];

    guard1 = (firstEntry->StartAddress & PAGE_MASK);
    guard2 = (((lastEntry->StartAddress & PAGE_MASK) + lastEntry->Length - 1) & PAGE_MASK);

    if (Qualification & EPT_RAW_RIGHTS_R)
    {
        Guest->HibernateData.State = HibernateEnter;

        status = _HvHibSaveDataBeforeHibernate(Guest);
        if (!NTSUCCESS(status))
        {
            LOG_FUNC_FAIL("_HvHibSaveDataBeforeHibernate", status);
        }

        *(QWORD*)(Guest->HibernateData.Buffer) = HvChecksum64(Guest->HibernateData.Buffer + sizeof(QWORD), Guest->HibernateData.BufferSize - sizeof(QWORD));

        // hibernate begins - remove read hooks from the guard pages
        status = EptSetRights(GstGetEptOfPhysicalMemory(Guest), guard1 & PAGE_MASK, 0, EPT_RIGHTS_R);
        if (!SUCCESS(status))
        {
            VCPULOG(Vcpu, "EptSetRights failed for page at GPA %018p, status = %s\n", Gpa, NtStatusToString(status));
        }

        status = EptSetRights(GstGetEptOfPhysicalMemory(Guest), guard2 & PAGE_MASK, 0, EPT_RIGHTS_R);
        if (!SUCCESS(status))
        {
            VCPULOG(Vcpu, "EptSetRights failed for page at GPA %018p, status = %s\n", Gpa, NtStatusToString(status));
        }

        // Just try re-executing the read instruction
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }
    else
    {
        if (Qualification & EPT_RAW_RIGHTS_W)
        {
            if (Guest->HibernateData.State == HibernateNotStarted)
            {
                Guest->HibernateData.State = HibernateResumeBegin;
            }
            else if (Guest->HibernateData.State == HibernateResumeBegin)
            {
                Guest->HibernateData.State = HibernateResumeEnd;
            }

            // remove hook from this guard page
            status = EptSetRights(GstGetEptOfPhysicalMemory(Guest), Gpa & PAGE_MASK, 0, EPT_RIGHTS_RW);
            if (!SUCCESS(status))
            {
                VCPULOG(Vcpu, "EptSetRights failed for page at GPA %018p, status = %s\n", Gpa, NtStatusToString(status));
            }

            // Just try re-executing the write instruction
            status = CX_STATUS_SUCCESS;
            goto cleanup;

        }
        else
        {
            VCPULOG(Vcpu, "Guest tries to access GPA %p. Exit qualification %p, i.e. for some other unsupported reason.\n", Gpa, Qualification);
        }
    }

cleanup:
    return status;
}

NTSTATUS
HvHibRegisterClient(
    _In_ GUEST *Guest,
    _In_ HVHIB_GETDATA_CALLBACK GetCallback,
    _In_ HVHIB_PUTDATA_CALLBACK PutCallback,
    _In_ DWORD RequiredSize
)
{
    NTSTATUS status;

    // check for available client slot
    if (Guest->HibernateData.NumberOfClients == HVHIB_MAX_CLIENTS)
    {
        status = STATUS_TOO_MANY_DEVICES;
        goto cleanup;
    }

    // check for enough free size
    if (Guest->HibernateData.FreeSize < RequiredSize)
    {
        status = CX_STATUS_DATA_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    // must have callbacks
    if (GetCallback == NULL || PutCallback == NULL)
    {
        status = STATUS_NOT_A_VALID_POINTER;
        goto cleanup;
    }

    // check the required size
    if (RequiredSize == 0)
    {
        status = CX_STATUS_INVALID_PARAMETER_4;
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

    // check for already existing
    for (BYTE i = 0; i < Guest->HibernateData.NumberOfClients; i++)
    {
        if ((Guest->HibernateData.Clients[i].GetCallback == GetCallback) || (Guest->HibernateData.Clients[i].PutCallback == PutCallback))
        {
            status = STATUS_OVERLAP_VIOLATION;
            break;
        }
    }

    if (!SUCCESS(status))
    {
        goto cleanup;
    }

    Guest->HibernateData.Clients[Guest->HibernateData.NumberOfClients].GetCallback = GetCallback;
    Guest->HibernateData.Clients[Guest->HibernateData.NumberOfClients].PutCallback = PutCallback;
    Guest->HibernateData.Clients[Guest->HibernateData.NumberOfClients].StartOffset = Guest->HibernateData.FreeOffset;
    Guest->HibernateData.Clients[Guest->HibernateData.NumberOfClients].Size = RequiredSize;

    Guest->HibernateData.NumberOfClients++;
    Guest->HibernateData.FreeOffset += RequiredSize;
    Guest->HibernateData.FreeSize -= RequiredSize;

cleanup:
    return status;
}

NTSTATUS
HvHibCheckCompleteRestorationOfSavedData(
    _In_ VCPU *Vcpu
)
{
    if (!Vcpu) return CX_STATUS_INVALID_INTERNAL_STATE;

    if (!(Vcpu->Guest->HibernateData.State == HibernateResumeEnd &&
        Vcpu->Guest->HibernateData.CrtRetryHibernateRestoreCheck < Vcpu->Guest->HibernateData.MaxNumberOfHibernateRestoreChecks))
    {
        return CX_STATUS_DATA_NOT_FOUND;
    }

    QWORD currentHash;
    GUEST *guest = &(Vcpu->Guest[0]);
    NTSTATUS status;

    // If it was signaled that windows has started restoring data by triggering the write ept violation,
    // check if data is completely restored (by checking if the checksum at the begining of the restored buffer == checksum of the rest of the buffer)
    {
        QWORD guard1, guard2;
        MEM_MAP_ENTRY* firstEntry = NULL;
        MEM_MAP_ENTRY* lastEntry = NULL;

        firstEntry = &guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[0];
        lastEntry = &guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Entry[guest->HibernateData.HibernateContextRestoreGuestPhyMemMap.Count - 1];

        guard1 = (firstEntry->StartAddress & PAGE_MASK);
        guard2 = (((lastEntry->StartAddress & PAGE_MASK) + lastEntry->Length - 1) & PAGE_MASK);

        // Check if the checksum at the begining of the restored buffer == checksum of the rest of the buffer
        currentHash = HvChecksum64(guest->HibernateData.Buffer + sizeof(QWORD), guest->HibernateData.BufferSize - sizeof(QWORD));
        if (currentHash != *(QWORD*)(guest->HibernateData.Buffer))
        {
            CRITICAL("Inconsistent hibernate data hash: Current read hash %lld Current computed hash %lld\n", *(QWORD*)(guest->HibernateData.Buffer), currentHash);
            status = CX_STATUS_DATA_NOT_READY;
        }
        // If data is restored, change ept-violation from write to read, such that when we enter hibernate again the write data sequence will be notified
        else
        {
            // call all clients to restore their data
            status = _HvHibRestoreDataAfterHibernate(guest);

            // remove all rights from guard pages so we can intercept next transition
            status = EptSetRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), guard1 & PAGE_MASK, 0, EPT_RIGHTS_NONE);
            if (!SUCCESS(status))
            {
                VCPULOG(Vcpu, "EptSetRights failed for GUARD PAGE 1\n", );
                goto cleanup;
            }

            status = EptSetRights(GstGetEptOfPhysicalMemory(Vcpu->Guest), guard2 & PAGE_MASK, 0, EPT_RIGHTS_NONE);
            if (!SUCCESS(status))
            {
                VCPULOG(Vcpu, "EptSetRights failed for GUARD PAGE 2\n");
                goto cleanup;
            }
            LOG("Hibernate data restoration complete after %lld attempts\n", Vcpu->Guest->HibernateData.CrtRetryHibernateRestoreCheck);

            // mark that the hibernate process is not in progress anymore
            guest->HibernateData.State = HibernateNotStarted;
        }
    }

 cleanup:
    // Increase the number of times we have tried to read the hibernate data
    Vcpu->Guest->HibernateData.CrtRetryHibernateRestoreCheck++;
    return status;
}


///@}