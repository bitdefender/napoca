/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
//  $Id$
//
//  Copyright (C) 2011 BitDefender S.R.L.
//
#include "hvdefs.h"
#include "hvstatus.h"
#include "crt/crt.h"
#include "kernel/kernel.h"
#include "io/io.h"

#include "../acpia/source/include/acpi.h"

#define ACPI_MAX_INIT_TABLES    32
static ACPI_TABLE_DESC      AcpiTableArray[ACPI_MAX_INIT_TABLES];

BOOLEAN
InitMpSupport(
    void
    )
//
/// ...
//
/// \ret FALSE ...
/// \ret TRUE ...
//
{
    // check for acpi tables
    ACPI_STATUS acpiStatus;
    ACPI_TABLE_MADT* madt = NULL;
//    ACPI_TABLE_DMAR* dmar;

    /* Initialize the ACPICA Table Manager and get all ACPI tables */
    acpiStatus = AcpiInitializeTables (AcpiTableArray, ACPI_MAX_INIT_TABLES, TRUE);
    if (!ACPI_SUCCESS(acpiStatus))
    {
        TRACE("AcpiInitializeTables failed, status=0x%08x\n", acpiStatus);
        return FALSE;
    }

    {
//        BYTE type;
//        PVOID p;
//        DWORD structSize;

        // get the
        acpiStatus = AcpiGetTable("APIC", 0, (ACPI_TABLE_HEADER**)&madt);
        if (!ACPI_SUCCESS(acpiStatus))
        {
            LOG("[ERROR] : AcpiGetTable for MADT failed, acpiStatus = 0x%x\n", acpiStatus);
            return FALSE;
        }

        TRACE("MADT at 0x%p\n", madt);
        TRACE("Local APIC address = 0x%x\n", madt->Address);

/*
        G.LAPICBase = (QWORD) madt->Address;

        type = *(BYTE*)(madt + 1);
        p = (PVOID) (madt + 1);
        structSize = *(BYTE*)((QWORD)p + 1);

        while ((QWORD) p < (QWORD)((QWORD)madt + madt->Header.Length))
        {
            acpiStatus = AE_OK;

            switch(type)
            {

            case ACPI_MADT_TYPE_LOCAL_APIC:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_APIC\n");
                {
                    ACPI_MADT_LOCAL_APIC *cpu = (ACPI_MADT_LOCAL_APIC*)p;
                    // HvTrace("--> CPU ACPI Processor Id = %d, APIC ID = %d, %s\n", cpu->ProcessorId, cpu->Id, (cpu->LapicFlags & ACPI_MADT_ENABLED)?" -> USABLE":" -> NOT USABLE");

                    if (cpu->LapicFlags & ACPI_MADT_ENABLED)
                    {
                        HvTrace("--> Usable CPU Found : Acpi Proc ID = %d, APIC_ID = %d\n", cpu->ProcessorId, cpu->Id);
                    }
                }
                break;

            case ACPI_MADT_TYPE_IO_APIC:
                // HvTrace("Found ACPI_MADT_TYPE_IO_APIC\n");
                break;

            case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE:
                // HvTrace("Found ACPI_MADT_INTERRUPT_OVERRIDE\n");
                break;

            case ACPI_MADT_TYPE_NMI_SOURCE:
                // HvTrace("Found ACPI_MADT_TYPE_NMI_SOURCE\n");
                break;

            case ACPI_MADT_TYPE_LOCAL_APIC_NMI:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_APIC_NMI\n");
                break;

            case ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE\n");
                break;

            case ACPI_MADT_TYPE_IO_SAPIC:
                // HvTrace("Found ACPI_MADT_TYPE_IO_SAPIC\n");
                break;

            case ACPI_MADT_TYPE_LOCAL_SAPIC:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_SAPIC\n");
                break;

            case ACPI_MADT_TYPE_INTERRUPT_SOURCE:
                // HvTrace("Found ACPI_MADT_TYPE_INTERRUPT_SOURCE\n");
                break;

            case ACPI_MADT_TYPE_LOCAL_X2APIC:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_X2APIC\n");
                break;

            case ACPI_MADT_TYPE_LOCAL_X2APIC_NMI:
                // HvTrace("Found ACPI_MADT_TYPE_LOCAL_X2APIC_NMI\n");
                break;

            case ACPI_MADT_TYPE_RESERVED:
                // HvTrace("Found ACPI_MADT_TYPE_RESERVED\n");
                break;

            default:
                HvTrace("[ERROR] : Unrecognized MADT type : %d\n", (DWORD) type);
                acpiStatus = AE_ERROR;
                break;
            }

            if (!ACPI_SUCCESS(acpiStatus))
            {
                break;
            }

            p = (PVOID) ((QWORD)p + structSize);
            type = *(BYTE*)p;
            structSize = *(BYTE*)((QWORD)p + 1);
        }

        acpiStatus = AcpiGetTable("DMAR", 0, (ACPI_TABLE_HEADER**)&dmar);
        if (!ACPI_SUCCESS(acpiStatus))
        {
            HvPrint("[ERROR] : AcpiGetTable for DMAR failed, acpiStatus = 0x%x\n", acpiStatus);
            return FALSE;
        }

        HvPrint("yupiii....\n");
//*/

        return TRUE;
    }
}
