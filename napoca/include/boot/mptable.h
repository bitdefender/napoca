/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _MP_TABLE_H_
#define _MP_TABLE_H_

#include "kernel/kernel.h"
#include "guests/devices.h"

#pragma pack(push)
#pragma pack(1)

//
// Intel MP 1.4 specific structures
//

typedef struct _MP_FLOAT {
    DWORD         Signature;      // "_MP_"
    DWORD         MpConfigPtr;
    BYTE          Length;
    BYTE          Revision;       // 0x04 ==> Intel MP Specification 1.4
    BYTE          Checksum;
    BYTE          MpSystemType;   // 0x00 ==> valid config table present
    BYTE          Feat2;          // 0x80 ==> IMCR register present
    BYTE          Feat3;
    BYTE          Feat4;
    BYTE          Feat5;
} MP_FLOAT, *PMP_FLOAT;

typedef struct _MP_CONFIG_TABLE {

    DWORD         Signature;      // "PCMP"     // offset 0
    WORD          Length;                       // offset 4
    BYTE          Revision;                     // offset 6
    BYTE          Checksum;                     // offset 7
    CHAR          Oem[8];                       // offset 8
    CHAR          Product[12];                  // offset 16
    DWORD         OemPtr;                       // offset 28
    WORD          OemSize;                      // offset 32
    WORD          EntryCount;                   // offset 34
    DWORD         LocalApicBase;                // offset 36
    WORD          ExtendedTableLength;          // offset 40
    BYTE          ExtendedTableChecksum;        // offset 42

    BYTE          Reserved;                     // offset 43, for alignment

} MP_CONFIG_TABLE, *PMP_CONFIG_TABLE;

typedef struct _MP_CPU_ENTRY {
    BYTE          EntryType;
    BYTE          ApicId;
    BYTE          ApicVer;
    BYTE          CpuFlags;       // 0x01 - enabled, 0x02 - BSP
    DWORD         CpuSignature;
    DWORD         CpuFeats;
    QWORD         Reserved;
} MP_CPU_ENTRY, *PMP_CPU_ENTRY;

typedef struct _MP_BUS_ENTRY
{
    BYTE        EntryType;
    BYTE        BusId;
    BYTE        BusTypeString[6];
} MP_BUS_ENTRY, *PMP_BUS_ENTRY;

typedef struct _MP_IO_APIC_ENTRY {
    BYTE          EntryType;
    BYTE          ApicId;
    BYTE          ApicVer;
    BYTE          ApicFlags;
    DWORD         BaseAddress;
} MP_IOAPIC_ENTRY, *PMP_IOAPIC_ENTRY;

typedef struct _MP_IO_ENTRY{
    BYTE          EntryType;
    BYTE          IntType;
    union {
        WORD          Flags;
        struct {
            WORD      PO : 2;
            WORD      EL : 2;
            WORD      RES : 12;
        };
    };
    BYTE          SrcBusId;
    union {
        BYTE          SrcBusIrq;
        struct {
            BYTE IntLine   : 2; // 0-2
            BYTE DevNumber : 5; // 2-5
            BYTE Reserved  : 1; // 5-7
        };
    };
    BYTE          DestIoApicId;
    BYTE          DestIoApicInt;
} MP_IO_INT_ENTRY, *PMP_IO_INT_ENTRY;

typedef struct _MP_LOCAL_INT_ENTRY{
    BYTE          EntryType;
    BYTE          IntType;
    WORD          Flags;
    BYTE          SrcBusId;
    BYTE          SrcBusIrq;
    BYTE          DestLocalApicId;
    BYTE          DestLocalApicInt;
} MP_LOCAL_INT_ENTRY, *PMP_LOCAL_INT_ENTRY;

//typedef struct _MP_EXT_ENTRY_HEADER{
//    BYTE EntryType;
//    BYTE EntryLength;
//}MP_EXT_ENTRY_HEADER, *PMP_EXT_ENTRY_HEADER;

#pragma pack(pop)


NTSTATUS
InitHostMpTable(
    );


NTSTATUS
MpTableMapToGuest(
    _In_ PGUEST Guest
    );


NTSTATUS
MpTableScanAndAddGuestNewEntries(
    _In_ PGUEST Guest
    );


NTSTATUS
MpTableFindFreeBus(
    _Inout_ PBYTE BusNumber
    );


VOID
MpDumpTable(
    _In_ PMP_CONFIG_TABLE MPConfigTable
    );

#endif //_MP_TABLE_H_
