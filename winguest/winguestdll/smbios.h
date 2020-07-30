/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SMBIOS_H_
#define _SMBIOS_H_

//
// SmBios structures in registry
// http://wiki.osdev.org/System_Management_BIOS
//
#pragma pack(push, 1)
typedef struct _SMBIOS_WIN_ENTRY_POINT{
    BYTE        Used20CallingMethod;
    BYTE        SMBIOSMajorVersion;
    BYTE        SMBIOSMinorVersion;
    BYTE        DmiRevision;
    DWORD       Length;
    BYTE        SMBIOSTableData[1];
} SMBIOS_WIN_ENTRY_POINT, *PSMBIOS_WIN_ENTRY_POINT;

typedef struct _SMBIOS_STRUCTURE{
    UINT8   Type;
    UINT8   Length;
    UINT16  Handle;
} SMBIOS_STRUCTURE, *PSMBIOS_STRUCTURE;

typedef BYTE SMBIOS_TABLE_STRING;

typedef struct {
    DWORD  Reserved                          :2;  ///< Bits 0-1.
    DWORD  Unknown                           :1;
    DWORD  BiosCharacteristicsNotSupported   :1;
    DWORD  IsaIsSupported                    :1;
    DWORD  McaIsSupported                    :1;
    DWORD  EisaIsSupported                   :1;
    DWORD  PciIsSupported                    :1;
    DWORD  PcmciaIsSupported                 :1;
    DWORD  PlugAndPlayIsSupported            :1;
    DWORD  ApmIsSupported                    :1;
    DWORD  BiosIsUpgradable                  :1;
    DWORD  BiosShadowingAllowed              :1;
    DWORD  VlVesaIsSupported                 :1;
    DWORD  EscdSupportIsAvailable            :1;
    DWORD  BootFromCdIsSupported             :1;
    DWORD  SelectableBootIsSupported         :1;
    DWORD  RomBiosIsSocketed                 :1;
    DWORD  BootFromPcmciaIsSupported         :1;
    DWORD  EDDSpecificationIsSupported       :1;
    DWORD  JapaneseNecFloppyIsSupported      :1;
    DWORD  JapaneseToshibaFloppyIsSupported  :1;
    DWORD  Floppy525_360IsSupported          :1;
    DWORD  Floppy525_12IsSupported           :1;
    DWORD  Floppy35_720IsSupported           :1;
    DWORD  Floppy35_288IsSupported           :1;
    DWORD  PrintScreenIsSupported            :1;
    DWORD  Keyboard8042IsSupported           :1;
    DWORD  SerialIsSupported                 :1;
    DWORD  PrinterIsSupported                :1;
    DWORD  CgaMonoIsSupported                :1;
    DWORD  NecPc98                           :1;
    DWORD  ReservedForVendor                 :32; ///< Bits 32-63. Bits 32-47 reserved for BIOS vendor
    ///< and bits 48-63 reserved for System Vendor.
} MISC_BIOS_CHARACTERISTICS;

typedef struct _SMBIOS_TABLE_TYPE0{
    SMBIOS_STRUCTURE          Hdr;
    SMBIOS_TABLE_STRING       Vendor;
    SMBIOS_TABLE_STRING       BiosVersion;
    WORD                      BiosSegment;
    SMBIOS_TABLE_STRING       BiosReleaseDate;
    BYTE                      BiosSize;
    MISC_BIOS_CHARACTERISTICS BiosCharacteristics;
    BYTE                      BIOSCharacteristicsExtensionBytes[2];
    BYTE                      SystemBiosMajorRelease;
    BYTE                      SystemBiosMinorRelease;
    BYTE                      EmbeddedControllerFirmwareMajorRelease;
    BYTE                      EmbeddedControllerFirmwareMinorRelease;
    BYTE                      Buffer[0];
} SMBIOS_TABLE_TYPE0, *PSMBIOS_TABLE_TYPE0;

typedef struct _SMBIOS_TABLE_TYPE1{
    SMBIOS_STRUCTURE        Hdr;
    SMBIOS_TABLE_STRING     Manufacturer;
    SMBIOS_TABLE_STRING     ProductName;
    SMBIOS_TABLE_STRING     Version;
    SMBIOS_TABLE_STRING     SerialNumber;
    BYTE                    Uuid[16];
    BYTE                    WakeUpType;           ///< The enumeration value from MISC_SYSTEM_WAKEUP_TYPE.
    SMBIOS_TABLE_STRING     SKUNumber;
    SMBIOS_TABLE_STRING     Family;
    BYTE                    Buffer[0];
} SMBIOS_TABLE_TYPE1, *PSMBIOS_TABLE_TYPE1;

typedef struct {
    BYTE  Motherboard           :1;
    BYTE  RequiresDaughterCard  :1;
    BYTE  Removable             :1;
    BYTE  Replaceable           :1;
    BYTE  HotSwappable          :1;
    BYTE  Reserved              :3;
} BASE_BOARD_FEATURE_FLAGS;

typedef struct _SMBIOS_TABLE_TYPE2{
    SMBIOS_STRUCTURE          Hdr;
    SMBIOS_TABLE_STRING       Manufacturer;
    SMBIOS_TABLE_STRING       ProductName;
    SMBIOS_TABLE_STRING       Version;
    SMBIOS_TABLE_STRING       SerialNumber;
    SMBIOS_TABLE_STRING       AssetTag;
    BASE_BOARD_FEATURE_FLAGS  FeatureFlag;
    SMBIOS_TABLE_STRING       LocationInChassis;
    WORD                      ChassisHandle;
    BYTE                      BoardType;              ///< The enumeration value from BASE_BOARD_TYPE.
    BYTE                      NumberOfContainedObjectHandles;
    WORD                      ContainedObjectHandles[0];
} SMBIOS_TABLE_TYPE2, *PSMBIOS_TABLE_TYPE2;

typedef struct {
    UINT8                 ContainedElementType;
    UINT8                 ContainedElementMinimum;
    UINT8                 ContainedElementMaximum;
} CONTAINED_ELEMENT;

typedef struct {
    SMBIOS_STRUCTURE            Hdr;
    SMBIOS_TABLE_STRING         Manufacturer;
    UINT8                       Type;
    SMBIOS_TABLE_STRING         Version;
    SMBIOS_TABLE_STRING         SerialNumber;
    SMBIOS_TABLE_STRING         AssetTag;
    UINT8                       BootupState;            ///< The enumeration value from MISC_CHASSIS_STATE.
    UINT8                       PowerSupplyState;       ///< The enumeration value from MISC_CHASSIS_STATE.
    UINT8                       ThermalState;           ///< The enumeration value from MISC_CHASSIS_STATE.
    UINT8                       SecurityStatus;         ///< The enumeration value from MISC_CHASSIS_SECURITY_STATE.
    UINT8                       OemDefined[4];
    UINT8                       Height;
    UINT8                       NumberofPowerCords;
    UINT8                       ContainedElementCount;
    UINT8                       ContainedElementRecordLength;
    CONTAINED_ELEMENT           ContainedElements[1];
} SMBIOS_TABLE_TYPE3, *PSMBIOS_TABLE_TYPE3;

typedef enum {
    ProcessorOther   = 0x01,
    ProcessorUnknown = 0x02,
    CentralProcessor = 0x03,
    MathProcessor    = 0x04,
    DspProcessor     = 0x05,
    VideoProcessor   = 0x06
} PROCESSOR_TYPE_DATA;

///
/// Processor Information - Processor Family.
///
typedef enum {
    ProcessorFamilyOther                  = 0x01,
    ProcessorFamilyUnknown                = 0x02,
    ProcessorFamily8086                   = 0x03,
    ProcessorFamily80286                  = 0x04,
    ProcessorFamilyIntel386               = 0x05,
    ProcessorFamilyIntel486               = 0x06,
    ProcessorFamily8087                   = 0x07,
    ProcessorFamily80287                  = 0x08,
    ProcessorFamily80387                  = 0x09,
    ProcessorFamily80487                  = 0x0A,
    ProcessorFamilyPentium                = 0x0B,
    ProcessorFamilyPentiumPro             = 0x0C,
    ProcessorFamilyPentiumII              = 0x0D,
    ProcessorFamilyPentiumMMX             = 0x0E,
    ProcessorFamilyCeleron                = 0x0F,
    ProcessorFamilyPentiumIIXeon          = 0x10,
    ProcessorFamilyPentiumIII             = 0x11,
    ProcessorFamilyM1                     = 0x12,
    ProcessorFamilyM2                     = 0x13,
    ProcessorFamilyIntelCeleronM          = 0x14,
    ProcessorFamilyIntelPentium4Ht        = 0x15,
    ProcessorFamilyAmdDuron               = 0x18,
    ProcessorFamilyK5                     = 0x19,
    ProcessorFamilyK6                     = 0x1A,
    ProcessorFamilyK6_2                   = 0x1B,
    ProcessorFamilyK6_3                   = 0x1C,
    ProcessorFamilyAmdAthlon              = 0x1D,
    ProcessorFamilyAmd29000               = 0x1E,
    ProcessorFamilyK6_2Plus               = 0x1F,
    ProcessorFamilyPowerPC                = 0x20,
    ProcessorFamilyPowerPC601             = 0x21,
    ProcessorFamilyPowerPC603             = 0x22,
    ProcessorFamilyPowerPC603Plus         = 0x23,
    ProcessorFamilyPowerPC604             = 0x24,
    ProcessorFamilyPowerPC620             = 0x25,
    ProcessorFamilyPowerPCx704            = 0x26,
    ProcessorFamilyPowerPC750             = 0x27,
    ProcessorFamilyIntelCoreDuo           = 0x28,
    ProcessorFamilyIntelCoreDuoMobile     = 0x29,
    ProcessorFamilyIntelCoreSoloMobile    = 0x2A,
    ProcessorFamilyIntelAtom              = 0x2B,
    ProcessorFamilyAlpha3                 = 0x30,
    ProcessorFamilyAlpha21064             = 0x31,
    ProcessorFamilyAlpha21066             = 0x32,
    ProcessorFamilyAlpha21164             = 0x33,
    ProcessorFamilyAlpha21164PC           = 0x34,
    ProcessorFamilyAlpha21164a            = 0x35,
    ProcessorFamilyAlpha21264             = 0x36,
    ProcessorFamilyAlpha21364             = 0x37,
    ProcessorFamilyAmdTurionIIUltraDualCoreMobileM    = 0x38,
    ProcessorFamilyAmdTurionIIDualCoreMobileM         = 0x39,
    ProcessorFamilyAmdAthlonIIDualCoreM   = 0x3A,
    ProcessorFamilyAmdOpteron6100Series   = 0x3B,
    ProcessorFamilyAmdOpteron4100Series   = 0x3C,
    ProcessorFamilyAmdOpteron6200Series   = 0x3D,
    ProcessorFamilyAmdOpteron4200Series   = 0x3E,
    ProcessorFamilyMips                   = 0x40,
    ProcessorFamilyMIPSR4000              = 0x41,
    ProcessorFamilyMIPSR4200              = 0x42,
    ProcessorFamilyMIPSR4400              = 0x43,
    ProcessorFamilyMIPSR4600              = 0x44,
    ProcessorFamilyMIPSR10000             = 0x45,
    ProcessorFamilyAmdCSeries             = 0x46,
    ProcessorFamilyAmdESeries             = 0x47,
    ProcessorFamilyAmdSSeries             = 0x48,
    ProcessorFamilyAmdGSeries             = 0x49,
    ProcessorFamilySparc                  = 0x50,
    ProcessorFamilySuperSparc             = 0x51,
    ProcessorFamilymicroSparcII           = 0x52,
    ProcessorFamilymicroSparcIIep         = 0x53,
    ProcessorFamilyUltraSparc             = 0x54,
    ProcessorFamilyUltraSparcII           = 0x55,
    ProcessorFamilyUltraSparcIIi          = 0x56,
    ProcessorFamilyUltraSparcIII          = 0x57,
    ProcessorFamilyUltraSparcIIIi         = 0x58,
    ProcessorFamily68040                  = 0x60,
    ProcessorFamily68xxx                  = 0x61,
    ProcessorFamily68000                  = 0x62,
    ProcessorFamily68010                  = 0x63,
    ProcessorFamily68020                  = 0x64,
    ProcessorFamily68030                  = 0x65,
    ProcessorFamilyHobbit                 = 0x70,
    ProcessorFamilyCrusoeTM5000           = 0x78,
    ProcessorFamilyCrusoeTM3000           = 0x79,
    ProcessorFamilyEfficeonTM8000         = 0x7A,
    ProcessorFamilyWeitek                 = 0x80,
    ProcessorFamilyItanium                = 0x82,
    ProcessorFamilyAmdAthlon64            = 0x83,
    ProcessorFamilyAmdOpteron             = 0x84,
    ProcessorFamilyAmdSempron             = 0x85,
    ProcessorFamilyAmdTurion64Mobile      = 0x86,
    ProcessorFamilyDualCoreAmdOpteron     = 0x87,
    ProcessorFamilyAmdAthlon64X2DualCore  = 0x88,
    ProcessorFamilyAmdTurion64X2Mobile    = 0x89,
    ProcessorFamilyQuadCoreAmdOpteron     = 0x8A,
    ProcessorFamilyThirdGenerationAmdOpteron = 0x8B,
    ProcessorFamilyAmdPhenomFxQuadCore    = 0x8C,
    ProcessorFamilyAmdPhenomX4QuadCore    = 0x8D,
    ProcessorFamilyAmdPhenomX2DualCore    = 0x8E,
    ProcessorFamilyAmdAthlonX2DualCore    = 0x8F,
    ProcessorFamilyPARISC                 = 0x90,
    ProcessorFamilyPaRisc8500             = 0x91,
    ProcessorFamilyPaRisc8000             = 0x92,
    ProcessorFamilyPaRisc7300LC           = 0x93,
    ProcessorFamilyPaRisc7200             = 0x94,
    ProcessorFamilyPaRisc7100LC           = 0x95,
    ProcessorFamilyPaRisc7100             = 0x96,
    ProcessorFamilyV30                    = 0xA0,
    ProcessorFamilyQuadCoreIntelXeon3200Series  = 0xA1,
    ProcessorFamilyDualCoreIntelXeon3000Series  = 0xA2,
    ProcessorFamilyQuadCoreIntelXeon5300Series  = 0xA3,
    ProcessorFamilyDualCoreIntelXeon5100Series  = 0xA4,
    ProcessorFamilyDualCoreIntelXeon5000Series  = 0xA5,
    ProcessorFamilyDualCoreIntelXeonLV          = 0xA6,
    ProcessorFamilyDualCoreIntelXeonULV         = 0xA7,
    ProcessorFamilyDualCoreIntelXeon7100Series  = 0xA8,
    ProcessorFamilyQuadCoreIntelXeon5400Series  = 0xA9,
    ProcessorFamilyQuadCoreIntelXeon            = 0xAA,
    ProcessorFamilyDualCoreIntelXeon5200Series  = 0xAB,
    ProcessorFamilyDualCoreIntelXeon7200Series  = 0xAC,
    ProcessorFamilyQuadCoreIntelXeon7300Series  = 0xAD,
    ProcessorFamilyQuadCoreIntelXeon7400Series  = 0xAE,
    ProcessorFamilyMultiCoreIntelXeon7400Series = 0xAF,
    ProcessorFamilyPentiumIIIXeon         = 0xB0,
    ProcessorFamilyPentiumIIISpeedStep    = 0xB1,
    ProcessorFamilyPentium4               = 0xB2,
    ProcessorFamilyIntelXeon              = 0xB3,
    ProcessorFamilyAS400                  = 0xB4,
    ProcessorFamilyIntelXeonMP            = 0xB5,
    ProcessorFamilyAMDAthlonXP            = 0xB6,
    ProcessorFamilyAMDAthlonMP            = 0xB7,
    ProcessorFamilyIntelItanium2          = 0xB8,
    ProcessorFamilyIntelPentiumM          = 0xB9,
    ProcessorFamilyIntelCeleronD          = 0xBA,
    ProcessorFamilyIntelPentiumD          = 0xBB,
    ProcessorFamilyIntelPentiumEx         = 0xBC,
    ProcessorFamilyIntelCoreSolo          = 0xBD,  ///< SMBIOS spec 2.6 correct this value
    ProcessorFamilyReserved               = 0xBE,
    ProcessorFamilyIntelCore2             = 0xBF,
    ProcessorFamilyIntelCore2Solo         = 0xC0,
    ProcessorFamilyIntelCore2Extreme      = 0xC1,
    ProcessorFamilyIntelCore2Quad         = 0xC2,
    ProcessorFamilyIntelCore2ExtremeMobile = 0xC3,
    ProcessorFamilyIntelCore2DuoMobile    = 0xC4,
    ProcessorFamilyIntelCore2SoloMobile   = 0xC5,
    ProcessorFamilyIntelCoreI7            = 0xC6,
    ProcessorFamilyDualCoreIntelCeleron   = 0xC7,
    ProcessorFamilyIBM390                 = 0xC8,
    ProcessorFamilyG4                     = 0xC9,
    ProcessorFamilyG5                     = 0xCA,
    ProcessorFamilyG6                     = 0xCB,
    ProcessorFamilyzArchitectur           = 0xCC,
    ProcessorFamilyIntelCoreI5            = 0xCD,
    ProcessorFamilyIntelCoreI3            = 0xCE,
    ProcessorFamilyViaC7M                 = 0xD2,
    ProcessorFamilyViaC7D                 = 0xD3,
    ProcessorFamilyViaC7                  = 0xD4,
    ProcessorFamilyViaEden                = 0xD5,
    ProcessorFamilyMultiCoreIntelXeon           = 0xD6,
    ProcessorFamilyDualCoreIntelXeon3Series     = 0xD7,
    ProcessorFamilyQuadCoreIntelXeon3Series     = 0xD8,
    ProcessorFamilyViaNano                      = 0xD9,
    ProcessorFamilyDualCoreIntelXeon5Series     = 0xDA,
    ProcessorFamilyQuadCoreIntelXeon5Series     = 0xDB,
    ProcessorFamilyDualCoreIntelXeon7Series     = 0xDD,
    ProcessorFamilyQuadCoreIntelXeon7Series     = 0xDE,
    ProcessorFamilyMultiCoreIntelXeon7Series    = 0xDF,
    ProcessorFamilyMultiCoreIntelXeon3400Series = 0xE0,
    ProcessorFamilyEmbeddedAmdOpteronQuadCore   = 0xE6,
    ProcessorFamilyAmdPhenomTripleCore          = 0xE7,
    ProcessorFamilyAmdTurionUltraDualCoreMobile = 0xE8,
    ProcessorFamilyAmdTurionDualCoreMobile      = 0xE9,
    ProcessorFamilyAmdAthlonDualCore            = 0xEA,
    ProcessorFamilyAmdSempronSI                 = 0xEB,
    ProcessorFamilyAmdPhenomII                  = 0xEC,
    ProcessorFamilyAmdAthlonII                  = 0xED,
    ProcessorFamilySixCoreAmdOpteron            = 0xEE,
    ProcessorFamilyAmdSempronM                  = 0xEF,
    ProcessorFamilyi860                   = 0xFA,
    ProcessorFamilyi960                   = 0xFB,
    ProcessorFamilyIndicatorFamily2       = 0xFE,
    ProcessorFamilyReserved1              = 0xFF
} PROCESSOR_FAMILY_DATA;

///
/// Processor Information2 - Processor Family2.
///
typedef enum {
    ProcessorFamilySH3                   = 0x0104,
    ProcessorFamilySH4                   = 0x0105,
    ProcessorFamilyARM                   = 0x0118,
    ProcessorFamilyStrongARM             = 0x0119,
    ProcessorFamily6x86                  = 0x012C,
    ProcessorFamilyMediaGX               = 0x012D,
    ProcessorFamilyMII                   = 0x012E,
    ProcessorFamilyWinChip               = 0x0140,
    ProcessorFamilyDSP                   = 0x015E,
    ProcessorFamilyVideoProcessor        = 0x01F4
} PROCESSOR_FAMILY2_DATA;

///
/// Processor Information - Voltage.
///
typedef struct {
    UINT8  ProcessorVoltageCapability5V        :1;
    UINT8  ProcessorVoltageCapability3_3V      :1;
    UINT8  ProcessorVoltageCapability2_9V      :1;
    UINT8  ProcessorVoltageCapabilityReserved  :1; ///< Bit 3, must be zero.
    UINT8  ProcessorVoltageReserved            :3; ///< Bits 4-6, must be zero.
    UINT8  ProcessorVoltageIndicateLegacy      :1;
} PROCESSOR_VOLTAGE;

///
/// Processor Information - Processor Upgrade.
///
typedef enum {
    ProcessorUpgradeOther         = 0x01,
    ProcessorUpgradeUnknown       = 0x02,
    ProcessorUpgradeDaughterBoard = 0x03,
    ProcessorUpgradeZIFSocket     = 0x04,
    ProcessorUpgradePiggyBack     = 0x05, ///< Replaceable.
    ProcessorUpgradeNone          = 0x06,
    ProcessorUpgradeLIFSocket     = 0x07,
    ProcessorUpgradeSlot1         = 0x08,
    ProcessorUpgradeSlot2         = 0x09,
    ProcessorUpgrade370PinSocket  = 0x0A,
    ProcessorUpgradeSlotA         = 0x0B,
    ProcessorUpgradeSlotM         = 0x0C,
    ProcessorUpgradeSocket423     = 0x0D,
    ProcessorUpgradeSocketA       = 0x0E, ///< Socket 462.
    ProcessorUpgradeSocket478     = 0x0F,
    ProcessorUpgradeSocket754     = 0x10,
    ProcessorUpgradeSocket940     = 0x11,
    ProcessorUpgradeSocket939     = 0x12,
    ProcessorUpgradeSocketmPGA604 = 0x13,
    ProcessorUpgradeSocketLGA771  = 0x14,
    ProcessorUpgradeSocketLGA775  = 0x15,
    ProcessorUpgradeSocketS1      = 0x16,
    ProcessorUpgradeAM2           = 0x17,
    ProcessorUpgradeF1207         = 0x18,
    ProcessorSocketLGA1366        = 0x19,
    ProcessorUpgradeSocketG34     = 0x1A,
    ProcessorUpgradeSocketAM3     = 0x1B,
    ProcessorUpgradeSocketC32     = 0x1C,
    ProcessorUpgradeSocketLGA1156 = 0x1D,
    ProcessorUpgradeSocketLGA1567 = 0x1E,
    ProcessorUpgradeSocketPGA988A = 0x1F,
    ProcessorUpgradeSocketBGA1288 = 0x20,
    ProcessorUpgradeSocketrPGA988B = 0x21,
    ProcessorUpgradeSocketBGA1023 = 0x22,
    ProcessorUpgradeSocketBGA1224 = 0x23,
    ProcessorUpgradeSocketBGA1155 = 0x24,
    ProcessorUpgradeSocketLGA1356 = 0x25,
    ProcessorUpgradeSocketLGA2011 = 0x26,
    ProcessorUpgradeSocketFS1     = 0x27,
    ProcessorUpgradeSocketFS2     = 0x28,
    ProcessorUpgradeSocketFM1     = 0x29,
    ProcessorUpgradeSocketFM2     = 0x2A
} PROCESSOR_UPGRADE;

///
/// Processor ID Field Description
///
typedef struct {
    UINT32  ProcessorSteppingId:4;
    UINT32  ProcessorModel:     4;
    UINT32  ProcessorFamily:    4;
    UINT32  ProcessorType:      2;
    UINT32  ProcessorReserved1: 2;
    UINT32  ProcessorXModel:    4;
    UINT32  ProcessorXFamily:   8;
    UINT32  ProcessorReserved2: 4;
} PROCESSOR_SIGNATURE;

typedef struct {
    UINT32  ProcessorFpu       :1;
    UINT32  ProcessorVme       :1;
    UINT32  ProcessorDe        :1;
    UINT32  ProcessorPse       :1;
    UINT32  ProcessorTsc       :1;
    UINT32  ProcessorMsr       :1;
    UINT32  ProcessorPae       :1;
    UINT32  ProcessorMce       :1;
    UINT32  ProcessorCx8       :1;
    UINT32  ProcessorApic      :1;
    UINT32  ProcessorReserved1 :1;
    UINT32  ProcessorSep       :1;
    UINT32  ProcessorMtrr      :1;
    UINT32  ProcessorPge       :1;
    UINT32  ProcessorMca       :1;
    UINT32  ProcessorCmov      :1;
    UINT32  ProcessorPat       :1;
    UINT32  ProcessorPse36     :1;
    UINT32  ProcessorPsn       :1;
    UINT32  ProcessorClfsh     :1;
    UINT32  ProcessorReserved2 :1;
    UINT32  ProcessorDs        :1;
    UINT32  ProcessorAcpi      :1;
    UINT32  ProcessorMmx       :1;
    UINT32  ProcessorFxsr      :1;
    UINT32  ProcessorSse       :1;
    UINT32  ProcessorSse2      :1;
    UINT32  ProcessorSs        :1;
    UINT32  ProcessorReserved3 :1;
    UINT32  ProcessorTm        :1;
    UINT32  ProcessorReserved4 :2;
} PROCESSOR_FEATURE_FLAGS;

typedef struct {
    PROCESSOR_SIGNATURE     Signature;
    DWORD                   FeatureFlags; /// < PROCESSOR_FEATURE_FLAGS
} PROCESSOR_ID_DATA;

typedef struct {
    SMBIOS_STRUCTURE      Hdr;
    SMBIOS_TABLE_STRING   Socket;
    UINT8                 ProcessorType;          ///< The enumeration value from PROCESSOR_TYPE_DATA.
    UINT8                 ProcessorFamily;        ///< The enumeration value from PROCESSOR_FAMILY_DATA.
    SMBIOS_TABLE_STRING   ProcessorManufacture;
    PROCESSOR_ID_DATA     ProcessorId;
    SMBIOS_TABLE_STRING   ProcessorVersion;
    PROCESSOR_VOLTAGE     Voltage;
    UINT16                ExternalClock;
    UINT16                MaxSpeed;
    UINT16                CurrentSpeed;
    UINT8                 Status;
    UINT8                 ProcessorUpgrade;      ///< The enumeration value from PROCESSOR_UPGRADE.
    UINT16                L1CacheHandle;
    UINT16                L2CacheHandle;
    UINT16                L3CacheHandle;
    SMBIOS_TABLE_STRING   SerialNumber;
    SMBIOS_TABLE_STRING   AssetTag;
    SMBIOS_TABLE_STRING   PartNumber;
    //
    // Add for smbios 2.5
    //
    UINT8                 CoreCount;
    UINT8                 EnabledCoreCount;
    UINT8                 ThreadCount;
    UINT16                ProcessorCharacteristics;
    //
    // Add for smbios 2.6
    //
    UINT16                ProcessorFamily2;
} SMBIOS_TABLE_TYPE4;

typedef union {
    SMBIOS_STRUCTURE      Hdr;
    SMBIOS_TABLE_TYPE0    Type0;
    SMBIOS_TABLE_TYPE1    Type1;
    SMBIOS_TABLE_TYPE2    Type2;
    SMBIOS_TABLE_TYPE3    Type3;
    SMBIOS_TABLE_TYPE4    Type4;
    BYTE                  Raw[0];
} SMBIOS_STRUCTURE_POINTER, *PSMBIOS_STRUCTURE_POINTER;

#pragma pack(pop)

SMBIOS_STRUCTURE_POINTER const*
SmbiosGetTableFromType(
    BYTE const* RawTables,
    SIZE_T Size,
    BYTE   Type,
    DWORD  Index
);

std::string
SmbiosGetString(
    _In_ SMBIOS_STRUCTURE_POINTER const *SmbiosTable,
    _In_ SMBIOS_TABLE_STRING       String
);

#endif // _SMBIOS_H_
