/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _LOADER_INTERFACE_H_
#define _LOADER_INTERFACE_H_

#include "cx_native.h"
#include "base/cx_intrin.h"
#include "sal.h"

/** @name Pointer size handling
 *  @brief Definitions that help us maintain the size of a pointer at 8 bytes
 *  even if it is built on 32 bits (a 4-byte dummy is added then).
 */
///@{
#ifdef CX_ARCH64
#define LD_POINTER_MEMBER(TYPE, NAME) TYPE *NAME
#define LD_POINTER_VALUE(PTR) PTR

#define LD_FUNC_MEMBER(TYPE, NAME) TYPE NAME
#define LD_FUNC_VALUE(PTR) PTR

#else

#define LD_POINTER_MEMBER(TYPE, NAME) TYPE *NAME; CX_UINT32 NAME ## HighPart
#define LD_POINTER_VALUE(PTR) PTR, 0

#define LD_FUNC_MEMBER(TYPE, NAME) TYPE NAME; CX_UINT32 NAME ## HighPart
#define LD_FUNC_VALUE(PTR) PTR, 0
#endif
///@}

/// @brief Signals wakeup from S3 power transition
#define BOOT_MODE_FLAG_ACPI_S3_WAKEUP       0x1

/// @brief E820 memory types, conform http://www.acpi.info/DOWNLOADS/ACPIspec40a.pdf, Table 14-1, "Address Range Types"
///
/// NOTE: any type changes MUST BE REFLECTED to the conversion functions in loader_interface.c!
///
typedef enum
{
    E820_TYPE_INVALID                       = 0,
    E820_TYPE_MEMORY                        = 1,    ///< "This range is available RAM usable by the operating system"
    E820_TYPE_RESERVED                      = 2,    ///< "This range of addresses is in use or reserved by the system and is not to be included in the allocatable memory pool of the operating system's memory manager."
    E820_TYPE_ACPI                          = 3,    ///< "ACPI Reclaim Memory. This range is available RAM usable by the OS after it reads the ACPI tables."
    E820_TYPE_NVS                           = 4,    ///< "ACPI NVS Memory. This range of addresses is in use or reserve by the system and must not be used by the operating system.This rangeis required to be saved and restored across an NVS sleep"
    E820_TYPE_UNUSABLE                      = 5,    ///< "This range of addresses contains memory in which errors have been detected.This range must not be used by OSPM."
    E820_TYPE_DISABLED                      = 6,    ///< "This range of addresses contains memory that is not enabled. This range must not be used by OSPM."
    E820_TYPE_RESERVED_ANY_ABOVE            = 7,    ///< "Undefined. Reserved for future use. OSPM must treat any range of this type as if the type returned was AddressRangeReserved"
}LD_E820_MEM_TYPE;

/// @brief EFI memory types defined in Unified Extensible Firmware Interface Specification (Version 2.6)
///
/// NOTE: any type changes MUST BE REFLECTED to the conversion functions in loader_interface.c!
///
typedef enum
{
    EFI_RESERVED_MEMORY_TYPE,                       ///< "Not used."
    EFI_LOADER_CODE,                                ///< The code portions of a loaded application. (Note that UEFI OS loaders are UEFI applications.)
    EFI_LOADER_DATA,                                ///< The data portions of a loaded application and the default data allocation type used by an application to allocate pool memory.
    EFI_BOOT_SERVICES_CODE,                         ///< The code portions of a loaded Boot Services Driver.
    EFI_BOOT_SERVICES_DATA,                         ///< The data portions of a loaded Boot Serves Driver, and the default data allocation type used by a Boot Services Driver to allocate pool memory.
    EFI_RUNTIME_SERVICES_CODE,                      ///< The code portions of a loaded Runtime Services Driver.
    EFI_RUNTIME_SERVICES_DATA,                      ///< The data portions of a loaded Runtime Services Driver and the default data allocation type used by a Runtime Services Driver to allocate pool memory.
    EFI_CONVENTIONAL_MEMORY,                        ///< Free (unallocated) memory.
    EFI_UNUSABLE_MEMORY,                            ///< Memory in which errors have been detected.
    EFI_ACPIRECLAIM_MEMORY,                         ///< Memory that holds the ACPI tables.
    EFI_ACPIMEMORY_NVS,                             ///< Address space reserved for use by the firmware.
    EFI_MEMORY_MAPPED_IO,                           ///< Used by system firmware to request that a memory-mapped IO region be mapped by the OS to a virtual address so it can be accessed by EFI runtime services.
    EFI_MEMORY_MAPPED_IOPORT_SPACE,                 ///< System memory-mapped IO region that is used to translate memory cycles to IO cycles by the processor.
    EFI_PAL_CODE,                                   ///< Address space reserved by the firmware for code that is part of the processor.
    EFI_MAX_MEMORY_TYPE
}LD_EFI_MEM_TYPE;

/// @brief internal HV memory types
///
/// NOTE: any type changes MUST BE REFLECTED to the conversion functions in loader_interface.c!
///
typedef enum
{
    BOOT_MEM_TYPE_INVALID,
    BOOT_MEM_TYPE_AVAILABLE,
    BOOT_MEM_TYPE_RESERVED,
    BOOT_MEM_TYPE_ACPI,                             ///< "Memory that holds the ACPI tables"
    BOOT_MEM_TYPE_NVS,                              ///< "Address space reserved for use by the firmware"
    BOOT_MEM_TYPE_UNUSABLE,                         ///< "Memory in which errors have been detected"
    BOOT_MEM_TYPE_DISABLED,                         ///< "This range of addresses contains memory that is not enabled. This range must not be used by OSPM."
    BOOT_MEM_TYPE_MMIO,                             ///< "memory cycles to IO cycles by the processor"
    BOOT_MEM_TYPE_PAL_CODE,                         ///< "Address space reserved by the firmware for code that is part of the processor."
    BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED,         ///< area occupied by HV code/data, NOT to be mapped with EPT under guests
    BOOT_MEM_TYPE_RAM_HYPERVISOR_SHARED,            ///< area occupied by HV code/data, EPT mapped but not known (e820) to guests
    BOOT_MEM_TYPE_LAPIC,                            ///< used only for LAPIC pages
    BOOT_MEM_TYPE_MAX_VALUE,                        ///< end of valid list values
}LD_HV_MEM_TYPE;

/** @name Memory flags
 *
 */
///@{
#define BOOT_MEM_TYPE_HYPERVISOR_IN_USE     0x80    ///< already IN USE by the hypervisor (in contrast to 'reserved for hypervisor use')

#define BOOT_MEM_READ                       0x001
#define BOOT_MEM_WRITE                      0x002
#define BOOT_MEM_EXECUTE                    0x004
#define BOOT_MEM_READWRITE                  (BOOT_MEM_READ | BOOT_MEM_WRITE)
#define BOOT_MEM_RWX                        (BOOT_MEM_READ | BOOT_MEM_WRITE | BOOT_MEM_EXECUTE)
#define BOOT_MEM_READONLY                   (BOOT_MEM_READ | BOOT_MEM_EXECUTE)
#define BOOT_MEM_PRESENT                    0x007   // if all three bits (2:0) are 0, the entry is NOT present
#define BOOT_MEM_CACHE_UC                   0x000   // Uncacheable (UC), bit 5:3 = 0
#define BOOT_MEM_CACHE_WC                   0x008   // Write Combining (WC), bit 5:3 = 1
#define BOOT_MEM_CACHE_WT                   0x020   // Write Through (WT), bit 5:3 = 4
#define BOOT_MEM_CACHE_WP                   0x028   // Write Protected (WP), bit 5:3 = 5
#define BOOT_MEM_CACHE_WB                   0x030   // Write Back (WB), bit 5:3 = 6
#define BOOT_MEM_CACHE_MASK                 0x038   // bits 5:3
#define BOOT_MEM_CACHE_IGNORE               0x040   // conform 25.2.4.2
#define BOOT_MEM_RESERVED                   0x800
#define BOOT_MEM_CHAINED                    0x400
///@}

/// @brief Wraps in a union together the 3 types of memory (e820, Efi, Hv)
/// to have generic access to memory information any of them would be
typedef union _LD_MEM_TYPE
{
    LD_E820_MEM_TYPE    E820;
    LD_EFI_MEM_TYPE     Efi;
    LD_HV_MEM_TYPE      Hv;
    CX_UINT32           Raw;
}LD_MEM_TYPE;

#define UEFI_LOAD_CONTROL   L"BdHvLoadControl"
/// @brief Uefi load data
typedef struct _UEFI_LOAD_CONTROL_DATA
{
    CX_UINT32 FailCount : 4;    ///< Number of current attempts to boot
    CX_UINT32 Boot      : 1;    ///< A boot was currently attempted
    CX_UINT32 Crash     : 1;    ///< This is set at boot and cleared from user mode. If at boot we find this set then the last boot was not successful (UM component not loaded)
}UEFI_LOAD_CONTROL_DATA;

//
// Callbacks
//

/// @brief Callback to convert physical memory to virtual memory within the loader
typedef
CX_UINT64
(*PFUNC_PhysicalToVirtual)(
    _In_ CX_UINT64 PhysicalAddress,
    _In_opt_ void *Context
    );

/// @brief Callback to convert virtual memory to physical memory within the loader
typedef
CX_UINT64
(*PFUNC_VirtualToPhysical)(
    _In_ CX_UINT64 VirtualAddress,
    _In_opt_ void *Context
    );

/** @name Approximate the total HV memory allocation (including KZ)
 *
 */
///@{
#define NAPOCA_MEM_ESTIMATE_FIXED           (128 * CX_MEGA)
#define NAPOCA_MEM_ESTIMATE_PERCENT         2
#define NAPOCA_MEM_SHARED_BUFFER            (32 * CX_MEGA)      ///< shared buffer between hv and guests
///@}

#ifndef LD_LOG
#define LD_LOG
#endif
#define LD_LOG_FUNC_FAIL(FunctionName, Status)     LD_LOG("%s failed, status = 0x%X\n", FunctionName, Status)
#define LD_LOGN LD_LOG

#ifndef LD_UINT64_FMT
#define LD_UINT64_FMT "%018p"
#endif

#pragma pack(push, 1)
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

/// @brief Generic definition for a memory block sent by the loader, all memory regions should be defined as modules
typedef struct _LD_NAPOCA_MODULE
{
    CX_UINT64                   Va;     ///< Where is this region mapped in VA space
    CX_UINT64                   Pa;     ///< Where is the PA range
    CX_UINT32                   Size;   ///< Size in bytes
    CX_UINT32                   Flags;  ///< Generic information about the module
}
LD_NAPOCA_MODULE;

/// @brief a simple buffer (already mapped) used with an irreversible allocator (#LdAlloc)
typedef struct _LD_MEM_BUFFER
{
    CX_UINT64 Va;
    CX_UINT64 Pa;
    CX_UINT64 Length;
    CX_UINT64 NextFreeAddress;
} LD_MEM_BUFFER;

/// @brief The structure that maintains the information needed to map a memory area
typedef struct _LD_VA_MAPPER
{
    LD_POINTER_MEMBER(LD_NAPOCA_MODULE, Modules);                       ///< List of modules
    CX_UINT32                   NumberOfModules;                        ///< Number of modules
    LD_POINTER_MEMBER(LD_MEM_BUFFER, MemBuffer);                        ///< The internal structure used to hold information from where we can allocate new memory pages
    LD_FUNC_MEMBER(PFUNC_PhysicalToVirtual, CustomPhysicalToVirtual);   ///< Callback that converts a physical address to a virtual address
    LD_POINTER_MEMBER(void, CustomContextPhysicalToVirtual);            ///< Optional context that can be passed to the callback that converts a physical memory into virtual memory
    LD_FUNC_MEMBER(PFUNC_VirtualToPhysical, CustomVirtualToPhysical);   ///< Callback that converts a virtual address to a physical address
    LD_POINTER_MEMBER(void, CustomContextVirtualToPhysical);            ///< Optional context that can be passed to the callback that converts a virtual memory into physical memory
}LD_VA_MAPPER;

/// @brief structures defining the physical memory map (e820-like)
typedef struct _LD_MEM_MAP_ENTRY
{
    CX_UINT64                   BaseAddress;            ///< Base address of the memory entry
    CX_UINT64                   Length;                 ///< Length of the "region"
    LD_MEM_TYPE                 Type;                   ///< Detailed type interpretation (based on specific memory type)
    CX_UINT32                   Attributes;             ///< MEM_ATTR..
} LD_MEM_MAP_ENTRY;

/// @brief Used to differentiate between E820 memory or Efi memory
typedef enum {
    LD_MEMORY_MAP_TYPE_E820,
    LD_MEMORY_MAP_TYPE_EFI
}LD_MEMORY_MAP_TYPE;

/// @brief Memory map
typedef struct _LD_MEMORY_MAP
{
    LD_MEMORY_MAP_TYPE          MapType;            ///< Type of memory (E820, Efi)
    CX_UINT32                   NumberOfEntries;    ///< Number of memory entries
    LD_MEM_MAP_ENTRY            Entries[1];         ///< Array of memory entries.
} LD_MEMORY_MAP;

/// @brief How much memory does a map occupy for NumberOfEntries
#define LD_MEMORY_MAP_SIZE(NumberOfEntries) (sizeof(LD_MEMORY_MAP) + ((NumberOfEntries) - 1) * sizeof(LD_MEM_MAP_ENTRY))

/** @name Structures defining what memory the loader has already prepared for HV internal usage
 *  @brief The memory described inside the map IS NOT MAPPED by the loader
 */
///@{
/// @brief Entry of memory
typedef struct _MEM_MAP_ENTRY
{
    CX_UINT64           StartAddress;           ///< Start address
    CX_UINT64           Length;                 ///< Size of entry in bytes
    LD_HV_MEM_TYPE      Type;                   ///< Memory type converted from a generic LD_MEM_TYPE
    union
    {
        CX_UINT16       CacheAndRights;         ///< Cache and rights using EPT-like flags
        CX_UINT32       Attributes;             ///< MEM_ATTR..
    };
    union {
        CX_UINT64       _Reserved3;
        CX_UINT64       DestAddress;            ///< used for EPT dest mapping
    };
} LD_HVMEMORY_ENTRY, MEM_MAP_ENTRY;

/// @brief Hv memory map prepared by loader
typedef struct _LD_HVMEMORY_MAP
{
    CX_UINT32                   TotalNumberOfEntries;   ///< Number of memory entries. The loader must allocate enough entries to allow covering of all hv needs
    CX_UINT32                   HvZoneCount;            ///< Memory zones that will not be accessible to guests via E820 and EPT
    CX_UINT32                   GuestZoneCount;         ///< Memory zones that will be exposed to guests via E820 and EPT
    LD_HVMEMORY_ENTRY           Entries[1];             ///< Array of #LD_HVMEMORY_ENTRY entries
} LD_HVMEMORY_MAP, HV_MEM_MAP;
///@}

/// @brief How much memory does a hv map occupy for NumberOfEntries
#define LD_HVMEMORY_MAP_SIZE(NumberOfEntries) (sizeof(LD_HVMEMORY_MAP) + ((NumberOfEntries) - 1) * sizeof(LD_HVMEMORY_ENTRY))

/// @brief Structure sent to IniInit64
///
/// Note: THIS STRUCTURE MUST BE KEPT IN SYNC WITH THE DEFINITION USED BY OUR LOADERS
///
typedef struct _LD_BOOT_CONTEXT
{
    CX_UINT32                   BootMode;                                   ///< One of #BOOT_MODE
    CX_UINT32                   GuestArch;                                  ///< x86 or x64 guest
    LD_POINTER_MEMBER(LD_NAPOCA_MODULE, Modules);                           ///< NAPOCA_MODULE *Modules (below 4GB)
    CX_UINT64                   ModulesPa;                                  ///< Base PA of modules array
    CX_UINT32                   NumberOfModules;                            ///< Number of modules
    CX_UINT32                   NumberOfLoaderCpus;                         ///< how many ACTIVE CPUs were there at load time
    CX_UINT64                   OriginalStackTop;                           ///< Top of stack from loader. OPTIONAL, default 0
    CX_UINT64                   Cr3;                                        ///< Base PA of page tables root
    CX_UINT64                   Cr4;                                        ///< Snapshot of CR4 register from the loader
    CX_UINT64                   Cr0;                                        ///< Snapshot of CR0 register from the loader
    CX_UINT64                   Cr8;                                        ///< Snapshot of CR8 register from the loader
    CX_UINT16                   GdtLimit;                                   ///< GDT limit saved by the loader
    CX_UINT64                   GdtBase;                                    ///< GDT base address saved by the loader

    CX_UINT16                   IdtLimit;                                   ///< IDT limit saved by the loader
    CX_UINT64                   IdtBase;                                    ///< IDT base address saved by the loader

    CX_UINT64                   Rax;                                        ///< Snapshot of RAX register from the loader
    CX_UINT64                   Rbx;                                        ///< Snapshot of RBX register from the loader
    CX_UINT64                   Rcx;                                        ///< Snapshot of RCX register from the loader
    CX_UINT64                   Rdx;                                        ///< Snapshot of RDX register from the loader
    CX_UINT64                   Rsi;                                        ///< Snapshot of RSI register from the loader
    CX_UINT64                   Rdi;                                        ///< Snapshot of RDI register from the loader
    CX_UINT64                   Rbp;                                        ///< Snapshot of RBP register from the loader
    CX_UINT64                   Rsp;                                        ///< Snapshot of RSP register from the loader
    CX_UINT64                   R8;                                         ///< Snapshot of R8 register from the loader
    CX_UINT64                   R9;                                         ///< Snapshot of R9 register from the loader
    CX_UINT64                   R10;                                        ///< Snapshot of R10 register from the loader
    CX_UINT64                   R11;                                        ///< Snapshot of R11 register from the loader
    CX_UINT64                   R12;                                        ///< Snapshot of R12 register from the loader
    CX_UINT64                   R13;                                        ///< Snapshot of R13 register from the loader
    CX_UINT64                   R14;                                        ///< Snapshot of R14 register from the loader
    CX_UINT64                   R15;                                        ///< Snapshot of R15 register from the loader
    CX_UINT64                   RFlags;                                     ///< Snapshot of RFLAGS register from the loader
#pragma warning (suppress:4324)
    __declspec(align(16))   CX_UINT64 Align[2];
    // there's alignment to 16 bytes in asm (structure allocated on stack by boot loaders),
    // => incapsulate inside an aligned structure to simulate the alignment
} LD_BOOT_CONTEXT;

typedef struct _LD_CONFIGURATION_OPTIONS
{
    CX_UINT8                    RecoveryEnabled;    ///< Emergency recovery option. If set to true, the legacy loader will restore the MBR to the state before configuring the hypervisor (thus disabling it)
    CX_UINT8                    GrubBoot;           ///< Marks the fact that the hypervisor was booted via GRUB on a legacy configuration
}LD_CONFIGURATION_OPTIONS;

//
// LD_MODID_LOADER_CUSTOM structures (LD_LOADER_CUSTOM) for different boot loaders
//
typedef struct
{
    CX_UINT8 Part3;
    CX_UINT8 Part2;
    CX_UINT8 Part1;
    CX_UINT8 Drive;
}LD_MULTIBOOT_DEVICE;

typedef struct
{
    CX_UINT32 BootMode;             ///< Specifies whether we're starting from a MBR loader or a PXE loader
    LD_MULTIBOOT_DEVICE BiosOsDrive;///< Contains the BIOS INT13H device ID for the boot device containing the MBR that loaded the HV
}LD_LEGACY_CUSTOM;

typedef struct _LD_UEFI_CUSTOM
{
    CX_UINT8    BootMode;                   ///< Always equal to BOOT_MODE::bootUefi, other values are reserved for future use
    CX_UINT64   RSDPPhysicalAddress;        ///< The physical address of the RSDP data structures as reported by the firmware to the UEFI loader
    CX_UINT64   MpPhysicalAddress;          ///< The physical address of the MP Table as reported by the firmware to the loader
    CX_UINT64   HibernateNvsPhysicalAddress;///< Contain the physical address of a memory region configured by the UEFI loader as NVS, such that the OS will take it into account on hibernation
    CX_UINT64   HibernateNvsSize;           ///< Size of NVS area prepared by the UEFI loader.
}LD_UEFI_CUSTOM;

/// @brief Describe types of boots
typedef union
{
    LD_LEGACY_CUSTOM Legacy;    ///< Leagacy boot
    LD_UEFI_CUSTOM Uefi;        ///< Efi boot
    //...
}LD_LOADER_CUSTOM;

#pragma pack(pop)

/** @brief Module IDs
 *
 * All modules except for the memory map are optionally prepared by some loader or loaders chain
 * Always keep synchronized the definitions found here, in #loader_interface.nasm and the array of names (#ModuleInformation in loader_interface.c)
 *
 */
typedef enum
{
    LD_MODID_INVALID,                       ///< this is not a valid module entry
    LD_MODID_BOOT_CONTEXT,                  ///< specifies where the data sent to Init64 is located
    LD_MODID_NAPOCA_IMAGE,                  ///< describes the area occupied by the kernel
    LD_MODID_NAPOCA_STACK,                  ///< describes the area occupied by the kernel stack, optional if the stack is part of another persistent module
    LD_MODID_MEMORY_MAP,                    ///< E820-like memory map sent by a loader
    LD_MODID_HVMEMORY_MAP,                  ///< hypervisor memory prepared/allocated by the loader
    LD_MODID_COMMAND_LINE,                  ///< string sent by some loader
    LD_MODID_FREE_MEMORY,                   ///< mem. free for any use by the HV -- will alloc. any necessary mem for uninitialized modules from here
    LD_MODID_INTRO_EXCEPTIONS,              ///< exceptions.bin module for introspection
    LD_MODID_INTRO_CORE,                    ///< introspection engine
    LD_MODID_INTRO_LIVE_UPDATE,             ///< intro_live_update.bin module for introspection

    // necessary if the loader doesn't prepare memory for all uninitialized memory modules, must cover all the memory requirements
    // for allocating all missing modules
    LD_MODID_ORIG_MBR,                      ///< custom data for a given boot mode (mbr prepared by our loader belonging to primary os etc..)
    LD_MODID_LOADER_CUSTOM,

    // modules that are automatically allocated (LD_MODID_FREE_MEMORY) unless prepared/sent by our loader
    LD_MODID_BOOT_STATE,                    ///< captured state of the hardware resources before loading the HV (gBootState)
    LD_MODID_NVS,                           ///< memory buffer for reading and writing data persistent over hibernate

    // HV-internal modules, a loader shouldn't set these modules
    LD_MODID_FEEDBACK,                      ///< logs
    LD_MODID_MBR_SETTINGS,                  ///< loader module containing settings for the MBR/PXE boot loader
    LD_MAX_MODULES,                         ///< how many modules are recognized by NAPOCA
}LD_MODID;

#define LD_MODFLAG_DEFAULT          0       ///< (avoid it) let the HV decide what persistence to use
#define LD_MODFLAG_EARLYBOOT        1       ///< this module should be available only at napoca entry point, won't be mapped and kept in mem after changing the boot VA space
#define LD_MODFLAG_PHASE1           2       ///< module memory (PA + VA) should be available throughout all phase1
#define LD_MODFLAG_PHASE2           4       ///< module memory (PA + VA) should be available throughout all phase2
#define LD_MODFLAG_PERMANENT        8       ///< module memory (PA + VA) should be ALWAYS available, even after the guests are up&running
#define LD_MODFLAG_DYNAMICALLY_ALLOCATED 16 ///< module was not allocated from the loader memory buffer

#define LD_WCHAR CX_UINT16
#define LD_CHAR  char

/// @brief The id that identifies a directory that contains specific binaries
typedef enum
{
    SDK_DIR_HV,             ///< Contains napoca.bin, cmdline, etc.
    SDK_DIR_KM,             ///< Currently unused
    SDK_DIR_UM,             ///< Currently unused
    SDK_DIR_MBR,            ///< Contains MBR specific boot files
    SDK_DIR_EFI,            ///< Contains EFI specific boot files
    SDK_DIR_UPDATES_INTRO,  ///< Contains files used to update introspection engine (exceptions.bin, intro_live_update.bin)
    SDK_DIR_DYNAMIC,        ///< More generic files

    SDK_DIR_MAX_ID
}LD_SDKDIR_ID;

/// @brief Flags used when installing a file
typedef struct _LD_INSTALL_FILE_FLAGS
{
    union
    {
        CX_UINT32       Raw;
        struct
        {
            CX_UINT32   Mbr : 1;                    ///< Files used for legacy booting
            CX_UINT32   Efi : 1;                    ///< Files used for UEFI booting
            CX_UINT32   Pxe : 1;                    ///< Files used for Legacy PXE booting
            CX_UINT32   UpdateIntro : 1;            ///< Updates delivered for the HVMI module
            CX_UINT32   GrubBoot : 1;               ///< Identifies a GRUB module that instruct the loader to boot the hypervisor
            CX_UINT32   GrubRecovery : 1;           ///< Identifies a GRUB module that instruct the loader to recover the MBR (emergency disable the hypervisor)
            CX_UINT32   MainModule : 1;             ///< Identifies the kernel (hv) loaded by GRUB
            CX_UINT32   FinalCmdLine : 1;           ///< Identifies the hypervisor command line after applying customizations
        };
    };
}LD_INSTALL_FILE_FLAGS;

/// @brief Encodes a file into an id
typedef enum _LD_UNIQUE_ID
{
    undefinedId = 0,
    defaultCmdLine,
    efiPreloader,
    finalCmdLine,
    efiLoaderBackup,
    napocabin,
    introcorebin,
    exceptionsbin,
    introliveupdtbin,

    maxuniqueid
}LD_UNIQUE_ID;

/// @brief Information about a file required for installation
typedef struct _LD_INSTALL_FILE
{
    LD_UNIQUE_ID            UniqueId;               ///< File unique ID

    LD_SDKDIR_ID            SourceDir;              ///< Source directory of the file
    LD_WCHAR                *SourceFileName;        ///< The file name in the source directory
    LD_WCHAR                *DestinationFileName;   ///< The file name after it is moved to the specific installation location
    LD_INSTALL_FILE_FLAGS   Flags;                  ///< See #LD_INSTALL_FILE_FLAGS

    LD_MODID                LdModId;                ///< See #LD_MODID
    LD_CHAR                 *MultibootName;
}LD_INSTALL_FILE;

#pragma warning(pop)

///
/// @brief Convert from Efi memory type to HV memory type
///
/// We use a specific encoding for the HV memory so we have to do the conversion from the Efi memory types
///
/// @param[in]  EfiType                 Efi memory type. One of #LD_EFI_MEM_TYPE
///
/// @returns    HV memory type converted from Efi memory type
///
LD_HV_MEM_TYPE
LdConvertEfiMemTypeToHvMemType(
    _In_ LD_EFI_MEM_TYPE EfiType
    );

///
/// @brief Convert from E820 memory type to HV memory type
///
/// We use a specific encoding for the HV memory so we have to do the conversion from the E820 memory types
///
/// @param[in]  E820Type            E820 memory type. One of #LD_E820_MEM_TYPE
///
/// @returns    HV memory type converted from E820 memory type
///
LD_HV_MEM_TYPE
LdConvertE820MemTypeToHvMemType(
    _In_ LD_E820_MEM_TYPE E820Type
    );

///
/// @brief Convert from HV memory type to E820 memory type
///
/// We use a specific encoding for the HV memory so we have to do the conversion from/to the E820 memory types
///
/// @param[in]  HvType              HV memory type. One of #LD_HV_MEM_TYPE
///
/// @returns    E820 memory type converted from HV memory type
///
LD_E820_MEM_TYPE
LdConvertHvMemTypeToE820MemType(
    _In_ LD_HV_MEM_TYPE HvType
    );

///
/// @brief Check if given memory type can be used for GUEST or it is restricted to be HV only
///
/// @param[in]  HvType              HV memory type. One of #LD_HV_MEM_TYPE
///
/// @returns    TRUE                - if memory is NOT restricted to be HV only
/// @returns    FALSE               - if memory is restricted to be HV only
///
CX_BOOL
LdIsHvMemTypeAvailableToGuests(
    _In_ LD_HV_MEM_TYPE HvType
    );

///
/// @brief Helper function for retrieving the name of a specified module id.
///
/// @param[in] ModuleId     The module id which can be for example the napoca image, introspection engine, etc.
///
/// @returns    Module name as null-terminated multibyte string - if everything was with success.
/// @returns    "N/A"                                           - ModuleId is not valid
///
char *
LdGetModuleName(
    _In_ LD_MODID ModuleId
    );

///
/// @brief Allocates a memory area of a specified size
///
/// One-time memory allocator (irreversible) which manages a LD_MEM_BUFFER specified range of continuous memory.
/// Allocated memory cannot be freed and reused using this method.
///
/// @param[in,out]  MemoryRegion        Specifies where the memory will be allocated
/// @param[in]      Size                Amount of needed memory in bytes
/// @param[in]      AlignedTo           Address alignment constraint (0 or 1 if no alignment required)
/// @param[out]     Address             Where to store the virtual address of allocated range (as UINT64, even if building in 32 bits)
/// @param[out]     PhysicalAddress     Where to store the physical address of allocated range (as UINT64, even if building in 32 bits)
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if MemoryRegion is NULL
/// @returns    CX_STATUS_DATA_BUFFER_TOO_SMALL - if memory cannot be allocated whith the size of the Size parameter
/// @returns    CX_STATUS_SUCCESS               - if succeeded
///
CX_STATUS
LdAlloc(
    _Inout_ LD_MEM_BUFFER *MemoryRegion,
    _In_ CX_UINT64 Size,
    _In_ CX_UINT32 AlignedTo,
    __out_opt CX_UINT64 *Address,
    __out_opt CX_UINT64 *PhysicalAddress
    );

///
/// @brief Returns a module according to the ModuleId parameter
///
/// @param[in]      Modules             List of modules managed by LdGetModule and LdSetModule
/// @param[in]      NumberOfModules     Number of elements allocated in the modules array
/// @param[in]      ModuleId            The module id which can be for example the napoca image, introspection engine, etc.
/// @param[out]     Result              Where to store the address of the specified module
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if Modules is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_4   - if Result is NULL
/// @returns    CX_STATUS_DATA_NOT_FOUND        - if ModuleId is not valid
/// @returns    CX_STATUS_NOT_INITIALIZED       - if target module not initialized yet
/// @returns    CX_STATUS_SUCCESS               - if succeeded
///
CX_STATUS
LdGetModule(
    _In_ LD_NAPOCA_MODULE *Modules,
    _In_ CX_UINT32 NumberOfModules,
    _In_ CX_UINT32 ModuleId,
    _Out_ LD_NAPOCA_MODULE **Result
    );

///
/// @brief Initializes a module from the module list
///
/// @param[in]      Modules             List of modules managed by LdGetModule and LdSetModule
/// @param[in]      MaxModules          How many modules can be maximum in the Modules list
/// @param[in]      ModuleId            The module id which can be for example the napoca image, introspection engine, etc.
/// @param[in]      Va                  The virtual address of the module described by ModuleId
/// @param[in]      Pa                  The physical address of the module described by ModuleId
/// @param[in]      Size                The size of the module described by ModuleId
/// @param[in]      Flags               Generic information about the module
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if Modules is NULL
/// @returns    CX_STATUS_OUT_OF_RANGE          - if ModuleId is greater than MaxModules
/// @returns    CX_STATUS_SUCCESS               - if succeeded
///
CX_STATUS
LdSetModule(
    _In_ LD_NAPOCA_MODULE *Modules,
    _In_ CX_UINT32 MaxModules,
    _In_ CX_UINT32 ModuleId,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT32 Size,
    _In_ CX_UINT32 Flags
    );

///
/// @brief Maps a memory page to the virtual address space
///
/// @param[in]      Mapper              The data structure that helps us map within a module
/// @param[in]      Va                  The virtual address where the page will be mapped
/// @param[in]      Pa                  The physical address where the page will be mapped
/// @param[in]      Rights              Access rights (read, write, execute)
/// @param[in,out]  TablesRoot          Address of a UINT64 variable that contains (or will receive) the address of the page tables root
/// @param[in]      TablesDepth         From 4 to max 6. 4 for VA, 6 for VT-d
///
/// @returns    CX_STATUS_SUCCESS               - if succeeded
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if Mapper is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_5   - if TablesRoot is NULL
/// @returns    OTHERS                          - other possible values returned by the APIs used by the function
///
CX_STATUS
LdMapPage(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT8 Rights,
    _Inout_ CX_UINT64 *TablesRoot,
    _In_ CX_UINT8 TablesDepth
    );

///
/// @brief Maps one or more pages into the virtual address space
///
/// @param[in]      Mapper              The data structure that helps us map within a module
/// @param[in]      Va                  The virtual address where the pages will be mapped
/// @param[in]      Pa                  The physical address where the pages will be mapped
/// @param[in]      Rights              Access rights (read, write, execute)
/// @param[in]      NumberOfPages       The number of continuous pages to be mapped
/// @param[in,out]  TablesRoot          Address of a UINT64 variable that contains (or will receive) the address of the page tables root
/// @param[in]      TablesDepth         From 4 to max 6. 4 for VA, 6 for VT-d
///
/// @returns    CX_STATUS_SUCCESS               - if succeeded
/// @returns    CX_STATUS_INVALID_PARAMETER_1   - if Mapper is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_6   - if TablesRoot is NULL
/// @returns    OTHERS                          - other possible values returned by the APIs used by the function
///
CX_STATUS
LdMapPages(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Pa,
    _In_ CX_UINT8 Rights,
    _In_ CX_UINT64 NumberOfPages,
    _Inout_ CX_UINT64 *TablesRoot,
    _In_ CX_UINT8 TablesDepth
    );

///
/// @brief Maps a memory area of a specified size
///
/// @param[in]      Mapper              The data structure that helps us map within a module
/// @param[in]      VirtualAddress      The virtual address where the memory will be mapped
/// @param[in]      PhysicalAddress     The physical address where the memory will be mapped
/// @param[in]      Rights              Access rights (read, write, execute)
/// @param[in]      NumberOfBytes       The number of bytes to be mapped
/// @param[in,out]  TablesRoot          Address of a UINT64 variable that contains (or will receive) the address of the page tables root
/// @param[in]      TablesDepth         From 4 to max 6. 4 for VA, 6 for VT-d
///
/// @returns    CX_STATUS_SUCCESS                   - if succeeded
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - if Mapper is NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_6       - if TablesRoot is NULL
/// @returns    CX_STATUS_ALIGNMENT_INCONSISTENCY   - if the offset in the virtual page is different from the offset in the physical page
/// @returns    OTHERS                              - other possible values returned by the APIs used by the function
///
CX_STATUS
LdMapRange(
    _In_ LD_VA_MAPPER *Mapper,
    _In_ CX_UINT64 VirtualAddress,
    _In_ CX_UINT64 PhysicalAddress,
    _In_ CX_UINT8 Rights,
    _In_ CX_UINT64 NumberOfBytes,
    _Inout_ CX_UINT64 *TablesRoot,
    _In_ CX_UINT8 TablesDepth
    );

///
/// @brief Wrapper over #LdMapRange
///
#define LD_MAP_RANGE(Mapper, Va, Pa, Length, Rights, RootPtr, TablesDepth) LdMapRange(Mapper, Va, Pa, Rights, \
    Length, RootPtr, TablesDepth)

///
/// @brief Convert physical address to virtual address
///
/// @param[in]      VaMapper            The data structure that helps us manage memory mapping within loader interface
/// @param[in]      Pa                  The physical address to convert
///
/// @returns        Virtual address leading to physical address Pa
///
CX_UINT64
LdPaToVa(
    _In_ LD_VA_MAPPER* VaMapper,
    _In_ CX_UINT64 Pa
    );

///
/// @brief Convert virtual address to physical address
///
/// @param[in]      VaMapper            The data structure that helps us manage memory mapping within loader interface
/// @param[in]      Va                  The virtual address to convert
///
/// @returns        The physical address to which the virtual address Va is translated
///
CX_UINT64
LdVaToPa(
    _In_ LD_VA_MAPPER* VaMapper,
    _In_ CX_UINT64 Va
    );

///
/// @brief Estimate how much memory does the hypervisor need
///
/// @param[in]      TotalSystemMemory   Total system physical memory
/// @param[in]      NumberOfGuests      Number of guests
/// @param[in]      SharedBufferSize    Size of shared buffer between hv and guests
/// @param[out]     TotalRequiredMemory Memory required for hypervisor
/// @param[out]     TotalGuestsMemory   Memory required just for the guests
///
/// @returns STATUS_SUCCESS             - always
///
CX_STATUS
LdEstimateRequiredHvMem(
    _In_ CX_UINT64 TotalSystemMemory,
    _In_ CX_UINT32 NumberOfGuests,
    _In_ CX_UINT32 SharedBufferSize,
    __out_opt CX_UINT64 *TotalRequiredMemory,
    __out_opt CX_UINT64 *TotalGuestsMemory
    );

/** @name Debugging utils
 *
 */
///@{
CX_UINT64
LdWalkTablesDump(
    _In_ CX_UINT64 Cr3,
    _In_ CX_UINT64 Adr,
    _In_opt_ PFUNC_PhysicalToVirtual Callback
);

#define LdDumpLdNapocaModule(ptr) LdDumpLdNapocaModule2 (ptr, 0, 2, CX_TRUE, 8)
#define LdDumpLdBootContext(ptr) LdDumpLdBootContext2 (ptr, 0, 2, CX_TRUE, LD_MAX_MODULES)

CX_STATUS
LdDumpMemory(
    _In_opt_ char *Message,
    _In_ void *Address,
    _In_ CX_UINT32 Length
    );

CX_STATUS
LdDumpMemBuffer(
    _In_opt_ CX_INT8 *Message,
    _In_ LD_MEM_BUFFER *Mem
    );

CX_STATUS
LdDumpLdNapocaModule2(
    _In_ LD_NAPOCA_MODULE *Ptr,
    _In_ CX_UINT32 Depth,
    _In_ CX_UINT32 MaxDepth,
    _In_ CX_BOOL FollowPointers,
    _In_ CX_UINT64 ArraysMaxIterationCount
    );

CX_STATUS
LdDumpLdBootContext2(
    _In_ LD_BOOT_CONTEXT *Ptr,
    _In_ CX_UINT32 Depth,
    _In_ CX_UINT32 MaxDepth,
    _In_ CX_BOOL FollowPointers,
    _In_ CX_UINT64 ArraysMaxIterationCount
    );


#define LD_DUMP_MODULE(LOG_FN, ModulePtr)\
    LOG_FN("%-10s - %016p: dumping LD_NAPOCA_MODULE\n", "    ", (ModulePtr));\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ModulePtr)->Va), "(CX_UINT64) Va", (ModulePtr)->Va);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ModulePtr)->Pa), "(CX_UINT64) Pa", (ModulePtr)->Pa);\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ModulePtr)->Size), "(CX_UINT32) Size", (ModulePtr)->Size);\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ModulePtr)->Flags), "(CX_UINT32) Flags", (ModulePtr)->Flags)

#define LD_DUMP_MEMBUFFER(LOG_FN, MemBufferPtr)\
    LOG_FN("--> %-18s  <%016p>\n", "Va", (MemBufferPtr)->Va);\
    LOG_FN("--> %-18s  <%016p>\n", "Pa", (MemBufferPtr)->Pa);\
    LOG_FN("--> %-18s  <%016p>\n", "Length", (MemBufferPtr)->Length);\
    LOG_FN("--> %-18s  <%016p>\n", "NextFreeAddress", (MemBufferPtr)->NextFreeAddress);\
    LOG_FN("--> %-18s  <%d>\n", "Used(KB)", ((MemBufferPtr)->NextFreeAddress - (MemBufferPtr)->Va)/CX_PAGE_SIZE_4K);\
    LOG_FN("--> %-18s  <%d>\n", "Free(KB)", ((MemBufferPtr)->Length - ((MemBufferPtr)->NextFreeAddress - (MemBufferPtr)->Va)) / 1024)

#define LD_DUMP_CONTEXT(LOG_FN, ContextPtr)\
    LOG_FN("%-10s - %016p: dumping LD_BOOT_CONTEXT\n", "    ", (ContextPtr));\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ContextPtr)->BootMode), "(CX_UINT32) BootMode", (ContextPtr)->BootMode);\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ContextPtr)->GuestArch), "(CX_UINT32) GuestArch", (ContextPtr)->GuestArch);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Modules), "(POINTER) Modules", (ContextPtr)->Modules);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->ModulesPa), "(CX_UINT64) ModulesPa", (ContextPtr)->ModulesPa);\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ContextPtr)->NumberOfModules), "(CX_UINT32) NumberOfModules", (ContextPtr)->NumberOfModules);\
    LOG_FN("%-10s - %016p: %-46s 0x%08X\n", "    ", &((ContextPtr)->NumberOfLoaderCpus), "(CX_UINT32) NumberOfLoaderCpus", (ContextPtr)->NumberOfLoaderCpus);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->OriginalStackTop), "(CX_UINT64) OriginalStackTop", (ContextPtr)->OriginalStackTop);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Cr3), "(CX_UINT64) Cr3", (ContextPtr)->Cr3);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Cr4), "(CX_UINT64) Cr4", (ContextPtr)->Cr4);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Cr0), "(CX_UINT64) Cr0", (ContextPtr)->Cr0);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Cr8), "(CX_UINT64) Cr8", (ContextPtr)->Cr8);\
    LOG_FN("%-10s - %016p: %-46s 0x%04X\n", "    ", &((ContextPtr)->GdtLimit), "(CX_UINT16) GdtLimit", (ContextPtr)->GdtLimit);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->GdtBase), "(CX_UINT64) GdtBase", (ContextPtr)->GdtBase);\
    LOG_FN("%-10s - %016p: %-46s 0x%04X\n", "    ", &((ContextPtr)->IdtLimit), "(CX_UINT16) IdtLimit", (ContextPtr)->IdtLimit);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->IdtBase), "(CX_UINT64) IdtBase", (ContextPtr)->IdtBase);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rax), "(CX_UINT64) Rax", (ContextPtr)->Rax);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rbx), "(CX_UINT64) Rbx", (ContextPtr)->Rbx);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rcx), "(CX_UINT64) Rcx", (ContextPtr)->Rcx);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rdx), "(CX_UINT64) Rdx", (ContextPtr)->Rdx);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rsi), "(CX_UINT64) Rsi", (ContextPtr)->Rsi);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rdi), "(CX_UINT64) Rdi", (ContextPtr)->Rdi);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rbp), "(CX_UINT64) Rbp", (ContextPtr)->Rbp);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->Rsp), "(CX_UINT64) Rsp", (ContextPtr)->Rsp);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R8), "(CX_UINT64) R8", (ContextPtr)->R8);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R9), "(CX_UINT64) R9", (ContextPtr)->R9);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R10), "(CX_UINT64) R10", (ContextPtr)->R10);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R11), "(CX_UINT64) R11", (ContextPtr)->R11);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R12), "(CX_UINT64) R12", (ContextPtr)->R12);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R13), "(CX_UINT64) R13", (ContextPtr)->R13);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R14), "(CX_UINT64) R14", (ContextPtr)->R14);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->R15), "(CX_UINT64) R15", (ContextPtr)->R15);\
    LOG_FN("%-10s - %016p: %-46s %016p\n", "    ", &((ContextPtr)->RFlags), "(CX_UINT64) RFlags", (ContextPtr)->RFlags)

#define LD_DUMP_MODULES(LOG_FN, ModulesPtr, NumberOfModules)\
    {\
        CX_UINT32 tempI;\
        LOG_FN("Dumping %d modules found at %p\n", NumberOfModules, (CX_UINT64)((CX_SIZE_T)ModulesPtr));\
        for (tempI = 0; (tempI < NumberOfModules); tempI++)\
        {\
            if (ModulesPtr[tempI].Size != 0)\
            {\
                LOG_FN("Processed module %-32s(%d): PA:%08X, VA:%08X, SIZE:%08X, FLAGS:%08X\n", LdGetModuleName(tempI), tempI,\
                    ModulesPtr[tempI].Pa, ModulesPtr[tempI].Va, ModulesPtr[tempI].Size, ModulesPtr[tempI].Flags);\
            }\
        }\
    }

#define LD_DUMP_RIP_TRANSLATIONS LOG("current RIP page address translations: "), \
    LdWalkTablesDump(__readcr3(), CpuGetRIP(), CX_NULL)
///@}

#endif //_LOADER_INTERFACE_H_