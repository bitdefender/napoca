/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// internal uefi definitions, don't include it outside this project!

#ifndef _UEFI_INTERNAL_H_
#define _UEFI_INTERNAL_H_

#include "autogen/efi_cmdline.h"
#include "autogen/efi_buildconfig.h"

#include <Uefi.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/PeImage.h>
#include <Library/PeCoffLib.h>
#include <Library/DxeCoreEntryPoint.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library\Printlib.h>

#include "MemDebugLib/MemDebugLib.h"

#include "wrappers/cx_winsal.h"

#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
#define _SUCCESS CX_SUCCESS
#define SUCCESS CX_SUCCESS
typedef CX_UINT8 BYTE, *PBYTE, CHAR, *PCHAR;
typedef CX_UINT16 WORD, *PWORD;
typedef CX_UINT32 DWORD, *PDWORD, ULONG, *PULONG;
typedef CX_UINT64 QWORD, *PQWORD, ULONGLONG, *PULONGLONG;

typedef CX_INT32 LONG, *PLONG;
typedef CX_SIZE_T SIZE_T;
typedef CX_STATUS NTSTATUS;

char *
NtStatusToString(
    _In_ NTSTATUS Status
);
#include "common/debug/memlog.h"

extern UD_VAR_INFO EfiCommandLineVariablesInfo[];
extern DWORD EfiCommandLineVariablesInfoCount;

#define CpuEnableInterrupts()           _enable()
#define CpuDisableInterrupts()          _disable()
#define CpuInterruptsAreEnabled()       ((__readeflags() & 0x00000200 /*RFLAGS_IF*/) != 0)

extern volatile BOOLEAN UefiBypassTimeout;
extern volatile BOOLEAN UefiVirtualized;

#define MILISECOND_FROM_MICROSECOND             1000
#define SECOND_FROM_MICROSECOND                 (1000 * MILISECOND_FROM_MICROSECOND)
#define MILISECOND_FROM_100_NANOSECOND          10000
#define SECOND_FROM_100_NANOSECOND              (1000 * MILISECOND_FROM_100_NANOSECOND)


typedef
VOID
(EFIAPI *EFI_AP_PROCEDURE)(
  void  *Buffer
  );

char
UefiGetKey(
    void
    );
void AsmHvBreak(void);


#include <Protocol\MpService.h>             //EFI_MP_SERVICES_PROTOCOL_GUID
#include <Protocol\FrameworkMpService.h>    //FRAMEWORK_EFI_MP_SERVICES_PROTOCOL_GUID

#include "pedefs.h"

//
// Constants
//
//#define ONE_TERABYTE                        ((QWORD)1024 * (QWORD)ONE_GIGABYTE)
#ifndef PAGE_SIZE
#define PAGE_SIZE                           4096
#endif


//
// Macro definitions
//
#define PAGE_MASK               0xFFFFFFFFFFFFF000ULL
#define PAGE_OFFSET_MASK        (PAGE_SIZE - 1)
#define PAGE_OFFSET(adr)        (((QWORD)(adr)) & (QWORD)PAGE_OFFSET_MASK)
#define PVOID void *
#define PAGE_BASE(X)            ((UINT64)((UINT64)(X) / (UINT64)PAGE_SIZE))
#define PAGE_BASE_VA(adr)       (((QWORD)((SIZE_T)adr)) & (QWORD)PAGE_MASK)
#define PAGE_BASE_PA            PAGE_BASE_VA
#define PAGE_COUNT(adr,bytes)   (1+(PAGE_BASE_VA(((QWORD)(adr)) + (bytes)) - PAGE_BASE_VA((QWORD)(adr)))/PAGE_SIZE)
//#define ROUND_DOWN(v,a)         ((((v) % (a))==0)?(v):((v) - ((v) % (a))))
//#define ROUND_UP(v,a)           ((((v) % (a))==0)?(v):((v) + ((a) - ((v) % (a)))))

#define DWORD_AT(ptr, index)    (*((DWORD*)((BYTE *)(ptr) + (index))))
#define PTR_DELTA(a,b)          (PVOID)((SIZE_T)(a) - (SIZE_T)(b))

#define SAME_GUID(X,Y) (((((UINT64*)(X))[0] == ((UINT64*)(Y))[0])) && ((((UINT64*)(X))[1] == ((UINT64*)(Y))[1])))

//
// Global variables
//
extern EFI_SYSTEM_TABLE                 *UefiSystemTable;
extern EFI_BOOT_SERVICES                *UefiBootServices;
extern EFI_RUNTIME_SERVICES             *UefiRuntimeServices;
extern EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *UefiTextOutputProtocol;

extern EFI_HANDLE                       UefiImageHandle;
extern BOOLEAN                          UefiGopAvailable;
extern UINTN                            UefiNumberOfColumns;
extern UINTN                            UefiNumberOfLines;

extern EFI_GUID                         UefiMpServicesGuid;
extern EFI_GUID                         UefiFramewordkMpServicesGuid;
extern EFI_MP_SERVICES_PROTOCOL             *UefiMpProtocol;
extern FRAMEWORK_EFI_MP_SERVICES_PROTOCOL   *UefiFrameworkMpProtocol;


//
// Types
//
typedef struct _HV_EXPORTS
{
    UINT64 Init64HvVa;
}HV_EXPORTS, *PHV_EXPORTS;

#pragma pack(push, 1)

typedef struct _TSS64 {
    DWORD           Reserved1;
    QWORD           RSP0;
    QWORD           RSP1;
    QWORD           RSP2;
    QWORD           Reserved2;
    QWORD           IST1;
    QWORD           IST2;
    QWORD           IST3;
    QWORD           IST4;
    QWORD           IST5;
    QWORD           IST6;
    QWORD           IST7;
    QWORD           Reserved3;
    WORD            Reserved4;
    WORD            IoMapBaseAddr;
} TSS64, *PTSS64;

#pragma pack(pop)

extern QWORD UefiTotalHvMemory;
//
// API
//
void *
UefiAlloc(
    _In_ UINT64 Amount );

void *
UefiAllocHv(
    _In_ UINT64 Amount,
    _In_ BOOLEAN Initialized
    );

void
UefiFree (
    _In_ void * Buffer );


DWORD
UefiGetLocalApicId (
    void );

void
UefiSetTs (
   void *GdtBase );


EFI_STATUS
UefiGetMemoryMap(
    _Out_       EFI_MEMORY_DESCRIPTOR **MemoryMap,
    _Out_       UINT64 *DescriptorSize,
    _Out_       UINT64 *NumberOfMemoryDescriptors,
    __out_opt   UINT64 *TotalConventionalMemAvailable );


EFI_STATUS
UefiExecuteEfiFile(
    _In_ CHAR16 *FileName );


EFI_STATUS
UefiExecuteEfiFileA(
    _In_ char *FileName
    );

void
InternalInit(
    _In_ EFI_SYSTEM_TABLE *SystemTable,
    _In_ EFI_HANDLE ImageHandle);


CHAR16*
UefiStatusToText(
    _In_ EFI_STATUS Status );


void
UefiWaitKey(
    void );


void
UefiWaitKeyMsg(
    _In_ CHAR16 *Message);

EFI_STATUS
UefiCheckUserHvBypass(
    VOID
    );

void
UefiMemDumper(
    _In_ void *Buffer,
    _In_ UINT32 Length,
    _In_ BOOLEAN PromptOnFullScreen);
void
UefiAsciiDumper(
    _In_ void *Buffer,
    _In_ UINT32 Length,
    _In_ BOOLEAN PromptOnFullScreen);

//
// External functions, implemented in yasm
//

UINT64
UefiGetRSP(
   void );


// synchronization
DWORD
UefiInterlockedIncrement(
    _Inout_ volatile DWORD *volatile Variable );
DWORD
UefiInterlockedDecrement(
    _Inout_ volatile DWORD *volatile Variable );

DWORD
UefiAcquireLock(
    _Inout_ volatile DWORD *volatile Lock );

DWORD UefiReleaseLock(
    _Inout_ volatile DWORD *volatile Lock );


EFI_STATUS
InternalGetCpuCount(
    _Out_ UINTN *NumberOfProcessors
    );

EFI_STATUS
InternalStartupAllApProcessors(
    void (*ApProc) (void *Buffer),
    void *Buffer,
    __inout_opt EFI_EVENT ApEvent
    );

EFI_STATUS
UefiDumpEfiModule(
    _In_ char *FileName,
    _In_ void *SomeAddressInModuleMemory
    );


#pragma pack(push, 1)
typedef struct _IDT_DESCRIPTOR
{
//  struct
//  {
//      DWORD Offset15_0:16;
//      DWORD Selector:16;
//  };
//  struct
//  {
//      DWORD IST:3;
//      DWORD Zeroes:5;
//      DWORD Type:4;
//      DWORD Zero:1;
//      DWORD DPL:2;
//      DWORD P:1;
//      DWORD Offset31_16:16;
//  };
//  struct
//  {
//      DWORD Offset63_32;
//      DWORD Reserved;
//  };
    struct {
        WORD        Offset15_0;
        WORD        Selector;
        WORD        Fields;
        WORD        Offset31_16;
        DWORD       Offset63_32;
        DWORD       Reserved2;
    };
}IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;
typedef struct _IDT
{
    WORD Limit;
    QWORD Base;
}IDT, *PIDT;

#pragma pack(pop)

//
// debug macros
//
extern volatile QWORD gOutputLock;
extern volatile QWORD gHvOutputLock;
extern volatile DWORD gNumberOfCpusPrepared;

// based on CFG_UEFI_HV_OUT define HV_PRINT
#if (CFG_UEFI_HV_OUT)
    // let the HV print a string
    #define HV_PRINT(...) ((CFG_UEFI_HV_OUT) && ((UefiAcquireLock((volatile DWORD *)&gHvOutputLock),\
        (UefiVirtualized&&\
        ((AsciiSPrintUnicodeFormat((CHAR8 *)UartTempBuffer, UART_TEMP_BUFFER_SIZE, __VA_ARGS__)) &&\
        (!HvWriteBuffer((PCHAR)UartTempBuffer, UART_TEMP_BUFFER_SIZE)))), \
        UefiReleaseLock((volatile DWORD *)&gHvOutputLock))))
    #define HVLOG(...)          (HV_PRINT(__VA_ARGS__))
    #define HVLOGA(...)         1
#else
    #define HV_PRINT(...)       1
    #define HVLOG(...)          1
    #define HVLOGA(...)         1
#endif


// based on CFG_UEFI_MEMLOG_OUT define MEM_*
#if (CFG_UEFI_MEMLOG_OUT)
    extern EFI_GUID gBdHvGuid;
    extern MD_LOG_BUFFER *gLog;

    #define MEM_LOG_FORCEFLUSH()    (MdSaveLogToVariable(gLog, L"BdHvLoaderLog", &gBdHvGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS))
    #define MEM_LOG_AUTOFLUSH()     ((CFG_UEFI_MEMLOG_AUTOFLUSH) && (MEM_LOG_FORCEFLUSH()))
    #define MEM_LOG(...)            (MD_ULOG(gLog, __VA_ARGS__), MEM_LOG_AUTOFLUSH())
    #define MEM_LOGA(...)           (MD_LOG(gLog, __VA_ARGS__), MEM_LOG_AUTOFLUSH())
#else
    extern EFI_GUID gBdHvGuid;
    #define MEM_LOG_FORCEFLUSH()    1
    #define MEM_LOG_AUTOFLUSH()     1
    #define MEM_LOG(...)            1
    #define MEM_LOGA(...)           1
#endif

// based on CFG_UEFI_GOP_OUT define GOP*
#define GOPLOG(...)         (CfgDebugGopOutput && Print(__VA_ARGS__))
#define GOPLOGA(...)        (CfgDebugGopOutput &&AsciiPrint(__VA_ARGS__))


// clean and file/func/line prefixed output
#define LOG(...)            (GOPLOG(__VA_ARGS__), MEM_LOG(__VA_ARGS__))
#define LOGA(...)           (GOPLOGA(__VA_ARGS__), MEM_LOGA(__VA_ARGS__))

#define TRACE(...)          (LOG(L"%-12a:%4d - ", __FUNCDNAME__, __LINE__), LOG(__VA_ARGS__))
#define TRACEA(...)         (LOGA("%-12a:%4d - ", __FUNCDNAME__, __LINE__), LOGA(__VA_ARGS__))

// error messages
#define ERR_NT(Fn, Status)  TRACE(L"%a has failed with NT status %a\n", Fn, NtStatusToString(Status))
#define ERR(Fn, Status)     TRACE(L"%a has failed with status %a\n", Fn, UefiStatusToText(Status))

// debug messages
#define DBG                 MEM_LOGA


#endif // _UEFI_INTERNAL_H_

