/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpu_state.h
*   @brief Describes the state of a processor
*/

#ifndef _CPU_STATE_H_
#define _CPU_STATE_H_
#include "cx_native.h"


/** @brief Maximum AP processors supported
 *
 *  Should be 64 or 256.
 *
 */
#define CPUSTATE_MAX_GUEST_CPU_COUNT        64

typedef CX_UINT8 CPU_STATE_BOOL;

#pragma pack(push)
#pragma pack(1)

/// @brief If XSAVE, XRESTOR, XSETBV, XGETBV supported, the extended state will be saved here
typedef CX_UINT8 EXTENDED_STATE[4096+63];   // + 63 because the address shall be aligned to 64

/// @brief Describe the memory area used for one of the _xsaveopt64 / _xsave64 / _fxsave64 instruction
typedef CX_UINT8 CPU_EXT_STATE[4096];

/// @brief The structure that describes a snapshot of a state within the guest
typedef struct _CPUSTATE_GUEST_STATE_INFO
{
    CPU_STATE_BOOL IsStructureInitialized;
    CX_UINT64 Rax, Rbx, Rcx, Rdx, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
    CPU_STATE_BOOL UsingFakedTr;
    CX_UINT16  Es;
    CX_UINT16  Cs;
    CX_UINT16  Ss;
    CX_UINT16  Ds;
    CX_UINT16  Fs;
    CX_UINT16  Gs;
    CX_UINT16  Ldtr;
    CX_UINT16  Tr;
    CX_UINT64 LinkPointer;
    CX_UINT64 Ia32Debugctl;
    CX_UINT64 Ia32Pat;
    CX_UINT64 Ia32Efer;
    CX_UINT64 Ia32PerfGlobalCtrl;
    CX_UINT64 Pdpte0;
    CX_UINT64 Pdpte1;
    CX_UINT64 Pdpte2;
    CX_UINT64 Pdpte3;
    CX_UINT32 EsLimit;
    CX_UINT32 CsLimit;
    CX_UINT32 SsLimit;
    CX_UINT32 DsLimit;
    CX_UINT32 FsLimit;
    CX_UINT32 GsLimit;
    CX_UINT32 LdtrLimit;
    CX_UINT32 TrLimit;
    CX_UINT32 GdtrLimit;
    CX_UINT32 IdtrLimit;
    CX_UINT32 EsAccessRights;
    CX_UINT32 CsAccessRights;
    CX_UINT32 SsAccessRights;
    CX_UINT32 DsAccessRights;
    CX_UINT32 FsAccessRights;
    CX_UINT32 GsAccessRights;
    CX_UINT32 LdtrAccessRights;
    CX_UINT32 TrAccessRights;
    CX_UINT32 InterruptibilityState;
    CX_UINT32 ActivityState;
    CX_UINT32 SmBase;
    CX_UINT32 Ia32SysenterCs;
    CX_UINT32 VmxPreemptionTimerValue;
    CX_UINT64 Cr0;
    CX_UINT64 Cr2;
    CX_UINT64 Cr3;
    CX_UINT64 Cr4;
    CX_UINT64 Cr8;
    CX_UINT64 EsBase;
    CX_UINT64 CsBase;
    CX_UINT64 SsBase;
    CX_UINT64 DsBase;
    CX_UINT64 FsBase;
    CX_UINT64 GsBase;
    CX_UINT64 LdtrBase;
    CX_UINT64 TrBase;
    CX_UINT64 GdtrBase;
    CX_UINT64 IdtrBase;
    CX_UINT64 Dr7;
    CX_UINT64 Rsp;
    CX_UINT64 Rip;
    CX_UINT64 Rflags;
    CX_UINT64 PendingDebugExceptions;
    CX_UINT64 Ia32SysenterEsp;
    CX_UINT64 Ia32SysenterEip;
    CX_UINT64 Ia32KernelGsBase;
    CX_UINT64 Star;
    CX_UINT64 LStar;
    CX_UINT64 CStar;
    EXTENDED_STATE Extensions;

    CX_UINT32 LapicId;
}CPUSTATE_GUEST_STATE_INFO;

/// @brief The structure that contains for each CPU a snapshot with its status at boot time
typedef struct _CPUSTATE_BOOT_GUEST_STATE
{
    volatile CX_INT32           NumberOfInitializedEntries;                     ///< How many structures are initialized (should be equal to the number of CPUs in GUEST)
    CPU_STATE_BOOL              _Reserved0;
    CX_UINT8                    _Padding[3];
    CPUSTATE_GUEST_STATE_INFO   BootVcpuState[CPUSTATE_MAX_GUEST_CPU_COUNT];    ///< Array of #CPUSTATE_GUEST_STATE_INFO structures
} CPUSTATE_BOOT_GUEST_STATE;
#pragma pack(pop)

/** @name Function definitions from NASM
 *  @brief Functions that help capture processor registers that determine its state
 */
///@{

///
/// @brief Takes a snapshot of the processor registers
///
/// @param[out] GuestInfo                     the structure where the registers were saved
///
void
CpustateCaptureGuestState(
    _Out_ CPUSTATE_GUEST_STATE_INFO *GuestInfo
    );

///
/// @brief Sets the RIP into the structure that represents the snapshot of the processor registers
///
/// @param[in, out] GuestInfo                       the structure where the RIP value will be saved
/// @param[in]      ripValue                        the RIP value to be saved
///
void
CpustateSetRIP(
    _Inout_ CPUSTATE_GUEST_STATE_INFO* GuestInfo,
    _In_ CX_UINT64 ripValue
    );

///
/// @brief Sets the RSP into the structure that represents the snapshot of the processor registers
///
/// @param[in, out] GuestInfo                       the structure where the RSP value will be saved
/// @param[in]      rspValue                        the RSP value to be saved
///
void
CpustateSetRSP(
    _Inout_ CPUSTATE_GUEST_STATE_INFO* GuestInfo,
    _In_ CX_UINT64 rspValue
    );

///
/// @brief Restores a snapshot in the processor registers
///
/// @param[in] GuestInfo                       the structure where the registers snapshot was saved
///
void
CpustateRestoreGuestState(
    _In_ CPUSTATE_GUEST_STATE_INFO* GuestInfo
    );

///
/// @brief Used if we needed to rebuild gdt to add a valid tr
///
/// @param[in] GuestInfo                        the structure where the registers snapshot was saved
/// @param[in] SecondaryGdt                     the address of new descriptors table
///
void
CpustateGetTrFromSecondaryGdt(
    _In_ CPUSTATE_GUEST_STATE_INFO* GuestInfo,
    _In_ void *SecondaryGdt
    );

///
/// @brief Save Processor Extended States
///
/// @param[in,out] FxSaveMap            the memory on which xsave is executed
///
void
CpustateCaptureGuestXState(
    _Inout_ CX_VOID *FxSaveMap
    );

///
/// @brief Restore Processor Extended States
///
/// @param[in,out] FxSaveMap            the memory on which xrstor is executed
///
void
CpustateRestoreGuestXState(
    _Inout_ CX_VOID *FxSaveMap
    );

///
/// @brief Getter for GDT base
///
CX_UINT64
CpustateGetGdtBase(
    void
    );

///
/// @brief Getter for GDT limit
///
CX_UINT16
CpustateGetGdtLimit(
    void
    );

///
/// @brief Getter for CS register
///
CX_UINT16
CpustateGetCs(
    void
    );
///@}

#endif
