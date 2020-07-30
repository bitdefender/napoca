/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file cpuops.h
*   @brief CPUOPS - macro wrappers and prototypes for intrinsics and plain assembler CPU operations
*
*/

#ifndef _CPUOPS_H_
#define _CPUOPS_H_

// this is a rather low-level include file, only include exactly what is needed here to avoid include loops
#include "common/kernel/vmxdefs.h"
#include "common/kernel/cpudefs.h"
#include "common/boot/cpu_features.h"
#include "core.h"

typedef struct _VCPU VCPU;
#pragma pack(push)
#pragma pack(1)

///
/// @brief Most important x86-64 architectural registers
///
/// @remark IMPORTANT: the order of the first 16 registers is very important
/// @remark Conform Intel Vol 3B, 24.2.1, "Basic VM-EXIT Information", Table 24-3
///
typedef struct _ARCH_REGS
{
    union {
        CX_UINT64 RAX;          // +0x000
        CX_UINT32 EAX;
        CX_UINT16 AX;
        CX_UINT8 AL;
    };
    union {
        CX_UINT64 RCX;          // +0x008
        CX_UINT32 ECX;
        CX_UINT16  CX;
        CX_UINT8  CL;
    };
    union {
        CX_UINT64 RDX;          // +0x010
        CX_UINT32 EDX;
        CX_UINT16  DX;
        CX_UINT8  DL;
    };
    union {
        CX_UINT64 RBX;          // +0x018
        CX_UINT32 EBX;
        CX_UINT16  BX;
        CX_UINT8  BL;
    };
    union {
        CX_UINT64 RSP;          // +0x020
        CX_UINT32 ESP;
        CX_UINT16  SP;
    };
    union {
        CX_UINT64 RBP;          // +0x028
        CX_UINT32 EBP;
        CX_UINT16  BP;
    };
    union {
        CX_UINT64 RSI;          // +0x030
        CX_UINT32 ESI;
        CX_UINT16  SI;
    };
    union {
        CX_UINT64 RDI;          // +0x038
        CX_UINT32 EDI;
        CX_UINT16  DI;
    };
    CX_UINT64 R8;               // +0x040
    CX_UINT64 R9;               // +0x048
    CX_UINT64 R10;              // +0x050
    CX_UINT64 R11;              // +0x058
    CX_UINT64 R12;              // +0x060
    CX_UINT64 R13;              // +0x068
    CX_UINT64 R14;              // +0x070
    CX_UINT64 R15;              // +0x078
    CX_UINT64 DR7;              // +0x080
    union {
        CX_UINT64 RFLAGS;       // +0x088
        CX_UINT32 EFLAGS;
    };
    union {
        CX_UINT64 RIP;          // +0x090
        CX_UINT32 EIP;
    };
    CX_UINT64 CR0;              // +0x098
    CX_UINT64 CR2;              // +0x0A0
    CX_UINT64 CR3;              // +0x0A8
    CX_UINT64 CR4;              // +0x0B0
    CX_UINT64 CR8;              // +0x0B8   ///< *NOT AUTOMATICALLY SAVED*
    CX_UINT64 XCR0;             // +0x0C0

    CX_UINT64 IdtrBase;         // +0x0C8
    CX_UINT16  IdtrLimit;        // +0x0D0
    CX_UINT16  _ReservedW1;      // +0x0D2
    CX_UINT32 _ReservedD1;      // +0x0D4

    CX_UINT64 GdtrBase;         // +0x0D8
    CX_UINT16  GdtrLimit;        // +0x0E0
    CX_UINT16  _ReservedW2;      // +0x0E2
    CX_UINT32  _ReservedD2;     // +0x0E4

    CX_UINT64 DR6;              // +0x0E8

    // Reserved for future use.
    CX_UINT64 _Reserved6;       // +0x0F0
    CX_UINT64 _Reserved7;       // +0x0F8
} ARCH_REGS;

///
/// @brief Combined register for address calculations, CS:RIP and SS:RSP combined into one single final linear address
///
typedef struct _PSEUDO_REGS
{
    union {
        CX_UINT64 CsRip;          ///< current RIP, accounting for CS segment base
        CX_UINT32 CsEip;          ///< current EIP, accounting for CS segment base
        CX_UINT32 CsIp;           ///< current IP, accounting for CS segment base
    };
    union {
        CX_UINT64 SsRsp;          ///< current RSP, accounting for SS segment base
        CX_UINT32 SsEsp;          ///< current ESP, accounting for SS segment base
        CX_UINT32 SsSp;           ///< current SP, accounting for SS segment base
    };
}PSEUDO_REGS;


///
/// @brief FPU/MMX registers + XMM registers; check "Layout of the 64-bit-mode FXSAVE64 Map", Vol. 2A 3-463
///
typedef struct _EXTENDED_REGS
{
    CX_UINT16    FCW;            // +0x000
    CX_UINT16    FSW;            // +0x002
    CX_UINT8    FTW;            // +0x004
    CX_UINT8    _Reserved1;     // +0x005
    CX_UINT16    FOP;            // +0x006
    CX_UINT64   FPUIP;          // +0x008
    CX_UINT64   FPUDP;          // +0x010
    CX_UINT32   MXCSR;          // +0x018
    CX_UINT32   MXCSR_MASK;     // +0x01C
    CX_UINT64   MM0[2];         // +0x020
    CX_UINT64   MM1[2];         // +0x030
    CX_UINT64   MM2[2];         // +0x040
    CX_UINT64   MM3[2];         // +0x050
    CX_UINT64   MM4[2];         // +0x060
    CX_UINT64   MM5[2];         // +0x070
    CX_UINT64   MM6[2];         // +0x080
    CX_UINT64   MM7[2];         // +0x090
    CX_UINT64   XMM0[2];        // +0x0A0
    CX_UINT64   XMM1[2];        // +0x0B0
    CX_UINT64   XMM2[2];        // +0x0C0
    CX_UINT64   XMM3[2];        // +0x0D0
    CX_UINT64   XMM4[2];        // +0x0E0
    CX_UINT64   XMM5[2];        // +0x0F0
    CX_UINT64   XMM6[2];        // +0x100
    CX_UINT64   XMM7[2];        // +0x110
    CX_UINT64   XMM8[2];        // +0x120
    CX_UINT64   XMM9[2];        // +0x130
    CX_UINT64   XMM10[2];       // +0x140
    CX_UINT64   XMM11[2];       // +0x150
    CX_UINT64   XMM12[2];       // +0x160
    CX_UINT64   XMM13[2];       // +0x170
    CX_UINT64   XMM14[2];       // +0x180
    CX_UINT64   XMM15[2];       // +0x190
    CX_UINT64   _Reserved2[6];  // +0x1A0
    CX_UINT64   Available[6];   // +0x1F0
} EXTENDED_REGS;

#pragma pack(pop)


extern CX_UINT64 gCpuMaxPhysicalAddress;
extern CX_UINT8 gCpuPhysicalAddressWidth;
extern CX_UINT8 gCpuVirtualAddressWidth;

//
// prototypes for CPU functions implemented in ASM
//


///
/// @brief        Initialize the x87 FPU without checking for pending unmasked floating-point exceptions.
///
void FpuSseInit(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from TR.
///
/// @returns      The TR value.
///
CX_UINT16 CpuGetTR(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in TR.
///
/// @param[in]    Selector                         The new TR value
///
void CpuSetTR(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from CS.
///
/// @returns      The CS value.
///
CX_UINT16 CpuGetCS(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in CS.
///
/// @param[in]    Selector                         The new CS value
///
void CpuSetCS(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from DS.
///
/// @returns      The DS value.
///
CX_UINT16 CpuGetDS(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in DS.
///
/// @param[in]    Selector                         The new DS value
///
void CpuSetDS(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from SS.
///
/// @returns      The SS value.
///
CX_UINT16 CpuGetSS(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in SS.
///
/// @param[in]    Selector                         The new SS value
///
void CpuSetSS(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from ES.
///
/// @returns      The ES value.
///
CX_UINT16 CpuGetES(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in ES.
///
/// @param[in]    Selector                         The new ES value
///
void CpuSetES(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from FS.
///
/// @returns      The FS value.
///
CX_UINT16 CpuGetFS(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in FS.
///
/// @param[in]    Selector                         The new FS value
///
void CpuSetFS(
    _In_ CX_UINT16 Selector
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from GS.
///
/// @returns      The GS value.
///
CX_UINT16 CpuGetGS(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value of GS.
///
/// @param[in]    Selector                         The new GS value
///
void CpuSetGS(
    _In_ CX_UINT16 Selector
    );

///
/// @brief        CPU function primitive implemented in assembly for getting the value from RIP.
///
/// @returns      The RIP value.
///
CX_UINT64 __cdecl CpuGetRIP(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from RSP.
///
/// @returns      The RSP value.
///
CX_UINT64 __stdcall CpuGetRSP(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for getting the value from RDI.
///
/// @returns      The RDI value.
///
CX_UINT64 __stdcall CpuGetRDI(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for setting/changing the value in RSP.
///
/// @param[in]    Rsp                              The new RSP value
///
/// @returns      The old RSP value.
///
CX_UINT64 __stdcall CpuSetRSP(
    _In_ CX_UINT64 Rsp
    );


///
/// @brief        CPU function primitive implemented in assembly for GETSEC.
///
/// @param[in]    Rbx                              Capabilities index
/// @param[in]    Rax                              Parameter for GETSEC, the leaf function selected
///
/// @returns      The return value depends on the input parameters, different for every leaf function.
///
CX_UINT64 __stdcall CpuGetsec(
    _In_ CX_UINT64 Rbx,
    _In_ CX_UINT64 Rax
    );


///
/// @brief        CPU function primitive implemented in assembly for RDPKRU.
///
/// @returns      The value of PKRU
///
CX_UINT32 __stdcall CpuGetPkru(
    void
    );


///
/// @brief        CPU function primitive implemented in assembly for dividing a 128-bit integer number with a 64-bit divisor.
///
/// @param[in]    LowPartDividend                  Low part (8 bytes) of the dividend
/// @param[in]    HighPartDividend                 High part (8 bytes) of the dividend
/// @param[in]    Divisor                          The divisor in the operation (8 bytes)
/// @param[out]   Quotient                         The quotient resulting the division
///
/// @returns      The result of the division on 8 bytes
///
CX_UINT64 __cdecl CpuDiv128(
    _In_ CX_UINT64 LowPartDividend,
    _In_ CX_UINT64 HighPartDividend,
    _In_ CX_UINT64 Divisor,
    _Out_ CX_UINT64 *Quotient
    );


///
/// @brief        CPU function primitive implemented in assembly for interlocked store.
///
/// @param[in]    Dest                             Destination address
/// @param[in]    Src                              Source address
/// @param[in]    Size                             Data size (1, 2, 4, 8, 16 bytes)
///
void
CpuLockStore(
    _In_ CX_VOID *Dest,
    _In_ CX_VOID *Src,
    _In_ CX_UINT8 Size
);


///
/// @brief        CPU function primitive implemented in assembly for GETSEC capability.
///
/// @param[in]    Index                            Capability index
///
/// @returns      The capability bitmap of GETSEC
///
CX_UINT32
CpuGetSecCapabilities(
    _In_ CX_UINT64 Index
);


//
// prototypes for CPU related functions implemented in C
//

///
/// @brief        Invalidate cached mappings of address translation based on VPID, calls the routine implemented in assembly after support validation,
///               if not supported than invalidates cache by re-writing CR3.
///
/// @param[in]    Type                             The type of the invalidation
/// @param[in]    LinearAddress                    The linear address of which translation is invalidated
/// @param[in]    Vpid                             The actual VPID for which the invalidation happens
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - in case we don't have a valid VPCU
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case the type of invalidation requested is not supported
///
CX_STATUS
CpuVmxInvVpid(
    _In_ CX_UINT64 Type,
    _In_ CX_VOID *LinearAddress,
    _In_ CX_UINT64 Vpid
    );


///
/// @brief        Invalidate cached EPT mappings(TLB) with INVEPT instruction, calls the routine implemented in assembly with a built descriptor.
///
/// @param[in]    Type                             The type of the invalidation (single context or all context)
/// @param[in]    Eptp                             The EPTP describing the EPT for which the invalidation happens
/// @param[in]    Address                          The GPA targeted by the invalidation
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      ERROR_STATUS                     - in case the INVEPT failed
///
CX_STATUS
CpuVmxInvEpt(
    _In_ INVEPT_TYPE Type,
    _In_ CX_UINT64 Eptp,
    _In_ CX_UINT64 Address
    );


///
/// @brief        Verifies support of the NXE(execute-disable) feature by CPUID and activates it in the IA32_EFER_MSR if available.
///
/// @returns      CX_STATUS_SUCCESS                - in case of successful activation
/// @returns      CX_STATUS_OPERATION_NOT_SUPPORTED - in case the NXE feature is not supported
///
CX_STATUS
CpuActivateNxe(
    CX_VOID
);


//
// inline routines and intrinsic based macros
//
/// @brief It halts the CPU in case the Unload feature is not enabled
#define CpuHalt()                       {if (!CfgFeaturesUnloadOnErrorsEnabled) __halt();}

/// @brief Enable interrupts using the intrinsic function provided for this purpose
#define CpuEnableInterrupts()           {{CRITICAL("%s, %u\n", __FILE__, __LINE__);} _enable();}

/// @brief Disable interrupts using the intrinsic function provided for this purpose
#define CpuDisableInterrupts()          _disable()

/// @brief Checks if interrupts are enabled by verifying the IF flag in RFLAGS
#define CpuInterruptsAreEnabled()       ((__readeflags() & RFLAGS_IF) != 0)


///
/// @brief        Checks if the current CPU is the BSP.
///
/// @returns      TRUE if yes and FALSE otherwise
///
__forceinline
CX_BOOL
CpuIsCurrentCpuTheBsp(
    void
    )
{
    // check out Intel docs, vol 3B, "Table B-2. IA-32 Architectural MSRs"
    return (__readmsr(0x1B) & 0x100) != 0;      // IA32_APIC_BASE, bit 8
}

/// @brief Returns the CPUs initial APIC-ID using CPUID
#define HvGetInitialLocalApicIdFromCpuid CpuGetOriginalApicId

///
/// @brief        Stores the floating-point state of the VCPU (x87 + SSE + etc.), saves also the Guest XCR0 and marks it for restoration.
///               Changes the MXCSR to the Host ones.
///
/// @param[in]    Vcpu                         The VCPU for which the Floating-point state is saved
///
void
CpuSaveFloatingArea(
    _In_ VCPU *Vcpu
);


///
/// @brief        Restores the floating-point state of the VCPU (x87 + SSE + etc.) for the Guest.
///
/// @param[in]    Vcpu                         The VCPU for which the Floating-point state is saved
///
void
CpuRestoreFloatingArea(
    _In_ VCPU *Vcpu
);



///
/// @brief        Checks if the NXE (Execute-Disable) feature is used or not.
///
/// @returns      TRUE if yes and FALSE otherwise
///
CX_BOOL
CpuIsXdUsed(
    CX_VOID
);


///
/// @brief        Retrieves the PAT support from the CPU or from the boot info and stores the support for feature queries (it does only once).
///
CX_VOID
CpuInitIa32Pat(
    CX_VOID
);


///
/// @brief        If PAT is supported, then it reads its current value from MSR_IA32_PAT.
///
/// @param[out]   Pat                              Address where the value of MSR_IA32_PAT will be written
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_DATA_NOT_FOUND         - in case the PAT feature is not supported
///
CX_STATUS
CpuGetIa32Pat(
    _Out_ CX_UINT64 *Pat
);


///
/// @brief        Reads bare-metal the cpuid instruction given by Eax and Ecx and masks all features that we don't support, we want to hide or
///               by the current configuration it has to be hidden.
///
/// @param[in]    Vcpu                             The VCPU on which the cpuid was requested
/// @param[in]    InEax                            The input value for the cpuid from the EAX register, denotes the leaf number
/// @param[in]    InEcx                            The input value for the cpuid from the ECX register, denotes the secondary leaf number (optional)
/// @param[out]   Eax                              The result of the cpuid instruction which has to be returned in the EAX register for the Guest
/// @param[out]   Ebx                              The result of the cpuid instruction which has to be returned in the EBX register for the Guest
/// @param[out]   Ecx                              The result of the cpuid instruction which has to be returned in the ECX register for the Guest
/// @param[out]   Edx                              The result of the cpuid instruction which has to be returned in the EDX register for the Guest
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_PARAMETER_1    - in case Vcpu is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - in case Eax is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_5    - in case Ebx is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_6    - in case Ecx is an invalid pointer
/// @returns      CX_STATUS_INVALID_PARAMETER_7    - in case Edx is an invalid pointer
///
CX_STATUS
CpuCpuidPrimaryGuest(
    _In_ const VCPU* Vcpu,
    _In_ CX_UINT32 InEax,
    _In_ CX_UINT32 InEcx,
    _Out_ CX_UINT32 *Eax,
    _Out_ CX_UINT32 *Ebx,
    _Out_ CX_UINT32 *Ecx,
    _Out_ CX_UINT32 *Edx
);


///
/// @brief        Validates the call of the Guests xsetbv instruction, if not valid, acts according to the Intel Software Developer manual.
///
/// @param[in]    Vcpu                             The VCPU on which the exit happened
/// @param[in]    Index                            The current privilege level when the instruction was executed, it should be 0
/// @param[in]    NewXcrValue                      The new value to written in the XCR register
///
/// @returns      CX_STATUS_SUCCESS                - in case it is valid
/// @returns      STATUS_INJECT_GP                 - on any violation of the rules or on any invalid internal state (requests \#GP injection in Guest)
///
CX_STATUS
CpuIsXsetbvCallValid(
    _In_ const VCPU* Vcpu,
    _In_ CX_UINT32 Index,
    _In_ CX_UINT64 NewXcrValue
);


///
/// @brief        Initializes by CPU interrogation the max physical & virtual address width and the max pyshical address.
///
CX_VOID
CpuInitAddressWidthData(
    CX_VOID
);


///
/// @brief        Returns the max physical address width reported on the current platform.
///
__forceinline
CX_UINT8
CpuGetPhysicalAddressWidth(
    CX_VOID
)
{
    return gCpuPhysicalAddressWidth;
}


///
/// @brief        Returns the max virtual address width reported on the current platform.
///
__forceinline
CX_UINT8
CpuGetVirtualAddressWidth(
    CX_VOID
)
{
    return gCpuVirtualAddressWidth;
}


///
/// @brief        Returns the max physical address supported on the current platform.
///
__forceinline
CX_UINT64 CpuGetMaxPhysicalAddress(CX_VOID)
{
    return gCpuMaxPhysicalAddress;
}


///
/// @brief        Returns the CPU index inside the CPU Map for the CPU identified by the local APIC id.
///
/// @param[in]    LapicId                          CPUs LAPIC ID
///
/// @returns      Returns the CPU index of the CPU or it halts the system in case the local APIC id is not of any valid CPUs.
///
CX_UINT16
CpuGetBootIndexForLocalApicId(
    _In_ CX_UINT32 LapicId
    );


///
/// @brief        Stores the floating-point state of the CPU (x87 + SSE + etc.), to the given memory address.
///
/// @param[in]    SaveArea                         The address where the floating-point state of the CPU will be stored
///
void
CpuSaveFloatingState(
    _In_ CX_VOID *SaveArea
);


///
/// @brief        Restores the floating-point state of the CPU (x87 + SSE + etc.), from the given memory address.
///
/// @param[in]    SaveArea                         The address where the floating-point state of the CPU was stored
///
void
CpuRestoreFloatingState(
    _In_ CX_VOID *SaveArea
);


///
/// @brief        Computes the size of the extended state area used for storing x87 and SSE state.
///
/// @param[in]    FeatureMask                      The active features from XCR0, in order to be able to compute the exact size
///
/// @returns      The size in bytes of the XSave area
///
CX_UINT32
CpuComputeExtendedStateSize(
    _In_ CX_UINT64 FeatureMask
);


///
/// @brief        Modify "run-time" the exposed features by the CPUID instruction for any pre-defined reserved CPUID leaf.
///
/// @param[in]    InEax                            The value of the EAX, the primary leaf number
/// @param[in]    InEcx                            The value of the ECX, the secondary leaf number (CPUID_ECX_ANY in case it doesn't matter)
/// @param[in]    RegisterIndex                    An index from [0, 3] interval, denoting the register in which the exposed features
///                                                 will be changed (EAX, EBX, ECX, EDX in order)
/// @param[in]    FlagsToChange                    A Bit mask of the exact flags on which the change must be applied
/// @param[in]    Expose                           TRUE in case the feature will be exposed to the Guest, FALSE in case the future
///                                                 will be hidden from the Guest
///
void
CpuidChangePrimaryGuestExposedFeatures(
    _In_ CX_UINT32      InEax,
    _In_ CX_UINT32      InEcx,
    _In_ CX_UINT8       RegisterIndex,
    _In_ CX_UINT32      FlagsToChange,
    _In_ CX_BOOL    Expose
    );

///
/// @brief        Applies a reserved CPUID leafs mask on the values of the registers given, if the CPUID leaf is amongst the reserved onces
///
/// @param[in]    InEax                            The value of the EAX, the primary leaf number
/// @param[in]    InEcx                            The value of the ECX, the secondary leaf number (CPUID_ECX_ANY in case it doesn't matter)
/// @param[in, out]   Eax                          The address in memory where the value returned for EAX from the CPUID is stored
/// @param[in, out]   Ebx                          The address in memory where the value returned for EBX from the CPUID is stored
/// @param[in, out]   Ecx                          The address in memory where the value returned for ECX from the CPUID is stored
/// @param[in, out]   Edx                          The address in memory where the value returned for EDX from the CPUID is stored
///
void
CpuidApplyForPrimaryGuestQuery(
    _In_        CX_UINT32       InEax,
    _In_        CX_UINT32       InEcx,
    _Inout_     CX_UINT32*      Eax,
    _Inout_     CX_UINT32*      Ebx,
    _Inout_     CX_UINT32*      Ecx,
    _Inout_     CX_UINT32*      Edx
    );

///
/// @brief        Queries the CPU for the maximum number of basic and extended CPUID leafs available on the CPU.
///
/// @param[out]   MaxBasic                         It is filled with the maximum number of basic CPUID leaf for the CPU
/// @param[out]   MaxExtended                      It is filled with the maximum number of extended CPUID leaf for the CPU
///
void
CpuidCollectMaxLeafValues(
    _Out_       CX_UINT32*      MaxBasic,
    _Out_       CX_UINT32*      MaxExtended
    );


///
/// @brief        Wrapper over intrinsic function for reading from the VMCS region of the CPU.
///
/// @param[in]    VmcsFieldId                      The field id of the desired VMCS field targeted by the read
/// @param[out]   Value                            A pointer to where the read completes with the returned value
///
/// @returns      0                                - The operation succeeded.
/// @returns      1                                - The operation failed with extended status available in the VM - instruction error field of the current VMCS.
/// @returns      2                                - The operation failed without status available.
///
/// @remark       *Value is valid as long as the vmread succeeds, otherwise it's an undefined value (+result)
///
__forceinline char vmx_vmread(_In_ CX_SIZE_T VmcsFieldId, _Out_ CX_SIZE_T *Value)
{
    char result = __vmx_vmread(VmcsFieldId, Value);
    *Value += result; // *Value is valid as long as the vmread succeeds, otherwise it's an undefined value (+result)
    return result;
}


///
/// @brief        Wrapper over intrinsic function for writing to the VMCS region of the CPU.
///
/// @param[in]    VmcsFieldId                      The field id of the desired VMCS field targeted by the write
/// @param[in]    Value                            The value to be written
///
/// @returns      0                                - The operation succeeded.
/// @returns      1                                - The operation failed with extended status available in the VM - instruction error field of the current VMCS.
/// @returns      2                                - The operation failed without status available.
///
__forceinline char vmx_vmwrite(_In_ CX_SIZE_T VmcsFieldId, _In_ CX_SIZE_T Value)
{
    return __vmx_vmwrite(VmcsFieldId, Value);
}


///
/// @brief        Checks if the Msr is a known MSR.
///
/// @param[in]    Msr                              The MSR address.
///
/// @returns      TRUE if yes, FALSE otherwise.
///
CX_BOOL
CpuIsKnownMsr(
    _In_ CX_UINT32 Msr
);

#endif // _CPUOPS_H_
