/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _HOOKS_H_
#define _HOOKS_H_

/// \addtogroup hooks
/// @{

#include "kernel/emu.h"

typedef struct _GUEST GUEST;
typedef struct _VCPU VCPU;

/// @brief Initialize the data for the hook tables(I/O, MSR, EPT)
///
/// @param[in]  Guest           The guest for which the hook will be set
///
/// @returns    CX_STATUS_SUCCESS                   - Always
CX_STATUS
HkPreinitGuestHookTables(
    _In_ GUEST* Guest
    );

//
// I/O port hook support
//

#define MAX_IO_HOOKS                    1024 ///< The maximum number of allowed I/O hooks at once

/// @brief The callback prototype for read operations on a hooked I/O port
///
/// @param[in]  IoPort          The exact port on which the read was intended to be executed
/// @param[in]  Length          The length of the operation (1, 2 or 4 bytes)
/// @param[out] Value           The value that will be seen by the guest
/// @param[in] Context          An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevReadIoPort)(_In_ CX_UINT16 IoPort, _In_ CX_UINT8 Length, _Out_ CX_UINT8 *Value, _In_opt_ CX_VOID* Context);
/// @brief The callback prototype for write operations on a hooked I/O port
///
/// @param[in] IoPort           The exact port on which the write was intended to be executed
/// @param[in] Length           The length of the operation (1, 2 or 4 bytes)
/// @param[in] Value            The value that the guest intended to write
/// @param[in] Context          An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevWriteIoPort)(_In_ CX_UINT16 IoPort, _In_ CX_UINT8 Length, _In_ CX_UINT8 *Value, _In_opt_ CX_VOID* Context);

/// @brief All the relevant information about an I/O hook
typedef struct _GUEST_IO_HOOK {
    CX_VOID* Context;             ///< The optional, generic argument that was passed when registering the callback
    PFUNC_DevReadIoPort ReadCb;   ///< The callback to be called in case of a read operation
    PFUNC_DevWriteIoPort WriteCb; ///< The callback to be called in case of a write operation
    CX_UINT16 Port;               ///< The starting I/O port hooked
    CX_UINT16 MaxPort;            ///< The last I/O port hooked
    CX_UINT32 Flags;              ///< Currently unused
} GUEST_IO_HOOK;

/// @brief I/O hook table
typedef struct _GUEST_IO_HOOK_TABLE {
    GUEST_IO_HOOK Hook[MAX_IO_HOOKS]; ///< I/O hooks, always sorted
    CX_UINT32 Count;                  ///< I/O hook count
    RW_SPINLOCK Lock;                 ///< The I/O hook lock
} GUEST_IO_HOOK_TABLE;


/// @brief Sets read and/or write callbacks for the hypervisor to call when intercepts a read and/or write on the given I/O port
///
/// The hook will be set for every VCPU. Hooks can not be overlapping. It's contention safe.
///
/// @param[in]  Guest           The guest for which the hook will be set
/// @param[in]  BasePort        The starting I/O port to be hooked
/// @param[in]  MaxPort         The last I/O port to be hooked
/// @param[in]  Flags           Currently unused
/// @param[in]  ReadCb          The callback to be called in case of a read operation over the [BasePort, MaxPort] I/O port range, optional if the WriteCb is set
/// @param[in]  WriteCb         The callback to be called in case of a write operation over the [BasePort, MaxPort] I/O port range, optional if the ReadCb is set
/// @param[in]  Context         An optional, generic argument that'll passed to the callback upon calling them
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is set
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - MaxPort can not be bigger then BasePort
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - ReadCb and WriteCb can not be both CX_NULL
/// @returns    STATUS_TOO_MANY_HOOKS               - The amount of hooks set reached the maximum supported value
/// @returns    STATUS_HOOK_ALREADY_SET             - At least one port from the [BasePort, MaxPort] I/O port range is already hooked
/// @returns    STATUS_HOOK_ALREADY_SET_GLOBAL      - At least one port from the [BasePort, MaxPort] I/O port range is already intercepted globally
///
CX_STATUS
HkSetIoHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT16 BasePort,
    _In_ CX_UINT16 MaxPort,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadIoPort ReadCb,
    _In_ PFUNC_DevWriteIoPort WriteCb,
    _In_opt_ CX_VOID* Context
    );

/// @brief Removes an already set hook, based on the BasePort of it
///
/// The hook will be removed from every VCPU. It's contention safe.
///
/// @param[in]  Guest           The guest for which the hook will be removed
/// @param[in]  BasePort        The I/O port based on which the hook will be identified
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is removed
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be CX_NULL
/// @returns    CX_STATUS_DATA_NOT_FOUND            - Can not find any hooks based on the given BasePort I/O port
///
CX_STATUS
HkRemoveIoHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT16 BasePort
    );

/// @brief Calls the I/O port hook set with HkSetIoHook()
///
/// It's contention safe. The synchronization of the callbacks is the role of the hook setter.
///
/// @param[in]  Vcpu            The VCPU for which the callback will be called
/// @param[in]  Port            The I/O port for which the callback will be called
/// @param[in]  ExitQual        The full exit qualification value from the VMCS of the given VCPU
/// @param[out] IoHook          Optionally returns a copy of the complete I/O hook structure identified based on the Port
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the callback was called
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Vcpu can not be CX_NULL or the given Vcpu is invalid
/// @returns    STATUS_NO_HOOK_MATCHED              - No hook found for the given I/O port
/// @returns    STATUS_NEEDS_EMULATION              - The operation needs to be emulated inside of the guest (REP prefix, callback can return this status)
/// @returns    STATUS_EXECUTE_ON_BARE_METAL        - The operation needs to be executed on the hardware inside of the host (callback can return this status)
/// @returns    OTHER                               - Any other internal issue returned by the callbacks
///
CX_STATUS
HkCallIoHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT16 Port,
    _In_ CX_UINT64 ExitQual,
    __out_opt GUEST_IO_HOOK* IoHook
    );


//
// MSR hook support
//
#define MAX_MSR_HOOKS                   256 ///< The maximum number of MSR hooks supported

/// @brief The callback prototype for read operations on a hooked MSR
///
/// @param[in]  Msr             The exact MSR on which the read was intended to be executed
/// @param[out] Value           The value that will be seen by the guest
/// @param[in] Context          An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevReadMsr)(_In_ CX_UINT64 Msr, _Out_ CX_UINT64 *Value, _In_opt_ CX_VOID* Context);
/// @brief The callback prototype for write operations on a hooked MSR
///
/// @param[in]  Msr             The exact MSR on which the write was intended to be executed
/// @param[in]  Value           The value that the guest intended to write
/// @param[in]  Context         An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevWriteMsr)(_In_ CX_UINT64 Msr, _In_ CX_UINT64 Value, _In_opt_ CX_VOID* Context);

/// @brief All the relevant information about a MSR hook
typedef struct _GUEST_MSR_HOOK {
    CX_VOID* Context;          ///< The optional, generic argument that was passed when registering the callback
    PFUNC_DevReadMsr ReadCb;   ///< The callback to be called in case of a read operation
    PFUNC_DevWriteMsr WriteCb; ///< The callback to be called in case of a write operation
    CX_UINT32 Msr;             ///< The starting MSR hooked
    CX_UINT32 MaxMsr;          ///< The last MSR hooked
    CX_UINT32 Flags;           ///< Currently unused
} GUEST_MSR_HOOK;

/// @brief MSR hook table
typedef struct _GUEST_MSR_HOOK_TABLE {
    GUEST_MSR_HOOK Hook[MAX_MSR_HOOKS]; ///< MSR hooks, always sorted
    CX_UINT32 Count;                    ///< MSR hook count
    RW_SPINLOCK Lock;                   ///< The MSR hook lock
} GUEST_MSR_HOOK_TABLE;

/// @brief Sets read and/or write callbacks for the hypervisor to call when intercepts a read and/or write on the given MSR
///
/// The hook will be set for every VCPU. Hooks can not be overlapping. It's contention safe.
///
/// @param[in]    Guest           The guest for which the hook will be set
/// @param[in]    BaseMsr         The staring MSR to be hooked
/// @param[in]    MaxMsr          The last MSR to be hooked
/// @param[in]    Flags           Currently unused
/// @param[in]    ReadCb          The callback to be called in case of a read operation over the [BaseMsr, MaxMsr] MSR range, optional if the WriteCb is set
/// @param[in]    WriteCb         The callback to be called in case of a write operation over the [BaseMsr, MaxMsr] MSR range, optional if the ReadCb is set
/// @param[in]    Context         An optional, generic argument that'll passed to the callback upon calling them
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is set
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - MaxMsr can not be bigger then BaseMsr
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - ReadCb and WriteCb can not be both CX_NULL
/// @returns    STATUS_TOO_MANY_HOOKS               - The amount of hooks set reached the maximum supported value
/// @returns    STATUS_HOOK_ALREADY_SET             - At least one MSR from the [BaseMsr, MaxMsr] MSR range is already hooked
CX_STATUS
HkSetMsrHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT32 BaseMsr,
    _In_ CX_UINT32 MaxMsr,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadMsr ReadCb,
    _In_ PFUNC_DevWriteMsr WriteCb,
    _In_opt_ CX_VOID* Context
    );

/// @brief Calls the MSR hook set with HkSetMsrHook
///
/// It's contention safe. The synchronization of the callbacks is the role of the hook setter.
///
/// @param[in]     Vcpu            The VCPU for which the callback will be called
/// @param[in]     Msr             The MSR for which the callback will be called
/// @param[in]     ItIsWrite       CX_FALSE if the read callback should be called, otherwise the write callback should be called
/// @param[in,out] Value           The value read/to write in the Msr
/// @param[out]    MsrHook         Optionally returns a copy of the complete MSR hook structure identified based on the Msr
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the callback was called
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Vcpu can not be CX_NULL or the given Vcpu is invalid
/// @returns    CX_STATUS_INVALID_PARAMETER_4       - Value can not be CX_NULL
/// @returns    STATUS_NO_HOOK_MATCHED              - No hook found for the given I/O port
/// @returns    STATUS_NEEDS_EMULATION              - The operation needs to be emulated inside of the guest (callback can return this status)
/// @returns    STATUS_EXECUTE_ON_BARE_METAL        - The operation needs to be executed on the hardware inside of the host (callback return this status)
/// @returns    OTHER                               - Any other internal issue returned by the callbacks
///
CX_STATUS
HkCallMsrHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT32 Msr,
    _In_ CX_BOOL ItIsWrite,
    _Inout_ CX_UINT64 *Value,
    __out_opt GUEST_MSR_HOOK* MsrHook
    );


//
// EPT hook support
//
#define MAX_EPT_HOOKS                   1024 ///< The maximum number of EPT hook supported

/// @brief The callback prototype for read operations on a hooked GPA
///
/// @param[in]  Address         The exact address on which the read was intended to be executed
/// @param[in]  Length          The length of the operation (1, 2, 4, 8 or 16 bytes)
/// @param[out] Value           The value that will be seen by the guest
/// @param[in]  Context         An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevReadMem)(CX_UINT64 Address, _In_ CX_UINT32 Length, _Out_ CX_UINT8 *Value, _In_opt_ CX_VOID* Context);
/// @brief The callback prototype for write operations on a hooked GPA
///
/// @param[in] Address          The exact address on which the write was intended to be executed
/// @param[in] Length           The length of the operation (1, 2, 4, 8 or 16 bytes)
/// @param[in] Value            The value that the guest intended to write
/// @param[in] Context          An optional, generic argument that was registered when setting the hook
typedef CX_STATUS (*PFUNC_DevWriteMem)(_In_ CX_UINT64 Address, _In_ CX_UINT32 Length, _In_ CX_UINT8 *Value, _In_opt_ CX_VOID* Context);

/// @brief All the relevant information about an EPT hook
typedef struct _GUEST_EPT_HOOK {
    CX_VOID* Context;          ///< The optional, generic argument that was passed when registering the callback
    PFUNC_DevReadMem ReadCb;   ///< The callback to be called in case of a read operation
    PFUNC_DevWriteMem WriteCb; ///< The callback to be called in case of a write operation
    CX_UINT64 BaseAddress;     ///< The first address hooked
    CX_UINT64 MaxAddress;      ///< The last address hooked
    CX_UINT32 Flags;           ///< Currently unused
} GUEST_EPT_HOOK;

/// @brief EPT hook table
typedef struct _GUEST_EPT_HOOK_TABLE {
    GUEST_EPT_HOOK Hook[MAX_EPT_HOOKS]; ///< EPT hooks, always sorted
    CX_UINT32 Count;                    ///< EPT hook count
    RW_SPINLOCK Lock;                   ///< The EPT hook lock
} GUEST_EPT_HOOK_TABLE;

/// @brief Sets read and/or write callback for the hypervisor to call when intercepts a read and/or write on the given memory range
///
/// The hook will be set for every VCPU. Hooks can not be overlapping. It's contention safe. Hooks for execute are not supported.
/// The BaseAddress and MaxAddress will be "rounded" to CX_PAGE_SIZE_4K if needed
/// Invalidation will be done automatically, if needed
///
/// @param[in] Guest           The guest for which the hook will be set
/// @param[in] BaseAddress     The starting address to be hooked
/// @param[in] MaxAddress      The last address to be hooked
/// @param[in] Flags           Currently unused
/// @param[in] ReadCb          The callback to be called in case of a read operation over the [BaseAddress, MaxAddress] memory range, optional if the WriteCb is set
/// @param[in] WriteCb         The callback to be called in case of a write operation over the [BaseAddress, MaxAddress] memory range, optional if the ReadCb is set
/// @param[in] Context         An optional, generic argument that'll passed to the callback upon calling them
///
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is set
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be CX_NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - MaxAdress can not be bigger then BaseAddress
/// @returns    CX_STATUS_INVALID_PARAMETER_5       - ReadCb and WriteCb can not be both CX_NULL
/// @returns    STATUS_TOO_MANY_HOOKS               - The amount of hooks set reached the maximum supported value
/// @returns    STATUS_HOOK_ALREADY_SET             - At least one PAGE out of the [BaseAddress, MaxAddress] memory range is hook already set
/// @returns    OTHER                               - Any other internal issue returned by the callbacks
CX_STATUS
HkSetEptHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT64 BaseAddress,
    _In_ CX_UINT64 MaxAddress,
    _In_ CX_UINT32 Flags,
    _In_ PFUNC_DevReadMem ReadCb,
    _In_ PFUNC_DevWriteMem WriteCb,
    _In_opt_ CX_VOID* Context
    );

/// @brief Calls the EPT hook set with HkSetEptHook
///
/// @param[in]  Vcpu            The VCPU for which the callback will be called
/// @param[in]  Address         The address based on which the callback will be identified
/// @param[out] EptHook         Optionally return a copy of the complete EPT hook structure
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Vcpu can not be CX_NULL or the given Vcpu is invalid
/// @returns    STATUS_NO_HOOK_MATCHED              - No hook found for the given address
/// @returns    STATUS_NEEDS_EMULATION              - The operation needs to be emulated inside of the guest
CX_STATUS
HkCallEptHook(
    _In_ VCPU* Vcpu,
    _In_ CX_UINT64 Address,
    __out_opt GUEST_EPT_HOOK* EptHook
    );


///
/// BIOS
///

#define MAX_BIOS_HOOKS                  32 ///< The maximum number of BIOS interrupts we can hook

#pragma pack(push, 1)
typedef CX_STATUS (*__HK_BIOS_HOOK_HANDLER) (_In_ CX_VOID *Hook, _In_ VCPU* Vcpu, _In_ CX_BOOL IsPostHook);
/// @brief All the relevant information about an IVT hook
typedef struct _BIOS_INT_HOOK
{
    CX_UINT8 InterruptNumber;       ///< The IVT index
    CX_UINT16 OldSegment;           ///< The segment before the hook
    CX_UINT16 OldOffset;            ///< The offset before the hook
    CX_UINT32 InGuestHookAddress;   ///< The address of the hook
    __HK_BIOS_HOOK_HANDLER Handler; ///< The callback that'll be called if the hook is triggered
    CX_UINT64 GuestIndex;           ///< The index of the guest for which the hook was set
}BIOS_INT_HOOK;
#pragma pack(pop)

/// @brief The callback prototype for any IVT hook
///
/// @param[in] Hook             The internal hook structure
/// @param[in] Vcpu             The VCPU on which the guest's INT was interrupted
/// @param[in] IsPostHook       TRUE if the hook is a post hook
typedef CX_STATUS (*HK_BIOS_HOOK_HANDLER) (_In_ BIOS_INT_HOOK *Hook, _In_ VCPU* Vcpu, _In_ CX_BOOL IsPostHook);

/// @brief Initialize everything BIOS hook related
///
/// @param[in] Guest            The guest for which the hooking will be initialized
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_SUCCESS                   - Everything was initialized
/// @returns    OTHER                               - Internal error
CX_STATUS
HkInitBiosHooks(
    _In_ GUEST* Guest
    );

/// @brief Set a hook for a given entry in the IVT
///
/// @param[in]  Guest           The guest for which the hook will be set
/// @param[in]  InterruptNumber The entry index in the IVT for which the hook will be set
/// @param[in]  Handler         The callback that'll be called in case the given INT is called by the guest
/// @param[out] Hook            Optionally return the hook that was set
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_3       - Handler can not be NULL
/// @returns    CX_STATUS_NOT_INITIALIZED           - A prerequisite was not met
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is set
/// @returns    CX_STATUS_INSUFFICIENT_RESOURCES    - Too many hooks
/// @returns    OTHER                               - Internal error
CX_STATUS
HkSetBiosHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT8 InterruptNumber,
    _In_ HK_BIOS_HOOK_HANDLER Handler,
    __out_opt BIOS_INT_HOOK **Hook
    );

/// @brief Remove a hook for a given entry in the IVT
///
/// @param[in] Guest           The guest for which the hook will be removed
/// @param[in] Hook            The hook that should be removed
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_INVALID_PARAMETER_2       - Hook can not be NULL
/// @returns    CX_STATUS_NOT_INITIALIZED           - A prerequisite was not met
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook is removed
CX_STATUS
HkRemoveBiosHook(
    _In_ GUEST* Guest,
    _In_ BIOS_INT_HOOK *Hook
    );

/// @brief Get a hook for a given linear address
///
/// @param[in]  Guest                    The guest for which the hook will be queried
/// @param[in]  LinearInstructionAddress The linear address based on what the hook will be searched, must take cs(base) intro account
/// @param[out] Hook                     The searched hook, if found
/// @param[out] IsPostHook               TRUE if the hook is post-hook, FALSE otherwise
///
/// @returns    CX_STATUS_INVALID_PARAMETER_1       - Guest can not be NULL
/// @returns    CX_STATUS_DATA_NOT_FOUND            - No hook was found
/// @returns    CX_STATUS_SUCCESS                   - Everything went as expected, the hook was found
CX_STATUS
HkGetBiosHook(
    _In_ GUEST* Guest,
    _In_ CX_UINT64 LinearInstructionAddress,
    __out_opt BIOS_INT_HOOK **Hook,
    __out_opt CX_BOOL *IsPostHook
    );

/// @}

#endif // _HOOKS_H_
