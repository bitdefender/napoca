/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DEVCLEANUP_H_
#define _DEVCLEANUP_H_
#include "core.h"

typedef struct _CPU_ORIGINAL_STATE CPU_ORIGINAL_STATE;

/** @file cleanup.h
 * @brief cleanup.h - Restore the system to its original state in case of a HV failure.
 *
 * Any code that makes changes that need to be reverted in case of HV unload (on failure) should:
 * - define a state structure type (having a CLN_ORIGINAL_STATE_HEADER at the beginning)
 * - capture the original resource state inside an instance of that structure
 * - create a restore state function of type CLN_CALLBACK able to revert all changes (given an original state)
 * - call CLN_REGISTER_*_HANDLER macros to register that restore state function. The registered callback function will be
 *   automatically called in case of HV initialization failure, allowing on-the-fly unload and returning to the loader
 */

#define CLN_UNLOAD(status) ClnUnload(status)        ///< Wrapper for ClnUnload

// define YET ANOTHER method for getting a unique CPU id, this one knowing apriori what ID does the BSP have
// and is available from any code phase
#define CLN_GET_CURRENT_CPUID() ((CpuIsCurrentCpuTheBsp())? CLN_BSP_ID : HvGetInitialLocalApicIdFromCpuid()) ///< Returns the CPU ID knowing if the current processor is the BSP or not. Available in any phase of the hypervisor
#define CLN_BSP_ID              ((CX_UINT32) -1)    ///< Dummy CPU ID for the BSP


/// Register a cleanup callback to be executed on the BSP
#define CLN_REGISTER_BSP_HANDLER(CleanupFunction, OriginalStatePtr, OutOptHandlerPtr)\
    ClnRegisterCleanupHandler(CleanupFunction, OriginalStatePtr, ((1<<16)+(__LINE__))|(0xBD00000000000000ULL), OutOptHandlerPtr, CLN_BSP_ID);

/// Register a cleanup callback targeting this specific processor
#define CLN_REGISTER_SELF_HANDLER(CleanupFunction, OriginalStatePtr, OutOptHandlerPtr)\
    ClnRegisterCleanupHandler(CleanupFunction, OriginalStatePtr, ((1<<16)+(__LINE__))|(0xBD00000000000000ULL), OutOptHandlerPtr, CLN_GET_CURRENT_CPUID());

/// Wrapper for ClnUnregisterCleanupHandler
#define CLN_UNREGISTER_HANDLER(CleanupHandler)\
    ClnUnregisterCleanupHandler((CleanupHandler))

#define CLN_MAX_HANDLERS        0x200        ///< Max number of cleanup handlers supported
static_assert(CLN_MAX_HANDLERS <= UINT32_MAX, "Current cleanup.c code does not work if we have more than 2^32 handlers!");

// TODO: this should be a structure containing information returned to loaders
// right now rax is set to the value of Status instead of pointing to the whole structure
typedef struct _CLN_UNLOAD_CONTEXT
{
    CX_STATUS Status;
}UNLOAD_CONTEXT;

typedef struct _CLN_ORIGINAL_STATE_HEADER
{
    CX_BOOL IsValid;
}CLN_ORIGINAL_STATE_HEADER;                     ///< Each programmed/changed physical device MUST have some kind of 'original state'


typedef CX_VOID CLN_ORIGINAL_STATE;             ///< Cleanup Original State dummy definition


typedef CX_VOID CLN_CONTEXT;                    ///< Informational context sent to registered cleanup callbacks about what happened

/**
 * @brief   Definition of a cleanup function for hardware changes done on some programmed device.
*/
typedef CX_STATUS (*CLN_CALLBACK)(
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_opt_ CLN_CONTEXT *Context
    );


typedef struct _CLN_HANDLER
{
    CX_UINT64 OriginatorId;                     ///< Informational field used for tracking tempered devices
    CLN_ORIGINAL_STATE *OriginalState;          ///< What state to restore, device dependent
    CLN_CALLBACK CleanupFunction;               ///< What function should be used to restore that state
    CX_UINT64 Flags;                            ///< Additional information
    CX_UINT32 CpuId;                            ///< Which CPU should do the cleanup, to avoid BSP ID confusions we're using (CX_UINT32) -1 for BSP
}CLN_HANDLER;                                   ///< Data saved on a stack. Defining the required steps, in correct order, for cleaning up any HV performed hardware state changes

/**
 * @brief Initializes the clenup mechanism.
 */
CX_VOID
ClnInitialize(
    CX_VOID
    );

/**
 * @brief Registers a cleanup handler used in case of a HV unload.
 *
 * Push the CLN_ORIGINAL_STATE on a cleanup stack.
 * Any code that makes changes that need to be reverted in case of HV unload should be registering such a callback
 *
 * @param[in]      CleanupFunction       The cleanup callback for reverting the required changes
 * @param[in]      OriginalState         What state to restore, device dependent, begins with a CLN_ORIGINAL_STATE_HEADER
 * @param[in]      OriginatorId          Information about what code registered the handler
 * @param[in,out]  Handler               Optionally returns a pointer to where the handler was saved
 * @param[in]      CpuId                 Which Cpu should do the cleanup
 *
 * @returns CX_STATUS_SUCCESS            Always. The cleanup registration completed successfully
 */
CX_STATUS
ClnRegisterCleanupHandler(
    _In_ CLN_CALLBACK CleanupFunction,
    _In_ CLN_ORIGINAL_STATE *OriginalState,
    _In_ CX_UINT64 OriginatorId,
    _Out_opt_ CLN_HANDLER **Handler,
    _In_ CX_UINT32 CpuId
    );

 /**
  * @brief Removes a cleanup handler.
  *
  * Removes a cleanup handler from the cleanup handlers list.
  *
  * @param[in]       ClnHandler              Address of the cleanup handler to be removed.
  *
  * @returns CX_STATUS_SUCCESS               If the handle was successfully removed
  * @returns CX_STATUS_INVALID_PARAMETER_1   If the ClnHandler does not match any available cleanup handlers
  */
CX_STATUS
ClnUnregisterCleanupHandler(
    _In_ _Post_invalid_ CLN_HANDLER*    ClnHandler
    );

/**
 * @brief Lock and retrieve a pointer to an already registered handler for performing additional manipulation.
 *
 * Retrieves a cleanup handler, identified by the OriginatorId, CpuId pair.
 * If LockAlreadyOwned is TRUE, acquires the gClnLock until a ClnUnlockApCleanupHandler is performed.
 * Potential deadlock may occur if used incorrectly!
 *
 * @param[in]       OriginatorId            The id of the handler to be updated. The pair OriginatorId, CpuId uniquely identify the handler to be updated.
 * @param[in]       CpuId                   The cpu id to which the handler is assigned. The pair OriginatorId, CpuId uniquely identify the handler to be updated.
 * @param[in,out]   Handler                 If not null, returns the address of the handler to be updated.
 * @param[in]       LockAlreadyOwned        If FALSE the gClnLock will not be acquired, otherwise it will try to lock.
 *
 * @returns CX_STATUS_SUCCESS               If the handle retrival succeeded
 * @returns CX_STATUS_DATA_NOT_FOUND        If no handler determined by the pair OriginatorId, CpuId exists
 */
CX_STATUS
ClnLockApCleanupHandler(
    _In_ CX_UINT64 OriginatorId,
    _In_ CX_UINT32 CpuId,
    _Out_opt_ CLN_HANDLER **Handler,
    _In_ CX_BOOL LockAlreadyOwned
    );

/**
 * @brief Release the lock taken via ClnLockApCleanupHandler.
 *
 * @param[in]       OriginatorId            Unused
 * @param[in]       CpuId                   Unused
 * @param[in]       LockAlreadyOwned        If TRUE will release the gClnLock, otherwise CX_STATUS_SUCCESS is returned
 *
 * @returns CX_STATUS_SUCCESS               If the gClnLock was successfully released
 */
CX_STATUS
ClnUnlockApCleanupHandler(
    _In_ CX_UINT64 OriginatorId,
    _In_ CX_UINT32 CpuId,
    _In_ CX_BOOL LockAlreadyOwned
    );

/**
 * @brief User-level routine for triggering the unload process.
 *
 * Don't use ClnUnload directly but instead call CLN_UNLOAD as the parameters are expected to change.
 *
 * @param[in]       StatusToReturn              Status returned to the loader
 *
 * @returns Should never return. Instead it should reboot/halt the processor.
 */
CX_STATUS
ClnUnload(
    _In_ CX_STATUS StatusToReturn
    );

extern volatile CX_UINT64 gClnAlreadyInitialized;   ///< Lock for avoiding reinitialization of the cleanup mechanism
extern volatile CX_UINT32 gClnNumberOfExitedCpus;   ///< Number of cpus that finished the cleanup process

#pragma pack(push)
#pragma pack(8)
typedef struct _MSR_INDEX_VALUE_PAIR
{
    QWORD                   Value;
    DWORD                   Index;
    DWORD                   __padding;
} MSR_INDEX_VALUE_PAIR;             ///< Tuple containing the index and value of a Msr.

#define MAX_MSRS_TO_RESTORE     1   ///< Maximum number of msr that can be held in a MSR_RESTORE_VALUES list

typedef struct _MSR_RESTORE_VALUES
{
    DWORD                   MaxArrayElements;
    DWORD                   CurentArrayElements;
    MSR_INDEX_VALUE_PAIR    Msrs[MAX_MSRS_TO_RESTORE];
} MSR_RESTORE_VALUES;               ///< List of Msr values used during cleanup.

// CPU ORIGINAL_STATE definition, used for unloading the HV
typedef struct _CPU_ORIGINAL_STATE
{
    CLN_ORIGINAL_STATE_HEADER   Header;
    LD_BOOT_CONTEXT             *LoaderBootContext;
    QWORD                       OriginatorId;
    QWORD                       Flags;
    MSR_RESTORE_VALUES          Msrs;
}CPU_ORIGINAL_STATE;                ///< The original boot state of the system at which the hardware will be restored during cleanup.
#pragma pack(pop)

/**
 * @brief Add a new entry in a structure of type key = msr value = value (msr) to be used in case of a state restoration.
 *
 * @param[in,out]   MsrValues                   The address for the dictionary
 * @param[in]       MsrIndex                    The key in the dictionary
 * @param[in]       MsrValue                    The value for the given key
 *
 * @returns CX_STATUS_SUCCESS                   The MsrIndex, MsrValue pair was added successfully.
 * @returns CX_STATUS_INVALID_PARAMETER_1       The given MsrValues dictionary address is null.
 * @returns CX_STATUS_DATA_BUFFER_TOO_SMALL     The dictionary is full.
 */
CX_STATUS
ClnAddMsrToRestoreArea(
    _Inout_     MSR_RESTORE_VALUES   *MsrValues,
    _In_        CX_UINT32            MsrIndex,
    _In_        CX_UINT64            MsrValue
);

/**
 * @brief Restore the CPU state to a consistent one, required for the code flow to return to loader for chain un-loading the hypervisor.
 *
 * @param[in,out]   OriginalState                   The state to be restored
 * @param[in]       Context                         The reason for unloading the hypervisor
 *
 * @returns CX_STATUS_SUCCESS                       Should not return.
 */
CX_STATUS
ClnCpuRestoreState(
    _In_ CPU_ORIGINAL_STATE   *OriginalState,
    _In_opt_ CLN_CONTEXT      *Context
);

#endif
