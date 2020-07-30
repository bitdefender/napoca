/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// \addtogroup ipc
/// @{

/**
* @file queue_ipc_common.h
* @brief Common declarations needed for handling inter-processor communication, declarations needed at a global scope (throughout the whole project)
*/

#ifndef _QUEUE_IPC_COMMON_h_
#define _QUEUE_IPC_COMMON_h_

#include "core.h"
#include "common/kernel/cpudefs.h"

struct _IPC_MESSAGE;
struct _CPU_IPC_QUEUE;

typedef struct _HV_TRAP_FRAME HV_TRAP_FRAME;


//
// Introduce the IRQL notion and its API
//

typedef enum
{
    // This needs to be kept ordered from the lowest priority to the highest
    IPC_PRIORITY_LOWEST = 0,
    IPC_PRIORITY_IPI = 0,

    // From here on, all remaining priorities are handled without locks, and can't be masked (otherwise, it should be lower)
    IPC_PRIORITY_NONBLOCKING_LEVEL = 1,
    IPC_PRIORITY_EPT_INVLD = 1,
    IPC_PRIORITY_TLB_INVLD = 2,
}IPC_PRIORITY;


#define IPC_PRIORITY_TOTAL_DISTINCT_LEVELS 3    ///< Number of IPC priority levels

typedef union
{
    struct
    {
        BYTE Priority : 7;
        BYTE Enabled : 1;
    };
    BYTE Raw;
}IPC_STATE;     ///< IPC mechanism internal state

/**
 * @brief           Changes the priority and state of the current cpu's IPC mechanism
 *
 * @param[in]       DoSetEnabledValue                   Determines if the final IPC Enable state will be modified or not
 * @param[in]       IpcEnabled                          If DoSetEnabledValue is TRUE, this field configures the Enable/Disable state of the IPC
 * @param[in]       DoSetIpcPriorityValue               Determines if the IPC priority should be modified
 * @param[in]       NewIpcPriority                      If DoSetIpcPriorityValue is TRUE, this field configures the new IPC priority. Determines the type of messages allowed to be processed
 *
 * @return          Returns the current cpu's old IPC state
 */
IPC_STATE
IpcSetPriority(
    _In_ BOOLEAN DoSetEnabledValue,
    _In_ BOOLEAN IpcEnabled,
    _In_ BOOLEAN DoSetIpcPriorityValue,
    _In_ IPC_PRIORITY NewIpcPriority
);

IPC_STATE
IpcGetState(
    VOID
);



//
// Introduce a generic/broad concept of interruptibility and related API
//


#define PROCESS_IPCS()      IpcProcessCpuMessages()     ///< Wrapper over IpcProcessCpuMessages method

/**
 * @brief           Weak (but fast) xorshift pseudo-random algorithm with a 2^32 - 1 period
 * @brief           Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
 *
 * @returns         A random 32-bit value
 */
__forceinline
DWORD
FastRand(
    VOID
)
{
    // A large ~2^31 prime value
    static volatile DWORD state = 2038074743;

    DWORD x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    state = x;
    return x;
}

#define PROCESS_IPC_RATIO_TO_CPU_YIELD (1 << 6)     ///< Must be a power of two!
                                                    ///< This will delay processing the queue at most 16.8 times, when none of a max of 1076 consecutive rand values
                                                    ///< are multiple of 64 (happening once in every 33*10^6 queue drainings)

#define CpuYield()      ( ((0 == (FastRand() & (PROCESS_IPC_RATIO_TO_CPU_YIELD - 1))) && PROCESS_IPCS()), (_mm_pause(), 0))     ///< Algorithm for yelding CPU. Try to process the IPC queue once in a while, otherwise simply pause the cpu.

typedef enum
{
    IPC_INTERRUPTS_DISABLED = 0,    ///< Interrupts are not available on the system
    IPC_INTERRUPTS_ENABLED = 1      ///< Interrupts are available
}IPC_INTERRUPTS;

typedef enum
{
    IPC_DISABLED = 0,       ///< IPC system is disabled and low priority messages won't be processed
    IPC_ENABLED = 1         ///< IPC system is enabled, low priority messages can be processed
}IPC;

typedef struct _IPC_INTERRUPTIBILITY
{
    DWORD InterruptsEnabledValue : 1;
    DWORD TprValue : 4;
    DWORD IpcEnabledValue : 1;
    DWORD IpcPriorityValue : 7;
    DWORD Reserved : 19;
}IPC_INTERRUPTIBILITY, IPC_INTERRUPTIBILITY_ORIG_VALUE;


typedef struct _IPC_INTERRUPTIBILITY_STATE
{
    DWORD InterruptsEnabledSelected : 1;
    DWORD IpcEnabledSelected : 1;
    DWORD IpcPrioritySelected : 1;

    DWORD InterruptsEnabledValue : 1; // IPC_INTERRUPTS

    DWORD IpcEnabledValue : 1;
    DWORD IpcPriorityValue : 7;

    DWORD Reserved : 11;
    DWORD Ignored : 4;  // can be used for other purposes
}IPC_INTERRUPTIBILITY_STATE;

__forceinline
CX_STATUS
IpcProcessCpuMessages(
    CX_VOID
);

/**
 * @brief           Configures IPC system and the interrupt flag state
 *
 * @returns         Returns a snapshot of the old values combined with the selection mask describing the modified fields
 */
__forceinline
IPC_INTERRUPTIBILITY_STATE
IpcSetInterruptibilityState(
    IPC_INTERRUPTIBILITY_STATE NewState
)
{
    IPC_INTERRUPTIBILITY_STATE oldInt;
    QWORD origFlags = __readeflags();

    // If we supress interrupts in the current system, the IPC system is not functional
    oldInt.InterruptsEnabledValue = ((origFlags & RFLAGS_IF) ? IPC_INTERRUPTS_ENABLED : IPC_INTERRUPTS_DISABLED);

    // Get the current IPC state (enable state and message priority state) if
    // no changes will be performed on it
    if (!NewState.IpcPrioritySelected && !NewState.IpcEnabledSelected)
    {
        IPC_STATE ipcState = IpcGetState();
        oldInt.IpcPriorityValue = ipcState.Priority; // otherwise it's captured below
        oldInt.IpcEnabledValue = ipcState.Enabled;
    }

    // Set a new IPC state
    if (NewState.InterruptsEnabledSelected || NewState.IpcPrioritySelected)
    {
        // First, disable interrupts while working on any values
        __writeeflags(origFlags & ~RFLAGS_IF);

        // Set relevant fields
        if (NewState.IpcPrioritySelected || NewState.IpcEnabledSelected)
        {
            IPC_STATE oldIpcState = IpcSetPriority(
                (BOOLEAN)NewState.IpcEnabledSelected,
                (BYTE)NewState.IpcEnabledValue,
                (BOOLEAN)NewState.IpcPrioritySelected,
                (BYTE)NewState.IpcPriorityValue);

            oldInt.IpcPriorityValue = oldIpcState.Priority;
            oldInt.IpcEnabledValue = oldIpcState.Enabled;
        }

        // Set new IF or just restore the original IF
        if (NewState.InterruptsEnabledSelected)
        {
            __writeeflags((origFlags & ~RFLAGS_IF) | (FALSE && NewState.InterruptsEnabledValue ? RFLAGS_IF : 0));
        }
        else
        {
            __writeeflags(origFlags);
        }
    }

    oldInt.InterruptsEnabledSelected = NewState.InterruptsEnabledSelected;
    oldInt.IpcEnabledSelected = NewState.IpcEnabledSelected;
    oldInt.IpcPrioritySelected = NewState.IpcPrioritySelected;

    return oldInt;
}

/**
 * @brief           Wrapper function over IpcSetInterruptibilityState. Creates a new IPC_INTERRUPTIBILITY_STATE based on the input parameters and assigns it to the system.
 *
 * @param[in]       DoSetInterrupts                     Determines if the Interrupt Flag in RFLAGS should be changed.
 * @param[in]       NewInterruptsEnabledValue           If DoSetInterrupts is TRUE, determines the final value of Interupt Flag in RFLAGS.
 * @param[in]       DoSetIpcEnabled                     Determines if the Enable state value of the IPC system should be changed.
 * @param[in]       NewIpcEnabledValue                  If DoSetIpcEnabled is TRUE, determines the value of the IPC Enable state.
 * @param[in]       DoSetIpcPriority                    Determines if the IPC Priority state should be changed.
 * @param[in]       NewIpcPriorityValue                 If DoSetIpcPriority is TRUE, determines the value of the IPC Priority.
 *
 * @returns         Returns a snapshot of the old values combined with the selection mask describing the modified fields
 */
__forceinline
IPC_INTERRUPTIBILITY_STATE
IpcSetInterruptibilityValues(
    _In_ BOOLEAN DoSetInterrupts,
    _In_ IPC_INTERRUPTS NewInterruptsEnabledValue,
    _In_ BOOLEAN DoSetIpcEnabled,
    _In_ BYTE NewIpcEnabledValue,
    _In_ BOOLEAN DoSetIpcPriority,
    _In_ BYTE NewIpcPriorityValue
)
{
    IPC_INTERRUPTIBILITY_STATE newInt = { 0 };

    newInt.InterruptsEnabledSelected = DoSetInterrupts;
    newInt.IpcEnabledSelected = DoSetIpcEnabled;
    newInt.IpcPrioritySelected = DoSetIpcPriority;

    newInt.InterruptsEnabledValue = NewInterruptsEnabledValue;
    newInt.IpcEnabledValue = NewIpcEnabledValue;
    newInt.IpcPriorityValue = NewIpcPriorityValue;
    return IpcSetInterruptibilityState(newInt);
}

#define IPC_INTERRUPTIBILITY_ALLOW_ALL gInterruptibilityAllowAll                                ///< Enabled and all interrupts&messages accepted
#define IPC_INTERRUPTIBILITY_BLOCK_ALL gInterruptibilityBlockAll                                ///< Stop every message type from being processed
#define IPC_INTERRUPTIBILITY_ALLOW_CURRENT gInterruptibilityAllowAtCurrentPriority              ///< Allow processing with no priority change
#define IPC_INTERRUPTIBILITY_ALLOW_HIGHEST_PRIORITY gInterruptibilityAllowHighestPriority       ///< Enable but only highest priority messages are allowed (IPI-like semantics)


extern const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowAll;
extern const IPC_INTERRUPTIBILITY_STATE gInterruptibilityBlockAll;
extern const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowAtCurrentPriority;
extern const IPC_INTERRUPTIBILITY_STATE gInterruptibilityAllowHighestPriority;



typedef
NTSTATUS
(*PNAPOCA_IPI_HANDLER)(                     ///< Callback template for IPI handling. When sending an IPI, this is the message-specific handler sent to be executed on each messaged processor.
    _In_ PVOID Context,
    _In_ HV_TRAP_FRAME *TrapFrame
    );



//
// Inter-CPU communication
//

typedef enum
{
    IPC_MESSAGE_TYPE_IPI_HANDLER,   ///< This implies "high IRQL"
    IPC_MESSAGE_TYPE_CALLBACK       ///< Any purpose remote processing (might be some low-priority operation)
}IPC_MESSAGE_TYPE;

typedef
NTSTATUS
(*IPC_CALLBACK)(                            ///< Callback template for IPC callback message handling. When sending an IPC callback message, this is the message-specific handler sent to be executed on each messaged processor.
    _In_ struct _IPC_MESSAGE *Message       // Message->OperationParam.Callback.Data offers a small preallocated buffer (for use as a PVOID Context, two QWORDS etc)
);

typedef struct _IPC_MESSAGE
{
    struct
    {
        // 7 bytes for sequencing / debugging fields
        QWORD Sequence : 28;
        QWORD SubSequence : 28;

        // One byte for type and flags
        QWORD MessageType : 4;   // IPC_MESSAGE_TYPE
        QWORD NeedsAcknowledge : 1;
        QWORD Trace : 1;
        QWORD Reserved : 2;
    };

    BOOLEAN volatile * volatile SetThisToAcknowledgeSender;

    union
    {
        // Execute an IPI-like handler
        struct
        {
            PNAPOCA_IPI_HANDLER CallbackFunction;
            PVOID CallbackContext;
        }IpiHandler;

        // IPC specific function / callback
        struct
        {
            IPC_CALLBACK CallbackFunction;
            BYTE Data[16];
        }Callback;
    }OperationParam;
}IPC_MESSAGE;                           ///< IPC message template. Inserted into each CPU message queue, it describes the actions needed to be performed on the CPU.


typedef
NTSTATUS
(*IPC_QUEUE_CONSUMER_CALLBACK)(                 ///< Custom IPC queue consumer callback. Used if a specific, custom treatment of the IPC message queue is required.
    _In_ struct _CPU_IPC_QUEUE *CpuQueue // Message->OperationParam.Callback.Data offers a small preallocated buffer (for use as a PVOID Context, two QWORDS etc)
    );

typedef
NTSTATUS
(*IPC_QUEUE_COLLAPSE_CALLBACK)(                 ///< Custom IPC queue collapse method. Used if a specific, custom treatment of the collapsed message mechanism is required.
    VOID
    );

#endif //_QUEUE_IPC_COMMON_h_
/// @}
