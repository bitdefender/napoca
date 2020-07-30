/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup hibernate
///@{

/** @file hibernate.h
 *  @brief HV_HIBERNATE - Support for saving data to persistent memory area, during of the power transition of the Guest into S4(Hibernate) state.
 *
 */

#ifndef __HV_HIBERNATE__
#define __HV_HIBERNATE__

#include "core.h"
#include "memory/mmap.h"

#define MAX_NUMBER_OF_HIBERNATE_RESTORE_CHECKS              100 ///< maximum number checks if the hibernate data was restored by the OS
#define GST_HIBERNATE_CONTEXT_RESTORE_AREA_NO_OF_PAGES      3   ///< number of 4KB pages used for data restoration on hibernate by the HV
#define GST_HIBERNATE_CONTEXT_RESTORE_AREA_SIZE             (GST_HIBERNATE_CONTEXT_RESTORE_AREA_NO_OF_PAGES * PAGE_SIZE) ///< the size of hibernate restoration area for hibernates
#define GST_HIBERNATE_CONTEXT_RESTORE_AREA_COUNT            1   ///< the number of such areas

// forward declarations
typedef struct _GUEST GUEST;
typedef struct _VCPU VCPU;

/// @brief Function pointer type for hibernate clients get callback, used to store data to the persistent area
typedef
NTSTATUS
(*HVHIB_GETDATA_CALLBACK)(
    _Out_ BYTE *DataBuffer,     ///< preallocated buffer of size given at register time; implementation will copy here data that is to be persisted;
    _In_ DWORD DataBufferSize   ///< buffer size; same size given at register time;
    );

/// @brief Function pointer type for hibernate clients put callback, used to restore data from the persistent area
typedef
NTSTATUS
(*HVHIB_PUTDATA_CALLBACK)(
    _In_ BYTE  *DataBuffer,     ///< preallocated buffer containing data that is to be restored
    _In_ DWORD DataBufferSize   ///< buffer size; same size given at register time;
    );

///
/// @brief State of the hibernate process
///
typedef enum _HIBERNATE_STATE
{
    HibernateNotStarted = 0,    ///< hibernate process is not in progress
    HibernateEnter,             ///< hibernate process begins => save data that needs to be persisted
    HibernateResumeBegin,       ///< hibernate resume begins => wait for all data to be restored
    HibernateResumeEnd          ///< hibernate resume ends => all data is restored and we can use it
}HIBERNATE_STATE;


#define HVHIB_MAX_CLIENTS   16  ///< The maximum number of hibernation clients that can be registered

///
/// @brief The representation of a hibernate client, who needs to save its data into the persisted memory area and restore it on wakeup.
///
typedef struct _HVHIB_CLIENT
{
    HVHIB_GETDATA_CALLBACK GetCallback;  ///< Callback function for getting the persisted data back at wakeup and restoring it, automatically called on wakeup by the hibernate procedure.
    HVHIB_PUTDATA_CALLBACK PutCallback;  ///< Callback function for putting the data to the persisted area before going into hibernation, automatically the entering of the Guests into the hibernate state.
    BYTE *StartOffset;                   ///< Start offset for this clients data inside the hibernate persisted memory area.
    DWORD Size;                          ///< The size of the stored that by the client.
}HVHIB_CLIENT;

///
/// @brief Stores all the data required for the hibernate power transition
///
typedef struct _HIBERNATE_DATA
{
    /// Used to keep track of the entries in guest's PhysMap that are used for saving/restoring the data the HV needs about a guest over a hibernate/wakeup operation of that guest.
    MMAP            HibernateContextRestoreGuestPhyMemMap;
    HIBERNATE_STATE State;                                ///< Current state of the hibernate process
    BYTE            *Buffer;                              ///< The buffer which holds all the persisted data of every hibernate client and the checksum computed over the data
    QWORD           BufferSize;                           ///< The total size of buffer
    BYTE            *FreeOffset;                          ///< The current offset inside buffer until we have data inserted from hibernate clients
    QWORD           FreeSize;                             ///< The current remaining free zone size of the hibernate buffer
    HVHIB_CLIENT    Clients[HVHIB_MAX_CLIENTS];           ///< A vector of hibernate clients
    BYTE            NumberOfClients;                      ///< The actual number of held hibernate clients
    QWORD           CrtRetryHibernateRestoreCheck;        ///< Counter for number of retries of data restoration (should spawn the time window between the last guard pages first write access and the actual complete restoration of the data by the guest)
    QWORD           MaxNumberOfHibernateRestoreChecks;    ///< The maximum number of retries of data restoration, after that we just forfeit trying anymore
}HIBERNATE_DATA;


///
/// @brief        Initializes the Guests Hibernate data, loads and maps the memory zone for the hibernate persistent data inside the EPT. Also,
///               updates memory maps and initializes a special memory map for maintaining the memory zones used by the hyper-visor for data perseverance
///               throughout a hibernate power transition. For legacy booted systems, we add the entry also in the Guests physical memory map, in order
///               to inform Windows about it.
///
/// @param[in, out] Guest                          Napoca specific guest identifier.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      OTHER                            - other error statuses returned by functions LdGetModule(), MmapAllocMapEntries() and EptMapMem()
///
NTSTATUS
HvHibInitialize(
    _Inout_ GUEST *Guest
);

///
/// @brief        Applies memory hooks inside EPT for hibernate support, it hooks only the first and last page of the persistent memory zone as
///               described in hibernate.c, the rest of the pages are mapped normally with read-write access rights.
///
/// @param[in, out] Guest                          Napoca specific guest identifier.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      OTHER                            - other error statuses returned by function EptSetRights
///
NTSTATUS
HvHibApplyMemoryHooks(
    _Inout_ GUEST *Guest
);

///
/// @brief        Checks if the Gpa is inside the hibernate persistent memory zone.
///
/// @param[in]    Guest                            Napoca specific guest identifier.
/// @param[in]    Gpa                              The Guest physical address which is to be verified.
///
/// @returns      TRUE                             - in case the address is inside the hibernate persistent memory zone
/// @returns      FALSE                            - otherwise
///
BOOLEAN
HvHibIsHibernateMemoryAddress(
    _In_ GUEST *Guest,
    _In_ QWORD Gpa
);

///
/// @brief        Handles Ept-Violations on the hooked guard pages of the hibernate persistent memory zone.
///               This is how we know when the saving of data is started by the Guest and when it ends and also the same is true
///               for the restoration of the data on wakeup. The purpose of it is described in hibernate.c as our hibernate
///               algorithm.
///
/// @param[in]    Guest                            Napoca specific guest identifier.
/// @param[in]    Vcpu                             The Virtual CPU on which the EPT-Violation happened.
/// @param[in]    Gpa                              The Guest physical address on which the violation happened.
/// @param[in]    Qualification                    The Exit Qualification of the EPT-Violation.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success and even on failures (overwrite errors in-order to not fail the exit handler,
///                                                although it should not be the case)
///
NTSTATUS
HvHibHandleHibernateMemory(
    _In_ GUEST *Guest,
    _In_ VCPU  *Vcpu,
    _In_ QWORD Gpa,
    _In_ QWORD Qualification
);

///
/// @brief        Routine for registering hibernate clients, which are called to store and re-store their specific data during the wakeup from hibernate
///               and on going to the hibernate state.
///
/// @param[in]    Guest                            Napoca specific guest identifier.
/// @param[in]    GetCallback                      The hibernate clients get callback, used to store data to the persistent area
/// @param[in]    PutCallback                      The hibernate clients put callback, used to restore data from the persistent area
/// @param[in]    RequiredSize                     The size in memory required by the hibernate client in order to store its data.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      STATUS_TOO_MANY_DEVICES          - in case we already reached #HVHIB_MAX_CLIENTS
/// @returns      CX_STATUS_DATA_BUFFER_TOO_SMALL  - in case we don't have enough memory to store the clients data
/// @returns      STATUS_NOT_A_VALID_POINTER       - in case either the Get or the Put callback is missing
/// @returns      CX_STATUS_INVALID_PARAMETER_4    - in case if the RequiredSize parameter equals 0
/// @returns      STATUS_OVERLAP_VIOLATION         - in case the clients callbacks were already registered
///
NTSTATUS
HvHibRegisterClient(
    _In_ GUEST *Guest,
    _In_ HVHIB_GETDATA_CALLBACK GetCallback,
    _In_ HVHIB_PUTDATA_CALLBACK PutCallback,
    _In_ DWORD RequiredSize
);

///
/// @brief        It verifies if the restoration process of the Guest ended, if it ended checks if the data restored data is intact by computing the checksum.
///               If the checksum matches with the restored checksum, then the data is restored by every hibernate client and the hooks on the guard pages
///               are placed back in order for us to be ready for the next power transition.
///
/// @param[in]   Vcpu                             The address of the current Virtual CPU structure.
///
/// @returns      CX_STATUS_SUCCESS                - in case of success
/// @returns      CX_STATUS_INVALID_INTERNAL_STATE - in case we didn't get a correct VCPU pointer
/// @returns      CX_STATUS_DATA_NOT_FOUND         - in case the hibernate wakeup process didn't end yet (Guest didn't completed to restore the whole
///                                                persistent memory), or we exhausted maximum number of trials for hibernate data restoration
/// @returns      CX_STATUS_DATA_NOT_READY         - in case the current computed checksum on the Hibernate data buffer is not the same as the
///                                                stored checksum inside the restored data (the first 8 bytes)
/// @returns      OTHER                            - other error statuses returned by function EptSetRights
///
NTSTATUS
HvHibCheckCompleteRestorationOfSavedData(
    _In_ VCPU *Vcpu
);
#endif


///@}