/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _COMMANDS_H_
#define _COMMANDS_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "common/communication/ringbuf.h"
#include "common/boot/cpu_features.h"

// we have to make sure DWORD, NTSTATUS and such definitions are available before we're including dacia_types and intro_types
#include "external_interface/wintypes_interface.h"
#include "dacia_types.h"
#include "intro_types.h"
#include "common/kernel/module_updates.h"


// VMCALL
#define VMCALL_GUEST_MAGIC              0x6C437648  ///< Signature for valid VMCALL Napoca HV APIs ('HvCl') - if changed here then should be changed in other (assembly) files as well

/*
Message ID fields:
0x00000000
  X         message type
   X        message target
    X       message class
     XXXXX  message number
*/

// message type
#define MSG_TYPE_SHIFT                  28
#define MSG_TYPE_MASK                   0xF0000000
#define MSG_TYPE_UNRESTRICTED           0x10000000 ///< Unrestricted Opt: Synchronous. The only target is the hypervisor and they may also come from UM. These do not use the shared memory buffer.
#define MSG_TYPE_OPT                    0x20000000 ///< Fast Option:      Synchronous only at the destination layer. Can be handled through VMCALL alone and through COMM_MESSAGE buffer.
#define MSG_TYPE_EXT                    0x30000000 ///< Extended:         Synchronous only at the destination layer. When sent to the HV they pass through shared memory. They use custom COMM_MESSAGE buffers.

// targeted component
#define MSG_TARGET_SHIFT                24
#define MSG_TARGET_MASK                 0x0F000000
#define MSG_TARGET_ANY                  0x01000000 ///< Messages can target any component
#define MSG_TARGET_HV                   0x02000000 ///< Messages target the Hypervisor
#define MSG_TARGET_WINGUEST_KM          0x03000000 ///< Messages target the Hypervisor Control Guest Driver (winguest.sys)
#define MSG_TARGET_WINGUEST_UM          0x04000000 ///< Messages target the Hypervisor Control user mode module (winguestdll.dll)
#define MSG_TARGET_FALX_KM              0x05000000 ///< Messages target the Hypervisor Test Guest Driver (falx.sys)
#define MSG_TARGET_FALX_UM              0x06000000 ///< Messages target the Hypervisor Test user mode module (falxdll.dll)

// message class
#define MSG_CLASS_SHIFT                 20
#define MSG_CLASS_MASK                  0x00F00000
#define MSG_CLASS_DEBUG                 0x00100000 ///< Debugging/Testing messages
#define MSG_CLASS_INTRO                 0x00200000 ///< Introspection related messages

#define TargetUndefined                 0
#define TargetAny                       ((COMM_COMPONENT)(MSG_TARGET_ANY >> MSG_TARGET_SHIFT))                  ///< Messages can target any component
#define TargetNapoca                    ((COMM_COMPONENT)(MSG_TARGET_HV >> MSG_TARGET_SHIFT))                   ///< Identifies the target as the Hypervisor
#define TargetWinguestKm                ((COMM_COMPONENT)(MSG_TARGET_WINGUEST_KM >> MSG_TARGET_SHIFT))          ///< Identifies the target as the Hypervisor Control Guest Driver (winguest.sys)
#define TargetWinguestUm                ((COMM_COMPONENT)(MSG_TARGET_WINGUEST_UM >> MSG_TARGET_SHIFT))          ///< Identifies the target as the Hypervisor Control user mode module (winguestdll.dll)
#define TargetFalxKm                    ((COMM_COMPONENT)(MSG_TARGET_FALX_KM >> MSG_TARGET_SHIFT))              ///< Identifies the target as the Hypervisor Test Guest Driver (falx.sys)
#define TargetFalxUm                    ((COMM_COMPONENT)(MSG_TARGET_FALX_UM >> MSG_TARGET_SHIFT))              ///< Identifies the target as the Hypervisor Test user mode module (falxdll.dll)
#define MESSAGE_TO_TARGET(MsgId)        ((COMM_COMPONENT)((MsgId & MSG_TARGET_MASK) >> MSG_TARGET_SHIFT))

//////////////////////////////////////////////////////////////////////////
// Message IDs

//
// Unrestricted Opt (can come from user mode)
//

#define VMCALL_GUEST_CHECK_HV                   (0x01 | MSG_TYPE_UNRESTRICTED | MSG_TARGET_HV)
#define VMCALL_GUEST_GET_HV_VERSION             (0x02 | MSG_TYPE_UNRESTRICTED | MSG_TARGET_HV)
#define VMCALL_GUEST_GET_REAL_TIME              (0x03 | MSG_TYPE_UNRESTRICTED | MSG_TARGET_HV)
#define VMCALL_GUEST_INTRO_SIM                  (0x04 | MSG_TYPE_UNRESTRICTED | MSG_TARGET_HV | MSG_CLASS_DEBUG)

//
// Fast Opt
//

// for HV
#define OPT_INIT_GUEST_COMMUNICATION            (0x01 | MSG_TYPE_OPT | MSG_TARGET_HV)
#define OPT_UNINIT_GUEST_COMMUNICATION          (0x02 | MSG_TYPE_OPT | MSG_TARGET_HV)
#define OPT_GET_HV_BOOT_MODE                    (0x03 | MSG_TYPE_OPT | MSG_TARGET_HV)
#define OPT_GET_POWERUP_INFO                    (0x04 | MSG_TYPE_OPT | MSG_TARGET_HV)
#define OPT_GET_MEMORY_INTRO_STATUS             (0x05 | MSG_TYPE_OPT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define OPT_REM_ALL_PROTECTED_PROCESSES         (0x06 | MSG_TYPE_OPT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define OPT_FLUSH_EXCEPTIONS_FROM_ALERTS        (0x07 | MSG_TYPE_OPT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define OPT_SET_INTRO_VERBOSITY                 (0x08 | MSG_TYPE_OPT | MSG_TARGET_HV | MSG_CLASS_INTRO)

//
// Extended messages
//

// for HV
#define cmdDriverCheckCompatWithNapoca          (0x01 | MSG_TYPE_EXT | MSG_TARGET_HV)
#define cmdGetLogsHv                            (0x02 | MSG_TYPE_EXT | MSG_TARGET_HV)
#define cmdGetCfgItemData                       (0x03 | MSG_TYPE_EXT | MSG_TARGET_HV)
#define cmdSetCfgItemData                       (0x04 | MSG_TYPE_EXT | MSG_TARGET_HV)
#define cmdUpdateModule                         (0x05 | MSG_TYPE_EXT | MSG_TARGET_HV)
#define cmdSendDbgCommand                       (0x06 | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_DEBUG)
#define cmdIntroFlags                           (0x07 | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define cmdSetProtectedProcess                  (0x08 | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define cmdAddExceptionFromAlert                (0x09 | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define cmdRemoveException                      (0x0A | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_INTRO)
#define cmdIntroGuestInfo                       (0x0B | MSG_TYPE_EXT | MSG_TARGET_HV | MSG_CLASS_INTRO)

// for winguest.sys
#define cmdCommandThreadCount                   (0x01 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)
#define cmdGetHvStatus                          (0x02 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)
#define cmdGetLogs                              (0x03 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)
#define cmdGetCompatibility                     (0x04 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)
#define cmdQueryComponent                       (0x05 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)
#define cmdUpdateComponent                      (0x06 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_KM)

// for winguest.dll
#define cmdSendPowerStateChange                 (0x01 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_UM)
#define cmdReportIntrospectionError             (0x02 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_UM | MSG_CLASS_INTRO)
#define cmdSendIntrospectionAlert               (0x03 | MSG_TYPE_EXT | MSG_TARGET_WINGUEST_UM | MSG_CLASS_INTRO)

// for falx.sys
#define cmdConnectHv                            (0x01 | MSG_TYPE_EXT | MSG_TARGET_FALX_KM | MSG_CLASS_DEBUG)
#define cmdMsrAccess                            (0x02 | MSG_TYPE_EXT | MSG_TARGET_FALX_KM | MSG_CLASS_DEBUG)
#define cmdAccessPhysMem                        (0x03 | MSG_TYPE_EXT | MSG_TARGET_FALX_KM | MSG_CLASS_DEBUG)

// for multiple components
#define cmdIgnore                               (0x01 | MSG_TYPE_EXT | MSG_TARGET_ANY | MSG_CLASS_DEBUG)
#define cmdTestComm                             (0x02 | MSG_TYPE_EXT | MSG_TARGET_ANY | MSG_CLASS_DEBUG)
#define cmdUmCheckCompatWithDrv                 (0x03 | MSG_TYPE_EXT | MSG_TARGET_ANY)
#define cmdFastOpt                              (0x04 | MSG_TYPE_EXT | MSG_TARGET_ANY)
#define cmdGetComponentVersion                  (0x05 | MSG_TYPE_EXT | MSG_TARGET_ANY)
#define cmdGetHostCrValues                      (0x06 | MSG_TYPE_EXT | MSG_TARGET_ANY)
#define cmdGetCpuSmxAndVirtFeat                 (0x07 | MSG_TYPE_EXT | MSG_TARGET_ANY)

//
// MSR requests
//

#define MSR_DBG_ENABLE_SERIAL_IO                0xBDBDBDB1          ///< Enable Serial Port communication with the Hypervisor
#define MSR_DBG_ENABLE_USB_LOG                  0xBDBDBDB2          ///< Enable USB logging
#define MSR_DBG_REQUEST_FEEDBACK_MODULE         0xBDBDBDB3          ///< Request log Physical Address

#pragma pack(push)
#pragma pack(8)         // Packing is MANDATORY to be exactly the same for all components involved

//////////////////////////////////////////////////////////////////////////
// Message Definitions

//
// Unrestricted Messages
//

/*! @def VMCALL_GUEST_CHECK_HV
 *
 *  @brief Check if the Hypervisor is running
 *
 *  @param[out] OutParam1   #VMCALL_RESPONSE_CHECK_HV
 */

#define VMCALL_RESPONSE_CHECK_HV    'VHDB'      ///< Valid response for VMCALL_GUEST_CHECK_HV


/*! @def VMCALL_GUEST_GET_HV_VERSION
 *
 *  @brief Get the Hypervisor version
 *
 *  @param[out] OutParam1   Major
 *  @param[out] OutParam1   Minor
 *  @param[out] OutParam1   Revision
 *  @param[out] OutParam1   Build number
 */


/*! @def VMCALL_GUEST_GET_REAL_TIME
 *
 *  @brief Get the real time (TSC and RTC)
 *
 *  @param[out] OutParam1   TSC >> 32
 *  @param[out] OutParam2   TSC & 0xFFFFFFFF
 *  @param[out] OutParam1   DATETIME >> 32
 *  @param[out] OutParam2   DATETIME & 0xFFFFFFFF
 */


/*! @def VMCALL_GUEST_INTRO_SIM
 *
 *  @brief Simulate Introspection messages coming from the hypervisor without actually involving the introspection engine (Used for testing)
 *
 *  @param[in] Param1       #_INTROSIM_OPTIONS
 *  @param[in] Param2       flags
 *  @param[in] Param3       Counter
 *  @param[in] Param4       Identifier
 */

#define INTROSIM_ALERT_EXHEADER_VALID       0x00000001 ///< Introsim Flag: generates an alert with a valid ExHeader

typedef enum _INTROSIM_TYPE
{
    introsimError = 1,  ///< Introspection Error
    introsimAlert       ///< Introspection Alert
}INTROSIM_TYPE;

typedef union _INTROSIM_OPTIONS
{
    struct{
        CX_UINT32 IntrosimType : 16;        ///< #_INTROSIM_TYPE
        CX_UINT32 IntroMessageType : 16;    ///< INTRO_ERROR_STATE or INTRO_EVENT_TYPE value
    };

    CX_UINT32 Raw;
} INTROSIM_OPTIONS;

static_assert (sizeof(INTROSIM_OPTIONS) == 4, "sizeof(INTROSIM_OPTIONS) != 4");


//
// fastopt
//

// for HV

/*! @def OPT_INIT_GUEST_COMMUNICATION
 *
 *  @brief Initialize guest - HV communication via shared ringbuffer
 *
 *  @param[in]  Param1      the component that connects
 *  @param[out] OutParam1   bits  0:31 of SharedMemGPA
 *  @param[out] OutParam2   bits 32:63 of SharedMemGPA
 *  @param[out] OutParam3   SharedMemSize
 */


/*! @def OPT_UNINIT_GUEST_COMMUNICATION
 *
 *  @brief Uninitialize guest - HV communication via shared ringbuffer
 *
 *  @param[in] Param1       the component that disconnects
 */


/*! @def OPT_GET_HV_BOOT_MODE
 *
 *  @brief Retrieve the current Boot Mode (PXE, MBR, UEFI, etc)
 *
 *  @param[out] OutParam1   BOOT_MODE
 */


/*! @def OPT_GET_POWERUP_INFO
 *
 *  @brief Retrieve last PowerUp type
 *
 *  @param[out] OutParam1   True: return from sleep, False: return from hibernate
 */


/*! @def OPT_GET_MEMORY_INTRO_STATUS
 *
 *  @brief Check if the Introspection engine is enabled
 *
 *  @param[out] OutParam1   True: On, False: Off
 */


/*! @def OPT_REM_ALL_PROTECTED_PROCESSES
 *
 *  @brief Remove all processes from the Introspection protection list
 */


/*! @def OPT_FLUSH_EXCEPTIONS_FROM_ALERTS
 *
 *  @brief Remove all custom alert based exceptions from the Introspection
 */


/*! @def OPT_SET_INTRO_VERBOSITY
 *
 *  @brief Set the verbosity of the Introspection log
 *
 *  @param[in] Param1   Desired Verbosity
 */

//
// ringbuffer messages
//

/*! @def cmdIgnore
 *
 *  @brief Stress Test the ringbuffer (never discarded)
*/


/*! @def cmdTestComm
 *
 *  @brief Test communication. Message is discarded immediately
 *
 *  Message: #_CMD_TEST_COMM
 */

typedef struct _CMD_TEST_COMM
{
    COMM_MESSAGE    Command;                ///< Standard Message Header
} CMD_TEST_COMM, *PCMD_TEST_COMM;


/*! @def cmdDriverCheckCompatWithNapoca
 *
 *  @brief Perform a compatibility handshake when a diver connects to the Hypervisor
 *
 *  Message: #_CMD_CHECK_COMPATIBILITY
 */

/*! @def cmdUmCheckCompatWithDrv
 *
 *  @brief Perform a compatibility handshake when a user mode module connects to the driver
 *
 *  Message: #_CMD_CHECK_COMPATIBILITY
*/

typedef struct _CMD_CHECK_COMPATIBILITY
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    struct
    {
        CX_UINT32       High;
        CX_UINT32       Low;
        CX_UINT32       Revision;
        CX_UINT32       Build;
    } Version;                              ///< Component version. Input: Version of Caller. Output: Version of Calee

    struct
    {
        CX_UINT32       High;
        CX_UINT32       Low;
        CX_UINT32       Revision;
        CX_UINT32       Build;
    } CompatVersion;                        ///< Compatibility version. Input: Version of Callee required by Caller. Output: Version of Caller required by calee
} CMD_CHECK_COMPATIBILITY, *PCMD_CHECK_COMPATIBILITY;


/*! @def cmdGetLogs
 *
 *  @brief Request hypervisor logs (UM -> KM)
 *
 *  Message: #_CMD_GET_LOGS
 */

/*! @def cmdGetLogsHv
 *
 *  @brief Request hypervisor logs (KM -> HV)
 *
 *  Message: #_CMD_GET_LOGS
 */

// Retrieves the hypervisor runtime log

typedef enum _LOG_TYPE
{
    logUefiPreloader = 1,   ///< UM                 retrieved from UEFI variable
    logUefiLoader = 2,      ///< UM -> KM           retrieved from physical address stored in UEFI variable
    logHypervisor = 3,      ///< UM -> KM -> HV     requested from HV
    logHvPhysAddr = 4,      ///<       KM -> HV     requested from HV
} LOG_TYPE, *PLOG_TYPE;

typedef struct _CMD_GET_LOGS
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    LOG_TYPE        Type;                   ///< Type of log required

    // in & out
    CX_UINT32       Size;                   ///< In/Out: Size of request
    CX_UINT32       Offset;                 ///< Offset in log
    CX_UINT64       PhysicalAddress;        ///< Physical Address
    CX_UINT32       PhysicalSize;           ///< Size of buffer located at #PhysicalAddress

    // out
    CX_UINT8        Buffer[1];              ///< Log Storage
} CMD_GET_LOGS, *PCMD_GET_LOGS;


/*! @def cmdGetCfgItemData
 *
 *  @brief Retrieve the value of a command line entry
 *
 *  Message: #_CMD_GET_CFG_ITEM_DATA
*/

typedef struct _CMD_GET_CFG_ITEM_DATA
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // inout
    CFG_ITEM_DATA   CfgItemData;            ///< Value Data
} CMD_GET_CFG_ITEM_DATA, *PCMD_GET_CFG_ITEM_DATA;


/*! @def cmdSetCfgItemData
 *
 *  @brief Set the value of a command line entry
 *
 *  Message: #_CMD_SET_CFG_ITEM_DATA
 */

typedef struct _CMD_SET_CFG_ITEM_DATA
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_UINT32       CmdlineLength;          ///< Length of #Cmdline buffer
    CX_INT8         Cmdline[1];             ///< Buffer that contains the command line to be applied
} CMD_SET_CFG_ITEM_DATA, *PCMD_SET_CFG_ITEM_DATA;


/*! @def cmdUpdateModule
 *
 *  @brief Update a hypervisor Module
 *
 *  Message: #_CMD_UPDATE_MODULE
 */

typedef struct _CMD_UPDATE_MODULE
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // inout
    UPD_INFO        Update;                 ///< Updated Module description
} CMD_UPDATE_MODULE, *PCMD_UPDATE_MODULE;


/*! @def cmdSendDbgCommand
 *
 *  @brief Send a debug command to the Hypervisor
 *
 *  Message: #_CMD_SEND_DBG_COMMAND
 */

typedef struct _CMD_SEND_DBG_COMMAND
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_UINT32       Length;                 ///< Length of #Buffer
    CX_INT8         Buffer[1];              ///< Debug command
} CMD_SEND_DBG_COMMAND, *PCMD_SEND_DBG_COMMAND;


/*! @def cmdIntroFlags
 *
 *  @brief Get/Set Introspection flags
 *
 *  Message: #_CMD_INTRO_FLAGS
 */

typedef struct _CMD_INTRO_FLAGS
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_BOOL         Write;                  ///< True: Write, False: Read

    // in/out
    CX_UINT64       Flags;                  ///< Introspection Flags
} CMD_INTRO_FLAGS, *PCMD_INTRO_FLAGS;


/*! @def cmdSetProtectedProcess
 *
 *  @brief Add a process to be protected by the Introspection engine
 *
 *  Message: #_CMD_SET_PROTECTED_PROCESS
 */

typedef struct _CMD_SET_PROTECTED_PROCESS
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_UINT32       Mask;                   ///< Protection flags
    CX_UINT64       Context;                ///< Context that identifies the protection rule
    CX_UINT32       PathLen;                ///< Size of Path Buffer
    WCHAR           Path[1];                ///< Path to the protected process
} CMD_SET_PROTECTED_PROCESS, *PCMD_SET_PROTECTED_PROCESS;


/*! @def cmdAddExceptionFromAlert
 *
 *  @brief Add a custom Introspection exception based on a previous Alert
 *
 *  Message: #_CMD_ADD_EXCEPTION_FROM_ALERT
 */

typedef struct _CMD_ADD_EXCEPTION_FROM_ALERT
{
    COMM_MESSAGE     Command;                ///< Standard Message Header

    // in
    CX_UINT64        Context;               ///< Context that identifies the exception rule
    CX_UINT32        AlertSize;             ///< Size of Alert
    INTRO_EVENT_TYPE AlertType;             ///< Type of Alert
    CX_BOOL          IsException;           ///< True: Exception Buffer, False: Full Alert
    CX_UINT8         AlertData[1];          ///< Alert bffer
} CMD_ADD_EXCEPTION_FROM_ALERT, *PCMD_ADD_EXCEPTION_FROM_ALERT;


/*! @def cmdRemoveException
 *
 *  @brief Remove a custom Introspection exception
 *
 *  Message: #_CMD_REMOVE_EXCEPTION
 */

typedef struct _CMD_REMOVE_EXCEPTION
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_UINT64       Context;                ///< Context that identifies the exception rule to be removed
} CMD_REMOVE_EXCEPTION, *PCMD_REMOVE_EXCEPTION;


/*! @def cmdIntroGuestInfo
 *
 *  @brief Retrieve information about the current guest from the Introspection engine
 *
 *  Message: #_CMD_GUEST_INFO
 */

typedef struct _CMD_GUEST_INFO
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // out
    GUEST_INFO      GuestInfo;              ///< Information about the current guest
} CMD_GUEST_INFO, *PCMD_GUEST_INFO;


/*! @def cmdGetHvStatus
 *
 *  @brief Retrieve the status of the Hypervisor from the driver
 *
 *  Message: #_CMD_GET_HV_STATUS
 */

typedef struct _CMD_GET_HV_STATUS
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // out
    CX_BOOL         Started;                ///< Hypervisor is active
    CX_BOOL         Connected;              ///< HV-KM connection established
    BOOT_MODE       BootMode;               ///< The current boot mode of the Hypervisor
} CMD_GET_HV_STATUS, *PCMD_GET_HV_STATUS;


/*! @def cmdGetCompatibility
 *
 *  @brief Gets the version of one component required by another component
 *
 *  Message: #_CMD_GET_COMPATIBILITY
 */

typedef struct _CMD_GET_COMPATIBILITY
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    //in
    BIN_COMPONENT   Component1;             ///< Component that has a requirement that must be retrieved
    BIN_COMPONENT   Component2;             ///< Component whose version required by the other component must be known

    //out
    CX_UINT32       VersionLow;
    CX_UINT32       VersionHigh;
    CX_UINT32       VersionRevision;
    CX_UINT32       VersionBuild;
} CMD_GET_COMPATIBILITY, *PCMD_GET_COMPATIBILITY;


/*! @def cmdUpdateComponent
 *
 *  @brief Request from User Mode the update of a module. This update will be first serviced by the driver and then passed to the Hypervisor
 *
 *  Message: #_CMD_UPDATE_COMPONENT
 */

typedef struct _CMD_UPDATE_COMPONENT
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    BIN_COMPONENT   Component;              ///< The component that will be updated
    CX_UINT32       PathSize;               ///< Size of the path on disk for the module
    CX_UINT32       DataSize;               ///< Size of the module custom data
    CX_UINT8        Buffer[1];              ///< Buffer that contains the module path, immediately followed by the module custom data
} CMD_UPDATE_COMPONENT, *PCMD_UPDATE_COMPONENT;


/*! @def cmdQueryComponent
 *
 *  @brief Request from User Mode information about a module.
 *
 *  Message: #_CMD_QUERY_COMPONENT
 */

typedef struct _CMD_QUERY_COMPONENT
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    BIN_COMPONENT   Component;              ///< The component that will be queried
    CX_UINT8        Buffer[1];              ///< Module custom data
} CMD_QUERY_COMPONENT, *PCMD_QUERY_COMPONENT;


/*! @def cmdSendPowerStateChange
 *
 *  @brief Report the fact that a power state change has occured
 *
 *  Message: #_CMD_SEND_POWER_STATE_CHANGED
 */

typedef struct _CMD_SEND_POWER_STATE_CHANGED
{
    COMM_MESSAGE    Command;                        ///< Standard Message Header

    // in
    CX_BOOL         PowerState;                     ///< True: Higher Power State, False: Lower Power State

    CX_BOOL         ResumeVolatileSettingsLost;     ///< Volatile settings have been lost due to the power transition and need to be reapplied (custom exceptions, protection rules, etc)
} CMD_SEND_POWER_STATE_CHANGED, *PCMD_SEND_POWER_STATE_CHANGED;


/*! @def cmdReportIntrospectionError
 *
 *  @brief Report that an Introspection Engine error has occured
 *
 *  Message: #_INTROSPECTION_ERROR
 */

typedef struct _INTROSPECTION_ERROR
{
    INTRO_ERROR_STATE   Type;               ///< Error that occured
    INTRO_ERROR_CONTEXT Context;            ///< Error specific data
} INTROSPECTION_ERROR;

typedef struct _CMD_REPORT_INTROSPECTION_ERROR
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    INTROSPECTION_ERROR Error;              ///< Error information
} CMD_REPORT_INTROSPECTION_ERROR, *PCMD_REPORT_INTROSPECTION_ERROR;


/*! @def cmdSendIntrospectionAlert
 *
 *  @brief Report that an Introspection Engine detection has occured
 *
 *  Message: #_CMD_SEND_INTROSPECTION_ALERT
 */

#define MAX_INTROSPECTION_ALERTS    16      ///< Maximum number of alerts per message

typedef union _INTROSPECTION_EVENT
{
    EVENT_EPT_VIOLATION                 EptViolation;
    EVENT_MSR_VIOLATION                 MsrViolation;
    EVENT_CR_VIOLATION                  CrViolation;
    EVENT_XCR_VIOLATION                 XcrViolation;
    EVENT_INTEGRITY_VIOLATION           IntegrityViolation;
    EVENT_TRANSLATION_VIOLATION         TranslationViolation;
    EVENT_MEMCOPY_VIOLATION             MemcopyViolation;
    EVENT_DTR_VIOLATION                 DtrViolation;
    EVENT_INTROSPECTION_MESSAGE         IntrospectionMessage;
    EVENT_PROCESS_EVENT                 ProcessEvent;
    EVENT_AGENT_EVENT                   AgentEvent;
    EVENT_MODULE_EVENT                  ModuleEvent;
    EVENT_CRASH_EVENT                   CrashEvent;
    EVENT_EXCEPTION_EVENT               ExceptionEvent;
    EVENT_CONNECTION_EVENT              ConnectionEvent;
    EVENT_PROCESS_CREATION_VIOLATION    ProcessCreationViolation;
    EVENT_MODULE_LOAD_VIOLATION         ModuleLoadViolation;
    EVENT_ENGINES_DETECTION_VIOLATION   EnginesDetectionViolation;
} INTROSPECTION_EVENT;

typedef struct _INTROSPECTION_ALERT
{
    INTRO_EVENT_TYPE    Type;               ///< The type of the detection
    CX_UINT64           IndexInQueue;       ///< Incrementing identifier to aid in serializing the events
    INTROSPECTION_EVENT Event;              ///< Detection information
} INTROSPECTION_ALERT;

typedef struct _CMD_SEND_INTROSPECTION_ALERT
{
    COMM_MESSAGE        Command;            ///< Standard Message Header

    CX_UINT16           Count;              ///< Number of detections
    INTROSPECTION_ALERT Alerts[1];          ///< Array of detections
} CMD_SEND_INTROSPECTION_ALERT, *PCMD_SEND_INTROSPECTION_ALERT;


/*! @def cmdConnectHv
 *
 *  @brief Instruct the Falx testing driver to initiate a connection to the hypervisor
 *
 *  Message: #_CMD_CONNECT_HV
 */

typedef struct _CMD_CONNECT_HV
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_BOOL         Connect;                ///< True: Connect, False: Disconnect
}CMD_CONNECT_HV, *PCMD_CONNECT_HV;


/*! @def cmdMsrAccess
 *
 *  @brief Perform a MSR value Read/Write
 *
 *  Message: #_CMD_MSR_ACCESS
 */

typedef struct _CMD_MSR_ACCESS
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    CX_BOOL         Write;                  ///< True: Write, False: Read
    CX_UINT32       MsrId;                  ///< Id of MSR

    // in/out
    CX_UINT64       MsrValue;               ///< MSR value
}CMD_MSR_ACCESS, *PCMD_MSR_ACCESS;


/*! @def cmdAccessPhysMem
 *
 *  @brief Read Physical Memory
 *
 *  Message: #_CMD_ACCESS_PHYS_MEM
 */

typedef enum _PHYS_MEM_ACCESS_WIDTH
{
    pmawNone = 0,
    pmawByte = 1,
    pmawWord = 2,
    pmawDoubleWord = 4,
    pmawQuadWord = 8
}PHYS_MEM_ACCESS_WIDTH;

typedef struct _CMD_ACCESS_PHYS_MEM
{
    COMM_MESSAGE          Command;              ///< Standard Message Header

    // in
    CX_UINT64             PhysAddress;          ///< Physical address to read
    PHYS_MEM_ACCESS_WIDTH AccessWidth;          ///< Size requested

    // out
    CX_UINT8              Data[8];              ///< Physical memory
}CMD_ACCESS_PHYS_MEM, *PCMD_ACCESS_PHYS_MEM;


/*! @def cmdFastOpt
 *
 *  @brief Alternative for sending FastOpts (if VMCALL is not an option)
 *
 *  @warning The parameters get truncated to CX_SIZE_T if sent via VMCALL to the Hypervisor. Generally only use all 64 bits for guest virtual addresses
 *
 *  Message: #_CMD_FAST_OPTION
 */

typedef struct _CMD_FAST_OPTION
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // in
    COMMAND_CODE    MsgId;                  ///< FastOpt Identifier

    //

    // in
    CX_UINT64       Param1;
    CX_UINT64       Param2;
    CX_UINT64       Param3;
    CX_UINT64       Param4;

    // out
    CX_UINT64       OutParam1;
    CX_UINT64       OutParam2;
    CX_UINT64       OutParam3;
    CX_UINT64       OutParam4;
} CMD_FAST_OPTION, *PCMD_FAST_OPTION;


/*! @def cmdGetComponentVersion
 *
 *  @brief Retrieve the version of a component
 *
 *  Message: #_CMD_GET_COMPONENT_VERSION
 */

typedef struct _CMD_GET_COMPONENT_VERSION
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    //in
    BIN_COMPONENT   Component;              ///< Component that is querried

    //out
    CX_UINT32       VersionHigh;
    CX_UINT32       VersionLow;
    CX_UINT32       VersionRevision;
    CX_UINT32       VersionBuild;
} CMD_GET_COMPONENT_VERSION, *PCMD_GET_COMPONENT_VERSION;


/*! @def cmdCommandThreadCount
 *
 *  @brief Set the number of threads that will process Hypervisor messages
 *
 *  Message: #_CMD_COMMAND_THREAD_COUNT
 */

typedef struct _CMD_COMMAND_THREAD_COUNT
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    //in
    CX_UINT32       ThreadCount;            ///< Number of threads
} CMD_COMMAND_THREAD_COUNT, *PCMD_COMMAND_THREAD_COUNT;


/*! @def cmdGetHostCrValues
 *
 *  @brief Get the values of CR0 ans CR4 processor control registers
 *
 *  Message: #_CMD_GET_CR_VALUES
 */

typedef struct _CMD_GET_CR_VALUES
{
    COMM_MESSAGE    Command;                ///< Standard Message Header

    // out
    CX_UINT64       Cr0;                    ///< Value of CR0
    CX_UINT64       Cr4;                    ///< Value of CR4
} CMD_GET_CR_VALUES, *PCMD_GET_CR_VALUES;


/*! @def cmdGetCpuSmxAndVirtFeat
 *
 *  @brief Get processor virtualization features and SMX capabilities
 *
 *  Message: #_CMD_GET_CPU_SMX_VIRT_FEATURES
 */

typedef struct _CMD_GET_CPU_SMX_VIRT_FEATURES
{
    COMM_MESSAGE            Command;                ///< Standard Message Header

    // out
    CPU_ENTRY               CpuEntry;               ///< Processor information
    VIRTUALIZATION_FEATURES VirtFeatures;           ///< Virtualization features
    SMX_CAPABILITIES        SmxCaps;                ///< SMX capabilities
} CMD_GET_CPU_SMX_VIRT_FEATURES, *PCMD_GET_CPU_SMX_VIRT_FEATURES;


#pragma pack(pop)


/**
 * @brief Perform a VMCALL operation to send the hypervisor a synchronous message.
 *
 * This performs calls the hypervisor with the NAPOCA HV standard message format:
 *  - Before calling
 *      - The value #VMCALL_GUEST_MAGIC must be stored in EBX
 *      - A message type identifier must be stored in EAX
 *      - Input parameters can be stored in ECX, EDX, ESI, EDI
 *  - After calling
 *      - A processing status must be placed in EAX
 *      - Output parameters can be stored in ECX, EDX, ESI, EDI
 *
 * @param[in]  MessageType      Type of message being sent
 * @param[in]  Param1           1st Input parameter
 * @param[in]  Param2           2nd Input parameter
 * @param[in]  Param3           3rd Input parameter
 * @param[in]  Param4           4th Input parameter
 * @param[out] OutParam1        1st Output parameter
 * @param[out] OutParam2        2nd Output parameter
 * @param[out] OutParam3        3rd Output parameter
 * @param[out] OutParam4        4th Output parameter
 *
 * @return CX_STATUS_SUCCESS    operation completed successfully
 * @return OTHER                other potential internal error
*/
extern
CX_STATUS
__cdecl
HvVmcall(
    _In_ CX_SIZE_T MessageType,
    _In_ CX_SIZE_T Param1,
    _In_ CX_SIZE_T Param2,
    _In_ CX_SIZE_T Param3,
    _In_ CX_SIZE_T Param4,
    _Out_ CX_SIZE_T *OutParam1,
    _Out_ CX_SIZE_T *OutParam2,
    _Out_ CX_SIZE_T *OutParam3,
    _Out_ CX_SIZE_T *OutParam4
    );

const
char *
CommComponentToString(
    _In_ CX_UINT8 Component
    );

const
char *
CommCommandToString(
    _In_ COMMAND_CODE CommandCode
    );

#ifdef __cplusplus
}
#endif

#endif //_COMMANDS_H_
