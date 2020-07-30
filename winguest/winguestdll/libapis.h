/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @ingroup integration
/// @{
#ifndef _LIBAPIS_H_
#define _LIBAPIS_H_

#include "winguestdll.h"
#include "intro_types.h"

#ifndef QWORD
#define QWORD unsigned __int64
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Establish the communication between the user mode and kernel mode components.
 *          It must be called before any other API that needs to comunicate with the kernel mode components is called.
 *
 * @return  STATUS_SUCCESS - initialization completed successfully.
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestConnectToDriver(
    void
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestConnectToDriver)(
    void
    );
/**
 * @brief   Close the communication between user mode and kernel mode components. All APIs that require a connection with kernel mode components will fail after this function is called.
 *
 * @return  STATUS_SUCCESS - action completed successfully
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestDisconnectFromDriver(
    void
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestDisconnectFromDriver)(
    void
    );

/**
 * @brief   Register callbacks that will be called when certain events occur.
 *
 * @param   CallbackId  - Callback Id that will be registered
 * @param   Callback    - Function pointer to a user defined function that will be called
 * @param   Context     - Caller defined value that will be passed back to the callback function
 *
 * @return  STATUS_SUCCESS
 * @return  STATUS_WG_NOT_INITIALIZED       - Library is not initialized.
 * @return  STATUS_INVALID_WG_CALLBACK_ID   - Callback is is not valid. It is not in the range defined by the WINGUEST_CALLBACK_ID enum.
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestRegisterCallback(
    _In_ WINGUEST_CALLBACK_ID CallbackId,
    _In_ WINGUEST_CALLBACK Callback,
    _In_ PVOID Context);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestRegisterCallback)(
    _In_ WINGUEST_CALLBACK_ID CallbackId,
    _In_ WINGUEST_CALLBACK Callback,
    _In_ PVOID Context);

/**
 * @brief   Set the number of threads the driver uses to exchange information with the User Mode component.
 *
 * @param   Count  - The number of threads that will be used
 *
 * @return  STATUS_SUCCESS          - the option has been set successfully
 * @return  STATUS_NOT_INITIALIZED  - initialization function was not called or did not complete successfully
 * @return  STATUS_UNSUCCESSFUL     - the option failed to be sent to the driver (only for driver options)
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetDriverMessageThreadCount(
    _In_ DWORD Count);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestSetDriverMessageThreadCount)(
    _In_ DWORD Count);

/**
 * @brief   Retrieve the current parameters of boot failsafe mechanism.
 *
 * @param   AllowedCount    - The number of boots the hv will attempt before it will stop booting
 * @param   FailCount       - The number of failed boot attempts since the last successful boot
 *
 * @return  STATUS_SUCCESS          - the value of the specified option has been retrieved successfully
 * @return  STATUS_NOT_INITIALIZED  - initialization function was not called or did not complete successfully
 * @return  STATUS_UNSUCCESSFUL     - the option's value couldn't be retrieved
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestReadLoadMonitor(
    _In_opt_ DWORD *AllowedCount,
    _In_opt_ DWORD *FailCount);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestReadLoadMonitor)(
    _In_opt_ DWORD *AllowedCount,
    _In_opt_ DWORD *FailCount);


/**
 * @brief   Configure the boot failsafe mechanism.
 *
 * @param   AllowedCount    - The number of boots the hv will attempt before it will stop booting
 * @param   ResetFailCount  - If TRUE, will reset the number of failed boot attempts since the last successful boot to 0
 *
 * @return STATUS_SUCCESS           - the option has been set successfully
 * @return STATUS_NOT_INITIALIZED   - initialization function was not called or did not complete successfully
 * @return STATUS_UNSUCCESSFUL      - the option couldn't be set in the driver
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestConfigureLoadMonitor(
    _In_opt_ DWORD *AllowedCount,
    _In_ BOOLEAN ResetFailCount);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestConfigureLoadMonitor)(
    _In_opt_ DWORD *AllowedCount,
    _In_ BOOLEAN ResetFailCount);

/**
 * @brief   Set path to various folders required by a hypervisor to operate correctly.
 *
 *          After setting any of these paths an call to either WinguestConfigureHypervior or WinguestPerformUpdate is required
 *          in order for the files in those locations to be used.
 *
 * @param   PathId  - id of the path to be set; it can be one of the CONFIG_PATH enum values.
 * @param   Path    - NULL terminated string that represents a valid local file-system location
 *
 * @return  STATUS_SUCCESS  - The operation completed successfully
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetPath(
    _In_ CONFIG_PATH PathId,
    _In_z_ PWCHAR Path
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestSetPath)(
    _In_ CONFIG_PATH PathId,
    _In_z_ PWCHAR Path
    );

/**
 * @brief   Perform an update for various runtime components.
 *
 *          Update can be performed only after a successfull call to WInguestConfigureHypervisor has been performed.
 *          In case of a failed WinguestConfigureHypervisor call the state of missing features.
 *          Missing features may be obtained by a call to WinguestGetMissingFeatures.
 *
 * @param   Components - any combination of the following values:
 *
 *               Value                           | Description
 *           ----------------------------        | -------------
 *           FLAG_UPDATE_COMPONENT_BASE          | Ignored. Update the core components of the hypervisor. This includes the hypervisor binary itself, its command lines, grub and efi loaders and the hvi binary.
 *           FLAG_UPDATE_COMPONENT_INTRO_UPDATES | Update the exceptions used by the HVI engine.
 *           FLAG_INSTALL_BOOT_FILES             | Update the exceptions used by the HVI engine.
 *
 * @return  STATUS_SUCCESS                          - Operation completed successfully.
 * @return  STATUS_WG_NOT_INITIALIZED               - winguest user mode communication library is not initialized.
 * @return  STATUS_NOT_CONNECTED                    - a connection to winguest kernel mode components is not established.
 * @return  STATUS_HYPERVISOR_NOT_CONFIGURED        - the hypervisor is not configured; in this case a successfull configuration operation must be performed so that updates can be applied.
 * @return  STATUS_UPDATE_FILE_ERROR                - one of the files involved in the update process was not successfully copied to its correct locaton; in this case the update operation must be retried at a later time.
 * @return  STATUS_UPDATE_RECOMMENDS_REBOOT         - a reboot is required to fully apply the update because it couldn't be applied on the fly due to unforseen cirtcumstances
 * @return  STATUS_UPDATE_REQUEST_REBOOT_FOR_UPDATE - a reboot is required to fully apply the update because the updated components cannot be updated on the fly
 * @return  STATUS_UPDATE_REQUIRES_REBOOT           - a reboot is required due to possible critical vulnerabilities existing in the currently installed version.
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestPerformUpdate(
    _In_ DWORD Components
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestPerformUpdate)(
    DWORD Components
    );

/**
 * @brief   Try to configure/deconfigure the hypervisor by applying any specified overrides to the default command line provided
 *          with the Dacia SDK. In case of deconfiguration, the additional command lines overrides are ignored.
 *
 * @param   Enable  - Indicates that the required action si to configure if the value is TRUE or to deconfigure if the value is FALSE
 * @param   CmdLine - Optional parameter used to specify overrides to the default command line of the hypervisor.
 *                    This parameter is recommended to be set to NULL, however if changes are needed to the default behavior
 *                    an array of chars containing the list of templates to be applied can be specified. It is intended mainly for debugging purposes
 *                    and to control advanced features of the hypervisor. Modifying it may lead to invalid or inconsistent values
 *                    in the command line and undefined behavior of the hypervisor.
 *
 * @return  STATUS_SUCCESS                          - action completed successfully
 * @return  STATUS_INVALID_SDK_FOLDER               - the base folder specified in a call to WinguestSetPath does not contain all needed files / folders that are required for proper configuratino of the hypervisor
 * @return  STATUS_HV_CONFIGURATION_NOT_SUPPORTED   - hyprvisor configuration failed. There may be multiple reasons for a hypervisor configuration failure. In order to get all detectable reasons for such a failure a call to WinguestGetMissingFeatures may be performed.
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestConfigureHypervisor(
    _In_ BOOLEAN Enable,
    _In_opt_z_ const PCHAR CmdLine
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestConfigureHypervisor)(
    _In_ BOOLEAN Enable,
    _In_opt_z_ const PCHAR CmdLine
    );

/**
@brief Mark the feedback data that is generated as internal.

This is usefull for testing purposes in order to differentiate between real life data and synthetic data generated by various test tools for example.
This is used with WinguestConfigureFeedback() function.
*/
#define FLAG_FEEDBACK_INTERNAL          (1 << 0)

/**
@brief This is used to control what kind of feedback data will be generated.

This is used with WinguestConfigureFeedback() function.
*/
typedef union _FEEDBACK_CONFIG_TYPES
{
    QWORD Flags;                /**< Access to raw value. */
    struct
    {
        QWORD FileIntro : 1;    /**< Controls if hvi generated events are considered for feedback persistence. */
    };
}FEEDBACK_CONFIG_TYPES;

/**
 * @brief Configure feedback behaviour (generation and storage on disk).
 *
 * @param Generation                - Controls which files will be generated
 * @param Flags                     - Possible values:
 *                                      FLAG_FEEDBACK_INTERNAL - (Marks the feedback as originating from internal testing)
 * @param LocalBackupDuration       - Time (in seconds) that the files will be kept on the machine before being deleted.
 * @param ThrottleTime              - Time (in seconds) that will be used for throttling introspection alerts. Setting it on 0 will disable throttling mechanism.
 *
 * @return  STATUS_SUCCESS - operation completed successfully
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestConfigureFeedback(
    _In_opt_ FEEDBACK_CONFIG_TYPES const * Generation,
    _In_opt_ QWORD const * Flags,
    _In_opt_ QWORD const * LocalBackupDuration,
    _In_opt_ QWORD const * ThrottleTime
    );

typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestConfigureFeedback)(
    _In_opt_ FEEDBACK_CONFIG_TYPES const * Generation,
    _In_opt_ QWORD const * Flags,
    _In_opt_ QWORD const * LocalBackupDuration,
    _In_opt_ QWORD const * ThrottleTime
);

/**
 * @brief Control the generation of compatibility feedback.
 *
 * @param FeedbackBuffer            - Buffer to retrieve the feedback file in memory.
 * @param FeedbackBufferSize        - Size of the FeedbackBuffer.
 * @param FeedbackBufferFilePath    - If present, path where the file will be stored on disk.
 *
 * @remarks     When requesting the feedback as a buffer, the following steps are necessary:
 *                  1. Call the function with a valid FeedbackBufferSize pointer and FeedbackBuffer set to NULL. The function will return a size sufficient to store the data in FeedbackBufferSize.
 *                  2. Allocate a buffer with the size returned.
 *                  3. Call the function again with FeedbackBufferSize equal to the size returned previously and FeedbackBuffer pointing to the allocated buffer. The function will write the data to the buffer and will update the FeedbackBufferSize parameter to indicate how much data was actually written to the buffer.
 *
 * @return STATUS_SUCCESS           - operation completed successfully
 * @return STATUS_BUFFER_TOO_SMALL  - size of FeedbackBuffer, specified in FeedbackBufferSize is too small
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGenerateCompatFeedback(
    _In_opt_ CHAR* FeedbackBuffer,
    _Inout_opt_ DWORD* FeedbackBufferSize,
    _In_opt_ const WCHAR* FeedbackBufferFilePath
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGenerateCompatFeedback)(
    _In_opt_ CHAR* FeedbackBuffer,
    _Inout_opt_ DWORD* FeedbackBufferSize,
    _In_opt_ const WCHAR* FeedbackBufferFilePath
    );

/**
 * @brief   Get all the required features needed to support the specified hypevisor configuration.
 *
 *          This function will return all detectable reasons for which a previous call to WinguestConfigureHypervisor failed.
 *          This function may also be used to check for mising features before a call to WinguestConfigureHypervisor is made
 *          but it will not reload any possible updates like hardware compatibility list. In case that the hypervisor is configured,
 *          any updates must be performed via a call to WinguestPerformUpdate and then a call to
 *          WinguestGetMissingFeatures may be performed otherwise a call to WinguestConfigureHypervisor is required to reload any new updates.
 *
 * @param   MissingFeatures - a pointer to a LOAD_MODE_MISSING_FEATURES structure in which the result will be stored; this structure is interpreted as a bitfield: for each bit that is set, its position p (p  [0 -> sizeof(LOAD_MODE_MISSING_FEATURES) * 8 - 1]) means that the status ((PTSTATUS)STATUS_PETRU_ERROR_BITS | STATUS_FACILITY_PETRU_WINGUEST | STATUS_REQUIRED_FEATURES | p) was encountered when trying to validate the supported load mode.
 *
 * @return STATUS_SUCCESS   - operation completed successfully;
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGetMissingFeatures(
    _Out_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGetMissingFeatures)(
    _Out_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    );

/**
 * @brief Get version information for a requested component.
 *
 * @param Component         - identifier for the component whose version information is required;
 * @param VersionHigh       - caller allocated buffer to hold major version;
 * @param VersionLow        - caller allocated buffer to hold minor version;
 * @param VersionRevision   - caller allocated buffer to hold revision information;
 * @param VersionBuild      - caller allocated buffer to hold revision information;
 *
 * @return STATUS_SUCCESS - operation completed successfully
 *
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGetComponentVersion(
    _In_    BIN_COMPONENT Component,
    _Inout_ PDWORD VersionHigh,
    _Inout_ PDWORD VersionLow,
    _Inout_ PDWORD VersionRevision,
    _Inout_ PDWORD VersionBuild
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGetComponentVersion)(
    _In_    BIN_COMPONENT Component,
    _Inout_ PDWORD VersionHigh,
    _Inout_ PDWORD VersionLow,
    _Inout_ PDWORD VersionRevision,
    _Inout_ PDWORD VersionBuild
    );

/**
 * @brief Get compatibility requirements between two components. It returns the version of Component2 required by Component1. If the components have not been loaded yet it will retrieve version 0.
 *
 * @param Component1        - identifier for the component that Component2 should be checked against;
 * @param Component2        - identifier for the component whose version information is requested;
 * @param VersionHigh       - caller allocated buffer to hold major version;
 * @param VersionLow        - caller allocated buffer to hold minor version;
 * @param VersionRevision   - caller allocated buffer to hold revision information;
 * @param VersionBuild      - caller allocated buffer to hold build information;
 *
 * @return STATUS_SUCCESS - retrieved required version and the requirement is met
 * @return STATUS_VERSION_INCOMPATIBLE - retrieved required version but the requirement is not met
 * @return STATUS_COMPONENT_NOT_KNOWN - Component identifiers invalid or the components have no compatibility relation between them
 *
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGetCompatibility(
    _In_    BIN_COMPONENT Component1,
    _In_    BIN_COMPONENT Component2,
    _Inout_ PDWORD VersionHigh,
    _Inout_ PDWORD VersionLow,
    _Inout_ PDWORD VersionRevision,
    _Inout_ PDWORD VersionBuild
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGetCompatibility)(
    _In_    BIN_COMPONENT Component1,
    _In_    BIN_COMPONENT Component2,
    _Inout_ PDWORD VersionHigh,
    _Inout_ PDWORD VersionLow,
    _Inout_ PDWORD VersionRevision,
    _Inout_ PDWORD VersionBuild
    );


/**
 * @brief Get the status of hypervisor and information about how it was loaded.
 *
 * @param Configured - pointer to a BOOLEAN that receives if the hypervisor was configured or not;
 * @param Started - pointer to a BOOLEAN that receives if the hypervisor is started or not;
 * @param BootMode - pointer to a BOOT_MODE that receives how the hypervisor was started;
 *
 * @return STATUS_SUCCESS - the requested values are valid
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGetHvStatus(
    _Out_opt_ BOOLEAN *Configured,
    _Out_opt_ BOOLEAN *Started,
    _Out_opt_ BOOT_MODE *BootMode
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGetHvStatus)(
    _Out_opt_ BOOLEAN *Configured,
    _Out_opt_ BOOLEAN *Started,
    _Out_opt_ BOOT_MODE *BootMode
    );


WINGUEST_DLL_API
PCHAR
WINGUEST_CALLING_CONV
WinguestNtStatusToString(
    _In_ NTSTATUS Status
    );
typedef
PCHAR
(WINGUEST_CALLING_CONV
*PFUNC_WinguestNtStatusToString)(
    _In_ NTSTATUS Status
    );

/**
 * @brief Add or remove protected processes from the Introspection engine.
 *
 * @param ProcessPath   - the name or the full path of the process that one wants to add/remove protection for.
 * @param Mask          - a bitmap that controls protection policies. A value of 0 means that the protection will be removed for the application. For a list of possible values see: Activation & protection flags;
 * @param Context       - user defined value that will be provided back to the caller when certain events are generated in the context of the protected process
 *
 * @return  STATUS_SUCCESS          - in case of success
 * @return  STATUS_NOT_FOUND        - in case introspection is not active for the current guest (either because it wasn't activated or because the guest OS is not supported)
 * @return  STATUS_NOT_INITIALIZED  - in case the introspection engine is not initialized
 *
 * @remarks     The list of protected processes is not preserved on hibernate. The processes must be added for protection on each boot and resume from hibernate.
 *              A process will be protected only if it was started after adding that process to the protected processes list. If the process is already started when adding it to the protected processes list, it will not be protected!
 *              If the ProcessPath parameter is not a full path (it contains only a base-name) then the application's process will be protected regardless of the actual path.
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetProtectedProcess(
    _In_ PWCHAR ProcessPath,
    _In_ DWORD Mask,
    _In_ QWORD Context
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestSetProtectedProcess)(
    _In_ PWCHAR ProcessPath,
    _In_ DWORD Mask,
    _In_ QWORD Context
    );

/**
 * @brief Remove all protected processes from the Introspection engine.
 *
 * @return  STATUS_SUCCESS - operation completed successfully
 *
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestRemoveAllProtectedProcesses(
    VOID
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestRemoveAllProtectedProcesses)(
    VOID
    );

/**
 * @brief Get the value of a given configuration parameter at runtime.
 *
 * @param CfgItemData - pointer to a CFG_ITEM_DATA structure that receives the value for the requested configuration parameter; caller must allocate this buffer and fill in the CFG_ITEM_DATA::Name field with the name of the configuration parameter for which he wants to retrieve its associated value;
 *
 * @return STATUS_SUCCESS                - the requested values are valid
 * @return STATUS_INSUFFICIENT_RESOURCES - in case that the value of requested configuration parameter does not fit into the allocated buffer; this is very unlikely to happen;
 * @return Any other error status        - the requested values are invalid
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestGetCfgItemData(
    _Inout_ PCFG_ITEM_DATA CfgItemData
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestGetCfgItemData)(
    _Inout_ PCFG_ITEM_DATA CfgItemData
    );


/**
 * @brief Modify dynamically the runtime variables. If the modification succeeded it tries to make the modified variable persistent on disk. If the persistent save fails, STATUS_SUCCESS is returned.
 *
 * @param Cmdline - An array of chars containing the list of templates to be applied.
 *
 * @return STATUS_SUCCESS               - operation completed successfully
 * @return STATUS_INVALID_PARAMETER_1   - NULL was passed as a parameter.
 * @return STATUS_INVALID_BUFFER_SIZE   - Size in bytes of the cmdline is too big.
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestSetCfgVar(
    _In_ const CHAR *Cmdline
    );
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestSetCfgVar)(
    _In_ const CHAR *Cmdline
    );

/**
 *
 * @brief Perform upgrade of modules containing executable code / data that is intended to be run / used at hypervisor level OR to issue comands towards such an existing and loaded module. Currently two such module exists (HVI and it's exceptions). The binaries should be placed the folders set by WinguestSetPath.
 *
 * @param ModuleId             - Module identifier of the item that will be upgraded. One of the values of BIN_COMPONENT enumeration.
 * @param ModuleCustomData     - Custom data to be passed to the module during the upgrade process (Ex: options)
 * @param ModuleCustomDataSize - Size of the custom data in bytes (it must match the structure coupled with the ModuleId)
 * @param Flags                - Flags to control the upgrade process. These flags are used by the upgrade mechanism and are not passed to the module being upgraded. Any data that needs to be passed to the module must be provided in the ModuleCustomData buffer
 *
 *             Value                               |   Description
 *         MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK   | Indicates that the module must be loaded from the disk
 *
 * @return STATUS_SUCCESS
 * @return STATUS_INVALID_PARAMETER_1 - if the first parameter contains an unsupported module id
 * @return STATUS_INVALID_PARAMETER_2 - in some cases the module data is necessary
 * @return STATUS_INVALID_PARAMETER_3 - the custom data size does not match the size of data required (if no module data is given this must be 0)
 * @return STATUS_WG_NOT_INITIALIZED - driver not connected, this operation requires an up and running connection with the driver
 * @return STATUS_INSUFFICIENT_RESOURCES - there is not enough memory to perform the operation
 * @return OTHER - Other potentially module specific value indicating the status of the upgrade operation
 * @return STATUS_INTROSPECTION_ENGINE_RESTARTED - the engine was restared
*/
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestControlModule(
    _In_ BIN_COMPONENT ModuleId,
    _In_ PVOID ModuleCustomData,
    _In_ DWORD ModuleCustomDataSize,
    _In_ QWORD Flags
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestControlModule)(
    _In_ BIN_COMPONENT ModuleId,
    _In_ PVOID ModuleCustomData,
    _In_ DWORD ModuleCustomDataSize,
    _In_ QWORD Flags
);

/**
 * @brief Perform a query for the state of the given module.
 *
 * @param ModuleId             - ID of the module. One of the values of BIN_COMPONENT enumeration.
 * @param ModuleQueryData      - Custom buffer based on the ModuleId parameter, where the queried information will be returned, in case of succes.
 * @param ModuleQueryDataSize  - Size of the custom buffer in bytes.
 * @param Flags                - Reserved
 *
 * @return STATUS_SUCCESS                  - operation completed successfully
 * @return STATUS_INVALID_PARAMETER_1      - if the first parameter contains an unsupported module id
 * @return STATUS_INVALID_PARAMETER_2      - ModuleData can not be NULL
 * @return STATUS_INVALID_PARAMETER_3      - the data size does not match the size of data required
 * @return STATUS_WG_NOT_INITIALIZED       - driver not connected, this operation requires an up and running connection with the driver
 * @return STATUS_INSUFFICIENT_RESOURCES   - there is not enough memory to perform the operation
 * @return OTHER                           - other, potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestQueryModule(
    _In_ BIN_COMPONENT ModuleId,
    _Out_ PVOID ModuleQueryData,
    _In_ DWORD ModuleQueryDataSize,
    _In_ QWORD Flags
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestQueryModule)(
    _In_ BIN_COMPONENT ModuleId,
    _Out_ PVOID ModuleQueryData,
    _In_ DWORD ModuleQueryDataSize,
    _In_ QWORD Flags
);

/**
 * @brief Add exception based on an alert generated by the introspection (generally for temporary exceptions). Additional info: Glue APIs exposed by Introcore#AddExceptionFromAlert
 *
 * @param AlertData    - Pointer to a previously generated alert that we want to except
 * @param AlertSize    - The size of the data
 * @param AlertType    - The type of the alert, an entry from the INTRO_EVENT_TYPE enumeration
 * @param IsException  - if FALSE, AlertData is a full alert; if TRUE, AlertData is the exception data extracted from the alert
 * @param Context      - Context passed with the exception(currently used solely for identifying the added exception in case of removing one)
 *
 * @return STATUS_SUCCESS                   - operation completed successfully
 * @return STATUS_INVALID_PARAMETER_1       - AlertData can not be NULL
 * @return STATUS_INVALID_PARAMETER_2       - if the AlertSize is bigger than any introspection event or the AlertSize is 0
 * @return STATUS_WG_NOT_INITIALIZED        - driver not connected, this operation requires an up and running connection with the driver
 * @return STATUS_INSUFFICIENT_RESOURCES    - there is not enough memory to perform the operation
 * @return OTHER                            - other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestAddExceptionFromAlert(
    _In_ PVOID AlertData,
    _In_ DWORD AlertSize,
    _In_ INTRO_EVENT_TYPE AlertType,
    _In_ BOOLEAN IsException,
    _In_opt_ QWORD Context
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestAddExceptionFromAlert)(
    _In_ PVOID AlertData,
    _In_ DWORD AlertSize,
    _In_ INTRO_EVENT_TYPE AlertType,
    _In_ BOOLEAN IsException,
    _In_opt_ QWORD Context
);

/**
 * @brief Clears every exception added with the WinguestAddExceptionFromAlert rutine. Additional info: Glue APIs exposed by Introcore#FlushAlertExceptions
 *
 * @return STATUS_SUCCESS
 * @return OTHER - other potential internal error
 */
WINGUEST_DLL_API
NTSTATUS
WINGUEST_CALLING_CONV
WinguestFlushAlertExceptions(
    VOID
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestFlushAlertExceptions)(
    VOID
);


/**
 * @brief Removes the exception added with the WinguestAddExceptionFromAlert rutine. Additional info: Glue APIs exposed by Introcore#FlushAlertExceptions (after the documentation gets updated)
 *
 * @param Context  - Context passed with the exception(currently used solely for identifying the added exception to be removed)
 *
 * @return STATUS_SUCCESS      - operation completed successfully
 * @return OTHER               - other potential internal error
*/
WINGUEST_DLL_API
NTSTATUS
WinguestRemoveException(
    _In_ QWORD Context
);
typedef
NTSTATUS
(WINGUEST_CALLING_CONV
*PFUNC_WinguestRemoveException)(
    _In_ QWORD Context
    );

#ifdef __cplusplus
}
#endif

#endif
/// @}
