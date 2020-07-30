/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _DACIA_TYPES_H_
#define _DACIA_TYPES_H_

#pragma pack(push)
#pragma pack(1)

// flags for WinguestGenerateCompatFeedback
#define FLAG_OPT_SEND_COMPAT_FEEDBACK_SUBMIT                        0x0000000000000001  // submit the json data
#define FLAG_OPT_SEND_COMPAT_FEEDBACK_IGNORE_CLOUD_SETTINGS         0x0000000000000002  // ignore cloud settings

// for WinguestParformUpdate
#define FLAG_UPDATE_COMPONENT_BASE              (1 << 0)
#define FLAG_UPDATE_COMPONENT_INTRO_UPDATES     (1 << 1)
#define FLAG_INSTALL_BOOT_FILES                 (1 << 2)


/**
 * @brief These represent the identifiers of various components used by hv and hvi engine
 */
typedef enum _BIN_COMPONENT
{
    compWinguestSys = 1,    /**< Identifies the kernel mode components */
    compWinguestDll = 2,    /**< Identifies the user mod components */
    compNapoca = 3,         /**< Identifies the hypervisor component */
    compIntro = 4,          /**< Identifies the hvi engine */
    compExceptions = 5,     /**< Identifies the exceptions used by the hvi engine */
    compIntroLiveUpdt = 6   /**< identifies the live updates used by the hvi engine */
}BIN_COMPONENT, *PBIN_COMPONENT;

/**
 * @brief This is used to handle version information for various components
 */
typedef struct _BIN_COMPONENT_VERSION
{
    DWORD Low;          /**< Indicates the low part of the version information */
    DWORD High;         /**< Indicates the high  part of the version information */
    DWORD Revision;     /**< Indicates the revision part of the version information */
    DWORD Build;        /**< Indicates the build number part of the version information */
}BIN_COMPONENT_VERSION, *PBIN_COMPONENT_VERSION;

//
// Module control
//
#define MC_FLAG_REQUEST_MODULE_LOAD_FROM_DISK                         0x1 // if the module needs to be loaded

#define FLAG_INTRO_CONTROL_OPTIONS          (1<<0)
#define FLAG_INTRO_CONTROL_STATE            (1<<1)
#define FLAG_INTRO_CONTROL_VERBOSITY        (1<<2)
#define FLAG_INTRO_CONTROL_ALL              (FLAG_INTRO_CONTROL_OPTIONS | FLAG_INTRO_CONTROL_STATE | FLAG_INTRO_CONTROL_VERBOSITY)

// compIntro
/**

@brief This structure is used to manage state and options for the hvi engine.

It can be used to turn on/off the hvi engine or to update the bahaviour of the hvi engine. The values for most of the fields in this structure ar opaque for
the hypervisor and are passed verbatim direclty to the hvi engine. For possible values for these fields one must consult the hvi engine documentation
*/
typedef struct _INTRO_CONTROL_MODULE_DATA
{
    struct
    {
        QWORD Options;      /**< Options that the hvi engine will use to activate / deactivate various functional features */
        BOOLEAN Enable;     /**< Global switch that controls if the hvi engine is to be completelely turned on or off. */
        DWORD Verbosity;    /**< Controls the ammount of log detail that hvi will output. */
    } ControlData;
    DWORD ControlFieldsToApply; /**< Indicates which fields from above have valid values.  One of the values of FLAG_INTRO_CONTROL_\* */
}INTRO_CONTROL_MODULE_DATA, *PINTRO_CONTROL_MODULE_DATA;

/**

@brief This structure is used to query state and options that are currently active for the hvi engine.

The values for most of the fields in this structure ar opaque for the hypervisor and are passed verbatim direclty to the hvi engine. For possible values for these fields one must consult the hvi engine documentation
This is used with WinguestControlModule() function and compIntro component id.
*/
typedef struct _INTRO_QUERY_MODULE_DATA
{
    QWORD Options;      /**< Options that the hvi engine will use to activate / deactivate various functional features */
    BOOLEAN Enabled;    /**< Global indicator if the hvi engine is turned on or completelely off. */
}INTRO_QUERY_MODULE_DATA, *PINTRO_QUERY_MODULE_DATA;

//
// WinguestSetPath flags
//
/**
@brief This is used to identify various paths for components.

Each path may point to a different local folder that an integration application chooses to use for a given kind of binaries. One may choose to keep executable code (that are highly unlikely to be updated ferquenlty)
separate from the update binaries (that may be updated with a high frequency)

For convenience all paths may be set to same folder. This is a valid usecase.

This is used with WinguestSetPath() function.
*/
typedef enum _CONFIG_PATH
{
    ConfigPathUnknown,          /**< Invalid path id. This will not be considered/used for any binary type. It is helper to iterate through all posible path ids. */
    ConfigPathBase,             /**< Identifies the base path. It will be used for core binaries. The hypervisor and the hvi engine must be located in that folder. */
    ConfigPathUpdatesIntro,     /**< Identifies the path to hvi related updates. Hvi expceptions and live update binaries will be searched for in this location. */
    ConfigPathFeedback,         /**< Identifies the path where hvi generated events will be persisted to disk for later examination. */
    ConfigPathMax               /**< Max (invalid) value for the path ids. Used only to help iterating through all possible path ids. */
} CONFIG_PATH;

/**
@brief Identifies various boot modes of the hypervisor

The hypervisor supports to be started in various ways and it will provide info on how it was started if requested.

This is used with WinguestGetHvStatus() function.
*/
typedef enum _BOOT_MODE
{
    bootUnknown = 0,            /**< Indicates that the boot mode of the hypervisor is not known. */
    bootMbr = 1,                /**< Indicates that the boot mode of the hypervisor is legacy boot mode (boot from a legacy BIOS via mbr). */
    bootMbrPxe = 2,             /**< Indicates that the boot mode of the hypervisor is network legacy boot mode. */
    bootUefi = 3,               /**< Indicates that the boot mode of the hypervisor is UEFI boot mode. */
    bootUefiPxe = 4,            /**< Indicates that the boot mode of the hypervisor is network UEFI boot mode. */
    bootModeLimit = 63          /**< Indicates that the boot mode of the hypervisor should not be more than this value */
}BOOT_MODE;

/**
@brief This is used to control the level of details to be included in a compatibility report.

This is used with WinguestGenerateCompatFeedback() function.
*/
typedef enum _CategoryDetailLevel
{
    cdlNone = 0,    /**< Lowest level of details - almost nothing will be collected */
    cdlOne,         /**< Level one - basic hardware information will be collected. In general this is enough for most usecases. */
    cdlTwo,
    cdlThree,
    cdlFour,
    cdlFive,
    cdlMaximum = cdlFive
} CATEGORY_DETAIL_LEVEL;

/**
@brief This is used to hold various hw/sw missing features that might prevent correct functionality of the hypervisor and hvi engine.

This is used with WinguestGetMissingFeatures() function.
*/
typedef struct
{
    DWORD MissingFeatures[4];
} HV_CONFIGURATION_MISSING_FEATURES, *PHV_CONFIGURATION_MISSING_FEATURES;

/**
@brief This is used to identify what kind of value is stored in a hypervisor configuration variable.

This is uesd with WinguestGetCfgItemData function
*/
typedef enum
{
    CfgValueTypeUnknown = 0,
    CfgValueTypeNumeric,
    CfgValueTypeAsciiString
} CFG_VALUETYPE;

/**
@brief This is used to retrieve the value at runtime of different hypervisor configuration variables.

This is uesd with WinguestGetCfgItemData function
*/

typedef struct _CFG_ITEM_DATA
{
    CHAR            Name[128];                             /**< NULL terminated string containing on input the name of the config parameter  */
    CFG_VALUETYPE   ValueType;                             /**< returns the type of the value for the given config parameter                 */
    DWORD           ValueLengh;                            /**< size in bytes of the value                                                   */
    union
    {
        QWORD       NumericValue;                          /**< numeric value for the parameter                  */
        CHAR        AsciiString[256];                      /**< NULL terminated string value for the parameter   */
    }Value;
}CFG_ITEM_DATA, *PCFG_ITEM_DATA;

#pragma pack(pop)

#endif // _DACIA_TYPES_H_
