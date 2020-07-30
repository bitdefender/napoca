/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _VERSION_H_
#define _VERSION_H_

#include "ver.h"    // global version info

#ifdef DEBUG
#define NAPOCA_VERSION_BUILDTYPE        "Debug"                                             ///< Constant string for denoting debug builds
#else
#define NAPOCA_VERSION_BUILDTYPE        "Release"                                           ///< Constant string for denoting release builds
#endif

#define NAPOCA_VERSION_MAJOR            GLOBAL_VERSION_MAJOR                                ///< Major version of the current build
#define NAPOCA_VERSION_MINOR            GLOBAL_VERSION_MINOR                                ///< Minor version of the current build
#define NAPOCA_VERSION_REVISION         GLOBAL_VERSION_REVISION                             ///< Revision version of the current build
#define NAPOCA_VERSION_BUILDNUMBER      GLOBAL_VERSION_BUILDNUMBER                          ///< Buildnumber version of the current build

#define STRINGIFY(Macro)                                   #Macro                           ///< Convert the Macro parameter into a string literal
#define BUILD_VER(Str, Major, Minor, Rev, Build)           Str ## "`" ## STRINGIFY(Major) ## "." ## STRINGIFY(Minor) ## "." ## STRINGIFY(Rev) ## "." ## STRINGIFY(Build) ## "`" ///< Used for building the version string
#define STRINGIFY_VER(Str, Major, Minor, Rev, Build)       BUILD_VER(Str, Major, Minor, Rev, Build) ///< Wrapper for BUILD_VER macro

#define NAPOCA_BUILD_DATE               __DATE__                                            ///< Date of the current build
#define NAPOCA_BUILD_TIME               __TIME__                                            ///< Time of the current build

#ifdef DEBUG
#define VER_FILEDESCRIPTION_STR         "NAPOCA Hypervisor (DEBUG)"                         ///< File description string for debug builds
#else
#define VER_FILEDESCRIPTION_STR         "NAPOCA Hypervisor"                                 ///< File description string for release builds
#endif

#define VER_INTERNALNAME_STR            "napoca.bin"                                        ///< Internal name of the napoca binary file

#define VER_ORIGINALFILENAME_STR        VER_INTERNALNAME_STR                                ///< Wrapper for VER_INTERNALNAME_STR

#ifdef VER_LEGALCOPYRIGHT_STR
#undef VER_LEGALCOPYRIGHT_STR
#endif
#define VER_LEGALCOPYRIGHT_STR          "\251 NapocaHv. All rights reserved."               ///< Legal copyright string

#ifdef VER_COMPANYNAME_STR
#undef VER_COMPANYNAME_STR
#endif
#define VER_COMPANYNAME_STR             "NapocaHv"                                          ///< Bitdefender company name and information string

#ifdef VER_PRODUCTNAME_STR
#undef VER_PRODUCTNAME_STR
#endif
#define VER_PRODUCTNAME_STR             "NapocaHv"                                          ///< Bitdefender product name string

#define VER_PRODUCTVERSION              1                                                   ///< Product version as number

#ifdef VER_PRODUCTVERSION_STR
#undef VER_PRODUCTVERSION_STR
#endif
#define VER_PRODUCTVERSION_STR          "1"                                                 ///< Product version as string

#ifdef VER_FILEVERSION
#undef VER_FILEVERSION
#endif
#define VER_FILEVERSION                 NAPOCA_VERSION_MAJOR,NAPOCA_VERSION_MINOR,NAPOCA_VERSION_REVISION,NAPOCA_VERSION_BUILDNUMBER    ///< Version for the current build

#ifdef DEBUG
#define BDVER_FILEVERSION_MAJORMINORREVBLD2(x,y,z,w) #x "." #y "." #z "." #w ", DEBUG"      ///< Converts and formats the current build version informations for debug versions
#else
#define BDVER_FILEVERSION_MAJORMINORREVBLD2(x,y,z,w) #x "." #y "." #z "." #w                ///< Converts and formats the current build version informations for release versions
#endif
#define BDVER_FILEVERSION_MAJORMINORREVBLD1(x,y,z,w) BDVER_FILEVERSION_MAJORMINORREVBLD2(x, y, z, w)    ///< Wrapper for BDVER_FILEVERSION_MAJORMINORREVBLD2 macro

#ifdef VER_FILEVERSION_STR
#undef VER_FILEVERSION_STR
#endif
#define VER_FILEVERSION_STR             BDVER_FILEVERSION_MAJORMINORREVBLD1(NAPOCA_VERSION_MAJOR, NAPOCA_VERSION_MINOR, NAPOCA_VERSION_REVISION, NAPOCA_VERSION_BUILDNUMBER)    ///< Produces the complete, formatted string for the current build version

/**
 * @brief Used for printing all relevant informations for the current build
*/
void
PrintVersionInfo(
    );


#endif // _VERSION_H_
