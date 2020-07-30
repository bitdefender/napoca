/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _NAPOCA_VERSION_H_
#define _NAPOCA_VERSION_H_

#include "cx_native.h"
#include "base/cx_status.h"

/*! @def NAPOCA_VERSION
 *
 *  @brief Contains the version of a component consisting of 4 hierarchical version descriptors
*/
typedef struct _NAPOCA_VERSION
{
    CX_UINT32   High;
    CX_UINT32   Low;
    CX_UINT32   Revision;
    CX_UINT32   Build;
} NAPOCA_VERSION;

/**
 * @brief Validates a version requirement
 *
 * @param[in]       ActualVersion       Version to be validated
 * @param[in]       RequiredVersion     Minimum version requirement
 *
 * @return CX_STATUS_SUCCESS            ActualVersion meets the requirement of RequiredVersion
 * @return CX_STATUS_OUT_OF_RANGE       ActualVersion does not meet requirement of RequiredVersion
 */
__forceinline
CX_STATUS
CheckCompatibility(
    _In_ NAPOCA_VERSION *ActualVersion,
    _In_ NAPOCA_VERSION *RequiredVersion
    )
{
    typedef union
    {
        CX_UINT64 Raw;
        struct
        {
            CX_UINT64 Build :16;
            CX_UINT64 Rev   :16;
            CX_UINT64 Minor :16;
            CX_UINT64 Major :16;
        };
    }VER;

    VER actualVer = {0}, reqVer = {0};

    if (ActualVersion == CX_NULL) return CX_STATUS_INVALID_PARAMETER_1;

    actualVer.Major = ActualVersion->High;
    actualVer.Minor = ActualVersion->Low;
    actualVer.Rev = ActualVersion->Revision;
    actualVer.Build = 0;

    reqVer.Major = RequiredVersion->High;
    reqVer.Minor = RequiredVersion->Low;
    reqVer.Rev = RequiredVersion->Revision;
    reqVer.Build = 0;

    return actualVer.Raw < reqVer.Raw ? CX_STATUS_OUT_OF_RANGE : CX_STATUS_SUCCESS;
}

/**
 * @brief Fills the fields of a #NAPOCA_VERSION structure
 *
 * @param[out]      Version             Version to initialize
 * @param[in]       High                Component High Version
 * @param[in]       Low                 Component Low Version
 * @param[in]       Revision            Component Revision
 * @param[in]       Build               Component Build Number
 */
__forceinline
CX_VOID
MakeVersion(
    _Out_ NAPOCA_VERSION *Version,
    _In_ CX_UINT32 High,
    _In_ CX_UINT32 Low,
    _In_ CX_UINT32 Revision,
    _In_ CX_UINT32 Build
    )
{
    Version->High = High;
    Version->Low = Low;
    Version->Revision = Revision;
    Version->Build = Build;
}

#endif // _NAPOCA_VERSION_H_
