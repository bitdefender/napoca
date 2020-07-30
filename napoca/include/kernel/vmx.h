/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file vmx.h
*   @brief VMX - Support for querying available virtualization features
*
*/
#ifndef _VMX_H_
#define _VMX_H_

#include "core.h"
#include "common/boot/cpu_features.h"


extern VIRTUALIZATION_FEATURES gVirtFeatures;           ///< The virtualization features found on the current platform

///
/// @brief        Checks if the platform supports the virtualization feature of VMFunc(VMFUNC instruction) and if the
///               feature is enabled by the HVs configuration.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsVmfuncAvailable(
    CX_VOID
)
{
    return CfgFeaturesVirtualizationVmFunc && gVirtFeatures.VmxProcBased2.Parsed.One.EnableVMFunctions;
}


///
/// @brief        Checks if the platform supports the virtualization feature of \#VE(Virtualization Exception) and if the
///               feature is enabled by the HVs configuration.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsVeAvailable(
    CX_VOID
)
{
    return CfgFeaturesVirtualizationVe && gVirtFeatures.VmxProcBased2.Parsed.One.EptViolationCauseException;
}



///
/// @brief        Checks if the platform supports the virtualization feature of SPP (Sub-Page Protection) and if the
///               feature is enabled by the HVs configuration.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsSppAvailable(
    CX_VOID
)
{
    return CfgFeaturesVirtualizationSpp && gVirtFeatures.VmxProcBased2.Parsed.One.SPP;
}



///
/// @brief        Checks if the platform supports the virtualization feature of Execute-only EPT pages.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEptExecuteOnlyPagesAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.EptExecuteOnly;
}


///
/// @brief        Checks if 1GiB pages can be used
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEpt1GPagesFeatureAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.EptSupport1GbPage;
}


///
/// @brief        Checks if the platform supports the virtualization feature of INVVPID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsInvVpidSupported(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.InvVpidSupported;
}


///
/// @brief        Checks if the platform supports the virtualization feature of individual address invalidation support for INVVPID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsInvVpidAddressInvalidationSupported(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.InvVpidAddressSupported;
}


///
/// @brief        Checks if the platform supports the virtualization feature of single context invalidation support for INVVPID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsInvVpidSingleContextInvalidationSupported(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.InvVpidSingleContextSupported;
}


///
/// @brief        Checks if the platform supports the virtualization feature of all context invalidation support for INVVPID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsInvVpidAllContextInvalidationSupported(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.InvVpidAllContextSupported;
}


///
/// @brief        Checks if the platform supports the virtualization feature of all context-retaining-globals invalidation support for INVVPID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsInvVpidAllContextRetGlobalsInvalidationSupported(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.InvVpidAllContextRetGlobalsSupported;
}


///
/// @brief        Checks if the platform supports the virtualization feature of Xsave/xrstor instruction set.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEnableXsavesXrstorsAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.VmxProcBased2.Parsed.One.EnableXsavesXrstors;
}


///
/// @brief        Checks if the platform supports the virtualization feature of concealing VMX from Intel Processor Trace in VMX non-root operation.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsConcealVmxFromPtAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.VmxProcBased2.Parsed.One.ConcealVmxFromPt;
}


///
/// @brief        Checks if the platform supports the virtualization feature of INVPCID instruction.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEnableInvpcidAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.VmxProcBased2.Parsed.One.EnableInvpcid;
}


///
/// @brief        Checks if the platform supports the virtualization feature of a page-walk length of 4 for the EPT.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEptPageWalkLength4Available(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.EptPageWalkLength4;
}


///
/// @brief        Checks if the platform supports the virtualization feature of Write-Back caching for the EPT.
///
/// @returns      TRUE in case the feature is available, FALSE otherwise
///
__forceinline
CX_BOOL
VmxIsEptWBSupportAvailable(
    CX_VOID
)
{
    return !!gVirtFeatures.EptVpidFeatures.Parsed.EptWBSupport;
}

#endif