/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @defgroup introinterfaceinit Introspection interface initialization module, establishes the 2-way interaction by offering APIs for the Introspection engine
/// @ingroup introspection
///@{

/** @file intronapoca.c
*   @brief INTRONAPOCA - NAPOCA hypervisor glue layer, interface initializations for introspection
*
*/
#include "introspection/intronapoca.h"
#include "common/kernel/napoca_compatibility.h"
#include "introstatus.h"
#include "introspection/glue_layer/introguests.h"
#include "introspection/glue_layer/introphysmem.h"
#include "introspection/glue_layer/introept.h"
#include "introspection/glue_layer/intromsrhook.h"
#include "introspection/glue_layer/introreghook.h"
#include "introspection/glue_layer/introcpu.h"
#include "introspection/glue_layer/introspinlock.h"
#include "introspection/glue_layer/introtimer.h"
#include "introspection/glue_layer/introhvcall.h"
#include "introspection/glue_layer/introheap.h"
#include "introspection/glue_layer/intromisc.h"
#include "io/io.h"


NTSTATUS
IntNapInitGlueInterface(
    _Inout_ PVOID GlueInterfaceBuffer,
    _In_    DWORD BufferLength,
    _In_    DWORD RequestedIfaceVersion
    )
{
    PGLUE_IFACE iface;

    if (GlueInterfaceBuffer == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    // IMPORTANT: for now we support only one single version, the latest

    if (RequestedIfaceVersion != GLUE_IFACE_VERSION_LATEST) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (BufferLength < GLUE_IFACE_VERSION_LATEST_SIZE) return CX_STATUS_INVALID_PARAMETER_2;

    iface = (PGLUE_IFACE)GlueInterfaceBuffer;

    memzero(iface, BufferLength);

    iface->Version = GLUE_IFACE_VERSION_LATEST;
    iface->Size = GLUE_IFACE_VERSION_LATEST_SIZE;
    iface->Reserved = 0;
    iface->QueryGuestInfo = GuestIntNapQueryGuestInfo;
    iface->NotifyIntrospectionAlert = GuestIntNapIntroEventNotify;

    iface->GpaToHpa = GuestIntNapGpaToHpa;
    iface->PhysMemMapToHost = GuestIntNapPhysMemMapToHost;
    iface->PhysMemUnmap = GuestIntNapPhysMemUnmap;

    iface->EnableCrWriteExit = GuestIntNapEnableCrWriteExit;
    iface->DisableCrWriteExit = GuestIntNapDisableCrWriteExit;
    iface->RegisterCrWriteHandler = GuestIntNapRegisterCrWriteHandler;
    iface->UnregisterCrWriteHandler = GuestIntNapUnregisterCrWriteHandler;

    iface->EnableMSRExit = GuestIntNapEnableMsrExit;
    iface->DisableMSRExit = GuestIntNapDisableMsrExit;
    iface->RegisterMSRHandler = GuestIntNapRegisterMsrHandler;
    iface->UnregisterMSRHandler = GuestIntNapUnregisterMsrHandler;

    iface->GetEPTPageProtection = GuestIntNapGetEPTPageProtection;
    iface->SetEPTPageProtection = GuestIntNapSetEPTPageProtection;
    iface->GetEPTPageConvertible = GuestIntNapGetEPTPageConvertible;
    iface->SetEPTPageConvertible = GuestIntNapSetEPTPageConvertible;
    iface->SetSPPPageProtection = GuestIntNapSetSPPPageProtection;
    iface->GetSPPPageProtection = GuestIntNapGetSPPPageProtection;

    iface->SetVeInfoPage = GuestIntNapSetVEInfoPage;
    iface->CreateEPT = GuestIntNapCreateEPT;
    iface->DestroyEPT = GuestIntNapDestroyEPT;
    iface->SwitchEPT = GuestIntNapSwitchEPT;
    iface->RegisterEPTHandler = GuestIntNapRegisterEptHandler;
    iface->UnregisterEPTHandler = GuestIntNapUnregisterEptHandler;

    iface->PhysMemGetTypeFromMtrrs = GuestIntNapGetPhysicalPageTypeFromMtrrs;

    iface->ReserveVaSpaceWithPt = GuestIntNapReserveVaSpaceWithPt;

    iface->PauseVcpus = GuestIntNapPauseVcpus;
    iface->ResumeVcpus = GuestIntNapResumeVcpus;

    iface->ToggleRepOptimization = GuestIntNapToggleRepOptimization;

    iface->RegisterIntroCallHandler = GuestIntNapRegisterIntroCallHandler;
    iface->UnregisterIntroCallHandler = GuestIntNapUnregisterIntroCallHandler;

    iface->RegisterIntroTimerHandler = GuestIntNapRegisterVmxTimerHandler;
    iface->UnregisterIntroTimerHandler = GuestIntNapUnregisterVmxTimerHandler;

    iface->RegisterDtrHandler = GuestIntNapRegisterDescriptorTableHandler;
    iface->UnregisterDtrHandler = GuestIntNapUnregisterDescriptorTableHandler;

    iface->RegisterXcrWriteHandler = GuestIntNapRegisterXcrWriteHandler;
    iface->UnregisterXcrWriteHandler = GuestIntNapUnregisterXcrWriteHandler;

    iface->RegisterBreakpointHandler = GuestIntNapRegisterBreakpointHandler;
    iface->UnregisterBreakpointHandler = GuestIntNapUnregisterBreakpointHandler;

    iface->RegisterEventInjectionHandler = GuestIntNapRegisterEventInjectionHandler;
    iface->UnregisterEventInjectionHandler = GuestIntNapUnregisterEventInjectionHandler;

    iface->InjectTrap = GuestIntNapInjectTrap;

    iface->NotifyIntrospectionDetectedOs = GuestIntNapNotifyGuestDetectedOs;
    iface->NotifyIntrospectionErrorState = GuestIntNapNotifyIntrospectionErrorState;

    iface->SetIntroEmulatorContext = GuestIntNapSetIntroEmulatorContext;

    iface->NotifyIntrospectionActivated = GuestIntNapNotifyIntrospectionActivated;
    iface->NotifyIntrospectionDeactivated = GuestIntNapNotifyIntrospectionDeactivated;

    iface->ReleaseBuffer = GuestIntNapReleaseBuffer;

    return CX_STATUS_SUCCESS;
}



NTSTATUS
IntNapInitUpperInterface(
    _Inout_ PVOID UpperInterfaceBuffer,
    _In_    DWORD BufferLength,
    _In_    DWORD RequestedIfaceVersion
    )
{
    PUPPER_IFACE upperIface;

    if (UpperInterfaceBuffer == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (RequestedIfaceVersion != UPPER_IFACE_VERSION_LATEST) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (BufferLength < UPPER_IFACE_VERSION_LATEST_SIZE) return CX_STATUS_INVALID_PARAMETER_2;

    upperIface = (PUPPER_IFACE)UpperInterfaceBuffer;

    memzero(upperIface, BufferLength);

    // initialize upper interface
    upperIface->Version = UPPER_IFACE_VERSION_LATEST;
    upperIface->Size = UPPER_IFACE_VERSION_LATEST_SIZE;
    upperIface->TracePrint = TracePrint;
    upperIface->MemAllocWithTagAndInfo = GuestIntNapHpAllocWithTagAndInfo;
    upperIface->MemFreeWithTagAndInfo = GuestIntNapHpFreeWithTagAndInfo;

    upperIface->SpinLockInit = GuestIntNapSpinLockInit;
    upperIface->SpinLockUnInit = GuestIntNapSpinLockUnInit;
    upperIface->SpinLockAcquire = GuestIntNapSpinLockAcquire;
    upperIface->SpinLockRelease = GuestIntNapSpinLockRelease;
    upperIface->RwSpinLockInit = GuestIntNapRwSpinLockInit;
    upperIface->RwSpinLockUnInit = GuestIntNapRwSpinLockUnInit;
    upperIface->RwSpinLockAcquireExclusive = GuestIntNapRwSpinLockAcquireExclusive;
    upperIface->RwSpinLockAcquireShared = GuestIntNapRwSpinLockAcquireShared;
    upperIface->RwSpinLockReleaseExclusive = GuestIntNapRwSpinLockReleaseExclusive;
    upperIface->RwSpinLockReleaseShared = GuestIntNapRwSpinLockReleaseShared;
    upperIface->QueryHeapSize = GuestIntNapQueryHeapSize;
    upperIface->EnterDebugger = GuestIntNapEnterDebugger;
    upperIface->BugCheck = GuestIntNapBugCheck;

    return CX_STATUS_SUCCESS;
}


///@}