/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __WINGUEST_TYPES_H__
#define __WINGUEST_TYPES_H__

typedef unsigned __int64        QWORD, *PQWORD;
typedef unsigned __int8         BYTE, *PBYTE;

#include <intsafe.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntdef.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <strsafe.h>
#include "undocumented.h"
#include "consts.h"
#include "dacia_types.h"
#include "intro_types.h"
#include "common/boot/cpu_features.h"
#include "common/boot/bootdefs.h"
#include "common/boot/loader_interface.h"
#include "common/communication/commands.h"
#include "common/kernel/napoca_version.h"
#include "common/debug/memlog.h"
typedef struct _DRV_GLOBAL_DATA
{
    BOOLEAN         Initialized;            ///< Records if the driver has been properly initialized
    BOOLEAN         DelayedInitializeDone;  ///< Records if the delayed initialization (when user mode connects) has been performed

    // driver object pointer
    WDFDRIVER      WdfDriver;
    PDRIVER_OBJECT DriverObject;
    UNICODE_STRING DriverRegistryPath;      ///< Registry path to the driver configuration data

    WDFDEVICE      WdfDevice;
    WDFDEVICE      WdfDeviceRef;

    // singleton for device
    volatile LONG  WdfdeviceCount;

    KBUGCHECK_REASON_CALLBACK_RECORD BugcheckCbRecord;  ///< Callback record for the Kernel Bugcheck Callback

    RTL_OSVERSIONINFOEXW OsVersionInfo;     ///< Windows version

    POOL_TYPE      DefaultMemPoolType;      ///< Memory Pool Type to use when allocating memory

    DWORD          ReinitMaxCallCount;      ///< Maximum number of attempts when trying to reinitialize the driver

    UNDOCUMENTED_FUNCTIONS  WinApis;        ///< Undocumented APIs imported by pointer

    // HV boot mode
    BOOT_MODE               HvBootMode;     ///< Boot mode of the Napoca hypervisor
    BOOLEAN                 HvSleeping;     ///< Set to true when a power transition to a lower state is going to occur

    // keep device locked in memory
    volatile LONG   DeviceObjectRefCnt;     ///< used to keep winguest loaded until all clients are disconnected

    // Communication with WINGUESTDLL
    PVOID                   WdfFileObject;
    HANDLE                  CommandProcessId;
    KGUARDED_MUTEX          CommandLock;
    volatile DWORD          CommandCountLimit;
    volatile DWORD          CommandActiveCount;
    KEVENT                  CommandEvent;
    CHAR                    ClientConnected;    ///< If user mode connected. Actually a BOOLEAN value but we need a signed type for calling _Interlocked* functions

    //
    // options for WINGUEST.SYS
    //
    volatile QWORD OptCommandTimeout;           ///< timeout for sending non-alert messages
    volatile QWORD OptAlertCommandTimeout;      ///< timeout for sending alert messages

    // HV data --->

    // start/stop locks and data
    BOOLEAN                 HypervisorStarted;          ///< If hypervisor is started
    BOOLEAN                 HypervisorIncompatible;     ///< If hypervisor is incompatible
    BOOLEAN                 HvCommInitialized;          ///< If hypervisor communication initialized
    volatile BOOLEAN        HvCommConnected;            ///< If hypervisor communication active
    PCOMM_SHMEM_HEADER      SharedHvMem;                ///< Pointer to the shared communication buffer allocated by the hypervisor
    QWORD                   SharedHvMemGPA;             ///< Physical address of the shared communication buffer
    SIZE_T                  SharedHvMemSize;            ///< Size of the shared communication buffer
    ERESOURCE               HvCommLock;                 ///< Lock that allows exlusive access to the communication buffer
    BOOLEAN                 HvCommLockInitialized;      ///< If HvCommLock is initialized

    // worker for HV -> WINGUEST messages
    HANDLE                  HvCommWorker;               ///< Thread that handles hypervisor messages that target the driver
    KEVENT                  HvEventThreadFinish;        ///< Event that can request termination of HvCommWorker
    KEVENT                  HvEventThreadWork;          ///< Event that can wake the HvCommWorker thread

    // worker for HV -> WINGUESTDLL messages
    HANDLE                  HvCommWorkerUm;             ///< Thread that handles hypervisor messages that target the user mode components
    KEVENT                  HvEventThreadFinishUm;      ///< Event that can request termination of HvCommWorkerUm
    KEVENT                  HvEventThreadWorkUm;        ///< Event that can wake the HvCommWorkerUm thread
    LARGE_INTEGER           HvUmTimeout;                ///< Timeout to wait for the HvCommWorkerUm thread associated events

    // <--- END HV Data

    CPU_ENTRY               CpuEntry;                   ///< Processor information that can be requested from user mode
    VIRTUALIZATION_FEATURES VirtualizationFeatures;     ///< Processor Virtualization features that can be requested from user mode
    SMX_CAPABILITIES        SmxCaps;                    ///< SMX Capabilities that can be requested from user mode

    // component versions
    NAPOCA_VERSION          NapocaVer;                  ///< Version of Napoca Hypervisor
    INT_VERSION_INFO        IntroVer;                   ///< Version of Introspection engine
    WORD                    ExceptionsVerHigh;          ///< Version (High) of Introspection exceptions
    WORD                    ExceptionsVerLow;           ///< Version (Low) of Introspection exceptions
    DWORD                   ExceptionsVerBuild;         ///< Version (Build number) of Introspection exceptions
    DWORD                   LiveSupportVerHigh;         ///< Version (High) of Introspection CAMI
    DWORD                   LiveSupportVerLow;          ///< Version (Low) of Introspection CAMI
    DWORD                   LiveSupportVerBuild;        ///< Version (Build number) of Introspection CAMI

    // version requirements
    NAPOCA_VERSION          WinguestSysRequiredByHv;    ///< Minimum driver version required by currently loaded Napoca Hypervisor

    QWORD                   HvLogPhysicalAddr;          ///< Physical address of hypervisor log
    PVOID                   HvLogVirtualAddr;           ///< Virtual address of hypervisor log
    DWORD                   HvLogSize;                  ///< Size of hypervisor log
    BOOLEAN                 HvLogReserveBuffer;         ///< If the driver reserves a buffer (to backup the hypervisor log) that will be included in a memory dump in case of Kernel Bugcheck
    BYTE                    *HvLogDrvBuffer;            ///< Address of hypervisor log backup buffer (included in a memory dump in case of Kernel Bugcheck)
} DRV_GLOBAL_DATA, *PDRV_GLOBAL_DATA;

typedef struct _FDO_DATA {
    WDFDEVICE           WdfDevice;              ///< the device this FDO manages

    PCALLBACK_OBJECT    CallbackObject;
    PVOID               CallbackObjectHandle;
} FDO_DATA, *PFDO_DATA;

extern DRV_GLOBAL_DATA gDrv;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FDO_DATA, WinguestFdoGetData)

int
WinguestExceptionFilter(
    _In_ struct _EXCEPTION_POINTERS *ep,
    _In_ PCHAR File,
    _In_ DWORD Line
    );
#define WINGUEST_EXCEPTION_FILTER WinguestExceptionFilter(GetExceptionInformation(), __FILE__, __LINE__ )

#endif //__WINGUEST_TYPES_H__
