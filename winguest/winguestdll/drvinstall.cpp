/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file drvinstall.cpp
*   @brief Driver (un)installation
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <setupapi.h>
#include <cfgmgr32.h>
#include <newdev.h>
#include <strsafe.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <atlcomcli.h>
#include <VersionHelpers.h>
#include <intrin.h>

#include "drvinstall.h"
#include "winguest_status.h"
#include "common/boot/cpu_features.h"
#include "reg_opts.h"
#include "wmi.h"
#include "bcd.h"
#include "trace.h"
#include "drvinstall.tmh"

#define TDR_REG_KEY                         L"System\\CurrentControlSet\\Control\\GraphicsDrivers" // subkey of HKLM
#define TDR_REG_KEY_VALUE_TDR_DELAY         L"TdrDelay"
#define TDR_REG_KEY_VALUE_TDR_DDI_DELAY     L"TdrDdiDelay"
#define TDR_REG_KEY_VALUE_TDR_LIMIT_COUNT   L"TdrLimitCount"

#define TDR_DELAY_VALUE                     5
#define TDR_DDI_DELAY_VALUE                 10
#define TDR_LIMIT_COUNT_VALUE               10

// http://social.technet.microsoft.com/Forums/windows/en-US/ecd96c7e-9c30-45dd-bf0d-89ff39f6d854/bsod-dpc-watchdog-violation-error
#define DPC_WATCHDOG_REG_KEY                            L"System\\CurrentControlSet\\Control\\Session Manager\\Kernel" // subkey of HKLM
#define DPC_WATCHDOG_REG_KEY_VALUE_DPCWATCHDOGPERIOD    L"DpcWatchdogPeriod"
#define DPC_WATCHDOG_REG_KEY_VALUE_DPCTIMEOUT           L"DpcTimeout"
#define WATCHDOG_DPC_TIMEOUT_VALUE                      0
#define WATCHDOG_DPC_WATCHDOGPERIOD_VALUE               0x0003a980

extern BOOLEAN gInitialized;
extern BOOLEAN gConnected;

/**
 * @brief Check if suppplied Hardware Id is white listed for installation / uninstallation
 *
 * @param[in] HwId          Device hardware Id
 *
 * @return true         White listed
 * @return false        Not White listed
 */
static
bool
_IsKnownHwId(
    __in std::wstring const& HwId
    )
{
    static std::wstring const knownHwIds[] = {
        L"{8a5531a8-2c02-482e-9b2e-99f8cacecc9d}\\BdWinguest",          // Hypervisor Control Guest Driver (winguest.sys)
        L"{8a5531a8-2c02-482e-9b2e-99f8cacecc9d}\\BdFalx"               // Hypervisor Test Guest Driver (falx.sys)
    };

    for (auto id : knownHwIds)
        if (_wcsnicmp(id.c_str(), HwId.c_str(), id.size()) == 0)
            return true;

    return false;
}

/**
 * @brief Check if string exists in MultiSz (Multiple zero terminated strings)
 *
 * @param[in] MultiSz       MultiSz
 * @param[in] SearchFor     String that is searched for
 *
 * @return true         String found
 * @return false        String not found
 */
static
bool
_DrvSearchInMultiSz(
    _In_ WCHAR const *MultiSz,
    _In_ WCHAR const *SearchFor
    )
{
    if (!MultiSz || !SearchFor) return false;

    for (; MultiSz[0]; MultiSz += wcslen(MultiSz) + 1)
    {
        if (_wcsicmp(MultiSz, SearchFor) == 0)
        {
            return true;
        }
    }

    return false;
}

static
__drv_allocatesMem(object)
/**
 * @brief Get MultiSz property for Device
 *
 * @param[in] Devs      Handle to list of devices
 * @param[in] DevInfo   Device to be querried
 * @param[in] Prop      MultiSz Property requested
 *
 * @return pointer      (new) Allocated buffer for property or NULL
 */
WCHAR*
_DrvGetMultiSzProperty(
    _In_ HDEVINFO Devs,
    _In_ SP_DEVINFO_DATA* DevInfo,
    _In_ DWORD Prop
    )
{
    WCHAR *buffer = NULL;
    DWORD size = 0;
    DWORD reqSize = 0;
    DWORD dataType;
    DWORD szChars = 0;

    while (!SetupDiGetDeviceRegistryProperty(Devs, DevInfo, Prop, &dataType, (LPBYTE)buffer, size, &reqSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER
            || dataType != REG_MULTI_SZ)
        {
            goto failed;
        }

        size = reqSize;
        szChars = reqSize / sizeof(WCHAR);

        if (buffer) delete[] buffer;
        buffer = new WCHAR[szChars + 2];
        if (!buffer)
        {
            goto failed;
        }
    }

    buffer[szChars] = L'\0';
    buffer[szChars + 1] = L'\0';

    return buffer;

failed:
    if (buffer) delete[] buffer;

    return NULL;
}

/**
 * @brief Get System OEM information file for driver
 *
 * @param[in]  Devs     Handle to list of devices
 * @param[in]  DevInfo  Device to be querried
 * @param[out] Inf      Driver information file name
 *
 * @return true         Operation successful
 * @return false        Operation failed
 */
static
bool
_DrvGetCurrentDriverOemInf(
    _In_ HDEVINFO Devs,
    _In_ SP_DEVINFO_DATA* DevInfo,
    _Out_ std::wstring& Inf
)
{
    DWORD lastErr;
    SP_DEVINSTALL_PARAMS deviceInstallParams = {};
    SP_DRVINFO_DATA driverInfoData = {};
    SP_DRVINFO_DETAIL_DATA detail = {};

    deviceInstallParams.cbSize = sizeof(deviceInstallParams);
    driverInfoData.cbSize = sizeof(driverInfoData);
    detail.cbSize = sizeof(detail);

    deviceInstallParams.FlagsEx |= (DI_FLAGSEX_INSTALLEDDRIVER | DI_FLAGSEX_ALLOWEXCLUDEDDRVS);

    if (!SetupDiSetDeviceInstallParams(Devs, DevInfo, &deviceInstallParams))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetupDiSetDeviceInstallParams");
        return false;
    }

    if (!SetupDiBuildDriverInfoList(Devs, DevInfo, SPDIT_CLASSDRIVER))
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetupDiBuildDriverInfoList");
        return false;
    }

    if (!SetupDiEnumDriverInfo(Devs, DevInfo, SPDIT_CLASSDRIVER, 0, &driverInfoData)) // got current driver
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetupDiEnumDriverInfo");
        return false;
    }

    if (!SetupDiGetDriverInfoDetail(Devs, DevInfo, &driverInfoData, &detail, sizeof(detail), NULL)
        && GetLastError() != ERROR_INSUFFICIENT_BUFFER) // this function is guaranteed to fill in all static fields in the SP_DRVINFO_DETAIL_DATA structure even if the buffer is too small
    {
        lastErr = GetLastError();
        LogFuncErrorLastErr(lastErr, "SetupDiGetDriverInfoDetail");
        return false;
    }

    // trim only the file name

    WCHAR* lastBSlash = wcsrchr(detail.InfFileName, L'\\');
    if (lastBSlash == NULL)
    {
        SetLastError(ERROR_NOT_FOUND);
        return false;
    }

    Inf = lastBSlash + 1;
    return true;
}

/**
 * @brief Remove driver service
 *
 * @param[in] ServiceName   Service to be removed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
_DrvRemoveServiceFromServiceManager(
    __in std::wstring const& ServiceName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    SC_HANDLE scManagerHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    SERVICE_STATUS serviceStatus = { 0 };

    scManagerHandle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (scManagerHandle == NULL)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "OpenSCManager");
        goto cleanup;
    }

    serviceHandle = OpenService(scManagerHandle, ServiceName.c_str(), SERVICE_ALL_ACCESS);
    if (serviceHandle == NULL)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "OpenService");;
        goto cleanup;
    }

    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus))
    {
        if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE
            && GetLastError() != ERROR_INVALID_SERVICE_CONTROL
            )
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "ControlService / SERVICE_CONTROL_STOP");
        }
    }

    if (!ChangeServiceConfig(
        serviceHandle,
        SERVICE_NO_CHANGE,
        SERVICE_DISABLED,
        SERVICE_NO_CHANGE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "ChangeServiceConfig");
    }

    if (!DeleteService(serviceHandle))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "DeleteService");
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (serviceHandle != NULL) CloseServiceHandle(serviceHandle);
    if (scManagerHandle != NULL) CloseServiceHandle(scManagerHandle);

    return status;
}

/**
 * @brief Configure BCD for better Napoca Hypervisor compatibility
 *
 * @param[in]  BootLoader       BCD entry where changes are applied
 * @param[out] RequireRestart   If restart is required to apply settings
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
static
HRESULT
_DrvConfigureBcdForHv(
    __in_opt std::wstring const& BootLoader,
    __out    BOOLEAN* RequireRestart
)
{
    HRESULT hr = E_FAIL;

    BcdStore   sysBcdStore;
    BcdObject* current = NULL;

    BOOLEAN bVal = FALSE;
    std::wstring wsVal;
    CPUID_REGS cpuidRegs = { 0 };

    if (NULL == RequireRestart) return STATUS_INVALID_PARAMETER_2;

    *RequireRestart = FALSE;

    hr = sysBcdStore.OpenStore(L"");
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenStore");
        goto cleanup;
    }

    hr = sysBcdStore.OpenObject(BootLoader, current);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "OpenObject");
        goto cleanup;
    }

    // check if CPU supports PAE, and force enable it
    __cpuid((int*)&cpuidRegs, 1);
    if (0 != (cpuidRegs.Edx & CX_BIT(6)))
    {
        hr = *RequireRestart ? E_FAIL : current->GetIntegerElement(BcdOSLoaderInteger_PAEPolicy, wsVal);
        *RequireRestart |= !(SUCCEEDED(hr) && wsVal == std::to_wstring(PaePolicyForceEnable));

        hr = current->SetIntegerElement(BcdOSLoaderInteger_PAEPolicy, PaePolicyForceEnable);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SetBooleanElement");
            goto cleanup;
        }

    }

    if (IsWindows8OrGreater())
    {
        hr = *RequireRestart ? E_FAIL : current->GetBooleanElement(BcdOsLoaderBoolean_DisableDynamicTick, bVal);
        *RequireRestart |= !(SUCCEEDED(hr) && bVal == TRUE);

        hr = current->SetBooleanElement(BcdOsLoaderBoolean_DisableDynamicTick, TRUE);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SetBooleanElement");
            goto cleanup;
        }

    }

cleanup:
    sysBcdStore.DisposeOfObject(current);
    sysBcdStore.CloseStore();

    return hr;
}

/**
 * @brief Generic API that can update a registry value but checks if required value already set
 *
 * @param[in]  Key              Registry Key
 * @param[in]  ValueName        Registry Value
 * @param[in]  NewValue         New value for ValueName
 * @param[out] Changed          If value was changed
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
_DrvQueryAndUpdateRegValue(
    __in std::wstring const& Key,
    __in std::wstring const& ValueName,
    __in DWORD NewValue,
    __out BOOL* Changed
)
{
    LSTATUS error;
    DWORD oldValue = 0;
    DWORD dwordSize = sizeof(DWORD);

    *Changed = FALSE;

    error = RegGetValue(
        HKEY_LOCAL_MACHINE,
        Key.c_str(),
        ValueName.c_str(),
        RRF_RT_REG_DWORD,
        NULL,
        &oldValue,
        &dwordSize
    );
    if (error == ERROR_SUCCESS && oldValue == NewValue)
    {
        *Changed = FALSE;
        return STATUS_SUCCESS;
    }

    *Changed = TRUE;

    error = RegSetKeyValue(
        HKEY_LOCAL_MACHINE,
        Key.c_str(),
        ValueName.c_str(),
        REG_DWORD,
        &NewValue,
        dwordSize
    );
    if (error != ERROR_SUCCESS)
    {
        LogFuncErrorLastErr(error, "RegSetKeyValue");
        return WIN32_TO_NTSTATUS(error);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Configure Graphics drivers Timeout Detection and Recovery for better Napoca Hypervisor compatibility
 *
 * @param[out] RequireRestart   If restart is required to apply settings
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
_DrvUpdateTdrValues(
    __out BOOLEAN* RequireRestart
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL restartParam = FALSE;

    if (NULL == RequireRestart) return STATUS_INVALID_PARAMETER_1;

    *RequireRestart = FALSE;

    status = _DrvQueryAndUpdateRegValue(TDR_REG_KEY, TDR_REG_KEY_VALUE_TDR_DELAY, TDR_DELAY_VALUE, &restartParam);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "QueryAndUpdateRegValue");
        goto cleanup;
    }
    *RequireRestart |= restartParam;

    status = _DrvQueryAndUpdateRegValue(TDR_REG_KEY, TDR_REG_KEY_VALUE_TDR_DDI_DELAY, TDR_DDI_DELAY_VALUE, &restartParam);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "QueryAndUpdateRegValue");
        goto cleanup;
    }
    *RequireRestart |= restartParam;

    status = _DrvQueryAndUpdateRegValue(TDR_REG_KEY, TDR_REG_KEY_VALUE_TDR_LIMIT_COUNT, TDR_LIMIT_COUNT_VALUE, &restartParam);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "QueryAndUpdateRegValue");
        goto cleanup;
    }
    *RequireRestart |= restartParam;

cleanup:
    return status;
}

/**
 * @brief Configure DPC Watchdog for better Napoca Hypervisor compatibility
 *
 * @param[out] RequireRestart   If restart is required to apply settings
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
_DrvUpdateDpcValues(
    __out BOOLEAN* RequireRestart
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL restartParam = FALSE;

    if (NULL == RequireRestart) return STATUS_INVALID_PARAMETER_1;

    *RequireRestart = FALSE;

    status = _DrvQueryAndUpdateRegValue(DPC_WATCHDOG_REG_KEY, DPC_WATCHDOG_REG_KEY_VALUE_DPCTIMEOUT, WATCHDOG_DPC_TIMEOUT_VALUE, &restartParam);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "QueryAndUpdateRegValue");
        goto cleanup;
    }
    *RequireRestart |= restartParam;

    status = _DrvQueryAndUpdateRegValue(DPC_WATCHDOG_REG_KEY, DPC_WATCHDOG_REG_KEY_VALUE_DPCWATCHDOGPERIOD, WATCHDOG_DPC_WATCHDOGPERIOD_VALUE, &restartParam);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "QueryAndUpdateRegValue");
        goto cleanup;
    }
    *RequireRestart |= restartParam;

cleanup:
    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestInstallDriver(
    __in WCHAR const* InfFile,
    __in WCHAR const* HwId,
    __in DWORD Flags,
    __in_opt VOID* Context
    )
{
    UNREFERENCED_PARAMETER((Flags, Context));

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    std::wstring hwIdList;
    GUID classGUID;
    std::wstring className;
    DWORD classLength;
    HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA deviceInfoData = {};
    DWORD instFlags = INSTALLFLAG_FORCE;
    BOOL rebootRequired;

    if (!gInitialized) return STATUS_WG_NOT_INITIALIZED;
    if (gConnected)    return STATUS_DRIVER_CONNECTION_ACTIVE;
    if (!InfFile)      return STATUS_INVALID_PARAMETER_1;
    if (!HwId)         return STATUS_INVALID_PARAMETER_2;

    LogInfo("Installing %S", HwId);

    if (!_IsKnownHwId(HwId))
    {
        status = STATUS_UNKNOWN_HW_ID;
        LogFuncErrorStatus(status, "IsKnownHwId");
        goto cleanup;
    }

    // Try to update the driver for an existing device

    if (UpdateDriverForPlugAndPlayDevices(NULL, HwId, InfFile, instFlags, &rebootRequired))
    {
        status = rebootRequired ? STATUS_DEVICE_INSTALL_REQUIRES_RESTART : STATUS_SUCCESS;
        goto cleanup;
    }

    // Couldn't update -> Try to create a device and instal the driver for it

    // Use the INF File to extract the Class GUID.
    className.resize(MAX_CLASS_NAME_LEN);
    if (!SetupDiGetINFClass(InfFile, &classGUID, &className[0], MAX_CLASS_NAME_LEN, &classLength))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiGetINFClass");
        goto cleanup;
    }
    className.resize(classLength - 1);


    // Create the container for the to-be-created Device Information Element
    deviceInfoSet = SetupDiCreateDeviceInfoList(&classGUID, 0);
    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiCreateDeviceInfoList");
        goto cleanup;
    }

    // Now create the element using the Class GUID and Name from the INF file
    deviceInfoData.cbSize = sizeof(deviceInfoData);
    if (!SetupDiCreateDeviceInfo(
        deviceInfoSet,
        className.c_str(),
        &classGUID,
        NULL,
        0,
        DICD_GENERATE_ID,
        &deviceInfoData))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiCreateDeviceInfo");
        goto cleanup;
    }

    // List of hardware ID's must be REG_MULTI_SZ (string list terminated by an empty string)
    hwIdList = HwId;
    hwIdList.push_back(L'\0'); // REG_MULTI_SZ

    // Add the HardwareID to the Device's HardwareID property.
    if (!SetupDiSetDeviceRegistryProperty(
        deviceInfoSet,
        &deviceInfoData,
        SPDRP_HARDWAREID,
        (LPBYTE)hwIdList.c_str(),
        (DWORD)(hwIdList.size() + 1) * sizeof(WCHAR)))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiSetDeviceRegistryProperty");
        goto cleanup;
    }

    // Transform the registry element into an actual devnode in the PnP HW tree.
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, deviceInfoSet, &deviceInfoData))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiCallClassInstaller");
        goto cleanup;
    }

    // update the driver for the device we just created
    if(!UpdateDriverForPlugAndPlayDevices(NULL, HwId, InfFile, instFlags, &rebootRequired))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "UpdateDriverForPlugAndPlayDevices");
        goto cleanup;
    }

    status = rebootRequired ? STATUS_DEVICE_INSTALL_REQUIRES_RESTART : STATUS_SUCCESS;

cleanup:
    if (deviceInfoSet != INVALID_HANDLE_VALUE)
    {
        SetupDiDestroyDeviceInfoList(deviceInfoSet);
    }

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestUninstallDriver(
    __in WCHAR const* InfFile,
    __in WCHAR const* HwId,
    __in DWORD Flags,
    __in_opt VOID* Context
    )
{
    UNREFERENCED_PARAMETER((Flags, Context));

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lastErr;
    HDEVINFO devs = INVALID_HANDLE_VALUE;
    DWORD devIndex;
    SP_DEVINFO_DATA devInfo;
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;
    BOOL rebootRequired = FALSE;
    BOOL remCount = 0;
    std::wstring oemInf;
    std::wstring serviceName;

    if (!gInitialized) return STATUS_WG_NOT_INITIALIZED;
    if (gConnected)    return STATUS_DRIVER_CONNECTION_ACTIVE;
    if (!HwId)         return STATUS_INVALID_PARAMETER_2;

    LogInfo("Uninstalling %S", HwId);

    if (!_IsKnownHwId(HwId))
    {
        status = STATUS_UNKNOWN_HW_ID;
        LogFuncErrorStatus(status, "IsKnownHwId");
        goto cleanup;
    }

    // get devices
    devs = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devs == INVALID_HANDLE_VALUE)
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiGetClassDevs");
        goto cleanup;
    }

    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if (!SetupDiGetDeviceInfoListDetail(devs, &devInfoListDetail))
    {
        status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
        LogFuncErrorLastErr(lastErr, "SetupDiGetDeviceInfoListDetail");
        goto cleanup;
    }

    devInfo.cbSize = sizeof(devInfo);
    for (devIndex = 0; SetupDiEnumDeviceInfo(devs, devIndex, &devInfo); devIndex++)
    {
        // determine hardware IDs and search for matches
        WCHAR* hwIds = _DrvGetMultiSzProperty(devs, &devInfo, SPDRP_HARDWAREID);

        BOOL match = _DrvSearchInMultiSz(hwIds, HwId);

        if (hwIds) delete[] hwIds;

        if (!match) continue;

        // Get the driver package inf before removing the device

        if (!_DrvGetCurrentDriverOemInf(devs, &devInfo, oemInf))
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "GetCurrentDriverOemInf");
        }

        // Remove device

        BOOL drvRebootReq;
        if (!DiUninstallDevice(NULL, devs, &devInfo, 0, &drvRebootReq))
        {
            status = WIN32_TO_NTSTATUS(lastErr = GetLastError());
            LogFuncErrorLastErr(lastErr, "DiUninstallDevice");
            goto cleanup;
        }

        rebootRequired |= drvRebootReq;
        remCount++;

        // Remove the driver package

        if (!oemInf.empty() && !SetupUninstallOEMInf(oemInf.c_str(), 0, NULL))
        {
            lastErr = GetLastError();
            LogFuncErrorLastErr(lastErr, "SetupUninstallOEMInf - Could not remove driver package");
        }
    }

    // on older Windows versions the service doesn't get removed automatically
    serviceName.resize(LINE_LEN);
    if (GetPrivateProfileString(L"Strings", L"ServiceName", NULL, &serviceName[0], static_cast<DWORD>(serviceName.size()), InfFile) != 0)
    {
        serviceName.resize(wcslen(serviceName.c_str()));
        _DrvRemoveServiceFromServiceManager(serviceName);
    }

    LogInfo("Removed %d devices", remCount);

    status = rebootRequired ? STATUS_DEVICE_INSTALL_REQUIRES_RESTART : STATUS_SUCCESS;

cleanup:
    if (devs != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devs);

    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestSetDefaultBcdValues(
    __in_opt WCHAR const* Configuration
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HRESULT hr;
    BOOLEAN requireReboot = FALSE;
    BOOLEAN paramReboot = FALSE;

    if (!gInitialized) return STATUS_WG_NOT_INITIALIZED;

    LogVerbose("Setting BCD values for %S", Configuration);

    hr = _DrvConfigureBcdForHv(Configuration ? Configuration : BCD_GUID_CURRENT, &paramReboot);
    if (FAILED(hr))
    {
        status = WIN32_TO_NTSTATUS(hr);
        LogFuncErrorHr(hr, "ConfigureBcdForHv");
        goto cleanup;
    }

    requireReboot |= paramReboot;

    status = _DrvUpdateTdrValues(&paramReboot);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DrvUpdateTdrValues");
        goto cleanup;
    }

    requireReboot |= paramReboot;

    status = _DrvUpdateDpcValues(&paramReboot);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "DrvUpdateDpcValues");
        goto cleanup;
    }

    requireReboot |= paramReboot;

    if (requireReboot) status = STATUS_CONFIGURATION_REQUIRES_RESTART;

cleanup:
    return status;
}

WINGUEST_DLL_API
NTSTATUS
WinguestPerformCleanup(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    HKEY hKey = NULL;

    LogVerbose("Removing our registry values");

    // registry cleanup - full delete of HKLM\Software\Dacia key and subkeys
    __try
    {
        error = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SOFTWARE_UM, 0, KEY_ALL_ACCESS, &hKey);
        if (error != ERROR_SUCCESS)
        {
            LogFuncErrorLastErr(error, "RegOpenKeyEx");
            status = WIN32_TO_NTSTATUS(error);
            __leave;
        }

        error = RegDeleteTree(hKey, L"Dacia");
        if (error != ERROR_SUCCESS && error != ERROR_PATH_NOT_FOUND)
        {
            LogFuncErrorLastErr(error, "RegDeleteTree");
            status = WIN32_TO_NTSTATUS(error);
            __leave;
        }
    }
    __finally
    {
        if (hKey) RegCloseKey(hKey);
    }

    return status;
}
