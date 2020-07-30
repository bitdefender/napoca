/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file deploy_validation.cpp
*   @brief Validate deployment requirements and integrity
*/

#include <cwctype>
#include <algorithm>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <VersionHelpers.h>
#include <Shlobj.h>

#include <PowrProf.h>
//#include <powerbase.h> // if targeted for Win8+

#include "winguest_status.h"
#include "common/boot/cpu_features.h"
#include "deploy_validation.h"
#include "deploy_legacy.h"
#include "deploy_uefi.h"
#include "helpers.h"
#include "consts.h"

#include "trace.h"
#include "deploy_validation.tmh"

#define BIT(n)                                  (1ull << (n))

/// note: PowerDeterminePlatformRoleEx exists in Win8. Load from Lib instead of dll when Windows target SDK will be upgraded.
/*POWER_PLATFORM_ROLE
WINAPI
PowerDeterminePlatformRoleEx(
    _In_  ULONG Version
    );*/
typedef POWER_PLATFORM_ROLE(WINAPI* PFUNC_PowerDeterminePlatformRoleEx) (_In_ ULONG Version);

static BOOLEAN gIsUefiBooted = FALSE;
static BOOLEAN gIsSecureBoot = FALSE;

extern CPU_ENTRY gCpu;
extern VIRTUALIZATION_FEATURES gVirtFeat;
extern QWORD    gHostCr4;

extern BOOLEAN gHypervisorStarted;
extern BOOLEAN gHypervisorConfigured;

BOOLEAN gOverrideBootx64;

//<FAMILY>00 + extended model(<'extended_model'> << 4 + model)

static WORD gIntelProcessorsFamilyModel[] = {
                                        //i3, i5, i7
                                             0x060a
                                            ,0x061a
                                            ,0x061e
                                            ,0x0625
                                            ,0x062a
                                            ,0x062c
                                            ,0x062d
                                            ,0x063a
                                            ,0x063c
                                            ,0x063e
                                            ,0x0645
                                            ,0x0646
                                        //xeon
                                            ,0x060f
                                            ,0x0617
                                            ,0x061d
                                            ,0x062e
                                            ,0x062f
                                            ,0x0f01
                                            ,0x0f02
                                            ,0x0f03
                                            ,0x0f04
                                        //Celeron
                                            ,0x0637
                                        //Atom
                                            ,0x064d
                                        //Broadwell
                                            ,0x063d
};

/**
 * @brief Map multiple statuses into a bitmap
 *
 * @param[out]    Status            Winguest Status
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return true         ok
 * @return false        an error occured
 */
bool
StatusToFeaturesBitmask(
    __in NTSTATUS Status,
    __inout PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    DWORD status;
    DWORD fieldSize;

    if (!MissingFeatures)
    {
        return false;
    }

    // LogVerbose("get bitmap for: %x\n", Status);

    fieldSize = sizeof(MissingFeatures->MissingFeatures[0]) * 8;

    if (REQUIRED_FEATURES_MASK == (REQUIRED_FEATURES_MASK & Status))
    {
        status = (Status & 0xFF);
        MissingFeatures->MissingFeatures[status / fieldSize] |= BIT(status % fieldSize);
        // LogInfo("new features: %x\n", MissingFeatures->MissingFeatures[status / (sizeof(DWORD) * 8)]);
    }
    /*else
    {
        LogError("\n\n\nbitmap: Invalid status!\n\n\n");
    }*/

    return true;
}

/**
 * @brief Get minimum required RAM for Napoca Hypervisor
 *
 * @return RAM required
 */
static
constexpr
ULONGLONG
GetMinPhysicalMemoryReq(
    void
)
{
    return (ULONGLONG)(ONE_GIGABYTE);
}

/**
 * @brief Detect whether system is booted via UEFI or Legacy BIOS firmware
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
DetectFirmwareInfo(
    void
)
{
    DWORD ret = 0;

    gIsUefiBooted = FALSE;
    gIsSecureBoot = FALSE;

    ret = GetFirmwareEnvironmentVariable(L"", L"{00000000-0000-0000-0000-000000000000}", NULL, 0);
    gIsUefiBooted = ((0 == ret) && (ERROR_INVALID_FUNCTION != GetLastError()));

    if (gIsUefiBooted)
    {
        ret = GetFirmwareEnvironmentVariable(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &gIsSecureBoot, sizeof(gIsSecureBoot));
    }

    LogInfo("Detected firmware info: EFI: %s SecureBoot: %s\n",
        gIsUefiBooted ? "true" : "false",
        gIsSecureBoot ? "true" : "false");

    return STATUS_SUCCESS;
}

/**
 * @brief Check whether system is booted via UEFI or Legacy BIOS firmware
 *
 * @return true             UEFI firmware
 * @return false            Legacy BIOS firmware
 */
BOOLEAN
IsUefiBootedOs(
    void
)
{
    return gIsUefiBooted;
}

/**
 * @brief Check whether UEFI Secure Boot is enabled
 *
 * @return true             Secure Boot enabled
 * @return false            Secure Boot disabled
 */
BOOLEAN
IsSecureBootEnabled(
    void
)
{
    return gIsSecureBoot;
}

/**
 * @brief Check if running in VMWare
 *
 * @return true             VMWare detected
 * @return false            VMWare not found
 */
static
bool
CheckIfRunningInVMWare(
    void
)
{
    int regs[4] = { 0 };
    char hyper_vendor_id[13];

    __cpuid(regs, 0x1);

    if (regs[2] & HYPERVISOR_PRESENT_BIT)
    {
        __cpuid(regs, 0x40000000);
        memcpy(hyper_vendor_id + 0, &regs[1], 4);
        memcpy(hyper_vendor_id + 4, &regs[2], 4);
        memcpy(hyper_vendor_id + 8, &regs[3], 4);
        hyper_vendor_id[12] = '\0';
        if (!strcmp(hyper_vendor_id, "VMwareVMware"))
        {
            return true;    // Success - running under VMware
        }
    }

    return false;
}

/**
 * @brief Check if running in HyperV
 *
 * @return true             HyperV detected
 * @return false            HyperV not found
 */
static
bool
CheckIfRunningInHyperV(
    void
)
{
    int regs[4] = { 0 };
    std::string hyper_vendor_id;

    hyper_vendor_id.resize(3 * sizeof(DWORD));

    __cpuid(regs, 0x1);

    if (regs[2] & HYPERVISOR_PRESENT_BIT)
    {
        __cpuid(regs, 0x40000000);
        memcpy(&hyper_vendor_id[0], &regs[1], 3 * sizeof(DWORD));

        if (hyper_vendor_id == "Microsoft Hv")
        {
            return true;    // Success - running under HyperV
        }
    }

    return false;
}

/**
 * @brief Check if running in VirtualBox
 *
 * @return true             VirtualBox detected
 * @return false            VirtualBox not found
 */
static
bool
CheckIfRunningInVBox(
    void
)
{
    NTSTATUS status = STATUS_SUCCESS;
    LSTATUS error;
    std::wstring biosVersion;
    DWORD biosVersionSize;

    {
        HKEY hKey = NULL;

        // detect VirtualBox - Method 1 (http://pastebin.com/RU6A2UuB)
        error = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\ACPI\\DSDT\\VBOX__",
            0,
            STANDARD_RIGHTS_READ, // maybe not necessary
            &hKey
        );
        if (error == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            hKey = NULL;
            LogVerbose("ACPI\\DSDT\\VBOX__ found");

            return true;
        }
    }

    {
        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System",
            L"SystemBiosVersion",
            RRF_RT_REG_MULTI_SZ,
            NULL,
            NULL,
            &biosVersionSize
        );
        if (error != ERROR_SUCCESS)
        {
            goto check_videobios;
        }

        biosVersion.resize(biosVersionSize / sizeof(WCHAR));

        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System",
            L"SystemBiosVersion",
            RRF_RT_REG_MULTI_SZ,
            NULL,
            &biosVersion[0],
            &biosVersionSize
        );
        if (error != ERROR_SUCCESS)
        {
            LogFuncErrorLastErr(error, "RegGetValue");
            status = WIN32_TO_NTSTATUS(error);
            goto check_videobios;
        }

        biosVersion.resize(biosVersionSize / sizeof(WCHAR) - 1);

        std::transform(biosVersion.begin(), biosVersion.end(), biosVersion.begin(), std::towlower);

        if (biosVersion.find(L"vbox", 0) != std::string::npos)
        {
            return true;
        }
    }

check_videobios:
    {
        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System",
            L"VideoBiosVersion",
            RRF_RT_REG_MULTI_SZ,
            NULL,
            NULL,
            &biosVersionSize
        );
        if (error != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        biosVersion.resize(biosVersionSize / sizeof(WCHAR));

        error = RegGetValue(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System",
            L"VideoBiosVersion",
            RRF_RT_REG_MULTI_SZ,
            NULL,
            &biosVersion[0],
            &biosVersionSize
        );
        if (error != ERROR_SUCCESS)
        {
            LogFuncErrorLastErr(error, "RegGetValue");
            goto cleanup;
        }

        biosVersion.resize(biosVersionSize / sizeof(WCHAR) - 1);

        std::transform(biosVersion.begin(), biosVersion.end(), biosVersion.begin(), std::towlower);

        if (biosVersion.find(L"oracle",     0) != std::string::npos
            || biosVersion.find(L"virtualbox", 0) != std::string::npos)
        {
            return true;
        }
    }

cleanup:
    return false;
}

/**
 * @brief Check if running in common virtualization enviromnents
 *
 * @param[out] InVm     If another Hypervisor detected
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
CheckInVm(
    __in BOOLEAN* InVm
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (NULL == InVm)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    // check VBox
    *InVm = CheckIfRunningInVBox();

    // check VMWARE
    if (*InVm == FALSE)
    {
        *InVm = CheckIfRunningInVMWare();
    }

    if (*InVm == FALSE)
    {
        *InVm = CheckIfRunningInHyperV();
    }

    return status;
}

/**
 * @brief Check if software environment is compatible with Napoca Hypervisor
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckEnvironment(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inVm = FALSE;

    __try
    {
        if (!IsWindows7OrGreater())
        {
            LogError("Windows version not supported!\n");
            status = STATUS_OS_VERSION_NOT_SUPPORTED;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = CheckInVm(&inVm);
        if (inVm)
        {
            LogError("Detected virtualized guest - cannot install winguest\n");
            status = STATUS_NOT_SUPPORTED_WHILE_IN_VM;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }
    }
    __finally
    {
    }

    return status;
}
/**
 * @brief Check Connected Standby support
 *
 * @return true             Connected Standby supported
 * @return false            Connected Standby not supported
 */
bool
GetConnectedStandbySupport(
    void
)
{
    NTSTATUS status;
    SYSTEM_POWER_CAPABILITIES powerCaps = { 0 };
    DWORD majorVer = 0;
    DWORD minorVer = 0;

    status = GetWindowsVersion(&majorVer, &minorVer, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "GetWindowsVersion");
        return false;
    }

    if (majorVer < 6 || (majorVer == 6 && minorVer < 2))
    {
        // Windows <= 7
        return false;
    }

    // Windows >= 8
    status = CallNtPowerInformation(
        SystemPowerCapabilities,
        NULL,
        0,
        &powerCaps,
        sizeof(SYSTEM_POWER_CAPABILITIES)
    );
    if (!NT_SUCCESS(status))
    {
        LogFuncErrorStatus(status, "CallNtPowerInfotmation");
        return false;
    }

    return !!powerCaps.AoAc;
}

/**
 * @brief Get machine Power Platform Role
 *
 * @param[out] PlatformRole     Power Platform Role
 */
void
GetPowerPlatformRole(
    POWER_PLATFORM_ROLE* PlatformRole
)
{
    HRESULT hRes = E_FAIL;

    PFUNC_PowerDeterminePlatformRoleEx pPowerDeterminePlatformRoleEx = NULL;
    DWORD winMajor = 0;
    DWORD winMinor = 0;

    PWCHAR sys32Path = NULL;
    std::wstring dllPath;

    GetWindowsVersion(&winMajor, &winMinor, NULL, NULL, NULL, NULL, NULL, NULL);

    if ((winMajor > 6 || (winMajor == 6 && winMinor >= 2))) // >= Win8
    {
        hRes = SHGetKnownFolderPath(
            FOLDERID_System,
            KF_FLAG_DEFAULT_PATH | KF_FLAG_NO_ALIAS | KF_FLAG_DONT_UNEXPAND,
            NULL,
            &sys32Path
        );
        if (SUCCEEDED(hRes))
        {
            dllPath = std::wstring(sys32Path) + L"\\Powrprof.dll";

            CoTaskMemFree(sys32Path);
            sys32Path = NULL;

            pPowerDeterminePlatformRoleEx = (PFUNC_PowerDeterminePlatformRoleEx)GetProcAddress(GetModuleHandle(dllPath.c_str()), "PowerDeterminePlatformRoleEx");
        }
    }

    if (pPowerDeterminePlatformRoleEx)
    {
        *PlatformRole = pPowerDeterminePlatformRoleEx(POWER_PLATFORM_ROLE_V2);
    }
    else
    {
        *PlatformRole = PowerDeterminePlatformRole();
    }
}

/**
 * @brief Check if processor meets requirements of Napoca Hypervisor
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckProcessor(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CPUID_REGS cpuidRegs = { 0 };

    __try
    {
        // must be an Intel CPU
        if (!gCpu.ProcessorType.Intel)
        {
            LogError("Not an Intel CPU.\n");
            status = STATUS_UNSUPPORTED_CPU;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        // this CPU must support PAE
        __cpuid((int*)&cpuidRegs, 1);
        if (0 == (cpuidRegs.Edx & 0x40))
        {
            LogError("This CPU doesn't supports PAE.\n");
            status = STATUS_UNSUPPORTED_CPU;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }
        // and must have PAE enabled
        if (0 == (gHostCr4 & 0x20))
        {
            LogError("This CPU doesn't have PAE enabled.\n");
            status = STATUS_UNSUPPORTED_CPU;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check if processor is in white list of supported Intel families
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckProcessorCharacteristics(
    void
)
{
    DWORD family = gCpu.FamilyFields.ExtendedFamily;
    family = family + gCpu.FamilyFields.Family;

    DWORD model = gCpu.FamilyFields.ExtendedModel;
    model = (model << 4) | gCpu.FamilyFields.Model;

    DWORD processorCharacteristic = (family << 8) | model;

    for (DWORD i = 0; i < _countof(gIntelProcessorsFamilyModel); i++)
    {
        if (processorCharacteristic == gIntelProcessorsFamilyModel[i])
        {
            //LogVerbose("Found processor %x at %x\n", model, i);
            return STATUS_SUCCESS;
        }
    }

    std::string brandIdentificationString;
    INT32 regs[4];

    brandIdentificationString.resize(3 * 4 * sizeof(DWORD));
    for (INT32 tempI = 0; tempI < 3; tempI++)
    {
        __cpuid(regs, (INT32)0x80000002 + tempI);
        memcpy(&brandIdentificationString[4 * sizeof(DWORD) * tempI], regs, 4 * sizeof(DWORD));
    }

    LogError("Name: %s, family: %x, model: %x characteristic: %x\n", gCpu.Name, family, model, processorCharacteristic);
    LogError("Processor: %s is not supported!\n", brandIdentificationString.c_str());

    return STATUS_UNSUPPORTED_PLATFORM;
}

/**
 * @brief Check if processor meets virtualization requirements of Napoca Hypervisor
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckVirtualizationFeatures(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try
    {
        // in case hv is started the we
        if (gHypervisorStarted)
        {
            return STATUS_SUCCESS;
        }

        // check global lock and state of VMX
        if (0 == (gVirtFeat.MsrFeatureControl & 0x4) && (0 != (gVirtFeat.MsrFeatureControl & 0x1)))
        {
            status = STATUS_VMX_FEATURES_LOCKED_DISABLED;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        // check single guest virtualization features
        if ((0 != gCpu.MiscIntelFeatures.x64) &&
            (0 != gCpu.MiscIntelFeatures.VMX) &&
            (0 != gCpu.MiscIntelFeatures.EPT) &&
            (0 != gCpu.MiscIntelFeatures.VPID) &&
            (0 != gCpu.MiscIntelFeatures.CMPXCHG16B) &&
            (0 != gCpu.MiscIntelFeatures.InvariantTSC) &&
            (0 != gVirtFeat.VmxProcBased2.Parsed.One.UnrestrictedGuest) &&
            (0 != gCpu.IntelFeatures.Edx.PAE)
            )
        {
        }
        else
        {
            LogError("Requested virtualization features for one guest not detected.\n");
            status = STATUS_VIRTUALIZATION_FEATURES_NOT_AVAILABLE;
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check other miscellaneous requirements of Napoca Hypervisor
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckMiscFeatures(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    POWER_PLATFORM_ROLE platformRole = PlatformRoleUnspecified;

    __try
    {
        GetPowerPlatformRole(&platformRole);
        if (PlatformRoleSlate == platformRole)
        {
            LogInfo("Determined platform role: %d!", platformRole);
            status = CheckProcessorCharacteristics();
            if (NT_SUCCESS(status))
            {
                LogInfo("Supported!\n");
            }
            else
            {
                LogError("Not supported!\n");
                if (!StatusToFeaturesBitmask(status, MissingFeatures))
                {
                    __leave;
                }
            }
        }

        ULONGLONG totalPhysMemInKb = { 0 };
        if (GetPhysicallyInstalledSystemMemory(&totalPhysMemInKb))
        {
            const ULONGLONG minReqInKb = GetMinPhysicalMemoryReq() / ONE_KILOBYTE;

            LogInfo("Determined %lld kb of ram! Minimum required is %lld kb!\n", totalPhysMemInKb, minReqInKb);
            if (totalPhysMemInKb < minReqInKb)
            {
                status = STATUS_INSUFFICIENT_PHYSICAL_MEMORY;
                if (!StatusToFeaturesBitmask(status, MissingFeatures))
                {
                    __leave;
                }
            }
        }
        else
        {
            LogError("Could not determine amount of physical memory! 0x%x\n", GetLastError());
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check all requirements of Napoca Hypervisor
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckRequiredFeatures(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try
    {
        status = CheckEnvironment(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CheckEnvironment");
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = CheckProcessor(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CheckProcessor");
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = CheckVirtualizationFeatures(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CheckVirtualizationFeatures");
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = CheckMiscFeatures(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CheckMiscFeatures");
            if (!StatusToFeaturesBitmask(status, MissingFeatures))
            {
                __leave;
            }
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check required features for Napoca Hypervisor Before OS boot
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckBeforeOsFeatures(
    __in_opt PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try
    {
        if (IsUefiBootedOs())
        {
            if (ConfigUefiSupported())
            {
                status = STATUS_SUCCESS;
                __leave;
            }
        }
        else
        {
            status = ConfigGrubSupported(MissingFeatures);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ConfigGrubSupported");
                if (!StatusToFeaturesBitmask(status, MissingFeatures))
                {
                    __leave;
                }
            }
        }
        status = STATUS_SUCCESS;
    }
    __finally
    {
    }

    return status;
}

/**
 * @brief Check previously performed configuration integrity
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
static
NTSTATUS
CheckConfigurationIntegrity(
    _Out_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
)
{
    if (IsUefiBootedOs())
    {
        if (FAILED(UefiCheckConfigurationIntegrity()))
        {
            StatusToFeaturesBitmask(STATUS_BOOT_ORDER_OVERRIDEN, MissingFeatures);
        }
    }
    else
    {
        DWORD ourMbrCount = 0;

        NTSTATUS status = GetSystemLegacyConfiguration(NULL, &ourMbrCount, NULL, FALSE);
        if (!NT_SUCCESS(status) || ourMbrCount == 0)
        {
            StatusToFeaturesBitmask(STATUS_BOOT_ORDER_OVERRIDEN, MissingFeatures);
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Validate Hypervisor configuration
 *
 * @param[in,out] MissingFeatures   Bitmap that maps statuses
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
ValidateHvConfiguration(
    _Out_opt_ PHV_CONFIGURATION_MISSING_FEATURES MissingFeatures
    )
{
    NTSTATUS status = STATUS_HV_CONFIGURATION_NOT_SUPPORTED;
    BOOLEAN compatible = TRUE;

    __try
    {
        status = CheckRequiredFeatures(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            compatible = FALSE;
        }

        status = CheckBeforeOsFeatures(MissingFeatures);
        if (!NT_SUCCESS(status))
        {
            compatible = FALSE;
        }

        if (gHypervisorConfigured)
        {
            CheckConfigurationIntegrity(MissingFeatures);
        }
    }
    __finally
    {
    }

    return compatible ? STATUS_SUCCESS : STATUS_HV_CONFIGURATION_NOT_SUPPORTED;
}


/**
 * @brief Validate Hypervisor Confiruation thread
 *
 * This is a Event Timer Event thread
 */
NTSTATUS
CheckCurrentHvConfigurationTimerCallback(
    void
    )
{
    HV_CONFIGURATION_MISSING_FEATURES missingFeatures = { 0 };

    if (!gHypervisorConfigured)
    {
        return STATUS_SUCCESS;
    }

    ValidateHvConfiguration(&missingFeatures);

    if (missingFeatures.MissingFeatures[0] != 0
        || missingFeatures.MissingFeatures[1] != 0
        || missingFeatures.MissingFeatures[2] != 0
        || missingFeatures.MissingFeatures[3] != 0)
    {
        std::lock_guard<std::mutex> guard(gCallbacksMutex);

        if (NULL != gCallbacks.IncompatibleHvConfigurationCallback)
        {
            gCallbacks.IncompatibleHvConfigurationCallback(
                &missingFeatures,
                gContexts.IncompatibleHvConfigurationContext);
        }
    }

    return STATUS_SUCCESS;
}
