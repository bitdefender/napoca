/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// EFI boot file entry point code

#include "userdata.h"
#include "uefi_internal.h"
#include "common/boot/loader_interface.h"
#include "FileOperationsLib/FileOperationsLib.h"
#include "newload.h"

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include "MemDebugLib/MemDebugLib.h"

#define TEMP_BUFFER_SIZE            (64 * CX_MEGA)

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

UD_VAR_INFO EfiCommandLineVariablesInfo[] = UD_VAR_INFO_TABLE;
DWORD EfiCommandLineVariablesInfoCount = (sizeof(EfiCommandLineVariablesInfo) / sizeof(UD_VAR_INFO));

volatile BOOLEAN UefiBypassTimeout = FALSE;
HV_FEEDBACK_HEADER *HvFeedback = NULL;

LD_INSTALL_FILE gInstallFiles[] =
{
#include "autogen/install_files.h" // auto-generated list (_preprocess via prebuild.cfg based on installer.cfg)
};

DWORD gInstallFilesCount = (sizeof(gInstallFiles) / sizeof(LD_INSTALL_FILE));
typedef struct _UEFI_LOADED_MODULES
{
    void *Buffer;
    UINTN BufferSize;
}UEFI_LOADED_MODULES, *PUEFI_LOADED_MODULES;

extern LD_NAPOCA_MODULE UefiModules[LD_MAX_MODULES];
extern CONST UINT32 _gUefiDriverRevision = 0;

CHAR8 *gEfiCallerBaseName = "Bdhv";

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE ImageHandle
)
{
    //
    // This code should be compiled out and never called
    //
    ASSERT(FALSE);
}

VOID
EFIAPI
DummyNotifyMe(
  IN  EFI_EVENT                       Event,
  IN  VOID                            *Context
  )
{
    TRACE(L"Notified!\n");
    return;
}



VOID
EFIAPI
UefiNotifyBypassTimeout(
  IN  EFI_EVENT                       Event,
  IN  VOID                            *Context
  )
{
    UefiBypassTimeout = TRUE;
}



EFI_STATUS
UefiSaveHvLog(
    BOOLEAN SaveToDisk
    )
{
    EFI_STATUS status = EFI_UNSUPPORTED;
    NTSTATUS ntStatus;

    if (NULL != HvFeedback)
    {
        UINT64 varHvLog[2] = { 0 };
        HV_FEEDBACK_HEADER *head = (HV_FEEDBACK_HEADER*)gHvLogPhysicalAddress;
        DWORD hvLogLength = 0;
        DWORD startOffset = MEMLOG_NO_OFFSET;
        DWORD freeBufferLength = gHvLogSize - (sizeof(HV_FEEDBACK_HEADER) + head->Logger.BufferSize);

        ntStatus = GetLogInfo(&HvFeedback->Logger, &startOffset, &hvLogLength);
        if (!SUCCESS(ntStatus))
        {
            ERR_NT("GetLogInfo", ntStatus);
            status = EFI_ABORTED;
            goto cleanup;
        }

        if (0 == hvLogLength) /// TODO: remove; we must try to save loader log even if hv log is missing
        {
            status = EFI_ABORTED;
            goto cleanup;
        }

        hvLogLength = hvLogLength < freeBufferLength ? hvLogLength : freeBufferLength;

        ntStatus = GetLogChunk(&HvFeedback->Logger, startOffset, hvLogLength, head->Logger.Buffer + head->Logger.BufferSize);
        if (!SUCCESS(ntStatus))
        {
            ERR_NT("GetLogChunk", ntStatus);
            status = EFI_ABORTED;
            goto cleanup;
        }

        head->Logger.BufferSize += hvLogLength;
        head->Logger.BufferWritePos = head->Logger.BufferSize;

        // TODO: Encrypt(head->Logger.Buffer, head->Logger.BufferSize); if considered necessary

        varHvLog[0] = (QWORD)gHvLogPhysicalAddress;
        varHvLog[1] = sizeof(HV_FEEDBACK_HEADER) + head->Logger.BufferSize;

        status = MdSaveBufferToUefiVariable((CHAR8*)(SIZE_T)&varHvLog, sizeof(varHvLog), VAR_HV_LOG_NAME, &gBdHvGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
        if (EFI_ERROR(status))
        {
            goto cleanup;
        }

        if (SaveToDisk)
        {
            status = FoStoreFileA(CfgFilesHvLog, (CHAR8*)(SIZE_T)&varHvLog, sizeof(varHvLog));
            if (EFI_ERROR(status))
            {
                goto cleanup;
            }
        }
    }

    status = EFI_SUCCESS;
cleanup:
    if (status != EFI_SUCCESS)
    {
        GOPLOGA("Uefi save hv log failed with 0x%x\n", status);
    }
    return status;
}


EFI_STATUS
UefiSaveFeedbackLog(
    BOOLEAN SaveToDisk
    )
{
    EFI_STATUS status = EFI_UNSUPPORTED;
    UINTN hvLogMaxLength = gHvLogSize;
    UINTN loaderLogLength = 0;
    HV_FEEDBACK_HEADER *head = (HV_FEEDBACK_HEADER*)gHvLogPhysicalAddress;
    UINT8 *pointerToFeedbackBuffer = NULL;
    pointerToFeedbackBuffer = head->Logger.Buffer;

    status = MdSaveLogToBuffer(gLog, (CHAR8**)&pointerToFeedbackBuffer, &hvLogMaxLength);
    if (EFI_ERROR(status))
    {
        GOPLOGA("MdSaveLogToBuffer failed with 0x%x\n", status);
        goto cleanup;
    }

    loaderLogLength = AsciiStrLen(head->Logger.Buffer);

    head->Version = 1;
    head->Logger.Initialized = 1;
    head->Logger.BufferSize = (DWORD)loaderLogLength;
    head->Logger.BufferWritePos = head->Logger.BufferSize;

    status = UefiSaveHvLog(SaveToDisk);
    if (EFI_ERROR(status))
    {
        GOPLOGA("UefiSaveHvLog failed with 0x%x!\n", status);
        goto cleanup;
    }

    status = EFI_SUCCESS;

cleanup:
    return status;
}

EFI_STATUS
UefiLoadBootModules(
    void
)
{
    void *buffer;
    UINTN bufferSize;
    DWORD i;
    char filePath[512];
    UINTN sprintResult;
    EFI_STATUS status;
    for (i = 0; i < gInstallFilesCount; i++)
    {

        LD_INSTALL_FILE *file = &gInstallFiles[i];

        // skip files that are not needed by the HV or entries irrelevant to an UEFI boot
        if ((file->LdModId == LD_MODID_INVALID) || !(file->Flags.Efi))
        {
            continue;
        }
        if (file->LdModId >= LD_MAX_MODULES)
        {
            TRACE(L"Unrecognized boot module with ID=0x%X, aborting!\n", file->LdModId);
            return EFI_NOT_FOUND;
        }

        sprintResult = AsciiSPrint(filePath, sizeof(filePath), "%a\\%S", CFG_UEFI_INSTALL_DIR, file->DestinationFileName);
        if (sprintResult >= sizeof(filePath))
        {
            /// todo: free the buffers
            status = EFI_BUFFER_TOO_SMALL;
            return status;
        }

        status = FoLoadFileA(filePath, &buffer, &bufferSize, 0);
        if (EFI_ERROR(status))
        {
            TRACE(L"Failed FoLoadFileA [%a]!\r\n", filePath);
            return status;
        }
        else
        {
            TRACE(L"Loaded %a (%a)\n", filePath, LdGetModuleName(file->LdModId));
        }

        // fill-in the Pa and Size
        UefiModules[file->LdModId].Pa = (QWORD)(SIZE_T)buffer;
        UefiModules[file->LdModId].Size = (DWORD)bufferSize;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
UefiUnloadBootModules(
)
{
    DWORD i;
    EFI_STATUS status;
    EFI_STATUS tmp;
    for (i = 0; i < LD_MAX_MODULES; i++)
    {
        if ((UefiModules[i].Pa == 0) || (UefiModules[i].Size == 0))
        {
            continue;
        }
        tmp = FoUnloadFile((PVOID)(SIZE_T)UefiModules[i].Pa, UefiModules[i].Size);
        if (EFI_ERROR(tmp))
        {
            status = tmp;
        }
        UefiModules[i].Pa = 0;
        UefiModules[i].Size = 0;
    }
    return status;
}


EFI_STATUS EFIAPI
UefiMain (
    _In_ EFI_HANDLE ImageHandle,
    _In_ EFI_SYSTEM_TABLE  *SystemTable)
{
    EFI_STATUS status;
    QWORD hvCr3 = 0;
    UEFI_LOAD_CONTROL_DATA loadControlData = {0};
    BOOLEAN aborted = FALSE;

#if CFG_UEFI_MEMLOG_OUT
    // let the log creation silently fail if that's the case
    MdCreateLog(128*1024, 4*1024, &gLog);
#endif

    //
    // Initialize our runtime
    //
    InternalInit(SystemTable, ImageHandle);

    FoLibConstructor(ImageHandle, SystemTable);

    MdLibConstructor(ImageHandle, SystemTable);

    //
    // Allocate a NVS buffer for hibernate
    //
    status = UefiAllocHibernateBuffer(64 * CX_KILO);
    if (EFI_ERROR(status))
    {
        TRACE(L"Couldn't allocate NVS hibernate buffer, status: 0x%08x", status);
    }

    //
    // Load the configuration file and the "load control" data structure from a firmware var
    //
    {
        void *buffer = NULL;
        UINTN bufferSize = 0;
        UD_NUMBER consumed = 0;

        bufferSize = sizeof(loadControlData);
        status = MdGetBufferFromUefiVariable((CHAR8*)(SIZE_T)&loadControlData, &bufferSize, UEFI_LOAD_CONTROL, &gBdHvGuid, NULL);
        if (EFI_ERROR(status) || bufferSize != sizeof(loadControlData))
        {
            TRACE(L"Cannot get the uefi configuration from the variable!\n");
            ZeroMem(&loadControlData, sizeof(loadControlData));
        }

        status = FoLoadFileA(CFG_UEFI_CONFIG_FILE, &buffer, &bufferSize, 0);
        if (EFI_ERROR(status))
        {
            goto no_config;
        }

        if (!UdMatchVariablesFromText(EfiCommandLineVariablesInfo, EfiCommandLineVariablesInfoCount, buffer, bufferSize, &consumed))
        {
            TRACE(L"Failed to match the input configuration, consumed %d out %d bytes\n", consumed, bufferSize);
        }
        else
        {
            TRACE(L"Configuration file loaded [up to %d/%d]\n", consumed, bufferSize);
        }
        UefiBootServices->FreePages((EFI_PHYSICAL_ADDRESS)buffer, (bufferSize + 4095) / 4096);
    }
no_config:

    // prepare the keyboard timer for bypassing the HV (the ESC key detection)
    if (0 != CfgUserInterractionAllowKeyboardBypass)
    {
        if (0 == CfgUserInterractionTimeOutInSeconds)
        {
            // consider it already expired, the user can still bypass the HV by pressing the key before we're calling the HV entry point
            UefiBypassTimeout = TRUE;
        }
        else
        {
            EFI_EVENT bypassEvent;
            if ((NULL != UefiSystemTable->ConOut) && (NULL != UefiSystemTable->ConOut->Mode))
            {
                INT32 attr;
                attr = UefiSystemTable->ConOut->Mode->Attribute;
                UefiSystemTable->ConOut->SetAttribute(UefiSystemTable->ConOut, EFI_LIGHTGREEN);
                GOPLOG(L"%a\n", CfgUserInterractionBypassMessage);
                UefiSystemTable->ConOut->SetAttribute(UefiSystemTable->ConOut, attr);
            }
            else
            {
                GOPLOG(L"%a\n", CfgUserInterractionBypassMessage);
            }
            status = UefiBootServices->CreateEvent(EVT_TIMER|EVT_NOTIFY_SIGNAL, TPL_NOTIFY, UefiNotifyBypassTimeout, NULL, &bypassEvent);
            if (EFI_ERROR(status))
            {
                TRACE(L"[bsp]CreateEvent failed with status = %S\r\n", UefiStatusToText(status));
                goto cleanup;
            }
            status = UefiBootServices->SetTimer(bypassEvent, TimerRelative, CfgUserInterractionTimeOutInSeconds * SECOND_FROM_100_NANOSECOND);
            if (EFI_ERROR(status))
            {
                TRACE(L"[bsp]SetTimer failed with status = %S\r\n", UefiStatusToText(status));
                goto cleanup;
            }
        }
    }

    //
    // Check for boot failures and activate the fail count mechanism if needed
    //
    {
        // UM clears the Boot at each boot, being set it means last time we didn't succeed in starting up the system.
        if (loadControlData.Boot)
        {
            loadControlData.Crash = 1;
        }

        if (0 != CfgAllowedRetries &&
            loadControlData.FailCount >= CfgAllowedRetries)
        {
            TRACE(L"Maximum allowed consecutive failures triggered (%d vs %d), will bypass to OS\n",
                loadControlData.FailCount, CfgAllowedRetries);
            loadControlData.Boot = FALSE;
            status = EFI_NOT_STARTED;
            goto cleanup;
        }

        TRACE(L"Maximum allowed consecutive failures %d vs %d\n",
            loadControlData.FailCount, CfgAllowedRetries);

        loadControlData.Boot = TRUE;
        loadControlData.FailCount++;

        // delete the variable first (will succeed only if already existing) -- we don't care about the returned value
        UefiRuntimeServices->SetVariable(
            UEFI_LOAD_CONTROL,
            &gBdHvGuid,
            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            0,
            &loadControlData
        );

        status = MdSaveBufferToUefiVariable((CHAR8*)(SIZE_T)&loadControlData, sizeof(loadControlData), UEFI_LOAD_CONTROL, &gBdHvGuid, EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
        if (EFI_ERROR(status))
        {
            TRACE(L"Cannot save the uefi configuration into the variable!\n");
            goto cleanup;
        }
    }

    if (EFI_ABORTED == UefiCheckUserHvBypass())
    {
        status = EFI_ABORTED;
        aborted = TRUE;
        goto cleanup;
    }
    status = UefiLoadBootModules();
    if (EFI_ERROR(status))
    {
        TRACE(L"Failed loading the boot modules!\n");
        goto cleanup;
    }

    if (CfgDebugConfirmHv)
    {
        char key;
        TRACE(L"Boot options: press 'a' to load the HV or 'o' to skip to OS\n");
        key = UefiGetKey();
        if ('a' == key)
        {
            CfgBypassHv = CONF_BYPASSHV_NONE;
            loadControlData.Boot = TRUE;
        }
        else if ('o' == key)
        {
            CfgBypassHv = CONF_BYPASSHV_BYPASS;
            loadControlData.Boot = FALSE;
            status = EFI_SUCCESS;
            goto cleanup;
        }
    }

    //
    // runtime version debug info
    //
    TRACE(L"Uefi(%a) HV loading process started\n", __DATE__" "__TIME__);
    if (CfgDebugDumpVersion)
    {
        TRACE(L"System information:\r\n");
        TRACE(L"--> Firmware Vendor:          %S\r\n", UefiSystemTable->FirmwareVendor);
        TRACE(L"--> Firmware Revision:        %X (%d.%d)\r\n", UefiSystemTable->FirmwareRevision, UefiSystemTable->FirmwareRevision>>16, UefiSystemTable->FirmwareRevision&0xFFFF);
        TRACE(L"--> System Table Revision:    %X (%d.%d)\r\n", UefiSystemTable->Hdr.Revision, UefiSystemTable->Hdr.Revision>>16, UefiSystemTable->Hdr.Revision&0xFFFF);
        TRACE(L"--> BootServices Revision:    %X\r\n", UefiBootServices->Hdr.Revision);
        TRACE(L"--> RuntimeServices Revision: %X\r\n", UefiSystemTable->RuntimeServices->Hdr.Revision);
    }

    if (EFI_ABORTED == UefiCheckUserHvBypass())
    {
        status = EFI_ABORTED;
        aborted = TRUE;
        goto cleanup;
    }

    //
    // Decide whether we skip the HV or not
    //
    if (CfgFilesEfiHvEnabled)
    {
        CfgBypassHv = CONF_BYPASSHV_BYPASS;
    }


    if (CfgBypassHv != CONF_BYPASSHV_BYPASS)
    {
        if (EFI_ABORTED == UefiCheckUserHvBypass())
        {
            status = EFI_ABORTED;
            aborted = TRUE;
            goto cleanup;
        }

        //
        // Run the HV
        //
        status = UefiSetupModules(
            TEMP_BUFFER_SIZE,
            &hvCr3,             // set to 0 the actual *Cr3 QWORD before the call if there is no pml4 root already set up
            UefiModules[LD_MODID_NAPOCA_IMAGE].Pa,
            UefiModules[LD_MODID_NAPOCA_IMAGE].Size,
            1                   // number of guests to consider for memory allocation
        );

        //
        // Save the feedback log if available and the HV died
        //
        if (EFI_ERROR(status))
        {
            if (CfgDebugDumpCrashLog)
            {
                if (EFI_ERROR(UefiSaveFeedbackLog(TRUE)));
                {
                    TRACE(L"Hv feedback log couldn't be saved!\n");
                }
            }
            goto cleanup;
        }
        else if (CfgDebugSimulateSecondLoad)
        {
            TRACE(L"Second try simulation...\n");
            CfgBypassHv = TRUE;
            status = UefiSetupModules(
                TEMP_BUFFER_SIZE,
                &hvCr3,             // set to 0 the actual *Cr3 QWORD before the call if there is no pml4 root already set up
                UefiModules[LD_MODID_NAPOCA_IMAGE].Pa,
                UefiModules[LD_MODID_NAPOCA_IMAGE].Size,
                1                   // number of guests to consider for memory allocation
                );
            if (EFI_ERROR(status))
            {
                TRACE(L"FAILED\n");
            }
        }
    }
    else
    {
        status = EFI_SUCCESS;
    }

cleanup:
    MEM_LOG_FORCEFLUSH();

    //
    // Don't reflect it as a failure if the user aborted the hv boot
    //
    if (aborted)
    {
        // delete the variable first (will succeed only if already existing) -- we don't care about the returned value
        UefiRuntimeServices->SetVariable(
            UEFI_LOAD_CONTROL,
            &gBdHvGuid,
            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            0,
            &loadControlData
        );

        loadControlData.Boot = FALSE;   // no, we didn't try to load the HV
        loadControlData.FailCount--;    // restore (by decrementing) the original value of the counter

        status = MdSaveBufferToUefiVariable((CHAR8*)(SIZE_T)&loadControlData, sizeof(loadControlData), UEFI_LOAD_CONTROL, &gBdHvGuid, EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
        if (EFI_ERROR(status))
        {
            TRACE(L"Cannot save the uefi configuration into the variable!\n");
            /// goto cleanup; -- DON'T go to cleanup...
        }
    }

    if (EFI_ERROR(status))
    {
        if (CfgDebugHaltOnErrors)
        {
            CpuDisableInterrupts();
            __halt();
        }
        if (CfgDebugConfirmErrors)
        {
            UefiWaitKeyMsg(L"Press any key to bypass the HV and load the OS ignoring the error\n");
        }
    }

    if (CfgDebugDumpLastLog)
    {
        if (EFI_ERROR(UefiSaveFeedbackLog(FALSE)))
        {
            TRACE(L"Hv last log couldn't be saved\n");
        }
    }


    //
    // Runtime features supported debug info
    //
    if (CfgDebugDumpRuntimeTables)
    {
        UINTN i;
        EFI_GUID vEFI_ACPI_20_TABLE_GUID = {0x8868e871,0xe4f1,0x11d3,0xbc,0x22,0x0,0x80,0xc7,0x3c,0x88,0x81};
        EFI_GUID vACPI_TABLE_GUID = {0xeb9d2d30,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d};
        EFI_GUID vSAL_SYSTEM_TABLE_GUID = {0xeb9d2d32,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d};
        EFI_GUID vSMBIOS_TABLE_GUID = {0xeb9d2d31,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d};
        EFI_GUID vMPS_TABLE_GUID = {0xeb9d2d2f,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d};
        EFI_GUID vEFI_ACPI_TABLE_GUID = {0x8868e871,0xe4f1,0x11d3,0xbc,0x22,0x0,0x80,0xc7,0x3c,0x88,0x81};
        EFI_GUID vACPI_10_TABLE_GUID = {0xeb9d2d30,0x2d88,0x11d3,0x9a,0x16,0x0,0x90,0x27,0x3f,0xc1,0x4d};

        ///InternalListHandlesAndProtocols();
        for (i = 0; i < UefiSystemTable->NumberOfTableEntries; i++)
        {
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vEFI_ACPI_20_TABLE_GUID))
            {
                TRACE(L"%d: vEFI_ACPI_20_TABLE_GUID\n", i);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vACPI_TABLE_GUID))
            {
                TRACE(L"%d: vACPI_TABLE_GUID\n", i);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vSAL_SYSTEM_TABLE_GUID))
            {
                TRACE(L"%d: vSAL_SYSTEM_TABLE_GUID\n", i);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vSMBIOS_TABLE_GUID))
            {
                TRACE(L"%d: vSMBIOS_TABLE_GUID\n", i);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vMPS_TABLE_GUID))
            {
                TRACE(L"%d: vMPS_TABLE_GUID => %p\n", i, UefiSystemTable->ConfigurationTable[i].VendorTable);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vEFI_ACPI_TABLE_GUID))
            {
                TRACE(L"%d: vEFI_ACPI_TABLE_GUID\n", i);
            }
            if (SAME_GUID(&UefiSystemTable->ConfigurationTable[i].VendorGuid, &vACPI_10_TABLE_GUID))
            {
                TRACE(L"%d: vACPI_10_TABLE_GUID\n", i);
            }
        }
    }


    if(CfgDebugDumpEnvironmentVariables)
    {
        EFI_GUID guid;
        CHAR16 varName[4096];
        char buffer[4096];
        UINTN size;
        UINT32 attr;
        varName[0] = 0;
        size = sizeof(varName);
        while (!EFI_ERROR(UefiRuntimeServices->GetNextVariableName(&size, varName, &guid)))
        {
            TRACE(L"var[%S] %g\n", varName, &guid);
            size = sizeof(buffer);
            status = UefiRuntimeServices->GetVariable(varName, &guid, &attr, &size, buffer);
            if (!EFI_ERROR(status))
            {
                char ascii[512];
                UnicodeStrToAsciiStr(varName, ascii);
                UefiMemDumper(buffer, (UINT32)size, FALSE);
            }
            else
            {
                TRACE(L"Error reading the variable\n");
            }
            size = sizeof(varName);
        }
    }
    //UefiWaitKey();
    if (CfgDebugConfirmOs)
    {
        TRACE(L"Press 'b' to start the OS...\n");
        while ('b' != UefiGetKey());
    }

    //var_cleanup:
    if (!CfgActiveOsLoad)
    {
        UefiWaitKeyMsg(L"Press any key to return to caller\n");
        return EFI_SUCCESS;
    }

    if ((NULL != CfgFilesEfiHv)&& (CfgFilesEfiHvEnabled))
    {
        UefiWaitKeyMsg(L"Press any key to load the EFI HV!\n");
        TRACE(L"Loading the EFI hv\n");
        status = UefiExecuteEfiFileA(CfgFilesEfiHv);
        TRACE(L"result:%d\n", status);
    }

    TRACE(L"EFI: Loading and executing the original OS loader...\n");

    status = UefiExecuteEfiFileA(CfgFilesOs);
    // continue with the backup option if the primary entry fails
    status = UefiExecuteEfiFileA(CfgFilesOsBackup);
    TRACE(L"result:%d\n", status);
    UefiWaitKeyMsg(L"CONTROL RETURNED, THE LOADER DIDN'T SUCCEED :(\r\n");

    MEM_LOG_FORCEFLUSH();
    return EFI_SUCCESS;
}
