/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file updates.c
*   @brief Update hypervisor modules
*/

#include "winguest_types.h"
#include "updates.h"
#include "common/kernel/module_updates.h"
#include "autogen/napoca_buildconfig.h"
#include "driver.h"
#include "memory.h"
#include "umlibcomm.h"
#include "umlibcommands.h"
#include "comm_hv.h"
#include "misc_utils.h"
#include "introstatus.h"
#include "trace.h"
#include "updates.tmh"

/**
 * @brief Send an update package to the hypervisor
 *
 *
 * @param[in] Update                        Update payload
 *
 * @return STATUS_SUCCESS
 * @return OTHER                            Other potential internal error
 */
NTSTATUS
RequestModuleUpdate(
    _In_ UPD_INFO* Update
)
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_UPDATE_MODULE *updateCmd = NULL;
    BOOLEAN lockAcquired = FALSE;

    __try
    {
        if (gDrv.HvCommConnected == FALSE)
        {
            status = STATUS_DRIVER_HYPERVISOR_NOT_CONNECTED;
            __leave;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&gDrv.HvCommLock, TRUE);
        lockAcquired = TRUE;

        status = CommAllocMessage(gDrv.SharedHvMem, cmdUpdateModule, 0,
            TargetNapoca, TargetWinguestKm, sizeof(CMD_UPDATE_MODULE), (PCOMM_MESSAGE*)&updateCmd);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommAllocMessage");
            __leave;
        }

        updateCmd->Update = *Update;

        status = CommSendMessage(gDrv.SharedHvMem, &updateCmd->Command);
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "cmdUpdateModule");
            __leave;
        }

        status = updateCmd->Command.ProcessingStatus;
        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "CommSendMessage");
            __leave;
        }

        *Update = updateCmd->Update;

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (NULL != updateCmd)
        {
            CommFreeMessage(gDrv.SharedHvMem, &updateCmd->Command);
        }

        if (TRUE == lockAcquired)
        {
            ExReleaseResourceLite(&gDrv.HvCommLock);
            KeLeaveCriticalRegion();
        }
    }

    return status;
}

/**
 * @brief Construct and send an update package to the hypervisor
 *
 *
 * @param[in]  FilePath                         Path to the file that contains the updated module
 * @param[in]  ModuleId                         Id of module to be updated
 * @param[in]  ModuleCustomData                 Configuration Buffer that will be sent along the update
 * @param[in]  ModuleCustomDataSize             Size of configuration buffer
 * @param[out] NewVersion                       Version of updated module
 *
 * @return STATUS_SUCCESS
 * @return OTHER                                Other potential internal error
 */
NTSTATUS
UpdateModule(
    _In_ PUNICODE_STRING FilePath,
    _In_ DWORD ModuleId,
    _In_opt_ PVOID ModuleCustomData,
    _In_opt_ DWORD ModuleCustomDataSize,
    _Out_opt_ NAPOCA_VERSION *NewVersion
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES objAttribs;
    IO_STATUS_BLOCK statusBlock;
    HANDLE hFile = NULL;
    FILE_STANDARD_INFORMATION fileInfo;
    BYTE *data = NULL;
    DWORD dataSize = 0;
    BYTE *customData = NULL;
    UPD_INFO update = { 0 };

    __try
    {
        if (!HVStarted())
        {
            status = STATUS_SUCCESS;
            __leave;
        }

        // no file load from disk were requested
        if (FilePath != 0)
        {
            LogInfo("Opening module file: %wZ\n", SafeEmpty(FilePath));
            InitializeObjectAttributes(&objAttribs, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
            RtlZeroMemory(&statusBlock, sizeof(IO_STATUS_BLOCK));

            status = ZwOpenFile(&hFile, GENERIC_READ, &objAttribs, &statusBlock, FILE_SHARE_READ, FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwOpenFile");
                __leave;
            }

            RtlZeroMemory(&statusBlock, sizeof(IO_STATUS_BLOCK));
            status = ZwQueryInformationFile(hFile, &statusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwQueryInformationFile");
                __leave;
            }

            if (fileInfo.EndOfFile.LowPart == 0 || fileInfo.EndOfFile.HighPart != 0)
            {
                status = STATUS_INVALID_SIGNATURE;
                LogError("File size is 0");
                __leave;
            }

            dataSize = fileInfo.EndOfFile.LowPart;

            data = ExAllocatePoolWithTag(gDrv.DefaultMemPoolType, dataSize, 'EXNA');
            if (!data)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            status = ZwReadFile(hFile, NULL, NULL, NULL, &statusBlock, data, dataSize, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "ZwReadFile");
                __leave;
            }

            ZwClose(hFile);
            hFile = NULL;
        }

        if (ModuleCustomData != NULL)
        {
            if (ModuleCustomDataSize == 0 || ModuleCustomDataSize > 4096)
            {
                LogError("Invalid custom data size");
                status = STATUS_INVALID_PARAMETER_4;
                __leave;
            }

            customData = ExAllocatePoolWithTag(gDrv.DefaultMemPoolType, ModuleCustomDataSize, 'EXNA');
            if (customData == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            memcpy_s(customData, ModuleCustomDataSize, ModuleCustomData, ModuleCustomDataSize);
        }

        update.Magic = UPD_MAGIC;
        update.Data = (CX_UINT64)data;
        update.DataSize = dataSize;
        update.CustomData = (CX_UINT64)customData;
        update.CustomDataSize = ModuleCustomDataSize;
        update.ModId = ModuleId;

        // special case for introcore update
        /// several retries might be needed in order to get the introcore uninitialized
        // because all hooks must be removed and they can be removed only if there is no
        // thread with the rip in the intro hooks
        if (ModuleId == LD_MODID_INTRO_CORE)
        {
            // intro updates can fail and need to be retried

            LARGE_INTEGER timeout;
            DWORD remainingTries = 5;

            timeout.QuadPart = 100 * DELAY_ONE_MILLISECOND;

            do
            {
                status = RequestModuleUpdate(&update);
                if (status == INT_STATUS_CANNOT_UNLOAD)
                {
                    LogInfo("It's not safe to disable introspection. Will wait and retry!");
                    KeDelayExecutionThread(KernelMode, FALSE, &timeout);
                }
                else
                {
                    if (!NT_SUCCESS(status))
                    {
                        LogFuncErrorStatus(status, "RequestModuleUpdate");
                    }

                    break;
                }
            } while (status == INT_STATUS_CANNOT_UNLOAD && --remainingTries > 0);
        }
        else if (ModuleId == LD_MODID_INTRO_EXCEPTIONS)
        {
            // exceptions can be loaded only if intro is present

            SIZE_T started;
            status = HvVmcallSafe(OPT_GET_MEMORY_INTRO_STATUS,
                0, 0, 0, 0,
                &started, NULL, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "HvVmcallSafe");
                __leave;
            }

            if (started)
            {
                status = RequestModuleUpdate(&update);
                if (!NT_SUCCESS(status))
                {
                    LogFuncErrorStatus(status, "RequestModuleUpdate");
                    __leave;
                }
            }
        }
        else
        {
            // other updates do not have restrictions

            status = RequestModuleUpdate(&update);
            if (!NT_SUCCESS(status))
            {
                LogFuncErrorStatus(status, "RequestModuleUpdate");
                __leave;
            }
        }

        if (!NT_SUCCESS(status))
        {
            LogFuncErrorStatus(status, "RequestModuleUpdate");
            __leave;
        }

        if (NewVersion)
        {
            NewVersion->High = update.High;
            NewVersion->Low = update.Low;
            NewVersion->Revision = update.Revision;
            NewVersion->Build = update.Build;
        }
    }
    __finally
    {
        if (NULL != hFile)
        {
            ZwClose(hFile);
        }

        if (NULL != data)
        {
            ExFreePoolWithTagAndNull(&data, 'EXNA');
        }

        if (NULL != customData)
        {
            ExFreePoolWithTagAndNull(&customData, 'EXNA');
        }
    }

    return status;
}