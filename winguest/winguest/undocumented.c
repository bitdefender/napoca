/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file undocumented.c
*   @brief Retrieve and use undocumented APIs of the Windows Kernel
*/

#include <intsafe.h>
#include <ntddk.h>

#include "undocumented.h"
#include "trace.h"
#include "undocumented.tmh"

/**
 * @brief Retrieve pointers to undocumented Windows Kernel APIs
 *
 * @param[out] Functions                    List of APIs
 *
 * @return STATUS_SUCCESS
 * @return STATUS_NOT_FOUND                 Could not retrieve all needed APIs
 */
NTSTATUS
RetrieveUndocumentedFunctions(
    UNDOCUMENTED_FUNCTIONS *Functions
    )
{
    UNICODE_STRING funcName;

    RtlInitUnicodeString(&funcName, L"ZwSetSystemInformation");
    Functions->ZwSetSystemInformation = (PFUNC_ZwSetSystemInformation)MmGetSystemRoutineAddress(&funcName);


    if (Functions->ZwSetSystemInformation == NULL)
    {
        LogError("Could not locate all needed functions!");
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}
