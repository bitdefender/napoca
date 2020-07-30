/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file smbios.cpp
*   @brief Read SMBIOS tables and data
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "smbios.h"
#include "winguest_status.h"

/**
 * @brief Compute SMBIOS Table length
 *
 * @param[in]  SmbiosTable      Table to be analyzed
  *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
static
SIZE_T
SmbiosTableLength(
    _In_ SMBIOS_STRUCTURE_POINTER const* const SmbiosTable
)
{
    BYTE const* aChar = SmbiosTable->Raw + SmbiosTable->Hdr.Length;

    for (; (*aChar != 0) || (*(aChar + 1) != 0); aChar++);

    return aChar - SmbiosTable->Raw + 2;
}

/**
 * @brief Get a SMBIOS table that matches a type and index
 *
 * @param[in] RawTables         Raw tables buffer
 * @param[in] Size              Size of RawTables
 * @param[in] Type              Type of requested table
 * @param[in] Index             Index of requested table
 *
 * @return pointer              Pointer to requested table
 * @return NULL                 No table found that matches the type or not enough tables to reach the index
 */
SMBIOS_STRUCTURE_POINTER const *
SmbiosGetTableFromType(
    BYTE const* RawTables,
    SIZE_T Size,
    BYTE   Type,
    DWORD  Index
)
{
    if (RawTables == NULL) return NULL;

    BYTE SmbiosTypeIndex = 0;

    for (SMBIOS_STRUCTURE_POINTER const* SmbiosTable = reinterpret_cast<SMBIOS_STRUCTURE_POINTER const*>(RawTables);
        reinterpret_cast<BYTE const*>(SmbiosTable) + sizeof(SMBIOS_STRUCTURE_POINTER) < RawTables + Size;
        SmbiosTable = reinterpret_cast<SMBIOS_STRUCTURE_POINTER const*>(SmbiosTable->Raw + SmbiosTableLength(SmbiosTable)))
    {
        if (SmbiosTable->Hdr.Type == Type)
        {
            if (SmbiosTypeIndex++ == Index)
                return SmbiosTable;
        }
    }

    return NULL;
}

/**
 * @brief Get a SMBIOS table that matches a type and index
 *
 * @param[in] SmbiosTable       Raw tables buffer
 * @param[in] String            Requested string
 *
 * @return
 * @return Requested string or empty if not found
 */
std::string
SmbiosGetString(
    _In_ SMBIOS_STRUCTURE_POINTER const *SmbiosTable,
    _In_ SMBIOS_TABLE_STRING       String
)
{
    if (!SmbiosTable || String == 0) return "";

    CHAR* aString = (CHAR*)(SmbiosTable->Raw + SmbiosTable->Hdr.Length);

    for (BYTE i = 1; i != String && *aString; i++)
    {
        aString += strlen(aString) + 1;
    }

    return aString;
}
