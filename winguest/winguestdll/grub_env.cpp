/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file grub_env.cpp
*   @brief Utilities to interact with GRUB envoronment variables
*/

#include <string>
#include <sstream>
#include <map>
#include <vector>

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <Windows.h>

typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "grub_env.h"

#define GRUB_ENVIRONMENT_SIGNATURE      "# GRUB Environment Block"

typedef std::map<std::string, std::string> GRUB_ENV;

/**
 * @brief Split String by Delimiter
 *
 * @param[in] Str           String to be split
 * @param[in] Delimiter     Delimiter for string tokens
 *
 * @return vector of tokens
 */
static
std::vector<std::string>
split(
    const std::string &Str,
    const char Delimiter
)
{
    size_t start = 0;
    size_t end = Str.find_first_of(Delimiter);

    std::vector<std::string> output;

    while (end <= std::string::npos)
    {
        output.emplace_back(Str.substr(start, end - start));

        if (end == std::string::npos)
            break;

        start = end + 1;
        end = Str.find_first_of(Delimiter, start);
    }

    return output;
}

/**
 * @brief Parse GRUB environend and construct in memory view
 *
 * @param[out] Env          GRUB environment
 * @param[in]  Source       GRUB environment raw text
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GrubEnvironmentParseRaw(
    _Out_ PVOID *Env,
    _In_  std::string const &Source
    )
{
    std::vector<std::string> lines;
    std::vector<std::string> tokens;

    if (NULL == Env)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    *Env = NULL;
    GRUB_ENV *env = new GRUB_ENV();

    lines = split(Source, '\n');

    for (const std::string line : lines)
    {
        tokens = split(line, '=');

        if (tokens.size() != 2 && !(tokens.size() == 1 && line[line.size() - 1] == '='))
        {
            continue;
        }

        if (tokens.size() == 2)
        {
            (*env)[tokens[0]] = tokens[1];
        }
        else
        {
            (*env)[tokens[0]] = std::string("");
        }
    }

    *Env = (PVOID)env;

    return STATUS_SUCCESS;
}

/**
 * @brief Free GRUB in memory view
 *
 * @param[in,out] Env       GRUB environment
  *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
void
GrubEnvironmentFree(
    _Inout_ PVOID *Env
    )
{
    if (Env && *Env)
    {
        delete (GRUB_ENV*)*Env;
        *Env = NULL;
    }
}

/**
 * @brief Convert in memory GRUB environment to raw file format
 *
 * @param[in]  Env          GRUB environment
 * @param[out] Buffer       GRUB environment raw text
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GrubEnvironmentGetRaw(
    _In_ PVOID Env,
    _Out_ std::string& Buffer
)
{
    GRUB_ENV* env = (GRUB_ENV*)Env;

    if (Env == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    Buffer = GRUB_ENVIRONMENT_SIGNATURE "\n";

    for (const auto kv : (*env))
    {
        Buffer += kv.first + "=" + kv.second + "\n";
    }

    if (Buffer.length() < 1024)
        Buffer.resize(1024, '#');

    return STATUS_SUCCESS;
}

/**
 * @brief Set value in GRUB environment
 *
 * @param[in]  Env          GRUB environment
 * @param[in]  Key          Key to be set
 * @param[in]  Value        Value of Key
 *
 * @return STATUS_SUCCESS
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GrubEnvironmentSetValue(
    _In_ PVOID Env,
    _In_ std::string const &Key,
    _In_ std::string const &Value
    )
{
    GRUB_ENV *env = (GRUB_ENV*)Env;

    if (Env == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    (*env)[Key] = Value;

    return STATUS_SUCCESS;
}

/**
 * @brief Get value in GRUB environment
 *
 * @param[in]  Env          GRUB environment
 * @param[in]  Key          Key to be retrieved
 * @param[out] Value        Value of Key
 *
 * @return STATUS_SUCCESS
 * @return STATUS_NOT_FOUND Key not found
 * @return OTHER            Other potential internal error
 */
NTSTATUS
GrubEnvironmentGetValue(
    _In_ PVOID Env,
    _In_ std::string const &Key,
    _Out_ std::string &Value
    )
{
    GRUB_ENV *env = (GRUB_ENV*)Env;

    if (Env == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (env->count(Key) == 0)
    {
        return STATUS_NOT_FOUND;
    }

    Value =(*env)[Key];

    return STATUS_SUCCESS;
}

