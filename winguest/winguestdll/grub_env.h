/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _GRUB_ENV_H_
#define _GRUB_ENV_H_

NTSTATUS
GrubEnvironmentParseRaw(
    _Out_ PVOID *Env,
    _In_  std::string const& Source
);

void
GrubEnvironmentFree(
    _Inout_ PVOID *Env
);

NTSTATUS
GrubEnvironmentGetRaw(
    _In_ PVOID Env,
    _Out_ std::string& Buffer
);

NTSTATUS
GrubEnvironmentSetValue(
    _In_ PVOID Env,
    _In_ std::string const &Key,
    _In_ std::string const &Value
);

NTSTATUS
GrubEnvironmentGetValue(
    _In_ PVOID Env,
    _In_ std::string const &Key,
    _Out_ std::string &Value
);

#endif //_GRUB_ENV_H_
