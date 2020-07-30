/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _BASE64_H_
#define _BASE64_H_

#define GetToBase64Size(Length)     ((((Length + 2) / 3) * 4) + 1)
#define GetFromBase64Size(Length)   ((Length / 4) * 3)

NTSTATUS
Tobase64(
    _Out_ CHAR *Out,
    _In_ const BYTE *In,
    _In_ QWORD InLength,
    _In_ QWORD OutLength
    );

NTSTATUS
FromBase64(
    _Out_ BYTE *Out,
    _In_ const CHAR *In,
    _In_ QWORD OutLength
    );

#endif // _BASE64_H_
