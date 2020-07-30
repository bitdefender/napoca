/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _UMLIBCOMM_H_
#define _UMLIBCOMM_H_

NTSTATUS
InitUmlibComm(
    );

NTSTATUS
UninitUmlibComm(
    );

NTSTATUS
UmLibCommReceiveMessage(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ UINT32 OutputBufferLength,
    _Out_ UINT32* BytesReturned
    );

NTSTATUS
UmLibCommNewClientConnected(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject,
    _In_ ULONG ProcessId
    );

NTSTATUS
UmLibCommClientDisconnected(
    _In_ PVOID/*WDFFILEOBJECT*/ WdfFileObject
    );

NTSTATUS
UmLibCommSendMessage(
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferLength,
    __out_opt PVOID OutputBuffer,
    _In_opt_ DWORD OutputBufferLength,
    _Out_ DWORD* BytesReturned
    );

#endif