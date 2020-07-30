/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "cxqueueuser.h"

#define STATUS_WIN32_ERROR                              ((NTSTATUS)0xE8F00000L) // + Win32 error from GetLastError()
#define WIN32_TO_NTSTATUS(Win32Error)                   (STATUS_WIN32_ERROR | (Win32Error & 0x0000FFFF))

#define MAX_COMM_THREADS        16

#ifndef NTSUCCESS
#define NTSUCCESS(Status)                   (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)                  (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SUCCESS
#define SUCCESS(Status)                     (((NTSTATUS)(Status)) >= 0)
#endif


typedef struct _QUEUE_COMM_DATA
{
    COMM_INIT_DATA_U   InitData;

    HANDLE              CommHandle;

    HANDLE              Threads[MAX_COMM_THREADS];
    HANDLE              StopEvent;
}QUEUE_COMM_DATA, *PQUEUE_COMM_DATA;

static
QUEUE_COMM_DATA gCommData = { 0 };

DWORD
WINAPI CommThreadProc(
    LPVOID lpThreadParameter
    );

NTSTATUS
CommInitializeCommunicationU(
    _In_ PCOMM_INIT_DATA_U CommInitData,
    _Out_ PHANDLE CommHandle
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (CommInitData == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CommHandle == NULL)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    *CommHandle = NULL;

    // already initialized
    if (gCommData.CommHandle != NULL)
    {
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

    if (CommInitData->ThreadCount >= MAX_COMM_THREADS)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (CommInitData->MessageSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    __try
    {    // copy init struct
        gCommData.InitData = *CommInitData;

        // try to open the device
        gCommData.CommHandle = CreateFileW(
            gCommData.InitData.Name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL);
        if (gCommData.CommHandle == INVALID_HANDLE_VALUE)
        {
            gCommData.CommHandle = NULL;
            status = WIN32_TO_NTSTATUS(GetLastError());
            __leave;
        }

        // create worker threads if needed
        if (gCommData.InitData.ThreadCount)
        {
            DWORD i = 0;

            // create stop event
            gCommData.StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            if (gCommData.StopEvent == NULL)
            {
                status = WIN32_TO_NTSTATUS(GetLastError());
                __leave;
            }

            // create the threads
            for (i = 0; i < gCommData.InitData.ThreadCount; i++)
            {
                gCommData.Threads[i] = CreateThread(NULL, 0, CommThreadProc, &gCommData, 0, NULL);
            }
        }
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            // close the device is we have one opened
            if (gCommData.CommHandle != NULL)
            {
                CloseHandle(gCommData.CommHandle);
            }

            // if we have a stop event then signal it and wait for any possible threads
            if (gCommData.StopEvent != NULL)
            {
                DWORD waitResult = 0;
                DWORD i = 0;

                // signal the threads
                SetEvent(gCommData.StopEvent);

                // wait for all to finish
                waitResult = WaitForMultipleObjects(gCommData.InitData.ThreadCount, gCommData.Threads, TRUE, INFINITE);

                // close handles
                for (i = 0; i < gCommData.InitData.ThreadCount; i++)
                {
                    CloseHandle(gCommData.Threads[i]);
                }
            }

            ZeroMemory(&gCommData, sizeof(gCommData));

            *CommHandle = NULL;
        }
        else
        {
            *CommHandle = gCommData.CommHandle;
        }
    }

    return status;
}

NTSTATUS
CommUninitializeCommunicationU(
    _In_ HANDLE CommHandle
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if ( (CommHandle == NULL) || (CommHandle != gCommData.CommHandle))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // if we have a stop event then signal it and wait for any possible threads
    if (gCommData.StopEvent != NULL)
    {
        DWORD waitResult = 0;
        DWORD i = 0;

        // signal the threads
        SetEvent(gCommData.StopEvent);

        // wait for all to finish
        waitResult = WaitForMultipleObjects(gCommData.InitData.ThreadCount, gCommData.Threads, TRUE, INFINITE);

        // close handles
        for (i = 0; i < gCommData.InitData.ThreadCount; i++)
        {
            CloseHandle(gCommData.Threads[i]);
        }

        CloseHandle(gCommData.StopEvent);
    }

    // close the device is we have one opened
    if (gCommData.CommHandle != NULL)
    {
        CloseHandle(gCommData.CommHandle);
    }

    ZeroMemory(&gCommData, sizeof(gCommData));

    return status;
}

NTSTATUS
CommStartQueueCommunicationU(
    _In_ HANDLE CommHandle
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if ((CommHandle == NULL) || (CommHandle != gCommData.CommHandle))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    return status;
}

NTSTATUS
CommStopQueueCommunicationU(
    _In_ HANDLE CommHandle
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if ((CommHandle == NULL) || (CommHandle != gCommData.CommHandle))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    return status;
}

NTSTATUS
CommSendQueueDataU(
    _In_ HANDLE CommHandle,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize
)
{
    return CommSendQueueDataUEx(
        CommHandle,
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        ActualOutputBufferSize,
        INFINITE);
}

NTSTATUS
CommSendQueueDataUEx(
    _In_ HANDLE CommHandle,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ActualOutputBufferSize) PVOID OutputBuffer,
    _In_ DWORD OutputBufferSize,
    _Out_opt_ DWORD *ActualOutputBufferSize,
    _In_ DWORD Timeout
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD result = 0;
    OVERLAPPED o = { 0 };

    // check init state
    if ((CommHandle == NULL) || (CommHandle != gCommData.CommHandle))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // check buffer size
    if ((InputBufferSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE) || (OutputBufferSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (o.hEvent == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // send data
    if (!DeviceIoControl(CommHandle, COMM_QUEUE_IOCTL_CODE, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, ActualOutputBufferSize, &o))
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            result = WaitForSingleObject(o.hEvent, Timeout);
            if (result == WAIT_TIMEOUT)
            {
                status = STATUS_TIMEOUT;
            }
            else if (result == WAIT_ABANDONED)
            {
                status = STATUS_ABANDONED;
            }
            else if (result == WAIT_FAILED)
            {
                status = WIN32_TO_NTSTATUS(GetLastError());
            }
            else
            {
                status = STATUS_SUCCESS;
            }

            if (status != STATUS_SUCCESS)
            {
                CancelIo(CommHandle);
            }
        }
        else
        {
            status = WIN32_TO_NTSTATUS(GetLastError());
        }
    }

    if (o.hEvent)
    {
        CloseHandle(o.hEvent);
    }

    return status;
}

static
NTSTATUS
_CommSendQueueDataReplyU(
    _In_ HANDLE CommHandle,
    _In_ PVOID InputBuffer,
    _In_ DWORD InputBufferSize,
    _Inout_ PVOID OutputBuffer,
    _Inout_ DWORD OutputBufferSize,
    _Out_ DWORD *ActualOutputBufferSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVERLAPPED o = { 0 };

    // check init state
    if ((CommHandle == NULL) || (CommHandle != gCommData.CommHandle))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // check buffer size
    if ((InputBufferSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE) || (OutputBufferSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (o.hEvent == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // send data
    if (!DeviceIoControl(CommHandle, COMM_QUEUE_REPLY_IOCTL_CODE, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, ActualOutputBufferSize, &o))
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            WaitForSingleObject(o.hEvent, INFINITE);

            status = STATUS_SUCCESS;
        }
        else
        {
            status = WIN32_TO_NTSTATUS(GetLastError());
        }
    }

    if (o.hEvent)
    {
        CloseHandle(o.hEvent);
    }

    return status;
}


DWORD
WINAPI CommThreadProc(
    LPVOID lpThreadParameter
    )
{
    PQUEUE_COMM_DATA data = (PQUEUE_COMM_DATA)lpThreadParameter;
    OVERLAPPED overlapped = { 0 };
    HANDLE hEvents[2] = { 0 };
    DWORD waitResult = 0;
    PCOMM_INVERTED_MESSAGE msg = NULL;
    DWORD msgSize = ((data->InitData.MessageSize? data->InitData.MessageSize:CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE) + sizeof(COMM_INVERTED_HEADER));
    DWORD receivedMsgSize = 0;
    DWORD toSendMsgSize = 0;
    BOOLEAN thisIsReply = FALSE;
    HANDLE hNotificationEvent = NULL;

    if (msgSize == 0)
    {
        return 1;
    }

    msg = data->InitData.Alloc ? data->InitData.Alloc(msgSize) : HeapAlloc(GetProcessHeap(), 0, msgSize);
    if (msg)
    {
        ZeroMemory(msg, msgSize);
    }
    else
    {
        return 1;
    }


    // create an overlapped event
    hNotificationEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    hEvents[0] = data->StopEvent;
    hEvents[1] = hNotificationEvent;

    while (msg)
    {
        // init overlapped structure
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        overlapped.hEvent = hNotificationEvent;

        // issue an io ctl that will be held pending until the driver has something to send
#pragma prefast(suppress: 6385, "SAL assumes receivedMsgSize represents validity")
        if (!DeviceIoControl(data->CommHandle,
            COMM_QUEUE_INVERTED_IOCTL_CODE,
            msg,
            msgSize,
            msg,
            msgSize,
            &receivedMsgSize,
            &overlapped))
        {
            DWORD lastErr = GetLastError();
            if (lastErr != ERROR_IO_PENDING)
            {
                waitResult = WaitForSingleObject(data->StopEvent, 1);
            }
        }

        thisIsReply = FALSE;

        // wait for completion
        waitResult = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0)
        {
            // we get here because stop notification has been received
            // we need to cancel all pending IO operations
            CancelIo(data->CommHandle);
            break;
        }
        else if (waitResult == WAIT_OBJECT_0 + 1)
        {
            // we get here because we have some message from kernel

            // get the actual number of bytes returned
            GetOverlappedResult(data->CommHandle, &overlapped, &receivedMsgSize, FALSE);

            // check if this a successful message
            if (NT_SUCCESS(overlapped.Internal))
            {
                // this is a complete message that can be forwarded to the clients
                if (msg->Header.Status == CX_STATUS_QUEUE_COMM_SUCCESS)
                {
                    data->InitData.CommReceiveDataU(data->CommHandle,
                        (PBYTE)msg + sizeof(COMM_INVERTED_HEADER),
                        receivedMsgSize - sizeof(COMM_INVERTED_HEADER),
                        NULL,
                        0,
                        NULL);
                }
                else if (msg->Header.Status == CX_STATUS_QUEUE_COMM_BUFFER_TO_SMALL)
                {
                    // we get here because the kernel has a buffer bigger that what we had previously allocated
                    // we need to free the previous one, allocate another one, send a new ioctl
                    // and then return to the default message size
//                     PCOMM_INVERTED_MESSAGE resizedMessage =
//                         data->InitData.Alloc ? data->InitData.Alloc(msg->Header.RequestedSize) : HeapAlloc(GetProcessHeap(), 0, msg->Header.RequestedSize);
//                     if (resizedMessage != NULL)
//                     {
//                         // clean header
//                         ZeroMemory(resizedMessage, sizeof(msg->Header));
//
//                         // init some header members
//                         resizedMessage->Header.BufferSize = msg->Header.RequestedSize;
//
//                         // free old buffer
//                         data->InitData.Free ? data->InitData.Free(msg) : HeapFree(GetProcessHeap(), 0, msg);
//
//                         // use the new buffer
//                         msg = resizedMessage;
//                     }
                }
                else if (msg->Header.Status == CX_STATUS_QUEUE_COMM_REQUEST_REPLY)
                {
                    NTSTATUS status = CX_STATUS_QUEUE_COMM_SUCCESS;

                    // forward to client and then based on the status returned by the client
                    // send the reply to kernel
                    // remember to keep sequence number
                    status = data->InitData.CommReceiveDataU(data->CommHandle,
                        (PBYTE)msg + sizeof(COMM_INVERTED_HEADER),
                        receivedMsgSize - sizeof(COMM_INVERTED_HEADER),
                        (PBYTE)msg + sizeof(COMM_INVERTED_HEADER),
                        receivedMsgSize - sizeof(COMM_INVERTED_HEADER),
                        &toSendMsgSize);

                    if (!NT_SUCCESS(status) || (toSendMsgSize == 0))
                    {
                        // client cannot send a reply
                        msg->Header.Status = CX_STATUS_QUEUE_COMM_REPLY_FAILED;
                    }
                    else
                    {
                        // client has a reply
                        msg->Header.Status = STATUS_SUCCESS;
                    }

                    thisIsReply = TRUE;
                }
                else
                {
                    // we get here with some weird error code from the driver
                    // what to do here???
                }
            }
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            // we get here because we waited to much on the handles
            // nothing much to do
        }
        else if (waitResult == ERROR_OPERATION_ABORTED)
        {
            // we get here because someone canceled the IO operation
            // nothing much to do here
        }

        // send the reply if needed
        if (thisIsReply)
        {
            OVERLAPPED o = { 0 };
            NTSTATUS status = STATUS_SUCCESS;

            // send a request to km and wait for its completion
            o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
            if (o.hEvent != NULL)
            {
                // send data
                if (!DeviceIoControl(data->CommHandle,
                    COMM_QUEUE_REPLY_IOCTL_CODE,
                    msg,
                    toSendMsgSize + sizeof(COMM_INVERTED_HEADER),
                    msg,
                    toSendMsgSize + sizeof(COMM_INVERTED_HEADER),
                    &receivedMsgSize,
                    &o))
                {
                    if (GetLastError() == ERROR_IO_PENDING)
                    {
                        WaitForSingleObject(o.hEvent, INFINITE);

                        status = STATUS_SUCCESS;
                    }
                    else
                    {
                        status = WIN32_TO_NTSTATUS(GetLastError());
                    }
                }

                CloseHandle(o.hEvent);
            }
        }

        // now clean the buffer
        ZeroMemory((PBYTE)msg + sizeof(COMM_INVERTED_HEADER), msgSize - sizeof(COMM_INVERTED_HEADER));
    }

    // free the buffer
    if (msg)
    {
        //(data->InitData.Free != NULL) ? data->InitData.Free(msg) : HeapFree(GetProcessHeap(), 0, msg);
        data->InitData.Free ? data->InitData.Free(msg) : (void)(HeapFree(GetProcessHeap(), 0, msg));
    }

    // close the notification event handle
    if (hNotificationEvent)
    {
        CloseHandle(hNotificationEvent);
    }

    return 0;
}
