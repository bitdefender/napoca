/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "cxqueuekernel.h"
#include <ntstatus.h>
#include <devguid.h>

#define QUEUELOG(...)

//
// Device protection string
// This is the ACL used for the device object created by the driver.
//
DECLARE_CONST_UNICODE_STRING(
COMM_QUEUE_DEVICE_PROTECTION,
L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)");
extern const UNICODE_STRING  COMM_QUEUE_DEVICE_PROTECTION;

DECLARE_CONST_UNICODE_STRING(
COMM_QUEUE_DEVICE_PROTECTION_FULL,
L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;RC)");
extern const UNICODE_STRING     COMM_QUEUE_DEVICE_PROTECTION_FULL;

//
// Comm queue device context structure
//
// KMDF will associate this structure with each comm queue device that
// this driver creates.
//
typedef struct _COMM_QUEUE_DEVICE_CONTEXT {
    WDFQUEUE    NotificationQueue;
    volatile LONG       Sequence;
} COMM_QUEUE_DEVICE_CONTEXT, *PCOMM_QUEUE_DEVICE_CONTEXT;

//
// Accessor structure
//
// Given a WDFDEVICE handle, we'll use the following function to return
// a pointer to our device's context area.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(COMM_QUEUE_DEVICE_CONTEXT, CommQueueGetContextFromDevice)

typedef struct __COMM_REPLY_EVENT_DATA
{
    UINT64 Sequence;
    KEVENT ReplyAvailable;
    KEVENT ReplyProcessed;
    WDFREQUEST ReplyRequest;
    PVOID InputBuffer;
    SIZE_T InputBufferSize;
    PVOID OutputBuffer;
    SIZE_T OutputBufferSize;
}COMM_REPLY_EVENT_DATA, *PCOMM_REPLY_EVENT_DATA;

#define COMM_QUEUE_MAX_REPLY_DATA_COUNT     64
typedef struct __COMM_QUEUE_GLOBAL
{
    COMM_INIT_DATA          CommInitData;                               // initialization data
    WDFDEVICE               CommDevice;                                 // communication device
    COMM_REPLY_EVENT_DATA   Replies[COMM_QUEUE_MAX_REPLY_DATA_COUNT];   // simultaneous replies that can be pending
    volatile LONG           NextFree;                                   // next hint in case that a new reply is needed
    KEVENT                  StopEvent;                                  // signaled to stop/cancel all pending requests
}COMM_QUEUE_GLOBAL, *PCOMM_QUEUE_GLOBAL;


COMM_QUEUE_GLOBAL gCommQueue = { 0 };

EVT_WDF_DEVICE_FILE_CREATE  CommQueueEvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE          CommQueueEvtFileClose;
EVT_WDF_FILE_CLEANUP        CommQueueEvtFileCleanup;


EVT_WDF_IO_QUEUE_IO_DEFAULT                 CommQueueEvtIoDefault;
EVT_WDF_IO_QUEUE_IO_READ                    CommQueueEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE                   CommQueueEvtIoWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL          CommQueueEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL CommQueueEvtIoInternalDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP                    CommQueueEvtIoStop;
EVT_WDF_IO_QUEUE_IO_RESUME                  CommQueueEvtIoResume;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE       CommQueueEvtIoCanceledOnQueue;

EVT_WDF_OBJECT_CONTEXT_CLEANUP CommQueueDeviceCleanup;
EVT_WDF_OBJECT_CONTEXT_DESTROY CommQueueDeviceDestroy;


VOID
CommQueueEvtIoDefault(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}

VOID
CommQueueEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(ActionFlags);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}


VOID
CommQueueEvtIoResume(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}


VOID
CommQueueEvtIoRead(
    _In_  WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t Length
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(Length);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}


VOID
CommQueueEvtIoWrite(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t Length
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Length);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}

VOID
CommQueueEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 size = 0;
    size_t actualRequestSize = 0;
    BOOLEAN completeRequest = TRUE;  // by default we complete any requests

    PVOID inputMsg = NULL;
    PVOID outputMsg = NULL;

    switch (IoControlCode)
    {
    case COMM_QUEUE_IOCTL_CODE:
        {
            __try
            {
                status = WdfRequestRetrieveInputBuffer(
                    Request,
                    InputBufferLength,
                    &inputMsg,
                    &actualRequestSize
                    );
                if (!NT_SUCCESS(status))
                {
                    QUEUELOG("WdfRequestRetrieveInputBuffer", status);
                    __leave;
                }

                status = WdfRequestRetrieveOutputBuffer(
                    Request,
                    OutputBufferLength,
                    &outputMsg,
                    &actualRequestSize
                    );
                if (!NT_SUCCESS(status))
                {
                    QUEUELOG("WdfRequestRetrieveOutputBuffer", status);
                    __leave;
                }

                if (gCommQueue.CommInitData.CommReceiveData)
                {
                    status = gCommQueue.CommInitData.CommReceiveData(WdfRequestGetFileObject(Request), inputMsg, (UINT32)InputBufferLength, outputMsg, (UINT32)OutputBufferLength, &size);
                    if (!NT_SUCCESS(status))
                    {
                        QUEUELOG("CommReceiveData", status);
                        __leave;
                    }
                }
            }
            __finally
            {
            }
        }
        break;
    case COMM_QUEUE_INVERTED_IOCTL_CODE:
        {
            PCOMM_QUEUE_DEVICE_CONTEXT ctx = NULL;

            ctx = CommQueueGetContextFromDevice(WdfIoQueueGetDevice(Queue));
            if (ctx && ctx->NotificationQueue)
            {
                status = WdfRequestForwardToIoQueue(Request, ctx->NotificationQueue);
                if (!NT_SUCCESS(status))
                {
                    NT_ASSERTMSG("WdfRequestForwardToIoQueue failed.", FALSE);
                }
            }

            // in case of errors we have to complete the request
            completeRequest = NT_SUCCESS(status) ? FALSE : TRUE;
        }
        break;
    case COMM_QUEUE_REPLY_IOCTL_CODE:
        {
            BOOLEAN found = FALSE;
            LONG idx = 0;

            __try
            {
                status = WdfRequestRetrieveInputBuffer(
                    Request,
                    InputBufferLength,
                    &inputMsg,
                    &actualRequestSize
                );
                if (!NT_SUCCESS(status))
                {
                    QUEUELOG("WdfRequestRetrieveInputBuffer", status);
                    __leave;
                }

                status = WdfRequestRetrieveOutputBuffer(
                    Request,
                    OutputBufferLength,
                    &outputMsg,
                    &actualRequestSize
                );
                if (!NT_SUCCESS(status))
                {
                    QUEUELOG("WdfRequestRetrieveOutputBuffer", status);
                    __leave;
                }

                // search for the corresponding reply info
                // and signal the waiting thread to start processing the request
                for (idx = 0; idx < COMM_QUEUE_MAX_REPLY_DATA_COUNT; idx++)
                {
                    if (((PCOMM_INVERTED_MESSAGE)inputMsg)->Header.Sequence == gCommQueue.Replies[idx].Sequence)
                    {
                        found = TRUE;
                        gCommQueue.Replies[idx].ReplyRequest = Request;
                        gCommQueue.Replies[idx].InputBuffer = inputMsg;
                        gCommQueue.Replies[idx].InputBufferSize = InputBufferLength;
                        gCommQueue.Replies[idx].OutputBuffer = outputMsg;
                        gCommQueue.Replies[idx].OutputBufferSize = OutputBufferLength;

                        KeSetEvent(&gCommQueue.Replies[idx].ReplyAvailable, IO_NO_INCREMENT, FALSE);
                        break;
                    }
                }

                // if not found then we have to complete this request with some kind of error
                if (!found)
                {
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    size = 0;
                    __leave;
                }
                else
                {
                    // in case the request is found then we have to wait for the signaled thread above
                    // to complete the processing of this reply
                    NTSTATUS waitStatus = STATUS_SUCCESS;

                    // wait for processing on client side
                    waitStatus = KeWaitForSingleObject(&gCommQueue.Replies[idx].ReplyProcessed, Executive, KernelMode, FALSE, NULL);

                    // cleanup the used reply info
                    RtlZeroMemory(&gCommQueue.Replies[idx], sizeof(gCommQueue.Replies[idx]));

                    status = STATUS_SUCCESS;
                    size = sizeof(COMM_INVERTED_MESSAGE);
                }
            }
            __finally
            {
            }
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        size = 0;
        break;
    }

    if (completeRequest)
    {
        WdfRequestCompleteWithInformation(Request, status, size);
    }

    return;
}


VOID
CommQueueEvtIoInternalDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 size = 0;

    PVOID inputMsg = NULL;
    PVOID outputMsg = NULL;

    UNREFERENCED_PARAMETER(Queue);

    if (LEGACY_PORT_IOCTL_CODE != IoControlCode)
    {
        WdfRequestCompleteWithInformation(Request, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)0);
        return;
    }

    __try
    {
        status = WdfRequestRetrieveInputBuffer(
            Request,
            CX_COMMUNICATION_QUEUE_MIN_MESSAGE_SIZE,
            &inputMsg,
            NULL);
        if (!NT_SUCCESS(status))
        {
            QUEUELOG("WdfRequestRetrieveInputBuffer", status);
            __leave;
        }

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            CX_COMMUNICATION_QUEUE_MIN_MESSAGE_SIZE,
            &outputMsg,
            NULL);
        if (!NT_SUCCESS(status))
        {
            QUEUELOG("WdfRequestRetrieveOutputBuffer", status);
            __leave;
        }

        if (gCommQueue.CommInitData.CommReceiveDataInternal)
        {
            status = gCommQueue.CommInitData.CommReceiveDataInternal(WdfRequestGetFileObject(Request), inputMsg, (UINT32)InputBufferLength, outputMsg, (UINT32)OutputBufferLength, &size);
            if (!NT_SUCCESS(status))
            {
                QUEUELOG("CommReceiveDataInternal", status);
                __leave;
            }
        }
    }
    __finally
    {
    }

    WdfRequestCompleteWithInformation(Request, status, size);


    return;
}


VOID
CommQueueEvtIoCanceledOnQueue(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);

    NT_ASSERTMSG("Operation not allowed!", FALSE);

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);

    return;
}

VOID
CommQueueEvtDeviceFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);

    if (gCommQueue.CommInitData.CommClientConnected)
    {
        status = gCommQueue.CommInitData.CommClientConnected(FileObject, IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request)));
        if (NT_SUCCESS(status))
        {
            status = STATUS_SUCCESS;
        }
    }

    WdfRequestComplete(Request, status);
}

VOID
CommQueueEvtFileClose(
    _In_ WDFFILEOBJECT FileObject
    )
{
    if (gCommQueue.CommInitData.CommClientDisconnected)
    {
        gCommQueue.CommInitData.CommClientDisconnected(FileObject);
    }

    return;
}


VOID
CommQueueEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    UNREFERENCED_PARAMETER(FileObject);
}

VOID
CommQueueDeviceCleanup(
    _In_ WDFOBJECT Object
    )
{
    UNREFERENCED_PARAMETER(Object);
    return;
}

VOID
CommQueueDeviceDestroy(
    _In_ WDFOBJECT Object
    )
{
    UNREFERENCED_PARAMETER(Object);

    return;
}


NTSTATUS
CommInitializeQueueCommunication(
    _In_ WDFDRIVER Driver,
    _In_ PCOMM_INIT_DATA CommInitData
    )
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

    WDFQUEUE                        queue = { 0 };
    WDF_IO_QUEUE_CONFIG             ioQueueConfig = { 0 };
    WDF_FILEOBJECT_CONFIG           fileConfig = { 0 };
    WDF_OBJECT_ATTRIBUTES           objAttributes;
    WDFDEVICE                       controlDevice = NULL;
    PCOMM_QUEUE_DEVICE_CONTEXT      devContext = NULL;
    PWDFDEVICE_INIT                 deviceInit = NULL;
    UNICODE_STRING                  deviceName = { 0 };

    RtlSecureZeroMemory(&gCommQueue, sizeof(COMM_QUEUE_GLOBAL));
    gCommQueue.CommInitData = *CommInitData;

    KeInitializeEvent(&gCommQueue.StopEvent, NotificationEvent, FALSE);

    __try
    {
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&objAttributes,
            COMM_QUEUE_DEVICE_CONTEXT);

        objAttributes.ExecutionLevel = WdfExecutionLevelPassive;
        objAttributes.EvtCleanupCallback = CommQueueDeviceCleanup;
        objAttributes.EvtDestroyCallback = CommQueueDeviceDestroy;

        deviceInit = WdfControlDeviceInitAllocate(Driver, &COMM_QUEUE_DEVICE_PROTECTION_FULL);
        if (deviceInit == NULL)
        {
            __leave;
        }

        RtlInitUnicodeString(&deviceName, gCommQueue.CommInitData.NativeDeviceName);
        status = WdfDeviceInitAssignName(deviceInit, &deviceName);
        if (!NT_SUCCESS(status))
        {
            WdfDeviceInitFree(deviceInit);
            deviceInit = NULL;
            __leave;
        }

        status = WdfDeviceInitAssignSDDLString(deviceInit, &COMM_QUEUE_DEVICE_PROTECTION_FULL);
        if (!NT_SUCCESS(status))
        {
            WdfDeviceInitFree(deviceInit);
            deviceInit = NULL;
            __leave;
        }

        WdfDeviceInitSetCharacteristics(deviceInit, (FILE_DEVICE_SECURE_OPEN | FILE_CHARACTERISTIC_PNP_DEVICE), FALSE);

        WDF_FILEOBJECT_CONFIG_INIT(&fileConfig,
            CommQueueEvtDeviceFileCreate,
            CommQueueEvtFileClose,
            CommQueueEvtFileCleanup
            );

        fileConfig.AutoForwardCleanupClose = WdfTrue;

        WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

        status = WdfDeviceCreate(&deviceInit, &objAttributes, &controlDevice);
        if (!NT_SUCCESS(status))
        {
            WdfDeviceInitFree(deviceInit);
            deviceInit = NULL;
            __leave;
        }

        RtlInitUnicodeString(&deviceName, gCommQueue.CommInitData.UserDeviceName);
        status = WdfDeviceCreateSymbolicLink(controlDevice, &deviceName);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        gCommQueue.CommDevice = controlDevice;

        devContext = CommQueueGetContextFromDevice(controlDevice);
        if (devContext == NULL)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            __leave;
        }

        devContext->Sequence = 0;
        devContext->NotificationQueue = NULL;

        //WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);

        WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);
        ioQueueConfig.Settings.Parallel.NumberOfPresentedRequests = ((ULONG)-1);

        ioQueueConfig.EvtIoDefault = CommQueueEvtIoDefault;
        ioQueueConfig.EvtIoRead = CommQueueEvtIoRead;
        ioQueueConfig.EvtIoWrite = CommQueueEvtIoWrite;
        ioQueueConfig.EvtIoDeviceControl = CommQueueEvtIoDeviceControl;
        ioQueueConfig.EvtIoInternalDeviceControl = CommQueueEvtIoInternalDeviceControl;
        ioQueueConfig.EvtIoStop = CommQueueEvtIoStop;
        ioQueueConfig.EvtIoResume = CommQueueEvtIoResume;
        ioQueueConfig.EvtIoCanceledOnQueue = CommQueueEvtIoCanceledOnQueue;
        ioQueueConfig.PowerManaged = WdfFalse;


        status = WdfIoQueueCreate(controlDevice, &ioQueueConfig, NULL, &queue);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig, WdfIoQueueDispatchManual);

        status = WdfIoQueueCreate(controlDevice, &ioQueueConfig, NULL, &devContext->NotificationQueue);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        WdfControlFinishInitializing(controlDevice);
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            CommUninitializeQueueCommunication();
        }
    }

    return status;
}

NTSTATUS
CommStartQueueCommunication(
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gCommQueue.CommDevice)
    {
        WdfIoQueuePurge(
            WdfDeviceGetDefaultQueue(gCommQueue.CommDevice),
            WDF_NO_EVENT_CALLBACK,
            WDF_NO_CONTEXT
        );

        WdfIoQueueStart(WdfDeviceGetDefaultQueue(gCommQueue.CommDevice));
    }
    else
    {
        status = STATUS_DEVICE_NOT_READY;
    }

    return status;
}

NTSTATUS
CommStopQueueCommunication(
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gCommQueue.CommDevice)
    {
        WDFQUEUE defaultQueue;

        // notify any reply waiters that they need to abort waiting
        KeSetEvent(&gCommQueue.StopEvent, IO_NO_INCREMENT, FALSE);

        defaultQueue = WdfDeviceGetDefaultQueue(gCommQueue.CommDevice);

        if (defaultQueue)
        {
            WdfIoQueuePurgeSynchronously(defaultQueue);
            WdfIoQueueStop(defaultQueue, NULL, NULL);
        }
    }
    else
    {
        status = STATUS_DEVICE_NOT_READY;
    }

    return status;
}

NTSTATUS
CommSendQueueData(
    _In_ PVOID/*WDFFILEOBJECT*/ FileObject,
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferSize,
    _Inout_opt_ PVOID OutputBuffer,
    _Inout_opt_ UINT32 OutputBufferSize,
    _Out_opt_ UINT32 *ActualOutputBufferSize,
    _In_opt_ UINT64 Timeout
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCOMM_QUEUE_DEVICE_CONTEXT devContext;
    WDFDEVICE device = NULL;
    WDFREQUEST request = NULL;
    PCOMM_INVERTED_MESSAGE msg = NULL;
    size_t msgSize = 0;

    if (FileObject == NULL)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (InputBuffer == NULL)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (InputBufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (InputBufferSize > CX_COMMUNICATION_QUEUE_MAX_MESSAGE_SIZE)
    {
        return CX_STATUS_QUEUE_COMM_BUFFER_TOO_BIG;
    }

    __try
    {
        device = WdfFileObjectGetDevice(FileObject);
        if (device == NULL)
        {
            status = STATUS_DEVICE_NOT_READY;
            __leave;
        }

        devContext = CommQueueGetContextFromDevice(device);
        if (devContext == NULL)
        {
            status = STATUS_DEVICE_NOT_READY;
            __leave;
        }

        status = WdfIoQueueRetrieveRequestByFileObject(devContext->NotificationQueue, FileObject, &request);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        // input buffer here is output buffer in UM
        status = WdfRequestRetrieveOutputBuffer(
            request,
            sizeof(COMM_INVERTED_HEADER),
            &msg,
            &msgSize
            );
        if (!NT_SUCCESS(status))
        {
            QUEUELOG("WdfRequestRetrieveOutputBuffer", status);
            __leave;
        }

        // validate that we can send this much data
        if (msgSize < (InputBufferSize + sizeof(COMM_INVERTED_HEADER)))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        // clear buffer
        RtlSecureZeroMemory((PUINT8)msg + sizeof(msg->Header), msgSize - sizeof(msg->Header));

        // init header fields
        if ((OutputBuffer != NULL) && (OutputBufferSize != 0))
        {
            msg->Header.Status = CX_STATUS_QUEUE_COMM_REQUEST_REPLY;
        }
        else
        {
            msg->Header.Status = STATUS_SUCCESS;
        }
        msg->Header.Sequence = _InterlockedIncrement(&devContext->Sequence);

        // copy data
        RtlCopyMemory((PUINT8)msg + sizeof(COMM_INVERTED_HEADER), InputBuffer, InputBufferSize);

        // check if we need a reply for this request
        if ((OutputBuffer != NULL) && (OutputBufferSize != 0))
        {
            LONG64 seqId = 0;
            LONG idx = 0;
            LARGE_INTEGER timeout = { 0 };
            NTSTATUS waitStatus = 0;
            PCOMM_REPLY_EVENT_DATA replyData = NULL;
            PKEVENT events[2];

            // save the sequence id
            seqId = msg->Header.Sequence;

            //////////////////////////////////////////////////////////////////////////
            #pragma message ("use locking here")
            do
            {
                idx = (_InterlockedIncrement(&gCommQueue.NextFree) % COMM_QUEUE_MAX_REPLY_DATA_COUNT);
            } while ((gCommQueue.Replies[idx].Sequence != 0));

            replyData = &gCommQueue.Replies[idx];

            replyData->Sequence = seqId;

            KeInitializeEvent(&replyData->ReplyAvailable, NotificationEvent, FALSE);
            KeInitializeEvent(&replyData->ReplyProcessed, NotificationEvent, FALSE);

            replyData->ReplyRequest = NULL;
            //////////////////////////////////////////////////////////////////////////

            events[0] = &replyData->ReplyAvailable;
            events[1] = &gCommQueue.StopEvent;

            // yes we do need a reply so we complete this request and then
            // we wait for another request with the same sequence number
            // that will hold the reply
            WdfRequestCompleteWithInformation(request, status, InputBufferSize + sizeof(COMM_INVERTED_HEADER));
            request = NULL;

            timeout.QuadPart = Timeout;
            waitStatus = KeWaitForMultipleObjects(2, events, WaitAny, Executive, KernelMode, FALSE, timeout.QuadPart ? &timeout : NULL, NULL);

            if (waitStatus == STATUS_WAIT_0)
            {
                // now we have the request with reply data
                msg = (PCOMM_INVERTED_MESSAGE)replyData->OutputBuffer;

                if (msg->Header.Status == STATUS_SUCCESS)
                {
                    // copy data from user mode to caller buffer
                    if (OutputBufferSize <= (replyData->OutputBufferSize - sizeof(COMM_INVERTED_HEADER)))
                    {
                        RtlCopyMemory(OutputBuffer,
                            ((PUINT8)replyData->OutputBuffer + sizeof(COMM_INVERTED_HEADER)),
                            (replyData->OutputBufferSize - sizeof(COMM_INVERTED_HEADER))
                        );
                    }
                    else
                    {
                        status = CX_STATUS_QUEUE_COMM_BUFFER_TO_SMALL;
                    }

                    if (ActualOutputBufferSize)
                    {
                        *ActualOutputBufferSize = (UINT32)(replyData->OutputBufferSize - sizeof(COMM_INVERTED_HEADER));
                    }
                }
                else
                {
                    if (ActualOutputBufferSize)
                    {
                        *ActualOutputBufferSize = 0;
                    }

                }
            }
            else
            {
                status = CX_STATUS_QUEUE_COMM_REPLY_FAILED;
            }

            // signal that the processing is completed
            KeSetEvent(&replyData->ReplyProcessed, IO_NO_INCREMENT, FALSE);
        }
        else
        {
            if (ActualOutputBufferSize)
            {
                *ActualOutputBufferSize = 0; // no reply
            }
        }
    }
    __finally
    {
        if (NT_SUCCESS(status))
        {
            if (request)
            {
                WdfRequestCompleteWithInformation(request, status, InputBufferSize + sizeof(COMM_INVERTED_HEADER));
            }
        }
        else if (status == CX_STATUS_QUEUE_COMM_BUFFER_TOO_BIG)
        {
            if (request)
            {
                WdfRequestRequeue(request);
            }
        }
        else
        {
            if (request)
            {
                WdfRequestComplete(request, status);
            }
        }
    }

    return status;
}

NTSTATUS
CommUninitializeQueueCommunication(
    void
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gCommQueue.CommDevice)
    {
        status = CommStopQueueCommunication();

        WdfObjectDelete(gCommQueue.CommDevice);
        gCommQueue.CommDevice = NULL;

    }
    else
    {
        status = STATUS_DEVICE_NOT_READY;
    }

    return status;
}
