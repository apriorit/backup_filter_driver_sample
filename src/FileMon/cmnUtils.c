#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntintsafe.h>
#include "cmnUtils.h"
#include "ntddk.h"
#include "ntdddisk.h"
#include <stdio.h>

static
NTSTATUS AsyncCompletionBase(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // For the asynchronous example, cleanup of the MDLs attached to the IRP
    // are done here in the completion routine.  This allows us to free the
    // IRP below.
    PMDL mdl;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (Irp->UserIosb)
    {
        Irp->UserIosb->Information = Irp->IoStatus.Information;
        Irp->UserIosb->Status = Irp->IoStatus.Status;
    }

    if (Irp->MdlAddress != NULL) {
        //
        // Unlock any pages that may be described by MDLs.
        //
        mdl = Irp->MdlAddress;
        while (mdl != NULL)
        {
            if (mdl->MdlFlags & MDL_PAGES_LOCKED)
                MmUnlockPages(mdl);
            mdl = mdl->Next;
        }
        IoFreeMdl(Irp->MdlAddress);
    }

    IoFreeIrp(Irp);

    // This advises the I/O Manager to STOP PROCESSING this request - that the
    // DRIVER is going to perform (and may, in fact, have already performed)
    // additional processing on the I/O request.
    //
    // In fact, in this case, note that we've already freed the IRP - it might be
    // a VERY BAD idea for the I/O Manager to do ANYTHING with that IRP at this 
    // point (since it isn't even an IRP anymore...)
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS DrvAsyncCompletionSignaled(PDEVICE_OBJECT DeviceObject
    , PIRP Irp
    , PVOID Context)
{
    NTSTATUS status = AsyncCompletionBase(DeviceObject, Irp);

    KeSetEvent((PRKEVENT)Context, IO_DISK_INCREMENT, 0);

    return status;
}

NTSTATUS DrvCreateIrp(IN PDEVICE_OBJECT DeviceObject,
                       IN PFILE_OBJECT FileObject,
                       OUT PIO_STATUS_BLOCK  IoStatusBlock,
                       IN KPROCESSOR_MODE requestorMode,
                       IN ULONG MajorFunctionCode,
                       IN ULONG MinorFunctionCode,
                       IN PETHREAD Thread,
                       OUT PIRP* ppIrp)
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION irpSp = NULL;
    if(IoStatusBlock)
    {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }

    // Allocate and initialize the I/O Request Packet (IRP) for this operation.
    irp = IoAllocateIrp( DeviceObject->StackSize, FALSE );
    if (irp == NULL) {
        // An IRP can not be allocated.  Cleanup and return an appropriate error status code
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->Tail.Overlay.Thread = Thread;
    irp->Tail.Overlay.AuxiliaryBuffer = (PCHAR) NULL;
    irp->RequestorMode = requestorMode;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = (PDRIVER_CANCEL) NULL;

    // Fill in the service independent parameters in the IRP.
    irp->MdlAddress = NULL;
    irp->UserIosb = IoStatusBlock;
    irp->UserEvent = NULL;
    irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;
    irp->Overlay.AsynchronousParameters.UserApcContext = NULL;

    //
    // Get a pointer to the stack location for the first driver.  This will be
    // used to pass the original function codes and parameters.  Note that
    // setting the major function here also sets:
    //
    //      MinorFunction = 0;
    //      Flags = 0;
    //      Control = 0;
    //
    irpSp = IoGetNextIrpStackLocation( irp );
    irpSp->MajorFunction = (UCHAR)MajorFunctionCode;
    irpSp->MinorFunction = (UCHAR)MinorFunctionCode;
    irpSp->FileObject = FileObject;

    irpSp->Control = 0;
    irpSp->Context = 0;
    //
    // Now determine whether this device expects to have data buffered to it
    // or whether it performs direct I/O.

    irp->AssociatedIrp.SystemBuffer = (PVOID) NULL;
    irp->MdlAddress = (PMDL) NULL;

    *ppIrp = irp;
    return STATUS_SUCCESS;
}

NTSTATUS DrvSendIrpSetInformation (IN PDEVICE_OBJECT f_pTargetDeviceObject,
                                IN PFILE_OBJECT f_pFileObject,
                                OUT PIO_STATUS_BLOCK  f_pIoStatusBlock,
                                IN FILE_INFORMATION_CLASS f_FileInformationClass,
                                OUT PVOID  f_pBuffer,
                                IN ULONG  f_Length,
                                IN BOOLEAN f_bReplaceIfExists,
                                IN BOOLEAN f_bAdvanceOnly,
                                IN KPROCESSOR_MODE f_requestorMode,
                                IN OPTIONAL PEVENT_DISPATCH f_pIrpCreationDispatch,
                                IN OPTIONAL PVOID f_pIrpCreationContext )
{
    NTSTATUS ntStatus;
    KEVENT ioEvent;
    PIRP pIRP = NULL;
    PIO_STACK_LOCATION pIOStack = NULL;

    ntStatus = DrvCreateIrp(f_pTargetDeviceObject,
                             f_pFileObject,
                             f_pIoStatusBlock,
                             f_requestorMode,
                             IRP_MJ_SET_INFORMATION,
                             0, 
                             PsGetCurrentThread(),
                             &pIRP);

    if( !NT_SUCCESS(ntStatus) )
        return ntStatus;

    // Irp parameters additional initialization
    pIRP->AssociatedIrp.SystemBuffer = f_pBuffer;

    if ( f_pIrpCreationDispatch )
        f_pIrpCreationDispatch ( pIRP, f_pIrpCreationContext );

    // Irp Stack parameters additional initialization
    pIOStack = IoGetNextIrpStackLocation(pIRP);
    pIOStack->Parameters.SetFile.FileInformationClass = f_FileInformationClass;
    pIOStack->Parameters.SetFile.Length = f_Length;

    pIOStack->Parameters.SetFile.AdvanceOnly = f_bAdvanceOnly;
    pIOStack->Parameters.SetFile.ReplaceIfExists = f_bReplaceIfExists;

    // Process irp synchronously
    KeInitializeEvent(&ioEvent, NotificationEvent, FALSE);
    IoSetCompletionRoutine ( pIRP, DrvAsyncCompletionSignaled, &ioEvent, TRUE, TRUE, TRUE );
    ntStatus = IoCallDriver(f_pTargetDeviceObject, pIRP);

    if (STATUS_PENDING == ntStatus) 
    {
        KeWaitForSingleObject(&ioEvent, Executive, KernelMode, FALSE, NULL);
        ntStatus = f_pIoStatusBlock->Status;
    }

    return ntStatus;
}

// just get allocation size for file
NTSTATUS DrvSetAllocationSize(IN PDEVICE_OBJECT pTargetDeviceObject,
                              IN FILE_OBJECT* hFile,
                              IN OUT PLARGE_INTEGER lpAllocationSize)
{
    IO_STATUS_BLOCK iosb;

    FILE_ALLOCATION_INFORMATION lFileAllocationInformation;
    lFileAllocationInformation.AllocationSize = *lpAllocationSize;

    NTSTATUS status = DrvSendIrpSetInformation(pTargetDeviceObject,
        hFile,
        &iosb,
        FileAllocationInformation,
        &lFileAllocationInformation,
        sizeof(lFileAllocationInformation),
        FALSE,
        FALSE,
        KernelMode,
        0,
        0);
    if (NT_SUCCESS(status))
    {
        lpAllocationSize->QuadPart = iosb.Information;
    }
    return status;
}

static void TrimNullEndedUnicodeString(PWSTR Buffer, PUSHORT Length)
{
    while (*Length > 1 && Buffer[*Length / 2 - 1] == 0)
        (*Length) -= 2;
}

#define DELAY_MILLISEC 10

NTKERNELAPI
NTSTATUS
ExUuidCreate(
    OUT UUID *Uuid
);
typedef GUID UUID;

void DrvGenerateSafeGUID(PGUID pGuid)
{
    NTSTATUS status;
    LARGE_INTEGER delay;

    delay.QuadPart = -DELAY_MILLISEC * 10;

    for (;;)
    {
        status = ExUuidCreate(pGuid);

        if (NT_SUCCESS(status) || status == RPC_NT_UUID_LOCAL_ONLY)
        {
            return;
        }
        // if STATUS_RETRY
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

// just IoCompleteRequest
NTSTATUS DrvCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Info)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}