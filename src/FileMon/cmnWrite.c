#include <ntifs.h>
#include "cmnUtils.h"
#include "cmnWrite.h"

static
NTSTATUS ValidateParameters(IN PDEVICE_OBJECT NextDeviceObject,
    IN PFILE_OBJECT FileObject,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  Buffer,
    IN ULONG  Length,
    IN PLARGE_INTEGER  ByteOffset,
    IN KPROCESSOR_MODE requestorMode)
{
    LARGE_INTEGER fileOffset = { 0,0 };

    if (!NextDeviceObject || !IoStatusBlock || !Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    //  Negative file offsets are illegal.
    //
    if (fileOffset.HighPart < 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // capture ByteOffset parameter if it is present.
    //

    if (ARGUMENT_PRESENT(ByteOffset)) {
        fileOffset = *ByteOffset;
    }

    if (requestorMode != KernelMode)
    {
        if (!FileObject)
            return STATUS_INVALID_PARAMETER;

        //Validate offset
        if (FileObject->Flags & FO_NO_INTERMEDIATE_BUFFERING)
        {
            //
            // The file was opened without intermediate buffering enabled.
            // Check that the Buffer is properly aligned, and that the
            // length is an integral number of the block size.
            //

            if ((NextDeviceObject->SectorSize &&
                (Length & (NextDeviceObject->SectorSize - 1))) ||
                (ULONG_PTR)Buffer &NextDeviceObject->AlignmentRequirement)
            {

                //
                // Check for sector sizes that are not a power of two.
                //

                if ((NextDeviceObject->SectorSize &&
                    Length %NextDeviceObject->SectorSize) ||
                    (ULONG_PTR)Buffer &NextDeviceObject->AlignmentRequirement)
                {
                    ASSERT(FALSE);
                    return STATUS_INVALID_PARAMETER;
                }
            }

            //
            // If a ByteOffset parameter was specified, ensure that it
            // is a valid argument.
            //

            if (ARGUMENT_PRESENT(ByteOffset))
            {
                if (NextDeviceObject->SectorSize &&
                    (fileOffset.LowPart &(NextDeviceObject->SectorSize - 1)))
                {
                    ASSERT(FALSE);
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }

    }
    return STATUS_SUCCESS;
}

static
NTSTATUS WriteCreateIrp(IN PDEVICE_OBJECT DeviceObject,
    IN PFILE_OBJECT FileObject,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  Buffer,
    IN ULONG  Length,
    IN ULONG MajorFunctionCode,
    IN ULONG MinorFunctionCode,
    IN PETHREAD Thread,
    IN LOCK_OPERATION Operation,
    IN BOOLEAN fMdlCopy,
    OUT PIRP* ppIrp)
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION irpSp = NULL;

    if (IoStatusBlock)
    {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }

    // Allocate and initialize the I/O Request Packet (IRP) for this operation.
    irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (irp == NULL) {
        // An IRP can not be allocated.  Cleanup and return an appropriate error status code
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->Tail.Overlay.Thread = Thread;
    irp->Tail.Overlay.AuxiliaryBuffer = (PCHAR)NULL;
    irp->RequestorMode = KernelMode;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = (PDRIVER_CANCEL)NULL;

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
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = (UCHAR)MajorFunctionCode;
    irpSp->MinorFunction = (UCHAR)MinorFunctionCode;
    irpSp->FileObject = FileObject;

    irpSp->Control = 0;
    irpSp->Context = 0;
    //
    // Now determine whether this device expects to have data buffered to it
    // or whether it performs direct I/O.

    irp->AssociatedIrp.SystemBuffer = (PVOID)NULL;
    irp->MdlAddress = (PMDL)NULL;

    irp->Flags = IRP_DEFER_IO_COMPLETION;

    if (DeviceObject->Flags & DO_BUFFERED_IO) {
        if (Length) {
            irp->AssociatedIrp.SystemBuffer = Buffer;
        }
    }
    else if (DeviceObject->Flags & DO_DIRECT_IO) {
        //
        // This is a direct I/O operation.  Allocate an MDL and invoke the
        // memory management routine to lock the buffer into memory.This
        // is done using an exception handler that will perform cleanup if
        // the operation fails.  Note that no MDL is allocated, nor is any
        // memory probed or locked if the length of the request was zero.
        //
        if (fMdlCopy == TRUE) {
            irp->MdlAddress = (PMDL)Buffer;
        }
        else if (Length) {
            __try {
                //
                // Allocate an MDL, charging quota for it,and hang it off of
                // the IRP.  Probe and lock the pages associated with the
                // caller's buffer for write access and fill in the MDL with
                // the PFNs of those pages.
                //
                irp->MdlAddress = IoAllocateMdl(Buffer, Length, 0, 0, 0);
                if (irp->MdlAddress == NULL) {
                    IoFreeIrp(irp);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                MmProbeAndLockPages(irp->MdlAddress, KernelMode, Operation);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                IoFreeMdl(irp->MdlAddress);
                IoFreeIrp(irp);
                return STATUS_UNSUCCESSFUL;
                //return GetExceptionCode();
            }
        }
    }
    else {
        // Pass the address of the user's buffer so the driver has access to
        // it.  It is now the driver's responsibility to do everything.
        irp->UserBuffer = Buffer;
    }

    *ppIrp = irp;
    return STATUS_SUCCESS;
}

NTSTATUS DrvSendWriteIrp(IN PDEVICE_OBJECT pNextDeviceObject,
                  IN PFILE_OBJECT pFileObject,
                  OUT PIO_STATUS_BLOCK ioStatusBlock,
                  IN PVOID pBuffer,
                  IN ULONG ulLength,
                  IN PLARGE_INTEGER pliByteOffset)
{
    NTSTATUS ntStatus;
    KEVENT ioEvent;
    PIRP pIRP = NULL;
    PIO_STACK_LOCATION pIOStack = NULL;

    ntStatus = ValidateParameters(pNextDeviceObject,
                                 pFileObject,
                                 ioStatusBlock,
                                 pBuffer,
                                 ulLength,
                                 pliByteOffset,
                                 KernelMode);
    
    if(!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    ntStatus = WriteCreateIrp(pNextDeviceObject,
                         pFileObject,
                         ioStatusBlock,
                         pBuffer,
                         ulLength,
                         IRP_MJ_WRITE,
                         IRP_MN_NORMAL, 
                         PsGetCurrentThread(),
                         IoReadAccess,
                         FALSE,
                         &pIRP);

    if(!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    pIRP->Flags |= IRP_WRITE_OPERATION | IRP_DEFER_IO_COMPLETION;

    if (pFileObject != NULL)
    {
    if (pFileObject->Flags & FO_NO_INTERMEDIATE_BUFFERING)
    {
            pIRP->Flags |= IRP_NOCACHE;
    }
    }

    pIOStack = IoGetNextIrpStackLocation(pIRP);

    pIOStack->Parameters.Write.Length = ulLength;
    pIOStack->Parameters.Write.Key = 0;
    pIOStack->Parameters.Write.ByteOffset = *pliByteOffset;

    KeInitializeEvent(&ioEvent, NotificationEvent, FALSE);

    IoSetCompletionRoutine(pIRP, DrvAsyncCompletionSignaled, &ioEvent, TRUE, TRUE, TRUE);

    ntStatus = IoCallDriver(pNextDeviceObject, pIRP);

    if (STATUS_PENDING == ntStatus) 
    {
        KeWaitForSingleObject(&ioEvent, Executive, KernelMode, FALSE, NULL);

        ntStatus = ioStatusBlock->Status;
    }

    return ntStatus;
}
