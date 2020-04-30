#pragma once

#define DRV_CHECK_STATUS if (!NT_SUCCESS(status)) goto cleanup;
#define DRV_CHECK_ALLOC(X) if (!(X)) { status = STATUS_INSUFFICIENT_RESOURCES; goto cleanup; }
#define DRV_CONST_UNICODE_STRING_VAL(Str)  {sizeof(Str)-2, sizeof(Str)-2, Str}

typedef
VOID
(*PEVENT_DISPATCH) (IN PIRP Irp, IN PVOID Context);

// will be deleted async
NTSTATUS DrvCreateIrp(IN PDEVICE_OBJECT DeviceObject,
                       IN PFILE_OBJECT FileObject,
                       OUT PIO_STATUS_BLOCK  IoStatusBlock,
                       IN KPROCESSOR_MODE requestorMode,
                       IN ULONG MajorFunctionCode,
                       IN ULONG MinorFunctionCode,
                       IN PETHREAD Thread,
                       OUT PIRP* ppIrp);

// create Irp, send, wait while processed and async deleted
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
                                IN OPTIONAL PVOID f_pIrpCreationContext );

// just get allocation size for file (using DrcSendIrpSetInformation)
NTSTATUS DrvSetAllocationSize(IN PDEVICE_OBJECT f_pTargetDeviceObject,
                             IN FILE_OBJECT* hFile,
                             IN OUT PLARGE_INTEGER lpAllocationSize);

// just creates GUID
void DrvGenerateSafeGUID(OUT PGUID pGuid);

// just IoCompleteRequest call
NTSTATUS DrvCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Info);

// callback for async Irp processing - deletes Irp
NTSTATUS DrvAsyncCompletionSignaled(PDEVICE_OBJECT DeviceObject
    , PIRP Irp
    , PVOID Context);
