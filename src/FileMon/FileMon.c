/*
 *  This is the main module of the FileMon miniFilter driver.
*/
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntintsafe.h>
#include "cmnUtils.h"
#include "DrvDisk.h"
#include "FileMon.h"

#define EXTERN_C_START 
#define EXTERN_C_END 

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define NTFS_MFT_CLUSTER_SIZE 4096
PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
int filterRegistered = 0;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
ULONG gTraceFlags = 0;

static UNICODE_STRING g_monFolderName =
    DRV_CONST_UNICODE_STRING_VAL(L"c:\\storage");

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START
// dbg pring
NTSTATUS
DrvFileMonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

// dbg pring
VOID
DrvFileMonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

// dbg pring
VOID
DrvFileMonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

// dbg pring
NTSTATUS
DrvFileMonUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// dbg pring
NTSTATUS
DrvFileMonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// NpFileMonDoRequestOperationStatus check
FLT_PREOP_CALLBACK_STATUS
DrvFileMonPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// dbg pring
VOID
DrvFileMonOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

// dbg pring
FLT_POSTOP_CALLBACK_STATUS
DrvFileMonPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// dbg pring
FLT_PREOP_CALLBACK_STATUS
DrvFileMonPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// return boolean state based on which operations we are interested in
BOOLEAN
DrvFileMonDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DrvFileMonUnload)
#pragma alloc_text(PAGE, DrvFileMonInstanceQueryTeardown)
#pragma alloc_text(PAGE, DrvFileMonInstanceSetup)
#pragma alloc_text(PAGE, DrvFileMonInstanceTeardownStart)
#pragma alloc_text(PAGE, DrvFileMonInstanceTeardownComplete)
#endif
//
//  operation registration
//

typedef struct _FileStreamContext {
    UNICODE_STRING fileName;
    LONG forceReplaceOnCreate;
    GUID streamUID;
} FileStreamContext;

// just ExFreePool for filename buffer
VOID
FileStreamContextCleanup(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
)
{
    UNREFERENCED_PARAMETER(ContextType);
    FileStreamContext * pContext = (PFLT_CONTEXT)Context;
    if (pContext->fileName.Buffer)
    {
        ExFreePool(pContext->fileName.Buffer);
    }
}

// creates FileStreamContext to our filter
static
NTSTATUS CreateContext(PCFLT_RELATED_OBJECTS   FltObjects,
                       UNICODE_STRING * pFileName,
                       PFILE_OBJECT pFileObject)
{
    FileStreamContext * pContext = 0, * pOldContext = 0;
    NTSTATUS status = FltAllocateContext(FltObjects->Filter,
                                        FLT_STREAM_CONTEXT, 
                                        sizeof(FileStreamContext),
                                        PagedPool,
                                        &pContext);
    if (!NT_SUCCESS(status))
        return status;

    RtlZeroMemory(pContext, sizeof(FileStreamContext));

    // gen uid
    DrvGenerateSafeGUID(&pContext->streamUID);

    // take ownership
    pContext->fileName = *pFileName;
    RtlZeroMemory(pFileName, sizeof(UNICODE_STRING));

    status = FltSetStreamContext(FltObjects->Instance,
        pFileObject,
        FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
        pContext,
        &pOldContext);

    DRV_CHECK_STATUS

cleanup:
    if (pContext)
    {
        FltReleaseContext(pContext);
    }
    if (pOldContext)
    {
        FltReleaseContext(pOldContext);
    }
    return status;
}

//store /*/ from pTarget to targetChunk (same internal buffer used!)
static int ParseChunk(const UNICODE_STRING * pTarget,
                      OUT UNICODE_STRING  * targetChunk,
                      int offset)
{
    int i = offset;
    int maxLength = pTarget->Length / 2;
    targetChunk->Buffer = 0;
    targetChunk->Length = 0;
    targetChunk->MaximumLength = 0;

    // skip slashes
    for (;;)
    {
        if (i >= maxLength)
        {
            return i;
        }
        targetChunk->Buffer = pTarget->Buffer + i;
        if (pTarget->Buffer[i] != L'/' &&
            pTarget->Buffer[i] != L'\\')
        {
            break;
        }
        ++i;
    }
    // slashes skipped well
    for (;;)
    {
        if (i >= maxLength)
        {
            break;
        }
        if (pTarget->Buffer[i] == L'/' ||
            pTarget->Buffer[i] == L'\\')
        {
            break;
        }
        targetChunk->Length += 2;
        ++i;
    }
    targetChunk->MaximumLength = targetChunk->Length;
    return i;
}

// compare ^/*/ of pTarget and pPattern
static int SmartStartsWith(const UNICODE_STRING * pTarget,
                           const UNICODE_STRING * pPattern)
{
    int targetOffset = 0;
    int patternOffset = 0;
    UNICODE_STRING targetChunk;
    UNICODE_STRING patternChunk;

    for(;;)
    {
        targetOffset = ParseChunk(pTarget, &targetChunk, targetOffset);
        patternOffset = ParseChunk(pPattern, &patternChunk, patternOffset);

        if (patternChunk.Length == 0)
        {
            return 1;
        }
        if (RtlCompareUnicodeString(&targetChunk, &patternChunk, TRUE))
        {
            return 0;
        }
    }
}

// just apply some checks and return FLT_PREOP_SUCCESS_WITH_CALLBACK
FLT_PREOP_CALLBACK_STATUS MiniFilter_PreCreate(
    __inout PFLT_CALLBACK_DATA      Data,
    __in    PCFLT_RELATED_OBJECTS   FltObjects,
    __out   PVOID                  *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();

    ASSERT(Data->Iopb->MajorFunction == IRP_MJ_CREATE ||
        Data->Iopb->MajorFunction == IRP_MJ_NETWORK_QUERY_OPEN);

    // check is it really interesting file access
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL ||
        ExGetPreviousMode() == KernelMode ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE) ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)
        )
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// creates context for filters as drive name and filename
FLT_POSTOP_CALLBACK_STATUS
MiniFilter_PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING  * pVolumeName = 0;
    UNICODE_STRING volumeDosName = { 0, };
    UNICODE_STRING resultFileName = { 0, };
    USHORT resultMaxSizeInBytes = 0;
    FileStreamContext * pFileStreamContext = 0;
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    NTSTATUS streamStatus = FltGetStreamContext(FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        &pFileStreamContext
    );
    if (NT_SUCCESS(streamStatus))
    {
        if ((!pFileStreamContext->forceReplaceOnCreate) ||
            (0 == InterlockedCompareExchange(&pFileStreamContext->forceReplaceOnCreate, 0, 1)))
        {
            FltReleaseContext(pFileStreamContext);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    // resolving file name
    NTSTATUS status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED |
        FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInfo);
    DRV_CHECK_STATUS

    status = FltParseFileNameInformation(nameInfo);
    DRV_CHECK_STATUS
        
    status = IoVolumeDeviceToDosName(FltObjects->FileObject->DeviceObject, &volumeDosName);
    DRV_CHECK_STATUS

    status = RtlUShortAdd(volumeDosName.Length, nameInfo->Name.Length, &resultMaxSizeInBytes);
    DRV_CHECK_STATUS

    resultFileName.Buffer = ExAllocatePool(PagedPool, resultMaxSizeInBytes);
    DRV_CHECK_ALLOC(resultFileName.Buffer);
    resultFileName.MaximumLength = resultMaxSizeInBytes;

    status = RtlAppendUnicodeStringToString(&resultFileName, &volumeDosName);
    DRV_CHECK_STATUS

    UNICODE_STRING fileName;
    fileName.Buffer = Add2Ptr(nameInfo->Name.Buffer, nameInfo->Volume.Length);
    fileName.Length = nameInfo->Name.Length - nameInfo->Volume.Length - nameInfo->Stream.Length;
    fileName.MaximumLength = fileName.Length;
    
    status = RtlAppendUnicodeStringToString(&resultFileName, &fileName);
    DRV_CHECK_STATUS
 
    // compare names
    if (!SmartStartsWith(&resultFileName, &g_monFolderName))
    {
        goto cleanup;
    }

    // save it
    status = CreateContext(FltObjects,
                           &resultFileName,
                           Data->Iopb->TargetFileObject);
    DRV_CHECK_STATUS

cleanup:
    if (nameInfo)
    {
        FltReleaseFileNameInformation(nameInfo);
    }
    if (resultFileName.Buffer)
    {
        ExFreePool(resultFileName.Buffer);
    }
    if (volumeDosName.Buffer)
    {
        ExFreePool(volumeDosName.Buffer);
    }
    if (pVolumeName)
    {
        ExFreePool(pVolumeName);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

typedef struct IOCompletionContext
{
    long long offset;
} IOCompletionContext_type;

// set offset for logging as IOCompletionContext_type
FLT_PREOP_CALLBACK_STATUS MiniFilter_PreWrite(
    __inout PFLT_CALLBACK_DATA      Data,
    __in    PCFLT_RELATED_OBJECTS   FltObjects,
    __out   PVOID                  *CompletionContext
)
{
    FLT_PREOP_CALLBACK_STATUS opStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    *CompletionContext = 0;
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return opStatus;
    }

    FileStreamContext * pFileStreamContext = 0;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        &pFileStreamContext
    );
    if (!NT_SUCCESS(status))
    {
        return opStatus;
    }

    // context acquired
    if ((Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) == 0)
    {
        // this is regular IO
        FSRTL_COMMON_FCB_HEADER* pFCB = (FSRTL_COMMON_FCB_HEADER*)Data->Iopb->TargetFileObject->FsContext;
        if (pFCB->AllocationSize.QuadPart < NTFS_MFT_CLUSTER_SIZE)
        {
            LARGE_INTEGER liAllocationSize = { NTFS_MFT_CLUSTER_SIZE,0 };
            PDEVICE_OBJECT pDeviceObject = IoGetBaseFileSystemDeviceObject(Data->Iopb->TargetFileObject);

            if (!FLT_IS_IRP_OPERATION(Data)) {

                opStatus = FLT_PREOP_DISALLOW_FASTIO;
                goto cleanup;
            }

            status  = DrvSetAllocationSize(pDeviceObject, Data->Iopb->TargetFileObject, &liAllocationSize);
            if (!NT_SUCCESS(status))
            {
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                opStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
        }
        opStatus = opStatus;
        goto cleanup;
    }

    // this is paging IO we are interested in
    *CompletionContext = ExAllocatePool(PagedPool, sizeof(IOCompletionContext_type));
    if (*CompletionContext == 0)
    {
        opStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto cleanup;
    }
    // init context
    {
        IOCompletionContext_type * pContext = (IOCompletionContext_type *)*CompletionContext;
        pContext->offset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
    }
    opStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

cleanup:
    FltReleaseContext(pFileStreamContext);
    return opStatus;
}

// just ExFreePool
static void FreeCompletionContext(IOCompletionContext_type * pContext)
{
    if (pContext)
    {
        ExFreePool(pContext);
    }
}

// if context (drive name and filename) exists - DiskCache_LogWithName
static void AnalyseAndReport(PCFLT_RELATED_OBJECTS FltObjects,
                             void * pOrigBuf,
                             ULONG_PTR bufferSize,
                             PFILE_OBJECT pFileObject,
                             IOCompletionContext_type * pContext)
{
    // report
    FileStreamContext * pFileStreamContext = 0;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance,
        pFileObject,
        &pFileStreamContext
    );
    if (NT_SUCCESS(status))
    {
        DiskCache_LogWithName(&pFileStreamContext->streamUID,
            &pFileStreamContext->fileName,
            pOrigBuf,
            bufferSize,
            pContext->offset);

        FltReleaseContext(pFileStreamContext);
    }
}

// writes context and orig buff via AnalyseAndReport
static
FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffersWhenSafe(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PVOID origBuf;
    NTSTATUS status;
    IOCompletionContext_type * pContext = (IOCompletionContext_type * )CompletionContext;
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);

    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status)) 
    {
        FreeCompletionContext(pContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress,
                                           NormalPagePriority);
    if (origBuf == NULL) 
    {
        FreeCompletionContext(pContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    AnalyseAndReport(FltObjects,
                     origBuf, 
                     Data->IoStatus.Information,
                     FltObjects->FileObject,
                     pContext);
    FreeCompletionContext(pContext);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// write to file using SwapPostReadBuffersWhenSafe or AnalyseAndReport
FLT_POSTOP_CALLBACK_STATUS
MiniFilter_PostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    PVOID origBuf;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
    IOCompletionContext_type * pContext = (IOCompletionContext_type *)CompletionContext;

    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        (Data->IoStatus.Information == 0)) 
    {
        FreeCompletionContext(pContext);
        return retValue;
    }

    if (iopb->Parameters.Write.MdlAddress != NULL) 
    {
        origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress,
            NormalPagePriority);

        if (origBuf == NULL) 
        {
            FreeCompletionContext(pContext);
            return retValue;
        }

    }
    else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
        FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) 
    {
        origBuf = iopb->Parameters.Write.WriteBuffer;
    }
    else 
    {
        if (!FltDoCompletionProcessingWhenSafe(Data,
            FltObjects,
            CompletionContext,
            Flags,
            SwapPostReadBuffersWhenSafe,
            &retValue)) 
        {
            Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
            Data->IoStatus.Information = 0;
        }
        FreeCompletionContext(pContext);
        return retValue;
    }

    AnalyseAndReport(FltObjects,
                    origBuf, 
                    Data->IoStatus.Information,
                    FltObjects->FileObject,
                    pContext);
    FreeCompletionContext(pContext);
    return retValue;
}

// if FileRenameInformation - set forceReplaceOnCreate of FileStreamContext
FLT_PREOP_CALLBACK_STATUS NpFileMonPreSetInformation(
    __inout PFLT_CALLBACK_DATA      Data,
    __in    PCFLT_RELATED_OBJECTS   FltObjects,
    __out   PVOID                  *CompletionContext
)
{
    FileStreamContext * pFileStreamContext = 0;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        &pFileStreamContext
    );

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    if (!NT_SUCCESS(status))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS fileInformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (fileInformationClass == FileRenameInformation)
    {
        InterlockedExchange(&pFileStreamContext->forceReplaceOnCreate, 1);
    }

    FltReleaseContext(pFileStreamContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      MiniFilter_PreCreate,
      MiniFilter_PostCreate },

    { IRP_MJ_WRITE,
      0,
      MiniFilter_PreWrite,
      MiniFilter_PostWrite },

    { IRP_MJ_SET_INFORMATION,
      0,
      NpFileMonPreSetInformation,
      NULL },

    { IRP_MJ_CLEANUP,
      0,
      DrvFileMonPreOperation,
      DrvFileMonPostOperation },

    { IRP_MJ_CLOSE,
      0,
      DrvFileMonPreOperation,
      DrvFileMonPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//
const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAM_CONTEXT,
        0,
        FileStreamContextCleanup,
        sizeof(FileStreamContext),
        'IqsC'},

    { FLT_CONTEXT_END }
};


CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ), //  Size
    FLT_REGISTRATION_VERSION,   //  Version
    0,                          //  Flags

    ContextRegistration,        //  Context
    Callbacks,                  //  Operation callbacks

    DrvFileMonUnload,            //  MiniFilterUnload

    DrvFileMonInstanceSetup,                    //  InstanceSetup
    DrvFileMonInstanceQueryTeardown,            //  InstanceQueryTeardown
    DrvFileMonInstanceTeardownStart,            //  InstanceTeardownStart
    DrvFileMonInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                       //  GenerateFileName
    NULL,                       //  GenerateDestinationFileName
    NULL                        //  NormalizeNameComponent

};


NTSTATUS
DrvFileMonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
DrvFileMonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}

VOID
DrvFileMonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonInstanceTeardownStart: Entered\n"));
}

VOID
DrvFileMonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonInstanceTeardownComplete: Entered\n"));
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/
NTSTATUS
DrvRegisterMinifilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = 0;
    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("NpFileMon!RegisterMinifilter: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) 
    {
        filterRegistered = 1;
        status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(status)) 
        {
            DrvUnregisterFilter();
        }
    }
    return status;
}

// just FltUnregisterFilter
void DrvUnregisterFilter()
{
    if (filterRegistered)
    {
        FltUnregisterFilter(gFilterHandle);
        filterRegistered = 0;
    }
}

// Driver.c
void DrvCommonDriverUnload();

// unload + unregister filter
NTSTATUS
DrvFileMonUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("NpFileMon!NpFileMonUnload: Entered\n") );

    DrvCommonDriverUnload();
    FltUnregisterFilter( gFilterHandle );
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
DrvFileMonPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonPreOperation: Entered\n"));

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (DrvFileMonDoRequestOperationStatus(Data)) {

        status = FltRequestOperationStatusCallback(Data,
            DrvFileMonOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("NpFileMon!NpFileMonPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID
DrvFileMonOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("NpFileMon!NpFileMonOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_POSTOP_CALLBACK_STATUS
DrvFileMonPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonPostOperation: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
DrvFileMonPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("NpFileMon!NpFileMonPreOperationNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
DrvFileMonDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

        //
        //  Check for oplock operations
        //

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
        ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
            (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
            (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
            (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

            ||

            //
            //    Check for directy change notification
            //

            ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
            (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
            );
}