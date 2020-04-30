#include <fltKernel.h>
#include <stdio.h>
#include "cmnUtils.h"
#include "DrvDisk.h"
#include "cmnWrite.h"

#define CLUSTER_SIZE             4096
#define BUFFER_SIZE_IN_CLUSTERS     4

#define TYPE_WRITE_OP               1

// Handle, file, device
static DrvVolume_type g_volume = { 0, };
static ERESOURCE g_resource = { 0, };
static LONG g_inited = 0;

static long long g_currentCluster = 0;

// working buffer - will be allocated with allocPool
static void * g_pWorkingBuffer = 0;
static int g_workingBufferSize = CLUSTER_SIZE*BUFFER_SIZE_IN_CLUSTERS;
static int g_sizeInBuffer = 0;

// magic1: APIO - normal IO block
static char g_magic[4] = { 'A', 'P', 'I', 'O' };
#pragma pack(push, 1)
typedef struct _OperationInfo{
    unsigned char  magic[4];
    INT32 sizeOfHeader;
    GUID streamGuid;
    INT32 typeAndFlags;
    INT32 sizeOfPacket;
    INT32 sizeOfFileName;
    INT32 sizeOfBuffer;
    INT64 offset;
}OperationInfo_type;
#pragma pack(pop)

NTSTATUS DrvOpenVolume(PUNICODE_STRING ObjectName,
    DrvVolume_type* pVolume)
{
    PFILE_OBJECT fileObject;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    RtlZeroMemory(pVolume, sizeof(*pVolume));

    InitializeObjectAttributes(&objectAttributes,
        ObjectName,
        0,
        (HANDLE)NULL,
        (PSECURITY_DESCRIPTOR)NULL);

    status = ZwOpenFile(&fileHandle,
        0,
        &objectAttributes,
        &ioStatus,
        0,
        FILE_NON_DIRECTORY_FILE);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)& fileObject,
        NULL);

    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        return status;
    }

    pVolume->pFileObject = fileObject;
    pVolume->pDeviceObject = IoGetRelatedDeviceObject(fileObject);
    pVolume->hVolume = fileHandle;
    return status;
}

void DrvCloseVolume(DrvVolume_type* pVolume)
{
    if (pVolume->pFileObject)
    {
        ObDereferenceObject(pVolume->pFileObject);
    }
    if (pVolume->hVolume)
    {
        ZwClose(pVolume->hVolume);
    }
    RtlZeroMemory(pVolume, sizeof(DrvVolume_type));
}

NTSTATUS DrvOpenVolumeByNumber(int number,
    DrvVolume_type* pVolume)
{
    wchar_t tempBuf[32];
    int size = _snwprintf(tempBuf,
        32,
        L"\\??\\HarddiskVolume%d",
        number);
    if (size == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    UNICODE_STRING driveName;
    driveName.Buffer = tempBuf;
    driveName.Length = (USHORT)(size * sizeof(wchar_t));
    driveName.MaximumLength = driveName.Length;
    return DrvOpenVolume(&driveName, pVolume);
}

// write buffer to g_volume using DrvSendWriteIrp; Switch to the next cluster if required
static
void FlushAndPrepareBuffer(int switchToNext)
{
    IO_STATUS_BLOCK block;
    LARGE_INTEGER byteOffset;
    NTSTATUS status;
    int sizeToWrite = g_sizeInBuffer;

    if (sizeToWrite % CLUSTER_SIZE)
    {
        sizeToWrite = sizeToWrite + CLUSTER_SIZE - (sizeToWrite % CLUSTER_SIZE);
    }
    
    byteOffset.QuadPart = g_currentCluster * CLUSTER_SIZE;

    status =  DrvSendWriteIrp(g_volume.pDeviceObject,
        g_volume.pFileObject,
        &block,
        g_pWorkingBuffer,
        sizeToWrite,
        &byteOffset);

    if (switchToNext)
    {
        g_currentCluster += BUFFER_SIZE_IN_CLUSTERS;
        g_sizeInBuffer = 0;
    }
}

// reservs free space in g_pWorkingBuffer if possible
static
void * BufferAlloc(int size)
{
    void * pResult = 0;
    int freeSpaceInBuffer = g_workingBufferSize - g_sizeInBuffer;
    if (freeSpaceInBuffer < size)
    {
        return 0;
    }
    pResult = (char*)g_pWorkingBuffer + g_sizeInBuffer;
    g_sizeInBuffer += size;
    return pResult;
}

// alloc at least OperationInfo_type (calls FlushAndPrepareBuffer if no enough space)); will alloc pResultSize with g_workingBufferSize as limit
static
void * BufferAllocSomething(IN int size, OUT int * pResultSize)
{
    void * pResult = 0;
    int freeSpaceInBuffer = g_workingBufferSize - g_sizeInBuffer;
    if (freeSpaceInBuffer < sizeof(OperationInfo_type))
    {
        FlushAndPrepareBuffer(TRUE);
    }
    // g_sizeInBuffer may be 0
    freeSpaceInBuffer = g_workingBufferSize - g_sizeInBuffer;
    pResult = (char*)g_pWorkingBuffer + g_sizeInBuffer;
    if (freeSpaceInBuffer < size)
    {
        g_sizeInBuffer += freeSpaceInBuffer;
        *pResultSize = freeSpaceInBuffer;
    }
    else
    {
        g_sizeInBuffer += size;
        *pResultSize = size;
    }
    return pResult;
}

// just writes pData to buffer
static void BufferCopy(const void * pData, int size)
{
    int sizeToWrite = size;
    const char * pDataToWrite = (const char * )pData;
    for (; sizeToWrite;)
    {
        int sizeAllocated = 0;
        void * pAllocated = BufferAllocSomething(sizeToWrite, &sizeAllocated);
        memcpy(pAllocated, pDataToWrite, sizeAllocated);
        pDataToWrite += sizeAllocated;
        sizeToWrite -= sizeAllocated;
    }
}

// writes file name and pOrigBuf to buffer
static
void DiskCache_LogWithNameImpl(const GUID * pStreamUID,
    const UNICODE_STRING * pFileName,
    void * pOrigBuf,
    ULONG_PTR bufferSize,
    long long offset)
{
    OperationInfo_type * pHeader = 0;
    if ((int)bufferSize < 0)
    {
        // overflow
        return;
    }

    //  fill header
    pHeader = BufferAlloc(sizeof(OperationInfo_type));
    if (!pHeader)
    {
        FlushAndPrepareBuffer(TRUE);
        pHeader = BufferAlloc(sizeof(OperationInfo_type));
    }
    RtlZeroMemory(pHeader, sizeof(OperationInfo_type));
    memcpy(pHeader->magic, g_magic, sizeof(g_magic));
    pHeader->streamGuid = *pStreamUID;
    pHeader->typeAndFlags = TYPE_WRITE_OP;
    pHeader->sizeOfHeader = sizeof(OperationInfo_type);
    pHeader->sizeOfPacket = (int)sizeof(OperationInfo_type) + (int)pFileName->Length + (int)bufferSize;

    pHeader->sizeOfFileName = pFileName->Length;
    pHeader->sizeOfBuffer = (int)bufferSize;
    pHeader->offset = offset;

    // put file name
    BufferCopy(pFileName->Buffer, pFileName->Length);
    BufferCopy(pOrigBuf, (int)bufferSize);
    FlushAndPrepareBuffer(FALSE);
}

NTSTATUS DiskCache_Init()
{
    NTSTATUS status = ExInitializeResourceLite(&g_resource);
    if (NT_SUCCESS(status))
    {
        g_pWorkingBuffer = ExAllocatePool(PagedPool, g_workingBufferSize);
        if (!g_pWorkingBuffer)
        {
            ExDeleteResourceLite(&g_resource);
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_inited, 1);
    }
    return status;
}

void DiskCache_Free()
{
    if (g_inited)
    {
        InterlockedExchange(&g_inited, 0);

        if (g_pWorkingBuffer)
        {
            ExFreePool(g_pWorkingBuffer);
        }
        DrvCloseVolume(&g_volume);
        ExDeleteResourceLite(&g_resource);
    }
}

void DiskCache_LogWithName(const GUID * pStreamUID,
                           const UNICODE_STRING * pFileName,
                           void * pOrigBuf,
                           ULONG_PTR bufferSize,
                           long long offset)
{
    if (!g_inited)
    {
        return;
    }

    ExAcquireResourceSharedLite(&g_resource, TRUE);

    if (g_volume.pDeviceObject)
    {
        DiskCache_LogWithNameImpl(pStreamUID,
            pFileName,
            pOrigBuf,
            bufferSize,
            offset);
    }

    ExReleaseResourceLite(&g_resource);
}

NTSTATUS DiskCache_SetStorageVolume(int number)
{
    NTSTATUS status = 0;
    DrvVolume_type volume = { 0, };
    
    if (!g_inited)
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = DrvOpenVolumeByNumber(number, &volume);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // switch
    ExAcquireResourceExclusiveLite(&g_resource, TRUE);

    DrvCloseVolume(&g_volume);
    g_volume = volume;

    g_currentCluster = 0;
    g_sizeInBuffer = 0;
    ExReleaseResourceLite(&g_resource);
    return status;
}