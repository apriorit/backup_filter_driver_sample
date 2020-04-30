#pragma once

typedef struct DrvVolume
{
    HANDLE hVolume;
    PFILE_OBJECT pFileObject;
    PDEVICE_OBJECT pDeviceObject;
} DrvVolume_type;


// ZwOpenFile + ObReferenceObjectByHandle
NTSTATUS DrvOpenVolume(PUNICODE_STRING ObjectName,
    DrvVolume_type* pVolume);

// ZwClose + ObDereferenceObject
void DrvCloseVolume(DrvVolume_type* pVolume);

NTSTATUS DrvOpenVolumeByNumber(int number,
    DrvVolume_type* pVolume);

// calls DiskCache_LogWithNameImpl -  writes pFileName and then pOrigBuf to g_volume
void DiskCache_LogWithName(const GUID * pStreamUID,
                           const UNICODE_STRING * pFileName,
                           void * pOrigBuf,
                           ULONG_PTR bufferSize,
                           long long offset);

// opens volume and sets to g_volume (if already set - closes first)
NTSTATUS DiskCache_SetStorageVolume(int number);
// just  init g_resource, alloc buffer and set g_inited 1
NTSTATUS DiskCache_Init();
// just free buffer and set g_inited 0
void DiskCache_Free();
