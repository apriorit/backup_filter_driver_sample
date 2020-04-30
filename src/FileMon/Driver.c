#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

#include "cmnUtils.h"
#include "FileMon.h"
#include "DrvCommon.h"
#include "DrvDisk.h"

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

static UNICODE_STRING g_symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\" DEVICE_NAME);
static UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\simplebackupdrv");
static PDEVICE_OBJECT g_pCDODeviceObject = 0;

#define DEVICE_SDDL  L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// interface
static 
NTSTATUS SetStorageVolume(void * pBuffer, 
                          ULONG inputBufferSize, 
                          ULONG outputBufferSize,
                          ULONG_PTR * pBytesWritten)
{
    int number = 0;
    *pBytesWritten = 0;
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (inputBufferSize != sizeof(int))
    {
        return STATUS_INVALID_PARAMETER;
    }
    number = *(int*)pBuffer;
    return DiskCache_SetStorageVolume(number);
}

// now used just to set volume
static
NTSTATUS DeviceMjDeviceControlRoutine(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    ULONG_PTR BytesWritten = 0;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG method = ControlCode & 0x03;
    ULONG InputBufferSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR Buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (method != METHOD_BUFFERED)
    {
        return DrvCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    switch (ControlCode)
    {
        case IOCTL_SET_STORAGE_VOLUME:
        {
            status = SetStorageVolume(Buffer, InputBufferSize, OutputBufferSize, &BytesWritten);
            break;
        }
    }
    return DrvCompleteIrp(Irp, status, BytesWritten);
}

static
NTSTATUS DeviceMjPassThrough(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return DrvCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

void DrvCommonDriverUnload()
{
    if (g_pCDODeviceObject)
    {
        IoDeleteDevice(g_pCDODeviceObject);
        g_pCDODeviceObject = 0;
    }
    IoDeleteSymbolicLink(&g_symbolicLinkName);
    DrvUnregisterFilter();
    DiskCache_Free();
}

static 
VOID DriverUnload(__in PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DrvCommonDriverUnload();
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = 0;
    ULONG i = 0;
    UNICODE_STRING deviceSDDLString;
    
    RtlInitUnicodeString(&deviceSDDLString, DEVICE_SDDL);
    DriverObject->DriverUnload = DriverUnload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = DeviceMjPassThrough;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceMjDeviceControlRoutine;

    status = IoCreateDeviceSecure(DriverObject, 
        0,                                     
        &g_deviceName,                         
        FILE_DEVICE_UNKNOWN,                   
        0,                                     
        FALSE,                                 
        &deviceSDDLString,
        NULL,
        &g_pCDODeviceObject);                      

    DRV_CHECK_STATUS

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    DRV_CHECK_STATUS

    status = DrvRegisterMinifilter(DriverObject, RegistryPath);
    DRV_CHECK_STATUS

    status = DiskCache_Init();
    DRV_CHECK_STATUS

    return status;

cleanup:
    DrvCommonDriverUnload();
    return status;
}