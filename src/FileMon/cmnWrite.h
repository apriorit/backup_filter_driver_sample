#pragma once

// just writes buffer to pFileObject
NTSTATUS DrvSendWriteIrp(IN PDEVICE_OBJECT pNextDeviceObject,
                      IN PFILE_OBJECT pFileObject,
                      OUT PIO_STATUS_BLOCK ioStatusBlock,
                      IN PVOID pBuffer,
                      IN ULONG ulLength,
                      IN PLARGE_INTEGER pliByteOffset);
