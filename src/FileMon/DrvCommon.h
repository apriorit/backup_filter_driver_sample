﻿#define DEVICE_NAME     L"simplebackupdrv"

#define IOCTL_SET_STORAGE_VOLUME                  \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ALL_ACCESS)
