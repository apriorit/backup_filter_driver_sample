#pragma once

NTSTATUS
DrvRegisterMinifilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

void DrvUnregisterFilter();