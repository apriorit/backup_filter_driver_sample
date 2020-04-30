#include "System.h"

namespace drvcontrol
{

void CDevice::Close()
{
    if (m_hHandle)
    {
        CloseHandle(m_hHandle);
        m_hHandle = 0;
    }
}
void CDevice::Connect(const std::wstring & symLinkShortName)
{
    std::wstring fullName = L"\\\\.\\" + symLinkShortName;
    HANDLE hHandle = CreateFileW(
        fullName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hHandle == INVALID_HANDLE_VALUE)
    {
        throw Exception("Can't access device", GetLastError());
    }

    Close();
    m_hHandle = hHandle;
}
CDevice::CDevice()
{
}
CDevice::~CDevice()
{
    Close();
}
size_t CDevice::DeviceControl(ULONG code,
                              const void * pData,
                              size_t size,
                              void * pOutData,
                              size_t outSize)
{
    if (!m_hHandle)
    {
        throw Exception("Device is not accessible");
    }

    DWORD resSize = 0;
    BOOL result = DeviceIoControl(m_hHandle,
        code,
        (void*)pData,
        (ULONG)size,
        pOutData,
        (ULONG)outSize,
        &resSize,
        NULL);
    if (!result)
    {
        throw Exception("Device call failed", GetLastError());
    }
    return resSize;
}


}