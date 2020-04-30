#pragma once

#include "windows.h"
#include "stdexcept"
#include "string"
#include "vector"

namespace drvcontrol
{

class Exception:public std::runtime_error
{
    ULONG m_win32Error;
public:
    Exception(const std::string & text, ULONG errorCode = 0)
        :
            std::runtime_error(text),
            m_win32Error(errorCode)
    {
    }
    ULONG GetErrorCode() const
    {
        return m_win32Error;
    }
};


class CDevice
{
    CDevice(const CDevice&);
    CDevice& operator = (const CDevice&);

    HANDLE m_hHandle = 0;
public:
    CDevice();
    ~CDevice();

    void Connect(const std::wstring & symLinkShortName);
    void Close();
    size_t DeviceControl(ULONG code,
                        const void * pData,
                        size_t size,
                        void * pOutData,
                        size_t outSize);

};

}
