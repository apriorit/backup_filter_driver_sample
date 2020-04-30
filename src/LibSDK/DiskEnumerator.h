#pragma once

#include "System.h"

namespace drvcontrol
{
    
class CDiskEnumerator
{
    std::vector<wchar_t> m_buffer;
    int m_offset;
public:
    CDiskEnumerator(bool bRefresh);
    void Refresh();

    void ClearState();
    bool QueryNextDrive(std::wstring * pDrive);
};

ULONG QueryNTName(const std::wstring & volumePath,
    std::vector<char> & cache,
    std::wstring * pNTName);

DWORD GetFirstRelatedPhysicalDisk(HANDLE hVolume, std::wstring* firstPhysicalName);
}