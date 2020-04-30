#include "DiskEnumerator.h"
#include "DrvCommon.h"

namespace drvcontrol
{

CDiskEnumerator::CDiskEnumerator(bool bRefresh)
    :
    m_buffer(1024),
    m_offset(-1)
{
    if (bRefresh)
    {
        Refresh();
    }
}
void CDiskEnumerator::Refresh()
{
    DWORD dwRes = GetLogicalDriveStringsW((DWORD)m_buffer.size() - 1, &m_buffer.front());
    if (!dwRes)
        throw Exception("Can't enum logical drives", GetLastError());
    ClearState();
}

void CDiskEnumerator::ClearState()
{
    m_offset = -1;
}
bool CDiskEnumerator::QueryNextDrive(std::wstring * pDrive)
{
    pDrive->clear();
    wchar_t * pData = &m_buffer.front() + m_offset + 1;
    if (!*pData)
        return false;

    *pDrive = pData;
    ++m_offset;
    while (*pData)
    {
        ++pData;
        ++m_offset;
    }
    return true;
}


ULONG QueryNTName(const std::wstring & volumePath,
    std::vector<char> & cache,
    std::wstring * pNTName)
{
    pNTName->clear();
    cache.resize(1024 * 2);
    wchar_t * pNTNameBuffer = (wchar_t*)&cache.front();
    std::wstring volumePath2 = volumePath;
    for(;;)
    {
        if (volumePath2.empty())
        {
            return ERROR_INVALID_FUNCTION;
        }
        if (volumePath2.back() != L'\\')
        {
            break;
        }
        volumePath2.resize(volumePath2.size() - 1);
    }
    if (wcsncmp(volumePath2.c_str(), L"\\\\.\\", 4) == 0)
    {
        volumePath2.erase(0, 4);
    }
    if (wcsncmp(volumePath2.c_str(), L"\\??\\", 4) == 0)
    {
        volumePath2.erase(0, 4);
    }

    if (!QueryDosDeviceW(volumePath2.c_str(), pNTNameBuffer, (DWORD)cache.size() / 2))
    {
        return GetLastError();
    }
    *pNTName = pNTNameBuffer;
    return NO_ERROR;
}

static DWORD GetPhysicalDrives(HANDLE hnd, std::vector<ULONG>& physicalDisks)
{
    VOLUME_DISK_EXTENTS vde;
    memset(&vde, 0, sizeof(VOLUME_DISK_EXTENTS));
    DWORD bytes = 0;

    if (DeviceIoControl(hnd,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        NULL,
        0,
        &vde,
        sizeof(vde),
        &bytes,
        NULL))
    {
        if (!vde.NumberOfDiskExtents)
        {
            physicalDisks.clear();
            return ERROR_NO_DATA_DETECTED;
        }
        physicalDisks.assign(vde.NumberOfDiskExtents, 0);
        physicalDisks[0] = vde.Extents[0].DiskNumber;
        return 0;
    }

    DWORD err = GetLastError();
    if (err != ERROR_MORE_DATA)
        return err;
    if (vde.NumberOfDiskExtents > 1)
    {
        std::vector<char> tmp_buf(sizeof(VOLUME_DISK_EXTENTS) +
            (vde.NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT));
        PVOLUME_DISK_EXTENTS pExtVde = (PVOLUME_DISK_EXTENTS)&tmp_buf[0];

        DWORD totalSize = tmp_buf.size();

        if (!DeviceIoControl(hnd,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            NULL,
            0,
            pExtVde,
            totalSize,
            &bytes,
            NULL))
        {
            return GetLastError();
        }
        physicalDisks.assign(pExtVde->NumberOfDiskExtents, 0);
        for (DWORD i = 0; i < pExtVde->NumberOfDiskExtents; ++i)
        {
            physicalDisks[i] = pExtVde->Extents[i].DiskNumber;
        }
    }
    return 0;
}


DWORD GetFirstRelatedPhysicalDisk(HANDLE hVolume, std::wstring* firstPhysicalName)
{
    std::vector<ULONG> numbOfFirstPhysDrive;
    DWORD err = GetPhysicalDrives(hVolume, numbOfFirstPhysDrive);
    if (err != ERROR_SUCCESS)
    {
        firstPhysicalName->clear();
        return err;
    }
    firstPhysicalName->assign(L"\\\\.\\PhysicalDrive" + std::to_wstring(numbOfFirstPhysDrive[0]));
    return 0;
}

}