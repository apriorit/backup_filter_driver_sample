#include "Device.h"
#include "iostream"
#include "DiskEnumerator.h"
#include "map"
#include "sstream"
#include "memory"

static void PrintUsage()
{
    std::cout << "Usage: <command> <parameters>\n";
    std::cout << "Commands: \n";
    std::cout << "    set_volume <volume_number>\n";
    std::cout << "    enum_volumes\n";
}

union DiskPartitions
{
    PARTITION_INFORMATION partitionInfo;
    PARTITION_INFORMATION_EX partitionInfoEx;
};

static void PrintPartitionInfo(HANDLE hVolume)
{
    union DiskPartitions partitions;
    DWORD retBytes = 0;

    if (DeviceIoControl(hVolume,
        IOCTL_DISK_GET_PARTITION_INFO,
        0,
        0,
        &partitions.partitionInfo,
        sizeof(PARTITION_INFORMATION),
        &retBytes,
        0))
    {
        std::wcout << L"Offset: " << partitions.partitionInfo.StartingOffset.QuadPart << L"\n";
        std::wcout << L"Size: " << partitions.partitionInfo.PartitionLength.QuadPart << L"\n";
        return;
    }
    if (DeviceIoControl(hVolume,
        IOCTL_DISK_GET_PARTITION_INFO_EX,
        0,
        0,
        &partitions.partitionInfoEx,
        sizeof(PARTITION_INFORMATION_EX),
        &retBytes,
        0))
    {
        if (partitions.partitionInfoEx.IsServicePartition)
        {
            std::wcout << L"In Use: Service Partition\n";
        }
        std::wcout << L"Offset: " << partitions.partitionInfoEx.StartingOffset.QuadPart << L"\n";
        std::wcout << L"Size: " << partitions.partitionInfoEx.PartitionLength.QuadPart << L"\n";
        return;
    }
    std::wcout << L"Can't receive partition info: " << GetLastError()<< L"\n";
}
static void EnumDisks()
{
    drvcontrol::CDiskEnumerator enumerator(true);
    std::wstring drive, ntName;
    std::vector<char> cache;

    std::wcout <<"Volumes: \n";
    std::map<std::wstring, std::wstring> ntNamesInUse;
    while (enumerator.QueryNextDrive(&drive))
    {
        if (drvcontrol::QueryNTName(drive, cache, &ntName) == 0)
        {
            ntNamesInUse[ntName] = drive;
        }
    }

    wchar_t tempBuf[32];
    for (int i = 1; i < 1024; ++i)
    {
        _snwprintf_s(tempBuf,
            32,
            L"\\??\\HarddiskVolume%d",
            i);

        HANDLE hDisk = CreateFile(tempBuf,
            SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
            OPEN_EXISTING,
            0,
            0);
        if (hDisk == INVALID_HANDLE_VALUE)
        {
            break;
        }
        std::shared_ptr<void> pv(hDisk, CloseHandle);

        std::wcout<<L"------- "<< tempBuf << L" ------\n";
        std::wstring physDisk;
        ULONG error = drvcontrol::GetFirstRelatedPhysicalDisk(hDisk, &physDisk);
        if (error)
        {
            std::wcout << L"Can't read physical disk, error code " << error << L"\n";
        }
        else
        {
            std::wcout << L"Disk: " << physDisk << L"\n";
        }
        error = drvcontrol::QueryNTName(tempBuf, cache, &ntName);
        if (error)
        {
            std::wcout << L"Can't access drive, error code " << error << L"\n";
        }
        else
        {
            auto it = ntNamesInUse.find(ntName);
            if (it != ntNamesInUse.end())
            {
                std::wcout << "In use, mapped to [" << it->second << "] \n";
            }
            else
            {
                PrintPartitionInfo(hDisk);
            }
        }
    }
}
static void SetVolume(const std::wstring & volumeNumber)
{
    int param = 0;
    try
    {
        param = std::stoi(volumeNumber);
    }
    catch (...)
    {
        throw std::runtime_error("Can't parse volume number, please specify valid number [1-N]");
    }
    if (param < 1)
    {
        throw std::runtime_error("Please specify valid number [1-N]");
    }

    drvcontrol::CDrvDevice device;
    device.Connect();
    device.SetStorageVolume(param);
}
int wmain(int argc, wchar_t * argv[])
{
    try
    {
        if (argc < 2)
        {
            PrintUsage();
            return 0;
        }
        if (wcscmp(argv[1], L"enum_volumes") == 0)
        {
            EnumDisks();
        }
        else if (wcscmp(argv[1], L"set_volume") == 0)
        {
            if (argc != 3)
            {
                throw std::runtime_error("Illegal number of arguments");
            }
            SetVolume(argv[2]);
        }
        else
        {
            throw std::runtime_error("Invalid command");
        }
    }
    catch (const drvcontrol::Exception & e)
    {
        std::cout<<"Error: "<<e.what()<<"\n";
        if (!e.GetErrorCode())
        {
            return 1;
        }
        std::cout<<"Code: "<<e.GetErrorCode()<<"\n";
        return e.GetErrorCode();
    }
    catch (const std::exception & e)
    {
        std::cout<<"Error: "<<e.what()<<"\n";
        return 1;
    }
    return 0;
}