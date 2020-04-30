#pragma once

#include "System.h"

namespace drvcontrol
{

class CDrvDevice
{
    CDevice m_device;
public:
    CDrvDevice();
    void Connect();
    void Close();
    void SetStorageVolume(int number);
};


}
