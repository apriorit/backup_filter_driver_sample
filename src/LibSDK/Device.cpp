#include "Device.h"
#include "DrvCommon.h"

namespace drvcontrol
{

CDrvDevice::CDrvDevice()
{
}
void CDrvDevice::Connect()
{
    m_device.Connect(DEVICE_NAME);
}
void CDrvDevice::Close()
{
    m_device.Close();
}
void CDrvDevice::SetStorageVolume(int number)
{
    int param = number;
    m_device.DeviceControl(IOCTL_SET_STORAGE_VOLUME, 
                           &param,
                           sizeof(param),
                           0,
                           0);
}

}