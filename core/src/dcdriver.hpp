#pragma once
#include <ntifs.h>
#include <wdm.h>

namespace DiskCryptor {

class DriverMain {
public:
    static DriverMain& Instance();

    NTSTATUS Initialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath);

private:
    DriverMain() = default;

    void LoadConfig(PUNICODE_STRING registryPath);
    int GetCpuCount();
    void CheckBaseMemory();
    static void AutoMountThread(void* param);
    static void ReinitRoutine(PDRIVER_OBJECT driverObject, void* context, uint32_t count);
    int CreateControlDevice(PDRIVER_OBJECT driverObject);
    NTSTATUS DispatchIrp(PDEVICE_OBJECT deviceObject, PIRP irp);

    PDEVICE_OBJECT m_DeviceObject = nullptr;
    ULONG m_ConfigFlags = 0;
    ULONG m_LoadFlags = 0;
    ULONG m_BootFlags = 0;
    ULONG m_BootMemKbs = 0;
    ULONG m_CpuCount = 0;
};

} // namespace DiskCryptor
