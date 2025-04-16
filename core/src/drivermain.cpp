#include <ntifs.h>
#include <wdm.h>
#include "dcdriver.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    return DiskCryptor::DriverMain::Instance().Initialize(DriverObject, RegistryPath);
}
