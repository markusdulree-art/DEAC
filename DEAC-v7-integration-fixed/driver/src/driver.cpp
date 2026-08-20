#include <ntddk.h>
#include "deac_driver.h"
#include "event_queue.h"
#include "deac_protocol.h"

extern "C" DRIVER_INITIALIZE DriverEntry;

static VOID DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
    DeacStopHeartbeat();
    DeacUnregisterCallbacks();
    DeacDeleteDevice(driverObject);
    deac::kernel::g_event_queue.Reset();
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    driverObject->DriverUnload = DriverUnload;
    deac::kernel::g_event_queue.Initialize();

    NTSTATUS status = DeacInitializeDevice(driverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DeacRegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        DeacDeleteDevice(driverObject);
        return status;
    }

    status = DeacStartHeartbeat();
    if (!NT_SUCCESS(status)) {
        DeacUnregisterCallbacks();
        DeacDeleteDevice(driverObject);
        return status;
    }

    return STATUS_SUCCESS;
}
