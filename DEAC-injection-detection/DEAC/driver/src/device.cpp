#include <ntddk.h>
#include <wdmsec.h>
#include "deac_protocol.h"
#include "deac_driver.h"
#include "event_queue.h"

namespace {
PDEVICE_OBJECT g_device = nullptr;
UNICODE_STRING g_device_name = RTL_CONSTANT_STRING(L"\\Device\\DEAC");
UNICODE_STRING g_dos_name = RTL_CONSTANT_STRING(L"\\DosDevices\\DEAC");

deac::protocol::PlatformSecurityState g_platform{};
ULONG g_policy_flags = 0;

NTSTATUS Complete(_Inout_ PIRP irp, NTSTATUS status, ULONG_PTR information = 0) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP irp) { return Complete(irp, STATUS_SUCCESS); }

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP irp) {
    auto* stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (code == IOCTL_DEAC_GET_VERSION) {
        if (outLen < sizeof(std::uint32_t)) return Complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        *static_cast<std::uint32_t*>(irp->AssociatedIrp.SystemBuffer) = deac::protocol::kProtocolVersion;
        return Complete(irp, STATUS_SUCCESS, sizeof(std::uint32_t));
    }

    if (code == IOCTL_DEAC_GET_STATUS) {
        if (outLen < sizeof(deac::protocol::DriverStatus)) return Complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        deac::protocol::DriverStatus status{};
        status.size = sizeof(status);
        status.version = deac::protocol::kProtocolVersion;
        status.state = 1;
        status.platform = g_platform;
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &status, sizeof(status));
        return Complete(irp, STATUS_SUCCESS, sizeof(status));
    }

    if (code == IOCTL_DEAC_SET_POLICY_FLAGS) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(deac::protocol::PolicyFlags))
            return Complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        const auto* input = static_cast<const deac::protocol::PolicyFlags*>(irp->AssociatedIrp.SystemBuffer);
        if (input->size != sizeof(*input) || input->version != deac::protocol::kProtocolVersion)
            return Complete(irp, STATUS_REVISION_MISMATCH, 0);
        // Policy flags are deliberately limited to service-controlled configuration bits.
        g_policy_flags = input->flags;
        return Complete(irp, STATUS_SUCCESS);
    }

    if (code == IOCTL_DEAC_GET_EVENT) {
        if (outLen < sizeof(deac::protocol::Event)) return Complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        deac::protocol::Event event{};
        if (!deac::kernel::g_event_queue.Pop(&event)) return Complete(irp, STATUS_NO_MORE_ENTRIES, 0);
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &event, sizeof(event));
        return Complete(irp, STATUS_SUCCESS, sizeof(event));
    }

    return Complete(irp, STATUS_INVALID_DEVICE_REQUEST);
}
}

NTSTATUS DeacInitializeDevice(PDRIVER_OBJECT driverObject) {
    PDEVICE_OBJECT device = nullptr;
    // Restrict the device object to SYSTEM and local Administrators. The service runs under a
    // managed service identity; ordinary desktop processes must not be able to issue write IOCTLs.
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    const GUID device_class_guid = { 0x7b4b9f61, 0x31af, 0x4cbb, { 0x8f, 0xb0, 0x2b, 0x8f, 0x8a, 0x1f, 0x2d, 0x5e } };
    NTSTATUS status = IoCreateDeviceSecure(
        driverObject, 0, &g_device_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
        &device_class_guid, &device);
    if (!NT_SUCCESS(status)) return status;

    g_device = device;
    status = IoCreateSymbolicLink(&g_dos_name, &g_device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = nullptr;
        return status;
    }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        driverObject->MajorFunction[i] = CreateClose;
    }
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return DeacQueryPlatformSecurity(&g_platform);
}

VOID DeacDeleteDevice(PDRIVER_OBJECT) {
    IoDeleteSymbolicLink(&g_dos_name);
    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = nullptr;
    }
}
