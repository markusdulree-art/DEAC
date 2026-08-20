#include "driver_client.h"

namespace deac::service {

DriverClient::~DriverClient() { disconnect(); }

bool DriverClient::connect() {
    disconnect();
    handle_ = CreateFileW(
        L"\\\\.\\DEAC", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    return connected();
}

void DriverClient::disconnect() noexcept {
    if (connected()) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

std::optional<deac::protocol::DriverStatus> DriverClient::status() {
    if (!connected()) return std::nullopt;
    deac::protocol::DriverStatus result{};
    DWORD returned = 0;
    if (!DeviceIoControl(handle_, IOCTL_DEAC_GET_STATUS, nullptr, 0,
                         &result, sizeof(result), &returned, nullptr)) {
        return std::nullopt;
    }
    if (returned != sizeof(result) || result.version != deac::protocol::kProtocolVersion) {
        return std::nullopt;
    }
    return result;
}

std::optional<deac::protocol::Event> DriverClient::nextEvent() {
    if (!connected()) return std::nullopt;
    deac::protocol::Event event{};
    DWORD returned = 0;
    if (!DeviceIoControl(handle_, IOCTL_DEAC_GET_EVENT, nullptr, 0,
                         &event, sizeof(event), &returned, nullptr)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) return std::nullopt;
        return std::nullopt;
    }
    if (returned != sizeof(event) || event.version != deac::protocol::kProtocolVersion) {
        return std::nullopt;
    }
    return event;
}

} // namespace deac::service
