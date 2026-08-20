#pragma once
#include <windows.h>
#include <optional>
#include "deac_protocol.h"

namespace deac::service {

class DriverClient final {
public:
    DriverClient() = default;
    DriverClient(const DriverClient&) = delete;
    DriverClient& operator=(const DriverClient&) = delete;
    ~DriverClient();

    bool connect();
    void disconnect() noexcept;
    bool connected() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

    std::optional<deac::protocol::DriverStatus> status();
    std::optional<deac::protocol::Event> nextEvent();

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

} // namespace deac::service
