#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace deac::config {

struct Settings final {
    std::uint16_t telemetry_port{30080};
    std::uint32_t telemetry_max_body_bytes{64 * 1024};
    std::uint32_t telemetry_poll_ms{50};
    std::uint32_t heartbeat_timeout_ms{5000};
    std::uint32_t evidence_flush_ms{1000};
    std::uint32_t minimum_supporting_events{3};
    std::uint32_t minimum_supporting_families{2};
    float monitor_threshold{0.70f};
    float review_threshold{0.82f};
    float enforce_threshold{0.93f};
    bool enable_local_http{true};
};

Settings Defaults();
Settings Load(const std::filesystem::path& path);
bool Save(const std::filesystem::path& path, const Settings& settings);

} // namespace deac::config
