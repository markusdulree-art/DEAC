#pragma once
#include <cstdint>

namespace deac::telemetry {

struct Sample final {
    std::uint64_t monotonic_ns{};
    float aim_speed_deg_s{};
    float input_interval_stddev_ms{};
    float reaction_ms{};
    float movement_efficiency{};
    float view_delta_deg{};
    std::uint32_t shots{};
    std::uint32_t headshots{};
};

struct Aggregate final {
    std::uint64_t sample_count{};
    float headshot_ratio{};
    float mean_aim_speed{};
    float stddev_input_interval{};
    float mean_reaction{};
    float movement_efficiency{};
};

} // namespace deac::telemetry
