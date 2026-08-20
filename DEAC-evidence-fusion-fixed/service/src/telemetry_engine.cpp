#include "telemetry_engine.h"
#include <algorithm>
#include <cmath>

namespace deac::telemetry {

Aggregate AggregateSamples(const Sample* samples, std::size_t count) {
    Aggregate out{};
    out.received_count = count;
    if (!samples || count == 0) return out;

    double aim = 0.0, variance = 0.0, reaction = 0.0, movement = 0.0;
    std::uint64_t shots = 0, headshots = 0;

    for (std::size_t i = 0; i < count; ++i) {
        const auto& sample = samples[i];
        if (!std::isfinite(sample.aim_speed_deg_s) ||
            !std::isfinite(sample.input_interval_stddev_ms) ||
            !std::isfinite(sample.reaction_ms) ||
            !std::isfinite(sample.movement_efficiency)) {
            continue;
        }

        ++out.valid_count;
        aim += std::max(0.0f, sample.aim_speed_deg_s);
        variance += std::max(0.0f, sample.input_interval_stddev_ms);
        reaction += std::max(0.0f, sample.reaction_ms);
        movement += std::clamp(sample.movement_efficiency, 0.0f, 1.0f);
        shots += sample.shots;
        headshots += std::min(sample.headshots, sample.shots);
    }

    out.invalid_count = out.received_count - out.valid_count;
    out.coverage_ratio = count ? static_cast<float>(out.valid_count) / static_cast<float>(count) : 0.0f;
    if (out.valid_count == 0) return out;

    const double denom = static_cast<double>(out.valid_count);
    out.mean_aim_speed = static_cast<float>(aim / denom);
    out.stddev_input_interval = static_cast<float>(variance / denom);
    out.mean_reaction = static_cast<float>(reaction / denom);
    out.movement_efficiency = static_cast<float>(movement / denom);
    out.headshot_ratio = shots ? static_cast<float>(headshots) / static_cast<float>(shots) : 0.0f;
    return out;
}

void Engine::add(const Sample& sample) {
    samples_[next_] = sample;
    next_ = (next_ + 1) % kWindow;
    if (count_ < kWindow) ++count_;
}

Aggregate Engine::aggregate() const {
    if (count_ == 0) return {};
    return AggregateSamples(samples_, count_ < kWindow ? count_ : kWindow);
}

std::size_t Engine::size() const noexcept { return count_; }
void Engine::clear() { count_ = 0; next_ = 0; }

} // namespace deac::telemetry
