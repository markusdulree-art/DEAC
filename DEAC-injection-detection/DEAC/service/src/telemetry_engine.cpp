#include "telemetry_engine.h"
#include <algorithm>
#include <cmath>

namespace deac::telemetry {

Aggregate AggregateSamples(const Sample* samples, std::size_t count) {
    Aggregate out{};
    if (!samples || count == 0) return out;
    double aim=0, variance=0, reaction=0, movement=0;
    std::uint64_t shots=0, headshots=0;
    for (std::size_t i=0; i<count; ++i) {
        if (!std::isfinite(samples[i].aim_speed_deg_s) || !std::isfinite(samples[i].input_interval_stddev_ms) ||
            !std::isfinite(samples[i].reaction_ms) || !std::isfinite(samples[i].movement_efficiency)) continue;
        aim += std::max(0.0f, samples[i].aim_speed_deg_s);
        variance += std::max(0.0f, samples[i].input_interval_stddev_ms);
        reaction += std::max(0.0f, samples[i].reaction_ms);
        movement += std::clamp(samples[i].movement_efficiency, 0.0f, 1.0f);
        shots += samples[i].shots;
        headshots += std::min(samples[i].headshots, samples[i].shots);
    }
    out.sample_count = count;
    out.mean_aim_speed = static_cast<float>(aim / count);
    out.stddev_input_interval = static_cast<float>(variance / count);
    out.mean_reaction = static_cast<float>(reaction / count);
    out.movement_efficiency = static_cast<float>(movement / count);
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
    if (count_ < kWindow) return AggregateSamples(samples_, count_);
    return AggregateSamples(samples_, kWindow);
}

std::size_t Engine::size() const noexcept { return count_; }
void Engine::clear() { count_ = 0; next_ = 0; }

} // namespace deac::telemetry
