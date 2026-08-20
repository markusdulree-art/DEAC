#include "deac_detection.h"
#include <algorithm>
#include <cmath>

namespace deac::detection {

Score Evaluate(const telemetry::Aggregate& a) {
    Score result{};
    if (a.valid_count < 20 || a.coverage_ratio < 0.70f) return result;

    const float reaction_component = std::clamp((120.0f - a.mean_reaction) / 120.0f, 0.0f, 1.0f);
    const float aim_component = std::clamp(a.mean_aim_speed / 2500.0f, 0.0f, 1.0f);
    const float regularity_component = std::clamp(1.0f - a.stddev_input_interval / 150.0f, 0.0f, 1.0f);
    const float headshot_component = std::clamp((a.headshot_ratio - 0.35f) / 0.65f, 0.0f, 1.0f);

    result.anomaly =
        0.25f * reaction_component +
        0.20f * aim_component +
        0.25f * regularity_component +
        0.30f * headshot_component;

    result.data_quality = std::clamp(
        0.60f * a.coverage_ratio +
        0.40f * (static_cast<float>(a.valid_count) / 500.0f), 0.0f, 1.0f);
    result.action_ready = result.data_quality >= 0.8f && result.anomaly >= 0.85f;
    return result;
}

} // namespace deac::detection
