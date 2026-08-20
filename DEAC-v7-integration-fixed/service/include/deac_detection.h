#pragma once
#include "deac_telemetry.h"

namespace deac::detection {

struct Score final {
    float anomaly{};
    float data_quality{};
    bool action_ready{};
};

Score Evaluate(const telemetry::Aggregate& aggregate);

} // namespace deac::detection
