#include "deac_detection.h"
#include "deac_policy.h"
#include "telemetry_engine.h"
#include "deac_config.h"
#include <filesystem>
#include <cassert>
#include <iostream>

int main() {
    deac::telemetry::Aggregate empty{};
    assert(deac::detection::Evaluate(empty).anomaly == 0.0f);

    deac::telemetry::Engine telemetry;
    deac::telemetry::Sample sample{};
    sample.aim_speed_deg_s = 2500.0f;
    sample.input_interval_stddev_ms = 5.0f;
    sample.reaction_ms = 20.0f;
    sample.movement_efficiency = 0.8f;
    sample.shots = 10;
    sample.headshots = 9;
    for (int i = 0; i < 500; ++i) telemetry.add(sample);
    const auto aggregate = telemetry.aggregate();
    const auto score = deac::detection::Evaluate(aggregate);
    assert(score.anomaly > 0.85f);
    assert(score.action_ready);

    deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 3, 16});
    for (int i = 0; i < 3; ++i) {
        deac::policy::Evidence e{};
        e.anomaly = 0.96f; e.data_quality = 1.0f; e.event_type = 9; e.sequence = i + 1;
        policy.add(e);
    }
    const auto result = policy.evaluate();
    assert(result.decision == deac::policy::Decision::Enforce);
    assert(result.supporting_events == 3);

    const auto configPath = std::filesystem::temp_directory_path() / "deac_config_test.json";
    auto settings = deac::config::Defaults();
    settings.telemetry_port = 80;
    settings.monitor_threshold = 0.95f;
    settings.review_threshold = 0.10f;
    settings.enforce_threshold = 0.20f;
    assert(deac::config::Save(configPath, settings));
    const auto loaded = deac::config::Load(configPath);
    assert(loaded.telemetry_port >= 1024);
    assert(loaded.monitor_threshold <= loaded.review_threshold);
    assert(loaded.review_threshold <= loaded.enforce_threshold);
    std::filesystem::remove(configPath);

    std::cout << "DEAC detection/policy/config tests passed\n";
    return 0;
}
