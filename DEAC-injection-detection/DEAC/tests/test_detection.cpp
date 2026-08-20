#include "deac_detection.h"
#include "deac_policy.h"
#include "telemetry_engine.h"
#include "deac_config.h"
#include "evidence_graph.h"
#include "process_identity.h"
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


    {
        using namespace deac;
        identity::ProcessIdentity cs2{100, 10001, "cs2.exe"};
        identity::ProcessIdentity helper{200, 20002, "helper.exe"};
        identity::ProcessIdentity reused{200, 20003, "helper.exe"};
        graph::EvidenceGraph graph(10000, 128);

        graph.observe({1000, 1, graph::EventKind::DangerousHandle, cs2, helper, "handle", 0.25f, 0.35f});
        graph.observe({1100, 2, graph::EventKind::ImageLoaded, cs2, {}, "unsigned-module", 0.92f, 0.90f});
        auto corr = graph.correlate(helper, cs2, graph::EventKind::ImageLoaded, 1101);
        assert(corr.same_target_instance);
        assert(corr.same_source_instance);
        assert(corr.handle_before_module);
        assert(corr.boost >= 0.30f);

        graph.observe({1200, 3, graph::EventKind::MemoryPrivateExecutablePe, cs2, helper, "0x1234", 0.90f, 0.94f});
        corr = graph.correlate(helper, cs2, graph::EventKind::MemoryPrivateExecutablePe, 1201);
        assert(corr.handle_before_memory);
        assert(corr.module_before_memory);

        // PID reuse must not correlate with the previous process instance.
        corr = graph.correlate(reused, cs2, graph::EventKind::ImageLoaded, 1202);
        assert(!corr.same_source_instance);
    }

    std::cout << "DEAC detection/policy/config/graph tests passed\n";
    return 0;
}
