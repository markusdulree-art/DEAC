#include "deac_detection.h"
#include "deac_policy.h"
#include "telemetry_engine.h"
#include "deac_config.h"
#include "evidence_graph.h"
#include "process_identity.h"
#include <filesystem>
#include <cassert>
#include <iostream>
#include <limits>

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
    assert(aggregate.received_count == 500);
    assert(aggregate.valid_count == 500);
    assert(aggregate.coverage_ratio > 0.99f);

    deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 3, 2, 16});
    for (int i = 0; i < 3; ++i) {
        deac::policy::Evidence e{};
        e.anomaly = 0.96f; e.data_quality = 1.0f; e.event_type = 9; e.sequence = i + 1;
        e.evidence_family = (i == 0 ? "module-provenance" : (i == 1 ? "memory-integrity" : "handle-integrity"));
        e.correlation_id = "session:1";
        e.correlation_edges = 1;
        e.correlation_boost = 0.40f;
        policy.add(e);
    }
    const auto result = policy.evaluate();
    assert(result.decision == deac::policy::Decision::Enforce);
    assert(result.supporting_events == 3);


    {
        deac::telemetry::Engine invalids;
        deac::telemetry::Sample bad{};
        bad.aim_speed_deg_s = std::numeric_limits<float>::quiet_NaN();
        for (int i = 0; i < 30; ++i) invalids.add(bad);
        const auto a = invalids.aggregate();
        assert(a.received_count == 30);
        assert(a.valid_count == 0);
        assert(a.invalid_count == 30);
        assert(a.coverage_ratio == 0.0f);
    }

#ifdef _WIN32
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

#endif


    {
        using namespace deac;
        identity::ProcessIdentity cs2{100, 10001, "cs2.exe"};
        identity::ProcessIdentity helper{200, 20002, "helper.exe"};
        identity::ProcessIdentity reused{200, 20003, "helper.exe"};
        graph::EvidenceGraph graph(deac::graph::TimingConfig{1000, 1200, 2000, 5000}, 128);

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


    {
        // Shared target/source context alone must not create a causal relationship.
        using namespace deac;
        identity::ProcessIdentity cs2{101, 10101, "cs2.exe"};
        identity::ProcessIdentity helper{201, 20101, "helper.exe"};
        graph::EvidenceGraph graph(deac::graph::TimingConfig{500, 700, 1000, 5000}, 128);
        graph.observe({1000, 1, graph::EventKind::ProcessCreated, cs2, helper, {}, 0.0f, 0.1f});
        auto corr = graph.correlate(helper, cs2, graph::EventKind::ImageLoaded, 1100);
        assert(!corr.relationship_valid);
        assert(corr.boost == 0.0f);
        assert(!corr.temporal_proximity);
    }

    {
        // Independent evidence families should reinforce nonlinearly, while duplicate keys are discounted.
        deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 3, 3, 32});
        const char* families[] = {"module-provenance", "memory-integrity", "handle-integrity"};
        for (int i = 0; i < 3; ++i) {
            deac::policy::Evidence e{};
            e.anomaly = 0.88f;
            e.data_quality = 0.98f;
            e.sequence = static_cast<std::uint64_t>(10 + i);
            e.evidence_key = std::string(families[i]) + ":1";
            e.evidence_family = families[i];
            e.correlation_id = "session:independent";
            e.correlation_edges = 1;
            e.correlation_boost = 0.55f;
            policy.add(e);
        }
        auto r = policy.evaluate();
        assert(r.supporting_families == 3);
        assert(r.correlated_events == 1);
        assert(r.confidence > 0.93f);

        deac::policy::Evidence duplicate{};
        duplicate.anomaly = 0.99f;
        duplicate.data_quality = 1.0f;
        duplicate.sequence = 20;
        duplicate.evidence_key = "module-provenance:1";
        duplicate.evidence_family = "module-provenance";
        policy.add(duplicate);
        auto r2 = policy.evaluate();
        assert(r2.supporting_families == 3);
    }


    {
        // Repeated observations from one family must not satisfy the minimum independent-family requirement.
        deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 3, 2, 32});
        for (int i = 0; i < 3; ++i) {
            deac::policy::Evidence e{};
            e.anomaly = 0.99f;
            e.data_quality = 1.0f;
            e.sequence = static_cast<std::uint64_t>(100 + i);
            e.evidence_key = "same-memory-region";
            e.evidence_family = "memory-integrity";
            e.correlation_id = "session:duplicates";
            e.correlation_edges = 1;
            e.correlation_boost = 0.5f;
            policy.add(e);
        }
        const auto r = policy.evaluate();
        assert(r.supporting_families == 1);
        assert(r.supporting_events == 1);
        assert(r.decision != deac::policy::Decision::Enforce);
    }

    {
        // Correlation metadata must not inflate raw evidence strength. The relationship is
        // consumed structurally by policy (and is required for enforcement), not as a scalar
        // anomaly bonus.
        deac::policy::Engine plain({0.70f, 0.82f, 0.93f, 1, 2, 32});
        deac::policy::Engine correlated({0.70f, 0.82f, 0.93f, 1, 2, 32});
        for (auto* engine : {&plain, &correlated}) {
            deac::policy::Evidence a{};
            a.anomaly = 0.80f;
            a.data_quality = 1.0f;
            a.evidence_key = "access:1";
            a.evidence_family = "process-access";
            engine->add(a);

            deac::policy::Evidence b{};
            b.anomaly = 0.80f;
            b.data_quality = 1.0f;
            b.evidence_key = "memory:1";
            b.evidence_family = "memory-integrity";
            if (engine == &correlated) {
                b.correlation_id = "session:chain:1";
                b.correlation_edges = 2;
                b.correlation_boost = 0.90f;
            }
            engine->add(b);
        }
        const auto plain_result = plain.evaluate();
        const auto correlated_result = correlated.evaluate();
        assert(std::abs(plain_result.confidence - correlated_result.confidence) < 0.001f);
        assert(correlated_result.correlated_events == 1);
        assert(plain_result.correlated_events == 0);
    }

    {
        // Telemetry loss is a confidence ceiling, not a positive evidence vote.
        deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 2, 2, 32});
        for (const char* family : {"process-access", "memory-integrity", "module-provenance"}) {
            deac::policy::Evidence e{};
            e.anomaly = 0.99f;
            e.data_quality = 1.0f;
            e.evidence_key = std::string(family) + ":1";
            e.evidence_family = family;
            e.correlation_id = "session:loss-chain";
            e.correlation_edges = 1;
            policy.add(e);
        }
        deac::policy::Evidence loss{};
        loss.event_type = static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow);
        loss.evidence_family = "telemetry-integrity";
        loss.evidence_key = "queue-loss";
        policy.add(loss);
        const auto result = policy.evaluate();
        assert(result.telemetry_integrity == 0.55f);
        assert(result.confidence <= 0.55f);
        assert(result.decision != deac::policy::Decision::Enforce);
    }

    {
        // Three distinct observations from one family have diminishing returns and must not
        // impersonate three independent families.
        deac::policy::Engine policy({0.70f, 0.82f, 0.93f, 3, 2, 32});
        for (int i = 0; i < 3; ++i) {
            deac::policy::Evidence e{};
            e.anomaly = 0.90f;
            e.data_quality = 1.0f;
            e.sequence = static_cast<std::uint64_t>(300 + i);
            e.evidence_key = "access:" + std::to_string(i);
            e.evidence_family = "process-access";
            policy.add(e);
        }
        const auto result = policy.evaluate();
        assert(result.supporting_families == 1);
        assert(result.decision != deac::policy::Decision::Enforce);
    }

    {
        // Mixed valid/invalid samples: means use valid samples only and coverage reflects reality.
        deac::telemetry::Engine mixed;
        deac::telemetry::Sample good{};
        good.aim_speed_deg_s = 1000.0f;
        good.input_interval_stddev_ms = 50.0f;
        good.reaction_ms = 100.0f;
        good.movement_efficiency = 0.5f;
        good.shots = 10;
        good.headshots = 5;
        deac::telemetry::Sample bad = good;
        bad.reaction_ms = std::numeric_limits<float>::infinity();
        for (int i = 0; i < 8; ++i) mixed.add(good);
        for (int i = 0; i < 2; ++i) mixed.add(bad);
        const auto a = mixed.aggregate();
        assert(a.received_count == 10);
        assert(a.valid_count == 8);
        assert(a.invalid_count == 2);
        assert(a.coverage_ratio == 0.8f);
        assert(a.mean_aim_speed == 1000.0f);
        assert(a.mean_reaction == 100.0f);
    }

    std::cout << "DEAC detection/policy/config/graph tests passed\n";
    return 0;
}
