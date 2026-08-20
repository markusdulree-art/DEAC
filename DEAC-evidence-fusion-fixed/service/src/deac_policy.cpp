#include "deac_policy.h"
#include <algorithm>
#include <cmath>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace deac::policy {

void Engine::Sanitize(Config& config) {
    config.monitor_threshold = std::clamp(config.monitor_threshold, 0.0f, 1.0f);
    config.review_threshold = std::clamp(config.review_threshold, config.monitor_threshold, 1.0f);
    config.enforce_threshold = std::clamp(config.enforce_threshold, config.review_threshold, 1.0f);
    config.minimum_supporting_events = std::max<std::uint32_t>(1, config.minimum_supporting_events);
    config.minimum_supporting_families = std::max<std::uint32_t>(1, config.minimum_supporting_families);
    config.max_evidence = std::clamp<std::uint32_t>(config.max_evidence, 8, 4096);
}

Engine::Engine(Config config) : config_(config) {
    Sanitize(config_);
    evidence_.reserve(config_.max_evidence);
}

void Engine::configure(Config config) {
    Sanitize(config);
    std::scoped_lock lock(mutex_);
    config_ = config;
    if (evidence_.size() > config_.max_evidence) {
        evidence_.erase(evidence_.begin(), evidence_.begin() +
            static_cast<std::ptrdiff_t>(evidence_.size() - config_.max_evidence));
    }
}

void Engine::add(const Evidence& evidence) {
    if (evidence.evidence_family.empty()) return;
    const bool integrity_event =
        evidence.evidence_family == "telemetry-integrity" ||
        evidence.event_type == static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow);
    if (evidence.data_quality <= 0.0f && !integrity_event) return;
    std::scoped_lock lock(mutex_);
    if (evidence_.size() >= config_.max_evidence) evidence_.erase(evidence_.begin());
    evidence_.push_back(evidence);
}

float Engine::EvidenceStrength(const Evidence& evidence) noexcept {
    const float quality = std::clamp(evidence.data_quality, 0.0f, 1.0f);
    const float anomaly = std::clamp(evidence.anomaly, 0.0f, 1.0f);
    if (quality <= 0.0f || anomaly <= 0.0f) return 0.0f;

    // Correlation metadata is deliberately NOT folded into raw evidence strength.
    // Relationships are resolved after family-level evidence has been fused. This prevents
    // a single handle->memory chain from masquerading as an independent vote.
    return std::clamp(anomaly * quality, 0.0f, 1.0f);
}

Result Engine::evaluate() const {
    std::scoped_lock lock(mutex_);
    Result result{};
    if (evidence_.empty()) return result;

    struct FamilyState {
        // Logical evidence key -> strongest observation for that logical fact.
        std::unordered_map<std::string, float> observations;
    };

    std::unordered_map<std::string, FamilyState> families;
    std::unordered_set<std::string> correlated_ids;
    std::unordered_set<std::string> accepted_event_keys;
    float telemetry_integrity = 1.0f;

    for (const auto& e : evidence_) {
        if (e.event_type == static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow)) {
            result.integrity_flags |= 1u;
            // A loss event is not evidence of cheating. It is evidence that our confidence
            // in *absence* of cheating is degraded, so it directly lowers the confidence ceiling.
            telemetry_integrity = std::min(telemetry_integrity, 0.55f);
            continue;
        }

        const float quality = std::clamp(e.data_quality, 0.0f, 1.0f);
        if (quality <= 0.0f || e.evidence_family.empty()) continue;

        if (e.evidence_family == "telemetry-integrity") {
            telemetry_integrity = std::min(telemetry_integrity, quality);
            continue;
        }

        const std::string key = e.evidence_key.empty()
            ? (e.evidence_family + ":seq:" + std::to_string(e.sequence))
            : e.evidence_key;
        const float strength = EvidenceStrength(e);
        if (strength <= 0.0f) continue;

        auto& family = families[e.evidence_family];
        auto [it, inserted] = family.observations.emplace(key, strength);
        if (!inserted && strength > it->second) it->second = strength;

        if (inserted && strength >= config_.monitor_threshold) {
            accepted_event_keys.insert(e.evidence_family + "|" + key);
        }

        if (e.correlation_edges > 0 && !e.correlation_id.empty()) {
            correlated_ids.insert(e.correlation_id);
        }
    }

    result.telemetry_integrity = telemetry_integrity;
    result.supporting_families = static_cast<std::uint32_t>(families.size());
    result.supporting_events = static_cast<std::uint32_t>(accepted_event_keys.size());
    result.correlated_events = static_cast<std::uint32_t>(correlated_ids.size());

    // Each family gets one bounded score. Within a family, repeated *different* logical
    // observations have diminishing returns; repeated copies of the same key are collapsed
    // to the strongest observation. This makes quantity useful without allowing one noisy
    // detector family to dominate the entire decision.
    double survival = 1.0;
    for (auto& [family_name, family] : families) {
        std::vector<float> strengths;
        strengths.reserve(family.observations.size());
        for (const auto& [_, strength] : family.observations) strengths.push_back(strength);
        std::sort(strengths.begin(), strengths.end(), std::greater<float>{});

        double family_score = 0.0;
        double diminishing = 1.0;
        for (const float strength : strengths) {
            family_score += static_cast<double>(strength) * diminishing;
            diminishing *= 0.50;
            if (diminishing < 0.03125) break;
        }
        family_score = std::clamp(family_score, 0.0, 0.90);

        // Independent families combine probabilistically. There is intentionally no
        // correlation_boost term here: graph relationships remain relationship metadata.
        survival *= (1.0 - family_score);

        if (family_score >= static_cast<double>(config_.monitor_threshold)) {
            result.supporting_evidence_families.push_back(family_name);
            for (const auto& [key, strength] : family.observations) {
                if (strength >= config_.monitor_threshold) {
                    result.supporting_evidence_keys.push_back(key);
                }
            }
        }
    }

    std::sort(result.supporting_evidence_families.begin(), result.supporting_evidence_families.end());
    std::sort(result.supporting_evidence_keys.begin(), result.supporting_evidence_keys.end());

    result.supporting_correlation_ids.assign(correlated_ids.begin(), correlated_ids.end());
    std::sort(result.supporting_correlation_ids.begin(), result.supporting_correlation_ids.end());

    float confidence = static_cast<float>(1.0 - survival);

    // Telemetry integrity is a confidence ceiling, not another evidence vote. A queue loss
    // therefore cannot increase confidence, and a high anomaly score cannot outrun missing data.
    confidence = std::min(confidence, telemetry_integrity);
    result.confidence = std::clamp(confidence, 0.0f, 1.0f);

    const bool enough_families = result.supporting_families >= config_.minimum_supporting_families;
    const bool enough_events = result.supporting_events >= config_.minimum_supporting_events;
    const bool has_relationship = result.correlated_events > 0;

    if (result.confidence >= config_.enforce_threshold &&
        enough_events && enough_families && has_relationship &&
        telemetry_integrity >= 0.80f) {
        result.decision = Decision::Enforce;
    } else if (result.confidence >= config_.review_threshold) {
        result.decision = Decision::Review;
    } else if (result.confidence >= config_.monitor_threshold) {
        result.decision = Decision::Monitor;
    }
    return result;
}

void Engine::clear() {
    std::scoped_lock lock(mutex_);
    evidence_.clear();
}

std::size_t Engine::size() const {
    std::scoped_lock lock(mutex_);
    return evidence_.size();
}

} // namespace deac::policy
