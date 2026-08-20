#include "deac_policy.h"
#include <algorithm>
#include <cmath>
#include <unordered_map>
#include <unordered_set>

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
    std::scoped_lock lock(mutex_);
    if (evidence_.size() >= config_.max_evidence) evidence_.erase(evidence_.begin());
    evidence_.push_back(evidence);
}

float Engine::EvidenceStrength(const Evidence& evidence) noexcept {
    const float quality = std::clamp(evidence.data_quality, 0.0f, 1.0f);
    const float anomaly = std::clamp(evidence.anomaly, 0.0f, 1.0f);
    const float graph = std::clamp(evidence.correlation_boost, 0.0f, 0.90f);
    // Correlation reinforces an observation but cannot turn weak/noisy evidence into
    // strong evidence by itself.
    const float relationship_gain = evidence.correlation_edges == 0 ? 0.0f : 0.20f * graph;
    return std::clamp((anomaly + relationship_gain) * quality, 0.0f, 1.0f);
}

Result Engine::evaluate() const {
    std::scoped_lock lock(mutex_);
    Result result{};
    if (evidence_.empty()) return result;

    std::unordered_map<std::string, float> family_strength;
    std::unordered_map<std::string, std::uint32_t> family_counts;
    std::unordered_set<std::string> correlated_keys;
    std::unordered_set<std::string> seen_keys;
    float telemetry_integrity = 1.0f;

    for (const auto& e : evidence_) {
        const float quality = std::clamp(e.data_quality, 0.0f, 1.0f);
        if (e.event_type == static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow)) {
            result.integrity_flags |= 1u;
            telemetry_integrity = std::min(telemetry_integrity, 0.55f);
            continue;
        }
        if (quality <= 0.0f || e.evidence_family.empty()) continue;

        const std::string family = e.evidence_family;
        const float strength = EvidenceStrength(e);
        const auto key = e.evidence_key.empty()
            ? (family + ":" + std::to_string(e.sequence))
            : e.evidence_key;

        // Keep repeated observations from the same logical key from counting as independent evidence.
        const bool first_key = seen_keys.insert(key).second;
        const float contribution = first_key ? strength : strength * 0.20f;
        family_strength[family] = std::max(family_strength[family], contribution);
        family_counts[family] += 1;

        if (e.correlation_edges > 0 && !e.correlation_id.empty()) {
            correlated_keys.insert(e.correlation_id);
        }

        if (family == "telemetry-integrity") {
            telemetry_integrity = std::min(telemetry_integrity, quality);
        }
    }

    result.telemetry_integrity = telemetry_integrity;
    result.supporting_families = static_cast<std::uint32_t>(family_strength.size());
    for (const auto& [family, strength] : family_strength) {
        if (strength >= config_.review_threshold) {
            result.supporting_events += std::min<std::uint32_t>(family_counts[family], 1u);
        }
    }
    result.correlated_events = static_cast<std::uint32_t>(correlated_keys.size());

    // Nonlinear fusion across independent evidence families. A second observation from
    // the same family has diminishing returns; different families reinforce one another.
    double survival = 1.0;
    for (const auto& [_, strength] : family_strength) {
        const double independent = std::clamp(static_cast<double>(strength) * 0.92, 0.0, 0.92);
        survival *= (1.0 - independent);
    }
    float confidence = static_cast<float>(1.0 - survival);

    // Correlation is additional context, not another independent family.
    if (result.correlated_events > 0) {
        confidence = std::clamp(confidence + 0.06f *
            static_cast<float>(std::min<std::uint32_t>(result.correlated_events, 3u)), 0.0f, 1.0f);
    }

    confidence *= telemetry_integrity;
    result.confidence = std::clamp(confidence, 0.0f, 1.0f);

    if (result.confidence >= config_.enforce_threshold &&
        result.supporting_events >= config_.minimum_supporting_events &&
        result.supporting_families >= config_.minimum_supporting_families &&
        result.correlated_events > 0 && telemetry_integrity >= 0.80f) {
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
