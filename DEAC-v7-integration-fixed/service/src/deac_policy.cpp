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
    if (evidence.evidence_family.empty() || evidence.data_quality <= 0.0f) return;
    std::scoped_lock lock(mutex_);
    if (evidence_.size() >= config_.max_evidence) evidence_.erase(evidence_.begin());
    evidence_.push_back(evidence);
}

float Engine::EvidenceStrength(const Evidence& evidence) noexcept {
    const float quality = std::clamp(evidence.data_quality, 0.0f, 1.0f);
    const float anomaly = std::clamp(evidence.anomaly, 0.0f, 1.0f);
    if (quality <= 0.0f || anomaly <= 0.0f) return 0.0f;

    // Correlation is contextual reinforcement, never an independent vote. Its gain is
    // deliberately bounded and multiplied by the base anomaly so weak observations remain weak.
    const float correlation = std::clamp(evidence.correlation_boost, 0.0f, 0.90f);
    const float relationship_gain = evidence.correlation_edges == 0
        ? 0.0f
        : 0.30f * correlation * anomaly;
    return std::clamp((anomaly + relationship_gain) * quality, 0.0f, 1.0f);
}

Result Engine::evaluate() const {
    std::scoped_lock lock(mutex_);
    Result result{};
    if (evidence_.empty()) return result;

    struct FamilyState {
        float strongest{0.0f};
        std::unordered_set<std::string> keys;
    };

    std::unordered_map<std::string, FamilyState> families;
    std::unordered_set<std::string> correlated_ids;
    std::unordered_set<std::string> accepted_event_keys;
    float telemetry_integrity = 1.0f;

    for (const auto& e : evidence_) {
        if (e.event_type == static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow)) {
            result.integrity_flags |= 1u;
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
        auto& family = families[e.evidence_family];
        const float strength = EvidenceStrength(e);

        // The same logical evidence contributes with diminishing returns. We retain the
        // strongest representative per family/key rather than treating repeated samples as
        // independent evidence.
        const bool first_key = family.keys.insert(key).second;
        family.strongest = std::max(family.strongest, first_key ? strength : strength * 0.20f);

        if (first_key && strength >= config_.monitor_threshold) {
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

    // Independent-family fusion. We intentionally do not sum raw events: each evidence
    // family contributes one bounded strength value, so correlated copies cannot overwhelm
    // the decision merely by quantity.
    double survival = 1.0;
    for (const auto& [_, family] : families) {
        const double independent = std::clamp(static_cast<double>(family.strongest) * 0.92, 0.0, 0.92);
        survival *= (1.0 - independent);
    }
    float confidence = static_cast<float>(1.0 - survival);

    // Relationship evidence increases confidence only after independent families are present.
    if (result.supporting_families >= 2 && result.correlated_events > 0) {
        confidence = std::clamp(confidence +
            0.05f * static_cast<float>(std::min<std::uint32_t>(result.correlated_events, 3u)),
            0.0f, 1.0f);
    }

    // A healthy telemetry stream is required for high-confidence enforcement. Degraded
    // telemetry can still support monitor/review outcomes.
    confidence *= telemetry_integrity;
    result.confidence = std::clamp(confidence, 0.0f, 1.0f);

    if (result.confidence >= config_.enforce_threshold &&
        result.supporting_events >= config_.minimum_supporting_events &&
        result.supporting_families >= config_.minimum_supporting_families &&
        result.correlated_events > 0 &&
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
