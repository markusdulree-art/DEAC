#include "deac_policy.h"
#include <algorithm>
#include <cmath>
#include <unordered_set>

namespace deac::policy {

void Engine::Sanitize(Config& config) {
    config.monitor_threshold = std::clamp(config.monitor_threshold, 0.0f, 1.0f);
    config.review_threshold = std::clamp(config.review_threshold, config.monitor_threshold, 1.0f);
    config.enforce_threshold = std::clamp(config.enforce_threshold, config.review_threshold, 1.0f);
    config.minimum_supporting_events = std::max<std::uint32_t>(1, config.minimum_supporting_events);
    config.minimum_supporting_families = std::max<std::uint32_t>(1, config.minimum_supporting_families);
    config.max_evidence = std::max<std::uint32_t>(8, config.max_evidence);
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
    const float graph_strength = std::clamp(evidence.correlation_boost, 0.0f, 0.90f);
    // Relationship evidence is a bounded multiplicative/contextual gain, not a replacement for
    // the underlying observation. This prevents one weak observation from becoming a ban signal.
    return std::clamp((0.75f * anomaly + 0.25f * graph_strength) * quality, 0.0f, 1.0f);
}

Result Engine::evaluate() const {
    std::scoped_lock lock(mutex_);
    Result result{};
    if (evidence_.empty()) return result;

    double weighted_sum = 0.0;
    double weight = 0.0;
    std::uint32_t high_confidence = 0;
    std::unordered_set<std::string> families;
    std::unordered_set<std::string> correlated_groups;

    for (const auto& e : evidence_) {
        const float quality = std::clamp(e.data_quality, 0.0f, 1.0f);
        if (quality <= 0.0f) {
            if (e.event_type == static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow))
                result.integrity_flags |= 1u;
            continue;
        }

        const float strength = EvidenceStrength(e);
        weighted_sum += strength;
        weight += quality;

        if (strength >= config_.review_threshold && quality >= 0.80f) {
            ++high_confidence;
            if (!e.evidence_family.empty()) families.insert(e.evidence_family);
        }
        if (e.correlation_edges >= 1 && !e.correlation_id.empty()) {
            correlated_groups.insert(e.correlation_id);
        }
    }

    result.confidence = weight > 0.0 ?
        std::clamp(static_cast<float>(weighted_sum / weight), 0.0f, 1.0f) : 0.0f;
    result.supporting_events = high_confidence;
    result.supporting_families = static_cast<std::uint32_t>(families.size());

    if (result.confidence >= config_.enforce_threshold &&
        result.supporting_events >= config_.minimum_supporting_events &&
        result.supporting_families >= config_.minimum_supporting_families &&
        !correlated_groups.empty()) {
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
