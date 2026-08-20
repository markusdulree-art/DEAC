#include "deac_policy.h"
#include <algorithm>
#include <cmath>

namespace deac::policy {

Engine::Engine(Config config) : config_(config) {
    config_.monitor_threshold = std::clamp(config_.monitor_threshold, 0.0f, 1.0f);
    config_.review_threshold = std::clamp(config_.review_threshold, config_.monitor_threshold, 1.0f);
    config_.enforce_threshold = std::clamp(config_.enforce_threshold, config_.review_threshold, 1.0f);
    config_.minimum_supporting_events = std::max<std::uint32_t>(1, config_.minimum_supporting_events);
    config_.max_evidence = std::max<std::uint32_t>(8, config_.max_evidence);
    evidence_.reserve(config_.max_evidence);
}

void Engine::configure(Config config) {
    std::scoped_lock lock(mutex_);
    config_.monitor_threshold = std::clamp(config.monitor_threshold, 0.0f, 1.0f);
    config_.review_threshold = std::clamp(config.review_threshold, config_.monitor_threshold, 1.0f);
    config_.enforce_threshold = std::clamp(config.enforce_threshold, config_.review_threshold, 1.0f);
    config_.minimum_supporting_events = std::max<std::uint32_t>(1, config.minimum_supporting_events);
    config_.max_evidence = std::max<std::uint32_t>(8, config.max_evidence);
    if (evidence_.size() > config_.max_evidence) {
        evidence_.erase(evidence_.begin(), evidence_.begin() + static_cast<std::ptrdiff_t>(evidence_.size() - config_.max_evidence));
    }
}

void Engine::add(const Evidence& evidence) {
    std::scoped_lock lock(mutex_);
    if (evidence_.size() >= config_.max_evidence) {
        evidence_.erase(evidence_.begin());
    }
    evidence_.push_back(evidence);
}

Result Engine::evaluate() const {
    std::scoped_lock lock(mutex_);
    Result result{};
    if (evidence_.empty()) return result;

    float weighted_sum = 0.0f;
    float weight = 0.0f;
    std::uint32_t high_confidence = 0;

    for (const auto& e : evidence_) {
        const float quality = std::clamp(e.data_quality, 0.0f, 1.0f);
        const float anomaly = std::clamp(e.anomaly, 0.0f, 1.0f);
        if (quality >= 0.8f && anomaly >= config_.review_threshold) ++high_confidence;
        weighted_sum += anomaly * quality;
        weight += quality;
        result.integrity_flags |= static_cast<std::uint32_t>(e.event_type ==
            static_cast<std::uint32_t>(deac::protocol::EventType::QueueOverflow));
    }

    const float confidence = weight > 0.0f ? weighted_sum / weight : 0.0f;
    result.confidence = std::clamp(confidence, 0.0f, 1.0f);
    result.supporting_events = high_confidence;

    if (result.confidence >= config_.enforce_threshold &&
        high_confidence >= config_.minimum_supporting_events) {
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
