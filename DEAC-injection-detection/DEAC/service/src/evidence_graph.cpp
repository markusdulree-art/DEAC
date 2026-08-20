#include "evidence_graph.h"

#include <algorithm>

namespace deac::graph {

EvidenceGraph::EvidenceGraph(std::uint64_t window_ms, std::size_t capacity)
    : window_ms_(std::max<std::uint64_t>(1000, window_ms)),
      capacity_(std::max<std::size_t>(64, capacity)) {}

bool EvidenceGraph::sameProcess(const identity::ProcessIdentity& a,
                                const identity::ProcessIdentity& b) const noexcept {
    return a.valid() && b.valid() && a.pid == b.pid && a.birth_token == b.birth_token;
}

float EvidenceGraph::EdgeBoost(const Correlation& c) noexcept {
    float boost = 0.0f;
    if (c.same_target_instance) boost += 0.08f;
    if (c.same_source_instance) boost += 0.10f;
    if (c.temporal_proximity) boost += 0.10f;
    if (c.handle_before_module) boost += 0.22f;
    if (c.handle_before_memory) boost += 0.26f;
    if (c.module_before_memory) boost += 0.16f;
    return std::min(boost, 0.85f);
}

void EvidenceGraph::observe(Event event) {
    std::scoped_lock lock(mutex_);
    events_.push_back(std::move(event));
    const auto newest = events_.back().monotonic_ms;
    while (!events_.empty() &&
           (newest > events_.front().monotonic_ms && newest - events_.front().monotonic_ms > window_ms_ ||
            events_.size() > capacity_)) {
        events_.pop_front();
    }
}

Correlation EvidenceGraph::correlate(const identity::ProcessIdentity& source,
                                      const identity::ProcessIdentity& target,
                                      EventKind current_kind,
                                      std::uint64_t now_ms) const {
    std::scoped_lock lock(mutex_);
    Correlation result{};

    for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
        const auto& prior = *it;
        if (now_ms < prior.monotonic_ms || now_ms - prior.monotonic_ms > window_ms_) continue;

        const bool target_match = sameProcess(prior.target, target);
        const bool source_match = sameProcess(prior.source, source);
        if (target_match) result.same_target_instance = true;
        if (source_match) result.same_source_instance = true;
        if (target_match) result.temporal_proximity = true;

        if (!target_match) continue;

        if (current_kind == EventKind::MemoryPrivateExecutablePe ||
            current_kind == EventKind::MemoryPrivateExecutable) {
            if (prior.kind == EventKind::DangerousHandle && source_match && prior.monotonic_ms <= now_ms) {
                result.handle_before_memory = true;
                ++result.supporting_edges;
            }
            if (prior.kind == EventKind::ImageLoaded && prior.anomaly >= 0.80f && prior.monotonic_ms <= now_ms) {
                result.module_before_memory = true;
                ++result.supporting_edges;
            }
        }

        if (current_kind == EventKind::ImageLoaded &&
            prior.kind == EventKind::DangerousHandle && source_match && prior.monotonic_ms <= now_ms) {
            result.handle_before_module = true;
            ++result.supporting_edges;
        }
    }

    result.boost = EdgeBoost(result);
    return result;
}

std::vector<Event> EvidenceGraph::recent_for_target(const identity::ProcessIdentity& target,
                                                    std::uint64_t now_ms) const {
    std::scoped_lock lock(mutex_);
    std::vector<Event> result;
    for (const auto& event : events_) {
        if (now_ms >= event.monotonic_ms && now_ms - event.monotonic_ms <= window_ms_ &&
            sameProcess(event.target, target)) {
            result.push_back(event);
        }
    }
    return result;
}

std::vector<identity::ProcessIdentity> EvidenceGraph::recent_sources(const identity::ProcessIdentity& target,
                                                                     EventKind kind,
                                                                     std::uint64_t now_ms) const {
    std::scoped_lock lock(mutex_);
    std::vector<identity::ProcessIdentity> result;
    for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
        const auto& event = *it;
        if (now_ms < event.monotonic_ms || now_ms - event.monotonic_ms > window_ms_) continue;
        if (event.kind != kind || !sameProcess(event.target, target) || !event.source.valid()) continue;
        const auto exists = std::find_if(result.begin(), result.end(), [&](const auto& candidate) {
            return sameProcess(candidate, event.source);
        });
        if (exists == result.end()) result.push_back(event.source);
    }
    return result;
}

Snapshot EvidenceGraph::snapshot() const {
    std::scoped_lock lock(mutex_);
    Snapshot result{};
    result.events = events_.size();
    if (!events_.empty()) result.oldest_ms = events_.front().monotonic_ms;

    std::vector<std::string> targets;
    std::vector<std::string> sources;
    for (const auto& event : events_) {
        if (event.target.valid()) targets.push_back(event.target.Key());
        if (event.source.valid()) sources.push_back(event.source.Key());
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    std::sort(sources.begin(), sources.end());
    sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
    result.active_targets = targets.size();
    result.active_sources = sources.size();
    return result;
}

void EvidenceGraph::clear() {
    std::scoped_lock lock(mutex_);
    events_.clear();
}

} // namespace deac::graph
