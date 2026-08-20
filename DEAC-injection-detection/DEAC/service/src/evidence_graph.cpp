#include "evidence_graph.h"
#include <algorithm>

namespace deac::graph {

EvidenceGraph::EvidenceGraph(TimingConfig timing, std::size_t capacity)
    : timing_(timing), capacity_(std::max<std::size_t>(64, capacity)) {
    timing_.handle_to_module_ms = std::clamp<std::uint64_t>(timing_.handle_to_module_ms, 1, 5000);
    timing_.handle_to_memory_ms = std::clamp<std::uint64_t>(timing_.handle_to_memory_ms, 1, 5000);
    timing_.module_to_memory_ms = std::clamp<std::uint64_t>(timing_.module_to_memory_ms, 1, 10000);
    timing_.generic_ms = std::clamp<std::uint64_t>(timing_.generic_ms, 1, 30000);
}

bool EvidenceGraph::sameProcess(const identity::ProcessIdentity& a,
                                const identity::ProcessIdentity& b) noexcept {
    return a.sameInstance(b);
}

std::uint64_t EvidenceGraph::WindowFor(EventKind current_kind, EventKind prior_kind) const noexcept {
    if ((current_kind == EventKind::ImageLoaded && prior_kind == EventKind::DangerousHandle))
        return timing_.handle_to_module_ms;
    if ((current_kind == EventKind::MemoryPrivateExecutable || current_kind == EventKind::MemoryPrivateExecutablePe) &&
        prior_kind == EventKind::DangerousHandle)
        return timing_.handle_to_memory_ms;
    if ((current_kind == EventKind::MemoryPrivateExecutable || current_kind == EventKind::MemoryPrivateExecutablePe) &&
        prior_kind == EventKind::ImageLoaded)
        return timing_.module_to_memory_ms;
    return timing_.generic_ms;
}

float EvidenceGraph::EdgeBoost(const Correlation& c) noexcept {
    float boost = 0.0f;
    if (c.same_target_instance) boost += 0.06f;
    if (c.same_source_instance) boost += 0.10f;
    if (c.temporal_proximity) boost += 0.06f;
    if (c.handle_before_module) boost += 0.28f;
    if (c.handle_before_memory) boost += 0.32f;
    if (c.module_before_memory) boost += 0.20f;
    return std::min(boost, 0.90f);
}

void EvidenceGraph::observe(Event event) {
    std::scoped_lock lock(mutex_);
    events_.push_back(std::move(event));
    const auto newest = events_.back().monotonic_ms;
    while (!events_.empty() &&
           (newest > events_.front().monotonic_ms && newest - events_.front().monotonic_ms > timing_.generic_ms ||
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
        if (now_ms < prior.monotonic_ms) continue;
        const auto delta = now_ms - prior.monotonic_ms;
        if (delta > timing_.generic_ms) continue;

        const bool target_match = sameProcess(prior.target, target);
        const bool source_match = sameProcess(prior.source, source);
        if (target_match) result.same_target_instance = true;
        if (source_match) result.same_source_instance = true;
        if (!target_match) continue;

        const auto relevant_window = WindowFor(current_kind, prior.kind);
        if (delta > relevant_window) continue;
        result.temporal_proximity = true;

        if ((current_kind == EventKind::MemoryPrivateExecutablePe ||
             current_kind == EventKind::MemoryPrivateExecutable) &&
            prior.kind == EventKind::DangerousHandle && source_match && prior.monotonic_ms <= now_ms) {
            result.handle_before_memory = true;
            ++result.supporting_edges;
        }

        // Only a genuinely suspicious image observation can contribute the module→memory edge.
        if ((current_kind == EventKind::MemoryPrivateExecutablePe ||
             current_kind == EventKind::MemoryPrivateExecutable) &&
            prior.kind == EventKind::ImageLoaded && prior.anomaly >= 0.80f &&
            prior.quality >= 0.75f && prior.monotonic_ms <= now_ms) {
            result.module_before_memory = true;
            ++result.supporting_edges;
        }

        if (current_kind == EventKind::ImageLoaded &&
            prior.kind == EventKind::DangerousHandle && source_match && prior.monotonic_ms <= now_ms) {
            result.handle_before_module = true;
            ++result.supporting_edges;
        }
    }

    result.relationship_valid = result.supporting_edges > 0;
    // A mere shared target/source is context, not a causal relationship. Only an
    // event-specific edge is allowed to contribute correlation strength.
    if (!result.relationship_valid) {
        result.temporal_proximity = false;
        result.boost = 0.0f;
    } else {
        result.boost = EdgeBoost(result);
    }
    return result;
}

std::vector<Event> EvidenceGraph::recent_for_target(const identity::ProcessIdentity& target,
                                                    std::uint64_t now_ms) const {
    std::scoped_lock lock(mutex_);
    std::vector<Event> result;
    for (const auto& event : events_) {
        if (now_ms >= event.monotonic_ms && now_ms - event.monotonic_ms <= timing_.generic_ms &&
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
        if (now_ms < event.monotonic_ms || now_ms - event.monotonic_ms > timing_.generic_ms) continue;
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
