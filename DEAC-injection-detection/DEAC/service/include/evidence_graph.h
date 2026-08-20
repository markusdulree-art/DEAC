#pragma once

#include "process_identity.h"
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace deac::graph {

enum class NodeType : std::uint32_t {
    Process = 1,
    Module = 2,
    MemoryRegion = 3,
    Observation = 4,
};

enum class EventKind : std::uint32_t {
    Unknown = 0,
    ProcessCreated,
    ProcessExited,
    ImageLoaded,
    DangerousHandle,
    ReadHandle,
    MemoryPrivateExecutable,
    MemoryPrivateExecutablePe,
    QueueOverflow,
};

struct Event final {
    std::uint64_t monotonic_ms{};
    std::uint64_t sequence{};
    EventKind kind{EventKind::Unknown};
    identity::ProcessIdentity target{};
    identity::ProcessIdentity source{};
    std::string object_key;
    float anomaly{};
    float quality{};
};

struct Correlation final {
    bool same_source_instance{};
    bool same_target_instance{};
    bool temporal_proximity{};
    bool handle_before_memory{};
    bool handle_before_module{};
    bool module_before_memory{};
    std::uint32_t supporting_edges{};
    float boost{};
};

struct Snapshot final {
    std::size_t events{};
    std::size_t active_targets{};
    std::size_t active_sources{};
    std::uint64_t oldest_ms{};
};

class EvidenceGraph final {
public:
    explicit EvidenceGraph(std::uint64_t window_ms = 10'000, std::size_t capacity = 4096);

    void observe(Event event);
    Correlation correlate(const identity::ProcessIdentity& source,
                          const identity::ProcessIdentity& target,
                          EventKind current_kind,
                          std::uint64_t now_ms) const;
    std::vector<Event> recent_for_target(const identity::ProcessIdentity& target,
                                         std::uint64_t now_ms) const;
    std::vector<identity::ProcessIdentity> recent_sources(const identity::ProcessIdentity& target,
                                                           EventKind kind,
                                                           std::uint64_t now_ms) const;
    Snapshot snapshot() const;
    void clear();

private:
    bool sameProcess(const identity::ProcessIdentity& a, const identity::ProcessIdentity& b) const noexcept;
    static float EdgeBoost(const Correlation& c) noexcept;

    std::uint64_t window_ms_;
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<Event> events_;
};

} // namespace deac::graph
