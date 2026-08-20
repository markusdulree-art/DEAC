#pragma once

#include "deac_protocol.h"
#include "process_identity.h"
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace deac::policy {

enum class Decision : std::uint32_t {
    Allow = 0,
    Monitor = 1,
    Review = 2,
    Enforce = 3,
};

struct Evidence final {
    std::uint64_t timestamp_ms{};
    std::uint64_t sequence{};
    float anomaly{};
    float data_quality{};
    std::uint32_t event_type{};
    std::uint64_t pid{};
    std::uint64_t tid{};
    std::uint64_t source_pid{};
    std::uint64_t source_birth_token{};
    identity::ProcessIdentity target{};
    identity::ProcessIdentity source{};
    std::uint32_t correlation_edges{};
    float correlation_boost{};
    std::string evidence_key;
    std::string evidence_family;
    std::string correlation_id;
};

struct Result final {
    Decision decision{Decision::Allow};
    float confidence{};
    std::uint32_t supporting_events{};
    std::uint32_t supporting_families{};
    std::uint32_t integrity_flags{};
};

struct Config final {
    float monitor_threshold{0.70f};
    float review_threshold{0.82f};
    float enforce_threshold{0.93f};
    std::uint32_t minimum_supporting_events{3};
    std::uint32_t minimum_supporting_families{2};
    std::uint32_t max_evidence{256};
};

class Engine final {
public:
    explicit Engine(Config config = {});

    void configure(Config config);
    void add(const Evidence& evidence);
    Result evaluate() const;
    void clear();
    std::size_t size() const;

private:
    static void Sanitize(Config& config);
    static float EvidenceStrength(const Evidence& evidence) noexcept;

    Config config_;
    mutable std::mutex mutex_;
    std::vector<Evidence> evidence_;
};

} // namespace deac::policy
