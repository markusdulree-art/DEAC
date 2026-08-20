#pragma once

#include "process_identity.h"
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace deac::audit {

struct Record final {
    std::string category;
    std::string message;
    std::uint64_t monotonic_ms{};
    std::uint64_t sequence{};
    std::uint32_t event_type{};
    std::string session_id;
    std::optional<identity::ProcessIdentity> target;
    std::optional<identity::ProcessIdentity> source;
    std::string evidence_key;
    std::string correlation_id;
    float anomaly{};
    float quality{};
};

class Log final {
public:
    explicit Log(std::filesystem::path path);
    bool write(std::string_view category, std::string_view message);
    bool write(const Record& record);

private:
    std::filesystem::path path_;
    std::mutex mutex_;
};

} // namespace deac::audit
