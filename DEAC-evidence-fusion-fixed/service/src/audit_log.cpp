#include "audit_log.h"
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>

namespace deac::audit {
using json = nlohmann::json;

Log::Log(std::filesystem::path path) : path_(std::move(path)) {
    std::error_code ec;
    if (path_.has_parent_path()) std::filesystem::create_directories(path_.parent_path(), ec);
}

bool Log::write(std::string_view category, std::string_view message) {
    Record record{};
    record.category = std::string(category);
    record.message = std::string(message);
    return write(record);
}

bool Log::write(const Record& r) {
    std::scoped_lock lock(mutex_);
    std::ofstream out(path_, std::ios::out | std::ios::app);
    if (!out) return false;

    const auto wall = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    json record = {
        {"schema", 2},
        {"wall_time_ms", wall},
        {"monotonic_ms", r.monotonic_ms},
        {"sequence", r.sequence},
        {"event_type", r.event_type},
        {"category", r.category},
        {"message", r.message},
        {"session_id", r.session_id},
        {"evidence_key", r.evidence_key},
        {"correlation_id", r.correlation_id},
        {"evidence_family", r.evidence_family},
        {"correlation_edges", r.correlation_edges},
        {"correlation_boost", r.correlation_boost},
        {"anomaly", r.anomaly},
        {"quality", r.quality},
        {"evidence_keys", r.evidence_keys},
        {"evidence_families", r.evidence_families},
        {"correlation_ids", r.correlation_ids}
    };
    if (r.target) record["target_process"] = r.target->Key();
    if (r.source) record["source_process"] = r.source->Key();
    out << record.dump() << '\n';
    return static_cast<bool>(out);
}

} // namespace deac::audit
