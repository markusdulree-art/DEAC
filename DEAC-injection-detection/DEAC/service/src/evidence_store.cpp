#include "evidence_store.h"
#include <iomanip>
#include <nlohmann/json.hpp>

namespace deac::evidence {
using json = nlohmann::json;

Store::Store(std::filesystem::path path) : path_(std::move(path)) {
    std::error_code ec;
    if (path_.has_parent_path()) std::filesystem::create_directories(path_.parent_path(), ec);
    out_.open(path_, std::ios::out | std::ios::app);
}

bool Store::append(const policy::Evidence& e) {
    std::scoped_lock lock(mutex_);
    if (!out_.is_open()) return false;

    const json record = {
        {"schema", 2},
        {"timestamp_ms", e.timestamp_ms},
        {"sequence", e.sequence},
        {"event_type", e.event_type},
        {"pid", e.pid},
        {"tid", e.tid},
        {"source_pid", e.source_pid},
        {"source_birth_token", e.source_birth_token},
        {"target_process", e.target.Key()},
        {"source_process", e.source.Key()},
        {"anomaly", e.anomaly},
        {"data_quality", e.data_quality},
        {"correlation_edges", e.correlation_edges},
        {"correlation_boost", e.correlation_boost},
        {"evidence_key", e.evidence_key},
        {"evidence_family", e.evidence_family},
        {"correlation_id", e.correlation_id},
        {"target_identity", e.target.Key()},
        {"source_identity", e.source.Key()}
    };

    out_ << record.dump() << '\n';
    out_.flush();
    if (out_) { ++records_; return true; }
    return false;
}

} // namespace deac::evidence
