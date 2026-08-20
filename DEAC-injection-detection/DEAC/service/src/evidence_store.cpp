#include "evidence_store.h"
#include <iomanip>

namespace deac::evidence {

Store::Store(std::filesystem::path path) : path_(std::move(path)) {
    std::error_code ec;
    if (path_.has_parent_path()) std::filesystem::create_directories(path_.parent_path(), ec);
    out_.open(path_, std::ios::out | std::ios::app);
}

bool Store::append(const policy::Evidence& evidence) {
    std::scoped_lock lock(mutex_);
    if (!out_.is_open()) return false;
    out_ << evidence.timestamp_ms << ','
         << evidence.sequence << ','
         << std::setprecision(7) << evidence.anomaly << ','
         << evidence.data_quality << ','
         << evidence.event_type << ','
         << evidence.pid << ','
         << evidence.tid << '\n';
    out_.flush();
    if (out_) { ++records_; return true; }
    return false;
}

} // namespace deac::evidence
