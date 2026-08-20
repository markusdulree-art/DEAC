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
    std::scoped_lock lock(mutex_);
    std::ofstream out(path_, std::ios::out | std::ios::app);
    if (!out) return false;

    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const json record = {
        {"timestamp_ms", now},
        {"category", category},
        {"message", message}
    };
    out << record.dump() << '\n';
    return static_cast<bool>(out);
}

} // namespace deac::audit
