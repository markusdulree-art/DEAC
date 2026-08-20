#include "deac_config.h"

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#include <Windows.h>
#endif

namespace deac::config {
namespace {
using json = nlohmann::json;

template <typename T>
T ClampValue(T value, T lo, T hi) { return std::clamp(value, lo, hi); }

void Sanitize(Settings& s) {
    s.telemetry_port = ClampValue<std::uint16_t>(s.telemetry_port, 1024, 65535);
    s.telemetry_max_body_bytes = ClampValue<std::uint32_t>(s.telemetry_max_body_bytes, 4096, 1024 * 1024);
    s.telemetry_poll_ms = ClampValue<std::uint32_t>(s.telemetry_poll_ms, 10, 1000);
    s.heartbeat_timeout_ms = ClampValue<std::uint32_t>(s.heartbeat_timeout_ms, 1000, 60000);
    s.evidence_flush_ms = ClampValue<std::uint32_t>(s.evidence_flush_ms, 100, 10000);
    s.minimum_supporting_events = ClampValue<std::uint32_t>(s.minimum_supporting_events, 1, 100);
    s.minimum_supporting_families = ClampValue<std::uint32_t>(s.minimum_supporting_families, 1, 10);
    s.monitor_threshold = ClampValue(s.monitor_threshold, 0.0f, 1.0f);
    s.review_threshold = ClampValue(s.review_threshold, s.monitor_threshold, 1.0f);
    s.enforce_threshold = ClampValue(s.enforce_threshold, s.review_threshold, 1.0f);
}

}

Settings Defaults() { return {}; }

Settings Load(const std::filesystem::path& path) {
    Settings result = Defaults();
    std::ifstream input(path, std::ios::binary);
    if (!input) return result;
    try {
        const auto j = json::parse(input);
        if (j.contains("telemetry_port")) result.telemetry_port = j.at("telemetry_port").get<std::uint16_t>();
        if (j.contains("telemetry_max_body_bytes")) result.telemetry_max_body_bytes = j.at("telemetry_max_body_bytes").get<std::uint32_t>();
        if (j.contains("telemetry_poll_ms")) result.telemetry_poll_ms = j.at("telemetry_poll_ms").get<std::uint32_t>();
        if (j.contains("heartbeat_timeout_ms")) result.heartbeat_timeout_ms = j.at("heartbeat_timeout_ms").get<std::uint32_t>();
        if (j.contains("evidence_flush_ms")) result.evidence_flush_ms = j.at("evidence_flush_ms").get<std::uint32_t>();
        if (j.contains("minimum_supporting_events")) result.minimum_supporting_events = j.at("minimum_supporting_events").get<std::uint32_t>();
        if (j.contains("minimum_supporting_families")) result.minimum_supporting_families = j.at("minimum_supporting_families").get<std::uint32_t>();
        if (j.contains("monitor_threshold")) result.monitor_threshold = j.at("monitor_threshold").get<float>();
        if (j.contains("review_threshold")) result.review_threshold = j.at("review_threshold").get<float>();
        if (j.contains("enforce_threshold")) result.enforce_threshold = j.at("enforce_threshold").get<float>();
        if (j.contains("enable_local_http")) result.enable_local_http = j.at("enable_local_http").get<bool>();
        if (j.contains("trusted_signer_thumbprints") && j.at("trusted_signer_thumbprints").is_array()) {
            result.trusted_signer_thumbprints.clear();
            for (const auto& value : j.at("trusted_signer_thumbprints")) {
                if (value.is_string()) result.trusted_signer_thumbprints.push_back(value.get<std::string>());
                if (result.trusted_signer_thumbprints.size() >= 64) break;
            }
        }
    } catch (...) {
        return Defaults();
    }
    Sanitize(result);
    return result;
}

bool Save(const std::filesystem::path& path, const Settings& input) {
    Settings settings = input;
    Sanitize(settings);

    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return false;

    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream output(tmp, std::ios::binary | std::ios::trunc);
        if (!output) return false;
        const json j = {
            {"telemetry_port", settings.telemetry_port},
            {"telemetry_max_body_bytes", settings.telemetry_max_body_bytes},
            {"telemetry_poll_ms", settings.telemetry_poll_ms},
            {"heartbeat_timeout_ms", settings.heartbeat_timeout_ms},
            {"evidence_flush_ms", settings.evidence_flush_ms},
            {"minimum_supporting_events", settings.minimum_supporting_events},
            {"minimum_supporting_families", settings.minimum_supporting_families},
            {"monitor_threshold", settings.monitor_threshold},
            {"review_threshold", settings.review_threshold},
            {"enforce_threshold", settings.enforce_threshold},
            {"enable_local_http", settings.enable_local_http},
            {"trusted_signer_thumbprints", settings.trusted_signer_thumbprints}
        };
        output << j.dump(2) << '\n';
        if (!output) return false;
    }

#ifdef _WIN32
    const auto tmpw = std::filesystem::path(tmp).wstring();
    const auto destw = path.wstring();
    if (!MoveFileExW(tmpw.c_str(), destw.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
#else
    std::filesystem::rename(tmp, path, ec);
    if (ec) { std::filesystem::remove(tmp, ec); return false; }
    return true;
#endif
}

} // namespace deac::config
