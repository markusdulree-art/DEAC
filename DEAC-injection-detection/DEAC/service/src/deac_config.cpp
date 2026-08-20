#include "deac_config.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <string>
#include <type_traits>

namespace deac::config {

namespace {

template <typename T>
T ClampValue(T value, T lo, T hi) { return std::clamp(value, lo, hi); }

void Sanitize(Settings& s) {
    s.telemetry_port = ClampValue<std::uint16_t>(s.telemetry_port, 1024, 65535);
    s.telemetry_max_body_bytes = ClampValue<std::uint32_t>(s.telemetry_max_body_bytes, 4096, 1024 * 1024);
    s.telemetry_poll_ms = ClampValue<std::uint32_t>(s.telemetry_poll_ms, 10, 1000);
    s.heartbeat_timeout_ms = ClampValue<std::uint32_t>(s.heartbeat_timeout_ms, 1000, 60000);
    s.evidence_flush_ms = ClampValue<std::uint32_t>(s.evidence_flush_ms, 100, 10000);
    s.minimum_supporting_events = ClampValue<std::uint32_t>(s.minimum_supporting_events, 1, 100);
    s.monitor_threshold = ClampValue(s.monitor_threshold, 0.0f, 1.0f);
    s.review_threshold = ClampValue(s.review_threshold, s.monitor_threshold, 1.0f);
    s.enforce_threshold = ClampValue(s.enforce_threshold, s.review_threshold, 1.0f);
}

std::string ReadAll(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

template <typename T>
void ReadNumber(const std::string& text, const char* key, T& out) {
    const std::regex expression(std::string("\\\"") + key + "\\\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
    std::smatch match;
    if (std::regex_search(text, match, expression)) {
        try {
            if constexpr (std::is_floating_point_v<T>) out = static_cast<T>(std::stod(match[1].str()));
            else out = static_cast<T>(std::stoull(match[1].str()));
        } catch (...) {}
    }
}

void ReadBool(const std::string& text, const char* key, bool& out) {
    const std::regex expression(std::string("\\\"") + key + "\\\"\\s*:\\s*(true|false)");
    std::smatch match;
    if (std::regex_search(text, match, expression)) out = match[1].str() == "true";
}

} // namespace

Settings Defaults() { return {}; }

Settings Load(const std::filesystem::path& path) {
    Settings result = Defaults();
    const std::string text = ReadAll(path);
    if (text.empty()) return result;

    ReadNumber(text, "telemetry_port", result.telemetry_port);
    ReadNumber(text, "telemetry_max_body_bytes", result.telemetry_max_body_bytes);
    ReadNumber(text, "telemetry_poll_ms", result.telemetry_poll_ms);
    ReadNumber(text, "heartbeat_timeout_ms", result.heartbeat_timeout_ms);
    ReadNumber(text, "evidence_flush_ms", result.evidence_flush_ms);
    ReadNumber(text, "minimum_supporting_events", result.minimum_supporting_events);
    ReadNumber(text, "monitor_threshold", result.monitor_threshold);
    ReadNumber(text, "review_threshold", result.review_threshold);
    ReadNumber(text, "enforce_threshold", result.enforce_threshold);
    ReadBool(text, "enable_local_http", result.enable_local_http);
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
        output << "{\n"
               << "  \"telemetry_port\": " << settings.telemetry_port << ",\n"
               << "  \"telemetry_max_body_bytes\": " << settings.telemetry_max_body_bytes << ",\n"
               << "  \"telemetry_poll_ms\": " << settings.telemetry_poll_ms << ",\n"
               << "  \"heartbeat_timeout_ms\": " << settings.heartbeat_timeout_ms << ",\n"
               << "  \"evidence_flush_ms\": " << settings.evidence_flush_ms << ",\n"
               << "  \"minimum_supporting_events\": " << settings.minimum_supporting_events << ",\n"
               << "  \"monitor_threshold\": " << settings.monitor_threshold << ",\n"
               << "  \"review_threshold\": " << settings.review_threshold << ",\n"
               << "  \"enforce_threshold\": " << settings.enforce_threshold << ",\n"
               << "  \"enable_local_http\": " << (settings.enable_local_http ? "true" : "false") << "\n"
               << "}\n";
        if (!output) return false;
    }

    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

} // namespace deac::config
