#include "gsi_adapter.h"
#include <nlohmann/json.hpp>
#include <windows.h>
#include <algorithm>
#include <cmath>

namespace deac::gsi {
using json = nlohmann::json;

std::optional<telemetry::Sample> Adapter::parse(std::string_view json_text) const {
    try {
        const json root = json::parse(json_text);
        telemetry::Sample sample{};
        sample.monotonic_ns = GetTickCount64() * 1'000'000ULL;

        if (root.contains("player") && root["player"].is_object()) {
            const auto& player = root["player"];
            if (player.contains("state") && player["state"].is_object()) {
                const auto& state = player["state"];
                if (state.contains("round_kills") && state["round_kills"].is_number_unsigned()) {
                    sample.shots = state["round_kills"].get<std::uint32_t>();
                }
            }
        }

        // GSI does not expose raw mouse input or authoritative aim timing.
        // Those features intentionally remain zero/unknown rather than being invented.
        return sample;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace deac::gsi
