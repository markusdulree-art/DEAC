#pragma once

#include "deac_telemetry.h"
#include <string_view>
#include <optional>

namespace deac::gsi {

class Adapter final {
public:
    // Parses only fields used by DEAC from a CS2 Game State Integration document.
    // Missing game-state fields are treated as unknown rather than fabricated.
    std::optional<deac::telemetry::Sample> parse(std::string_view json_text) const;
};

} // namespace deac::gsi
