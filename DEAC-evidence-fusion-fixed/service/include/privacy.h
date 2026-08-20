#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace deac::privacy {

std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> data);
std::string Hex(std::span<const std::uint8_t> bytes);
std::string StablePseudonym(std::string_view installation_secret, std::string_view stable_input);

} // namespace deac::privacy
