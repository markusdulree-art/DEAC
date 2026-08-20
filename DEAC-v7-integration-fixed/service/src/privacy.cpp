#include "privacy.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <stdexcept>
#pragma comment(lib, "bcrypt.lib")

namespace deac::privacy {

std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> data) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0, result_length = 0;
    std::array<std::uint8_t, 32> digest{};

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider");
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &result_length, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0); throw std::runtime_error("BCryptGetProperty");
    }
    std::vector<std::uint8_t> object(object_length);
    if (BCryptCreateHash(alg, &hash, object.data(), object_length, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0); throw std::runtime_error("BCryptCreateHash");
    }
    if (BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0) < 0 ||
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); throw std::runtime_error("BCryptHash");
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return digest;
}

std::string Hex(std::span<const std::uint8_t> bytes) {
    static constexpr char table[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) { out.push_back(table[b >> 4]); out.push_back(table[b & 0xF]); }
    return out;
}

std::string StablePseudonym(std::string_view installation_secret, std::string_view stable_input) {
    std::vector<std::uint8_t> buffer;
    buffer.reserve(installation_secret.size() + 1 + stable_input.size());
    buffer.insert(buffer.end(), installation_secret.begin(), installation_secret.end());
    buffer.push_back(0);
    buffer.insert(buffer.end(), stable_input.begin(), stable_input.end());
    return Hex(Sha256(buffer));
}

} // namespace deac::privacy
